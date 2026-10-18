"""Origin-pinned HTTPS transport for the runner's closed control-plane calls.

This is the only network path from the customer runner to Heel Cloud. It is deliberately
narrow: one configured ``https://`` origin, system trust (TLS 1.2+, hostname checked), no
redirects, no proxies, a bounded JSON response and a fixed per-call deadline. Failures are
reported as closed reason codes and never carry request or response material.

The optional ``ca_bundle`` argument exists so tests can trust an ephemeral loopback CA.
It is a constructor argument only: no environment variable, flag or configuration file
selects it, and it replaces (never extends) the trust store when given.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import socket
import ssl
import time
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit


MAX_CONTROL_RESPONSE_BYTES = 256 * 1024
MAX_CONTROL_REQUEST_BYTES = 272 * 1024
CONTROL_TIMEOUT_SECONDS = 30.0
_READ_CHUNK = 16 * 1024
_HOST = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$",
    flags=re.ASCII,
)
_PORT = re.compile(r"^[1-9][0-9]{0,4}$", flags=re.ASCII)
_PATH = re.compile(r"^/v1(?:/[A-Za-z0-9._~-]+)+$", flags=re.ASCII)
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$", flags=re.ASCII)
_HEADER_VALUE = re.compile(r"^[\x21-\x7e](?:[\x20-\x7e]{0,1022}[\x21-\x7e])?$", flags=re.ASCII)
# Callers may only set request metadata; framing, routing and ambient authority are owned here.
_FORBIDDEN_REQUEST_HEADERS = frozenset({
    "host", "content-length", "transfer-encoding", "connection", "keep-alive", "upgrade",
    "te", "trailer", "proxy-authorization", "proxy-connection", "authorization", "cookie",
    "x-heel-edge-auth", "x-heel-client-key", "x-heel-internal-origin", "origin", "expect",
})
# The only response headers a runner control decoder reads, in the exact case it reads them.
_RESPONSE_HEADERS = {"x-heel-runner-next-nonce": "X-Heel-Runner-Next-Nonce", "retry-after": "Retry-After"}


class ControlTransportError(RuntimeError):
    """A closed, secret-free transport failure."""

    CODES = frozenset({
        "invalid_origin", "invalid_request", "tls_trust_failed", "connection_failed",
        "timeout", "redirect_refused", "response_too_large", "malformed_response",
    })

    def __init__(self, code: str):
        if code not in self.CODES:
            code = "malformed_response"
        super().__init__(f"runner control transport failed: {code}")
        self.code = code


def validate_control_origin(origin: object) -> tuple[str, str, int]:
    """Return ``(origin, host, port)`` for one exact pathless lowercase ``https`` origin."""
    if type(origin) is not str or not 1 <= len(origin) <= 300 or not origin.isascii():
        raise ControlTransportError("invalid_origin")
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError:
        raise ControlTransportError("invalid_origin") from None
    host = parsed.hostname
    netloc = parsed.netloc
    if (
        parsed.scheme != "https" or not netloc or host is None
        or parsed.username is not None or parsed.password is not None or "@" in netloc
        or parsed.path or parsed.query or parsed.fragment or origin.endswith(("?", "#"))
        or origin != f"https://{netloc}" or _HOST.fullmatch(host) is None
        or host.endswith(".") or netloc.split(":", 1)[0] != host
    ):
        raise ControlTransportError("invalid_origin")
    if ":" in netloc:
        if _PORT.fullmatch(netloc.split(":", 1)[1]) is None or port is None or not 1 <= port <= 65535:
            raise ControlTransportError("invalid_origin")
        if port == 443:
            # The canonical spelling of the default port has no explicit port.
            raise ControlTransportError("invalid_origin")
    return origin, host, 443 if port is None else port


def _validate_path(path: object) -> str:
    if type(path) is not str or len(path) > 512 or _PATH.fullmatch(path) is None:
        raise ControlTransportError("invalid_request")
    if any(segment in {".", ".."} for segment in path.split("/")):
        raise ControlTransportError("invalid_request")
    return path


def _validate_headers(headers: object) -> dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, Mapping) or len(headers) > 16:
        raise ControlTransportError("invalid_request")
    result: dict[str, str] = {}
    seen: set[str] = set()
    for name, value in headers.items():
        if (
            type(name) is not str or type(value) is not str
            or _HEADER_NAME.fullmatch(name) is None or _HEADER_VALUE.fullmatch(value) is None
            or name.lower() in _FORBIDDEN_REQUEST_HEADERS or name.lower() in seen
        ):
            raise ControlTransportError("invalid_request")
        seen.add(name.lower())
        result[name] = value
    return result


def _strict_json(raw: bytes) -> dict[str, Any]:
    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value

    try:
        decoded = json.loads(
            raw.decode("utf-8", errors="strict"),
            parse_constant=reject_constant, object_pairs_hook=unique_object,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ControlTransportError("malformed_response") from None
    if not isinstance(decoded, dict):
        raise ControlTransportError("malformed_response")
    return decoded


class HTTPSControlTransport:
    """``post(path, *, headers, body) -> (status, headers, json | None)`` over pinned HTTPS."""

    def __init__(
        self, origin: str, *, ca_bundle: Path | str | None = None,
        timeout_seconds: float = CONTROL_TIMEOUT_SECONDS,
    ):
        self.origin, self._host, self._port = validate_control_origin(origin)
        if (
            isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
            or not 0 < timeout_seconds <= CONTROL_TIMEOUT_SECONDS
        ):
            raise ValueError("runner control timeout must be within the fixed bound")
        self._timeout = float(timeout_seconds)
        self._context = self._tls_context(ca_bundle)
        self.last_status: int | None = None
        self.last_error_code: str | None = None

    @staticmethod
    def _tls_context(ca_bundle: Path | str | None) -> ssl.SSLContext:
        if ca_bundle is None:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        else:
            path = os.fspath(ca_bundle)
            if type(path) is not str or not os.path.isabs(path):
                raise ValueError("explicit CA bundle must be an absolute path")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cafile=path)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def post(self, path: str, *, headers: Mapping[str, str] | None = None, body: bytes = b"") -> tuple[int, dict[str, str], dict[str, Any] | None]:
        path = _validate_path(path)
        request_headers = _validate_headers(headers)
        if type(body) is not bytes or len(body) > MAX_CONTROL_REQUEST_BYTES:
            raise ControlTransportError("invalid_request")
        self.last_status = None
        self.last_error_code = None
        deadline = time.monotonic() + self._timeout
        connection = http.client.HTTPSConnection(
            self._host, self._port, context=self._context, timeout=self._timeout,
        )
        try:
            try:
                connection.putrequest("POST", path, skip_host=True, skip_accept_encoding=True)
                connection.putheader("Host", self._host if self._port == 443 else f"{self._host}:{self._port}")
                connection.putheader("Accept", "application/json")
                connection.putheader("Content-Length", str(len(body)))
                for name, value in request_headers.items():
                    connection.putheader(name, value)
                connection.endheaders(body)
                response = connection.getresponse()
            except ssl.SSLCertVerificationError:
                raise ControlTransportError("tls_trust_failed") from None
            except ssl.SSLError:
                raise ControlTransportError("tls_trust_failed") from None
            except (socket.timeout, TimeoutError):
                raise ControlTransportError("timeout") from None
            except (http.client.HTTPException, OSError):
                raise ControlTransportError("connection_failed") from None
            return self._decode(response, connection, deadline)
        finally:
            connection.close()

    def _decode(
        self, response: http.client.HTTPResponse, connection: http.client.HTTPSConnection,
        deadline: float,
    ) -> tuple[int, dict[str, str], dict[str, Any] | None]:
        status = response.status
        if 300 <= status <= 399:
            # Never follow: a redirect could move signed runner proofs to another origin.
            raise ControlTransportError("redirect_refused")
        if not 200 <= status <= 599 or status == 101:
            raise ControlTransportError("malformed_response")
        selected: dict[str, str] = {}
        content_type: list[str] = []
        length: list[str] = []
        for name, value in response.getheaders():
            lowered = name.lower()
            if lowered == "content-type":
                content_type.append(value)
            elif lowered == "content-length":
                length.append(value)
            elif lowered in _RESPONSE_HEADERS:
                canonical = _RESPONSE_HEADERS[lowered]
                if canonical in selected:
                    raise ControlTransportError("malformed_response")
                selected[canonical] = value
        if len(content_type) > 1 or len(length) > 1:
            raise ControlTransportError("malformed_response")
        if length:
            if re.fullmatch(r"[0-9]{1,12}", length[0]) is None:
                raise ControlTransportError("malformed_response")
            if int(length[0]) > MAX_CONTROL_RESPONSE_BYTES:
                raise ControlTransportError("response_too_large")
            if status == 204 and int(length[0]) != 0:
                # http.client discards a 204 body silently; a framing contradiction is malformed.
                raise ControlTransportError("malformed_response")
        raw = self._read_bounded(response, connection, deadline)
        self.last_status = status
        if status == 204:
            if raw:
                raise ControlTransportError("malformed_response")
            return status, selected, None
        media = content_type[0].split(";", 1)[0].strip().lower() if content_type else ""
        if media != "application/json":
            raise ControlTransportError("malformed_response")
        payload = _strict_json(raw)
        code = payload.get("code")
        if status >= 400 and type(code) is str and re.fullmatch(r"[a-z0-9_]{1,64}", code):
            self.last_error_code = code
        return status, selected, payload

    @staticmethod
    def _read_bounded(
        response: http.client.HTTPResponse, connection: http.client.HTTPSConnection,
        deadline: float,
    ) -> bytes:
        chunks: list[bytes] = []
        total = 0
        try:
            while True:
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    raise ControlTransportError("timeout")
                if connection.sock is not None:
                    # One fixed deadline for the whole call, so a trickling peer cannot extend it.
                    connection.sock.settimeout(remaining_time)
                # read1 returns after at most one socket read, so the deadline is checked per recv.
                chunk = response.read1(min(_READ_CHUNK, MAX_CONTROL_RESPONSE_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_CONTROL_RESPONSE_BYTES:
                    raise ControlTransportError("response_too_large")
        except ControlTransportError:
            raise
        except (socket.timeout, TimeoutError):
            raise ControlTransportError("timeout") from None
        except (http.client.HTTPException, OSError, ValueError):
            raise ControlTransportError("malformed_response") from None
        return b"".join(chunks)


__all__ = [
    "CONTROL_TIMEOUT_SECONDS", "ControlTransportError", "HTTPSControlTransport",
    "MAX_CONTROL_RESPONSE_BYTES", "validate_control_origin",
]
