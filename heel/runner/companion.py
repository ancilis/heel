"""Strict loopback-only companion for local canary results and disclosure preview."""
from __future__ import annotations

import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import threading
import time
from collections.abc import Mapping
from typing import Any, Callable

from heel.canary_contracts import (
    canonical_bytes,
    validate_canary_findings,
    validate_operational_run,
)
from heel.crypto import verify_envelope
from heel.runner.containment import LOCAL_EVENT_CODES


_RESULT_SCHEMA = "heel.local-result-view.v1"
_DISCLOSURE_SCHEMA = "heel.local-disclosure-preview.v1"
_RESULT_FIELDS = {
    "schema_version", "operational_projection", "findings_projection", "containment_summary",
}
_SUMMARY_FIELDS = {"event_count", "head_digest", "codes", "redaction_count"}
_DISCLOSURE_FIELDS = {
    "schema_version", "projection", "projection_digest", "projection_bytes",
    "scenario_count", "finding_count",
}
_MAX_BOOTSTRAP_BODY = 512
_BOOTSTRAP_TTL_SECONDS = 60.0
_COOKIE_NAME = "heel_local_session"
_SHELL = b"""<!doctype html><html><head><meta charset=utf-8><title>Heel local result</title></head><body><main id=app>Opening your local Heel result...</main><script>'use strict';const b=location.hash.slice(1),h={'X-Heel-Local-Origin':location.origin};history.replaceState(null,'',location.pathname);fetch('/v1/session',{method:'POST',headers:{...h,'Content-Type':'application/json'},body:JSON.stringify({bootstrap:b})}).then(r=>{if(!r.ok)throw Error('session');return fetch('/v1/result',{headers:h})}).then(r=>r.json()).then(v=>{document.getElementById('app').textContent=JSON.stringify(v)});</script></body></html>"""


def _hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


def _token_from_bytes(value: bytes) -> str:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("companion bootstrap must contain exactly 32 random bytes")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _bounded_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= (1 << 53) - 1:
        raise ValueError(f"invalid {label}")
    return value


def _verify_projection_signature(
    projection: Mapping[str, Any], trusted_runner_keys: Mapping[str, object],
) -> None:
    if not isinstance(trusted_runner_keys, Mapping) or len(trusted_runner_keys) != 1:
        raise ValueError("one bound runner verification key is required")
    unsigned = {
        key: value for key, value in projection.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    try:
        verify_envelope(
            dict(trusted_runner_keys),
            {
                "signing_key_id": projection["signing_key_id"],
                "signature_b64": projection["signature_b64"],
            },
            canonical_bytes(unsigned),
        )
    except (TypeError, ValueError):
        raise ValueError("local projection signature is invalid") from None


def validate_local_result_view(
    value: Any, *, trusted_runner_keys: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _RESULT_FIELDS:
        raise ValueError("invalid local result view")
    if value["schema_version"] != _RESULT_SCHEMA:
        raise ValueError("invalid local result view")
    operational = validate_operational_run(value["operational_projection"])
    findings = validate_canary_findings(value["findings_projection"])
    if trusted_runner_keys is not None:
        _verify_projection_signature(operational, trusted_runner_keys)
        _verify_projection_signature(findings, trusted_runner_keys)
    if (
        operational["run_id"] != findings["run_id"]
        or operational["grant_id"] != findings["grant_id"]
        or operational["manifest_digest"] != findings["manifest_digest"]
        or operational["approval_projection_digest"] != findings["approval_projection_digest"]
        or operational["grant_digest"] != findings["grant_digest"]
    ):
        raise ValueError("local result projections are not bound")
    summary = value["containment_summary"]
    if not isinstance(summary, Mapping) or set(summary) != _SUMMARY_FIELDS:
        raise ValueError("invalid local containment summary")
    _bounded_integer(summary["event_count"], "containment event count")
    _bounded_integer(summary["redaction_count"], "redaction count")
    head = summary["head_digest"]
    if type(head) is not str or len(head) != 64 or any(char not in "0123456789abcdef" for char in head):
        raise ValueError("invalid containment head digest")
    codes = summary["codes"]
    if (
        not isinstance(codes, list)
        or codes != sorted(set(codes))
        or any(code not in LOCAL_EVENT_CODES for code in codes)
    ):
        raise ValueError("invalid local containment summary")
    return {
        "schema_version": _RESULT_SCHEMA,
        "operational_projection": operational,
        "findings_projection": findings,
        "containment_summary": {
            "event_count": summary["event_count"],
            "head_digest": head,
            "codes": list(codes),
            "redaction_count": summary["redaction_count"],
        },
    }


def validate_disclosure_preview(
    value: Any, *, trusted_runner_keys: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _DISCLOSURE_FIELDS:
        raise ValueError("invalid local disclosure preview")
    if value["schema_version"] != _DISCLOSURE_SCHEMA:
        raise ValueError("invalid local disclosure preview")
    projection = validate_canary_findings(value["projection"])
    if trusted_runner_keys is not None:
        _verify_projection_signature(projection, trusted_runner_keys)
    if value["projection_digest"] != projection["projection_digest"]:
        raise ValueError("local disclosure digest mismatch")
    if _bounded_integer(value["projection_bytes"], "projection byte count") != len(canonical_bytes(projection)):
        raise ValueError("local disclosure byte count mismatch")
    scenarios = len(projection["scenario_results"])
    findings = sum(item["finding"] is not None for item in projection["scenario_results"])
    if (
        _bounded_integer(value["scenario_count"], "scenario count") != scenarios
        or _bounded_integer(value["finding_count"], "finding count") != findings
    ):
        raise ValueError("local disclosure count mismatch")
    return {
        "schema_version": _DISCLOSURE_SCHEMA,
        "projection": projection,
        "projection_digest": projection["projection_digest"],
        "projection_bytes": value["projection_bytes"],
        "scenario_count": scenarios,
        "finding_count": findings,
    }


class _LoopbackHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


class CompanionServer:
    """One-result HTTP server whose only bind address is the literal IPv4 loopback."""

    def __init__(
        self,
        local_result: Mapping[str, Any],
        disclosure_preview: Mapping[str, Any],
        *,
        trusted_runner_keys: Mapping[str, object],
        bootstrap_bytes: bytes | None = None,
        session_bytes: Callable[[int], bytes] = secrets.token_bytes,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._result = validate_local_result_view(
            local_result, trusted_runner_keys=trusted_runner_keys,
        )
        self._disclosure = validate_disclosure_preview(
            disclosure_preview, trusted_runner_keys=trusted_runner_keys,
        )
        if self._disclosure["projection"] != self._result["findings_projection"]:
            raise ValueError("disclosure preview is not the local findings projection")
        self._clock = clock
        bootstrap = _token_from_bytes(bootstrap_bytes or secrets.token_bytes(32))
        self._session_source = session_bytes
        self._bootstrap_hash = _hash_token(bootstrap)
        self._session_hash = b"\0" * 32
        self._bootstrap_fragment = bootstrap
        self._bootstrap_issued = float(clock())
        self._bootstrap_used = False
        self._lock = threading.Lock()
        self._server: _LoopbackHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("companion is not running")
        return int(self._server.server_address[1])

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def url(self) -> str:
        return self.origin + "/#" + self._bootstrap_fragment

    def _consume_bootstrap(self, candidate: Any) -> bool:
        if type(candidate) is not str:
            return False
        try:
            candidate_hash = _hash_token(candidate)
        except UnicodeEncodeError:
            return False
        with self._lock:
            if (
                self._bootstrap_used
                or float(self._clock()) - self._bootstrap_issued > _BOOTSTRAP_TTL_SECONDS
                or not hmac.compare_digest(candidate_hash, self._bootstrap_hash)
            ):
                return False
            self._bootstrap_used = True
            self._bootstrap_hash = b"\0" * 32
            return True

    def _valid_session(self, cookie_header: str | None) -> bool:
        if type(cookie_header) is not str or len(cookie_header) > 4096:
            return False
        values = {}
        for part in cookie_header.split(";"):
            if "=" not in part:
                return False
            name, value = (item.strip() for item in part.split("=", 1))
            if name in values:
                return False
            values[name] = value
        token = values.get(_COOKIE_NAME)
        if token is None:
            return False
        try:
            return hmac.compare_digest(_hash_token(token), self._session_hash)
        except UnicodeEncodeError:
            return False

    def start(self) -> None:
        if self._server is not None:
            raise RuntimeError("companion is already running")
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "HeelLocal"
            sys_version = ""

            def log_message(self, format: str, *args: object) -> None:
                del format, args

            def _headers(self, status: int, content_type: str, length: int, *, cookie: str | None = None) -> None:
                self.send_response(status)
                self.send_header("Cache-Control", "no-store")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; "
                    "style-src 'none'; img-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
                    "form-action 'none'",
                )
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(length))
                if cookie is not None:
                    self.send_header("Set-Cookie", cookie)
                self.end_headers()

            def _reject(self, status: int = 404) -> None:
                payload = b'{"error":"request_rejected"}'
                self._headers(status, "application/json", len(payload))
                if self.command != "HEAD":
                    self.wfile.write(payload)

            def _request_ok(self, *, api: bool) -> bool:
                expected_host = f"127.0.0.1:{owner.port}"
                peer = self.client_address[0]
                hosts = self.headers.get_all("Host", [])
                local_origins = self.headers.get_all("X-Heel-Local-Origin", [])
                origins = self.headers.get_all("Origin", [])
                cookies = self.headers.get_all("Cookie", [])
                lengths = self.headers.get_all("Content-Length", [])
                content_types = self.headers.get_all("Content-Type", [])
                transfer_encodings = self.headers.get_all("Transfer-Encoding", [])
                if (
                    peer != "127.0.0.1"
                    or hosts != [expected_host]
                    or len(origins) > 1
                    or len(cookies) > 1
                    or len(lengths) > 1
                    or len(content_types) > 1
                    or transfer_encodings
                ):
                    self._reject(403)
                    return False
                if "?" in self.path or "%" in self.path or "#" in self.path or "\\" in self.path:
                    self._reject(400)
                    return False
                if api:
                    origin = origins[0] if origins else None
                    if (
                        local_origins != [owner.origin]
                        or (origin is not None and origin != owner.origin)
                    ):
                        self._reject(403)
                        return False
                return True

            def do_OPTIONS(self) -> None:
                self._reject(405)

            def do_HEAD(self) -> None:
                self._reject(405)

            def do_GET(self) -> None:
                if not self._request_ok(api=self.path != "/"):
                    return
                if self.headers.get_all("Content-Length", []):
                    self._reject(400)
                    return
                if self.path == "/":
                    self._headers(200, "text/html; charset=utf-8", len(_SHELL))
                    self.wfile.write(_SHELL)
                    return
                if self.path not in {"/v1/result", "/v1/disclosure-preview"}:
                    self._reject(404)
                    return
                if not owner._valid_session(self.headers.get("Cookie")):
                    self._reject(403)
                    return
                value = owner._result if self.path == "/v1/result" else owner._disclosure
                payload = canonical_bytes(value)
                self._headers(200, "application/json", len(payload))
                self.wfile.write(payload)

            def do_POST(self) -> None:
                if not self._request_ok(api=True):
                    return
                if self.path != "/v1/session":
                    self._reject(404)
                    return
                if self.headers.get_all("Content-Type", []) != ["application/json"]:
                    self._reject(400)
                    return
                lengths = self.headers.get_all("Content-Length", [])
                if len(lengths) != 1:
                    self._reject(400)
                    return
                raw_length = lengths[0]
                if raw_length is None or not raw_length.isascii() or not raw_length.isdecimal():
                    self._reject(400)
                    return
                length = int(raw_length)
                if length > _MAX_BOOTSTRAP_BODY:
                    self._reject(413)
                    return
                body = self.rfile.read(length)
                try:
                    value = json.loads(body.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError, RecursionError):
                    self._reject(400)
                    return
                if not isinstance(value, dict) or set(value) != {"bootstrap"} or not owner._consume_bootstrap(value["bootstrap"]):
                    self._reject(403)
                    return
                session_token = None
                # The token itself is never kept in the URL or response body.  Reconstructing it
                # is impossible from the hash, so retain it only in this closure until issuance.
                if not hasattr(owner, "_session_token"):
                    self._reject(500)
                    return
                session_token = owner._session_token
                del owner._session_token
                cookie = f"{_COOKIE_NAME}={session_token}; Path=/; HttpOnly; SameSite=Strict"
                self._headers(204, "application/json", 0, cookie=cookie)

        # Keep the clear session token only until the one allowed bootstrap exchange.
        session_value = _token_from_bytes(self._session_source(32))
        self._session_hash = _hash_token(session_value)
        self._session_token = session_value
        self._server = _LoopbackHTTPServer(("127.0.0.1", 0), Handler)
        if self._server.server_address[0] != "127.0.0.1":
            self._server.server_close()
            self._server = None
            raise RuntimeError("companion did not bind literal loopback")
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="heel-local-companion",
        )
        self._thread.start()

    def close(self) -> None:
        server, thread = self._server, self._thread
        self._server = None
        self._thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(2)


__all__ = [
    "CompanionServer", "validate_disclosure_preview", "validate_local_result_view",
]
