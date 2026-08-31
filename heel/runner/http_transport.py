"""Purpose-built cancellable HTTPS transport for exact approved canary reads.

This module intentionally does not use a general HTTP client, proxy configuration, or
the commercial control-plane network guard.  DNS, numeric connection selection, TLS,
request construction, response framing, cancellation, and the single retry are all
closed here for the open-core runner.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import inspect
import ipaddress
import json
import math
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .adapters import ADAPTER_REGISTRY, PreparedAction
from .openapi_routes import normalize_route_template
from .redaction import Redactor


HTTPS_PORT = 443
MAX_DNS_ANSWERS = 16
MAX_HEADER_BYTES = 16 * 1024
DEFAULT_BODY_BYTES = 256 * 1024
DEFAULT_TIMEOUT_SECONDS = 5.0
_HOSTNAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-.")
_SPECIAL_SUFFIXES = (
    ".localhost", ".local", ".internal", ".invalid", ".test", ".example", ".onion",
    ".home.arpa", ".corp", ".lan", ".localdomain",
)
_SPECIAL_NAMES = frozenset({
    "localhost", "broadcasthost", "ip6-allnodes", "ip6-allrouters",
    "ip6-localhost", "ip6-loopback",
})
_DENY_CORPUS = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "::ffff:0:0/96",
    "64:ff9b::/96", "100::/64", "2001::/32", "2001:2::/48", "2001:db8::/32",
    "2001:10::/28", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
))
_FAILURE_CODES = frozenset({
    "cancelled", "concurrency_exceeded", "connect_error", "dns_changed", "gate_rejected",
    "evidence_rejected", "invalid_auth", "invalid_origin", "invalid_route", "peer_mismatch",
    "response_rejected", "response_too_large", "timeout", "tls_error", "unsafe_dns",
})
_HEADER_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", flags=re.ASCII)
_COOKIE_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}", flags=re.ASCII)
_EVIDENCE_REFERENCE = re.compile(r"ev1_[0-9a-f]{64}", flags=re.ASCII)
_ROUTE_PLACEHOLDER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]{0,63}\}", flags=re.ASCII)

IANA_TLD_VERSION = "2026082301"
IANA_TLD_SHA256 = "1e296954a3bbe1525756893e68e3b5917604c299a696b2e59390a8a2e99289ef"
IANA_TLD_LINE_COUNT = 1439
_IANA_PAYLOAD_B64 = "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"
_IANA_SOURCE = gzip.decompress(base64.b64decode(_IANA_PAYLOAD_B64))
if hashlib.sha256(_IANA_SOURCE).hexdigest() != IANA_TLD_SHA256:
    raise RuntimeError("runner IANA TLD payload integrity mismatch")
_IANA_LINES = _IANA_SOURCE.decode("ascii").splitlines()
if (
    len(_IANA_LINES) != IANA_TLD_LINE_COUNT
    or not _IANA_LINES[0].startswith("# Version " + IANA_TLD_VERSION)
):
    raise RuntimeError("runner IANA TLD payload version mismatch")
IANA_ROOT_TLDS = frozenset(line.lower() for line in _IANA_LINES[1:])


class TransportFailure(Exception):
    """One closed non-reflective target-transport failure."""

    __slots__ = ("code", "requests_made", "gate_error", "stop_reason")

    def __init__(self, code: str, *, requests_made: int = 0):
        if code not in _FAILURE_CODES:
            raise ValueError("transport failure code is not closed")
        self.code = code
        self.requests_made = requests_made
        self.gate_error: str | None = None
        self.stop_reason = "none"
        super().__init__(code)

    def __repr__(self) -> str:
        return f"TransportFailure(code={self.code!r}, requests_made={self.requests_made})"


def normalize_target_origin(origin: str) -> str:
    """Accept exactly an ASCII public-root ``https://host`` origin."""
    if not isinstance(origin, str) or not origin:
        raise TransportFailure("invalid_origin")
    if any(ord(char) > 127 or char.isspace() or ord(char) < 0x20 for char in origin):
        raise TransportFailure("invalid_origin")
    if not origin.startswith("https://") or "//" not in origin or "%" in origin or "\\" in origin:
        raise TransportFailure("invalid_origin")
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query or parsed.fragment:
        raise TransportFailure("invalid_origin")
    if parsed.username is not None or parsed.password is not None or ":" in parsed.netloc:
        raise TransportFailure("invalid_origin")
    try:
        if parsed.port is not None:
            raise TransportFailure("invalid_origin")
    except ValueError:
        raise TransportFailure("invalid_origin") from None
    hostname = parsed.hostname
    if hostname is None:
        raise TransportFailure("invalid_origin")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise TransportFailure("invalid_origin")
    host = hostname.lower()
    labels = host.split(".")
    if (
        host.endswith(".")
        or len(host) > 253
        or len(labels) < 2
        or not set(host).issubset(_HOSTNAME_CHARS)
        or any(not label or len(label) > 63 for label in labels)
        or any(label[0] == "-" or label[-1] == "-" for label in labels)
        or host in _SPECIAL_NAMES
        or host.endswith(_SPECIAL_SUFFIXES)
        or host.startswith("xn--")
        or ".xn--" in host
        or labels[-1] == "arpa"
        or labels[-1] not in IANA_ROOT_TLDS
    ):
        raise TransportFailure("invalid_origin")
    return "https://" + host


def _as_ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return value
    if not isinstance(value, (str, bytes, bytearray)):
        raise TransportFailure("unsafe_dns")
    try:
        text = bytes(value).decode("ascii") if isinstance(value, (bytes, bytearray)) else value
        return ipaddress.ip_address(text)
    except (UnicodeDecodeError, ValueError):
        raise TransportFailure("unsafe_dns") from None


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not (
        not address.is_global
        or (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None)
        or any(address in network for network in _DENY_CORPUS)
    )


def select_public_addresses(
    addresses: Iterable[Any],
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    try:
        parsed = [_as_ip(value) for value in addresses]
    except TypeError:
        raise TransportFailure("unsafe_dns") from None
    if not parsed or len(parsed) > MAX_DNS_ANSWERS or any(not _is_public(value) for value in parsed):
        raise TransportFailure("unsafe_dns")
    deduped = {(address.version, address.packed): address for address in parsed}
    return tuple(deduped[key] for key in sorted(deduped))


class BoundedResolver:
    """Resolve a full absolute A+AAAA address set within the caller's deadline."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic):
        self.clock = clock

    def __call__(self, hostname: str, *, deadline: float) -> list[str]:
        remaining = deadline - self.clock()
        if remaining <= 0:
            raise TransportFailure("timeout")
        completed = threading.Event()
        result: list[Any] = []
        failure: list[BaseException] = []

        def resolve() -> None:
            try:
                result.extend(socket.getaddrinfo(
                    hostname.rstrip(".") + ".", HTTPS_PORT,
                    family=socket.AF_UNSPEC, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
                ))
            except BaseException as exc:
                failure.append(exc)
            finally:
                completed.set()

        threading.Thread(target=resolve, daemon=True, name="heel-bounded-dns").start()
        if not completed.wait(remaining):
            raise TransportFailure("timeout")
        if failure:
            raise TransportFailure("unsafe_dns")
        answers = [item[4][0] for item in result]
        select_public_addresses(answers)
        return answers


class SocketTransport:
    def connect(
        self, address: tuple[str, int], timeout: float, cancellation: CancellationToken,
    ) -> socket.socket:
        family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        raw = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        raw.settimeout(timeout)
        cancellation.register(raw)
        try:
            raw.connect(address)
            return raw
        except BaseException:
            cancellation.unregister(raw)
            try:
                raw.close()
            except OSError:
                pass
            raise


class TLSTransport:
    def __init__(self) -> None:
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.check_hostname = True
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def wrap(self, raw_socket: Any, hostname: str, timeout: float) -> Any:
        raw_socket.settimeout(timeout)
        wrapped = self.context.wrap_socket(raw_socket, server_hostname=hostname)
        wrapped.settimeout(timeout)
        return wrapped


class CancellationToken:
    """Thread-safe stop token that actively tears down every registered socket."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cancelled = False
        self._sockets: set[Any] = set()

    @property
    def cancelled(self) -> bool:
        with self._lock:
            return self._cancelled

    @staticmethod
    def _close(value: Any) -> None:
        try:
            value.shutdown(socket.SHUT_RDWR)
        except (AttributeError, OSError):
            pass
        try:
            value.close()
        except (AttributeError, OSError):
            pass

    def register(self, value: Any) -> None:
        with self._lock:
            if self._cancelled:
                close_now = True
            else:
                self._sockets.add(value)
                close_now = False
        if close_now:
            self._close(value)
            raise TransportFailure("cancelled")

    def unregister(self, value: Any) -> None:
        with self._lock:
            self._sockets.discard(value)

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True
            registered = tuple(self._sockets)
            self._sockets.clear()
        for value in registered:
            self._close(value)

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise TransportFailure("cancelled")


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    maximum_retries: int
    retryable_failure_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        codes_are_closed = (
            type(self.retryable_failure_codes) is tuple
            and len(self.retryable_failure_codes) <= 2
            and all(
                type(code) is str and code in {"connect_error", "timeout"}
                for code in self.retryable_failure_codes
            )
        )
        if (
            isinstance(self.maximum_retries, bool)
            or not isinstance(self.maximum_retries, int)
            or not 0 <= self.maximum_retries <= 1
            or not codes_are_closed
            or (
                codes_are_closed
                and tuple(sorted(set(self.retryable_failure_codes)))
                != self.retryable_failure_codes
            )
        ):
            raise ValueError("retry policy is not the closed grant policy")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RetryPolicy:
        if not isinstance(value, Mapping) or set(value) != {
            "maximum_retries", "retryable_failure_codes",
        }:
            raise ValueError("retry policy is not the closed grant policy")
        codes = value["retryable_failure_codes"]
        if not isinstance(codes, list):
            raise ValueError("retry policy codes must come from the validated grant")
        return cls(value["maximum_retries"], tuple(codes))


@dataclass(frozen=True, slots=True)
class AttemptPermit:
    deadline: float

    def __post_init__(self) -> None:
        if (
            isinstance(self.deadline, bool)
            or not isinstance(self.deadline, (int, float))
            or not math.isfinite(self.deadline)
            or self.deadline <= 0
        ):
            raise ValueError("attempt permit deadline is invalid")
        object.__setattr__(self, "deadline", float(self.deadline))


@dataclass(frozen=True, slots=True)
class EvidenceContext:
    action_ordinal: int
    route_template: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.action_ordinal, bool)
            or not isinstance(self.action_ordinal, int)
            or self.action_ordinal < 0
        ):
            raise ValueError("evidence action ordinal is invalid")
        normalized, _ = normalize_route_template(self.route_template)
        if normalized != self.route_template:
            raise ValueError("evidence route template is not canonical")


@dataclass(frozen=True, slots=True)
class BoundedResponseEvidence:
    action_ordinal: int
    scenario_id: str
    semantic_auth_role: str
    method: str
    route_template: str
    attempt: int
    status_code: int
    raw_headers: bytes
    raw_body: bytes

    def __post_init__(self) -> None:
        if (
            isinstance(self.action_ordinal, bool)
            or not isinstance(self.action_ordinal, int)
            or self.action_ordinal < 0
            or isinstance(self.attempt, bool)
            or not isinstance(self.attempt, int)
            or self.attempt < 1
            or isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)
            or not 100 <= self.status_code <= 599
            or self.method not in {"GET", "HEAD"}
            or type(self.scenario_id) is not str
            or type(self.semantic_auth_role) is not str
            or type(self.raw_headers) is not bytes
            or type(self.raw_body) is not bytes
            or len(self.raw_headers) > MAX_HEADER_BYTES
            or len(self.raw_body) > DEFAULT_BODY_BYTES
        ):
            raise ValueError("bounded response evidence is invalid")
        normalized, _ = normalize_route_template(self.route_template)
        if normalized != self.route_template:
            raise ValueError("bounded response evidence route is invalid")


@dataclass(frozen=True, slots=True)
class TargetResponse:
    status_code: int
    body_shape: str
    response_bytes: int
    requests_made: int
    evidence_ref: str = "ev1_" + "0" * 64
    redaction_count: int = 0

    def __post_init__(self) -> None:
        if (
            isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)
            or not 100 <= self.status_code <= 599
            or self.body_shape not in {"absent", "json_object"}
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in (self.response_bytes, self.requests_made, self.redaction_count)
            )
            or self.response_bytes > DEFAULT_BODY_BYTES
            or not 1 <= self.requests_made <= 2
            or self.redaction_count > 1024
            or type(self.evidence_ref) is not str
            or len(self.evidence_ref) != 68
            or _EVIDENCE_REFERENCE.fullmatch(self.evidence_ref) is None
        ):
            raise ValueError("target response is invalid")


def _remaining(clock: Callable[[], float], deadline: float) -> float:
    remaining = deadline - clock()
    if remaining <= 0:
        raise TransportFailure("timeout")
    return remaining


def _bounded_call(
    callback: Callable[[], Any],
    *,
    clock: Callable[[], float],
    deadline: float,
    cancellation: CancellationToken,
) -> Any:
    completed = threading.Event()
    result: list[Any] = []
    failure: list[BaseException] = []

    def invoke() -> None:
        try:
            result.append(callback())
        except BaseException as exc:
            failure.append(exc)
        finally:
            completed.set()

    threading.Thread(target=invoke, daemon=True, name="heel-bounded-callback").start()
    while not completed.is_set():
        cancellation.raise_if_cancelled()
        completed.wait(min(0.01, _remaining(clock, deadline)))
    cancellation.raise_if_cancelled()
    _remaining(clock, deadline)
    if failure:
        raise failure[0]
    return result[0]


def _valid_route(action: PreparedAction) -> str:
    if not isinstance(action, PreparedAction) or action.method not in {"GET", "HEAD"}:
        raise TransportFailure("invalid_route")
    adapter = ADAPTER_REGISTRY.get(action.scenario_id)
    if (
        adapter is None
        or action.adapter_version != adapter["adapter_version"]
        or action.method not in adapter["allowed_methods"]
        or action.semantic_auth_role not in adapter["semantic_roles"]
        or action.side_effect_class != "read_only"
        or (
            action.semantic_auth_role == "anonymous"
            and action.auth_profile != "anonymous"
        )
        or (
            action.semantic_auth_role != "anonymous"
            and action.auth_profile not in {"bearer", "cookie_jar", "x_api_key"}
        )
        or type(action.route) is not str
    ):
        raise TransportFailure("invalid_route")
    route = action.route
    try:
        encoded = route.encode("ascii")
    except UnicodeError:
        raise TransportFailure("invalid_route") from None
    segments = route.split("/")[1:] if route.startswith("/") else []
    if (
        not encoded
        or len(encoded) > 2048
        or not route.startswith("/")
        or route.startswith("//")
        or any(character in route for character in ("%", "\\", "?", "#", "{", "}"))
        or "//" in route
        or any(segment in {".", ".."} for segment in segments)
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in route)
    ):
        raise TransportFailure("invalid_route")
    return route


def _matches_evidence_template(route: str, template: str) -> bool:
    pattern = re.escape(template)
    pattern = _ROUTE_PLACEHOLDER.sub("[^/]+", pattern.replace("\\{", "{").replace("\\}", "}"))
    return re.fullmatch(pattern, route) is not None


def _credential_header(profile: str, credential: object) -> bytes:
    if profile == "anonymous":
        if credential is not None:
            raise TransportFailure("invalid_auth")
        return b""
    if profile in {"bearer", "x_api_key"}:
        if type(credential) is not str:
            raise TransportFailure("invalid_auth")
        try:
            encoded = credential.encode("ascii")
        except UnicodeError:
            raise TransportFailure("invalid_auth") from None
        if not encoded or len(encoded) > 16 * 1024 or any(byte < 0x21 or byte > 0x7E for byte in encoded):
            raise TransportFailure("invalid_auth")
        prefix = b"Authorization: Bearer " if profile == "bearer" else b"X-API-Key: "
        return prefix + encoded + b"\r\n"
    if profile == "cookie_jar":
        if type(credential) is not dict or not credential or len(credential) > 32:
            raise TransportFailure("invalid_auth")
        pairs: list[str] = []
        if any(type(name) is not str for name in credential):
            raise TransportFailure("invalid_auth")
        for name in sorted(credential):
            value = credential[name]
            if type(name) is not str or _COOKIE_NAME.fullmatch(name) is None or type(value) is not str:
                raise TransportFailure("invalid_auth")
            try:
                encoded_value = value.encode("ascii")
            except UnicodeError:
                raise TransportFailure("invalid_auth") from None
            if (
                not encoded_value
                or len(encoded_value) > 4096
                or any(byte < 0x21 or byte > 0x7E or chr(byte) in ';, "\\' for byte in encoded_value)
            ):
                raise TransportFailure("invalid_auth")
            pairs.append(name + "=" + value)
        encoded = ("Cookie: " + "; ".join(pairs) + "\r\n").encode("ascii")
        if len(encoded) > 16 * 1024 + len(b"Cookie: \r\n"):
            raise TransportFailure("invalid_auth")
        return encoded
    raise TransportFailure("invalid_auth")


def _parse_headers(raw: bytes, *, method: str, maximum_response_bytes: int) -> tuple[int, int]:
    try:
        lines = raw.decode("latin-1").split("\r\n")
    except UnicodeError:
        raise TransportFailure("response_rejected") from None
    if not lines or re.fullmatch(r"HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?", lines[0]) is None:
        raise TransportFailure("response_rejected")
    status = int(lines[0].split(" ", 2)[1])
    if 300 <= status <= 399:
        raise TransportFailure("response_rejected")
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line or line[0].isspace():
            raise TransportFailure("response_rejected")
        name, value = line.split(":", 1)
        if _HEADER_NAME.fullmatch(name) is None:
            raise TransportFailure("response_rejected")
        if value.startswith(" "):
            value = value[1:]
        if (
            value != value.strip(" \t")
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise TransportFailure("response_rejected")
        key = name.lower()
        if key in fields:
            raise TransportFailure("response_rejected")
        fields[key] = value
    if "transfer-encoding" in fields or "content-encoding" in fields:
        raise TransportFailure("response_rejected")
    content_length = fields.get("content-length")
    if content_length is None and method == "HEAD":
        return status, 0
    if (
        content_length is None
        or len(content_length) > 20
        or not content_length.isascii()
        or not content_length.isdecimal()
    ):
        raise TransportFailure("response_rejected")
    length = int(content_length)
    if length > maximum_response_bytes:
        raise TransportFailure("response_too_large")
    return status, length


def _body_shape(body: bytes, *, method: str) -> str:
    if not body:
        return "absent"
    if method == "HEAD":
        raise TransportFailure("response_rejected")

    def reject_duplicate(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    try:
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=reject_duplicate,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite")),
        )
    except (UnicodeError, ValueError, RecursionError):
        raise TransportFailure("response_rejected") from None
    if not isinstance(value, dict):
        raise TransportFailure("response_rejected")
    return "json_object"


class TargetHTTPSClient:
    """A one-concurrency, exact-host, direct-socket target client."""

    def __init__(
        self,
        *,
        origin: str,
        preflight_addresses: Sequence[Any],
        resolver: Callable[..., Sequence[Any]] | None = None,
        sockets: Any = None,
        tls: Any = None,
        clock: Callable[[], float] = time.monotonic,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        maximum_response_bytes: int = DEFAULT_BODY_BYTES,
    ):
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
            or timeout_seconds > DEFAULT_TIMEOUT_SECONDS
        ):
            raise ValueError("target timeout must be in (0, 5]")
        if (
            isinstance(maximum_response_bytes, bool)
            or not isinstance(maximum_response_bytes, int)
            or maximum_response_bytes <= 0
            or maximum_response_bytes > DEFAULT_BODY_BYTES
        ):
            raise ValueError("target response bound is invalid")
        normalized = normalize_target_origin(origin)
        self.origin = normalized
        self.hostname = normalized[len("https://"):]
        self.preflight_addresses = select_public_addresses(preflight_addresses)
        self.resolver = resolver or BoundedResolver(clock=clock)
        try:
            inspect.signature(self.resolver).bind(self.hostname, deadline=0.0)
        except (TypeError, ValueError):
            raise ValueError("resolver must accept one absolute deadline") from None
        self.sockets = sockets or SocketTransport()
        try:
            inspect.signature(self.sockets.connect).bind(
                ("93.184.216.34", HTTPS_PORT), 1.0, CancellationToken(),
            )
        except (TypeError, ValueError):
            raise ValueError("socket transport must accept cancellation") from None
        self.tls = tls or TLSTransport()
        self.clock = clock
        self._timeout_seconds = float(timeout_seconds)
        self._maximum_response_bytes = maximum_response_bytes
        self._request_lock = threading.Lock()

    @property
    def timeout_seconds(self) -> float:
        return self._timeout_seconds

    @property
    def maximum_response_bytes(self) -> int:
        return self._maximum_response_bytes

    def _gate_and_resolve(
        self, deadline: float, cancellation: CancellationToken,
    ) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        cancellation.raise_if_cancelled()
        _remaining(self.clock, deadline)
        try:
            answer = _bounded_call(
                lambda: self.resolver(self.hostname, deadline=deadline),
                clock=self.clock,
                deadline=deadline,
                cancellation=cancellation,
            )
        except TransportFailure:
            raise
        except (TimeoutError, socket.timeout):
            raise TransportFailure("timeout") from None
        except BaseException:
            raise TransportFailure("unsafe_dns") from None
        current = select_public_addresses(answer)
        if current != self.preflight_addresses:
            raise TransportFailure("dns_changed")
        return current[0]

    def _one_attempt(
        self,
        action: PreparedAction,
        request_bytes: bytes,
        deadline: float,
        cancellation: CancellationToken,
        *,
        attempt: int,
        evidence_context: EvidenceContext,
        evidence_sink: Callable[[BoundedResponseEvidence], str],
        redactor: Redactor,
    ) -> TargetResponse:
        selected = self._gate_and_resolve(deadline, cancellation)
        raw_socket = tls_socket = None
        try:
            try:
                raw_socket = self.sockets.connect(
                    (selected.compressed, HTTPS_PORT),
                    _remaining(self.clock, deadline),
                    cancellation,
                )
            except (socket.timeout, TimeoutError):
                raise TransportFailure("timeout") from None
            except OSError:
                if cancellation.cancelled:
                    raise TransportFailure("cancelled") from None
                raise TransportFailure("connect_error") from None
            cancellation.register(raw_socket)
            try:
                tls_socket = self.tls.wrap(
                    raw_socket, self.hostname, _remaining(self.clock, deadline),
                )
            except (socket.timeout, TimeoutError):
                raise TransportFailure("timeout") from None
            except (ssl.SSLError, OSError):
                if cancellation.cancelled:
                    raise TransportFailure("cancelled") from None
                raise TransportFailure("tls_error") from None
            cancellation.unregister(raw_socket)
            raw_socket = None
            cancellation.register(tls_socket)
            try:
                if _as_ip(tls_socket.getpeername()[0]) != selected:
                    raise TransportFailure("peer_mismatch")
            except (OSError, TypeError):
                if cancellation.cancelled:
                    raise TransportFailure("cancelled") from None
                raise TransportFailure("peer_mismatch") from None
            tls_socket.settimeout(_remaining(self.clock, deadline))
            try:
                tls_socket.sendall(request_bytes)
            except (socket.timeout, TimeoutError):
                raise TransportFailure("timeout") from None
            except OSError:
                if cancellation.cancelled:
                    raise TransportFailure("cancelled") from None
                raise TransportFailure("connect_error") from None
            response = bytearray()
            header_end = -1
            while header_end < 0:
                cancellation.raise_if_cancelled()
                if len(response) > MAX_HEADER_BYTES:
                    raise TransportFailure("response_rejected")
                tls_socket.settimeout(_remaining(self.clock, deadline))
                try:
                    chunk = tls_socket.recv(min(4096, MAX_HEADER_BYTES + 4 - len(response)))
                except (socket.timeout, TimeoutError):
                    raise TransportFailure("timeout") from None
                except OSError:
                    if cancellation.cancelled:
                        raise TransportFailure("cancelled") from None
                    raise TransportFailure("connect_error") from None
                if not chunk:
                    raise TransportFailure("response_rejected")
                response.extend(chunk)
                header_end = response.find(b"\r\n\r\n")
            if header_end > MAX_HEADER_BYTES:
                raise TransportFailure("response_rejected")
            status, content_length = _parse_headers(
                bytes(response[:header_end]),
                method=action.method,
                maximum_response_bytes=self.maximum_response_bytes,
            )
            expected_body_length = 0 if action.method == "HEAD" else content_length
            body = bytearray(response[header_end + 4:])
            if len(body) > expected_body_length:
                raise TransportFailure("response_rejected")
            while len(body) < expected_body_length:
                cancellation.raise_if_cancelled()
                tls_socket.settimeout(_remaining(self.clock, deadline))
                try:
                    chunk = tls_socket.recv(min(4096, expected_body_length - len(body)))
                except (socket.timeout, TimeoutError):
                    raise TransportFailure("timeout") from None
                except OSError:
                    if cancellation.cancelled:
                        raise TransportFailure("cancelled") from None
                    raise TransportFailure("connect_error") from None
                if not chunk:
                    raise TransportFailure("response_rejected")
                body.extend(chunk)
            tls_socket.settimeout(_remaining(self.clock, deadline))
            try:
                trailing = tls_socket.recv(1)
            except (socket.timeout, TimeoutError):
                raise TransportFailure("timeout") from None
            except OSError:
                if cancellation.cancelled:
                    raise TransportFailure("cancelled") from None
                raise TransportFailure("connect_error") from None
            if trailing:
                raise TransportFailure("response_rejected")
            raw_headers = bytes(response[:header_end])
            raw_body = bytes(body)
            try:
                redaction_count = redactor.count_bytes(raw_headers, raw_body)
                evidence = BoundedResponseEvidence(
                    action_ordinal=evidence_context.action_ordinal,
                    scenario_id=action.scenario_id,
                    semantic_auth_role=action.semantic_auth_role,
                    method=action.method,
                    route_template=evidence_context.route_template,
                    attempt=attempt,
                    status_code=status,
                    raw_headers=raw_headers,
                    raw_body=raw_body,
                )
                evidence_ref = _bounded_call(
                    lambda: evidence_sink(evidence),
                    clock=self.clock,
                    deadline=deadline,
                    cancellation=cancellation,
                )
            except TransportFailure as exc:
                if exc.code == "cancelled":
                    raise
                raise TransportFailure("evidence_rejected") from None
            except BaseException:
                raise TransportFailure("evidence_rejected") from None
            if (
                type(evidence_ref) is not str
                or len(evidence_ref) != 68
                or _EVIDENCE_REFERENCE.fullmatch(evidence_ref) is None
            ):
                raise TransportFailure("evidence_rejected")
            shape = _body_shape(raw_body, method=action.method)
            return TargetResponse(
                status, shape, len(raw_body), 1, evidence_ref, redaction_count,
            )
        finally:
            for closable in (tls_socket, raw_socket):
                if closable is not None:
                    cancellation.unregister(closable)
                    try:
                        closable.close()
                    except (AttributeError, OSError):
                        pass

    def request(
        self,
        action: PreparedAction,
        *,
        credential: object,
        cancellation: CancellationToken,
        retry_policy: RetryPolicy,
        remaining_requests: int,
        before_attempt: Callable[[int, str | None], AttemptPermit],
        evidence_context: EvidenceContext,
        evidence_sink: Callable[[BoundedResponseEvidence], str],
        redactor: Redactor,
    ) -> TargetResponse:
        route = _valid_route(action)
        if (
            not isinstance(cancellation, CancellationToken)
            or not isinstance(retry_policy, RetryPolicy)
            or isinstance(remaining_requests, bool)
            or not isinstance(remaining_requests, int)
            or not 0 <= remaining_requests <= 20
            or not callable(before_attempt)
            or not isinstance(evidence_context, EvidenceContext)
            or not callable(evidence_sink)
            or not isinstance(redactor, Redactor)
            or not _matches_evidence_template(route, evidence_context.route_template)
        ):
            raise TransportFailure("gate_rejected")
        if remaining_requests == 0:
            raise TransportFailure("gate_rejected")
        auth = _credential_header(action.auth_profile, credential)
        request_bytes = (
            f"{action.method} {route} HTTP/1.1\r\n"
            f"Host: {self.hostname}\r\n"
            "Accept: application/json\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n"
        ).encode("ascii") + auth + b"\r\n"
        cancellation.raise_if_cancelled()
        if not self._request_lock.acquire(blocking=False):
            raise TransportFailure("concurrency_exceeded")
        request_deadline = self.clock() + self.timeout_seconds
        attempts = 0
        previous_failure_code: str | None = None
        try:
            while True:
                next_attempt = attempts + 1
                try:
                    permit = _bounded_call(
                        lambda: before_attempt(next_attempt, previous_failure_code),
                        clock=self.clock,
                        deadline=request_deadline,
                        cancellation=cancellation,
                    )
                except TransportFailure as exc:
                    exc.requests_made = attempts
                    raise
                except BaseException:
                    raise TransportFailure("gate_rejected", requests_made=attempts) from None
                if not isinstance(permit, AttemptPermit) or permit.deadline <= self.clock():
                    raise TransportFailure("gate_rejected", requests_made=attempts)
                attempts = next_attempt
                attempt_deadline = min(request_deadline, permit.deadline)
                try:
                    result = self._one_attempt(
                        action,
                        request_bytes,
                        attempt_deadline,
                        cancellation,
                        attempt=attempts,
                        evidence_context=evidence_context,
                        evidence_sink=evidence_sink,
                        redactor=redactor,
                    )
                    return TargetResponse(
                        result.status_code,
                        result.body_shape,
                        result.response_bytes,
                        attempts,
                        result.evidence_ref,
                        result.redaction_count,
                    )
                except TransportFailure as exc:
                    retryable = (
                        exc.code in {"connect_error", "timeout"}
                        and exc.code in retry_policy.retryable_failure_codes
                    )
                    if (
                        retryable
                        and not cancellation.cancelled
                        and self.clock() < request_deadline
                        and attempts - 1 < retry_policy.maximum_retries
                        and attempts < remaining_requests
                    ):
                        previous_failure_code = exc.code
                        continue
                    exc.requests_made = attempts
                    raise
        finally:
            self._request_lock.release()


__all__ = [
    "AttemptPermit", "BoundedResolver", "BoundedResponseEvidence", "CancellationToken",
    "EvidenceContext", "IANA_ROOT_TLDS", "RetryPolicy", "SocketTransport", "TLSTransport",
    "TargetHTTPSClient", "TargetResponse", "TransportFailure", "normalize_target_origin",
    "select_public_addresses",
]
