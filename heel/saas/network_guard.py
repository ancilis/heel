"""Fail-closed ownership proof for exact public HTTPS origins.

This is deliberately a tiny client rather than a general HTTP implementation. It resolves a
host once, rejects an entire mixed-safe DNS answer, connects only to the selected numeric address,
and keeps the original hostname solely for SNI and certificate verification.
"""
from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .iana_root_tlds import IANA_ROOT_TLDS


CHALLENGE_PATH = "/.well-known/heel-verify.txt"
HTTPS_PORT = 443
MAX_CHALLENGE_BODY_BYTES = 4096
MAX_CHALLENGE_HEADER_BYTES = 16384
MAX_DNS_ANSWERS = 16
_HOSTNAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-.")
_SPECIAL_SUFFIXES = (
    ".localhost", ".local", ".internal", ".invalid", ".test", ".example", ".onion",
    ".home.arpa", ".corp", ".lan", ".localdomain",
)
_SPECIAL_NAMES = frozenset({"localhost", "broadcasthost", "ip6-allnodes", "ip6-allrouters", "ip6-localhost", "ip6-loopback"})

# Frozen special-use corpus. ``is_global`` remains defence in depth, never the only decision.
_DENY_CORPUS = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001::/32",
    "2001:2::/48", "2001:db8::/32", "2001:10::/28", "2002::/16", "fc00::/7",
    "fe80::/10", "ff00::/8",
))


class NetworkGuardError(Exception):
    """Base class for deliberate network guard rejections."""


class OriginValidationError(NetworkGuardError):
    pass


class AddressSetValidationError(NetworkGuardError):
    pass


class DNSResolutionTimeout(AddressSetValidationError):
    pass


class VerificationError(NetworkGuardError):
    pass


class VerificationTimeout(VerificationError):
    pass


class PeerMismatch(VerificationError):
    pass


def normalize_verified_origin(origin: str) -> str:
    """Accept only already-canonical ``https://host`` input."""
    if not isinstance(origin, str) or not origin:
        raise OriginValidationError("origin must be a nonempty string")
    if any(ord(char) > 127 or char.isspace() or ord(char) < 0x20 for char in origin):
        raise OriginValidationError("origin must be ASCII without whitespace")
    if not origin.startswith("https://") or "://" not in origin or "%" in origin:
        raise OriginValidationError("origin must start with lowercase https://")
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or parsed.netloc == "" or parsed.path or parsed.query or parsed.fragment:
        raise OriginValidationError("origin must be exactly https://host")
    if parsed.username is not None or parsed.password is not None or ":" in parsed.netloc:
        raise OriginValidationError("credentials are forbidden")
    try:
        if parsed.port is not None:
            raise OriginValidationError("explicit ports are forbidden")
    except ValueError as exc:
        raise OriginValidationError("invalid authority") from exc
    hostname = parsed.hostname
    if hostname is None:
        raise OriginValidationError("hostname is required")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise OriginValidationError("literal IPs are forbidden")
    host = hostname.lower()
    labels = host.split(".")
    if (host.endswith(".") or len(host) > 253 or any(not label or len(label) > 63 for label in labels)
            or len(labels) < 2 or not set(host).issubset(_HOSTNAME_CHARS)):
        raise OriginValidationError("hostname is not an exact DNS name")
    if any(label[0] == "-" or label[-1] == "-" for label in labels):
        raise OriginValidationError("hostname has invalid label hyphenation")
    if host in _SPECIAL_NAMES or host.endswith(_SPECIAL_SUFFIXES) or host.startswith("xn--") or ".xn--" in host:
        raise OriginValidationError("special or IDNA hostname is forbidden")
    if labels[-1] == "arpa" or labels[-1] not in IANA_ROOT_TLDS:
        raise OriginValidationError("hostname is not under a public root-zone TLD")
    return f"https://{host}"


def _as_ip(value: Any) -> ipaddress._BaseAddress:
    if isinstance(value, ipaddress._BaseAddress):
        return value
    if not isinstance(value, (str, bytes, bytearray)):
        raise AddressSetValidationError("resolver address has unsupported type")
    try:
        text = bytes(value).decode("ascii") if isinstance(value, (bytes, bytearray)) else value
        return ipaddress.ip_address(text)
    except (UnicodeDecodeError, ValueError) as exc:
        raise AddressSetValidationError("resolver returned invalid address") from exc


def is_public_address(address: ipaddress._BaseAddress) -> bool:
    return not (not address.is_global or (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None)
                or any(address in network for network in _DENY_CORPUS))


def select_safe_addresses(addresses: Iterable[Any]) -> list[ipaddress._BaseAddress]:
    parsed = [_as_ip(value) for value in addresses]
    if not parsed:
        raise AddressSetValidationError("DNS answer is empty")
    if len(parsed) > MAX_DNS_ANSWERS:
        raise AddressSetValidationError("DNS answer exceeds configured bound")
    for address in parsed:
        if not is_public_address(address):
            raise AddressSetValidationError(f"unsafe DNS answer contains {address.compressed}")
    deduped = {(address.version, address.packed): address for address in parsed}
    return [deduped[key] for key in sorted(deduped)]


class BoundedDNSResolver:
    """Typed dnspython resolver with explicit answers and time bounds."""
    def __init__(self, *, lifetime: float = 2.0, resolver: Any = None):
        if resolver is None:
            try:
                import dns.resolver  # type: ignore[import-not-found]
            except ImportError as exc:
                raise RuntimeError("verified-environment DNS requires dnspython==2.8.0") from exc
            resolver = dns.resolver.Resolver(configure=True)
        self.resolver = resolver
        self.lifetime = lifetime

    def __call__(self, hostname: str) -> list[str]:
        absolute = hostname.rstrip(".") + "."
        answers: list[str] = []
        for record_type in ("A", "AAAA"):
            try:
                response = self.resolver.resolve(
                    absolute, record_type, lifetime=self.lifetime, search=False, raise_on_no_answer=False,
                )
            except Exception as exc:
                if type(exc).__name__ in {"NXDOMAIN", "NoAnswer"}:
                    continue
                if type(exc).__name__ in {"LifetimeTimeout", "Timeout"}:
                    raise DNSResolutionTimeout("DNS resolution timed out") from exc
                raise AddressSetValidationError("DNS resolution failed") from exc
            answers.extend(str(record) for record in response)
            if len(answers) > MAX_DNS_ANSWERS:
                raise AddressSetValidationError("DNS answer exceeds configured bound")
        # Poison the full A+AAAA answer before a TXT proof can authorize this origin.
        select_safe_addresses(answers)
        return answers

    def txt(self, hostname: str) -> list[str]:
        """Resolve only exact ASCII TXT values at ``_heel.<host>.`` after public-IP validation."""
        host = hostname.rstrip(".")
        self(host)
        name = "_heel." + host + "."
        try:
            response = self.resolver.resolve(
                name, "TXT", lifetime=self.lifetime, search=False, raise_on_no_answer=False,
            )
        except Exception as exc:
            if type(exc).__name__ in {"NXDOMAIN", "NoAnswer"}:
                return []
            if type(exc).__name__ in {"LifetimeTimeout", "Timeout"}:
                raise DNSResolutionTimeout("DNS TXT resolution timed out") from exc
            raise AddressSetValidationError("DNS TXT resolution failed") from exc
        values: list[str] = []
        for record in response:
            fragments = getattr(record, "strings", None)
            if fragments is None:
                text = str(record).strip('"')
            else:
                try:
                    text = b"".join(fragments).decode("ascii")
                except (TypeError, UnicodeDecodeError) as exc:
                    raise AddressSetValidationError("DNS TXT answer is not ASCII") from exc
            if len(text) > 512:
                raise AddressSetValidationError("DNS TXT answer exceeds bound")
            values.append(text)
            if len(values) > MAX_DNS_ANSWERS:
                raise AddressSetValidationError("DNS TXT answer exceeds bound")
        return values


class SocketTransport:
    """Direct sockets only; no URL client or proxy environment is involved."""
    def connect(self, address: tuple[str, int], timeout: float) -> socket.socket:
        return socket.create_connection(address, timeout=timeout)

    def configure(self, connected_socket: socket.socket, timeout: float) -> None:
        connected_socket.settimeout(timeout)


class TLSTransport:
    def __init__(self) -> None:
        self.context = ssl.create_default_context()
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.check_hostname = True
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def wrap(self, connected_socket: Any, hostname: str, timeout: float) -> Any:
        wrapped = self.context.wrap_socket(connected_socket, server_hostname=hostname)
        wrapped.settimeout(timeout)
        return wrapped


@dataclass(frozen=True)
class PinnedHTTPSVerifier:
    """One pinned-address GET of the ownership file, with an absolute monotonic deadline."""
    pin_sha256_hex: str | None = None
    timeout_seconds: float = 5.0
    resolver: Callable[[str], Sequence[Any]] | None = None
    sockets: SocketTransport | None = None
    tls: TLSTransport | None = None
    clock: Callable[[], float] = time.monotonic

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0 or self.timeout_seconds > 5:
            raise ValueError("timeout must be in (0, 5]")
        if self.pin_sha256_hex is not None:
            try:
                digest = bytes.fromhex(self.pin_sha256_hex)
            except ValueError as exc:
                raise ValueError("certificate pin must be hexadecimal") from exc
            if len(digest) != 32:
                raise ValueError("certificate pin must contain 32 SHA-256 bytes")

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - self.clock()
        if remaining <= 0:
            raise VerificationTimeout("verification deadline expired")
        return remaining

    def resolve(self, hostname: str) -> ipaddress._BaseAddress:
        try:
            answer = (self.resolver or BoundedDNSResolver())(hostname)
            return select_safe_addresses(answer)[0]
        except NetworkGuardError:
            raise
        except Exception as exc:
            raise AddressSetValidationError("DNS resolution failed") from exc

    @staticmethod
    def _parse_headers(raw: bytes) -> int:
        lines = raw.decode("latin-1").split("\r\n")
        if not lines or lines[0] not in {"HTTP/1.0 200 OK", "HTTP/1.1 200 OK"}:
            raise VerificationError("response must have HTTP/1 status 200")
        fields: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line or line[0].isspace():
                raise VerificationError("malformed response header")
            name, value = line.split(":", 1)
            key = name.lower()
            if key in fields:
                raise VerificationError("ambiguous duplicate response header")
            fields[key] = value.strip()
        if "content-encoding" in fields or fields.get("transfer-encoding", "identity").lower() != "identity":
            raise VerificationError("compressed or transfer-encoded responses are forbidden")
        length = fields.get("content-length")
        if length is None or not length.isascii() or not length.isdecimal():
            raise VerificationError("response requires one decimal content-length")
        body_length = int(length)
        if body_length > MAX_CHALLENGE_BODY_BYTES:
            raise VerificationError("challenge exceeds streaming bound")
        return body_length

    @staticmethod
    def _parse_token(body: bytes) -> str:
        if body.endswith(b"\n"):
            body = body[:-1]
        if not body or b"\n" in body or b"\r" in body:
            raise VerificationError("challenge body is not an exact token")
        try:
            token = body.decode("ascii")
        except UnicodeDecodeError as exc:
            raise VerificationError("challenge token must be ASCII") from exc
        if any(ord(char) < 33 or ord(char) > 126 for char in token):
            raise VerificationError("challenge token is not an exact ASCII token")
        return token

    def verify(self, origin: str) -> str:
        hostname = normalize_verified_origin(origin)[len("https://"):]
        deadline = self.clock() + self.timeout_seconds
        selected = self.resolve(hostname)
        selected_ip = selected.compressed
        raw_socket = tls_socket = None
        try:
            transport = self.sockets or SocketTransport()
            raw_socket = transport.connect((selected_ip, HTTPS_PORT), self._remaining(deadline))
            transport.configure(raw_socket, self._remaining(deadline))
            tls_socket = (self.tls or TLSTransport()).wrap(raw_socket, hostname, self._remaining(deadline))
            raw_socket = None
            if _as_ip(tls_socket.getpeername()[0]) != selected:
                raise PeerMismatch("connected peer differs from selected DNS address")
            if self.pin_sha256_hex is not None:
                certificate = tls_socket.getpeercert(binary_form=True)
                if not certificate or hashlib.sha256(certificate).hexdigest() != self.pin_sha256_hex:
                    raise PeerMismatch("connected peer does not equal pinned certificate")
            request = (f"GET {CHALLENGE_PATH} HTTP/1.1\r\nHost: {hostname}\r\n"
                       "Accept: text/plain\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").encode("ascii")
            tls_socket.settimeout(self._remaining(deadline))
            tls_socket.sendall(request)
            response = bytearray()
            header_end = -1
            while header_end < 0:
                if len(response) > MAX_CHALLENGE_HEADER_BYTES:
                    raise VerificationError("response headers exceed bound")
                tls_socket.settimeout(self._remaining(deadline))
                chunk = tls_socket.recv(min(4096, MAX_CHALLENGE_HEADER_BYTES + 4 - len(response)))
                if not chunk:
                    raise VerificationError("response headers are incomplete")
                response.extend(chunk)
                header_end = response.find(b"\r\n\r\n")
            body_length = self._parse_headers(bytes(response[:header_end]))
            body = bytearray(response[header_end + 4:])
            if len(body) > body_length:
                raise VerificationError("response framing is ambiguous")
            while len(body) < body_length:
                tls_socket.settimeout(self._remaining(deadline))
                chunk = tls_socket.recv(body_length - len(body))
                if not chunk:
                    raise VerificationError("response body is truncated")
                body.extend(chunk)
            tls_socket.settimeout(self._remaining(deadline))
            if tls_socket.recv(1):
                raise VerificationError("response framing is ambiguous")
            return self._parse_token(bytes(body))
        except (socket.timeout, TimeoutError) as exc:
            raise VerificationTimeout("verification deadline expired") from exc
        finally:
            for closable in (tls_socket, raw_socket):
                if closable is not None:
                    try:
                        closable.close()
                    except OSError:
                        pass
