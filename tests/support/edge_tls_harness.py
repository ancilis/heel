"""Test-only loopback TLS edge in front of the real Python control plane.

``EdgeTLSHarness`` plays the public Worker's part for runner pairing tests: it terminates
TLS with an ephemeral CA (``localhost`` only), strips any caller-supplied edge headers,
injects ``X-Heel-Edge-Auth`` / ``X-Heel-Client-Key`` and the same-origin marker exactly as
the Worker does, and forwards to ``serve(ControlPlane(edge_auth_secret=...))``. The control
plane keeps every production guard; the only seam the runner sees is the explicit CA bundle
path handed to ``HTTPSControlTransport``.

``ScriptedTLSServer`` answers every request with a fixed raw response, for transport
failure tests (redirects, malformed or oversized bodies, slow peers).
"""
from __future__ import annotations

import datetime
import hashlib
import http.client
import ipaddress
import json
import secrets
import socket
import ssl
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from heel.saas.http_api import ControlPlane, serve


_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer",
    "upgrade", "host", "content-length",
})
_EDGE_OWNED = frozenset({"x-heel-edge-auth", "x-heel-client-key", "x-heel-internal-origin"})


class EphemeralCA:
    """A throwaway CA plus one leaf for ``localhost`` (and optionally other names)."""

    def __init__(self, directory: Path, *, names: tuple[str, ...] = ("localhost",)):
        directory.mkdir(parents=True, exist_ok=True)
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "heel test edge CA " + secrets.token_hex(4))])
        ca_cert = (
            x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
            .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(hours=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        alt_names: list[x509.GeneralName] = []
        for name in names:
            try:
                alt_names.append(x509.IPAddress(ipaddress.ip_address(name)))
            except ValueError:
                alt_names.append(x509.DNSName(name))
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(ca_name).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        self.ca_path = directory / "edge-ca.pem"
        self.cert_path = directory / "edge-leaf.pem"
        self.key_path = directory / "edge-leaf-key.pem"
        self.ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        self.cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
        self.key_path.write_bytes(leaf_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))

    def server_context(self, *, minimum: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
                       maximum: ssl.TLSVersion | None = None) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = minimum
        if maximum is not None:
            context.maximum_version = maximum
        context.load_cert_chain(self.cert_path, self.key_path)
        return context


class _TLSServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, handler, context: ssl.SSLContext):
        super().__init__(("127.0.0.1", 0), handler)
        self._tls_context = context

    def handle_error(self, request, client_address):
        # Peers in refusal tests close mid-response on purpose; that is not a harness failure.
        return

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(10)
        try:
            return self._tls_context.wrap_socket(sock, server_side=True), address
        except (ssl.SSLError, OSError):
            sock.close()
            raise


def _start(server: ThreadingHTTPServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


class EdgeTLSHarness:
    """Loopback TLS edge → real ``serve(ControlPlane(edge_auth_secret=...))``."""

    def __init__(self, root: Path, **control_plane_options):
        self.root = Path(root)
        self.ca = EphemeralCA(self.root / "edge-tls")
        self.edge_secret = secrets.token_urlsafe(32)
        self.forwarded: list[tuple[str, str]] = []
        harness = self

        class EdgeHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                return

            def _proxy(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                headers = {}
                for name, value in self.headers.items():
                    lowered = name.lower()
                    if lowered in _HOP_BY_HOP or lowered in _EDGE_OWNED:
                        continue
                    headers[name] = value
                headers["X-Heel-Edge-Auth"] = harness.edge_secret
                headers["X-Heel-Client-Key"] = hashlib.sha256(
                    ("edge-client\0" + self.client_address[0]).encode()
                ).hexdigest()
                if self.headers.get("Origin") == harness.origin:
                    headers["X-Heel-Internal-Origin"] = "same-origin"
                harness.forwarded.append((self.command, self.path))
                upstream = http.client.HTTPConnection("127.0.0.1", harness.backend_port, timeout=10)
                try:
                    upstream.request(self.command, self.path, body if self.command != "GET" else None, headers)
                    response = upstream.getresponse()
                    payload = response.read()
                    self.send_response(response.status)
                    for name, value in response.getheaders():
                        if name.lower() not in _HOP_BY_HOP:
                            self.send_header(name, value)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                finally:
                    upstream.close()

            do_GET = do_POST = do_DELETE = _proxy

        self._edge = _TLSServer(EdgeHandler, self.ca.server_context())
        self.port = self._edge.server_address[1]
        self.origin = f"https://localhost:{self.port}"
        options = {
            "device_token_pepper": b"d" * 32, "runner_auth_pepper": b"r" * 32,
            "enable_device_auth": True, "trust_edge_client_key": True,
        }
        options.update(control_plane_options)
        self.control_plane = ControlPlane(
            str(self.root / "control-plane.sqlite3"),
            public_origin=self.origin, edge_auth_secret=self.edge_secret, **options,
        )
        self._backend = serve(self.control_plane)
        self.backend_port = self._backend.server_address[1]
        self._threads = [_start(self._backend), _start(self._edge)]

    # Browser-side helpers: these go through the TLS edge like a real browser session.
    def request(self, method: str, path: str, body: object | None = None, *,
                cookie: str | None = None, origin: str | None = "same") -> tuple[int, object, str | None]:
        context = ssl.create_default_context(cafile=str(self.ca.ca_path))
        connection = http.client.HTTPSConnection("localhost", self.port, context=context, timeout=10)
        headers = {}
        if origin is not None:
            headers["Origin"] = self.origin if origin == "same" else origin
        if cookie is not None:
            headers["Cookie"] = cookie
        payload = None
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        try:
            connection.request(method, path, payload, headers)
            response = connection.getresponse()
            raw = response.read()
            set_cookie = response.getheader("Set-Cookie")
        finally:
            connection.close()
        return response.status, (json.loads(raw) if raw else None), set_cookie

    def signup_owner(self, email: str) -> tuple[str, str]:
        status, body, cookie = self.request(
            "POST", "/v1/signup", {"email": email, "password": "correct-horse-battery"},
        )
        assert status == 201 and cookie, status
        return body["workspace_id"], cookie.split(";", 1)[0]

    def close(self) -> None:
        self._edge.shutdown()
        self._edge.server_close()
        self._backend.shutdown()
        self._backend.server_close()

    def __enter__(self) -> "EdgeTLSHarness":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


class ScriptedTLSServer:
    """Answer every request with ``responder(path) -> raw HTTP response bytes``."""

    def __init__(self, ca: EphemeralCA, responder: Callable[[str], bytes], *,
                 delay_seconds: float = 0.0, context: ssl.SSLContext | None = None):
        self.requests: list[tuple[str, dict[str, str], bytes]] = []
        scripted = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                scripted.requests.append((self.path, dict(self.headers.items()), body))
                raw = responder(self.path)
                if delay_seconds:
                    head, _, rest = raw.partition(b"\r\n\r\n")
                    self.wfile.write(head + b"\r\n\r\n")
                    self.wfile.flush()
                    for byte in rest:
                        threading.Event().wait(delay_seconds)
                        try:
                            self.wfile.write(bytes([byte]))
                            self.wfile.flush()
                        except OSError:
                            return
                else:
                    self.wfile.write(raw)
                self.close_connection = True

        self._server = _TLSServer(Handler, context or ca.server_context())
        self.port = self._server.server_address[1]
        self.origin = f"https://localhost:{self.port}"
        self._thread = _start(self._server)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def raw_json_response(status: int, payload: bytes, *, reason: str = "OK",
                      extra: tuple[tuple[str, str], ...] = (),
                      content_type: str = "application/json") -> bytes:
    lines = [f"HTTP/1.1 {status} {reason}", f"Content-Type: {content_type}",
             f"Content-Length: {len(payload)}", "Connection: close"]
    lines.extend(f"{name}: {value}" for name, value in extra)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + payload


def free_loopback_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def temporary_root(prefix: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix))
