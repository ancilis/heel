"""Test-only loopback TLS edge in front of the real Python control plane.

``EdgeTLSHarness`` plays the public Worker's part for runner pairing tests: it terminates
TLS with an ephemeral CA (``localhost`` only) and mirrors the Worker's control-plane contract
for the routes these tests use (``apps/heel-cloud/worker/index.ts`` ``controlPlaneRoute`` and
``controlPlaneRequestHeaders``): the exact route/method allowlist (anything else is 404),
fresh per-family upstream headers, the same-origin + ``Sec-Fetch-Site`` + cookie-only rule for
the human runner routes, request bodies forwarded for POST only with the Worker's per-family
caps, and ``X-Heel-Edge-Auth`` / ``X-Heel-Client-Key`` / ``X-Heel-Internal-Origin`` injected
by the edge alone. It forwards to ``serve(ControlPlane(edge_auth_secret=...))``. The control
plane keeps every production guard; the only seam the runner sees is the explicit CA bundle
path handed to ``HTTPSControlTransport``. It is not the Worker: final acceptance still needs
the deployed edge.

``ScriptedTLSServer`` answers every request with a fixed raw response, for transport
failure tests (redirects, malformed or oversized bodies, slow peers).
"""
from __future__ import annotations

import datetime
import hashlib
import http.client
import ipaddress
import json
import re
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

# Route families copied from apps/heel-cloud/worker/index.ts (same names, same patterns).
_WS = "ws_[0-9a-f]{16}"
_RUNNER = "[A-Za-z0-9_-]{1,128}"
_RUNNER_PAIRING_EXCHANGE = "/v1/runner-pairings/exchange"
_RUNNER_PAIRING_ACTIVATE = re.compile(r"^/v1/runner-pairings/pending_[0-9a-f]{32}/(?:activate|activation-abort)$")
_RUNNER_ROTATION_PUBLIC = re.compile(r"^/v1/runner-rotations/rotation_[0-9a-f]{32}/(?:activate|poll|activation-abort)$")
_RUNNER_PAIRING_MANAGE = re.compile(rf"^/v1/workspaces/{_WS}/runner-pairings(?:/pending_[0-9a-f]{{32}}(?:/approve)?)?$")
_RUNNER_ROTATION_START = re.compile(rf"^/v1/workspaces/{_WS}/runners/{_RUNNER}/rotate$")
_RUNNER_ROTATION_APPROVE = re.compile(rf"^/v1/workspaces/{_WS}/runners/{_RUNNER}/rotations/rotation_[0-9a-f]{{32}}/approve$")
_RUNNER_REVOKE = re.compile(rf"^/v1/workspaces/{_WS}/runners/{_RUNNER}/revoke$")
_RUNNER_CONTROL = re.compile(rf"^/v1/workspaces/{_WS}/runners/{_RUNNER}(?:/claim|/runs/{_RUNNER}/(?:heartbeat|progress|result|stop-ack))$")
_RUNNER_CONTEXT_CONTROL = re.compile(rf"^/v1/workspaces/{_WS}/runners/{_RUNNER}/contexts(?:/list|/rcb_[0-9a-f]{{32}}/(?:claim|approval-projections))$")
_RUNNER_RESULT_PROJECTION = re.compile(rf"^/v1/workspaces/{_WS}/runners/{_RUNNER}/runs/crun_[0-9a-f]{{32}}/result-projection$")
_RUNNER_RESYNC = re.compile(rf"^/v1/workspaces/{_WS}/runners/{_RUNNER}/resync/(?:start|complete)$")
# ``index.ts`` ``RUNNER_INACTIVE_CLAIM_ATTESTATION``: classified exactly like the resync family.
_RUNNER_INACTIVE_CLAIM_ATTESTATION = re.compile(
    rf"^/v1/workspaces/{_WS}/runners/{_RUNNER}/runs/crun_[0-9a-f]{{32}}/inactive-claim-attestation$")


def _resync_family(path: str) -> bool:
    return bool(_RUNNER_RESYNC.match(path) or _RUNNER_INACTIVE_CLAIM_ATTESTATION.match(path))
# ``index.ts`` ``API_KEY_AUTHORIZATION`` / ``DEVICE_AUTHORIZATION``: the only Authorization values
# ``controlPlaneCredentials`` forwards (trimmed); any other non-empty value refuses the request.
_API_KEY_AUTHORIZATION = re.compile(r"Bearer heel_sk_[A-Za-z0-9_-]+")
_DEVICE_AUTHORIZATION = re.compile(r"Bearer heel_at_[A-Za-z0-9_-]{43}")
# Owner project/environment/context-binding routes (``index.ts`` PROJECTS_ROUTE, ENVIRONMENTS_ROUTE,
# ENVIRONMENT_CHECK_ROUTE, ENVIRONMENT_REVOKE_ROUTE, RUNNER_CONTEXT_BINDINGS_ROUTE,
# RUNNER_CONTEXT_REVOKE_ROUTE), mirrored for the T2b-2 binding gate (Astra-approved scope).
_PRJ = "prj_[0-9a-f]{32}"
_PROJECTS = re.compile(rf"^/v1/workspaces/{_WS}/projects$")
_ENVIRONMENTS = re.compile(rf"^/v1/workspaces/{_WS}/projects/{_PRJ}/environments$")
_ENVIRONMENT_CHECK = re.compile(rf"^/v1/workspaces/{_WS}/projects/{_PRJ}/environments/env_[0-9a-f]{{32}}/check$")
_ENVIRONMENT_REVOKE = re.compile(rf"^/v1/workspaces/{_WS}/projects/{_PRJ}/environments/env_[0-9a-f]{{32}}/revoke$")
_RUNNER_CONTEXT_BINDINGS = re.compile(rf"^/v1/workspaces/{_WS}/projects/{_PRJ}/runner-context-bindings$")
_RUNNER_CONTEXT_REVOKE = re.compile(rf"^/v1/workspaces/{_WS}/projects/{_PRJ}/runner-context-bindings/rcb_[0-9a-f]{{32}}/revoke$")
_RUNNER_HEADERS = ("X-Heel-Runner-Id", "X-Heel-Runner-Key-Id", "X-Heel-Runner-Timestamp-Ms",
                   "X-Heel-Runner-Nonce", "X-Heel-Runner-Sequence", "X-Heel-Runner-Signature")
_RUNNER_RESYNC_HEADERS = ("X-Heel-Runner-Id", "X-Heel-Runner-Key-Id", "X-Heel-Runner-Timestamp-Ms",
                          "X-Heel-Runner-Signature")
# Anonymous like the Worker's SIGNUP_ROUTE/LOGIN_ROUTE branch. Logout is not anonymous: it takes
# the default credential branch so the session cookie reaches the server and is revoked.
_SESSION_ROUTES = ("/v1/signup", "/v1/login")
_LOGOUT_ROUTE = "/v1/logout"
_ME_ROUTE = "/v1/me"


class _EdgeRefusal(Exception):
    def __init__(self, status: int, error: str):
        super().__init__(error)
        self.status, self.error = status, error


def _human_owner_route(method: str, path: str) -> bool:
    """``isHumanCanaryRoute`` (context bindings only) or ``isHumanEnvironmentRoute``."""
    if _RUNNER_CONTEXT_BINDINGS.match(path) or _ENVIRONMENTS.match(path):
        return method in {"GET", "POST"}
    return method == "POST" and bool(
        _RUNNER_CONTEXT_REVOKE.match(path) or _ENVIRONMENT_CHECK.match(path) or _ENVIRONMENT_REVOKE.match(path)
    )


def _edge_route(method: str, path: str) -> bool:
    """The subset of the Worker's ``controlPlaneRoute`` allowlist these tests reach."""
    if _human_owner_route(method, path):
        return True
    if _PROJECTS.match(path):
        return method in {"GET", "POST"}
    if path in _SESSION_ROUTES or path == _LOGOUT_ROUTE:
        return method == "POST"
    if path == _ME_ROUTE:
        return method == "GET"
    if path == _RUNNER_PAIRING_EXCHANGE or _RUNNER_PAIRING_ACTIVATE.match(path) or _RUNNER_ROTATION_PUBLIC.match(path):
        return method == "POST"
    if _RUNNER_PAIRING_MANAGE.match(path):
        return method in {"GET", "POST", "DELETE"}
    if _RUNNER_ROTATION_START.match(path) or _RUNNER_ROTATION_APPROVE.match(path) or _RUNNER_REVOKE.match(path):
        return method == "POST"
    if (_RUNNER_CONTROL.match(path) or _RUNNER_CONTEXT_CONTROL.match(path)
            or _RUNNER_RESULT_PROJECTION.match(path) or _resync_family(path)):
        return method == "POST"
    return False


def _body_cap(path: str) -> int:
    """The Worker's per-family POST body maximum for the routes above."""
    if _RUNNER_CONTEXT_BINDINGS.match(path):
        return 2 * 1024
    if _RUNNER_CONTEXT_REVOKE.match(path):
        return 256
    if _ENVIRONMENTS.match(path) or _ENVIRONMENT_CHECK.match(path) or _ENVIRONMENT_REVOKE.match(path):
        return 16 * 1024
    if _RUNNER_RESULT_PROJECTION.match(path):
        return 272 * 1024
    if _RUNNER_CONTEXT_CONTROL.match(path):
        if path.endswith("/contexts/list"):
            return 128
        return 256 if path.endswith("/claim") else 69632
    if _RUNNER_CONTROL.match(path):
        return 256 if path.endswith("/claim") else 36 * 1024
    if _resync_family(path):
        return 2 * 1024
    if (path == _RUNNER_PAIRING_EXCHANGE or _RUNNER_PAIRING_ACTIVATE.match(path)
            or _RUNNER_ROTATION_PUBLIC.match(path) or _RUNNER_PAIRING_MANAGE.match(path)
            or _RUNNER_ROTATION_START.match(path) or _RUNNER_ROTATION_APPROVE.match(path)
            or _RUNNER_REVOKE.match(path)):
        return 16 * 1024
    return 256 * 1024


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

            def _single(self, name: str) -> str | None:
                values = self.headers.get_all(name) or []
                if len(values) > 1:
                    raise _EdgeRefusal(400, "invalid control plane request")
                return values[0] if values else None

            def _credentials(self) -> dict[str, str]:
                """Mirror ``controlPlaneCredentials``' Authorization filter.

                A malformed Authorization value refuses the request before anything is forwarded;
                a valid API-key or device bearer is forwarded trimmed; an empty one is dropped.
                Known limitation: the cookie is forwarded as sent (harness clients use the upstream
                ``heel_session`` name, not the browser ``__Host-`` name the Worker rewrites), so
                the Worker's session-token pattern and its bearer-plus-session refusal are not
                mirrored here.
                """
                headers = {}
                cookie = self._single("Cookie")
                if cookie is not None:
                    headers["Cookie"] = cookie
                authorization = (self._single("Authorization") or "").strip()
                if authorization:
                    if not (_API_KEY_AUTHORIZATION.fullmatch(authorization)
                            or _DEVICE_AUTHORIZATION.fullmatch(authorization)):
                        raise _EdgeRefusal(400, "invalid control plane request")
                    headers["Authorization"] = authorization
                return headers

            def _upstream_headers(self, path: str) -> dict[str, str]:
                """Mirror ``controlPlaneRequestHeaders``: a fresh header set per family."""
                method = self.command
                has = lambda name: self.headers.get(name) is not None  # noqa: E731
                runner_control = bool(_RUNNER_CONTROL.match(path) or _RUNNER_CONTEXT_CONTROL.match(path)
                                      or _RUNNER_RESULT_PROJECTION.match(path))
                public = bool(path == _RUNNER_PAIRING_EXCHANGE or _RUNNER_PAIRING_ACTIVATE.match(path)
                              or _RUNNER_ROTATION_PUBLIC.match(path))
                human = bool(_RUNNER_PAIRING_MANAGE.match(path) or _RUNNER_ROTATION_START.match(path)
                             or _RUNNER_ROTATION_APPROVE.match(path) or _RUNNER_REVOKE.match(path))
                owner = _human_owner_route(method, path)
                if runner_control or _resync_family(path):
                    names = _RUNNER_HEADERS if runner_control else _RUNNER_RESYNC_HEADERS
                    forbidden = ("Authorization", "Cookie", "X-Heel-Internal-Origin", "Content-Encoding") if runner_control \
                        else ("Authorization", "Cookie", "X-Heel-Runner-Nonce", "X-Heel-Runner-Sequence")
                    if method != "POST" or any(has(name) for name in forbidden):
                        raise _EdgeRefusal(400, "invalid control plane request")
                    headers = {}
                    for name in names:
                        value = self._single(name)
                        if value is None:
                            raise _EdgeRefusal(400, "invalid control plane request")
                        headers[name] = value
                elif public:
                    if method != "POST" or has("Authorization") or has("Cookie"):
                        raise _EdgeRefusal(400, "invalid control plane request")
                    headers = {}
                elif owner:
                    # ``controlPlaneRequestHeaders`` human canary/environment branch: cookie only;
                    # a POST also needs the configured origin and ``Sec-Fetch-Site: same-origin``.
                    if has("Authorization"):
                        raise _EdgeRefusal(400, "invalid control plane request")
                    headers = self._credentials()
                    if "Cookie" not in headers or "Authorization" in headers:
                        raise _EdgeRefusal(400, "invalid control plane request")
                    if method == "POST":
                        origin = self._single("Origin") or ""
                        if origin != harness.origin or self._single("Sec-Fetch-Site") != "same-origin":
                            raise _EdgeRefusal(400, "invalid control plane request")
                        headers["X-Heel-Internal-Origin"] = "same-origin"
                        headers["Origin"] = origin
                elif human:
                    origin = self._single("Origin") or ""
                    if origin != harness.origin or self._single("Sec-Fetch-Site") != "same-origin":
                        raise _EdgeRefusal(400, "invalid control plane request")
                    headers = self._credentials()
                    if "Cookie" not in headers or "Authorization" in headers:
                        raise _EdgeRefusal(400, "invalid control plane request")
                    headers["X-Heel-Internal-Origin"] = "same-origin"
                    headers["Origin"] = origin
                elif path in _SESSION_ROUTES:
                    headers = {}
                else:
                    headers = self._credentials()
                headers["X-Heel-Edge-Auth"] = harness.edge_secret
                if method != "POST":
                    return headers
                if has("Transfer-Encoding"):
                    raise _EdgeRefusal(400, "invalid control plane request")
                content_type = (self._single("Content-Type") or "").strip().lower()
                if content_type.split(";", 1)[0] != "application/json" or "," in content_type:
                    raise _EdgeRefusal(400, "invalid control plane request")
                if (self._single("Content-Encoding") or "identity").strip().lower() != "identity":
                    raise _EdgeRefusal(400, "invalid control plane request")
                declared = self._single("Content-Length") or ""
                if re.fullmatch(r"(?:0|[1-9][0-9]*)", declared) is None or len(declared) > 6 \
                        or int(declared) > _body_cap(path):
                    raise _EdgeRefusal(400, "invalid control plane request")
                headers["Content-Type"] = "application/json"
                headers["Content-Encoding"] = "identity"
                headers["Content-Length"] = declared
                if path == "/v1/signup":
                    headers["X-Heel-Client-Key"] = hashlib.sha256(
                        ("edge-client\0" + self.client_address[0]).encode()
                    ).hexdigest()
                return headers

            def _refuse(self, status: int, error: str) -> None:
                payload = json.dumps({"error": error}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)
                self.close_connection = True

            def _proxy(self):
                path = self.path
                if not _edge_route(self.command, path):
                    self.close_connection = True
                    self._refuse(404, "not found")
                    return
                try:
                    headers = self._upstream_headers(path)
                except _EdgeRefusal as refusal:
                    self._refuse(refusal.status, refusal.error)
                    return
                # Like the Worker, only POST carries a body upstream; any other method is
                # forwarded bodiless (the caller's bytes are discarded with the connection).
                body = None
                if self.command == "POST":
                    body = self.rfile.read(int(headers["Content-Length"]))
                else:
                    self.close_connection = True
                harness.forwarded.append((self.command, path))
                upstream = http.client.HTTPConnection("127.0.0.1", harness.upstream_port, timeout=10)
                try:
                    try:
                        upstream.request(self.command, path, body, headers)
                        response = upstream.getresponse()
                        payload = response.read()
                    except (OSError, http.client.HTTPException):
                        # The Worker's ``catch`` around ``CONTROL_PLANE.fetch``: the edge stays up.
                        self._refuse(502, "control plane request failed")
                        return
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
        self.upstream_port = self.backend_port
        self._threads = [_start(self._backend), _start(self._edge)]

    def pause_upstream(self) -> None:
        """Make the control plane unreachable from the edge while the edge itself stays up."""
        self.upstream_port = free_loopback_port()

    def resume_upstream(self) -> None:
        self.upstream_port = self.backend_port

    # Browser-side helpers: these go through the TLS edge like a real browser session.
    def request(self, method: str, path: str, body: object | None = None, *,
                cookie: str | None = None, origin: str | None = "same",
                fetch_site: str | None = "same-origin", raw: bytes | None = None,
                headers: dict[str, str] | None = None) -> tuple[int, object, str | None]:
        context = ssl.create_default_context(cafile=str(self.ca.ca_path))
        connection = http.client.HTTPSConnection("localhost", self.port, context=context, timeout=10)
        extra, headers = headers or {}, {}
        if origin is not None:
            headers["Origin"] = self.origin if origin == "same" else origin
        if fetch_site is not None:
            headers["Sec-Fetch-Site"] = fetch_site
        if cookie is not None:
            headers["Cookie"] = cookie
        payload = raw
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode()
        if payload is not None:
            headers["Content-Type"] = "application/json"
        headers.update(extra)
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
