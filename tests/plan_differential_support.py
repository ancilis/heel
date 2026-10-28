"""Loopback synthetic staging target and test-only seam objects for the plan-differential runner.

Nothing here ships in the wheel. The seam replaces exactly one module attribute,
``heel.runner.plan_differential._build_client``; request construction, framing, gate,
budget, reservation, evidence, redaction, predicates and logging stay product code. The
seam proves nothing about TLS, DNS answers or address selection.
"""
from __future__ import annotations

import contextlib
import datetime
import http.server
import io
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import threading

from heel import cli
from heel import scope as scope_module
from heel.runner import plan_differential
from heel.runner.http_transport import TargetHTTPSClient


SYNTHETIC_HOST = "plan-differential-synthetic.heel.dev"
SYNTHETIC_ORIGIN = "https://" + SYNTHETIC_HOST
PUBLIC_ADDRESS = "93.184.216.34"
FREE_TOKEN = "synthetic-free-session-0001"
PRO_TOKEN = "synthetic-pro-session-0001"
MARKER = "heel-canary-export-0001"
FIXTURE = Path(__file__).resolve().parent / "fixtures/plan_differential/openapi.json"
SESSIONS = {FREE_TOKEN: "free", PRO_TOKEN: "pro"}
EXPORT = {
    "account_id": "acct_canary",
    "format": "csv",
    "rows": [{"id": "row_1", "amount_cents": 1200}],
    "total": 1,
}
BEHAVIORS = ("vulnerable", "hardened", "envelope", "subset")
DENIAL_ENVELOPE = {"error": "upgrade required"}


class _Listener:
    """One stdlib loopback HTTP listener bound to port 0, recording every request."""

    def __init__(self, sessions: dict[str, str] | None = None) -> None:
        self.sessions = dict(SESSIONS if sessions is None else sessions)
        self.requests: list[dict[str, str]] = []
        # Called on the server thread with the zero-based arrival index, before responding.
        self.on_request = None
        self._lock = threading.Lock()
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            # HTTP/1.0: every response closes the connection; no transfer encoding.
            protocol_version = "HTTP/1.0"

            def log_message(self, *_args) -> None:
                return None

            def _serve(self) -> None:
                header = self.headers.get("Authorization")
                token = (header or "").removeprefix("Bearer ")
                with owner._lock:
                    index = len(owner.requests)
                    owner.requests.append({
                        "method": self.command,
                        "path": self.path,
                        "host": self.headers.get("Host", ""),
                        "plan": "none" if header is None else owner.sessions.get(token, "unknown"),
                    })
                if owner.on_request is not None:
                    owner.on_request(index)
                status, headers, body = owner.respond(self.command, self.path, token)
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = _serve

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def respond(self, method: str, path: str, token: str) -> tuple[int, dict[str, str], bytes]:
        return 404, {"Content-Type": "application/json"}, b'{"error":"not found"}'

    def start(self):
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(5)

    def __enter__(self):
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    def seen(self) -> list[tuple[str, str, str]]:
        with self._lock:
            return [(item["method"], item["path"], item["plan"]) for item in self.requests]


def _json(status: int, value: dict) -> tuple[int, dict[str, str], bytes]:
    return status, {"Content-Type": "application/json"}, json.dumps(value).encode("utf-8")


def pricing(token: str) -> dict:
    """Ordinary numeric JSON the inherited redaction count refuses, echoing the credential."""
    return {
        "echo": token,
        "price": 1.5,
        "delta": -3,
        "big": 2 ** 60,
        "tiers": {f"tier_{index:03d}": index * 0.25 for index in range(300)},
    }


class SyntheticTarget(_Listener):
    """Two bearer sessions carrying a plan flag.

    ``behavior`` selects what the lower plan receives on the plan-gated reads:
    ``vulnerable`` (the same 200 object), ``hardened`` (403), ``envelope`` (a 200 denial
    body) or ``subset`` (a 200 object with fewer keys). It may be changed between runs.
    """

    def __init__(self, *, behavior: str = "vulnerable", redirect_port: int = 9,
                 sessions: dict[str, str] | None = None) -> None:
        super().__init__(sessions)
        assert behavior in BEHAVIORS
        self.behavior = behavior
        self.redirect_port = redirect_port

    def respond(self, method: str, path: str, token: str) -> tuple[int, dict[str, str], bytes]:
        plan = self.sessions.get(token)
        if plan is None:
            return _json(401, {"error": "unauthenticated"})
        pro = plan == "pro"
        behavior = "vulnerable" if pro else self.behavior
        gated = behavior == "hardened"
        if path == "/api/export" and method in {"GET", "HEAD"}:
            if gated:
                return _json(403, DENIAL_ENVELOPE)
            if behavior == "envelope":
                return _json(200, DENIAL_ENVELOPE)
            if behavior == "subset":
                return _json(200, {"account_id": EXPORT["account_id"], "total": 0})
            return _json(200, EXPORT)
        if path == "/api/pricing":
            return _json(403, DENIAL_ENVELOPE) if gated else _json(200, pricing(token))
        if path == "/api/reports":
            if not pro:
                return _json(403, {"error": "plan required"})
            return _json(200, {"reports": [{"id": "r1", "title": "Q1"}]})
        if path == "/api/billing":
            if not pro:
                return _json(200, {"error": "upgrade required"})
            return _json(200, {"invoices": [{"id": "inv_1"}], "plan": "pro"})
        if path == "/api/summary":
            if not pro:
                return _json(200, {"count": 1, "plan": "free"})
            return _json(200, {"breakdown": {"paid": 1}, "count": 1, "plan": "pro"})
        if path == "/api/empty":
            return 204, {}, b""
        if path == "/api/text":
            return 200, {"Content-Type": "text/plain"}, b"plain text"
        if path == "/api/redirect":
            return 302, {"Location": f"http://127.0.0.1:{self.redirect_port}/landing"}, b""
        if path == "/api/echo":
            status, headers, body = _json(200, {"echo": token, "quoted": "session " + token})
            return status, {**headers, "X-Echo": token}, body
        if path.startswith("/exports/"):
            if gated:
                return _json(403, {"error": "export requires pro"})
            if behavior == "envelope":
                return _json(200, DENIAL_ENVELOPE)
            if behavior == "subset":
                return _json(200, {"rows": []})
            return _json(200, {"protected_canary": path.removeprefix("/exports/"), "rows": []})
        if path.startswith("/bulk/"):
            return _json(200, {"n": 1}) if pro else _json(403, DENIAL_ENVELOPE)
        if path.startswith("/items/"):
            return _json(200, {"id": path.removeprefix("/items/")})
        return _json(404, {"error": "not found"})


class SecondListener(_Listener):
    """Where an off-allowlist redirect points. It must never be contacted."""


class LoopbackResolver:
    """Returns one fixed public address; ``change_after`` simulates DNS rebinding."""

    def __init__(self, *, change_after: int | None = None) -> None:
        self.calls = 0
        self.change_after = change_after

    def __call__(self, hostname: str, *, deadline: float) -> list[str]:
        self.calls += 1
        if self.change_after is not None and self.calls > self.change_after:
            return ["93.184.216.35"]
        return [PUBLIC_ADDRESS]


class _PinnedSocket:
    """A real loopback socket that reports the pinned public address as its peer."""

    def __init__(self, raw: socket.socket) -> None:
        self._raw = raw

    def getpeername(self):
        return (PUBLIC_ADDRESS, 443)

    def __getattr__(self, name: str):
        return getattr(self._raw, name)


class LoopbackSockets:
    """Connects to the loopback target; ``fail_connects`` are zero-based connect indexes."""

    def __init__(self, port: int, *, fail_connects=()) -> None:
        self.port = port
        self.fail_connects = frozenset(fail_connects)
        self.addresses: list[tuple[str, int]] = []

    def connect(self, address, timeout, cancellation):
        index = len(self.addresses)
        self.addresses.append(tuple(address))
        if index in self.fail_connects:
            raise ConnectionRefusedError("synthetic connect failure")
        return _PinnedSocket(socket.create_connection(("127.0.0.1", self.port), timeout))


class PassThroughTLS:
    def __init__(self) -> None:
        self.hostnames: list[str] = []

    def wrap(self, raw_socket, hostname: str, timeout: float):
        self.hostnames.append(hostname)
        raw_socket.settimeout(timeout)
        return raw_socket


class LoopbackFactory:
    """Replacement for ``_build_client``: a real client over the loopback seam objects."""

    def __init__(self, port: int, *, change_after: int | None = None, fail_connects=()):
        self.resolver = LoopbackResolver(change_after=change_after)
        self.sockets = LoopbackSockets(port, fail_connects=fail_connects)
        self.tls = PassThroughTLS()
        self.origins: list[str] = []

    def __call__(self, origin: str) -> TargetHTTPSClient:
        self.origins.append(origin)
        return TargetHTTPSClient(
            origin=origin, preflight_addresses=[PUBLIC_ADDRESS], resolver=self.resolver,
            sockets=self.sockets, tls=self.tls,
        )


def install(monkeypatch, factory) -> None:
    monkeypatch.setattr(plan_differential, "_build_client", factory)


def invoke(*arguments: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main(list(arguments))
    return code, stdout.getvalue(), stderr.getvalue()


def use_home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "heel-home"
    monkeypatch.setenv("HEEL_HOME", str(home))
    monkeypatch.delenv("HEEL_SIGNING_KEY", raising=False)
    return home


class Journey:
    """The documented operator journey through the unmodified public CLI."""

    def __init__(self, tmp_path, monkeypatch, *, host: str = SYNTHETIC_HOST,
                 tokens: tuple[str, str] = (FREE_TOKEN, PRO_TOKEN), marker: str | None = None,
                 fixture: Path = FIXTURE, limits: dict | None = None, on_scope=None,
                 profiles: tuple[str, str] = ("bearer", "bearer")):
        self.monkeypatch = monkeypatch
        self.home = use_home(tmp_path, monkeypatch)
        self.origin = "https://" + host
        self.tokens = tokens
        if limits is None:
            self.scope_id = self.create_scope(host)
        else:
            # Test setup only: the product never calls create_scope for this feature.
            self.scope_id = scope_module.create_scope(
                [host], "plan-differential-test", limits=limits,
            ).scope_id
        if on_scope is not None:
            on_scope(self)
        code, output, error = invoke(
            "runner", "run", "--scope", self.scope_id, "--base-url", self.origin, "--dry-run",
        )
        assert (code, error) == (0, ""), (code, output, error)
        self.bootstrap = json.loads(output)
        self.handles = []
        for role, profile in zip(("lower_plan", "higher_plan"), profiles, strict=True):
            code, output, error = invoke(
                "runner", "credential", "add", "--role", role, "--profile", profile,
                "--label", "PRIVATE " + role, "--backend", "ephemeral-env",
            )
            assert (code, error) == (0, ""), (code, output, error)
            self.handles.append(json.loads(output)["credential_handle"])
        code, output, error = invoke("runner", "import-openapi", str(fixture))
        assert (code, error) == (0, ""), (code, output, error)
        if marker is not None:
            self.map("GET", "/exports/{id}", {"id": marker})

    @staticmethod
    def create_scope(*hosts: str) -> str:
        arguments = ["scope", "create", "--confirm", "--operator", "plan-differential-test"]
        for host in hosts:
            arguments += ["--target", host]
        code, output, _ = invoke(*arguments)
        assert code == 0
        return json.loads(output)["created_scope"]

    def map(self, method: str, route: str, fixtures: dict[str, str]) -> None:
        reader, writer = os.pipe()
        os.write(writer, json.dumps(fixtures).encode("utf-8"))
        os.close(writer)
        os.set_inheritable(reader, True)
        try:
            code, output, error = invoke(
                "runner", "map", "--scenario", "plan_entitlement_read", "--method", method,
                "--route", route, "--fixture-fd", str(reader),
            )
        finally:
            os.close(reader)
        assert (code, error) == (0, ""), (code, output, error)

    def supply_credentials(self, *, skip_higher: bool = False) -> None:
        for handle, token in zip(self.handles, self.tokens, strict=True):
            name = "HEEL_RUNNER_CREDENTIAL_" + handle.upper()
            if skip_higher and handle == self.handles[1]:
                self.monkeypatch.delenv(name, raising=False)
            else:
                self.monkeypatch.setenv(name, token)

    def arguments(self, *extra: str, scope: str | None = None, origin: str | None = None,
                  identities: tuple[tuple[str, str], ...] | None = None) -> list[str]:
        if identities is None:
            identities = (("free", self.handles[0]), ("pro", self.handles[1]))
        arguments = [
            "runner", "run", "--scope", self.scope_id if scope is None else scope,
            "--base-url", self.origin if origin is None else origin,
        ]
        for label, handle in identities:
            arguments += ["--as", f"{label}={handle}"]
        return arguments + list(extra)

    def run(self, *extra: str, **keywords) -> tuple[int, dict | None, str]:
        self.supply_credentials()
        code, output, error = invoke(*self.arguments(*extra, **keywords))
        return code, (json.loads(output) if output else None), error

    def findings(self, run_id: str) -> list[dict]:
        code, output, _ = invoke("findings", "--run", run_id)
        assert code == 0
        return json.loads(output)["findings"]

    def containment(self, run_id: str) -> dict:
        code, output, _ = invoke("log", "--run", run_id)
        assert code == 0
        return json.loads(output)


class World:
    """A synthetic target, the listener a redirect points at, the seam, and one journey."""

    def __init__(self, tmp_path, monkeypatch, *, behavior: str = "vulnerable", seam: bool = True,
                 change_after: int | None = None, fail_connects=(), **journey):
        tokens = journey.get("tokens", (FREE_TOKEN, PRO_TOKEN))
        self.second = SecondListener().start()
        self.target = SyntheticTarget(
            behavior=behavior, redirect_port=self.second.port,
            sessions={tokens[0]: "free", tokens[1]: "pro"},
        ).start()
        self.factory = LoopbackFactory(
            self.target.port, change_after=change_after, fail_connects=fail_connects,
        )
        if seam:
            install(monkeypatch, self.factory)
        try:
            tmp_path.mkdir(parents=True, exist_ok=True)
            self.journey = Journey(tmp_path, monkeypatch, **journey)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        self.target.stop()
        self.second.stop()

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def scope_path(home: Path, scope_id: str) -> Path:
    return home / "scopes" / (scope_id + ".json")


def bulk_openapi(path: Path, count: int) -> Path:
    """An OpenAPI document with ``count`` unparameterized GET reads under /bulk/."""
    document = {
        "openapi": "3.1.0",
        "info": {"title": "Plan-differential bulk reads", "version": "1.0.0"},
        "paths": {
            f"/bulk/{index:03d}": {
                "get": {
                    "operationId": f"getBulk{index:03d}",
                    "responses": {"200": {"description": "ok"}},
                },
            }
            for index in range(count)
        },
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def pairs_by_route(result: dict) -> dict[tuple[str, str], dict]:
    return {(item["method"], item["route_template"]): item for item in result["pairs"]}


def home_contains(home: Path, needle: bytes) -> list[str]:
    """Every file under HEEL_HOME whose bytes contain the needle."""
    hits = []
    for directory, _, names in os.walk(home):
        for name in names:
            path = Path(directory) / name
            if needle in path.read_bytes():
                hits.append(str(path))
    return hits


# --------------------------------------------------------------------------- #
# Real-handshake helpers: a test CA generated per test and a loopback TLS server.
# --------------------------------------------------------------------------- #
def make_test_ca(hostname: str = SYNTHETIC_HOST) -> tuple[bytes, bytes, bytes]:
    """Return (CA certificate, server certificate, server key) as PEM."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Heel plan-differential test CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_name).public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    return (
        ca_certificate.public_bytes(pem),
        server_certificate.public_bytes(pem),
        server_key.private_bytes(
            pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ),
    )


class TLSLoopbackServer:
    """A real ``ssl`` server on loopback that answers one byte after each handshake.

    ``minimum``/``maximum`` bound the server's protocol versions explicitly; ``ciphers``
    is only for hosting a legacy-protocol fixture. Setting them may raise on builds that
    cannot host those bounds; callers decide what that means.
    """

    def __init__(
        self, tmp_path, certificate: bytes, key: bytes, *,
        minimum: ssl.TLSVersion | None = None, maximum: ssl.TLSVersion | None = None,
        ciphers: str | None = None,
    ) -> None:
        certificate_path, key_path = tmp_path / "server.pem", tmp_path / "server.key"
        certificate_path.write_bytes(certificate)
        key_path.write_bytes(key)
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(certificate_path, key_path)
        if ciphers is not None:
            self._context.set_ciphers(ciphers)
        if minimum is not None:
            self._context.minimum_version = minimum
        if maximum is not None:
            self._context.maximum_version = maximum
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self.handshakes = 0
        self._stopped = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        self._listener.settimeout(0.1)
        while not self._stopped.is_set():
            try:
                raw, _ = self._listener.accept()
            except OSError:
                continue
            try:
                raw.settimeout(5)
                with self._context.wrap_socket(raw, server_side=True) as wrapped:
                    self.handshakes += 1
                    wrapped.sendall(b"k")
            except (OSError, ssl.SSLError):
                pass
            finally:
                raw.close()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._stopped.set()
        self._thread.join(5)
        self._listener.close()


def is_public(address: str) -> bool:
    return ipaddress.ip_address(address).is_global
