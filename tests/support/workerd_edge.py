"""Test-only: the actual public Worker (``apps/heel-cloud/worker/index.ts``) in ``workerd``.

``WorkerdEdgeHarness`` has the ``EdgeTLSHarness`` surface the runner integration tests use, but
the edge is not a mirror: ``worker/index.ts`` and ``worker/control-plane-dispatch.ts`` are bundled
unchanged with esbuild and served by the pinned ``workerd`` runtime (the app's own
``node_modules``) at the production compatibility date, with ``CONTROL_PLANE`` bound to the real
``serve(ControlPlane(edge_auth_secret=...))`` over loopback HTTP (the deployed
``CONTROL_PLANE_TRANSPORT=http`` VPC transport).

Labelled seams (none is public acceptance; the final proof stays the deployed edge):
- SEAM-APP: only the two ``vinext`` imports (page handler, image optimizer) are stubbed; control
  plane requests never reach them.
- SEAM-EDGE-CA: a loopback TLS front with an ephemeral ``localhost`` CA stands in for Cloudflare's
  TLS termination; the runner receives it through the explicit CA bundle argument.
- SEAM-CF-CONNECTION: Cloudflare documents that every request it hands onward carries
  ``Connection: Keep-Alive`` (a client value is overwritten); the front applies exactly that one
  normalization (``cloudflare_connection=True``, the default). Every other header, the method, the
  path and the body bytes are relayed unchanged.
- SEAM-HOST: runners reach the Worker at ``https://localhost:<port>``; the Worker's configured
  ``PUBLIC_ORIGIN`` (and the control plane's) is ``PUBLIC_ORIGIN`` below, which browser-shaped
  requests send as ``Origin``. The Worker never consults ``Host`` for the routes used here.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from heel.saas.http_api import ControlPlane, serve
from tests.support.edge_tls_harness import EphemeralCA, _start, _TLSServer, free_loopback_port

_ROOT = Path(__file__).resolve().parents[2]
_APP = _ROOT / "apps" / "heel-cloud"
PUBLIC_ORIGIN = "https://heel-wire.example.com"
# ``vite.config.ts`` / ``production-artifact.test.mjs``: the deployed runtime contract.
COMPATIBILITY_DATE = "2026-08-20"
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade",
    "content-length",
})
_BUNDLES: dict[str, Path] = {}
_BUNDLE_LOCK = threading.Lock()


def workerd_available() -> bool:
    return (_APP / "node_modules" / ".bin" / "workerd").exists() and (_APP / "node_modules" / ".bin" / "esbuild").exists()


def _bundle() -> Path:
    """Bundle the Worker sources once per content digest (SEAM-APP stubs only the app handler)."""
    sources = [_APP / "worker" / "index.ts", _APP / "worker" / "control-plane-dispatch.ts",
               _APP / "build" / "deployment-config.ts"]
    digest = hashlib.sha256(b"".join(path.read_bytes() for path in sources)).hexdigest()
    with _BUNDLE_LOCK:
        cached = _BUNDLES.get(digest)
        if cached is not None and cached.exists():
            return cached
        directory = Path(tempfile.mkdtemp(prefix="heel-workerd-bundle-"))
        stub_app = directory / "stub-app.js"
        stub_app.write_text("export default { fetch() { return new Response('app', { status: 404 }); } };\n")
        stub_image = directory / "stub-image.js"
        stub_image.write_text(
            "export function handleImageOptimization() { return new Response('image', { status: 404 }); }\n"
            "export const DEFAULT_DEVICE_SIZES = []; export const DEFAULT_IMAGE_SIZES = [];\n")
        output = directory / "worker.js"
        subprocess.run([
            str(_APP / "node_modules" / ".bin" / "esbuild"), str(_APP / "worker" / "index.ts"),
            "--bundle", "--format=esm", "--platform=neutral", "--target=es2022",
            f"--alias:vinext/server/app-router-entry={stub_app}",
            f"--alias:vinext/server/image-optimization={stub_image}",
            f"--outfile={output}", "--log-level=error",
        ], check=True, cwd=_APP, timeout=120)
        _BUNDLES[digest] = output
        return output


def _wait_listening(port: int, process: subprocess.Popen, log: Path, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("workerd exited: " + log.read_text(errors="replace")[-2000:])
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("workerd did not listen: " + log.read_text(errors="replace")[-2000:])


class WorkerdEdgeHarness:
    """TLS front (SEAM-EDGE-CA, SEAM-CF-CONNECTION) → workerd(worker/index.ts) → real control plane."""

    def __init__(self, root: Path, *, cloudflare_connection: bool = True, **control_plane_options):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.ca = EphemeralCA(self.root / "edge-tls")
        self.edge_secret = secrets.token_urlsafe(32)
        self.public_origin = PUBLIC_ORIGIN
        self.cloudflare_connection = cloudflare_connection
        # Requests that actually reached the control plane, i.e. that the Worker forwarded.
        self.forwarded: list[tuple[str, str]] = []
        # Every Worker answer the front relayed: (method, path, status, body bytes).
        self.edge_answers: list[tuple[str, str, int, bytes]] = []
        harness = self

        options = {
            "device_token_pepper": b"d" * 32, "runner_auth_pepper": b"r" * 32,
            "enable_device_auth": True, "trust_edge_client_key": True,
        }
        options.update(control_plane_options)
        self.control_plane = ControlPlane(
            str(self.root / "control-plane.sqlite3"),
            public_origin=PUBLIC_ORIGIN, edge_auth_secret=self.edge_secret, **options,
        )
        self._backend = serve(self.control_plane)
        base_handler = self._backend.RequestHandlerClass

        class RecordingHandler(base_handler):
            def _route(self, method):
                harness.forwarded.append((method, self.path))
                return super()._route(method)

        self._backend.RequestHandlerClass = RecordingHandler
        self.backend_port = self._backend.server_address[1]

        self._worker_port = free_loopback_port()
        config = self.root / "workerd.capnp"
        bundle = _bundle()
        shutil.copyfile(bundle, self.root / "worker.js")
        bindings = {
            "PUBLIC_ORIGIN": PUBLIC_ORIGIN, "CONTROL_PLANE_EDGE_SECRET": self.edge_secret,
            "CONTROL_PLANE_TRANSPORT": "http",
        }
        text_bindings = ", ".join(
            f'(name = "{name}", text = {json.dumps(value)})' for name, value in bindings.items())
        config.write_text(f"""using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    (name = "edge", worker = .edge),
    (name = "control-plane", external = (address = "127.0.0.1:{self.backend_port}", http = ())),
  ],
  sockets = [(name = "http", address = "127.0.0.1:{self._worker_port}", http = (), service = "edge")],
);
const edge :Workerd.Worker = (
  modules = [(name = "worker.js", esModule = embed "worker.js")],
  compatibilityDate = "{COMPATIBILITY_DATE}",
  compatibilityFlags = ["nodejs_compat"],
  bindings = [(name = "CONTROL_PLANE", service = "control-plane"), {text_bindings}],
);
""")
        self._workerd_log = self.root / "workerd.log"
        log = self._workerd_log.open("wb")
        self._workerd = subprocess.Popen(
            [str(_APP / "node_modules" / ".bin" / "workerd"), "serve", str(config)],
            stdout=log, stderr=subprocess.STDOUT, cwd=self.root,
        )
        log.close()
        self._threads = [_start(self._backend)]
        _wait_listening(self._worker_port, self._workerd, self._workerd_log)

        class FrontHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                return

            def _relay(self):
                self.close_connection = True
                headers = [(name, value) for name, value in self.headers.items()
                           if not (harness.cloudflare_connection and name.lower() == "connection")]
                if any(name.lower() == "transfer-encoding" for name, _ in headers):
                    self.send_error(400)
                    return
                lengths = [value for name, value in headers if name.lower() == "content-length"]
                body = self.rfile.read(int(lengths[0])) if lengths and lengths[0].isdigit() else b""
                if harness.cloudflare_connection:
                    headers.append(("Connection", "Keep-Alive"))  # SEAM-CF-CONNECTION
                upstream = http.client.HTTPConnection("127.0.0.1", harness._worker_port, timeout=30)
                try:
                    upstream.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                    for name, value in headers:
                        upstream.putheader(name, value)
                    upstream.endheaders(body if lengths else None)
                    response = upstream.getresponse()
                    payload = response.read()
                    harness.edge_answers.append((self.command, self.path, response.status, payload))
                    self.send_response(response.status)
                    for name, value in response.getheaders():
                        if name.lower() not in _HOP_BY_HOP:
                            self.send_header(name, value)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                finally:
                    upstream.close()

            do_GET = do_POST = do_DELETE = do_PUT = do_PATCH = _relay

        self._front = _TLSServer(FrontHandler, self.ca.server_context())
        self.port = self._front.server_address[1]
        self.origin = f"https://localhost:{self.port}"
        self._threads.append(_start(self._front))

    def pause_upstream(self) -> None:  # pragma: no cover - not offered by the real-Worker edge
        raise NotImplementedError("the workerd edge has a fixed control-plane binding")

    resume_upstream = pause_upstream

    def worker_log(self) -> str:
        return self._workerd_log.read_text(errors="replace")

    # Browser-side helper: same-origin dashboard requests carry the configured public Origin.
    def request(self, method: str, path: str, body: object | None = None, *,
                cookie: str | None = None, origin: str | None = "same",
                fetch_site: str | None = "same-origin", raw: bytes | None = None,
                headers: dict[str, str] | None = None) -> tuple[int, object, str | None]:
        import ssl

        context = ssl.create_default_context(cafile=str(self.ca.ca_path))
        connection = http.client.HTTPSConnection("localhost", self.port, context=context, timeout=30)
        extra, sent = headers or {}, {}
        if origin is not None:
            sent["Origin"] = self.public_origin if origin == "same" else origin
        if fetch_site is not None:
            sent["Sec-Fetch-Site"] = fetch_site
        if cookie is not None:
            sent["Cookie"] = cookie
        payload = raw
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode()
        if payload is not None:
            sent["Content-Type"] = "application/json"
        sent.update(extra)
        try:
            # The dashboard calls the control plane through the Worker's browser prefix.
            connection.request(method, "/api/control-plane" + path, payload, sent)
            response = connection.getresponse()
            data = response.read()
            set_cookie = response.getheader("Set-Cookie")
        finally:
            connection.close()
        return response.status, (json.loads(data) if data else None), set_cookie

    def signup_owner(self, email: str) -> tuple[str, str]:
        status, body, cookie = self.request(
            "POST", "/v1/signup", {"email": email, "password": "correct-horse-battery"},
        )
        assert status == 201 and cookie, (status, body)
        return body["workspace_id"], cookie.split(";", 1)[0]

    def close(self) -> None:
        self._front.shutdown()
        self._front.server_close()
        self._workerd.terminate()
        try:
            self._workerd.wait(10)
        except subprocess.TimeoutExpired:
            self._workerd.kill()
            self._workerd.wait(10)
        self._backend.shutdown()
        self._backend.server_close()

    def __enter__(self) -> "WorkerdEdgeHarness":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


__all__ = ["PUBLIC_ORIGIN", "WorkerdEdgeHarness", "workerd_available"]
