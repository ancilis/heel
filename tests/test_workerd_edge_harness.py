"""Hygiene of the real-Worker test harness itself (``tests/support/workerd_edge.py``).

Two harness-only flows are pinned here, without touching the Worker or the control plane:
- the per-harness edge secret is never written to disk (the workerd config names an environment
  variable instead of embedding the value), and still reaches the actual Worker;
- the TLS front relays only a validated origin-form request target to the fixed loopback Worker
  socket, refuses every other target form locally, and never follows an upstream redirect.
"""
from __future__ import annotations

import http.client
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.support.edge_tls_harness import EphemeralCA, _start, _TLSServer
from tests.support.workerd_edge import WorkerdEdgeHarness, workerd_available

needs_workerd = pytest.mark.skipif(
    not workerd_available(), reason="apps/heel-cloud node_modules (workerd, esbuild) not installed")

# Targets the runner and dashboard actually send through the Worker (shapes from the wire tests).
LEGITIMATE = [
    "/api/control-plane/v1/signup",
    "/v1/runner-pairings/exchange",
    "/v1/workspaces/ws_01J8Z9/runners/rn_01J8Z9/contexts/list",
    "/v1/workspaces/ws_01J8Z9/runners/rn_01J8Z9/contexts/cb_1/approval-projections",
    "/v1/workspaces/ws_01J8Z9/runners/rn_01J8Z9/runs/run-1/result",
    "/api/control-plane/v1/workspaces/ws_1/canary-approval-requests?state=pending&limit=10",
    "/",
]

ESCAPES = [
    "http://evil.example/v1/signup",          # absolute-form, other host
    "https://127.0.0.1:1/v1/signup",           # absolute-form, other loopback port
    "HTTP://evil.example/",                    # scheme case trick
    "//evil.example/v1/signup",                # scheme-relative (http.server rewrites self.path)
    "evil.example:443",                        # authority-form
    "*",                                       # asterisk-form
    "/@evil.example/v1",                       # userinfo-shaped
    "/v1/x@evil.example",
    "/api/control-plane/../v1/signup",         # dot segments
    "/api/control-plane/./v1/signup",
    "/..",
    "/api/control-plane/%2e%2e/v1/signup",     # encoded dot segment
    "/api/control-plane%2f..%2fv1",            # encoded slash
    "/a\\b",                                   # backslash
    "/v1//signup",                             # empty segment
    "/v1/signup#frag",                         # fragment
    "/v1/sign up",                             # whitespace
    "/v1/é",                              # non-ASCII
    "",
    "v1/signup",                               # no leading slash
]


def test_origin_form_target_accepts_the_legitimate_frames():
    from tests.support.workerd_edge import origin_form_target

    assert [origin_form_target(target) for target in LEGITIMATE] == LEGITIMATE


@pytest.mark.parametrize("target", ESCAPES)
def test_origin_form_target_refuses_every_escape_form(target):
    from tests.support.workerd_edge import origin_form_target

    assert origin_form_target(target) is None


def _raw_request(edge, target: str) -> int:
    """Send ``GET <target>`` exactly as given (no client-side normalization) through the front."""
    context = ssl.create_default_context(cafile=str(edge.ca.ca_path))
    with socket.create_connection(("127.0.0.1", edge.port), timeout=30) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as tls:
            tls.sendall(f"GET {target} HTTP/1.1\r\nHost: localhost:{edge.port}\r\n\r\n".encode("latin-1"))
            data = b""
            while b"\r\n" not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
    return int(data.split(b" ", 2)[1])


@needs_workerd
def test_edge_secret_reaches_the_worker_without_touching_disk(tmp_path):
    with WorkerdEdgeHarness(tmp_path / "cloud") as edge:
        # The secret is load-bearing: the control plane refuses a request without it …
        direct = http.client.HTTPConnection("127.0.0.1", edge.backend_port, timeout=30)
        try:
            direct.request("POST", "/v1/signup", b'{"email":"d@example.test","password":"correct-horse-battery"}',
                           {"Content-Type": "application/json"})
            refused = direct.getresponse().status
        finally:
            direct.close()
        assert refused != 201
        # … and accepts the same call relayed by the actual Worker, which got it from its binding.
        workspace_id, _cookie = edge.signup_owner("owner-secret@example.test")
        assert workspace_id
        assert ("POST", "/v1/signup") in edge.forwarded
        secret = edge.edge_secret.encode()
        written = {path: path.read_bytes() for path in edge.root.rglob("*") if path.is_file()}
        assert edge.root / "workerd.capnp" in written
        assert [path for path, content in written.items() if secret in content] == []


@needs_workerd
@pytest.mark.parametrize("target", [t for t in ESCAPES if t and " " not in t])
def test_front_refuses_escape_targets_before_the_worker(tmp_path, target):
    with WorkerdEdgeHarness(tmp_path / "cloud") as edge:
        assert _raw_request(edge, target) == 400
        assert edge.edge_answers == [] and edge.forwarded == []
        # The same front still relays a legitimate target to the Worker and on to the control plane.
        _raw_request(edge, "/api/control-plane/v1/me")
        assert [(method, path) for method, path, *_rest in edge.edge_answers] == [
            ("GET", "/api/control-plane/v1/me")]


def test_front_relays_an_upstream_redirect_without_following_it(tmp_path):
    from tests.support.workerd_edge import _front_handler

    escaped: list[str] = []
    upstream_seen: list[tuple[str, str]] = []

    class Escape(BaseHTTPRequestHandler):
        def do_GET(self):
            escaped.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            return

    escape = ThreadingHTTPServer(("127.0.0.1", 0), Escape)
    location = f"http://127.0.0.1:{escape.server_address[1]}/escaped"

    class Redirecting(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            upstream_seen.append((self.command, self.path))
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            return

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Redirecting)
    answers: list[tuple] = []
    ca = EphemeralCA(tmp_path / "tls")
    front = _TLSServer(_front_handler(upstream.server_address[1], cloudflare_connection=lambda: True,
                                      on_answer=answers.append), ca.server_context())
    threads: list[threading.Thread] = [_start(escape), _start(upstream), _start(front)]
    try:
        client = http.client.HTTPSConnection(
            "localhost", front.server_address[1], timeout=30,
            context=ssl.create_default_context(cafile=str(ca.ca_path)))
        try:
            client.request("GET", "/v1/redirecting")
            response = client.getresponse()
            response.read()
        finally:
            client.close()
        assert (response.status, response.getheader("Location")) == (302, location)
        assert upstream_seen == [("GET", "/v1/redirecting")]
        assert escaped == []
        assert [(method, path, status) for method, path, status, _body in answers] == [
            ("GET", "/v1/redirecting", 302)]
    finally:
        for server in (front, upstream, escape):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(5)
