"""T2a: runner pairing over a real TLS edge, the HTTPS control transport and its refusals.

The integration tests drive the real Python control plane through ``EdgeTLSHarness``:
browser-session HTTP for the owner's invite/approve/revoke and ``RunnerDaemon`` for the
runner's exchange/activate/control calls. No row is seeded or edited and no runner
credential is fabricated. The only test seams are the explicit CA bundle argument and the
secret backend passed through the existing ``backend=`` constructor injection (limited proof:
real OS secret-store persistence is recorded separately in the T2a closing).
"""
from __future__ import annotations

import base64
import contextlib
import http.client
import inspect
import io
import json
import os
import re
import socket
import ssl
import threading
import time
from pathlib import Path

import pytest

from heel import cli
from heel.crypto import SigningAuthority
from heel.runner import daemon as daemon_module
from heel.runner import control_transport
from heel.runner.control_transport import (
    MAX_CONTROL_RESPONSE_BYTES, ControlTransportError, HTTPSControlTransport,
    validate_control_origin,
)
from heel.runner.daemon import RunnerDaemon, RunnerPairingError, self_serve_access
from heel.runner.identity import (
    RUNNER_PAIRING_SIGNER_LABEL_PREFIX, LinuxSecretServiceBackend, MacOSKeychainSecretBackend,
)
from heel.runner.store import RunnerStore
from tests.support.edge_tls_harness import (
    EdgeTLSHarness, EphemeralCA, ScriptedTLSServer, raw_json_response,
)


class RecordingSecretBackend:
    """Test-code OS secret backend double, injected only through ``backend=``."""

    def __init__(self):
        self.values: dict[str, bytes] = {}
        self.deleted: list[str] = []

    def load(self, label):
        value = self.values.get(label)
        return None if value is None else bytes(value)

    def store(self, label, seed):
        if label in self.values:
            raise ValueError("runner signing identity already exists")
        self.values[label] = bytes(seed)

    def delete(self, label):
        self.deleted.append(label)
        self.values.pop(label, None)


REVOKE_BODY = {"schema_version": "heel.runner-revoke.v1", "reason_code": "human_revocation"}


@pytest.fixture
def harness(tmp_path):
    authority = SigningAuthority.generate()
    with EdgeTLSHarness(
        tmp_path / "cloud", grant_authority=authority,
        grant_trusted_keys={authority.key_id: authority.public_key},
    ) as edge:
        yield edge


def _home(tmp_path: Path, name: str) -> Path:
    home = tmp_path / name
    home.mkdir(mode=0o700)
    return home


def _daemon(home: Path, harness: EdgeTLSHarness, backend: RecordingSecretBackend, **options) -> RunnerDaemon:
    return RunnerDaemon(
        home, secret_backend=backend, ca_bundle=harness.ca.ca_path,
        poll_interval_seconds=0.05, **options,
    )


def _invite(harness: EdgeTLSHarness, workspace_id: str, cookie: str) -> str:
    status, body, _ = harness.request(
        "POST", f"/v1/workspaces/{workspace_id}/runner-pairings",
        {"schema_version": "heel.runner-pairing-invite.v1"}, cookie=cookie,
    )
    assert status == 201
    return body["invitation_token"]


def _pair_with_owner_approval(harness, daemon, workspace_id, cookie, token, *, approve=True):
    """Run ``pair`` like the CLI while the owner compares and approves in the browser."""
    events: list[dict] = []
    pending = threading.Event()
    outcome: dict[str, object] = {}

    def emit(event):
        events.append(event)
        if event["event"] == "pairing_pending":
            pending.set()

    def run():
        try:
            outcome["result"] = daemon.pair(harness.origin, token, display_name="Runner T2a", emit=emit)
        except BaseException as error:  # surfaced to the test thread below
            outcome["error"] = error
            pending.set()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert pending.wait(30)
    if "error" not in outcome and approve:
        printed = events[0]
        status, view, _ = harness.request(
            "GET", f"/v1/workspaces/{workspace_id}/runner-pairings/{printed['pairing_id']}", cookie=cookie,
        )
        assert status == 200 and view["status"] == "pending"
        # The human compares the six words and fingerprint the runner printed with the browser.
        assert view["pairing_phrase"] == printed["pairing_phrase"]
        assert view["fingerprint"] == printed["fingerprint"]
        assert len(printed["pairing_phrase"].split()) == 6
        status, _, _ = harness.request(
            "POST", f"/v1/workspaces/{workspace_id}/runner-pairings/{printed['pairing_id']}/approve",
            {"schema_version": "heel.runner-pairing-approve.v1",
             "pairing_phrase": view["pairing_phrase"], "fingerprint": view["fingerprint"]},
            cookie=cookie,
        )
        assert status == 200
    thread.join(30)
    assert not thread.is_alive()
    return events, outcome


def _home_bytes(home: Path) -> bytes:
    data = []
    for path in sorted(home.rglob("*")):
        if path.is_file():
            data.append(path.read_bytes())
    return b"\0".join(data)


def test_real_pairing_over_tls_edge_harness_activates_persists_heartbeats_and_revokes(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("owner-t2a@example.test")
    token = _invite(harness, workspace_id, cookie)
    home = _home(tmp_path, "runner-home")
    backend = RecordingSecretBackend()

    events, outcome = _pair_with_owner_approval(
        harness, _daemon(home, harness, backend), workspace_id, cookie, token,
    )
    assert "error" not in outcome, outcome
    paired = outcome["result"]
    assert [event["event"] for event in events] == ["pairing_pending", "paired"]
    assert paired["state"] == "active" and paired["workspace_id"] == workspace_id
    assert paired["origin"] == harness.origin
    runner_id, key_id = paired["runner_id"], paired["runner_key_id"]
    # Every runner call crossed the TLS edge; the edge injected its secret, the runner never held it.
    assert ("POST", "/v1/runner-pairings/exchange") in harness.forwarded
    assert ("POST", f"/v1/runner-pairings/{events[0]['pairing_id']}/activate") in harness.forwarded
    # The Ed25519 seed exists only in the (injected) OS secret backend under the pairing namespace.
    assert len(backend.values) == 1
    (label, seed), = backend.values.items()
    assert label.startswith(RUNNER_PAIRING_SIGNER_LABEL_PREFIX) and len(seed) == 32
    persisted = _home_bytes(home)
    for needle in (seed, base64.b64encode(seed), seed.hex().encode(), token.encode(),
                   harness.edge_secret.encode()):
        assert needle not in persisted
    # The cloud row was produced by the protocol: active runner with the runner's key.
    row = harness.control_plane.store.conn.execute(
        "SELECT status FROM canary_runners WHERE workspace_id=? AND runner_id=?", (workspace_id, runner_id),
    ).fetchone()
    assert tuple(row) == ("active",)

    # Process restart: a fresh daemon object re-reads the store and re-loads the same seed.
    restarted = _daemon(home, harness, backend)
    status = restarted.status()
    assert status["state"] == "active", status
    assert status["runner_id"] == runner_id and status["runner_key_id"] == key_id
    assert status["control_plane"]["state"] == "confirmed"
    assert status["control_plane"]["context_bindings"] == 0
    # A second live call proves the claim chain cursor advanced and persisted.
    assert _daemon(home, harness, backend).status()["control_plane"]["state"] == "confirmed"
    offline = _daemon(home, harness, backend).status(check_control_plane=False)
    assert offline["state"] == "active" and offline["control_plane"] == {"state": "not_checked"}
    assert offline["access"]["state"] == "access.incomplete"

    # Owner revokes through the browser session over HTTP (the reasoned-revocation POST, not a
    # server-side store call); the runner's next call must fail closed.
    revoke_path = f"/v1/workspaces/{workspace_id}/runners/{runner_id}/revoke"
    status_code, body, _ = harness.request("POST", revoke_path, REVOKE_BODY, cookie=cookie)
    assert (status_code, body) == (200, {"schema_version": "heel.runner-revoke-result.v1", "revoked": True})
    assert ("POST", revoke_path) in harness.forwarded
    owner = harness.request("GET", "/v1/me", cookie=cookie)[1]["user_id"]
    assert _revocation_audit(harness, workspace_id, runner_id) == [(owner, "human_revocation")]
    revoked = _daemon(home, harness, backend).status()
    assert revoked["state"] == "runner_revoked"
    assert revoked["control_plane"] == {"state": "rejected", "reason": "runner_revoked"}
    assert _daemon(home, harness, backend).status()["state"] == "runner_revoked"
    result = _daemon(home, harness, backend).unpair()
    assert result["state"] == "unpaired" and result["removed"] is True
    assert backend.values == {} and backend.deleted == [label]
    assert _daemon(home, harness, backend).status() == {"state": "unpaired"}


def _revocation_audit(harness, workspace_id, runner_id):
    return [tuple(row) for row in harness.control_plane.store.conn.execute(
        "SELECT actor, reason_code FROM canary_runner_audit_records "
        "WHERE workspace_id=? AND runner_id=? AND action='runner_revoked' ORDER BY created_at",
        (workspace_id, runner_id),
    )]


def _pair_runner(tmp_path, harness, workspace_id, cookie, name):
    home, backend = _home(tmp_path, name), RecordingSecretBackend()
    _, outcome = _pair_with_owner_approval(
        harness, _daemon(home, harness, backend), workspace_id, cookie, _invite(harness, workspace_id, cookie),
    )
    assert outcome["result"]["state"] == "active", outcome
    return home, backend, outcome["result"]["runner_id"]


def _raw_tls(harness, request: bytes) -> int:
    context = ssl.create_default_context(cafile=str(harness.ca.ca_path))
    with socket.create_connection(("127.0.0.1", harness.port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as tls:
            tls.sendall(request)
            head = tls.recv(4096)
    return int(head.split(b" ", 2)[1])


def _direct_backend(harness, method, path, body, headers):
    """Bypass the edge on purpose to pin the server's own framing order (never gate evidence)."""
    connection = http.client.HTTPConnection("127.0.0.1", harness.backend_port, timeout=10)
    try:
        connection.putrequest(method, path)
        for name, value in headers:
            connection.putheader(name, value)
        connection.endheaders(body)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def test_runner_revoke_is_post_only_same_origin_exact_body_and_bounded_at_edge_and_server(tmp_path, harness):
    """Replaces the T2a diagnostic that pinned the unreachable DELETE route."""
    workspace_id, cookie = harness.signup_owner("owner-revoke-route@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "runner")
    retired = f"/v1/workspaces/{workspace_id}/runners/{runner_id}"
    revoke_path = retired + "/revoke"
    refused = (400, {"error": "invalid control plane request"})

    # The retired DELETE is no longer allowlisted at the edge, with or without a body.
    sent = len(harness.forwarded)
    assert harness.request("DELETE", retired, cookie=cookie)[:2] == (404, {"error": "not found"})
    assert harness.request("DELETE", retired, REVOKE_BODY, cookie=cookie)[:2] == (404, {"error": "not found"})
    # Server semantics behind the edge: generic framing runs before route matching, so a
    # DELETE body is still ambiguous framing, while the bodiless retired route is unrouted.
    edge_auth = ("X-Heel-Edge-Auth", harness.edge_secret)
    body = json.dumps(REVOKE_BODY).encode()
    assert _direct_backend(harness, "DELETE", retired, body, [edge_auth, ("Content-Length", str(len(body)))]) == (
        400, {"error": "request body is not allowed", "code": "ambiguous_request_framing"})
    assert _direct_backend(harness, "DELETE", retired, None, [edge_auth]) == (404, {"error": "not found"})
    # Other methods on the new path are not allowlisted either.
    assert harness.request("GET", revoke_path, cookie=cookie)[:2] == (404, {"error": "not found"})
    assert harness.request("DELETE", revoke_path, cookie=cookie)[:2] == (404, {"error": "not found"})

    # Edge: browser same-origin ceremony, cookie-only credentials, POST body contract and cap.
    for options in (
        {"origin": "https://evil.example"}, {"origin": None}, {"fetch_site": None},
        {"fetch_site": "cross-site"}, {"fetch_site": "same-site"}, {"cookie": None},
        {"headers": {"Authorization": "Bearer heel_sk_" + "a" * 32}},
        {"headers": {"Content-Type": "text/plain"}},
        {"headers": {"Content-Encoding": "gzip"}},
        {"raw": b'{"schema_version":"heel.runner-revoke.v1","reason_code":"' + b"x" * (16 * 1024) + b'"}'},
    ):
        options = {"cookie": cookie, **options}
        payload = None if "raw" in options else REVOKE_BODY
        assert harness.request("POST", revoke_path, payload, **options)[:2] == refused, options
    origin = harness.origin.encode()
    head = (b"POST " + revoke_path.encode() + b" HTTP/1.1\r\nHost: localhost\r\nOrigin: " + origin
            + b"\r\nSec-Fetch-Site: same-origin\r\nCookie: " + cookie.encode()
            + b"\r\nContent-Type: application/json\r\n")
    assert _raw_tls(harness, head + b"Content-Length: %d\r\nContent-Length: %d\r\n\r\n" % (len(body), len(body)) + body) == 400
    assert _raw_tls(harness, head + b"Transfer-Encoding: chunked\r\n\r\n%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n") == 400
    assert harness.forwarded[sent:] == [], "edge refusals must not reach the control plane"

    # Server, behind a satisfied edge: the exact closed body schema, checked after the ceremony.
    invalid = (400, {"error": "invalid runner revocation", "code": "invalid_runner_revocation"})
    for candidate in (
        {}, {"schema_version": "heel.runner-revoke.v1"},
        {"schema_version": "heel.runner-revoke.v2", "reason_code": "human_revocation"},
        {**REVOKE_BODY, "extra": True}, {"schema_version": "heel.runner-revoke.v1", "reason_code": 7},
        {"schema_version": "heel.runner-revoke.v1", "reason_code": ""},
        {"schema_version": "heel.runner-revoke.v1", "reason_code": " human_revocation"},
        {"schema_version": "heel.runner-revoke.v1", "reason_code": "r" * 129},
    ):
        assert harness.request("POST", revoke_path, candidate, cookie=cookie)[:2] == invalid, candidate
    assert harness.request("POST", revoke_path, raw=b"{not json", cookie=cookie)[:2] == (400, {"error": "invalid JSON body"})
    assert harness.request("POST", revoke_path, raw=b"", cookie=cookie)[:2] == invalid
    assert harness.request(
        "POST", revoke_path, raw=b'{"schema_version":"heel.runner-revoke.v1","reason_code":"a","reason_code":"b"}',
        cookie=cookie,
    )[:2] == (400, {"error": "invalid JSON body"})
    assert _revocation_audit(harness, workspace_id, runner_id) == []
    assert _daemon(home, harness, backend).status()["state"] == "active"

    status, body_out, _ = harness.request(
        "POST", revoke_path, {"schema_version": "heel.runner-revoke.v1", "reason_code": "device_lost"}, cookie=cookie,
    )
    assert (status, body_out) == (200, {"schema_version": "heel.runner-revoke-result.v1", "revoked": True})
    owner = harness.request("GET", "/v1/me", cookie=cookie)[1]["user_id"]
    assert _revocation_audit(harness, workspace_id, runner_id) == [(owner, "device_lost")]
    assert _daemon(home, harness, backend).status()["state"] == "runner_revoked"


def test_http_runner_revoke_retries_and_other_workspaces_have_no_effect(tmp_path, harness):
    """Replaces the T2a direct ``RunnerAuthStore.revoke`` diagnostic with real HTTP revocation."""
    workspace_id, cookie = harness.signup_owner("owner-revoke-scope@example.test")
    other_workspace, other_cookie = harness.signup_owner("owner-revoke-other@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "runner")
    # The free plan allows one active runner per workspace, so the bystander lives in workspace B.
    other_home, other_backend, other_id = _pair_runner(tmp_path, harness, other_workspace, other_cookie, "other")
    (label,) = backend.values
    revoke_path = f"/v1/workspaces/{workspace_id}/runners/{runner_id}/revoke"
    invalid = (400, {"error": "invalid runner revocation", "code": "invalid_runner_revocation"})

    # Another workspace's owner cannot revoke it, through either workspace's path.
    assert harness.request("POST", revoke_path, REVOKE_BODY, cookie=other_cookie)[:2] == (
        403, {"error": "a recent owner or admin browser session is required", "code": "recent_auth_required"})
    assert harness.request(
        "POST", f"/v1/workspaces/{other_workspace}/runners/{runner_id}/revoke", REVOKE_BODY, cookie=other_cookie,
    )[:2] == invalid
    # Nor can this owner revoke workspace B's runner through workspace A's path.
    assert harness.request(
        "POST", f"/v1/workspaces/{workspace_id}/runners/{other_id}/revoke", REVOKE_BODY, cookie=cookie,
    )[:2] == invalid
    assert _daemon(home, harness, backend).status()["state"] == "active"

    assert harness.request("POST", revoke_path, REVOKE_BODY, cookie=cookie)[:2] == (
        200, {"schema_version": "heel.runner-revoke-result.v1", "revoked": True})
    # A retry is refused and has no second effect.
    assert harness.request("POST", revoke_path, REVOKE_BODY, cookie=cookie)[:2] == invalid
    owner = harness.request("GET", "/v1/me", cookie=cookie)[1]["user_id"]
    assert _revocation_audit(harness, workspace_id, runner_id) == [(owner, "human_revocation")]
    revoked = _daemon(home, harness, backend).status()
    assert revoked["control_plane"] == {"state": "rejected", "reason": "runner_revoked"}
    # It stays rejected after another restart (the staged call is replayed, never re-signed).
    assert _daemon(home, harness, backend).status()["state"] == "runner_revoked"
    # Workspace B's runner is untouched.
    assert _daemon(other_home, harness, other_backend).status()["state"] == "active"
    assert _revocation_audit(harness, other_workspace, other_id) == []
    result = _daemon(home, harness, backend).unpair()
    assert result["state"] == "unpaired" and result["removed"] is True
    assert backend.values == {} and backend.deleted == [label]
    assert _daemon(home, harness, backend).status() == {"state": "unpaired"}


def test_runner_pair_cli_refuses_reused_invitation_and_wrong_origin(tmp_path, harness, monkeypatch):
    workspace_id, cookie = harness.signup_owner("owner-reuse@example.test")
    token = _invite(harness, workspace_id, cookie)

    # CLI: a non-https or non-canonical origin is refused before any local or network effect.
    cli_home = _home(tmp_path, "cli-home")
    monkeypatch.setenv("HEEL_HOME", str(cli_home))
    port = harness.port
    for origin in (
        f"http://localhost:{port}", f"https://localhost:{port}/", f"https://localhost:{port}/v1",
        f"https://user@localhost:{port}", f"https://LOCALHOST:{port}", "https://localhost:443",
        f"https://localhost.:{port}", f"https://localhost:{port}?x=1", f"https://localhost:{port}#f",
        "https://[::1]:8443", "ftp://localhost", f"https://localhost:0{port}", "https://exa mple.test",
    ):
        code, out, err = _invoke("runner", "pair", "--origin", origin, "--invite", token)
        assert (code, out, err) == (2, "", "Heel runner pairing failed: invalid_origin.\n"), origin
    for bad in ("short", token + "A", token[:-1] + "!", token.replace("=", "")):
        code, out, err = _invoke("runner", "pair", "--origin", harness.origin, "--invite", bad)
        assert (code, out, err) == (2, "", "Heel runner pairing failed: invalid_invitation.\n")
    assert not (cli_home / "runner-daemon").exists()

    # Wrong origin for the edge certificate (127.0.0.1 is not the certified name): TLS refuses,
    # nothing persists and the freshly created seed is removed again.
    wrong_home, wrong_backend = _home(tmp_path, "wrong"), RecordingSecretBackend()
    wrong = RunnerDaemon(wrong_home, secret_backend=wrong_backend, ca_bundle=harness.ca.ca_path)
    with pytest.raises(RunnerPairingError) as refused:
        wrong.pair(f"https://127.0.0.1:{port}", token)
    assert refused.value.code == "tls_trust_failed"
    assert wrong_backend.values == {} and wrong.status() == {"state": "unpaired"}

    # First use of the invitation pairs runner A.
    home_a, backend_a = _home(tmp_path, "runner-a"), RecordingSecretBackend()
    _, outcome = _pair_with_owner_approval(harness, _daemon(home_a, harness, backend_a), workspace_id, cookie, token)
    assert outcome["result"]["state"] == "active"
    # Pairing the same home again is refused locally, before any network call.
    sent = len(harness.forwarded)
    with pytest.raises(RunnerPairingError) as again:
        _daemon(home_a, harness, backend_a).pair(harness.origin, token)
    assert again.value.code == "already_paired" and len(harness.forwarded) == sent

    # Reusing the one-time invitation from another machine is rejected by the control plane.
    home_b, backend_b = _home(tmp_path, "runner-b"), RecordingSecretBackend()
    with pytest.raises(RunnerPairingError) as reused:
        _daemon(home_b, harness, backend_b).pair(harness.origin, token)
    assert reused.value.code == "invitation_rejected"
    assert token not in str(reused.value)
    assert backend_b.values == {} and _daemon(home_b, harness, backend_b).status() == {"state": "unpaired"}
    count = harness.control_plane.store.conn.execute(
        "SELECT COUNT(*) FROM canary_runners WHERE workspace_id=?", (workspace_id,),
    ).fetchone()[0]
    assert count == 1


def test_unapproved_pairing_times_out_fails_closed_and_unpair_allows_a_fresh_invitation(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("owner-timeout@example.test")
    token = _invite(harness, workspace_id, cookie)
    home, backend = _home(tmp_path, "runner"), RecordingSecretBackend()
    clock = {"now": int(time.time() * 1000)}

    def sleep(_seconds):
        clock["now"] += 11 * 60 * 1000  # past the ten minute challenge

    daemon = _daemon(home, harness, backend, clock_ms=lambda: clock["now"], sleep=sleep)
    with pytest.raises(RunnerPairingError) as expired:
        daemon.pair(harness.origin, token)
    assert expired.value.code == "approval_timeout"
    status = _daemon(home, harness, backend).status()
    assert status["state"] == "pairing_incomplete" and "heel runner unpair" in status["next_steps"]
    fresh = _invite(harness, workspace_id, cookie)
    sent = len(harness.forwarded)
    with pytest.raises(RunnerPairingError) as blocked:
        _daemon(home, harness, backend).pair(harness.origin, fresh)
    assert blocked.value.code == "pairing_incomplete" and len(harness.forwarded) == sent
    assert _daemon(home, harness, backend).unpair()["removed"] is True
    assert backend.values == {}
    # The refused attempt never spent the fresh invitation, so it still pairs.
    _, outcome = _pair_with_owner_approval(harness, _daemon(home, harness, backend), workspace_id, cookie, fresh)
    assert outcome["result"]["state"] == "active"


def test_pair_without_a_supported_secret_service_fails_closed_without_file_fallback(tmp_path, monkeypatch):
    # The Linux helper is pinned to /usr/bin/secret-tool; moving the constant out of the
    # allowlist makes the real backend unavailable on every platform.
    monkeypatch.setattr("heel.runner.identity._LINUX_SECRET_TOOL_PATH", "/nonexistent/secret-tool")
    home = _home(tmp_path, "no-secrets")
    daemon = RunnerDaemon(home, secret_backend=LinuxSecretServiceBackend())
    with pytest.raises(RunnerPairingError) as refused:
        daemon.pair("https://heel.example", "A" * 43 + "=")
    assert refused.value.code == "no_supported_secret_service"
    assert str(refused.value) == "no supported runner OS secret service"
    assert daemon.status() == {"state": "unpaired"}
    assert not any(path.name.endswith((".key", ".seed")) for path in home.rglob("*"))
    assert not (home / "runner" / "paired-identity.json").exists()


def test_pair_refuses_a_secret_store_that_does_not_return_the_stored_seed(tmp_path):
    class LossyBackend(RecordingSecretBackend):
        # Mirrors the observed real-Keychain failure: store "succeeds", the item is empty.
        def store(self, label, seed):
            super().store(label, b"")

        def load(self, label):
            return None if label not in self.values else b""

    home, backend = _home(tmp_path, "lossy"), LossyBackend()
    daemon = RunnerDaemon(home, secret_backend=backend)
    with pytest.raises(RunnerPairingError) as refused:
        daemon.pair("https://heel.example", "A" * 43 + "=")  # never reaches the network
    assert refused.value.code == "secret_store_unverified"
    assert backend.values == {} and len(backend.deleted) == 1
    assert daemon.status() == {"state": "unpaired"}


def test_cli_paths_cannot_select_an_in_memory_backend_or_a_ca_bundle():
    # The CLI constructs the daemon with defaults only; neither seam is reachable from argv.
    for function in (cli._runner_pair, cli._runner_status, cli._runner_unpair):
        source = inspect.getsource(function)
        assert "RunnerDaemon()" in source
        assert "ca_bundle" not in source and "secret_backend" not in source
    default = RunnerDaemon()
    assert default._secret_backend is None and default._ca_bundle is None
    for module in (daemon_module, control_transport):
        source = inspect.getsource(module)
        assert "os.environ" not in source and "getenv" not in source
        assert "InMemorySecretBackend" not in source and "PYTEST_CURRENT_TEST" not in source
    code, _, err = _invoke("runner", "pair", "--origin", "https://heel.example", "--invite",
                           "A" * 43 + "=", "--ca-bundle", "/tmp/ca.pem")
    assert (code, err) == (2, "Heel runner command was rejected.\n")


def test_seed_removal_uses_only_the_fixed_os_helpers(monkeypatch):
    calls = []

    class Completed:
        def __init__(self, code): self.returncode = code

    monkeypatch.setattr(
        "heel.runner.identity._run_bounded_security",
        lambda arguments, *, payload, popen: calls.append(("security", arguments, payload)) or Completed(44),
    )
    monkeypatch.setattr(
        "heel.runner.identity._run_bounded_secret_tool",
        lambda arguments, *, payload, popen: calls.append(("secret-tool", arguments, payload)) or Completed(0),
    )
    label = RUNNER_PAIRING_SIGNER_LABEL_PREFIX + "a" * 32
    daemon_module._delete_signer_seed(MacOSKeychainSecretBackend(), label)
    daemon_module._delete_signer_seed(LinuxSecretServiceBackend(), label)
    assert calls == [
        ("security", ("delete-generic-password", "-s", "heel.runner.ed25519.v1", "-a", label), None),
        ("secret-tool", ("clear", "heel", "runner", "label", label), None),
    ]
    with pytest.raises(RuntimeError):
        daemon_module._delete_signer_seed(object(), label)


def test_self_serve_access_requires_both_plan_labels_and_never_infers_them(tmp_path):
    from tests.test_runner_cli import bind_home

    home = _home(tmp_path, "access")
    bind_home(home)
    store = RunnerStore(home)
    missing = self_serve_access(store)
    assert missing["state"] == "access.incomplete" and missing["reason"] == "credential_missing"
    assert len(missing["next_steps"]) == 2
    assert "--role lower_plan --plan-label <your lower-plan name>" in missing["next_steps"][0]
    # A legacy record without a plan label is usable by the CLI but not by the self-serve path.
    store.register_ephemeral_credential(
        semantic_role="lower_plan", auth_profile="bearer", source_kind="environment", label="free",
    )
    store.register_ephemeral_credential(
        semantic_role="higher_plan", auth_profile="bearer", source_kind="environment", label="pro",
        plan_label="pro",
    )
    partial = self_serve_access(RunnerStore(home))
    assert partial["state"] == "access.incomplete" and partial["reason"] == "plan_label_missing"
    assert partial["plan_labels"] == [{"role": "higher_plan", "label": "pro"}]
    assert "credential_handle" not in json.dumps(partial)


# --------------------------------------------------------------------------- transport


def _invoke(*arguments):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main(list(arguments))
    return code, stdout.getvalue(), stderr.getvalue()


@pytest.fixture
def ca(tmp_path):
    return EphemeralCA(tmp_path / "scripted-ca")


@contextlib.contextmanager
def scripted(ca, responder, **options):
    server = ScriptedTLSServer(ca, responder, **options)
    try:
        yield server
    finally:
        server.close()


def _post(transport):
    return transport.post("/v1/runner-pairings/exchange", headers={"Content-Type": "application/json"}, body=b"{}")


def test_transport_accepts_bounded_json_and_exposes_only_known_headers(ca):
    nonce = base64.b64encode(b"n" * 32).decode()
    response = raw_json_response(200, b'{"ok":true}', extra=(
        ("x-heel-runner-next-nonce", nonce), ("Set-Cookie", "a=b"), ("X-Other", "1"),
    ))
    with scripted(ca, lambda _path: response) as server:
        transport = HTTPSControlTransport(server.origin, ca_bundle=ca.ca_path)
        assert _post(transport) == (200, {"X-Heel-Runner-Next-Nonce": nonce}, {"ok": True})
        path, headers, body = server.requests[0]
        assert path == "/v1/runner-pairings/exchange" and body == b"{}"
        assert headers["Host"] == f"localhost:{server.port}"
        assert not {"Cookie", "Authorization", "X-Heel-Edge-Auth"} & set(headers)
    with scripted(ca, lambda _path: b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n") as server:
        assert _post(HTTPSControlTransport(server.origin, ca_bundle=ca.ca_path)) == (204, {}, None)


@pytest.mark.parametrize("response, code", [
    (b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/v1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
     "redirect_refused"),
    (b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://localhost/v1/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
     "redirect_refused"),
    (raw_json_response(200, b"{" + b'"a":"' + b"x" * MAX_CONTROL_RESPONSE_BYTES + b'"}'), "response_too_large"),
    (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
     + b"".join(b"4000\r\n" + b" " * 0x4000 + b"\r\n" for _ in range(17)) + b"0\r\n\r\n", "response_too_large"),
    (raw_json_response(200, b"{bad json SECRET-MARKER}"), "malformed_response"),
    (raw_json_response(200, b'{"a":1,"a":2}'), "malformed_response"),
    (raw_json_response(200, b'{"a":NaN}'), "malformed_response"),
    (raw_json_response(200, b'["SECRET-MARKER"]'), "malformed_response"),
    (raw_json_response(200, b'{"a":1}', content_type="text/html"), "malformed_response"),
    (raw_json_response(200, b'\xff\xfe'), "malformed_response"),
    (raw_json_response(200, b'{"a":1}', extra=(("X-Heel-Runner-Next-Nonce", "a"), ("X-Heel-Runner-Next-Nonce", "b"))),
     "malformed_response"),
    (b"HTTP/1.1 204 No Content\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}", "malformed_response"),
    (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 999999999\r\nConnection: close\r\n\r\n",
     "response_too_large"),
    (b"NOT HTTP SECRET-MARKER\r\n\r\n", "connection_failed"),
], ids=[
    "redirect-302", "redirect-307-to-http", "oversized-length", "oversized-chunked", "bad-json",
    "duplicate-key", "nan", "non-object", "wrong-media-type", "invalid-utf8", "duplicate-nonce",
    "204-with-body", "declared-oversize", "not-http",
])
def test_transport_refuses_redirects_oversized_and_malformed_responses_with_secret_safe_errors(ca, response, code):
    with scripted(ca, lambda _path: response) as server:
        transport = HTTPSControlTransport(server.origin, ca_bundle=ca.ca_path)
        with pytest.raises(ControlTransportError) as refused:
            _post(transport)
        assert refused.value.code == code
        rendered = f"{refused.value!s} {refused.value!r} {refused.value.args!r}"
        assert "SECRET-MARKER" not in rendered and "evil" not in rendered
        assert refused.value.__cause__ is None
        assert refused.value.__context__ is None or refused.value.__suppress_context__
        assert len(server.requests) == 1  # never followed or retried


def test_transport_enforces_one_deadline_against_a_trickling_peer(ca):
    response = raw_json_response(200, b'{"slow":"' + b"x" * 64 + b'"}')
    with scripted(ca, lambda _path: response, delay_seconds=0.05) as server:
        transport = HTTPSControlTransport(server.origin, ca_bundle=ca.ca_path, timeout_seconds=0.5)
        started = time.monotonic()
        with pytest.raises(ControlTransportError) as refused:
            _post(transport)
        assert refused.value.code == "timeout"
        assert time.monotonic() - started < 3
    with pytest.raises(ValueError):
        HTTPSControlTransport("https://heel.example", timeout_seconds=31)


def test_transport_tls_trust_failures_fail_closed(ca, tmp_path):
    response = raw_json_response(200, b'{"ok":true}')
    with scripted(ca, lambda _path: response) as server:
        # System trust does not include the ephemeral CA.
        with pytest.raises(ControlTransportError) as system:
            _post(HTTPSControlTransport(server.origin))
        assert system.value.code == "tls_trust_failed"
        # A different explicit CA is not trusted either.
        other = EphemeralCA(tmp_path / "other-ca")
        with pytest.raises(ControlTransportError) as foreign:
            _post(HTTPSControlTransport(server.origin, ca_bundle=other.ca_path))
        assert foreign.value.code == "tls_trust_failed"
        # The certificate names localhost, not the IP literal.
        with pytest.raises(ControlTransportError) as name:
            _post(HTTPSControlTransport(f"https://127.0.0.1:{server.port}", ca_bundle=ca.ca_path))
        assert name.value.code == "tls_trust_failed"
        assert server.requests == []
    if hasattr(ssl, "TLSVersion"):
        try:
            legacy = ca.server_context(minimum=ssl.TLSVersion.TLSv1, maximum=ssl.TLSVersion.TLSv1_1)
        except (ssl.SSLError, ValueError):
            legacy = None
        if legacy is not None:
            with contextlib.suppress(ssl.SSLError, OSError, ValueError):
                with scripted(ca, lambda _path: response, context=legacy) as server:
                    with pytest.raises(ControlTransportError) as downgraded:
                        _post(HTTPSControlTransport(server.origin, ca_bundle=ca.ca_path))
                    assert downgraded.value.code == "tls_trust_failed"
                    assert server.requests == []
    with pytest.raises(ValueError):
        HTTPSControlTransport("https://heel.example", ca_bundle="relative/ca.pem")


def test_transport_refuses_url_confusion_header_injection_and_plain_http(ca):
    response = raw_json_response(200, b'{"ok":true}')
    with scripted(ca, lambda _path: response) as server:
        transport = HTTPSControlTransport(server.origin, ca_bundle=ca.ca_path)
        for path in (
            "https://evil.example/v1/x", "//evil.example/v1/x", "/v1/../admin", "/v1/./x", "/v1/x?y=1",
            "/v1/x#y", "/v1/%2e%2e/x", "/v1/x\r\nHost: evil", "/v1//x", "/v2/x", "v1/x", "/v1/x y",
            "/v1/é", "/v1/x\\y", "/v1/" + "a" * 600,
        ):
            with pytest.raises(ControlTransportError) as refused:
                transport.post(path, headers={}, body=b"{}")
            assert refused.value.code == "invalid_request", path
        for headers in (
            {"X-Test": "a\r\nX-Injected: 1"}, {"X-Test": "a\nb"}, {"X-Test": "\x00"}, {"Bad Name": "x"},
            {"Host": "evil.example"}, {"Cookie": "heel_session=x"}, {"Authorization": "Bearer x"},
            {"X-Heel-Edge-Auth": "x"}, {"Content-Length": "0"}, {"Transfer-Encoding": "chunked"},
            {"Origin": "https://evil.example"}, {"X-Test": " leading"}, {"X-Test": "é"},
            {"x-test": "1", "X-Test": "2"},
        ):
            with pytest.raises(ControlTransportError) as refused:
                transport.post("/v1/runner-pairings/exchange", headers=headers, body=b"{}")
            assert refused.value.code == "invalid_request", headers
        with pytest.raises(ControlTransportError):
            transport.post("/v1/x", headers={}, body="{}")
        assert server.requests == []
    for origin in ("http://localhost:1", "HTTPS://heel.example", "https://heel.example/", "https://heel.example:443",
                   "https://a@heel.example", "https://heel.example:99999", "https://", "https://heel_example",
                   "https://heel.example\n", "https://xn--hl-cia.exampleé"):
        with pytest.raises(ControlTransportError) as refused:
            validate_control_origin(origin)
        assert refused.value.code == "invalid_origin"
    assert validate_control_origin("https://heel.example") == ("https://heel.example", "heel.example", 443)
    assert validate_control_origin("https://localhost:8443") == ("https://localhost:8443", "localhost", 8443)


def test_transport_never_reaches_a_plain_http_listener(tmp_path):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    received = []

    def serve_plain():
        try:
            connection, _ = listener.accept()
        except OSError:
            return
        with connection:
            connection.settimeout(2)
            with contextlib.suppress(OSError):
                received.append(connection.recv(4096))
                connection.sendall(raw_json_response(200, b'{"ok":true}'))

    thread = threading.Thread(target=serve_plain, daemon=True)
    thread.start()
    try:
        transport = HTTPSControlTransport(f"https://localhost:{port}", timeout_seconds=2)
        with pytest.raises(ControlTransportError) as refused:
            _post(transport)
        assert refused.value.code in {"tls_trust_failed", "connection_failed"}
        # Only a TLS ClientHello was written; no HTTP request bytes reached the plain listener.
        assert all(b"POST" not in chunk for chunk in received)
    finally:
        listener.close()
        thread.join(3)
