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
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from heel import cli
from heel.canary_contracts import canonical_bytes
from heel.crypto import SigningAuthority, ed25519_key_id, load_public_key_base64, verify_envelope
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
from heel.runner.store import RunnerStore, RunnerStoreError
from heel.saas.tenancy import hash_api_key
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
    # T2b-1: the record holds the control plane's own grant-signing public key, delivered inside the
    # approved activation (no seeding, no separate fetch), and its key ID is derived from the key.
    record = _daemon_record(home)
    cloud = harness.control_plane.grant_authority
    assert record["grant_authority_key_id"] == cloud.key_id
    assert record["grant_authority_public_key_b64"] == cloud.canonical_public_key
    public_key = base64.b64decode(record["grant_authority_public_key_b64"], validate=True)
    assert ed25519_key_id(public_key) == record["grant_authority_key_id"]
    _assert_record_key_verifies_context_bindings(harness, record, workspace_id, runner_id, key_id)

    # Process restart: a fresh daemon object re-reads the store and re-loads the same seed.
    restarted = _daemon(home, harness, backend)
    status = restarted.status()
    assert status["state"] == "active", status
    assert status["runner_id"] == runner_id and status["runner_key_id"] == key_id
    assert status["grant_authority_key_id"] == cloud.key_id
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
    # T2b2R1: the refused fresh resync is reported as an authentication rejection, never as a
    # proven revocation (the server answers a wrong clock the same way).
    revoked = _daemon(home, harness, backend).status()
    assert revoked["state"] == "runner_authentication_rejected"
    assert revoked["control_plane"] == {"state": "rejected", "reason": "runner_authentication_rejected"}
    assert _daemon(home, harness, backend).status()["state"] == "runner_authentication_rejected"
    result = _daemon(home, harness, backend).unpair()
    assert result["state"] == "unpaired" and result["removed"] is True
    assert backend.values == {} and backend.deleted == [label]
    assert _daemon(home, harness, backend).status() == {"state": "unpaired"}


def _assert_record_key_verifies_context_bindings(harness, record, workspace_id, runner_id, runner_key_id):
    """The persisted key verifies a context-binding signature made by the control plane's binding
    service (the service the coordinator's binding claim relies on) and nothing signed by another key."""
    from heel.saas.runner_contexts import CONTEXT_DOMAIN  # noqa: PLC0415 - server-side test import only
    trusted = {record["grant_authority_key_id"]: load_public_key_base64(record["grant_authority_public_key_b64"])}
    unsigned = {"schema_version": "heel.runner-context-binding.v1", "workspace_id": workspace_id,
                "runner_binding": {"runner_id": runner_id, "runner_key_id": runner_key_id}}
    payload = CONTEXT_DOMAIN + canonical_bytes(unsigned)
    signing = harness.control_plane.runner_contexts.signing
    assert signing is harness.control_plane.grant_authority
    verify_envelope(trusted, signing.sign(payload), payload)
    with pytest.raises(ValueError):
        verify_envelope(trusted, SigningAuthority.generate().sign(payload), payload)
    with pytest.raises(ValueError):
        verify_envelope(trusted, signing.sign(payload), payload + b"x")


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
    assert _daemon(home, harness, backend).status()["state"] == "runner_authentication_rejected"


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
    assert revoked["control_plane"] == {"state": "rejected", "reason": "runner_authentication_rejected"}
    # It stays rejected after another restart: the staged call is replayed (never re-signed) and
    # the one fresh resync per check is refused again; no authority comes back.
    assert _daemon(home, harness, backend).status()["state"] == "runner_authentication_rejected"
    # Workspace B's runner is untouched.
    assert _daemon(other_home, harness, other_backend).status()["state"] == "active"
    assert _revocation_audit(harness, other_workspace, other_id) == []
    result = _daemon(home, harness, backend).unpair()
    assert result["state"] == "unpaired" and result["removed"] is True
    assert backend.values == {} and backend.deleted == [label]
    assert _daemon(home, harness, backend).status() == {"state": "unpaired"}


def _session_revoked_at(harness, cookie):
    token = cookie.split("=", 1)[1]
    (revoked_at,), = harness.control_plane.auth.conn.execute(
        "SELECT revoked_at FROM sessions WHERE token_hash=?", (hash_api_key(token),),
    ).fetchall()
    return revoked_at


def _runner_rows(harness, workspace_id):
    return sorted(tuple(row) for row in harness.control_plane.store.conn.execute(
        "SELECT runner_id, status FROM canary_runners WHERE workspace_id=?", (workspace_id,),
    ))


def test_edge_harness_logout_forwards_the_cookie_and_revokes_the_session(tmp_path, harness):
    """Like the Worker, logout carries the session cookie upstream, so the session really ends."""
    workspace_id, cookie = harness.signup_owner("owner-logout@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "runner")
    status, _, _ = harness.request("GET", "/v1/me", cookie=cookie)
    assert status == 200 and _session_revoked_at(harness, cookie) is None

    status, body, set_cookie = harness.request("POST", "/v1/logout", {}, cookie=cookie)
    assert (status, body) == (200, {"ok": True})
    assert set_cookie == "heel_session=; Max-Age=0; Path=/"
    assert harness.forwarded[-1] == ("POST", "/v1/logout")
    assert _session_revoked_at(harness, cookie) is not None

    # The old cookie is refused afterwards, for reads and for the owner's revoke ceremony.
    assert harness.request("GET", "/v1/me", cookie=cookie)[0] == 401
    revoke_path = f"/v1/workspaces/{workspace_id}/runners/{runner_id}/revoke"
    assert harness.request("POST", revoke_path, REVOKE_BODY, cookie=cookie)[:2] == (
        403, {"error": "a recent owner or admin browser session is required", "code": "recent_auth_required"})
    assert ("POST", revoke_path) in harness.forwarded
    assert _revocation_audit(harness, workspace_id, runner_id) == []
    assert _daemon(home, harness, backend).status()["state"] == "active"


def test_real_pair_revoke_unpair_and_fresh_invitation_pairs_again_over_tls(tmp_path, harness):
    """Owner HTTP revocation frees the plan's runner slot, so a re-pair after unpair activates."""
    workspace_id, cookie = harness.signup_owner("owner-repair@example.test")
    other_workspace, other_cookie = harness.signup_owner("owner-repair-other@example.test")
    other_home, other_backend, other_id = _pair_runner(tmp_path, harness, other_workspace, other_cookie, "other")
    home, backend, first_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "runner")
    (first_label,) = backend.values
    assert _daemon(home, harness, backend).status()["control_plane"]["state"] == "confirmed"

    revoke_path = f"/v1/workspaces/{workspace_id}/runners/{first_id}/revoke"
    assert harness.request("POST", revoke_path, REVOKE_BODY, cookie=cookie)[:2] == (
        200, {"schema_version": "heel.runner-revoke-result.v1", "revoked": True})
    assert ("POST", revoke_path) in harness.forwarded
    assert _daemon(home, harness, backend).status()["state"] == "runner_authentication_rejected"
    result = _daemon(home, harness, backend).unpair()
    assert result["state"] == "unpaired" and result["removed"] is True
    assert backend.values == {} and backend.deleted == [first_label]

    # A fresh invitation pairs the same home again through the full exchange/approve/activate
    # flow; activation is not refused by the runner quota because the old row is revoked.
    events, outcome = _pair_with_owner_approval(
        harness, _daemon(home, harness, backend), workspace_id, cookie, _invite(harness, workspace_id, cookie),
    )
    assert "error" not in outcome, outcome
    assert [event["event"] for event in events] == ["pairing_pending", "paired"]
    second_id = outcome["result"]["runner_id"]
    assert outcome["result"]["state"] == "active" and second_id != first_id
    assert ("POST", f"/v1/runner-pairings/{events[0]['pairing_id']}/activate") in harness.forwarded
    (second_label,) = backend.values
    assert second_label != first_label
    status = _daemon(home, harness, backend).status()
    assert status["state"] == "active" and status["runner_id"] == second_id
    assert status["control_plane"]["state"] == "confirmed"
    assert _runner_rows(harness, workspace_id) == sorted([(first_id, "revoked"), (second_id, "active")])

    # The bystander in another workspace was never touched.
    assert _daemon(other_home, harness, other_backend).status()["state"] == "active"
    assert _runner_rows(harness, other_workspace) == [(other_id, "active")]
    assert _revocation_audit(harness, other_workspace, other_id) == []


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


class GatedSecretBackend(RecordingSecretBackend):
    """Holds the first ``store`` (after the pair record is reserved) until released."""

    def __init__(self):
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()
        self._gated = True

    def store(self, label, seed):
        if self._gated:
            self._gated = False
            self.entered.set()
            assert self.release.wait(30)
        super().store(label, seed)


def _server_runner_statuses(harness, workspace_id):
    rows = harness.control_plane.store.conn.execute(
        "SELECT status FROM canary_runners WHERE workspace_id=?", (workspace_id,),
    ).fetchall()
    return sorted(row[0] for row in rows)


def _daemon_record(home):
    path = home / "runner-daemon" / "pairing.json"
    return json.loads(path.read_text()) if path.exists() else None


@pytest.mark.parametrize("invitations", ["same", "distinct"])
def test_concurrent_pair_attempts_never_clobber_an_active_pairing(tmp_path, harness, invitations):
    # T2aR D5: B passed the local checks, was descheduled, A paired, then B overwrote and removed A's record.
    workspace_id, cookie = harness.signup_owner(f"owner-race-{invitations}@example.test")
    token_a = _invite(harness, workspace_id, cookie)
    tokens = {"b": token_a}
    home, backend = _home(tmp_path, "race"), RecordingSecretBackend()
    a_done, b_checked = threading.Event(), threading.Event()

    class DescheduledDaemon(RunnerDaemon):
        def _backend(self):
            b_checked.set()
            assert a_done.wait(30)  # after the early already-paired check, before the reservation
            return super()._backend()

    b = DescheduledDaemon(home, secret_backend=backend, ca_bundle=harness.ca.ca_path, poll_interval_seconds=0.05)
    b_outcome = {}

    def run_b():
        try:
            b_outcome["result"] = b.pair(harness.origin, tokens["b"])
        except RunnerPairingError as error:
            b_outcome["error"] = error.code
        except BaseException as error:  # surfaced by the equality assertion below
            b_outcome["unexpected"] = repr(error)

    thread = threading.Thread(target=run_b, daemon=True)
    thread.start()
    assert b_checked.wait(30)
    _, outcome = _pair_with_owner_approval(harness, _daemon(home, harness, backend), workspace_id, cookie, token_a)
    assert outcome["result"]["state"] == "active"
    record_a = _daemon_record(home)
    if invitations == "distinct":
        # The workspace holds one open invitation at a time; B's is minted once A's is spent.
        tokens["b"] = _invite(harness, workspace_id, cookie)
    sent = len(harness.forwarded)
    a_done.set()
    thread.join(30)
    assert not thread.is_alive()
    assert b_outcome == {"error": "already_paired"}
    assert len(harness.forwarded) == sent  # B never reached the cloud
    assert _daemon_record(home) == record_a
    assert len(backend.values) == 1 and backend.deleted == []
    status = _daemon(home, harness, backend).status()
    assert status["state"] == "active" and status["control_plane"]["state"] == "confirmed"
    assert status["runner_id"] == outcome["result"]["runner_id"]
    assert _server_runner_statuses(harness, workspace_id) == ["active"]
    assert _daemon(home, harness, backend).unpair()["removed"] is True
    assert backend.values == {} and _daemon_record(home) is None


def test_a_reserved_incomplete_pairing_blocks_a_second_attempt_until_it_completes(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("owner-reserved@example.test")
    token_b = _invite(harness, workspace_id, cookie)
    token_a = "A" * 43 + "="  # refused locally before any use, so it need not be a live invitation
    home, backend = _home(tmp_path, "reserved"), GatedSecretBackend()
    result = {}
    first = threading.Thread(target=lambda: result.update(pair=_pair_with_owner_approval(
        harness, _daemon(home, harness, backend), workspace_id, cookie, token_b)), daemon=True)
    first.start()
    assert backend.entered.wait(30)
    reserved = _daemon_record(home)
    assert reserved["state"] == "preparing"
    sent = len(harness.forwarded)
    with pytest.raises(RunnerPairingError) as blocked:
        _daemon(home, harness, backend).pair(harness.origin, token_a)
    assert blocked.value.code == "pairing_incomplete"
    assert len(harness.forwarded) == sent and backend.values == {}
    assert _daemon_record(home) == reserved
    assert _daemon(home, harness, backend).status()["state"] == "pairing_incomplete"
    backend.release.set()
    first.join(60)
    assert result["pair"][1]["result"]["state"] == "active"
    assert _daemon_record(home)["installation_id"] == reserved["installation_id"]
    assert len(backend.values) == 1
    assert _daemon(home, harness, backend).status()["state"] == "active"


def test_unpair_during_pair_leaves_no_unreachable_seed_and_the_attempt_fails_closed(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("owner-unpair-race@example.test")
    token = _invite(harness, workspace_id, cookie)
    home, backend = _home(tmp_path, "unpair-race"), GatedSecretBackend()
    outcome = {}

    def run():
        try:
            outcome["result"] = _daemon(home, harness, backend).pair(harness.origin, token)
        except RunnerPairingError as error:
            outcome["error"] = error.code

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert backend.entered.wait(30)
    # The operator unpairs the incomplete attempt while it is between reservation and exchange.
    assert _daemon(home, harness, backend).unpair()["removed"] is True
    assert _daemon_record(home) is None
    backend.release.set()
    thread.join(30)
    assert outcome == {"error": "local_state_invalid"}
    # The attempt noticed its record was gone and removed its own seed; nothing names a key.
    assert backend.values == {} and len(backend.deleted) == 2
    assert _daemon_record(home) is None
    assert _daemon(home, harness, backend).status() == {"state": "unpaired"}
    assert "active" not in _server_runner_statuses(harness, workspace_id)


def test_pair_record_updates_and_removals_are_bound_to_the_attempt_installation_id(tmp_path):
    home = _home(tmp_path, "bound")
    daemon, store = RunnerDaemon(home), RunnerStore(home)
    record = {
        "schema_version": "heel.runner-daemon-pairing.v1", "state": "preparing",
        "origin": "https://heel.example", "installation_id": "a" * 32, "display_name": "Heel runner",
        "created_at_ms": 1, "pairing_id": None, "runner_id": None, "workspace_id": None,
        "runner_key_id": None, "fingerprint": None,
    }
    with pytest.raises(RunnerPairingError) as absent:
        daemon._write_record(store, record)
    assert absent.value.code == "local_state_invalid" and _daemon_record(home) is None
    daemon._reserve_record(store, record)
    with pytest.raises(RunnerPairingError) as twice:
        daemon._reserve_record(store, {**record, "installation_id": "b" * 32})
    assert twice.value.code == "pairing_incomplete"
    other = {**record, "installation_id": "b" * 32, "state": "exchanged"}
    with pytest.raises(RunnerPairingError) as foreign:
        daemon._write_record(store, other)
    assert foreign.value.code == "local_state_invalid"
    assert daemon._remove_record(store, "b" * 32) is False
    assert _daemon_record(home) == record
    daemon._write_record(store, {**record, "state": "exchanged"})
    assert _daemon_record(home)["state"] == "exchanged"
    assert daemon._remove_record(store, "a" * 32) is True and _daemon_record(home) is None


def test_status_reports_cloud_authority_missing_for_a_legacy_record_and_unpair_still_works(tmp_path, harness, monkeypatch):
    """A record written before the grant-authority bootstrap stays inspectable and removable."""
    workspace_id, cookie = harness.signup_owner("owner-legacy@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "legacy")
    (label,) = backend.values
    record_path = home / "runner-daemon" / "pairing.json"
    current = _daemon_record(home)
    legacy = {key: value for key, value in current.items() if not key.startswith("grant_authority_")}
    assert set(current) - set(legacy) == {"grant_authority_key_id", "grant_authority_public_key_b64"}
    record_path.write_text(json.dumps(legacy))
    spare_token = _invite(harness, workspace_id, cookie)  # owner browser call, before the baseline
    forwarded = len(harness.forwarded)
    expected_steps = ["heel runner unpair", "heel runner pair --origin <origin> --invite <new token>"]
    for check in (True, False):
        status = _daemon(home, harness, backend).status(check_control_plane=check)
        assert status == {
            "state": "cloud_authority_missing", "origin": harness.origin, "workspace_id": workspace_id,
            "runner_id": runner_id, "runner_key_id": legacy["runner_key_id"],
            "fingerprint": legacy["fingerprint"], "next_steps": expected_steps,
        }
    # The shipped CLI prints the same closed state and exits non-zero, live or offline.
    monkeypatch.setenv("HEEL_HOME", str(home))
    for argv in (["runner", "status"], ["runner", "status", "--offline"]):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            assert cli.main(argv) == 1
        printed = json.loads(stdout.getvalue())
        assert printed["state"] == "cloud_authority_missing" and printed["next_steps"] == expected_steps
    assert len(harness.forwarded) == forwarded  # no network call
    with pytest.raises(RunnerPairingError) as again:
        _daemon(home, harness, backend).pair(harness.origin, spare_token)
    assert again.value.code == "already_paired"
    assert _daemon_record(home) == legacy

    # Inconsistent key material is also reported as missing; a half transition is invalid state.
    other = SigningAuthority.generate()
    for bad in (
        {**legacy, "grant_authority_key_id": other.key_id,
         "grant_authority_public_key_b64": current["grant_authority_public_key_b64"]},
        {**legacy, "grant_authority_key_id": current["grant_authority_key_id"],
         # A canonical but different key: the replaced final character must differ (it was "A" in
         # about one run in sixteen, which left the key unchanged and made this case flaky).
         "grant_authority_public_key_b64": current["grant_authority_public_key_b64"][:-2]
         + ("E=" if current["grant_authority_public_key_b64"][-2] == "A" else "A=")},
    ):
        record_path.write_text(json.dumps(bad))
        assert _daemon(home, harness, backend).status()["state"] == "cloud_authority_missing"
    for invalid in (
        {**legacy, "grant_authority_key_id": current["grant_authority_key_id"]},
        {**legacy, "grant_authority_public_key_b64": current["grant_authority_public_key_b64"]},
        {**current, "grant_authority_key_id": None},
        {**current, "state": "exchanged"},
        {**current, "grant_authority_hint": "x"},
    ):
        record_path.write_text(json.dumps(invalid))
        with pytest.raises(RunnerPairingError) as refused:
            _daemon(home, harness, backend).status()
        assert refused.value.code == "local_state_invalid"
    assert len(harness.forwarded) == forwarded

    # The legacy record unpairs normally: its seed is removed and the home pairs afresh with a key.
    record_path.write_text(json.dumps(legacy))
    result = _daemon(home, harness, backend).unpair()
    assert result["state"] == "unpaired" and result["removed"] is True and result["runner_id"] == runner_id
    assert backend.values == {} and _daemon_record(home) is None
    assert harness.request("POST", f"/v1/workspaces/{workspace_id}/runners/{runner_id}/revoke",
                           REVOKE_BODY, cookie=cookie)[0] == 200
    # The refused ``already_paired`` attempt sent nothing, so its invitation is still unused.
    _, outcome = _pair_with_owner_approval(
        harness, _daemon(home, harness, backend), workspace_id, cookie, spare_token,
    )
    assert outcome["result"]["state"] == "active", outcome
    assert _daemon_record(home)["grant_authority_key_id"] == harness.control_plane.grant_authority.key_id
    assert _daemon(home, harness, backend).status()["state"] == "active"


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
    for function in (cli._runner_pair, cli._runner_status, cli._runner_unpair, cli._runner_serve):
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


# --------------------------------------------------------------------------- serve (T2b-2)
#
# Seams, each labelled where used: SEAM-EDGE-CA (explicit CA bundle for the loopback TLS edge),
# SEAM-SECRET-BACKEND (injected seed store; real macOS Keychain acceptance runs separately) and
# SEAM-ENV-DNS (``ControlPlane(environment_dns_txt=…)`` answers the TXT record the owner publishes;
# environment start/check/list and binding creation run through the real HTTP API at the edge).
# No row is seeded, no binding or activation is installed by hand, no backend is called directly.

_ROOT = Path(__file__).resolve().parents[1]
_STAGING = "staging.example.com"


@pytest.fixture
def serve_harness(tmp_path):
    zone: dict[str, list[str]] = {}
    authority = SigningAuthority.generate()
    with EdgeTLSHarness(
        tmp_path / "cloud", grant_authority=authority,
        grant_trusted_keys={authority.key_id: authority.public_key},
        environment_dns_txt=lambda name: list(zone.get(name, ())),  # SEAM-ENV-DNS
    ) as edge:
        yield edge, zone


def _owner(harness, method, path, body, cookie):
    # The dashboard sends canonical JSON; the binding routes compare the raw bytes to it.
    raw = None if body is None else canonical_bytes(body)
    status, payload, _ = harness.request(method, path, raw=raw, cookie=cookie)
    return status, payload


def _authorize_binding(harness, zone, workspace_id, cookie, runner_id, runner_key_id):
    """The owner's browser flow over the TLS edge: project → verified environment → binding."""
    status, project = _owner(harness, "POST", f"/v1/workspaces/{workspace_id}/projects", {"name": "Staging"}, cookie)
    assert status == 201, project
    base = f"/v1/workspaces/{workspace_id}/projects/{project['project_ref']}"
    status, challenge = _owner(harness, "POST", f"{base}/environments", {
        "schema_version": "heel.verified-environment-start.v1", "origin": f"https://{_STAGING}",
        "environment_class": "staging", "proof_method": "dns-txt",
        "attestation_text": "ownership verified; environment classification supplied by you",
        "attestation_version": "v1", "attestation_acknowledgement": "accepted",
    }, cookie)
    assert status == 201, challenge
    # SEAM-ENV-DNS: the owner publishes the record the server asked for; the server checks it.
    zone[f"_heel.{_STAGING}"] = ["heel-verify=" + challenge["token"]]
    status, checked = _owner(harness, "POST", f"{base}/environments/{challenge['environment_id']}/check",
                             {"schema_version": "heel.verified-environment-check.v1"}, cookie)
    assert (status, checked["verified"]) == (200, True), checked
    status, listed = _owner(harness, "GET", f"{base}/environments", None, cookie)
    (environment,) = [item for item in listed["environments"] if item["environment_id"] == challenge["environment_id"]]
    assert environment["status"] == "verified" and environment["is_executable"] is True
    status, created = _owner(harness, "POST", f"{base}/runner-context-bindings", {
        "schema_version": "heel.runner-context-binding-create.v1",
        "environment_id": environment["environment_id"],
        "verification_record_digest": environment["verification_record_digest"],
        "runner_id": runner_id, "runner_key_id": runner_key_id,
    }, cookie)
    assert status == 201, created
    return base, created["context_binding"]


def _serve_in_thread(daemon, **options):
    events: list[dict] = []
    outcome: dict[str, object] = {}

    def run():
        try:
            outcome["result"] = daemon.serve(emit=events.append, **options)
        except BaseException as error:  # surfaced to the test thread
            outcome["error"] = error

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, events, outcome


def _serve_state(home):
    try:
        return json.loads((home / "runner-daemon" / "serve-state.json").read_text())
    except (FileNotFoundError, ValueError):
        return None


def _wait_serve_state(home, predicate, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = _serve_state(home)
        if state is not None and predicate(state):
            return state
        time.sleep(0.02)
    raise AssertionError(f"serve state not reached: {_serve_state(home)}")


def _states(events):
    sequence = []
    for event in events:
        if event.get("event") == "serve_state" and (not sequence or sequence[-1] != event["state"]):
            sequence.append(event["state"])
    return sequence


def _runner_calls(harness, runner_id):
    return [path for _method, path in harness.forwarded if f"/runners/{runner_id}/" in path]


# Child processes run the real ``heel.cli.main`` from an empty working directory with
# ``python -I``. ``RunnerDaemon()`` is swapped for one with SEAM-SECRET-BACKEND (seeds read from a
# 0600 file the parent wrote) and SEAM-EDGE-CA; argv cannot reach either seam.
_CHILD = r"""
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from heel import cli
from heel.runner import daemon as daemon_module
home, ca_bundle, seeds, options = Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]), json.loads(sys.argv[5])

class FileSecretBackend:
    def load(self, label):
        value = json.loads(seeds.read_text()).get(label)
        return None if value is None else bytes.fromhex(value)
    def store(self, label, seed):
        raise ValueError("the child never creates runner seeds")
    def delete(self, label):
        raise ValueError("the child never deletes runner seeds")

Real = daemon_module.RunnerDaemon
daemon_module.RunnerDaemon = lambda: Real(home, secret_backend=FileSecretBackend(), ca_bundle=ca_bundle, **options)
sys.exit(cli.main(sys.argv[6:]))
"""


def _child_seeds(tmp_path, backend):
    path = tmp_path / f"child-seeds-{len(list(tmp_path.glob('child-seeds-*')))}.json"
    path.write_text(json.dumps({label: seed.hex() for label, seed in backend.values.items()}))
    path.chmod(0o600)
    return path


def _child_env(home, tmp_path):
    workdir = tmp_path / "child-cwd"
    workdir.mkdir(exist_ok=True)
    return workdir, {
        "HEEL_HOME": str(home), "PATH": "/usr/bin:/bin", "LC_ALL": "C",
        "TMPDIR": os.environ.get("TMPDIR", str(tmp_path)), "HOME": str(tmp_path),
    }


def _child_argv(harness, home, seeds, options, *argv):
    return [sys.executable, "-I", "-c", _CHILD, str(_ROOT), str(home), str(harness.ca.ca_path),
            str(seeds), json.dumps(options), *argv]


def _child_cli(tmp_path, harness, home, seeds, *argv, options=None, timeout=60):
    workdir, env = _child_env(home, tmp_path)
    completed = subprocess.run(
        _child_argv(harness, home, seeds, options or {}, *argv), cwd=workdir, env=env,
        capture_output=True, text=True, timeout=timeout,
    )
    return completed.returncode, completed.stdout, completed.stderr


def _child_serve(tmp_path, harness, home, seeds, *argv, options=None):
    workdir, env = _child_env(home, tmp_path)
    return subprocess.Popen(
        _child_argv(harness, home, seeds, options or {}, "runner", "serve", *argv), cwd=workdir,
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def _serve_lock_inode(home):
    return os.stat(home / "runner-daemon" / ".serve.lock", follow_symlinks=False).st_ino


def test_runner_serve_claims_a_context_binding_and_reports_access_over_tls(tmp_path, serve_harness):
    """Gate: pair → serve → owner authorizes a binding at the edge → serve claims and installs it
    → two labelled credential adds through the CLI → ``access.ready``. Control plane only: no
    target traffic exists in T2b-2."""
    harness, zone = serve_harness
    workspace_id, cookie = harness.signup_owner("owner-serve-bind@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "serve-bind")
    record = _daemon_record(home)
    seeds = _child_seeds(tmp_path, backend)
    daemon = _daemon(home, harness, backend)
    thread, events, outcome = _serve_in_thread(daemon)
    online = _wait_serve_state(home, lambda state: state["state"] == "online")
    assert online["binding_id"] is None and online["runner_id"] == runner_id and online["access"] is None
    assert not RunnerStore(home).is_context_bound
    # Before the owner authorizes the runner nothing can bind the store: credential add refuses.
    add = ("runner", "credential", "add", "--role", "lower_plan", "--plan-label", "Free",
           "--profile", "bearer", "--label", "lower", "--backend", "ephemeral-env")
    assert _child_cli(tmp_path, harness, home, seeds, *add)[0] == 2

    base, binding = _authorize_binding(harness, zone, workspace_id, cookie, runner_id, record["runner_key_id"])
    assert binding["signing_key_id"] == record["grant_authority_key_id"]
    bound = _wait_serve_state(home, lambda state: state["binding_id"] == binding["binding_id"])
    assert bound["state"] == "online" and bound["access"]["state"] == "access.incomplete"
    claim_path = f"/v1/workspaces/{workspace_id}/runners/{runner_id}/contexts/{binding['binding_id']}/claim"
    assert ("POST", claim_path) in harness.forwarded
    # The store is bound only by the claimed, cloud-signed artifact, verified with the record's key.
    store = RunnerStore(home)
    assert store.is_context_bound
    trusted = {record["grant_authority_key_id"]: load_public_key_base64(record["grant_authority_public_key_b64"])}
    installed = store.load_cloud_context_binding()
    assert installed["binding_id"] == binding["binding_id"] and installed["signature_b64"] == binding["signature_b64"]
    payload = {key: installed[key] for key in ("schema_version", "binding_id", "workspace_id", "project_id",
                                               "environment", "runner_binding", "authorization",
                                               "issued_at_ms", "expires_at_ms")}
    from heel.saas.runner_contexts import CONTEXT_DOMAIN  # noqa: PLC0415 - verification constant only
    envelope = {"signing_key_id": installed["signing_key_id"], "signature_b64": installed["signature_b64"]}
    verify_envelope(trusted, envelope, CONTEXT_DOMAIN + canonical_bytes(payload))

    # Two labelled credential adds through the CLI entrypoint in child processes, while serving.
    handles = []
    for role, label in (("lower_plan", "Free"), ("higher_plan", "Pro")):
        argv = ("runner", "credential", "add", "--role", role, "--plan-label", label, "--profile",
                "bearer", "--label", role, "--backend", "ephemeral-env")
        code, out, err = _child_cli(tmp_path, harness, home, seeds, *argv)
        assert (code, err) == (0, ""), err
        printed = json.loads(out)
        assert (printed["role"], printed["plan_label"]) == (role, label)
        handles.append(printed["credential_handle"])
    ready = _wait_serve_state(home, lambda state: (state["access"] or {}).get("state") == "access.ready")
    assert ready["access"]["plan_labels"] == [{"role": "lower_plan", "label": "Free"},
                                              {"role": "higher_plan", "label": "Pro"}]
    # ``status`` works while serving, reads the serve state and does not touch the claim chain.
    forwarded = len(harness.forwarded)
    code, out, err = _child_cli(tmp_path, harness, home, seeds, "runner", "status", "--offline")
    assert code == 0, err
    offline = json.loads(out)
    assert offline["access"]["state"] == "access.ready"
    assert offline["serve"]["state"] == "online" and offline["serve"]["binding_id"] == binding["binding_id"]
    live = _daemon(home, harness, backend).status()
    assert live["state"] == "active" and live["control_plane"] == {"state": "not_checked", "reason": "serve_running"}
    assert not [path for path in harness.forwarded[forwarded:] if "/runners/" in path and "/contexts/list" not in path]

    daemon.request_stop()
    thread.join(10)
    assert not thread.is_alive() and outcome["result"]["state"] == "stopped", outcome
    assert _serve_state(home)["state"] == "stopped"
    assert _states(events) == ["starting", "online", "stopped"]
    # Handles and seeds never leave the local credential records: not in serve state, events,
    # status output or anything sent to the control plane (labels only).
    owner_view = _owner(harness, "GET", f"{base}/runner-context-bindings", None, cookie)[1]
    exposed = json.dumps([_serve_state(home), events, offline, live, owner_view, harness.forwarded])
    for handle in handles:
        assert handle not in exposed
    for seed in backend.values.values():
        assert seed.hex() not in exposed and base64.b64encode(seed).decode() not in exposed


def test_runner_serve_offline_shows_offline_state_and_resumes(tmp_path, harness):
    """Gate: the edge stays up while its upstream is unreachable (the Worker's 502) → ``offline``
    with bounded backoff → upstream back → ``online`` only after a fresh authenticated answer."""
    workspace_id, cookie = harness.signup_owner("owner-serve-offline@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "serve-offline")
    daemon = _daemon(home, harness, backend, serve_backoff_seconds=(0.4, 1.0))
    thread, events, outcome = _serve_in_thread(daemon)
    first = _wait_serve_state(home, lambda state: state["state"] == "online")

    harness.pause_upstream()
    paused_at = len(harness.forwarded)
    offline = _wait_serve_state(home, lambda state: state["state"] == "offline")
    assert offline["last_error_code"] == "upstream_unavailable" and offline["since_ms"] >= first["since_ms"]
    status = _daemon(home, harness, backend).status()
    assert status["state"] == "offline" and status["serve"]["state"] == "offline"
    assert status["control_plane"] == {"state": "not_checked", "reason": "serve_running"}
    time.sleep(3.0)
    during = [path for _method, path in harness.forwarded[paused_at:] if path.endswith("/contexts/list")]
    # Each retry resends the one staged signed call; backoff 0.4 s doubling to a 1.0 s cap (±25 %).
    assert 2 <= len(during) <= 8, during
    assert _serve_state(home)["state"] == "offline" and thread.is_alive()

    harness.resume_upstream()
    resumed_at = len(harness.forwarded)
    resumed = _wait_serve_state(home, lambda state: state["state"] == "online" and state["since_ms"] > offline["since_ms"])
    assert resumed["last_error_code"] is None
    # Online again only after a new answer to an authenticated call made after the outage.
    assert any(path.endswith("/contexts/list") for _method, path in harness.forwarded[resumed_at:])
    daemon.request_stop()
    thread.join(10)
    assert outcome["result"]["state"] == "stopped", outcome
    assert _states(events) == ["starting", "online", "offline", "online", "stopped"]
    # The staged call was replayed exactly once and the chain continued: nothing left pending and
    # a fresh status confirms the same identity with the control plane.
    after = _daemon(home, harness, backend).status()
    assert after["state"] == "active" and after["control_plane"]["state"] == "confirmed", after
    assert after["serve"] == {"state": "not_running", "last_state": "stopped", "last_error_code": None,
                              "updated_at_ms": _serve_state(home)["updated_at_ms"]}


def test_runner_serve_stops_within_deadline_on_revoke(tmp_path, harness):
    """Gate: owner POST revoke at the edge → serve ends ``rejected`` (exit 3) within 5 s, then no
    control call. The refused fresh resync is the signal; it is not labelled a proven revocation."""
    workspace_id, cookie = harness.signup_owner("owner-serve-revoke@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "serve-revoke")
    daemon = _daemon(home, harness, backend, serve_backoff_seconds=(0.4, 1.0))
    thread, events, outcome = _serve_in_thread(daemon)
    _wait_serve_state(home, lambda state: state["state"] == "online")
    # A previous outage on this serve must not colour the later refusal (no shared transport status).
    harness.pause_upstream()
    _wait_serve_state(home, lambda state: state["state"] == "offline")
    harness.resume_upstream()
    _wait_serve_state(home, lambda state: state["state"] == "online")

    started = time.monotonic()
    status, body, _ = harness.request(
        "POST", f"/v1/workspaces/{workspace_id}/runners/{runner_id}/revoke", REVOKE_BODY, cookie=cookie,
    )
    assert (status, body["revoked"]) == (200, True)
    thread.join(10)
    elapsed = time.monotonic() - started
    assert not thread.is_alive() and elapsed <= 5.0, elapsed
    error = outcome["error"]
    assert isinstance(error, daemon_module.RunnerServeError)
    assert (error.code, error.state) == ("runner_authentication_rejected", "rejected")
    state = _serve_state(home)
    assert (state["state"], state["last_error_code"]) == ("rejected", "runner_authentication_rejected")
    assert _states(events)[-1] == "rejected"
    calls = len(_runner_calls(harness, runner_id))
    time.sleep(2.5)
    assert len(_runner_calls(harness, runner_id)) == calls  # no call after shutdown


def _wait_child_online(proc, home, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = _serve_state(home)
        if state is not None and state["state"] == "online" and state["pid"] == proc.pid:
            return state
        if proc.poll() is not None:
            raise AssertionError(f"child serve exited {proc.returncode}: {proc.stderr.read()}")
        time.sleep(0.02)
    raise AssertionError(f"child serve not online: {_serve_state(home)}")


def _stop_child(proc, sig=signal.SIGTERM, timeout=10.0):
    proc.send_signal(sig)
    started = time.monotonic()
    out, err = proc.communicate(timeout=timeout)
    return proc.returncode, out, err, time.monotonic() - started


def test_second_serve_exits_already_serving_without_touching_the_record(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("owner-serve-second@example.test")
    home, backend, _runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "serve-second")
    seeds = _child_seeds(tmp_path, backend)
    first = _child_serve(tmp_path, harness, home, seeds)
    try:
        _wait_child_online(first, home)
        record_bytes = (home / "runner-daemon" / "pairing.json").read_bytes()
        inode = _serve_lock_inode(home)
        forwarded = len(harness.forwarded)

        class Untouchable(RecordingSecretBackend):
            def load(self, label):
                raise AssertionError("a refused serve must not reach the secret store")

        started = time.monotonic()
        with pytest.raises(daemon_module.RunnerServeError) as refused:
            _daemon(home, harness, Untouchable()).serve()
        assert refused.value.code == "already_serving" and time.monotonic() - started < 1.0
        # The CLI entrypoint in another process: fixed line, exit 2, no traceback.
        code, out, err = _child_cli(tmp_path, harness, home, seeds, "runner", "serve")
        assert (code, out, err) == (2, "", "Heel runner serve stopped: already_serving.\n")
        assert (home / "runner-daemon" / "pairing.json").read_bytes() == record_bytes
        assert _serve_state(home)["pid"] == first.pid and _serve_lock_inode(home) == inode
        assert len(harness.forwarded) - forwarded <= 4  # only the first serve's idle polls
    finally:
        code, _out, err, _elapsed = _stop_child(first)
    assert code == 0, err


def test_status_and_credential_add_succeed_while_serve_holds_the_instance_lock(tmp_path, serve_harness):
    harness, zone = serve_harness
    workspace_id, cookie = harness.signup_owner("owner-serve-concurrent@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "serve-concurrent")
    record = _daemon_record(home)
    seeds = _child_seeds(tmp_path, backend)
    proc = _child_serve(tmp_path, harness, home, seeds)
    try:
        _wait_child_online(proc, home)
        _base, binding = _authorize_binding(harness, zone, workspace_id, cookie, runner_id, record["runner_key_id"])
        _wait_serve_state(home, lambda state: state["binding_id"] == binding["binding_id"])
        results: list[tuple] = []

        def add(role, label):
            results.append(_child_cli(
                tmp_path, harness, home, seeds, "runner", "credential", "add", "--role", role,
                "--plan-label", label, "--profile", "x_api_key", "--label", role, "--backend", "ephemeral-fd",
            ))

        def status():
            results.append(("status", _daemon(home, harness, backend).status()))

        workers = [threading.Thread(target=add, args=("lower_plan", "Starter")),
                   threading.Thread(target=add, args=("higher_plan", "Business")),
                   threading.Thread(target=status), threading.Thread(target=status)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(60)
        adds = [item for item in results if item[0] != "status"]
        assert [code for code, _out, _err in adds] == [0, 0], adds
        for _tag, view in (item for item in results if item[0] == "status"):
            assert view["state"] == "active" and view["serve"]["state"] == "online"
            assert view["control_plane"] == {"state": "not_checked", "reason": "serve_running"}
        assert _wait_serve_state(home, lambda state: (state["access"] or {}).get("state") == "access.ready")
        assert proc.poll() is None  # serve kept running through the concurrent local commands
    finally:
        code, _out, err, _elapsed = _stop_child(proc)
    assert code == 0, err


def test_unpair_refuses_while_serve_runs_and_succeeds_after_sigterm(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("owner-serve-unpair@example.test")
    home, backend, _runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "serve-unpair")
    seeds = _child_seeds(tmp_path, backend)
    proc = _child_serve(tmp_path, harness, home, seeds)
    _wait_child_online(proc, home)
    inode = _serve_lock_inode(home)
    started = time.monotonic()
    with pytest.raises(RunnerPairingError) as refused:
        _daemon(home, harness, backend).unpair()
    assert refused.value.code == "serve_running" and time.monotonic() - started < 1.0
    assert backend.values and _daemon_record(home) is not None  # nothing removed
    code, out, err, elapsed = _stop_child(proc)
    assert (code, err) == (0, "") and elapsed < 5.0, (code, err, elapsed)
    assert json.loads(out.splitlines()[-1]) == {"access": None, "binding_id": None, "event": "serve_stopped",
                                                "state": "stopped"}
    assert _serve_state(home)["state"] == "stopped"
    result = _daemon(home, harness, backend).unpair()
    assert result["removed"] is True and backend.values == {}
    assert _serve_state(home) is None and _serve_lock_inode(home) == inode  # lock file never unlinked


def test_serve_instance_lock_is_released_on_sigkill_without_a_stale_pid_check(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("owner-serve-kill@example.test")
    home, backend, _runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "serve-kill")
    seeds = _child_seeds(tmp_path, backend)
    proc = _child_serve(tmp_path, harness, home, seeds)
    killed = _wait_child_online(proc, home)
    inode = _serve_lock_inode(home)
    proc.kill()
    proc.communicate(timeout=10)
    # The stale file still says online with a dead PID; only the kernel lock is authority.
    assert _serve_state(home) == killed
    view = _daemon(home, harness, backend).status(check_control_plane=False)["serve"]
    assert view == {"state": "not_running", "last_state": "online", "last_error_code": None,
                    "updated_at_ms": killed["updated_at_ms"]}
    daemon = _daemon(home, harness, backend)
    thread, _events, outcome = _serve_in_thread(daemon)
    restarted = _wait_serve_state(home, lambda state: state["state"] == "online" and state["pid"] == os.getpid(), timeout=10)
    assert restarted["since_ms"] > killed["since_ms"] and _serve_lock_inode(home) == inode
    daemon.request_stop()
    thread.join(10)
    assert outcome["result"]["state"] == "stopped", outcome


def test_serve_handles_sigterm_with_local_stop_and_exits_stopped(tmp_path, harness):
    """SIGINT/SIGTERM interrupt the idle poll and the offline backoff; exit 0 ``stopped``."""
    workspace_id, cookie = harness.signup_owner("owner-serve-signal@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "serve-signal")
    seeds = _child_seeds(tmp_path, backend)
    # Idle poll: SIGINT.
    proc = _child_serve(tmp_path, harness, home, seeds)
    _wait_child_online(proc, home)
    code, out, err, elapsed = _stop_child(proc, signal.SIGINT)
    assert (code, err) == (0, "") and elapsed < 3.0, (code, err, elapsed)
    assert "Traceback" not in out and json.loads(out.splitlines()[-1])["state"] == "stopped"
    # Offline backoff of up to 60 s: SIGTERM ends it at once, and no call follows.
    proc = _child_serve(tmp_path, harness, home, seeds, options={"serve_backoff_seconds": [30.0, 60.0]})
    _wait_child_online(proc, home)
    harness.pause_upstream()
    try:
        _wait_serve_state(home, lambda state: state["state"] == "offline")
        calls = len(_runner_calls(harness, runner_id))
        code, out, err, elapsed = _stop_child(proc, signal.SIGTERM)
    finally:
        harness.resume_upstream()
    assert (code, err) == (0, "") and elapsed < 3.0, (code, err, elapsed)
    assert [json.loads(line)["state"] for line in out.splitlines()] == ["starting", "online", "offline", "stopped", "stopped"]
    assert len(_runner_calls(harness, runner_id)) == calls
    assert _serve_state(home)["state"] == "stopped"


class _GatedTransport:
    """Test-only timing gate around the real HTTPS transport: while armed, the next call is sent
    to the real edge and its answer is held until released (a response still in flight)."""

    def __init__(self, transport, gate):
        self._transport, self._gate = transport, gate

    def post(self, path, **options):
        answer = self._transport.post(path, **options)
        if self._gate["armed"].is_set():
            self._gate["armed"].clear()
            self._gate["holding"].set()
            assert self._gate["release"].wait(30)
        return answer


def _gate_daemon(daemon):
    gate = {"armed": threading.Event(), "holding": threading.Event(), "release": threading.Event()}
    real = daemon._transport
    daemon._transport = lambda origin: _GatedTransport(real(origin), gate)
    return gate


def test_shutdown_during_a_pending_control_call_keeps_ownership_until_the_call_ends(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("owner-serve-pending@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "serve-pending")
    daemon = _daemon(home, harness, backend)
    gate = _gate_daemon(daemon)
    thread, _events, outcome = _serve_in_thread(daemon)
    _wait_serve_state(home, lambda state: state["state"] == "online")
    gate["armed"].set()
    assert gate["holding"].wait(10)  # the server answered; the runner has not consumed it yet
    daemon.request_stop()
    time.sleep(0.3)
    assert thread.is_alive()
    # Immediately: status, restart and unpair all see the old serve still owning the instance.
    status = _daemon(home, harness, backend).status()
    assert status["serve"]["state"] == "online"
    assert status["control_plane"] == {"state": "not_checked", "reason": "serve_running"}
    with pytest.raises(daemon_module.RunnerServeError) as again:
        _daemon(home, harness, backend).serve(once=True)  # bounded negative check
    assert again.value.code == "already_serving"
    with pytest.raises(RunnerPairingError) as unpair:
        _daemon(home, harness, backend).unpair()
    assert unpair.value.code == "serve_running"
    calls = len(_runner_calls(harness, runner_id))
    gate["release"].set()
    thread.join(10)
    assert outcome["result"]["state"] == "stopped", outcome
    assert len(_runner_calls(harness, runner_id)) == calls  # the stop issued no further call
    # The in-flight answer was committed: the next client continues the same chain.
    assert _daemon(home, harness, backend).status()["control_plane"]["state"] == "confirmed"
    restarted = _daemon(home, harness, backend)
    thread, _events, outcome = _serve_in_thread(restarted)
    _wait_serve_state(home, lambda state: state["state"] == "online" and state["since_ms"] > 0)
    restarted.request_stop()
    thread.join(10)
    assert outcome["result"]["state"] == "stopped", outcome


def test_serve_keeps_the_instance_lock_until_its_own_cycle_workers_have_ended(tmp_path, harness, monkeypatch):
    """Two independent serves in one process: stopping A waits only for A's own in-flight worker
    call (through A's cycle adapter), never for B's, and A's adapter refuses any later call."""
    homes = []
    for name in ("a", "b"):  # one active runner per free workspace: two owners
        workspace_id, cookie = harness.signup_owner(f"owner-serve-workers-{name}@example.test")
        homes.append(_pair_runner(tmp_path, harness, workspace_id, cookie, f"serve-workers-{name}")[:2])
    (home_a, backend_a), (home_b, backend_b) = homes
    from heel.runner.coordinator import RunnerCoordinator, RunnerMaintenanceResult

    entered = {"a": threading.Event(), "b": threading.Event()}
    finish = {"a": threading.Event(), "b": threading.Event()}
    done = {"a": threading.Event(), "b": threading.Event()}
    owners: dict[str, object] = {}

    def slow_maintenance(coordinator, *, limit=16, now_ms=None):
        name = "a" if Path(coordinator.store.root) == home_a else "b"
        entered[name].set()
        assert finish[name].wait(30)  # e.g. a maintenance batch still writing local runtime state
        done[name].set()
        return RunnerMaintenanceResult(processed=0, has_more=False)

    real_serve = daemon_module.RunnerService.serve

    def serve_with_an_early_maintenance_call(service, stop_event):
        # The service's own worker waits 60 s before its first tick; call the same adapter method
        # on a worker thread now so the cycle has an in-flight worker call to own.
        name = "a" if Path(service.coordinator._coordinator.store.root) == home_a else "b"
        owners[name] = service.coordinator
        threading.Thread(target=lambda: service.coordinator.maintenance_once(limit=16), daemon=True).start()
        real_serve(service, stop_event)

    monkeypatch.setattr(RunnerCoordinator, "maintenance_once", slow_maintenance)
    monkeypatch.setattr(daemon_module.RunnerService, "serve", serve_with_an_early_maintenance_call)
    serve_a, serve_b = _daemon(home_a, harness, backend_a), _daemon(home_b, harness, backend_b)
    thread_a, _ev_a, outcome_a = _serve_in_thread(serve_a)
    thread_b, _ev_b, outcome_b = _serve_in_thread(serve_b)
    assert entered["a"].wait(20) and entered["b"].wait(20)
    _wait_serve_state(home_a, lambda state: state["state"] == "online")

    serve_a.request_stop()
    time.sleep(0.3)
    assert thread_a.is_alive()  # A's own worker call is still in flight: A keeps ownership
    assert _daemon(home_a, harness, backend_a).status(check_control_plane=False)["serve"]["state"] == "online"
    finish["a"].set()
    thread_a.join(10)
    assert not thread_a.is_alive() and outcome_a["result"]["state"] == "stopped", outcome_a
    assert not finish["b"].is_set() and thread_b.is_alive()  # A never waited on B's worker
    with pytest.raises(daemon_module.RunnerServeError):
        owners["a"].maintenance_once(limit=16)  # a stale worker of A can no longer reach A's store

    serve_b.request_stop()
    finish["b"].set()
    thread_b.join(10)
    assert outcome_b["result"]["state"] == "stopped", outcome_b


def test_serve_exits_execution_unavailable_closed_without_traffic_or_traceback(monkeypatch):
    """Unit (mock coordinator): any lease is refused before the heartbeat worker starts. A real
    legacy catalog lease over HTTP is T4a's ``test_serve_refuses_a_catalog_projection_lease_…``."""
    from heel.runner.service import ClaimLease, RunnerService

    calls: list[str] = []

    class Runtime:
        def __init__(self):
            self.active = []

        def load_active_run_controls(self, limit):
            return list(self.active)

    class Coordinator:
        def __init__(self, lease=None, record_then_fail=False):
            self.control = type("Control", (), {"runtime": Runtime()})()
            self.lease, self.record_then_fail = lease, record_then_fail

        def ensure_runner_context(self):
            calls.append("ensure")
            return True

        def claim(self):
            calls.append("claim")
            if self.record_then_fail:
                self.control.runtime.active.append(type("Active", (), {"run_id": "crun_" + "a" * 32})())
                raise RunnerStoreError("local approved pair is unavailable")
            return self.lease

        def __getattr__(self, name):
            def forbidden(*_args, **_kwargs):
                calls.append(name)
                raise AssertionError(f"{name} must not be called")
            return forbidden

    lease = ClaimLease("crun_" + "b" * 32, object(), {"schema_version": "x"})
    for coordinator in (Coordinator(lease=lease), Coordinator(record_then_fail=True)):
        calls.clear()
        contacts: list[int] = []
        service = RunnerService(
            coordinator=daemon_module._ServeCoordinator(coordinator, lambda: contacts.append(1)),
            executor=daemon_module._ExecutionUnavailable(),
        )
        with pytest.raises(daemon_module.RunnerServeError) as refused:
            service.run_once()
        assert refused.value.code == "execution_unavailable"
        assert calls == ["ensure", "claim"]  # no heartbeat, progress, result or stop-ack
        assert daemon_module._serve_failure(refused.value) == ("failed", "execution_unavailable")
    # A claim that fails without recording a run keeps its own failure.
    plain = Coordinator()
    plain.claim = lambda: (_ for _ in ()).throw(ValueError("invalid runner claim response"))
    with pytest.raises(ValueError):
        daemon_module._ServeCoordinator(plain, lambda: None).claim()
    # The CLI turns the closed code into its fixed line: exit 2, no traceback.
    def refuse(self, **_options):
        raise daemon_module.RunnerServeError("execution_unavailable")
    monkeypatch.setattr(daemon_module.RunnerDaemon, "serve", refuse)
    assert _invoke("runner", "serve") == (2, "", "Heel runner serve stopped: execution_unavailable.\n")


def test_serve_failure_classification_is_attributed_to_the_failing_call(ca):
    """A stale or concurrent 503 never turns a malformed, unauthorized or upgrade answer into an
    offline retry: each call raises its own outcome and nothing reads shared transport status."""
    answers = {
        "/v1/t/unavailable": raw_json_response(503, b'{"error":"control plane unavailable"}'),
        "/v1/t/gateway": raw_json_response(502, b'{"error":"control plane request failed"}'),
        "/v1/t/revoked": raw_json_response(401, b'{"code":"invalid_runner_auth","error":"unauthorized"}'),
        "/v1/t/unauthorized": raw_json_response(401, b'{"code":"invalid_signature","error":"unauthorized"}'),
        "/v1/t/upgrade": raw_json_response(403, b'{"code":"runner_protocol_upgrade_required","error":"upgrade"}'),
        "/v1/t/internal": raw_json_response(500, b'{"error":"internal error"}'),
        "/v1/t/malformed": raw_json_response(200, b'{"schema_version":"unexpected"}'),
    }
    server = ScriptedTLSServer(ca, lambda path: answers[path], delay_seconds=0.002)
    try:
        transport = daemon_module._AttributedTransport(HTTPSControlTransport(server.origin, ca_bundle=ca.ca_path))
        outcomes: dict[str, tuple[str, str]] = {}

        def call(path):
            try:
                status, _headers, payload = transport.post(path, headers={"Content-Type": "application/json"}, body=b"{}")
                if status != 200 or payload.get("schema_version") != "expected":
                    raise ValueError("invalid runner context response")  # the client's own check
            except Exception as error:
                outcomes[path] = daemon_module._serve_failure(error)

        # The calls share one transport concurrently, as the service's threads would. Each batch
        # mixes an outage with closed answers and stays within the scripted server's listen backlog
        # (5; it completes TLS handshakes one at a time), so no connect is refused under load.
        for batch in (("/v1/t/unavailable", "/v1/t/revoked", "/v1/t/malformed", "/v1/t/upgrade"),
                      ("/v1/t/gateway", "/v1/t/unauthorized", "/v1/t/internal")):
            workers = [threading.Thread(target=call, args=(path,)) for path in batch]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(30)
        assert outcomes == {
            "/v1/t/unavailable": ("offline", "upstream_unavailable"),
            "/v1/t/gateway": ("offline", "upstream_unavailable"),
            # T2b2R1: 401 is returned to the control client (lost chain authority is recovered
            # there); a raw 401 that reaches this classification is a decoding error.
            "/v1/t/revoked": ("failed", "response_rejected"),
            "/v1/t/unauthorized": ("failed", "response_rejected"),
            "/v1/t/upgrade": ("failed", "protocol_upgrade_required"),
            "/v1/t/internal": ("failed", "response_rejected"),
            "/v1/t/malformed": ("failed", "response_rejected"),
        }
        # Sequentially: the shared attributes now say 503, yet a malformed answer stays closed.
        with pytest.raises(daemon_module._ControlCallRejected):
            transport.post("/v1/t/unavailable", body=b"{}")
        assert transport._transport.last_status == 503
        try:
            call("/v1/t/malformed")
        finally:
            assert outcomes["/v1/t/malformed"] == ("failed", "response_rejected")
    finally:
        server.close()
    # Only an explicit cause counts: a decoding error raised while handling an earlier outage
    # (implicit context) is a decoding error.
    try:
        try:
            raise daemon_module._ControlCallRejected("upstream_unavailable")
        except daemon_module._ControlCallRejected:
            raise ValueError("invalid runner context response")
    except ValueError as error:
        assert daemon_module._serve_failure(error) == ("failed", "response_rejected")
    wrapped = RuntimeError("runner heartbeat failed closed")
    wrapped.__cause__ = ControlTransportError("timeout")
    assert daemon_module._serve_failure(wrapped) == ("offline", "timeout")
    for code in ("tls_trust_failed", "redirect_refused", "response_too_large", "malformed_response"):
        assert daemon_module._serve_failure(ControlTransportError(code)) == ("failed", code)
    assert daemon_module._serve_failure(RunnerStoreError("x")) == ("failed", "local_state_invalid")
    from heel.runner.control_client import (
        RunnerAuthenticationRejected, RunnerChainRecoveryDeferred, RunnerChainRecoveryRequired,
    )
    assert daemon_module._serve_failure(RunnerAuthenticationRejected()) == ("rejected", "runner_authentication_rejected")
    deferred = RuntimeError("cycle failed")
    deferred.__cause__ = RunnerChainRecoveryDeferred(1_500)
    assert daemon_module._serve_failure(deferred) == ("offline", "recovery_rate_limited")
    assert daemon_module._recovery_delay_seconds(deferred) == 1.5
    assert daemon_module._recovery_delay_seconds(RuntimeError("x")) == 0.0
    assert daemon_module._serve_failure(RunnerChainRecoveryRequired("claim")) == ("failed", "recovery_required")
    # The serve path never consults the transport's shared last-call attributes.
    for item in (daemon_module._AttributedTransport, daemon_module._serve_failure,
                 daemon_module._ServeSession, daemon_module._ServeCoordinator):
        source = inspect.getsource(item)
        assert ".last_status" not in source and ".last_error_code" not in source


@pytest.mark.parametrize("answer, expected", [
    ((200, {"schema_version": "heel.runner-context-list-result.v1"}), "response_rejected"),
    ((401, {"code": "invalid_signature", "error": "unauthorized"}), "response_rejected"),
    ((403, {"code": "runner_protocol_upgrade_required", "error": "upgrade"}), "protocol_upgrade_required"),
    ((500, {"error": "internal error"}), "response_rejected"),
])
def test_serve_fails_closed_on_malformed_or_unauthorized_answers_after_an_outage(tmp_path, harness, answer, expected):
    """After a real outage (edge 502) a bad answer ends the serve closed, with no retry."""
    workspace_id, cookie = harness.signup_owner(f"owner-serve-bad-{answer[0]}-{expected}@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "serve-bad")
    daemon = _daemon(home, harness, backend, serve_backoff_seconds=(0.4, 1.0))
    tamper = threading.Event()
    real = daemon._transport

    class Tampering:
        """Test-only: replaces one real answer after the real edge produced it."""

        def __init__(self, transport):
            self._transport = transport

        def post(self, path, **options):
            status, headers, payload = self._transport.post(path, **options)
            if tamper.is_set() and path.endswith("/contexts/list"):
                tamper.clear()
                self._transport.last_status = 503  # a stale shared value must not matter
                return answer[0], headers, dict(answer[1])
            return status, headers, payload

    daemon._transport = lambda origin: Tampering(real(origin))
    thread, events, outcome = _serve_in_thread(daemon)
    _wait_serve_state(home, lambda state: state["state"] == "online")
    harness.pause_upstream()
    _wait_serve_state(home, lambda state: state["state"] == "offline")
    tamper.set()
    harness.resume_upstream()
    thread.join(15)
    assert not thread.is_alive()
    error = outcome["error"]
    assert isinstance(error, daemon_module.RunnerServeError) and (error.state, error.code) == ("failed", expected)
    assert _states(events)[-2:] == ["offline", "failed"]
    calls = len(_runner_calls(harness, runner_id))
    time.sleep(2.5)
    assert len(_runner_calls(harness, runner_id)) == calls


def test_serve_refuses_a_legacy_record_before_secret_store_or_network(tmp_path, harness, monkeypatch):
    workspace_id, cookie = harness.signup_owner("owner-serve-legacy@example.test")
    home, backend, _runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "serve-legacy")
    record_path = home / "runner-daemon" / "pairing.json"
    current = _daemon_record(home)
    record_path.write_text(json.dumps({key: value for key, value in current.items()
                                       if not key.startswith("grant_authority_")}))
    forwarded = len(harness.forwarded)

    class Untouchable(RecordingSecretBackend):
        def load(self, label):
            raise AssertionError("no secret-store access without a cloud authority")

    with pytest.raises(daemon_module.RunnerServeError) as refused:
        _daemon(home, harness, Untouchable()).serve()
    assert (refused.value.code, refused.value.state) == ("cloud_authority_missing", "failed")
    assert len(harness.forwarded) == forwarded
    assert _serve_state(home)["last_error_code"] == "cloud_authority_missing"
    monkeypatch.setenv("HEEL_HOME", str(home))
    code, out, err = _invoke("runner", "serve")
    assert (code, err) == (2, "Heel runner serve stopped: cloud_authority_missing.\n")
    assert [json.loads(line) for line in out.splitlines()] == [{
        "access": None, "binding_id": None, "event": "serve_state",
        "last_error_code": "cloud_authority_missing", "state": "failed",
    }]
    assert len(harness.forwarded) == forwarded
    # Unpaired and incomplete homes refuse the same way, without creating state.
    empty = _home(tmp_path, "serve-empty")
    with pytest.raises(daemon_module.RunnerServeError) as unpaired:
        _daemon(empty, harness, backend).serve()
    assert unpaired.value.code == "unpaired" and not (empty / "runner-daemon").exists()


def test_serve_lock_first_creation_race_and_unsafe_lock_files_fail_closed(tmp_path, monkeypatch):
    # Many simultaneous first opens of a not-yet-existing lock: exactly one exclusive owner per
    # round, every other contender sees a closed refusal, never a raw OS error.
    for round_number in range(20):
        directory_path = tmp_path / f"race-{round_number}"
        directory_path.mkdir(mode=0o700)
        directory = os.open(directory_path, os.O_RDONLY)
        barrier, outcomes = threading.Barrier(12), []

        def contend():
            barrier.wait()
            try:
                descriptor = daemon_module._open_serve_lock(directory)
            except OSError as error:
                outcomes.append(("oserror", error))
                return
            if daemon_module._try_flock(descriptor, daemon_module.fcntl.LOCK_EX):
                outcomes.append(("owner", descriptor))
            else:
                os.close(descriptor)
                outcomes.append(("busy", None))

        workers = [threading.Thread(target=contend) for _ in range(12)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)
        kinds = sorted(kind for kind, _ in outcomes)
        assert kinds.count("owner") == 1 and "oserror" not in kinds, outcomes
        for kind, descriptor in outcomes:
            if kind == "owner":
                daemon_module._release_serve_lock(descriptor)
        os.close(directory)
    # The macOS ENOENT race is retried; a persistent one is reported as closed local state.
    real_open = os.open
    failures = {"count": 2}

    def flaky(path, flags, mode=0o777, *, dir_fd=None):
        if path == ".serve.lock" and failures["count"]:
            failures["count"] -= 1
            raise FileNotFoundError(2, "No such file or directory")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(daemon_module.os, "open", flaky)
    home = _home(tmp_path, "flaky")
    (home / "runner-daemon").mkdir(mode=0o700)
    directory = real_open(home / "runner-daemon", os.O_RDONLY)
    try:
        daemon_module._release_serve_lock(daemon_module._open_serve_lock(directory))
        failures["count"] = 100
        with pytest.raises(FileNotFoundError):
            daemon_module._open_serve_lock(directory)
    finally:
        os.close(directory)
    monkeypatch.setattr(daemon_module.os, "open", real_open)

    def persistent_enoent(_directory, _name=daemon_module._SERVE_LOCK):
        raise FileNotFoundError(2, "No such file or directory")

    with monkeypatch.context() as patched:
        patched.setattr(daemon_module, "_open_serve_lock", persistent_enoent)
        patched.setattr(daemon_module.RunnerDaemon, "_load_record", lambda *_a: pytest.fail("record read"))
        with pytest.raises(daemon_module.RunnerServeError) as refused:
            RunnerDaemon(home).serve()
    assert refused.value.code == "local_state_invalid"
    # A symlinked or hard-linked lock is refused, closed, by serve, status and unpair alike.
    lock = home / "runner-daemon" / ".serve.lock"
    lock.unlink()
    (home / "elsewhere").write_text("")
    lock.symlink_to(home / "elsewhere")
    with pytest.raises(daemon_module.RunnerServeError) as symlinked:
        RunnerDaemon(home).serve()
    assert symlinked.value.code == "local_state_invalid"
    lock.unlink()
    os.link(home / "elsewhere", lock)
    with pytest.raises(daemon_module.RunnerServeError) as linked:
        RunnerDaemon(home).serve()
    assert linked.value.code == "local_state_invalid"
    with pytest.raises(RunnerPairingError) as unpair:
        RunnerDaemon(home).unpair()
    assert unpair.value.code == "local_state_invalid"


def test_serve_startup_racing_unpair_and_re_pair_serves_only_the_current_pairing(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("owner-serve-repair@example.test")
    home, backend, old_runner = _pair_runner(tmp_path, harness, workspace_id, cookie, "serve-repair")
    # 1. Serve starting while an unpair owns the instance: refused at once, no network.
    in_unpair, release = threading.Event(), threading.Event()

    owned: dict[str, bool] = {}

    class SlowUnpair(RunnerDaemon):
        def _unpair_locked(self, store):
            # The injection point: instance ownership is already held (nobody else can take the
            # lock) and no removal or network I/O has started yet.
            directory = self._daemon_fd(store, create=False)
            try:
                probe = daemon_module._open_serve_lock(directory)
                owned["serve_lock_held"] = not daemon_module._try_flock(probe, daemon_module.fcntl.LOCK_EX)
                os.close(probe)
            finally:
                os.close(directory)
            owned["record_present"] = _daemon_record(home) is not None
            in_unpair.set()
            assert release.wait(30)
            return super()._unpair_locked(store)

    unpair_outcome: dict = {}
    unpairing = threading.Thread(target=lambda: unpair_outcome.setdefault(
        "result", SlowUnpair(home, secret_backend=backend).unpair()), daemon=True)
    unpairing.start()
    assert in_unpair.wait(10)
    assert owned == {"serve_lock_held": True, "record_present": True}
    forwarded = len(harness.forwarded)
    # Bounded: a missed refusal returns after one cycle and fails here instead of serving forever.
    try:
        with pytest.raises(daemon_module.RunnerServeError) as refused:
            _daemon(home, harness, backend).serve(once=True)
    finally:
        release.set()
    assert refused.value.code == "already_serving" and len(harness.forwarded) == forwarded
    unpairing.join(10)
    assert unpair_outcome["result"]["removed"] is True
    with pytest.raises(daemon_module.RunnerServeError) as gone:
        _daemon(home, harness, backend).serve(once=True)  # bounded negative check
    assert gone.value.code == "unpaired"
    assert harness.request("POST", f"/v1/workspaces/{workspace_id}/runners/{old_runner}/revoke",
                           REVOKE_BODY, cookie=cookie)[0] == 200

    # 2. A re-pair in progress (record exchanged, not active): serve refuses, nothing sent.
    token = _invite(harness, workspace_id, cookie)
    events, outcome = [], {}
    pending = threading.Event()

    def pair():
        try:
            outcome["result"] = _daemon(home, harness, backend).pair(
                harness.origin, token, emit=lambda event: (events.append(event), pending.set()))
        except BaseException as error:
            outcome["error"] = error
            pending.set()

    pairing = threading.Thread(target=pair, daemon=True)
    pairing.start()
    assert pending.wait(30) and "error" not in outcome
    forwarded = len(harness.forwarded)
    with pytest.raises(daemon_module.RunnerServeError) as incomplete:
        _daemon(home, harness, backend).serve(once=True)  # bounded negative check
    assert incomplete.value.code == "pairing_incomplete"
    assert all("/runners/" not in path for _m, path in harness.forwarded[forwarded:])
    printed = events[0]
    view = harness.request("GET", f"/v1/workspaces/{workspace_id}/runner-pairings/{printed['pairing_id']}", cookie=cookie)[1]
    assert harness.request(
        "POST", f"/v1/workspaces/{workspace_id}/runner-pairings/{printed['pairing_id']}/approve",
        {"schema_version": "heel.runner-pairing-approve.v1", "pairing_phrase": view["pairing_phrase"],
         "fingerprint": view["fingerprint"]}, cookie=cookie,
    )[0] == 200
    pairing.join(30)
    new_runner = outcome["result"]["runner_id"]
    assert new_runner != old_runner
    # 3. Serve now runs the new pairing only; a record changed under it fails closed before the
    #    next cycle's first call (simulated corruption: no product path rewrites it while serving).
    daemon = _daemon(home, harness, backend, serve_backoff_seconds=(0.4, 1.0))
    thread, _events, serve_outcome = _serve_in_thread(daemon)
    online = _wait_serve_state(home, lambda state: state["state"] == "online")
    assert online["runner_id"] == new_runner
    assert not [path for path in _runner_calls(harness, old_runner) if path.endswith("/contexts/list")
                and harness.forwarded.index(("POST", path)) >= forwarded]
    record_path = home / "runner-daemon" / "pairing.json"
    changed = {**_daemon_record(home), "display_name": "changed"}
    harness.pause_upstream()  # force a new cycle
    _wait_serve_state(home, lambda state: state["state"] == "offline")
    record_path.write_text(json.dumps(changed))
    calls = len(_runner_calls(harness, new_runner))
    harness.resume_upstream()
    thread.join(10)
    error = serve_outcome["error"]
    assert (error.code, error.state) == ("local_state_invalid", "failed")
    assert len(_runner_calls(harness, new_runner)) == calls


def test_edge_harness_owner_routes_mirror_the_worker_methods_headers_and_caps(tmp_path, harness):
    """The mirrored owner routes refuse what ``index.ts`` refuses (wrong method, bearer, no cookie,
    cross-site or missing origin on POST, oversize body) before anything reaches the server."""
    workspace_id, cookie = harness.signup_owner("owner-edge-mirror@example.test")
    project = harness.request("POST", f"/v1/workspaces/{workspace_id}/projects", {"name": "Mirror"}, cookie=cookie)[1]
    base = f"/v1/workspaces/{workspace_id}/projects/{project['project_ref']}"
    env, rcb = "env_" + "a" * 32, "rcb_" + "b" * 32
    routes = {
        f"{base}/environments": {"GET", "POST"},
        f"{base}/environments/{env}/check": {"POST"},
        f"{base}/environments/{env}/revoke": {"POST"},
        f"{base}/runner-context-bindings": {"GET", "POST"},
        f"{base}/runner-context-bindings/{rcb}/revoke": {"POST"},
        f"/v1/workspaces/{workspace_id}/projects": {"GET", "POST"},
    }
    caps = {
        f"{base}/environments": 16 * 1024, f"{base}/environments/{env}/check": 16 * 1024,
        f"{base}/environments/{env}/revoke": 16 * 1024, f"{base}/runner-context-bindings": 2 * 1024,
        f"{base}/runner-context-bindings/{rcb}/revoke": 256,
    }
    for path, allowed in routes.items():
        for method in ("GET", "POST", "DELETE"):  # the methods the loopback edge dispatches
            if method in allowed:
                continue
            before = len(harness.forwarded)
            status, _body, _ = harness.request(method, path, cookie=cookie, raw=b"{}" if method != "GET" else None)
            assert status == 404 and len(harness.forwarded) == before, (method, path, status)
        # Known harness limitation (not parity): ``BaseHTTPRequestHandler`` answers methods it does
        # not dispatch with 501 where the Worker answers 404. Both deny and forward nothing.
        for method in ("PUT", "PATCH"):
            before = len(harness.forwarded)
            context = ssl.create_default_context(cafile=str(harness.ca.ca_path))
            connection = http.client.HTTPSConnection("localhost", harness.port, context=context, timeout=10)
            try:
                connection.request(method, path, b"{}", {"Cookie": cookie, "Origin": harness.origin,
                                                         "Sec-Fetch-Site": "same-origin",
                                                         "Content-Type": "application/json"})
                status = connection.getresponse().status
            finally:
                connection.close()
            assert status == 501 and len(harness.forwarded) == before, (method, path, status)
    for path, cap in caps.items():
        refusals = [
            dict(cookie=None, raw=b"{}"),
            dict(cookie=cookie, raw=b"{}", headers={"Authorization": "Bearer " + "x" * 40}),
            dict(cookie=cookie, raw=b"{}", origin="https://evil.example"),
            dict(cookie=cookie, raw=b"{}", origin=None),
            dict(cookie=cookie, raw=b"{}", fetch_site="cross-site"),
            dict(cookie=cookie, raw=b"{}", fetch_site=None),
            dict(cookie=cookie, raw=b" " * (cap + 1)),
            dict(cookie=cookie, raw=b"{}", headers={"Content-Type": "text/plain"}),
            dict(cookie=cookie, raw=b"{}", headers={"Content-Encoding": "gzip"}),
        ]
        for options in refusals:
            before = len(harness.forwarded)
            status, body, _ = harness.request("POST", path, **options)
            assert (status, body) == (400, {"error": "invalid control plane request"}), (path, options)
            assert len(harness.forwarded) == before
        # At the cap the edge forwards (the server then judges the body itself).
        before = len(harness.forwarded)
        status, _body, _ = harness.request("POST", path, cookie=cookie, raw=b" " * cap)
        assert status != 404 and len(harness.forwarded) == before + 1, (path, status)
    # GET carries only the cookie; a bearer on a human environment/binding route is refused.
    for path in (f"{base}/environments", f"{base}/runner-context-bindings"):
        assert harness.request("GET", path, cookie=cookie, origin=None, fetch_site=None)[0] == 200
        assert harness.request("GET", path, cookie=None)[0] == 400
        assert harness.request("GET", path, cookie=cookie, headers={"Authorization": "Bearer " + "x" * 40})[0] == 400
    # Projects take the default credential branch (no origin rule), like the Worker.
    assert harness.request("GET", f"/v1/workspaces/{workspace_id}/projects", cookie=cookie, origin=None, fetch_site=None)[0] == 200


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


class _PacedPeer:
    """One-connection loopback peer that follows a script of TLS/byte-pacing steps.

    ``after_tls`` is the response to drip; ``fast_prefix`` bytes go at once, the next
    ``slow_bytes`` one per ``step`` seconds, then the rest. ``tls=False`` accepts TCP and stays
    silent; ``respond=False`` completes TLS, reads the request and stays silent.
    """

    def __init__(self, ca, response=b"", *, tls=True, respond=True, fast_prefix=0, slow_bytes=0,
                 step=0.2, reset_after=None):
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.origin = f"https://localhost:{self.port}"
        self.peer_saw_close = threading.Event()
        self._stop = threading.Event()
        self._context = ca.server_context()
        self._args = (response, tls, respond, fast_prefix, slow_bytes, step, reset_after)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _wait_for_close(self, conn):
        conn.settimeout(0.05)
        while not self._stop.is_set():
            try:
                if conn.recv(65536) == b"":
                    break
            except (socket.timeout, TimeoutError):
                continue
            except (OSError, ssl.SSLError):
                break
        self.peer_saw_close.set()

    def _serve(self):
        response, tls, respond, fast_prefix, slow_bytes, step, reset_after = self._args
        try:
            conn, _ = self.listener.accept()
        except OSError:
            return
        try:
            if tls:
                conn.settimeout(5)
                conn = self._context.wrap_socket(conn, server_side=True)
                try:
                    conn.recv(65536)
                except OSError:
                    pass
            if tls and respond:
                conn.sendall(response[:fast_prefix])
                for index in range(fast_prefix, min(len(response), fast_prefix + slow_bytes)):
                    if self._stop.wait(step):
                        return
                    try:
                        conn.sendall(response[index:index + 1])
                    except OSError:
                        self.peer_saw_close.set()
                        return
                if reset_after is not None:
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
                    conn.close()
                    return
                conn.sendall(response[fast_prefix + slow_bytes:])
            self._wait_for_close(conn)
        except OSError:
            self.peer_saw_close.set()
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self._stop.set()
        self.listener.close()
        self.thread.join(5)


_SLOW_RESPONSE = raw_json_response(200, b'{"ok":true}')


def _timed_post(ca, peer, timeout_seconds):
    transport = HTTPSControlTransport(peer.origin, ca_bundle=ca.ca_path, timeout_seconds=timeout_seconds)
    threads_before = threading.active_count()
    started = time.monotonic()
    try:
        _post(transport)
    except ControlTransportError as error:
        outcome = error.code
    else:
        outcome = "completed"
    elapsed = time.monotonic() - started
    # The deadline is enforced on the calling thread: no watchdog thread is left behind.
    assert threading.active_count() <= threads_before
    return outcome, elapsed


def test_transport_enforces_one_deadline_against_a_trickling_status_line(ca):
    # T2aR D4: 12 status-line bytes at 0.5 s each held a 1 s call open for 6.1 s.
    peer = _PacedPeer(ca, _SLOW_RESPONSE, slow_bytes=12, step=0.25)
    try:
        outcome, elapsed = _timed_post(ca, peer, 0.75)
        assert outcome == "timeout"
        assert 0.7 <= elapsed < 1.5
        # The socket is closed with the call: the peer observes it, no background read remains.
        assert peer.peer_saw_close.wait(2)
    finally:
        peer.close()


@pytest.mark.parametrize("phase, options", [
    ("silent-before-tls-handshake", {"tls": False}),
    ("silent-after-tls-handshake", {"respond": False}),
    ("trickled-headers", {"fast_prefix": _SLOW_RESPONSE.index(b"\r\n") + 2, "slow_bytes": 40}),
    ("trickled-body", {"fast_prefix": _SLOW_RESPONSE.index(b"\r\n\r\n") + 4, "slow_bytes": 11, "step": 0.3}),
])
def test_transport_deadline_covers_handshake_header_and_body_phases(ca, phase, options):
    peer = _PacedPeer(ca, _SLOW_RESPONSE, **options)
    try:
        outcome, elapsed = _timed_post(ca, peer, 0.75)
        assert outcome == "timeout", phase
        assert 0.7 <= elapsed < 1.5, (phase, elapsed)
        assert peer.peer_saw_close.wait(2), phase
    finally:
        peer.close()


def test_transport_completes_a_paced_response_inside_the_deadline_and_maps_resets(ca):
    peer = _PacedPeer(ca, _SLOW_RESPONSE, slow_bytes=4, step=0.05)
    try:
        assert _timed_post(ca, peer, 2.0)[0] == "completed"
    finally:
        peer.close()
    # A peer that resets mid-headers fails closed promptly, never as a hang or a partial result.
    peer = _PacedPeer(ca, _SLOW_RESPONSE, fast_prefix=20, reset_after=True)
    try:
        outcome, elapsed = _timed_post(ca, peer, 2.0)
        assert outcome in {"connection_failed", "malformed_response"}
        assert elapsed < 1.5
    finally:
        peer.close()
    # Nothing listening: refused before any deadline, closed code.
    closed = socket.create_server(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    transport = HTTPSControlTransport(f"https://localhost:{port}", ca_bundle=ca.ca_path, timeout_seconds=1.0)
    with pytest.raises(ControlTransportError) as refused:
        _post(transport)
    assert refused.value.code == "connection_failed"


class _ScriptedSocket:
    """Stands in for ``socket.socket`` inside the transport: connects stall or fail, never send."""

    created: list["_ScriptedSocket"] = []

    def __init__(self, family, kind, protocol, *, behaviour):
        self.behaviour, self.timeouts, self.sent, self.closed = behaviour, [], [], False
        _ScriptedSocket.created.append(self)

    def settimeout(self, value):
        self.timeouts.append(value)

    def connect(self, address):
        if self.behaviour == "blackhole":
            time.sleep(self.timeouts[-1])  # a dropped SYN waits for the whole socket timeout
            raise TimeoutError("timed out")
        raise ConnectionRefusedError("refused")

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


def _patch_resolution(monkeypatch, *, delay, behaviours):
    _ScriptedSocket.created = []
    addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"192.0.2.{index + 1}", 443))
                 for index in range(len(behaviours))]

    def resolve(host, port, type=0):
        time.sleep(delay)
        return addresses

    queue = list(behaviours)
    monkeypatch.setattr(control_transport.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(control_transport.socket, "socket",
                        lambda family, kind, protocol: _ScriptedSocket(family, kind, protocol, behaviour=queue.pop(0)))


def test_transport_deadline_spans_resolution_and_every_resolved_address(monkeypatch):
    # Slow resolver (0.3 s), then three addresses that each drop SYNs: one deadline covers all.
    _patch_resolution(monkeypatch, delay=0.3, behaviours=["refused", "blackhole", "blackhole"])
    transport = HTTPSControlTransport("https://heel.example", timeout_seconds=0.75)
    started = time.monotonic()
    with pytest.raises(ControlTransportError) as refused:
        _post(transport)
    elapsed = time.monotonic() - started
    assert refused.value.code == "timeout"
    assert 0.7 <= elapsed < 1.1
    # The refused address and the first blackhole shared the time left after resolution; the
    # third address was never tried, nothing was ever sent and every socket was closed.
    assert len(_ScriptedSocket.created) == 2
    first, second = _ScriptedSocket.created
    assert first.timeouts[0] <= 0.45 + 0.05 and second.timeouts[0] <= first.timeouts[0]
    assert all(not item.sent and item.closed for item in _ScriptedSocket.created)


def test_transport_reports_the_resolver_overrun_limit_without_any_network_io(monkeypatch):
    # Known limit: a resolver slower than the deadline is not interrupted. The call then ends
    # with ``timeout`` as soon as resolution returns, having created no socket and sent nothing.
    _patch_resolution(monkeypatch, delay=0.9, behaviours=["refused"])
    transport = HTTPSControlTransport("https://heel.example", timeout_seconds=0.5)
    threads_before = threading.active_count()
    started = time.monotonic()
    with pytest.raises(ControlTransportError) as refused:
        _post(transport)
    elapsed = time.monotonic() - started
    assert refused.value.code == "timeout"
    assert 0.9 <= elapsed < 1.2
    assert _ScriptedSocket.created == []
    assert threading.active_count() <= threads_before


def test_transport_all_addresses_refused_fails_fast_with_connection_failed(monkeypatch):
    _patch_resolution(monkeypatch, delay=0, behaviours=["refused", "refused"])
    transport = HTTPSControlTransport("https://heel.example", timeout_seconds=1.0)
    with pytest.raises(ControlTransportError) as refused:
        _post(transport)
    assert refused.value.code == "connection_failed"
    assert len(_ScriptedSocket.created) == 2 and all(item.closed for item in _ScriptedSocket.created)


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


# ---------------------------------------------------------------------------
# T2b2R1: chain-authority recovery over the real TLS edge and control plane.
#
# SEAM-CLOCK (labelled): the loopback control plane runs in this process, so shifting
# ``time.time``/``time.time_ns`` advances the server's clock AND the runner's signing clock
# (``RunnerDaemon`` defaults to ``time.time_ns``) together, exactly like that much wall time passing.
# Monotonic time (locks, backoff, test deadlines) is untouched. Real waits of 35 s / 65 s are run
# separately in the real Keychain acceptance (T2b2R1-artifacts); the server code is unchanged.

from heel.runner.runtime import RunnerRuntimeState  # noqa: E402


@contextlib.contextmanager
def _seam_clock(seconds: float):
    real_time, real_time_ns = time.time, time.time_ns
    time.time = lambda: real_time() + seconds
    time.time_ns = lambda: real_time_ns() + int(seconds * 1_000_000_000)
    try:
        yield
    finally:
        time.time, time.time_ns = real_time, real_time_ns


class _FaultTransport:
    """Test-only faults around the real HTTPS transport, by exact route suffix and in order.

    ``drop_before``: the request never leaves (refused connect); ``drop_after``: the real edge and
    server answer, then the answer is lost; a callable rewrites ``(path, headers, body)`` before
    sending.
    """

    def __init__(self, transport, faults):
        self._transport, self._faults = transport, faults
        self.last_status = self.last_error_code = None

    def post(self, path, *, headers=None, body=b""):
        for suffix, queue in self._faults.items():
            if path.endswith(suffix) and queue:
                fault = queue.pop(0)
                if fault == "drop_before":
                    raise ControlTransportError("connection_failed")
                if fault == "drop_after":
                    self._transport.post(path, headers=headers, body=body)
                    raise ControlTransportError("timeout")
                if callable(fault):
                    path, headers, body = fault(path, dict(headers or {}), body)
                break
        answer = self._transport.post(path, headers=headers, body=body)
        self.last_status = self._transport.last_status
        self.last_error_code = self._transport.last_error_code
        return answer


def _fault_daemon(daemon, faults):
    real = daemon._transport
    daemon._transport = lambda origin: _FaultTransport(real(origin), faults)
    return daemon


def _runtime_view(home, harness, backend):
    view_daemon = _daemon(home, harness, backend)
    record = _daemon_record(home)
    identity, signer = view_daemon._active_identity(view_daemon._store(), record)
    runtime = RunnerRuntimeState(view_daemon.runtime_path, identity, signer)
    try:
        cursor = runtime.load_chain("claim", None)
        return {
            "pending": [(item.request_operation, item.generation) for item in runtime.load_pending_calls()],
            "tombstones": [(item.request_operation, item.generation, item.superseded_by_generation)
                           for item in runtime.load_superseded_calls()],
            "generation": cursor.generation, "attempt": runtime.load_resync_attempt("claim"),
            "active_runs": [item.run_id for item in runtime.load_active_run_controls(limit=64)],
        }
    finally:
        runtime.close()


def _server_claim_generation(harness, workspace_id, runner_id):
    return harness.control_plane.store.conn.execute(
        "SELECT generation FROM canary_runner_chain_cursors WHERE workspace_id=? AND runner_id=? AND chain_name='claim'",
        (workspace_id, runner_id),
    ).fetchone()[0]


def _server_resyncs(harness, workspace_id, runner_id):
    return [row[0] for row in harness.control_plane.store.conn.execute(
        "SELECT status FROM canary_runner_resync_challenges WHERE workspace_id=? AND runner_id=? ORDER BY created_at",
        (workspace_id, runner_id),
    )]


def _serve_once(daemon):
    try:
        return daemon.serve(once=True)
    except daemon_module.RunnerServeError as error:
        return error


def test_first_serve_after_pairing_idle_beyond_nonce_ttl_resyncs_and_is_online(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("r1-first-serve@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r1-first")
    record_before = _daemon_record(home)
    with _seam_clock(65.0):  # SEAM-CLOCK: pair, then 65 s idle (> 60 s nonce TTL) before the first serve
        daemon = _daemon(home, harness, backend)
        thread, events, outcome = _serve_in_thread(daemon)
        _wait_serve_state(home, lambda state: state["state"] == "online")
        daemon.request_stop()
        thread.join(10)
    assert outcome["result"]["state"] == "stopped", outcome
    assert _states(events) == ["starting", "online", "stopped"]
    assert _server_resyncs(harness, workspace_id, runner_id) == ["completed"]
    assert _server_claim_generation(harness, workspace_id, runner_id) == 1
    view = _runtime_view(home, harness, backend)
    assert view["pending"] == [] and view["attempt"] is None and view["generation"] == 1
    assert view["tombstones"] == [("list-contexts", 0, 1)]
    assert _daemon_record(home) == record_before  # identity and pairing untouched by recovery
    status = _daemon(home, harness, backend).status()
    assert (status["state"], status["control_plane"]["state"]) == ("active", "confirmed")


def test_status_after_idle_beyond_nonce_ttl_resyncs_and_confirms(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("r1-status-idle@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r1-status")
    with _seam_clock(65.0):  # SEAM-CLOCK
        first = _daemon(home, harness, backend).status()
        second = _daemon(home, harness, backend).status()
    assert (first["state"], first["control_plane"]["state"]) == ("active", "confirmed"), first
    assert (second["state"], second["control_plane"]["state"]) == ("active", "confirmed")
    # A fresh chain needs no further resync: exactly one recovery for the idle gap.
    assert _server_resyncs(harness, workspace_id, runner_id) == ["completed"]
    assert _runtime_view(home, harness, backend)["tombstones"] == [("list-contexts", 0, 1)]


@pytest.mark.parametrize("outage_seconds", [35.0, 65.0])
def test_serve_resumes_after_an_outage_longer_than_the_proof_window_with_a_staged_call(tmp_path, harness, outage_seconds):
    workspace_id, cookie = harness.signup_owner(f"r1-outage-{int(outage_seconds)}@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r1-outage")
    daemon = _daemon(home, harness, backend, serve_backoff_seconds=(0.4, 1.0))
    thread, events, outcome = _serve_in_thread(daemon)
    try:
        _wait_serve_state(home, lambda state: state["state"] == "online")
        harness.pause_upstream()
        _wait_serve_state(home, lambda state: state["state"] == "offline")
        with _seam_clock(outage_seconds):  # SEAM-CLOCK: the outage lasts this long
            harness.resume_upstream()
            _wait_serve_state(home, lambda state: state["state"] == "online", timeout=30)
            daemon.request_stop()
            thread.join(10)
    finally:
        harness.resume_upstream()
        daemon.request_stop()
        thread.join(10)
    assert outcome["result"]["state"] == "stopped", outcome
    assert "revoked" not in _states(events) and "rejected" not in _states(events)
    assert _states(events)[-3:] == ["offline", "online", "stopped"]
    view = _runtime_view(home, harness, backend)
    assert view["pending"] == [] and view["attempt"] is None
    assert view["tombstones"] == [("list-contexts", 0, 1)]
    assert _server_resyncs(harness, workspace_id, runner_id) == ["completed"]
    status = _daemon(home, harness, backend).status()
    assert status["control_plane"]["state"] == "confirmed"


def _bound_events(harness, binding_id):
    return [row[0] for row in harness.control_plane.store.conn.execute(
        "SELECT action FROM canary_runner_context_events WHERE rcb_id=? ORDER BY created_at_ms,rowid", (binding_id,),
    )]


@pytest.mark.parametrize("fault, shift", [("drop_before", 35.0), ("drop_after", 65.0)])
def test_staged_claim_context_lost_before_or_after_commit_recovers_one_binding(tmp_path, serve_harness, fault, shift):
    harness, zone = serve_harness
    workspace_id, cookie = harness.signup_owner(f"r1-claim-{fault}@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r1-claim")
    record = _daemon_record(home)
    _base, binding = _authorize_binding(harness, zone, workspace_id, cookie, runner_id, record["runner_key_id"])
    binding_id = binding["binding_id"]
    first = _fault_daemon(_daemon(home, harness, backend), {f"/contexts/{binding_id}/claim": [fault]})
    assert isinstance(_serve_once(first), daemon_module.RunnerServeError)  # offline: claim answer lost
    assert _runtime_view(home, harness, backend)["pending"] == [("claim-context", 0)]
    with _seam_clock(shift):  # SEAM-CLOCK
        result = _serve_once(_daemon(home, harness, backend))
    assert not isinstance(result, BaseException), (result.state, result.code)
    assert (result["state"], result["binding_id"]) == ("stopped", binding_id), result
    assert RunnerStore(home).is_context_bound
    view = _runtime_view(home, harness, backend)
    assert view["pending"] == [] and view["attempt"] is None
    if fault == "drop_before":
        # Never recorded: the stale claim is superseded and the same binding is claimed again.
        assert view["tombstones"] == [("claim-context", 0, 1)]
    else:
        # Recorded: its sealed receipt replays with no resync for it; the later fresh list found an
        # expired nonce and that is what was recovered.
        assert view["tombstones"] == [("list-contexts", 0, 1)]
    assert _server_resyncs(harness, workspace_id, runner_id) == ["completed"]
    # Exactly one first claim server-side, whichever path ran: no duplicate binding effect.
    assert _bound_events(harness, binding_id).count("claimed") == 1


def test_real_revocation_still_stops_promptly_and_never_regains_authority(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("r1-revoked@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r1-revoked")
    daemon = _daemon(home, harness, backend)
    thread, events, outcome = _serve_in_thread(daemon)
    _wait_serve_state(home, lambda state: state["state"] == "online")
    started = time.monotonic()
    assert harness.request(
        "POST", f"/v1/workspaces/{workspace_id}/runners/{runner_id}/revoke", REVOKE_BODY, cookie=cookie,
    )[0] == 200
    thread.join(10)
    assert not thread.is_alive() and time.monotonic() - started <= 5.0
    error = outcome["error"]
    assert (error.code, error.state) == ("runner_authentication_rejected", "rejected")
    assert daemon_module.SERVE_EXIT_CODES[error.state] == 3
    calls = len(_runner_calls(harness, runner_id))
    time.sleep(2.5)
    assert len(_runner_calls(harness, runner_id)) == calls
    # Later and even far in the future: a revoked key is refused before any challenge is created.
    for shift in (0.0, 120.0):
        with _seam_clock(shift):  # SEAM-CLOCK
            status = _daemon(home, harness, backend).status()
        assert status["state"] == "runner_authentication_rejected", status
        assert status["control_plane"] == {"state": "rejected", "reason": "runner_authentication_rejected"}
        assert "revoked" not in json.dumps(status["control_plane"])
    assert _server_resyncs(harness, workspace_id, runner_id) == []
    view = _runtime_view(home, harness, backend)
    assert view["tombstones"] == [] and view["attempt"] is None and view["generation"] == 0


def test_a_wrong_local_clock_is_reported_honestly_and_correcting_it_recovers(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("r1-clock@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r1-clock")
    skewed = _daemon(home, harness, backend, clock_ms=lambda: time.time_ns() // 1_000_000 + 120_000)
    status = skewed.status()
    assert status["state"] == "runner_authentication_rejected"
    assert any("clock" in step for step in status["next_steps"])
    assert _runtime_view(home, harness, backend)["pending"] == [("list-contexts", 0)]
    corrected = _daemon(home, harness, backend).status()
    assert (corrected["state"], corrected["control_plane"]["state"]) == ("active", "confirmed"), corrected
    view = _runtime_view(home, harness, backend)
    assert view["pending"] == [] and view["tombstones"] == [("list-contexts", 0, 1)]


def test_resync_rate_limit_429_backs_off_and_never_reports_revoked(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("r1-rate@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r1-rate")
    # SEAM-TAMPER-429: the control plane's exact rate-limit answer (http_api.py), with a short
    # retry_after_ms so the retry is observable; the real start is not sent for that one answer.
    limited = (429, {}, {"schema_version": "heel.runner-error.v1", "code": "runner_resync_rate_limited",
                         "retry_after_ms": 1_500})
    daemon = _daemon(home, harness, backend, serve_backoff_seconds=(0.1, 0.2))

    class Limited(_FaultTransport):
        starts = []

        def post(self, path, *, headers=None, body=b""):
            if path.endswith("/resync/start"):
                Limited.starts.append(time.monotonic())
                if len(Limited.starts) == 1:
                    return limited
            return super().post(path, headers=headers, body=body)

    real = RunnerDaemon._transport
    daemon._transport = lambda origin: Limited(real(daemon, origin), {})
    with _seam_clock(65.0):  # SEAM-CLOCK
        thread, events, outcome = _serve_in_thread(daemon)
        state = _wait_serve_state(home, lambda item: item["state"] == "offline")
        assert state["last_error_code"] == "recovery_rate_limited"
        _wait_serve_state(home, lambda item: item["state"] == "online", timeout=20)
        daemon.request_stop()
        thread.join(10)
    assert outcome["result"]["state"] == "stopped"
    assert len(Limited.starts) == 2 and Limited.starts[1] - Limited.starts[0] >= 1.4  # honoured, no busy loop
    assert "revoked" not in _states(events) and "rejected" not in _states(events)


def test_lost_resync_answers_and_restart_recover_by_retransmission_or_one_fresh_start(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("r1-lost@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r1-lost")
    # (1) Idle 65 s; the start's answer is lost after the server created the challenge.
    with _seam_clock(65.0):  # SEAM-CLOCK
        lost_start = _fault_daemon(_daemon(home, harness, backend), {"/resync/start": ["drop_after"]})
        assert lost_start.status()["state"] == "offline"
        assert _runtime_view(home, harness, backend)["attempt"].challenge_id is None
        # Restart within the challenge lifetime: the byte-identical start returns the same challenge.
        assert _daemon(home, harness, backend).status()["control_plane"]["state"] == "confirmed"
    assert _server_resyncs(harness, workspace_id, runner_id) == ["completed"]
    # (2) Idle again; now the completion's answer is lost after the server completed it.
    with _seam_clock(140.0):  # SEAM-CLOCK
        lost_complete = _fault_daemon(_daemon(home, harness, backend), {"/resync/complete": ["drop_after"]})
        assert lost_complete.status()["state"] == "offline"
        assert _server_claim_generation(harness, workspace_id, runner_id) == 2
        assert _runtime_view(home, harness, backend)["generation"] == 1
        # The exact completion is answered from the server's sealed record: no second challenge.
        assert _daemon(home, harness, backend).status()["control_plane"]["state"] == "confirmed"
    assert _server_resyncs(harness, workspace_id, runner_id) == ["completed", "completed"]
    # (3) Start answer lost, restart only after the challenge expired: the stale retransmission is
    # refused and exactly one fresh start recovers; recovery itself is never a stale-proof trap.
    with _seam_clock(215.0):  # SEAM-CLOCK
        assert _fault_daemon(_daemon(home, harness, backend), {"/resync/start": ["drop_after"]}).status()["state"] == "offline"
    with _seam_clock(290.0):  # SEAM-CLOCK: +75 s, the challenge (60 s) and its proof window expired
        assert _daemon(home, harness, backend).status()["control_plane"]["state"] == "confirmed"
    assert _server_resyncs(harness, workspace_id, runner_id)[-1] == "completed"
    view = _runtime_view(home, harness, backend)
    assert view["pending"] == [] and view["attempt"] is None
    assert view["generation"] == _server_claim_generation(harness, workspace_id, runner_id) == 3


def _rewrite_signature(path, headers, body):
    signature = base64.b64decode(headers["X-Heel-Runner-Signature"])
    headers["X-Heel-Runner-Signature"] = base64.b64encode(bytes([signature[0] ^ 1]) + signature[1:]).decode()
    return path, headers, body


def _rewrite_workspace(path, headers, body):
    workspace = path.split("/")[3]
    # A well-formed workspace that is not this runner's: the edge forwards it, the server refuses.
    return path.replace(workspace, "ws_" + "0" * 16, 1), headers, body


@pytest.mark.parametrize("route, fault, expected", [
    ("/resync/complete", _rewrite_signature, "runner_authentication_rejected"),
    ("/resync/start", _rewrite_signature, "runner_authentication_rejected"),
    # The server's protocol gate answers first for a runner unknown in that workspace (unchanged).
    ("/resync/start", _rewrite_workspace, "protocol_upgrade_required"),
])
def test_forged_or_misdirected_resync_never_supersedes(tmp_path, harness, route, fault, expected):
    workspace_id, cookie = harness.signup_owner(f"r1-forged-{route[8:]}-{fault.__name__}@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r1-forged")
    with _seam_clock(65.0):  # SEAM-CLOCK
        status = _fault_daemon(_daemon(home, harness, backend), {route: [fault, fault]}).status()
    assert status["control_plane"] == {"state": "rejected", "reason": expected}, status
    assert status["state"] in {"runner_authentication_rejected", "active"} and "revoked" not in status["state"]
    view = _runtime_view(home, harness, backend)
    assert view["pending"] == [("list-contexts", 0)] and view["tombstones"] == [] and view["generation"] == 0
    assert _server_claim_generation(harness, workspace_id, runner_id) == 0


def test_a_wrong_generation_in_the_completion_is_refused_then_the_chain_converges(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("r1-generation@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r1-generation")

    class WrongGeneration(_FaultTransport):
        """Test-only: the real server completed; the runner is shown a generation one past it."""

        done = False

        def post(self, path, *, headers=None, body=b""):
            status, response_headers, payload = super().post(path, headers=headers, body=body)
            if path.endswith("/resync/complete") and not WrongGeneration.done:
                WrongGeneration.done = True
                return status, response_headers, {**payload, "generation": payload["generation"] + 1}
            return status, response_headers, payload

    with _seam_clock(65.0):  # SEAM-CLOCK
        daemon = _daemon(home, harness, backend)
        real = RunnerDaemon._transport
        daemon._transport = lambda origin: WrongGeneration(real(daemon, origin), {})
        status = daemon.status()
        assert status["control_plane"] == {"state": "rejected", "reason": "response_rejected"}
        view = _runtime_view(home, harness, backend)
        assert view["pending"] == [("list-contexts", 0)] and view["tombstones"] == [] and view["generation"] == 0
        assert _server_claim_generation(harness, workspace_id, runner_id) == 1  # the server did advance
        # T2b2R2: the completed attempt is kept, so the next check retransmits the exact completion
        # and the server answers it from its sealed record: no second challenge, no extra generation.
        assert _runtime_view(home, harness, backend)["attempt"].complete_body is not None
        assert _daemon(home, harness, backend).status()["control_plane"]["state"] == "confirmed"
    view = _runtime_view(home, harness, backend)
    assert view["generation"] == _server_claim_generation(harness, workspace_id, runner_id) == 1
    assert view["tombstones"] == [("list-contexts", 0, 1)] and view["attempt"] is None
    assert _server_resyncs(harness, workspace_id, runner_id) == ["completed"]


# --------------------------------------------------------------- T2b2R2: kept attempts (finding 4.1)
#
# SEAM-MANGLE (labelled, test-only): the REAL server's 200 resync answer is shown to the runner with
# one field removed; the server itself is unchanged and its challenge/completion rows are real.


class _RouteLog(_FaultTransport):
    """``_FaultTransport`` that also records every resync request it is asked to send, in order."""

    def __init__(self, transport, faults, log, mangle=None):
        super().__init__(transport, faults)
        self._log, self._mangle = log, mangle or {}

    def post(self, path, *, headers=None, body=b""):
        route = path.rsplit("/", 2)
        if route[-2] == "resync":
            self._log.append((route[-1], dict(headers or {}), body))
        status, response_headers, payload = super().post(path, headers=headers, body=body)
        for suffix, (count, field) in self._mangle.items():
            if path.endswith(suffix) and status == 200 and count[0] > 0:
                count[0] -= 1
                return status, response_headers, {k: v for k, v in payload.items() if k != field}
        return status, response_headers, payload


def _logged_daemon(home, harness, backend, log, *, faults=None, mangle=None, **options):
    daemon = _daemon(home, harness, backend, **options)
    real = RunnerDaemon._transport
    daemon._transport = lambda origin: _RouteLog(real(daemon, origin), faults or {}, log, mangle)
    return daemon


def _wire(log, phase):
    return [(headers, body) for name, headers, body in log if name == phase]


@pytest.mark.parametrize("scenario", ["next_valid", "repeated", "after_proof_window", "after_challenge_expiry"])
def test_a_malformed_resync_challenge_keeps_the_signed_start_for_an_exact_retransmission(tmp_path, harness, scenario):
    workspace_id, cookie = harness.signup_owner(f"r2-challenge-{scenario.replace('_', '-')}@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r2-challenge")
    log, mangles = [], [2 if scenario == "repeated" else 1]
    with _seam_clock(65.0):  # SEAM-CLOCK: idle beyond the nonce TTL
        first = _logged_daemon(home, harness, backend, log,
                               mangle={"/resync/start": (mangles, "server_challenge_b64")}).status()
        assert first["control_plane"] == {"state": "rejected", "reason": "response_rejected"}, first
        assert _server_resyncs(harness, workspace_id, runner_id) == ["pending"]
        kept = _runtime_view(home, harness, backend)["attempt"]
        assert kept is not None and kept.challenge_id is None  # the valid signed start is kept
        if scenario == "repeated":
            # Restart (a new daemon and runtime handle); the same malformed body again: refused
            # honestly as a response problem, the start kept, no fresh start, no new challenge.
            again = _logged_daemon(home, harness, backend, log,
                                   mangle={"/resync/start": (mangles, "server_challenge_b64")}).status()
            assert again["control_plane"] == {"state": "rejected", "reason": "response_rejected"}, again
            assert _server_resyncs(harness, workspace_id, runner_id) == ["pending"]
            assert _runtime_view(home, harness, backend)["attempt"] == kept
    shift = {"after_proof_window": 65.0 + 35.0, "after_challenge_expiry": 65.0 + 61.0}.get(scenario, 65.0)
    with _seam_clock(shift):  # SEAM-CLOCK
        # Restart between the answers: a new daemon and runtime handle; the key is active and the
        # clock correct, so this must never be presented as an authentication rejection.
        later = _logged_daemon(home, harness, backend, log).status()
    assert (later["state"], later["control_plane"]["state"]) == ("active", "confirmed"), later
    starts = _wire(log, "start")
    assert all(item == starts[0] for item in starts[:-1])  # every retransmission is byte-identical
    if scenario == "after_challenge_expiry":
        # The server invalidated the expired challenge and refused the stale retransmission; exactly
        # one fresh start (a different nonce and signature) then recovered.
        assert _server_resyncs(harness, workspace_id, runner_id) == ["invalidated", "completed"]
        assert starts[-1] != starts[0] and len(starts) == 3
    else:
        # Within the challenge lifetime (even after the 30 s proof window) the exact start is answered
        # from the server's own record: one challenge, completed, no fresh start.
        assert _server_resyncs(harness, workspace_id, runner_id) == ["completed"]
        assert starts[-1] == starts[0] and len(starts) == (3 if scenario == "repeated" else 2)
    view = _runtime_view(home, harness, backend)
    assert view["pending"] == [] and view["attempt"] is None and view["tombstones"] == [("list-contexts", 0, 1)]
    assert view["generation"] == _server_claim_generation(harness, workspace_id, runner_id) == 1


@pytest.mark.parametrize("scenario", ["next_valid", "repeated", "after_completed_cache"])
def test_a_malformed_resync_completion_keeps_the_attempt_and_the_exact_retransmission_converges(tmp_path, harness, scenario):
    workspace_id, cookie = harness.signup_owner(f"r2-completion-{scenario.replace('_', '-')}@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r2-completion")
    log, mangles = [], [2 if scenario == "repeated" else 1]
    with _seam_clock(65.0):  # SEAM-CLOCK
        first = _logged_daemon(home, harness, backend, log,
                               mangle={"/resync/complete": (mangles, "next_nonce_b64")}).status()
        assert first["control_plane"] == {"state": "rejected", "reason": "response_rejected"}, first
        # The real server committed; nothing was installed locally and the exact completion is kept.
        assert _server_resyncs(harness, workspace_id, runner_id) == ["completed"]
        assert _server_claim_generation(harness, workspace_id, runner_id) == 1
        view = _runtime_view(home, harness, backend)
        assert view["generation"] == 0 and view["pending"] == [("list-contexts", 0)] and view["tombstones"] == []
        assert view["attempt"].complete_body is not None
        if scenario == "repeated":
            again = _logged_daemon(home, harness, backend, log,
                                   mangle={"/resync/complete": (mangles, "next_nonce_b64")}).status()
            assert again["control_plane"] == {"state": "rejected", "reason": "response_rejected"}, again
            assert _server_resyncs(harness, workspace_id, runner_id) == ["completed"]
    # The server's completed cache answers an exact completion for 600 s.
    shift = 65.0 + 601.0 if scenario == "after_completed_cache" else 65.0
    with _seam_clock(shift):  # SEAM-CLOCK
        later = _logged_daemon(home, harness, backend, log).status()
    assert (later["state"], later["control_plane"]["state"]) == ("active", "confirmed"), later
    completes = _wire(log, "complete")
    view = _runtime_view(home, harness, backend)
    if scenario == "after_completed_cache":
        # Past the cache the exact completion is refused, the single re-sign of the same body is
        # refused too (the server holds the original digest), the exact start probe is refused (no
        # pending challenge matches it), then exactly one fresh start.
        starts = _wire(log, "start")
        assert _server_resyncs(harness, workspace_id, runner_id) == ["completed", "completed"]
        assert len(starts) == 3 and starts[1] == starts[0] and starts[2] != starts[0]
        assert len(completes) == 4 and completes[1] == completes[0]
        assert completes[2][1] == completes[0][1] and completes[2][0] != completes[0][0]
        assert view["tombstones"] == [("list-contexts", 0, 2)]
    else:
        assert _server_resyncs(harness, workspace_id, runner_id) == ["completed"]
        assert len(_wire(log, "start")) == 1 and all(item == completes[0] for item in completes)
        assert view["tombstones"] == [("list-contexts", 0, 1)]
    assert view["pending"] == [] and view["attempt"] is None
    assert view["generation"] == _server_claim_generation(harness, workspace_id, runner_id)


@pytest.mark.parametrize("phase, fault, shift, expected", [
    # Start lost after the server created its challenge; retry after the 30 s proof window.
    ("start", "drop_after", 35.0, "retransmitted"),
    # Start never reached the server; the stale retransmission is refused, one fresh start.
    ("start", "drop_before", 35.0, "fresh_start"),
    # Completion committed, answer lost; the exact completion is answered from the server's cache.
    ("complete", "drop_after", 35.0, "retransmitted"),
    # Completion never reached the server: the challenge is still pending and the stale proof is
    # refused; the identical completion body is re-signed once and the server accepts it.
    ("complete", "drop_before", 35.0, "resigned"),
])
def test_lost_resync_requests_and_answers_at_the_proof_window_boundary(tmp_path, harness, phase, fault, shift, expected):
    workspace_id, cookie = harness.signup_owner(f"r2-boundary-{phase}-{fault.replace('_', '-')}@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r2-boundary")
    log = []
    with _seam_clock(65.0):  # SEAM-CLOCK
        first = _logged_daemon(home, harness, backend, log, faults={f"/resync/{phase}": [fault]}).status()
        assert first["state"] == "offline", first
        assert _server_resyncs(harness, workspace_id, runner_id) == (
            [] if (phase, fault) == ("start", "drop_before")
            else ["completed"] if (phase, fault) == ("complete", "drop_after") else ["pending"]
        )
    with _seam_clock(65.0 + shift):  # SEAM-CLOCK: past the proof window, inside the challenge lifetime
        later = _logged_daemon(home, harness, backend, log).status()
    assert (later["state"], later["control_plane"]["state"]) == ("active", "confirmed"), later
    starts, completes = _wire(log, "start"), _wire(log, "complete")
    assert _server_resyncs(harness, workspace_id, runner_id) == ["completed"]
    if expected == "fresh_start":
        assert len(starts) == 3 and starts[1] == starts[0] and starts[2] != starts[0]
    elif phase == "start":
        assert len(starts) == 2 and starts[1] == starts[0]
    else:
        assert len(starts) == 1  # the challenge was recorded; only the completion is retransmitted
    if expected == "resigned":
        # The retransmission was byte-identical; the re-signed request carries the same body and a
        # new proof; the server accepted exactly one completion.
        assert len(completes) == 3 and completes[1] == completes[0]
        assert completes[2][1] == completes[0][1] and completes[2][0] != completes[0][0]
    elif phase == "complete":
        assert len(completes) == 2 and completes[1] == completes[0]
    view = _runtime_view(home, harness, backend)
    assert view["pending"] == [] and view["attempt"] is None and view["tombstones"] == [("list-contexts", 0, 1)]
    assert view["generation"] == _server_claim_generation(harness, workspace_id, runner_id) == 1


def test_a_resigned_completion_is_never_a_second_acceptance_of_a_completed_challenge(tmp_path, harness):
    """Server idempotency (heel/saas/runner_auth.py complete_resync, unchanged): a completed
    challenge answers only its original signed digest; a re-signed copy of the same body is refused
    and never completes that challenge again. SEAM-TAMPER-SIGNATURE (test-only) corrupts one
    retransmission in transit so the client is made to re-sign a completion the server committed."""
    workspace_id, cookie = harness.signup_owner("r2-resigned-completed@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r2-resigned")
    log = []
    with _seam_clock(65.0):  # SEAM-CLOCK
        assert _logged_daemon(home, harness, backend, log,
                              faults={"/resync/complete": ["drop_after"]}).status()["state"] == "offline"
        assert _server_resyncs(harness, workspace_id, runner_id) == ["completed"]
        assert _server_claim_generation(harness, workspace_id, runner_id) == 1
        later = _logged_daemon(home, harness, backend, log,
                               faults={"/resync/complete": [_rewrite_signature]}).status()
    completes, starts = _wire(log, "complete"), _wire(log, "start")
    # original (answer lost), exact retransmission (corrupted in transit, 401), the re-signed same
    # body (refused: the completed record holds the original digest) -- never a second acceptance.
    assert completes[1] == completes[0]
    assert completes[2][1] == completes[0][1] and completes[2][0] != completes[0][0]
    # The exact start probe: the committed challenge is no longer pending and the start's proof is
    # still fresh, so the server answers with a NEW challenge for that start; the client adopts it
    # as this recovery's one fresh start and completes it (no orphaned challenge is left).
    assert len(starts) == 2 and starts[1] == starts[0]
    assert len(completes) == 4 and completes[3][1] != completes[0][1]
    assert (later["state"], later["control_plane"]["state"]) == ("active", "confirmed"), later
    assert _server_resyncs(harness, workspace_id, runner_id) == ["completed", "completed"]
    view = _runtime_view(home, harness, backend)
    assert view["generation"] == _server_claim_generation(harness, workspace_id, runner_id) == 2
    assert view["tombstones"] == [("list-contexts", 0, 2)] and view["attempt"] is None


def test_a_probe_created_challenge_is_never_orphaned_for_a_later_lost_call(tmp_path, harness):
    """The start probe inside its 30 s proof window after the first challenge was completed makes
    the server create a NEW challenge for the same signed start. That challenge must be completed
    (adopted as this recovery's one fresh start), never left pending: a later call lost before
    commit and retried after the proof window must not hit it as a false authentication refusal."""
    workspace_id, cookie = harness.signup_owner("r2-probe-orphan@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r2-orphan")
    log = []
    with _seam_clock(65.0):  # SEAM-CLOCK
        assert _logged_daemon(home, harness, backend, log,
                              faults={"/resync/complete": ["drop_after"]}).status()["state"] == "offline"
        # SEAM-TAMPER-SIGNATURE on the exact retransmission: retransmission and re-sign refused,
        # the probe gets a new challenge for the same start.
        tampered = _logged_daemon(home, harness, backend, log,
                                  faults={"/resync/complete": [_rewrite_signature]}).status()
        print("probe-created challenge outcome:", tampered["state"], tampered["control_plane"],
              _server_resyncs(harness, workspace_id, runner_id))
        settled = _logged_daemon(home, harness, backend, log).status()
        assert (settled["state"], settled["control_plane"]["state"]) == ("active", "confirmed"), settled
        assert "pending" not in _server_resyncs(harness, workspace_id, runner_id)  # nothing orphaned
        assert _runtime_view(home, harness, backend)["attempt"] is None
        # A later control call is lost before it reaches the server ...
        lost = _logged_daemon(home, harness, backend, log, faults={"/contexts/list": ["drop_before"]}).status()
        assert lost["state"] == "offline", lost
    with _seam_clock(65.0 + 35.0):  # SEAM-CLOCK: ... and retried after the proof window
        retried = _logged_daemon(home, harness, backend, log).status()
    assert (retried["state"], retried["control_plane"]["state"]) == ("active", "confirmed"), retried
    resyncs = _server_resyncs(harness, workspace_id, runner_id)
    assert "pending" not in resyncs and resyncs.count("completed") == len(resyncs)
    view = _runtime_view(home, harness, backend)
    assert view["pending"] == [] and view["attempt"] is None
    assert view["generation"] == _server_claim_generation(harness, workspace_id, runner_id)


def test_a_resigned_completion_is_refused_for_a_revoked_key_and_creates_nothing(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("r2-resigned-revoked@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r2-revoked")
    log = []
    with _seam_clock(65.0):  # SEAM-CLOCK
        assert _logged_daemon(home, harness, backend, log,
                              faults={"/resync/complete": ["drop_before"]}).status()["state"] == "offline"
    assert harness.request(
        "POST", f"/v1/workspaces/{workspace_id}/runners/{runner_id}/revoke", REVOKE_BODY, cookie=cookie,
    )[0] == 200
    resyncs = _server_resyncs(harness, workspace_id, runner_id)
    generation = _server_claim_generation(harness, workspace_id, runner_id)  # as the revocation left it
    for shift in (65.0 + 35.0, 65.0 + 200.0):  # inside the challenge lifetime, then long after it
        with _seam_clock(shift):  # SEAM-CLOCK
            status = _logged_daemon(home, harness, backend, log).status()
        assert status["state"] == "runner_authentication_rejected", status
        assert status["control_plane"] == {"state": "rejected", "reason": "runner_authentication_rejected"}
    # The revoked key never completed or created a challenge (the server checks the active key first).
    assert _server_resyncs(harness, workspace_id, runner_id) == resyncs
    assert all(item != "completed" for item in resyncs)
    assert _server_claim_generation(harness, workspace_id, runner_id) == generation
    view = _runtime_view(home, harness, backend)
    assert view["pending"] == [("list-contexts", 0)] and view["tombstones"] == [] and view["generation"] == 0


@pytest.mark.parametrize("skew_ms", [-120_000, 120_000])
def test_a_wrong_clock_never_drops_a_pending_attempt_and_correcting_it_recovers_at_once(tmp_path, harness, skew_ms):
    workspace_id, cookie = harness.signup_owner(f"r2-resigned-clock-{skew_ms > 0}@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r2-clock")
    log = []
    with _seam_clock(65.0):  # SEAM-CLOCK
        assert _logged_daemon(home, harness, backend, log,
                              faults={"/resync/complete": ["drop_before"]}).status()["state"] == "offline"
        original = _runtime_view(home, harness, backend)["attempt"]
    with _seam_clock(65.0 + 35.0):  # SEAM-CLOCK; the runner's own clock is additionally wrong
        skewed = _logged_daemon(home, harness, backend, log,
                                clock_ms=lambda: time.time_ns() // 1_000_000 + skew_ms).status()
        assert skewed["state"] == "runner_authentication_rejected", skewed
        assert any("clock" in step for step in skewed["next_steps"])
        # Retransmission and the one re-sign refused (the proof's clock); the exact start probe was
        # answered with this attempt's own pending challenge, so nothing is dropped or started.
        completes, starts = _wire(log, "complete"), _wire(log, "start")
        assert len(completes) == 3 and len(starts) == 2 and starts[1] == starts[0]
        assert _server_resyncs(harness, workspace_id, runner_id) == ["pending"]
        assert _server_claim_generation(harness, workspace_id, runner_id) == 0
        kept = _runtime_view(home, harness, backend)["attempt"]
        assert kept.challenge_id == original.challenge_id
        assert kept.complete_headers == original.complete_headers  # the original completion restored
        corrected = _logged_daemon(home, harness, backend, log).status()
    # Corrected clock: the stale retransmission is refused, the identical body is re-signed and
    # accepted for the same pending challenge. Never "revoked", never a fresh start.
    assert (corrected["state"], corrected["control_plane"]["state"]) == ("active", "confirmed"), corrected
    assert _server_resyncs(harness, workspace_id, runner_id) == ["completed"]
    assert len(_wire(log, "start")) == 2 and len(_wire(log, "complete")) == 5
    view = _runtime_view(home, harness, backend)
    assert view["pending"] == [] and view["attempt"] is None and view["tombstones"] == [("list-contexts", 0, 1)]
    assert view["generation"] == _server_claim_generation(harness, workspace_id, runner_id) == 1


def _issue_grant_fixture(harness, workspace_id, cookie, base, binding, runner_id, runner_key_id, seed):
    """SEAM-GRANT-FIXTURE (explicit): issue ONE real grant for this paired runner.

    The owner's projection submit and execution approval go straight to the control plane backend
    (``_direct_backend``: the edge harness does not mirror those routes) with the owner session; the
    approval projection is signed with the paired runner's own key, as the runner will in T3b. It
    proves recovery against a real issued grant only, not browser approval or launch acceptance.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from heel.canary_contracts import canonical_digest
    from tests.canary_test_support import approval_projection

    runner_key = SigningAuthority.from_private_key(Ed25519PrivateKey.from_private_bytes(seed), runner_key_id)
    environment = binding["environment"]
    projection = approval_projection(
        runner_key, workspace_id=workspace_id, project_ref=binding["project_id"],
        environment_id=environment["environment_id"], runner_id=runner_id,
        verification_digest=environment["verification_record_digest"],
    )
    identity = json.loads(harness.control_plane.store.conn.execute(
        "SELECT identity_json FROM canary_runner_identity_records WHERE workspace_id=? AND runner_id=?",
        (workspace_id, runner_id),
    ).fetchone()[0])
    projection = {k: v for k, v in projection.items() if k not in {"projection_digest", "signing_key_id", "signature_b64"}}
    projection["environment"]["origin"] = environment["origin"]
    projection["egress"]["hostname"] = environment["origin"].split("//", 1)[1]
    projection["runner"].update(runner_version=identity["runner_version"], adapter_versions=identity["adapter_versions"])
    for item in projection["scenarios"] + projection["actions"]:
        item["adapter_version"] = identity["adapter_versions"][0]
    projection["projection_digest"] = canonical_digest(projection)
    projection.update(runner_key.sign(canonical_bytes({k: v for k, v in projection.items() if k != "projection_digest"})))
    owner = [("X-Heel-Edge-Auth", harness.edge_secret), ("Cookie", cookie), ("Origin", harness.origin),
             ("X-Heel-Internal-Origin", "same-origin"), ("Content-Type", "application/json")]
    body = canonical_bytes(projection)
    status, submitted = _direct_backend(harness, "POST", f"{base}/canary-approval-projections", body,
                                        owner + [("Content-Length", str(len(body)))])
    assert status == 201, submitted
    approve = canonical_bytes({
        "schema_version": "heel.canary-execution-approval.v1", "projection_digest": projection["projection_digest"],
        "hostname_retype": projection["egress"]["hostname"], "reason": "Run the exact bounded staging rehearsal",
    })
    status, approved = _direct_backend(harness, "POST", f"{base}/canary-runs/{submitted['run_id']}/approve", approve, owner + [
        ("Content-Length", str(len(approve))), ("Idempotency-Key", "ca1-" + "a" * 64), ("If-Heel-Control-Generation", "0"),
    ])
    assert status == 201, approved
    return approved["grant"]["grant_id"]


def _grant_effects(harness, workspace_id):
    conn = harness.control_plane.store.conn
    return {
        "grants": [row[0] for row in conn.execute(
            "SELECT status FROM canary_execution_grants WHERE workspace_id=?", (workspace_id,))],
        "consumed_nonces": conn.execute(
            "SELECT COUNT(*) FROM canary_consumed_nonces WHERE workspace_id=?", (workspace_id,)).fetchone()[0],
        "run_chains": conn.execute(
            "SELECT COUNT(*) FROM canary_runner_chain_cursors WHERE workspace_id=? AND chain_name!='claim'",
            (workspace_id,)).fetchone()[0],
    }


def _bound_runner_with_staged_claim(tmp_path, serve_harness, name, *, fault="drop_before", grant=False):
    harness, zone = serve_harness
    workspace_id, cookie = harness.signup_owner(f"r1-{name}@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, name)
    record = _daemon_record(home)
    base, binding = _authorize_binding(harness, zone, workspace_id, cookie, runner_id, record["runner_key_id"])
    assert _serve_once(_daemon(home, harness, backend))["state"] == "stopped"  # bound, online, idle
    if grant and fault == "drop_after":
        # The grant exists before the lost answer: the server claims it, the runner never hears.
        _issue_grant_fixture(harness, workspace_id, cookie, base, binding, runner_id,
                             record["runner_key_id"], next(iter(backend.values.values())))
    lost = _fault_daemon(_daemon(home, harness, backend), {f"/runners/{runner_id}/claim": [fault]})
    assert isinstance(_serve_once(lost), daemon_module.RunnerServeError)
    assert _runtime_view(home, harness, backend)["pending"] == [("claim", 0)]
    if grant and fault == "drop_before":
        _issue_grant_fixture(harness, workspace_id, cookie, base, binding, runner_id,
                             record["runner_key_id"], next(iter(backend.values.values())))
    return harness, workspace_id, home, backend, runner_id


def _claim_ledger(harness, workspace_id, runner_id):
    return [tuple(row) for row in harness.control_plane.store.conn.execute(
        "SELECT sequence,generation,response_status,path FROM canary_runner_request_ledger "
        "WHERE workspace_id=? AND runner_id=? AND chain_name='claim'", (workspace_id, runner_id))]


def test_serve_resumes_after_an_outage_longer_than_the_proof_window_with_a_staged_job_claim(tmp_path, serve_harness):
    harness, workspace_id, home, backend, runner_id = _bound_runner_with_staged_claim(tmp_path, serve_harness, "r1-jobq")
    with _seam_clock(35.0):  # SEAM-CLOCK
        result = _serve_once(_daemon(home, harness, backend))
    assert not isinstance(result, BaseException), (result.state, result.code)
    assert result["state"] == "stopped" and result["binding_id"] is not None
    view = _runtime_view(home, harness, backend)
    assert view["pending"] == [] and view["attempt"] is None and view["tombstones"] == [("claim", 0, 1)]
    assert _server_resyncs(harness, workspace_id, runner_id) == ["completed"]
    assert _grant_effects(harness, workspace_id) == {"grants": [], "consumed_nonces": 0, "run_chains": 0}
    # The latest claim-chain receipt is the NEW signed poll at the recovered generation (idle 204).
    ((_sequence, generation, status, path),) = _claim_ledger(harness, workspace_id, runner_id)
    assert (generation, status, path.endswith("/claim")) == (1, 204, True)


def test_a_superseded_job_claim_then_claims_an_existing_grant_exactly_once(tmp_path, serve_harness):
    harness, workspace_id, home, backend, runner_id = _bound_runner_with_staged_claim(
        tmp_path, serve_harness, "r1-jobg", grant=True,
    )
    assert _grant_effects(harness, workspace_id)["grants"] == ["issued"]
    with _seam_clock(35.0):  # SEAM-CLOCK
        result = _serve_once(_daemon(home, harness, backend))
    # The fresh poll takes the grant; serve has no execution bridge yet and fails closed.
    assert (result.state, result.code) == ("failed", "execution_unavailable")
    assert _grant_effects(harness, workspace_id) == {"grants": ["claimed"], "consumed_nonces": 1, "run_chains": 4}
    view = _runtime_view(home, harness, backend)
    assert view["tombstones"] == [("claim", 0, 1)] and view["pending"] == []


def test_a_job_claim_answer_lost_after_commit_replays_its_receipt_without_resync(tmp_path, serve_harness):
    harness, workspace_id, home, backend, runner_id = _bound_runner_with_staged_claim(
        tmp_path, serve_harness, "r1-jobc", fault="drop_after", grant=True,
    )
    assert _grant_effects(harness, workspace_id)["grants"] == ["claimed"]
    receipt = _claim_ledger(harness, workspace_id, runner_id)
    (claimed_run,) = [row[0] for row in harness.control_plane.store.conn.execute(
        "SELECT run_id FROM canary_runs WHERE workspace_id=? AND status='claimed'", (workspace_id,))]
    with _seam_clock(65.0):  # SEAM-CLOCK: beyond the proof window; the receipt lookup comes first
        result = _serve_once(_daemon(home, harness, backend))
    # Recovery part, proven: the staged call resolved from its sealed receipt (no resync, no new
    # claim, server effects unchanged) and the claimed run is durably installed locally, not lost.
    assert _server_resyncs(harness, workspace_id, runner_id) == []
    assert _grant_effects(harness, workspace_id) == {"grants": ["claimed"], "consumed_nonces": 1, "run_chains": 4}
    assert _claim_ledger(harness, workspace_id, runner_id) == receipt
    view = _runtime_view(home, harness, backend)
    assert view["pending"] == [] and view["tombstones"] == [] and view["active_runs"] == [claimed_run]
    # NOT functional recovery: a pre-T4a limitation. The claimed run has no local approved pair, so
    # startup hydration fails closed; restart-after-claim is owned by T4a (recorded for review).
    assert (result.state, result.code) == ("failed", "local_state_invalid")


def test_a_consumed_job_claim_sequence_behind_an_expired_receipt_is_kept_as_recovery_required(tmp_path, serve_harness):
    harness, workspace_id, home, backend, runner_id = _bound_runner_with_staged_claim(
        tmp_path, serve_harness, "r1-jobx", fault="drop_after",
    )
    ((sequence, generation, status, _path),) = _claim_ledger(harness, workspace_id, runner_id)
    assert (generation, status) == (0, 204)  # committed idle poll, answer lost
    # SEAM-CLOCK: past the 30-day receipt retention -> the exact replay answers 401 although the
    # sequence was consumed; the accepted resync's cursor (S + 1) proves it and nothing is retired.
    with _seam_clock(31 * 86_400.0):
        result = _serve_once(_daemon(home, harness, backend))
        status_view = _daemon(home, harness, backend).status()
    assert (result.state, result.code) == ("failed", "recovery_required")
    assert status_view["state"] == "recovery_required"
    assert status_view["control_plane"] == {
        "state": "recovery_required", "reason": "claim_sequence_consumed", "operation": "claim",
    }
    view = _runtime_view(home, harness, backend)
    assert view["pending"] == [("claim", 0)] and view["tombstones"] == [] and view["generation"] == 0
    assert view["attempt"] is not None and view["attempt"].complete_body is not None
    assert _server_claim_generation(harness, workspace_id, runner_id) == 1


def test_a_forged_completion_for_a_staged_job_claim_never_supersedes(tmp_path, serve_harness):
    harness, workspace_id, home, backend, runner_id = _bound_runner_with_staged_claim(tmp_path, serve_harness, "r1-jobf")

    class ForgedCompletion(_FaultTransport):
        """Test-only: the real server completed; the runner is shown a sequence past it."""

        def post(self, path, *, headers=None, body=b""):
            status, response_headers, payload = super().post(path, headers=headers, body=body)
            if path.endswith("/resync/complete"):
                return status, response_headers, {**payload, "next_sequence": payload["next_sequence"] + 1}
            return status, response_headers, payload

    daemon = _daemon(home, harness, backend)
    real = RunnerDaemon._transport
    daemon._transport = lambda origin: ForgedCompletion(real(daemon, origin), {})
    with _seam_clock(35.0):  # SEAM-CLOCK
        result = _serve_once(daemon)
    assert (result.state, result.code) == ("failed", "recovery_required")
    view = _runtime_view(home, harness, backend)
    assert view["pending"] == [("claim", 0)] and view["tombstones"] == [] and view["generation"] == 0
    assert _grant_effects(harness, workspace_id)["consumed_nonces"] == 0


# --------------------------------------------------------------- T2b2R1 F2/F3/F4: live status ownership


def test_concurrent_live_status_checks_are_serialized_and_both_confirm(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("r1-f4@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r1-f4")
    holder = _daemon(home, harness, backend)
    gate = _gate_daemon(holder)
    gate["armed"].set()
    results: dict[str, dict] = {}
    first = threading.Thread(target=lambda: results.setdefault("first", holder.status()))
    first.start()
    assert gate["holding"].wait(10)  # the first check's answer is in flight
    second = threading.Thread(target=lambda: results.setdefault("second", _daemon(home, harness, backend).status()))
    second.start()
    time.sleep(0.5)
    assert second.is_alive()  # waits for the turnstile; it never shares the claim chain
    gate["release"].set()
    first.join(10); second.join(10)
    assert results["first"]["control_plane"]["state"] == "confirmed", results
    assert results["second"]["control_plane"]["state"] == "confirmed", results


def test_serve_start_waits_for_a_status_check_and_reports_contention_distinctly(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("r1-f2@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r1-f2")
    holder = _daemon(home, harness, backend)
    gate = _gate_daemon(holder)
    gate["armed"].set()
    checked: dict[str, dict] = {}
    status_thread = threading.Thread(target=lambda: checked.setdefault("status", holder.status()))
    status_thread.start()
    assert gate["holding"].wait(10)
    # A short-grace serve gives up with ``status_busy`` (never ``already_serving``) ...
    impatient = _daemon(home, harness, backend, transport_timeout_seconds=0.1)
    started = time.monotonic()
    with pytest.raises(daemon_module.RunnerServeError) as busy:
        impatient.serve()
    assert busy.value.code == "status_busy" and time.monotonic() - started < 5
    # ... and a normal serve simply starts once the check is over.
    serving = _daemon(home, harness, backend)
    thread, events, outcome = _serve_in_thread(serving)
    time.sleep(0.3)
    assert thread.is_alive() and _serve_state(home) is None
    gate["release"].set()
    status_thread.join(10)
    _wait_serve_state(home, lambda state: state["state"] == "online")
    serving.request_stop()
    thread.join(10)
    assert outcome["result"]["state"] == "stopped" and checked["status"]["control_plane"]["state"] == "confirmed"


class _GatedLoadBackend(RecordingSecretBackend):
    """Holds identity loads while armed (a slow OS secret store during serve startup or unpair)."""

    def __init__(self, values):
        super().__init__()
        self.values = values
        self.armed, self.entered, self.release = threading.Event(), threading.Event(), threading.Event()

    def load(self, label):
        if self.armed.is_set():
            self.armed.clear()
            self.entered.set()
            assert self.release.wait(30)
        return super().load(label)

    def delete(self, label):
        if self.armed.is_set():
            self.armed.clear()
            self.entered.set()
            assert self.release.wait(30)
        super().delete(label)


def test_status_never_presents_a_previous_serve_file_during_startup_or_unpair(tmp_path, harness):
    workspace_id, cookie = harness.signup_owner("r1-f3@example.test")
    home, backend, runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, "r1-f3")
    assert _serve_once(_daemon(home, harness, backend))["state"] == "stopped"
    previous = _serve_state(home)
    assert previous["state"] == "stopped"
    gated = _GatedLoadBackend(backend.values)
    gated.armed.set()
    serving = _daemon(home, harness, gated)
    thread, _events, outcome = _serve_in_thread(serving)
    assert gated.entered.wait(10)  # serve owns the instance and is still loading its identity
    view = _daemon(home, harness, backend).status(check_control_plane=False)
    # The published state identifies the new serve's file. since_ms/updated_at_ms are descriptive
    # wall-clock readings with no order across serves (see the injected-clock restart tests below).
    assert view["serve"]["state"] == "starting", view
    gated.release.set()
    _wait_serve_state(home, lambda state: state["state"] == "online")
    serving.request_stop()
    thread.join(10)
    assert outcome["result"]["state"] == "stopped"
    # During an unpair (held inside its seed removal), status says so instead of describing a
    # half-removed instance or a previous serve as live; a serve is still refused at once.
    gated = _GatedLoadBackend(backend.values)
    unpairing = _daemon(home, harness, gated)
    gated.armed.set()
    done: dict[str, dict] = {}
    unpair_thread = threading.Thread(target=lambda: done.setdefault("unpair", unpairing.unpair()))
    unpair_thread.start()
    assert gated.entered.wait(10)
    during = _daemon(home, harness, backend).status()
    assert during["state"] == "unpairing" and during["serve"]["state"] == "unpairing", during
    assert during["control_plane"] == {"state": "not_checked", "reason": "unpair_running"}
    with pytest.raises(daemon_module.RunnerServeError) as refused:
        _daemon(home, harness, backend).serve(once=True)
    assert refused.value.code == "already_serving"
    gated.release.set()
    unpair_thread.join(10)
    assert done["unpair"]["removed"] is True
    assert _daemon(home, harness, backend).status() == {"state": "unpaired"} and _serve_state(home) is None


_SERVE_VIEW_FIELDS = ("state", "since_ms", "updated_at_ms", "last_error_code", "binding_id", "pid")


@contextlib.contextmanager
def _restart_held_in_identity_load(tmp_path, harness, name, clock_before_load):
    """Serve once, then restart a serve held in its identity load and yield ``(previous, view)``:
    the previous serve's file and status while the restart is held. Only the restarted daemon's
    ``clock_ms`` is injected: ``clock_before_load(previous)`` until the load is entered, real time
    after it (before any signed call). The gate is released and the serve stopped and joined
    even when an assertion fails."""
    workspace_id, cookie = harness.signup_owner(f"{name}@example.test")
    home, backend, _runner_id = _pair_runner(tmp_path, harness, workspace_id, cookie, name)
    assert _serve_once(_daemon(home, harness, backend))["state"] == "stopped"
    previous = _serve_state(home)
    assert previous["state"] == "stopped"
    gated = _GatedLoadBackend(backend.values)

    def clock():
        return daemon_module._now_ms() if gated.entered.is_set() else clock_before_load(previous)

    gated.armed.set()
    serving = _daemon(home, harness, gated, clock_ms=clock)
    thread, _events, outcome = _serve_in_thread(serving)
    try:
        assert gated.entered.wait(10)  # serve owns the instance and is still loading its identity
        yield previous, _daemon(home, harness, backend).status(check_control_plane=False)
        gated.release.set()
        _wait_serve_state(home, lambda state: state["state"] == "online")
    finally:
        gated.release.set()
        serving.request_stop()
        thread.join(10)
    assert not thread.is_alive() and outcome["result"]["state"] == "stopped", outcome


def test_status_shows_the_restarted_serve_when_it_starts_in_the_same_millisecond(tmp_path, harness):
    """D-H1F-1: the restart's ``starting`` publish reads the same millisecond as the previous serve
    file's last update. Equal stamps are expected; the state identifies the new file."""
    with _restart_held_in_identity_load(
        tmp_path, harness, "q1i-equal-ms", lambda previous: previous["updated_at_ms"],
    ) as (previous, view):
        assert view["serve"]["state"] == "starting", (view, previous)
        assert view["serve"]["since_ms"] == view["serve"]["updated_at_ms"] == previous["updated_at_ms"]


def test_status_would_present_a_stale_file_without_the_starting_publish(tmp_path, harness, monkeypatch):
    """Control: without the ``starting`` publish before the turnstile opens, status presents the
    previous serve's file as the running serve, field for field, under the same-millisecond clock.
    The state oracle above is what detects that; no timestamp can."""
    publish = daemon_module._ServeSession._publish

    def without_starting(session, state, **options):
        if state != "starting":
            publish(session, state, **options)

    monkeypatch.setattr(daemon_module._ServeSession, "_publish", without_starting)
    with _restart_held_in_identity_load(
        tmp_path, harness, "q1i-stale", lambda previous: previous["updated_at_ms"],
    ) as (previous, view):
        assert view["serve"] == {key: previous[key] for key in _SERVE_VIEW_FIELDS}, (view, previous)
        assert view["serve"]["state"] == "stopped"


def test_status_shows_the_restarted_serve_when_the_clock_stepped_back(tmp_path, harness):
    """The wall clock stepped back 5 s across the restart: the new file carries older stamps than
    the previous one and is still the one status presents."""
    with _restart_held_in_identity_load(
        tmp_path, harness, "q1i-step-back", lambda previous: previous["updated_at_ms"] - 5_000,
    ) as (previous, view):
        assert view["serve"]["state"] == "starting", (view, previous)
        assert view["serve"]["since_ms"] == view["serve"]["updated_at_ms"] == previous["updated_at_ms"] - 5_000


def test_edge_harness_default_route_refuses_a_malformed_bearer_like_the_worker(tmp_path, harness):
    """F5: ``controlPlaneCredentials`` refuses any non-empty Authorization that is not an API-key or
    device bearer before forwarding; valid project routes still work with the session cookie."""
    workspace_id, cookie = harness.signup_owner("r1-f5@example.test")
    path = f"/v1/workspaces/{workspace_id}/projects"
    for value in ("Bearer not-an-api-key", "Basic abc", "Bearer heel_sk_", "Bearer heel_at_" + "a" * 42, "x"):
        forwarded = len(harness.forwarded)
        status, _body, _ = harness.request("POST", path, {"name": "P"}, cookie=cookie, headers={"Authorization": value})
        assert status == 400 and len(harness.forwarded) == forwarded, value
    forwarded = len(harness.forwarded)
    assert harness.request("POST", path, {"name": "P"}, cookie=cookie)[0] == 201
    assert harness.request("POST", path, {"name": "Q"}, cookie=cookie, headers={"Authorization": "  "})[0] == 201
    assert len(harness.forwarded) == forwarded + 2
    # A well-formed API-key bearer is forwarded (the control plane, not the edge, decides on it).
    forwarded = len(harness.forwarded)
    harness.request("GET", path, headers={"Authorization": "Bearer heel_sk_" + "a" * 32})
    assert len(harness.forwarded) == forwarded + 1
