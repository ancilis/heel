"""Runner protocol frames through the actual public Worker (``worker/index.ts`` in ``workerd``).

``tests/test_runner_daemon.py`` proves the runner against ``EdgeTLSHarness``, a Python mirror of
the Worker. The deployed Worker refused the paired rc2 runner's first signed control call
(``POST …/contexts/list`` → HTTP 400 ``invalid control plane request``) because the mirror and
the real runtime differ. These tests drive the same product code (``RunnerDaemon`` with the real
``HTTPSControlTransport`` and ``RunnerControlClient`` signing) through ``WorkerdEdgeHarness``:
the unchanged Worker sources in ``workerd`` at the production compatibility date, in front of the
real ``serve(ControlPlane(...))``. Seams are listed in ``tests/support/workerd_edge.py``
(SEAM-APP, SEAM-EDGE-CA, SEAM-CF-CONNECTION, SEAM-HOST) plus the existing SEAM-SECRET-BACKEND
and SEAM-ENV-DNS of the daemon tests. Nothing is seeded into the control plane.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from heel.crypto import SigningAuthority
from heel.runner.store import RunnerStore
from tests.support.workerd_edge import WorkerdEdgeHarness, workerd_available
from tests.test_runner_daemon import (
    RecordingSecretBackend, _authorize_binding, _daemon, _daemon_record, _home, _invite,
    _pair_with_owner_approval, _serve_once,
)

pytestmark = pytest.mark.skipif(not workerd_available(), reason="apps/heel-cloud node_modules (workerd, esbuild) not installed")

REFUSED = (400, b'{"error":"invalid control plane request"}')


def _edge(tmp_path, **options):
    zone: dict[str, list[str]] = {}
    authority = SigningAuthority.generate()
    return WorkerdEdgeHarness(
        tmp_path / "cloud", grant_authority=authority,
        grant_trusted_keys={authority.key_id: authority.public_key},
        environment_dns_txt=lambda name: list(zone.get(name, ())),  # SEAM-ENV-DNS
        **options,
    ), zone


@pytest.fixture
def worker_edge(tmp_path):
    edge, zone = _edge(tmp_path)
    with edge:
        yield edge, zone


def _paired(tmp_path, edge, name):
    workspace_id, cookie = edge.signup_owner(f"owner-{name}@example.test")
    home, backend = _home(tmp_path, name), RecordingSecretBackend()
    events, outcome = _pair_with_owner_approval(
        edge, _daemon(home, edge, backend), workspace_id, cookie, _invite(edge, workspace_id, cookie),
    )
    assert "error" not in outcome, (outcome, edge.edge_answers[-3:])
    assert outcome["result"]["state"] == "active"
    return workspace_id, cookie, home, backend, outcome["result"]["runner_id"]


def _answers(edge, suffix):
    return [(status, body) for _method, path, status, body in edge.edge_answers if path.endswith(suffix)]


def test_paired_runner_lists_and_claims_its_context_through_the_actual_worker(tmp_path, worker_edge):
    """Live failure gate: pair → owner authorizes → ``status`` confirms → ``serve --once`` binds."""
    edge, zone = worker_edge
    workspace_id, cookie, home, backend, runner_id = _paired(tmp_path, edge, "wire-bind")
    record = _daemon_record(home)
    list_path = f"/v1/workspaces/{workspace_id}/runners/{runner_id}/contexts/list"

    # Before authorization: the signed list must reach the control plane and answer zero contexts.
    status = _daemon(home, edge, backend).status()
    plane = status["control_plane"]
    assert (plane["state"], plane.get("context_bindings")) == ("confirmed", 0), (plane, _answers(edge, "/contexts/list"))
    assert ("POST", list_path) in edge.forwarded

    _base, binding = _authorize_binding(edge, zone, workspace_id, cookie, runner_id, record["runner_key_id"])
    plane = _daemon(home, edge, backend).status()["control_plane"]
    assert (plane["state"], plane.get("context_bindings")) == ("confirmed", 1), plane

    result = _serve_once(_daemon(home, edge, backend))
    assert not isinstance(result, BaseException), (result, edge.edge_answers[-3:])
    assert result["binding_id"] == binding["binding_id"]
    claim_path = f"/v1/workspaces/{workspace_id}/runners/{runner_id}/contexts/{binding['binding_id']}/claim"
    assert ("POST", claim_path) in edge.forwarded
    assert RunnerStore(home).load_cloud_context_binding()["binding_id"] == binding["binding_id"]
    # Every runner answer the Worker relayed came from the control plane, never an edge refusal.
    runner_answers = [(path, status, body) for _m, path, status, body in edge.edge_answers
                      if f"/runners/{runner_id}/" in path]
    assert runner_answers and all(body != REFUSED[1] for _path, _status, body in runner_answers)
    # The edge secret never reached the runner home.
    persisted = b"".join(path.read_bytes() for path in home.rglob("*") if path.is_file())
    assert edge.edge_secret.encode() not in persisted


# --------------------------------------------------------------------------- first scan
#
# The first read-only plan → approval → job exchange through the actual Worker. It needs the
# accepted-but-unreleased daemon-owned plan submission (``RunnerCoordinator.submit_pending_projection``,
# PARALLEL-RUNNER-HANDOFF.md commit aa6e8314); on source without it the test is skipped, never faked.
# Additional labelled seams (as in the accepted replay suite): SEAM-VAULT (an OS-backend-shaped vault
# double with synthetic tokens) and SEAM-TARGET (``TargetHTTPSClient``'s resolver/socket/TLS
# collaborators answer as a scripted target and record every request). The owner's approval is the
# browser-shaped request through the Worker, not a backend shortcut.

FIRST_SCAN_SCENARIO = "object_ownership_read"
FIRST_SCAN_MARKER = "heel-canary-item-0137"
FIRST_SCAN_ROUTE = "/items/{item_id}"
FIRST_SCAN_TOKENS = {"object_owner": "synthetic-wire-token-object-owner",
                     "non_owner": "synthetic-wire-token-non-owner"}


def _accepted_plan_submission() -> bool:
    from heel.runner.coordinator import RunnerCoordinator

    return hasattr(RunnerCoordinator, "submit_pending_projection")


class _Vault:
    """SEAM-VAULT."""

    supported = True
    backend_id = "macos_keychain"

    def __init__(self):
        self.tokens: dict[str, str] = {}

    def load(self, handle_id):
        return self.tokens[handle_id].encode("ascii")


class _Target:
    """SEAM-TARGET: the still-vulnerable customer application at the verified origin."""

    def __init__(self, hostname):
        self.hostname = hostname
        self.requests: list[bytes] = []

    def network(self):
        from tests.test_runner_http_transport import PUBLIC, Resolver, Sockets, TLSSocket, response

        target = self

        class Answering(TLSSocket):
            def __init__(self):
                super().__init__(b"")

            def recv(self, size):
                if not self.payload:
                    request = b"".join(self.sent)
                    target.requests.append(request)
                    self.payload = response(200, json.dumps({"protected_canary": FIRST_SCAN_MARKER}).encode())
                return super().recv(size)

        class TLS:
            def wrap(self, raw, hostname, timeout):
                assert hostname == target.hostname
                return Answering()

        return {"resolver": Resolver([[PUBLIC]]), "sockets": Sockets([]), "tls": TLS()}


@pytest.mark.skipif(not _accepted_plan_submission(), reason="accepted daemon-owned plan submission source not present")
def test_first_scan_frames_cross_the_actual_worker(tmp_path, worker_edge, monkeypatch):
    """context claim → projection submit → approval queue/approve → claim lease → heartbeat/progress/result."""
    import contextlib
    import hashlib
    import io
    import os

    from heel import cli
    from heel.canary_contracts import canonical_bytes
    from heel.runner import daemon as daemon_module
    from tests.test_runner_daemon import _STAGING

    edge, zone = worker_edge
    workspace_id, cookie, home, backend, runner_id = _paired(tmp_path, edge, "wire-scan")
    record = _daemon_record(home)
    base, binding = _authorize_binding(edge, zone, workspace_id, cookie, runner_id, record["runner_key_id"])
    vault, target = _Vault(), _Target(_STAGING)
    monkeypatch.setenv("HEEL_HOME", str(home))
    real = daemon_module.RunnerDaemon
    monkeypatch.setattr(daemon_module, "RunnerDaemon", lambda: real(  # SEAM-SECRET-BACKEND/CA
        home, secret_backend=backend, ca_bundle=edge.ca.ca_path))
    monkeypatch.setattr("heel.runner.vault.select_vault", lambda _backend: vault)  # SEAM-VAULT

    def serve():
        result = _serve_once(_daemon(home, edge, backend, vault_factory=lambda _b: vault,
                                     target_network=target.network()))
        assert not isinstance(result, BaseException), (result, edge.edge_answers[-4:])
        return result

    def run_cli(*arguments):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(arguments))
        assert (code, err.getvalue()) == (0, ""), err.getvalue()
        return json.loads(out.getvalue()) if out.getvalue().strip() else None

    assert serve()["binding_id"] == binding["binding_id"]                     # contexts/list + claim
    fixture = Path(__file__).resolve().parent / "fixtures/canary/staging-openapi.json"
    run_cli("runner", "import-openapi", str(fixture))
    store = RunnerStore(home)
    for role, token in FIRST_SCAN_TOKENS.items():
        reserved = store.reserve_os_credential(semantic_role=role, auth_profile="bearer",
                                               label=f"wire {role}", backend="macos_keychain")
        store.activate_credential(reserved["credential_handle_id"])
        vault.tokens[reserved["credential_handle_id"]] = token
    read, write = os.pipe()
    os.set_inheritable(read, True)
    try:
        os.write(write, json.dumps({"item_id": FIRST_SCAN_MARKER}).encode())
        os.close(write)
        run_cli("runner", "map", "--scenario", FIRST_SCAN_SCENARIO, "--method", "GET",
                "--route", FIRST_SCAN_ROUTE, "--fixture-fd", str(read))
    finally:
        os.close(read)
    prepared = run_cli("runner", "prepare", "--live")
    serve()                                                                   # approval-projections
    shown = run_cli("runner", "status", "--offline")["projection_submission"]
    assert (shown["state"], shown["projection_id"]) == ("submitted", prepared["submission"]["projection_id"])
    assert target.requests == []                                              # nothing before approval

    status, listed, _ = edge.request("GET", f"{base}/canary-approval-requests", cookie=cookie)
    assert status == 200, listed
    (queued,) = listed["requests"]
    assert (queued["approval_id"], queued["run_id"]) == (shown["approval_id"], shown["run_id"])
    approval = canonical_bytes({
        "schema_version": "heel.canary-execution-approval.v1", "projection_digest": shown["projection_digest"],
        "hostname_retype": _STAGING, "reason": "Run the first bounded staging scan",
    })
    status, approved, _ = edge.request(
        "POST", f"{base}/canary-runs/{shown['run_id']}/approve", raw=approval, cookie=cookie, headers={
            "Idempotency-Key": "ca1-" + hashlib.sha256(shown["run_id"].encode()).hexdigest(),
            "If-Heel-Control-Generation": "0"})
    assert status == 201, approved

    serve()                                                                   # claim lease → execute
    assert RunnerStore(home).load_run(shown["run_id"])["state"] == "terminal"
    assert [item.split(b"\r\n", 1)[0] for item in target.requests] == [
        f"GET /items/{FIRST_SCAN_MARKER} HTTP/1.1".encode()] * 2
    runner_base = f"/v1/workspaces/{workspace_id}/runners/{runner_id}"
    reached = {path for method, path in edge.forwarded if method == "POST" and path.startswith(runner_base)}
    expected = {f"{runner_base}/contexts/list", f"{runner_base}/contexts/{binding['binding_id']}/claim",
                f"{runner_base}/contexts/{binding['binding_id']}/approval-projections", f"{runner_base}/claim",
                f"{runner_base}/runs/{shown['run_id']}/result"}
    assert expected <= reached, sorted(reached)
    status, run, _ = edge.request("GET", f"{base}/canary-runs/{shown['run_id']}", cookie=cookie)
    assert status == 200, run
    # No Worker refusal on any runner or owner call of the journey, and no secret in what it relayed.
    assert all(body != REFUSED[1] and status_code < 500 for _m, _p, status_code, body in edge.edge_answers)
    relayed = b"".join(body for *_rest, body in edge.edge_answers)
    for value in (*FIRST_SCAN_TOKENS.values(), edge.edge_secret):
        assert value.encode() not in relayed


# --------------------------------------------------------------------------- result handoff (H2)
#
# The two routes the accepted result-handoff design adds (spec 2026-11-11 §3.3) must cross the
# actual Worker on their exact families: the runner's PoP ``disclosure-poll`` (runner-proof
# header family, 2 KiB cap) and the human ``view`` read ``GET …/disclosure`` (session family).
# Nothing is seeded: an unknown run answers the control plane's own closed error, which proves
# the Worker forwarded the request instead of refusing it at the edge.

_HANDOFF_RUN = "crun_" + "c" * 32
_HANDOFF_PROOF = {
    "X-Heel-Runner-Key-Id": "key_wire_handoff", "X-Heel-Runner-Timestamp-Ms": "1",
    "X-Heel-Runner-Nonce": "N" * 43 + "=", "X-Heel-Runner-Sequence": "1",
    "X-Heel-Runner-Signature": "S" * 86 + "==",
}


def test_result_handoff_routes_cross_the_actual_worker_on_their_exact_families(worker_edge):
    edge, _zone = worker_edge
    workspace_id, cookie = edge.signup_owner("owner-handoff@example.test")
    status, project, _ = edge.request(
        "POST", f"/v1/workspaces/{workspace_id}/projects", {"name": "Handoff"}, cookie=cookie,
    )
    assert status == 201, project
    project_ref = project["project_ref"]

    read_path = (
        f"/v1/workspaces/{workspace_id}/projects/{project_ref}/canary-runs/{_HANDOFF_RUN}/disclosure"
    )
    status, body, _ = edge.request("GET", read_path, cookie=cookie)
    assert ("GET", read_path) in edge.forwarded, edge.edge_answers[-1:]
    assert (status, body) == (
        404, {"schema_version": "heel.canary-error.v1", "code": "canary_run_not_found"},
    )
    # The read is GET-only at the edge.
    before = len(edge.forwarded)
    status, _, _ = edge.request("POST", read_path, {}, cookie=cookie)
    assert status in {400, 404, 405} and len(edge.forwarded) == before

    runner_id = "runr_" + "d" * 32
    poll_path = (
        f"/v1/workspaces/{workspace_id}/runners/{runner_id}/runs/{_HANDOFF_RUN}/disclosure-poll"
    )
    small = json.dumps({"schema_version": "heel.runner-disclosure-poll.v1"}).encode()
    status, body, _ = edge.request(
        "POST", poll_path, raw=small, origin=None, fetch_site=None,
        headers={"X-Heel-Runner-Id": runner_id, **_HANDOFF_PROOF},
    )
    assert ("POST", poll_path) in edge.forwarded, edge.edge_answers[-1:]
    assert (status, body) == (
        401, {"schema_version": "heel.runner-error.v1", "code": "invalid_runner_auth"},
    )

    before = len(edge.forwarded)
    oversized = b'{"p":"' + b"x" * 2048 + b'"}'
    status, _, _ = edge.request(
        "POST", poll_path, raw=oversized, origin=None, fetch_site=None,
        headers={"X-Heel-Runner-Id": runner_id, **_HANDOFF_PROOF},
    )
    assert status == 413 and len(edge.forwarded) == before
    # A session cookie never authorizes the runner route at the edge.
    status, _, _ = edge.request("POST", poll_path, raw=small, cookie=cookie)
    assert status in {400, 401, 403} and len(edge.forwarded) == before
