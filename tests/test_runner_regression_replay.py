"""Saved paired-runner regression replay: fresh approval, verified recording, bounded results.

Real: the Python control plane behind the TLS edge (``EdgeTLSHarness``), runner pairing and the
owner's context binding over the edge, ``heel.cli.main`` for every customer command, the serve
owner (``RunnerDaemon.serve``) that submits, claims and executes, ``RunnerCoordinator``,
``LocalCanaryExecutor``, ``TargetHTTPSClient`` and the signed local finals in ``RunnerStore``.

Seams (labelled, local fixtures only; none is public browser acceptance):
- SEAM-SECRET-BACKEND/CA: the CLI's ``RunnerDaemon()`` is the test's daemon (in-memory seed
  backend, harness CA), as in ``tests/test_runner_daemon.py``. No OS keychain item is created.
- SEAM-VAULT: an OS-backend-shaped vault double holds repository-owned synthetic bearer tokens.
- SEAM-TARGET: the resolver/socket/TLS collaborators of ``TargetHTTPSClient`` answer as a scripted
  local target (``vulnerable``, ``patched`` or ``error_envelope``) and record every request.
- LOCAL-APPROVAL-FIXTURE: the owner's execution approval is posted to the control-plane backend
  with the owner session, exactly like ``_issue_grant_fixture``: browser-equivalent, not the
  public browser journey.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os

import pytest

from heel import cli
from heel.canary_contracts import canonical_bytes, canonical_digest
from heel.crypto import SigningAuthority
from heel.runner import daemon as daemon_module
from heel.runner.store import RunnerStore
from tests.test_runner_daemon import (  # noqa: F401 - fixtures are used by name
    REVOKE_BODY, _STAGING, _authorize_binding, _daemon, _daemon_record, _direct_backend,
    _fault_daemon, _pair_runner, _serve_once, serve_harness,
)
from tests.test_runner_http_transport import PUBLIC, Resolver, Sockets, TLSSocket, response

FIXTURE = __import__("pathlib").Path(__file__).resolve().parent / "fixtures/canary/staging-openapi.json"
SCENARIO = "object_ownership_read"
MARKER = "heel-canary-item-0137"
ROUTE = "/items/{item_id}"
TOKENS = {
    "object_owner": "synthetic-replay-token-object-owner",
    "non_owner": "synthetic-replay-token-non-owner",
}
REPLAY_FAILURE = "Heel runner regression replay could not be prepared safely.\n"
RECORD_FAILURE = "Heel runner regression result could not be recorded safely.\n"


# --------------------------------------------------------------------------- local seams


class ReplayVault:
    """SEAM-VAULT: OS-backend-shaped; loads repository-owned synthetic tokens by handle."""

    supported = True
    backend_id = "macos_keychain"

    def __init__(self):
        self.tokens: dict[str, str] = {}
        self.available = True

    def load(self, handle_id):
        if not self.available:
            from heel.runner.vault import VaultUnavailable

            raise VaultUnavailable("secure credential vault unavailable on this platform")
        return self.tokens[handle_id].encode("ascii")


class _TargetSocket(TLSSocket):
    """Answers after reading the request, by the bearer token that reached the target."""

    def __init__(self, target):
        super().__init__(b"")
        self.target = target

    def recv(self, size):
        if not self.payload:
            request = b"".join(self.sent)
            self.target.requests.append(request)
            self.payload = self.target.answer(request)
        return super().recv(size)


class ScriptedTarget:
    """SEAM-TARGET: the customer's application at the verified origin, scripted per mode."""

    def __init__(self):
        self.mode = "vulnerable"
        self.requests: list[bytes] = []

    def answer(self, request: bytes) -> bytes:
        protected = json.dumps({"protected_canary": MARKER}).encode()
        if f"Bearer {TOKENS['object_owner']}".encode() in request:
            return response(200, protected)
        assert f"Bearer {TOKENS['non_owner']}".encode() in request
        if self.mode == "vulnerable":
            return response(200, protected)
        if self.mode == "patched":
            return response(404, b"")
        return response(403, b'{"error":"forbidden"}')  # error envelope: neither proof

    def lines(self) -> list[bytes]:
        return [item.split(b"\r\n", 1)[0] for item in self.requests]

    def network(self):
        target = self

        class TLS:
            def wrap(self, raw, hostname, timeout):
                assert hostname == _STAGING
                return _TargetSocket(target)

        return {"resolver": Resolver([[PUBLIC]]), "sockets": Sockets([]), "tls": TLS()}


# --------------------------------------------------------------------------- customer journey


class Customer:
    """One paired, context-bound customer runner home driven through ``heel.cli.main``."""

    def __init__(self, tmp_path, serve_harness, monkeypatch, name):
        harness, zone = serve_harness
        self.harness = harness
        self.workspace_id, self.cookie = harness.signup_owner(f"owner-{name}@example.test")
        self.home, self.backend, self.runner_id = _pair_runner(
            tmp_path, harness, self.workspace_id, self.cookie, name)
        record = _daemon_record(self.home)
        self.base, self.binding = _authorize_binding(
            harness, zone, self.workspace_id, self.cookie, self.runner_id, record["runner_key_id"])
        self.vault = ReplayVault()
        self.target = ScriptedTarget()
        self.approvals = 0
        monkeypatch.setenv("HEEL_HOME", str(self.home))
        real = daemon_module.RunnerDaemon
        monkeypatch.setattr(daemon_module, "RunnerDaemon", lambda: real(  # SEAM-SECRET-BACKEND/CA
            self.home, secret_backend=self.backend, ca_bundle=harness.ca.ca_path))
        monkeypatch.setattr("heel.runner.vault.select_vault", lambda backend: self.vault)  # SEAM-VAULT
        assert not isinstance(self.serve(), BaseException)  # bound, online, idle

    @property
    def store(self) -> RunnerStore:
        return RunnerStore(self.home)

    def cli(self, *arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(list(arguments))
        return code, stdout.getvalue(), stderr.getvalue()

    def ok(self, *arguments):
        code, out, err = self.cli(*arguments)
        assert (code, err) == (0, ""), err
        return json.loads(out)

    def map(self, route=ROUTE, fixture=MARKER):
        read, write = os.pipe()
        os.set_inheritable(read, True)
        try:
            payload = json.dumps({"item_id": fixture} if "{" in route else {}).encode()
            os.write(write, payload)
            os.close(write)
            code, _out, err = self.cli("runner", "map", "--scenario", SCENARIO, "--method", "GET",
                                       "--route", route, "--fixture-fd", str(read))
        finally:
            os.close(read)
        assert code == 0, err

    def configure(self):
        """Customer CLI import + mapping; OS credentials registered through the store API."""
        assert self.cli("runner", "import-openapi", str(FIXTURE))[0] == 0
        for role, token in TOKENS.items():
            record = self.store.reserve_os_credential(
                semantic_role=role, auth_profile="bearer", label=f"local {role}", backend="macos_keychain")
            self.store.activate_credential(record["credential_handle_id"])
            self.vault.tokens[record["credential_handle_id"]] = token
        self.map()

    def serve(self, faults=None):
        daemon = _daemon(self.home, self.harness, self.backend,
                         vault_factory=lambda backend: self.vault, target_network=self.target.network())
        if faults:
            daemon = _fault_daemon(daemon, faults)
        return _serve_once(daemon)

    def submitted(self):
        shown = self.ok("runner", "status", "--offline")["projection_submission"]
        assert shown["state"] == "submitted", shown
        return shown

    def approve(self, shown):
        """LOCAL-APPROVAL-FIXTURE: the owner's browser-equivalent one-shot execution approval."""
        self.approvals += 1
        owner = [("X-Heel-Edge-Auth", self.harness.edge_secret), ("Cookie", self.cookie),
                 ("Origin", self.harness.origin), ("X-Heel-Internal-Origin", "same-origin"),
                 ("Content-Type", "application/json")]
        body = canonical_bytes({
            "schema_version": "heel.canary-execution-approval.v1",
            "projection_digest": shown["projection_digest"], "hostname_retype": _STAGING,
            "reason": "Replay the saved bounded staging regression",
        })
        key = "ca1-" + hashlib.sha256(shown["run_id"].encode()).hexdigest()
        status, approved = _direct_backend(
            self.harness, "POST", f"{self.base}/canary-runs/{shown['run_id']}/approve", body, owner + [
                ("Content-Length", str(len(body))), ("Idempotency-Key", key), ("If-Heel-Control-Generation", "0")])
        assert status == 201, approved
        return approved["grant"]

    def execute(self, shown, mode):
        """Fresh approval, then the serve owner claims and executes against ``mode``."""
        self.target.mode = mode
        before = len(self.target.requests)
        grant = self.approve(shown)
        result = self.serve()
        assert not isinstance(result, BaseException), (result.state, result.code)
        assert self.store.load_run(shown["run_id"])["state"] == "terminal"
        assert self.target.lines()[before:] == [f"GET /items/{MARKER} HTTP/1.1".encode()] * 2
        return grant

    def prepare(self, *extra):
        return self.ok("runner", "prepare", "--live", *extra)

    def submit(self, *extra):
        """``prepare`` then one serve submission; no target request may precede approval."""
        before = len(self.target.requests)
        prepared = self.prepare(*extra)
        assert not isinstance(self.serve(), BaseException)
        shown = self.submitted()
        assert shown["projection_id"] == prepared["submission"]["projection_id"]
        assert len(self.target.requests) == before
        return prepared, shown

    def source_finding(self):
        """An observed source finding from an ordinary approved paired run, saved as a definition."""
        _prepared, shown = self.submit()
        self.execute(shown, "vulnerable")
        added = self.ok("runner", "regress", "add", "--run", shown["run_id"], "--scenario", SCENARIO,
                        "--name", "Ownership read")
        return shown["run_id"], added["regression"]


def _file(store: RunnerStore, name: str):
    path = store.root / "runner" / "contexts" / store.namespace / name
    return path


def _snapshot(store: RunnerStore):
    names = ("regressions.json", "regression-replays.json", "regression-results.json",
             "projection-submission.json")
    return {name: (_file(store, name).read_bytes() if _file(store, name).exists() else None) for name in names}


def _approval_posts(harness):
    return [path for method, path in harness.forwarded if method == "POST" and "approval-projections" in path]


def _assert_quiet(*texts):
    blob = "\n".join(texts)
    for value in (*TOKENS.values(), MARKER, "protected_canary", "credential_handle", "signature_b64"):
        assert value not in blob


# --------------------------------------------------------------------------- tests


def test_saved_regression_replays_with_fresh_approval_and_records_fail_then_pass(
    tmp_path, serve_harness, monkeypatch,
):
    """Finite local journey: observed source -> save -> replay (vulnerable) -> fail -> patch ->
    fresh replay -> pass. Every replay is a new plan, approval, grant and run."""
    customer = Customer(tmp_path, serve_harness, monkeypatch, "replay-journey")
    customer.configure()
    source_run, definition = customer.source_finding()
    regression_id = definition["regression_id"]

    # Replay 1 against the still-vulnerable target.
    prepared, shown = customer.submit("--regression", regression_id)
    assert prepared["scenario_ids"] == [SCENARIO]
    assert prepared["regression"] == {"regression_id": regression_id,
                                      "projection_id": prepared["submission"]["projection_id"]}
    assert prepared["projection_digest"] != definition["approval_projection_digest"]
    assert prepared["manifest_digest"] != definition["manifest_digest"]
    (association,) = customer.store.list_regression_replays()
    assert association["regression_id"] == regression_id
    assert (association["projection_id"], association["projection_digest"], association["manifest_digest"]) == (
        shown["projection_id"], prepared["projection_digest"], prepared["manifest_digest"])
    # The browser queue shows exactly the one selected GET route for this replay.
    status, listed, _ = customer.harness.request(
        "GET", f"{customer.base}/canary-approval-requests", cookie=customer.cookie)
    request = next(item for item in listed["requests"] if item["approval_id"] == shown["projection_id"])
    assert status == 200 and (request["routes"], request["scenarios"]) == (
        [f"GET {ROUTE}", f"GET {ROUTE}"], [SCENARIO])
    first_grant = customer.execute(shown, "vulnerable")
    first_run = shown["run_id"]
    recorded = customer.ok("runner", "regress", "record", "--regression", regression_id, "--run", first_run)
    assert recorded["created"] is True
    fail = recorded["result"]
    assert (fail["outcome"], fail["assessment_outcome"], fail["run_id"]) == ("fail", "observed", first_run)

    # The customer patches the target; a deliberate new replay is a new plan and approval.
    prepared2, shown2 = customer.submit("--regression", regression_id)
    second_grant = customer.execute(shown2, "patched")
    second_run = shown2["run_id"]
    recorded2 = customer.ok("runner", "regress", "record", "--regression", regression_id, "--run", second_run)
    passed = recorded2["result"]
    assert (passed["outcome"], passed["assessment_outcome"]) == ("pass", "blocked")

    # Fresh identities everywhere: no replay reused the source or the previous replay.
    assert len({source_run, first_run, second_run}) == 3
    assert len({definition["grant_id"], first_grant["grant_id"], second_grant["grant_id"]}) == 3
    assert len({definition["approval_projection_digest"], prepared["projection_digest"],
                prepared2["projection_digest"]}) == 3
    assert customer.approvals == 3

    # Duplicate recording is deterministic and writes nothing.
    before = _snapshot(customer.store)
    again = customer.ok("runner", "regress", "record", "--regression", regression_id, "--run", second_run)
    assert again == {"created": False, "result": passed}
    assert _snapshot(customer.store) == before

    # Exposed through ``regress list`` after a fresh process-equivalent reopen.
    listed = customer.ok("runner", "regress", "list")
    assert listed["regression_count"] == 1 and listed["regressions"] == [definition]
    assert listed["result_count"] == 2 and listed["results"] == [fail, passed]
    assert [item["outcome"] for item in RunnerStore(customer.home).list_regression_results()] == ["fail", "pass"]

    # Only identifiers and digests are persisted or printed: no token, fixture value or signature.
    state = b"".join(value for value in _snapshot(customer.store).values() if value)
    _assert_quiet(json.dumps([prepared, prepared2, recorded, recorded2, listed]), state.decode())
    forwarded = json.dumps(customer.harness.forwarded)
    assert all(token not in forwarded for token in TOKENS.values())
    # The target saw exactly six GETs of the selected route, all after an approval.
    assert customer.target.lines() == [f"GET /items/{MARKER} HTTP/1.1".encode()] * 6


def test_replay_prepare_refuses_changed_inputs_before_any_state_or_request(
    tmp_path, serve_harness, monkeypatch,
):
    customer = Customer(tmp_path, serve_harness, monkeypatch, "replay-guards")
    customer.configure()
    _source_run, definition = customer.source_finding()
    regression_id = definition["regression_id"]
    store = customer.store
    baseline = _snapshot(store)
    posts = len(_approval_posts(customer.harness))

    def refused(*arguments):
        code, out, err = customer.cli("runner", "prepare", *arguments)
        assert (code, out, err) == (2, "", REPLAY_FAILURE)
        assert _snapshot(store) == baseline
        assert store.list_regression_replays() == []
        assert not isinstance(customer.serve(), BaseException)
        assert len(_approval_posts(customer.harness)) == posts

    refused("--regression", regression_id)                       # never without --live
    refused("--live", "--regression", "rreg_" + "0" * 24)        # unknown definition
    refused("--live", "--regression", "../" + regression_id)     # malformed identifier

    customer.map(route="/items")                                 # changed route mapping
    refused("--live", "--regression", regression_id)
    customer.map(fixture="heel-canary-item-0999")                # changed fixture value
    refused("--live", "--regression", regression_id)
    customer.map()                                               # restored exact mapping

    customer.vault.available = False                             # unavailable credentials
    refused("--live", "--regression", regression_id)
    customer.vault.available = True

    # A mapping that changes between the guard and the compiler cannot widen the queued plan.
    from heel.runner.compiler import CanaryCompiler

    original = CanaryCompiler.compile

    def racing_compile(self, selected, **options):
        self.store.save_mapping(SCENARIO, method="GET", route_template="/items/{item_id}",
                                fixture_bindings={"item_id": "heel-canary-item-0998"})
        return original(self, selected, **options)

    monkeypatch.setattr(CanaryCompiler, "compile", racing_compile)
    code, out, err = customer.cli("runner", "prepare", "--live", "--regression", regression_id)
    monkeypatch.setattr(CanaryCompiler, "compile", original)
    assert (code, out, err) == (2, "", REPLAY_FAILURE)
    assert store.list_regression_replays() == [] and _snapshot(store)["projection-submission.json"] == (
        baseline["projection-submission.json"])
    customer.map()

    # A definition bound to another context or identity is never replayed.
    path = _file(store, "regressions.json")
    original_bytes = path.read_bytes()
    for field, value in (("origin", "https://other.example.com"), ("runner_key_id", "rk_other")):
        tampered = json.loads(original_bytes)
        tampered["regressions"][0][field] = value
        path.write_bytes(canonical_bytes(tampered))
        baseline = _snapshot(store)
        refused("--live", "--regression", regression_id)
    path.write_bytes(original_bytes)
    baseline = _snapshot(store)

    # The exact unchanged definition still replays (the guards above refused only changes).
    prepared, _shown = customer.submit("--regression", regression_id)
    assert prepared["regression"]["regression_id"] == regression_id
    assert customer.target.requests[-1:] and len(customer.target.requests) == 2  # source run only


def test_recording_requires_the_exact_durable_replay_association(tmp_path, serve_harness, monkeypatch):
    """Superseded/unsent replays, lost replies, queue replacement, unrelated same-route runs."""
    customer = Customer(tmp_path, serve_harness, monkeypatch, "replay-record")
    customer.configure()
    source_run, definition = customer.source_finding()
    regression_id = definition["regression_id"]

    # Two deliberate prepares: two distinct associations; only the latest is queued.
    superseded = customer.prepare("--regression", regression_id)
    latest = customer.prepare("--regression", regression_id)
    assert superseded["submission"]["projection_id"] != latest["submission"]["projection_id"]
    assert [item["projection_id"] for item in customer.store.list_regression_replays()] == [
        superseded["submission"]["projection_id"], latest["submission"]["projection_id"]]
    # The submission answer is lost after commit; the next serve resubmits the same projection.
    lost = customer.serve(faults={"/approval-projections": ["drop_after"]})
    assert isinstance(lost, daemon_module.RunnerServeError) and lost.state == "offline"
    assert not isinstance(customer.serve(), BaseException)
    shown = customer.submitted()
    assert shown["projection_id"] == latest["submission"]["projection_id"]
    customer.execute(shown, "error_envelope")
    replay_run = shown["run_id"]

    # An ordinary plan on the same route replaces the queue slot; the association survives.
    _prepared, unrelated = customer.submit()
    customer.execute(unrelated, "vulnerable")
    assert customer.store.load_projection_submission()["projection_id"] == unrelated["projection_id"]

    store = customer.store
    before = _snapshot(store)
    for run_id in (unrelated["run_id"], source_run, "crun_" + "f" * 32, "../" + replay_run):
        code, out, err = customer.cli("runner", "regress", "record", "--regression", regression_id, "--run", run_id)
        assert (code, out, err) == (2, "", RECORD_FAILURE)
    code, out, err = customer.cli("runner", "regress", "record", "--regression", "rreg_" + "0" * 24,
                                  "--run", replay_run)
    assert (code, out, err) == (2, "", RECORD_FAILURE)
    assert _snapshot(store) == before

    # The error-envelope replay is recorded as inconclusive, never pass.
    recorded = customer.ok("runner", "regress", "record", "--regression", regression_id, "--run", replay_run)
    assert (recorded["created"], recorded["result"]["outcome"]) == (True, "inconclusive")
    assert recorded["result"]["assessment_outcome"] == "inconclusive"
    assert recorded["result"]["projection_id"] == latest["submission"]["projection_id"]
    # Reopened state: a new store sees the same association and result; recording again is a no-op.
    after = _snapshot(store)
    assert customer.ok("runner", "regress", "record", "--regression", regression_id, "--run", replay_run) == {
        "created": False, "result": recorded["result"]}
    assert _snapshot(RunnerStore(customer.home)) == after


def _resign_findings_with_foreign_key(store: RunnerStore, run_id: str) -> None:
    path = store.run_path(run_id) / "finals.json"
    envelope = json.loads(path.read_bytes())
    foreign = SigningAuthority.generate()
    findings = envelope["findings_projection"]
    unsigned = {key: value for key, value in findings.items()
                if key not in {"projection_digest", "signing_key_id", "signature_b64"}}
    resigned = {**unsigned, "projection_digest": canonical_digest(unsigned), **foreign.sign(canonical_bytes(unsigned))}
    envelope["findings_projection"] = resigned
    envelope["local_view"]["findings_projection"] = resigned
    envelope["disclosure_preview"]["projection"] = resigned
    envelope["disclosure_preview"]["projection_digest"] = resigned["projection_digest"]
    envelope["finals_digest"] = canonical_digest({k: v for k, v in envelope.items() if k != "finals_digest"})
    path.write_bytes(canonical_bytes(envelope))


def test_forged_finals_tampered_associations_and_revocation_never_yield_a_result(
    tmp_path, serve_harness, monkeypatch,
):
    customer = Customer(tmp_path, serve_harness, monkeypatch, "replay-forged")
    customer.configure()
    _source_run, definition = customer.source_finding()
    regression_id = definition["regression_id"]
    store = customer.store

    # Foreign-signed finals for an associated replay run: refused, nothing written.
    _prepared, shown = customer.submit("--regression", regression_id)
    customer.execute(shown, "patched")
    run_path = store.run_path(shown["run_id"]) / "finals.json"
    genuine = run_path.read_bytes()
    _resign_findings_with_foreign_key(store, shown["run_id"])
    before = _snapshot(store)
    code, out, err = customer.cli("runner", "regress", "record", "--regression", regression_id,
                                  "--run", shown["run_id"])
    assert (code, out, err) == (2, "", RECORD_FAILURE) and _snapshot(store) == before
    # Malformed finals bytes: refused the same way.
    run_path.write_bytes(genuine[:-7])
    code, out, err = customer.cli("runner", "regress", "record", "--regression", regression_id,
                                  "--run", shown["run_id"])
    assert (code, out, err) == (2, "", RECORD_FAILURE) and _snapshot(store) == before
    run_path.write_bytes(genuine)

    # A forged association digest no longer matches the run's grant/pair: recording refuses.
    replays = _file(store, "regression-replays.json")
    original = replays.read_bytes()
    tampered = json.loads(original)
    tampered["replays"][0]["projection_digest"] = "e" * 64
    replays.write_bytes(canonical_bytes(tampered))
    code, out, err = customer.cli("runner", "regress", "record", "--regression", regression_id,
                                  "--run", shown["run_id"])
    assert (code, out, err) == (2, "", RECORD_FAILURE) and _snapshot(store) == {**before, "regression-replays.json": replays.read_bytes()}
    # A malformed association (an extra raw field) is refused by record and prepare alike.
    tampered = json.loads(original)
    tampered["replays"][0]["fixture_value"] = MARKER
    replays.write_bytes(canonical_bytes(tampered))
    malformed = _snapshot(store)
    code, out, err = customer.cli("runner", "regress", "record", "--regression", regression_id,
                                  "--run", shown["run_id"])
    assert (code, out, err) == (2, "", RECORD_FAILURE)
    code, out, err = customer.cli("runner", "prepare", "--live", "--regression", regression_id)
    assert (code, out, err) == (2, "", REPLAY_FAILURE) and _snapshot(store) == malformed
    replays.write_bytes(original)
    assert customer.ok("runner", "regress", "record", "--regression", regression_id,
                       "--run", shown["run_id"])["result"]["outcome"] == "pass"

    # Revocation after approval: the replay is never claimed, the target never contacted, and
    # there is no run to record.
    _prepared, revoked = customer.submit("--regression", regression_id)
    customer.approve(revoked)
    requests = len(customer.target.requests)
    status, _body, _ = customer.harness.request(
        "POST", f"/v1/workspaces/{customer.workspace_id}/runners/{customer.runner_id}/revoke",
        REVOKE_BODY, cookie=customer.cookie)
    assert status == 200
    assert isinstance(customer.serve(), daemon_module.RunnerServeError)
    assert len(customer.target.requests) == requests
    before = _snapshot(store)
    code, out, err = customer.cli("runner", "regress", "record", "--regression", regression_id,
                                  "--run", revoked["run_id"])
    assert (code, out, err) == (2, "", RECORD_FAILURE) and _snapshot(store) == before
    assert [item["outcome"] for item in store.list_regression_results()] == ["pass"]


def test_regression_replay_and_result_records_are_closed_and_bounded():
    from heel.runner import regressions

    replay = {
        "regression_id": "rreg_" + "a" * 24, "definition_digest": "1" * 64,
        "projection_id": "projection_" + "b" * 24, "projection_digest": "2" * 64,
        "manifest_digest": "3" * 64, "binding_digest": "4" * 64, "created_at_ms": 5,
    }
    assert regressions.validate_regression_replay(replay) == replay
    for bad in ({**replay, "credential_handle_id": "x"}, {**replay, "projection_id": "../x"},
                {**replay, "created_at_ms": True}, {k: v for k, v in replay.items() if k != "binding_digest"}):
        with pytest.raises(regressions.SavedRegressionError):
            regressions.validate_regression_replay(bad)
    assert regressions.MAX_REGRESSION_REPLAYS <= 200 and regressions.MAX_REGRESSION_RESULTS <= 200
