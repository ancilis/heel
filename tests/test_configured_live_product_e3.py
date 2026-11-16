"""E3: browser-authored configured live tests delivered to the paired runner and back.

Real: the control plane behind the TLS edge (``EdgeTLSHarness``), owner signup/pairing/context
binding, workspace-private custom revisions with a configured live test, the configured plan
request, ``RunnerDaemon.serve`` with ``RunnerCoordinator``/``RunnerControlClient`` over the PoP claim
chain (``configured-plan-sync`` and the configured projection submission), ``heel.cli.main`` for
every customer runner command (import, ``input add --type text``), the cloud approval with the
versioned condition review, grant claim, ``LocalCanaryExecutor`` + ``TargetHTTPSClient``, signed
v2 findings, the explicit disclosure permit/upload, and the configured regression replay.

Seams (the ones labelled in ``tests/test_runner_regression_replay.py``): secret backend/CA,
OS vault (in-memory object with the OS backend id), DNS proof, scripted target socket and the
browser-equivalent owner calls sent directly to the control plane with the owner's session
cookie (the browser UI itself is exercised separately in the local browser proof).
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time

import pytest

from heel.canary_contracts import (
    CONFIGURED_FINDINGS_SCHEMA,
    canonical_bytes,
)
from heel.runner.store import RunnerStore
from tests.test_runner_daemon import _STAGING, _direct_backend, serve_harness  # noqa: F401 - fixture
from tests.test_runner_http_transport import PUBLIC, Resolver, Sockets
from tests.test_runner_regression_replay import Customer, _TargetSocket, response

ROUTE = "/billing/features"
TOKENS = {"lower_plan": "synthetic-free-plan-token-e3-01", "higher_plan": "synthetic-pro-plan-token-e3-02"}
SECRET_HINT = "e3-sentinel-4421-SECRET-HINT"  # a privacy sentinel: must never reach the cloud
OPENAPI = {
    "openapi": "3.1.0", "info": {"title": "Ordinary billing API", "version": "1.0.0"},
    "paths": {
        ROUTE: {"get": {"operationId": "getFeatures", "responses": {"200": {"description": "ok"}}}},
        "/items/{item_id}": {"get": {"operationId": "getItem", "responses": {"200": {"description": "ok"}}}},
    },
}


def _assertion(condition: dict) -> dict:
    return {
        "schema_version": "heel.live-read-assertion.v1",
        "success_witness": {"path": ["meta", "state"], "expected_fixture": "export_ok"},
        "condition": condition,
    }


HINT_EQUALS = _assertion({"kind": "json_scalar_equals_fixture", "path": ["export", "rows", 0, "ssn_hint"],
                          "expected_fixture": "secret_hint"})
PLAN_EQUALS = _assertion({"kind": "json_scalar_equals_fixture", "path": ["export", "plan"],
                          "expected_fixture": "pro_plan"})
AUDIT_PRESENT = _assertion({"kind": "json_field_present", "path": ["export", "audit_log"]})


def _body(plan: str) -> bytes:
    return json.dumps({"meta": {"state": "ok"}, "export": {"plan": plan, "rows": [{"ssn_hint": SECRET_HINT}]}}).encode()


class BillingTarget:
    """SEAM-TARGET: an ordinary plan-gated billing read answering by bearer token; no marker."""

    def __init__(self):
        self.mode = "vulnerable"
        self.requests: list[bytes] = []

    def answer(self, request: bytes) -> bytes:
        line = request.split(b"\r\n", 1)[0].decode()
        assert line.split(" ")[1] == ROUTE, line
        if f"Bearer {TOKENS['higher_plan']}".encode() in request:
            return response(200, _body("pro"))
        assert f"Bearer {TOKENS['lower_plan']}".encode() in request
        if self.mode == "patched":
            return response(403, b"")
        return response(200, _body("free"))

    def lines(self):
        return [item.split(b"\r\n", 1)[0] for item in self.requests]

    def network(self):
        target = self

        class TLS:
            def wrap(self, raw, hostname, timeout):
                assert hostname == _STAGING
                return _TargetSocket(target)

        return {"resolver": Resolver([[PUBLIC]]), "sockets": Sockets([]), "tls": TLS()}


class E3Vault:
    """SEAM-VAULT: OS-backend-shaped; credential tokens plus stored local input bytes by handle."""

    supported = True
    backend_id = "macos_keychain"

    def __init__(self):
        self.tokens: dict[str, str] = {}
        self.items: dict[str, bytes] = {}

    def store(self, handle_id, secret):
        assert handle_id not in self.items
        self.items[handle_id] = bytes(secret)

    def load(self, handle_id):
        from heel.runner.vault import VaultUnavailable

        if handle_id in self.items:
            return self.items[handle_id]
        if handle_id in self.tokens:
            return self.tokens[handle_id].encode("ascii")
        raise VaultUnavailable("secure credential was not found")

    def exists(self, handle_id):
        return handle_id in self.items

    def delete(self, handle_id):
        self.items.pop(handle_id, None)


class E3Customer(Customer):
    def __init__(self, tmp_path, serve_harness, monkeypatch, name):
        super().__init__(tmp_path, serve_harness, monkeypatch, name)
        self.vault = E3Vault()
        self.target = BillingTarget()
        self.spec = tmp_path / f"{name}-openapi.json"
        self.spec.write_text(json.dumps(OPENAPI))

    # --- browser-equivalent owner calls (session cookie, same origin) ---------------------
    def browser(self, method, path, body=None, *, extra=()):
        raw = b"" if body is None else json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
        headers = [("X-Heel-Edge-Auth", self.harness.edge_secret), ("Cookie", self.cookie),
                   ("Origin", self.harness.origin), ("X-Heel-Internal-Origin", "same-origin"),
                   ("Sec-Fetch-Site", "same-origin")]
        if body is not None:
            headers += [("Content-Type", "application/json"), ("Content-Length", str(len(raw)))]
        return _direct_backend(self.harness, method, path, raw if body is not None else None, headers + list(extra))

    @property
    def ws(self):
        return f"/v1/workspaces/{self.workspace_id}"

    def save_test(self, suffix, assertion, *, supersedes=None, route=ROUTE):
        definition = {
            "id": f"sc.internal.{suffix}", "objective": f"Lower plan must not read {suffix}",
            "category": "license_entitlement", "kind": "plan",
            "success_criterion": {"prop": "gated_by", "equals": "client"}, "severity_model": {"likelihood": 0.5, "impact": 0.5},
            "recommended_control": "Enforce the plan entitlement on the server.",
            "containment_limits": {"backoff": True, "max_probe_calls": 5, "sample": "canary_only", "no_live_targets": True},
        }
        status, body = self.browser("POST", f"{self.ws}/scenario-library/custom", {
            "schema_version": "heel.custom-scenario.v2", "definition": definition,
            "supersedes_revision": supersedes, "execution_binding": None,
            "live_test": {"schema_version": "heel.custom-live-test.v1", "scenario_id": "plan_entitlement_read",
                          "method": "GET", "route_template": route, "assertion": assertion},
        })
        return status, body

    def request_plan(self, body):
        return self.browser("POST", f"{self.base}/runner-context-bindings/{self.binding['binding_id']}/configured-plan-requests", body)

    def plan_view(self, plan_request_id):
        status, body = self.browser("GET", f"{self.base}/configured-plan-requests/{plan_request_id}")
        assert status == 200, body
        return body

    def approval_request(self):
        status, listed = self.browser("GET", f"{self.base}/canary-approval-requests")
        assert status == 200, listed
        (request,) = listed["requests"]
        return request

    def review_from(self, request):
        """Build the acknowledgement from the DISPLAYED configuration, as the UI does."""
        configured = request["configured"]
        return {
            "schema_version": configured["review_schema"], "plan_labels": configured["plan_labels"],
            "maximum_requests": request["request_budget"],
            "instances": [{key: item[key] for key in (
                "test_instance_id", "source", "scenario_id", "method", "route_template", "roles",
                "request_count", "assertion", "local_input_refs")} for item in configured["instances"]],
        }

    def approve_configured(self, request, *, review="displayed", key=None):
        body = {"schema_version": "heel.canary-execution-approval.v2", "projection_digest": request["projection_digest"],
                "hostname_retype": _STAGING, "reason": "Run the configured bounded staging reads",
                "condition_review": self.review_from(request) if review == "displayed" else review}
        if review is None:
            body = {key_: value for key_, value in body.items() if key_ != "condition_review"}
            body["schema_version"] = "heel.canary-execution-approval.v1"
        raw = canonical_bytes(body)
        key = key or "ca1-" + hashlib.sha256(request["run_id"].encode()).hexdigest()
        return _direct_backend(self.harness, "POST", f"{self.base}/canary-runs/{request['run_id']}/approve", raw, [
            ("X-Heel-Edge-Auth", self.harness.edge_secret), ("Cookie", self.cookie),
            ("Origin", self.harness.origin), ("X-Heel-Internal-Origin", "same-origin"),
            ("Content-Type", "application/json"), ("Content-Length", str(len(raw))),
            ("Idempotency-Key", key), ("If-Heel-Control-Generation", "0")])

    # --- customer runner commands -------------------------------------------------------------
    def setup_runner(self):
        assert self.cli("runner", "import-openapi", str(self.spec))[0] == 0
        for role, token in TOKENS.items():
            record = self.store.reserve_os_credential(
                semantic_role=role, auth_profile="bearer", label=f"local {role}", backend="macos_keychain")
            self.store.activate_credential(record["credential_handle_id"])
            self.vault.tokens[record["credential_handle_id"]] = token

    def add_input(self, name, text):
        read, write = os.pipe()
        os.set_inheritable(read, True)
        try:
            os.write(write, text.encode() + b"\n")
            os.close(write)
            code, out, err = self.cli("runner", "input", "add", "--name", name, "--backend", "keychain",
                                      "--type", "text", "--secret-fd", str(read))
        finally:
            os.close(read)
        assert (code, err) == (0, ""), err
        assert len(text) < 6 or text not in out
        return json.loads(out)

    def disclose(self, run_id):
        """Explicit, normal disclosure: runner registers metadata, owner permits, runner uploads."""
        assert not isinstance(self.serve(), BaseException)
        status, shown = self.browser("GET", f"{self.base}/canary-runs/{run_id}/disclosure")
        assert status == 200, shown
        status, permit = self.browser("POST", f"{self.base}/canary-runs/{run_id}/disclosure-permits", {
            "schema_version": "heel.canary-disclosure-request.v1",
            "projection_digest": shown["projection"]["projection_digest"],
            "projection_bytes": shown["projection"]["byte_count"],
            "scenario_count": shown["projection"]["scenario_count"],
            "finding_count": shown["projection"]["finding_count"]})
        assert shown["projection"]["schema_version"] == CONFIGURED_FINDINGS_SCHEMA
        assert status == 201, permit
        for _ in range(3):
            assert not isinstance(self.serve(), BaseException)
            status, findings = self.browser("GET", f"{self.base}/canary-runs/{run_id}/findings")
            if status == 200:
                return findings
        raise AssertionError(findings)


def _cloud_text(harness) -> str:
    """Every byte the control plane stored, as text: the privacy sentinel must be absent."""
    conn = sqlite3.connect(harness.root / "control-plane.sqlite3")
    try:
        chunks = []
        for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
            for row in conn.execute(f'SELECT * FROM "{table}"'):
                chunks.append(repr(row))
        return "\n".join(chunks)
    finally:
        conn.close()


def _results(findings):
    assert findings["schema_version"] == CONFIGURED_FINDINGS_SCHEMA
    return {item["source"]["source_scenario_id"]: item for item in findings["test_results"]}


@pytest.fixture
def customer(tmp_path, serve_harness, monkeypatch):
    return E3Customer(tmp_path, serve_harness, monkeypatch, "e3")


def test_two_conditions_on_one_primitive_route_flow_from_private_revisions_to_signed_results(customer):
    """Author -> request -> readiness -> local setup -> signed dry-run -> reviewed approval ->
    execution -> explicit disclosure; then an edit changes only the next run; then replay."""
    c = customer
    status, hint = c.save_test("export-hint", HINT_EQUALS)
    assert status == 201 and hint["revision"] == 1 and hint["live_support"] == "configured_live_read", hint
    assert hint["live_test"]["local_input_refs"] == ["export_ok", "secret_hint"]
    status, plan = c.save_test("export-plan", PLAN_EQUALS)
    assert status == 201, plan
    labels = [{"role": "higher_plan", "plan_label": "Pro"}, {"role": "lower_plan", "plan_label": "Free"}]
    tests = [{"source_scenario_id": "sc.internal.export-hint", "source_revision": 1},
             {"source_scenario_id": "sc.internal.export-plan", "source_revision": 1}]
    # Plan labels are operator-supplied and required for a plan comparison.
    status, refused = c.request_plan({"schema_version": "heel.configured-plan-request.v1",
                                      "plan_kind": "configured_live_read", "tests": tests, "plan_labels": []})
    assert (status, refused["code"]) == (400, "plan_labels_required"), refused
    status, created = c.request_plan({"schema_version": "heel.configured-plan-request.v1",
                                      "plan_kind": "configured_live_read", "tests": tests, "plan_labels": labels})
    assert status == 201 and created["status"] == "open" and created["runner_seen_at_ms"] is None, created
    assert "plan_request_nonce" not in json.dumps(created)
    first_ids = [item["test_instance_id"] for item in created["instances"]]
    assert len(set(first_ids)) == 2

    # Runner not yet set up: readiness names exactly the selected tests' needs; no submission.
    assert not isinstance(c.serve(), BaseException)
    view = c.plan_view(created["plan_request_id"])
    assert view["status"] == "open" and view["runner_seen_at_ms"] is not None
    needs = {(item["kind"], item["subject"], item["state"]) for entry in view["readiness"]["instances"]
             for item in entry["requirements"]}
    assert needs == {("route", None, "missing"), ("role_credential", "lower_plan", "missing"),
                     ("role_credential", "higher_plan", "missing"), ("local_input", "export_ok", "missing"),
                     ("local_input", "secret_hint", "missing"), ("local_input", "pro_plan", "missing")}
    assert c.target.requests == []

    # Local setup with ordinary text (no JSON quotes), values through an fd only.
    c.setup_runner()
    c.add_input("export_ok", "ok")
    c.add_input("secret_hint", SECRET_HINT)
    assert not isinstance(c.serve(), BaseException)
    view = c.plan_view(created["plan_request_id"])
    pending = {(item["subject"], item["state"]) for entry in view["readiness"]["instances"]
               for item in entry["requirements"] if item["state"] != "ready"}
    assert pending == {("pro_plan", "missing")} and view["status"] == "open"
    c.add_input("pro_plan", "pro")
    assert not isinstance(c.serve(), BaseException)
    view = c.plan_view(created["plan_request_id"])
    assert view["status"] == "projected" and view["run_id"], view
    assert c.target.requests == []  # a signed dry-run only: no target traffic before approval

    request = c.approval_request()
    assert request["run_id"] == view["run_id"] and request["request_budget"] == 20  # signed ceiling
    shown = request["configured"]
    assert sum(item["request_count"] for item in shown["instances"]) == 4  # planned reads
    assert [item["test_instance_id"] for item in shown["instances"]] == first_ids
    assert [item["assertion"] for item in shown["instances"]] == [HINT_EQUALS, PLAN_EQUALS]
    assert all(item["roles"] == ["lower_plan", "higher_plan"] for item in shown["instances"])
    assert shown["plan_labels"] == labels

    # An old client (v1 approval, digest only) and a stale review cannot approve.
    status, old = c.approve_configured(request, review=None)
    assert (status, old["code"]) == (409, "configured_review_required"), old
    stale = c.review_from(request)
    stale["instances"][1]["assertion"] = AUDIT_PRESENT
    status, mismatch = c.approve_configured(request, review=stale)
    assert (status, mismatch["code"]) == (409, "configured_review_mismatch"), mismatch
    status, approved = c.approve_configured(request)
    assert status == 201, approved
    # An idempotent retry returns the same grant; it never reserves or executes twice.
    status, again = c.approve_configured(request)
    assert status == 201 and again["grant"]["grant_id"] == approved["grant"]["grant_id"]

    assert not isinstance(c.serve(), BaseException)
    run_id = request["run_id"]
    assert c.store.load_run(run_id)["state"] == "terminal"
    assert c.target.lines() == [f"GET {ROUTE} HTTP/1.1".encode()] * 4

    findings = c.disclose(run_id)
    results = _results(findings)
    assert (results["sc.internal.export-hint"]["assessment_outcome"],
            results["sc.internal.export-hint"]["reason"]) == ("observed", "restricted_condition_true")
    assert (results["sc.internal.export-plan"]["assessment_outcome"],
            results["sc.internal.export-plan"]["reason"]) == ("blocked", "restricted_condition_false")
    assert [item["test_instance_id"] for item in findings["test_results"]] == first_ids

    # Edit: a new immutable revision with a different condition affects only the next run.
    status, edited = c.save_test("export-plan", AUDIT_PRESENT, supersedes=1)
    assert status == 201 and edited["revision"] == 2
    status, second = c.request_plan({"schema_version": "heel.configured-plan-request.v1",
                                     "plan_kind": "configured_live_read",
                                     "tests": [{"source_scenario_id": "sc.internal.export-plan", "source_revision": 2}],
                                     "plan_labels": labels})
    assert status == 201, second
    assert not isinstance(c.serve(), BaseException)
    request2 = c.approval_request()
    assert request2["configured"]["instances"][0]["assertion"] == AUDIT_PRESENT
    assert c.approve_configured(request2)[0] == 201
    assert not isinstance(c.serve(), BaseException)
    findings2 = c.disclose(request2["run_id"])
    edited_result = findings2["test_results"][0]
    assert edited_result["source"] == {"source_scenario_id": "sc.internal.export-plan", "source_revision": 2}
    assert edited_result["assessment_outcome"] == "inconclusive"  # the field is absent for both roles
    # The old run stays frozen at revision 1 with its original verdict.
    status, old_findings = c.browser("GET", f"{c.base}/canary-runs/{run_id}/findings")
    assert status == 200 and old_findings == findings
    # The frozen definitions behind the old result are still the revision-1 conditions, by instance.
    status, frozen = c.browser("GET", f"{c.base}/canary-runs/{run_id}/configured-plan")
    assert status == 200 and frozen["run_id"] == run_id
    assert frozen["projection_digest"] == findings["approval_projection_digest"]
    assert {item["test_instance_id"]: item["assertion"] for item in frozen["instances"]} == dict(zip(first_ids, [HINT_EQUALS, PLAN_EQUALS]))
    assert {item["test_instance_id"]: item["assertion_digest"] for item in frozen["instances"]} == {
        item["test_instance_id"]: item["assertion_digest"] for item in findings["test_results"]}

    # Save/replay the observed instance through the product: frozen handles, fresh approval.
    hint_instance = results["sc.internal.export-hint"]["test_instance_id"]
    c.target.mode = "patched"
    status, replay = c.request_plan({"schema_version": "heel.configured-plan-request.v1",
                                     "plan_kind": "configured_regression", "source_run_id": run_id,
                                     "test_instance_id": hint_instance})
    assert status == 201 and replay["instances"][0]["test_instance_id"] == hint_instance, replay
    assert replay["plan_labels"] == labels
    c.add_input("secret_hint", "a-rotated-value-that-must-not-be-used")  # names rotate; handles do not
    assert not isinstance(c.serve(), BaseException)
    request3 = c.approval_request()
    assert request3["configured"]["plan_kind"] == "configured_regression"
    assert c.approve_configured(request3)[0] == 201
    assert not isinstance(c.serve(), BaseException)
    findings3 = c.disclose(request3["run_id"])
    replayed = findings3["test_results"][0]
    assert replayed["test_instance_id"] == hint_instance
    assert (replayed["assessment_outcome"], replayed["reason"]) == ("blocked", "restricted_empty_denial")

    # Privacy: no expected value, token or raw response field reached any cloud row.
    stored = _cloud_text(c.harness)
    for sentinel in (SECRET_HINT, "a-rotated-value-that-must-not-be-used", *TOKENS.values()):
        assert sentinel not in stored


def test_configured_requests_are_workspace_private_and_fail_closed(tmp_path, serve_harness, monkeypatch):
    owner = E3Customer(tmp_path, serve_harness, monkeypatch, "owner-a")
    assert owner.save_test("private-a", HINT_EQUALS)[0] == 201
    status, static = owner.browser("POST", f"{owner.ws}/scenario-library/custom", {
        "schema_version": "heel.custom-scenario.v1", "definition": {
            "id": "sc.internal.static-only", "objective": "Static only", "category": "license_entitlement",
            "kind": "plan", "success_criterion": {"prop": "gated_by", "equals": "client"},
            "severity_model": {"likelihood": 0.5, "impact": 0.5}, "recommended_control": "Gate it.",
            "containment_limits": {"backoff": True, "max_probe_calls": 5, "sample": "canary_only", "no_live_targets": True}},
        "supersedes_revision": None, "execution_binding": None})
    assert status == 201 and static["live_support"] == "static_only"
    other = E3Customer(tmp_path, serve_harness, monkeypatch, "owner-b")
    labels = [{"role": "higher_plan", "plan_label": "Pro"}, {"role": "lower_plan", "plan_label": "Free"}]

    def ask(who, test, kind="configured_live_read"):
        return who.request_plan({"schema_version": "heel.configured-plan-request.v1", "plan_kind": kind,
                                 "tests": [test], "plan_labels": labels})

    # Another workspace's revision id is invisible; a static revision is not a live test.
    assert ask(other, {"source_scenario_id": "sc.internal.private-a", "source_revision": 1})[1]["code"] == \
        "custom_revision_not_found"
    assert ask(owner, {"source_scenario_id": "sc.internal.static-only", "source_revision": 1})[1]["code"] == \
        "live_test_not_configured"
    assert ask(owner, {"source_scenario_id": "sc.internal.private-a", "source_revision": 2})[1]["code"] == \
        "custom_revision_not_found"
    # Unknown request versions and parameterized routes are refused with closed codes.
    status, unknown = owner.request_plan({"schema_version": "heel.configured-plan-request.v2",
                                         "plan_kind": "configured_live_read", "tests": [], "plan_labels": []})
    assert (status, unknown["code"]) == (400, "invalid_configured_plan_request")
    status, parameterized = owner.save_test("param", HINT_EQUALS, route="/items/{item_id}")
    assert (status, parameterized["code"]) == (400, "live_test_route_unsupported"), parameterized
    # Another workspace's binding cannot be targeted.
    status, foreign = other.browser(
        "POST", f"{other.base}/runner-context-bindings/{owner.binding['binding_id']}/configured-plan-requests",
        {"schema_version": "heel.configured-plan-request.v1", "plan_kind": "configured_live_read",
         "tests": [{"source_scenario_id": "sc.internal.private-a", "source_revision": 1}], "plan_labels": labels})
    assert status == 404, foreign
    # A regression must name a terminal configured run of the same runner.
    status, missing = owner.request_plan({"schema_version": "heel.configured-plan-request.v1",
                                         "plan_kind": "configured_regression", "source_run_id": "crun_" + "0" * 32,
                                         "test_instance_id": "lti_" + "0" * 32})
    assert (status, missing["code"]) == (409, "configured_source_run_unavailable")
    # One open request per binding; cancellation frees it, and a cancelled request is never delivered.
    assert ask(owner, {"source_scenario_id": "sc.internal.private-a", "source_revision": 1})[0] == 201
    status, busy = ask(owner, {"source_scenario_id": "sc.internal.private-a", "source_revision": 1})
    assert (status, busy["code"]) == (409, "plan_request_open")
    status, listed = owner.browser("GET", f"{owner.base}/configured-plan-requests")
    assert status == 200 and len(listed["requests"]) == 1
    status, cancelled = owner.browser(
        "POST", f"{owner.base}/configured-plan-requests/{listed['requests'][0]['plan_request_id']}/cancel",
        {"schema_version": "heel.configured-plan-request-cancel.v1"})
    assert status == 200 and cancelled["status"] == "cancelled", cancelled
    assert not isinstance(owner.serve(), BaseException)
    assert owner.browser("GET", f"{owner.base}/canary-approval-requests")[1]["requests"] == []


def test_a_runner_signed_condition_that_differs_from_the_frozen_request_is_refused(customer, monkeypatch):
    """Tamper: the runner signs a different condition than the browser froze -> refused before
    any approval record, grant or target request."""
    from heel.runner import compiler as compiler_module

    c = customer
    assert c.save_test("tamper", HINT_EQUALS)[0] == 201
    c.setup_runner()
    for name, value in (("export_ok", "ok"), ("secret_hint", SECRET_HINT)):
        c.add_input(name, value)
    labels = [{"role": "higher_plan", "plan_label": "Pro"}, {"role": "lower_plan", "plan_label": "Free"}]
    status, created = c.request_plan({"schema_version": "heel.configured-plan-request.v1",
                                      "plan_kind": "configured_live_read",
                                      "tests": [{"source_scenario_id": "sc.internal.tamper", "source_revision": 1}],
                                      "plan_labels": labels})
    assert status == 201
    real = compiler_module.CanaryCompiler.compile_configured

    def widened(self, instances, **kwargs):
        changed = [{**item, "assertion": _assertion({"kind": "json_field_present", "path": ["export"]}),
                    "local_inputs": {"export_ok": "export_ok"}} for item in instances]
        return real(self, changed, **kwargs)

    monkeypatch.setattr(compiler_module.CanaryCompiler, "compile_configured", widened)
    result = c.serve()
    assert isinstance(result, BaseException)  # the cloud refused the mismatched signed plan
    view = c.plan_view(created["plan_request_id"])
    assert view["status"] == "open" and view["run_id"] is None
    assert c.browser("GET", f"{c.base}/canary-approval-requests")[1]["requests"] == []
    assert c.target.requests == []


def _readiness(view):
    readiness = view.get("readiness")
    if readiness is None:
        return None
    return {(item["kind"], item["subject"], item["state"]) for entry in readiness["instances"]
            for item in entry["requirements"]}


def test_an_ineligible_replay_source_is_reported_unavailable_and_one_serve_keeps_running(customer):
    """A replay of a terminal instance that was NOT observed (here: blocked) cannot be saved as a
    regression. The runner reports its frozen run as not ready for that request (no compile, no
    submission, no target request) and the same long-lived serve stays online; an eligible
    frozen replay requested next in that process still runs under a fresh approval."""
    from tests.test_runner_daemon import _daemon, _serve_in_thread, _serve_state, _wait_serve_state

    c = customer
    assert c.save_test("export-hint", HINT_EQUALS)[0] == 201
    assert c.save_test("export-plan", PLAN_EQUALS)[0] == 201
    c.setup_runner()
    for name, value in (("export_ok", "ok"), ("secret_hint", SECRET_HINT), ("pro_plan", "pro")):
        c.add_input(name, value)
    labels = [{"role": "higher_plan", "plan_label": "Pro"}, {"role": "lower_plan", "plan_label": "Free"}]
    status, _created = c.request_plan({
        "schema_version": "heel.configured-plan-request.v1", "plan_kind": "configured_live_read",
        "tests": [{"source_scenario_id": "sc.internal.export-hint", "source_revision": 1},
                  {"source_scenario_id": "sc.internal.export-plan", "source_revision": 1}],
        "plan_labels": labels})
    assert status == 201
    assert not isinstance(c.serve(), BaseException)
    request = c.approval_request()
    assert c.approve_configured(request)[0] == 201
    assert not isinstance(c.serve(), BaseException)
    run_id = request["run_id"]
    local = c.store.load_final_projections(run_id)["local_view"]["findings_projection"]
    outcomes = {item["source"]["source_scenario_id"]: item for item in local["test_results"]}
    assert outcomes["sc.internal.export-hint"]["assessment_outcome"] == "observed"
    assert outcomes["sc.internal.export-plan"]["assessment_outcome"] == "blocked"
    blocked = outcomes["sc.internal.export-plan"]["test_instance_id"]
    observed = outcomes["sc.internal.export-hint"]["test_instance_id"]
    assert len(c.target.requests) == 4

    daemon = _daemon(c.home, c.harness, c.backend, vault_factory=lambda backend: c.vault,
                     target_network=c.target.network())
    thread, events, outcome = _serve_in_thread(daemon)
    try:
        _wait_serve_state(c.home, lambda state: state["state"] == "online")
        c.target.mode = "patched"
        status, ineligible = c.request_plan({"schema_version": "heel.configured-plan-request.v1",
                                             "plan_kind": "configured_regression", "source_run_id": run_id,
                                             "test_instance_id": blocked})
        assert status == 201, ineligible
        deadline = time.monotonic() + 30
        view = c.plan_view(ineligible["plan_request_id"])
        while _readiness(view) is None and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.1)
            view = c.plan_view(ineligible["plan_request_id"])
        assert thread.is_alive(), outcome
        # The run is present but not an eligible source: frozen_run is not ready, nothing else is
        # claimed about the run, nothing is compiled, submitted or sent to the target.
        assert _readiness(view) == {("route", None, "ready"), ("role_credential", "lower_plan", "ready"),
                                    ("role_credential", "higher_plan", "ready"),
                                    ("frozen_run", None, "missing")}, view
        assert view["status"] == "open" and view["run_id"] is None, view
        time.sleep(2.5)  # one more idle cycle of the same process sees the same open request
        assert thread.is_alive(), outcome
        assert _serve_state(c.home)["state"] == "online"
        assert c.browser("GET", f"{c.base}/canary-approval-requests")[1]["requests"] == []
        assert len(c.target.requests) == 4
        status, cancelled = c.browser(
            "POST", f"{c.base}/configured-plan-requests/{ineligible['plan_request_id']}/cancel",
            {"schema_version": "heel.configured-plan-request-cancel.v1"})
        assert status == 200 and cancelled["status"] == "cancelled", cancelled

        # The ordinary eligible frozen replay, requested next in the SAME serve, still runs.
        status, eligible = c.request_plan({"schema_version": "heel.configured-plan-request.v1",
                                           "plan_kind": "configured_regression", "source_run_id": run_id,
                                           "test_instance_id": observed})
        assert status == 201, eligible
        deadline = time.monotonic() + 30
        listed: list = []
        while not listed and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.1)
            listed = c.browser("GET", f"{c.base}/canary-approval-requests")[1]["requests"]
        (replay,) = listed
        assert replay["configured"]["plan_kind"] == "configured_regression"
        assert [item["test_instance_id"] for item in replay["configured"]["instances"]] == [observed]
        assert c.approve_configured(replay)[0] == 201
        deadline = time.monotonic() + 30
        while thread.is_alive() and time.monotonic() < deadline:
            try:
                if c.store.load_run(replay["run_id"])["state"] == "terminal":
                    break
            except Exception:
                pass
            time.sleep(0.1)
        assert thread.is_alive(), outcome
        replayed = c.store.load_final_projections(replay["run_id"])["local_view"]["findings_projection"]
        (result,) = replayed["test_results"]
        assert result["test_instance_id"] == observed
        assert (result["assessment_outcome"], result["reason"]) == ("blocked", "restricted_empty_denial")
        assert len(c.target.requests) == 6  # exactly the replay's two approved reads
    finally:
        daemon.request_stop()
        thread.join(15)
    assert outcome.get("result", {}).get("state") == "stopped", outcome
    assert "failed" not in [event["state"] for event in events if event.get("event") == "serve_state"]
