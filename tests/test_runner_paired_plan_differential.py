"""Plan-differential comparator inside the paired (browser-approved) executor.

The paired serve path runs ``plan_entitlement_read`` through ``LocalCanaryExecutor``. When no
``heel-canary-`` fixture is bound, the executor re-reads the two stored, redacted response
bodies of exactly that scenario's lower/higher actions and applies the existing
``evaluate_plan_pair`` comparator (row 6 observed, row 7 held, every other row inconclusive).

Real: control plane behind the TLS edge, pairing, context binding, ``heel.cli.main`` for every
customer command, ``RunnerDaemon.serve``, ``RunnerCoordinator``, ``LocalCanaryExecutor``,
``TargetHTTPSClient`` and ``RunnerStore``. Seams are the ones labelled in
``tests/test_runner_regression_replay.py`` (secret backend/CA, vault, scripted target socket,
browser-equivalent owner approval). The target serves ordinary JSON export bodies: no Heel
marker field and no declared finding annotation in the OpenAPI input.
"""
from __future__ import annotations

import json

import pytest

from heel.canary_contracts import validate_canary_findings
from heel.runner.store import RunnerStore
from tests.plan_differential_support import DENIAL_ENVELOPE, EXPORT
from tests.test_runner_daemon import _STAGING, serve_harness  # noqa: F401 - fixture by name
from tests.test_runner_http_transport import PUBLIC, Resolver, Sockets
from tests.test_runner_regression_replay import Customer, _TargetSocket

SCENARIO = "plan_entitlement_read"
EXPORT_ROUTE = "/api/export"
CANARY_ROUTE = "/exports/{export_id}"
CANARY = "heel-canary-export-0042"
TOKENS = {
    "lower_plan": "synthetic-plan-token-free-0001",
    "higher_plan": "synthetic-plan-token-pro-0002",
}
OWNERSHIP_TOKENS = {
    "object_owner": "synthetic-plan-token-owner-0003",
    "non_owner": "synthetic-plan-token-nonowner-0004",
}
OBSERVED_TITLE = "Lower-plan read covered every key path of the higher-plan response"
CANARY_TITLE = "Canary authorization boundary was crossed"
FORBIDDEN_PROJECTION_TEXT = (
    "acct_canary", "row_1", "upgrade required", "amount_cents", *TOKENS.values(),
)

# An ordinary OpenAPI document: no Heel marker field, no declared finding annotation.
OPENAPI = {
    "openapi": "3.1.0",
    "info": {"title": "Ordinary export API", "version": "1.0.0"},
    "paths": {
        "/api/export": {
            "get": {"operationId": "getExport", "responses": {"200": {"description": "ok"}}},
            "head": {"operationId": "headExport", "responses": {"200": {"description": "ok"}}},
        },
        "/exports/{export_id}": {
            "get": {"operationId": "getExportById", "responses": {"200": {"description": "ok"}}},
        },
        "/items/{item_id}": {
            "get": {"operationId": "getItem", "responses": {"200": {"description": "ok"}}},
        },
    },
}


def _http(status: int, body: bytes, *, head: bool = False) -> bytes:
    head_bytes = (
        f"HTTP/1.1 {status} Status\r\nContent-Length: {len(body)}\r\n"
        "Content-Type: application/json\r\n\r\n"
    ).encode("ascii")
    return head_bytes if head else head_bytes + body


def _json(value) -> bytes:
    return json.dumps(value).encode()


EXPORT_BODY = _json(EXPORT)
HOLLOW_BODY = _json({"account_id": "", "format": "", "rows": [], "total": 0})
SUBSET_BODY = _json({"account_id": EXPORT["account_id"], "total": 0})
PAYLOAD_DENIAL = _json({**EXPORT, "error": "upgrade required"})

# What the lower ("free") identity receives on /api/export, per mode; "pro" is always EXPORT.
LOWER_EXPORT = {
    "vulnerable": (200, EXPORT_BODY),
    "patched": (403, b""),
    "envelope": (403, _json(DENIAL_ENVELOPE)),
    "subset": (200, SUBSET_BODY),
    "hollow": (200, HOLLOW_BODY),
    "status_only": (403, PAYLOAD_DENIAL),
}


class PlanTarget:
    """SEAM-TARGET: an ordinary plan-gated export application, answering by bearer token."""

    def __init__(self):
        self.mode = "vulnerable"
        self.unmarked_canary = False
        self.requests: list[bytes] = []

    def answer(self, request: bytes) -> bytes:
        line = request.split(b"\r\n", 1)[0].decode()
        method, path, _ = line.split(" ")
        head = method == "HEAD"
        if f"Bearer {OWNERSHIP_TOKENS['object_owner']}".encode() in request or (
            f"Bearer {OWNERSHIP_TOKENS['non_owner']}".encode() in request
        ):
            item = path.removeprefix("/items/")
            return _http(200, _json({"protected_canary": item}))
        pro = f"Bearer {TOKENS['higher_plan']}".encode() in request
        assert pro or f"Bearer {TOKENS['lower_plan']}".encode() in request
        if path.startswith("/exports/"):
            if self.unmarked_canary:  # the marker-bound route no longer carries the marker
                return _http(200, EXPORT_BODY)
            body = _json({"protected_canary": path.removeprefix("/exports/"), "rows": []})
            if pro or self.mode == "vulnerable":
                return _http(200, body)
            return _http(403, b"")
        assert path == EXPORT_ROUTE, path
        status, body = (200, EXPORT_BODY) if pro else LOWER_EXPORT[self.mode]
        return _http(status, body, head=head)

    def lines(self) -> list[bytes]:
        return [item.split(b"\r\n", 1)[0] for item in self.requests]

    def network(self):
        target = self

        class TLS:
            def wrap(self, raw, hostname, timeout):
                assert hostname == _STAGING
                return _TargetSocket(target)

        return {"resolver": Resolver([[PUBLIC]]), "sockets": Sockets([]), "tls": TLS()}


class PlanCustomer(Customer):
    """The saved-replay customer journey, configured for an ordinary plan-gated export read."""

    def __init__(self, tmp_path, serve_harness, monkeypatch, name):
        super().__init__(tmp_path, serve_harness, monkeypatch, name)
        self.target = PlanTarget()
        self.openapi = tmp_path / f"{name}-openapi.json"
        self.openapi.write_text(json.dumps(OPENAPI))
        self.method = "GET"

    def map_plan(self, route=EXPORT_ROUTE, method="GET", fixture=None, scenario=SCENARIO):
        import os

        read, write = os.pipe()
        os.set_inheritable(read, True)
        try:
            name = route[route.index("{") + 1:route.index("}")] if "{" in route else None
            os.write(write, json.dumps({name: fixture} if name else {}).encode())
            os.close(write)
            code, _out, err = self.cli("runner", "map", "--scenario", scenario, "--method", method,
                                       "--route", route, "--fixture-fd", str(read))
        finally:
            os.close(read)
        assert code == 0, err
        if scenario == SCENARIO:
            self.method = method

    def register(self, tokens):
        """Explicit local plan labels: each credential is registered under its stated role."""
        for role, token in tokens.items():
            record = self.store.reserve_os_credential(
                semantic_role=role, auth_profile="bearer", label=f"local {role}",
                backend="macos_keychain")
            self.store.activate_credential(record["credential_handle_id"])
            self.vault.tokens[record["credential_handle_id"]] = token

    def configure(self, route=EXPORT_ROUTE, method="GET", fixture=None):
        assert self.cli("runner", "import-openapi", str(self.openapi))[0] == 0
        self.register(TOKENS)
        self.map_plan(route, method, fixture)

    def execute(self, shown, mode):
        self.target.mode = mode
        before = len(self.target.requests)
        grant = self.approve(shown)
        result = self.serve()
        assert not isinstance(result, BaseException), (result.state, result.code)
        assert self.store.load_run(shown["run_id"])["state"] == "terminal"
        self.sent = self.target.lines()[before:]
        return grant

    def run(self, mode):
        """prepare --live -> serve submission -> owner approval -> serve execution."""
        _prepared, shown = self.submit()
        self.execute(shown, mode)
        return shown["run_id"], self.ok("runner", "findings", "--run", shown["run_id"])


def _scenario(view, scenario_id=SCENARIO):
    (result,) = [item for item in view["findings_projection"]["scenario_results"]
                 if item["scenario_id"] == scenario_id]
    return result


# Request lines this module's synthetic target can legitimately receive; anything else is
# reported only as "unlisted" so a diagnostic message can never echo an unexpected request.
_DIAGNOSTIC_REQUEST_LINES = frozenset(
    f"{method} {path} HTTP/1.1"
    for method in ("GET", "HEAD")
    for path in (EXPORT_ROUTE, f"/exports/{CANARY}")
)


def _outcome_diagnostic(customer, view, scenario_id=SCENARIO) -> str:
    """Failure-only, allowlisted operational facts for an outcome assertion message.

    Discriminates incomplete execution (disposition/error/stop/containment), wrong observations
    (role/status/body_shape per observation, request lines) and adapter classification (a
    completed run whose observations are in shape). Never a full view, body, header, credential,
    handle or environment value.
    """
    operational = view.get("operational_projection") or {}
    scenarios = [item for item in (view.get("findings_projection") or {}).get(
        "scenario_results", []) if item.get("scenario_id") == scenario_id]
    result = scenarios[0] if len(scenarios) == 1 else {}
    facts = {
        "execution_disposition": operational.get("execution_disposition"),
        "error_category": operational.get("error_category"),
        "stop_reason": operational.get("stop_reason"),
        "containment_codes": list(operational.get("containment_codes") or []),
        "scenario_containment_codes": list(result.get("containment_codes") or []),
        "observations": [
            {key: item.get(key) for key in ("semantic_role", "status_code", "body_shape")}
            for item in result.get("observations") or []
        ],
        "request_lines": [
            line.decode("ascii", "replace") if line.decode("ascii", "replace")
            in _DIAGNOSTIC_REQUEST_LINES else "unlisted"
            for line in getattr(customer, "sent", [])
        ],
    }
    return "diagnostic=" + json.dumps(facts, sort_keys=True)


def _assert_redacted_projection(customer, run_id, view):
    findings = view["findings_projection"]
    assert validate_canary_findings(findings) == findings
    blob = json.dumps(view)
    for text in FORBIDDEN_PROJECTION_TEXT:
        assert text not in blob
    # The disclosed (cloud) result is the same validated projection; no body crossed it.
    finals = customer.store.load_final_projections(run_id)
    assert finals["findings_projection"] == findings


@pytest.fixture
def customer(tmp_path, serve_harness, monkeypatch):
    return PlanCustomer(tmp_path, serve_harness, monkeypatch, "plan-diff")


# --------------------------------------------------------------------------- T1-T5, T7


def test_t1_vulnerable_ordinary_export_is_an_observed_undeclared_finding(customer):
    customer.configure()
    run_id, view = customer.run("vulnerable")
    assert customer.sent == [f"GET {EXPORT_ROUTE} HTTP/1.1".encode()] * 2
    result = _scenario(view)
    assert result["assessment_outcome"] == "observed"
    assert view["findings_projection"]["assessment_outcome"] == "observed"
    finding = result["finding"]
    assert finding["title"] == OBSERVED_TITLE
    assert finding["confidence"] == "medium"
    assert "values were not compared" in finding["reachability_rationale"]
    assert "not plan-gated by design" in finding["reachability_rationale"]
    assert result["route"] == {"method": "GET", "route_template": EXPORT_ROUTE}
    assert sorted(item["semantic_role"] for item in result["observations"]) == [
        "higher_plan", "lower_plan"]
    assert len(result["local_evidence_refs"]) == 2
    _assert_redacted_projection(customer, run_id, view)
    assert view["operational_projection"]["execution_disposition"] == "completed"


@pytest.mark.parametrize("mode, outcome", [
    ("patched", "blocked"),        # T2 free 403, empty body: row 7 held
    ("envelope", "inconclusive"),  # T3 free 403 {"error":"upgrade required"}: row 9
    ("subset", "inconclusive"),    # T4 free 200 with a key-path subset: row 8 candidate only
    ("hollow", "inconclusive"),    # T4 free 200 echoing keys with empty values: row 9
    ("status_only", "inconclusive"),  # free 403 whose body still carries every payload path
])
def test_t2_t4_lower_responses_map_to_the_existing_comparator_rows(customer, mode, outcome):
    customer.configure()
    run_id, view = customer.run(mode)
    result = _scenario(view)
    assert result["assessment_outcome"] == outcome
    assert result["finding"] is None
    assert view["findings_projection"]["assessment_outcome"] == outcome
    _assert_redacted_projection(customer, run_id, view)


@pytest.mark.parametrize("mode, outcome", [("vulnerable", "inconclusive"), ("patched", "blocked")])
def test_t5_head_pair_is_never_observed(customer, mode, outcome):
    customer.configure(method="HEAD")
    run_id, view = customer.run(mode)
    assert customer.sent == [f"HEAD {EXPORT_ROUTE} HTTP/1.1".encode()] * 2
    result = _scenario(view)
    assert (result["assessment_outcome"], result["finding"]) == (outcome, None)
    _assert_redacted_projection(customer, run_id, view)


@pytest.mark.parametrize("fault", ["missing", "expired", "malformed"])
def test_t7_unavailable_or_invalid_evidence_fails_closed(customer, monkeypatch, fault):
    from heel.runner.store import RunnerStoreError

    original = RunnerStore.load_response_evidence

    def faulty(self, run_id, reference, *, now_ms):
        if fault == "missing":
            raise RunnerStoreError("local evidence is unavailable")
        if fault == "expired":
            return original(self, run_id, reference, now_ms=2 ** 62)
        headers, _body = original(self, run_id, reference, now_ms=now_ms)
        return headers, b"\xff{not json"

    customer.configure()
    monkeypatch.setattr(RunnerStore, "load_response_evidence", faulty)
    run_id, view = customer.run("vulnerable")
    monkeypatch.setattr(RunnerStore, "load_response_evidence", original)
    result = _scenario(view)
    assert (result["assessment_outcome"], result["finding"]) == ("inconclusive", None)
    assert view["operational_projection"]["execution_disposition"] == "completed"
    _assert_redacted_projection(customer, run_id, view)


# --------------------------------------------------------------------------- T6 marker path


def test_t6_marker_bound_runs_keep_the_existing_canary_result(customer):
    customer.configure(route=CANARY_ROUTE, fixture=CANARY)
    run_id, view = customer.run("vulnerable")
    assert customer.sent == [f"GET /exports/{CANARY} HTTP/1.1".encode()] * 2
    result = _scenario(view)
    assert result["assessment_outcome"] == "observed"
    assert result["finding"]["title"] == CANARY_TITLE
    assert result["finding"]["confidence"] == "high"

    _run_id, patched = customer.run("patched")
    assert (_scenario(patched)["assessment_outcome"], _scenario(patched)["finding"]) == (
        "blocked", None), _outcome_diagnostic(customer, patched)

    # The bound marker is missing from both bodies: the canary path owns the decision and the
    # markerless comparator is never consulted, even though both bodies share every key path.
    customer.target.unmarked_canary = True
    _run_id, unmarked = customer.run("vulnerable")
    assert (_scenario(unmarked)["assessment_outcome"], _scenario(unmarked)["finding"]) == (
        "inconclusive", None)


def test_outcome_diagnostic_reports_only_allowlisted_operational_facts():
    """The T6 failure message carries enumerated facts only: never a body, header, token,
    handle, environment value or an unexpected request line."""
    secret_header = f"Authorization: Bearer {TOKENS['lower_plan']}"
    view = {
        "operational_projection": {
            "execution_disposition": "incomplete", "error_category": "target_timeout",
            "stop_reason": "none", "containment_codes": ["target_timeout"],
            "run_id": "run-secret-id", "signature_b64": "c2lnbmF0dXJl", "environ": {"HOME": "/h"},
        },
        "findings_projection": {"scenario_results": [{
            "scenario_id": SCENARIO, "assessment_outcome": "inconclusive",
            "containment_codes": ["evidence_unavailable"],
            "finding": {"title": "acct_canary row_1", "evidence": PAYLOAD_DENIAL.decode()},
            "local_evidence_refs": ["ev1_" + "a" * 64],
            "observations": [
                {"semantic_role": "higher_plan", "status_code": 200, "body_shape": "json_object",
                 "truncation_state": "complete", "body": EXPORT_BODY.decode(),
                 "headers": secret_header, "credential_handle_id": "cred-handle-0001"},
            ],
        }]},
    }

    class Sent:
        sent = [f"GET /exports/{CANARY} HTTP/1.1".encode(),
                f"GET /exports/{TOKENS['higher_plan']} HTTP/1.1".encode(),
                secret_header.encode()]

    message = _outcome_diagnostic(Sent(), view)
    facts = json.loads(message.removeprefix("diagnostic="))
    assert facts == {
        "execution_disposition": "incomplete", "error_category": "target_timeout",
        "stop_reason": "none", "containment_codes": ["target_timeout"],
        "scenario_containment_codes": ["evidence_unavailable"],
        "observations": [{"semantic_role": "higher_plan", "status_code": 200,
                          "body_shape": "json_object"}],
        "request_lines": [f"GET /exports/{CANARY} HTTP/1.1", "unlisted", "unlisted"],
    }
    for text in (*FORBIDDEN_PROJECTION_TEXT, *TOKENS.values(), *OWNERSHIP_TOKENS.values(),
                 "Bearer", "Authorization", "run-secret-id", "c2lnbmF0dXJl", "HOME",
                 "cred-handle-0001", "ev1_", "rows", "acct_"):
        assert text not in message
    # A missing or malformed view still yields a message rather than masking the assertion.
    assert json.loads(_outcome_diagnostic(object(), {}).removeprefix("diagnostic="))[
        "observations"] == []


# --------------------------------------------------------------------------- ordinal binding


def test_comparator_reads_only_the_plan_scenarios_own_actions_in_a_mixed_run(customer):
    """Another scenario in the same run returns a marker body; the plan pair is bound to its
    own lower/higher action ordinals and never to the other scenario's evidence."""
    customer.configure()
    customer.register(OWNERSHIP_TOKENS)
    customer.map_plan("/items/{item_id}", fixture="heel-canary-item-0137",
                      scenario="object_ownership_read")
    run_id, view = customer.run("patched")
    assert len(customer.sent) == 4
    plan = _scenario(view)
    ownership = _scenario(view, "object_ownership_read")
    assert (plan["assessment_outcome"], plan["finding"]) == ("blocked", None)
    assert ownership["assessment_outcome"] == "observed"
    assert ownership["finding"]["title"] == CANARY_TITLE
    assert not set(plan["local_evidence_refs"]) & set(ownership["local_evidence_refs"])
    _assert_redacted_projection(customer, run_id, view)


def test_shared_loader_binds_exact_ordinals_and_refuses_unrelated_evidence(customer):
    from heel.runner.plan_differential import load_plan_pair_observations

    customer.configure()
    customer.register(OWNERSHIP_TOKENS)
    customer.map_plan("/items/{item_id}", fixture="heel-canary-item-0137",
                      scenario="object_ownership_read")
    run_id, view = customer.run("vulnerable")
    store = customer.store
    grant = store.load_run_grant(run_id)
    manifest, _projection = store.load_approved_pair(grant["approval"]["projection_id"])
    ordinals = {action["semantic_auth_role"]: action["ordinal"] for action in manifest["actions"]}
    plan_refs = _scenario(view)["local_evidence_refs"]
    other_refs = _scenario(view, "object_ownership_read")["local_evidence_refs"]
    now = __import__("time").time_ns() // 1_000_000

    def load(references, lower=ordinals["lower_plan"], higher=ordinals["higher_plan"]):
        return load_plan_pair_observations(
            store, run_id, references, lower_ordinal=lower, higher_ordinal=higher, now_ms=now)

    lower, higher = load(plan_refs)
    assert (lower.status, higher.status) == (200, 200)
    assert json.loads(lower.body) == EXPORT == json.loads(higher.body)
    assert {lower.evidence_ref, higher.evidence_ref} == set(plan_refs)
    # Unrelated evidence from the same run, a mixed selection, an extra reference or swapped
    # or foreign ordinals are all refused, never re-bound.
    assert load(other_refs) == (None, None)
    assert load([plan_refs[0], other_refs[0]]) == (None, None)
    assert load([*plan_refs, other_refs[0]]) == (None, None)
    assert load(plan_refs, lower=ordinals["object_owner"]) == (None, None)
    assert load(plan_refs, lower=ordinals["lower_plan"], higher=ordinals["lower_plan"]) == (None, None)
    assert load([plan_refs[0], plan_refs[0]]) == (None, None)
    assert load(["ev1_" + "0" * 64, plan_refs[1]]) == (None, None)


# --------------------------------------------------------------------------- saved replay


def test_markerless_export_finding_saves_and_replays_fail_then_pass(customer):
    """Finite acceptance: map -> prepare --live -> approve -> serve -> findings observed ->
    regress add -> replay (vulnerable) fail -> patch -> fresh replay -> blocked/pass."""
    customer.configure()
    source_run, view = customer.run("vulnerable")
    assert _scenario(view)["assessment_outcome"] == "observed"
    added = customer.ok("runner", "regress", "add", "--run", source_run, "--scenario", SCENARIO,
                        "--name", "Free plan export")
    regression_id = added["regression"]["regression_id"]

    _prepared, shown = customer.submit("--regression", regression_id)
    customer.execute(shown, "vulnerable")
    fail = customer.ok("runner", "regress", "record", "--regression", regression_id,
                       "--run", shown["run_id"])["result"]
    assert (fail["outcome"], fail["assessment_outcome"]) == ("fail", "observed")

    _prepared, shown2 = customer.submit("--regression", regression_id)
    customer.execute(shown2, "patched")
    passed = customer.ok("runner", "regress", "record", "--regression", regression_id,
                         "--run", shown2["run_id"])["result"]
    assert (passed["outcome"], passed["assessment_outcome"]) == ("pass", "blocked")
    assert len({source_run, shown["run_id"], shown2["run_id"]}) == 3
    assert customer.approvals == 3
    assert customer.target.lines() == [f"GET {EXPORT_ROUTE} HTTP/1.1".encode()] * 6
    listed = customer.ok("runner", "regress", "list")
    assert [item["outcome"] for item in listed["results"]] == ["fail", "pass"]
    blob = json.dumps(listed)
    for text in FORBIDDEN_PROJECTION_TEXT:
        assert text not in blob
