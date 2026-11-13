"""Browser-local static scenario assessment (heel/browser_assess.py)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from heel.agents import evaluate_criterion, run_adversarial
from heel.browser_assess import (
    NOTE_NO_SURFACE,
    affordances_from_model,
    assess_scenarios_json,
    evaluate_criterion3,
)
from heel.browser_review import BrowserReviewError
from heel.contracts import AbuseScenario, Affordance, Category
from heel.importers import _affordances, target_from_product_model
from heel.product_model import product_model_from_dict
from heel.review_contract import stable_json_hash
from heel.saas.scenario_library import ScenarioLibraryService

from canary_test_support import connect


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "tests/fixtures/canary/staging-openapi.json").read_text(encoding="utf-8")
RICH_MODEL = json.loads((ROOT / "examples/saas_demo/product_model.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def listing():
    return ScenarioLibraryService(connect()).listing("ws_canary")


def _entry(row):
    return {
        "scenario_id": row["id"], "source": row["source"], "revision": row["revision"],
        "definition_digest": row["definition_digest"], "definition": row["definition"],
    }


def _custom(scenario_id, criterion, *, kind="endpoint", revision=1, **extra):
    definition = {
        "id": scenario_id, "category": "unintended_endpoints", "objective": "Custom check",
        "kind": kind, "success_criterion": criterion,
        "severity_model": {"likelihood": 0.5, "impact": 0.5},
        "recommended_control": "enforce the server-side rule",
        "containment_limits": {"canary_only": True, "no_live_targets": True, "sample_cap": 1},
        **extra,
    }
    return {"scenario_id": scenario_id, "source": "custom", "revision": revision,
            "definition_digest": stable_json_hash(definition), "definition": definition}


def _selection(listing, entries):
    return json.dumps({
        "schema_version": "heel.scenario-assessment-selection.v1",
        "library_digest": listing["library_digest"],
        "scenarios": entries,
    })


def _assess(listing, entries, answers="[]", source=SOURCE):
    return json.loads(assess_scenarios_json(source, answers, _selection(listing, entries)))


def _by_id(envelope):
    return {row["scenario_id"]: row for row in envelope["results"]}


def test_assess_outputs_three_states(listing):
    library = [_entry(row) for row in listing["scenarios"]]
    first = assess_scenarios_json(SOURCE, "[]", _selection(listing, library))
    second = assess_scenarios_json(SOURCE, "[]", _selection(listing, library))
    assert first == second  # deterministic, canonical
    envelope = json.loads(first)
    assert envelope["schema_version"] == "heel.scenario-assessment.v1"
    assert envelope["privacy"] == {"execution": "browser_local", "network_calls": False, "uploaded": False}
    assert envelope["library_digest"] == listing["library_digest"]
    assert envelope["model_coverage"]["entitlement_graph_edges"] == "not_evaluated"
    assert [row["scenario_id"] for row in envelope["results"]] == [row["id"] for row in listing["scenarios"]]
    none = [row for row in envelope["results"] if row["outcome"] == "no_matching_surface"]
    assert none and all(row["note"] == NOTE_NO_SURFACE and row["applicability"] == "unknown"
                        and row["evidence_state"] == "unknown" and row["surface"] is None for row in none)
    assert all(row["evidence_state"] in {"inferred", "customer_declared", "unknown"} for row in envelope["results"])

    probe = [
        _custom("sc.internal.list_items_get", {"all_of": [
            {"prop": "operation_id", "equals": "listitems"}, {"prop": "method", "equals": "GET"}]}),
        _custom("sc.internal.admin_users_get", {"all_of": [
            {"prop": "operation_id", "equals": "listadminusers"}, {"prop": "method", "equals": "GET"}]}),
    ]
    plain = _by_id(_assess(listing, probe))
    assert plain["sc.internal.list_items_get"]["outcome"] == "inferred_finding"
    assert plain["sc.internal.list_items_get"]["evidence_state"] == "inferred"  # undeclared surface
    assert plain["sc.internal.list_items_get"]["surface"] == {"method": "GET", "route": "/items"}

    unknown = _by_id(_assess(listing, probe, json.dumps([
        {"surface": "listitems", "field": "tenant_filter", "value": "unknown"}])))
    assert unknown["sc.internal.list_items_get"]["outcome"] == "inferred_finding"
    assert unknown["sc.internal.list_items_get"]["evidence_state"] == "unknown"
    assert unknown["sc.internal.admin_users_get"]["evidence_state"] == "inferred"

    declared = json.loads(assess_scenarios_json(SOURCE, json.dumps([
        {"surface": "listitems", "field": "tenant_filter", "value": "enforced"}]), _selection(listing, probe)))
    assert _by_id(declared)["sc.internal.list_items_get"]["evidence_state"] == "customer_declared"
    assert declared["answers_hash"] != json.loads(first)["answers_hash"]
    assert declared["model_hash"] != json.loads(first)["model_hash"]


def test_absent_inputs_stay_unknown_where_the_legacy_boolean_evaluator_fires(listing):
    entries = [
        _custom("sc.internal.missing_guard", {"guard_absent": False}),
        _custom("sc.internal.guard_absent_true", {"guard_absent": True}),
        _custom("sc.internal.not_prop_exists", {"not": {"prop_exists": "rate_limit"}}),
        _custom("sc.internal.missing_equals_null", {"prop": "rate_limit", "equals": None}),
        _custom("sc.internal.exists_false", {"prop": "rate_limit", "exists": False}),
        _custom("sc.internal.agent_only", {"prop": "method", "equals": "GET"},
                applies_when="has_agent_surface"),
    ]
    envelope = _assess(listing, entries)
    rows = _by_id(envelope)
    # The legacy evaluator fires on absence for these (boolean); the browser path never does.
    for scenario_id in ("sc.internal.missing_guard", "sc.internal.guard_absent_true",
                        "sc.internal.not_prop_exists", "sc.internal.missing_equals_null",
                        "sc.internal.exists_false"):
        assert rows[scenario_id]["outcome"] == "criterion_unknown", scenario_id
        assert rows[scenario_id]["applicability"] == "matched_surface"
        assert rows[scenario_id]["evidence_state"] == "unknown"
    assert rows["sc.internal.agent_only"]["outcome"] == "no_matching_surface"
    assert envelope["model_coverage"]["agent_surface"] == "unknown"

    # Prove the legacy evaluator really is positive on the same absent inputs.
    target = target_from_product_model(_openapi_model())
    endpoint = next(item for item in target.affordances if item.properties.get("operation_id") == "listitems")
    assert evaluate_criterion({"guard_absent": False}, endpoint) is True
    assert evaluate_criterion({"not": {"prop_exists": "rate_limit"}}, endpoint) is True
    assert evaluate_criterion({"prop": "rate_limit", "equals": None}, endpoint) is True
    assert evaluate_criterion({"prop": "rate_limit", "exists": False}, endpoint) is True


def test_undeclared_business_rule_is_never_a_finding(listing):
    rows = {row["id"]: row for row in listing["scenarios"]}
    qualified = [_entry(rows[name]) for name in (
        "sc.endpoint.hidden", "sc.research.unintended_endpoints.forced_browsing_admin")]
    for entry in qualified:
        assert entry["definition"]["success_criterion"]["all_of"][0] == {
            "prop": "business_rule_applicable", "equals": True}
    results = _by_id(_assess(listing, qualified))
    for row in results.values():
        assert row["outcome"] in {"investigation_prompt", "criterion_unknown", "no_matching_surface"}
        assert row["outcome"] != "inferred_finding"
        assert row["rule_source"] == "unknown" or row["surface"] is None
    assert results["sc.research.unintended_endpoints.forced_browsing_admin"]["outcome"] == "investigation_prompt"


def test_selection_is_exact_and_attribution_survives_legacy_dedup(listing):
    rows = {row["id"]: row for row in listing["scenarios"]}
    first = _custom("sc.internal.get_route_a", {"prop": "method", "equals": "GET"})
    second = _custom("sc.internal.get_route_b", {"prop_contains": ["route", "/"]})
    chosen = [first, _entry(rows["sc.flag.tiergate"]), second]
    envelope = _assess(listing, chosen)
    assert [row["scenario_id"] for row in envelope["results"]] == [
        "sc.internal.get_route_a", "sc.flag.tiergate", "sc.internal.get_route_b"]
    assert not any(row["scenario_id"].startswith("sc.discovered.") for row in envelope["results"])
    assert envelope["custom"] == [
        {"scenario_id": first["scenario_id"], "revision": 1, "definition_digest": first["definition_digest"]},
        {"scenario_id": second["scenario_id"], "revision": 1, "definition_digest": second["definition_digest"]},
    ]
    by_id = _by_id(envelope)
    # Both custom criteria hit the same surfaces; each keeps its own attribution.
    assert by_id["sc.internal.get_route_a"]["outcome"] == "inferred_finding"
    assert by_id["sc.internal.get_route_b"]["outcome"] == "inferred_finding"
    shared = {json.dumps(m["surface"], sort_keys=True) for m in by_id["sc.internal.get_route_a"]["matches"]} & {
        json.dumps(m["surface"], sort_keys=True) for m in by_id["sc.internal.get_route_b"]["matches"]}
    assert shared
    # The legacy run deduplicates per surface and keeps only one scenario there.
    legacy_scenarios = [
        AbuseScenario(id=item["scenario_id"], category=Category.UNINTENDED_ENDPOINTS, objective="x",
                      target_affordance_pattern={"kind": "endpoint"}, probe_strategy="x",
                      success_criterion=item["definition"]["success_criterion"],
                      severity_model={"likelihood": 0.5, "impact": 0.5}, mechanism_id=item["scenario_id"])
        for item in (first, second)
    ]

    class _NoDiscovery:
        name = "test-no-discovery"

        def discover(self, *_args):
            return [], []

    legacy = run_adversarial(target_from_product_model(_openapi_model()), legacy_scenarios,
                             lambda *_: None, "t", model=_NoDiscovery())
    # One legacy finding per surface; here both scenarios keep every surface they matched.
    ours = by_id["sc.internal.get_route_a"]["match_count"] + by_id["sc.internal.get_route_b"]["match_count"]
    legacy_surfaces = {(f.reproduction["observed"] and f.affordance_id) for f in legacy["findings"]}
    assert len(legacy["findings"]) == len(legacy_surfaces) < ours


def test_custom_criterion_participates_and_no_raw_input_is_echoed(listing):
    marker = "listadminusers"
    custom = _custom("sc.community.admin_listing", {"prop": "operation_id", "equals": marker})
    answers = json.dumps([{"surface": "getitem", "field": "entitlement_check", "value": "unknown"}])
    rendered = assess_scenarios_json(SOURCE, answers, _selection(listing, [custom]))
    row = json.loads(rendered)["results"][0]
    assert row["outcome"] == "inferred_finding" and row["source"] == "custom"
    assert row["definition_digest"] == custom["definition_digest"]
    spec = json.loads(SOURCE)
    for text in (spec["info"]["title"], "entitlement_check", "getitem"):
        assert text not in rendered
    assert SOURCE not in rendered


def test_assess_rejects_invalid_custom_and_prohibited_content(listing):
    good = _custom("sc.internal.ok", {"prop": "method", "equals": "GET"})
    tampered = dict(good, definition={**good["definition"], "objective": "changed"})
    unknown_operator = _custom("sc.internal.bad_operator", {"eval": "anything"})
    too_deep = {"prop": "method", "equals": "GET"}
    for _ in range(10):
        too_deep = {"not": too_deep}
    deep = _custom("sc.internal.too_deep", too_deep)
    bad_handoff = _custom("sc.internal.bad_handoff", {"prop": "method", "equals": "GET"}, handoff="exec")
    cases = [
        ([tampered], "definition_digest_mismatch"),
        ([unknown_operator], "invalid_custom_scenario"),
        ([deep], "invalid_custom_scenario"),
        ([bad_handoff], "invalid_custom_scenario"),
        ([good, good], "invalid_selection"),
        ([dict(good, revision=None)], "invalid_selection"),
        ([], "invalid_selection"),
    ]
    for entries, code in cases:
        with pytest.raises(BrowserReviewError) as raised:
            assess_scenarios_json(SOURCE, "[]", _selection(listing, entries))
        assert raised.value.code == code, entries
    with pytest.raises(BrowserReviewError) as raised:
        assess_scenarios_json(SOURCE, "[]", "x" * (512 * 1024 + 1))
    assert raised.value.code == "invalid_selection"
    with pytest.raises(BrowserReviewError) as raised:
        assess_scenarios_json(SOURCE, "[{\"surface\":1}]", _selection(listing, [good]))
    assert raised.value.code == "invalid_answers"
    with pytest.raises(BrowserReviewError) as raised:
        assess_scenarios_json("{", "[]", _selection(listing, [good]))
    assert raised.value.code == "invalid_json"


def _openapi_model():
    from heel.openapi_model import product_model_from_openapi
    return product_model_from_openapi(json.loads(SOURCE))


@pytest.mark.parametrize("model_factory", [_openapi_model, lambda: RICH_MODEL])
def test_browser_affordances_and_definite_results_equal_the_legacy_engine(listing, model_factory):
    model = model_factory()
    legacy = _affordances(product_model_from_dict(model))
    ported = affordances_from_model(model)
    assert [(a.id, a.kind, a.properties) for a in legacy] == [
        (b["id"], b["kind"], b["properties"]) for b in ported]
    definite = 0
    for definition in (row["definition"] for row in listing["scenarios"]):
        for criterion in (definition["success_criterion"], definition["investigation_signals"]):
            if not criterion:
                continue
            for old, new in zip(legacy, ported):
                view = Affordance(id=new["id"], kind=new["kind"], category=Category.UNINTENDED_ENDPOINTS,
                                  properties=new["properties"], guard_present=new["guard"] is not False,
                                  reachability=0.5)
                result = evaluate_criterion3(criterion, new, view)
                if new["guard"] is not None:
                    assert new["guard"] == old.guard_present
                if result is not None:
                    definite += 1
                    assert result == evaluate_criterion(criterion, old), (definition["id"], old.id)
    assert definite > 20


def test_agent_surface_is_evaluated_only_when_the_model_declares_one(listing):
    spec = json.loads(SOURCE)
    spec["paths"]["/agent/tools/run"] = {"post": {
        "operationId": "runAgentTool", "summary": "Run an agent tool",
        "responses": {"200": {"description": "ok"}}}}
    entry = _custom("sc.internal.agent_tool_post", {"prop": "method", "equals": "POST"},
                    kind="agent_tool", applies_when="has_agent_surface")
    declared = json.loads(assess_scenarios_json(json.dumps(spec), "[]", _selection(listing, [entry])))
    assert declared["model_coverage"]["agent_surface"] == "declared"
    assert declared["results"][0]["outcome"] == "inferred_finding"
    assert declared["results"][0]["surface"] == {"method": "POST", "route": "/agent/tools/run"}
    undeclared = _assess(listing, [entry])
    assert undeclared["results"][0]["outcome"] == "no_matching_surface"
    assert undeclared["results"][0]["note"] == NOTE_NO_SURFACE
