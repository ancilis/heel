"""Browser-local static scenario assessment over a customer's own OpenAPI-derived model.

This module runs inside the reviewed browser engine closure. It performs no I/O, no network
access, no model discovery and no execution: it evaluates explicitly selected library and
validated custom scenario definitions against the affordances of the product model that
``product_model_from_openapi`` derives from the customer's document (after any customer review
answers), and returns a canonical ``heel.scenario-assessment.v1`` envelope.

Evaluation mirrors ``heel.agents.evaluate_criterion`` and ``heel.importers`` affordance
derivation (the legacy engine cannot enter the reviewed closure: it imports the network-capable
model module and dynamic helpers), with one deliberate difference: it is three-valued. A
criterion that depends on a property ABSENT from the supplied model is ``unknown``; absence is
never turned into a finding (``not prop_exists``, ``equals null``, a defaulted guard, an
unmatched semantic family, or an undeclared agent surface all stay unknown). Wherever this
evaluator is definite it agrees with the legacy evaluator; tests prove that equivalence.

Every result is static and inferred. Nothing here is evidence that a check ran against the
product, and ``no_matching_surface`` is never evidence of absence.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .browser_review import BrowserReviewError, review_openapi_json
from .contracts import Affordance, Category
from .openapi_model import OpenAPIImportError, product_model_from_openapi
from .review_answers import ReviewAnswerError, apply_review_answers, parse_review_answers
from .review_contract import ENGINE_VERSION, stable_json, stable_json_hash
from .semantic import semantic_specificity


ASSESSMENT_SCHEMA = "heel.scenario-assessment.v1"
SELECTION_SCHEMA = "heel.scenario-assessment-selection.v1"
MAX_SELECTION_BYTES = 512 * 1024
MAX_SELECTED_SCENARIOS = 160
MAX_CRITERION_DEPTH = 8
MAX_CRITERION_NODES = 128
MAX_MATCHES_PER_SCENARIO = 16
MAX_ASSESSMENT_BYTES = 4 * 1024 * 1024
HEX_DIGITS = "0123456789abcdef"

NOTE_NO_SURFACE = "no matching surface in the supplied model; not evidence of absence"
NOTE_UNKNOWN = (
    "the criterion depends on properties absent from the supplied model; unknown, not a negative result"
)
NOTE_NOT_MET = (
    "the supplied properties do not meet the criterion; static only, not evidence the product is safe"
)
NOTE_FINDING = "inferred from the supplied model only; nothing was executed against the product"
NOTE_INVESTIGATION = "investigation prompt: confirm the intended product rule; nothing was executed"
NOTE_HANDOFF = "pure model-jailbreak surface handed off to model red-team; not a Heel finding"

OUTCOME_RANK = {
    "inferred_finding": 6,
    "handoff": 5,
    "investigation_prompt": 4,
    "criterion_unknown": 3,
    "criterion_not_met": 2,
    "no_matching_surface": 1,
}
OUTCOME_NOTES = {
    "inferred_finding": NOTE_FINDING,
    "handoff": NOTE_HANDOFF,
    "investigation_prompt": NOTE_INVESTIGATION,
    "criterion_unknown": NOTE_UNKNOWN,
    "criterion_not_met": NOTE_NOT_MET,
    "no_matching_surface": NOTE_NO_SURFACE,
}

# Mirrors heel.importers._FIELD_SPECS order, kinds and default categories.
FIELD_SPECS = (
    ("tenants", "tenant", "compliance_boundary"),
    ("roles", "role", "identity_account"),
    ("plans", "plan", "license_entitlement"),
    ("meters", "meter", "license_entitlement"),
    ("coupons_promotions", "promotion", "license_entitlement"),
    ("features_flags", "flag", "unintended_endpoints"),
    ("endpoints_routes", "endpoint", "unintended_endpoints"),
    ("exports", "export", "data_harvesting"),
    ("identity_auth_flows", "auth_flow", "identity_account"),
    ("billing_objects", "billing", "license_entitlement"),
    ("integration_oauth_apps", "oauth_app", "integration_extensibility"),
    ("webhooks", "integration", "integration_extensibility"),
    ("support_admin_actions", "admin_action", "compliance_boundary"),
    ("agent_tools", "agent_tool", "agent_mcp_surface"),
    ("mcp_connectors", "mcp_connector", "agent_mcp_surface"),
    ("data_classes", "data_class", "compliance_boundary"),
    ("audit_events", "audit_event", "compliance_boundary"),
)
ITEM_ID_KEYS = (
    "id", "name", "route", "path", "tool", "connector", "role", "plan", "event", "action",
)
BAD_CONTROL_VALUES = frozenset({
    "missing", "none", "false", "disabled", "off", "no", "weak", "client",
})
NON_EVIDENCE_CONTROL_VALUES = frozenset({"", "unknown"})
CONTROL_HINTS = (
    "check", "guard", "limit", "protection", "filter", "isolation", "allowlist",
    "audit", "verification", "entitlement", "authz",
)
CRITERION_OPERATORS = frozenset({
    "semantic", "guard_absent", "prop_exists", "prop", "equals", "in", "exists",
    "prop_contains", "prop_neq", "all_of", "any_of", "not",
})
APPLIES_WHEN = frozenset({"always", "has_agent_surface"})
HANDOFFS = frozenset({"", "appsec", "model_redteam"})
DEFINITION_TEXT_FIELDS = ("id", "kind", "recommended_control")


def _assessment_error(code: str) -> BrowserReviewError:
    messages = {
        "invalid_selection": "The scenario selection is invalid or unsupported.",
        "invalid_custom_scenario": "A custom scenario definition is not a supported validated criterion.",
        "definition_digest_mismatch": "A scenario definition does not match its recorded digest.",
        "invalid_answers": "The submitted review answers are invalid or unsupported.",
        "invalid_openapi": "The document is not a supported OpenAPI 3.0 or 3.1 document.",
        "assessment_failed": "The browser-local assessment could not be completed safely.",
        "result_too_large": "The assessment result exceeds the safe browser limit.",
    }
    return BrowserReviewError(code, messages[code])


def _is_digest(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(ch in HEX_DIGITS for ch in value)


def _safe_id(value: str) -> str:
    # Mirrors heel.importers._safe_id exactly.
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "_", value.strip())
    cleaned = cleaned.strip("_")
    return cleaned[:80] or "item"


def _item_id(item: Any, index: int) -> str:
    if isinstance(item, dict):
        for key in ITEM_ID_KEYS:
            if item.get(key):
                return _safe_id(str(item[key]))
    return str(index)


def _properties(item: Any, source_field: str) -> dict:
    if isinstance(item, dict):
        props = {str(key): value for key, value in item.items()}
    else:
        props = {"name": str(item)}
    props["source_field"] = source_field
    return props


def _kind_for(field_name: str, default_kind: str, props: dict) -> str:
    explicit = props.get("kind")
    if isinstance(explicit, str) and explicit:
        return explicit
    if field_name == "identity_auth_flows":
        text = " ".join(
            str(props.get(key, "")) for key in ("id", "name", "flow", "route", "description")
        ).lower()
        if "reset" in text or "recover" in text:
            return "auth_reset"
        if "signup" in text or "registration" in text:
            return "signup"
    return default_kind


def _guard_state(props: dict) -> Any:
    """Three-valued guard: True/False when the model says so, None when only defaulted."""
    if isinstance(props.get("guard_present"), bool):
        return bool(props["guard_present"])
    if props.get("guard_absent") is True:
        return False
    evidence = False
    for key, value in props.items():
        if any(hint in str(key).lower() for hint in CONTROL_HINTS):
            if value is False or (isinstance(value, str) and value.strip().lower() in BAD_CONTROL_VALUES):
                return False
            if value is not None and not (
                isinstance(value, str) and value.strip().lower() in NON_EVIDENCE_CONTROL_VALUES
            ):
                evidence = True
    return True if evidence else None


def affordances_from_model(model: dict) -> list[dict]:
    """Product-model field affordances exactly as heel.importers derives them (graph edges excluded)."""
    out = []
    for field_name, default_kind, category in FIELD_SPECS:
        items = model.get(field_name, [])
        if type(items) is not list:
            continue
        for index, item in enumerate(items):
            props = _properties(item, field_name)
            out.append({
                "id": "pm:" + _safe_id(field_name) + ":" + _item_id(item, index),
                "kind": _kind_for(field_name, default_kind, props),
                "category": category,
                "properties": props,
                "guard": _guard_state(props),
            })
    return out


def _all3(values: list) -> Any:
    if any(value is False for value in values):
        return False
    if any(value is None for value in values):
        return None
    return True


def _any3(values: list) -> Any:
    if any(value is True for value in values):
        return True
    if any(value is None for value in values):
        return None
    return False


def evaluate_criterion3(criterion: dict, affordance: dict, semantic_view: Any) -> Any:
    """Three-valued port of heel.agents.evaluate_criterion: True, False, or None (unknown)."""
    props = affordance["properties"]
    if "semantic" in criterion:
        return True if semantic_specificity(criterion["semantic"], semantic_view) > 0 else None
    if "guard_absent" in criterion:
        guard = affordance["guard"]
        if guard is None:
            return None
        return (not guard) == bool(criterion["guard_absent"])
    if "prop_exists" in criterion:
        return True if criterion["prop_exists"] in props else None
    if "prop" in criterion and "equals" in criterion:
        if criterion["prop"] not in props:
            return None
        return props[criterion["prop"]] == criterion["equals"]
    if "prop" in criterion and "in" in criterion:
        if criterion["prop"] not in props:
            return None
        return props[criterion["prop"]] in criterion["in"]
    if "prop" in criterion and "exists" in criterion:
        if criterion["prop"] not in props:
            return None
        return bool(criterion["exists"])
    if "prop_contains" in criterion:
        key, needle = criterion["prop_contains"]
        if key not in props or props[key] is None:
            return None
        return needle in str(props[key])
    if "prop_neq" in criterion:
        left, right = criterion["prop_neq"]
        if props.get(left) is None or props.get(right) is None:
            return None
        return props[left] != props[right]
    if "all_of" in criterion:
        return _all3([evaluate_criterion3(item, affordance, semantic_view) for item in criterion["all_of"]])
    if "any_of" in criterion:
        return _any3([evaluate_criterion3(item, affordance, semantic_view) for item in criterion["any_of"]])
    if "not" in criterion:
        inner = evaluate_criterion3(criterion["not"], affordance, semantic_view)
        return None if inner is None else not inner
    return None


def _criterion_supported(value: Any, depth: int, budget: list) -> bool:
    budget.append(1)
    if depth > MAX_CRITERION_DEPTH or len(budget) > MAX_CRITERION_NODES:
        return False
    if type(value) is not dict or not value or not all(key in CRITERION_OPERATORS for key in value):
        return False
    if "all_of" in value or "any_of" in value:
        key = "all_of" if "all_of" in value else "any_of"
        items = value[key]
        return (len(value) == 1 and type(items) is list and 0 < len(items) <= 32
                and all(_criterion_supported(item, depth + 1, budget) for item in items))
    if "not" in value:
        return len(value) == 1 and _criterion_supported(value["not"], depth + 1, budget)
    if "semantic" in value:
        return len(value) == 1 and type(value["semantic"]) is str and len(value["semantic"]) <= 128
    if "guard_absent" in value:
        return len(value) == 1 and type(value["guard_absent"]) is bool
    if "prop_exists" in value:
        return len(value) == 1 and type(value["prop_exists"]) is str
    if "prop_contains" in value or "prop_neq" in value:
        key = "prop_contains" if "prop_contains" in value else "prop_neq"
        pair = value[key]
        return (len(value) == 1 and type(pair) is list and len(pair) == 2
                and all(type(item) is str for item in pair))
    if "prop" in value:
        if type(value["prop"]) is not str or len(value) != 2:
            return False
        if "in" in value:
            return type(value["in"]) is list and len(value["in"]) <= 64
        if "exists" in value:
            return type(value["exists"]) is bool
        return "equals" in value
    return False


def _parse_selection(selection_json: str) -> dict:
    if type(selection_json) is not str or len(selection_json.encode("utf-8")) > MAX_SELECTION_BYTES:
        raise _assessment_error("invalid_selection")
    try:
        selection = json.loads(selection_json)
    except (ValueError, RecursionError):
        raise _assessment_error("invalid_selection") from None
    if (type(selection) is not dict
            or sorted(selection) != ["library_digest", "scenarios", "schema_version"]
            or selection["schema_version"] != SELECTION_SCHEMA
            or not _is_digest(selection["library_digest"])
            or type(selection["scenarios"]) is not list
            or not 0 < len(selection["scenarios"]) <= MAX_SELECTED_SCENARIOS):
        raise _assessment_error("invalid_selection")
    seen = set()
    for entry in selection["scenarios"]:
        if (type(entry) is not dict
                or sorted(entry) != ["definition", "definition_digest", "revision", "scenario_id", "source"]
                or entry["source"] not in ("library", "custom")
                or type(entry["scenario_id"]) is not str
                or not 0 < len(entry["scenario_id"]) <= 128
                or entry["scenario_id"] in seen
                or not _is_digest(entry["definition_digest"])
                or type(entry["definition"]) is not dict):
            raise _assessment_error("invalid_selection")
        if entry["source"] == "library" and entry["revision"] is not None:
            raise _assessment_error("invalid_selection")
        if entry["source"] == "custom" and (
                type(entry["revision"]) is not int or entry["revision"] < 1):
            raise _assessment_error("invalid_selection")
        seen.add(entry["scenario_id"])
        if stable_json_hash(entry["definition"]) != entry["definition_digest"]:
            raise _assessment_error("definition_digest_mismatch")
        if not _definition_supported(entry["definition"], entry["scenario_id"]):
            raise _assessment_error(
                "invalid_custom_scenario" if entry["source"] == "custom" else "invalid_selection"
            )
    return selection


def _definition_supported(definition: dict, scenario_id: str) -> bool:
    if definition.get("id") != scenario_id:
        return False
    if not all(type(definition.get(name)) is str and definition.get(name) for name in DEFINITION_TEXT_FIELDS):
        return False
    if definition.get("applies_when", "always") not in APPLIES_WHEN:
        return False
    if definition.get("handoff", "") not in HANDOFFS:
        return False
    signals = definition.get("investigation_signals", {})
    if type(signals) is not dict:
        return False
    if signals and not _criterion_supported(signals, 1, []):
        return False
    return _criterion_supported(definition.get("success_criterion"), 1, [])


def _evidence_state(props: dict) -> str:
    declarations = props.get("customer_declarations")
    states = set()
    if type(declarations) is dict:
        for value in declarations.values():
            if type(value) is dict and type(value.get("evidence_state")) is str:
                states.add(value["evidence_state"])
    if props.get("control_evidence_state") == "customer_declared" or "customer_declared" in states:
        return "customer_declared"
    if "unknown" in states:
        return "unknown"
    return "inferred"


def _surface(affordance: dict) -> dict:
    props = affordance["properties"]
    if type(props.get("route")) is str and type(props.get("method")) is str:
        return {"method": props["method"], "route": props["route"][:512]}
    return {"source_field": props["source_field"], "item": affordance["id"][:160]}


def _assess_one(definition: dict, affordances: list, views: list, has_agent_surface: bool) -> dict:
    kind = definition["kind"]
    mechanism = definition.get("mechanism_id") or definition["id"]
    if definition.get("applies_when", "always") == "has_agent_surface" and not has_agent_surface:
        return {"outcome": "no_matching_surface", "matches": [], "match_count": 0}
    signals = definition.get("investigation_signals", {})
    matches = []
    for index, affordance in enumerate(affordances):
        if kind != "*" and affordance["kind"] != kind:
            continue
        props = affordance["properties"]
        if (props.get("bulk_access_permitted") is True and mechanism in {
                "export-read-entitlement", "automation-entitlement", "object-access"}) or (
                props.get("stacking_permitted") is True and "coupon" in definition["id"]):
            continue
        hit = evaluate_criterion3(definition["success_criterion"], affordance, views[index])
        investigate = evaluate_criterion3(signals, affordance, views[index]) if signals else False
        if hit is True:
            outcome = "handoff" if definition.get("handoff", "") == "model_redteam" else "inferred_finding"
        elif investigate is True:
            outcome = "investigation_prompt"
        elif hit is None:
            outcome = "criterion_unknown"
        else:
            outcome = "criterion_not_met"
        matches.append({
            "outcome": outcome,
            "surface": _surface(affordance),
            "evidence_state": "unknown" if outcome == "criterion_unknown" else _evidence_state(props),
            "rule_source": str(props.get("rule_source", "unknown"))[:160],
        })
    if not matches:
        return {"outcome": "no_matching_surface", "matches": [], "match_count": 0}
    ordered = sorted(matches, key=lambda item: -OUTCOME_RANK[item["outcome"]])
    return {"outcome": ordered[0]["outcome"], "matches": ordered[:MAX_MATCHES_PER_SCENARIO],
            "match_count": len(matches)}


def _result_row(entry: dict, assessed: dict) -> dict:
    definition = entry["definition"]
    outcome = assessed["outcome"]
    top = assessed["matches"][0] if assessed["matches"] else None
    return {
        "scenario_id": entry["scenario_id"],
        "source": entry["source"],
        "revision": entry["revision"],
        "definition_digest": entry["definition_digest"],
        "mechanism_id": definition.get("mechanism_id") or definition["id"],
        "outcome": outcome,
        "applicability": "unknown" if top is None else "matched_surface",
        "evidence_state": "unknown" if top is None else top["evidence_state"],
        "rule_source": "unknown" if top is None else top["rule_source"],
        "surface": None if top is None else top["surface"],
        "match_count": assessed["match_count"],
        "matches": assessed["matches"],
        "recommended_control": definition["recommended_control"][:500],
        "note": OUTCOME_NOTES[outcome],
    }


def assess_scenarios_json(source: str, answers_json: str = "[]", selection_json: str = "{}") -> str:
    """Return canonical ``heel.scenario-assessment.v1`` JSON without I/O or active execution."""
    review_json = review_openapi_json(source, "[]")
    selection = _parse_selection(selection_json)
    try:
        answers = parse_review_answers(answers_json)
    except ReviewAnswerError:
        raise _assessment_error("invalid_answers") from None
    try:
        spec = json.loads(source)
        if answers:
            questions = json.loads(review_json)["questions"]
            spec = apply_review_answers(spec, answers, questions)
        model = product_model_from_openapi(spec, source="openapi:browser")
    except ReviewAnswerError:
        raise _assessment_error("invalid_answers") from None
    except OpenAPIImportError:
        raise _assessment_error("invalid_openapi") from None
    except (RecursionError, UnicodeError, ValueError, TypeError, KeyError):
        raise _assessment_error("assessment_failed") from None
    affordances = affordances_from_model(model)
    views = [
        Affordance(id=item["id"], kind=item["kind"], category=Category(item["category"]),
                   properties=item["properties"], guard_present=item["guard"] is not False,
                   reachability=0.5)
        for item in affordances
    ]
    has_agent_surface = bool(model.get("agent_tools") or model.get("mcp_connectors"))
    results = [
        _result_row(entry, _assess_one(entry["definition"], affordances, views, has_agent_surface))
        for entry in selection["scenarios"]
    ]
    envelope = {
        "schema_version": ASSESSMENT_SCHEMA,
        "engine_version": ENGINE_VERSION,
        "source_hash": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "model_hash": stable_json_hash(model),
        "answers_hash": stable_json_hash(answers),
        "library_digest": selection["library_digest"],
        "selection_hash": stable_json_hash([
            [entry["scenario_id"], entry["source"], entry["revision"], entry["definition_digest"]]
            for entry in selection["scenarios"]
        ]),
        "custom": [
            {"scenario_id": entry["scenario_id"], "revision": entry["revision"],
             "definition_digest": entry["definition_digest"]}
            for entry in selection["scenarios"] if entry["source"] == "custom"
        ],
        "model_coverage": {
            "product_model_fields": "evaluated",
            "entitlement_graph_edges": "not_evaluated",
            "agent_surface": "declared" if has_agent_surface else "unknown",
        },
        "results": results,
        "privacy": {"execution": "browser_local", "network_calls": False, "uploaded": False},
    }
    rendered = stable_json(envelope)
    if len(rendered.encode("utf-8")) > MAX_ASSESSMENT_BYTES:
        raise _assessment_error("result_too_large")
    return rendered
