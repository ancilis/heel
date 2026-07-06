"""
Offline control simulator.

The simulator estimates which product controls would block or reduce a contained
abuse finding. It is intentionally report-layer only: it never touches a live
target, never authorizes a target, and never creates or mutates scopes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from .contracts import Category


CONTROL_SIMULATOR_VERSION = "control-simulator.v1"
EVIDENCE_LEVEL = "proposed_offline_estimate_not_verified_control"


@dataclass(frozen=True)
class ControlSpec:
    control: str
    estimated_exploitability_reduction: float
    estimated_friction_cost: float
    preserves_legitimate_customer_path: bool
    default_blocks: str
    regression_default: bool = True


DEFAULT_CONTROL_BANK: dict[str, ControlSpec] = {
    "entitlement_check": ControlSpec(
        "entitlement_check", 0.86, 0.16, True, "the entitlement decision before protected capability use"
    ),
    "per_tenant_rate_limit": ControlSpec(
        "per_tenant_rate_limit", 0.65, 0.12, True, "repeat attempts by the same tenant or workspace"
    ),
    "quota": ControlSpec(
        "quota", 0.58, 0.20, True, "unbounded consumption beyond the intended product allowance"
    ),
    "proof_of_uniqueness": ControlSpec(
        "proof_of_uniqueness", 0.72, 0.38, False, "serial account or trial creation across weak identities"
    ),
    "session_concurrency_limit": ControlSpec(
        "session_concurrency_limit", 0.58, 0.22, True, "parallel session sharing or excessive concurrent use"
    ),
    "payment_verification": ControlSpec(
        "payment_verification", 0.64, 0.45, False, "free or low-trust conversion into higher-cost abuse"
    ),
    "audit_event": ControlSpec(
        "audit_event", 0.38, 0.05, True, "undetected abuse continuation and missing operator visibility"
    ),
    "tenant_filter": ControlSpec(
        "tenant_filter", 0.90, 0.14, True, "cross-tenant object access before the data leaves storage"
    ),
    "oauth_scope_minimization": ControlSpec(
        "oauth_scope_minimization", 0.76, 0.18, True, "over-broad integration permissions at install and token use"
    ),
    "human_approval": ControlSpec(
        "human_approval", 0.62, 0.52, False, "high-impact or irreversible action execution"
    ),
    "agent_tool_scope_reduction": ControlSpec(
        "agent_tool_scope_reduction", 0.88, 0.14, True, "agent tool authority beyond caller intent or tenant"
    ),
    "per_action_authorization": ControlSpec(
        "per_action_authorization", 0.80, 0.26, True, "each privileged tool action before execution"
    ),
    "cost_ceiling": ControlSpec(
        "cost_ceiling", 0.78, 0.10, True, "cost amplification before spend exceeds an operator-approved ceiling"
    ),
    "step_bound": ControlSpec(
        "step_bound", 0.82, 0.16, True, "unbounded multi-step agent or workflow loops"
    ),
    "webhook_signature/replay_protection": ControlSpec(
        "webhook_signature/replay_protection", 0.82, 0.20, True, "forged or replayed webhook delivery"
    ),
}


_CATEGORY_FALLBACKS: dict[str, list[str]] = {
    Category.LICENSE_ENTITLEMENT.value: ["entitlement_check", "quota", "per_tenant_rate_limit"],
    Category.DATA_HARVESTING.value: ["entitlement_check", "per_tenant_rate_limit", "audit_event"],
    Category.UNINTENDED_ENDPOINTS.value: ["entitlement_check", "audit_event"],
    Category.FUNCTION_ABUSE.value: ["quota", "cost_ceiling", "audit_event"],
    Category.CONTENT_POLICY.value: ["human_approval", "audit_event"],
    Category.IDENTITY_ACCOUNT.value: ["proof_of_uniqueness", "per_tenant_rate_limit", "session_concurrency_limit"],
    Category.TRUST_ECONOMY.value: ["proof_of_uniqueness", "per_tenant_rate_limit", "audit_event"],
    Category.INTEGRATION_EXTENSIBILITY.value: [
        "oauth_scope_minimization",
        "webhook_signature/replay_protection",
        "audit_event",
    ],
    Category.COMPLIANCE_BOUNDARY.value: ["tenant_filter", "audit_event", "entitlement_check"],
    Category.AGENT_MCP_SURFACE.value: ["agent_tool_scope_reduction", "per_action_authorization", "audit_event"],
}


def simulate_finding(
    finding: Mapping[str, Any] | Any,
    *,
    affordance_properties: Mapping[str, Any] | None = None,
    scenario_category: str | Category | None = None,
    product_model: Mapping[str, Any] | Any | None = None,
    entitlement_graph: Any | None = None,
    control_bank: Mapping[str, Any] | None = None,
) -> dict:
    """Estimate candidate controls for one finding without touching a live target."""
    f = _as_mapping(finding)
    category = _category_value(scenario_category or f.get("category"))
    props = _extract_properties(f, affordance_properties)
    graph_signals = _entitlement_signals(f, product_model=product_model, entitlement_graph=entitlement_graph)
    for signal in graph_signals:
        props.setdefault("entitlement_signal", signal)

    bank = _merge_control_bank(control_bank)
    builder = _CandidateBuilder(bank, f, category, props, graph_signals)
    builder.add_matches()
    candidates = builder.ranked()
    if not candidates:
        builder.add_category_fallbacks()
        candidates = builder.ranked()

    return {
        "version": CONTROL_SIMULATOR_VERSION,
        "evidence_level": EVIDENCE_LEVEL,
        "verified": False,
        "input": {
            "vector_id": str(f.get("id") or f.get("vector_id") or ""),
            "scenario_id": str(f.get("scenario_id") or ""),
            "category": category,
            "affordance_id": str(f.get("affordance_id") or ""),
        },
        "candidates": candidates,
        "recommended_bundle": _recommended_bundle(candidates),
        "limitations": [
            "Proposed controls are offline estimates, not verified controls.",
            "Verification requires an operator-owned regression or launch-review follow-up inside a human-created scope.",
            "Confidence is capped below certainty because no live target is touched.",
        ],
    }


def simulate_run(findings: list[Mapping[str, Any]], *, run_id: str | None = None,
                 control_bank: Mapping[str, Any] | None = None) -> dict:
    simulations = [simulate_finding(f, control_bank=control_bank) for f in findings]
    return {
        "version": CONTROL_SIMULATOR_VERSION,
        "evidence_level": EVIDENCE_LEVEL,
        "verified": False,
        "run_id": run_id,
        "simulations": simulations,
        "recommended_bundle": _aggregate_bundle(simulations),
        "limitations": [
            "Run-level bundles aggregate proposed controls across stored findings only.",
            "No live target is contacted and no authorization scope is created or changed.",
        ],
    }


def load_finding_json(path: str) -> tuple[dict, dict]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("finding JSON must be an object")
    if "finding" in data and isinstance(data["finding"], dict):
        options = {k: data.get(k) for k in ("affordance_properties", "product_model", "control_bank")}
        return data["finding"], {k: v for k, v in options.items() if v is not None}
    return data, {}


class _CandidateBuilder:
    def __init__(self, bank, finding, category, properties, graph_signals):
        self.bank = bank
        self.finding = finding
        self.category = category
        self.properties = properties
        self.graph_signals = set(graph_signals)
        self._candidates: dict[str, dict] = {}

    def add_matches(self) -> None:
        scenario = str(self.finding.get("scenario_id") or "").lower()
        affordance = str(self.finding.get("affordance_id") or "").lower()
        blob = _evidence_blob(self.finding, self.properties)

        if _has_any(blob, "export", "bulk") or "export_without_entitlement" in self.graph_signals:
            self.add("entitlement_check", "the authorization point before bulk export", 0.78,
                     ["export/bulk data path evidence"])
            self.add("per_tenant_rate_limit", "repeat export attempts before large-scale collection", 0.72,
                     ["bulk export path benefits from tenant-scoped throttling"])
            self.add("audit_event", "post-control monitoring for export attempts and overrides", 0.68,
                     ["operator visibility is needed for bulk data movement"])

        if (
            "trial" in scenario or "trial" in affordance or "sybil" in scenario
            or _prop_equals(self.properties, "identity_check", "email_only")
            or _prop_equals(self.properties, "verification", "none")
        ):
            self.add("proof_of_uniqueness", "serial signup or trial identity reuse", 0.78,
                     ["trial/account creation evidence"])
            self.add("payment_verification", "higher-cost trial conversion before resource use", 0.66,
                     ["trial farming often needs a payment or billing trust step"])

        if (
            "overscope" in scenario
            or "agent_tool_overscope" in self.graph_signals
            or _mismatch(self.properties, "granted_scope", "intended_scope")
        ):
            self.add("agent_tool_scope_reduction", "tool authority before the agent receives it", 0.82,
                     ["agent granted scope exceeds intended scope"])
            self.add("per_action_authorization", "each privileged agent tool call before execution", 0.76,
                     ["agent action should be re-authorized at use time"])
            if "all_tenants" in blob or "global" in blob:
                self.add("tenant_filter", "cross-tenant agent action or data access", 0.74,
                         ["agent scope evidence crosses tenant boundary"])

        if (
            "cost" in scenario or "cost" in affordance or "amplification" in blob
            or _prop_equals(self.properties, "multi_step", "unbounded")
            or "unmetered_billable_resource" in self.graph_signals
        ):
            self.add("step_bound", "unbounded multi-step loop before repeated execution", 0.80,
                     ["unbounded step evidence"])
            self.add("cost_ceiling", "spend before it exceeds an approved ceiling", 0.78,
                     ["cost amplification evidence"])
            self.add("quota", "aggregate resource consumption beyond intended allowance", 0.64,
                     ["consumption needs bounded allowance"])

        if (
            "tenant_filter_missing" in self.graph_signals
            or _prop_bad(self.properties, "tenant_filter")
            or _prop_bad(self.properties, "tenant_check")
            or "cross_tenant" in blob
        ):
            self.add("tenant_filter", "object selection before cross-tenant data access", 0.82,
                     ["tenant isolation evidence"])
            self.add("audit_event", "tenant-boundary access visibility", 0.70,
                     ["cross-tenant attempts should be observable"])

        if "oauth" in scenario or _prop_equals(self.properties, "scope", "all") or "oauth_overreach" in self.graph_signals:
            self.add("oauth_scope_minimization", "integration grant before token issuance and use", 0.78,
                     ["OAuth scope is broader than needed"])
            self.add("human_approval", "high-impact integration install before activation", 0.62,
                     ["over-broad integration grants may need review"])
            self.add("audit_event", "integration install and token-use visibility", 0.66,
                     ["integration permission changes should be logged"])

        if "webhook" in scenario or "webhook" in affordance or _prop_bad(self.properties, "replay_protection"):
            self.add("webhook_signature/replay_protection", "webhook authenticity and freshness checks", 0.80,
                     ["webhook replay or signature evidence"])
            self.add("audit_event", "webhook delivery and rejection visibility", 0.66,
                     ["operators need replay/failure evidence"])
            self.add("per_tenant_rate_limit", "replayed deliveries before high-volume side effects", 0.64,
                     ["webhook replay benefits from tenant-scoped throttling"])

        if _prop_equals(self.properties, "audit_logged", False) or "missing_audit_event" in self.graph_signals:
            self.add("audit_event", "operator visibility for the sensitive action", 0.78,
                     ["missing audit event evidence"])

        if "session" in scenario or "seat" in affordance or _prop_bad(self.properties, "sharing_detection"):
            self.add("session_concurrency_limit", "concurrent session or seat sharing", 0.70,
                     ["session or sharing evidence"])
            self.add("audit_event", "visibility into repeated account sharing signals", 0.62,
                     ["sharing controls need observability"])

        if not self._candidates and str(self.finding.get("recommended_control") or "").strip():
            self.add_category_fallbacks()

    def add_category_fallbacks(self) -> None:
        for control in _CATEGORY_FALLBACKS.get(self.category, ["audit_event"]):
            self.add(control, self.bank[control].default_blocks, 0.55, ["category-level fallback only"])

    def add(self, control: str, blocks: str, confidence: float, evidence: list[str]) -> None:
        if control not in self.bank:
            return
        spec = self.bank[control]
        existing = self._candidates.get(control)
        if existing:
            existing["confidence"] = round(min(0.90, max(existing["confidence"], confidence)), 2)
            existing["evidence"] = sorted(set(existing["evidence"] + evidence))
            if len(blocks) > len(existing["blocks"]):
                existing["blocks"] = blocks
            return
        self._candidates[control] = {
            "control": control,
            "candidate_control": control,
            "estimated_exploitability_reduction": spec.estimated_exploitability_reduction,
            "estimated_friction_cost": spec.estimated_friction_cost,
            "confidence": round(min(0.90, confidence), 2),
            "blocks": blocks or spec.default_blocks,
            "should_become_regression": bool(spec.regression_default),
            "preserves_legitimate_customer_path": bool(spec.preserves_legitimate_customer_path),
            "verified": False,
            "evidence": list(evidence),
        }

    def ranked(self) -> list[dict]:
        return sorted(self._candidates.values(), key=_rank_key)


def _rank_key(candidate: Mapping[str, Any]):
    return (
        -float(candidate.get("estimated_exploitability_reduction") or 0.0),
        float(candidate.get("estimated_friction_cost") or 1.0),
        not bool(candidate.get("preserves_legitimate_customer_path")),
        -float(candidate.get("confidence") or 0.0),
        str(candidate.get("control") or ""),
    )


def _recommended_bundle(candidates: list[dict], size: int = 3) -> list[dict]:
    return [dict(c) for c in candidates[:size]]


def _aggregate_bundle(simulations: list[dict], size: int = 5) -> list[dict]:
    merged: dict[str, dict] = {}
    for sim in simulations:
        vector_id = sim.get("input", {}).get("vector_id")
        for cand in sim.get("recommended_bundle", []):
            control = cand["control"]
            row = merged.setdefault(control, dict(cand, vector_ids=[], blocks_paths=[]))
            row["estimated_exploitability_reduction"] = max(
                row["estimated_exploitability_reduction"], cand["estimated_exploitability_reduction"]
            )
            row["estimated_friction_cost"] = min(row["estimated_friction_cost"], cand["estimated_friction_cost"])
            row["confidence"] = max(row["confidence"], cand["confidence"])
            if vector_id:
                row["vector_ids"].append(vector_id)
            row["blocks_paths"].append(cand["blocks"])
    for row in merged.values():
        row["vector_ids"] = sorted(set(row["vector_ids"]))
        row["blocks_paths"] = sorted(set(row["blocks_paths"]))
    return sorted(merged.values(), key=_rank_key)[:size]


def _merge_control_bank(control_bank: Mapping[str, Any] | None) -> dict[str, ControlSpec]:
    bank = dict(DEFAULT_CONTROL_BANK)
    for key, value in (control_bank or {}).items():
        if isinstance(value, ControlSpec):
            bank[key] = value
        elif isinstance(value, Mapping):
            base = bank.get(key)
            bank[key] = ControlSpec(
                control=str(value.get("control") or key),
                estimated_exploitability_reduction=float(
                    value.get("estimated_exploitability_reduction", base.estimated_exploitability_reduction if base else 0.5)
                ),
                estimated_friction_cost=float(value.get("estimated_friction_cost", base.estimated_friction_cost if base else 0.3)),
                preserves_legitimate_customer_path=bool(
                    value.get("preserves_legitimate_customer_path", base.preserves_legitimate_customer_path if base else True)
                ),
                default_blocks=str(value.get("blocks") or value.get("default_blocks") or (base.default_blocks if base else "the abuse path")),
                regression_default=bool(value.get("should_become_regression", value.get("regression_default", True))),
            )
    return bank


def _as_mapping(value: Mapping[str, Any] | Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if hasattr(value, "__dict__"):
        return value.__dict__
    return {}


def _category_value(value: str | Category | None) -> str:
    if isinstance(value, Category):
        return value.value
    if value is None:
        return ""
    return str(value)


def _extract_properties(finding: Mapping[str, Any], explicit: Mapping[str, Any] | None) -> dict:
    props: dict[str, Any] = {}
    for source in (finding.get("affordance_properties"), explicit):
        if isinstance(source, Mapping):
            props.update(source)
    repro = finding.get("reproduction")
    if isinstance(repro, Mapping):
        observed = repro.get("observed")
        if isinstance(observed, Mapping):
            aff_props = observed.get("affordance_properties")
            if isinstance(aff_props, Mapping):
                props.update(aff_props)
            else:
                for k, v in observed.items():
                    if k not in {"criterion", "obs"} and not isinstance(v, (list, dict)):
                        props.setdefault(k, v)
    return props


def _entitlement_signals(finding, *, product_model=None, entitlement_graph=None) -> list[str]:
    graph = entitlement_graph
    if graph is None and product_model is not None:
        try:
            from .entitlements import EntitlementGraph
            graph = EntitlementGraph.from_product_model(product_model)
        except Exception:
            graph = None
    if graph is None or not hasattr(graph, "edges"):
        return []
    aff_id = str(finding.get("affordance_id") or "")
    out = []
    for edge in getattr(graph, "edges", []):
        source_id = str(getattr(edge, "source_id", ""))
        signal = str(getattr(edge, "signal", ""))
        if signal and source_id and (source_id in aff_id or aff_id.endswith(source_id)):
            out.append(signal)
    return sorted(set(out))


def _evidence_blob(finding: Mapping[str, Any], props: Mapping[str, Any]) -> str:
    parts = [
        str(finding.get("id") or ""),
        str(finding.get("scenario_id") or ""),
        str(finding.get("category") or ""),
        str(finding.get("affordance_id") or ""),
        json.dumps(props, sort_keys=True, default=str),
    ]
    return " ".join(parts).lower()


def _has_any(blob: str, *needles: str) -> bool:
    return any(n in blob for n in needles)


def _prop_equals(props: Mapping[str, Any], key: str, value: Any) -> bool:
    actual = props.get(key)
    if isinstance(value, bool):
        return actual is value
    return str(actual).strip().lower() == str(value).strip().lower()


def _prop_bad(props: Mapping[str, Any], key: str) -> bool:
    if key not in props:
        return False
    value = props.get(key)
    return value is False or str(value).strip().lower() in {"missing", "none", "false", "disabled", "off", "no", "weak"}


def _mismatch(props: Mapping[str, Any], left: str, right: str) -> bool:
    return left in props and right in props and props.get(left) != props.get(right)
