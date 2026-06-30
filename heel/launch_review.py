"""
Launch review mode.

This module compares two sanitized ProductModel documents and highlights newly
added or changed product surfaces that could introduce SaaS abuse paths. It is a
static model review: it performs no live probing, network calls, credential use,
or customer-data access.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import subprocess
from typing import Any, Mapping

from .importers import ProductModelError, load_product_model, validate_product_model


SURFACE_FIELDS = [
    "endpoints_routes",
    "exports",
    "meters",
    "billing_objects",
    "plans",
    "coupons_promotions",
    "features_flags",
    "integration_oauth_apps",
    "webhooks",
    "support_admin_actions",
    "agent_tools",
    "mcp_connectors",
    "tenants",
    "data_classes",
    "declared_controls",
]

_MISSING_VALUES = {"", "missing", "none", "false", "disabled", "off", "no", "weak", "client", "client_only"}
_LOW_REACH_PLANS = {"trial", "free", "starter", "basic"}
_HIGH_SCOPE_VALUES = {"all", "*", "admin", "full_access", "read_write_all", "global", "all_tenants"}
_SCOPE_RANK = {
    "own_tenant": 1,
    "tenant": 1,
    "workspace": 2,
    "org": 3,
    "global": 4,
    "all_tenants": 4,
    "all": 4,
}


@dataclass(frozen=True)
class ChangedSurface:
    surface_type: str
    surface_id: str
    change_type: str
    before: dict[str, Any] | None
    after: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        out = {
            "surface_type": self.surface_type,
            "surface_id": self.surface_id,
            "change_type": self.change_type,
            "after": self.after,
        }
        if self.before is not None:
            out["before"] = self.before
        return out


@dataclass(frozen=True)
class RiskFinding:
    surface_type: str
    surface_id: str
    risk: str
    severity: str
    control: str
    reason: str
    reachable: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "surface_type": self.surface_type,
            "surface_id": self.surface_id,
            "risk": self.risk,
            "severity": self.severity,
            "control": self.control,
            "reason": self.reason,
            "reachable": self.reachable,
        }


@dataclass(frozen=True)
class SuggestedRegression:
    surface_type: str
    surface_id: str
    name: str
    expected_status: str
    scenario_hint: str
    safety: str = "model-only, canary-contained; no live probing"

    def to_dict(self) -> dict[str, Any]:
        return {
            "surface_type": self.surface_type,
            "surface_id": self.surface_id,
            "name": self.name,
            "expected_status": self.expected_status,
            "scenario_hint": self.scenario_hint,
            "safety": self.safety,
        }


@dataclass(frozen=True)
class LaunchReview:
    product_id: str
    changed_surfaces: list[ChangedSurface] = field(default_factory=list)
    new_abuse_affordances: list[RiskFinding] = field(default_factory=list)
    high_risk_missing_controls: list[RiskFinding] = field(default_factory=list)
    recommended_controls: list[RiskFinding] = field(default_factory=list)
    suggested_regression_tests: list[SuggestedRegression] = field(default_factory=list)
    launch_gate_status: str = "pass"
    safety: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "product_id": self.product_id,
            "launch_gate_status": self.launch_gate_status,
            "changed_surfaces": [s.to_dict() for s in self.changed_surfaces],
            "new_abuse_affordances": [f.to_dict() for f in self.new_abuse_affordances],
            "high_risk_missing_controls": [f.to_dict() for f in self.high_risk_missing_controls],
            "recommended_controls": [f.to_dict() for f in self.recommended_controls],
            "suggested_regression_tests": [r.to_dict() for r in self.suggested_regression_tests],
            "safety": dict(self.safety),
        }


def review_product_models(before: Mapping[str, Any], after: Mapping[str, Any]) -> LaunchReview:
    """Compare two sanitized ProductModel dictionaries and produce a launch review."""
    _validate_or_raise(before, "before")
    _validate_or_raise(after, "after")
    changed = _changed_surfaces(before, after)
    risks = []
    for surface in changed:
        risks.extend(_risk_findings(surface))
    high = [r for r in risks if r.severity == "block"]
    gate = "block" if high else "warn" if risks else "pass"
    regressions = _suggested_regressions(risks)
    return LaunchReview(
        product_id=str(after.get("product_id") or before.get("product_id") or ""),
        changed_surfaces=changed,
        new_abuse_affordances=risks,
        high_risk_missing_controls=high,
        recommended_controls=risks,
        suggested_regression_tests=regressions,
        launch_gate_status=gate,
        safety={
            "mode": "static ProductModel diff",
            "live_probing": False,
            "network_calls": False,
            "requires_signed_scope_for_live_or_staging_runs": True,
            "canary_only": True,
        },
    )


def load_and_review(before_path: str, after_path: str) -> LaunchReview:
    return review_product_models(load_product_model(before_path), load_product_model(after_path))


def review_git_diff(rev_range: str) -> LaunchReview:
    """Review the first changed ProductModel JSON file in a git revision range."""
    base, head = _split_rev_range(rev_range)
    paths = _changed_json_paths(rev_range)
    errors: list[str] = []
    for path in paths:
        try:
            before = _git_json(base, path)
            after = _git_json(head, path)
        except ProductModelError as exc:
            errors.append(str(exc))
            continue
        if validate_product_model(before).ok and validate_product_model(after).ok:
            return review_product_models(before, after)
    detail = "; ".join(errors) if errors else "no changed ProductModel JSON files found"
    raise ProductModelError(f"cannot build launch review from git diff {rev_range}: {detail}")


def render_human_summary(review: LaunchReview) -> str:
    lines = [
        f"Launch gate: {review.launch_gate_status}",
        f"Product: {review.product_id}",
        f"Changed surfaces: {len(review.changed_surfaces)}",
        f"New abuse affordances: {len(review.new_abuse_affordances)}",
        f"High-risk missing controls: {len(review.high_risk_missing_controls)}",
    ]
    for finding in review.high_risk_missing_controls:
        lines.append(f"Blocker: {finding.reason}")
    if review.launch_gate_status == "warn":
        for finding in review.new_abuse_affordances:
            lines.append(f"Warning: {finding.reason}")
    return "\n".join(lines)


def review_to_json(review: LaunchReview) -> str:
    return json.dumps(review.to_dict(), indent=2, sort_keys=True)


def _validate_or_raise(model: Mapping[str, Any], label: str) -> None:
    result = validate_product_model(model)
    if not result.ok:
        raise ProductModelError(f"{label} ProductModel invalid: {'; '.join(result.errors)}")


def _changed_surfaces(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[ChangedSurface]:
    changed: list[ChangedSurface] = []
    for field_name in SURFACE_FIELDS:
        before_items = _items_by_id(before.get(field_name, []))
        after_items = _items_by_id(after.get(field_name, []))
        for sid in sorted(after_items):
            after_item = after_items[sid]
            before_item = before_items.get(sid)
            if before_item is None:
                changed.append(ChangedSurface(field_name, sid, "added", None, after_item))
            elif _stable_json(before_item) != _stable_json(after_item):
                changed.append(ChangedSurface(field_name, sid, "changed", before_item, after_item))
    return changed


def _risk_findings(surface: ChangedSurface) -> list[RiskFinding]:
    props = surface.after
    if surface.surface_type == "exports":
        return _export_risks(surface, props)
    if surface.surface_type == "endpoints_routes":
        return _endpoint_risks(surface, props)
    if surface.surface_type in {"meters", "billing_objects"}:
        return _meter_risks(surface, props)
    if surface.surface_type == "coupons_promotions":
        return _coupon_risks(surface, props)
    if surface.surface_type == "integration_oauth_apps":
        return _oauth_risks(surface, props)
    if surface.surface_type == "support_admin_actions":
        return _admin_action_risks(surface, props)
    if surface.surface_type in {"agent_tools", "mcp_connectors"}:
        return _agent_surface_risks(surface, props)
    if surface.surface_type == "features_flags":
        return _feature_flag_risks(surface, props)
    if surface.surface_type in {"tenants", "data_classes", "declared_controls"}:
        return _tenant_data_control_risks(surface, props)
    return []


def _export_risks(surface: ChangedSurface, props: Mapping[str, Any]) -> list[RiskFinding]:
    findings = []
    entitlement_missing = _bad_control(_first(props, "entitlement_check", "authz_check", "guard", "guard_present"))
    quota_missing = _bad_control(_first(props, "tenant_quota", "quota", "rate_limit", "export_limit"))
    if entitlement_missing:
        findings.append(_finding(
            surface,
            risk="export_without_entitlement",
            severity="block" if _reachable(props) else "warn",
            control="server-side entitlement check",
            reason=f"new {surface.surface_id} export reachable without server-side entitlement check",
            reachable=_reachable(props),
        ))
    if quota_missing:
        findings.append(_finding(
            surface,
            risk="export_without_tenant_quota",
            severity="block" if _reachable(props) else "warn",
            control="tenant quota",
            reason=f"new {surface.surface_id} export lacks tenant quota or rate limit",
            reachable=_reachable(props),
        ))
    return findings


def _endpoint_risks(surface: ChangedSurface, props: Mapping[str, Any]) -> list[RiskFinding]:
    text = _text(props, "id", "name", "route", "path")
    if "export" in text:
        return _export_risks(surface, props)
    tenant_missing = _bad_control(_first(props, "tenant_filter", "tenant_check", "tenant_isolation"))
    if not tenant_missing:
        return []
    return [_finding(
        surface,
        risk="endpoint_without_tenant_filter",
        severity="block" if _reachable(props) else "warn",
        control="tenant filter",
        reason=f"new {surface.surface_id} endpoint lacks server-side tenant filtering",
        reachable=_reachable(props),
    )]


def _meter_risks(surface: ChangedSurface, props: Mapping[str, Any]) -> list[RiskFinding]:
    if not _truthy(_first(props, "billable", "cost_bearing", "metered", "charges_money")):
        return []
    accounting_missing = _bad_control(_first(props, "server_side_accounting", "server_authoritative", "meter_accounting"))
    quota_missing = _bad_control(_first(props, "quota", "cost_ceiling", "spend_limit"))
    if not (accounting_missing or quota_missing):
        return []
    return [_finding(
        surface,
        risk="unmetered_billable_resource",
        severity="warn",
        control="server-side meter accounting and cost ceiling",
        reason=f"new {surface.surface_id} billable surface lacks server-side accounting or cost ceiling",
        reachable=_reachable(props),
    )]


def _coupon_risks(surface: ChangedSurface, props: Mapping[str, Any]) -> list[RiskFinding]:
    stackable = _truthy(props.get("stackable"))
    redemption_missing = _bad_control(_first(props, "redemption_limit", "max_redemptions", "per_account_limit", "proof_of_uniqueness"))
    if not (stackable and redemption_missing):
        return []
    discount = _number(_first(props, "discount_percent", "discount"))
    severe_discount = discount >= 90 or str(props.get("applies_to", "")).lower() in {"all_plans", "all"}
    severity = "block" if severe_discount and _reachable(props) else "warn"
    return [_finding(
        surface,
        risk="stackable_coupon_without_redemption_limit",
        severity=severity,
        control="redemption limit and proof of uniqueness",
        reason=f"new {surface.surface_id} stackable coupon lacks redemption limit",
        reachable=_reachable(props),
    )]


def _oauth_risks(surface: ChangedSurface, props: Mapping[str, Any]) -> list[RiskFinding]:
    scope_value = str(_first(props, "scope", "granted_scope", "oauth_scope") or "").strip().lower()
    granted = {s.lower() for s in _to_list(_first(props, "granted_scopes", "scopes"))}
    needed = {s.lower() for s in _to_list(_first(props, "needed_scopes", "required_scopes", "intended_scopes"))}
    scope_all = scope_value in _HIGH_SCOPE_VALUES
    excess = bool(granted and needed and not granted.issubset(needed))
    if not (scope_all or excess):
        return []
    auto = _truthy(_first(props, "auto_approved", "auto_install", "default_approved"))
    low_role = str(_first(props, "installable_by_role", "reachable_by_role", "role") or "").lower() in {"member", "user", "anyone", "anonymous"}
    severity = "block" if auto and low_role else "warn"
    return [_finding(
        surface,
        risk="oauth_scope_overbroad",
        severity=severity,
        control="OAuth scope minimization and approval",
        reason=f"new {surface.surface_id} OAuth app grants overbroad scope",
        reachable=_reachable(props) or auto or low_role,
    )]


def _admin_action_risks(surface: ChangedSurface, props: Mapping[str, Any]) -> list[RiskFinding]:
    required = str(_first(props, "required_role", "min_role", "intended_role") or "").lower()
    reachable = str(_first(props, "reachable_by_role", "granted_role", "observed_role") or "").lower()
    audit_missing = _bad_control(_first(props, "audit_logged", "audit_event", "audit_event_id"))
    if not required and not audit_missing:
        return []
    role_mismatch = reachable and reachable != required and reachable in {"member", "user", "support"}
    if not (role_mismatch or audit_missing):
        return []
    severity = "block" if role_mismatch and audit_missing else "warn"
    return [_finding(
        surface,
        risk="admin_action_without_role_or_audit_control",
        severity=severity,
        control="admin role gate and audit event",
        reason=f"new {surface.surface_id} support/admin action lacks role or audit controls",
        reachable=_reachable(props) or role_mismatch,
    )]


def _agent_surface_risks(surface: ChangedSurface, props: Mapping[str, Any]) -> list[RiskFinding]:
    granted = str(_first(props, "granted_scope", "effective_scope", "scope") or "").lower()
    intended = str(_first(props, "intended_scope", "required_scope", "declared_scope") or "").lower()
    if not granted or not intended or not _scope_wider(granted, intended):
        return []
    return [_finding(
        surface,
        risk="agent_surface_overscope",
        severity="block",
        control="tool scope minimization",
        reason=f"new {surface.surface_id} agent/MCP surface grants {granted} beyond intended {intended}",
        reachable=True,
    )]


def _feature_flag_risks(surface: ChangedSurface, props: Mapping[str, Any]) -> list[RiskFinding]:
    required = str(_first(props, "required_plan", "entitlement_plan", "min_plan") or "").lower()
    reachable = str(_first(props, "reachable_by_plan", "granted_plan", "current_plan") or "").lower()
    client_gate = str(_first(props, "gated_by", "guard") or "").lower() in {"client", "client_only"}
    if not (required and reachable and required != reachable) and not client_gate:
        return []
    return [_finding(
        surface,
        risk="feature_flag_plan_mismatch",
        severity="warn",
        control="server-side feature entitlement check",
        reason=f"new {surface.surface_id} feature flag may be reachable outside intended plan",
        reachable=_reachable(props),
    )]


def _tenant_data_control_risks(surface: ChangedSurface, props: Mapping[str, Any]) -> list[RiskFinding]:
    control_removed = surface.surface_type == "declared_controls" and str(props.get("status", "")).lower() in {"removed", "disabled"}
    sensitive_data = surface.surface_type == "data_classes" and _truthy(_first(props, "sensitive", "regulated", "customer_data"))
    if not (control_removed or sensitive_data):
        return []
    return [_finding(
        surface,
        risk="tenant_or_data_control_change",
        severity="warn",
        control="tenant/data control review",
        reason=f"changed {surface.surface_id} tenant/data control needs abuse review",
        reachable=False,
    )]


def _finding(surface: ChangedSurface, *, risk: str, severity: str, control: str, reason: str, reachable: bool) -> RiskFinding:
    return RiskFinding(surface.surface_type, surface.surface_id, risk, severity, control, reason, reachable)


def _suggested_regressions(risks: list[RiskFinding]) -> list[SuggestedRegression]:
    seen: set[tuple[str, str, str]] = set()
    out: list[SuggestedRegression] = []
    for risk in risks:
        key = (risk.surface_type, risk.surface_id, risk.risk)
        if key in seen:
            continue
        seen.add(key)
        out.append(SuggestedRegression(
            surface_type=risk.surface_type,
            surface_id=risk.surface_id,
            name=f"launch_review_{_safe_id(risk.surface_id)}_{_safe_id(risk.risk)}",
            expected_status="blocked",
            scenario_hint=risk.risk,
        ))
    return out


def _items_by_id(value: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(value, list):
        return out
    for idx, item in enumerate(value):
        props = dict(item) if isinstance(item, Mapping) else {"value": item}
        sid = _surface_id(props, idx)
        out[sid] = _ordered(props)
    return out


def _surface_id(props: Mapping[str, Any], idx: int) -> str:
    for key in ("id", "name", "route", "path", "tool", "connector", "role", "plan", "event", "action"):
        if props.get(key):
            return str(props[key])
    if "value" in props:
        return str(props["value"])
    return str(idx)


def _first(props: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in props:
            return props[name]
    return None


def _bad_control(value: Any) -> bool:
    if value is False or value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in _MISSING_VALUES
    return False


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, (int, float)) and value:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "on", "enabled", "billable", "metered", "paid"}
    return False


def _reachable(props: Mapping[str, Any]) -> bool:
    if props.get("reachable") is False:
        return False
    if _truthy(props.get("reachable")):
        return True
    plan = str(_first(props, "reachable_by_plan", "granted_plan", "current_plan") or "").lower()
    role = str(_first(props, "reachable_by_role", "installable_by_role", "granted_role") or "").lower()
    return plan in _LOW_REACH_PLANS or role in {"anonymous", "member", "user", "anyone"}


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _to_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    if isinstance(value, str) and "," in value:
        return [v.strip() for v in value.split(",") if v.strip()]
    return [str(value)]


def _scope_wider(granted: str, intended: str) -> bool:
    return _SCOPE_RANK.get(granted, 0) > _SCOPE_RANK.get(intended, 0) or granted in _HIGH_SCOPE_VALUES and granted != intended


def _text(props: Mapping[str, Any], *names: str) -> str:
    return " ".join(str(props.get(n, "")) for n in names).lower()


def _ordered(props: Mapping[str, Any]) -> dict[str, Any]:
    return {k: props[k] for k in sorted(props)}


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _safe_id(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._:-" else "_" for ch in value).strip("_")[:80] or "surface"


def _split_rev_range(rev_range: str) -> tuple[str, str]:
    if "..." in rev_range:
        left, right = rev_range.split("...", 1)
    elif ".." in rev_range:
        left, right = rev_range.split("..", 1)
    else:
        raise ProductModelError("--diff must be a git revision range such as main..feature")
    return left or "HEAD~1", right or "HEAD"


def _changed_json_paths(rev_range: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", rev_range, "--", "*.json"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise ProductModelError(result.stderr.strip() or f"git diff failed for {rev_range}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _git_json(rev: str, path: str) -> dict[str, Any]:
    result = subprocess.run(
        ["git", "show", f"{rev}:{path}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise ProductModelError(result.stderr.strip() or f"cannot read {path} at {rev}")
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ProductModelError(f"{path} at {rev} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ProductModelError(f"{path} at {rev} is not a JSON object")
    return data
