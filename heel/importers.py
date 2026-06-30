"""
ProductModel import contract.

This module turns an operator-authored, sanitized SaaS product description into a
HEEL target model without touching the real system. It deliberately has no live
adapter code and no network calls. Imported targets are model rehearsals only and
must still be run through a human-created signed AuthorizationScope.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Mapping

from .contracts import Affordance, Category, SyntheticTarget

PRODUCT_MODEL_VERSION = "ProductModel.v0.1"
ALLOWED_ENVIRONMENTS = {"production", "staging", "sandbox", "synthetic"}

LIST_FIELDS = [
    "tenants",
    "roles",
    "plans",
    "meters",
    "coupons_promotions",
    "features_flags",
    "endpoints_routes",
    "exports",
    "identity_auth_flows",
    "billing_objects",
    "integration_oauth_apps",
    "webhooks",
    "support_admin_actions",
    "agent_tools",
    "mcp_connectors",
    "data_classes",
    "audit_events",
    "declared_controls",
    "canary_accounts",
    "safety_notes",
]
REQUIRED_FIELDS = ["schema_version", "product_id", "source", "generated_at", "environments"] + LIST_FIELDS

_SECRET_KEY_RE = re.compile(
    r"(?i)(^|[_\-.])(api[_\-.]?key|secret|token|password|passwd|private[_\-.]?key|"
    r"client[_\-.]?secret|access[_\-.]?key|refresh[_\-.]?token|session[_\-.]?cookie|"
    r"cookie|authorization|bearer)($|[_\-.])"
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)(sk-(live|test)?[-_a-z0-9]{8,}|xox[baprs]-[-_a-z0-9]{8,}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer\s+[A-Za-z0-9._~+/=-]{12,})"
)
_BAD_CONTROL_VALUES = {"missing", "none", "false", "disabled", "off", "no", "weak", "client"}
_CONTROL_HINTS = (
    "check", "guard", "limit", "protection", "filter", "isolation", "allowlist",
    "audit", "verification", "entitlement", "authz",
)


class ProductModelError(ValueError):
    """Raised when a ProductModel cannot be loaded, validated, or converted."""


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: list[str]
    warnings: list[str]
    summary: str
    schema_version: str = PRODUCT_MODEL_VERSION
    target_id: str = ""


@dataclass(frozen=True)
class ProductModel:
    schema_version: str
    product_id: str
    source: str
    generated_at: str
    environments: list[str]
    tenants: list[Any]
    roles: list[Any]
    plans: list[Any]
    meters: list[Any]
    coupons_promotions: list[Any]
    features_flags: list[Any]
    endpoints_routes: list[Any]
    exports: list[Any]
    identity_auth_flows: list[Any]
    billing_objects: list[Any]
    integration_oauth_apps: list[Any]
    webhooks: list[Any]
    support_admin_actions: list[Any]
    agent_tools: list[Any]
    mcp_connectors: list[Any]
    data_classes: list[Any]
    audit_events: list[Any]
    declared_controls: list[Any]
    canary_accounts: list[Any]
    safety_notes: list[str]
    raw: dict = field(default_factory=dict, repr=False)


@dataclass
class ImportedTarget(SyntheticTarget):
    imported_schema_version: str = PRODUCT_MODEL_VERSION
    source: str = ""
    safety_metadata: dict = field(default_factory=dict)
    safety_notes: list[str] = field(default_factory=list)
    requires_scope: bool = True


def load_product_model(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ProductModelError(f"invalid JSON: {exc}") from exc
    except OSError as exc:
        raise ProductModelError(f"cannot read ProductModel: {exc}") from exc
    if not isinstance(data, dict):
        raise ProductModelError("ProductModel must be a JSON object")
    return data


def validate_product_model(model: Mapping[str, Any]) -> ValidationResult:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(model, Mapping):
        return ValidationResult(False, ["ProductModel must be a JSON object"], [], "invalid ProductModel")

    missing = [f for f in REQUIRED_FIELDS if f not in model]
    errors.extend(f"missing required field: {f}" for f in missing)

    schema_version = str(model.get("schema_version", ""))
    if schema_version and schema_version != PRODUCT_MODEL_VERSION:
        errors.append(f"schema_version must be {PRODUCT_MODEL_VERSION}")

    for field_name in ("product_id", "source", "generated_at"):
        if field_name in model and not _nonempty_string(model.get(field_name)):
            errors.append(f"{field_name} must be a non-empty string")

    product_id = str(model.get("product_id", ""))
    if product_id and not re.match(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", product_id):
        errors.append("product_id must be a stable ASCII identifier without whitespace")

    envs = model.get("environments")
    if "environments" in model:
        if not isinstance(envs, list) or not envs:
            errors.append("environments must be a non-empty list")
        else:
            bad = [e for e in envs if e not in ALLOWED_ENVIRONMENTS]
            if bad:
                errors.append("environments may only contain production, staging, sandbox, synthetic")

    for field_name in LIST_FIELDS:
        if field_name in model and not isinstance(model[field_name], list):
            errors.append(f"{field_name} must be a list")
    if "safety_notes" in model and isinstance(model["safety_notes"], list) and not model["safety_notes"]:
        errors.append("safety_notes must include at least one operator-written safety note")

    _find_secret_material(model, "$", errors)

    if "production" in (envs or []) and not model.get("canary_accounts"):
        warnings.append("production-like ProductModels should declare canary_accounts before rehearsal")

    target_id = f"imported:{product_id}" if product_id else ""
    affordance_count = sum(len(model.get(f, [])) for f in _AFFORDANCE_FIELD_ORDER if isinstance(model.get(f), list))
    summary = (
        f"{PRODUCT_MODEL_VERSION} {product_id or '<missing product_id>'}: "
        f"{len(envs or []) if isinstance(envs, list) else 0} environment(s), "
        f"{affordance_count} modeled affordance(s), target {target_id or '<unavailable>'}"
    )
    return ValidationResult(not errors, errors, warnings, summary, PRODUCT_MODEL_VERSION, target_id)


def product_model_from_dict(model: Mapping[str, Any]) -> ProductModel:
    result = validate_product_model(model)
    if not result.ok:
        raise ProductModelError("; ".join(result.errors))
    raw = json.loads(json.dumps(dict(model), default=str))
    return ProductModel(
        schema_version=raw["schema_version"],
        product_id=raw["product_id"],
        source=raw["source"],
        generated_at=raw["generated_at"],
        environments=list(raw["environments"]),
        raw=raw,
        **{f: list(raw[f]) for f in LIST_FIELDS},
    )


def target_from_product_model(model: Mapping[str, Any] | ProductModel) -> ImportedTarget:
    pm = model if isinstance(model, ProductModel) else product_model_from_dict(model)
    affordances = _affordances(pm)
    has_agent_surface = bool(pm.agent_tools or pm.mcp_connectors)
    safety_metadata = {
        "schema_version": PRODUCT_MODEL_VERSION,
        "product_id": pm.product_id,
        "source": pm.source,
        "generated_at": pm.generated_at,
        "environments": list(pm.environments),
        "scope_required": True,
        "authorization": "human_created_signed_scope_required",
        "live_probing_disabled": True,
        "imported_model_rehearsal": True,
        "secrets_checked": True,
        "canary_accounts": list(pm.canary_accounts),
        "data_classes": list(pm.data_classes),
        "declared_controls": list(pm.declared_controls),
        "safety_notes": list(pm.safety_notes),
    }
    return ImportedTarget(
        id=f"imported:{pm.product_id}",
        kind="imported_ai_agent" if has_agent_surface else "imported_saas",
        has_agent_surface=has_agent_surface,
        affordances=affordances,
        planted_vectors=[],
        description=f"Imported ProductModel rehearsal for {pm.product_id}; no live probing.",
        source=pm.source,
        safety_metadata=safety_metadata,
        safety_notes=list(pm.safety_notes),
        requires_scope=True,
    )


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _find_secret_material(value: Any, path: str, errors: list[str]) -> None:
    if isinstance(value, Mapping):
        for k, v in value.items():
            key = str(k)
            child = f"{path}.{key}"
            if _SECRET_KEY_RE.search(key):
                errors.append(f"{child}: field name looks secret-bearing; import references or redacted ids, never secrets")
            _find_secret_material(v, child, errors)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _find_secret_material(item, f"{path}[{i}]", errors)
    elif isinstance(value, str) and _SECRET_VALUE_RE.search(value):
        errors.append(f"{path}: value looks secret-bearing; remove it or replace it with a canary/redacted reference")


_FIELD_SPECS = {
    "tenants": ("tenant", Category.COMPLIANCE_BOUNDARY),
    "roles": ("role", Category.IDENTITY_ACCOUNT),
    "plans": ("plan", Category.LICENSE_ENTITLEMENT),
    "meters": ("meter", Category.LICENSE_ENTITLEMENT),
    "coupons_promotions": ("promotion", Category.LICENSE_ENTITLEMENT),
    "features_flags": ("flag", Category.UNINTENDED_ENDPOINTS),
    "endpoints_routes": ("endpoint", Category.UNINTENDED_ENDPOINTS),
    "exports": ("export", Category.DATA_HARVESTING),
    "identity_auth_flows": ("auth_flow", Category.IDENTITY_ACCOUNT),
    "billing_objects": ("billing", Category.LICENSE_ENTITLEMENT),
    "integration_oauth_apps": ("oauth_app", Category.INTEGRATION_EXTENSIBILITY),
    "webhooks": ("integration", Category.INTEGRATION_EXTENSIBILITY),
    "support_admin_actions": ("admin_action", Category.COMPLIANCE_BOUNDARY),
    "agent_tools": ("agent_tool", Category.AGENT_MCP_SURFACE),
    "mcp_connectors": ("mcp_connector", Category.AGENT_MCP_SURFACE),
    "data_classes": ("data_class", Category.COMPLIANCE_BOUNDARY),
    "audit_events": ("audit_event", Category.COMPLIANCE_BOUNDARY),
}
_AFFORDANCE_FIELD_ORDER = list(_FIELD_SPECS)


def _affordances(pm: ProductModel) -> list[Affordance]:
    out: list[Affordance] = []
    for field_name in _AFFORDANCE_FIELD_ORDER:
        kind, default_category = _FIELD_SPECS[field_name]
        for idx, item in enumerate(getattr(pm, field_name)):
            props = _properties(item, field_name)
            actual_kind = _kind_for(field_name, kind, props)
            category = _category_for(props, default_category)
            out.append(Affordance(
                id=f"pm:{_safe_id(field_name)}:{_item_id(item, idx)}",
                kind=actual_kind,
                category=category,
                properties=props,
                guard_present=_guard_present(props),
                reachability=_reachability(props),
                planted_weakness=None,
                true_severity=None,
                decoy=False,
            ))
    return out


def _properties(item: Any, source_field: str) -> dict:
    if isinstance(item, Mapping):
        props = {str(k): v for k, v in item.items()}
    else:
        props = {"name": str(item)}
    props["source_field"] = source_field
    return props


def _kind_for(field_name: str, default_kind: str, props: dict) -> str:
    explicit = props.get("kind")
    if isinstance(explicit, str) and explicit:
        return explicit
    if field_name == "identity_auth_flows":
        text = " ".join(str(props.get(k, "")) for k in ("id", "name", "flow", "route", "description")).lower()
        if "reset" in text or "recover" in text:
            return "auth_reset"
        if "signup" in text or "registration" in text:
            return "signup"
    return default_kind


def _category_for(props: dict, default_category: Category) -> Category:
    value = props.get("category")
    if isinstance(value, str):
        try:
            return Category(value)
        except ValueError:
            return default_category
    return default_category


def _guard_present(props: dict) -> bool:
    if isinstance(props.get("guard_present"), bool):
        return bool(props["guard_present"])
    if props.get("guard_absent") is True:
        return False
    for key, value in props.items():
        k = str(key).lower()
        if any(h in k for h in _CONTROL_HINTS) and _bad_control_value(value):
            return False
    return True


def _bad_control_value(value: Any) -> bool:
    if value is False or value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in _BAD_CONTROL_VALUES
    return False


def _reachability(props: dict) -> float:
    if isinstance(props.get("reachability"), (int, float)):
        return round(max(0.05, min(0.95, float(props["reachability"]))), 3)
    env = str(props.get("environment", "")).lower()
    if env == "production":
        return 0.7
    if env in {"sandbox", "synthetic"}:
        return 0.45
    return 0.6


def _item_id(item: Any, idx: int) -> str:
    if isinstance(item, Mapping):
        for key in ("id", "name", "route", "path", "tool", "connector", "role", "plan", "event", "action"):
            if item.get(key):
                return _safe_id(str(item[key]))
    return str(idx)


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "_", value.strip())
    cleaned = cleaned.strip("_")
    return cleaned[:80] or "item"
