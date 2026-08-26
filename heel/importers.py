"""Native ProductModel loading and target conversion compatibility surface."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Mapping

from .contracts import Affordance, Category, SyntheticTarget
from .entitlements import EntitlementGraph
from .product_model import (
    ALLOWED_ENVIRONMENTS,
    LIST_FIELDS,
    PRODUCT_MODEL_VERSION,
    REQUIRED_FIELDS,
    ProductModel,
    ProductModelError,
    ValidationResult,
    product_model_from_dict,
    validate_product_model,
)


_BAD_CONTROL_VALUES = {
    "missing", "none", "false", "disabled", "off", "no", "weak", "client",
}
_CONTROL_HINTS = (
    "check", "guard", "limit", "protection", "filter", "isolation", "allowlist",
    "audit", "verification", "entitlement", "authz",
)


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


def target_from_product_model(model: Mapping[str, Any] | ProductModel) -> ImportedTarget:
    pm = model if isinstance(model, ProductModel) else product_model_from_dict(model)
    graph = EntitlementGraph.from_product_model(pm)
    affordances = _affordances(pm) + graph.to_affordances()
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
        "entitlement_graph_edges": len(graph.edges),
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
        text = " ".join(
            str(props.get(k, ""))
            for k in ("id", "name", "flow", "route", "description")
        ).lower()
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
        if any(hint in str(key).lower() for hint in _CONTROL_HINTS) \
                and _bad_control_value(value):
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
    environment = str(props.get("environment", "")).lower()
    if environment == "production":
        return 0.7
    if environment in {"sandbox", "synthetic"}:
        return 0.45
    return 0.6


def _item_id(item: Any, idx: int) -> str:
    if isinstance(item, Mapping):
        for key in (
            "id", "name", "route", "path", "tool", "connector", "role", "plan",
            "event", "action",
        ):
            if item.get(key):
                return _safe_id(str(item[key]))
    return str(idx)


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "_", value.strip())
    cleaned = cleaned.strip("_")
    return cleaned[:80] or "item"
