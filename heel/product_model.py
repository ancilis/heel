"""Pure ProductModel types, validation, and in-memory transformation."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Mapping

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
_AFFORDANCE_FIELD_ORDER = [
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
]

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
