"""Pure OpenAPI validation, normalization, and ProductModel mapping."""
from __future__ import annotations

import re
from typing import Any, Mapping

from .product_model import LIST_FIELDS, PRODUCT_MODEL_VERSION, validate_product_model
from .review_rules import is_broad_scope


class OpenAPIImportError(ValueError):
    """Raised when an OpenAPI document cannot be safely converted."""


_SECRET_VALUE_RE = re.compile(
    r"(?i)(sk-(live|test)?[-_a-z0-9]{8,}|xox[baprs]-[-_a-z0-9]{8,}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer\s+[A-Za-z0-9._~+/=-]{12,})"
)
_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
_OPENAPI_VERSION_RE = re.compile(r"3\.(?:0|1)\.\d+\Z")
_PATH_ITEM_REF_PREFIX = "#/components/pathItems/"
_HEEL_STRING_EXTENSIONS = (
    "x-heel-tenant-scope", "x-heel-plan", "x-heel-data-class",
)
_MISSING_EXTENSION_VALUES = {
    "", "missing", "none", "false", "disabled", "off", "no", "weak",
    "client", "client_only",
}
_CONTROL_ALIASES = {
    "entitlement": frozenset({
        "entitlement", "entitlement_check", "server_side_entitlement_check",
    }),
    "rate": frozenset({
        "rate", "rate_limit", "tenant_rate_limit", "server_side_rate_limit",
    }),
}
QUESTION_PROMPTS = {
    "missing_tenant_metadata": "How is tenant access enforced for this operation?",
    "missing_entitlement_metadata": "Which plan or entitlement protects this operation?",
    "broad_oauth_scope": "Which least-privilege OAuth scopes should protect this surface?",
    "export_missing_rate_limit": (
        "Which server-side rate limit protects this export operation?"
    ),
    "agent_scope_metadata_missing": (
        "What intended and granted scopes constrain this agent operation?"
    ),
}


def product_model_from_openapi(spec: Mapping[str, Any], source: str = "openapi:inline") -> dict:
    info, paths = _validate_openapi_document(spec)
    _reject_remote_refs(spec)
    _reject_secret_examples(spec)
    product_id = _safe_id(str(info.get("x-heel-product-id") or info["title"]))
    model = {field: [] for field in LIST_FIELDS}
    model.update({
        "schema_version": PRODUCT_MODEL_VERSION,
        "product_id": product_id,
        "source": source,
        "generated_at": str(info.get("x-heel-generated-at") or "1970-01-01T00:00:00Z"),
        "environments": ["staging"],
        "safety_notes": [
            "OpenAPI-derived draft; review and enrich before rehearsal. No live probing or customer data.",
        ],
        "product_areas": [],
        "import_warnings": [],
        "import_question_hints": [],
    })

    warnings: list[str] = []
    question_hints: list[dict[str, str]] = []
    product_areas: dict[str, dict] = {}
    operation_locations: dict[str, str] = {}
    _security_controls(spec, model, warnings, question_hints)

    route_items: list[tuple[str, Any]] = []
    for route, path_item in paths.items():
        if not isinstance(route, str):
            raise OpenAPIImportError("paths keys must be strings beginning with /")
        if route.startswith("x-"):
            continue
        if not route.startswith("/"):
            raise OpenAPIImportError(f"paths key {route!r} must begin with /")
        route_items.append((route, path_item))

    for route, path_item_value in sorted(route_items):
        path_item = _resolve_path_item(spec, path_item_value, route=route)
        for method, operation in sorted(path_item.items(), key=lambda item: str(item[0])):
            normalized_method = str(method).lower()
            if normalized_method not in _METHODS:
                continue
            if not isinstance(operation, Mapping):
                raise OpenAPIImportError(
                    f"operation {normalized_method.upper()} {route} must be an object"
                )
            op = dict(operation)
            _validate_operation(op, method=normalized_method, route=route)
            op = _normalize_heel_extensions(
                op, method=normalized_method, route=route,
            )
            tags = list(op.get("tags", []))
            for tag in tags:
                product_areas.setdefault(tag, {"id": tag, "source": "openapi-tag"})
            entry = _route_entry(route, normalized_method.upper(), op, tags)
            operation_id = entry["operation_id"]
            location = f"{entry['method']} {entry['route']}"
            if operation_id in operation_locations:
                raise OpenAPIImportError(
                    f"duplicate operation id after normalization: {operation_id} "
                    f"at {operation_locations[operation_id]} and {location}"
                )
            operation_locations[operation_id] = location
            model["endpoints_routes"].append(entry)
            _map_operation(model, entry, op, warnings, question_hints)

    model["product_areas"] = sorted(product_areas.values(), key=lambda p: p["id"])
    model["import_warnings"] = _unique(warnings)
    model["import_question_hints"] = sorted(
        question_hints,
        key=lambda hint: tuple(hint[field] for field in (
            "code", "field", "method", "route", "operation_id", "message",
        )),
    )
    result = validate_product_model(model)
    if not result.ok:
        raise OpenAPIImportError("; ".join(result.errors))
    return model


def _validate_openapi_document(
    spec: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    if not isinstance(spec, Mapping):
        raise OpenAPIImportError("OpenAPI document must be an object")
    version = spec.get("openapi")
    if not isinstance(version, str) or _OPENAPI_VERSION_RE.fullmatch(version) is None:
        raise OpenAPIImportError("openapi must declare a supported 3.0.x or 3.1.x version string")
    info = spec.get("info")
    if not isinstance(info, Mapping):
        raise OpenAPIImportError("info must be an object")
    for field_name in ("title", "version"):
        value = info.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise OpenAPIImportError(f"info.{field_name} must be a nonempty string")
    paths = spec.get("paths")
    if not isinstance(paths, Mapping):
        raise OpenAPIImportError("paths must be an object")
    return info, paths


def _validate_operation(
    operation: Mapping[str, Any], *, method: str, route: str,
) -> None:
    location = f"{method.upper()} {route}"
    if "operationId" in operation:
        operation_id = operation["operationId"]
        if not isinstance(operation_id, str) or not operation_id.strip():
            raise OpenAPIImportError(f"operationId for {location} must be a nonempty string")
    if "tags" in operation:
        tags = operation["tags"]
        if not isinstance(tags, list) or any(
            not isinstance(tag, str) or not tag.strip() for tag in tags
        ):
            raise OpenAPIImportError(f"tags for {location} must be a list of nonempty strings")


def _normalize_heel_extensions(
    operation: Mapping[str, Any], *, method: str, route: str,
) -> dict[str, Any]:
    normalized = dict(operation)
    location = f"{method.upper()} {route}"
    for extension in _HEEL_STRING_EXTENSIONS:
        if extension not in operation:
            continue
        raw = operation[extension]
        if not isinstance(raw, str):
            raise OpenAPIImportError(
                f"{extension} for {location} must be a string"
            )
        value = raw.strip()
        if value.lower() in _MISSING_EXTENSION_VALUES:
            normalized.pop(extension, None)
        else:
            normalized[extension] = value

    if "x-heel-control" in operation:
        controls = _normalize_controls(operation["x-heel-control"], location=location)
        if controls:
            normalized["x-heel-control"] = controls
        else:
            normalized.pop("x-heel-control", None)
    return normalized


def _normalize_controls(raw: Any, *, location: str) -> list[str]:
    values: list[str]
    if isinstance(raw, str):
        values = [raw]
    elif isinstance(raw, list):
        if any(not isinstance(value, str) for value in raw):
            raise OpenAPIImportError(
                f"x-heel-control for {location} list values must be strings"
            )
        values = list(raw)
    elif isinstance(raw, Mapping):
        if any(
            not isinstance(key, str) or type(enabled) is not bool
            for key, enabled in raw.items()
        ):
            raise OpenAPIImportError(
                f"x-heel-control for {location} must map strings to booleans"
            )
        values = [key for key, enabled in raw.items() if enabled]
    else:
        raise OpenAPIImportError(
            f"x-heel-control for {location} must be a string, list of strings, "
            "or string-to-boolean map"
        )

    controls = {
        _normalize_control_identifier(value)
        for value in values
    }
    return sorted(
        control for control in controls
        if control and control not in _MISSING_EXTENSION_VALUES
    )


def _normalize_control_identifier(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def _resolve_path_item(
    spec: Mapping[str, Any], value: Any, *, route: str,
    ref_chain: tuple[str, ...] = (),
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise OpenAPIImportError(f"path item for {route} must be an object")
    if "$ref" not in value:
        return dict(value)

    ref = value["$ref"]
    if not isinstance(ref, str) or not ref.startswith(_PATH_ITEM_REF_PREFIX):
        raise OpenAPIImportError(
            f"path item for {route} may only reference local components.pathItems"
        )
    token = ref[len(_PATH_ITEM_REF_PREFIX):]
    if not token or "/" in token:
        raise OpenAPIImportError(f"path item for {route} has an invalid local reference")
    name = _unescape_json_pointer_token(token)
    if ref in ref_chain:
        raise OpenAPIImportError(f"path item for {route} contains a cyclic local reference")

    components = spec.get("components")
    path_items = components.get("pathItems") if isinstance(components, Mapping) else None
    target = path_items.get(name) if isinstance(path_items, Mapping) else None
    if not isinstance(target, Mapping):
        raise OpenAPIImportError(
            f"path item for {route} references a missing or non-object component"
        )

    resolved = _resolve_path_item(
        spec, target, route=route, ref_chain=(*ref_chain, ref),
    )
    resolved.update({key: child for key, child in value.items() if key != "$ref"})
    return resolved


def _unescape_json_pointer_token(token: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(token):
        character = token[index]
        if character != "~":
            output.append(character)
            index += 1
            continue
        if index + 1 >= len(token) or token[index + 1] not in {"0", "1"}:
            raise OpenAPIImportError("path item reference contains an invalid JSON Pointer escape")
        output.append("~" if token[index + 1] == "0" else "/")
        index += 2
    return "".join(output)


def _security_controls(
    spec: Mapping[str, Any], model: dict, warnings: list[str],
    question_hints: list[dict[str, str]],
) -> None:
    components = spec.get("components") if isinstance(spec.get("components"), Mapping) else {}
    schemes = components.get("securitySchemes") if isinstance(components.get("securitySchemes"), Mapping) else {}
    for name, scheme in sorted(schemes.items()):
        scheme = scheme if isinstance(scheme, Mapping) else {}
        control = {
            "id": f"security_scheme:{name}",
            "name": str(name),
            "kind": str(scheme.get("type", "securityScheme")),
        }
        if scheme.get("type") == "oauth2":
            scopes = _oauth_scheme_scopes(scheme)
            control["scopes"] = scopes
            if any(is_broad_scope(scope) for scope in scopes):
                _add_warning(
                    warnings,
                    question_hints,
                    code="broad_oauth_scope",
                    field="product_rule",
                    message=f"broad OAuth scope declared by security scheme {name}",
                )
        model["declared_controls"].append(control)


def _map_operation(
    model: dict, entry: dict, operation: Mapping[str, Any], warnings: list[str],
    question_hints: list[dict[str, str]],
) -> None:
    text = _operation_text(entry, operation)
    controls = _controls(operation)
    has_tenant_scope = bool(entry.get("tenant_scope"))
    has_entitlement = bool(entry.get("required_plan") or _has_control(controls, "entitlement"))
    has_rate = _has_control(controls, "rate")
    if not has_tenant_scope:
        _add_warning(
            warnings,
            question_hints,
            code="missing_tenant_metadata",
            field="tenant_filter",
            message=f"missing tenant metadata for {entry['route']}",
            entry=entry,
        )
    if not has_entitlement:
        _add_warning(
            warnings,
            question_hints,
            code="missing_entitlement_metadata",
            field="entitlement_check",
            message=f"missing entitlement metadata for {entry['route']}",
            entry=entry,
        )
    if controls:
        declared = {
            "id": f"operation:{entry['operation_id']}:controls",
            "route": entry["route"],
            "controls": controls,
        }
        model["declared_controls"].append(declared)

    if _contains_any(text, ("export", "download", "bulk")):
        export = dict(entry)
        export.update({"id": entry["operation_id"], "kind": "export"})
        export["entitlement_check"] = "declared" if has_entitlement else "missing"
        export["rate_limit"] = "declared" if has_rate else "missing"
        model["exports"].append(export)
        if not has_rate:
            _add_warning(
                warnings,
                question_hints,
                code="export_missing_rate_limit",
                field="rate_limit",
                message=f"missing rate-limit metadata for {entry['route']}",
                entry=entry,
            )

    if _contains_any(text, ("signup", "trial")):
        model["identity_auth_flows"].append({**entry, "id": entry["operation_id"], "kind": "signup"})

    if _contains_any(text, ("billing", "subscription", "usage", "meter")):
        model["billing_objects"].append({**entry, "id": entry["operation_id"], "kind": "billing"})
        meter = operation.get("x-heel-meter")
        if meter or _contains_any(text, ("usage", "meter")):
            model["meters"].append({**entry, "id": str(meter or entry["operation_id"]), "kind": "meter"})

    if _contains_any(text, ("invite", "user", "member", "seat")):
        model["roles"].append({**entry, "id": entry["operation_id"], "kind": "seat"})

    if _contains_any(text, ("oauth", "integration", "app", "webhook")):
        if "webhook" in text:
            model["webhooks"].append({**entry, "id": entry["operation_id"], "kind": "webhook"})
        else:
            scopes = _operation_oauth_scopes(operation)
            model["integration_oauth_apps"].append({**entry, "id": entry["operation_id"], "kind": "oauth_app", "scopes": scopes})
            if any(is_broad_scope(scope) for scope in scopes):
                _add_warning(
                    warnings,
                    question_hints,
                    code="broad_oauth_scope",
                    field="product_rule",
                    message=f"broad OAuth scope on {entry['route']}",
                    entry=entry,
                )

    if _contains_any(text, ("admin", "support")):
        model["support_admin_actions"].append({**entry, "id": entry["operation_id"], "kind": "admin_action"})

    agent_tool = operation.get("x-heel-agent-tool")
    if agent_tool or _contains_any(text, ("agent", "tool")):
        item = {**entry, "id": entry["operation_id"], "tool": entry["operation_id"], "kind": "agent_tool"}
        if isinstance(agent_tool, Mapping):
            item.update({str(k): v for k, v in agent_tool.items()})
        model["agent_tools"].append(item)
        if not (item.get("intended_scope") and item.get("granted_scope")):
            _add_warning(
                warnings,
                question_hints,
                code="agent_scope_metadata_missing",
                field="product_rule",
                message=f"agent-like endpoint lacks scope metadata: {entry['route']}",
                entry=entry,
            )

    data_class = operation.get("x-heel-data-class")
    if data_class and data_class not in model["data_classes"]:
        model["data_classes"].append(data_class)


def _add_warning(
    warnings: list[str], question_hints: list[dict[str, str]], *,
    code: str, field: str, message: str, entry: Mapping[str, Any] | None = None,
) -> None:
    warnings.append(message)
    if entry is None:
        method = route = operation_id = "product"
    else:
        method = str(entry["method"])
        route = str(entry["route"])
        operation_id = str(entry["operation_id"])
    question_hints.append({
        "code": code,
        "field": field,
        "method": method,
        "route": route,
        "operation_id": operation_id,
        "message": message,
    })


def operation_surface_id(method: str, route: str, operation: Mapping[str, Any]) -> str:
    """Return the canonical operation surface identifier used by review questions."""
    return _safe_id(str(operation.get("operationId") or f"{method.lower()}_{route}"))


def _route_entry(route: str, method: str, operation: Mapping[str, Any], tags: list[str]) -> dict:
    operation_id = operation_surface_id(method, route, operation)
    controls = _controls(operation)
    product_area = tags[0] if tags else ""
    entry = {
        "id": operation_id,
        "route": route,
        "method": method,
        "operation_id": operation_id,
        "product_area": product_area,
        "tags": tags,
        "tenant_scope": operation.get("x-heel-tenant-scope"),
        "required_plan": operation.get("x-heel-plan"),
        "data_class": operation.get("x-heel-data-class"),
        "controls": controls,
    }
    if _has_control(controls, "entitlement"):
        entry["entitlement_check"] = "declared"
    if _has_control(controls, "rate"):
        entry["rate_limit"] = "declared"
    if entry.get("tenant_scope"):
        entry["tenant_filter"] = "declared"
    return {k: v for k, v in entry.items() if v not in (None, "", [])}


def _controls(operation: Mapping[str, Any]) -> list[str]:
    raw = operation.get("x-heel-control")
    if raw is None:
        return []
    return list(raw)


def _operation_text(entry: Mapping[str, Any], operation: Mapping[str, Any]) -> str:
    parts = [
        entry.get("route", ""),
        entry.get("operation_id", ""),
        operation.get("summary", ""),
        operation.get("description", ""),
        " ".join(str(t) for t in operation.get("tags", [])),
    ]
    for key in ("x-heel-meter", "x-heel-plan", "x-heel-tenant-scope", "x-heel-data-class"):
        parts.append(str(operation.get(key, "")))
    return " ".join(str(p) for p in parts).lower()


def _operation_oauth_scopes(operation: Mapping[str, Any]) -> list[str]:
    scopes: list[str] = []
    security = operation.get("security")
    if isinstance(security, list):
        for item in security:
            if isinstance(item, Mapping):
                for values in item.values():
                    if isinstance(values, list):
                        scopes.extend(str(v) for v in values)
    return sorted(set(scopes))


def _oauth_scheme_scopes(scheme: Mapping[str, Any]) -> list[str]:
    scopes: list[str] = []
    flows = scheme.get("flows") if isinstance(scheme.get("flows"), Mapping) else {}
    for flow in flows.values():
        if isinstance(flow, Mapping) and isinstance(flow.get("scopes"), Mapping):
            scopes.extend(str(k) for k in flow["scopes"].keys())
    return sorted(set(scopes))


def _reject_secret_examples(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            _reject_secret_examples(child, f"{path}.{key}")
    elif isinstance(value, list):
        for i, child in enumerate(value):
            _reject_secret_examples(child, f"{path}[{i}]")
    elif isinstance(value, str) and _SECRET_VALUE_RE.search(value):
        raise OpenAPIImportError(f"{path}: secret-looking example value is not importable; replace it with a canary or redacted value")


def _reject_remote_refs(value: Any) -> None:
    if isinstance(value, Mapping):
        reference = value.get("$ref")
        if "$ref" in value and (
            not isinstance(reference, str) or not reference.startswith("#/")
        ):
            raise OpenAPIImportError(
                "remote OpenAPI references are not importable; use local document references"
            )
        for child in value.values():
            _reject_remote_refs(child)
    elif isinstance(value, list):
        for child in value:
            _reject_remote_refs(child)


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)


def _has_control(controls: list[str], needle: str) -> bool:
    return any(control in _CONTROL_ALIASES.get(needle, ()) for control in controls)


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._:-]+", "-", value.strip().lower())
    cleaned = cleaned.strip("-")
    return cleaned[:80] or "openapi-product"


def _unique(values: list[str]) -> list[str]:
    return sorted(dict.fromkeys(values))
