"""Closed deterministic adapters for Heel's launch canary catalog."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any

from .catalog import CATALOG, CATALOG_BY_ID, NONANONYMOUS_AUTH_PROFILES
from .openapi_routes import normalize_route_template


_ACTION_KEYS = frozenset({
    "ordinal", "scenario_id", "adapter_version", "method", "route_template",
    "fixture_bindings", "semantic_auth_role", "auth_profile", "assertion_class",
    "allowed_status_codes", "allowed_body_shapes", "side_effect_class",
})
_FIXTURE_SEGMENT = re.compile(r"[A-Za-z0-9._~:-]{1,128}", flags=re.ASCII)
_SAFE_COPY = {
    "anonymous_authenticated_read": (
        "Authentication boundary blocked lower-role access",
        "Require authentication consistently",
    ),
    "object_ownership_read": (
        "Ownership boundary blocked non-owner access",
        "Enforce object ownership",
    ),
    "role_bound_read": (
        "Role boundary blocked lower-privilege access",
        "Enforce role authorization",
    ),
    "plan_entitlement_read": (
        "Plan entitlement boundary blocked lower-plan access",
        "Enforce plan entitlement",
    ),
}


def _adapter(entry: Mapping[str, Any]) -> MappingProxyType:
    return MappingProxyType({
        "scenario_id": entry["scenario_id"],
        "adapter_version": entry["adapter_version"],
        "assertion_class": entry["assertion_class"],
        "semantic_roles": entry["semantic_roles"],
        "allowed_methods": entry["allowed_methods"],
        "allowed_status_codes": entry["allowed_status_codes"],
        "allowed_body_shapes": entry["allowed_body_shapes"],
        "side_effect_class": "read_only",
    })


ADAPTER_REGISTRY = MappingProxyType({
    entry["scenario_id"]: _adapter(entry)
    for entry in CATALOG
})


@dataclass(frozen=True, slots=True)
class PreparedAction:
    scenario_id: str
    adapter_version: str
    method: str
    route: str
    semantic_auth_role: str
    auth_profile: str
    side_effect_class: str


@dataclass(frozen=True, slots=True)
class PairEvaluation:
    outcome: str
    finding: str
    control: str


def _exact_action(action: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    if not isinstance(action, Mapping) or set(action) != _ACTION_KEYS:
        raise ValueError("action must use the closed manifest action schema")
    scenario_id = action.get("scenario_id")
    if type(scenario_id) is not str or scenario_id not in ADAPTER_REGISTRY:
        raise ValueError("action scenario is not in the launch registry")
    adapter = ADAPTER_REGISTRY[scenario_id]
    exact = {
        "adapter_version": adapter["adapter_version"],
        "assertion_class": adapter["assertion_class"],
        "side_effect_class": adapter["side_effect_class"],
    }
    for key, expected in exact.items():
        if action.get(key) != expected:
            raise ValueError(f"action {key} does not match the launch adapter")
    if action.get("method") not in adapter["allowed_methods"]:
        raise ValueError("action method is not permitted by the launch adapter")
    if action.get("semantic_auth_role") not in adapter["semantic_roles"]:
        raise ValueError("action semantic role does not match the launch adapter")
    if action.get("allowed_status_codes") != list(adapter["allowed_status_codes"]):
        raise ValueError("action status contract does not match the launch adapter")
    if action.get("allowed_body_shapes") != list(adapter["allowed_body_shapes"]):
        raise ValueError("action body contract does not match the launch adapter")
    ordinal = action.get("ordinal")
    if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0:
        raise ValueError("action ordinal must be a non-negative integer")
    return action, adapter


def prepare_action(
    action: Mapping[str, Any],
    fixture_values: Mapping[str, str] | None = None,
    *,
    auth_profile: str | None = None,
) -> PreparedAction:
    """Bind exact local fixture segments without exposing a general request builder."""
    action, adapter = _exact_action(action)
    route, placeholders = normalize_route_template(action["route_template"])
    bindings = action.get("fixture_bindings")
    if not isinstance(bindings, list):
        raise ValueError("fixture bindings must be a list")
    bound_values: dict[str, str] = {}
    for binding in bindings:
        if not isinstance(binding, Mapping) or set(binding) != {"parameter_name", "fixture_id"}:
            raise ValueError("fixture binding must be closed")
        name = binding["parameter_name"]
        fixture_id = binding["fixture_id"]
        if (
            type(name) is not str
            or type(fixture_id) is not str
            or _FIXTURE_SEGMENT.fullmatch(fixture_id) is None
            or fixture_id in {".", ".."}
        ):
            raise ValueError("fixture binding is invalid")
        if name in bound_values:
            raise ValueError("fixture bindings must be unique")
        bound_values[name] = fixture_id
    if sorted(bound_values) != placeholders:
        raise ValueError("fixture bindings must exactly cover route placeholders")
    if fixture_values is not None:
        if not isinstance(fixture_values, Mapping) or dict(fixture_values) != bound_values:
            raise ValueError("fixture values cannot override the approved manifest binding")
    for name in placeholders:
        value = bound_values[name]
        route = route.replace("{" + name + "}", value)
    route, remaining = normalize_route_template(route)
    if remaining:
        raise ValueError("prepared route retains a placeholder")

    declared_profile = action.get("auth_profile")
    selected_profile = declared_profile if auth_profile is None else auth_profile
    if auth_profile is not None and declared_profile != auth_profile:
        raise ValueError("auth profile cannot override the approved action")
    role = action["semantic_auth_role"]
    if role == "anonymous":
        if selected_profile != "anonymous":
            raise ValueError("anonymous action requires the anonymous auth profile")
    elif selected_profile not in NONANONYMOUS_AUTH_PROFILES:
        raise ValueError("nonanonymous action requires one closed auth profile")
    return PreparedAction(
        scenario_id=action["scenario_id"],
        adapter_version=adapter["adapter_version"],
        method=action["method"],
        route=route,
        semantic_auth_role=role,
        auth_profile=selected_profile,
        side_effect_class="read_only",
    )


def evaluate_pair(
    scenario_id: str,
    first_status: int,
    second_status: int,
    *,
    method: str = "GET",
    first_body_shape: str = "absent",
    second_body_shape: str = "absent",
) -> PairEvaluation:
    """Evaluate two observations in the exact role order declared by the catalog."""
    if scenario_id not in ADAPTER_REGISTRY:
        raise ValueError("scenario is not in the launch registry")
    adapter = ADAPTER_REGISTRY[scenario_id]
    finding, control = _SAFE_COPY[scenario_id]
    shapes = (first_body_shape, second_body_shape)
    statuses = (first_status, second_status)
    if (
        method not in adapter["allowed_methods"]
        or any(type(status) is not int or isinstance(status, bool) for status in statuses)
        or any(shape not in adapter["allowed_body_shapes"] for shape in shapes)
        or (method == "HEAD" and shapes != ("absent", "absent"))
        or any(status not in adapter["allowed_status_codes"] for status in statuses)
    ):
        return PairEvaluation("inconclusive", finding, control)
    if statuses == (200, 200):
        return PairEvaluation("observed", finding, control)
    blocked = False
    if scenario_id == "anonymous_authenticated_read":
        blocked = first_status in {401, 403, 404} and second_status == 200
    elif scenario_id == "object_ownership_read":
        blocked = first_status == 200 and second_status in {403, 404}
    elif scenario_id == "role_bound_read":
        blocked = first_status in {403, 404} and second_status == 200
    elif scenario_id == "plan_entitlement_read":
        blocked = first_status in {402, 403, 404} and second_status == 200
    return PairEvaluation("blocked" if blocked else "inconclusive", finding, control)


__all__ = [
    "ADAPTER_REGISTRY", "PairEvaluation", "PreparedAction", "evaluate_pair", "prepare_action",
]
