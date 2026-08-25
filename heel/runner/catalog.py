"""Immutable differential read scenarios for the verified-canary launch."""
from __future__ import annotations

from types import MappingProxyType


CATALOG_IDS = (
    "anonymous_authenticated_read",
    "object_ownership_read",
    "role_bound_read",
    "plan_entitlement_read",
)
SEMANTIC_ROLES = frozenset({
    "anonymous",
    "authenticated",
    "object_owner",
    "non_owner",
    "lower_privilege",
    "higher_privilege",
    "lower_plan",
    "higher_plan",
})
AUTH_PROFILES = frozenset({"anonymous", "bearer", "cookie_jar", "x_api_key"})
NONANONYMOUS_AUTH_PROFILES = AUTH_PROFILES - {"anonymous"}

# No launch profile accepts arbitrary header names or raw cookie header text.
AUTH_PROFILE_DEFINITIONS = MappingProxyType({
    "anonymous": MappingProxyType({"credential_required": False, "transport": "none"}),
    "bearer": MappingProxyType({"credential_required": True, "transport": "bearer"}),
    "cookie_jar": MappingProxyType({"credential_required": True, "transport": "closed_cookie_jar"}),
    "x_api_key": MappingProxyType({
        "credential_required": True,
        "transport": "fixed_header",
        "header_name": "X-API-Key",
    }),
})


def _entry(
    ordinal: int,
    scenario_id: str,
    semantic_roles: tuple[str, str],
    allowed_methods: tuple[str, ...],
    assertion_class: str,
    statuses: tuple[int, ...],
):
    return MappingProxyType({
        "ordinal": ordinal,
        "scenario_id": scenario_id,
        "adapter_version": "1",
        "semantic_roles": semantic_roles,
        "allowed_methods": allowed_methods,
        "assertion_class": assertion_class,
        "allowed_status_codes": tuple(sorted(statuses)),
        "allowed_body_shapes": ("absent", "json_object"),
        "side_effect_class": "read_only",
    })


CATALOG = (
    _entry(
        0,
        CATALOG_IDS[0],
        ("anonymous", "authenticated"),
        ("GET", "HEAD"),
        "anonymous_authenticated",
        (200, 401, 403, 404),
    ),
    _entry(
        1,
        CATALOG_IDS[1],
        ("object_owner", "non_owner"),
        ("GET",),
        "object_ownership",
        (200, 403, 404),
    ),
    _entry(
        2,
        CATALOG_IDS[2],
        ("lower_privilege", "higher_privilege"),
        ("GET",),
        "role_boundary",
        (200, 403, 404),
    ),
    _entry(
        3,
        CATALOG_IDS[3],
        ("lower_plan", "higher_plan"),
        ("GET",),
        "plan_entitlement",
        (200, 402, 403, 404),
    ),
)
CATALOG_BY_ID = MappingProxyType({entry["scenario_id"]: entry for entry in CATALOG})
ROLE_TO_SCENARIO = MappingProxyType({
    role: entry["scenario_id"]
    for entry in CATALOG
    for role in entry["semantic_roles"]
})
