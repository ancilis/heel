"""The immutable launch catalog for customer-local read-only canaries."""
from __future__ import annotations

from types import MappingProxyType


CATALOG_IDS = (
    "anonymous_authenticated_read",
    "object_ownership_read",
    "role_bound_read",
    "plan_entitlement_read",
)
AUTH_PROFILES = frozenset({"anonymous", "bearer", "cookie_jar", "x_api_key"})

# Cookie behavior is a closed jar capability; no launch profile accepts arbitrary
# header names or cookie text. X-API-Key is the sole fixed custom header.
AUTH_PROFILE_DEFINITIONS = MappingProxyType({
    "anonymous": MappingProxyType({"credential_required": False, "transport": "none"}),
    "bearer": MappingProxyType({"credential_required": True, "transport": "bearer"}),
    "cookie_jar": MappingProxyType({"credential_required": True, "transport": "cookie_jar"}),
    "x_api_key": MappingProxyType({
        "credential_required": True, "transport": "fixed_header", "header_name": "X-API-Key",
    }),
})


def _entry(
    ordinal: int,
    scenario_id: str,
    auth_profile: str,
    assertion_class: str,
    statuses: tuple[int, ...],
    body_shapes: tuple[str, ...],
):
    return MappingProxyType({
        "ordinal": ordinal,
        "scenario_id": scenario_id,
        "adapter_version": "1",
        "semantic_auth_role": scenario_id,
        "auth_profile": auth_profile,
        "assertion_class": assertion_class,
        "allowed_status_codes": tuple(sorted(statuses)),
        "allowed_body_shapes": tuple(sorted(body_shapes)),
        "side_effect_class": "read_only",
    })


CATALOG = (
    _entry(0, CATALOG_IDS[0], "anonymous", "anonymous_authenticated", (200,), ("absent",)),
    _entry(1, CATALOG_IDS[1], "bearer", "object_ownership", (200, 403, 404),
           ("absent", "json_object")),
    _entry(2, CATALOG_IDS[2], "cookie_jar", "role_boundary", (200, 403, 404),
           ("absent", "json_object")),
    _entry(3, CATALOG_IDS[3], "x_api_key", "plan_entitlement", (200, 402, 403, 404),
           ("absent", "json_object")),
)
CATALOG_BY_ID = MappingProxyType({entry["scenario_id"]: entry for entry in CATALOG})
