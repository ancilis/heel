from dataclasses import fields
from types import MappingProxyType

import pytest

from heel.runner.adapters import ADAPTER_REGISTRY, PreparedAction, evaluate_pair, prepare_action
from heel.runner.catalog import CATALOG, CATALOG_BY_ID


def action(scenario_id, role, *, method="GET", profile="bearer", route="/items/{id}"):
    catalog = CATALOG_BY_ID[scenario_id]
    return {
        "ordinal": 0,
        "scenario_id": scenario_id,
        "adapter_version": "1",
        "method": method,
        "route_template": route,
        "fixture_bindings": [{"parameter_name": "id", "fixture_id": "local-id"}],
        "semantic_auth_role": role,
        "auth_profile": profile,
        "assertion_class": catalog["assertion_class"],
        "allowed_status_codes": list(catalog["allowed_status_codes"]),
        "allowed_body_shapes": list(catalog["allowed_body_shapes"]),
        "side_effect_class": "read_only",
    }


def test_registry_exactly_matches_catalog_order_and_is_deeply_immutable():
    assert tuple(ADAPTER_REGISTRY) == tuple(item["scenario_id"] for item in CATALOG)
    assert len(ADAPTER_REGISTRY) == 4
    for scenario_id, adapter in ADAPTER_REGISTRY.items():
        catalog = CATALOG_BY_ID[scenario_id]
        assert isinstance(adapter, MappingProxyType)
        assert adapter["scenario_id"] == scenario_id
        assert adapter["adapter_version"] == catalog["adapter_version"]
        assert adapter["assertion_class"] == catalog["assertion_class"]
        assert adapter["semantic_roles"] == catalog["semantic_roles"]
        assert adapter["allowed_methods"] == catalog["allowed_methods"]
        assert adapter["side_effect_class"] == "read_only"
    with pytest.raises(TypeError):
        ADAPTER_REGISTRY["anonymous_authenticated_read"] = {}  # type: ignore[index]


def test_prepared_action_is_closed_immutable_and_transport_free():
    assert {item.name for item in fields(PreparedAction)} == {
        "scenario_id", "adapter_version", "method", "route",
        "semantic_auth_role", "auth_profile", "side_effect_class",
    }
    source = action(
        "anonymous_authenticated_read", "anonymous",
        method="HEAD", profile="anonymous",
    )
    prepared = prepare_action(source, {"id": "local-id"})
    assert prepared.route == "/items/local-id"
    assert prepared.side_effect_class == "read_only"
    with pytest.raises((AttributeError, TypeError)):
        prepared.route = "/changed"  # type: ignore[misc]


def test_prepare_action_rejects_widened_method_role_profile_and_fixture_surface():
    base = action("role_bound_read", "lower_privilege")
    assert prepare_action(base, {"id": "local-id"}).auth_profile == "bearer"
    for mutation in (
        {"method": "POST"},
        {"semantic_auth_role": "anonymous"},
        {"auth_profile": "anonymous"},
        {"side_effect_class": "write"},
        {"assertion_class": "other"},
        {"allowed_status_codes": [200, 500]},
        {"allowed_body_shapes": ["text"]},
        {"url": "https://attacker.example"},
        {"headers": {"X-Anything": "value"}},
        {"plugin": "dynamic"},
        {"model": "provider"},
    ):
        with pytest.raises(ValueError):
            prepare_action({**base, **mutation}, {"id": "local-id"})
    for fixtures in (
        {}, {"id": "replacement"}, {"id": "../escaped"},
        {"id": "x/y"}, {"id": "%2e"},
    ):
        with pytest.raises(ValueError):
            prepare_action(base, fixtures)


def test_prepared_route_uses_only_the_manifest_bound_fixture_segment():
    source = action("object_ownership_read", "object_owner")
    assert prepare_action(source, {"id": "local-id"}).route == "/items/local-id"
    assert prepare_action(source).route == "/items/local-id"
    with pytest.raises(ValueError):
        prepare_action(source, {"id": "other-approved-looking-id"})


@pytest.mark.parametrize(
    "scenario_id,first,second,blocked",
    [
        ("anonymous_authenticated_read", 401, 200, True),
        ("anonymous_authenticated_read", 403, 200, True),
        ("anonymous_authenticated_read", 404, 200, True),
        ("object_ownership_read", 200, 403, True),
        ("object_ownership_read", 200, 404, True),
        ("role_bound_read", 403, 200, True),
        ("role_bound_read", 404, 200, True),
        ("plan_entitlement_read", 402, 200, True),
        ("plan_entitlement_read", 403, 200, True),
        ("plan_entitlement_read", 404, 200, True),
        ("anonymous_authenticated_read", 200, 401, False),
        ("object_ownership_read", 404, 404, False),
        ("role_bound_read", 200, 403, False),
        ("plan_entitlement_read", 200, 402, False),
    ],
)
def test_exact_catalog_order_blocked_matrix(scenario_id, first, second, blocked):
    assert evaluate_pair(scenario_id, first, second).outcome == "inconclusive"
    positive_first = scenario_id == "object_ownership_read"
    if blocked:
        assert evaluate_pair(scenario_id, first, second,
            first_protected=positive_first, second_protected=not positive_first).outcome == "blocked"


@pytest.mark.parametrize("scenario_id", tuple(CATALOG_BY_ID))
def test_observed_requires_two_200s_and_every_other_pair_is_inconclusive(scenario_id):
    allowed = CATALOG_BY_ID[scenario_id]["allowed_status_codes"]
    for first in allowed:
        for second in allowed:
            result = evaluate_pair(scenario_id, first, second)
            if first == second == 200:
                assert result.outcome == "inconclusive"
            elif result.outcome != "blocked":
                assert result.outcome == "inconclusive"
            assert result.finding and result.control
    assert evaluate_pair(scenario_id, 500, 200).outcome == "inconclusive"
    assert evaluate_pair(scenario_id, 200, 500).outcome == "inconclusive"


def test_body_shape_contract_is_closed_and_head_is_always_absent():
    assert evaluate_pair(
        "anonymous_authenticated_read", 401, 200,
        method="HEAD", first_body_shape="absent", second_body_shape="absent",
    ).outcome == "inconclusive"
    assert evaluate_pair(
        "role_bound_read", 403, 200,
        first_body_shape="json_object", second_body_shape="absent",
    ).outcome == "inconclusive"
    assert evaluate_pair(
        "role_bound_read", 403, 200,
        first_body_shape="text", second_body_shape="absent",
    ).outcome == "inconclusive"
    assert evaluate_pair(
        "anonymous_authenticated_read", 401, 200,
        method="HEAD", first_body_shape="json_object", second_body_shape="absent",
    ).outcome == "inconclusive"
