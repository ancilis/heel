"""Saved regression definitions derived from verified, signed, terminal paired-runner results.

A saved regression is data, never authority. It records which observed catalog finding a
later, separately approved replay should expect to be ``blocked``; it carries no grant,
signature, credential handle, raw fixture value, response byte or local path. Replay must
compile a fresh single-scenario pair and obtain a new browser approval and one-shot grant.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from heel.canary_contracts import canonical_digest
from heel.runner.catalog import CATALOG_BY_ID
from heel.runner.openapi_routes import normalize_route_template

if TYPE_CHECKING:
    from heel.runner.store import RunnerStore


SAVED_REGRESSIONS_SCHEMA = "heel.runner-saved-regressions.v1"
FIXTURE_BINDINGS_DOMAIN = "heel.runner-regression-fixture-bindings.v1"
MAX_SAVED_REGRESSIONS = 100
EXPECTED_OUTCOME = "blocked"

_RUN_ID = re.compile(r"^crun_[A-Za-z0-9_-]{1,64}$", flags=re.ASCII)
_REGRESSION_ID = re.compile(r"^rreg_[0-9a-f]{24}$", flags=re.ASCII)
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$", flags=re.ASCII)
_DIGEST = re.compile(r"^[0-9a-f]{64}$", flags=re.ASCII)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$", flags=re.ASCII)
_MAX_MS = (1 << 53) - 1

RECORD_FIELDS = (
    "regression_id", "name", "source_run_id", "scenario_id", "adapter_version",
    "method", "route_template", "fixture_bindings_sha256",
    "findings_projection_digest", "approval_projection_digest", "manifest_digest",
    "grant_id", "grant_digest",
    "workspace_id", "project_id", "environment_id", "origin",
    "runner_id", "runner_key_id",
    "expected_outcome", "created_at_ms",
)
# Every field except the creation instant is a deterministic function of the source run.
_SOURCE_FIELDS = tuple(field for field in RECORD_FIELDS if field != "created_at_ms")


class SavedRegressionError(ValueError):
    """A fixed, non-reflecting refusal; never carries caller input."""


def _refuse() -> SavedRegressionError:
    return SavedRegressionError("saved regression source is not eligible")


def regression_id_for(source_run_id: str, scenario_id: str) -> str:
    if (
        type(source_run_id) is not str or _RUN_ID.fullmatch(source_run_id) is None
        or type(scenario_id) is not str or scenario_id not in CATALOG_BY_ID
    ):
        raise _refuse()
    digest = hashlib.sha256(f"{source_run_id}:{scenario_id}".encode("ascii")).hexdigest()
    return "rreg_" + digest[:24]


def fixture_bindings_sha256(bindings: Any) -> str:
    if (
        not isinstance(bindings, list) or len(bindings) > 20
        or any(
            not isinstance(item, Mapping) or set(item) != {"parameter_name", "fixture_id"}
            for item in bindings
        )
    ):
        raise _refuse()
    normalized = [
        {"parameter_name": item["parameter_name"], "fixture_id": item["fixture_id"]}
        for item in bindings
    ]
    return canonical_digest({"domain": FIXTURE_BINDINGS_DOMAIN, "fixture_bindings": normalized})


def validate_saved_regression(value: Any) -> dict[str, Any]:
    """Structurally validate one persisted definition; context binding is checked by the store."""
    if not isinstance(value, Mapping) or set(value) != set(RECORD_FIELDS):
        raise _refuse()
    record = {field: value[field] for field in RECORD_FIELDS}
    strings = [field for field in RECORD_FIELDS if field != "created_at_ms"]
    if any(type(record[field]) is not str for field in strings):
        raise _refuse()
    if (
        _NAME.fullmatch(record["name"]) is None
        or _REGRESSION_ID.fullmatch(record["regression_id"]) is None
        or record["scenario_id"] not in CATALOG_BY_ID
        or record["regression_id"]
        != regression_id_for(record["source_run_id"], record["scenario_id"])
        or record["adapter_version"] != CATALOG_BY_ID[record["scenario_id"]]["adapter_version"]
        or record["method"] not in CATALOG_BY_ID[record["scenario_id"]]["allowed_methods"]
        or record["expected_outcome"] != EXPECTED_OUTCOME
        or not record["origin"].startswith(("https://", "http://"))
        or len(record["origin"]) > 2048
        or any(
            _DIGEST.fullmatch(record[field]) is None
            for field in (
                "fixture_bindings_sha256", "findings_projection_digest",
                "approval_projection_digest", "manifest_digest", "grant_digest",
            )
        )
        or any(
            _IDENTIFIER.fullmatch(record[field]) is None
            for field in (
                "grant_id", "workspace_id", "project_id", "environment_id",
                "runner_id", "runner_key_id",
            )
        )
    ):
        raise _refuse()
    created = record["created_at_ms"]
    if isinstance(created, bool) or not isinstance(created, int) or not 0 < created <= _MAX_MS:
        raise _refuse()
    try:
        route, _placeholders = normalize_route_template(record["route_template"])
    except (TypeError, ValueError):
        raise _refuse() from None
    if route != record["route_template"]:
        raise _refuse()
    return record


def same_source(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return all(left[field] == right[field] for field in _SOURCE_FIELDS)


def load_terminal_local_view(store: "RunnerStore", run_id: str) -> dict[str, Any]:
    """Return the store-verified signed redacted local view of one terminal run only."""
    if type(run_id) is not str or _RUN_ID.fullmatch(run_id) is None:
        raise _refuse()
    if store.load_run(run_id)["state"] != "terminal":
        raise _refuse()
    view = store.load_final_projections(run_id)["local_view"]
    if view["operational_projection"]["lifecycle_phase"] != "terminal":
        raise _refuse()
    return view


def derive_saved_regression(
    store: "RunnerStore", *, run_id: str, scenario_id: str, name: str, now_ms: int,
) -> dict[str, Any]:
    """Derive one definition from verified stored artifacts only; never writes.

    The source must be a terminal local run whose stored grant, approved manifest/projection
    pair and signed final projections all bind each other and the current bound context,
    and whose result for ``scenario_id`` is ``observed`` with a finding. A route match alone
    never establishes context: method, route and fixture bindings come from the immutable
    approved manifest the grant names.
    """
    if (
        type(scenario_id) is not str or scenario_id not in CATALOG_BY_ID
        or isinstance(now_ms, bool) or not isinstance(now_ms, int) or not 0 < now_ms <= _MAX_MS
    ):
        raise _refuse()
    regression_id = regression_id_for(run_id, scenario_id)
    state = store.load_run(run_id)
    grant = store.load_run_grant(run_id)
    approval = grant["approval"]
    if (
        grant["run_id"] != run_id
        or grant["grant_id"] != state["grant_id"]
        or grant["grant_digest"] != state["grant_digest"]
        or approval["manifest_digest"] != state["manifest_digest"]
    ):
        raise _refuse()
    # Re-verifies the bound runner signature and exact context of the approved pair.
    manifest, projection = store.load_approved_pair(approval["projection_id"])
    context = store.load_context()
    identity = store.load_binding()["identity"]
    if (
        projection["projection_digest"] != approval["projection_digest"]
        or manifest["manifest_digest"] != approval["manifest_digest"]
        or projection["manifest_digest"] != manifest["manifest_digest"]
        or grant["environment"] != manifest["environment"]
        or grant["workspace_id"] != context.workspace_id
        or grant["project_id"] != context.project_id
        or manifest["environment"]["origin"] != context.origin
        or manifest["environment"]["environment_id"] != context.environment_id
        or grant["runner_binding"]["runner_id"] != identity["runner_id"]
        or grant["runner_binding"]["runner_key_id"] != identity["runner_key_id"]
    ):
        raise _refuse()
    # Re-verifies both final signatures against the run's reserved (= bound) runner key.
    view = load_terminal_local_view(store, run_id)
    findings = view["findings_projection"]
    operational = view["operational_projection"]
    for record in (findings, operational):
        if (
            record["run_id"] != run_id
            or record["grant_id"] != grant["grant_id"]
            or record["grant_digest"] != grant["grant_digest"]
            or record["manifest_digest"] != manifest["manifest_digest"]
            or record["approval_projection_digest"] != projection["projection_digest"]
            or record["workspace_id"] != context.workspace_id
            or record["project_id"] != context.project_id
        ):
            raise _refuse()
    if findings["environment_id"] != context.environment_id:
        raise _refuse()
    results = [item for item in findings["scenario_results"] if item["scenario_id"] == scenario_id]
    scenarios = [item for item in manifest["scenarios"] if item["scenario_id"] == scenario_id]
    actions = [item for item in manifest["actions"] if item["scenario_id"] == scenario_id]
    if len(results) != 1 or len(scenarios) != 1 or not actions:
        raise _refuse()
    result = results[0]
    if result["assessment_outcome"] != "observed" or result["finding"] is None:
        raise _refuse()
    route = {"method": actions[0]["method"], "route_template": actions[0]["route_template"]}
    bindings = actions[0]["fixture_bindings"]
    if (
        result["route"] != route
        or result["adapter_version"] != scenarios[0]["adapter_version"]
        or any(
            action["method"] != route["method"]
            or action["route_template"] != route["route_template"]
            or action["fixture_bindings"] != bindings
            or action["adapter_version"] != scenarios[0]["adapter_version"]
            for action in actions
        )
    ):
        raise _refuse()
    return validate_saved_regression({
        "regression_id": regression_id,
        "name": name,
        "source_run_id": run_id,
        "scenario_id": scenario_id,
        "adapter_version": scenarios[0]["adapter_version"],
        "method": route["method"],
        "route_template": route["route_template"],
        "fixture_bindings_sha256": fixture_bindings_sha256(bindings),
        "findings_projection_digest": findings["projection_digest"],
        "approval_projection_digest": projection["projection_digest"],
        "manifest_digest": manifest["manifest_digest"],
        "grant_id": grant["grant_id"],
        "grant_digest": grant["grant_digest"],
        "workspace_id": context.workspace_id,
        "project_id": context.project_id,
        "environment_id": context.environment_id,
        "origin": context.origin,
        "runner_id": identity["runner_id"],
        "runner_key_id": identity["runner_key_id"],
        "expected_outcome": EXPECTED_OUTCOME,
        "created_at_ms": now_ms,
    })


__all__ = [
    "EXPECTED_OUTCOME", "MAX_SAVED_REGRESSIONS", "RECORD_FIELDS", "SAVED_REGRESSIONS_SCHEMA",
    "SavedRegressionError", "derive_saved_regression", "fixture_bindings_sha256",
    "load_terminal_local_view", "regression_id_for", "same_source", "validate_saved_regression",
]
