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


def _verified_terminal_run(store: "RunnerStore", run_id: str) -> dict[str, Any]:
    """Load one terminal run whose grant, approved pair and signed finals bind each other.

    Every artifact must also bind the current bound context and runner identity. Shared by
    saving a definition and recording a replay result; it never writes.
    """
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
    return {
        "grant": grant, "manifest": manifest, "projection": projection, "findings": findings,
        "operational": operational, "context": context, "identity": identity,
    }


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
    verified = _verified_terminal_run(store, run_id)
    manifest, projection = verified["manifest"], verified["projection"]
    grant, findings = verified["grant"], verified["findings"]
    context, identity = verified["context"], verified["identity"]
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

# --- Replay: a fresh single-scenario plan and its verified result -------------------------
#
# A replay association is local provenance, never authority: it ties one saved definition (by
# its digest) to one fresh compiled projection the serve owner submits for a new browser
# approval. Only a terminal run whose stored grant names that exact projection, and whose
# signed finals verify, can produce a result. Identifiers and digests only.

REPLAYS_SCHEMA = "heel.runner-regression-replays.v1"
RESULTS_SCHEMA = "heel.runner-regression-results.v1"
DEFINITION_DOMAIN = "heel.runner-regression-definition.v1"
MAX_REGRESSION_REPLAYS = 200
MAX_REGRESSION_RESULTS = 200
REPLAY_FIELDS = (
    "regression_id", "definition_digest", "projection_id", "projection_digest",
    "manifest_digest", "binding_digest", "created_at_ms",
)
RESULT_FIELDS = (
    "regression_id", "definition_digest", "run_id", "projection_id", "projection_digest",
    "manifest_digest", "grant_id", "grant_digest", "findings_projection_digest",
    "assessment_outcome", "execution_disposition", "outcome", "recorded_at_ms",
)
RESULT_OUTCOMES = ("pass", "fail", "inconclusive")
_ASSESSMENTS = frozenset({"blocked", "observed", "inconclusive"})
_DISPOSITIONS = frozenset({"completed", "incomplete", "failed", "stopped"})


def _instant(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= _MAX_MS:
        raise _refuse()
    return value


def _closed(value: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise _refuse()
    return {field: value[field] for field in fields}


def _check_strings(record: Mapping[str, Any], digests: tuple[str, ...], identifiers: tuple[str, ...]) -> None:
    if (
        type(record["regression_id"]) is not str
        or _REGRESSION_ID.fullmatch(record["regression_id"]) is None
        or any(type(record[field]) is not str or _DIGEST.fullmatch(record[field]) is None
               for field in digests)
        or any(type(record[field]) is not str or _IDENTIFIER.fullmatch(record[field]) is None
               for field in identifiers)
    ):
        raise _refuse()


def definition_digest(regression: Mapping[str, Any]) -> str:
    """Domain-separated digest of one validated saved definition (its full record)."""
    return canonical_digest({"domain": DEFINITION_DOMAIN, "regression": validate_saved_regression(regression)})


def validate_regression_replay(value: Any) -> dict[str, Any]:
    record = _closed(value, REPLAY_FIELDS)
    _check_strings(
        record, ("definition_digest", "projection_digest", "manifest_digest", "binding_digest"),
        ("projection_id",),
    )
    _instant(record["created_at_ms"])
    return record


def outcome_for(assessment_outcome: str, execution_disposition: str) -> str:
    """``observed`` fails; ``blocked`` passes only for a completed run; all else is inconclusive."""
    if assessment_outcome == "observed":
        return "fail"
    if assessment_outcome == "blocked" and execution_disposition == "completed":
        return "pass"
    return "inconclusive"


def validate_regression_result(value: Any) -> dict[str, Any]:
    record = _closed(value, RESULT_FIELDS)
    _check_strings(
        record,
        ("definition_digest", "projection_digest", "manifest_digest", "grant_digest",
         "findings_projection_digest"),
        ("projection_id", "grant_id"),
    )
    if (
        type(record["run_id"]) is not str or _RUN_ID.fullmatch(record["run_id"]) is None
        or type(record["assessment_outcome"]) is not str
        or record["assessment_outcome"] not in _ASSESSMENTS
        or type(record["execution_disposition"]) is not str
        or record["execution_disposition"] not in _DISPOSITIONS
        or record["outcome"] != outcome_for(record["assessment_outcome"], record["execution_disposition"])
    ):
        raise _refuse()
    _instant(record["recorded_at_ms"])
    return record


def same_result(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return all(left[field] == right[field] for field in RESULT_FIELDS if field != "recorded_at_ms")


def _require_bound_context(regression: Mapping[str, Any], context: Any, identity: Mapping[str, Any]) -> None:
    if (
        regression["workspace_id"] != context.workspace_id
        or regression["project_id"] != context.project_id
        or regression["environment_id"] != context.environment_id
        or regression["origin"] != context.origin
        or regression["runner_id"] != identity["runner_id"]
        or regression["runner_key_id"] != identity["runner_key_id"]
        or dict(identity["adapter_versions"]).get(regression["scenario_id"]) != regression["adapter_version"]
    ):
        raise _refuse()


def check_replay_inputs(store: "RunnerStore", regression: Mapping[str, Any]) -> None:
    """Before compiling: the bound context, identity, inventory and mapping equal the definition."""
    regression = validate_saved_regression(regression)
    _require_bound_context(regression, store.load_context(), store.load_binding()["identity"])
    coordinate = (regression["method"], regression["route_template"])
    if coordinate not in {(item["method"], item["route_template"]) for item in store.list_routes()}:
        raise _refuse()
    mappings = [item for item in store.list_mappings() if item["scenario_id"] == regression["scenario_id"]]
    if (
        len(mappings) != 1
        or (mappings[0]["method"], mappings[0]["route_template"]) != coordinate
        or fixture_bindings_sha256(mappings[0]["fixture_bindings"]) != regression["fixture_bindings_sha256"]
    ):
        raise _refuse()


def check_replay_pair(
    regression: Mapping[str, Any], manifest: Mapping[str, Any], projection: Mapping[str, Any],
    *, context: Any, identity: Mapping[str, Any],
) -> None:
    """The fresh compiled pair is exactly the definition's one scenario, route and fixtures.

    Run after compiling and again under the queue lock, so a mapping changed between the
    guard and the compiler can never widen what is queued, and again when recording.
    """
    regression = validate_saved_regression(regression)
    _require_bound_context(regression, context, identity)
    scenario_id = regression["scenario_id"]
    expected_scenarios = [{
        "ordinal": 0, "scenario_id": scenario_id, "adapter_version": regression["adapter_version"],
    }]
    actions, shown = manifest["actions"], projection["actions"]
    roles = list(CATALOG_BY_ID[scenario_id]["semantic_roles"])
    if (
        manifest["scenarios"] != expected_scenarios or projection["scenarios"] != expected_scenarios
        or [action["semantic_auth_role"] for action in actions] != roles
        or len(shown) != len(actions)
        or projection["manifest_digest"] != manifest["manifest_digest"]
        or manifest["workspace_id"] != context.workspace_id
        or manifest["project_id"] != context.project_id
        or projection["workspace_id"] != context.workspace_id
        or projection["project_id"] != context.project_id
        or manifest["environment"] != projection["environment"]
        or manifest["environment"]["origin"] != context.origin
        or manifest["environment"]["environment_id"] != context.environment_id
        or manifest["runner"]["runner_id"] != identity["runner_id"]
        or manifest["runner"]["runner_key_id"] != identity["runner_key_id"]
        or projection["runner"]["runner_id"] != identity["runner_id"]
        or projection["runner"]["runner_key_id"] != identity["runner_key_id"]
        # A replay is a freshly compiled plan, never the source run's approved pair.
        or projection["projection_digest"] == regression["approval_projection_digest"]
        or manifest["manifest_digest"] == regression["manifest_digest"]
    ):
        raise _refuse()
    for action, public in zip(actions, shown):
        if (
            action["scenario_id"] != scenario_id
            or action["adapter_version"] != regression["adapter_version"]
            or action["method"] != regression["method"]
            or action["route_template"] != regression["route_template"]
            or fixture_bindings_sha256(action["fixture_bindings"]) != regression["fixture_bindings_sha256"]
            or any(public[key] != action[key] for key in (
                "scenario_id", "adapter_version", "method", "route_template", "semantic_auth_role"))
        ):
            raise _refuse()


def new_regression_replay(
    regression: Mapping[str, Any], manifest: Mapping[str, Any], projection: Mapping[str, Any],
    *, binding_digest: str, now_ms: int,
) -> dict[str, Any]:
    return validate_regression_replay({
        "regression_id": regression["regression_id"],
        "definition_digest": definition_digest(regression),
        "projection_id": projection["projection_id"],
        "projection_digest": projection["projection_digest"],
        "manifest_digest": manifest["manifest_digest"],
        "binding_digest": binding_digest,
        "created_at_ms": now_ms,
    })


def derive_regression_result(
    store: "RunnerStore", *, regression: Mapping[str, Any], replay: Mapping[str, Any],
    run_id: str, now_ms: int,
) -> dict[str, Any]:
    """Derive one result from a verified terminal run of the exact associated replay; never writes."""
    regression = validate_saved_regression(regression)
    replay = validate_regression_replay(replay)
    _instant(now_ms)
    if (
        type(run_id) is not str or _RUN_ID.fullmatch(run_id) is None
        or run_id == regression["source_run_id"]
        or replay["regression_id"] != regression["regression_id"]
        or replay["definition_digest"] != definition_digest(regression)
    ):
        raise _refuse()
    verified = _verified_terminal_run(store, run_id)
    manifest, projection, grant = verified["manifest"], verified["projection"], verified["grant"]
    findings, operational = verified["findings"], verified["operational"]
    approval = grant["approval"]
    if (
        approval["projection_id"] != replay["projection_id"]
        or approval["projection_digest"] != replay["projection_digest"]
        or approval["manifest_digest"] != replay["manifest_digest"]
        or projection["projection_id"] != replay["projection_id"]
        or projection["projection_digest"] != replay["projection_digest"]
        or manifest["manifest_digest"] != replay["manifest_digest"]
    ):
        raise _refuse()
    check_replay_pair(
        regression, manifest, projection, context=verified["context"], identity=verified["identity"],
    )
    results = findings["scenario_results"]
    if (
        len(results) != 1
        or results[0]["scenario_id"] != regression["scenario_id"]
        or results[0]["adapter_version"] != regression["adapter_version"]
        or results[0]["route"] != {
            "method": regression["method"], "route_template": regression["route_template"],
        }
    ):
        raise _refuse()
    assessment = results[0]["assessment_outcome"]
    disposition = operational["execution_disposition"]
    return validate_regression_result({
        "regression_id": regression["regression_id"],
        "definition_digest": replay["definition_digest"],
        "run_id": run_id,
        "projection_id": replay["projection_id"],
        "projection_digest": replay["projection_digest"],
        "manifest_digest": replay["manifest_digest"],
        "grant_id": grant["grant_id"],
        "grant_digest": grant["grant_digest"],
        "findings_projection_digest": findings["projection_digest"],
        "assessment_outcome": assessment,
        "execution_disposition": disposition,
        "outcome": outcome_for(assessment, disposition),
        "recorded_at_ms": now_ms,
    })


__all__ = [
    "EXPECTED_OUTCOME", "MAX_REGRESSION_REPLAYS", "MAX_REGRESSION_RESULTS", "MAX_SAVED_REGRESSIONS",
    "RECORD_FIELDS", "REPLAYS_SCHEMA", "REPLAY_FIELDS", "RESULTS_SCHEMA", "RESULT_FIELDS",
    "RESULT_OUTCOMES", "SAVED_REGRESSIONS_SCHEMA", "SavedRegressionError", "check_replay_inputs",
    "check_replay_pair", "definition_digest", "derive_regression_result", "derive_saved_regression",
    "fixture_bindings_sha256", "load_terminal_local_view", "new_regression_replay", "outcome_for",
    "regression_id_for", "same_result", "same_source", "validate_regression_replay",
    "validate_regression_result", "validate_saved_regression",
]
