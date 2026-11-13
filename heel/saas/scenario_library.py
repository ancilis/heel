"""Workspace scenario library, private custom revisions, and run-frozen selection provenance.

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Three bounded customer surfaces over the existing open-core library (no new engine):

* A read-only listing of every effective library scenario (builtins, semantic families, JSON
  packs) plus the workspace's current private custom revisions. Applicability is always
  ``unknown`` here: a listing never claims a scenario applies to the product.
* Immutable, digest-addressed custom revisions validated by ``validate_scenario``. A custom
  scenario is analysis-only unless the customer explicitly opts in to ONE closed runner check
  with the exact fixed coverage acknowledgement; ``kind`` is never consulted for that.
* Run bindings frozen before approval: an association from selected library/custom revisions to
  literal action tuples of the stored, re-validated signed approval projection. Bindings are
  accepted only while the approval is awaiting and unexpired, are write-once, and carry a bounded
  display snapshot so later library or custom edits can never relabel an old run.

Customer definitions never leave the workspace and are never written to package data. Error
responses carry closed codes plus validator messages; definitions are not logged.
"""
from __future__ import annotations

from dataclasses import asdict
import json
import re
import sqlite3
import time
from types import MappingProxyType
from typing import Any, Callable, Mapping

import heel
from heel.canary_contracts import validate_approval_projection
from heel.review_contract import stable_json, stable_json_hash
from heel.runner.catalog import CATALOG_BY_ID, CATALOG_IDS
from heel.scenario_validate import validate_scenario
from heel.scenarios import list_scenarios


LIBRARY_SCHEMA = "heel.scenario-library.v1"
CUSTOM_REQUEST_SCHEMA = "heel.custom-scenario.v1"
BINDINGS_REQUEST_SCHEMA = "heel.run-scenario-bindings.v1"
BINDINGS_VIEW_SCHEMA = "heel.run-scenario-bindings-view.v1"
BINDING_POLICY_VERSION = 1
CUSTOM_ID_PREFIXES = ("sc.community.", "sc.internal.")
MAX_BINDING_ITEMS = 8
MAX_CUSTOM_DEFINITION_BYTES = 4096
MAX_CUSTOM_SCENARIOS_PER_WORKSPACE = 16
MAX_REVISIONS_PER_SCENARIO = 32
MAX_CUSTOM_JSON_DEPTH = 8
MAX_CUSTOM_JSON_NODES = 256
_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ROUTE_TEMPLATE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@/{}-]{0,511}$")
_RUN = re.compile(r"^crun_[0-9a-f]{32}$")

# The only closed library-to-runner bindings. Each library entry's static objective is broader
# than the executed differential read; the coverage statement says so wherever it is shown.
LIBRARY_EXECUTION_BINDINGS = MappingProxyType({
    "sc.endpoint.hidden": "anonymous_authenticated_read",
    "sc.research.unintended_endpoints.forced_browsing_admin": "anonymous_authenticated_read",
    "sc.flag.tiergate": "plan_entitlement_read",
    "sc.research.license_entitlement.tier_gate_client_trusted": "plan_entitlement_read",
})
# Custom scenarios may opt in only to the two launch actions with a positive-control fixture.
CUSTOM_BINDABLE_CATALOG_IDS = ("anonymous_authenticated_read", "plan_entitlement_read")
CUSTOM_EVALUATION_FIELDS = frozenset({
    "id", "category", "objective", "kind", "success_criterion", "severity_model",
    "recommended_control", "containment_limits", "applies_when", "pack", "probe_strategy",
    "investigation_signals", "exploitability_reduction",
})
_RUNNER_SETUP_STEPS = (
    "heel runner import-openapi",
    "heel runner credential add --role <role>",
    "heel runner map --scenario <catalog id>",
    "protected_canary marker fixture served to the positive-control role",
)
_DISPLAY_LIMIT = 500
_DISPLAY_BYTE_LIMIT = 1024


class ScenarioLibraryError(Exception):
    """A closed customer-facing failure. ``details`` carries validator text only."""

    def __init__(self, status: int, code: str, *, errors: list[str] | None = None,
                 warnings: list[str] | None = None):
        super().__init__(code)
        self.status = status
        self.code = code
        self.errors = list(errors or [])
        self.warnings = list(warnings or [])

    def body(self) -> dict:
        body: dict[str, Any] = {"schema_version": "heel.scenario-library-error.v1", "code": self.code}
        if self.errors or self.warnings:
            body["errors"] = self.errors
            body["warnings"] = self.warnings
        return body


def coverage_statement(catalog_scenario_id: str) -> str:
    """The fixed sentence a customer must acknowledge verbatim to bind a custom revision."""
    entry = CATALOG_BY_ID[catalog_scenario_id]
    methods = "/".join(entry["allowed_methods"])
    roles = " and ".join(entry["semantic_roles"])
    return (
        f"Executed check: {catalog_scenario_id} ({methods}, roles {roles}). "
        "The custom objective and its criterion are not executed; they are analysis-only."
    )


def library_coverage_statement(catalog_scenario_id: str) -> str:
    entry = CATALOG_BY_ID[catalog_scenario_id]
    methods = "/".join(entry["allowed_methods"])
    roles = " and ".join(entry["semantic_roles"])
    return (
        f"Executed check: {catalog_scenario_id} ({methods}, roles {roles}). "
        "The library objective beyond this check remains inferred; it is not executed."
    )


def _prerequisites(catalog_scenario_id: str) -> list[str]:
    entry = CATALOG_BY_ID[catalog_scenario_id]
    return [
        "methods: " + ", ".join(entry["allowed_methods"]),
        "roles: " + ", ".join(entry["semantic_roles"]),
        "statuses: " + ", ".join(str(code) for code in entry["allowed_status_codes"]),
        *_RUNNER_SETUP_STEPS,
    ]


def _canonical_number(value: Any) -> Any:
    # Integral floats collapse to integers so a browser JSON round trip keeps the same digest.
    if type(value) is float and value.is_integer():
        return int(value)
    if type(value) is list:
        return [_canonical_number(item) for item in value]
    if type(value) is dict:
        return {key: _canonical_number(item) for key, item in value.items()}
    return value


def _library_definition(scenario) -> dict:
    """The full effective evaluation definition of one library scenario (the digest subject)."""
    raw = asdict(scenario)
    definition = {
        "id": scenario.id,
        "category": scenario.category.value,
        "objective": scenario.objective,
        "kind": str(scenario.target_affordance_pattern.get("kind", "")),
        "probe_strategy": scenario.probe_strategy,
        "success_criterion": raw["success_criterion"],
        "investigation_signals": raw["investigation_signals"],
        "severity_model": raw["severity_model"],
        "applies_when": scenario.applies_when.value,
        "pack": scenario.pack.value,
        "source": scenario.source.value,
        "recommended_control": scenario.recommended_control,
        "containment_limits": raw["containment_limits"],
        "exploitability_reduction": scenario.exploitability_reduction,
        "handoff": scenario.handoff,
        "classification_impact": scenario.classification_impact,
        "mechanism_id": scenario.mechanism_id,
    }
    return _canonical_number(json.loads(stable_json(definition)))


def _build_library() -> tuple[tuple[dict, ...], str]:
    definitions = tuple(sorted((_library_definition(item) for item in list_scenarios()),
                               key=lambda item: item["id"]))
    ids = [item["id"] for item in definitions]
    if len(ids) != len(set(ids)):
        raise RuntimeError("scenario library contains duplicate identifiers")
    digest = stable_json_hash({
        "schema_version": "heel.scenario-library-digest.v1",
        "engine_version": heel.__version__,
        "definitions": list(definitions),
        "binding_policy": {
            "version": BINDING_POLICY_VERSION,
            "library": dict(sorted(LIBRARY_EXECUTION_BINDINGS.items())),
            "custom": list(CUSTOM_BINDABLE_CATALOG_IDS),
            "catalog_ids": list(CATALOG_IDS),
        },
    })
    return definitions, digest


_LIBRARY_DEFINITIONS, _LIBRARY_DIGEST = _build_library()
_LIBRARY_BY_ID = MappingProxyType({item["id"]: item for item in _LIBRARY_DEFINITIONS})
_LIBRARY_DEFINITION_DIGESTS = MappingProxyType({
    item["id"]: stable_json_hash(item) for item in _LIBRARY_DEFINITIONS
})

# Import-time closure of the binding policy against the real catalog and library.
if not set(LIBRARY_EXECUTION_BINDINGS) <= set(_LIBRARY_BY_ID):
    raise RuntimeError("library execution binding names an unknown library scenario")
if not set(LIBRARY_EXECUTION_BINDINGS.values()) <= set(CATALOG_IDS):
    raise RuntimeError("library execution binding names an unknown catalog check")
if not set(CUSTOM_BINDABLE_CATALOG_IDS) <= set(CATALOG_IDS):
    raise RuntimeError("custom binding policy names an unknown catalog check")


def library_digest() -> str:
    return _LIBRARY_DIGEST


def library_definition_digest(scenario_id: str) -> str | None:
    return _LIBRARY_DEFINITION_DIGESTS.get(scenario_id)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS workspace_custom_scenarios(
  workspace_id TEXT NOT NULL,
  scenario_id TEXT NOT NULL CHECK(length(scenario_id) BETWEEN 3 AND 128),
  revision INTEGER NOT NULL CHECK(revision>=1),
  definition_json TEXT NOT NULL CHECK(length(CAST(definition_json AS BLOB)) BETWEEN 2 AND 4096),
  definition_digest TEXT NOT NULL CHECK(length(definition_digest)=64 AND definition_digest NOT GLOB '*[^0-9a-f]*'),
  execution_binding_json TEXT CHECK(execution_binding_json IS NULL OR length(CAST(execution_binding_json AS BLOB)) BETWEEN 2 AND 1024),
  created_by TEXT NOT NULL,
  created_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, scenario_id, revision),
  FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id));
CREATE TRIGGER IF NOT EXISTS workspace_custom_scenarios_immutable
BEFORE UPDATE ON workspace_custom_scenarios
BEGIN SELECT RAISE(ABORT, 'custom scenario revisions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS workspace_custom_scenarios_no_delete
BEFORE DELETE ON workspace_custom_scenarios
BEGIN SELECT RAISE(ABORT, 'custom scenario revisions are immutable'); END;
CREATE TABLE IF NOT EXISTS run_scenario_bindings(
  workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, run_id TEXT NOT NULL, approval_id TEXT NOT NULL,
  projection_digest TEXT NOT NULL CHECK(length(projection_digest)=64 AND projection_digest NOT GLOB '*[^0-9a-f]*'),
  manifest_digest TEXT NOT NULL CHECK(length(manifest_digest)=64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
  catalog_scenario_id TEXT NOT NULL, method TEXT NOT NULL, route_template TEXT NOT NULL,
  library_scenario_id TEXT NOT NULL, source TEXT NOT NULL CHECK(source IN ('library','custom')),
  revision INTEGER CHECK((source='library' AND revision IS NULL) OR (source='custom' AND revision>=1)),
  definition_digest TEXT NOT NULL CHECK(length(definition_digest)=64 AND definition_digest NOT GLOB '*[^0-9a-f]*'),
  library_digest TEXT NOT NULL CHECK(length(library_digest)=64 AND library_digest NOT GLOB '*[^0-9a-f]*'),
  binding_version INTEGER NOT NULL CHECK(binding_version=1),
  display_json TEXT NOT NULL CHECK(length(CAST(display_json AS BLOB)) BETWEEN 2 AND 2048),
  bound_by TEXT NOT NULL, bound_at INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, project_ref, run_id, library_scenario_id),
  FOREIGN KEY(workspace_id, project_ref, run_id)
    REFERENCES canary_approval_projections(workspace_id, project_ref, run_id),
  FOREIGN KEY(workspace_id, project_ref, approval_id)
    REFERENCES canary_approval_projections(workspace_id, project_ref, approval_id));
CREATE TRIGGER IF NOT EXISTS run_scenario_bindings_immutable
BEFORE UPDATE ON run_scenario_bindings
BEGIN SELECT RAISE(ABORT, 'run scenario bindings are frozen'); END;
CREATE TRIGGER IF NOT EXISTS run_scenario_bindings_no_delete
BEFORE DELETE ON run_scenario_bindings
BEGIN SELECT RAISE(ABORT, 'run scenario bindings are frozen'); END;
"""


def _encoded_text_size(text: str) -> int:
    """UTF-8 bytes the text occupies inside the stored display JSON, escapes included."""
    return len(json.dumps(text, ensure_ascii=False).encode("utf-8")) - 2


def _bounded_text(value: Any) -> str:
    # Bounded by characters and by encoded bytes so the display snapshot always fits its column.
    text = str(value or "")
    if len(text) <= _DISPLAY_LIMIT and _encoded_text_size(text) <= _DISPLAY_BYTE_LIMIT:
        return text
    budget = _DISPLAY_BYTE_LIMIT - _encoded_text_size("…")
    kept: list[str] = []
    for char in text[: _DISPLAY_LIMIT - 1]:
        size = _encoded_text_size(char)
        if size > budget:
            break
        kept.append(char)
        budget -= size
    return "".join(kept) + "…"


def _json_shape_within_limits(value: Any) -> bool:
    stack = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_CUSTOM_JSON_NODES or depth > MAX_CUSTOM_JSON_DEPTH:
            return False
        if type(current) is dict:
            stack.extend((item, depth + 1) for item in current.values())
        elif type(current) is list:
            stack.extend((item, depth + 1) for item in current)
        elif current is not None and type(current) not in (str, int, float, bool):
            return False
    return True


class ScenarioLibraryService:
    """SQLite-backed library listing, custom revisions and run-frozen bindings."""

    def __init__(self, conn: sqlite3.Connection, *, clock: Callable[[], float] = time.time):
        self.conn = conn
        self.clock = clock
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)

    # --- listing ---------------------------------------------------------------------------
    def _library_row(self, definition: Mapping[str, Any]) -> dict:
        catalog = LIBRARY_EXECUTION_BINDINGS.get(definition["id"])
        return {
            "id": definition["id"],
            "source": "library",
            "revision": None,
            "definition_digest": _LIBRARY_DEFINITION_DIGESTS[definition["id"]],
            "definition": dict(definition),
            "mechanism_id": definition["mechanism_id"] or definition["id"],
            "applicability": "unknown",
            "applicability_rule": definition["applies_when"],
            "evidence_state": "inferred",
            "execution_support": "runner_supported" if catalog else "static_only",
            "catalog_scenario_id": catalog,
            "binding_version": BINDING_POLICY_VERSION if catalog else None,
            "coverage_statement": library_coverage_statement(catalog) if catalog else None,
            "prerequisites": _prerequisites(catalog) if catalog else [],
        }

    def _custom_row(self, row: sqlite3.Row | tuple) -> dict:
        definition = json.loads(row["definition_json"])
        binding = json.loads(row["execution_binding_json"]) if row["execution_binding_json"] else None
        catalog = binding["catalog_scenario_id"] if binding else None
        return {
            "id": row["scenario_id"],
            "source": "custom",
            "revision": int(row["revision"]),
            "definition_digest": row["definition_digest"],
            "definition": definition,
            "mechanism_id": definition["id"],
            "applicability": "unknown",
            "applicability_rule": definition.get("applies_when", "always"),
            "evidence_state": "customer_declared",
            "execution_support": "runner_supported" if catalog else "static_only",
            "catalog_scenario_id": catalog,
            "binding_version": BINDING_POLICY_VERSION if catalog else None,
            "coverage_statement": coverage_statement(catalog) if catalog else None,
            "prerequisites": _prerequisites(catalog) if catalog else [],
        }

    def _current_custom_rows(self, workspace_id: str) -> list:
        return self.conn.execute(
            "SELECT c.* FROM workspace_custom_scenarios c JOIN ("
            " SELECT scenario_id, MAX(revision) AS revision FROM workspace_custom_scenarios"
            " WHERE workspace_id=? GROUP BY scenario_id) m"
            " ON c.scenario_id=m.scenario_id AND c.revision=m.revision"
            " WHERE c.workspace_id=? ORDER BY c.scenario_id",
            (workspace_id, workspace_id),
        ).fetchall()

    def listing(self, workspace_id: str) -> dict:
        rows = [self._library_row(item) for item in _LIBRARY_DEFINITIONS]
        rows.extend(self._custom_row(row) for row in self._current_custom_rows(workspace_id))
        return {
            "schema_version": LIBRARY_SCHEMA,
            "library_digest": _LIBRARY_DIGEST,
            "engine_version": heel.__version__,
            "binding_version": BINDING_POLICY_VERSION,
            "custom_coverage_statements": {
                catalog: coverage_statement(catalog) for catalog in CUSTOM_BINDABLE_CATALOG_IDS
            },
            "scenarios": rows,
        }

    # --- custom revisions --------------------------------------------------------------------
    def create_custom(self, workspace_id: str, actor: str, body: Any) -> dict:
        if (type(body) is not dict
                or set(body) != {"schema_version", "definition", "supersedes_revision", "execution_binding"}
                or body.get("schema_version") != CUSTOM_REQUEST_SCHEMA):
            raise ScenarioLibraryError(400, "invalid_custom_request")
        definition = body["definition"]
        supersedes = body["supersedes_revision"]
        binding = body["execution_binding"]
        if supersedes is not None and (type(supersedes) is not int or supersedes < 1):
            raise ScenarioLibraryError(400, "invalid_custom_request")
        if type(definition) is not dict or not _json_shape_within_limits(definition):
            raise ScenarioLibraryError(400, "invalid_custom_request")
        try:
            canonical = _canonical_number(json.loads(stable_json(definition)))
        except (TypeError, ValueError):
            raise ScenarioLibraryError(400, "invalid_custom_request") from None
        serialized = stable_json(canonical)
        if len(serialized.encode("utf-8")) > MAX_CUSTOM_DEFINITION_BYTES:
            raise ScenarioLibraryError(400, "custom_definition_too_large")
        unknown = sorted(set(canonical) - CUSTOM_EVALUATION_FIELDS)
        if unknown:
            raise ScenarioLibraryError(
                400, "invalid_scenario",
                errors=[f"{name}: unsupported field for a custom scenario" for name in unknown[:8]],
            )
        result = validate_scenario(canonical)
        errors = list(result.errors)
        warnings = list(result.warnings)
        if "investigation_signals" in canonical:
            signals = validate_scenario({**canonical, "success_criterion": canonical["investigation_signals"]})
            errors.extend(
                "investigation_signals" + message[len("success_criterion"):]
                for message in signals.errors if message.startswith("success_criterion")
            )
        if errors:
            raise ScenarioLibraryError(400, "invalid_scenario", errors=errors, warnings=warnings)
        scenario_id = canonical["id"]
        if not scenario_id.startswith(CUSTOM_ID_PREFIXES) or not _ID.fullmatch(scenario_id):
            raise ScenarioLibraryError(
                400, "invalid_scenario",
                errors=["id: custom scenarios must use the sc.community. or sc.internal. namespace"],
            )
        if scenario_id in _LIBRARY_BY_ID:
            raise ScenarioLibraryError(409, "library_id_collision")
        execution_binding = None
        if binding is not None:
            if (type(binding) is not dict
                    or set(binding) != {"catalog_scenario_id", "binding_version", "coverage_ack"}
                    or binding.get("catalog_scenario_id") not in CUSTOM_BINDABLE_CATALOG_IDS
                    or binding.get("binding_version") != BINDING_POLICY_VERSION
                    or type(binding.get("coverage_ack")) is not str
                    or binding["coverage_ack"] != coverage_statement(binding["catalog_scenario_id"])):
                raise ScenarioLibraryError(400, "binding_ack_required")
            execution_binding = {
                "catalog_scenario_id": binding["catalog_scenario_id"],
                "binding_version": BINDING_POLICY_VERSION,
                "coverage_statement": coverage_statement(binding["catalog_scenario_id"]),
            }
        digest = stable_json_hash(canonical)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            current = self.conn.execute(
                "SELECT MAX(revision) FROM workspace_custom_scenarios WHERE workspace_id=? AND scenario_id=?",
                (workspace_id, scenario_id),
            ).fetchone()[0]
            if current != supersedes:
                raise ScenarioLibraryError(409, "revision_conflict")
            if current is None:
                count = self.conn.execute(
                    "SELECT COUNT(DISTINCT scenario_id) FROM workspace_custom_scenarios WHERE workspace_id=?",
                    (workspace_id,),
                ).fetchone()[0]
                if count >= MAX_CUSTOM_SCENARIOS_PER_WORKSPACE:
                    raise ScenarioLibraryError(409, "custom_scenario_limit")
            elif current >= MAX_REVISIONS_PER_SCENARIO:
                raise ScenarioLibraryError(409, "custom_revision_limit")
            revision = 1 if current is None else current + 1
            self.conn.execute(
                "INSERT INTO workspace_custom_scenarios(workspace_id,scenario_id,revision,definition_json,"
                "definition_digest,execution_binding_json,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (workspace_id, scenario_id, revision, serialized, digest,
                 stable_json(execution_binding) if execution_binding else None, actor, self.clock()),
            )
            self.conn.execute(
                "INSERT INTO admin_audit(actor,action,subject,reason,ts) VALUES(?,?,?,?,?)",
                (actor, "custom_scenario_revision", f"{workspace_id}:{scenario_id}:{revision}",
                 "workspace-private custom scenario revision " + ("bound" if execution_binding else "static"),
                 self.clock()),
            )
            row = self.conn.execute(
                "SELECT * FROM workspace_custom_scenarios WHERE workspace_id=? AND scenario_id=? AND revision=?",
                (workspace_id, scenario_id, revision),
            ).fetchone()
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise
        created = self._custom_row(row)
        created["warnings"] = warnings
        return created

    def _current_custom(self, workspace_id: str, scenario_id: str):
        return self.conn.execute(
            "SELECT * FROM workspace_custom_scenarios WHERE workspace_id=? AND scenario_id=? "
            "ORDER BY revision DESC LIMIT 1",
            (workspace_id, scenario_id),
        ).fetchone()

    # --- run bindings ------------------------------------------------------------------------
    def _approval(self, workspace_id: str, project_ref: str, run_id: str):
        if type(run_id) is not str or not _RUN.fullmatch(run_id):
            raise ScenarioLibraryError(404, "run_not_found")
        row = self.conn.execute(
            "SELECT approval_id,run_id,status,expires_at,projection_digest,manifest_digest,projection_json "
            "FROM canary_approval_projections WHERE workspace_id=? AND project_ref=? AND run_id=?",
            (workspace_id, project_ref, run_id),
        ).fetchone()
        if row is None:
            raise ScenarioLibraryError(404, "run_not_found")
        return row

    @staticmethod
    def _actions(row) -> list[dict]:
        if not row["projection_json"]:
            raise ScenarioLibraryError(409, "projection_unavailable")
        try:
            projection = validate_approval_projection(json.loads(row["projection_json"]))
        except (TypeError, ValueError):
            raise ScenarioLibraryError(409, "projection_unavailable") from None
        if (projection["projection_digest"] != row["projection_digest"]
                or projection["manifest_digest"] != row["manifest_digest"]):
            raise ScenarioLibraryError(409, "projection_unavailable")
        return [
            {"catalog_scenario_id": action["scenario_id"], "method": action["method"],
             "route_template": action["route_template"]}
            for action in projection["actions"]
        ]

    def _binding_rows(self, workspace_id: str, project_ref: str, run_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM run_scenario_bindings WHERE workspace_id=? AND project_ref=? AND run_id=? "
            "ORDER BY library_scenario_id",
            (workspace_id, project_ref, run_id),
        ).fetchall()
        return [{
            "catalog_scenario_id": row["catalog_scenario_id"],
            "method": row["method"],
            "route_template": row["route_template"],
            "library_scenario_id": row["library_scenario_id"],
            "source": row["source"],
            "revision": row["revision"],
            "definition_digest": row["definition_digest"],
            "library_digest": row["library_digest"],
            "binding_version": row["binding_version"],
            "approval_id": row["approval_id"],
            "projection_digest": row["projection_digest"],
            "manifest_digest": row["manifest_digest"],
            "display": json.loads(row["display_json"]),
            "bound_at_ms": row["bound_at"],
        } for row in rows]

    def bindings_view(self, workspace_id: str, project_ref: str, run_id: str) -> dict:
        row = self._approval(workspace_id, project_ref, run_id)
        now = int(self.clock() * 1000)
        awaiting = row["status"] == "awaiting_execution_approval" and int(row["expires_at"]) > now
        return {
            "schema_version": BINDINGS_VIEW_SCHEMA,
            "run_id": row["run_id"],
            "approval_id": row["approval_id"],
            "projection_digest": row["projection_digest"],
            "manifest_digest": row["manifest_digest"],
            "accepting_bindings": awaiting,
            # Action tuples are part of the signed plan the approver already sees; nothing else.
            "actions": self._actions(row) if awaiting else [],
            "bindings": self._binding_rows(workspace_id, project_ref, run_id),
            "library_digest": _LIBRARY_DIGEST,
        }

    @staticmethod
    def _parse_items(body: Any) -> tuple[str, list[dict]]:
        if (type(body) is not dict or set(body) != {"schema_version", "projection_digest", "items"}
                or body.get("schema_version") != BINDINGS_REQUEST_SCHEMA
                or type(body.get("projection_digest")) is not str
                or not _DIGEST.fullmatch(body["projection_digest"])
                or type(body.get("items")) is not list
                or not 1 <= len(body["items"]) <= MAX_BINDING_ITEMS):
            raise ScenarioLibraryError(400, "invalid_binding_request")
        items = []
        seen = set()
        for item in body["items"]:
            if (type(item) is not dict or set(item) != {
                    "catalog_scenario_id", "method", "route_template", "library_scenario_id",
                    "source", "definition_digest", "binding_version"}
                    or item["catalog_scenario_id"] not in CATALOG_IDS
                    or item["method"] not in ("GET", "HEAD")
                    or type(item["route_template"]) is not str
                    or not _ROUTE_TEMPLATE.fullmatch(item["route_template"])
                    or type(item["library_scenario_id"]) is not str
                    or not _ID.fullmatch(item["library_scenario_id"])
                    or item["source"] not in ("library", "custom")
                    or type(item["definition_digest"]) is not str
                    or not _DIGEST.fullmatch(item["definition_digest"])
                    or item["binding_version"] != BINDING_POLICY_VERSION
                    or type(item["binding_version"]) is not int):
                raise ScenarioLibraryError(400, "invalid_binding_request")
            if item["library_scenario_id"] in seen:
                raise ScenarioLibraryError(400, "invalid_binding_request")
            seen.add(item["library_scenario_id"])
            items.append(dict(item))
        return body["projection_digest"], items

    def freeze_bindings(self, workspace_id: str, project_ref: str, run_id: str, actor: str, body: Any) -> dict:
        projection_digest, items = self._parse_items(body)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._approval(workspace_id, project_ref, run_id)
            now = int(self.clock() * 1000)
            if row["status"] != "awaiting_execution_approval" or int(row["expires_at"]) <= now:
                raise ScenarioLibraryError(409, "run_bindings_frozen")
            if row["projection_digest"] != projection_digest:
                raise ScenarioLibraryError(409, "projection_mismatch")
            if self.conn.execute(
                "SELECT 1 FROM run_scenario_bindings WHERE workspace_id=? AND project_ref=? AND run_id=? LIMIT 1",
                (workspace_id, project_ref, run_id),
            ).fetchone() is not None:
                raise ScenarioLibraryError(409, "run_bindings_exist")
            actions = {
                (action["catalog_scenario_id"], action["method"], action["route_template"])
                for action in self._actions(row)
            }
            prepared = []
            for item in items:
                if (item["catalog_scenario_id"], item["method"], item["route_template"]) not in actions:
                    raise ScenarioLibraryError(400, "action_not_in_plan")
                prepared.append(self._resolve_item(workspace_id, item))
            for item, (revision, display) in zip(items, prepared):
                self.conn.execute(
                    "INSERT INTO run_scenario_bindings(workspace_id,project_ref,run_id,approval_id,"
                    "projection_digest,manifest_digest,catalog_scenario_id,method,route_template,"
                    "library_scenario_id,source,revision,definition_digest,library_digest,binding_version,"
                    "display_json,bound_by,bound_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (workspace_id, project_ref, run_id, row["approval_id"], row["projection_digest"],
                     row["manifest_digest"], item["catalog_scenario_id"], item["method"],
                     item["route_template"], item["library_scenario_id"], item["source"], revision,
                     item["definition_digest"], _LIBRARY_DIGEST, BINDING_POLICY_VERSION,
                     stable_json(display), actor, now),
                )
            self.conn.execute(
                "INSERT INTO admin_audit(actor,action,subject,reason,ts) VALUES(?,?,?,?,?)",
                (actor, "run_scenario_bindings_freeze", f"{workspace_id}:{project_ref}:{run_id}",
                 f"froze {len(items)} scenario binding(s) before approval", self.clock()),
            )
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise
        return self.bindings_view(workspace_id, project_ref, run_id)

    def _resolve_item(self, workspace_id: str, item: Mapping[str, Any]) -> tuple[int | None, dict]:
        scenario_id = item["library_scenario_id"]
        catalog = item["catalog_scenario_id"]
        if item["source"] == "library":
            if LIBRARY_EXECUTION_BINDINGS.get(scenario_id) != catalog:
                raise ScenarioLibraryError(400, "binding_not_allowed")
            if _LIBRARY_DEFINITION_DIGESTS[scenario_id] != item["definition_digest"]:
                raise ScenarioLibraryError(400, "stale_definition")
            definition = _LIBRARY_BY_ID[scenario_id]
            return None, {
                "objective": _bounded_text(definition["objective"]),
                "mechanism_id": definition["mechanism_id"] or scenario_id,
                "pack": definition["pack"],
                "coverage_statement": library_coverage_statement(catalog),
            }
        current = self._current_custom(workspace_id, scenario_id)
        if current is None:
            raise ScenarioLibraryError(400, "binding_not_allowed")
        binding = json.loads(current["execution_binding_json"]) if current["execution_binding_json"] else None
        if binding is None or binding.get("catalog_scenario_id") != catalog:
            raise ScenarioLibraryError(400, "binding_not_allowed")
        if current["definition_digest"] != item["definition_digest"]:
            raise ScenarioLibraryError(400, "stale_definition")
        definition = json.loads(current["definition_json"])
        return int(current["revision"]), {
            "objective": _bounded_text(definition["objective"]),
            "mechanism_id": scenario_id,
            "pack": "custom",
            "coverage_statement": coverage_statement(catalog),
        }
