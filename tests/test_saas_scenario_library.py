"""Workspace scenario library, private custom revisions and run-frozen bindings over real HTTP."""
from __future__ import annotations

import http.client
import json
import re
import sqlite3
import threading
import time

import pytest

from heel.canary_contracts import canonical_bytes, canonical_digest
from heel.runner.catalog import CATALOG_IDS
from heel.saas.catalog import CATALOG_VERSION
from heel.saas.scenario_library import (
    LIBRARY_EXECUTION_BINDINGS,
    MAX_CUSTOM_SCENARIOS_PER_WORKSPACE,
    coverage_statement,
    library_definition_digest,
    library_digest,
)
from heel.saas.tenancy import Role
from heel.scenarios import list_scenarios

from canary_test_support import approval_projection
from test_canary_http import CanaryHttpFixture


@pytest.fixture
def lib(tmp_path):
    fixture = CanaryHttpFixture(tmp_path / "library")
    try:
        yield fixture
    finally:
        fixture.close()


def _base(fixture, workspace=None):
    return f"/v1/workspaces/{workspace or fixture.workspace}"


def _definition(scenario_id="sc.internal.admin_route_read", **overrides):
    value = {
        "id": scenario_id,
        "category": "unintended_endpoints",
        "objective": "Admin listing must not be readable anonymously",
        "kind": "endpoint",
        "success_criterion": {"all_of": [{"prop": "method", "equals": "GET"},
                                         {"prop_contains": ["route", "/admin"]}]},
        "severity_model": {"likelihood": 0.5, "impact": 0.7},
        "recommended_control": "require an authenticated session on admin routes",
        "containment_limits": {"canary_only": True, "no_live_targets": True, "sample_cap": 1},
    }
    value.update(overrides)
    return value


def _custom(fixture, definition=None, *, supersedes=None, binding=None, headers=None, workspace=None):
    body = {"schema_version": "heel.custom-scenario.v1", "definition": definition or _definition(),
            "supersedes_revision": supersedes, "execution_binding": binding}
    return fixture.request("POST", _base(fixture, workspace) + "/scenario-library/custom", body,
                           headers if headers is not None else fixture.browser)


def _ack(catalog="anonymous_authenticated_read", ack=None):
    return {"catalog_scenario_id": catalog, "binding_version": 1,
            "coverage_ack": coverage_statement(catalog) if ack is None else ack}


def _projection(fixture, projection_id="ap_canary", route="/api/canary"):
    value = approval_projection(fixture.runner, workspace_id=fixture.workspace, project_ref=fixture.project)
    if projection_id == "ap_canary" and route == "/api/canary":
        return value
    value = {key: item for key, item in value.items()
             if key not in {"projection_digest", "signing_key_id", "signature_b64"}}
    value["projection_id"] = projection_id
    value["actions"][0]["route_template"] = route
    value["projection_digest"] = canonical_digest(value)
    value.update(fixture.runner.sign(canonical_bytes({
        key: item for key, item in value.items() if key != "projection_digest"})))
    return value


def _submit(fixture, **kwargs):
    projection = _projection(fixture, **kwargs)
    status, _, body = fixture.request(
        "POST", f"{_base(fixture)}/projects/{fixture.project}/canary-approval-projections",
        projection, fixture.browser)
    assert status == 201, body
    return projection, body["run_id"]


def _bindings_path(fixture, run_id, project=None, workspace=None):
    return f"{_base(fixture, workspace)}/projects/{project or fixture.project}/canary-runs/{run_id}/scenario-bindings"


def _item(scenario_id="sc.endpoint.hidden", *, source="library", catalog="anonymous_authenticated_read",
          route="/api/canary", digest=None, method="GET"):
    return {"catalog_scenario_id": catalog, "method": method, "route_template": route,
            "library_scenario_id": scenario_id, "source": source,
            "definition_digest": digest or library_definition_digest(scenario_id), "binding_version": 1}


def _freeze(fixture, run_id, projection_digest, items, headers=None, **path):
    return fixture.request("POST", _bindings_path(fixture, run_id, **path), {
        "schema_version": "heel.run-scenario-bindings.v1", "projection_digest": projection_digest,
        "items": items}, headers if headers is not None else fixture.browser)


def _approve(fixture, run_id, projection_digest):
    return fixture.request(
        "POST", f"{_base(fixture)}/projects/{fixture.project}/canary-runs/{run_id}/approve",
        {"schema_version": "heel.canary-execution-approval.v1", "projection_digest": projection_digest,
         "hostname_retype": "canary.acme.dev", "reason": "Run the exact bounded staging rehearsal"},
        {**fixture.browser, "Idempotency-Key": "ca1-" + "c" * 64, "If-Heel-Control-Generation": "0"})


def _other_member(fixture, role=Role.OWNER, *, workspace=None):
    store = fixture.cp.store
    if workspace is None:
        org = store.create_org("Other")
        workspace = store.create_workspace(org, "Other", "free", CATALOG_VERSION)
    user = store.create_user(f"{role.value}-{time.time_ns()}@other.test")
    store.add_member(workspace, user, role)
    session = fixture.cp.auth.create_session(user)
    return workspace, {"Cookie": f"heel_session={session.token}", "Origin": "https://heel.test",
                       "X-Heel-Internal-Origin": "same-origin"}


def _approval_row(fixture, run_id):
    conn = sqlite3.connect(fixture.cp.store.conn.execute("PRAGMA database_list").fetchone()[2])
    try:
        return conn.execute("SELECT * FROM canary_approval_projections WHERE run_id=?", (run_id,)).fetchone()
    finally:
        conn.close()


def test_binding_table_closed(lib):
    library_ids = {item.id for item in list_scenarios()}
    assert len(LIBRARY_EXECUTION_BINDINGS) == 4
    assert set(LIBRARY_EXECUTION_BINDINGS) <= library_ids
    assert set(LIBRARY_EXECUTION_BINDINGS.values()) <= set(CATALOG_IDS)
    assert set(LIBRARY_EXECUTION_BINDINGS.values()) == {"anonymous_authenticated_read", "plan_entitlement_read"}
    with pytest.raises(TypeError):
        LIBRARY_EXECUTION_BINDINGS["sc.internal.x"] = "role_bound_read"  # type: ignore[index]
    status, _, body = lib.request("GET", _base(lib) + "/scenario-library", headers=lib.browser)
    assert status == 200
    supported = {row["id"]: row for row in body["scenarios"] if row["execution_support"] == "runner_supported"}
    assert {key: row["catalog_scenario_id"] for key, row in supported.items()} == dict(LIBRARY_EXECUTION_BINDINGS)


def test_library_listing_labels(lib):
    status, headers, first = lib.request("GET", _base(lib) + "/scenario-library", headers=lib.browser)
    assert status == 200 and int(headers["Content-Length"]) < 272 * 1024
    _, _, second = lib.request("GET", _base(lib) + "/scenario-library", headers=lib.browser)
    assert first == second
    assert first["schema_version"] == "heel.scenario-library.v1"
    assert re.fullmatch(r"[0-9a-f]{64}", first["library_digest"]) and first["library_digest"] == library_digest()
    rows = first["scenarios"]
    assert len(rows) >= 100 and len({row["id"] for row in rows}) == len(rows)
    assert all(row["applicability"] == "unknown" for row in rows)
    for row in rows:
        bound = row["id"] in LIBRARY_EXECUTION_BINDINGS
        assert (row["execution_support"] == "runner_supported") is bound
        assert (row["coverage_statement"] is not None) is bound
        assert bool(row["prerequisites"]) is bound
        assert row["definition_digest"] == library_definition_digest(row["id"])
        assert row["evidence_state"] == "inferred"
    hidden = next(row for row in rows if row["id"] == "sc.endpoint.hidden")
    assert "heel runner map --scenario <catalog id>" in hidden["prerequisites"]
    assert hidden["coverage_statement"].startswith("Executed check: anonymous_authenticated_read (GET/HEAD")


def test_library_digest_covers_builtins_semantic_families_and_binding_policy():
    import heel.saas.scenario_library as module
    ids = {item["id"] for item in module._LIBRARY_DEFINITIONS}
    assert any(name.startswith("sc.sem.") for name in ids)  # semantic families
    assert "sc.flag.tiergate" in ids  # builtin
    assert "sc.research.unintended_endpoints.forced_browsing_admin" in ids  # JSON pack
    definitions, digest = module._build_library()
    assert digest == library_digest()
    original = dict(module.LIBRARY_EXECUTION_BINDINGS)
    try:
        module.LIBRARY_EXECUTION_BINDINGS = {**original, "sc.endpoint.hidden": "plan_entitlement_read"}
        assert module._build_library()[1] != digest
    finally:
        module.LIBRARY_EXECUTION_BINDINGS = module.MappingProxyType(original)


def test_custom_revisions_immutable(lib):
    status, _, rev1 = _custom(lib)
    assert status == 201, rev1
    assert (rev1["revision"], rev1["execution_support"], rev1["source"]) == (1, "static_only", "custom")
    assert rev1["applicability"] == "unknown" and rev1["evidence_state"] == "customer_declared"
    status, _, rev2 = _custom(lib, _definition(objective="Admin listing stays private"), supersedes=1)
    assert status == 201 and rev2["revision"] == 2 and rev2["definition_digest"] != rev1["definition_digest"]
    status, _, conflict = _custom(lib, _definition(objective="third"), supersedes=1)
    assert (status, conflict["code"]) == (409, "revision_conflict")
    status, _, conflict = _custom(lib, _definition(scenario_id="sc.internal.new_one"), supersedes=3)
    assert (status, conflict["code"]) == (409, "revision_conflict")
    conn = lib.cp.store.conn
    stored = conn.execute(
        "SELECT revision, definition_digest FROM workspace_custom_scenarios ORDER BY revision").fetchall()
    assert [(row[0], row[1]) for row in stored] == [(1, rev1["definition_digest"]), (2, rev2["definition_digest"])]
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("UPDATE workspace_custom_scenarios SET definition_json='{}' WHERE revision=1")
    conn.rollback()
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM workspace_custom_scenarios")
    conn.rollback()
    _, _, listing = lib.request("GET", _base(lib) + "/scenario-library", headers=lib.browser)
    current = [row for row in listing["scenarios"] if row["source"] == "custom"]
    assert [(row["id"], row["revision"]) for row in current] == [("sc.internal.admin_route_read", 2)]
    audit = conn.execute("SELECT action, subject, reason FROM admin_audit WHERE action='custom_scenario_revision'").fetchall()
    assert len(audit) == 2 and all("Admin listing" not in row[2] for row in audit)


def test_custom_binding_requires_explicit_ack(lib):
    status, _, static = _custom(lib, _definition("sc.internal.endpoint_static"))
    assert status == 201 and static["execution_support"] == "static_only" and static["catalog_scenario_id"] is None
    status, _, wrong = _custom(lib, _definition("sc.internal.endpoint_wrong"), binding=_ack(ack="I agree"))
    assert (status, wrong["code"]) == (400, "binding_ack_required")
    for bad in ({"catalog_scenario_id": "role_bound_read", "binding_version": 1,
                 "coverage_ack": coverage_statement("role_bound_read")},
                {**_ack(), "binding_version": 2}, {**_ack(), "extra": True}):
        status, _, body = _custom(lib, _definition("sc.internal.endpoint_wrong"), binding=bad)
        assert (status, body["code"]) == (400, "binding_ack_required")
    status, _, bound = _custom(lib, _definition("sc.internal.endpoint_bound"), binding=_ack())
    assert status == 201 and bound["execution_support"] == "runner_supported"
    assert bound["coverage_statement"] == coverage_statement("anonymous_authenticated_read")
    assert "not executed; they are analysis-only" in bound["coverage_statement"]
    status, _, meter = _custom(lib, _definition("sc.internal.meter_bound", kind="meter"),
                               binding=_ack("plan_entitlement_read"))
    assert status == 201 and meter["catalog_scenario_id"] == "plan_entitlement_read"


def test_custom_validation_errors_verbatim(lib):
    missing = _definition("sc.internal.missing")
    del missing["recommended_control"]
    status, _, body = _custom(lib, missing)
    assert (status, body["code"]) == (400, "invalid_scenario")
    assert "recommended_control: required field is missing" in body["errors"]
    status, _, body = _custom(lib, _definition("sc.internal.bad", objective="run sqlmap against prod"))
    assert (status, body["code"]) == (400, "invalid_scenario")
    assert "scenario.objective: prohibited content or payload-like instruction is not allowed" in body["errors"]
    status, _, body = _custom(lib, _definition("sc.research.custom_take"))
    assert (status, body["code"]) == (400, "invalid_scenario")
    assert any("sc.community." in error for error in body["errors"])
    status, _, body = _custom(lib, _definition("sc.attack.custom"))
    assert (status, body["code"]) == (400, "invalid_scenario")
    status, _, body = _custom(lib, _definition(investigation_signals={"eval": "x"}))
    assert (status, body["code"]) == (400, "invalid_scenario")
    assert any(error.startswith("investigation_signals") for error in body["errors"])
    status, _, body = _custom(lib, _definition(handoff="model_redteam"))
    assert (status, body["code"]) == (400, "invalid_scenario")
    # A library identifier inside a custom namespace cannot collide; a real library id can't be claimed.
    community = next(item.id for item in list_scenarios() if item.id.startswith("sc.community."))
    status, _, body = _custom(lib, _definition(community))
    assert (status, body["code"]) == (409, "library_id_collision")


def test_custom_intake_bounds_malformed_and_privileged_paths(lib):
    huge = _definition("sc.internal.huge", objective="x" * 5000)
    status, _, body = _custom(lib, huge)
    assert (status, body["code"]) == (400, "custom_definition_too_large")
    deep = {"prop": "method", "equals": "GET"}
    for _ in range(10):
        deep = {"not": deep}
    status, _, body = _custom(lib, _definition("sc.internal.deep", success_criterion=deep))
    assert (status, body["code"]) == (400, "invalid_custom_request")
    status, _, body = lib.request("POST", _base(lib) + "/scenario-library/custom", raw=b"{\"a\":1,\"a\":2}",
                                  headers={**lib.browser, "Content-Type": "application/json"})
    assert status == 400
    status, _, body = lib.request("POST", _base(lib) + "/scenario-library/custom",
                                  {"schema_version": "heel.custom-scenario.v1", "definition": _definition()},
                                  lib.browser)
    assert (status, body["code"]) == (400, "invalid_custom_request")
    no_origin = {"Cookie": lib.browser["Cookie"]}
    status, _, body = _custom(lib, headers=no_origin)
    assert (status, body["code"]) == (403, "same_origin_required")
    status, _, _ = _custom(lib, headers={"Origin": "https://heel.test", "X-Heel-Internal-Origin": "same-origin"})
    assert status == 401
    _, viewer = _other_member(lib, Role.VIEWER, workspace=lib.workspace)
    status, _, body = _custom(lib, headers=viewer)
    assert (status, body["code"]) == (403, "forbidden")
    for index in range(MAX_CUSTOM_SCENARIOS_PER_WORKSPACE):
        assert _custom(lib, _definition(f"sc.community.limit_{index:02d}"))[0] == 201
    status, _, body = _custom(lib, _definition("sc.community.limit_overflow"))
    assert (status, body["code"]) == (409, "custom_scenario_limit")
    status, headers, _ = lib.request("GET", _base(lib) + "/scenario-library", headers=lib.browser)
    assert status == 200 and int(headers["Content-Length"]) < 272 * 1024


def test_custom_scenarios_are_workspace_private(lib):
    assert _custom(lib)[0] == 201
    other, other_headers = _other_member(lib)
    status, _, body = lib.request("GET", _base(lib, other) + "/scenario-library", headers=other_headers)
    assert status == 200 and not [row for row in body["scenarios"] if row["source"] == "custom"]
    status, _, body = lib.request("GET", _base(lib) + "/scenario-library", headers=other_headers)
    assert (status, body["code"]) == (404, "not_found")
    status, _, body = _custom(lib, headers=other_headers)  # other owner cannot write into this workspace
    assert (status, body["code"]) == (404, "not_found")
    status, _, _ = lib.request("GET", _base(lib) + "/scenario-library")
    assert status == 401


def test_run_bindings_require_awaiting_and_projection_match(lib):
    projection, run_id = _submit(lib)
    digest = projection["projection_digest"]
    status, _, view = lib.request("GET", _bindings_path(lib, run_id), headers=lib.browser)
    assert status == 200 and view["accepting_bindings"] is True and view["bindings"] == []
    assert view["actions"] == [{"catalog_scenario_id": "anonymous_authenticated_read", "method": "GET",
                                "route_template": "/api/canary"}]
    cases = [
        ([_item(route="/api/other")], 400, "action_not_in_plan"),
        ([_item(method="HEAD")], 400, "action_not_in_plan"),
        ([_item("sc.flag.tiergate", catalog="anonymous_authenticated_read")], 400, "binding_not_allowed"),
        ([_item(digest="0" * 64)], 400, "stale_definition"),
        ([_item("sc.internal.nope", source="custom", digest="1" * 64)], 400, "binding_not_allowed"),
        ([_item(), _item()], 400, "invalid_binding_request"),
        ([_item()] * 9, 400, "invalid_binding_request"),
        ([], 400, "invalid_binding_request"),
    ]
    for items, expected_status, code in cases:
        status, _, body = _freeze(lib, run_id, digest, items)
        assert (status, body["code"]) == (expected_status, code), items
    status, _, body = _freeze(lib, run_id, "f" * 64, [_item()])
    assert (status, body["code"]) == (409, "projection_mismatch")
    status, _, custom = _custom(lib, binding=_ack())
    stale = custom["definition_digest"]
    assert _custom(lib, _definition(objective="newer revision"), supersedes=1, binding=_ack())[0] == 201
    status, _, body = _freeze(lib, run_id, digest, [_item(custom["id"], source="custom", digest=stale)])
    assert (status, body["code"]) == (400, "stale_definition")
    before = _approval_row(lib, run_id)
    status, _, frozen = _freeze(lib, run_id, digest, [_item()])
    assert status == 201 and [row["library_scenario_id"] for row in frozen["bindings"]] == ["sc.endpoint.hidden"]
    assert frozen["bindings"][0]["projection_digest"] == digest
    assert frozen["bindings"][0]["manifest_digest"] == projection["manifest_digest"]
    assert frozen["bindings"][0]["display"]["coverage_statement"].startswith("Executed check: anonymous_authenticated_read")
    assert _approval_row(lib, run_id) == before  # the approval record is never touched
    status, _, body = _freeze(lib, run_id, digest, [_item("sc.research.unintended_endpoints.forced_browsing_admin")])
    assert (status, body["code"]) == (409, "run_bindings_exist")
    status, _, approved = _approve(lib, run_id, digest)
    assert status == 201, approved
    status, _, body = _freeze(lib, run_id, digest, [_item()])
    assert (status, body["code"]) == (409, "run_bindings_frozen")
    status, _, view = lib.request("GET", _bindings_path(lib, run_id), headers=lib.browser)
    assert view["accepting_bindings"] is False and view["actions"] == [] and len(view["bindings"]) == 1


def test_bindings_after_expiry_are_frozen_and_approval_is_possible_without_bindings(lib):
    projection, run_id = _submit(lib)
    conn = lib.cp.store.conn
    conn.execute("UPDATE canary_approval_projections SET expires_at=created_at+1 WHERE run_id=?", (run_id,))
    conn.commit()
    status, _, body = _freeze(lib, run_id, projection["projection_digest"], [_item()])
    assert (status, body["code"]) == (409, "run_bindings_frozen")
    projection2, run2 = _submit(lib, projection_id="ap_second", route="/api/canary")
    status, _, approved = _approve(lib, run2, projection2["projection_digest"])
    assert status == 201, approved  # zero bindings: the run stands for no library entry
    _, _, view = lib.request("GET", _bindings_path(lib, run2), headers=lib.browser)
    assert view["bindings"] == []


def test_later_edits_never_relabel_old_run(lib):
    status, _, rev1 = _custom(lib, binding=_ack())
    assert status == 201
    projection, run_id = _submit(lib)
    status, _, frozen = _freeze(lib, run_id, projection["projection_digest"], [
        _item(rev1["id"], source="custom", digest=rev1["definition_digest"])])
    assert status == 201
    frozen_rows = frozen["bindings"]
    assert frozen_rows[0]["revision"] == 1
    status, _, rev2 = _custom(lib, _definition(objective="A different objective entirely"), supersedes=1,
                              binding=_ack())
    assert status == 201 and rev2["revision"] == 2
    _, _, view = lib.request("GET", _bindings_path(lib, run_id), headers=lib.browser)
    assert view["bindings"] == frozen_rows
    assert view["bindings"][0]["definition_digest"] == rev1["definition_digest"]
    assert view["bindings"][0]["display"]["objective"] == "Admin listing must not be readable anonymously"
    _, _, listing = lib.request("GET", _base(lib) + "/scenario-library", headers=lib.browser)
    assert next(row for row in listing["scenarios"] if row["id"] == rev1["id"])["revision"] == 2
    projection2, run2 = _submit(lib, projection_id="ap_next", route="/api/canary")
    status, _, body = _freeze(lib, run2, projection2["projection_digest"], [
        _item(rev1["id"], source="custom", digest=rev1["definition_digest"])])
    assert (status, body["code"]) == (400, "stale_definition")
    status, _, body = _freeze(lib, run2, projection2["projection_digest"], [
        _item(rev1["id"], source="custom", digest=rev2["definition_digest"])])
    assert status == 201 and body["bindings"][0]["revision"] == 2
    _, _, old = lib.request("GET", _bindings_path(lib, run_id), headers=lib.browser)
    assert old["bindings"] == frozen_rows


def test_wrong_project_run_workspace_refused(lib):
    projection, run_id = _submit(lib)
    digest = projection["projection_digest"]
    other, other_headers = _other_member(lib)
    status, _, body = _freeze(lib, run_id, digest, [_item()], headers=other_headers)
    assert (status, body["code"]) == (404, "not_found")
    status, _, body = lib.request("GET", _bindings_path(lib, run_id), headers=other_headers)
    assert (status, body["code"]) == (404, "not_found")
    status, _, body = _freeze(lib, run_id, digest, [_item()], headers=other_headers, workspace=other)
    assert (status, body["code"]) == (404, "run_not_found")
    second_project = lib.cp.projects.create(lib.workspace, "Second", created_by=lib.user).project_ref
    status, _, body = _freeze(lib, run_id, digest, [_item()], project=second_project)
    assert (status, body["code"]) == (404, "run_not_found")
    status, _, body = lib.request("GET", _bindings_path(lib, run_id, project=second_project), headers=lib.browser)
    assert (status, body["code"]) == (404, "run_not_found")
    status, _, body = _freeze(lib, "crun_" + "0" * 32, digest, [_item()])
    assert (status, body["code"]) == (404, "run_not_found")
    _, member = _other_member(lib, Role.MEMBER, workspace=lib.workspace)
    status, _, body = _freeze(lib, run_id, digest, [_item()], headers=member)
    assert (status, body["code"]) == (403, "recent_auth_required")
    status, _, _ = _freeze(lib, run_id, digest, [_item()], headers={"Cookie": lib.browser["Cookie"]})
    assert status == 403
    status, _, body = _freeze(lib, run_id, digest, [_item()])
    assert status == 201


def test_binding_and_approval_race_is_atomic(lib):
    projection, run_id = _submit(lib)
    path = lib.cp.store.conn.execute("PRAGMA database_list").fetchone()[2]
    racer = sqlite3.connect(path, isolation_level=None)
    racer.execute("PRAGMA busy_timeout=5000")
    racer.execute("BEGIN IMMEDIATE")
    racer.execute(
        "UPDATE canary_approval_projections SET status='approved',approved_by='racer',reason='race',"
        "approved_at=created_at+1 WHERE run_id=?", (run_id,))
    result = {}

    def post():
        result["response"] = _freeze(lib, run_id, projection["projection_digest"], [_item()])

    thread = threading.Thread(target=post)
    thread.start()
    time.sleep(0.3)
    racer.execute("COMMIT")
    racer.close()
    thread.join(10)
    status, _, body = result["response"]
    assert (status, body["code"]) == (409, "run_bindings_frozen")
    assert lib.cp.store.conn.execute(
        "SELECT COUNT(*) FROM run_scenario_bindings WHERE run_id=?", (run_id,)).fetchone()[0] == 0


def test_findings_body_untouched(lib):
    projection, run_id = _submit(lib)
    findings_path = f"{_base(lib)}/projects/{lib.project}/canary-runs/{run_id}/findings"

    def raw():
        connection = http.client.HTTPConnection("127.0.0.1", lib.server.server_address[1], timeout=5)
        connection.request("GET", findings_path, None, lib.browser)
        response = connection.getresponse()
        return response.status, response.read()

    before = raw()
    status_before = lib.request("GET", f"{_base(lib)}/projects/{lib.project}/canary-runs/{run_id}",
                                headers=lib.browser)[2]
    assert _freeze(lib, run_id, projection["projection_digest"], [_item()])[0] == 201
    assert raw() == before
    status_after = lib.request("GET", f"{_base(lib)}/projects/{lib.project}/canary-runs/{run_id}",
                               headers=lib.browser)[2]
    status_before.pop("approval_control_generation", None)
    status_after.pop("approval_control_generation", None)
    assert status_after == status_before


def test_binding_foreign_keys_match_real_parent_keys(lib):
    conn = lib.cp.store.conn
    keys = {tuple(row[3] for row in group) for group in [
        [row for row in conn.execute("PRAGMA foreign_key_list(run_scenario_bindings)") if row[0] == fk]
        for fk in {row[0] for row in conn.execute("PRAGMA foreign_key_list(run_scenario_bindings)")}]}
    assert keys == {("workspace_id", "project_ref", "run_id"), ("workspace_id", "project_ref", "approval_id")}
    assert conn.execute("PRAGMA foreign_key_check(run_scenario_bindings)").fetchall() == []
    assert conn.execute("PRAGMA foreign_key_check(workspace_custom_scenarios)").fetchall() == []
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO run_scenario_bindings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (lib.workspace, lib.project, "crun_" + "1" * 32, "ap_missing", "a" * 64, "b" * 64,
             "anonymous_authenticated_read", "GET", "/x", "sc.endpoint.hidden", "library", None,
             "c" * 64, "d" * 64, 1, "{}", "u", 1))
    conn.rollback()
