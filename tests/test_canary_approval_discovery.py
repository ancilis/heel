from __future__ import annotations

import tempfile
import time
from pathlib import Path

from canary_test_support import approval_projection
from test_canary_http import CanaryHttpFixture


def test_session_discovery_returns_one_closed_pending_approval_request():
    with tempfile.TemporaryDirectory() as directory:
        fixture = CanaryHttpFixture(Path(directory))
        try:
            base = f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}"
            projection = approval_projection(fixture.runner, workspace_id=fixture.workspace, project_ref=fixture.project)
            assert fixture.request("POST", base + "/canary-approval-projections", projection, fixture.browser)[0] == 201
            status, _, value = fixture.request("GET", base + "/canary-approval-requests", headers={"Cookie": fixture.browser["Cookie"]})
            assert status == 200
            assert set(value) == {"schema_version", "server_time_ms", "requests", "has_more"}
            assert value["schema_version"] == "heel.canary-approval-request-list.v1"
            assert value["has_more"] is False and len(value["requests"]) == 1
            item = value["requests"][0]
            assert set(item) == {"approval_id", "run_id", "projection_digest", "status", "submitted_at_ms", "expires_at_ms", "origin", "hostname", "routes", "scenarios", "request_budget", "duration_seconds", "egress"}
            assert item["status"] == "awaiting_execution_approval"
            assert item["routes"] == ["GET /api/canary"]
        finally:
            fixture.close()


def test_discovery_uses_the_live_expiry_seek_index_without_a_scan_or_sort():
    with tempfile.TemporaryDirectory() as directory:
        fixture = CanaryHttpFixture(Path(directory))
        try:
            base = f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}"
            projection = approval_projection(
                fixture.runner, workspace_id=fixture.workspace, project_ref=fixture.project,
            )
            assert fixture.request(
                "POST", base + "/canary-approval-projections", projection, fixture.browser,
            )[0] == 201
            statements: list[str] = []
            fixture.cp.store.conn.set_trace_callback(statements.append)
            try:
                fixture.cp.canary_runs.list_pending_approval_requests(
                    fixture.workspace, fixture.project, fixture.user,
                )
            finally:
                fixture.cp.store.conn.set_trace_callback(None)
            query = next(
                statement for statement in statements
                if "idx_canary_approval_pending_live_seek" in statement
            )
            details = [row[3] for row in fixture.cp.store.conn.execute("EXPLAIN QUERY PLAN " + query)]
            assert any("idx_canary_approval_pending_live_seek" in detail for detail in details)
            assert any("idx_canary_runs_pending_approval_discovery" in detail for detail in details)
            assert not any("SCAN" in detail or "TEMP B-TREE" in detail or "AUTOMATIC" in detail for detail in details)
        finally:
            fixture.close()


def test_discovery_rejects_query_body_and_non_session_authority():
    with tempfile.TemporaryDirectory() as directory:
        fixture = CanaryHttpFixture(Path(directory))
        try:
            base = f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}/canary-approval-requests"
            assert fixture.request("GET", base + "?cursor=1", headers={"Cookie": fixture.browser["Cookie"]})[0] == 404
            assert fixture.request("GET", base, headers={"Cookie": fixture.browser["Cookie"], "Content-Length": "2"}, raw=b"{}") [0] == 400
            assert fixture.request("GET", base)[0] == 401
            assert fixture.request("POST", base, {}, fixture.browser)[0] == 404
        finally:
            fixture.close()


def test_projection_submission_rejects_a_sixty_fourth_live_pending_request_before_writing():
    with tempfile.TemporaryDirectory() as directory:
        fixture = CanaryHttpFixture(Path(directory))
        try:
            now = int(time.time() * 1000)
            sql = (
                "INSERT INTO canary_approval_projections(approval_id,workspace_id,project_ref,run_id,"
                "environment_id,runner_id,runner_key_id,manifest_digest,projection_digest,signing_key_id,"
                "status,projection_json,scenario_ids_json,budgets_json,uploaded_by,created_at,expires_at,purge_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            )
            fixture.cp.store.conn.executemany(sql, [
                (
                    f"ap_limit_{index}", fixture.workspace, fixture.project, f"crun_limit_{index}", "env_canary",
                    fixture.runner_id, fixture.runner.key_id, f"{index:064x}", f"{index + 64:064x}",
                    fixture.runner.key_id, "awaiting_execution_approval", "{}", "[]", "{}", fixture.user,
                    now, now + 60_000, now + 120_000,
                )
                for index in range(64)
            ])
            fixture.cp.store.conn.commit()
            before = fixture.cp.store.conn.execute("SELECT COUNT(*) FROM canary_approval_projections").fetchone()[0]
            projection = approval_projection(
                fixture.runner, workspace_id=fixture.workspace, project_ref=fixture.project,
            )
            status, _, value = fixture.request(
                "POST", f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}/canary-approval-projections",
                projection, fixture.browser,
            )
            assert status == 503
            assert value == {"schema_version": "heel.canary-error.v1", "code": "canary_authority_unavailable"}
            assert fixture.cp.store.conn.execute("SELECT COUNT(*) FROM canary_approval_projections").fetchone()[0] == before
        finally:
            fixture.close()
