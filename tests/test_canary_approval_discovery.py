from __future__ import annotations

import tempfile
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


def test_discovery_uses_the_tenant_pending_order_index_without_a_scan_or_sort():
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
                if "idx_canary_approval_pending_discovery_order" in statement
            )
            details = [row[3] for row in fixture.cp.store.conn.execute("EXPLAIN QUERY PLAN " + query)]
            assert any("idx_canary_approval_pending_discovery_order" in detail for detail in details)
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
