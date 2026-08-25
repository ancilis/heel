"""Tenant-safe, transactional findings-only continuity for the hosted control plane."""
from __future__ import annotations

import copy
import json
import os
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from heel.findings_sync import (
    findings_sync_request_digest,
    project_findings_sync,
    stable_json,
    validate_findings_sync_request,
)
from heel.review_service import review_openapi
from heel.review_contract import stable_json_hash
from heel.saas.catalog import CATALOG_VERSION, Meter, get_plan
from heel.saas.findings_sync import (
    ApprovalExpired,
    ApprovalRequired,
    FindingsSyncConflict,
    FindingsSyncService,
    SyncPrincipal,
)
from heel.saas.ledger import QuotaExceeded, UsageLedger
from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator
from heel.saas.ops import KillSwitchTripped, OpsStore
from heel.saas.projects import ProjectNotFound, ProjectStore
from heel.saas.tenancy import ControlPlaneStore, Role, role_can


ROOT = Path(__file__).resolve().parents[1]
SPEC = json.loads((ROOT / "tests/fixtures/openapi/saas_api.json").read_text())
PERIOD = "2026-08"
NOW = 1_786_000_000.0


def _request(project_ref: str, key: bytes, *, title: str, operation_suffix: str = ""):
    spec = copy.deepcopy(SPEC)
    spec["info"]["title"] = title
    if operation_suffix:
        operation = spec["paths"]["/api/export/bulk"]["get"]
        operation["operationId"] += operation_suffix
    review = review_openapi(spec, execution_mode="machine_local")
    return project_findings_sync(review, project_ref, key)


class CatalogCapabilityMigrationTests(unittest.TestCase):
    def test_synced_review_quotas_are_versioned_and_exact(self):
        self.assertEqual(CATALOG_VERSION, "2026-08-24")
        self.assertEqual(
            [get_plan(name).quota(Meter.SYNCED_REVIEWS) for name in ("free", "pro", "team")],
            [3, 25, 100],
        )
        self.assertEqual(get_plan("enterprise").quota(Meter.SYNCED_REVIEWS), -1)
        self.assertEqual(
            get_plan("pro", "2026-07-13").quota(Meter.SYNCED_REVIEWS),
            0,
        )

    def test_findings_capabilities_exclude_billing_and_limit_writes(self):
        writers = {Role.OWNER, Role.ADMIN, Role.MEMBER}
        readers = writers | {Role.VIEWER}
        for role in Role:
            self.assertEqual(role_can(role, "sync_findings"), role in writers, role)
            self.assertEqual(role_can(role, "view_synced_reviews"), role in readers, role)

    def test_migration_three_is_append_only_and_provisions_every_sync_table(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        migrator = Migrator(conn, CONTROL_PLANE_MIGRATIONS)
        self.assertEqual(migrator.apply_all(), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        self.assertEqual(migrator.apply_all(), [])
        tables = {
            row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertTrue({
            "projects", "project_namespace_keys", "synced_reviews", "project_findings",
            "synced_review_findings", "findings_source_observations",
            "findings_sync_approvals", "findings_sync_receipts", "findings_sync_audit",
        } <= tables)
        for table in tables & {
            "projects", "project_namespace_keys", "synced_reviews", "project_findings",
            "synced_review_findings", "findings_source_observations",
            "findings_sync_approvals", "findings_sync_receipts", "findings_sync_audit",
        }:
            columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            self.assertIn("workspace_id", columns, table)
        self.assertEqual(
            {row[1] for row in conn.execute("PRAGMA table_info(project_namespace_keys)")},
            {"workspace_id", "project_ref", "namespace_key_hex", "created_at"},
        )
        self.assertIn(
            "projection_json",
            {row[1] for row in conn.execute("PRAGMA table_info(synced_reviews)")},
        )
        self.assertIn(
            "ordinal",
            {row[1] for row in conn.execute("PRAGMA table_info(synced_review_findings)")},
        )
        self.assertTrue(
            {"request_json", "source_result_ref", "approval_id", "receipt_json"}
            <= {row[1] for row in conn.execute("PRAGMA table_info(findings_sync_receipts)")}
        )
        self.assertTrue(
            {"actor_ref", "synced_review_id", "ts"}
            <= {row[1] for row in conn.execute("PRAGMA table_info(findings_sync_audit)")}
        )

    def test_ledger_can_participate_in_one_caller_owned_transaction(self):
        ledger = UsageLedger.in_memory()
        self.addCleanup(ledger.conn.close)
        plan = get_plan("free")
        ledger.conn.execute("BEGIN IMMEDIATE")
        ledger.reserve_in_transaction(
            plan, "ws", Meter.SYNCED_REVIEWS, 1, PERIOD, idempotency_key="fs1-a",
        )
        ledger.conn.execute("ROLLBACK")
        self.assertEqual(ledger.usage("ws", Meter.SYNCED_REVIEWS, PERIOD), 0)

        ledger.conn.execute("BEGIN IMMEDIATE")
        reservation = ledger.reserve_in_transaction(
            plan, "ws", Meter.SYNCED_REVIEWS, 1, PERIOD, idempotency_key="fs1-b",
        )
        self.assertTrue(ledger.consume_in_transaction(reservation.reservation_id))
        ledger.conn.execute("COMMIT")
        self.assertEqual(ledger.usage("ws", Meter.SYNCED_REVIEWS, PERIOD), 1)


class FindingsSyncPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.control = ControlPlaneStore()
        self.addCleanup(self.control.conn.close)
        self.org = self.control.create_org("Acme")
        self.workspace = self.control.create_workspace(
            self.org, "Acme", "free", CATALOG_VERSION,
        )
        self.user = self.control.create_user("owner@example.test")
        self.control.add_member(self.workspace, self.user, Role.OWNER)
        self.projects = ProjectStore(self.control.conn)
        self.ledger = UsageLedger(self.control.conn)
        self.ops = OpsStore(self.control.conn)
        self.service = FindingsSyncService(
            self.control.conn,
            projects=self.projects,
            ledger=self.ledger,
            ops=self.ops,
            plan_for_workspace=lambda _workspace_id: get_plan("free"),
        )
        self.project = self.projects.create(
            self.workspace, "Production API", created_by=self.user, now=NOW,
        )
        self.key = self.projects.namespace_key(self.workspace, self.project.project_ref)
        self.submitter = SyncPrincipal(self.user, Role.OWNER, "human_session")

    def _approve(self, request, *, now=NOW, expires_at=NOW + 300):
        digest = findings_sync_request_digest(request, self.key)
        return self.service.approve(
            self.workspace,
            self.project.project_ref,
            digest,
            principal=self.submitter,
            now=now,
            expires_at=expires_at,
        )

    def _accept(self, request, *, now=NOW + 1):
        digest = findings_sync_request_digest(request, self.key)
        return self.service.accept(
            self.workspace,
            self.project.project_ref,
            request,
            principal=self.submitter,
            idempotency_key=f"fs1-{digest}",
            now=now,
        )

    def test_project_namespace_is_immutable_tenant_scoped_and_not_listed(self):
        self.assertEqual(len(self.key), 32)
        self.assertEqual(
            self.projects.namespace_key(self.workspace, self.project.project_ref),
            self.key,
        )
        listed = self.projects.list(self.workspace)
        self.assertEqual([item.project_ref for item in listed], [self.project.project_ref])
        self.assertFalse(hasattr(listed[0], "namespace_key"))
        other = self.control.create_workspace(
            self.org, "Other", "free", CATALOG_VERSION,
        )
        with self.assertRaises(ProjectNotFound):
            self.projects.namespace_key(other, self.project.project_ref)
        self.assertFalse(hasattr(self.projects, "rotate_namespace_key"))

    def test_exact_retry_returns_byte_equivalent_receipt_and_charges_once(self):
        request = _request(self.project.project_ref, self.key, title="First")
        self._approve(request)
        first = self._accept(request)
        second = self._accept(request, now=NOW + 700)
        self.assertEqual(stable_json(first), stable_json(second))
        self.assertEqual(first["disposition"], "created")
        self.assertTrue(first["metered"])
        self.assertEqual(
            self.ledger.usage(self.workspace, Meter.SYNCED_REVIEWS, PERIOD), 1,
        )
        self.assertEqual(
            self.control.conn.execute("SELECT COUNT(*) FROM findings_sync_receipts").fetchone()[0],
            1,
        )

    def test_same_projection_new_source_reuses_review_and_findings_without_charge(self):
        first_request = _request(self.project.project_ref, self.key, title="First source")
        second_request = _request(self.project.project_ref, self.key, title="Second source")
        self.assertEqual(first_request["projection_hash"], second_request["projection_hash"])
        self.assertNotEqual(first_request["source"]["result_ref"], second_request["source"]["result_ref"])
        self._approve(first_request)
        self._approve(second_request)
        first = self._accept(first_request)
        second = self._accept(second_request)
        self.assertEqual(first["synced_review_id"], second["synced_review_id"])
        self.assertEqual(second["disposition"], "reused")
        self.assertFalse(second["metered"])
        counts = {
            table: self.control.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "synced_reviews", "project_findings", "synced_review_findings",
                "findings_source_observations", "findings_sync_receipts",
            )
        }
        self.assertEqual(counts["synced_reviews"], 1)
        self.assertEqual(counts["project_findings"], len(first_request["findings"]))
        self.assertEqual(counts["synced_review_findings"], len(first_request["findings"]))
        self.assertEqual(counts["findings_source_observations"], 2)
        self.assertEqual(counts["findings_sync_receipts"], 2)
        self.assertEqual(self.ledger.usage(self.workspace, Meter.SYNCED_REVIEWS, PERIOD), 1)

    def test_same_source_claiming_a_different_projection_conflicts_without_writes(self):
        original = _request(self.project.project_ref, self.key, title="Original")
        changed = _request(
            self.project.project_ref, self.key, title="Changed", operation_suffix="V2",
        )
        changed["source"] = copy.deepcopy(original["source"])
        changed = validate_findings_sync_request(changed, self.key)
        self._approve(original)
        self._approve(changed)
        self._accept(original)
        before = self.control.conn.total_changes
        with self.assertRaises(FindingsSyncConflict):
            self._accept(changed)
        self.assertEqual(self.control.conn.total_changes, before)
        self.assertEqual(self.ledger.usage(self.workspace, Meter.SYNCED_REVIEWS, PERIOD), 1)

    def test_same_finding_can_change_valid_per_review_state(self):
        original = _request(self.project.project_ref, self.key, title="Warn state")
        changed = copy.deepcopy(original)
        finding = changed["findings"][0]
        self.assertEqual((finding["severity"], finding["reachable"]), ("warn", False))
        finding["severity"], finding["reachable"] = "block", True
        changed["gate_status"] = "block"
        changed["summary"]["blockers"] += 1
        changed["source"]["result_ref"] = "src1_" + "a" * 64
        changed["projection_hash"] = stable_json_hash({
            "schema_version": changed["schema_version"],
            "gate_status": changed["gate_status"],
            "summary": changed["summary"],
            "findings": changed["findings"],
        })
        changed = validate_findings_sync_request(changed, self.key)
        self._approve(original)
        self._approve(changed)
        first = self._accept(original)
        second = self._accept(changed)
        self.assertNotEqual(first["synced_review_id"], second["synced_review_id"])
        first_detail = self.service.get_review(
            self.workspace, self.project.project_ref, first["synced_review_id"],
        )
        second_detail = self.service.get_review(
            self.workspace, self.project.project_ref, second["synced_review_id"],
        )
        self.assertEqual(
            (first_detail["findings"][0]["severity"], first_detail["findings"][0]["reachable"]),
            ("warn", False),
        )
        self.assertEqual(
            (second_detail["findings"][0]["severity"], second_detail["findings"][0]["reachable"]),
            ("block", True),
        )
        self.assertEqual(
            self.control.conn.execute("SELECT COUNT(*) FROM project_findings").fetchone()[0],
            len(original["findings"]),
        )

    def test_same_source_with_changed_provenance_metadata_conflicts(self):
        original = _request(self.project.project_ref, self.key, title="Provenance")
        changed = copy.deepcopy(original)
        changed["source"]["engine_version"] = "1.1.1"
        changed = validate_findings_sync_request(changed, self.key)
        self._approve(original)
        self._approve(changed)
        self._accept(original)
        with self.assertRaises(FindingsSyncConflict):
            self._accept(changed)
        self.assertEqual(
            self.control.conn.execute(
                "SELECT COUNT(*) FROM findings_source_observations"
            ).fetchone()[0],
            1,
        )

    def test_core_rejects_non_writer_and_non_human_approval_principals(self):
        request = _request(self.project.project_ref, self.key, title="Authority")
        digest = findings_sync_request_digest(request, self.key)
        with self.assertRaises(PermissionError):
            self.service.approve(
                self.workspace,
                self.project.project_ref,
                digest,
                principal=SyncPrincipal("viewer", Role.VIEWER, "human_session"),
                now=NOW,
                expires_at=NOW + 300,
            )
        with self.assertRaises(PermissionError):
            self.service.approve(
                self.workspace,
                self.project.project_ref,
                digest,
                principal=SyncPrincipal("key", Role.MEMBER, "api_key"),
                now=NOW,
                expires_at=NOW + 300,
            )
        self._approve(request)
        with self.assertRaises(PermissionError):
            self.service.accept(
                self.workspace,
                self.project.project_ref,
                request,
                principal=SyncPrincipal("viewer", Role.VIEWER, "human_session"),
                idempotency_key=f"fs1-{digest}",
                now=NOW + 1,
            )

    def test_requires_live_immutable_approval_but_replay_survives_expiry(self):
        request = _request(self.project.project_ref, self.key, title="Approval")
        with self.assertRaises(ApprovalRequired):
            self._accept(request)
        self._approve(request, expires_at=NOW)
        with self.assertRaises(ApprovalExpired):
            self._accept(request, now=NOW + 1)
        self._approve(request, now=NOW + 2, expires_at=NOW + 100)
        receipt = self._accept(request, now=NOW + 3)
        self.assertEqual(self._accept(request, now=NOW + 1000), receipt)
        approvals = self.control.conn.execute(
            "SELECT request_digest, approved_by, approved_at, expires_at "
            "FROM findings_sync_approvals ORDER BY approved_at"
        ).fetchall()
        self.assertEqual(len(approvals), 2)
        self.assertTrue(all(row["request_digest"] == approvals[0]["request_digest"] for row in approvals))

    def test_receipt_failure_rolls_back_projection_findings_source_quota_and_audit(self):
        request = _request(self.project.project_ref, self.key, title="Rollback")
        self._approve(request)
        self.control.conn.execute("""
            CREATE TRIGGER fail_findings_receipt BEFORE INSERT ON findings_sync_receipts
            BEGIN SELECT RAISE(ABORT, 'forced receipt failure'); END
        """)
        with self.assertRaises(sqlite3.IntegrityError):
            self._accept(request)
        for table in (
            "synced_reviews", "project_findings", "synced_review_findings",
            "findings_source_observations", "findings_sync_receipts",
        ):
            self.assertEqual(
                self.control.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
                0,
                table,
            )
        self.assertEqual(
            self.control.conn.execute(
                "SELECT COUNT(*) FROM findings_sync_audit WHERE action LIKE 'sync_%'"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(self.ledger.usage(self.workspace, Meter.SYNCED_REVIEWS, PERIOD), 0)

    def test_kill_switch_denies_admission_without_spend(self):
        request = _request(self.project.project_ref, self.key, title="Paused")
        self._approve(request)
        self.ops.trip(self.workspace, actor="oncall", reason="incident")
        with self.assertRaises(KillSwitchTripped):
            self._accept(request)
        self.assertEqual(self.ledger.usage(self.workspace, Meter.SYNCED_REVIEWS, PERIOD), 0)
        self.assertEqual(
            self.control.conn.execute("SELECT COUNT(*) FROM synced_reviews").fetchone()[0],
            0,
        )

    def test_persistence_contains_only_the_findings_projection_ceiling(self):
        request = _request(self.project.project_ref, self.key, title="Never Persist This Title")
        self._approve(request)
        self._accept(request)
        forbidden = [
            "Never Persist This Title", "/api/export/bulk", "downloadBulkExport",
            "raw_openapi", "recommended_controls", "questions", "reason",
        ]
        tables = (
            "synced_reviews", "project_findings", "synced_review_findings",
            "findings_source_observations", "findings_sync_approvals",
            "findings_sync_receipts", "findings_sync_audit",
        )
        persisted = "\n".join(
            repr(tuple(row))
            for table in tables
            for row in self.control.conn.execute(f"SELECT * FROM {table}")
        )
        for value in forbidden:
            self.assertNotIn(value, persisted)

    def test_history_reads_remain_project_and_workspace_scoped(self):
        request = _request(self.project.project_ref, self.key, title="History")
        self._approve(request)
        receipt = self._accept(request)
        reviews = self.service.list_reviews(self.workspace, self.project.project_ref)
        self.assertEqual([row["synced_review_id"] for row in reviews], [receipt["synced_review_id"]])
        detail = self.service.get_review(
            self.workspace, self.project.project_ref, receipt["synced_review_id"],
        )
        self.assertEqual(detail["projection_hash"], request["projection_hash"])
        self.assertEqual(len(detail["findings"]), len(request["findings"]))
        with self.assertRaises(ProjectNotFound):
            self.service.list_reviews("ws_other", self.project.project_ref)


class FindingsSyncRaceTests(unittest.TestCase):
    def test_two_distinct_projections_racing_for_one_slot_never_overrun_quota(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = os.path.join(temporary.name, "sync-race.db")
        control = ControlPlaneStore(path)
        org = control.create_org("Race")
        workspace = control.create_workspace(org, "Race", "free", CATALOG_VERSION)
        user = control.create_user("race@example.test")
        control.add_member(workspace, user, Role.OWNER)
        projects = ProjectStore(control.conn)
        project = projects.create(workspace, "API", created_by=user, now=NOW)
        key = projects.namespace_key(workspace, project.project_ref)
        ledger = UsageLedger(control.conn)
        service = FindingsSyncService(
            control.conn,
            projects=projects,
            ledger=ledger,
            ops=OpsStore(control.conn),
            plan_for_workspace=lambda _workspace_id: plan,
        )
        requests = [
            _request(project.project_ref, key, title=f"Race {index}", operation_suffix=f"V{index}")
            for index in (1, 2)
        ]
        for request in requests:
            service.approve(
                workspace,
                project.project_ref,
                findings_sync_request_digest(request, key),
                principal=SyncPrincipal(user, Role.OWNER, "human_session"),
                now=NOW,
                expires_at=NOW + 300,
            )
        control.conn.close()
        base = get_plan("free")
        plan = replace(base, quotas={**base.quotas, Meter.SYNCED_REVIEWS: 1})
        accepted, denied = [], []
        lock = threading.Lock()

        def sync(request):
            conn = sqlite3.connect(path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            local_projects = ProjectStore(conn)
            local_ledger = UsageLedger(conn)
            local_service = FindingsSyncService(
                conn,
                projects=local_projects,
                ledger=local_ledger,
                ops=OpsStore(conn),
                plan_for_workspace=lambda _workspace_id: plan,
            )
            digest = findings_sync_request_digest(request, key)
            try:
                receipt = local_service.accept(
                    workspace,
                    project.project_ref,
                    request,
                    principal=SyncPrincipal(user, Role.OWNER, "human_session"),
                    idempotency_key=f"fs1-{digest}",
                    now=NOW + 1,
                )
                with lock:
                    accepted.append(receipt)
            except QuotaExceeded:
                with lock:
                    denied.append(digest)
            finally:
                conn.close()

        threads = [threading.Thread(target=sync, args=(request,)) for request in requests]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual((len(accepted), len(denied)), (1, 1))
        check = sqlite3.connect(path)
        check.row_factory = sqlite3.Row
        self.addCleanup(check.close)
        self.assertEqual(
            UsageLedger(check).usage(workspace, Meter.SYNCED_REVIEWS, PERIOD),
            1,
        )
        self.assertEqual(check.execute("SELECT COUNT(*) FROM synced_reviews").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
