import sqlite3
import unittest

from heel.saas.catalog import (
    CATALOG_VERSION, LEGACY_CATALOG_VERSION, PRE_CANARY_CATALOG_VERSION, Meter, get_plan,
)
from heel.saas.ledger import IdempotencyConflict, UsageLedger
from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator


class CanaryMigrationTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.addCleanup(self.conn.close)
        Migrator(self.conn, CONTROL_PLANE_MIGRATIONS).apply_all()

    def table_columns(self, table):
        return {row[1] for row in self.conn.execute(f"PRAGMA table_info({table})")}

    def test_migration_six_creates_tenant_bound_unique_tables(self):
        self.assertEqual(CONTROL_PLANE_MIGRATIONS[-1].version, 6)
        tables = (
            "canary_environments", "canary_runners", "canary_runner_keys",
            "canary_consumed_nonces", "canary_approval_projections",
            "canary_execution_grants", "canary_runs", "canary_run_events",
            "canary_operational_receipts", "canary_disclosure_permits",
            "canary_findings_projections", "canary_audit_records",
        )
        for table in tables:
            self.assertIn("workspace_id", self.table_columns(table))
        for table in (
            "canary_environments", "canary_approval_projections", "canary_execution_grants",
            "canary_runs", "canary_run_events", "canary_operational_receipts",
            "canary_disclosure_permits", "canary_findings_projections", "canary_audit_records",
        ):
            self.assertIn("project_ref", self.table_columns(table))

        self.conn.execute(
            "INSERT INTO canary_runners VALUES(?,?,?,?,?)",
            ("runner-1", "ws", "runner", "active", 1),
        )
        self.conn.execute(
            "INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,?)",
            ("key-1", "ws", "runner-1", "public-key", "active", 1, None),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,?)",
                ("key-2", "ws", "runner-1", "public-key", "active", 1, None),
            )

    def test_current_catalog_only_has_new_meters(self):
        current_free = get_plan("free", CATALOG_VERSION)
        self.assertEqual(current_free.quota(Meter.ACTIVE_RUNNERS), 1)
        self.assertEqual(current_free.quota(Meter.CANARY_RUNS), 10)
        for plan_id in ("pro", "team", "enterprise"):
            self.assertEqual(get_plan(plan_id, CATALOG_VERSION).quota(Meter.ACTIVE_RUNNERS), 0)
            self.assertEqual(get_plan(plan_id, CATALOG_VERSION).quota(Meter.CANARY_RUNS), 0)
        for version in (PRE_CANARY_CATALOG_VERSION, LEGACY_CATALOG_VERSION):
            for plan_id in ("free", "pro", "team", "enterprise"):
                self.assertEqual(get_plan(plan_id, version).quota(Meter.ACTIVE_RUNNERS), 0)
                self.assertEqual(get_plan(plan_id, version).quota(Meter.CANARY_RUNS), 0)

    def test_consumed_canary_refund_is_once_and_reason_bounded(self):
        plan = get_plan("free")
        ledger = UsageLedger(self.conn)
        reservation = ledger.reserve(plan, "ws", Meter.CANARY_RUNS, 1, "2026-08")
        self.conn.execute("BEGIN IMMEDIATE")
        self.assertTrue(ledger.consume_in_transaction(reservation.reservation_id))
        self.conn.commit()
        self.assertEqual(ledger.usage("ws", Meter.CANARY_RUNS, "2026-08"), 1)
        reason = "platform_fault"
        self.conn.execute("BEGIN IMMEDIATE")
        self.assertTrue(ledger.refund_consumed_in_transaction(reservation.reservation_id, reason))
        self.conn.commit()
        self.assertEqual(ledger.usage("ws", Meter.CANARY_RUNS, "2026-08"), 0)
        linked = self.conn.execute(
            "SELECT kind, amount, reason FROM usage_ledger WHERE reservation_id=? "
            "AND kind='platform_fault_refund'",
            (reservation.reservation_id,)).fetchall()
        self.assertEqual([tuple(row) for row in linked], [("platform_fault_refund", -1, reason)])
        self.conn.execute("BEGIN IMMEDIATE")
        self.assertFalse(ledger.refund_consumed_in_transaction(reservation.reservation_id, reason))
        self.conn.rollback()

    def test_compensated_reservation_cannot_replay_an_idempotency_key(self):
        ledger = UsageLedger(self.conn)
        reservation = ledger.reserve(
            get_plan("free"), "ws", Meter.CANARY_RUNS, 1, "2026-08", idempotency_key="run-1",
        )
        self.conn.execute("BEGIN IMMEDIATE")
        ledger.consume_in_transaction(reservation.reservation_id)
        self.conn.commit()
        self.conn.execute("BEGIN IMMEDIATE")
        ledger.refund_consumed_in_transaction(reservation.reservation_id, "runner_fault")
        self.conn.commit()
        with self.assertRaises(IdempotencyConflict):
            ledger.reserve(
                get_plan("free"), "ws", Meter.CANARY_RUNS, 1, "2026-08", idempotency_key="run-1",
            )

    def test_legacy_meter_consumption_cannot_be_refunded(self):
        ledger = UsageLedger(self.conn)
        reservation = ledger.reserve(get_plan("free"), "ws", Meter.RUNS, 1, "2026-08")
        self.conn.execute("BEGIN IMMEDIATE")
        ledger.consume_in_transaction(reservation.reservation_id)
        self.conn.commit()
        self.conn.execute("BEGIN IMMEDIATE")
        with self.assertRaises(ValueError):
            ledger.refund_consumed_in_transaction(reservation.reservation_id, "platform_fault")
        self.conn.rollback()
