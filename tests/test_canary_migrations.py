import sqlite3
import unittest

from heel.saas.catalog import (
    CATALOG_VERSION, LEGACY_CATALOG_VERSION, PRE_CANARY_CATALOG_VERSION, Meter, get_plan,
)
from heel.saas.ledger import IdempotencyConflict, UsageLedger
from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, MigrationError, Migrator


class CanaryMigrationTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.addCleanup(self.conn.close)
        Migrator(self.conn, CONTROL_PLANE_MIGRATIONS).apply_all()

    def table_columns(self, table):
        return {row[1] for row in self.conn.execute(f"PRAGMA table_info({table})")}

    def seed_root(self, workspace_id: str, project_ref: str) -> None:
        self.conn.execute(
            "INSERT INTO workspaces VALUES(?,?,?,?,?,?)",
            (workspace_id, "org", workspace_id, "free", CATALOG_VERSION, 1),
        )
        self.conn.execute(
            "INSERT INTO projects VALUES(?,?,?,?,?)",
            (workspace_id, project_ref, project_ref, "owner", 1),
        )

    def test_migration_six_creates_tenant_bound_unique_tables(self):
        self.assertEqual(CONTROL_PLANE_MIGRATIONS[-1].version, 11)
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

        self.seed_root("ws", "prj")
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

    def test_migration_eleven_binds_runner_lifecycle_records_and_checks_vocabularies(self):
        self.seed_root("ws", "prj")
        self.conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner", "ws", "runner", "active", 1))
        for table in ("canary_runner_nonce_chains", "canary_runner_request_ledger", "canary_runner_rotations", "canary_runner_identity_records"):
            foreign = self.conn.execute(f"PRAGMA foreign_key_list({table})").fetchall()
            self.assertTrue(foreign, table)
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", ("ws", "runner", "claim", "a" * 64, 0, 1))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO canary_runner_pairings(pairing_id,workspace_id,runner_id,invitation_hash,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?)", ("pair", "ws", "", "a" * 64, "surprise", 1, 2))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO canary_runner_rotations(pairing_id,workspace_id,runner_id,phrase,public_key,fingerprint,key_id,runner_version,adapters_json,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", ("rotation", "other", "runner", "phrase", "A" * 44, "a" * 64, "k", "v", "{}", "rotation_pending", 1, 2))

    def test_migration_eleven_never_promotes_pre_pairing_runner_skeletons(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        Migrator(conn, CONTROL_PLANE_MIGRATIONS[:10]).apply_all()
        conn.execute("INSERT INTO orgs VALUES(?,?,?)", ("org", "org", 1))
        conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", ("ws", "org", "ws", "free", CATALOG_VERSION, 1))
        conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("skeleton", "ws", "skeleton", "active", 1)); conn.commit()
        Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
        self.assertEqual(conn.execute("SELECT status FROM canary_runners WHERE runner_id='skeleton'").fetchone()[0], "disabled")

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

    def test_canary_foreign_keys_reject_cross_workspace_or_project_references(self):
        def execute(sql, values):
            self.conn.execute(sql, values)

        with self.assertRaises(sqlite3.IntegrityError):
            execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("missing-runner", "missing-ws", "runner", "active", 1))
        with self.assertRaises(sqlite3.IntegrityError):
            execute("INSERT INTO canary_environments(environment_id,workspace_id,project_ref,origin,environment_class,status,created_at) VALUES(?,?,?,?,?,?,?)", ("missing-env", "missing-ws", "missing-prj", "https://missing.example", "staging", "verified", 1))
        self.seed_root("ws-1", "prj-1")
        self.seed_root("ws-2", "prj-2")
        execute("INSERT INTO canary_environments(environment_id,workspace_id,project_ref,origin,environment_class,status,created_at) VALUES(?,?,?,?,?,?,?)", ("env-1", "ws-1", "prj-1", "https://one.example", "staging", "verified", 1))
        execute("INSERT INTO canary_environments(environment_id,workspace_id,project_ref,origin,environment_class,status,created_at) VALUES(?,?,?,?,?,?,?)", ("env-1-alt", "ws-1", "prj-1", "https://one-alt.example", "staging", "verified", 1))
        execute("INSERT INTO canary_environments(environment_id,workspace_id,project_ref,origin,environment_class,status,created_at) VALUES(?,?,?,?,?,?,?)", ("env-2", "ws-2", "prj-2", "https://two.example", "staging", "verified", 1))
        execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner-1", "ws-1", "runner", "active", 1))
        execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner-1-alt", "ws-1", "runner", "active", 1))
        execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner-2", "ws-2", "runner", "active", 1))
        with self.assertRaises(sqlite3.IntegrityError):
            execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,?)", ("key-cross", "ws-1", "runner-2", "pk-cross", "active", 1, None))
        execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,?)", ("key-1", "ws-1", "runner-1", "pk-1", "active", 1, None))
        with self.assertRaises(sqlite3.IntegrityError):
            execute("INSERT INTO canary_consumed_nonces VALUES(?,?,?,?,?)", ("nonce-cross", "ws-1", "runner-2", 1, 2))
        execute("INSERT INTO canary_approval_projections VALUES(?,?,?,?,?,?,?,?,?)", ("approval-1", "ws-1", "prj-1", "env-1", "runner-1", "a" * 64, "{}", 1, 2))
        with self.assertRaises(sqlite3.IntegrityError):
            execute("INSERT INTO canary_execution_grants VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("grant-mixed-environment", "ws-1", "prj-1", "approval-1", "env-1-alt", "runner-1", "nonce-gme", "m" * 64, "approved", 2, 1))
        with self.assertRaises(sqlite3.IntegrityError):
            execute("INSERT INTO canary_execution_grants VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("grant-mixed-runner", "ws-1", "prj-1", "approval-1", "env-1", "runner-1-alt", "nonce-gmr", "n" * 64, "approved", 2, 1))
        with self.assertRaises(sqlite3.IntegrityError):
            execute("INSERT INTO canary_approval_projections VALUES(?,?,?,?,?,?,?,?,?)", ("approval-cross", "ws-1", "prj-1", "env-2", "runner-1", "b" * 64, "{}", 1, 2))
        with self.assertRaises(sqlite3.IntegrityError):
            execute("INSERT INTO canary_execution_grants VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("grant-cross", "ws-1", "prj-1", "approval-1", "env-2", "runner-1", "nonce-gc", "c" * 64, "approved", 2, 1,))
        execute("INSERT INTO canary_execution_grants VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("grant-1", "ws-1", "prj-1", "approval-1", "env-1", "runner-1", "nonce-g1", "d" * 64, "approved", 2, 1,))
        with self.assertRaises(sqlite3.IntegrityError):
            execute("INSERT INTO canary_runs VALUES(?,?,?,?,?,?,?,?,?)", ("run-mixed-environment", "ws-1", "prj-1", "grant-1", "env-1-alt", "runner-1", "approved", 1, 1))
        with self.assertRaises(sqlite3.IntegrityError):
            execute("INSERT INTO canary_runs VALUES(?,?,?,?,?,?,?,?,?)", ("run-mixed-runner", "ws-1", "prj-1", "grant-1", "env-1", "runner-1-alt", "approved", 1, 1))
        with self.assertRaises(sqlite3.IntegrityError):
            execute("INSERT INTO canary_runs VALUES(?,?,?,?,?,?,?,?,?)", ("run-cross", "ws-1", "prj-1", "grant-1", "env-2", "runner-1", "approved", 1, 1))
        execute("INSERT INTO canary_runs VALUES(?,?,?,?,?,?,?,?,?)", ("run-1", "ws-1", "prj-1", "grant-1", "env-1", "runner-1", "approved", 1, 1))
        for table, columns, values in (
            ("canary_run_events", "event_id,workspace_id,project_ref,run_id,sequence,event_type,payload_digest,created_at", ("event-cross", "ws-2", "prj-2", "run-1", 0, "claimed", "e" * 64, 1)),
            ("canary_operational_receipts", "run_id,workspace_id,project_ref,receipt_digest,receipt_json,created_at,updated_at", ("run-1", "ws-2", "prj-2", "f" * 64, "{}", 1, 1)),
            ("canary_disclosure_permits", "permit_id,workspace_id,project_ref,run_id,projection_digest,status,expires_at,created_at", ("permit-cross", "ws-2", "prj-2", "run-1", "g" * 64, "active", 2, 1)),
            ("canary_findings_projections", "finding_id,workspace_id,project_ref,run_id,projection_digest,projection_json,created_at", ("finding-cross", "ws-2", "prj-2", "run-1", "h" * 64, "{}", 1)),
            ("canary_audit_records", "audit_id,workspace_id,project_ref,run_id,subject_ref,action,actor,payload_digest,created_at", ("audit-cross", "ws-2", "prj-2", "run-1", "run-1", "approved", "owner", "i" * 64, 1)),
        ):
            with self.subTest(table=table), self.assertRaises(sqlite3.IntegrityError):
                execute(f"INSERT INTO {table}({columns}) VALUES({','.join('?' for _ in values)})", values)
        execute("INSERT INTO canary_audit_records VALUES(?,?,?,?,?,?,?,?,?)", ("audit-1", "ws-1", "prj-1", "run-1", "run-1", "approved", "owner", "i" * 64, 1))

    def test_failed_migration_six_is_atomic_and_retries_after_repair(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        prior = Migrator(conn, CONTROL_PLANE_MIGRATIONS[:5])
        self.assertEqual(prior.apply_all(), [1, 2, 3, 4, 5])
        rows = (
            ("refund-1", "ws", "canary_runs", "2026-08", "platform_fault_refund", -1, "resv-1", None, None, 1),
            ("refund-2", "ws", "canary_runs", "2026-08", "platform_fault_refund", -1, "resv-1", None, None, 2),
        )
        conn.executemany("INSERT INTO usage_ledger VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
        migration = Migrator(conn, CONTROL_PLANE_MIGRATIONS)
        with self.assertRaises(MigrationError):
            migration.apply_all()
        self.assertEqual(migration.current_version(), 5)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(usage_ledger)")}
        self.assertNotIn("reason", columns)
        self.assertIsNone(conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='canary_environments'"
        ).fetchone())
        conn.execute("DELETE FROM usage_ledger WHERE entry_id='refund-2'")
        conn.commit()
        self.assertEqual(migration.apply_all(), [6, 7, 8, 9, 10, 11])
        self.assertEqual(migration.current_version(), 11)
        self.assertIn("reason", {row[1] for row in conn.execute("PRAGMA table_info(usage_ledger)")})

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
