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

    def test_current_migrations_create_tenant_bound_unique_tables(self):
        self.assertEqual(CONTROL_PLANE_MIGRATIONS[-1].version, 16)
        self.assertEqual(CONTROL_PLANE_MIGRATIONS[-1].name, "runner_context_bindings")
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

    def test_coordination_foreign_keys_bind_exact_approval_grant_and_run(self):
        def foreign_key_shapes(table):
            grouped = {}
            for row in self.conn.execute(f"PRAGMA foreign_key_list({table})"):
                grouped.setdefault(row[0], []).append((row[3], row[4]))
            return [set(values) for values in grouped.values()]

        grant_shapes = foreign_key_shapes("canary_execution_grants")
        self.assertTrue(any({
            ("approval_id", "approval_id"), ("run_id", "run_id"),
            ("environment_id", "environment_id"), ("runner_id", "runner_id"),
            ("runner_key_id", "runner_key_id"),
        }.issubset(shape) for shape in grant_shapes))
        run_shapes = foreign_key_shapes("canary_runs")
        self.assertTrue(any({
            ("grant_id", "grant_id"), ("approval_id", "approval_id"),
            ("run_id", "run_id"), ("environment_id", "environment_id"),
            ("runner_id", "runner_id"), ("runner_key_id", "runner_key_id"),
        }.issubset(shape) for shape in run_shapes))

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

    def test_migration_thirteen_canonicalizes_populated_legacy_runner_chains(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        self.addCleanup(conn.close)
        Migrator(conn, CONTROL_PLANE_MIGRATIONS[:11]).apply_all()
        conn.execute("INSERT INTO orgs VALUES(?,?,?)", ("org", "org", 1))
        conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", ("ws", "org", "ws", "free", CATALOG_VERSION, 1))
        conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner", "ws", "runner", "active", 1))
        conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", ("ws", "runner", "runner_progress:run", "a" * 64, 3, 100))
        values = {
            "workspace_id":"ws", "runner_id":"runner", "request_digest":"b" * 64,
            "response_json":"sealed", "next_nonce":"c" * 64, "created_at":1,
            "nonce_hash":"d" * 64, "key_id":"key", "method":"POST", "timestamp_ms":1,
            "signed_request_digest":"e" * 64, "body_digest":"f" * 64,
            "response_ciphertext":"cipher", "next_nonce_ciphertext":"nonce-cipher",
        }
        def ledger(chain, sequence, capability, path):
            conn.execute("INSERT INTO canary_runner_request_ledger VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                values["workspace_id"], values["runner_id"], chain, sequence,
                values["request_digest"], values["response_json"], values["next_nonce"], values["created_at"],
                values["nonce_hash"], values["key_id"], capability, values["method"], path,
                values["timestamp_ms"], values["signed_request_digest"], values["body_digest"],
                values["response_ciphertext"], values["next_nonce_ciphertext"],
            ))
        ledger("runner_progress:run", 1, "runner_progress", "/v1/workspaces/ws/runners/runner/runs/run/progress")
        ledger("runner_heartbeat:run", 1, "runner_heartbeat", "/v1/workspaces/ws/runners/runner/runs/run/heartbeat")
        ledger("runner_heartbeat:run", 2, "runner_heartbeat", "/v1/workspaces/ws/runners/runner/runs/run/stop-ack")
        conn.commit()

        self.assertEqual(Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all(), [12, 13, 14, 15, 16])
        self.assertEqual([tuple(row) for row in conn.execute(
            "SELECT chain_name,next_sequence,generation FROM canary_runner_chain_cursors ORDER BY chain_name"
        )], [("heartbeat:run", 2, 0), ("progress:run", 3, 0), ("stop-ack:run", 3, 0)])
        self.assertEqual(tuple(conn.execute("SELECT chain_name,next_sequence FROM canary_runner_nonce_chains").fetchone()), ("progress:run", 3))
        self.assertEqual([tuple(row) for row in conn.execute(
            "SELECT chain_name,sequence,generation FROM canary_runner_request_ledger ORDER BY chain_name"
        )], [("heartbeat:run", 1, 0), ("progress:run", 1, 0), ("stop-ack:run", 2, 0)])

    def test_migration_thirteen_aborts_atomically_on_canonical_chain_collision(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        Migrator(conn, CONTROL_PLANE_MIGRATIONS[:12]).apply_all()
        conn.execute("INSERT INTO orgs VALUES(?,?,?)", ("org", "org", 1))
        conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", ("ws", "org", "ws", "free", CATALOG_VERSION, 1))
        conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner", "ws", "runner", "active", 1))
        conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", ("ws", "runner", "runner_progress:run", "a" * 64, 1, 100))
        conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", ("ws", "runner", "progress:run", "b" * 64, 1, 100)); conn.commit()
        with self.assertRaises(MigrationError):
            Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
        self.assertEqual(Migrator(conn, CONTROL_PLANE_MIGRATIONS).current_version(), 12)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM canary_runner_nonce_chains").fetchone()[0], 2)

    def test_migration_thirteen_upgrades_populated_v12_resync_challenges_with_foreign_keys_on(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        self.addCleanup(conn.close)
        Migrator(conn, CONTROL_PLANE_MIGRATIONS[:12]).apply_all()
        conn.execute("INSERT INTO orgs VALUES(?,?,?)", ("org", "org", 1))
        conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", ("ws", "org", "ws", "free", CATALOG_VERSION, 1))
        conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner", "ws", "runner", "active", 1))
        for index, status in enumerate(("pending", "completed", "invalidated"), 1):
            chain = f"progress:run-{index}"
            conn.execute("INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)", ("ws", "runner", chain, index, 0, 1))
            conn.execute(
                "INSERT INTO canary_runner_resync_challenges VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f"rrs_{index:032x}", "ws", "runner", chain, "a" * 64, "b" * 64,
                 "c" * 64, "client-cipher", "server-cipher", status, 1, 2,
                 "completed-cipher" if status == "completed" else None,
                 "d" * 64 if status == "completed" else None,
                 1.5 if status == "completed" else None),
            )
        conn.commit()

        self.assertEqual(Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all(), [13, 14, 15, 16])
        self.assertEqual(Migrator(conn, CONTROL_PLANE_MIGRATIONS).current_version(), 16)
        self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertEqual(
            [tuple(row) for row in conn.execute(
                "SELECT challenge_id,status,challenge_generation,result_generation "
                "FROM canary_runner_resync_challenges ORDER BY challenge_id"
            )],
            [(f"rrs_{index:032x}", "invalidated", 0, None) for index in range(1, 4)],
        )

    def test_migration_sixteen_adds_closed_runner_context_binding_tables(self):
        self.seed_root("ws", "prj")
        tables = {row[0] for row in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        self.assertTrue({
            "canary_runner_context_bindings",
            "canary_runner_context_projection_links",
            "canary_runner_context_events",
        }.issubset(tables))
        binding_sql = self.conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='canary_runner_context_bindings'"
        ).fetchone()[0]
        self.assertIn("status IN ('active','revoked','expired')", binding_sql)
        self.assertIn("environment_class IN ('staging','sandbox')", binding_sql)

    def test_migration_thirteen_runner_constraints_reject_hostile_rows(self):
        self.seed_root("ws", "prj")
        self.conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner", "ws", "runner", "active", 1))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO canary_runner_pairings(pairing_id,workspace_id,runner_id,invitation_hash,status,created_at,expires_at,display_name) VALUES(?,?,?,?,?,?,?,?)", ("pair", "ws", "", "a" * 64, "invited", 1, 2, " padded "))
        self.conn.execute("INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)", ("ws", "runner", "claim", 1, 0, 1))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO canary_runner_request_ledger(workspace_id,runner_id,chain_name,sequence,generation,request_digest,response_json,next_nonce,created_at,nonce_hash,key_id,capability,method,path,timestamp_ms,signed_request_digest,body_digest,response_ciphertext,next_nonce_ciphertext) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("ws", "runner", "claim", 1, 0, "a" * 64, "sealed", "b" * 64, 1, "c" * 64, "key", "runner_claim", "POST", "/claim", 1, "d" * 64, "e" * 64, None, "cipher"))

    def test_migration_fourteen_quarantines_archive_derived_active_rows_without_touching_exact_rows(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        self.addCleanup(conn.close)
        Migrator(conn, CONTROL_PLANE_MIGRATIONS[:12]).apply_all()
        conn.execute("INSERT INTO orgs VALUES(?,?,?)", ("org", "org", 1))
        conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)", ("ws", "org", "ws", "free", CATALOG_VERSION, 1))
        conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner", "ws", "runner", "active", 1))
        values = ("a" * 64, "sealed", "opaque", 1, "b" * 64, "key",
                  "runner_progress", "POST", 1, "c" * 64, "d" * 64, "cipher", "nonce-cipher")
        for chain, run_id in (("evil:run", "run"), ("progress:real", "real")):
            path = f"/v1/workspaces/ws/runners/runner/runs/{run_id}/progress"
            conn.execute(
                "INSERT INTO canary_runner_request_ledger VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("ws", "runner", chain, 1, values[0], values[1], values[2], values[3],
                 values[4], values[5], values[6], values[7], path, values[8], values[9],
                 values[10], values[11], values[12]),
            )
        conn.commit()

        self.assertEqual(Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all(), [13, 14, 15, 16])
        self.assertEqual(
            [tuple(row) for row in conn.execute("SELECT chain_name,sequence FROM canary_runner_request_ledger")],
            [("progress:real", 1)],
        )
        self.assertEqual(
            [tuple(row) for row in conn.execute("SELECT chain_name FROM canary_runner_chain_cursors")],
            [("progress:real",)],
        )
        self.assertEqual(
            [tuple(row) for row in conn.execute("SELECT legacy_chain_name,archive_reason FROM canary_runner_request_ledger_archive")],
            [("evil:run", "path_chain_mismatch")],
        )

    def test_migration_fourteen_runner_constraints_reject_hostile_chain_display_and_challenge_rows(self):
        self.seed_root("ws", "prj")
        self.conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner", "ws", "runner", "active", 1))
        pairing = "INSERT INTO canary_runner_pairings(pairing_id,workspace_id,runner_id,invitation_hash,status,created_at,expires_at,display_name) VALUES(?,?,?,?,?,?,?,?)"
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(pairing, ("pair-tab", "ws", "", "a" * 64, "invited", 1, 2, "\tbad"))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(pairing, ("pair-null", "ws", "", "b" * 64, "invited", 1, 2, None))
        for index, chain in enumerate(("progress:a/b", "result:" + "a" * 129), 1):
            with self.assertRaises(sqlite3.IntegrityError):
                self.conn.execute("INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)", ("ws", "runner", chain, 1, 0, index))
        self.conn.execute("INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)", ("ws", "runner", "progress:run", 1, 0, 1))
        challenge = "INSERT INTO canary_runner_resync_challenges(challenge_id,workspace_id,runner_id,chain_name,client_nonce_hash,server_challenge_hash,signed_digest,client_nonce_ciphertext,server_challenge_ciphertext,challenge_generation,result_generation,status,created_at,expires_at,completed_response_ciphertext,complete_signed_digest,completed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(challenge, ("rrs_" + "1" * 32, "ws", "runner", "progress:run", "a" * 64, "b" * 64, "c" * 64, "client", "server", 0, None, "pending", 1, 62, None, None, None))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(challenge, ("rrs_" + "2" * 32, "ws", "runner", "progress:run", "a" * 64, "b" * 64, "c" * 64, "client", "server", 0, 1, "invalidated", 1, 2, "completed", "d" * 64, 1.5))

    def test_runner_startup_rejects_non_nfc_or_category_c_persisted_display_names(self):
        from heel.saas.runner_auth import validate_runner_auth_schema

        self.seed_root("ws", "prj")
        self.conn.execute(
            "INSERT INTO canary_runner_pairings(pairing_id,workspace_id,runner_id,invitation_hash,status,created_at,expires_at,display_name) VALUES(?,?,?,?,?,?,?,?)",
            ("pair", "ws", "runner", "a" * 64, "activated", 1, 2, "Cafe\u0301"),
        )
        self.conn.commit()
        with self.assertRaisesRegex(RuntimeError, "display name"):
            validate_runner_auth_schema(self.conn)
        self.conn.execute("UPDATE canary_runner_pairings SET display_name=? WHERE pairing_id='pair'", ("A\u200dB",))
        self.conn.commit()
        with self.assertRaisesRegex(RuntimeError, "display name"):
            validate_runner_auth_schema(self.conn)

    def test_direct_control_plane_runtime_uses_final_runner_foreign_keys(self):
        from heel.saas.http_api import ControlPlane

        control = ControlPlane()
        self.addCleanup(control.close)
        conn = control.store.conn
        org = control.store.create_org("org")
        one = control.store.create_workspace(org, "one", "free", CATALOG_VERSION)
        two = control.store.create_workspace(org, "two", "free", CATALOG_VERSION)
        conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner-one", one, "one", "active", 1))
        conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", ("runner-two", two, "two", "active", 1)); conn.commit()
        for table in ("canary_runner_nonce_chains", "canary_runner_request_ledger", "canary_runner_rotations", "canary_runner_identity_records", "canary_runner_audit_records"):
            self.assertTrue(conn.execute(f"PRAGMA foreign_key_list({table})").fetchall(), table)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO canary_runner_pairings(pairing_id,workspace_id,runner_id,invitation_hash,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?)", ("orphan", "missing", "", "a" * 64, "invited", 1, 2))
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", (one, "runner-two", "claim", "a" * 64, 1, 2))
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO canary_runner_identity_records VALUES(?,?,?,?,?)", (one, "runner-two", "{}", "a" * 64, 1))

    def test_ops_first_runtime_initialization_cannot_mask_coordination_schema(self):
        from heel.saas.canary_store import CanaryStore
        from heel.saas.ops import OpsStore

        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        OpsStore(conn)
        CanaryStore(conn)
        self.assertIn(
            "verification_record_digest",
            {row[1] for row in conn.execute("PRAGMA table_info(canary_environments)")},
        )
        self.assertIn(
            "runner_key_id",
            {row[1] for row in conn.execute("PRAGMA table_info(canary_approval_projections)")},
        )
        self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_direct_control_plane_runner_schema_matches_migration_eleven_sql_and_keys(self):
        from heel.saas.http_api import ControlPlane

        migrated = sqlite3.connect(":memory:")
        self.addCleanup(migrated.close)
        Migrator(migrated, CONTROL_PLANE_MIGRATIONS).apply_all()
        control = ControlPlane()
        self.addCleanup(control.close)
        runtime = control.store.conn
        tables = (
            "canary_runner_pairings", "canary_runner_nonce_chains",
            "canary_runner_request_ledger", "canary_runner_rotations",
            "canary_runner_identity_records", "canary_runner_audit_records",
            "canary_approval_projections", "canary_execution_grants", "canary_runs",
            "canary_consumed_nonces", "canary_run_events",
            "canary_operational_receipts", "canary_audit_records",
            "canary_disclosure_requests", "canary_disclosure_permits",
            "canary_findings_projections", "canary_reaper_state", "canary_control_generation",
            "canary_runner_context_bindings", "canary_runner_context_projection_links",
            "canary_runner_context_events",
        )
        for table in tables:
            with self.subTest(table=table):
                migrated_sql = migrated.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()[0]
                runtime_sql = runtime.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()[0]
                self.assertEqual("".join(migrated_sql.split()), "".join(runtime_sql.split()))
                self.assertEqual([tuple(row) for row in migrated.execute(f"PRAGMA foreign_key_list({table})")], [tuple(row) for row in runtime.execute(f"PRAGMA foreign_key_list({table})")])
                self.assertEqual([tuple(row) for row in migrated.execute(f"PRAGMA index_list({table})")], [tuple(row) for row in runtime.execute(f"PRAGMA index_list({table})")])

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
        approval_sql = (
            "INSERT INTO canary_approval_projections(approval_id,workspace_id,project_ref,"
            "run_id,environment_id,runner_id,runner_key_id,manifest_digest,projection_digest,"
            "signing_key_id,status,projection_json,scenario_ids_json,budgets_json,uploaded_by,"
            "created_at,expires_at,purge_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        )
        approval = (
            "approval-1", "ws-1", "prj-1", "run-1", "env-1", "runner-1", "key-1",
            "a" * 64, "b" * 64, "key-1", "awaiting_execution_approval", "{}", "[]", "{}",
            "owner", 1, 2, 3,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            execute(approval_sql, approval[:4] + ("env-2",) + approval[5:])
        execute(approval_sql, approval)

        grant_sql = (
            "INSERT INTO canary_execution_grants(grant_id,workspace_id,project_ref,approval_id,"
            "run_id,environment_id,runner_id,runner_key_id,nonce_hash,grant_digest,grant_json,status,"
            "reservation_id,meter,period,idempotency_key,issued_at,expires_at,purge_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        )
        grant = (
            "grant-1", "ws-1", "prj-1", "approval-1", "run-1", "env-1", "runner-1",
            "key-1", "c" * 64, "d" * 64, "{}", "issued", "reservation-1", "canary_runs",
            "2026-08", "ca1-" + "e" * 64, 1, 2, 3,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            execute(grant_sql, grant[:5] + ("env-1-alt",) + grant[6:])
        execute(grant_sql, grant)

        run_sql = (
            "INSERT INTO canary_runs(run_id,workspace_id,project_ref,approval_id,grant_id,"
            "environment_id,runner_id,runner_key_id,status,error_category,stop_reason,"
            "source_event_sequence,cloud_event_sequence,stop_generation,stop_ack_late,quota_state,"
            "kill_switch_generation,created_at,updated_at,purge_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        )
        run = (
            "run-1", "ws-1", "prj-1", "approval-1", "grant-1", "env-1", "runner-1", "key-1",
            "approved", "none", "none", -1, 0, 0, 0, "reserved", 0, 1, 1, 3,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            execute(run_sql, run[:5] + ("env-1-alt",) + run[6:])
        execute(run_sql, run)
        with self.assertRaises(sqlite3.IntegrityError):
            execute(
                "INSERT INTO canary_consumed_nonces VALUES(?,?,?,?,?,?,?,?,?)",
                ("f" * 64, "ws-2", "prj-2", "runner-2", "run-1", "grant-1",
                 "execution_grant", 1, 2),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            execute(
                "INSERT INTO canary_run_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("event-cross", "ws-2", "prj-2", "run-1", 0, "grant_claimed", "{}",
                 "f" * 64, None, "system", "system", None, 1),
            )

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
        self.assertEqual(migration.apply_all(), [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        self.assertEqual(migration.current_version(), 16)
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
