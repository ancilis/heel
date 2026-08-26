from __future__ import annotations

import json
import sqlite3
import unittest
from copy import deepcopy

from heel.canary_contracts import canonical_bytes, canonical_digest, validate_runner_context_binding
from heel.crypto import SigningAuthority
from heel.saas.canary_runs import CanaryRunError
from heel.saas.runner_contexts import CONTEXT_DOMAIN, RunnerContextBindingService, RunnerContextError
from tests.canary_test_support import (
    Clock, ENVIRONMENT, NOW_MS, PROJECT, RUNNER, VERIFICATION_DIGEST, WORKSPACE,
    approval_projection, connect, seed_authority, service,
)


class RunnerContextBindingServiceTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect()
        self.addCleanup(self.conn.close)
        self.clock = Clock()
        self.runner = seed_authority(self.conn)
        self.cloud = seed_authority.__globals__["SigningAuthority"].generate()
        self.service = RunnerContextBindingService(self.conn, signing=self.cloud, clock=self.clock)

    def test_owner_creates_single_active_domain_signed_binding(self):
        binding = self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id},
            actor="user_owner", role="owner",
        )
        self.assertEqual(binding["schema_version"], "heel.runner-context-binding.v1")
        self.assertEqual(binding["authorization"], {"user_id": "user_owner", "role": "owner"})
        self.assertEqual(validate_runner_context_binding(binding), binding)
        row = self.conn.execute(
            "SELECT binding_json,status FROM canary_runner_context_bindings"
        ).fetchone()
        self.assertEqual(row["status"], "active")
        self.assertEqual(json.loads(row["binding_json"]), binding)
        with self.assertRaisesRegex(Exception, "conflict"):
            self.service.create(
                WORKSPACE, PROJECT,
                {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
                 "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
                 "runner_key_id": self.runner.key_id},
                actor="user_owner", role="owner",
            )

    def test_reaper_context_batches_refuse_unbounded_limits(self):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            for method in (
                self.service.expire_due_batch_in_transaction,
                self.service.cancel_due_batch_in_transaction,
            ):
                for limit in (0, 129, 10_000_000, True, 1.0, "128"):
                    with self.assertRaisesRegex(ValueError, "invalid runner context batch limit"):
                        method(self.service._now_ms(), limit=limit)
                for now_ms in (-1, True, 1.0, "1", 9_007_199_254_740_992):
                    with self.assertRaisesRegex(ValueError, "invalid runner context expiry time"):
                        method(now_ms)
        finally:
            self.conn.rollback()

    def test_runner_list_expiry_is_scoped_and_never_transitions_another_tenant(self):
        other_workspace = "ws_other_context"
        other_project = "prj_other_context"
        other_runner = "runr_other_context"
        other_environment = "env_other_context"
        self.conn.execute("INSERT INTO orgs VALUES(?,?,?)", ("org_other_context", "Other", NOW_MS // 1000))
        self.conn.execute(
            "INSERT INTO workspaces VALUES(?,?,?,?,?,?)",
            (other_workspace, "org_other_context", "Other", "free", "2025.01", NOW_MS // 1000),
        )
        self.conn.execute(
            "INSERT INTO projects VALUES(?,?,?,?,?)",
            (other_workspace, other_project, "Other", "user_owner", NOW_MS // 1000),
        )
        self.conn.execute(
            "INSERT INTO memberships VALUES(?,?,?,?)",
            (other_workspace, "user_owner", "owner", NOW_MS // 1000),
        )
        other_signer = seed_authority(
            self.conn, workspace_id=other_workspace, project_ref=other_project,
            environment_id=other_environment, runner_id=other_runner,
            proof_expires_at=self.clock.value + 2 * 60 * 60,
        )
        other = self.service.create(
            other_workspace, other_project,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": other_environment,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": other_runner,
             "runner_key_id": other_signer.key_id}, actor="user_owner", role="owner",
        )
        self.clock.value += 3 * 60 * 60

        self.conn.execute("BEGIN IMMEDIATE")
        listed = self.service.list_for_runner_in_transaction(WORKSPACE, RUNNER, self.runner.key_id)
        self.conn.commit()
        self.assertEqual(listed["contexts"], [])
        self.assertEqual(self.conn.execute(
            "SELECT status FROM canary_runner_context_bindings WHERE rcb_id=?", (other["binding_id"],),
        ).fetchone()[0], "active")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM canary_runner_context_events WHERE rcb_id=? AND action='expired'",
            (other["binding_id"],),
        ).fetchone()[0], 0)

    def test_affinity_request_checks_do_not_rescan_retained_claim_history(self):
        statements: list[str] = []
        self.conn.set_trace_callback(statements.append)
        try:
            self.service.list_for_human(WORKSPACE, PROJECT, actor="user_owner")
            self.service.create(
                WORKSPACE, PROJECT,
                {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
                 "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
                 "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
            )
        finally:
            self.conn.set_trace_callback(None)
        self.assertFalse(any(
            "first_claimed_at_ms is not null" in statement.lower() for statement in statements
        ))

    def test_generic_approval_expiry_anti_join_binds_the_full_context_link_identity(self):
        runs = service(self.conn, self.clock)
        statements: list[str] = []
        self.conn.set_trace_callback(statements.append)
        try:
            runs.expire_and_reconcile()
        finally:
            self.conn.set_trace_callback(None)
        anti_join = next(
            statement for statement in statements
            if "FROM canary_runner_context_projection_links l" in statement
            and "canary_runner_context_bindings b" in statement
        )
        for condition in (
            "b.environment_id=l.environment_id",
            "b.runner_id=l.runner_id",
            "b.runner_key_id=l.runner_key_id",
        ):
            self.assertIn(condition, anti_join)

    def test_runner_cannot_receive_two_active_contexts_across_projects(self):
        self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
        )
        other_project = "prj_other"
        other_environment = "env_other"
        self.conn.execute(
            "INSERT INTO projects VALUES(?,?,?,?,?)",
            (WORKSPACE, other_project, "Other", "user_owner", NOW_MS / 1000),
        )
        source = self.conn.execute(
            "SELECT * FROM canary_environments WHERE workspace_id=? AND project_ref=? AND environment_id=?",
            (WORKSPACE, PROJECT, ENVIRONMENT),
        ).fetchone()
        columns = tuple(source.keys())
        values = [source[column] for column in columns]
        values[columns.index("environment_id")] = other_environment
        values[columns.index("project_ref")] = other_project
        self.conn.execute(
            f"INSERT INTO canary_environments({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
            values,
        )
        self.conn.commit()

        with self.assertRaisesRegex(RunnerContextError, "conflict"):
            self.service.create(
                WORKSPACE, other_project,
                {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": other_environment,
                 "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
                 "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
            )
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM canary_runner_context_bindings WHERE workspace_id=? AND runner_id=? AND status='active'",
            (WORKSPACE, RUNNER),
        ).fetchone()[0], 1)

    def test_first_claim_fixes_runner_affinity_and_blocks_later_cross_project_creation(self):
        binding = self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
        )
        self.conn.execute("BEGIN IMMEDIATE")
        self.service.claim_in_transaction(
            WORKSPACE, RUNNER, self.runner.key_id, binding["binding_id"],
            {"schema_version": "heel.runner-context-claim.v1", "binding_id": binding["binding_id"],
             "binding_digest": binding["binding_digest"]},
        )
        self.conn.commit()
        affinity = self.conn.execute(
            "SELECT project_ref,environment_id,runner_key_id,established_rcb_id,established_binding_digest "
            "FROM canary_runner_context_affinities WHERE workspace_id=? AND runner_id=?",
            (WORKSPACE, RUNNER),
        ).fetchone()
        self.assertEqual(tuple(affinity), (PROJECT, ENVIRONMENT, self.runner.key_id,
                                           binding["binding_id"], binding["binding_digest"]))

        self.service.revoke(WORKSPACE, PROJECT, binding["binding_id"], actor="user_owner", role="owner")
        other_project, other_environment = "prj_affinity_other", "env_affinity_other"
        self.conn.execute(
            "INSERT INTO projects VALUES(?,?,?,?,?)", (WORKSPACE, other_project, "Other", "user_owner", NOW_MS / 1000),
        )
        source = self.conn.execute(
            "SELECT * FROM canary_environments WHERE workspace_id=? AND project_ref=? AND environment_id=?",
            (WORKSPACE, PROJECT, ENVIRONMENT),
        ).fetchone()
        columns = tuple(source.keys())
        values = [source[column] for column in columns]
        values[columns.index("project_ref")] = other_project
        values[columns.index("environment_id")] = other_environment
        self.conn.execute(
            f"INSERT INTO canary_environments({','.join(columns)}) VALUES({','.join('?' for _ in columns)})", values,
        )
        self.conn.commit()

        with self.assertRaisesRegex(RunnerContextError, "conflict"):
            self.service.create(
                WORKSPACE, other_project,
                {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": other_environment,
                 "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
                 "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
            )
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM canary_runner_context_bindings WHERE workspace_id=? AND project_ref=?",
            (WORKSPACE, other_project),
        ).fetchone()[0], 0)
        self.assertEqual(
            self.service.list_for_human(WORKSPACE, other_project, actor="user_owner")["runners"], [],
        )

    def test_claimed_runner_affinity_is_immutable(self):
        first = self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
        )
        self.conn.execute("BEGIN IMMEDIATE")
        self.service.claim_in_transaction(
            WORKSPACE, RUNNER, self.runner.key_id, first["binding_id"],
            {"schema_version": "heel.runner-context-claim.v1", "binding_id": first["binding_id"],
             "binding_digest": first["binding_digest"]},
        )
        self.conn.commit()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "affinity is immutable"):
            self.conn.execute(
                "DELETE FROM canary_runner_context_affinities WHERE workspace_id=? AND runner_id=?",
                (WORKSPACE, RUNNER),
            )
        self.assertEqual(self.conn.execute(
            "SELECT established_rcb_id FROM canary_runner_context_affinities WHERE workspace_id=? AND runner_id=?",
            (WORKSPACE, RUNNER),
        ).fetchone()[0], first["binding_id"])

    def test_dashboard_hides_runner_occupied_by_another_project_until_revoke(self):
        binding = self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
        )
        other_project = "prj_other"
        other_environment = "env_other"
        self.conn.execute(
            "INSERT INTO projects VALUES(?,?,?,?,?)",
            (WORKSPACE, other_project, "Other", "user_owner", NOW_MS / 1000),
        )
        source = self.conn.execute(
            "SELECT * FROM canary_environments WHERE workspace_id=? AND project_ref=? AND environment_id=?",
            (WORKSPACE, PROJECT, ENVIRONMENT),
        ).fetchone()
        columns = tuple(source.keys())
        values = [source[column] for column in columns]
        values[columns.index("environment_id")] = other_environment
        values[columns.index("project_ref")] = other_project
        self.conn.execute(
            f"INSERT INTO canary_environments({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
            values,
        )
        same_project_values = [source[column] for column in columns]
        same_project_values[columns.index("environment_id")] = "env_same_project"
        self.conn.execute(
            f"INSERT INTO canary_environments({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
            same_project_values,
        )
        self.conn.commit()

        current = self.service.list_for_human(WORKSPACE, PROJECT, actor="user_owner")
        occupied_elsewhere = self.service.list_for_human(WORKSPACE, other_project, actor="user_owner")
        # A second executable environment in this project cannot make a runner
        # eligible for another binding while its current one is active.
        self.assertEqual(current["runners"], [])
        self.assertEqual([item["binding_id"] for item in current["bindings"]], [binding["binding_id"]])
        self.assertEqual(occupied_elsewhere["runners"], [])
        self.assertEqual(occupied_elsewhere["bindings"], [])

        self.service.revoke(WORKSPACE, PROJECT, binding["binding_id"], actor="user_owner", role="owner")
        after_revoke = self.service.list_for_human(WORKSPACE, other_project, actor="user_owner")
        self.assertEqual([item["runner_id"] for item in after_revoke["runners"]], [RUNNER])

    def test_dashboard_runner_selector_uses_its_bounded_indexes_without_a_temp_sort(self):
        """The selector is a polling read; its writer-adjacent work must stay seek-bound."""
        statements: list[str] = []
        self.conn.set_trace_callback(statements.append)
        try:
            self.service.list_for_human(WORKSPACE, PROJECT, actor="user_owner")
        finally:
            self.conn.set_trace_callback(None)
        selector = next(
            statement for statement in statements
            if "FROM canary_runner_keys k INDEXED BY idx_canary_runner_keys_dashboard_selector" in statement
        )
        # ``k.runner_id`` equals the joined runner ID, so this is the frozen
        # runner/key lexical order while letting SQLite walk the exact key index.
        self.assertIn("ORDER BY k.runner_id,k.key_id LIMIT 17", selector)
        plan = self.conn.execute("EXPLAIN QUERY PLAN " + selector).fetchall()
        details = [row[3] for row in plan]
        self.assertTrue(any("idx_canary_runners_dashboard_selector" in detail for detail in details))
        self.assertTrue(any("idx_canary_runner_keys_dashboard_selector" in detail for detail in details))
        self.assertFalse(any("TEMP B-TREE" in detail or "AUTOMATIC" in detail for detail in details))
        history = next(
            statement for statement in statements
            if "FROM canary_runner_context_bindings INDEXED BY idx_runner_context_dashboard_history" in statement
        )
        history_details = [row[3] for row in self.conn.execute("EXPLAIN QUERY PLAN " + history)]
        self.assertTrue(any("idx_runner_context_dashboard_history" in detail for detail in history_details))
        self.assertFalse(any("SCAN" in detail or "TEMP B-TREE" in detail or "AUTOMATIC" in detail for detail in history_details))

    def test_dashboard_duplicate_active_runner_keys_are_lexically_scanned_and_fail_closed(self):
        """A malformed two-current-key state must never turn into two authorizable rows."""
        self.conn.execute(
            "INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)",
            (self.cloud.key_id, WORKSPACE, RUNNER, self.cloud.canonical_public_key,
             "active", NOW_MS / 1000),
        )
        self.conn.commit()
        keys = [row[0] for row in self.conn.execute(
            "SELECT key_id FROM canary_runner_keys INDEXED BY idx_canary_runner_keys_dashboard_selector "
            "WHERE workspace_id=? AND runner_id=? AND status='active' AND revoked_at IS NULL "
            "ORDER BY runner_id,key_id",
            (WORKSPACE, RUNNER),
        )]
        self.assertEqual(keys, sorted(keys))
        with self.assertRaisesRegex(RunnerContextError, "canary_authority_unavailable"):
            self.service.list_for_human(WORKSPACE, PROJECT, actor="user_owner")

    def test_revoke_marks_state_and_is_visible_to_runner_transaction(self):
        binding = self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
        )
        self.conn.execute("BEGIN IMMEDIATE")
        listed = self.service.list_for_runner_in_transaction(WORKSPACE, RUNNER, self.runner.key_id)
        self.conn.commit()
        self.assertEqual([item["binding_id"] for item in listed["contexts"]], [binding["binding_id"]])
        revoked = self.service.revoke(WORKSPACE, PROJECT, binding["binding_id"], actor="user_owner", role="owner")
        self.assertEqual(revoked["status"], "revoked")
        self.conn.execute("BEGIN IMMEDIATE")
        listed = self.service.list_for_runner_in_transaction(WORKSPACE, RUNNER, self.runner.key_id)
        self.conn.commit()
        self.assertEqual(listed["contexts"], [])

    def test_runner_list_and_claim_fail_closed_on_denormalized_signed_artifact(self):
        binding = self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
        )
        # This models a storage corruption that retains a structurally closed artifact
        # but changes a field that must stay equal to the indexed authority row.
        tampered = deepcopy(binding)
        tampered["environment"]["origin"] = "https://other.example"
        unsigned = {
            key: value for key, value in tampered.items()
            if key not in {"binding_digest", "signing_key_id", "signature_b64"}
        }
        tampered["binding_digest"] = canonical_digest(unsigned)
        # The production schema correctly prevents this mutation.  Turn FK
        # enforcement off only to model an at-rest corrupt database, preserving
        # the child event composite so the runner read is the deciding check.
        self.conn.execute("PRAGMA foreign_keys=OFF")
        self.conn.execute(
            "UPDATE canary_runner_context_bindings SET binding_json=?,binding_digest=? WHERE rcb_id=?",
            (canonical_bytes(tampered).decode(), tampered["binding_digest"], binding["binding_id"]),
        )
        self.conn.execute(
            "UPDATE canary_runner_context_events SET binding_digest=? WHERE rcb_id=?",
            (tampered["binding_digest"], binding["binding_id"]),
        )
        self.conn.commit()
        self.conn.execute("PRAGMA foreign_keys=ON")

        self.conn.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(RunnerContextError, "runner_context_binding_not_found"):
            self.service.list_for_runner_in_transaction(WORKSPACE, RUNNER, self.runner.key_id)
        self.conn.rollback()

        self.conn.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(RunnerContextError, "runner_context_binding_not_found"):
            self.service.claim_in_transaction(
                WORKSPACE, RUNNER, self.runner.key_id, binding["binding_id"], {
                    "schema_version": "heel.runner-context-claim.v1",
                    "binding_id": binding["binding_id"],
                    "binding_digest": tampered["binding_digest"],
                },
            )
        self.conn.rollback()

    def test_revoke_defers_linked_pregrant_cancellation_to_the_bounded_reaper(self):
        self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
        )
        binding = self.conn.execute("SELECT * FROM canary_runner_context_bindings").fetchone()
        runs = service(self.conn, self.clock)
        projection = approval_projection(self.runner)
        self.conn.execute("BEGIN IMMEDIATE")
        submitted = runs.submit_projection_from_runner_in_transaction(
            projection, binding, uploaded_by_runner_id=RUNNER,
        )
        self.conn.commit()

        self.service.revoke(
            WORKSPACE, PROJECT, binding["rcb_id"], actor="user_owner", role="owner",
        )
        self.assertEqual(tuple(self.conn.execute(
            "SELECT workspace_id,project_ref,rcb_id,binding_digest,binding_expires_at_ms,last_scanned_run_id "
            "FROM canary_runner_context_cancellation_queue",
        ).fetchone()), (
            WORKSPACE, PROJECT, binding["rcb_id"], binding["binding_digest"], binding["expires_at_ms"], None,
        ))
        self.assertEqual(self.conn.execute(
            "SELECT status FROM canary_approval_projections WHERE approval_id=?", (submitted["approval_id"],),
        ).fetchone()[0], "awaiting_execution_approval")
        self.conn.execute("BEGIN IMMEDIATE")
        self.service.cancel_due_batch_in_transaction(self.service._now_ms())
        self.conn.commit()
        self.assertEqual(self.conn.execute(
            "SELECT status FROM canary_runs WHERE run_id=?", (submitted["run_id"],),
        ).fetchone()[0], "cancelled")
        self.assertIsNone(self.conn.execute(
            "SELECT 1 FROM canary_runner_context_cancellation_queue",
        ).fetchone())
        event = self.conn.execute(
            "SELECT event_type,actor_class,actor_id,reason_code FROM canary_run_events WHERE run_id=? AND event_type='cancelled'",
            (submitted["run_id"],),
        ).fetchall()
        audit = self.conn.execute(
            "SELECT action,actor_class,actor_id,reason_code FROM canary_audit_records WHERE run_id=? AND action='cancelled'",
            (submitted["run_id"],),
        ).fetchall()
        self.assertEqual([tuple(row) for row in event], [("cancelled", "human", "user_owner", "runner_context_revoked")])
        self.assertEqual([tuple(row) for row in audit], [("cancelled", "human", "user_owner", "runner_context_revoked")])
        with self.assertRaisesRegex(RunnerContextError, "conflict"):
            self.service.revoke(WORKSPACE, PROJECT, binding["rcb_id"], actor="user_owner", role="owner")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM canary_run_events WHERE run_id=? AND event_type='cancelled'", (submitted["run_id"],),
        ).fetchone()[0], 1)

    def test_cancellation_stages_binding_then_link_seeks_without_a_scan_or_temp_sort(self):
        self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
        )
        binding = self.conn.execute("SELECT * FROM canary_runner_context_bindings").fetchone()
        runs = service(self.conn, self.clock)
        self.conn.execute("BEGIN IMMEDIATE")
        submitted = runs.submit_projection_from_runner_in_transaction(
            approval_projection(self.runner), binding, uploaded_by_runner_id=RUNNER,
        )
        self.conn.commit()
        self.service.revoke(WORKSPACE, PROJECT, binding["rcb_id"], actor="user_owner", role="owner")

        statements: list[str] = []
        self.conn.execute("BEGIN IMMEDIATE")
        self.conn.set_trace_callback(statements.append)
        try:
            counts = self.service.cancel_due_batch_in_transaction(self.service._now_ms())
        finally:
            self.conn.set_trace_callback(None)
            self.conn.rollback()
        self.assertEqual(counts["cancelled_context_runs"], 1)
        queue_seek = next(
            statement for statement in statements
            if "FROM canary_runner_context_cancellation_queue INDEXED BY idx_runner_context_cancellation_queue_order" in statement
        )
        parent_seek = next(
            statement for statement in statements
            if "FROM canary_runner_context_bindings INDEXED BY idx_runner_context_binding_cancellation_ref" in statement
        )
        link_seek = next(
            statement for statement in statements
            if "FROM canary_runner_context_projection_links l INDEXED BY idx_runner_context_links_binding_run" in statement
        )
        for statement in (queue_seek, parent_seek, link_seek):
            details = [row[3] for row in self.conn.execute("EXPLAIN QUERY PLAN " + statement)]
            self.assertFalse(any("SCAN" in detail or "TEMP B-TREE" in detail or "AUTOMATIC" in detail for detail in details))
        self.assertEqual(self.conn.execute(
            "SELECT status FROM canary_runs WHERE run_id=?", (submitted["run_id"],),
        ).fetchone()[0], "awaiting_execution_approval")

    def test_cancellation_queue_fails_closed_when_a_link_loses_its_run_authority(self):
        self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
        )
        binding = self.conn.execute("SELECT * FROM canary_runner_context_bindings").fetchone()
        runs = service(self.conn, self.clock)
        self.conn.execute("BEGIN IMMEDIATE")
        submitted = runs.submit_projection_from_runner_in_transaction(
            approval_projection(self.runner), binding, uploaded_by_runner_id=RUNNER,
        )
        self.conn.commit()
        self.service.revoke(WORKSPACE, PROJECT, binding["rcb_id"], actor="user_owner", role="owner")

        # The composite FKs make this impossible in normal operation.  Model an
        # at-rest corruption to ensure the bounded reaper cannot silently discard
        # the cancellation queue and lose the context-specific audit spine.
        self.conn.execute("PRAGMA foreign_keys=OFF")
        self.conn.execute("DELETE FROM canary_runs WHERE run_id=?", (submitted["run_id"],))
        self.conn.commit()
        self.conn.execute("PRAGMA foreign_keys=ON")

        self.conn.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(RuntimeError, "cancellation queue link is inconsistent"):
            self.service.cancel_due_batch_in_transaction(self.service._now_ms())
        self.conn.rollback()
        self.assertIsNotNone(self.conn.execute(
            "SELECT 1 FROM canary_runner_context_cancellation_queue",
        ).fetchone())
        self.assertEqual(self.conn.execute(
            "SELECT status FROM canary_approval_projections WHERE approval_id=?", (submitted["approval_id"],),
        ).fetchone()[0], "awaiting_execution_approval")

    def test_cancellation_queue_drains_one_hundred_twenty_nine_linked_runs_by_cursor(self):
        self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
        )
        binding = self.conn.execute("SELECT * FROM canary_runner_context_bindings").fetchone()
        runs = service(self.conn, self.clock)

        def unique_projection(index: int) -> dict:
            projection = approval_projection(self.runner)
            projection["projection_id"] = f"ap_{index:032x}"
            unsigned = {
                key: value for key, value in projection.items()
                if key not in {"projection_digest", "signing_key_id", "signature_b64"}
            }
            projection["projection_digest"] = canonical_digest(unsigned)
            projection.update(self.runner.sign(canonical_bytes(unsigned)))
            return projection

        self.conn.execute("BEGIN IMMEDIATE")
        # The public submission boundary admits at most 64 live requests.  The
        # remaining records model an older retained queue so this reaper test
        # continues to exercise the 128/129 cursor boundary without bypassing
        # the admission invariant.
        for index in range(64):
            runs.submit_projection_from_runner_in_transaction(
                unique_projection(index), binding, uploaded_by_runner_id=RUNNER,
            )
        approval_columns = (
            "approval_id", "workspace_id", "project_ref", "run_id", "environment_id", "runner_id",
            "runner_key_id", "manifest_digest", "projection_digest", "signing_key_id", "status",
            "projection_json", "scenario_ids_json", "budgets_json", "uploaded_by", "approved_by",
            "reason", "created_at", "expires_at", "approved_at", "purge_at",
        )
        run_columns = (
            "run_id", "workspace_id", "project_ref", "approval_id", "grant_id", "environment_id",
            "runner_id", "runner_key_id", "status", "execution_disposition", "error_category",
            "stop_reason", "source_event_sequence", "source_projection_digest", "cloud_event_sequence",
            "last_heartbeat_at_ms", "last_gate_at_ms", "claimed_at_ms", "started_at_ms",
            "stop_requested_at_ms", "stop_acknowledged_at_ms", "terminal_at_ms", "stop_generation",
            "stop_deadline_ms", "stop_ack_late", "reservation_id", "quota_state",
            "kill_switch_generation", "created_at", "updated_at", "purge_at",
        )
        link_columns = (
            "workspace_id", "project_ref", "approval_id", "run_id", "environment_id", "runner_id",
            "runner_key_id", "rcb_id", "binding_digest", "projection_digest", "created_at_ms",
        )
        source_approval = dict(self.conn.execute(
            "SELECT * FROM canary_approval_projections ORDER BY approval_id LIMIT 1",
        ).fetchone())
        source_run = dict(self.conn.execute(
            "SELECT * FROM canary_runs ORDER BY run_id LIMIT 1",
        ).fetchone())
        source_link = dict(self.conn.execute(
            "SELECT * FROM canary_runner_context_projection_links ORDER BY run_id LIMIT 1",
        ).fetchone())
        for index in range(64, 129):
            approval_id = f"ap_{index:032x}"
            run_id = f"crun_{index:032x}"
            digest = f"{index + 4096:064x}"
            approval = {**source_approval, "approval_id": approval_id, "run_id": run_id, "projection_digest": digest}
            run = {**source_run, "run_id": run_id, "approval_id": approval_id}
            link = {**source_link, "approval_id": approval_id, "run_id": run_id, "projection_digest": digest}
            self.conn.execute(
                f"INSERT INTO canary_approval_projections({','.join(approval_columns)}) VALUES({','.join('?' for _ in approval_columns)})",
                tuple(approval[column] for column in approval_columns),
            )
            self.conn.execute(
                f"INSERT INTO canary_runs({','.join(run_columns)}) VALUES({','.join('?' for _ in run_columns)})",
                tuple(run[column] for column in run_columns),
            )
            self.conn.execute(
                f"INSERT INTO canary_runner_context_projection_links({','.join(link_columns)}) VALUES({','.join('?' for _ in link_columns)})",
                tuple(link[column] for column in link_columns),
            )
        self.conn.commit()
        run_ids = [row[0] for row in self.conn.execute(
            "SELECT run_id FROM canary_runner_context_projection_links "
            "WHERE workspace_id=? AND project_ref=? AND rcb_id=? ORDER BY run_id",
            (WORKSPACE, PROJECT, binding["rcb_id"]),
        )]
        self.assertEqual(len(run_ids), 129)
        self.service.revoke(WORKSPACE, PROJECT, binding["rcb_id"], actor="user_owner", role="owner")

        self.conn.execute("BEGIN IMMEDIATE")
        first = self.service.cancel_due_batch_in_transaction(self.service._now_ms())
        self.conn.commit()
        self.assertEqual(first["cancelled_context_runs"], 128)
        self.assertEqual(first["runner_context_cancellation_has_more"], 1)
        self.assertEqual(self.conn.execute(
            "SELECT last_scanned_run_id FROM canary_runner_context_cancellation_queue",
        ).fetchone()[0], run_ids[127])
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM canary_runs WHERE status='cancelled'",
        ).fetchone()[0], 128)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM canary_run_events WHERE event_type='cancelled'",
        ).fetchone()[0], 128)

        self.conn.execute("BEGIN IMMEDIATE")
        second = self.service.cancel_due_batch_in_transaction(self.service._now_ms())
        self.conn.commit()
        self.assertEqual(second["cancelled_context_runs"], 1)
        self.assertEqual(second["runner_context_cancellation_has_more"], 0)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM canary_runs WHERE status='cancelled'",
        ).fetchone()[0], 129)
        self.assertIsNone(self.conn.execute(
            "SELECT 1 FROM canary_runner_context_cancellation_queue",
        ).fetchone())

    def test_purge_fails_closed_when_a_terminal_link_loses_its_run_authority(self):
        self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
        )
        binding = self.conn.execute("SELECT * FROM canary_runner_context_bindings").fetchone()
        runs = service(self.conn, self.clock)
        self.conn.execute("BEGIN IMMEDIATE")
        submitted = runs.submit_projection_from_runner_in_transaction(
            approval_projection(self.runner), binding, uploaded_by_runner_id=RUNNER,
        )
        self.conn.commit()
        self.service.revoke(WORKSPACE, PROJECT, binding["rcb_id"], actor="user_owner", role="owner")

        purge_now = self.service._now_ms() + 31 * 24 * 60 * 60 * 1000
        self.conn.execute("PRAGMA foreign_keys=OFF")
        self.conn.execute("DELETE FROM canary_runs WHERE run_id=?", (submitted["run_id"],))
        self.conn.execute(
            "UPDATE canary_runner_context_bindings SET purge_at_ms=? WHERE rcb_id=?",
            (purge_now, binding["rcb_id"]),
        )
        self.conn.execute(
            "UPDATE canary_runner_context_events SET purge_at_ms=? WHERE rcb_id=?",
            (purge_now, binding["rcb_id"]),
        )
        self.conn.commit()
        self.conn.execute("PRAGMA foreign_keys=ON")

        self.conn.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(RuntimeError, "cancellation queue link is inconsistent"):
            self.service.cancel_due_batch_in_transaction(purge_now)
        self.conn.rollback()
        self.assertIsNotNone(self.conn.execute(
            "SELECT 1 FROM canary_runner_context_bindings WHERE rcb_id=?", (binding["rcb_id"],),
        ).fetchone())

    def test_expiry_cancels_linked_pregrant_run_with_system_audit(self):
        conn = connect()
        self.addCleanup(conn.close)
        clock = Clock()
        runner = seed_authority(conn, proof_expires_at=clock.value + 48 * 60 * 60)
        contexts = RunnerContextBindingService(conn, signing=SigningAuthority.generate(), clock=clock)
        contexts.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": runner.key_id}, actor="user_owner", role="owner",
        )
        binding = conn.execute("SELECT * FROM canary_runner_context_bindings").fetchone()
        runs = service(conn, clock)
        projection = approval_projection(runner)
        conn.execute("BEGIN IMMEDIATE")
        submitted = runs.submit_projection_from_runner_in_transaction(
            projection, binding, uploaded_by_runner_id=RUNNER,
        )
        conn.commit()
        clock.value += 25 * 60 * 60

        conn.execute("BEGIN IMMEDIATE")
        expired = contexts.expire_due_batch_in_transaction(contexts._now_ms())
        cancelled = contexts.cancel_due_batch_in_transaction(contexts._now_ms())
        conn.commit()
        self.assertEqual(expired["expired_runner_contexts"], 1)
        self.assertEqual(cancelled["cancelled_context_runs"], 1)
        self.assertEqual(conn.execute(
            "SELECT status FROM canary_approval_projections WHERE approval_id=?", (submitted["approval_id"],),
        ).fetchone()[0], "cancelled")
        self.assertEqual(conn.execute(
            "SELECT status FROM canary_runs WHERE run_id=?", (submitted["run_id"],),
        ).fetchone()[0], "cancelled")
        self.assertEqual([tuple(row) for row in conn.execute(
            "SELECT actor_class,actor_id,reason_code FROM canary_run_events WHERE run_id=? AND event_type='cancelled'",
            (submitted["run_id"],),
        )], [("system", "control-plane", "runner_context_expired")])

    def test_expire_and_purge_removes_only_retained_terminal_context_records(self):
        conn = connect()
        self.addCleanup(conn.close)
        clock = Clock()
        runner = seed_authority(conn, proof_expires_at=clock.value + 48 * 60 * 60)
        contexts = RunnerContextBindingService(conn, signing=SigningAuthority.generate(), clock=clock)
        binding = contexts.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": runner.key_id}, actor="user_owner", role="owner",
        )
        clock.value += 31 * 24 * 60 * 60
        conn.execute("BEGIN IMMEDIATE")
        contexts.expire_due_batch_in_transaction(contexts._now_ms())
        conn.commit()
        clock.value += 31 * 24 * 60 * 60
        conn.execute("BEGIN IMMEDIATE")
        counts = contexts.expire_and_purge_in_transaction(contexts._now_ms())
        conn.commit()
        self.assertEqual(counts["expired_bindings"], 0)
        self.assertEqual(counts["purged_bindings"], 1)
        self.assertEqual(counts["purged_events"], 2)
        self.assertIsNone(conn.execute(
            "SELECT 1 FROM canary_runner_context_bindings WHERE rcb_id=?", (binding["binding_id"],),
        ).fetchone())

    def test_retention_purge_consumes_a_global_child_deletion_budget(self):
        binding = self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
        )
        self.service.revoke(WORKSPACE, PROJECT, binding["binding_id"], actor="user_owner", role="owner")
        self.clock.value += 31 * 24 * 60 * 60
        now = self.service._now_ms()

        self.conn.execute("BEGIN IMMEDIATE")
        counts = self.service.expire_and_purge_in_transaction(now, limit=1)
        self.conn.commit()

        self.assertEqual(counts["purged_links"] + counts["purged_events"] + counts["purged_bindings"], 1)
        self.assertIsNotNone(self.conn.execute(
            "SELECT 1 FROM canary_runner_context_bindings WHERE rcb_id=?", (binding["binding_id"],),
        ).fetchone())

    def test_late_context_expiry_defers_binding_purge_until_its_terminal_event_retention(self):
        conn = connect()
        self.addCleanup(conn.close)
        clock = Clock()
        runner = seed_authority(conn, proof_expires_at=clock.value + 48 * 60 * 60)
        contexts = RunnerContextBindingService(conn, signing=SigningAuthority.generate(), clock=clock)
        binding = contexts.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": runner.key_id}, actor="user_owner", role="owner",
        )
        initial = conn.execute(
            "SELECT expires_at_ms,purge_at_ms FROM canary_runner_context_bindings WHERE rcb_id=?",
            (binding["binding_id"],),
        ).fetchone()
        clock.value += 25 * 60 * 60  # Process the 24-hour TTL one hour late.
        conn.execute("BEGIN IMMEDIATE")
        contexts.expire_due_batch_in_transaction(contexts._now_ms())
        contexts.expire_and_purge_in_transaction(contexts._now_ms())
        conn.commit()
        delayed_deadline = contexts._now_ms() + 30 * 24 * 60 * 60 * 1000
        self.assertEqual(conn.execute(
            "SELECT purge_at_ms FROM canary_runner_context_bindings WHERE rcb_id=?", (binding["binding_id"],),
        ).fetchone()[0], delayed_deadline)

        clock.value = initial["purge_at_ms"] / 1000
        conn.execute("BEGIN IMMEDIATE")
        before_event_retention = contexts.expire_and_purge_in_transaction(contexts._now_ms())
        conn.commit()
        self.assertEqual(before_event_retention["purged_bindings"], 0)

        clock.value = delayed_deadline / 1000
        conn.execute("BEGIN IMMEDIATE")
        due = contexts.expire_and_purge_in_transaction(contexts._now_ms())
        conn.commit()
        self.assertEqual(due["purged_bindings"], 1)

    def test_retention_purge_skips_a_future_event_head_and_uses_later_ready_binding(self):
        """A retained future child must not head-of-line block an independently ready binding."""
        first = self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
        )
        self.service.revoke(WORKSPACE, PROJECT, first["binding_id"], actor="user_owner", role="owner")
        second = self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
        )
        self.service.revoke(WORKSPACE, PROJECT, second["binding_id"], actor="user_owner", role="owner")

        self.clock.value += 31 * 24 * 60 * 60
        now = self.service._now_ms()
        first_row = self.conn.execute(
            "SELECT * FROM canary_runner_context_bindings WHERE rcb_id=?", (first["binding_id"],),
        ).fetchone()
        self.conn.execute(
            "UPDATE canary_runner_context_bindings SET purge_at_ms=? WHERE rcb_id=?",
            (now - 2, first["binding_id"]),
        )
        self.conn.execute(
            "UPDATE canary_runner_context_bindings SET purge_at_ms=? WHERE rcb_id=?",
            (now - 1, second["binding_id"]),
        )
        # This is a valid retained history event but deliberately later than the binding's
        # old deadline.  The v23 trigger raises just this row's readiness deadline.
        self.conn.execute(
            "INSERT INTO canary_runner_context_events("
            "rce_id,workspace_id,project_ref,environment_id,runner_id,runner_key_id,rcb_id,"
            "action,actor_class,actor_id,reason_code,binding_digest,created_at_ms,purge_at_ms) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "rce_" + "f" * 32, first_row["workspace_id"], first_row["project_ref"],
                first_row["environment_id"], first_row["runner_id"], first_row["runner_key_id"],
                first_row["rcb_id"], "projection_submitted", "runner", RUNNER, None,
                first_row["binding_digest"], now, now + 1,
            ),
        )
        self.conn.commit()

        statements: list[str] = []
        self.conn.execute("BEGIN IMMEDIATE")
        self.conn.set_trace_callback(statements.append)
        try:
            counts = self.service.expire_and_purge_in_transaction(now, limit=1)
            self.conn.commit()
        finally:
            self.conn.set_trace_callback(None)

        self.assertEqual(counts["purged_events"], 1)
        queued = self.conn.execute(
            "SELECT rcb_id FROM canary_runner_context_purge_queue"
        ).fetchall()
        self.assertEqual([row["rcb_id"] for row in queued], [second["binding_id"]])
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM canary_runner_context_purge_queue WHERE rcb_id=?", (first["binding_id"],),
        ).fetchone()[0], 0)
        readiness_seek = next(
            statement for statement in statements
            if "FROM canary_runner_context_purge_readiness INDEXED BY idx_runner_context_purge_readiness_ready" in statement
        )
        details = [row[3] for row in self.conn.execute("EXPLAIN QUERY PLAN " + readiness_seek)]
        self.assertTrue(any("idx_runner_context_purge_readiness_ready" in detail for detail in details))
        self.assertFalse(any("SCAN" in detail or "TEMP B-TREE" in detail or "AUTOMATIC" in detail for detail in details))

    def test_human_dashboard_is_bounded_to_64_historical_bindings(self):
        # One runner may only have one active binding, but its revocation history
        # must not make the session-only dashboard unbounded.
        created = []
        for _ in range(65):
            binding = self.service.create(
                WORKSPACE, PROJECT,
                {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
                 "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
                 "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
            )
            created.append(binding["binding_id"])
            self.service.revoke(
                WORKSPACE, PROJECT, binding["binding_id"], actor="user_owner", role="owner",
            )

        dashboard = self.service.list_for_human(WORKSPACE, PROJECT, actor="user_owner")
        self.assertEqual(len(dashboard["bindings"]), 64)
        self.assertEqual(len(dashboard["runners"]), 1)
        self.assertEqual({binding["status"] for binding in dashboard["bindings"]}, {"revoked"})
        self.assertTrue(set(item["binding_id"] for item in dashboard["bindings"]).issubset(created))

    def test_human_dashboard_fails_closed_when_runner_discovery_exceeds_16(self):
        for ordinal in range(16):
            seed_authority(
                self.conn, runner_id=f"runr_extra_{ordinal:02d}",
                environment_id=f"env_extra_{ordinal:02d}",
            )
        self.conn.commit()

        with self.assertRaisesRegex(RunnerContextError, "canary_authority_unavailable"):
            self.service.list_for_human(WORKSPACE, PROJECT, actor="user_owner")

    def test_retention_purge_is_keyset_bounded_and_reports_the_last_processed_cursor(self):
        for _ in range(129):
            binding = self.service.create(
                WORKSPACE, PROJECT,
                {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
                 "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
                 "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
            )
            self.service.revoke(WORKSPACE, PROJECT, binding["binding_id"], actor="user_owner", role="owner")
        self.clock.value += 31 * 24 * 60 * 60
        now = self.service._now_ms()

        self.conn.execute("BEGIN IMMEDIATE")
        first = self.service.expire_and_purge_in_transaction(now, limit=128)
        self.conn.commit()
        self.assertLessEqual(
            first["purged_links"] + first["purged_events"] + first["purged_bindings"], 128,
        )
        self.assertIsNotNone(first["next_cursor"])
        for _ in range(4):
            self.conn.execute("BEGIN IMMEDIATE")
            self.service.expire_and_purge_in_transaction(now, limit=128)
            self.conn.commit()
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM canary_runner_context_bindings").fetchone()[0], 0)

    def test_runner_projection_replay_is_idempotent_without_new_authority_side_effects(self):
        self.service.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
             "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
             "runner_key_id": self.runner.key_id}, actor="user_owner", role="owner",
        )
        binding = self.conn.execute(
            "SELECT * FROM canary_runner_context_bindings WHERE workspace_id=?", (WORKSPACE,)
        ).fetchone()
        runs = service(self.conn, self.clock)
        projection = approval_projection(self.runner)

        self.conn.execute("BEGIN IMMEDIATE")
        first = runs.submit_projection_from_runner_in_transaction(
            projection, binding, uploaded_by_runner_id=RUNNER,
        )
        self.assertTrue(first.created)
        self.service._event(binding, "projection_submitted", "runner", RUNNER)
        self.conn.commit()
        tables = (
            "canary_approval_projections", "canary_runs", "canary_runner_context_projection_links",
            "canary_runner_context_events", "canary_run_events", "canary_audit_records",
            "canary_execution_grants",
        )
        counts = {
            table: self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in tables
        }

        self.conn.execute("BEGIN IMMEDIATE")
        retry = runs.submit_projection_from_runner_in_transaction(
            projection, binding, uploaded_by_runner_id=RUNNER,
        )
        self.assertFalse(retry.created)
        self.conn.commit()
        self.assertEqual(retry, first)
        self.assertEqual({
            table: self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in tables
        }, counts)

        changed_projection = deepcopy(projection)
        changed_projection["budgets"]["maximum_requests"] = 3
        unsigned = {
            key: value for key, value in changed_projection.items()
            if key not in {"projection_digest", "signing_key_id", "signature_b64"}
        }
        changed_projection["projection_digest"] = canonical_digest(unsigned)
        changed_projection.update(self.runner.sign(canonical_bytes(unsigned)))
        for candidate, candidate_binding, actor in (
            (changed_projection, binding, RUNNER),
            (projection, {**dict(binding), "binding_digest": "b" * 64}, RUNNER),
            (projection, binding, "other-runner"),
        ):
            self.conn.execute("BEGIN IMMEDIATE")
            with self.assertRaises(CanaryRunError):
                runs.submit_projection_from_runner_in_transaction(
                    candidate, candidate_binding, uploaded_by_runner_id=actor,
                )
            self.conn.rollback()

    def test_runner_approval_requires_live_exact_context_link_but_legacy_human_submission_does_not(self):
        def setup_runner_submission():
            conn = connect()
            clock = Clock()
            runner = seed_authority(conn)
            contexts = RunnerContextBindingService(
                conn, signing=SigningAuthority.generate(), clock=clock,
            )
            contexts.create(
                WORKSPACE, PROJECT,
                {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ENVIRONMENT,
                 "verification_record_digest": VERIFICATION_DIGEST, "runner_id": RUNNER,
                 "runner_key_id": runner.key_id}, actor="user_owner", role="owner",
            )
            binding = conn.execute("SELECT * FROM canary_runner_context_bindings").fetchone()
            runs = service(conn, clock)
            projection = approval_projection(runner)
            conn.execute("BEGIN IMMEDIATE")
            submitted = runs.submit_projection_from_runner_in_transaction(
                projection, binding, uploaded_by_runner_id=RUNNER,
            )
            conn.commit()
            return conn, clock, contexts, runs, submitted, projection

        for mutation, marker in (("missing", "a"), ("revoked", "b"), ("expired", "c"), ("mismatched", "d")):
            with self.subTest(mutation=mutation):
                conn, clock, contexts, runs, submitted, projection = setup_runner_submission()
                try:
                    if mutation == "missing":
                        conn.execute("DELETE FROM canary_runner_context_projection_links")
                        conn.commit()
                        contexts.revoke(WORKSPACE, PROJECT, conn.execute(
                            "SELECT rcb_id FROM canary_runner_context_bindings"
                        ).fetchone()[0], actor="user_owner", role="owner")
                    elif mutation == "revoked":
                        contexts.revoke(WORKSPACE, PROJECT, conn.execute(
                            "SELECT rcb_id FROM canary_runner_context_bindings"
                        ).fetchone()[0], actor="user_owner", role="owner")
                    elif mutation == "expired":
                        conn.execute("UPDATE canary_runner_context_bindings SET status='expired'")
                        conn.commit()
                    else:
                        conn.execute("PRAGMA foreign_keys=OFF")
                        conn.execute("UPDATE canary_runner_context_projection_links SET binding_digest=?", ("b" * 64,))
                        conn.commit()
                        conn.execute("PRAGMA foreign_keys=ON")
                    with self.assertRaises(CanaryRunError):
                        runs.approve(
                            WORKSPACE, PROJECT, submitted["run_id"], projection_digest=projection["projection_digest"],
                            actor="user_owner", role="owner", reason="Run the bounded canary rehearsal",
                            exact_hostname="canary.acme.dev", recent_auth_at_ms=NOW_MS,
                            idempotency_key="ca1-" + marker * 64, expected_kill_switch_generation=0,
                        )
                    self.assertEqual(conn.execute("SELECT COUNT(*) FROM canary_execution_grants").fetchone()[0], 0)
                finally:
                    conn.close()

        conn = connect()
        try:
            clock = Clock()
            runner = seed_authority(conn)
            runs = service(conn, clock)
            legacy = approval_projection(runner)
            submitted = runs.submit_projection(legacy, uploaded_by="user_owner")
            approved = runs.approve(
                WORKSPACE, PROJECT, submitted["run_id"], projection_digest=legacy["projection_digest"],
                actor="user_owner", role="owner", reason="Run the bounded canary rehearsal",
                exact_hostname="canary.acme.dev", recent_auth_at_ms=NOW_MS,
                idempotency_key="ca1-" + "e" * 64, expected_kill_switch_generation=0,
            )
            self.assertEqual(approved["run_id"], submitted["run_id"])
        finally:
            conn.close()
