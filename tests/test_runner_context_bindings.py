from __future__ import annotations

import json
import unittest
from copy import deepcopy

from heel.canary_contracts import canonical_bytes, canonical_digest, validate_runner_context_binding
from heel.crypto import SigningAuthority
from heel.saas.canary_runs import CanaryRunError
from heel.saas.runner_contexts import RunnerContextBindingService, RunnerContextError
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

    def test_revoke_cancels_linked_pregrant_run_with_one_run_event_and_audit(self):
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
        self.assertEqual(self.conn.execute(
            "SELECT status FROM canary_approval_projections WHERE approval_id=?", (submitted["approval_id"],),
        ).fetchone()[0], "cancelled")
        self.assertEqual(self.conn.execute(
            "SELECT status FROM canary_runs WHERE run_id=?", (submitted["run_id"],),
        ).fetchone()[0], "cancelled")
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
        now = self.service._now_ms() + 1
        self.conn.execute("UPDATE canary_runner_context_bindings SET purge_at_ms=?", (now,))
        self.conn.execute("UPDATE canary_runner_context_events SET purge_at_ms=?", (now,))
        self.conn.commit()

        expected = self.conn.execute(
            "SELECT purge_at_ms,rcb_id FROM canary_runner_context_bindings ORDER BY purge_at_ms,rcb_id LIMIT 128"
        ).fetchall()[-1]
        self.conn.execute("BEGIN IMMEDIATE")
        first = self.service.expire_and_purge_in_transaction(now, limit=128)
        self.conn.commit()
        self.assertEqual(first["purged_bindings"], 128)
        self.assertEqual(first["purged_events"], 256)
        self.assertEqual(first["next_cursor"], {"purge_at_ms": expected["purge_at_ms"], "rcb_id": expected["rcb_id"]})
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM canary_runner_context_bindings").fetchone()[0], 1)

        self.conn.execute("BEGIN IMMEDIATE")
        second = self.service.expire_and_purge_in_transaction(now, limit=128)
        self.conn.commit()
        self.assertEqual(second["purged_bindings"], 1)
        self.assertEqual(second["next_cursor"], None)

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
