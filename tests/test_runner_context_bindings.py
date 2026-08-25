from __future__ import annotations

import json
import unittest
from copy import deepcopy

from heel.canary_contracts import canonical_bytes, canonical_digest, validate_runner_context_binding
from heel.crypto import SigningAuthority
from heel.saas.canary_runs import CanaryRunError
from heel.saas.runner_contexts import RunnerContextBindingService
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
