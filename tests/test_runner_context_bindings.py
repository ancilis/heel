from __future__ import annotations

import json
import unittest

from heel.canary_contracts import validate_runner_context_binding
from heel.saas.runner_contexts import RunnerContextBindingService
from tests.canary_test_support import (
    Clock, ENVIRONMENT, NOW_MS, PROJECT, RUNNER, VERIFICATION_DIGEST, WORKSPACE,
    connect, seed_authority,
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

