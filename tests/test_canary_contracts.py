"""Fail-closed contracts for the verified-canary boundary."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import unittest

from heel.canary_contracts import (
    APPROVAL_PROJECTION_SCHEMA,
    CANARY_FINDINGS_SCHEMA,
    DISCLOSURE_PERMIT_SCHEMA,
    EXECUTION_GRANT_SCHEMA,
    OPERATIONAL_RUN_SCHEMA,
    RUNNER_IDENTITY_SCHEMA,
    TEST_MANIFEST_SCHEMA,
    ContractError,
    canonical_bytes,
    canonical_digest,
    parse_json,
    validate_approval_projection,
    validate_canary_findings,
    validate_disclosure_permit,
    validate_execution_grant,
    validate_operational_run,
    validate_runner_identity,
    validate_test_manifest,
)


HASH = "a" * 64
KEY = base64.b64encode(bytes(range(32))).decode("ascii")
SIG = base64.b64encode(bytes(range(64))).decode("ascii")
FIXTURES = Path(__file__).resolve().parent / "fixtures/canary/contracts"
FIXTURE_HASHES = {
    "approval-projection.v1.json": "608ae3c173168bcd5830e50f85a9cd4860951c6c915d9f244c76a34a24085a7b",
    "operational-run.v1.json": "9a81fb52d1bfd30cef67c6a6a01a856530a64da4793bc7c5cdaa2db4afc04056",
    "canary-findings.v1.json": "743be795e6212d90af54ea2864d19a0361ae8b3f4131bc86b7c9e0f79d4eecdd",
}


def _digest(record: dict, field: str) -> dict:
    result = copy.deepcopy(record)
    result[field] = canonical_digest({k: v for k, v in result.items()
                                      if k not in {field, "signing_key_id", "signature_b64"}})
    return result


def environment() -> dict:
    return {"environment_id": "env_staging", "verification_record_digest": HASH,
            "origin": "https://canary.example.com", "environment_class": "staging"}


def budgets() -> dict:
    return {"maximum_requests": 1, "maximum_concurrency": 1, "action_timeout_ms": 1,
            "wall_timeout_ms": 1, "maximum_response_bytes": 1}


def egress() -> dict:
    return {"hostname": "canary.example.com", "port": 443, "redirect_policy": "deny"}


def retry() -> dict:
    return {"maximum_retries": 0, "retryable_failure_codes": []}


def manifest() -> dict:
    value = {
        "schema_version": TEST_MANIFEST_SCHEMA, "workspace_id": "ws", "project_id": "prj",
        "environment": environment(),
        "runner": {"runner_id": "r", "runner_key_id": "rk", "minimum_runner_version": "1"},
        "compiler": {"compiler_version": "1", "engine_version": "1"},
        "scenarios": [{"ordinal": 0, "scenario_id": "s", "adapter_version": "1"}],
        "actions": [{"ordinal": 0, "scenario_id": "s", "adapter_version": "1", "method": "GET",
                     "route_template": "/safe", "fixture_bindings": [], "semantic_auth_role": "anonymous",
                     "auth_profile": "anonymous", "assertion_class": "anonymous_authenticated",
                     "allowed_status_codes": [200], "allowed_body_shapes": ["absent"],
                     "side_effect_class": "read_only"}],
        "credential_bindings": [], "budgets": budgets(), "egress": egress(), "retry_policy": retry(),
        "local_evidence_policy": {"retention_seconds": 1}, "compiled_at_ms": 1, "manifest_digest": HASH,
    }
    return _digest(value, "manifest_digest")


def approval() -> dict:
    value = {
        "schema_version": APPROVAL_PROJECTION_SCHEMA, "projection_id": "ap", "workspace_id": "ws", "project_id": "prj",
        "environment": environment(), "runner": {"runner_id": "r", "runner_key_id": "rk", "runner_version": "1", "adapter_versions": ["1"]},
        "compiler": {"compiler_version": "1", "engine_version": "1"}, "scenarios": [{"ordinal": 0, "scenario_id": "s", "adapter_version": "1"}],
        "actions": [{"ordinal": 0, "scenario_id": "s", "adapter_version": "1", "method": "GET", "route_template": "/safe", "semantic_auth_role": "anonymous", "assertion_class": "anonymous_authenticated", "allowed_status_codes": [200], "allowed_body_shapes": ["absent"], "side_effect_class": "read_only"}],
        "budgets": budgets(), "egress": egress(), "retry_policy": retry(), "compiled_at_ms": 1, "manifest_digest": HASH,
        "projection_digest": HASH, "signing_key_id": "key", "signature_b64": SIG,
    }
    return _digest(value, "projection_digest")


def identity() -> dict:
    value = {"schema_version": RUNNER_IDENTITY_SCHEMA, "runner_id": "r", "workspace_id": "ws",
             "public_key": {"algorithm": "Ed25519", "key_id": "rk", "public_key_b64": KEY}, "fingerprint": HASH,
             "runner_version": "1", "adapter_versions": ["1"],
             "capabilities": ["runner_claim", "runner_heartbeat", "runner_progress", "runner_result"],
             "pairing": {"paired_by": "u", "paired_at_ms": 1, "fingerprint_confirmation": "confirmed", "phrase_confirmation": "confirmed"},
             "last_heartbeat_at_ms": 1, "state": "active", "rotation": {"previous_key_ids": [], "rotated_at_ms": None, "verification_overlap_ends_at_ms": None},
             "revocation": {"revoked_at_ms": None, "revoked_by": None, "reason_code": None}, "identity_digest": HASH}
    return _digest(value, "identity_digest")


def grant() -> dict:
    value = {"schema_version": EXECUTION_GRANT_SCHEMA, "grant_id": "g", "run_id": "run", "workspace_id": "ws", "project_id": "prj",
             "approval": {"projection_id": "ap", "projection_digest": HASH, "manifest_digest": HASH}, "environment": environment(),
             "runner_binding": {"runner_id": "r", "runner_key_id": "rk", "public_key_digest": HASH},
             "approval_actor": {"user_id": "u", "role": "owner"}, "approval_reason": "ok", "consented_at_ms": 1,
             "budgets": budgets(), "egress": egress(), "retry_policy": retry(), "grant_nonce": "n", "kill_switch_generation": 1,
             "operational_receipt_policy": {"schema_version": OPERATIONAL_RUN_SCHEMA, "maximum_bytes": 1, "allowed_error_categories": ["none"], "allowed_stop_reasons": ["none"], "allowed_containment_codes": ["admitted"]},
             "issued_at_ms": 1, "expires_at_ms": 2, "grant_digest": HASH, "signing_key_id": "key", "signature_b64": SIG}
    return _digest(value, "grant_digest")


def operational() -> dict:
    value = {"schema_version": OPERATIONAL_RUN_SCHEMA, "run_id": "run", "grant_id": "g", "workspace_id": "ws", "project_id": "prj",
             "manifest_digest": HASH, "approval_projection_digest": HASH, "grant_digest": HASH, "event_sequence": 0,
             "lifecycle_phase": "prepared", "execution_disposition": None,
             "timestamps": {"claimed_at_ms": None, "started_at_ms": None, "updated_at_ms": 1, "stop_requested_at_ms": None, "stop_acknowledged_at_ms": None, "terminal_at_ms": None},
             "counters": {"requests_started": 0, "requests_completed": 0, "response_bytes_read": 0, "actions_contained": 0, "retries_used": 0, "remaining_requests": 1, "remaining_wall_ms": 1},
             "versions": {"runner_version": "1", "engine_version": "1", "adapter_versions": ["1"]}, "error_category": "none", "stop_reason": "none", "containment_codes": [], "redaction_count": 0,
             "projection_digest": HASH, "signing_key_id": "key", "signature_b64": SIG}
    return _digest(value, "projection_digest")


def findings() -> dict:
    value = {"schema_version": CANARY_FINDINGS_SCHEMA, "projection_id": "fp", "run_id": "run", "grant_id": "g", "workspace_id": "ws", "project_id": "prj", "environment_id": "env_staging",
             "manifest_digest": HASH, "approval_projection_digest": HASH, "grant_digest": HASH, "engine_version": "1", "adapter_versions": ["1"], "started_at_ms": 1, "finished_at_ms": 1,
             "assessment_outcome": "observed", "scenario_results": [{"ordinal": 0, "scenario_id": "s", "adapter_version": "1", "assessment_outcome": "observed", "route": {"method": "GET", "route_template": "/safe"}, "observations": [{"semantic_role": "anonymous", "status_code": 200, "body_shape": "absent", "truncation_state": "complete"}], "finding": None, "containment_codes": [], "redaction_count": 0, "local_evidence_refs": []}],
             "containment_codes": [], "redaction_count": 0, "projection_digest": HASH, "signing_key_id": "key", "signature_b64": SIG}
    return _digest(value, "projection_digest")


def permit() -> dict:
    value = {"schema_version": DISCLOSURE_PERMIT_SCHEMA, "permit_id": "p", "workspace_id": "ws", "project_id": "prj", "run_id": "run", "grant_id": "g", "runner_binding": {"runner_id": "r", "runner_key_id": "rk"}, "projection": {"schema_version": CANARY_FINDINGS_SCHEMA, "projection_digest": HASH, "maximum_bytes": 1, "scenario_count": 1, "finding_count": 0}, "approved_by": "u", "approved_at_ms": 1, "issued_at_ms": 1, "expires_at_ms": 2, "permit_nonce": "n", "permit_digest": HASH, "signing_key_id": "key", "signature_b64": SIG}
    return _digest(value, "permit_digest")


class CanaryContractTests(unittest.TestCase):
    def test_parse_json_rejects_nonportable_and_ambiguous_input(self):
        bad = [b'{"a":1,"a":2}', b'{"a":true}', b'{"a":1.0}', b'{"a":NaN}', b'{"a":9007199254740992}', b'{"a":"\\ud800"}', b'{"e\\u0301":1,"\\u00e9":2}', b'\xff']
        for raw in bad:
            with self.subTest(raw=raw):
                with self.assertRaises(ContractError): parse_json(raw, 1024)
        with self.assertRaises(ContractError): parse_json(b'{}', 1)

    def test_canonical_bytes_normalizes_and_orders_without_mutating(self):
        source = {"z": ["e\u0301"], "a": 1}
        self.assertEqual(canonical_bytes(source), b'{"a":1,"z":["\xc3\xa9"]}')
        self.assertEqual(source["z"][0], "e\u0301")
        self.assertEqual(canonical_digest(source), hashlib.sha256(canonical_bytes(source)).hexdigest())

    def test_all_validators_accept_detached_canonical_records(self):
        records = [(validate_test_manifest, manifest()), (validate_approval_projection, approval()), (validate_runner_identity, identity()), (validate_execution_grant, grant()), (validate_operational_run, operational()), (validate_canary_findings, findings()), (validate_disclosure_permit, permit())]
        for validator, record in records:
            with self.subTest(validator=validator.__name__):
                result = validator(record)
                self.assertEqual(result, record)
                self.assertIsNot(result, record)
                self.assertEqual(canonical_bytes(result), canonical_bytes(record))

    def test_validators_fail_closed_for_fields_privacy_digest_and_lifecycle(self):
        cases = [(validate_test_manifest, manifest(), "actions", [{"headers": {}}]), (validate_approval_projection, approval(), "credential_handle", "secret"), (validate_operational_run, operational(), "assessment", "private"), (validate_canary_findings, findings(), "raw_traffic", "private")]
        for validator, record, key, value in cases:
            with self.subTest(key=key):
                record[key] = value
                with self.assertRaisesRegex(ContractError, r"invalid|fields|forbidden|digest"):
                    validator(record)
        broken = manifest(); broken["manifest_digest"] = HASH
        with self.assertRaises(ContractError): validate_test_manifest(broken)
        terminal = operational(); terminal["lifecycle_phase"] = "terminal"; terminal = _digest(terminal, "projection_digest")
        with self.assertRaises(ContractError): validate_operational_run(terminal)

    def test_network_and_signature_constraints_are_enforced(self):
        invalid = manifest(); invalid["environment"]["origin"] = "https://127.0.0.1"; invalid = _digest(invalid, "manifest_digest")
        with self.assertRaises(ContractError): validate_test_manifest(invalid)
        invalid = manifest(); invalid["egress"]["port"] = 80; invalid = _digest(invalid, "manifest_digest")
        with self.assertRaises(ContractError): validate_test_manifest(invalid)
        invalid = approval(); invalid["signature_b64"] = base64.b64encode(b"x").decode(); invalid = _digest(invalid, "projection_digest")
        with self.assertRaises(ContractError): validate_approval_projection(invalid)

    def test_fixtures_are_literal_hashed_canonical_records_with_one_newline(self):
        validators = {
            "approval-projection.v1.json": validate_approval_projection,
            "operational-run.v1.json": validate_operational_run,
            "canary-findings.v1.json": validate_canary_findings,
        }
        for name, expected_hash in FIXTURE_HASHES.items():
            with self.subTest(name=name):
                raw = (FIXTURES / name).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), expected_hash)
                self.assertTrue(raw.endswith(b"\n"))
                record = validators[name](parse_json(raw, 256 * 1024))
                self.assertEqual(raw, canonical_bytes(record) + b"\n")
