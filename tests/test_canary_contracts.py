"""Fail-closed contracts for the verified-canary boundary."""
from __future__ import annotations

import base64
import copy
import hashlib
import inspect
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
    RUNNER_CONTEXT_BINDING_SCHEMA,
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
    validate_runner_claim_request,
    validate_runner_heartbeat_request,
    validate_runner_progress_request,
    validate_runner_result_request,
    validate_runner_stop_ack_request,
    validate_runner_identity,
    validate_runner_context_binding,
    validate_test_manifest,
)


HASH = "a" * 64
KEY = base64.b64encode(bytes(range(32))).decode("ascii")
SIG = base64.b64encode(bytes(range(64))).decode("ascii")
FIXTURES = Path(__file__).resolve().parent / "fixtures/canary/contracts"
FIXTURE_HASHES = {
    "approval-projection.v1.json": "61a25796ebdb3976694ff4bfe502a7fa47294b5015add279689e1dc400564f89",
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
        "projection_digest": HASH, "signing_key_id": "rk", "signature_b64": SIG,
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


def context_binding() -> dict:
    unsigned = {
        "schema_version": RUNNER_CONTEXT_BINDING_SCHEMA, "binding_id": "rcb_" + "a" * 32,
        "workspace_id": "ws", "project_id": "prj",
        "environment": environment(),
        "runner_binding": {"runner_id": "r", "runner_key_id": "rk", "public_key_digest": HASH},
        "authorization": {"user_id": "u", "role": "owner"},
        "issued_at_ms": 1, "expires_at_ms": 60_001,
    }
    value = {
        **unsigned,
        "binding_digest": canonical_digest(unsigned), "signing_key_id": "cloud",
        "signature_b64": SIG,
    }
    return value


class CanaryContractTests(unittest.TestCase):
    def test_runner_request_wrappers_are_closed_and_validate_operational_projection(self):
        claim = {"schema_version": "heel.runner-claim-request.v1"}
        self.assertEqual(validate_runner_claim_request(claim), claim)
        with self.assertRaises(ContractError):
            validate_runner_claim_request({**claim, "run_id": "run"})

        phases = {
            validate_runner_heartbeat_request: "claimed",
            validate_runner_progress_request: "running",
            validate_runner_result_request: "terminal",
            validate_runner_stop_ack_request: "stop_requested",
        }
        schemas = {
            validate_runner_heartbeat_request: "heartbeat",
            validate_runner_progress_request: "progress",
            validate_runner_result_request: "result",
            validate_runner_stop_ack_request: "stop-ack",
        }
        for validator, phase in phases.items():
            projection = operational()
            projection["lifecycle_phase"] = phase
            if phase == "claimed":
                projection["timestamps"]["claimed_at_ms"] = 1
            elif phase == "running":
                projection["timestamps"].update({"claimed_at_ms": 1, "started_at_ms": 1})
            elif phase == "terminal":
                projection["execution_disposition"] = "completed"
                projection["timestamps"].update({"claimed_at_ms": 1, "started_at_ms": 1, "terminal_at_ms": 1})
            else:
                projection["timestamps"].update({"claimed_at_ms": 1, "started_at_ms": 1, "stop_requested_at_ms": 1, "stop_acknowledged_at_ms": 1})
                projection["stop_reason"] = "cloud_stop"
            projection = _digest(projection, "projection_digest")
            request = {"schema_version": f"heel.runner-{schemas[validator]}-request.v1", "run_id": "run", "operational_projection": projection}
            with self.subTest(operation=schemas[validator]):
                self.assertEqual(validator(request), request)
                private = copy.deepcopy(request)
                private["operational_projection"]["headers"] = {"authorization": "secret"}
                with self.assertRaises(ContractError):
                    validator(private)
                with self.assertRaises(ContractError):
                    validator({**request, "findings": []})
    def test_parse_json_rejects_nonportable_and_ambiguous_input(self):
        bad = [b'{"a":1,"a":2}', b'{"a":true}', b'{"a":1.0}', b'{"a":NaN}', b'{"a":9007199254740992}', b'{"a":"\\ud800"}', b'{"e\\u0301":1,"\\u00e9":2}', b'\xff']
        for raw in bad:
            with self.subTest(raw=raw):
                with self.assertRaises(ContractError): parse_json(raw, max_bytes=1024)
        with self.assertRaises(ContractError): parse_json(b'{}', max_bytes=1)

    def test_canonical_bytes_normalizes_and_orders_without_mutating(self):
        source = {"z": ["e\u0301"], "a": 1}
        self.assertEqual(canonical_bytes(source), b'{"a":1,"z":["\xc3\xa9"]}')
        self.assertEqual(source["z"][0], "e\u0301")
        self.assertEqual(canonical_digest(source), hashlib.sha256(canonical_bytes(source)).hexdigest())

    def test_all_validators_accept_detached_canonical_records(self):
        records = [(validate_test_manifest, manifest()), (validate_approval_projection, approval()), (validate_runner_identity, identity()), (validate_execution_grant, grant()), (validate_operational_run, operational()), (validate_canary_findings, findings()), (validate_disclosure_permit, permit()), (validate_runner_context_binding, context_binding())]
        for validator, record in records:
            with self.subTest(validator=validator.__name__):
                result = validator(record)
                self.assertEqual(result, record)
                self.assertIsNot(result, record)
                self.assertEqual(canonical_bytes(result), canonical_bytes(record))

    def test_context_binding_is_closed_and_digest_is_over_exact_unsigned_artifact(self):
        binding = context_binding()
        self.assertEqual(validate_runner_context_binding(binding), binding)
        for key, value in (("binding_digest", HASH), ("expires_at_ms", 60_000), ("unknown", 1)):
            tampered = copy.deepcopy(binding)
            tampered[key] = value
            with self.subTest(key=key), self.assertRaises(ContractError):
                validate_runner_context_binding(tampered)

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
                record = validators[name](parse_json(raw, max_bytes=256 * 1024))
                self.assertEqual(raw, canonical_bytes(record) + b"\n")

    def test_parser_is_keyword_bounded_and_recursively_bounded(self):
        parameter = inspect.signature(parse_json).parameters["max_bytes"]
        self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        too_long = "x" * 4097
        for value in ({"outer": {"value": too_long}}, {too_long: "value"}):
            with self.subTest(value=list(value)[:1]):
                with self.assertRaises(ContractError):
                    canonical_bytes(value)
        with self.assertRaises(ContractError):
            parse_json(("{\"x\":\"" + too_long + "\"}").encode(), max_bytes=8192)
        nested: object = 0
        for _ in range(17): nested = [nested]
        with self.assertRaises(ContractError): canonical_bytes(nested)

    def test_special_hostname_and_scenario_identity_collisions_are_rejected(self):
        for hostname in ("canary.test", "canary.example", "canary.onion", "canary.home.arpa", "canary.internal"):
            record = manifest()
            record["environment"]["origin"] = "https://" + hostname
            record["egress"]["hostname"] = hostname
            with self.subTest(hostname=hostname):
                with self.assertRaises(ContractError): validate_test_manifest(_digest(record, "manifest_digest"))
        record = manifest()
        record["scenarios"].append({"ordinal": 1, "scenario_id": "s", "adapter_version": "2"})
        with self.assertRaises(ContractError): validate_test_manifest(_digest(record, "manifest_digest"))
        record = findings()
        duplicate = copy.deepcopy(record["scenario_results"][0]); duplicate["ordinal"] = 1; duplicate["adapter_version"] = "2"
        record["scenario_results"].append(duplicate)
        with self.assertRaises(ContractError): validate_canary_findings(_digest(record, "projection_digest"))

    def test_operational_phase_timestamps_and_counters_fail_closed(self):
        cancelled = operational(); cancelled["lifecycle_phase"] = "cancelled"; cancelled["execution_disposition"] = "stopped"; cancelled["timestamps"]["terminal_at_ms"] = 2
        with self.assertRaises(ContractError): validate_operational_run(_digest(cancelled, "projection_digest"))
        terminal = operational(); terminal["lifecycle_phase"] = "terminal"; terminal["execution_disposition"] = "completed"; terminal["timestamps"].update({"claimed_at_ms": 4, "started_at_ms": 3, "terminal_at_ms": 2})
        with self.assertRaises(ContractError): validate_operational_run(_digest(terminal, "projection_digest"))
        counters = operational(); counters["counters"].update({"requests_started": 21, "requests_completed": 22, "actions_contained": 21, "retries_used": 2, "remaining_requests": 21, "remaining_wall_ms": 60001})
        with self.assertRaises(ContractError): validate_operational_run(_digest(counters, "projection_digest"))

    def test_projection_collections_are_semantically_unique_and_sorted(self):
        record = manifest()
        record["actions"][0]["fixture_bindings"] = [{"parameter_name": "z", "fixture_id": "f2"}, {"parameter_name": "a", "fixture_id": "f1"}]
        with self.assertRaises(ContractError): validate_test_manifest(_digest(record, "manifest_digest"))
        record = manifest()
        record["credential_bindings"] = [{"semantic_role": "z", "credential_handle_id": "1" * 32, "auth_profile": "bearer"}, {"semantic_role": "a", "credential_handle_id": "2" * 32, "auth_profile": "bearer"}]
        with self.assertRaises(ContractError): validate_test_manifest(_digest(record, "manifest_digest"))
        record = findings()
        observations = record["scenario_results"][0]["observations"]
        observations.extend([{"semantic_role": "z", "status_code": 200, "body_shape": "absent", "truncation_state": "complete"}, {"semantic_role": "a", "status_code": 200, "body_shape": "absent", "truncation_state": "complete"}])
        with self.assertRaises(ContractError): validate_canary_findings(_digest(record, "projection_digest"))

    def test_findings_total_observation_ceiling_and_recursive_privacy_hold(self):
        record = findings()
        second = copy.deepcopy(record["scenario_results"][0]); second.update({"ordinal": 1, "scenario_id": "s2"})
        second["observations"] = copy.deepcopy(second["observations"]) * 20
        record["scenario_results"][0]["observations"] *= 2
        record["scenario_results"].append(second)
        with self.assertRaises(ContractError): validate_canary_findings(_digest(record, "projection_digest"))
        secret = "customer-private-value-do-not-echo"
        private = approval(); private["actions"][0]["nested"] = {"headers": {"x": secret}}
        with self.assertRaises(ContractError) as error: validate_approval_projection(_digest(private, "projection_digest"))
        self.assertNotIn(secret, str(error.exception))

    def test_numeric_budget_ceilings_and_deep_detachment_hold(self):
        for field, value in (("maximum_requests", 0), ("maximum_requests", 21), ("maximum_concurrency", 2), ("action_timeout_ms", 0), ("action_timeout_ms", 5001), ("wall_timeout_ms", 0), ("wall_timeout_ms", 60001)):
            record = manifest(); record["budgets"][field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ContractError): validate_test_manifest(_digest(record, "manifest_digest"))
        record = manifest()
        detached = validate_test_manifest(record)
        detached["environment"]["environment_id"] = "mutated"
        detached["actions"][0]["allowed_status_codes"].append(201)
        self.assertEqual(record["environment"]["environment_id"], "env_staging")
        self.assertEqual(record["actions"][0]["allowed_status_codes"], [200])

    def test_every_lifecycle_phase_has_a_closed_timestamp_contract(self):
        expected = {
            "prepared": ({}, None),
            "awaiting_execution_approval": ({}, None),
            "approved": ({}, None),
            "claimed": ({"claimed_at_ms": 1, "updated_at_ms": 1}, None),
            "running": ({"claimed_at_ms": 1, "started_at_ms": 2, "updated_at_ms": 2}, None),
            "stop_requested": ({"claimed_at_ms": 1, "started_at_ms": 2, "stop_requested_at_ms": 3, "updated_at_ms": 3}, None),
            "finalizing": ({"claimed_at_ms": 1, "started_at_ms": 2, "updated_at_ms": 2}, None),
            "terminal": ({"claimed_at_ms": 1, "started_at_ms": 2, "terminal_at_ms": 3, "updated_at_ms": 3}, "completed"),
            "cancelled": ({}, None),
            "expired": ({}, None),
        }
        for phase, (timestamps, disposition) in expected.items():
            record = operational()
            record["lifecycle_phase"] = phase
            record["execution_disposition"] = disposition
            record["timestamps"].update(timestamps)
            with self.subTest(phase=phase):
                validate_operational_run(_digest(record, "projection_digest"))
        for phase in ("cancelled", "expired"):
            record = operational(); record["lifecycle_phase"] = phase; record["timestamps"]["claimed_at_ms"] = 1
            with self.subTest(invalid=phase):
                with self.assertRaises(ContractError): validate_operational_run(_digest(record, "projection_digest"))
        record = operational(); record["lifecycle_phase"] = "finalizing"
        with self.assertRaises(ContractError): validate_operational_run(_digest(record, "projection_digest"))

    def test_response_bytes_are_portable_but_not_arbitrarily_aggregate_capped(self):
        record = operational()
        record["counters"]["response_bytes_read"] = 256 * 1024 + 1
        validate_operational_run(_digest(record, "projection_digest"))

    def test_manifest_methods_and_execution_ceilings_are_closed(self):
        for method in ("GET", "HEAD"):
            record = manifest(); record["actions"][0]["method"] = method
            with self.subTest(method=method): validate_test_manifest(_digest(record, "manifest_digest"))
        record = manifest(); record["actions"][0]["method"] = "POST"
        with self.assertRaises(ContractError): validate_test_manifest(_digest(record, "manifest_digest"))
        record = manifest()
        for ordinal in range(1, 21):
            action = copy.deepcopy(record["actions"][0]); action["ordinal"] = ordinal; record["actions"].append(action)
        with self.assertRaises(ContractError): validate_test_manifest(_digest(record, "manifest_digest"))
        record = manifest(); record["retry_policy"]["maximum_retries"] = 2
        with self.assertRaises(ContractError): validate_test_manifest(_digest(record, "manifest_digest"))

    def test_every_contract_rejects_closed_fields_and_enums(self):
        cases = []
        record = identity(); record["unexpected"] = True; cases.append((validate_runner_identity, record, "identity_digest"))
        record = identity(); record["public_key"]["extra"] = "x"; cases.append((validate_runner_identity, record, "identity_digest"))
        record = grant(); record["operational_receipt_policy"]["allowed_error_categories"] = ["not_a_category"]; cases.append((validate_execution_grant, record, "grant_digest"))
        record = grant(); record["approval_actor"]["role"] = "viewer"; cases.append((validate_execution_grant, record, "grant_digest"))
        record = operational(); record["error_category"] = "unbounded"; cases.append((validate_operational_run, record, "projection_digest"))
        record = operational(); record["timestamps"]["extra"] = 1; cases.append((validate_operational_run, record, "projection_digest"))
        record = findings(); record["scenario_results"][0]["observations"][0]["body_shape"] = "xml"; cases.append((validate_canary_findings, record, "projection_digest"))
        record = findings(); record["scenario_results"][0]["finding"] = {"title": "x", "reachability_rationale": "x", "confidence": "certain", "recommended_control": "x", "regression_suggestion": "x"}; cases.append((validate_canary_findings, record, "projection_digest"))
        record = permit(); record["projection"]["schema_version"] = "wrong"; cases.append((validate_disclosure_permit, record, "permit_digest"))
        record = permit(); record["extra"] = "x"; cases.append((validate_disclosure_permit, record, "permit_digest"))
        for validator, record, digest in cases:
            with self.subTest(validator=validator.__name__):
                with self.assertRaises(ContractError): validator(_digest(record, digest))

    def test_public_contract_entrypoints_never_leak_recursion_or_type_errors(self):
        raw = b"[" * 10_000 + b"0" + b"]" * 10_000
        with self.assertRaises(ContractError): parse_json(raw, max_bytes=64 * 1024)
        cases = []
        record = manifest(); record["actions"][0]["scenario_id"] = []; cases.append((validate_test_manifest, record, "manifest_digest"))
        record = approval(); record["actions"][0]["scenario_id"] = []; cases.append((validate_approval_projection, record, "projection_digest"))
        record = findings(); record["scenario_results"][0]["scenario_id"] = []; cases.append((validate_canary_findings, record, "projection_digest"))
        record = identity(); record["runner_id"] = []; cases.append((validate_runner_identity, record, "identity_digest"))
        record = grant(); record["approval"]["projection_id"] = []; cases.append((validate_execution_grant, record, "grant_digest"))
        record = operational(); record["run_id"] = []; cases.append((validate_operational_run, record, "projection_digest"))
        record = permit(); record["runner_binding"]["runner_id"] = []; cases.append((validate_disclosure_permit, record, "permit_digest"))
        for validator, record, digest in cases:
            with self.subTest(validator=validator.__name__):
                with self.assertRaises(ContractError): validator(_digest(record, digest))

    def test_updated_timestamp_is_required_for_every_lifecycle_phase(self):
        valid = {
            "prepared": {}, "awaiting_execution_approval": {}, "approved": {},
            "claimed": {"claimed_at_ms": 1}, "running": {"claimed_at_ms": 1, "started_at_ms": 2},
            "stop_requested": {"claimed_at_ms": 1, "started_at_ms": 2, "stop_requested_at_ms": 3},
            "finalizing": {"claimed_at_ms": 1, "started_at_ms": 2},
            "terminal": {"claimed_at_ms": 1, "started_at_ms": 2, "terminal_at_ms": 3},
            "cancelled": {}, "expired": {},
        }
        for phase, timestamps in valid.items():
            record = operational(); record["lifecycle_phase"] = phase; record["execution_disposition"] = "completed" if phase == "terminal" else None
            record["timestamps"].update(timestamps); record["timestamps"]["updated_at_ms"] = None
            with self.subTest(phase=phase):
                with self.assertRaises(ContractError): validate_operational_run(_digest(record, "projection_digest"))

    def test_response_budget_and_approval_signing_key_binding_are_frozen(self):
        for builder, validator, digest in ((manifest, validate_test_manifest, "manifest_digest"), (approval, validate_approval_projection, "projection_digest"), (grant, validate_execution_grant, "grant_digest")):
            record = builder(); record["budgets"]["maximum_response_bytes"] = 262144
            with self.subTest(builder=builder.__name__, boundary=True): validator(_digest(record, digest))
            record["budgets"]["maximum_response_bytes"] = 262145
            with self.subTest(builder=builder.__name__, boundary=False):
                with self.assertRaises(ContractError): validator(_digest(record, digest))
        record = approval(); record["signing_key_id"] = "other"
        with self.assertRaises(ContractError): validate_approval_projection(_digest(record, "projection_digest"))


# --- C2: discovery authorization, v2 plan object, inventory provenance (contract §2) ---

import pytest

from heel.canary_contracts import (
    APPROVAL_PROJECTION_V2_SCHEMA,
    DISCOVERY_ACKNOWLEDGEMENT,
    DISCOVERY_AUTHORIZATION_SCHEMA,
    DISCOVERY_ROUND_REPORT_SCHEMA,
    DISCOVERY_SEED_DIGEST,
    DISCOVERY_SEED_PATHS,
    PLAN_REQUEST_SCHEMA,
    RUNNER_PLAN_REQUEST_CLAIM_SCHEMA,
    discovery_frontier_digest,
    validate_discovery_authorization_request,
    validate_discovery_round_report,
    validate_plan_request,
    validate_route_inventory_rows,
    validate_runner_plan_request_claim,
)


def _v2(plan: dict, actions: list[dict] | None = None, *, maximum_requests: int | None = None) -> dict:
    record = approval()
    record["schema_version"] = APPROVAL_PROJECTION_V2_SCHEMA
    if actions is not None:
        record["actions"] = actions
    record["budgets"]["maximum_requests"] = maximum_requests or len(record["actions"])
    record["plan"] = plan
    return _digest(record, "projection_digest")


def _actions(routes: list[tuple[str, str]]) -> list[dict]:
    return [{"ordinal": index, "scenario_id": "s", "adapter_version": "1", "method": method,
             "route_template": route, "semantic_auth_role": "anonymous",
             "assertion_class": "anonymous_authenticated", "allowed_status_codes": [200],
             "allowed_body_shapes": ["absent"], "side_effect_class": "read_only"}
            for index, (method, route) in enumerate(routes)]


def _round1_plan(**overrides) -> dict:
    plan = {
        "plan_kind": "discovery", "authorization_id": "dau_" + "1" * 32,
        "authorization_digest": HASH, "round": 1, "frontier_digest": DISCOVERY_SEED_DIGEST,
        "cumulative_requests_before": 0, "transport_profile": "discovery", "action_count": 12,
        "sources": [{"ordinal": index, "round": 0, "source_ordinal": index} for index in range(12)],
    }
    plan.update(overrides)
    return plan


def _seed_actions() -> list[dict]:
    return _actions([("GET", path) for path in DISCOVERY_SEED_PATHS])


def test_discovery_plan_variant_is_closed_get_head_only_and_round1_matches_seed_digest():
    assert len(DISCOVERY_SEED_PATHS) == 12 and len(set(DISCOVERY_SEED_PATHS)) == 12
    assert DISCOVERY_SEED_DIGEST == canonical_digest(list(DISCOVERY_SEED_PATHS))
    accepted = _v2(_round1_plan(), _seed_actions())
    assert validate_approval_projection(accepted) == accepted
    # Seed order is irrelevant; the frozen seed set is what the digest binds.
    shuffled = list(reversed(DISCOVERY_SEED_PATHS))
    reordered = _round1_plan(sources=[
        {"ordinal": index, "round": 0, "source_ordinal": DISCOVERY_SEED_PATHS.index(path)}
        for index, path in enumerate(shuffled)
    ])
    validate_approval_projection(_v2(reordered, _actions([("GET", path) for path in shuffled])))

    rejected = {
        "unknown plan key": (_round1_plan(extra=1), _seed_actions()),
        "unknown plan kind": (_round1_plan(plan_kind="crawl"), _seed_actions()),
        "post action": (_round1_plan(), _actions([("POST", DISCOVERY_SEED_PATHS[0])] + [("GET", p) for p in DISCOVERY_SEED_PATHS[1:]])),
        "round 1 frontier digest": (_round1_plan(frontier_digest="b" * 64), _seed_actions()),
        "action count mismatch": (_round1_plan(action_count=11), _seed_actions()),
        "round above bound": (_round1_plan(round=6), _seed_actions()),
        "cumulative above bound": (_round1_plan(cumulative_requests_before=100), _seed_actions()),
        "transport profile": (_round1_plan(transport_profile="scan"), _seed_actions()),
        "source names a later round": (_round1_plan(sources=[{"ordinal": i, "round": 1, "source_ordinal": i} for i in range(12)]), _seed_actions()),
        "forbidden key in plan": (_round1_plan(token="x"), _seed_actions()),
    }
    for name, (plan, actions) in rejected.items():
        with pytest.raises(ContractError):
            validate_approval_projection(_v2(plan, actions))
        assert name
    # Exact seed membership is the server's round check (``seed_mismatch``, contract §4 step 9),
    # so a structurally valid round-1 plan naming another vocabulary path still parses here.
    validate_approval_projection(_v2(_round1_plan(), _actions([("GET", "/admin")] + [("GET", p) for p in DISCOVERY_SEED_PATHS[1:]])))
    with pytest.raises(ContractError):
        validate_approval_projection(_v2(_round1_plan(action_count=1, sources=[{"ordinal": 0, "round": 0, "source_ordinal": 0}]),
                                         _actions([("GET", DISCOVERY_SEED_PATHS[0])])))
    # 21 actions is a contract failure on every variant.
    later = {"plan_kind": "discovery", "authorization_id": "dau_" + "1" * 32, "authorization_digest": HASH,
             "round": 2, "frontier_digest": HASH, "cumulative_requests_before": 12,
             "transport_profile": "discovery", "action_count": 21,
             "sources": [{"ordinal": i, "round": 1, "source_ordinal": 0} for i in range(21)]}
    with pytest.raises(ContractError):
        validate_approval_projection(_v2(later, _actions([("GET", f"/r{i}") for i in range(21)]), maximum_requests=20))
    # maximum_requests is the round's action count, never larger.
    later.update(action_count=2, sources=[{"ordinal": i, "round": 1, "source_ordinal": 0} for i in range(2)])
    validate_approval_projection(_v2(later, _actions([("GET", "/a"), ("HEAD", "/b")])))
    with pytest.raises(ContractError):
        validate_approval_projection(_v2(later, _actions([("GET", "/a"), ("HEAD", "/b")]), maximum_requests=3))
    # v1 cannot carry a plan and v2 cannot omit one.
    v1_with_plan = approval(); v1_with_plan["plan"] = _round1_plan()
    with pytest.raises(ContractError):
        validate_approval_projection(_digest(v1_with_plan, "projection_digest"))
    v2_without_plan = approval(); v2_without_plan["schema_version"] = APPROVAL_PROJECTION_V2_SCHEMA
    with pytest.raises(ContractError):
        validate_approval_projection(_digest(v2_without_plan, "projection_digest"))


def test_discovery_frontier_digest_is_over_the_referenced_recorded_entries_in_source_order():
    first = {"round": 1, "candidate": {"method": "GET", "route_template": "/a", "provenance_kind": "html_link", "source_ordinal": 11, "status_code": 200}}
    second = {"round": 2, "candidate": {"method": "HEAD", "route_template": "/b", "provenance_kind": "js_literal", "source_ordinal": 0, "status_code": 404}}
    assert discovery_frontier_digest([first, second]) == canonical_digest([first, second])
    assert discovery_frontier_digest([first, second]) != discovery_frontier_digest([second, first])
    assert discovery_frontier_digest([first]) != discovery_frontier_digest([first, second])


def _scan_plan(**overrides) -> dict:
    plan = {"plan_kind": "plan_differential", "plan_request_id": "cpr_" + "2" * 32,
            "plan_request_nonce": "n" * 43, "inventory_digest": HASH, "selection_digest": "b" * 64,
            "selected_count": 1, "plan_labels": [{"role": "higher_plan", "plan_label": "Pro"},
                                                  {"role": "lower_plan", "plan_label": "Free"}],
            "max_ops": 2, "not_executed_count": 0, "not_executed_digest": "c" * 64}
    plan.update(overrides)
    return plan


def test_scan_plan_variant_is_closed_and_labels_cannot_carry_handles_or_secrets():
    validate_approval_projection(_v2(_scan_plan()))
    for bad in (
        {"extra": 1},
        {"plan_kind": "regression_all"},
        {"plan_labels": [{"role": "lower_plan", "plan_label": "Free"}]},
        {"plan_labels": [{"role": "admin", "plan_label": "Free"}, {"role": "lower_plan", "plan_label": "Pro"}]},
        {"plan_labels": [{"role": "higher_plan", "plan_label": "a" * 32}, {"role": "lower_plan", "plan_label": "Free"}]},
        {"plan_labels": [{"role": "higher_plan", "plan_label": "0123456789abcdef0123456789abcdef"}, {"role": "lower_plan", "plan_label": "Free"}]},
        {"plan_labels": [{"role": "higher_plan", "plan_label": "sk_live_abc"}, {"role": "lower_plan", "plan_label": "Free"}]},
        {"selected_count": 11},
        {"max_ops": 21},
    ):
        with pytest.raises(ContractError):
            validate_approval_projection(_v2(_scan_plan(**bad)))


ROW = {"method": "GET", "route_template": "/api/v1/orders/{p1}",
       "provenance": [{"kind": "js_literal", "round": 2, "source_ordinal": 3, "status_code": 200}],
       "first_seen_ms": 1, "state": "candidate"}

VALUE_CANARIES = (
    "/users/alice@example.com", "/reset?token=abc", "/t/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln",
    "/objects/0123456789abcdef0123456789abcdef", "/Users/Alice", "/a/12345", "/k/sk_live_abc123",
    "/api/v1/orders/{id}", "/x/{p2}", "/script.js", "/a/QmFzZTY0ZW5jb2RlZFNlY3JldA",
)


def test_inventory_rows_with_provenance_reject_urls_queries_bodies_and_forbidden_keys():
    assert validate_route_inventory_rows([ROW]) == [ROW]
    for canary in VALUE_CANARIES:
        with pytest.raises(ContractError):
            validate_route_inventory_rows([{**ROW, "route_template": canary}])
    excluded = {**ROW, "state": "excluded", "excluded_reason": "side_effect_risk"}
    assert validate_route_inventory_rows([excluded]) == [excluded]
    for bad in (
        {**ROW, "state": "excluded"},
        {**ROW, "excluded_reason": "static_asset"},
        {**ROW, "state": "deleted"},
        {**ROW, "method": "POST"},
        {**ROW, "provenance": [{**ROW["provenance"][0], "kind": "model_guess"}]},
        {**ROW, "provenance": []},
        {**ROW, "url": "https://canary.example.com/api"},
        {**ROW, "query": "token=1"},
        {**ROW, "body": "{}"},
        {**ROW, "headers": {}},
        {**ROW, "password": "p"},
        {**ROW, "cookie": "c"},
    ):
        with pytest.raises(ContractError):
            validate_route_inventory_rows([bad])
    with pytest.raises(ContractError):
        validate_route_inventory_rows([ROW, dict(ROW)])
    with pytest.raises(ContractError):
        validate_route_inventory_rows([{**ROW, "route_template": f"/r{i}"} for i in range(201)])
    # Exactly the fixed seed paths keep their file-like segments verbatim.
    for path in DISCOVERY_SEED_PATHS:
        validate_route_inventory_rows([{**ROW, "route_template": path}])


def _authorization_request(**overrides) -> dict:
    value = {"schema_version": DISCOVERY_AUTHORIZATION_SCHEMA, "environment_id": "env_staging",
             "identities_authorized": ["Admin user"], "login_exchange_authorized": False,
             "acknowledgement": DISCOVERY_ACKNOWLEDGEMENT}
    value.update(overrides)
    return value


def test_discovery_authorization_request_is_closed_and_login_exchange_is_refused_until_c5():
    assert DISCOVERY_ACKNOWLEDGEMENT == "I authorize Heel to send up to 100 GET/HEAD requests to this origin"
    accepted = validate_discovery_authorization_request(_authorization_request())
    # The boolean is stored in its only C2-legal canonical form.
    assert accepted["login_exchange_authorized"] == 0
    validate_discovery_authorization_request(_authorization_request(identities_authorized=[]))
    for bad in (
        {"login_exchange_authorized": True},
        {"login_exchange_authorized": 0},
        {"acknowledgement": DISCOVERY_ACKNOWLEDGEMENT.lower()},
        {"identities_authorized": ["a", "b", "c"]},
        {"identities_authorized": ["x" * 33]},
        {"identities_authorized": ["tab\there"]},
        {"identities_authorized": ["same", "same"]},
        {"password": "hunter2"},
        {"url": "https://canary.example.com/login"},
        {"schema_version": "heel.discovery-authorization.v2"},
    ):
        with pytest.raises(ContractError):
            validate_discovery_authorization_request(_authorization_request(**bad))


def _report(**overrides) -> dict:
    value = {"schema_version": DISCOVERY_ROUND_REPORT_SCHEMA, "authorization_id": "dau_" + "1" * 32,
             "round": 1, "run_id": "run", "grant_id": "g",
             "candidates": [{"method": "GET", "route_template": "/api/v1/orders", "provenance_kind": "html_link",
                             "source_ordinal": 11, "status_code": 200}],
             "excluded_count": 2, "truncated_count": 0, "bytes_received": 1024,
             "report_digest": HASH, "signing_key_id": "rk", "signature_b64": SIG}
    value.update(overrides)
    return _digest(value, "report_digest")


def test_discovery_round_report_is_closed_signed_templates_only_and_bounded():
    accepted = _report()
    assert validate_discovery_round_report(accepted) == accepted
    candidate = accepted["candidates"][0]
    for bad in (
        {"candidates": [{**candidate, "route_template": canary}] }
        for canary in VALUE_CANARIES
    ):
        with pytest.raises(ContractError):
            validate_discovery_round_report(_report(**bad))
    for bad in (
        {"candidates": [{**candidate, "method": "POST"}]},
        {"candidates": [{**candidate, "source_ordinal": 20}]},
        {"candidates": [{**candidate, "status_code": 600}]},
        {"candidates": [{**candidate, "provenance_kind": "customer_url"}]},
        {"candidates": [candidate, dict(candidate)]},
        {"candidates": [{**candidate, "route_template": f"/r{i}"} for i in range(201)]},
        {"round": 6},
        {"body": "x"},
        {"secret": "x"},
    ):
        with pytest.raises(ContractError):
            validate_discovery_round_report(_report(**bad))
    tampered = _report(); tampered["excluded_count"] = 3
    with pytest.raises(ContractError):
        validate_discovery_round_report(tampered)


def test_runner_result_request_may_carry_exactly_one_discovery_round_report():
    projection = operational()
    projection["lifecycle_phase"] = "terminal"; projection["execution_disposition"] = "completed"
    projection["timestamps"].update({"claimed_at_ms": 1, "started_at_ms": 1, "terminal_at_ms": 1})
    projection = _digest(projection, "projection_digest")
    request = {"schema_version": "heel.runner-result-request.v1", "run_id": "run",
               "operational_projection": projection, "discovery_round_report": _report()}
    assert validate_runner_result_request(request) == request
    with pytest.raises(ContractError):
        validate_runner_result_request({**request, "discovery_round_report": _report(run_id="other")})
    with pytest.raises(ContractError):
        validate_runner_result_request({**request, "discovery_round_report": _report(grant_id="other")})


def test_plan_request_and_runner_claim_are_closed_selections_of_route_templates():
    request = {"schema_version": PLAN_REQUEST_SCHEMA, "plan_kind": "plan_differential", "max_ops": 2,
               "routes": [{"method": "GET", "route_template": "/api/v1/orders"}]}
    assert validate_plan_request(request) == request
    for bad in (
        {"routes": []},
        {"routes": [{"method": "GET", "route_template": f"/r{i}"} for i in range(11)]},
        {"routes": [{"method": "DELETE", "route_template": "/r"}]},
        {"routes": [{"method": "GET", "route_template": "/r"}, {"method": "GET", "route_template": "/r"}]},
        {"routes": [{"method": "GET", "route_template": "/u/alice@example.com"}]},
        {"max_ops": 21},
        {"plan_kind": "discovery"},
        {"query": "x"},
    ):
        with pytest.raises(ContractError):
            validate_plan_request({**request, **bad})
    claim = {"schema_version": RUNNER_PLAN_REQUEST_CLAIM_SCHEMA, "binding_id": "rcb_" + "a" * 32,
             "binding_digest": HASH, "credential_roles": [{"role": "higher_plan", "plan_label": "Pro"},
                                                         {"role": "lower_plan", "plan_label": "Free"}]}
    assert validate_runner_plan_request_claim(claim) == claim
    for bad in (
        {"credential_roles": [{"role": "higher_plan", "plan_label": "Pro", "credential_handle_id": "a" * 32}]},
        {"credential_roles": [{"role": "higher_plan", "plan_label": "0123456789abcdef0123456789abcdef"}]},
        {"binding_id": "rcb_x"},
    ):
        with pytest.raises(ContractError):
            validate_runner_plan_request_claim({**claim, **bad})


# --- C2D D4: finite signed body profile; scan stays 256 KiB, discovery may reach 2 MiB ---

from heel.canary_contracts import DISCOVERY_BODY_BYTES, EXECUTION_GRANT_V2_SCHEMA, SCAN_BODY_BYTES


def test_discovery_profile_admits_two_mib_only_for_signed_discovery_plans_and_fails_closed_otherwise():
    assert (SCAN_BODY_BYTES, DISCOVERY_BODY_BYTES) == (262144, 2097152)

    def discovery(maximum: int, **plan):
        record = _v2(_round1_plan(**plan), _seed_actions())
        record = {k: v for k, v in record.items() if k not in {"projection_digest"}}
        record["budgets"] = {**record["budgets"], "maximum_response_bytes": maximum}
        return _digest(record, "projection_digest")

    validate_approval_projection(discovery(DISCOVERY_BODY_BYTES))
    with pytest.raises(ContractError):
        validate_approval_projection(discovery(DISCOVERY_BODY_BYTES + 1))
    for profile in ("scan", "discovery-2", "DISCOVERY"):
        with pytest.raises(ContractError):
            validate_approval_projection(discovery(1024, transport_profile=profile))
    without_profile = _round1_plan(); without_profile.pop("transport_profile")
    with pytest.raises(ContractError):
        validate_approval_projection(_v2(without_profile, _seed_actions()))
    scan = _v2(_scan_plan()); scan["budgets"]["maximum_response_bytes"] = SCAN_BODY_BYTES + 1
    with pytest.raises(ContractError):
        validate_approval_projection(_digest(scan, "projection_digest"))
    v1 = approval(); v1["budgets"]["maximum_response_bytes"] = SCAN_BODY_BYTES + 1
    with pytest.raises(ContractError):
        validate_approval_projection(_digest(v1, "projection_digest"))


def test_execution_grant_v2_budget_profile_is_finite_and_v1_grants_stay_256kib():
    v1 = grant(); v1["budgets"]["maximum_response_bytes"] = DISCOVERY_BODY_BYTES
    with pytest.raises(ContractError):
        validate_execution_grant(_digest(v1, "grant_digest"))

    def v2(maximum: int, **extra):
        record = grant()
        record["schema_version"] = EXECUTION_GRANT_V2_SCHEMA
        record["budget_profile"] = "discovery"
        record.update(extra)
        record["budgets"]["maximum_response_bytes"] = maximum
        return _digest(record, "grant_digest")

    accepted = v2(DISCOVERY_BODY_BYTES)
    assert validate_execution_grant(accepted) == accepted
    with pytest.raises(ContractError):
        validate_execution_grant(v2(DISCOVERY_BODY_BYTES + 1))
    for profile in ("scan", "other"):
        with pytest.raises(ContractError):
            validate_execution_grant(v2(1024, budget_profile=profile))
    missing = v2(1024); missing.pop("budget_profile")
    with pytest.raises(ContractError):
        validate_execution_grant(_digest(missing, "grant_digest"))
    with pytest.raises(ContractError):
        validate_execution_grant(_digest({**grant(), "budget_profile": "discovery"}, "grant_digest"))


# --- inactive-claim attestation wire contracts (C design §6.2/§6.5, ADDENDUM A5.2) ---
# The new names are read through the module so that, before they exist, only these tests fail.
import heel.canary_contracts as contracts

CHALLENGE = base64.b64encode(bytes(range(32, 64))).decode("ascii")
_ID128 = "i" * 128


def _inactive_request(**overrides) -> dict:
    value = {
        "schema_version": "heel.runner-inactive-claim-attestation-request.v1",
        "run_id": "run_1", "project_id": "prj", "grant_id": "grant_1", "grant_digest": HASH,
        "approval_id": "apr_1", "approval_projection_digest": "b" * 64,
        "bound_runner_key_id": "rk_1", "client_challenge_b64": CHALLENGE,
    }
    value.update(overrides)
    return value


def _cloud(status: str = "stop_requested", **overrides) -> dict:
    terminal = status == "terminal"
    value = {
        "status": status, "stop_reason": "cloud_stop", "stop_generation": 1,
        "stop_requested_at_ms": 10, "stop_deadline_ms": 20,
        "terminal_at_ms": 30 if terminal else None,
        "execution_disposition": "stopped" if terminal else None,
        "grant_status": "terminal" if terminal else "claimed",
        "started_at_ms": None, "stop_acknowledged_at_ms": None,
        "observation": "no_start_no_ack_no_execution_projection",
    }
    value.update(overrides)
    return value


_DEFAULT_CLOUD = object()


def _attestation(cloud: object = _DEFAULT_CLOUD, **overrides) -> dict:
    value = {
        "schema_version": "heel.inactive-claim-attestation.v1",
        "attestation_id": "ica_" + "0123456789abcdef" * 2,
        "workspace_id": "ws", "runner_id": "rnr", "project_id": "prj", "run_id": "run_1",
        "grant_id": "grant_1", "grant_digest": HASH, "approval_id": "apr_1",
        "approval_projection_digest": "b" * 64, "bound_runner_key_id": "rk_1",
        "authenticated_runner_key_id": "rk_1", "client_challenge_b64": CHALLENGE,
        "cloud": _cloud() if cloud is _DEFAULT_CLOUD else cloud, "attested_at_ms": 40,
        "attestation_digest": HASH, "signing_key_id": "grant-authority", "signature_b64": SIG,
    }
    value.update(overrides)
    try:
        return _digest(value, "attestation_digest")
    except ContractError:
        # A non-portable mutation has no canonical digest; the validator must reject it as given.
        return value


def _rejects(validator, record) -> None:
    with pytest.raises(ContractError):
        validator(record)


def test_inactive_claim_attestation_request_and_response_are_closed_canonical_and_domain_separated():
    assert contracts.RUNNER_INACTIVE_CLAIM_ATTESTATION_REQUEST_SCHEMA == "heel.runner-inactive-claim-attestation-request.v1"
    assert contracts.RUNNER_INACTIVE_CLAIM_ATTESTATION_PROOF_SCHEMA == "heel.runner-inactive-claim-attestation-proof.v1"
    assert contracts.RUNNER_INACTIVE_CLAIM_ATTESTATION_POP_DOMAIN == b"heel.runner-inactive-claim-attestation-pop.v1\0"
    assert contracts.INACTIVE_CLAIM_ATTESTATION_SCHEMA == "heel.inactive-claim-attestation.v1"
    assert contracts.INACTIVE_CLAIM_ATTESTATION_DOMAIN == b"heel.inactive-claim-attestation.v1\0"
    assert contracts.INACTIVE_CLAIM_OBSERVATION == "no_start_no_ack_no_execution_projection"
    assert contracts.RUNNER_INACTIVE_CLAIM_ATTESTATION_REQUEST_MAX_BYTES == 2048
    assert contracts.INACTIVE_CLAIM_ATTESTATION_RESPONSE_MAX_BYTES == 8192
    # The two new separators differ from each other and from every existing runner/resync PoP domain.
    domains = {contracts.RUNNER_INACTIVE_CLAIM_ATTESTATION_POP_DOMAIN, contracts.INACTIVE_CLAIM_ATTESTATION_DOMAIN,
               b"heel.runner-pop.v1\0", b"heel.runner-resync-start-pop.v2\0", b"heel.runner-resync-complete-pop.v2\0"}
    assert len(domains) == 5

    request = _inactive_request()
    accepted = contracts.validate_runner_inactive_claim_attestation_request(request)
    assert accepted == request and accepted is not request
    raw = canonical_bytes(request)
    assert contracts.validate_runner_inactive_claim_attestation_request(
        parse_json(raw, max_bytes=contracts.RUNNER_INACTIVE_CLAIM_ATTESTATION_REQUEST_MAX_BYTES)) == request

    # I1 (stop_requested/finalizing, no terminal fields) and I2 (terminal/stopped) are both valid.
    for cloud in (_cloud("stop_requested"), _cloud("finalizing"), _cloud("terminal")):
        record = _attestation(cloud)
        result = contracts.validate_inactive_claim_attestation(record)
        assert result == record and result["cloud"] is not record["cloud"]
        raw = canonical_bytes(record)
        assert contracts.validate_inactive_claim_attestation(
            parse_json(raw, max_bytes=contracts.INACTIVE_CLAIM_ATTESTATION_RESPONSE_MAX_BYTES)) == record

    # The signed payload is the domain plus the canonical record without digest and envelope fields.
    record = _attestation()
    unsigned = {k: v for k, v in record.items() if k not in {"attestation_digest", "signing_key_id", "signature_b64"}}
    payload = contracts.inactive_claim_attestation_signing_payload(record)
    assert payload == b"heel.inactive-claim-attestation.v1\0" + canonical_bytes(unsigned)
    assert contracts.inactive_claim_attestation_signing_payload(unsigned) == payload
    assert record["attestation_digest"] == canonical_digest(unsigned)


def test_inactive_claim_attestation_request_rejects_unknown_fields_types_and_encodings():
    missing = _inactive_request(); missing.pop("client_challenge_b64")
    for bad in (
        _inactive_request(unexpected=1),
        _inactive_request(workspace_id="ws"),
        missing,
        _inactive_request(schema_version="heel.runner-inactive-claim-attestation-request.v2"),
        _inactive_request(schema_version="heel.runner-resync-start.v2"),
        _inactive_request(run_id=""), _inactive_request(run_id=1), _inactive_request(run_id=True),
        _inactive_request(run_id=None), _inactive_request(run_id=["run_1"]),
        _inactive_request(project_id=_ID128 + "x"), _inactive_request(grant_id=False),
        _inactive_request(approval_id={"id": "apr_1"}), _inactive_request(bound_runner_key_id=0),
        _inactive_request(grant_digest="A" * 64), _inactive_request(grant_digest="a" * 63),
        _inactive_request(grant_digest=True), _inactive_request(approval_projection_digest="g" * 64),
        _inactive_request(client_challenge_b64=base64.b64encode(bytes(31)).decode()),
        _inactive_request(client_challenge_b64=base64.b64encode(bytes(33)).decode()),
        _inactive_request(client_challenge_b64=CHALLENGE.rstrip("=")),
        _inactive_request(client_challenge_b64=base64.urlsafe_b64encode(bytes([0xfb] * 32)).decode()),
        _inactive_request(client_challenge_b64=CHALLENGE + "\n"),
        _inactive_request(client_challenge_b64=" " + CHALLENGE),
        _inactive_request(client_challenge_b64=True),
        _inactive_request(client_challenge_b64=list(range(32))),
        "not an object", [], None,
    ):
        _rejects(contracts.validate_runner_inactive_claim_attestation_request, bad)
    # Boundary identifiers are accepted; a standard-alphabet challenge with '+' and '/' is canonical.
    contracts.validate_runner_inactive_claim_attestation_request(_inactive_request(
        run_id=_ID128, client_challenge_b64=base64.b64encode(bytes([0xfb, 0xff] * 16)).decode()))


def test_inactive_claim_attestation_wire_budgets_use_the_bounded_parser():
    request_max = contracts.RUNNER_INACTIVE_CLAIM_ATTESTATION_REQUEST_MAX_BYTES
    response_max = contracts.INACTIVE_CLAIM_ATTESTATION_RESPONSE_MAX_BYTES
    # The largest valid records (every identifier at its 128-byte ceiling) fit their budgets.
    request = _inactive_request(**{f: _ID128 for f in ("run_id", "project_id", "grant_id", "approval_id", "bound_runner_key_id")})
    assert len(canonical_bytes(contracts.validate_runner_inactive_claim_attestation_request(request))) < request_max
    ids = {f: _ID128 for f in ("workspace_id", "runner_id", "project_id", "run_id", "grant_id", "approval_id",
                                "bound_runner_key_id", "authenticated_runner_key_id", "signing_key_id")}
    response = _attestation(_cloud("terminal", stop_generation=(1 << 53) - 1, stop_requested_at_ms=(1 << 53) - 1,
                                   stop_deadline_ms=(1 << 53) - 1, terminal_at_ms=(1 << 53) - 1,
                                   stop_reason="local_emergency_stop", grant_status="terminal"),
                            attested_at_ms=(1 << 53) - 1, **ids)
    assert len(canonical_bytes(contracts.validate_inactive_claim_attestation(response))) < response_max
    # The byte budget is enforced by parse_json on the raw wire bytes, exactly at the ceiling.
    for record, maximum, validator in (
        (_inactive_request(), request_max, contracts.validate_runner_inactive_claim_attestation_request),
        (_attestation(), response_max, contracts.validate_inactive_claim_attestation),
    ):
        raw = canonical_bytes(record)
        at_limit = raw + b" " * (maximum - len(raw))
        assert validator(parse_json(at_limit, max_bytes=maximum)) == record
        with pytest.raises(ContractError, match="input exceeds size limit"):
            parse_json(at_limit + b" ", max_bytes=maximum)


def test_inactive_claim_attestation_timestamps_are_nonnegative_integers_without_unit_inference():
    # Seconds-looking and millisecond-looking integers, zero and the portable ceiling are all accepted
    # unchanged; the contract has no epoch floor and never rescales a bare integer.
    for moment in (0, 1, 1_800_000_000, 1_800_000_000_000, (1 << 53) - 1):
        record = _attestation(_cloud("terminal", stop_requested_at_ms=moment, stop_deadline_ms=moment,
                                     terminal_at_ms=moment), attested_at_ms=moment)
        assert contracts.validate_inactive_claim_attestation(record) == record
    for field in ("stop_requested_at_ms", "stop_deadline_ms", "terminal_at_ms", "stop_generation"):
        for bad in (-1, 1 << 53, True, False, "1", None if field != "terminal_at_ms" else "x", [1], {"ms": 1}):
            _rejects(contracts.validate_inactive_claim_attestation, _attestation(_cloud("terminal", **{field: bad})))
    for bad in (-1, 1 << 53, True, "40", None, [40]):
        _rejects(contracts.validate_inactive_claim_attestation, _attestation(attested_at_ms=bad))


def test_inactive_claim_attestation_rejects_incoherent_cloud_state_and_observation():
    cases = [
        _cloud("terminal", execution_disposition=None),
        _cloud("terminal", execution_disposition="completed"),
        _cloud("terminal", execution_disposition="failed"),
        _cloud("terminal", terminal_at_ms=None),
        _cloud("stop_requested", execution_disposition="stopped"),
        _cloud("finalizing", terminal_at_ms=30),
        _cloud("finalizing", execution_disposition="stopped", terminal_at_ms=30),
        _cloud("running"), _cloud("claimed"), _cloud("cancelled"), _cloud("expired"), _cloud("TERMINAL"),
        _cloud(stop_reason="none"), _cloud(stop_reason="cloud_disconnected"), _cloud(stop_reason=None),
        _cloud(grant_status="active"), _cloud(grant_status=None),
        _cloud(started_at_ms=0), _cloud(started_at_ms=11), _cloud(started_at_ms=False),
        _cloud(stop_acknowledged_at_ms=0), _cloud(stop_acknowledged_at_ms=12),
        _cloud(observation="no_start_no_ack_no_execution_projection "),
        _cloud(observation="NO_START_NO_ACK_NO_EXECUTION_PROJECTION"),
        _cloud(observation="not_executed"), _cloud(observation=None),
        {**_cloud(), "unexpected": None},
        {k: v for k, v in _cloud().items() if k != "started_at_ms"},
        {k: v for k, v in _cloud().items() if k != "observation"},
        "terminal", None, [],
    ]
    for cloud in cases:
        _rejects(contracts.validate_inactive_claim_attestation, _attestation(cloud))
    for reason in ("local_emergency_stop", "cloud_stop", "runner_revoked", "target_revoked", "kill_switch"):
        contracts.validate_inactive_claim_attestation(_attestation(_cloud("terminal", stop_reason=reason)))
    for status in ("prepared", "approved", "issued", "claimed", "expired", "revoked", "terminal"):
        contracts.validate_inactive_claim_attestation(_attestation(_cloud(grant_status=status)))


def test_inactive_claim_attestation_rejects_fields_ids_keys_challenge_and_digest_mutations():
    missing = _attestation(); missing.pop("authenticated_runner_key_id")
    cases = [
        _attestation(unexpected=1), _attestation(nonce="x"), _digest(missing, "attestation_digest"),
        _attestation(schema_version="heel.inactive-claim-attestation.v2"),
        _attestation(schema_version="heel.runner-inactive-claim-attestation-request.v1"),
        _attestation(attestation_id="ica_" + "0" * 31), _attestation(attestation_id="ica_" + "0" * 33),
        _attestation(attestation_id="ICA_" + "0" * 32), _attestation(attestation_id="ica_" + "A" * 32),
        _attestation(attestation_id="ica_" + "0" * 31 + "\n"), _attestation(attestation_id="rcb_" + "0" * 32),
        _attestation(attestation_id=None), _attestation(attestation_id=True),
        _attestation(authenticated_runner_key_id="rk_2"), _attestation(bound_runner_key_id="rk_2"),
        _attestation(workspace_id=""), _attestation(runner_id=_ID128 + "x"), _attestation(run_id=1),
        _attestation(project_id=True), _attestation(grant_id=None), _attestation(approval_id=["apr_1"]),
        _attestation(grant_digest="A" * 64), _attestation(approval_projection_digest="b" * 65),
        _attestation(client_challenge_b64=CHALLENGE.rstrip("=")),
        _attestation(client_challenge_b64=base64.b64encode(bytes(16)).decode()),
        _attestation(client_challenge_b64=base64.urlsafe_b64encode(bytes([0xfb] * 32)).decode()),
        _attestation(signing_key_id=""), _attestation(signing_key_id=True),
        _attestation(signature_b64=base64.b64encode(bytes(63)).decode()),
        _attestation(signature_b64=SIG.rstrip("=")),
        "attestation", None, [],
    ]
    # A field changed after the digest was computed, and a digest over the wrong field set.
    changed = _attestation(); changed["run_id"] = "run_2"; cases.append(changed)
    changed = _attestation(); changed["cloud"] = dict(changed["cloud"], stop_generation=2); cases.append(changed)
    wrong_set = _attestation(); wrong_set["attestation_digest"] = canonical_digest(
        {k: v for k, v in wrong_set.items() if k != "attestation_digest"}); cases.append(wrong_set)
    missing_digest = _attestation(); missing_digest.pop("attestation_digest"); cases.append(missing_digest)
    for bad_digest in ("A" * 64, "a" * 63, True, None):
        changed = _attestation(); changed["attestation_digest"] = bad_digest; cases.append(changed)
    for record in cases:
        _rejects(contracts.validate_inactive_claim_attestation, record)


def test_inactive_claim_attestation_validator_does_not_prove_authenticity_signature_is_caller_checked():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from heel.crypto import ed25519_key_id, sign_envelope, verify_envelope

    # A structurally valid record with an arbitrary well-formed signature passes the validator: the
    # contract is structural only and callers must verify the pinned grant-authority signature.
    assert contracts.validate_inactive_claim_attestation(_attestation())["signature_b64"] == SIG

    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = private.public_key()
    key_id = ed25519_key_id(public.public_bytes(Encoding.Raw, PublicFormat.Raw))
    record = _attestation(signing_key_id=key_id)
    record.update(sign_envelope(private, key_id, contracts.inactive_claim_attestation_signing_payload(record)))
    accepted = contracts.validate_inactive_claim_attestation(record)
    envelope = {"signing_key_id": accepted["signing_key_id"], "signature_b64": accepted["signature_b64"]}
    verify_envelope({key_id: public}, envelope, contracts.inactive_claim_attestation_signing_payload(accepted))
    # Domain separation: the same unsigned bytes without the separator, or under another domain, fail.
    unsigned_bytes = contracts.inactive_claim_attestation_signing_payload(accepted)[len(contracts.INACTIVE_CLAIM_ATTESTATION_DOMAIN):]
    for payload in (unsigned_bytes, b"heel.runner-pop.v1\0" + unsigned_bytes,
                    contracts.RUNNER_INACTIVE_CLAIM_ATTESTATION_POP_DOMAIN + unsigned_bytes):
        with pytest.raises(ValueError):
            verify_envelope({key_id: public}, envelope, payload)
    # A re-digested mutation is structurally valid again but no longer verifies.
    forged = _attestation(signing_key_id=key_id, run_id="run_2")
    forged.update(envelope)
    contracts.validate_inactive_claim_attestation(forged)
    with pytest.raises(ValueError):
        verify_envelope({key_id: public}, envelope, contracts.inactive_claim_attestation_signing_payload(forged))
