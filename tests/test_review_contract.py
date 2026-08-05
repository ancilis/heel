import json
import math
import unittest
from typing import Any, get_type_hints

from heel.review_contract import (
    ENGINE_VERSION,
    EXECUTION_MODES,
    REVIEW_SCHEMA_VERSION,
    build_review_envelope,
    stable_json,
    stable_json_hash,
    validate_review_envelope,
)


SOURCE_HASH = "a" * 64
MODEL_HASH = "b" * 64
BASELINE_HASH = "c" * 64


def finding(surface_type="exports", surface_id="export_users", risk="missing_entitlement",
            severity="block", control="entitlement check", reason="missing control",
            reachable=True):
    return {
        "surface_type": surface_type,
        "surface_id": surface_id,
        "risk": risk,
        "severity": severity,
        "control": control,
        "reason": reason,
        "reachable": reachable,
    }


def regression(surface_type="exports", surface_id="export_users", name="export entitlement",
               expected_status="blocked", scenario_hint="exercise export entitlement"):
    return {
        "surface_type": surface_type,
        "surface_id": surface_id,
        "name": name,
        "expected_status": expected_status,
        "scenario_hint": scenario_hint,
        "safety": "model-only, canary-contained; no live probing",
    }


def question(identifier="entitlement:1", field="entitlement_check", surface="/exports",
             prompt="Which entitlement protects /exports?", required=False):
    return {
        "id": identifier,
        "field": field,
        "surface": surface,
        "prompt": prompt,
        "required": required,
    }


def safety():
    return {
        "mode": "static ProductModel diff",
        "live_probing": False,
        "network_calls": False,
        "requires_signed_scope_for_live_or_staging_runs": True,
        "canary_only": True,
    }


class ReviewContractTests(unittest.TestCase):
    @staticmethod
    def _review():
        findings = [
            finding("meters", "api_calls", "missing_quota", "warn", "tenant quota",
                    "meter has no tenant quota"),
            finding("exports", "export_users", "export_without_tenant_quota", "block",
                    "tenant quota", "export is reachable without a tenant quota"),
            finding(),
        ]
        return {
            "product_id": "sample-saas",
            "launch_gate_status": "block",
            "changed_surfaces": [],
            "new_abuse_affordances": findings,
            "high_risk_missing_controls": findings[1:],
            "recommended_controls": [findings[1].copy(), findings[0].copy()],
            "suggested_regression_tests": [
                regression("meters", "api_calls", "meter quota", "limited", "exercise meter quota"),
                regression(),
            ],
            "safety": safety(),
        }

    def _build(self, review=None, *, execution_mode="machine_local", questions=None, **hashes):
        return build_review_envelope(
            review if review is not None else self._review(),
            source_hash=hashes.get("source_hash", SOURCE_HASH),
            model_hash=hashes.get("model_hash", MODEL_HASH),
            baseline_hash=hashes.get("baseline_hash", BASELINE_HASH),
            execution_mode=execution_mode,
            questions=questions if questions is not None else [question()],
        )

    def test_envelope_is_deterministic_and_set_like_records_are_canonical(self):
        one = self._build(questions=[question("z"), question("a")])
        reordered = self._review()
        reordered["new_abuse_affordances"].reverse()
        reordered["recommended_controls"].reverse()
        reordered["suggested_regression_tests"].reverse()
        two = self._build(reordered, questions=[question("a"), question("z")])

        self.assertEqual(one, two)
        self.assertEqual(
            [(item["severity"], item["surface_type"], item["surface_id"], item["risk"])
             for item in one["findings"]],
            [
                ("block", "exports", "export_users", "export_without_tenant_quota"),
                ("block", "exports", "export_users", "missing_entitlement"),
                ("warn", "meters", "api_calls", "missing_quota"),
            ],
        )
        for field in ("recommended_controls", "suggested_regressions", "questions"):
            self.assertEqual(one[field], sorted(one[field], key=stable_json))

    def test_finding_order_uses_canonical_record_as_final_tie_breaker(self):
        review = self._review()
        review["new_abuse_affordances"] = [
            finding(reason="z reason"),
            finding(reason="a reason"),
        ]
        review["launch_gate_status"] = "block"
        envelope = self._build(review)
        self.assertEqual([item["reason"] for item in envelope["findings"]],
                         ["a reason", "z reason"])

    def test_stable_json_is_compact_sorted_unicode_preserving_and_normalizes_negative_zero(self):
        value = {"value": -0.0, "nested": [-0.0], "emoji": "snowman ☃"}
        self.assertEqual(
            stable_json(value),
            '{"emoji":"snowman ☃","nested":[0.0],"value":0.0}',
        )

    def test_stable_json_accepts_finite_numbers_at_js_safe_boundaries(self):
        value = {"max": 2**53 - 1, "min": -(2**53 - 1), "float": 1.25}
        self.assertEqual(json.loads(stable_json(value)), value)

    def test_stable_json_rejects_non_json_or_non_portable_values(self):
        invalid = [
            {"value": math.nan},
            {"value": math.inf},
            {"value": -math.inf},
            {"value": 2**53},
            {"value": -(2**53)},
            {1: "non-string key"},
            {"value": (1, 2)},
            {"value": {1, 2}},
            {"value": "\ud800"},
            {"\udfff": "lone surrogate key"},
        ]
        for value in invalid:
            with self.subTest(value=repr(value)):
                with self.assertRaises((TypeError, ValueError)):
                    stable_json(value)

    def test_stable_hash_ignores_nested_mapping_order(self):
        one = {"outer": {"a": 1, "b": 2}, "items": [{"x": 3, "y": 4}]}
        two = {"items": [{"y": 4, "x": 3}], "outer": {"b": 2, "a": 1}}
        self.assertEqual(stable_json_hash(one), stable_json_hash(two))

    def test_envelope_fields_summary_and_identifier_contract(self):
        envelope = self._build()

        self.assertEqual(envelope["schema_version"], REVIEW_SCHEMA_VERSION)
        self.assertEqual(envelope["engine_version"], ENGINE_VERSION)
        self.assertEqual(envelope["product_id"], "sample-saas")
        self.assertEqual(envelope["source_hash"], SOURCE_HASH)
        self.assertEqual(envelope["model_hash"], MODEL_HASH)
        self.assertEqual(envelope["baseline_hash"], BASELINE_HASH)
        self.assertEqual(envelope["execution_mode"], "machine_local")
        self.assertEqual(envelope["gate_status"], "block")
        self.assertEqual(envelope["summary"], {"findings": 3, "blockers": 2, "questions": 1})
        self.assertEqual(envelope["safety"], safety())

        body = {key: value for key, value in envelope.items()
                if key not in {"review_id", "result_hash"}}
        self.assertEqual(envelope["result_hash"], stable_json_hash(body))
        self.assertEqual(envelope["review_id"], "review_" + envelope["result_hash"][:20])

    def test_envelope_validator_checks_schema_integrity_and_detaches(self):
        envelope = self._build()
        validated = validate_review_envelope(envelope)
        self.assertEqual(validated, envelope)
        self.assertIsNot(validated, envelope)
        self.assertIsNot(validated["findings"], envelope["findings"])

        validated["findings"][0]["reason"] = "mutated"
        self.assertNotEqual(validated, envelope)

    def test_envelope_validator_rejects_unknown_fields_and_content_tampering(self):
        unknown = self._build()
        unknown["raw_openapi"] = {"paths": {}}
        with self.assertRaisesRegex(ValueError, "v1 fields"):
            validate_review_envelope(unknown)

        tampered = self._build()
        tampered["product_id"] = "tampered"
        with self.assertRaisesRegex(ValueError, "result_hash"):
            validate_review_envelope(tampered)

    def test_envelope_validator_rejects_other_engine_even_when_rehashed(self):
        envelope = self._build()
        envelope["engine_version"] = "0.0.0"
        body = {
            key: value for key, value in envelope.items()
            if key not in {"review_id", "result_hash"}
        }
        envelope["result_hash"] = stable_json_hash(body)
        envelope["review_id"] = "review_" + envelope["result_hash"][:20]

        with self.assertRaisesRegex(ValueError, "engine_version"):
            validate_review_envelope(envelope)

    def test_execution_modes_have_truthful_mode_specific_privacy(self):
        self.assertIsInstance(EXECUTION_MODES, frozenset)
        self.assertEqual(EXECUTION_MODES,
                         frozenset({"browser_local", "machine_local", "cloud_isolated"}))
        expected = {
            "browser_local": {"uploaded": False, "sync_intent": "none"},
            "machine_local": {"uploaded": False, "sync_intent": "none"},
            "cloud_isolated": {"uploaded": True, "sync_intent": "sanitized_model"},
        }
        for execution_mode, mode_privacy in expected.items():
            with self.subTest(execution_mode=execution_mode):
                envelope = self._build(execution_mode=execution_mode)
                self.assertEqual(envelope["privacy"], {
                    "execution": execution_mode,
                    "network_calls": False,
                    **mode_privacy,
                })
                self.assertEqual(
                    envelope["safety"]["network_calls"],
                    envelope["privacy"]["network_calls"],
                )

    def test_static_safety_record_is_fixed_v1_output(self):
        self.assertEqual(self._build()["safety"], safety())

    def test_contradictory_static_safety_values_are_rejected(self):
        unsafe_variants = {
            "mode": "live ProductModel diff",
            "live_probing": True,
            "network_calls": True,
            "requires_signed_scope_for_live_or_staging_runs": False,
            "canary_only": False,
        }
        for field, unsafe_value in unsafe_variants.items():
            review = self._review()
            review["safety"][field] = unsafe_value
            with self.subTest(field=field, unsafe_value=unsafe_value):
                with self.assertRaisesRegex(ValueError, f"safety.{field}"):
                    self._build(review)

    def test_public_builder_annotations_match_strict_json_containers(self):
        hints = get_type_hints(build_review_envelope)
        self.assertEqual(hints["review"], dict[str, Any])
        self.assertEqual(hints["questions"], list[dict[str, Any]])
        self.assertEqual(hints["return"], dict[str, Any])

    def test_contract_is_json_serializable_and_baseline_hash_may_be_none(self):
        envelope = self._build(baseline_hash=None)
        self.assertEqual(json.loads(json.dumps(envelope, allow_nan=False)), envelope)

    def test_equivalent_mapping_order_produces_identical_envelope(self):
        review = self._review()
        reordered_review = {key: value for key, value in reversed(review.items())}
        reordered_review["new_abuse_affordances"] = [
            {key: value for key, value in reversed(item.items())}
            for item in review["new_abuse_affordances"]
        ]
        questions = [question()]
        reordered_questions = [
            {key: value for key, value in reversed(question().items())}
        ]

        self.assertEqual(self._build(review, questions=questions),
                         self._build(reordered_review, questions=reordered_questions))

    def test_envelope_is_deeply_detached_from_caller_inputs(self):
        review = self._review()
        questions = [question()]
        envelope = self._build(review, questions=questions)
        expected = json.loads(json.dumps(envelope))

        review["new_abuse_affordances"][0]["reason"] = "mutated"
        review["recommended_controls"][0]["control"] = "mutated"
        review["suggested_regression_tests"][0]["scenario_hint"] = "mutated"
        review["safety"]["mode"] = "mutated"
        review["new_abuse_affordances"].append(finding())
        questions[0]["prompt"] = "mutated"
        questions.append(question("later"))

        self.assertEqual(envelope, expected)
        body = {key: value for key, value in envelope.items()
                if key not in {"review_id", "result_hash"}}
        self.assertEqual(envelope["result_hash"], stable_json_hash(body))

    def test_empty_review_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "product_id"):
            self._build({})

    def test_gate_must_exactly_match_findings(self):
        review = self._review()
        review["launch_gate_status"] = "pass"
        with self.assertRaisesRegex(ValueError, "launch_gate_status"):
            self._build(review)

        review["new_abuse_affordances"] = [finding(severity="warn")]
        review["launch_gate_status"] = "warn"
        self.assertEqual(self._build(review)["gate_status"], "warn")

        review["new_abuse_affordances"] = []
        review["launch_gate_status"] = "pass"
        self.assertEqual(self._build(review)["gate_status"], "pass")

    def test_findings_reject_bad_severity_types_and_unknown_keys(self):
        bad_findings = [
            {**finding(), "severity": "critical"},
            {**finding(), "reachable": 1},
            {**finding(), "api_key": "sk-live-do-not-copy"},
        ]
        for bad_finding in bad_findings:
            review = self._review()
            review["new_abuse_affordances"] = [bad_finding]
            with self.subTest(bad_finding=bad_finding):
                with self.assertRaises(ValueError) as caught:
                    self._build(review)
                self.assertNotIn("sk-live-do-not-copy", str(caught.exception))

    def test_review_containers_must_be_json_arrays_and_objects(self):
        invalid = {
            "new_abuse_affordances": {},
            "recommended_controls": {},
            "suggested_regression_tests": {},
            "safety": [],
        }
        for field, value in invalid.items():
            review = self._review()
            review[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, field):
                    self._build(review)

    def test_controls_regressions_safety_and_questions_use_exact_v1_fields(self):
        cases = []
        review = self._review()
        review["recommended_controls"][0]["secret"] = "hidden"
        cases.append((review, [question()], "recommended_controls"))

        review = self._review()
        del review["suggested_regression_tests"][0]["scenario_hint"]
        cases.append((review, [question()], "suggested_regression_tests"))

        review = self._review()
        review["safety"]["extra"] = False
        cases.append((review, [question()], "safety"))

        cases.append((self._review(), [{**question(), "answer": "secret"}], "questions"))
        cases.append((self._review(), [{**question(), "required": 0}], "questions"))

        for review, questions, field in cases:
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, field):
                    self._build(review, questions=questions)

    def test_hashes_must_be_lowercase_sha256_hex(self):
        invalid = [
            {"source_hash": "a" * 63},
            {"model_hash": "B" * 64},
            {"baseline_hash": "g" * 64},
        ]
        for hashes in invalid:
            field = next(iter(hashes))
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, field):
                    self._build(**hashes)

    def test_unknown_execution_mode_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "execution_mode"):
            self._build(execution_mode="remote_magic")

    def test_non_string_mode_and_gate_are_rejected_as_validation_errors(self):
        try:
            self._build(execution_mode=[])
        except Exception as exc:
            self.assertIsInstance(exc, ValueError)
            self.assertIn("execution_mode", str(exc))
        else:
            self.fail("non-string execution_mode was accepted")

        review = self._review()
        review["launch_gate_status"] = []
        try:
            self._build(review)
        except Exception as exc:
            self.assertIsInstance(exc, ValueError)
            self.assertIn("launch_gate_status", str(exc))
        else:
            self.fail("non-string launch_gate_status was accepted")


if __name__ == "__main__":
    unittest.main()
