import json
import unittest

from heel.review_contract import (
    ENGINE_VERSION,
    EXECUTION_MODES,
    REVIEW_SCHEMA_VERSION,
    build_review_envelope,
    stable_json,
    stable_json_hash,
)


class ReviewContractTests(unittest.TestCase):
    @staticmethod
    def _review():
        return {
            "product_id": "sample-saas",
            "launch_gate_status": "block",
            "changed_surfaces": [],
            "new_abuse_affordances": [
                {
                    "surface_type": "meters",
                    "surface_id": "api_calls",
                    "risk": "missing_quota",
                    "severity": "warn",
                    "control": "tenant quota",
                    "reason": "meter has no tenant quota",
                    "reachable": True,
                },
                {
                    "surface_type": "exports",
                    "surface_id": "export_users",
                    "risk": "export_without_tenant_quota",
                    "severity": "block",
                    "control": "tenant quota",
                    "reason": "export is reachable without a tenant quota",
                    "reachable": True,
                },
                {
                    "surface_type": "exports",
                    "surface_id": "export_users",
                    "risk": "missing_entitlement",
                    "severity": "block",
                    "control": "entitlement check",
                    "reason": "export is reachable without an entitlement check",
                    "reachable": True,
                },
            ],
            "high_risk_missing_controls": [],
            "recommended_controls": [{"control": "tenant quota"}],
            "suggested_regression_tests": [{"name": "export quota"}],
            "safety": {"network_calls": False, "live_probing": False},
        }

    def _build(self, review=None, *, execution_mode="machine_local", questions=None):
        return build_review_envelope(
            review if review is not None else self._review(),
            source_hash="source",
            model_hash="model",
            baseline_hash="baseline",
            execution_mode=execution_mode,
            questions=questions if questions is not None else [{"id": "quota", "answer": None}],
        )

    def test_envelope_is_deterministic_and_findings_have_canonical_order(self):
        one = self._build()
        reordered = self._review()
        reordered["new_abuse_affordances"].reverse()
        two = self._build(reordered)

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

    def test_stable_json_is_compact_sorted_and_preserves_unicode(self):
        self.assertEqual(stable_json({"b": 2, "a": "café"}), '{"a":"café","b":2}')

    def test_stable_hash_ignores_nested_mapping_order(self):
        one = {"outer": {"a": 1, "b": 2}, "items": [{"x": 3, "y": 4}]}
        two = {"items": [{"y": 4, "x": 3}], "outer": {"b": 2, "a": 1}}
        self.assertEqual(stable_json_hash(one), stable_json_hash(two))

    def test_envelope_fields_summary_and_identifier_contract(self):
        envelope = self._build()

        self.assertEqual(envelope["schema_version"], REVIEW_SCHEMA_VERSION)
        self.assertEqual(envelope["engine_version"], ENGINE_VERSION)
        self.assertEqual(envelope["product_id"], "sample-saas")
        self.assertEqual(envelope["source_hash"], "source")
        self.assertEqual(envelope["model_hash"], "model")
        self.assertEqual(envelope["baseline_hash"], "baseline")
        self.assertEqual(envelope["execution_mode"], "machine_local")
        self.assertEqual(envelope["gate_status"], "block")
        self.assertEqual(envelope["summary"], {"findings": 3, "blockers": 2, "questions": 1})
        self.assertEqual(envelope["recommended_controls"], [{"control": "tenant quota"}])
        self.assertEqual(envelope["suggested_regressions"], [{"name": "export quota"}])
        self.assertEqual(envelope["questions"], [{"id": "quota", "answer": None}])
        self.assertEqual(envelope["safety"], {"network_calls": False, "live_probing": False})

        body = {key: value for key, value in envelope.items()
                if key not in {"review_id", "result_hash"}}
        self.assertEqual(envelope["result_hash"], stable_json_hash(body))
        self.assertEqual(envelope["review_id"], "review_" + envelope["result_hash"][:20])

    def test_execution_modes_have_exact_private_contracts(self):
        self.assertEqual(EXECUTION_MODES, {"browser_local", "machine_local", "cloud_isolated"})
        for execution_mode in EXECUTION_MODES:
            with self.subTest(execution_mode=execution_mode):
                envelope = self._build(execution_mode=execution_mode)
                self.assertEqual(envelope["execution_mode"], execution_mode)
                self.assertEqual(envelope["privacy"], {
                    "execution": execution_mode,
                    "network_calls": False,
                    "uploaded": False,
                    "sync_intent": "none",
                })

    def test_contract_is_json_serializable(self):
        envelope = self._build()
        self.assertEqual(json.loads(json.dumps(envelope)), envelope)

    def test_equivalent_mapping_order_produces_identical_envelope(self):
        review = self._review()
        reordered_review = {
            key: ({nested_key: item[nested_key] for nested_key in reversed(item)}
                  if isinstance(item, dict) else item)
            for key, item in reversed(review.items())
        }
        reordered_review["new_abuse_affordances"] = [
            {key: value for key, value in reversed(item.items())}
            for item in review["new_abuse_affordances"]
        ]
        questions = [{"id": "quota", "answer": None}]
        reordered_questions = [{"answer": None, "id": "quota"}]

        self.assertEqual(self._build(review, questions=questions),
                         self._build(reordered_review, questions=reordered_questions))

    def test_unknown_execution_mode_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "execution_mode"):
            self._build(execution_mode="remote_magic")


if __name__ == "__main__":
    unittest.main()
