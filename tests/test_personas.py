import json
import os
from dataclasses import asdict, replace
import tempfile
import unittest

os.environ["HEEL_HOME"] = tempfile.mkdtemp()

from heel import scope as scopemod  # noqa: E402
from heel.agents_human import run_opportunistic  # noqa: E402
from heel.contracts import Affordance, Category, SyntheticTarget  # noqa: E402
from heel.mcp_server import HeelServer  # noqa: E402
from heel.profiles import DEFAULT_PERSONAS, PERSONA_BY_ID  # noqa: E402
from heel.store import Store  # noqa: E402
from heel.targets import get_target  # noqa: E402


class PersonaBase(unittest.TestCase):
    def setUp(self):
        os.environ["HEEL_HOME"] = tempfile.mkdtemp()
        self.store = Store()
        self.server = HeelServer(self.store)
        self.caller = "persona-test-agent"
        self.scope = scopemod.create_scope(["synthetic-saas", "synthetic-ai"], operator="tester")

    def run_target(self, target, classes=None):
        args = {"scope_id": self.scope.scope_id, "target": target}
        if classes is not None:
            args["agent_classes"] = classes
        return self.server.heel_run(args, self.caller)["run_id"]

    def findings(self, run_id):
        return self.server.heel_get_findings({"run_id": run_id}, self.caller)["findings"]


class TestPersonaLibrary(unittest.TestCase):
    REQUIRED = {
        "coupon_stacker",
        "seat_sharer",
        "agency_reseller",
        "data_broker",
        "trial_farmer",
        "integration_overreacher",
        "support_pressure_user",
        "marketplace_reputation_gamer",
        "usage_meter_optimizer",
        "ai_cost_amplifier",
        "agent_wrapper_builder",
    }

    def test_required_personas_are_defined_with_controls_and_canary_examples(self):
        self.assertEqual(set(PERSONA_BY_ID), self.REQUIRED)
        for persona in DEFAULT_PERSONAS:
            self.assertTrue(persona.motivation)
            self.assertGreaterEqual(persona.sophistication, 0.0)
            self.assertGreaterEqual(persona.patience, 0.0)
            self.assertGreaterEqual(persona.risk_tolerance, 0.0)
            self.assertTrue(persona.target_affordance_types)
            self.assertTrue(persona.preferred_abuse_chains)
            self.assertTrue(persona.deterring_controls)
            self.assertTrue(persona.canary_rehearsal_examples)
            self.assertTrue(all("canary" in e.lower() for e in persona.canary_rehearsal_examples))

    def test_persona_requires_motivation_and_affordance_match(self):
        seat = PERSONA_BY_ID["seat_sharer"]
        target = SyntheticTarget(
            "t",
            "saas",
            False,
            [
                Affordance(
                    id="safe_seats",
                    kind="seat",
                    category=Category.LICENSE_ENTITLEMENT,
                    properties={"sharing_detection": "enforced"},
                    guard_present=True,
                    reachability=0.7,
                )
            ],
            [],
        )
        self.assertEqual(run_opportunistic(target, [seat], lambda *a: None, "r")["findings"], [])

        mismatched = replace(seat, motivation_tags=("unrelated",))
        target.affordances[0].properties["sharing_detection"] = "none"
        self.assertEqual(run_opportunistic(target, [mismatched], lambda *a: None, "r")["findings"], [])


class TestPersonaFindings(PersonaBase):
    def _direct(self, persona_id, target_id="synthetic-saas"):
        return run_opportunistic(get_target(target_id), [PERSONA_BY_ID[persona_id]], lambda *a: None, "persona-run")

    def test_seat_sharer_flags_seats_and_concurrency_issues(self):
        out = self._direct("seat_sharer")
        self.assertEqual([f.affordance_id for f in out["findings"]], ["seats"])
        finding = out["findings"][0]
        self.assertEqual(finding.reproduction["persona"]["id"], "seat_sharer")
        self.assertIn("concurrent", finding.recommended_control.lower())
        self.assertIn("why_this_customer_would_try_it", finding.reproduction["evidence"])

    def test_coupon_stacker_flags_promo_coupon_stacking(self):
        out = self._direct("coupon_stacker")
        self.assertEqual([f.affordance_id for f in out["findings"]], ["promo_stacking"])
        finding = out["findings"][0]
        self.assertIn("coupon", finding.scenario_id)
        self.assertIn("stack", finding.reproduction["evidence"]["why_this_customer_would_try_it"].lower())

    def test_data_broker_prioritizes_exports_and_enumeration(self):
        out = self._direct("data_broker")
        self.assertGreaterEqual(len(out["findings"]), 2)
        self.assertEqual(out["findings"][0].affordance_id, "export_records")
        self.assertIn("record_get", [f.affordance_id for f in out["findings"]])
        self.assertIn("enumeration", out["findings"][1].scenario_id)

    def test_trial_farmer_prioritizes_weak_signup_trial_eligibility(self):
        out = self._direct("trial_farmer")
        self.assertEqual([f.affordance_id for f in out["findings"]], ["trial_signup"])
        finding = out["findings"][0]
        evidence = finding.reproduction["evidence"]
        self.assertIn("eligibility", evidence["why_this_customer_would_try_it"].lower())
        self.assertIn("identity", evidence["affordance_match"].lower())

    def test_ai_cost_amplifier_prioritizes_unbounded_agent_cost_surfaces(self):
        out = self._direct("ai_cost_amplifier", "synthetic-ai")
        self.assertEqual(out["findings"][0].affordance_id, "agent_infer_loop")
        finding = out["findings"][0]
        self.assertEqual(finding.category, Category.AGENT_MCP_SURFACE)
        self.assertIn("cost", finding.reproduction["evidence"]["why_this_customer_would_try_it"].lower())
        self.assertIn("token", finding.reproduction["evidence"]["why_this_customer_would_try_it"].lower())

    def test_persona_findings_are_canary_only(self):
        out = run_opportunistic(get_target("synthetic-ai"), DEFAULT_PERSONAS, lambda *a: None, "persona-run")
        self.assertTrue(out["findings"])
        for finding in out["findings"]:
            self.assertEqual(finding.reproduction["sample"], "canary_only")
            self.assertTrue(finding.reproduction["contained"])
            self.assertTrue(finding.reproduction["canary_rehearsal"])

    def test_better_calibrated_adversarial_finding_is_kept_and_persona_evidence_is_attached(self):
        rid = self.run_target("synthetic-saas")
        export = next(f for f in self.findings(rid) if f["affordance_id"] == "export_records")

        self.assertFalse(export["scenario_id"].startswith("persona."))
        self.assertNotEqual(export["reproduction"].get("class"), "opportunistic_human")
        persona_ids = [e["persona_id"] for e in export["reproduction"].get("persona_evidence", [])]
        self.assertIn("data_broker", persona_ids)

    def test_disabling_opportunistic_agent_class_removes_persona_findings_and_evidence(self):
        rid = self.run_target("synthetic-saas", classes=["adversarial"])
        findings = self.findings(rid)
        self.assertFalse(any(f["reproduction"].get("class") == "opportunistic_human" for f in findings))
        self.assertFalse(any(f["reproduction"].get("persona_evidence") for f in findings))
        coverage = self.server.heel_get_coverage({"run_id": rid}, self.caller)["coverage"]
        self.assertEqual(coverage["opportunistic_findings"], 0)

    def test_persona_outputs_are_deterministic(self):
        target = get_target("synthetic-ai")
        first = run_opportunistic(target, DEFAULT_PERSONAS, lambda *a: None, "same-run")
        second = run_opportunistic(target, DEFAULT_PERSONAS, lambda *a: None, "same-run")

        def freeze(out):
            rows = []
            for finding in out["findings"]:
                d = asdict(finding)
                d["category"] = finding.category.value
                d["verification_status"] = finding.verification_status.value
                rows.append(d)
            return json.dumps(rows, sort_keys=True)

        self.assertEqual(freeze(first), freeze(second))


if __name__ == "__main__":
    unittest.main()
