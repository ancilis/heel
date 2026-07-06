import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest


def valid_scenario():
    return {
        "id": "sc.community.billing.coupon_stacking",
        "category": "license_entitlement",
        "objective": "Customer stacks promotional discounts beyond intended policy",
        "kind": "meter",
        "success_criterion": {"prop": "coupon_stacking", "equals": "allowed"},
        "severity_model": {"likelihood": 0.45, "impact": 0.55},
        "recommended_control": "enforce one active promotion per canary billing account",
        "containment_limits": {
            "canary_only": True,
            "max_examples": 3,
            "no_live_targets": True,
        },
        "applies_when": "always",
    }


class TestScenarioValidation(unittest.TestCase):
    def test_valid_scenario_passes(self):
        from arceo.scenario_validate import validate_scenario

        result = validate_scenario(valid_scenario())

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(result.scenario_id, "sc.community.billing.coupon_stacking")

    def test_bundled_community_pack_validates_and_keeps_limits(self):
        from arceo.scenario_validate import validate_scenario_file
        from arceo.scenarios import list_scenarios

        results = validate_scenario_file("arceo/scenarios_lib/community.json")

        self.assertTrue(all(result.ok for result in results), [r.errors for r in results])
        csv_scenario = next(s for s in list_scenarios() if s.id == "sc.community.csv_formula_injection")
        self.assertEqual(csv_scenario.containment_limits["max_examples"], 3)

    def test_missing_control_fails(self):
        from arceo.scenario_validate import validate_scenario

        scenario = valid_scenario()
        del scenario["recommended_control"]

        result = validate_scenario(scenario)

        self.assertFalse(result.ok)
        self.assertTrue(any("recommended_control" in e for e in result.errors))

    def test_unknown_operator_fails(self):
        from arceo.scenario_validate import validate_scenario

        scenario = valid_scenario()
        scenario["success_criterion"] = {"shell_exec": "blocked"}

        result = validate_scenario(scenario)

        self.assertFalse(result.ok)
        self.assertTrue(any("unsupported operator" in e for e in result.errors))

    def test_unsafe_payload_looking_string_fails_without_echoing_payload(self):
        from arceo.scenario_validate import validate_scenario

        scenario = valid_scenario()
        unsafe = "PAYLOAD_REDACTED: exploit real credentials and exfiltrate customer data"
        scenario["objective"] = unsafe

        result = validate_scenario(scenario)

        self.assertFalse(result.ok)
        joined = "\n".join(result.errors).lower()
        self.assertIn("prohibited", joined)
        self.assertNotIn(unsafe.lower(), joined)

    def test_scenario_namespace_and_containment_limits_are_required(self):
        from arceo.scenario_validate import validate_scenario

        scenario = valid_scenario()
        scenario["id"] = "sc.partner.coupon_stacking"
        scenario["containment_limits"] = {"canary_only": False}

        result = validate_scenario(scenario)

        self.assertFalse(result.ok)
        self.assertTrue(any("namespace" in e for e in result.errors))
        self.assertTrue(any("canary" in e for e in result.errors))

    def test_cli_validate_file_prints_errors(self):
        from arceo import cli

        scenario = valid_scenario()
        scenario["success_criterion"] = {"unknown": True}
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "scenario.json"
            path.write_text(json.dumps(scenario), encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli.main(["scenario", "validate", str(path)])

        self.assertEqual(rc, 1)
        self.assertIn("Scenario validation: FAIL", buf.getvalue())
        self.assertIn("unsupported operator", buf.getvalue())

    def test_cli_explain_prints_objective_category_control_and_safety_limits(self):
        from arceo import cli

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["scenario", "explain", "sc.community.csv_formula_injection"])

        self.assertEqual(rc, 0, buf.getvalue())
        out = buf.getvalue().lower()
        self.assertIn("csv/formula injection", out)
        self.assertIn("content_policy", out)
        self.assertIn("neutralize", out)
        self.assertIn("canary-only", out)

    def test_docs_include_operator_reference_and_safe_unsafe_examples(self):
        doc = Path("docs/SCENARIO_AUTHORING.md").read_text(encoding="utf-8")

        for token in (
            "guard_absent",
            "prop_exists",
            "prop_contains",
            "prop_neq",
            "all_of",
            "any_of",
            "semantic",
            "coupon stacking",
            "trial farming",
            "OAuth over-scope",
            "agent tool over-scope",
            "real credential use",
            "high-volume scraping",
        ):
            self.assertIn(token, doc)


if __name__ == "__main__":
    unittest.main()
