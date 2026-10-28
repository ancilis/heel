import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest

from heel import scope as scopemod  # noqa: E402


def incident(**overrides):
    data = {
        "incident_id": "inc-coupon-001",
        "summary": "Trial users stacked coupons to avoid paid conversion.",
        "product_area": "billing promotions",
        "affected_surfaces": ["checkout coupon redemption"],
        "customer_type": "trial_user",
        "abuse_goal": "coupon stacking and serial discount farming",
        "steps_observed": [
            "Used a canary account to redeem multiple promotions through the normal checkout affordance.",
        ],
        "business_impact": {"estimated_monthly_loss_usd": {"low": 1200, "high": 7000}},
        "controls_missing": ["coupon stacking limit", "per-account promotion velocity limit"],
        "controls_added": ["single active coupon per account"],
        "data_classes": ["billing_metadata"],
        "sanitized_evidence": {
            "evidence_id": "redacted-ticket-123",
            "coupon_attempts": "multiple canary redemptions observed",
        },
        "prohibited_fields_removed_confirmed": True,
        "source": "trust_safety",
        "safety_notes": ["Customer identifiers removed; canary-only evidence retained."],
    }
    data.update(overrides)
    return data


class IncidentBase(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.environ["HEEL_HOME"] = self.home

    def write_incident(self, data):
        path = Path(self.home) / f"{data['incident_id']}.json"
        path.write_text(json.dumps(data))
        return path


class TestIncidentToScenario(IncidentBase):
    def test_sanitized_coupon_stacking_becomes_license_entitlement_scenario_draft(self):
        from heel.incident import draft_scenario, import_incident

        record = import_incident(self.write_incident(incident()))
        draft = draft_scenario(record["incident_id"])
        scenario = draft["scenario"]

        self.assertEqual(scenario["category"], "license_entitlement")
        self.assertEqual(draft["mapping"]["persona"], "coupon_stacker")
        self.assertEqual(scenario["kind"], "promotion")
        self.assertEqual(scenario["success_criterion"]["prop"], "coupon_stacking")
        self.assertEqual(scenario["success_criterion"]["equals"], "observed")
        self.assertTrue(Path(draft["draft_path"]).exists())
        self.assertFalse(draft["auto_enabled"])

    def test_export_scraping_becomes_data_harvesting_scenario_draft(self):
        from heel.incident import draft_scenario, import_incident

        data = incident(
            incident_id="inc-export-001",
            summary="A customer repeatedly pulled bulk exports from a free account.",
            product_area="exports",
            affected_surfaces=["bulk export"],
            abuse_goal="export scraping",
            controls_missing=["export entitlement check", "per-tenant rate limit"],
            controls_added=["export entitlement check"],
            data_classes=["workspace_records"],
        )

        record = import_incident(self.write_incident(data))
        scenario = draft_scenario(record["incident_id"])["scenario"]

        self.assertEqual(scenario["category"], "data_harvesting")
        self.assertEqual(scenario["kind"], "export")
        self.assertEqual(scenario["success_criterion"]["prop"], "export_scraping")

    def test_support_workflow_gaming_becomes_workflow_scenario_draft(self):
        from heel.incident import draft_scenario, import_incident

        data = incident(
            incident_id="inc-support-001",
            summary="A customer gamed support approvals to bypass refund policy.",
            product_area="support workflow",
            affected_surfaces=["support refund approval"],
            abuse_goal="support workflow gaming",
            controls_missing=["dual approval", "refund audit event"],
            controls_added=["manual approval threshold"],
            data_classes=["support_ticket_metadata"],
            source="ticket",
        )

        record = import_incident(self.write_incident(data))
        draft = draft_scenario(record["incident_id"])

        self.assertIn(draft["scenario"]["category"], {"function_abuse", "trust_economy", "compliance_boundary"})
        self.assertEqual(draft["mapping"]["persona"], "support_workflow_gamer")
        self.assertEqual(draft["scenario"]["kind"], "support_workflow")

    def test_secrets_looking_evidence_is_rejected(self):
        from heel.incident import IncidentError, import_incident

        data = incident(
            sanitized_evidence={
                "api_token": "redacted",
                "customer_email": "person@example.com",
            },
        )

        with self.assertRaises(IncidentError) as err:
            import_incident(self.write_incident(data))
        self.assertIn("sanitized_evidence", str(err.exception))

    def test_generated_scenario_is_declarative_json_without_payloads(self):
        from heel.incident import draft_scenario, import_incident

        record = import_incident(self.write_incident(incident()))
        scenario = draft_scenario(record["incident_id"])["scenario"]
        serialized = json.dumps(scenario)

        self.assertIsInstance(scenario["success_criterion"], dict)
        self.assertIn("severity_model", scenario)
        self.assertNotIn("reproduction", scenario)
        self.assertNotIn("payload", serialized.lower())
        self.assertNotIn("steps", scenario)

    def test_generated_regression_is_canary_only(self):
        from heel.incident import add_regression_draft, import_incident

        record = import_incident(self.write_incident(incident()))
        regression = add_regression_draft(record["incident_id"])

        self.assertEqual(regression["source_incident_id"], record["incident_id"])
        self.assertTrue(regression["safety_flags"]["canary_only"])
        self.assertTrue(regression["safety_flags"]["contained"])
        self.assertTrue(regression["safety_flags"]["scope_required"])
        self.assertEqual(regression["evidence_mode"], "canary_only")
        self.assertTrue(Path(regression["draft_path"]).exists())

    def test_incident_cli_does_not_create_or_widen_scope(self):
        from heel import cli

        data = incident()
        path = self.write_incident(data)
        scope = scopemod.create_scope(["synthetic-saas"], operator="tester")
        scope_path = Path(scopemod.heel_home()) / "scopes" / f"{scope.scope_id}.json"
        before = json.loads(scope_path.read_text())

        for argv in (
            ["incident", "import", str(path)],
            ["incident", "draft-scenario", data["incident_id"]],
            ["incident", "add-regression", data["incident_id"]],
            ["incident", "review", data["incident_id"]],
        ):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(cli.main(argv), 0, out.getvalue())

        after = json.loads(scope_path.read_text())
        self.assertEqual(after["target_allowlist"], before["target_allowlist"])
        self.assertEqual(after["signature"], before["signature"])
        self.assertIsNone(scopemod.get_scope("scope-forged"))

    def test_incident_review_prints_exactly_what_would_be_added(self):
        from heel import cli

        data = incident()
        path = self.write_incident(data)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["incident", "import", str(path)]), 0)

        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main(["incident", "review", data["incident_id"]]), 0)
        review = json.loads(out.getvalue())

        self.assertFalse(review["auto_enabled"])
        self.assertEqual(review["would_add"]["scenario"]["category"], "license_entitlement")
        self.assertEqual(review["would_add"]["regression"]["evidence_mode"], "canary_only")
        self.assertTrue(review["would_add"]["regression"]["safety_flags"]["no_scope_widening"])


if __name__ == "__main__":
    unittest.main()
