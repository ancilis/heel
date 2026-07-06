import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest

os.environ["ARCEO_HOME"] = tempfile.mkdtemp()

from arceo.contracts import Category  # noqa: E402


def finding(vector_id, scenario_id, category, affordance_id, properties=None):
    return {
        "id": vector_id,
        "scenario_id": scenario_id,
        "category": category.value if isinstance(category, Category) else category,
        "affordance_id": affordance_id,
        "recommended_control": "",
        "reproduction": {
            "sample": "canary_only",
            "contained": True,
            "observed": {"affordance_properties": properties or {}},
        },
    }


def controls(report):
    return [c["control"] for c in report["candidates"]]


class TestControlSimulator(unittest.TestCase):
    def test_export_abuse_recommends_entitlement_rate_limit_and_audit(self):
        from arceo.control_simulator import simulate_finding

        report = simulate_finding(finding(
            "av-export",
            "sc.export.entitlement",
            Category.DATA_HARVESTING,
            "export_records",
            {"route": "/api/export", "entitlement_check": "missing"},
        ))

        self.assertTrue(
            {"entitlement_check", "per_tenant_rate_limit", "audit_event"}.issubset(controls(report)),
        )
        self.assertEqual(report["recommended_bundle"][0]["control"], "entitlement_check")
        self.assertFalse(report["verified"])

    def test_trial_farming_recommends_uniqueness_and_payment_verification(self):
        from arceo.control_simulator import simulate_finding

        report = simulate_finding(finding(
            "av-trial",
            "sc.trial.serial",
            Category.LICENSE_ENTITLEMENT,
            "trial_signup",
            {"identity_check": "email_only"},
        ))

        self.assertIn("proof_of_uniqueness", controls(report))
        self.assertIn("payment_verification", controls(report))

    def test_agent_overscope_recommends_tool_scope_reduction_and_per_action_authorization(self):
        from arceo.control_simulator import simulate_finding

        report = simulate_finding(finding(
            "av-agent",
            "sc.agent.overscope",
            Category.AGENT_MCP_SURFACE,
            "agent_tool_export",
            {"granted_scope": "all_tenants", "intended_scope": "own_tenant"},
        ))

        self.assertIn("agent_tool_scope_reduction", controls(report))
        self.assertIn("per_action_authorization", controls(report))

    def test_cost_amplification_recommends_cost_ceiling_and_step_bound(self):
        from arceo.control_simulator import simulate_finding

        report = simulate_finding(finding(
            "av-cost",
            "sc.agent.costamp",
            Category.AGENT_MCP_SURFACE,
            "agent_infer_loop",
            {"multi_step": "unbounded", "amplification": "cheap->expensive"},
        ))

        self.assertIn("cost_ceiling", controls(report))
        self.assertIn("step_bound", controls(report))

    def test_control_bundle_ranking_is_deterministic(self):
        from arceo.control_simulator import simulate_finding

        f = finding(
            "av-webhook",
            "sc.sem.webhook",
            Category.INTEGRATION_EXTENSIBILITY,
            "webhook_endpoint",
            {"replay_protection": "missing", "route": "/webhooks/in"},
        )

        first = simulate_finding(f)
        second = simulate_finding(json.loads(json.dumps(f)))

        self.assertEqual(first["recommended_bundle"], second["recommended_bundle"])
        self.assertEqual(controls(first), controls(second))

    def test_simulator_does_not_claim_certainty_without_evidence(self):
        from arceo.control_simulator import simulate_finding

        report = simulate_finding(finding(
            "av-unknown",
            "sc.unknown",
            Category.LICENSE_ENTITLEMENT,
            "unknown_affordance",
        ))

        self.assertFalse(report["verified"])
        self.assertIn("proposed", report["evidence_level"])
        self.assertTrue(report["candidates"])
        self.assertLess(max(c["confidence"] for c in report["candidates"]), 0.8)

    def test_product_model_signal_can_inform_control_choice(self):
        from arceo.control_simulator import simulate_finding

        model = {
            "product_id": "acme",
            "endpoints_routes": [
                {"id": "record_read", "route": "/api/records/{id}", "tenant_filter": "missing"},
            ],
        }
        report = simulate_finding(
            finding(
                "av-model",
                "sc.imported.unknown",
                Category.COMPLIANCE_BOUNDARY,
                "eg:endpoint:record_read:tenant_filter_missing",
            ),
            product_model=model,
        )

        self.assertEqual(report["recommended_bundle"][0]["control"], "tenant_filter")
        self.assertIn("tenant isolation evidence", report["recommended_bundle"][0]["evidence"])

    def test_cli_simulates_from_finding_json(self):
        from arceo import cli

        path = Path(tempfile.mkdtemp()) / "finding.json"
        path.write_text(json.dumps(finding(
            "av-cli",
            "sc.export.entitlement",
            Category.DATA_HARVESTING,
            "export_records",
            {"entitlement_check": "missing"},
        )))

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["controls", "simulate", "--finding-json", str(path)])

        self.assertEqual(rc, 0)
        report = json.loads(buf.getvalue())
        self.assertIn("entitlement_check", controls(report))
        self.assertEqual(report["input"]["vector_id"], "av-cli")

    def test_cli_simulates_from_vector_and_run(self):
        from arceo import cli

        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cli.main(["scope", "create", "--target", "synthetic-saas",
                                       "--operator", "tester", "--confirm"]), 0)
        scope_id = json.loads(buf.getvalue())["created_scope"]

        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cli.main(["run", "--scope", scope_id, "--target", "synthetic-saas"]), 0)
        run_id = json.loads(buf.getvalue())["run_id"]

        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cli.main(["findings", "--run", run_id]), 0)
        vector_id = json.loads(buf.getvalue())["findings"][0]["id"]

        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cli.main(["controls", "simulate", "--vector", vector_id]), 0)
        vector_report = json.loads(buf.getvalue())
        self.assertEqual(vector_report["input"]["vector_id"], vector_id)
        self.assertTrue(vector_report["recommended_bundle"])

        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cli.main(["controls", "simulate", "--run", run_id]), 0)
        run_report = json.loads(buf.getvalue())
        self.assertEqual(run_report["run_id"], run_id)
        self.assertTrue(run_report["simulations"])
        self.assertTrue(run_report["recommended_bundle"])


if __name__ == "__main__":
    unittest.main()
