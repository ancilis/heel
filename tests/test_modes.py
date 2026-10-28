import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest

os.environ["HEEL_HOME"] = tempfile.mkdtemp()

from heel import cli  # noqa: E402
from heel import scope as scopemod  # noqa: E402
from heel.mcp_server import TOOL_NAMES  # noqa: E402
from heel.targets import clear_imported_targets  # noqa: E402


MODEL_LIST_FIELDS = [
    "tenants",
    "roles",
    "plans",
    "meters",
    "coupons_promotions",
    "features_flags",
    "endpoints_routes",
    "exports",
    "identity_auth_flows",
    "billing_objects",
    "integration_oauth_apps",
    "webhooks",
    "support_admin_actions",
    "agent_tools",
    "mcp_connectors",
    "data_classes",
    "audit_events",
    "declared_controls",
    "canary_accounts",
    "safety_notes",
]


def product_model(product_id="acme-existing", canaries=True):
    model = {key: [] for key in MODEL_LIST_FIELDS}
    model.update(
        {
            "schema_version": "ProductModel.v0.1",
            "product_id": product_id,
            "source": "operator-authored existing product model",
            "generated_at": "2026-07-04T20:00:00Z",
            "environments": ["staging"],
            "plans": [{"id": "trial"}, {"id": "pro"}],
            "exports": [
                {
                    "id": "bulk_records",
                    "route": "/api/export",
                    "guard_present": False,
                    "data_class": "canary_records",
                }
            ],
            "data_classes": ["canary_records"],
            "safety_notes": ["sanitized model; canary-only, no live calls, no customer data"],
        }
    )
    if canaries:
        model["canary_accounts"] = ["canary-user-001"]
    return model


class TestHeelModes(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.environ["HEEL_HOME"] = self.home
        clear_imported_targets()

    def tearDown(self):
        clear_imported_targets()

    def _write_model(self, model):
        path = Path(tempfile.mkdtemp()) / f"{model['product_id']}.json"
        path.write_text(json.dumps(model), encoding="utf-8")
        return path

    def _run_cli(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(argv)
        return rc, buf.getvalue()

    def test_mode_registry_defines_required_safety_fields(self):
        from heel.modes import MODES, describe_mode

        self.assertEqual(
            set(MODES),
            {"synthetic", "launch-review", "staging", "existing-imported", "incident-regression"},
        )
        existing = describe_mode("existing-imported")

        for mode in MODES.values():
            data = mode.to_dict()
            for key in (
                "requires_scope",
                "allows_live_probe",
                "requires_canary_accounts",
                "default_rate_limits",
                "allowed_target_sources",
                "output_emphasis",
            ):
                self.assertIn(key, data)
            self.assertFalse(data["allows_live_probe"])

        self.assertTrue(existing["requires_scope"])
        self.assertIn("ProductModel", existing["allowed_target_sources"])
        self.assertIn("mature products", existing["output_emphasis"])

    def test_synthetic_mode_keeps_existing_run_behavior(self):
        scope = scopemod.create_scope(["synthetic-saas"], operator="tester")

        rc, out = self._run_cli(
            ["run", "--mode", "synthetic", "--scope", scope.scope_id, "--target", "synthetic-saas"]
        )

        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["status"], "complete")
        self.assertEqual(payload["mode"]["id"], "synthetic")
        self.assertEqual(payload["mode"]["target_source"], "built-in synthetic target")

    def test_existing_imported_mode_runs_product_model_without_live_calls(self):
        model_path = self._write_model(product_model())
        scope = scopemod.create_scope(["imported:acme-existing"], operator="tester")

        rc, out = self._run_cli(
            ["run", "--mode", "existing-imported", "--scope", scope.scope_id, "--target", str(model_path)]
        )

        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["status"], "complete")
        self.assertEqual(payload["mode"]["id"], "existing-imported")
        self.assertEqual(payload["mode"]["resolved_target"], "imported:acme-existing")
        self.assertFalse(payload["mode"]["allows_live_probe"])
        self.assertIn("ProductModel", payload["mode"]["target_source"])
        self.assertIn("no live probing", out)

    def test_staging_mode_requires_scope_and_canary_metadata(self):
        no_canary = self._write_model(product_model("staging-no-canary", canaries=False))
        with_canary = self._write_model(product_model("staging-with-canary", canaries=True))
        loose_scope = scopemod.create_scope(["imported:staging-with-canary"], operator="tester")
        strict_scope = scopemod.create_scope(
            ["imported:staging-with-canary"],
            operator="tester",
            limits={"max_requests": 20, "max_concurrency": 2, "backoff": True},
        )

        rc, out = self._run_cli(["run", "--mode", "staging", "--target", str(with_canary)])
        self.assertEqual(rc, 2)
        self.assertIn("requires --scope", out)

        rc, out = self._run_cli(
            ["run", "--mode", "staging", "--scope", loose_scope.scope_id, "--target", str(with_canary)]
        )
        self.assertEqual(rc, 2)
        self.assertIn("stricter", out)

        rc, out = self._run_cli(
            ["run", "--mode", "staging", "--scope", strict_scope.scope_id, "--target", str(no_canary)]
        )
        self.assertEqual(rc, 2)
        self.assertIn("canary", out.lower())

        rc, out = self._run_cli(
            ["run", "--mode", "staging", "--scope", strict_scope.scope_id, "--target", str(with_canary)]
        )
        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["mode"]["id"], "staging")
        self.assertTrue(payload["mode"]["requires_canary_accounts"])

    def test_launch_review_mode_uses_before_after_product_models(self):
        before = product_model("launch-mode")
        after = product_model("launch-mode")
        after["exports"].append(
            {
                "id": "new_bulk",
                "route": "/api/new-export",
                "entitlement_check": "missing",
                "tenant_quota": "missing",
                "reachable_by_plan": "trial",
            }
        )
        before_path = self._write_model(before)
        after_path = self._write_model(after)

        rc, out = self._run_cli(
            ["run", "--mode", "launch-review", "--before", str(before_path), "--after", str(after_path)]
        )

        self.assertEqual(rc, 2, out)
        self.assertIn("Launch gate: block", out)
        self.assertIn("mode: launch-review", out)
        self.assertIn("no live probing", out)

    def test_incident_regression_mode_runs_stored_regressions(self):
        scope = scopemod.create_scope(["synthetic-saas"], operator="tester")
        rc, out = self._run_cli(
            ["run", "--mode", "synthetic", "--scope", scope.scope_id, "--target", "synthetic-saas"]
        )
        self.assertEqual(rc, 0, out)
        run_id = json.loads(out)["run_id"]

        findings = io.StringIO()
        with redirect_stdout(findings):
            self.assertEqual(cli.main(["findings", "--run", run_id]), 0)
        vector = next(
            f for f in json.loads(findings.getvalue())["findings"]
            if f["scenario_id"] == "sc.trial.serial"
        )
        rc, out = self._run_cli(
            ["regress", "add", "--run", run_id, "--vector", vector["id"], "--name", "trial_regression"]
        )
        self.assertEqual(rc, 0, out)

        rc, out = self._run_cli(
            ["run", "--mode", "incident-regression", "--scope", scope.scope_id, "--target", "synthetic-saas"]
        )

        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["mode"]["id"], "incident-regression")
        self.assertEqual(len(payload["results"]), 1)
        self.assertTrue(payload["results"][0]["safety_flags"]["canary_only"])

    def test_no_mode_allows_scope_mutation(self):
        from heel.modes import MODES

        for mode in MODES.values():
            self.assertFalse(mode.allows_scope_mutation)
        for forbidden in ("heel_create_scope", "heel_widen_scope", "heel_add_target", "heel_set_limits"):
            self.assertNotIn(forbidden, TOOL_NAMES)

    def test_docs_list_safety_constraints_per_mode(self):
        doc = Path("docs/MODES.md").read_text(encoding="utf-8")

        for token in (
            "synthetic",
            "launch-review",
            "staging",
            "existing-imported",
            "incident-regression",
            "requires_scope",
            "allows_live_probe",
            "requires_canary_accounts",
            "default_rate_limits",
            "allowed_target_sources",
            "output emphasis",
            "no scope mutation",
        ):
            self.assertIn(token, doc)


if __name__ == "__main__":
    unittest.main()
