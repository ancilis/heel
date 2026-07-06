import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest

os.environ["ARCEO_HOME"] = tempfile.mkdtemp()

from arceo import cli  # noqa: E402
from arceo import scope as scopemod  # noqa: E402
from arceo.contracts import Category  # noqa: E402
from arceo.importers import target_from_product_model, validate_product_model  # noqa: E402
from arceo.targets import clear_imported_targets  # noqa: E402


DEMO_DIR = Path("examples/saas_demo")
PRODUCT_MODEL = DEMO_DIR / "product_model.json"
OPENAPI = DEMO_DIR / "openapi.json"
README = DEMO_DIR / "README.md"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _walk_json(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child)
    elif isinstance(value, str):
        yield value


class TestSaasDemoExample(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.environ["ARCEO_HOME"] = self.home
        clear_imported_targets()

    def tearDown(self):
        clear_imported_targets()

    def _run_cli(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(argv)
        return rc, buf.getvalue()

    def test_demo_files_exist_and_product_model_validates(self):
        self.assertTrue(PRODUCT_MODEL.is_file())
        self.assertTrue(OPENAPI.is_file())
        self.assertTrue(README.is_file())

        model = _load_json(PRODUCT_MODEL)
        result = validate_product_model(model)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(result.target_id, "imported:arceo-saas-demo")
        self.assertEqual(model["environments"], ["staging", "sandbox"])
        self.assertIn("canary-only", " ".join(model["safety_notes"]))

    def test_demo_models_required_saas_surfaces_and_weaknesses(self):
        model = _load_json(PRODUCT_MODEL)
        plan_ids = {plan["id"] for plan in model["plans"]}
        meter_ids = {meter["id"] for meter in model["meters"]}
        control_statuses = {control["status"] for control in model["declared_controls"]}

        self.assertEqual({"free", "pro", "enterprise"}, plan_ids)
        self.assertTrue(any(obj.get("kind") == "seat" for obj in model["billing_objects"]))
        self.assertTrue(any(flow.get("id") == "trial_signup" for flow in model["identity_auth_flows"]))
        self.assertTrue(model["coupons_promotions"])
        self.assertIn("monthly_api_calls", meter_ids)
        self.assertIn("ai_token_units", meter_ids)
        self.assertTrue(model["exports"])
        self.assertTrue(model["tenants"])
        self.assertTrue(any(route.get("id") == "team_invites" for route in model["endpoints_routes"]))
        self.assertTrue(model["integration_oauth_apps"])
        self.assertTrue(model["webhooks"])
        self.assertTrue(model["support_admin_actions"])
        self.assertTrue(model["agent_tools"])
        self.assertTrue(model["mcp_connectors"])
        self.assertTrue(model["canary_accounts"])
        self.assertIn("present", control_statuses)
        self.assertIn("missing", control_statuses)

        self.assertTrue(any(flow.get("identity_check") == "email_only" for flow in model["identity_auth_flows"]))
        self.assertTrue(any(export.get("entitlement_check") == "missing" for export in model["exports"]))
        self.assertTrue(any(coupon.get("stackable") is True for coupon in model["coupons_promotions"]))
        self.assertTrue(any(tool.get("multi_step") == "unbounded" for tool in model["agent_tools"]))
        self.assertTrue(any(app.get("scope") == "all" for app in model["integration_oauth_apps"]))
        self.assertTrue(any(tool.get("granted_scope") != tool.get("intended_scope") for tool in model["agent_tools"]))
        self.assertTrue(any(action.get("audit_logged") is False for action in model["support_admin_actions"]))

    def test_demo_target_represents_all_taxonomy_categories(self):
        target = target_from_product_model(_load_json(PRODUCT_MODEL))
        categories = {aff.category.value for aff in target.affordances}

        self.assertEqual({category.value for category in Category}, categories)
        self.assertTrue(target.has_agent_surface)
        self.assertTrue(target.requires_scope)
        self.assertTrue(target.safety_metadata["live_probing_disabled"])

    def test_demo_run_produces_expected_categories(self):
        scope = scopemod.create_scope(["imported:arceo-saas-demo"], operator="demo-tester")

        rc, out = self._run_cli([
            "run",
            "--mode", "existing-imported",
            "--target", str(PRODUCT_MODEL),
            "--scope", scope.scope_id,
        ])
        self.assertEqual(rc, 0, out)
        run_id = json.loads(out)["run_id"]

        rc, out = self._run_cli(["findings", "--run", run_id])
        self.assertEqual(rc, 0, out)
        categories = {finding["category"] for finding in json.loads(out)["findings"]}

        self.assertEqual({category.value for category in Category}, categories)

    def test_demo_files_do_not_contain_secret_material(self):
        forbidden_fragments = (
            "client_secret",
            "api_key",
            "password",
            "private_key",
            "refresh_token",
            "access_token",
            "Bearer ",
            "sk-live-",
            "sk-test-",
            "ghp_",
            "AKIA",
        )
        for path in (PRODUCT_MODEL, OPENAPI):
            text = path.read_text(encoding="utf-8")
            for fragment in forbidden_fragments:
                self.assertNotIn(fragment, text)
            self.assertFalse(any(str(value).startswith("sk-") for value in _walk_json(_load_json(path))))

    def test_demo_readme_commands_are_accurate(self):
        doc = README.read_text(encoding="utf-8")
        self.assertIn("arceo import validate examples/saas_demo/product_model.json", doc)
        self.assertIn("arceo scope create --target imported:arceo-saas-demo --operator you --confirm", doc)
        self.assertIn(
            "arceo run --mode existing-imported --target examples/saas_demo/product_model.json --scope <scope>",
            doc,
        )
        self.assertIn(
            "arceo launch-review --before examples/saas_demo/product_model.json --after examples/saas_demo/product_model.json",
            doc,
        )
        self.assertIn("local/canary-only", doc)
        self.assertIn("no live probing", doc)

        rc, out = self._run_cli(["import", "validate", str(PRODUCT_MODEL)])
        self.assertEqual(rc, 0, out)
        self.assertIn("ProductModel validation: PASS", out)

        rc, out = self._run_cli(["launch-review", "--before", str(PRODUCT_MODEL), "--after", str(PRODUCT_MODEL)])
        self.assertEqual(rc, 0, out)
        self.assertIn("Launch gate: pass", out)


if __name__ == "__main__":
    unittest.main()
