import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


FIXTURES = Path(__file__).parent / "fixtures" / "openapi"


class TestOpenAPIImport(unittest.TestCase):
    def test_json_openapi_import_creates_product_model(self):
        from heel.importers import validate_product_model
        from heel.openapi_import import import_openapi_file

        model = import_openapi_file(str(FIXTURES / "saas_api.json"))

        self.assertEqual(model["schema_version"], "ProductModel.v0.1")
        self.assertEqual(model["product_id"], "acme-platform-api")
        self.assertIn("openapi:", model["source"])
        self.assertEqual(model["environments"], ["staging"])
        self.assertTrue(model["safety_notes"])
        self.assertTrue(validate_product_model(model).ok)

    def test_export_and_oauth_paths_map_to_expected_surfaces(self):
        from heel.openapi_import import import_openapi_file

        model = import_openapi_file(str(FIXTURES / "saas_api.json"))

        self.assertTrue(any(e["route"] == "/api/export/bulk" for e in model["exports"]))
        self.assertTrue(any(app["route"] == "/oauth/apps" for app in model["integration_oauth_apps"]))
        self.assertTrue(any(c["id"] == "security_scheme:ApiKeyAuth" for c in model["declared_controls"]))
        self.assertTrue(any(area["id"] == "Exports" for area in model["product_areas"]))
        self.assertEqual(model["exports"][0]["product_area"], "Exports")

    def test_missing_metadata_creates_warnings(self):
        from heel.openapi_import import import_openapi_file

        model = import_openapi_file(str(FIXTURES / "saas_api.json"))
        warnings = "\n".join(model["import_warnings"])

        self.assertIn("missing tenant metadata", warnings)
        self.assertIn("missing entitlement metadata", warnings)
        self.assertIn("export route without declared rate or entitlement control", warnings)
        self.assertIn("broad OAuth scope", warnings)
        self.assertIn("agent-like endpoint lacks scope metadata", warnings)

    def test_x_heel_vendor_extensions_improve_mapping(self):
        from heel.openapi_import import import_openapi_file

        model = import_openapi_file(str(FIXTURES / "vendor_extensions.json"))
        export = next(e for e in model["exports"] if e["route"] == "/api/export/invoices")
        meter = model["meters"][0]
        tool = model["agent_tools"][0]

        self.assertEqual(export["required_plan"], "enterprise")
        self.assertEqual(export["tenant_scope"], "tenant")
        self.assertEqual(export["data_class"], "canary_invoices")
        self.assertEqual(export["entitlement_check"], "declared")
        self.assertEqual(export["rate_limit"], "declared")
        self.assertEqual(meter["id"], "invoice_exports")
        self.assertEqual(tool["tool"], "export_invoices")
        self.assertEqual(tool["intended_scope"], "tenant")

    def test_url_input_is_rejected_without_live_calls(self):
        from heel.openapi_import import OpenAPIImportError, import_openapi_file

        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("network called")) as urlopen:
            with self.assertRaises(OpenAPIImportError):
                import_openapi_file("https://example.invalid/openapi.json")
        urlopen.assert_not_called()

    def test_secret_looking_examples_are_rejected_without_echoing_secret(self):
        from heel.openapi_import import OpenAPIImportError, product_model_from_openapi

        secret = "sk-live-1234567890abcdef"
        spec = {
            "openapi": "3.1.0",
            "info": {"title": "Secret Demo", "version": "1"},
            "paths": {"/api/export": {"get": {"responses": {"200": {"example": {"api_key": secret}}}}}},
        }

        with self.assertRaises(OpenAPIImportError) as ctx:
            product_model_from_openapi(spec, source="unit-test")
        self.assertIn("secret", str(ctx.exception).lower())
        self.assertNotIn(secret, str(ctx.exception))

    def test_yaml_without_pyyaml_returns_clear_error(self):
        from heel.openapi_import import OpenAPIImportError, import_openapi_file

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "openapi.yaml"
            path.write_text("openapi: 3.1.0\ninfo:\n  title: YAML Demo\npaths: {}\n", encoding="utf-8")
            with mock.patch.dict(sys.modules, {"yaml": None}):
                with self.assertRaises(OpenAPIImportError) as ctx:
                    import_openapi_file(str(path))
        msg = str(ctx.exception)
        self.assertIn("PyYAML", msg)
        self.assertIn("JSON export", msg)


class TestOpenAPIImportCli(unittest.TestCase):
    def test_cli_init_from_openapi_writes_json(self):
        from heel import cli

        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "product_model.json"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli.main(["init", "--from-openapi", str(FIXTURES / "saas_api.json"), "--out", str(out)])

            self.assertEqual(rc, 0, buf.getvalue())
            model = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(model["product_id"], "acme-platform-api")
            self.assertIn("OpenAPI import: PASS", buf.getvalue())
            self.assertIn("warnings", buf.getvalue().lower())

    def test_cli_import_openapi_alias_writes_json(self):
        from heel import cli

        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "product_model.json"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli.main(["import", "openapi", str(FIXTURES / "vendor_extensions.json"), "--out", str(out)])

            self.assertEqual(rc, 0, buf.getvalue())
            model = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(model["product_id"], "extension-demo")
            self.assertTrue(model["agent_tools"])


if __name__ == "__main__":
    unittest.main()
