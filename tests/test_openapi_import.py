import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


FIXTURES = Path(__file__).parent / "fixtures" / "openapi"


def minimal_spec(**overrides):
    spec = {
        "openapi": "3.1.0",
        "info": {"title": "Minimal API", "version": "1"},
        "paths": {},
    }
    spec.update(overrides)
    return spec


class TestOpenAPIImport(unittest.TestCase):
    def test_paths_keys_must_be_routes_or_lowercase_extensions(self):
        from heel.openapi_import import OpenAPIImportError, product_model_from_openapi

        for bad_key in ("records", "X-vendor", 7):
            with self.subTest(bad_key=bad_key):
                with self.assertRaises(OpenAPIImportError):
                    product_model_from_openapi(minimal_spec(paths={bad_key: {}}))

        model = product_model_from_openapi(minimal_spec(paths={
            "x-vendor-documentation": ["ignored", "extension", "value"],
        }))
        self.assertEqual(model["endpoints_routes"], [])

    def test_malformed_operations_are_rejected_directly_and_through_local_refs(self):
        from heel.openapi_import import OpenAPIImportError, product_model_from_openapi

        malformed_path_items = {
            "get is not object": {"get": []},
            "post is not object": {"post": "invalid"},
            "operation id empty": {"get": {"operationId": ""}},
            "operation id blank": {"get": {"operationId": "  "}},
            "operation id non-string": {"get": {"operationId": 7}},
            "tags not list": {"get": {"tags": "Exports"}},
            "tag empty": {"get": {"tags": [""]}},
            "tag blank": {"get": {"tags": [" "]}},
            "tag non-string": {"get": {"tags": [7]}},
        }

        for label, path_item in malformed_path_items.items():
            for location in ("direct", "local ref"):
                if location == "direct":
                    spec = minimal_spec(paths={"/bad": path_item})
                else:
                    spec = minimal_spec(
                        components={"pathItems": {"Bad": path_item}},
                        paths={"/bad": {"$ref": "#/components/pathItems/Bad"}},
                    )
                with self.subTest(label=label, location=location):
                    with self.assertRaises(OpenAPIImportError):
                        product_model_from_openapi(spec)

    def test_openapi_root_structure_fails_closed(self):
        from heel.openapi_import import OpenAPIImportError, product_model_from_openapi

        valid = minimal_spec()
        invalid = {
            "empty document": {},
            "missing openapi": {key: value for key, value in valid.items() if key != "openapi"},
            "non-string openapi": minimal_spec(openapi=3.1),
            "unsupported openapi": minimal_spec(openapi="2.0"),
            "future openapi": minimal_spec(openapi="3.2.0"),
            "missing info": {key: value for key, value in valid.items() if key != "info"},
            "non-object info": minimal_spec(info=[]),
            "missing title": minimal_spec(info={"version": "1"}),
            "blank title": minimal_spec(info={"title": " ", "version": "1"}),
            "non-string title": minimal_spec(info={"title": 1, "version": "1"}),
            "missing version": minimal_spec(info={"title": "API"}),
            "blank version": minimal_spec(info={"title": "API", "version": " "}),
            "non-string version": minimal_spec(info={"title": "API", "version": 1}),
            "missing paths": {key: value for key, value in valid.items() if key != "paths"},
            "non-object paths": minimal_spec(paths=[]),
        }

        for label, spec in invalid.items():
            with self.subTest(label=label):
                with self.assertRaises(OpenAPIImportError):
                    product_model_from_openapi(spec)

    def test_openapi_30_document_is_accepted(self):
        from heel.openapi_import import product_model_from_openapi

        model = product_model_from_openapi(minimal_spec(openapi="3.0.3"))

        self.assertEqual(model["product_id"], "minimal-api")

    def test_local_path_item_ref_unescapes_pointer_and_merges_siblings(self):
        from heel.openapi_import import product_model_from_openapi

        spec = minimal_spec(
            components={
                "pathItems": {
                    "Exports/~daily": {
                        "get": {"operationId": "referencedExport"},
                    },
                },
            },
            paths={
                "/aliased": {
                    "$ref": "#/components/pathItems/Exports~1~0daily",
                    "post": {"operationId": "siblingOperation"},
                },
            },
        )

        model = product_model_from_openapi(spec)

        self.assertEqual(
            {(entry["method"], entry["operation_id"]) for entry in model["endpoints_routes"]},
            {("GET", "referencedexport"), ("POST", "siblingoperation")},
        )
        self.assertTrue(any(item["id"] == "referencedexport" for item in model["exports"]))

    def test_remote_path_item_ref_is_rejected_without_network(self):
        from heel.openapi_import import OpenAPIImportError, product_model_from_openapi

        spec = minimal_spec(paths={
            "/remote": {"$ref": "https://example.invalid/path-item.json"},
        })
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("network called")) as urlopen:
            with mock.patch("socket.create_connection", side_effect=AssertionError("network called")) as connect:
                with self.assertRaises(OpenAPIImportError):
                    product_model_from_openapi(spec)

        urlopen.assert_not_called()
        connect.assert_not_called()

    def test_invalid_local_path_item_refs_are_rejected(self):
        from heel.openapi_import import OpenAPIImportError, product_model_from_openapi

        cases = {
            "non-object path item": minimal_spec(paths={"/wrong": []}),
            "non-string ref": minimal_spec(paths={"/wrong": {"$ref": 7}}),
            "missing": minimal_spec(paths={
                "/missing": {"$ref": "#/components/pathItems/Missing"},
            }),
            "wrong type": minimal_spec(
                components={"pathItems": {"Wrong": []}},
                paths={"/wrong": {"$ref": "#/components/pathItems/Wrong"}},
            ),
            "invalid pointer escape": minimal_spec(
                components={"pathItems": {"Bad~2Name": {}}},
                paths={"/bad": {"$ref": "#/components/pathItems/Bad~2Name"}},
            ),
            "cyclic": minimal_spec(
                components={"pathItems": {
                    "A": {"$ref": "#/components/pathItems/B"},
                    "B": {"$ref": "#/components/pathItems/A"},
                }},
                paths={"/cycle": {"$ref": "#/components/pathItems/A"}},
            ),
        }

        for label, spec in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(OpenAPIImportError):
                    product_model_from_openapi(spec)

    def test_duplicate_operation_ids_are_rejected_after_normalization(self):
        from heel.openapi_import import OpenAPIImportError, product_model_from_openapi

        cases = {
            "exact duplicate": ("sharedOperation", "sharedOperation"),
            "normalized collision": ("Export Users", "export-users"),
        }
        for label, operation_ids in cases.items():
            spec = minimal_spec(paths={
                "/first": {"get": {"operationId": operation_ids[0]}},
                "/second": {"post": {"operationId": operation_ids[1]}},
            })
            with self.subTest(label=label):
                with self.assertRaisesRegex(OpenAPIImportError, "duplicate operation id"):
                    product_model_from_openapi(spec)

    def test_mapping_controls_are_sorted_independently_of_insertion_order(self):
        from heel.openapi_import import product_model_from_openapi

        def spec_with_controls(items):
            return minimal_spec(paths={
                "/records": {"get": {
                    "operationId": "listRecords",
                    "x-heel-control": dict(items),
                }},
            })

        forward = spec_with_controls([
            ("rate_limit", True),
            ("entitlement_check", True),
        ])
        reversed_controls = spec_with_controls([
            ("entitlement_check", True),
            ("rate_limit", True),
        ])

        first = product_model_from_openapi(forward)
        second = product_model_from_openapi(reversed_controls)

        self.assertEqual(first, second)
        self.assertEqual(first["endpoints_routes"][0]["controls"],
                         ["entitlement_check", "rate_limit"])

    def test_tenant_scope_emits_canonical_declared_tenant_filter(self):
        from heel.openapi_import import product_model_from_openapi

        model = product_model_from_openapi(minimal_spec(paths={
            "/records": {"get": {
                "operationId": "listRecords",
                "x-heel-tenant-scope": "tenant",
            }},
        }))

        endpoint = model["endpoints_routes"][0]
        self.assertEqual(endpoint["tenant_scope"], "tenant")
        self.assertEqual(endpoint["tenant_filter"], "declared")

    def test_missing_extension_sentinels_remain_missing(self):
        from heel.openapi_import import product_model_from_openapi

        sentinels = (
            "missing", "none", "false", "disabled", "off", "no", "weak",
            "client", "client_only", "", "   ", " MISSING ",
        )
        for sentinel in sentinels:
            with self.subTest(sentinel=repr(sentinel)):
                model = product_model_from_openapi(minimal_spec(paths={
                    "/records": {"get": {
                        "operationId": "listRecords",
                        "x-heel-tenant-scope": sentinel,
                        "x-heel-plan": sentinel,
                        "x-heel-data-class": sentinel,
                    }},
                }))

                endpoint = model["endpoints_routes"][0]
                for field in (
                    "tenant_scope", "tenant_filter", "required_plan", "data_class",
                ):
                    self.assertNotIn(field, endpoint)
                self.assertEqual(model["data_classes"], [])
                self.assertEqual(
                    {hint["field"] for hint in model["import_question_hints"]},
                    {"tenant_filter", "entitlement_check"},
                )

    def test_control_identifiers_use_exact_aliases_after_normalization(self):
        from heel.openapi_import import product_model_from_openapi

        entitlement_aliases = (
            "entitlement", "entitlement_check", "server_side_entitlement_check",
        )
        rate_aliases = (
            "rate", "rate_limit", "tenant_rate_limit", "server_side_rate_limit",
        )
        for alias in entitlement_aliases:
            with self.subTest(kind="entitlement", alias=alias):
                model = product_model_from_openapi(minimal_spec(paths={
                    "/records": {"get": {
                        "operationId": "listRecords",
                        "x-heel-control": alias,
                    }},
                }))
                endpoint = model["endpoints_routes"][0]
                self.assertEqual(endpoint["controls"], [alias])
                self.assertEqual(endpoint["entitlement_check"], "declared")
                self.assertNotIn("rate_limit", endpoint)

        for alias in rate_aliases:
            with self.subTest(kind="rate", alias=alias):
                model = product_model_from_openapi(minimal_spec(paths={
                    "/records": {"get": {
                        "operationId": "listRecords",
                        "x-heel-control": alias,
                    }},
                }))
                endpoint = model["endpoints_routes"][0]
                self.assertEqual(endpoint["controls"], [alias])
                self.assertEqual(endpoint["rate_limit"], "declared")
                self.assertNotIn("entitlement_check", endpoint)

        normalized = product_model_from_openapi(minimal_spec(paths={
            "/records": {"get": {
                "operationId": "listRecords",
                "x-heel-control": [
                    " Server-Side Entitlement Check ", "Tenant Rate-Limit",
                ],
            }},
        }))["endpoints_routes"][0]
        self.assertEqual(normalized["controls"], [
            "server_side_entitlement_check", "tenant_rate_limit",
        ])
        self.assertEqual(normalized["entitlement_check"], "declared")
        self.assertEqual(normalized["rate_limit"], "declared")

    def test_control_sentinels_and_misleading_names_do_not_count(self):
        from heel.openapi_import import product_model_from_openapi

        model = product_model_from_openapi(minimal_spec(paths={
            "/exports": {"get": {
                "operationId": "exportRecords",
                "x-heel-tenant-scope": "tenant",
                "x-heel-control": [
                    "missing", "none", "false", "disabled", "off", "no",
                    "weak", "client", "client_only", "",
                    "missing_entitlement_check", "rate_limit_missing",
                ],
            }},
        }))

        endpoint = model["endpoints_routes"][0]
        self.assertEqual(
            endpoint["controls"],
            ["missing_entitlement_check", "rate_limit_missing"],
        )
        self.assertNotIn("entitlement_check", endpoint)
        self.assertNotIn("rate_limit", endpoint)
        export = model["exports"][0]
        self.assertEqual(export["entitlement_check"], "unknown")
        self.assertEqual(export["rate_limit"], "unknown")

    def test_invalid_heel_extension_types_are_rejected(self):
        from heel.openapi_import import OpenAPIImportError, product_model_from_openapi

        invalid = {
            "tenant null": ("x-heel-tenant-scope", None),
            "tenant bool": ("x-heel-tenant-scope", True),
            "plan list": ("x-heel-plan", ["team"]),
            "data class map": ("x-heel-data-class", {"name": "private"}),
            "control integer": ("x-heel-control", 7),
            "control bool": ("x-heel-control", True),
            "control list member": ("x-heel-control", ["rate_limit", 7]),
            "control map key": ("x-heel-control", {7: True}),
            "control map value": ("x-heel-control", {"rate_limit": "true"}),
        }
        for label, (extension, value) in invalid.items():
            with self.subTest(label=label):
                with self.assertRaises(OpenAPIImportError):
                    product_model_from_openapi(minimal_spec(paths={
                        "/records": {"get": {
                            "operationId": "listRecords",
                            extension: value,
                        }},
                    }))

    def test_structured_question_hints_cover_every_warning_form(self):
        from heel.openapi_import import import_openapi_file

        model = import_openapi_file(str(FIXTURES / "saas_api.json"))
        hints = model["import_question_hints"]

        self.assertEqual({hint["code"] for hint in hints}, {
            "agent_scope_metadata_missing",
            "broad_oauth_scope",
            "export_missing_rate_limit",
            "missing_entitlement_metadata",
            "missing_tenant_metadata",
        })
        self.assertEqual(
            {
                code: sum(hint["code"] == code for hint in hints)
                for code in {hint["code"] for hint in hints}
            },
            {
                "agent_scope_metadata_missing": 1,
                "broad_oauth_scope": 2,
                "export_missing_rate_limit": 1,
                "missing_entitlement_metadata": 7,
                "missing_tenant_metadata": 7,
            },
        )
        self.assertEqual(
            {hint["message"] for hint in hints}, set(model["import_warnings"])
        )
        self.assertEqual(
            {
                hint["code"]: hint["field"]
                for hint in hints
            },
            {
                "agent_scope_metadata_missing": "product_rule",
                "broad_oauth_scope": "product_rule",
                "export_missing_rate_limit": "rate_limit",
                "missing_entitlement_metadata": "entitlement_check",
                "missing_tenant_metadata": "tenant_filter",
            },
        )
        for hint in hints:
            self.assertEqual(set(hint), {
                "code", "field", "method", "route", "operation_id", "message",
            })
            self.assertIn(hint["message"], model["import_warnings"])

        export_hint = next(
            hint for hint in hints if hint["code"] == "export_missing_rate_limit"
        )
        self.assertEqual(export_hint, {
            "code": "export_missing_rate_limit",
            "field": "rate_limit",
            "method": "GET",
            "route": "/api/export/bulk",
            "operation_id": "downloadbulkexport",
            "message": "missing rate-limit metadata for /api/export/bulk",
        })
        document_hint = next(
            hint for hint in hints
            if hint["message"] == "broad OAuth scope declared by security scheme OAuthAll"
        )
        self.assertEqual(document_hint, {
            "code": "broad_oauth_scope",
            "field": "product_rule",
            "method": "product",
            "route": "product",
            "operation_id": "product",
            "message": "broad OAuth scope declared by security scheme OAuthAll",
        })

    def test_same_route_methods_keep_distinct_question_hints(self):
        from heel.openapi_import import product_model_from_openapi

        model = product_model_from_openapi(minimal_spec(paths={
            "/records": {
                "get": {"operationId": "listRecords"},
                "post": {"operationId": "createRecords"},
            },
        }))

        self.assertEqual(len(model["import_warnings"]), 2)
        self.assertEqual(len(model["import_question_hints"]), 4)
        self.assertEqual(
            {(hint["method"], hint["operation_id"]) for hint in model["import_question_hints"]},
            {("GET", "listrecords"), ("POST", "createrecords")},
        )

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
        self.assertIn("missing rate-limit metadata", warnings)
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
