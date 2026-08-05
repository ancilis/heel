import ast
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
OPENAPI_FIXTURE = ROOT / "tests/fixtures/openapi/saas_api.json"


def _sample_source():
    return OPENAPI_FIXTURE.read_text(encoding="utf-8")


def _minimal_spec(**overrides):
    spec = {
        "openapi": "3.1.0",
        "info": {"title": "Browser API", "version": "1"},
        "paths": {},
    }
    spec.update(overrides)
    return spec


class BrowserReviewTests(unittest.TestCase):
    def assert_browser_error(self, source, code, answers_json="[]"):
        from heel.browser_review import BrowserReviewError, review_openapi_json

        with self.assertRaises(BrowserReviewError) as caught:
            review_openapi_json(source, answers_json)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), caught.exception.public_message)
        self.assertNotIn("Traceback", str(caught.exception))
        return caught.exception

    def test_valid_sample_returns_useful_strict_browser_local_envelope(self):
        from heel.browser_review import review_openapi_json
        from heel.review_contract import validate_review_envelope

        envelope = json.loads(review_openapi_json(_sample_source()))

        self.assertEqual(envelope["schema_version"], "heel.review.v1")
        self.assertEqual(envelope["execution_mode"], "browser_local")
        self.assertGreater(envelope["summary"]["findings"], 0)
        self.assertTrue(envelope["findings"][0]["reason"])
        self.assertEqual(envelope["privacy"], {
            "execution": "browser_local",
            "network_calls": False,
            "uploaded": False,
            "sync_intent": "none",
        })
        self.assertEqual(validate_review_envelope(envelope), envelope)

    def test_adapter_exactly_matches_native_browser_review(self):
        from heel.browser_review import review_openapi_json
        from heel.review_contract import stable_json
        from heel.review_service import review_openapi

        spec = json.loads(_sample_source())

        self.assertEqual(
            review_openapi_json(json.dumps(spec)),
            stable_json(review_openapi(spec, execution_mode="browser_local")),
        )

    def test_output_is_canonical_deterministic_and_silent(self):
        from heel.browser_review import review_openapi_json
        from heel.review_contract import stable_json

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            first = review_openapi_json(_sample_source())
            second = review_openapi_json(_sample_source())

        self.assertEqual(first, second)
        self.assertEqual(first, stable_json(json.loads(first)))
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

    def test_duplicate_source_and_answer_keys_fail_closed(self):
        source = (
            '{"openapi":"3.1.0","openapi":"3.0.3",'
            '"info":{"title":"Duplicate","version":"1"},"paths":{}}'
        )
        self.assert_browser_error(source, "invalid_json")

        valid = json.dumps(_minimal_spec())
        duplicate_answers = (
            '[{"surface":"first","surface":"second",'
            '"field":"tenant_filter","value":"enforced"}]'
        )
        self.assert_browser_error(valid, "invalid_answers", duplicate_answers)

    def test_non_object_root_and_malformed_json_fail_closed(self):
        self.assert_browser_error("[]", "invalid_document")
        self.assert_browser_error("{", "invalid_json")

    def test_lone_surrogates_and_invalid_unicode_fail_closed(self):
        escaped = (
            '{"openapi":"3.1.0","info":{"title":"\\ud800",'
            '"version":"1"},"paths":{}}'
        )
        self.assert_browser_error(escaped, "invalid_unicode")
        self.assert_browser_error("\ud800", "invalid_unicode")

    def test_source_byte_depth_and_node_limits_fail_before_review(self):
        from heel.browser_review import MAX_BROWSER_INPUT_BYTES, MAX_JSON_NODES

        self.assert_browser_error(
            " " * (MAX_BROWSER_INPUT_BYTES + 1), "input_too_large"
        )
        too_deep = '{"openapi":"3.1.0","info":{"title":"Deep","version":"1"},"paths":{},"x":' + "[" * 65 + "0" + "]" * 65 + "}"
        self.assert_browser_error(too_deep, "input_too_complex")
        too_many_nodes = _minimal_spec(x_nodes=[0] * MAX_JSON_NODES)
        self.assertLess(len(json.dumps(too_many_nodes).encode("utf-8")), MAX_BROWSER_INPUT_BYTES)
        self.assert_browser_error(json.dumps(too_many_nodes), "input_too_complex")

    def test_malformed_openapi_remote_ref_and_secret_example_have_stable_codes(self):
        malformed = _minimal_spec(openapi="2.0")
        self.assert_browser_error(json.dumps(malformed), "invalid_openapi")

        remote = _minimal_spec(paths={
            "/remote": {"$ref": "https://private.example.invalid/openapi.json"},
        })
        error = self.assert_browser_error(json.dumps(remote), "unsafe_document")
        self.assertNotIn("private.example.invalid", str(error))

        secret = "sk-live-1234567890abcdef"
        secret_spec = _minimal_spec(
            components={"examples": {"private": {"value": secret}}},
            paths={"/private/customer/export": {"get": {
                "operationId": "privateCustomerExport",
            }}},
        )
        error = self.assert_browser_error(json.dumps(secret_spec), "unsafe_document")
        self.assertNotIn(secret, str(error))
        self.assertNotIn("/private/customer/export", str(error))

    def test_remote_refs_are_rejected_anywhere_in_the_document(self):
        remote_schema = _minimal_spec(
            components={"schemas": {"Record": {
                "$ref": "https://private.example.invalid/record.json",
            }}},
        )

        error = self.assert_browser_error(
            json.dumps(remote_schema), "unsafe_document"
        )

        self.assertNotIn("private.example.invalid", str(error))

    def test_enforced_answers_rerun_and_remove_matching_risks_and_questions(self):
        from heel.browser_review import review_openapi_json

        spec = _minimal_spec(paths={
            "/exports": {"get": {"operationId": "exportUsers"}},
        })
        source = json.dumps(spec)
        before = json.loads(review_openapi_json(source))
        answers = [
            {"surface": "exportusers", "field": "tenant_filter", "value": "enforced"},
            {"surface": "exportusers", "field": "entitlement_check", "value": "enforced"},
            {"surface": "exportusers", "field": "product_rule", "value": "enforced"},
        ]

        after = json.loads(review_openapi_json(source, json.dumps(answers)))

        self.assertGreater(before["summary"]["findings"], after["summary"]["findings"])
        self.assertGreater(before["summary"]["questions"], after["summary"]["questions"])
        self.assertFalse(any(
            question["surface"] == "exportusers"
            for question in after["questions"]
        ))
        removed_risks = {
            "endpoint_without_tenant_filter",
            "export_without_entitlement",
            "export_without_tenant_quota",
        }
        self.assertFalse(removed_risks & {
            finding["risk"] for finding in after["findings"]
            if finding["surface_id"] == "exportusers"
        })

    def test_not_enforced_and_unknown_are_exact_envelope_noops(self):
        from heel.browser_review import review_openapi_json

        source = json.dumps(_minimal_spec(paths={
            "/records": {"get": {"operationId": "listRecords"}},
        }))
        before = review_openapi_json(source)

        for value in ("not_enforced", "unknown"):
            with self.subTest(value=value):
                answers = json.dumps([{
                    "surface": "listrecords",
                    "field": "tenant_filter",
                    "value": value,
                }])
                self.assertEqual(review_openapi_json(source, answers), before)

    def test_answer_errors_are_redacted_by_adapter(self):
        source = json.dumps(_minimal_spec(paths={
            "/private-path": {"get": {"operationId": "privateOperation"}},
        }))
        answers = json.dumps([{
            "surface": "private-secret-surface",
            "field": "tenant_filter",
            "value": "enforced",
        }])

        error = self.assert_browser_error(source, "invalid_answers", answers)

        self.assertNotIn("private-secret-surface", str(error))
        self.assertNotIn("/private-path", str(error))

    def test_browser_runtime_calls_no_io_network_or_subprocess_capability(self):
        import socket
        import subprocess
        import urllib.request
        from heel.browser_review import review_openapi_json

        with mock.patch("builtins.open", side_effect=AssertionError("filesystem called")), \
                mock.patch.object(socket, "create_connection", side_effect=AssertionError("network called")), \
                mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("network called")), \
                mock.patch.object(subprocess, "run", side_effect=AssertionError("subprocess called")):
            payload = review_openapi_json(json.dumps(_minimal_spec()))

        self.assertEqual(json.loads(payload)["execution_mode"], "browser_local")

    def test_browser_dependency_closure_contains_only_pure_modules(self):
        root_module = "heel.browser_review"
        pending = [root_module]
        closure = set()
        imported_roots = set()

        while pending:
            module = pending.pop()
            if module in closure:
                continue
            closure.add(module)
            path = ROOT / (module.replace(".", "/") + ".py")
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            package = module.rsplit(".", 1)[0]
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imported_roots.add(alias.name.split(".", 1)[0])
                        if alias.name.startswith("heel."):
                            pending.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.level == 1 and node.module:
                        dependency = package + "." + node.module
                        pending.append(dependency)
                    elif node.level == 0 and node.module:
                        imported_roots.add(node.module.split(".", 1)[0])
                        if node.module.startswith("heel."):
                            pending.append(node.module)

        self.assertEqual(closure, {
            "heel.browser_review",
            "heel.openapi_model",
            "heel.product_model",
            "heel.review_answers",
            "heel.review_contract",
            "heel.review_rules",
            "heel.review_service",
            "heel.static_review",
        })
        self.assertFalse({
            "os", "pathlib", "subprocess", "socket", "urllib",
        } & imported_roots)
        forbidden_local = (
            ".local_projects", ".store", ".mcp", ".rest", ".runner", ".saas",
        )
        self.assertFalse(any(
            marker in module for module in closure for marker in forbidden_local
        ))

    def test_compatibility_modules_reexport_the_pure_kernel(self):
        from heel import importers, launch_review, openapi_import
        from heel import openapi_model, product_model, static_review

        self.assertIs(importers.validate_product_model, product_model.validate_product_model)
        self.assertIs(importers.product_model_from_dict, product_model.product_model_from_dict)
        self.assertIs(openapi_import.OpenAPIImportError, openapi_model.OpenAPIImportError)
        self.assertIs(openapi_import.product_model_from_openapi,
                      openapi_model.product_model_from_openapi)
        self.assertIs(openapi_import.validate_product_model,
                      product_model.validate_product_model)
        self.assertIs(openapi_import.is_broad_scope, openapi_model.is_broad_scope)
        self.assertEqual(openapi_import.LIST_FIELDS, product_model.LIST_FIELDS)
        self.assertEqual(openapi_import.PRODUCT_MODEL_VERSION,
                         product_model.PRODUCT_MODEL_VERSION)
        self.assertIs(launch_review.LaunchReview, static_review.LaunchReview)
        self.assertIs(launch_review.review_product_models,
                      static_review.review_product_models)
        self.assertIs(launch_review.is_broad_scope, static_review.is_broad_scope)


if __name__ == "__main__":
    unittest.main()
