import hashlib
import inspect
import json
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
OPENAPI_FIXTURE = ROOT / "tests/fixtures/openapi/saas_api.json"
GOLDEN_FIXTURE = ROOT / "tests/fixtures/reviews/sample_review_v1.json"


def _sample_spec():
    return json.loads(OPENAPI_FIXTURE.read_text(encoding="utf-8"))


def _reverse_mappings(value):
    if isinstance(value, dict):
        return {
            key: _reverse_mappings(child)
            for key, child in reversed(list(value.items()))
        }
    if isinstance(value, list):
        return [_reverse_mappings(child) for child in value]
    return value


class ReviewServiceTests(unittest.TestCase):
    def test_valid_openapi_returns_useful_machine_local_review(self):
        from heel.review_service import review_openapi

        result = review_openapi(_sample_spec())

        self.assertEqual(result["schema_version"], "heel.review.v1")
        self.assertGreater(result["summary"]["findings"], 0)
        self.assertIn(result["gate_status"], {"warn", "block"})
        self.assertTrue(result["findings"][0]["reason"])
        self.assertTrue(result["findings"][0]["control"])
        risks = {finding["risk"] for finding in result["findings"]}
        self.assertGreaterEqual(risks, {
            "endpoint_without_tenant_filter",
            "export_without_entitlement",
            "oauth_scope_overbroad",
        })
        question_fields = {question["field"] for question in result["questions"]}
        self.assertGreaterEqual(question_fields, {
            "tenant_filter", "entitlement_check", "product_rule",
        })
        prompts = "\n".join(question["prompt"] for question in result["questions"])
        self.assertIn("GET /api/export/bulk", prompts)
        self.assertIn("broad OAuth scope declared by security scheme OAuthAll", prompts)
        self.assertEqual(result["execution_mode"], "machine_local")
        self.assertEqual(result["privacy"], {
            "execution": "machine_local",
            "network_calls": False,
            "uploaded": False,
            "sync_intent": "none",
        })

    def test_same_input_produces_identical_envelope(self):
        from heel.review_service import review_openapi

        spec = _sample_spec()
        self.assertEqual(review_openapi(spec), review_openapi(spec))

    def test_equivalent_mapping_order_produces_identical_envelope(self):
        from heel.review_service import review_openapi

        spec = _sample_spec()
        self.assertEqual(review_openapi(spec), review_openapi(_reverse_mappings(spec)))

    def test_mapping_control_order_produces_identical_result_hash(self):
        from heel.review_service import review_openapi

        def spec_with_controls(items):
            return {
                "openapi": "3.1.0",
                "info": {"title": "Control Order", "version": "1"},
                "paths": {"/records": {"get": {
                    "operationId": "listRecords",
                    "x-heel-control": dict(items),
                }}},
            }

        first = review_openapi(spec_with_controls([
            ("rate_limit", True),
            ("entitlement_check", True),
        ]))
        second = review_openapi(spec_with_controls([
            ("entitlement_check", True),
            ("rate_limit", True),
        ]))

        self.assertEqual(first["model_hash"], second["model_hash"])
        self.assertEqual(first["result_hash"], second["result_hash"])

    def test_declared_tenant_metadata_suppresses_question_and_finding(self):
        from heel.review_service import review_openapi

        result = review_openapi({
            "openapi": "3.1.0",
            "info": {"title": "Tenant Aware", "version": "1"},
            "paths": {"/records": {"get": {
                "operationId": "listRecords",
                "x-heel-tenant-scope": "tenant",
                "x-heel-plan": "team",
            }}},
        })

        self.assertFalse(any(
            question["field"] == "tenant_filter" for question in result["questions"]
        ))
        self.assertFalse(any(
            finding["risk"] == "endpoint_without_tenant_filter"
            for finding in result["findings"]
        ))

    def test_imported_all_scope_creates_oauth_overbreadth_finding(self):
        from heel.review_service import review_openapi

        result = review_openapi({
            "openapi": "3.1.0",
            "info": {"title": "OAuth Scope", "version": "1"},
            "paths": {"/oauth/apps": {"post": {
                "operationId": "createOAuthApp",
                "security": [{"OAuthAll": ["all"]}],
                "x-heel-tenant-scope": "tenant",
                "x-heel-plan": "team",
            }}},
        })

        finding = next(
            item for item in result["findings"]
            if item["risk"] == "oauth_scope_overbroad"
        )
        self.assertEqual(finding["surface_type"], "integration_oauth_apps")
        self.assertEqual(finding["control"], "OAuth scope minimization and approval")

    def test_local_path_item_ref_contributes_review_findings(self):
        from heel.review_service import review_openapi

        result = review_openapi({
            "openapi": "3.1.0",
            "info": {"title": "Referenced Paths", "version": "1"},
            "components": {"pathItems": {"Records": {
                "get": {"operationId": "listRecords"},
            }}},
            "paths": {"/records": {"$ref": "#/components/pathItems/Records"}},
        })

        self.assertTrue(any(
            finding["surface_id"] == "listrecords"
            and finding["risk"] == "endpoint_without_tenant_filter"
            for finding in result["findings"]
        ))

    def test_browser_local_preserves_substantive_review_with_truthful_identity(self):
        from heel.review_service import review_openapi

        machine = review_openapi(_sample_spec())
        browser = review_openapi(_sample_spec(), execution_mode="browser_local")

        for field in (
            "product_id", "source_hash", "model_hash", "baseline_hash",
            "gate_status", "summary", "findings", "recommended_controls",
            "suggested_regressions", "questions", "safety",
        ):
            self.assertEqual(machine[field], browser[field], field)
        self.assertNotEqual(machine["review_id"], browser["review_id"])
        self.assertNotEqual(machine["result_hash"], browser["result_hash"])
        self.assertEqual(browser["execution_mode"], "browser_local")
        self.assertEqual(browser["privacy"], {
            "execution": "browser_local",
            "network_calls": False,
            "uploaded": False,
            "sync_intent": "none",
        })

    def test_missing_metadata_becomes_exact_route_questions(self):
        from heel.review_contract import stable_json_hash
        from heel.review_service import review_openapi

        result = review_openapi({
            "openapi": "3.1.0",
            "info": {"title": "Question App", "version": "1"},
            "paths": {"/exports": {"get": {"operationId": "exportUsers"}}},
        })

        by_field = {question["field"]: question for question in result["questions"]}
        tenant_warning = "missing tenant metadata for /exports"
        entitlement_warning = "missing entitlement metadata for /exports"
        self.assertEqual(by_field["tenant_filter"], {
            "id": "tenant_filter:" + stable_json_hash([
                "missing_tenant_metadata", "tenant_filter", "GET", "/exports",
                "exportusers", tenant_warning,
            ])[:12],
            "field": "tenant_filter",
            "surface": "/exports",
            "prompt": "How is tenant access enforced for GET /exports (operation exportusers)?",
            "required": False,
        })
        self.assertEqual(by_field["entitlement_check"], {
            "id": "entitlement_check:" + stable_json_hash([
                "missing_entitlement_metadata", "entitlement_check", "GET", "/exports",
                "exportusers", entitlement_warning,
            ])[:12],
            "field": "entitlement_check",
            "surface": "/exports",
            "prompt": "Which plan or entitlement protects GET /exports (operation exportusers)?",
            "required": False,
        })
        for question in result["questions"]:
            self.assertEqual(
                set(question), {"id", "field", "surface", "prompt", "required"}
            )

    def test_other_import_warnings_become_product_rule_questions(self):
        from heel.review_service import review_openapi

        result = review_openapi(_sample_spec())

        broad_scope = next(
            question for question in result["questions"]
            if question["prompt"] == "broad OAuth scope declared by security scheme OAuthAll"
        )
        self.assertEqual(broad_scope["field"], "product_rule")
        self.assertEqual(broad_scope["surface"], "product")
        self.assertFalse(broad_scope["required"])
        self.assertRegex(broad_scope["id"], r"^product_rule:[0-9a-f]{12}$")

    def test_document_warning_question_uses_product_context_semantics(self):
        from heel.review_contract import stable_json_hash
        from heel.review_service import review_openapi

        message = "broad OAuth scope declared by security scheme OAuthAll"
        result = review_openapi({
            "openapi": "3.1.0",
            "info": {"title": "OAuth Document", "version": "1"},
            "paths": {},
            "components": {"securitySchemes": {"OAuthAll": {
                "type": "oauth2",
                "flows": {"clientCredentials": {
                    "scopes": {"all": "Broad access"},
                }},
            }}},
        })

        self.assertEqual(result["questions"], [{
            "id": "product_rule:" + stable_json_hash([
                "broad_oauth_scope", "product_rule", "product", "product",
                "product", message,
            ])[:12],
            "field": "product_rule",
            "surface": "product",
            "prompt": message,
            "required": False,
        }])

    def test_same_route_methods_produce_distinct_semantic_questions(self):
        from heel.review_service import review_openapi

        result = review_openapi({
            "openapi": "3.1.0",
            "info": {"title": "Method Context", "version": "1"},
            "paths": {"/records": {
                "get": {"operationId": "listRecords"},
                "post": {"operationId": "createRecords"},
            }},
        })

        self.assertEqual(result["summary"]["questions"], 4)
        self.assertEqual(len({question["id"] for question in result["questions"]}), 4)
        prompts = "\n".join(question["prompt"] for question in result["questions"])
        for expected in ("GET /records", "POST /records", "listrecords", "createrecords"):
            self.assertIn(expected, prompts)

    def test_empty_harmless_api_passes(self):
        from heel.review_service import review_openapi

        result = review_openapi({
            "openapi": "3.1.0",
            "info": {"title": "Harmless API", "version": "1"},
            "paths": {},
        })

        self.assertEqual(result["gate_status"], "pass")
        self.assertEqual(result["summary"], {
            "findings": 0,
            "blockers": 0,
            "questions": 0,
        })
        self.assertEqual(result["findings"], [])

    def test_hash_fields_are_actual_canonical_sha256_digests(self):
        from heel.openapi_import import product_model_from_openapi
        from heel.review_contract import stable_json
        from heel.review_service import empty_product_model, review_openapi

        spec = _sample_spec()
        model = product_model_from_openapi(spec, source="openapi:inline-local")
        baseline = empty_product_model(model["product_id"])
        result = review_openapi(spec)

        expected = {
            "source_hash": hashlib.sha256(stable_json(spec).encode("utf-8")).hexdigest(),
            "model_hash": hashlib.sha256(stable_json(model).encode("utf-8")).hexdigest(),
            "baseline_hash": hashlib.sha256(stable_json(baseline).encode("utf-8")).hexdigest(),
        }
        for field, digest in expected.items():
            self.assertEqual(result[field], digest)
            self.assertRegex(result[field], r"^[0-9a-f]{64}$")

    def test_empty_baseline_is_valid_and_canonical(self):
        from heel.importers import LIST_FIELDS, validate_product_model
        from heel.review_service import empty_product_model

        baseline = empty_product_model("sample-product")

        self.assertTrue(validate_product_model(baseline).ok)
        self.assertEqual(baseline["schema_version"], "ProductModel.v0.1")
        self.assertEqual(baseline["product_id"], "sample-product")
        self.assertEqual(baseline["source"], "heel:empty-baseline")
        self.assertEqual(baseline["generated_at"], "1970-01-01T00:00:00Z")
        self.assertEqual(baseline["environments"], ["synthetic"])
        for field in LIST_FIELDS:
            self.assertIn(field, baseline)
            self.assertIsInstance(baseline[field], list)
        for field in set(LIST_FIELDS) - {"safety_notes"}:
            self.assertEqual(baseline[field], [])

    def test_secret_examples_fail_without_echoing_secret(self):
        from heel.openapi_import import OpenAPIImportError
        from heel.review_service import review_openapi

        secret = "sk-live-1234567890abcdef"
        with self.assertRaises(OpenAPIImportError) as caught:
            review_openapi({
                "openapi": "3.1.0",
                "info": {"title": "Bad", "version": "1"},
                "paths": {},
                "components": {"examples": {"bad": {"value": secret}}},
            })
        self.assertIn("secret", str(caught.exception).lower())
        self.assertNotIn(secret, str(caught.exception))

    def test_review_does_not_use_io_network_registration_scope_or_orchestrator(self):
        import heel.orchestrator
        import heel.targets
        from heel.review_service import review_openapi

        spec = _sample_spec()
        forbidden = [
            mock.patch("builtins.open", side_effect=AssertionError("filesystem called")),
            mock.patch("socket.create_connection", side_effect=AssertionError("network called")),
            mock.patch("urllib.request.urlopen", side_effect=AssertionError("network called")),
            mock.patch("subprocess.run", side_effect=AssertionError("subprocess called")),
            mock.patch.object(heel.targets, "register_imported_target", side_effect=AssertionError("registration called")),
            mock.patch.object(heel.orchestrator, "run_abuse", side_effect=AssertionError("orchestrator called")),
        ]
        with forbidden[0], forbidden[1], forbidden[2], forbidden[3], forbidden[4], forbidden[5]:
            result = review_openapi(spec)

        self.assertEqual(result["schema_version"], "heel.review.v1")
        self.assertFalse(result["privacy"]["network_calls"])

    def test_public_signature_accepts_requested_execution_mode(self):
        from heel.review_service import review_openapi

        signature = inspect.signature(review_openapi)
        self.assertEqual(list(signature.parameters), ["spec", "execution_mode"])
        self.assertEqual(signature.parameters["execution_mode"].kind,
                         inspect.Parameter.KEYWORD_ONLY)
        self.assertEqual(signature.parameters["execution_mode"].default, "machine_local")
        self.assertEqual(review_openapi.__annotations__["spec"], "dict")
        self.assertEqual(review_openapi.__annotations__["execution_mode"], "str")
        self.assertEqual(review_openapi.__annotations__["return"], "dict")

    def test_sample_review_matches_deterministic_golden_fixture(self):
        from heel.review_service import review_openapi

        expected = json.loads(GOLDEN_FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(review_openapi(_sample_spec()), expected)


class LaunchReviewProducerRegressionTests(unittest.TestCase):
    @staticmethod
    def _baseline():
        from heel.importers import LIST_FIELDS, PRODUCT_MODEL_VERSION

        baseline = {field: [] for field in LIST_FIELDS}
        baseline.update({
            "schema_version": PRODUCT_MODEL_VERSION,
            "product_id": "producer-review",
            "source": "test:baseline",
            "generated_at": "1970-01-01T00:00:00Z",
            "environments": ["synthetic"],
            "safety_notes": ["Synthetic test baseline; no live probing."],
        })
        return baseline

    def test_admin_action_reachable_is_always_a_bool(self):
        from heel.launch_review import review_product_models

        baseline = self._baseline()
        model = json.loads(json.dumps(baseline))
        model["source"] = "test:after"
        model["support_admin_actions"] = [{
            "id": "support_impersonate",
            "required_role": "admin",
            "audit_logged": False,
        }]

        finding = review_product_models(baseline, model).new_abuse_affordances[0]

        self.assertIs(type(finding.reachable), bool)
        self.assertFalse(finding.reachable)
        self.assertIs(type(finding.to_dict()["reachable"]), bool)

    def test_all_risk_producers_satisfy_strict_review_v1_records(self):
        from heel.launch_review import review_product_models
        from heel.review_contract import build_review_envelope

        baseline = self._baseline()
        model = json.loads(json.dumps(baseline))
        model["source"] = "test:after"
        model["endpoints_routes"] = [{"id": "tenant_route", "tenant_filter": "missing"}]
        model["exports"] = [{"id": "bulk_export", "entitlement_check": "missing"}]
        model["meters"] = [{"id": "api_meter", "billable": True}]
        model["coupons_promotions"] = [{"id": "launch_coupon", "stackable": True}]
        model["integration_oauth_apps"] = [{"id": "oauth_app", "scope": "all"}]
        model["support_admin_actions"] = [{
            "id": "support_action", "required_role": "admin", "audit_logged": False,
        }]
        model["agent_tools"] = [{
            "id": "agent_tool", "granted_scope": "all_tenants",
            "intended_scope": "own_tenant",
        }]
        model["features_flags"] = [{"id": "paid_flag", "gated_by": "client"}]
        model["data_classes"] = [{"id": "pii", "sensitive": True}]
        model["declared_controls"] = [{"id": "legacy_guard", "status": "disabled"}]

        review = review_product_models(baseline, model).to_dict()
        envelope = build_review_envelope(
            review,
            source_hash="a" * 64,
            model_hash="b" * 64,
            baseline_hash="c" * 64,
            execution_mode="machine_local",
            questions=[],
        )

        self.assertEqual(envelope["summary"]["findings"], 11)
        self.assertTrue(all(type(item["reachable"]) is bool for item in envelope["findings"]))
        self.assertTrue(envelope["suggested_regressions"])
        self.assertEqual(envelope["safety"], {
            "mode": "static ProductModel diff",
            "live_probing": False,
            "network_calls": False,
            "requires_signed_scope_for_live_or_staging_runs": True,
            "canary_only": True,
        })

    def test_duplicate_modeled_surface_ids_are_rejected_on_both_sides(self):
        from heel.importers import ProductModelError
        from heel.launch_review import review_product_models

        for duplicate_side in ("before", "after"):
            before = self._baseline()
            after = json.loads(json.dumps(before))
            target = before if duplicate_side == "before" else after
            target["endpoints_routes"] = [
                {"id": "duplicate", "tenant_filter": "missing"},
                {"id": "duplicate", "tenant_filter": "declared"},
            ]
            with self.subTest(duplicate_side=duplicate_side):
                with self.assertRaisesRegex(ProductModelError, "duplicate modeled surface id"):
                    review_product_models(before, after)

    def test_duplicate_surface_cannot_overwrite_a_blocking_finding(self):
        from heel.importers import ProductModelError
        from heel.launch_review import review_product_models

        baseline = self._baseline()
        model = json.loads(json.dumps(baseline))
        model["exports"] = [
            {
                "id": "bulk_export",
                "entitlement_check": "missing",
                "rate_limit": "missing",
                "reachable_by_plan": "trial",
            },
            {
                "id": "bulk_export",
                "entitlement_check": "declared",
                "rate_limit": "declared",
            },
        ]

        with self.assertRaisesRegex(ProductModelError, "duplicate modeled surface id"):
            review_product_models(baseline, model)


if __name__ == "__main__":
    unittest.main()
