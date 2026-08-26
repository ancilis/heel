import copy
import json
from pathlib import Path
import unittest


PRESENTATION_FIXTURE = (
    Path(__file__).parent / "fixtures/reviews/browser_answer_presentation_v1.json"
)


def _spec(operation=None, **overrides):
    spec = {
        "openapi": "3.1.0",
        "info": {"title": "Answer API", "version": "1"},
        "paths": {
            "/exports": {"get": operation or {"operationId": "exportUsers"}},
        },
    }
    spec.update(overrides)
    return spec


def _questions(spec):
    from heel.review_service import review_openapi

    return review_openapi(spec, execution_mode="browser_local")["questions"]


class ReviewAnswerTests(unittest.TestCase):
    def test_tenant_answer_enriches_a_deep_copy_only(self):
        from heel.review_answers import apply_review_answers

        spec = _spec()
        original = copy.deepcopy(spec)
        answers = [{
            "surface": "exportusers",
            "field": "tenant_filter",
            "value": "enforced",
        }]
        questions = _questions(spec)

        enriched = apply_review_answers(spec, answers, questions)

        self.assertEqual(
            enriched["paths"]["/exports"]["get"]["x-heel-tenant-scope"],
            "tenant",
        )
        self.assertEqual(spec, original)
        self.assertEqual(answers, [{
            "surface": "exportusers",
            "field": "tenant_filter",
            "value": "enforced",
        }])
        self.assertIsNot(enriched, spec)

    def test_entitlement_answer_preserves_every_existing_control(self):
        from heel.review_answers import apply_review_answers

        operation = {
            "operationId": "exportUsers",
            "x-heel-tenant-scope": "workspace",
            "x-heel-control": {
                "tenant_rate_limit": True,
                "custom_guard": True,
                "disabled_legacy": False,
            },
        }
        spec = _spec(
            operation,
            servers=[{"url": "https://api.example.invalid"}],
        )
        answers = [{
            "surface": "exportusers",
            "field": "entitlement_check",
            "value": "enforced",
        }]

        enriched = apply_review_answers(spec, answers, _questions(spec))
        controls = enriched["paths"]["/exports"]["get"]["x-heel-control"]

        self.assertEqual(controls, {
            "custom_guard": True,
            "disabled_legacy": False,
            "server_side_entitlement_check": True,
            "tenant_rate_limit": True,
        })
        self.assertEqual(enriched["servers"], spec["servers"])

    def test_entitlement_answer_adds_only_entitlement_control(self):
        from heel.review_answers import apply_review_answers
        from heel.review_service import review_openapi

        spec = _spec(operation={
            "operationId": "exportUsers",
            "x-heel-tenant-scope": "tenant",
        })
        before = review_openapi(spec, execution_mode="browser_local")
        answers = [{
            "surface": "exportusers",
            "field": "entitlement_check",
            "value": "enforced",
        }]

        enriched = apply_review_answers(spec, answers, before["questions"])
        controls = enriched["paths"]["/exports"]["get"]["x-heel-control"]
        after = review_openapi(enriched, execution_mode="browser_local")

        self.assertEqual(controls, ["server_side_entitlement_check"])
        self.assertEqual(
            {
                question["field"] for question in after["questions"]
                if question["surface"] == "exportusers"
            },
            {"rate_limit"},
        )
        risks = {
            finding["risk"] for finding in after["findings"]
            if finding["surface_id"] == "exportusers"
        }
        self.assertNotIn("export_without_entitlement", risks)
        self.assertIn("export_without_tenant_quota", risks)

    def test_rate_limit_answer_adds_only_rate_limit_control(self):
        from heel.review_answers import apply_review_answers
        from heel.review_service import review_openapi

        spec = _spec(operation={
            "operationId": "exportUsers",
            "x-heel-tenant-scope": "tenant",
        })
        before = review_openapi(spec, execution_mode="browser_local")

        enriched = apply_review_answers(spec, [{
            "surface": "exportusers",
            "field": "rate_limit",
            "value": "enforced",
        }], before["questions"])
        after = review_openapi(enriched, execution_mode="browser_local")

        self.assertEqual(
            enriched["paths"]["/exports"]["get"]["x-heel-control"],
            ["server_side_rate_limit"],
        )
        self.assertEqual(
            {
                question["field"] for question in after["questions"]
                if question["surface"] == "exportusers"
            },
            {"entitlement_check"},
        )
        risks = {
            finding["risk"] for finding in after["findings"]
            if finding["surface_id"] == "exportusers"
        }
        self.assertIn("export_without_entitlement", risks)
        self.assertNotIn("export_without_tenant_quota", risks)

    def test_export_questions_track_each_missing_control_exactly(self):
        from heel.review_service import review_openapi

        cases = {
            "both missing": (None, {"entitlement_check", "rate_limit"}),
            "entitlement only": (
                ["entitlement_check"], {"rate_limit"},
            ),
            "rate only": (["rate_limit"], {"entitlement_check"}),
            "both present": ([], set()),
        }
        for label, (controls, expected_fields) in cases.items():
            operation = {
                "operationId": "exportUsers",
                "x-heel-tenant-scope": "tenant",
            }
            if label == "both present":
                operation["x-heel-control"] = [
                    "entitlement_check", "rate_limit",
                ]
            elif controls is not None:
                operation["x-heel-control"] = controls

            with self.subTest(label=label):
                result = review_openapi(
                    _spec(operation=operation), execution_mode="browser_local"
                )
                self.assertEqual(
                    {
                        question["field"] for question in result["questions"]
                        if question["surface"] == "exportusers"
                    },
                    expected_fields,
                )

    def test_missing_sentinel_can_be_strengthened_but_real_declarations_are_unchanged(self):
        from heel.review_answers import apply_review_answers

        spec = _spec(operation={
            "operationId": "exportUsers",
            "x-heel-tenant-scope": "missing",
            "x-heel-control": ["custom_guard"],
        })
        answers = [
            {"surface": "exportusers", "field": "tenant_filter", "value": "enforced"},
            {"surface": "exportusers", "field": "entitlement_check", "value": "enforced"},
        ]

        enriched = apply_review_answers(spec, answers, _questions(spec))

        operation = enriched["paths"]["/exports"]["get"]
        self.assertEqual(operation["x-heel-tenant-scope"], "tenant")
        self.assertEqual(operation["x-heel-control"], [
            "custom_guard", "server_side_entitlement_check",
        ])

    def test_not_enforced_and_unknown_validate_without_mutating(self):
        from heel.review_answers import apply_review_answers

        spec = _spec()
        questions = _questions(spec)
        for field in ("tenant_filter", "entitlement_check", "rate_limit"):
            for value in ("not_enforced", "unknown"):
                with self.subTest(field=field, value=value):
                    enriched = apply_review_answers(spec, [{
                        "surface": "exportusers",
                        "field": field,
                        "value": value,
                    }], questions)
                    self.assertEqual(enriched, spec)
                    self.assertIsNot(enriched, spec)

    def test_answer_application_has_stable_ordering(self):
        from heel.review_answers import apply_review_answers

        spec = _spec()
        questions = _questions(spec)
        answers = [
            {"surface": "exportusers", "field": "rate_limit", "value": "enforced"},
            {"surface": "exportusers", "field": "tenant_filter", "value": "enforced"},
        ]

        self.assertEqual(
            apply_review_answers(spec, answers, questions),
            apply_review_answers(spec, list(reversed(answers)), questions),
        )

    def test_consistent_duplicates_are_detached_and_contradictions_are_rejected(self):
        from heel.review_answers import ReviewAnswerError, apply_review_answers

        spec = _spec()
        question = {
            "surface": "exportusers",
            "field": "tenant_filter",
            "value": "enforced",
        }
        enriched = apply_review_answers(
            spec, [question, dict(question)], _questions(spec)
        )
        self.assertEqual(
            enriched["paths"]["/exports"]["get"]["x-heel-tenant-scope"],
            "tenant",
        )

        contradictory = [
            question,
            {**question, "value": "not_enforced"},
        ]
        with self.assertRaises(ReviewAnswerError):
            apply_review_answers(spec, contradictory, _questions(spec))

    def test_unknown_question_surface_field_value_and_extra_fields_are_rejected(self):
        from heel.review_answers import ReviewAnswerError, apply_review_answers

        spec = _spec()
        questions = _questions(spec)
        invalid = {
            "unknown surface": {
                "surface": "other", "field": "tenant_filter", "value": "enforced",
            },
            "unknown field": {
                "surface": "exportusers", "field": "quota", "value": "enforced",
            },
            "unknown value": {
                "surface": "exportusers", "field": "tenant_filter", "value": "yes",
            },
            "non-string value": {
                "surface": "exportusers", "field": "tenant_filter", "value": True,
            },
            "extra field": {
                "surface": "exportusers", "field": "tenant_filter",
                "value": "enforced", "authorization": "live",
            },
        }
        for label, answer in invalid.items():
            with self.subTest(label=label):
                with self.assertRaises(ReviewAnswerError):
                    apply_review_answers(spec, [answer], questions)

    def test_product_broad_oauth_agent_and_ambiguous_product_rules_are_rejected(self):
        from heel.review_answers import ReviewAnswerError, apply_review_answers

        document_oauth = {
            "openapi": "3.1.0",
            "info": {"title": "OAuth", "version": "1"},
            "paths": {},
            "components": {"securitySchemes": {"OAuthAll": {
                "type": "oauth2",
                "flows": {"clientCredentials": {"scopes": {"all": "All"}}},
            }}},
        }
        product_answer = [{
            "surface": "product", "field": "product_rule", "value": "enforced",
        }]
        with self.assertRaises(ReviewAnswerError):
            apply_review_answers(document_oauth, product_answer, _questions(document_oauth))

        agent = {
            "openapi": "3.1.0",
            "info": {"title": "Agent", "version": "1"},
            "paths": {"/agent/tool": {"post": {
                "operationId": "runAgentTool",
                "x-heel-agent-tool": True,
                "x-heel-tenant-scope": "tenant",
                "x-heel-plan": "team",
            }}},
        }
        agent_answer = [{
            "surface": "runagenttool", "field": "product_rule", "value": "enforced",
        }]
        with self.assertRaises(ReviewAnswerError):
            apply_review_answers(agent, agent_answer, _questions(agent))

        ambiguous = _spec(operation={
            "operationId": "exportOAuthUsers",
            "x-heel-agent-tool": True,
            "security": [{"OAuthAll": ["all"]}],
        })
        ambiguous_answer = [{
            "surface": "exportoauthusers", "field": "product_rule", "value": "enforced",
        }]
        self.assertGreaterEqual(sum(
            question["surface"] == "exportoauthusers"
            and question["field"] == "product_rule"
            for question in _questions(ambiguous)
        ), 2)
        with self.assertRaises(ReviewAnswerError):
            apply_review_answers(ambiguous, ambiguous_answer, _questions(ambiguous))

    def test_generic_product_rule_never_adds_export_controls(self):
        from heel.review_answers import ReviewAnswerError, apply_review_answers

        spec = _spec(operation={
            "operationId": "exportOAuthUsers",
            "x-heel-tenant-scope": "tenant",
            "security": [{"OAuthAll": ["all"]}],
        })
        answer = [{
            "surface": "exportoauthusers",
            "field": "product_rule",
            "value": "enforced",
        }]

        with self.assertRaises(ReviewAnswerError):
            apply_review_answers(spec, answer, _questions(spec))
        self.assertNotIn("x-heel-control", spec["paths"]["/exports"]["get"])

    def test_browser_answer_presentation_vocabulary_is_exact_and_versioned(self):
        fixture = json.loads(PRESENTATION_FIXTURE.read_text(encoding="utf-8"))

        self.assertEqual(fixture, {
            "schema_version": "heel.review-presentation.v1",
            "assumption": (
                "not declared in this OpenAPI; not proof the control is absent"
            ),
            "answer_receipts": {
                "enforced": "applied",
                "not_enforced": "confirmed_gap",
                "unknown": "unanswered",
            },
            "confidence": {
                "unanswered_or_unknown": "preliminary",
                "not_enforced": "confirmed_gaps",
                "enforced_reduced_questions_without_confirmed_gap": "improved",
            },
        })

    def test_answers_cannot_create_paths_change_targets_or_introduce_refs(self):
        from heel.review_answers import ReviewAnswerError, apply_review_answers

        spec = _spec()
        original_paths = set(spec["paths"])
        answer = [{
            "surface": "missingoperation",
            "field": "tenant_filter",
            "value": "enforced",
        }]
        with self.assertRaises(ReviewAnswerError):
            apply_review_answers(spec, answer, _questions(spec))
        self.assertEqual(set(spec["paths"]), original_paths)
        self.assertNotIn("$ref", json.dumps(spec))

    def test_local_path_item_question_updates_only_the_existing_component_operation(self):
        from heel.review_answers import apply_review_answers

        spec = {
            "openapi": "3.1.0",
            "info": {"title": "Ref API", "version": "1"},
            "components": {"pathItems": {"Records": {
                "get": {"operationId": "listRecords"},
            }}},
            "paths": {"/records": {"$ref": "#/components/pathItems/Records"}},
        }
        answer = [{
            "surface": "listrecords", "field": "tenant_filter", "value": "enforced",
        }]

        enriched = apply_review_answers(spec, answer, _questions(spec))

        self.assertEqual(
            enriched["components"]["pathItems"]["Records"]["get"]["x-heel-tenant-scope"],
            "tenant",
        )
        self.assertEqual(
            enriched["paths"]["/records"],
            {"$ref": "#/components/pathItems/Records"},
        )

    def test_answer_json_is_bounded_duplicate_safe_and_must_be_an_array(self):
        from heel.review_answers import (
            MAX_REVIEW_ANSWER_COUNT,
            MAX_REVIEW_ANSWERS_BYTES,
            ReviewAnswerError,
            parse_review_answers,
        )

        malformed = (
            "{",
            "{}",
            'null',
            '[{"surface":"a","surface":"b","field":"tenant_filter",'
            '"value":"unknown"}]',
        )
        for source in malformed:
            with self.subTest(source=source[:20]):
                with self.assertRaises(ReviewAnswerError):
                    parse_review_answers(source)

        too_many = [
            {"surface": f"surface-{index}", "field": "tenant_filter", "value": "unknown"}
            for index in range(MAX_REVIEW_ANSWER_COUNT + 1)
        ]
        with self.assertRaises(ReviewAnswerError):
            parse_review_answers(json.dumps(too_many))

        oversized = json.dumps([{
            "surface": "x" * MAX_REVIEW_ANSWERS_BYTES,
            "field": "tenant_filter",
            "value": "unknown",
        }])
        with self.assertRaises(ReviewAnswerError):
            parse_review_answers(oversized)


if __name__ == "__main__":
    unittest.main()
