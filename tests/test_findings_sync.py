from __future__ import annotations

import copy
import hashlib
import hmac
import importlib
import json
import math
from pathlib import Path
import unittest
from unittest import mock

from heel.review_contract import build_review_envelope, stable_json, stable_json_hash


PROJECT_REF = "prj_0123456789abcdef0123456789abcdef"
NAMESPACE_KEY = bytes(range(32))
OTHER_NAMESPACE_KEY = bytes(reversed(range(32)))
FIXTURES = Path(__file__).resolve().parent / "fixtures/findings_sync"
NEVER_CROSS = "heel-private-customer-value-do-not-sync"

RISK_CATALOG = {
    "export_without_entitlement": (
        "server-side entitlement check",
        "server_side_entitlement_check",
        ("endpoints_routes", "exports"),
    ),
    "export_without_tenant_quota": (
        "tenant quota",
        "tenant_quota",
        ("endpoints_routes", "exports"),
    ),
    "endpoint_without_tenant_filter": (
        "tenant filter",
        "tenant_filter",
        ("endpoints_routes",),
    ),
    "ui_backing_endpoint_paid_api_bypass": (
        "shared UI/API entitlement and lookup quota",
        "shared_ui_api_entitlement_and_lookup_quota",
        ("endpoints_routes",),
    ),
    "unmetered_billable_resource": (
        "server-side meter accounting and cost ceiling",
        "server_side_meter_accounting_and_cost_ceiling",
        ("meters", "billing_objects"),
    ),
    "stackable_coupon_without_redemption_limit": (
        "redemption limit and proof of uniqueness",
        "redemption_limit_and_proof_of_uniqueness",
        ("coupons_promotions",),
    ),
    "oauth_scope_overbroad": (
        "OAuth scope minimization and approval",
        "oauth_scope_minimization_and_approval",
        ("integration_oauth_apps",),
    ),
    "admin_action_without_role_or_audit_control": (
        "admin role gate and audit event",
        "admin_role_gate_and_audit_event",
        ("support_admin_actions",),
    ),
    "agent_surface_overscope": (
        "tool scope minimization",
        "tool_scope_minimization",
        ("agent_tools", "mcp_connectors"),
    ),
    "feature_flag_plan_mismatch": (
        "server-side feature entitlement check",
        "server_side_feature_entitlement_check",
        ("features_flags",),
    ),
    "tenant_or_data_control_change": (
        "tenant/data control review",
        "tenant_data_control_review",
        ("data_classes", "declared_controls"),
    ),
}
RISK_STATES = {
    "export_without_entitlement": (("warn", False), ("block", True)),
    "export_without_tenant_quota": (("warn", False), ("block", True)),
    "endpoint_without_tenant_filter": (("warn", False), ("block", True)),
    "ui_backing_endpoint_paid_api_bypass": (("warn", False), ("block", True)),
    "unmetered_billable_resource": (("warn", False), ("warn", True)),
    "stackable_coupon_without_redemption_limit": (
        ("warn", False), ("warn", True), ("block", True),
    ),
    "oauth_scope_overbroad": (("warn", False), ("warn", True), ("block", True)),
    "admin_action_without_role_or_audit_control": (
        ("warn", False), ("warn", True), ("block", True),
    ),
    "agent_surface_overscope": (("block", True),),
    "feature_flag_plan_mismatch": (("warn", False), ("warn", True)),
    "tenant_or_data_control_change": (("warn", False),),
}


def _sync():
    try:
        return importlib.import_module("heel.findings_sync")
    except ModuleNotFoundError:
        raise AssertionError("heel.findings_sync must be implemented") from None


def _safety() -> dict[str, object]:
    return {
        "mode": "static ProductModel diff",
        "live_probing": False,
        "network_calls": False,
        "requires_signed_scope_for_live_or_staging_runs": True,
        "canary_only": True,
    }


def _finding(
    *,
    surface_type: str = "exports",
    surface_id: str = NEVER_CROSS,
    risk: str = "export_without_entitlement",
    severity: str = "block",
    control: str = "server-side entitlement check",
    reason: str = NEVER_CROSS,
    reachable: bool = True,
) -> dict[str, object]:
    return {
        "surface_type": surface_type,
        "surface_id": surface_id,
        "risk": risk,
        "severity": severity,
        "control": control,
        "reason": reason,
        "reachable": reachable,
    }


def _review(
    findings: list[dict[str, object]] | None = None,
    *,
    execution_mode: str = "machine_local",
) -> dict[str, object]:
    records = findings if findings is not None else [_finding()]
    blockers = sum(record["severity"] == "block" for record in records)
    gate = "block" if blockers else "warn" if records else "pass"
    review = {
        "product_id": NEVER_CROSS,
        "launch_gate_status": gate,
        "changed_surfaces": [],
        "new_abuse_affordances": records,
        "high_risk_missing_controls": [
            record for record in records if record["severity"] == "block"
        ],
        "recommended_controls": [dict(record) for record in records],
        "suggested_regression_tests": [],
        "safety": _safety(),
    }
    return build_review_envelope(
        review,
        source_hash="a" * 64,
        model_hash="b" * 64,
        baseline_hash="c" * 64,
        execution_mode=execution_mode,
        questions=[{
            "id": "question:1",
            "field": "tenant_filter",
            "surface": NEVER_CROSS,
            "prompt": NEVER_CROSS,
            "required": False,
        }],
    )


def _tagged_hmac(tag: str, values: list[str], key: bytes = NAMESPACE_KEY) -> str:
    material = stable_json(["heel.findings-sync.v1", tag, *values]).encode("utf-8")
    return hmac.new(key, material, hashlib.sha256).hexdigest()


def _rehash_review(review: dict[str, object]) -> None:
    body = {
        key: value for key, value in review.items()
        if key not in {"review_id", "result_hash"}
    }
    review["result_hash"] = stable_json_hash(body)
    review["review_id"] = "review_" + str(review["result_hash"])[:20]


def _rehash_projection(request: dict[str, object]) -> None:
    request["projection_hash"] = stable_json_hash({
        "schema_version": request["schema_version"],
        "gate_status": request["gate_status"],
        "summary": request["summary"],
        "findings": request["findings"],
    })


def _valid_receipt(request: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "heel.findings-sync-receipt.v1",
        "receipt_id": "fsr_" + "1" * 32,
        "project_ref": PROJECT_REF,
        "request_digest": stable_json_hash(request),
        "projection_hash": request["projection_hash"],
        "synced_review_id": "synrev_" + "2" * 32,
        "disposition": "created",
        "metered": True,
        "accepted_at": "2026-08-04T12:34:56.789Z",
    }


class FindingsSyncProjectionTests(unittest.TestCase):
    def test_projects_the_exact_privacy_minimized_contract(self):
        sync = _sync()
        review = _review()
        request = sync.project_findings_sync(review, PROJECT_REF, NAMESPACE_KEY)
        expected_surface = "surf1_" + _tagged_hmac(
            "surface", ["exports", NEVER_CROSS]
        )
        expected_finding = "find1_" + _tagged_hmac(
            "finding", [expected_surface, "export_without_entitlement"]
        )
        expected_source = "src1_" + _tagged_hmac(
            "source", [str(review["result_hash"])]
        )

        self.assertEqual(set(request), {
            "schema_version", "project_ref", "source", "gate_status",
            "summary", "findings", "projection_hash",
        })
        self.assertEqual(request["schema_version"], "heel.findings-sync.v1")
        self.assertEqual(request["project_ref"], PROJECT_REF)
        self.assertEqual(request["source"], {
            "engine_version": review["engine_version"],
            "execution_mode": "machine_local",
            "result_ref": expected_source,
        })
        self.assertEqual(request["summary"], {"findings": 1, "blockers": 1})
        self.assertEqual(request["gate_status"], "block")
        self.assertEqual(request["findings"], [{
            "finding_id": expected_finding,
            "surface_ref": expected_surface,
            "surface_type": "exports",
            "risk_code": "export_without_entitlement",
            "control_code": "server_side_entitlement_check",
            "severity": "block",
            "reachable": True,
        }])
        expected_projection = stable_json_hash({
            "schema_version": "heel.findings-sync.v1",
            "gate_status": "block",
            "summary": {"findings": 1, "blockers": 1},
            "findings": request["findings"],
        })
        self.assertEqual(request["projection_hash"], expected_projection)

        serialized = stable_json(request)
        self.assertNotIn(NEVER_CROSS, serialized)
        for forbidden in (
            "product_id", "source_hash", "model_hash", "baseline_hash",
            "surface_id", "reason", "questions", "recommended_controls",
            "suggested_regressions", "raw_openapi", "prompt",
        ):
            self.assertNotIn(f'"{forbidden}"', serialized)

    def test_browser_and_machine_provenance_differ_but_substance_converges(self):
        sync = _sync()
        browser = sync.project_findings_sync(
            _review(execution_mode="browser_local"), PROJECT_REF, NAMESPACE_KEY
        )
        machine = sync.project_findings_sync(
            _review(execution_mode="machine_local"), PROJECT_REF, NAMESPACE_KEY
        )

        self.assertNotEqual(browser["source"]["result_ref"], machine["source"]["result_ref"])
        self.assertEqual(browser["projection_hash"], machine["projection_hash"])
        self.assertEqual(browser["findings"], machine["findings"])
        self.assertEqual(
            sync.findings_sync_request_digest(browser, NAMESPACE_KEY),
            stable_json_hash(browser),
        )
        self.assertNotEqual(
            sync.findings_sync_request_digest(browser, NAMESPACE_KEY),
            sync.findings_sync_request_digest(machine, NAMESPACE_KEY),
        )

    def test_different_project_key_changes_every_pseudonym(self):
        sync = _sync()
        review = _review()
        one = sync.project_findings_sync(review, PROJECT_REF, NAMESPACE_KEY)
        two = sync.project_findings_sync(review, PROJECT_REF, OTHER_NAMESPACE_KEY)
        self.assertNotEqual(one["source"]["result_ref"], two["source"]["result_ref"])
        self.assertNotEqual(one["findings"][0]["surface_ref"], two["findings"][0]["surface_ref"])
        self.assertNotEqual(one["findings"][0]["finding_id"], two["findings"][0]["finding_id"])
        self.assertNotEqual(one["projection_hash"], two["projection_hash"])

    def test_pass_projection_is_empty_and_canonical(self):
        sync = _sync()
        request = sync.project_findings_sync(_review([]), PROJECT_REF, NAMESPACE_KEY)
        self.assertEqual(request["gate_status"], "pass")
        self.assertEqual(request["summary"], {"findings": 0, "blockers": 0})
        self.assertEqual(request["findings"], [])
        self.assertEqual(
            request["projection_hash"],
            stable_json_hash({
                "schema_version": "heel.findings-sync.v1",
                "gate_status": "pass",
                "summary": {"findings": 0, "blockers": 0},
                "findings": [],
            }),
        )

    def test_closed_catalog_projects_all_current_engine_pairs(self):
        sync = _sync()
        for risk, (raw_control, control_code, surfaces) in RISK_CATALOG.items():
            for surface_type in surfaces:
                for severity, reachable in RISK_STATES[risk]:
                    with self.subTest(
                        risk=risk,
                        surface_type=surface_type,
                        severity=severity,
                        reachable=reachable,
                    ):
                        request = sync.project_findings_sync(_review([_finding(
                            surface_type=surface_type,
                            surface_id=f"private-{risk}",
                            risk=risk,
                            severity=severity,
                            control=raw_control,
                            reachable=reachable,
                        )]), PROJECT_REF, NAMESPACE_KEY)
                        item = request["findings"][0]
                        self.assertEqual(item["risk_code"], risk)
                        self.assertEqual(item["control_code"], control_code)
                        self.assertEqual(item["surface_type"], surface_type)

    def test_closed_catalog_rejects_a_bad_surface_and_state_for_every_risk(self):
        sync = _sync()
        for risk, (raw_control, _control_code, _surfaces) in RISK_CATALOG.items():
            for finding in (
                _finding(
                    surface_type="plans",
                    surface_id=f"bad-surface-{risk}",
                    risk=risk,
                    severity=RISK_STATES[risk][0][0],
                    control=raw_control,
                    reachable=RISK_STATES[risk][0][1],
                ),
                _finding(
                    surface_type=RISK_CATALOG[risk][2][0],
                    surface_id=f"bad-state-{risk}",
                    risk=risk,
                    severity="block",
                    control=raw_control,
                    reachable=False,
                ),
            ):
                with self.subTest(risk=risk, finding=finding):
                    with self.assertRaises(ValueError):
                        sync.project_findings_sync(
                            _review([finding]), PROJECT_REF, NAMESPACE_KEY
                        )

    def test_projection_rejects_bad_catalog_and_severity_surface_combinations(self):
        sync = _sync()
        invalid = [
            _finding(risk="not_a_catalog_risk"),
            _finding(control="customer supplied free form control"),
            _finding(control="🔒"),
            _finding(surface_type="meters"),
            _finding(severity="block", reachable=False),
            _finding(
                surface_type="agent_tools", risk="agent_surface_overscope",
                control="tool scope minimization", severity="warn", reachable=True,
            ),
            _finding(
                surface_type="data_classes", risk="tenant_or_data_control_change",
                control="tenant/data control review", severity="warn", reachable=True,
            ),
        ]
        for finding in invalid:
            with self.subTest(finding=finding):
                with self.assertRaises(ValueError) as caught:
                    sync.project_findings_sync(
                        _review([finding]), PROJECT_REF, NAMESPACE_KEY
                    )
                self.assertNotIn("customer supplied free form control", str(caught.exception))

    def test_findings_are_unique_and_sorted_by_finding_id(self):
        sync = _sync()
        findings = [
            _finding(surface_id="private-z"),
            _finding(surface_id="private-a"),
        ]
        request = sync.project_findings_sync(_review(findings), PROJECT_REF, NAMESPACE_KEY)
        ids = [item["finding_id"] for item in request["findings"]]
        self.assertEqual(ids, sorted(ids))

        with self.assertRaisesRegex(ValueError, "duplicate"):
            sync.project_findings_sync(
                _review([_finding(), _finding()]), PROJECT_REF, NAMESPACE_KEY
            )

    def test_projection_validates_the_complete_review_before_disclosure(self):
        sync = _sync()
        variants: list[dict[str, object]] = []
        tampered_hash = _review()
        tampered_hash["result_hash"] = "0" * 64
        variants.append(tampered_hash)

        bad_summary = _review()
        bad_summary["summary"] = {"findings": 9, "blockers": 1, "questions": 1}
        _rehash_review(bad_summary)
        variants.append(bad_summary)

        bad_engine = _review()
        bad_engine["engine_version"] = "9.9.9"
        _rehash_review(bad_engine)
        variants.append(bad_engine)

        bad_mode = _review()
        bad_mode["execution_mode"] = "remote_untrusted"
        bad_mode["privacy"]["execution"] = "remote_untrusted"
        _rehash_review(bad_mode)
        variants.append(bad_mode)

        bad_privacy = _review()
        bad_privacy["privacy"]["network_calls"] = True
        _rehash_review(bad_privacy)
        variants.append(bad_privacy)

        bad_safety = _review()
        bad_safety["safety"]["live_probing"] = True
        _rehash_review(bad_safety)
        variants.append(bad_safety)

        for variant in variants:
            with self.subTest(engine=variant.get("engine_version"), mode=variant.get("execution_mode")):
                with self.assertRaises(ValueError):
                    sync.project_findings_sync(variant, PROJECT_REF, NAMESPACE_KEY)

    def test_project_and_namespace_inputs_are_exact_and_bounded(self):
        sync = _sync()
        for project_ref in (
            "project_0123456789abcdef0123456789abcdef",
            "prj_0123",
            "prj_0123456789ABCDEF0123456789ABCDEF",
            1,
        ):
            with self.subTest(project_ref=project_ref):
                with self.assertRaises(ValueError):
                    sync.project_findings_sync(_review(), project_ref, NAMESPACE_KEY)
        for key in (b"x" * 31, b"x" * 33, bytearray(b"x" * 32), "x" * 32):
            with self.subTest(key_type=type(key).__name__, key_length=len(key)):
                with self.assertRaises(ValueError):
                    sync.project_findings_sync(_review(), PROJECT_REF, key)


class FindingsSyncRequestValidationTests(unittest.TestCase):
    def setUp(self):
        sync = _sync()
        self.sync = sync
        self.request = sync.project_findings_sync(_review(), PROJECT_REF, NAMESPACE_KEY)

    def test_validates_and_detaches_exact_request(self):
        validated = self.sync.validate_findings_sync_request(
            self.request, NAMESPACE_KEY
        )
        self.assertEqual(validated, self.request)
        self.assertIsNot(validated, self.request)
        self.assertIsNot(validated["source"], self.request["source"])
        self.assertIsNot(validated["findings"], self.request["findings"])
        parsed = self.sync.parse_findings_sync_request(
            stable_json(self.request), NAMESPACE_KEY
        )
        self.assertEqual(parsed, self.request)

    def test_request_has_exact_recursive_fields(self):
        variants = []
        for path, key in (
            ((), "raw_openapi"),
            (("source",), "result_hash"),
            (("summary",), "questions"),
            (("findings", 0), "reason"),
        ):
            value = copy.deepcopy(self.request)
            target: object = value
            for component in path:
                target = target[component]
            target[key] = NEVER_CROSS
            variants.append(value)
        missing = copy.deepcopy(self.request)
        del missing["source"]["result_ref"]
        variants.append(missing)

        for variant in variants:
            with self.subTest(keys=sorted(variant)):
                with self.assertRaises(ValueError) as caught:
                    self.sync.validate_findings_sync_request(variant, NAMESPACE_KEY)
                self.assertNotIn(NEVER_CROSS, str(caught.exception))

    def test_rejects_tampered_ids_hashes_counts_gate_and_order(self):
        variants = []
        for mutate in (
            lambda value: value["findings"][0].__setitem__("finding_id", "find1_" + "0" * 64),
            lambda value: value["findings"][0].__setitem__("surface_ref", "surf1_" + "0" * 64),
            lambda value: value.__setitem__("projection_hash", "0" * 64),
            lambda value: value["summary"].__setitem__("findings", 2),
            lambda value: value.__setitem__("gate_status", "pass"),
        ):
            value = copy.deepcopy(self.request)
            mutate(value)
            variants.append(value)

        second = self.sync.project_findings_sync(
            _review([_finding(surface_id="private-a"), _finding(surface_id="private-b")]),
            PROJECT_REF,
            NAMESPACE_KEY,
        )
        second["findings"].reverse()
        _rehash_projection(second)
        variants.append(second)

        for variant in variants:
            with self.subTest(variant=stable_json(variant)[:120]):
                with self.assertRaises(ValueError):
                    self.sync.validate_findings_sync_request(variant, NAMESPACE_KEY)

    def test_rejects_non_ascii_catalog_codes_with_contract_errors(self):
        value = copy.deepcopy(self.request)
        value["findings"][0]["control_code"] = "🔒"
        with self.assertRaises(ValueError):
            self.sync.validate_findings_sync_request(value, NAMESPACE_KEY)

    def test_rejects_duplicate_finding_identities(self):
        duplicate = copy.deepcopy(self.request)
        duplicate["findings"].append(copy.deepcopy(duplicate["findings"][0]))
        duplicate["summary"] = {"findings": 2, "blockers": 2}
        _rehash_projection(duplicate)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.sync.validate_findings_sync_request(duplicate, NAMESPACE_KEY)

    def test_accepts_only_frozen_source_versions_and_modes(self):
        for version in ("1.1.0", "1.1.1", "1.2.0"):
            value = copy.deepcopy(self.request)
            value["source"]["engine_version"] = version
            with self.subTest(version=version):
                self.assertEqual(
                    self.sync.validate_findings_sync_request(value, NAMESPACE_KEY),
                    value,
                )
        for version in ("1.0.0", "1.2.1", True):
            value = copy.deepcopy(self.request)
            value["source"]["engine_version"] = version
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    self.sync.validate_findings_sync_request(value, NAMESPACE_KEY)
        for mode in ("browser_local", "machine_local", "cloud_isolated"):
            value = copy.deepcopy(self.request)
            value["source"]["execution_mode"] = mode
            with self.subTest(mode=mode):
                self.assertEqual(
                    self.sync.validate_findings_sync_request(value, NAMESPACE_KEY),
                    value,
                )

    def test_rejects_bool_float_unsafe_integer_and_nonfinite_counts(self):
        for invalid in (True, 1.0, 2**53, math.nan, math.inf):
            value = copy.deepcopy(self.request)
            value["summary"]["findings"] = invalid
            with self.subTest(invalid=repr(invalid)):
                with self.assertRaises(ValueError):
                    self.sync.validate_findings_sync_request(value, NAMESPACE_KEY)

    def test_raw_parser_rejects_recursive_duplicates_constants_and_depth(self):
        duplicate = (
            '{"schema_version":"heel.findings-sync.v1","source":'
            '{"result_ref":"src1_' + '0' * 64 + '","result_ref":"src1_'
            + '1' * 64 + '"}}'
        )
        too_deep = '{"x":' * 17 + "null" + "}" * 17
        for source in (duplicate, '{"value":NaN}', '{"value":Infinity}', too_deep):
            with self.subTest(source=source[:40]):
                with self.assertRaises(ValueError):
                    self.sync.parse_findings_sync_request(source, NAMESPACE_KEY)

    def test_raw_and_canonical_requests_are_bounded(self):
        oversized = '{"padding":"' + "x" * (256 * 1024) + '"}'
        with self.assertRaises(ValueError):
            self.sync.parse_findings_sync_request(oversized, NAMESPACE_KEY)

        too_many = copy.deepcopy(self.request)
        too_many["findings"] = [copy.deepcopy(self.request["findings"][0]) for _ in range(513)]
        too_many["summary"] = {"findings": 513, "blockers": 513}
        _rehash_projection(too_many)
        with self.assertRaises(ValueError):
            self.sync.validate_findings_sync_request(too_many, NAMESPACE_KEY)

    def test_decoded_request_is_preflighted_before_canonical_serialization(self):
        enormous = copy.deepcopy(self.request)
        enormous["raw_openapi"] = {"paths": [None] * 20_001}
        with mock.patch.object(
            self.sync,
            "stable_json",
            side_effect=AssertionError("untrusted graph was serialized"),
        ):
            with self.assertRaisesRegex(ValueError, "complexity"):
                self.sync.validate_findings_sync_request(enormous, NAMESPACE_KEY)

    def test_raw_parser_rejects_massive_text(self):
        massive = "x" * (16 * 256 * 1024)
        with self.assertRaises(ValueError):
            self.sync.parse_findings_sync_request(massive, NAMESPACE_KEY)

    def test_errors_never_echo_customer_values(self):
        value = copy.deepcopy(self.request)
        value["raw_openapi"] = NEVER_CROSS
        with self.assertRaises(ValueError) as caught:
            self.sync.validate_findings_sync_request(value, NAMESPACE_KEY)
        self.assertNotIn(NEVER_CROSS, str(caught.exception))


class FindingsSyncReceiptTests(unittest.TestCase):
    def setUp(self):
        self.sync = _sync()
        request = self.sync.project_findings_sync(_review(), PROJECT_REF, NAMESPACE_KEY)
        self.receipt = _valid_receipt(request)

    def test_validates_parses_and_detaches_exact_receipt(self):
        validated = self.sync.validate_findings_sync_receipt(self.receipt)
        self.assertEqual(validated, self.receipt)
        self.assertIsNot(validated, self.receipt)
        self.assertEqual(
            self.sync.parse_findings_sync_receipt(stable_json(self.receipt)),
            self.receipt,
        )

    def test_receipt_fields_identifiers_disposition_meter_and_time_are_strict(self):
        variants = []
        extra = copy.deepcopy(self.receipt)
        extra["source_result_hash"] = NEVER_CROSS
        variants.append(extra)
        for field, invalid in (
            ("schema_version", "heel.findings-sync-receipt.v2"),
            ("receipt_id", "receipt_" + "1" * 32),
            ("project_ref", "project_" + "1" * 32),
            ("request_digest", "A" * 64),
            ("projection_hash", "0" * 63),
            ("synced_review_id", "synced_review_" + "2" * 32),
            ("disposition", "updated"),
            ("disposition", []),
            ("metered", 1),
            ("accepted_at", "2026-08-04T12:34:56Z"),
            ("accepted_at", "2026-02-30T12:34:56.789Z"),
        ):
            value = copy.deepcopy(self.receipt)
            value[field] = invalid
            variants.append(value)

        mismatch = copy.deepcopy(self.receipt)
        mismatch["disposition"] = "reused"
        variants.append(mismatch)

        for variant in variants:
            with self.subTest(variant=variant):
                with self.assertRaises(ValueError) as caught:
                    self.sync.validate_findings_sync_receipt(variant)
                self.assertNotIn(NEVER_CROSS, str(caught.exception))

        reused = copy.deepcopy(self.receipt)
        reused["disposition"] = "reused"
        reused["metered"] = False
        self.assertEqual(self.sync.validate_findings_sync_receipt(reused), reused)

    def test_receipt_parser_rejects_duplicates_constants_depth_and_oversize(self):
        duplicate = (
            '{"schema_version":"heel.findings-sync-receipt.v1",'
            '"receipt_id":"fsr_' + '1' * 32 + '","receipt_id":"fsr_'
            + '2' * 32 + '"}'
        )
        too_deep = '{"x":' * 17 + "null" + "}" * 17
        oversized = '{"padding":"' + "x" * (8 * 1024) + '"}'
        for source in (duplicate, '{"value":NaN}', too_deep, oversized):
            with self.subTest(source=source[:40]):
                with self.assertRaises(ValueError):
                    self.sync.parse_findings_sync_receipt(source)

    def test_decoded_receipt_is_preflighted_before_canonical_serialization(self):
        enormous = copy.deepcopy(self.receipt)
        enormous["raw_review"] = [None] * 513
        with mock.patch.object(
            self.sync,
            "stable_json",
            side_effect=AssertionError("untrusted receipt was serialized"),
        ):
            with self.assertRaisesRegex(ValueError, "complexity"):
                self.sync.validate_findings_sync_receipt(enormous)


class FindingsSyncFixtureTests(unittest.TestCase):
    def test_python_goldens_exist_as_exact_canonical_lines(self):
        sync = _sync()
        expected = {
            "request-one-finding.json": sync.project_findings_sync(
                _review(), PROJECT_REF, NAMESPACE_KEY
            ),
            "request-pass.json": sync.project_findings_sync(
                _review([]), PROJECT_REF, NAMESPACE_KEY
            ),
        }
        expected["receipt-created.json"] = _valid_receipt(
            expected["request-one-finding.json"]
        )
        for name, value in expected.items():
            with self.subTest(name=name):
                path = FIXTURES / name
                self.assertTrue(path.is_file(), f"missing golden fixture: {name}")
                self.assertEqual(
                    path.read_text(encoding="utf-8"), stable_json(value) + "\n"
                )


if __name__ == "__main__":
    unittest.main()
