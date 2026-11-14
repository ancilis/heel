"""E1: pure, closed, bounded live-read response assertions.

These tests pin the configured live-read semantics only. They do not exercise any
compiler, executor, API, UI or release path: E1 is not execution extensibility.
"""
from __future__ import annotations

import copy
import json
import re

import pytest

from heel.runner import content_assertion as ca
from heel.runner.content_assertion import (
    LIVE_READ_ASSERTION_SCHEMA,
    LIVE_READ_ROLE_POLICIES,
    LiveAssertionError,
    LiveReadResponse,
    canonical_live_read_assertion,
    evaluate_live_read_pair,
    live_read_assertion_digest,
    observe_live_read,
    parse_live_read_assertion,
    resolve_local_fixtures,
    validate_live_read_assertion,
)

# Sentinel values that must never be reflected in any return value, repr or error text.
CANARY = "SENTINEL-canary-7f3a91-do-not-reflect"
WITNESS_VALUE = "SENTINEL-export-ok-b2e4"
OTHER_VALUE = "SENTINEL-other-value-c9d1"

POLICY = "plan_entitlement_read"


_DEFAULT = object()


def assertion_dict(condition: dict, *, witness_path=_DEFAULT, witness_ref="export_ok") -> dict:
    return {
        "schema_version": LIVE_READ_ASSERTION_SCHEMA,
        "success_witness": {
            "path": ["meta", "state"] if witness_path is _DEFAULT else witness_path,
            "expected_fixture": witness_ref,
        },
        "condition": condition,
    }


def present(path) -> dict:
    return {"kind": "json_field_present", "path": path}


def equals(path, ref="secret_value") -> dict:
    return {"kind": "json_scalar_equals_fixture", "path": path, "expected_fixture": ref}


FIXTURES = {"export_ok": WITNESS_VALUE, "secret_value": CANARY, "other_value": OTHER_VALUE}


def build(condition: dict, fixtures=None, **kw):
    assertion = validate_live_read_assertion(assertion_dict(condition, **kw))
    return assertion, resolve_local_fixtures(assertion, FIXTURES if fixtures is None else fixtures)


def body(value) -> bytes:
    return json.dumps(value).encode()


def ok(status=200, value=None, raw=None) -> LiveReadResponse:
    return LiveReadResponse(status=status, body=raw if raw is not None else body(value))


# A body pair with NO ``protected_canary`` field: the configured paths alone decide.
CONTROL = {
    "meta": {"state": WITNESS_VALUE},
    "export": {"rows": [{"id": "r1", "ssn_hint": CANARY}], "owner": {"tier": "gold"}},
}
RESTRICTED = {
    "meta": {"state": WITNESS_VALUE},
    "export": {"rows": [{"id": "r1"}], "owner": {"tier": "gold"}},
}


def pair(assertion, expectations, *, restricted=None, control=None, method="GET", policy=POLICY):
    return evaluate_live_read_pair(
        role_policy=policy,
        method=method,
        assertion=assertion,
        expectations=expectations,
        control=control or ok(value=CONTROL),
        restricted=restricted or ok(value=RESTRICTED),
    )


def no_reflection(*objects) -> None:
    text = " ".join(repr(o) + str(o) for o in objects)
    for sentinel in (CANARY, WITNESS_VALUE, OTHER_VALUE):
        assert sentinel not in text


# --- distinct configured conditions on the SAME body pair --------------------------------


def test_different_nested_field_conditions_on_same_pair_give_different_outcomes():
    leak = build(present(["export", "rows", 0, "ssn_hint"]))
    shared = build(present(["export", "owner", "tier"]))
    value = build(equals(["export", "rows", 0, "ssn_hint"]))
    verdicts = [pair(*leak), pair(*shared), pair(*value)]
    assert [v.outcome for v in verdicts] == ["blocked", "observed", "blocked"]
    # The restricted body has the owner tier: a different configured field, a different verdict.
    restricted_leak = {**RESTRICTED, "export": CONTROL["export"]}
    assert pair(*leak, restricted=ok(value=restricted_leak)).outcome == "observed"
    assert pair(*value, restricted=ok(value=restricted_leak)).outcome == "observed"
    no_reflection(*verdicts)


def test_local_fixture_a_or_b_changes_result_without_code_changes():
    assertion = validate_live_read_assertion(assertion_dict(equals(["export", "owner", "tier"])))
    a = resolve_local_fixtures(assertion, {"export_ok": WITNESS_VALUE, "secret_value": "gold"})
    b = resolve_local_fixtures(assertion, {"export_ok": WITNESS_VALUE, "secret_value": "silver"})
    assert pair(assertion, a).outcome == "observed"
    # B: the positive control no longer satisfies the configured condition.
    verdict_b = pair(assertion, b)
    assert verdict_b.outcome == "inconclusive"
    assert verdict_b.reason == "positive_control_condition_false"
    silver_control = {**CONTROL, "export": {**CONTROL["export"], "owner": {"tier": "silver"}}}
    assert pair(assertion, b, control=ok(value=silver_control)).outcome == "blocked"


def test_fixtures_are_snapshotted_before_evaluation():
    assertion = validate_live_read_assertion(assertion_dict(equals(["export", "owner", "tier"])))
    local = {"export_ok": WITNESS_VALUE, "secret_value": "gold"}
    expectations = resolve_local_fixtures(assertion, local)
    local["secret_value"] = "silver"
    local.clear()
    assert pair(assertion, expectations).outcome == "observed"


def test_fixtures_bound_to_one_assertion_digest():
    a, expectations = build(present(["export", "owner", "tier"]))
    other = validate_live_read_assertion(assertion_dict(present(["export", "owner"])))
    verdict = pair(other, expectations)
    assert (verdict.outcome, verdict.reason) == ("inconclusive", "fixture_unbound")


# --- positive control ----------------------------------------------------------------------


@pytest.mark.parametrize("control, reason", [
    (ok(status=201, value=CONTROL), "positive_control_status"),
    (ok(status=403, value=CONTROL), "positive_control_status"),
    (ok(value={"meta": {"state": "other"}, "export": CONTROL["export"]}), "positive_control_unknown"),
    (ok(value={"export": CONTROL["export"]}), "positive_control_unknown"),
    (ok(value={"meta": {"state": WITNESS_VALUE}, "export": {}}), "positive_control_unknown"),
    (ok(value={"meta": {"state": WITNESS_VALUE}, "export": {"owner": {}}}), "positive_control_condition_false"),
    (ok(raw=b""), "positive_control_unknown"),
    (ok(raw=b"not json"), "positive_control_unknown"),
])
def test_positive_control_missing_or_failed_is_inconclusive(control, reason):
    verdict = pair(*build(present(["export", "owner", "tier"])), control=control,
                   restricted=ok(value=CONTROL))
    assert (verdict.outcome, verdict.reason, verdict.positive_control) == ("inconclusive", reason, False)
    assert verdict.restricted_condition is None


def test_witness_missing_or_false_is_unknown_even_when_condition_matches():
    assertion, expectations = build(present(["export", "owner", "tier"]))
    for value in (
        {"export": CONTROL["export"]},
        {"meta": {"state": False}, "export": CONTROL["export"]},
        {"meta": {"state": None}, "export": CONTROL["export"]},
        {"meta": [WITNESS_VALUE], "export": CONTROL["export"]},
        {"meta": {"state": {"v": WITNESS_VALUE}}, "export": CONTROL["export"]},
    ):
        obs = observe_live_read(ok(value=value), method="GET", assertion=assertion,
                                expectations=expectations)
        assert obs.state == "unknown" and obs.condition is None
        assert obs.reason in {"witness_not_matched", "witness_path_unresolved"}
        assert pair(assertion, expectations, restricted=ok(value=value)).outcome == "inconclusive"


# --- envelopes, status, HEAD ---------------------------------------------------------------


ENVELOPES = [
    {**RESTRICTED, "error": "upgrade required", "export": CONTROL["export"]},
    {**RESTRICTED, "ok": False, "export": CONTROL["export"]},
    {**RESTRICTED, "status": "PaymentRequired", "export": CONTROL["export"]},
    {**RESTRICTED, "status": 403.0, "export": CONTROL["export"]},
    {**RESTRICTED, "data": {"denied": True}, "export": CONTROL["export"]},
    {"message": "upgrade required"},
]


@pytest.mark.parametrize("status", [200, 206, 402, 403, 500])
@pytest.mark.parametrize("envelope", ENVELOPES)
def test_envelopes_at_any_status_never_finding_or_pass(status, envelope):
    assertion, expectations = build(present(["export", "rows", 0, "ssn_hint"]))
    verdict = pair(assertion, expectations, restricted=ok(status=status, value=envelope))
    assert verdict.outcome == "inconclusive"
    assert verdict.reason in {"restricted_denial_envelope", "restricted_ambiguous_message"}
    # The same envelope as positive control also withholds every result.
    verdict = pair(assertion, expectations, control=ok(status=200, value=envelope),
                   restricted=ok(value=CONTROL))
    assert verdict.outcome == "inconclusive" and not verdict.positive_control


def test_envelope_overrides_matching_condition_in_observation():
    assertion, expectations = build(present(["export", "owner", "tier"]))
    obs = observe_live_read(ok(value={**CONTROL, "error": "nope"}), method="GET",
                            assertion=assertion, expectations=expectations)
    assert (obs.state, obs.reason, obs.condition) == ("unknown", "denial_envelope", None)


@pytest.mark.parametrize("status", [401, 402, 403, 404, 409, 500, 302])
def test_nonempty_non_2xx_body_is_inconclusive_even_if_condition_matches(status):
    assertion, expectations = build(present(["export", "rows", 0, "ssn_hint"]))
    verdict = pair(assertion, expectations, restricted=ok(status=status, value=CONTROL))
    assert (verdict.outcome, verdict.reason) == ("inconclusive", "restricted_status_not_success")
    verdict = pair(assertion, expectations, restricted=ok(status=status, value=RESTRICTED))
    assert verdict.outcome == "inconclusive"


@pytest.mark.parametrize("status", [401, 402, 403, 404])
def test_empty_bounded_denial_is_blocked_only_with_valid_positive_control(status):
    assertion, expectations = build(present(["export", "rows", 0, "ssn_hint"]))
    verdict = pair(assertion, expectations, restricted=ok(status=status, raw=b""))
    assert (verdict.outcome, verdict.reason) == ("blocked", "restricted_empty_denial")
    failed = pair(assertion, expectations, restricted=ok(status=status, raw=b""),
                  control=ok(status=status, raw=b""))
    assert failed.outcome == "inconclusive"


@pytest.mark.parametrize("status", [200, 204, 400, 410, 500])
def test_other_empty_bodies_are_inconclusive(status):
    assertion, expectations = build(present(["export", "rows", 0, "ssn_hint"]))
    verdict = pair(assertion, expectations, restricted=ok(status=status, raw=b""))
    assert verdict.outcome == "inconclusive"


def test_status_alone_never_produces_finding():
    assertion, expectations = build(present(["export", "rows", 0, "ssn_hint"]))
    for status in (200, 201, 203, 206):
        for raw in (b"", b"{}", b"[]", b"null", body({"meta": {"state": WITNESS_VALUE}})):
            assert pair(assertion, expectations,
                        restricted=ok(status=status, raw=raw)).outcome != "observed"


@pytest.mark.parametrize("method", ["HEAD", "head", "get", "POST", "OPTIONS", ""])
def test_head_and_other_methods_always_inconclusive(method):
    assertion, expectations = build(present(["export", "rows", 0, "ssn_hint"]))
    verdict = pair(assertion, expectations, method=method, restricted=ok(value=CONTROL))
    assert (verdict.outcome, verdict.reason) == ("inconclusive", "method_not_observable")
    obs = observe_live_read(ok(value=CONTROL), method=method, assertion=assertion,
                            expectations=expectations)
    assert obs.state == "unknown"


@pytest.mark.parametrize("policy", [
    "object_ownership_read", "role_bound_read", "tenant_isolation_read", "", None,
])
def test_role_policy_restricted_to_two_existing_pairs(policy):
    assert LIVE_READ_ROLE_POLICIES == frozenset({"anonymous_authenticated_read", "plan_entitlement_read"})
    verdict = pair(*build(present(["export", "rows", 0, "ssn_hint"])), policy=policy,
                   restricted=ok(value=CONTROL))
    assert (verdict.outcome, verdict.reason) == ("inconclusive", "role_policy_unsupported")


def test_both_supported_policies_evaluate():
    for policy in sorted(LIVE_READ_ROLE_POLICIES):
        verdict = pair(*build(present(["export", "rows", 0, "ssn_hint"])), policy=policy,
                       restricted=ok(value=CONTROL))
        assert verdict.outcome == "observed"


# --- malformed / duplicate / deep / oversized bodies ---------------------------------------


@pytest.mark.parametrize("raw", [
    b"{",
    b'{"meta": {"state": "x"}, "meta": {"state": "y"}}',
    b'{"meta": {"state": "a", "state": "b"}}',
    b'{"x": NaN}',
    b'{"x": Infinity}',
    b'{"x": -Infinity}',
    b'{"x": 1e400}',
    b"\xff\xfe{}",
    b'\xef\xbb\xbf{"a": 1}',
    '{"a": 1}'.encode("utf-16"),
    b'{"a": "\xc3"}',
    b'{"a": "\\ud800"}',
    b'{"\\udfff": 1}',
    b"[" * 100 + b"]" * 100,
    b'{"a":' * 40 + b"1" + b"}" * 40,
    b'{"a":' * 5000 + b"1" + b"}" * 5000,
    b"[" + b"0," * 20000 + b"0]",
    b'{"n": ' + b"9" * 5000 + b"}",
    b'{"n": -1e-9999999999999999999999}',
    b'{"n": 1e9999999999999999999999}',
], ids=lambda value: value[:24])
def test_malformed_duplicate_deep_bodies_fail_closed(raw):
    assertion, expectations = build(present(["export", "rows", 0, "ssn_hint"]))
    obs = observe_live_read(ok(raw=raw), method="GET", assertion=assertion,
                            expectations=expectations)
    assert obs.state == "unknown" and obs.condition is None and obs.witness is None
    assert pair(assertion, expectations, restricted=ok(raw=raw)).outcome == "inconclusive"
    assert pair(assertion, expectations, control=ok(raw=raw)).outcome == "inconclusive"


def test_oversized_body_is_unknown_even_when_valid():
    assertion, expectations = build(present(["export", "rows", 0, "ssn_hint"]))
    padding = "p" * (ca.LIVE_READ_MAX_BODY_BYTES)
    big = body({**CONTROL, "pad": padding})
    assert len(big) > ca.LIVE_READ_MAX_BODY_BYTES
    obs = observe_live_read(ok(raw=big), method="GET", assertion=assertion, expectations=expectations)
    assert (obs.state, obs.reason) == ("unknown", "body_too_large")
    fits = body({**CONTROL, "pad": "p" * 1000})
    obs = observe_live_read(ok(raw=fits), method="GET", assertion=assertion, expectations=expectations)
    assert obs.state == "condition_true"


@pytest.mark.parametrize("raw", [b"[]", b"null", b'"x"', b"1", b"true"])
def test_non_object_bodies_are_unknown(raw):
    assertion, expectations = build(present(["export"]))
    obs = observe_live_read(ok(raw=raw), method="GET", assertion=assertion, expectations=expectations)
    assert (obs.state, obs.reason) == ("unknown", "body_not_object")


@pytest.mark.parametrize("status", [True, 99, 600, "200", 200.0, None])
def test_invalid_status_is_unknown(status):
    assertion, expectations = build(present(["export"]))
    obs = observe_live_read(LiveReadResponse(status=status, body=body(CONTROL)), method="GET",
                            assertion=assertion, expectations=expectations)
    assert (obs.state, obs.reason) == ("unknown", "status_invalid")


@pytest.mark.parametrize("raw", [bytearray(b"{}"), "{}", None, memoryview(b"{}")])
def test_body_must_be_bytes(raw):
    assertion, expectations = build(present(["export"]))
    obs = observe_live_read(LiveReadResponse(status=200, body=raw), method="GET",
                            assertion=assertion, expectations=expectations)
    assert obs.state == "unknown"


# --- path semantics: missing vs null, traversal type ---------------------------------------


def observe(condition, value, fixtures=None):
    assertion, expectations = build(condition, fixtures)
    return observe_live_read(ok(value=value), method="GET", assertion=assertion,
                             expectations=expectations)


def with_export(export) -> dict:
    return {"meta": {"state": WITNESS_VALUE}, "export": export}


def test_present_null_is_present_and_absent_is_false():
    assert observe(present(["export", "f"]), with_export({"f": None})).condition is True
    assert observe(present(["export", "f"]), with_export({"g": 1})).condition is False
    assert observe(present(["export", 1]), with_export([0, None])).condition is True
    assert observe(present(["export", 2]), with_export([0, None])).condition is False


def test_null_equals_only_null_fixture():
    null_fixtures = {"export_ok": WITNESS_VALUE, "secret_value": None}
    assert observe(equals(["export", "f"]), with_export({"f": None}), null_fixtures).condition is True
    assert observe(equals(["export", "f"]), with_export({"g": None}), null_fixtures).condition is False
    assert observe(equals(["export", "f"]), with_export({"f": False}), null_fixtures).condition is False
    assert observe(equals(["export", "f"]), with_export({"f": ""}), null_fixtures).condition is False


@pytest.mark.parametrize("export, reason", [
    ("scalar", "path_type_mismatch"),
    ([{"f": 1}], "path_type_mismatch"),
    ({"x": {"f": 1}}, "path_parent_missing"),
    ({"0": {"f": 1}}, "path_parent_missing"),
])
def test_wrong_traversal_type_or_missing_parent_is_unknown(export, reason):
    obs = observe(present(["export", "a", "f"]), with_export(export))
    assert (obs.state, obs.reason, obs.condition) == ("unknown", reason, None)


def test_int_segment_indexes_only_lists_and_string_only_objects():
    assert observe(present(["export", 0]), with_export({"0": 1})).reason == "path_type_mismatch"
    assert observe(present(["export", "0"]), with_export([1])).reason == "path_type_mismatch"
    assert observe(present(["export", "0"]), with_export({"0": 1})).condition is True


def test_equality_on_container_value_is_unknown():
    obs = observe(equals(["export", "f"]), with_export({"f": [CANARY]}))
    assert (obs.state, obs.reason) == ("unknown", "condition_value_not_scalar")
    obs = observe(equals(["export", "f"]), with_export({"f": {"v": CANARY}}))
    assert obs.state == "unknown"


def test_literal_keys_are_not_patterns():
    # A dotted key is one key, not a nested path, and vice versa.
    assert observe(present(["export", "a.b"]), with_export({"a": {"b": 1}})).condition is False
    assert observe(present(["export", "a", "b"]), with_export({"a.b": 1})).reason == "path_parent_missing"
    assert observe(present(["export", "A"]), with_export({"a": 1})).condition is False
    assert observe(present(["export", "row_"]), with_export({"row_1": 1})).condition is False


# --- strict scalar types -------------------------------------------------------------------


@pytest.mark.parametrize("expected, actual, result", [
    (1, 1, True),
    (1, 1.0, True),
    (1, True, False),
    (True, 1, False),
    (False, 0, False),
    (0, False, False),
    (False, False, True),
    (1, "1", False),
    ("1", 1, False),
    ("true", True, False),
    (None, "null", False),
    (None, 0, False),
    (0.1, 0.1, True),
    (100, 1e2, True),
    (-0.0, 0, True),
    ("Gold", "gold", False),
    ("é", "é", False),
    ("é", "é", True),
    (9007199254740993, 9007199254740993, True),
    (9007199254740993, 9007199254740992, False),
])
def test_scalar_equality_is_strict(expected, actual, result):
    fixtures = {"export_ok": WITNESS_VALUE, "secret_value": expected}
    obs = observe(equals(["export", "f"]), with_export({"f": actual}), fixtures)
    assert obs.condition is result


def test_number_comparison_is_exact_decimal_text_value():
    assertion, expectations = build(equals(["export", "f"]),
                                    {"export_ok": WITNESS_VALUE, "secret_value": 1})
    def raw_obs(text: bytes):
        raw = b'{"meta": {"state": "' + WITNESS_VALUE.encode() + b'"}, "export": {"f": ' + text + b"}}"
        return observe_live_read(ok(raw=raw), method="GET", assertion=assertion,
                                 expectations=expectations).condition
    assert raw_obs(b"1") is True
    assert raw_obs(b"1.0") is True
    assert raw_obs(b"1e0") is True
    assert raw_obs(b"10e-1") is True
    # A float parse would round this to 1.0; exact comparison does not.
    assert raw_obs(b"1.0000000000000000001") is False
    assert raw_obs(b'"1"') is False


def test_witness_also_compares_strictly():
    assertion, expectations = build(present(["export"]), {"export_ok": 1, "secret_value": CANARY})
    for state, result in ((1, "condition_true"), (True, "unknown"), ("1", "unknown"), (1.0, "condition_true")):
        obs = observe_live_read(ok(value={"meta": {"state": state}, "export": {}}), method="GET",
                                assertion=assertion, expectations=expectations)
        assert obs.state == result


# --- local fixtures: missing / invalid / unavailable ---------------------------------------


@pytest.mark.parametrize("fixtures, reason", [
    ({"export_ok": WITNESS_VALUE}, "fixture_missing"),
    ({"secret_value": CANARY}, "fixture_missing"),
    ({}, "fixture_missing"),
    ({"export_ok": WITNESS_VALUE, "secret_value": float("nan")}, "fixture_invalid"),
    ({"export_ok": WITNESS_VALUE, "secret_value": float("inf")}, "fixture_invalid"),
    ({"export_ok": WITNESS_VALUE, "secret_value": [CANARY]}, "fixture_invalid"),
    ({"export_ok": WITNESS_VALUE, "secret_value": {"v": 1}}, "fixture_invalid"),
    ({"export_ok": WITNESS_VALUE, "secret_value": b"bytes"}, "fixture_invalid"),
    ({"export_ok": WITNESS_VALUE, "secret_value": "x" * 2049}, "fixture_invalid"),
    ({"export_ok": WITNESS_VALUE, "secret_value": "é" * 1025}, "fixture_invalid"),
    ({"export_ok": WITNESS_VALUE, "secret_value": "\ud800"}, "fixture_invalid"),
    ({"export_ok": WITNESS_VALUE, "secret_value": 2 ** 63}, "fixture_invalid"),
    ({"export_ok": WITNESS_VALUE, "secret_value": object()}, "fixture_invalid"),
])
def test_missing_or_invalid_fixture_is_inconclusive_never_false(fixtures, reason):
    assertion, expectations = build(equals(["export", "rows", 0, "ssn_hint"]), fixtures)
    assert expectations.available is False and expectations.reason == reason
    for restricted in (ok(value=CONTROL), ok(value=RESTRICTED), ok(status=403, raw=b"")):
        verdict = pair(assertion, expectations, restricted=restricted)
        assert (verdict.outcome, verdict.reason) == ("inconclusive", reason)
    obs = observe_live_read(ok(value=CONTROL), method="GET", assertion=assertion,
                            expectations=expectations)
    assert (obs.state, obs.reason) == ("unknown", reason)
    no_reflection(expectations, verdict, obs)


def test_fixture_boundaries_accepted():
    for value in ("x" * 2048, "é" * 1024, "", 2 ** 63 - 1, -(2 ** 63) + 1, 0.5, True, None):
        _, expectations = build(equals(["export", "f"]), {"export_ok": "w", "secret_value": value})
        assert expectations.available is True, value


@pytest.mark.parametrize("fixtures", [
    [("export_ok", WITNESS_VALUE)],
    None,
    type("M", (dict,), {})(FIXTURES),
])
def test_fixtures_must_be_exact_dict(fixtures):
    assertion = validate_live_read_assertion(assertion_dict(present(["export"])))
    expectations = resolve_local_fixtures(assertion, fixtures)
    assert (expectations.available, expectations.reason) == (False, "fixtures_invalid")


def test_fixture_unrelated_entries_ignored_and_not_retained():
    assertion = validate_live_read_assertion(assertion_dict(present(["export"])))
    expectations = resolve_local_fixtures(assertion, {**FIXTURES, "junk": object()})
    assert expectations.available is True
    no_reflection(expectations)


def test_present_condition_needs_only_witness_fixture():
    assertion = validate_live_read_assertion(assertion_dict(present(["export"])))
    assert resolve_local_fixtures(assertion, {"export_ok": WITNESS_VALUE}).available is True


# --- assertion definition validation -------------------------------------------------------


def reject(value, reason):
    with pytest.raises(LiveAssertionError) as info:
        validate_live_read_assertion(value)
    assert info.value.reason == reason
    assert str(info.value) == reason
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__ is True or info.value.__context__ is None
    return info.value


def test_valid_assertion_round_trips_canonically():
    raw = assertion_dict(equals(["export", "rows", 0, "ssn_hint"]))
    a = validate_live_read_assertion(raw)
    canonical = canonical_live_read_assertion(a)
    assert json.loads(canonical) == raw
    assert canonical == json.dumps(raw, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False).encode()
    reordered = {"condition": raw["condition"], "success_witness": raw["success_witness"],
                 "schema_version": raw["schema_version"]}
    b = validate_live_read_assertion(reordered)
    assert live_read_assertion_digest(a) == live_read_assertion_digest(b)
    assert live_read_assertion_digest(a).startswith("sha256:")
    assert len(live_read_assertion_digest(a)) == len("sha256:") + 64
    assert parse_live_read_assertion(json.dumps(raw, indent=2).encode()) == a
    assert parse_live_read_assertion(canonical) == a
    # Any configured change changes the digest.
    other = validate_live_read_assertion(assertion_dict(equals(["export", "rows", 1, "ssn_hint"])))
    assert live_read_assertion_digest(other) != live_read_assertion_digest(a)


def test_validation_does_not_alias_input():
    raw = assertion_dict(present(["export", "owner"]))
    before = copy.deepcopy(raw)
    a = validate_live_read_assertion(raw)
    raw["condition"]["path"].append("tier")
    assert canonical_live_read_assertion(a) == canonical_live_read_assertion(
        validate_live_read_assertion(before))


@pytest.mark.parametrize("mutate, reason", [
    (lambda d: d.update(extra=1), "unknown_field"),
    (lambda d: d.pop("condition"), "missing_field"),
    (lambda d: d.pop("success_witness"), "missing_field"),
    (lambda d: d.update(schema_version="heel.live-read-assertion.v2"), "schema_version_unsupported"),
    (lambda d: d["success_witness"].update(status=200), "unknown_field"),
    (lambda d: d["success_witness"].pop("expected_fixture"), "missing_field"),
    (lambda d: d["condition"].update(kind="json_regex_match"), "condition_kind_unsupported"),
    (lambda d: d["condition"].update(kind="json_scalar_equals"), "condition_kind_unsupported"),
    (lambda d: d["condition"].update(expected_fixture="secret_value"), "unknown_field"),
    (lambda d: d["condition"].update(headers={"x": "y"}), "unknown_field"),
    (lambda d: d["condition"].update(status=200), "unknown_field"),
    (lambda d: d["condition"].update(expected="literal"), "unknown_field"),
    (lambda d: d["condition"].update(url="https://x"), "unknown_field"),
    (lambda d: d["condition"].update(callback="os.system"), "unknown_field"),
    (lambda d: d.update(condition=[1]), "field_type_invalid"),
    (lambda d: d.update(success_witness=None), "field_type_invalid"),
    (lambda d: d["condition"].update(kind=1), "condition_kind_unsupported"),
])
def test_closed_schema_rejects_unknown_missing_and_unsupported(mutate, reason):
    raw = assertion_dict(present(["export", "owner"]))
    mutate(raw)
    reject(raw, reason)


def test_equals_condition_requires_fixture_and_present_forbids_it():
    raw = assertion_dict(equals(["export"]))
    del raw["condition"]["expected_fixture"]
    reject(raw, "missing_field")


def test_plain_dict_only():
    class Sneaky(dict):
        pass
    reject(Sneaky(assertion_dict(present(["export"]))), "field_type_invalid")
    reject([("schema_version", LIVE_READ_ASSERTION_SCHEMA)], "field_type_invalid")
    reject("{}", "field_type_invalid")
    raw = assertion_dict(present(["export"]))
    raw[1] = "x"
    reject(raw, "unknown_field")


@pytest.mark.parametrize("path, reason", [
    ([], "path_length_invalid"),
    (["a"] * 9, "path_length_invalid"),
    ("export.owner", "path_type_invalid"),
    (None, "path_type_invalid"),
    ([""], "path_segment_invalid"),
    (["x" * 129], "path_segment_invalid"),
    (["é" * 129], "path_segment_invalid"),
    (["😀" * 65], "path_segment_invalid"),
    (["a\x00b"], "path_segment_invalid"),
    (["a\nb"], "path_segment_invalid"),
    (["a\x7f"], "path_segment_invalid"),
    (["a\u0085"], "path_segment_invalid"),
    (["\ud800"], "path_segment_invalid"),
    (["*"], "path_segment_reserved"),
    (["**"], "path_segment_reserved"),
    ([".."], "path_segment_reserved"),
    (["."], "path_segment_reserved"),
    (["$"], "path_segment_reserved"),
    ([-1], "path_segment_invalid"),
    ([1024], "path_segment_invalid"),
    ([True], "path_segment_invalid"),
    ([False], "path_segment_invalid"),
    ([1.0], "path_segment_invalid"),
    ([None], "path_segment_invalid"),
    ([["a"]], "path_segment_invalid"),
    ([{"a": 1}], "path_segment_invalid"),
])
def test_path_bounds(path, reason):
    reject(assertion_dict(present(path)), reason)
    reject(assertion_dict(present(["ok"]), witness_path=path), reason)


def test_path_boundaries_accepted():
    for path in (["a"] * 8, ["x" * 128], ["é" * 128], ["😀" * 64], [0], [1023], ["a.b/c[0]"],
                 ["$.export"], ["*a"]):
        validate_live_read_assertion(assertion_dict(present(path)))


@pytest.mark.parametrize("ref", [
    "", "1abc", "a" * 65, "secret value", "../secret", "a/b", "a.b", "é", "heel:canary",
    "a\n", 1, None, True, ["a"], "SENTINEL-canary-7f3a91-do-not-reflect!",
])
def test_fixture_reference_bounds(ref):
    reject(assertion_dict(equals(["export"], ref=ref)), "fixture_reference_invalid")
    reject(assertion_dict(present(["export"]), witness_ref=ref), "fixture_reference_invalid")


def test_fixture_reference_boundaries_accepted():
    for ref in ("a", "A" * 64, "export_ok", "lower-plan_value2"):
        validate_live_read_assertion(assertion_dict(equals(["export"], ref=ref)))


def test_total_canonical_definition_bound():
    big = ["😀" * 64] * 8
    within = assertion_dict(equals(big), witness_path=["s"])
    assert len(canonical_live_read_assertion(validate_live_read_assertion(within))) <= 4096
    over = assertion_dict(equals(big), witness_path=big)
    reject(over, "definition_too_large")


@pytest.mark.parametrize("raw, reason", [
    (b'{"schema_version": "a", "schema_version": "b"}', "definition_malformed"),
    (b'{"schema_version": "heel.live-read-assertion.v1", "success_witness": '
     b'{"path": ["a"], "path": ["b"], "expected_fixture": "w"}, '
     b'"condition": {"kind": "json_field_present", "path": ["x"]}}', "definition_malformed"),
    (b"{", "definition_malformed"),
    (b"\xff", "definition_malformed"),
    (b'{"a": NaN}', "definition_malformed"),
    (b"[]", "field_type_invalid"),
    (b" " * 8193, "definition_too_large"),
    ("{}", "definition_malformed"),
    (b"[" * 3000 + b"]" * 3000, "field_type_invalid"),
], ids=lambda value: value[:24] if isinstance(value, (bytes, str)) else value)
def test_raw_definition_parsing_is_strict(raw, reason):
    with pytest.raises(LiveAssertionError) as info:
        parse_live_read_assertion(raw)
    assert info.value.reason == reason
    assert info.value.__cause__ is None


def test_raw_definition_float_index_rejected():
    raw = json.dumps(assertion_dict(present(["export", 0]))).replace("0]", "0.0]").encode()
    with pytest.raises(LiveAssertionError) as info:
        parse_live_read_assertion(raw)
    assert info.value.reason == "path_segment_invalid"


# --- no reflection of sentinel canary values -----------------------------------------------


def test_no_reflection_in_any_output_or_error():
    assertion, expectations = build(equals(["export", "rows", 0, "ssn_hint"]))
    outputs = [
        expectations,
        assertion,
        pair(assertion, expectations),
        pair(assertion, expectations, restricted=ok(value=CONTROL)),
        pair(assertion, expectations, restricted=ok(status=500, value=CONTROL)),
        observe_live_read(ok(value=CONTROL), method="GET", assertion=assertion,
                          expectations=expectations),
        observe_live_read(ok(raw=body(CONTROL)[:-1]), method="GET", assertion=assertion,
                          expectations=expectations),
    ]
    no_reflection(*outputs)
    for verdict in outputs[2:5]:
        assert set(vars(verdict)) == {
            "outcome", "reason", "positive_control", "restricted_condition",
        }
        for value in vars(verdict).values():
            assert value is None or isinstance(value, (bool, str))
    # Errors raised for invalid definitions never echo the offending input.
    error = reject(assertion_dict(present([CANARY + "\x00"])), "path_segment_invalid")
    no_reflection(error, error.args)
    error = reject({**assertion_dict(present(["a"])), CANARY: 1}, "unknown_field")
    no_reflection(error, error.args)
    with pytest.raises(LiveAssertionError) as info:
        parse_live_read_assertion(b'{"' + CANARY.encode() + b'": ')
    no_reflection(info.value, info.value.args, info.value.__context__)


def test_reasons_are_closed_codes():
    assertion, expectations = build(equals(["export", "rows", 0, "ssn_hint"]))
    cases = [
        pair(assertion, expectations),
        pair(assertion, expectations, restricted=ok(value=CONTROL)),
        pair(assertion, expectations, restricted=ok(status=403, raw=b"")),
        pair(assertion, expectations, restricted=ok(raw=b"{")),
        pair(assertion, expectations, method="HEAD"),
        pair(assertion, expectations, policy="x"),
        pair(assertion, expectations, control=ok(status=500, value=CONTROL)),
    ]
    for verdict in cases:
        assert verdict.reason in ca.LIVE_READ_PAIR_REASONS
        assert verdict.outcome in {"observed", "blocked", "inconclusive"}


def test_module_has_no_dynamic_execution_surface():
    import inspect
    source = inspect.getsource(ca)
    for forbidden in ("eval(", "exec(", "__import__", "importlib", "getattr(", "socket",
                      "urllib", "http.client", "requests", "subprocess", "logging", "print("):
        assert forbidden not in source, forbidden
    # Only the regex compiler is used, never the code compiler.
    assert not re.search(r"(?<!re\.)\bcompile\(", source)


# --- legacy behavior unchanged -------------------------------------------------------------


def test_legacy_protected_content_unchanged():
    marker = "heel-canary-export-0001"
    p = ca.protected_content
    assert p(body({"protected_canary": marker}), marker=marker, status=200) is True
    assert p(body({"protected_canary": marker}), marker=marker, status=200, method="HEAD") is None
    assert p(b"", marker=marker, status=403) is False
    assert p(body({"error": "x", "protected_canary": marker}), marker=marker, status=200) is None
    assert p(body({"visibility": "public"}), marker=marker, status=200) is False
    assert p(body({"records": []}), marker=marker, status=200) is False
    assert p(body({"other": 1}), marker=marker, status=200) is None
    assert ca.is_denial_envelope({"status": 403.0}) is True
    assert ca.is_ambiguous_message({"message": "x"}) is True
