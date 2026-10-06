"""R11: the plan-differential predicates are three-valued and fail closed."""
from __future__ import annotations

import json

import pytest

from heel.runner import plan_differential
from heel.runner.plan_differential import (
    ExecutorOutcome,
    PlanObservation,
    evaluate_plan_pair,
    is_denial_envelope,
    key_paths,
)


MARKER = "heel-canary-export-0001"
FULL = {"account_id": "acct", "rows": [{"id": "r1", "amount": 12.5}], "total": 1}
SUBSET = {"account_id": "acct", "total": 0}
ENVELOPE = {"error": "upgrade required"}
COMPLETED = ExecutorOutcome("completed", "inconclusive")


def observation(status: int, value=None, *, raw: bytes | None = None) -> PlanObservation:
    body = raw if raw is not None else (b"" if value is None else json.dumps(value).encode())
    return PlanObservation(status, body, "ev1_" + "0" * 64)


def evaluate(lower, higher, *, method="GET", marker=None, outcome=COMPLETED):
    return evaluate_plan_pair(
        lower, higher, method=method, marker=marker, executor_outcome=outcome,
    )


def protected(marker: str = MARKER) -> dict:
    return {"protected_canary": marker, "rows": []}


# One case per §8.5 row: (row, lower, higher, keywords, verdict, state, predicate, reason).
ROWS = [
    (1, None, None, {"outcome": ExecutorOutcome("failed", "inconclusive", "transport:response_rejected")},
     "inconclusive", None, "inconclusive", "transport:response_rejected"),
    (2, observation(200, FULL), observation(403, ENVELOPE), {},
     "inconclusive", "inconclusive", "inconclusive", "no_positive_control"),
    (2, observation(200, protected()), observation(200, {"rows": []}), {"marker": MARKER},
     "inconclusive", "inconclusive", "inconclusive", "positive_control_missing_marker"),
    (3, observation(200, protected()), observation(200, protected()),
     {"marker": MARKER, "outcome": ExecutorOutcome("completed", "observed")},
     "finding", "verified", "marker_leak", "marker_present"),
    (4, observation(403, ENVELOPE), observation(200, protected()),
     {"marker": MARKER, "outcome": ExecutorOutcome("completed", "blocked")},
     "held", None, "marker_leak", "marker_absent"),
    (5, observation(200, {"rows": [1]}), observation(200, protected()),
     {"marker": MARKER, "outcome": ExecutorOutcome("completed", "inconclusive")},
     "inconclusive", "inconclusive", "inconclusive", "marker_undetermined"),
    (6, observation(200, FULL), observation(200, FULL), {},
     "finding", "observed", "body_superset", "lower_superset"),
    (7, observation(403, ENVELOPE), observation(200, FULL), {},
     "held", None, "status_parity", "lower_denied"),
    (8, observation(200, SUBSET), observation(200, FULL), {},
     "inconclusive", "inconclusive", "status_parity", "lower_subset"),
    (8, observation(204), observation(204), {},
     "inconclusive", "inconclusive", "status_parity", "status_only"),
    (8, observation(200), observation(200), {"method": "HEAD"},
     "inconclusive", "inconclusive", "status_parity", "head_status_only"),
    (9, observation(200, ENVELOPE), observation(200, FULL), {},
     "inconclusive", "inconclusive", "inconclusive", "lower_denial_envelope"),
    (9, observation(500, {"detail": "boom"}), observation(200, FULL), {},
     "inconclusive", "inconclusive", "inconclusive", "unexpected_status"),
]


@pytest.mark.parametrize(
    "row,lower,higher,keywords,verdict,state,predicate,reason", ROWS,
    ids=[f"row{case[0]}-{case[7]}" for case in ROWS],
)
def test_r11_verdict_table_rows(row, lower, higher, keywords, verdict, state, predicate, reason):
    result = evaluate(lower, higher, **keywords)
    assert (result.row, result.verdict, result.evidence_state, result.predicate, result.reason) == (
        row, verdict, state, predicate, reason,
    )
    # A finding is stored for rows 2, 3, 5, 6, 8 and 9 only; never for row 1 or a held pair.
    assert result.stores_finding is (row in {2, 3, 5, 6, 8, 9})
    # `candidate` is true on row 8 and nowhere else.
    assert result.candidate is (row == 8)
    assert {case[0] for case in ROWS} == set(range(1, 10))


def test_r11_predicates_fail_closed(monkeypatch):
    states = set()

    # Status parity alone is never observed, verified or held.
    for lower, higher, method in (
        (observation(200), observation(200), "GET"),
        (observation(204), observation(204), "GET"),
        (observation(200), observation(200), "HEAD"),
        (observation(200, SUBSET), observation(200, FULL), "GET"),
    ):
        result = evaluate(lower, higher, method=method)
        assert result.status_parity is True and result.body_superset is not True
        assert (result.verdict, result.evidence_state, result.candidate) == (
            "inconclusive", "inconclusive", True,
        )
        states.add(result.evidence_state)

    # A HEAD pair is only ever held (row 7) or inconclusive, whatever the bodies or marker.
    for lower_status in (200, 204, 401, 402, 403, 404, 500):
        for marker in (None, MARKER):
            result = evaluate(
                observation(lower_status, protected()), observation(200, protected()),
                method="HEAD", marker=marker,
                outcome=ExecutorOutcome("completed", "observed"),
            )
            assert result.verdict in {"held", "inconclusive"}
            assert result.body_superset is None and result.marker_leak is None
            assert result.verdict != "held" or result.row == 7 or marker is not None

    # Missing positive control: the higher plan failed, was enveloped, or lacked the marker.
    for higher in (observation(403, ENVELOPE), observation(200, ENVELOPE), observation(500)):
        result = evaluate(observation(200, FULL), higher)
        assert (result.row, result.verdict, result.reason) == (2, "inconclusive", "no_positive_control")
        assert result.status_parity is None and result.body_superset is None

    # Executor disagreement: the body says leak but the executor did not observe it.
    for outcome in ("blocked", "inconclusive", "not_reached"):
        result = evaluate(
            observation(200, protected()), observation(200, protected()), marker=MARKER,
            outcome=ExecutorOutcome("completed", outcome),
        )
        assert (result.marker_leak, result.verdict, result.reason) == (
            None, "inconclusive", "marker_undetermined",
        )
    result = evaluate(
        observation(403, ENVELOPE), observation(200, protected()), marker=MARKER,
        outcome=ExecutorOutcome("completed", "observed"),
    )
    assert (result.marker_leak, result.verdict) == (None, "inconclusive")

    # A marker pair never falls through to the body or status rows.
    result = evaluate(
        observation(200, {"protected_canary": "other", "rows": [], "x": 1}),
        observation(200, protected()), marker=MARKER,
    )
    assert result.row == 5 and result.evidence_state == "inconclusive"

    # Empty and unparseable bodies.
    assert evaluate(observation(200), observation(200, FULL)).reason == "lower_subset"
    assert evaluate(observation(200, FULL), observation(200)).reason == "status_only"
    duplicate = observation(200, raw=b'{"a": 1, "a": 2}')
    assert evaluate(duplicate, observation(200, {"a": 1})).body_superset is False
    assert evaluate(observation(200, raw=b'{"a": NaN}'), observation(200, {"a": 1})).verdict == "inconclusive"

    # Bounds: an over-deep or over-wide higher body is undetermined, never a finding.
    deep: dict = {}
    cursor = deep
    for _ in range(plan_differential.MAX_KEY_PATH_DEPTH + 2):
        cursor["k"] = {}
        cursor = cursor["k"]
    wide = {f"k{index}": index for index in range(plan_differential.MAX_KEY_PATH_NODES + 1)}
    for body in (deep, wide):
        with pytest.raises(plan_differential.BodyTooComplex):
            key_paths(body)
        result = evaluate(observation(200, body), observation(200, body))
        assert result.body_superset is None and result.evidence_state == "inconclusive"

    # Not completed, or evidence missing: row 1, nothing stored.
    for lower, higher, outcome, reason in (
        (None, None, ExecutorOutcome("incomplete", "inconclusive", "transport:dns_changed"), "transport:dns_changed"),
        (observation(200, FULL), None, COMPLETED, "evidence_unavailable"),
        (None, observation(200, FULL), COMPLETED, "evidence_unavailable"),
        (observation(200, FULL), observation(200, FULL), ExecutorOutcome("stopped", "inconclusive", "stopped"), "stopped"),
        (observation(200, FULL), observation(200, FULL), None, "evidence_unavailable"),
    ):
        result = evaluate(lower, higher, outcome=outcome)
        assert (result.row, result.verdict, result.evidence_state, result.reason) == (
            1, "inconclusive", None, reason,
        )
        assert result.stores_finding is False and result.candidate is False

    # An exception inside evaluation is inconclusive, never a pass.
    def explode(_value):
        raise RuntimeError("synthetic evaluation fault")

    monkeypatch.setattr(plan_differential, "key_paths", explode)
    result = evaluate(observation(403, ENVELOPE), observation(200, FULL))
    assert (result.verdict, result.evidence_state, result.reason, result.candidate) == (
        "inconclusive", "inconclusive", "predicate_error", False,
    )
    monkeypatch.undo()

    # `verified` only through row 3 and `observed` only through row 6, over a small grid.
    bodies = (None, FULL, SUBSET, ENVELOPE, protected(), {"ok": False}, {"rows": []})
    for lower_status in (200, 204, 302, 401, 403, 404, 500):
        for higher_status in (200, 204, 403):
            for lower_body in bodies:
                for higher_body in bodies:
                    for marker in (None, MARKER):
                        for outcome in ("observed", "blocked", "inconclusive"):
                            for method in ("GET", "HEAD"):
                                result = evaluate(
                                    observation(lower_status, lower_body),
                                    observation(higher_status, higher_body),
                                    method=method, marker=marker,
                                    outcome=ExecutorOutcome("completed", outcome),
                                )
                                assert (result.evidence_state == "verified") is (result.row == 3)
                                assert (result.evidence_state == "observed") is (result.row == 6)
                                assert (result.verdict == "held") is (result.row in {4, 7})
                                assert result.candidate is (result.row == 8)
                                if result.row == 3:
                                    assert marker and method == "GET" and outcome == "observed"
                                if result.row == 6:
                                    assert not marker and method == "GET"
                                    assert not is_denial_envelope(lower_body)
                                if result.verdict == "held":
                                    assert higher_status in {200, 204}
                                    assert not is_denial_envelope(higher_body)


def test_error_envelope_never_counts_as_parity():
    envelopes = (
        {"error": "upgrade required"}, {"errors": ["plan"]}, {"ok": False}, {"success": False},
        {"upgrade_required": True}, {"payment_required": True}, {"denied": True},
        {"forbidden": True},
        # An envelope that also carries every higher-plan key is still an envelope.
        {**FULL, "error": "upgrade required"},
    )
    for envelope in envelopes:
        assert is_denial_envelope(envelope) is True
        for lower_status in (200, 201, 204):
            result = evaluate(observation(lower_status, envelope), observation(200, FULL))
            # Undetermined: not True (no parity, no finding) and not False (no held, no pass).
            assert result.status_parity is None
            assert result.body_superset is None
            assert (result.verdict, result.evidence_state, result.reason, result.candidate) == (
                "inconclusive", "inconclusive", "lower_denial_envelope", False,
            )
        # The same envelope from the higher plan removes the positive control.
        assert evaluate(observation(200, FULL), observation(200, envelope)).row == 2

    # Without a marker an envelope is never held; a 4xx status is.
    assert evaluate(observation(403, ENVELOPE), observation(200, FULL)).verdict == "held"
    # With a marker, a 2xx envelope that still discloses the marker is a verified leak.
    leaked = evaluate(
        observation(200, {**protected(), "error": "upgrade required"}),
        observation(200, protected()), marker=MARKER,
        outcome=ExecutorOutcome("completed", "observed"),
    )
    assert leaked.evidence_state == "verified"

    # Near-misses are not envelopes. Non-boolean spellings of the vocabulary are envelopes
    # (T3 D1) and are pinned in tests/test_runner_plan_differential_redteam.py.
    for value in (
        {"error": ""}, {"error": None}, {"errors": []}, {"ok": True}, {"success": True},
        {"message": "upgrade"}, [], "error", None,
    ):
        assert is_denial_envelope(value) is False


def test_key_paths_are_structural_and_skip_secret_named_subtrees():
    value = {
        "a": 1, "b": {"c": [{"d": 1}, {"e": 2}], "token": {"hidden": 1}}, "list": [],
    }
    assert key_paths(value) == frozenset({
        "$.a", "$.b", "$.b.c", "$.b.c[]", "$.b.c[].d", "$.b.c[].e", "$.b.token", "$.list",
        "$.list[]",
    })
    assert key_paths({}) == frozenset()
    assert key_paths(3) == frozenset()


# --------------------------------------------------------------------------- #
# D4 (spec §8.6): body_superset needs a material superset as well as a key-path superset
# --------------------------------------------------------------------------- #
# Case ids are the §8.6 row ids. Expected columns: (row, reason, status_parity,
# body_superset, candidate).
D4_HIGHER = {
    "ok": True, "success": True, "status": "ok", "export_url": "https://files/x.csv", "rows": 3,
}
D4_HOLLOW_ECHO = {**D4_HIGHER, "rows": None}
D4_NESTED = {"a": {"b": "x", "c": 1}}
D4_ROWS = {"rows": [{"id": "r1", "amount": 1}]}
D4_TAGS = {"tags": ["a", "b"]}
D4_FINAL = {**D4_HIGHER, "export_url": None, "rows": None}
D4_OBSERVED = (6, "lower_superset", True, True, False)
D4_SUBSET = (8, "lower_subset", True, False, True)
D4_HOLLOW = (9, "lower_hollow_shape", None, None, False)


def _d4_without(value: dict, key: str) -> dict:
    return {name: item for name, item in value.items() if name != key}


def _d4_case(case_id, lower, higher, expected, *, statuses=(200,), method="GET"):
    return pytest.param(lower, higher, expected, statuses, method, id=case_id)


# Truth table T2: status 200 both sides, GET, no marker, positive control present.
D4_PAIR_ROWS = [
    _d4_case("missing_key", _d4_without(D4_HIGHER, "rows"), D4_HIGHER, D4_SUBSET),
    _d4_case("null_key", {**D4_HIGHER, "rows": None}, D4_HIGHER, D4_HOLLOW),
    _d4_case("empty_string", {**D4_HIGHER, "export_url": ""}, D4_HIGHER, D4_HOLLOW),
    _d4_case("empty_list_for_scalar", {**D4_HIGHER, "rows": []}, D4_HIGHER, D4_HOLLOW),
    _d4_case("empty_object_for_scalar", {**D4_HIGHER, "rows": {}}, D4_HIGHER, D4_HOLLOW),
    _d4_case(
        "false_for_true", {**D4_HIGHER, "verified": False}, {**D4_HIGHER, "verified": True},
        D4_HOLLOW,
    ),
    _d4_case("zero_for_three", {**D4_HIGHER, "rows": 0}, D4_HIGHER, D4_HOLLOW),
    _d4_case("zero_float", {**D4_HIGHER, "rows": 0.0}, D4_HIGHER, D4_HOLLOW),
    _d4_case(
        "different_string", {**D4_HIGHER, "export_url": "https://files/other.csv"}, D4_HIGHER,
        D4_OBSERVED,
    ),
    _d4_case("different_number", {**D4_HIGHER, "rows": 7}, D4_HIGHER, D4_OBSERVED),
    _d4_case("negative_number", {**D4_HIGHER, "rows": -1}, D4_HIGHER, D4_OBSERVED),
    _d4_case("string_for_number", {**D4_HIGHER, "rows": "seven"}, D4_HIGHER, D4_OBSERVED),
    _d4_case("number_for_string", {**D4_HIGHER, "export_url": 42}, D4_HIGHER, D4_OBSERVED),
    _d4_case("true_for_string", {**D4_HIGHER, "export_url": True}, D4_HIGHER, D4_OBSERVED),
    _d4_case("whitespace_string", {**D4_HIGHER, "export_url": " "}, D4_HIGHER, D4_OBSERVED),
    _d4_case("string_zero", {**D4_HIGHER, "rows": "0"}, D4_HIGHER, D4_OBSERVED),
    _d4_case("list_for_scalar", {**D4_HIGHER, "rows": [1]}, D4_HIGHER, D4_OBSERVED),
    _d4_case("object_for_scalar", {**D4_HIGHER, "rows": {"n": 1}}, D4_HIGHER, D4_OBSERVED),
    _d4_case(
        "nested_same_shape_other_values", {"a": {"b": "y", "c": 2}}, D4_NESTED, D4_OBSERVED,
    ),
    _d4_case("nested_null_leaf", {"a": {"b": None, "c": 2}}, D4_NESTED, D4_HOLLOW),
    _d4_case("nested_empty_object", {"a": {}}, {"a": {"b": "x"}}, D4_SUBSET),
    _d4_case(
        "list_rows_other_values", {"rows": [{"id": "z", "amount": 9}]}, D4_ROWS, D4_OBSERVED,
    ),
    _d4_case(
        "list_rows_null_stuffed", {"rows": [{"id": None, "amount": None}]}, D4_ROWS, D4_HOLLOW,
    ),
    _d4_case(
        "list_rows_one_material_element",
        {"rows": [{"id": None, "amount": None}, {"id": "z", "amount": 2}]}, D4_ROWS,
        D4_OBSERVED,
    ),
    _d4_case("list_empty_for_populated", {"rows": []}, {"rows": [{"id": "r1"}]}, D4_SUBSET),
    _d4_case("list_of_nulls_for_scalars", {"tags": [None]}, D4_TAGS, D4_HOLLOW),
    _d4_case("list_fewer_elements", {"tags": ["z"]}, D4_TAGS, D4_OBSERVED),
    _d4_case("higher_null_lower_null", {"a": 1, "b": None}, {"a": 1, "b": None}, D4_OBSERVED),
    _d4_case(
        "higher_null_lower_material", {"a": 2, "b": "x"}, {"a": 1, "b": None}, D4_OBSERVED,
    ),
    _d4_case(
        "higher_empty_list_lower_empty_list", {"a": 1, "b": []}, {"a": 1, "b": []}, D4_OBSERVED,
    ),
    _d4_case("higher_empty_list_lower_null", {"a": 1, "b": None}, {"a": 1, "b": []}, D4_SUBSET),
    _d4_case(
        "higher_false_lower_false", {"a": 1, "f": False}, {"a": 1, "f": False}, D4_OBSERVED,
    ),
    _d4_case("higher_false_lower_true", {"a": 1, "f": True}, {"a": 1, "f": False}, D4_OBSERVED),
    _d4_case("higher_all_hollow", {"a": None, "b": ""}, {"a": None, "b": ""}, D4_OBSERVED),
    _d4_case(
        "mixed_one_hollow", {**D4_HIGHER, "export_url": "https://files/y.csv", "rows": None},
        D4_HIGHER, D4_HOLLOW,
    ),
    _d4_case(
        "mixed_extra_keys_hollow", {**D4_HIGHER, "rows": None, "extra": "more"}, D4_HIGHER,
        D4_HOLLOW,
    ),
    _d4_case("extra_hollow_keys_only", {**D4_HIGHER, "extra": None}, D4_HIGHER, D4_OBSERVED),
    _d4_case(
        "final_status_false", {**D4_FINAL, "status": False, "message": "Upgrade required"},
        D4_HIGHER, D4_HOLLOW,
    ),
    _d4_case(
        "final_message_only", {**D4_FINAL, "message": "Upgrade required"}, D4_HIGHER, D4_HOLLOW,
    ),
    _d4_case(
        "final_PAYMENTREQUIRED", {**D4_FINAL, "code": "PAYMENTREQUIRED"}, D4_HIGHER, D4_HOLLOW,
    ),
    _d4_case(
        "final_accessdenied", {**D4_FINAL, "status": "accessdenied"}, D4_HIGHER, D4_HOLLOW,
    ),
    _d4_case(
        "denial_and_hollow", {**D4_FINAL, "ok": False}, D4_HIGHER,
        (9, "lower_denial_envelope", None, None, False),
    ),
]
# Truth table T3 rows that are decided by the pure verdict function.
D4_ORDER_ROWS = [
    _d4_case(
        "hollow_higher_denial_is_row_2", D4_HOLLOW_ECHO, {**D4_HIGHER, "ok": False},
        (2, "no_positive_control", None, None, False),
    ),
    _d4_case(
        "hollow_lower_denial_status_is_held", D4_HOLLOW_ECHO, D4_HIGHER,
        (7, "lower_denied", False, False, False), statuses=(403,),
    ),
    _d4_case(
        "hollow_lower_500_is_unexpected", D4_HOLLOW_ECHO, D4_HIGHER,
        (9, "unexpected_status", None, False, False), statuses=(500,),
    ),
    _d4_case(
        "hollow_lower_201_204_299", D4_HOLLOW_ECHO, D4_HIGHER, D4_HOLLOW,
        statuses=(201, 204, 299),
    ),
    _d4_case(
        "head_unaffected", D4_HOLLOW_ECHO, D4_HIGHER,
        (8, "head_status_only", True, None, True), method="HEAD",
    ),
    _d4_case(
        "secret_key_never_material", {"a": 1, "token": None}, {"a": 1, "token": "abc"},
        D4_OBSERVED,
    ),
]
D4_BY_ID = {case.id: case.values for case in D4_PAIR_ROWS + D4_ORDER_ROWS}
# The T2 row-6 rows whose lower body differs from the higher body in value or type.
D4_SAME_SHAPE_IDS = (
    "different_string", "different_number", "negative_number", "string_for_number",
    "number_for_string", "true_for_string", "whitespace_string", "string_zero",
    "list_for_scalar", "object_for_scalar", "nested_same_shape_other_values",
    "list_rows_other_values", "list_fewer_elements", "higher_null_lower_material",
    "higher_false_lower_true",
)
D4_HOLLOW_IDS = (
    "null_key", "empty_string", "zero_for_three", "list_rows_null_stuffed", "final_message_only",
)
D4_MARKER_HIGHER = {"protected_canary": MARKER, "rows": [{"id": "r1"}], "n": 1}
D4_MARKER_HOLLOW = {"protected_canary": MARKER, "rows": [{"id": None}], "n": None}
D4_MARKER_ABSENT = {"protected_canary": "", "rows": [{"id": None}], "n": None}
# The bodies of test_redteam_holds_affirmative_bodies_keep_the_positive_control.
D4_GUARD_BODIES = [
    {"ok": "yes", "rows": 3}, {"ok": 1.0, "rows": 3}, {"success": "true", "rows": 3},
    {"denied": "no", "rows": 3}, {"denied": "", "rows": 3}, {"denied": None, "rows": 3},
    {"forbidden": 0, "upgrade_required": "false", "rows": 3},
    {"error": None, "errors": [], "rows": 3},
    {"status": 200.0, "rows": 3}, {"status": "ok", "code": "OK", "rows": 3},
    {"items": [{"status": "error", "code": 403, "denied": True, "ok": False}], "total": 1},
]


def _d4_columns(result):
    return (
        result.row, result.reason, result.status_parity, result.body_superset, result.candidate,
    )


def _d4_complex_bodies() -> dict[str, dict]:
    deep: dict = {}
    cursor = deep
    for _ in range(plan_differential.MAX_KEY_PATH_DEPTH + 2):
        cursor["k"] = {}
        cursor = cursor["k"]
    wide = {f"k{index}": index for index in range(plan_differential.MAX_KEY_PATH_NODES + 1)}
    return {"deep": deep, "wide": wide}


# Truth table T1, as JSON text so the parsed value is the one the product walks.
@pytest.mark.parametrize("text,material", [
    ("null", False), ("false", False), ("0", False), ("0.0", False), ("-0.0", False),
    ("0e0", False), ('""', False), ("[]", False), ("{}", False),
    ('"x"', True), ('"0"', True), ('"false"', True), ('"null"', True), ('" "', True),
    ("1", True), ("-1", True), ("0.5", True), (str(2 ** 60), True), ("1e-9", True),
    ("true", True), ("[0]", True), ("[null]", True), ('[""]', True), ('{"a": null}', True),
    ('["a"]', True), ('{"a": 1}', True),
], ids=lambda value: value if isinstance(value, str) else None)
def test_d4_truthy_leaf_table(text, material):
    value = plan_differential._parsed(f'{{"k": {text}}}'.encode())
    assert ("$.k" in plan_differential.material_paths(value)) is material
    assert "$.k" in key_paths(value)
    # Only the container path of a non-truthy element or member is material.
    assert plan_differential.material_paths(value) <= (
        {"$.k", "$.k[]", "$.k.a"} if text in {'["a"]', '{"a": 1}'} else {"$.k"}
    )
    # Absent: no path at all.
    assert plan_differential.material_paths({}) == frozenset()
    # Under a secret-named key the path is kept, never material and not descended.
    secret = plan_differential._parsed(f'{{"token": {text}, "api_key": {{"inner": {text}}}}}'.encode())
    assert key_paths(secret) == frozenset({"$.token", "$.api_key"})
    assert plan_differential.material_paths(secret) == frozenset()


def test_d4_material_paths_are_structural_and_bounded():
    material_paths = plan_differential.material_paths
    assert "material_paths" in plan_differential.__all__
    value = {
        "a": 1, "b": {"c": [{"d": 1}, {"e": None}], "token": {"hidden": 1}}, "list": [],
        "z": None, "n": [None, 0], "m": [{"x": None}, {"x": "v"}], "o": [{"y": 0}, {"y": ""}],
    }
    assert material_paths(value) == frozenset({
        "$.a", "$.b", "$.b.c", "$.b.c[]", "$.b.c[].d", "$.n", "$.m", "$.m[]", "$.m[].x",
        "$.o", "$.o[]",
    })
    for scalar in ({}, [], 3, 0, "x", "", None, True):
        assert material_paths(scalar) == frozenset()
    assert material_paths([0, None]) == frozenset()
    assert material_paths([0, "x"]) == frozenset({"$[]"})

    # Same bounds and the same exception as key_paths, at every size around both limits.
    def raises(function, body) -> bool:
        try:
            function(body)
        except plan_differential.BodyTooComplex:
            return True
        return False

    for body in _d4_complex_bodies().values():
        with pytest.raises(plan_differential.BodyTooComplex):
            material_paths(body)
    for depth in range(plan_differential.MAX_KEY_PATH_DEPTH - 2, plan_differential.MAX_KEY_PATH_DEPTH + 3):
        for leaf in (None, 1):
            nested = leaf
            for _ in range(depth):
                nested = {"k": nested}
            assert raises(material_paths, nested) is raises(key_paths, nested)
    for width in range(plan_differential.MAX_KEY_PATH_NODES - 2, plan_differential.MAX_KEY_PATH_NODES + 3):
        for leaf in (None, 1):
            flat = {f"k{index}": leaf for index in range(width)}
            assert raises(material_paths, flat) is raises(key_paths, flat)
            assert raises(material_paths, list(flat.values())) is raises(key_paths, list(flat.values()))

    # A material path is always a key path, for every body of this file.
    bodies = [FULL, SUBSET, ENVELOPE, protected(), {"rows": []}, value, *D4_GUARD_BODIES,
              D4_MARKER_HIGHER, D4_MARKER_HOLLOW, D4_MARKER_ABSENT]
    for lower, higher, *_ in D4_BY_ID.values():
        bodies += [lower, higher]
    for body in bodies:
        assert material_paths(body) <= key_paths(body)
        assert material_paths(body) == material_paths(json.loads(json.dumps(body)))


@pytest.mark.parametrize("lower,higher,expected,statuses,method", D4_PAIR_ROWS + D4_ORDER_ROWS)
def test_d4_verdict_truth_table(lower, higher, expected, statuses, method):
    assert len(D4_PAIR_ROWS) == 42 and len(D4_BY_ID) == 48
    for status in statuses:
        result = evaluate(observation(status, lower), observation(200, higher), method=method)
        assert _d4_columns(result) == expected, status
        row = expected[0]
        assert result.verdict == ("finding" if row == 6 else "held" if row == 7 else "inconclusive")
        assert result.evidence_state == (
            "observed" if row == 6 else None if row == 7 else "inconclusive"
        )
        assert result.stores_finding is (row != 7)
        assert result.predicate == (
            "body_superset" if row == 6 else "status_parity" if row in {7, 8} else "inconclusive"
        )
        assert result.positive_control is (row != 2)
        assert result.marker_leak is None
        # A hollow lower body is never a regression pass: not observed and not held.
        if expected == D4_HOLLOW:
            assert result.body_superset is None and result.verdict != "held"


@pytest.mark.parametrize("case_id", [*D4_SAME_SHAPE_IDS, "account_specific_values"])
def test_d4_same_shape_different_values_stay_observed(case_id):
    if case_id == "account_specific_values":
        higher = {
            "account_id": "acct_pro_0091", "tenant": "tenant-pro", "plan": "pro",
            "owner": {"name": "Pat Pro", "email": "pat@pro.example", "seats": 25},
            "export_url": "https://files.example/pro/0091/export.csv",
            "rows": [{"id": "r1", "amount": 12.5, "paid": True}, {"id": "r2", "amount": 3, "paid": True}],
            "total": 2,
        }
        lower = {
            "account_id": "acct_free_7302", "tenant": "tenant-free", "plan": "free",
            "owner": {"name": "Fran Free", "email": "fran@free.example", "seats": 1},
            "export_url": "https://files.example/free/7302/export.csv",
            "rows": [{"id": "z9", "amount": 0.25, "paid": 1}],
            "total": 1,
        }
    else:
        lower, higher, expected, _statuses, _method = D4_BY_ID[case_id]
        assert expected == D4_OBSERVED
    assert lower != higher
    result = evaluate(observation(200, lower), observation(200, higher))
    assert (result.verdict, result.evidence_state, result.row) == ("finding", "observed", 6)
    assert _d4_columns(result) == D4_OBSERVED

    # Value-blind: any truthy value of any JSON type at a populated path changes nothing.
    for key in ("export_url", "rows"):
        for replacement in ("x", "0", " ", 7, -1, 0.5, 2 ** 60, True, [0], [None], {"n": None}):
            result = evaluate(
                observation(200, {**D4_HIGHER, key: replacement}), observation(200, D4_HIGHER),
            )
            assert _d4_columns(result) == D4_OBSERVED, (key, replacement)


@pytest.mark.parametrize("case_id", [
    *D4_HOLLOW_IDS, "marker_present_in_hollow_body", "marker_undetermined_in_hollow_body",
    "marker_absent_hollow_body",
])
def test_d4_hollow_shape_is_never_observed_candidate_or_held(case_id):
    def marker_pair(lower, outcome):
        return evaluate(
            observation(200, lower), observation(200, D4_MARKER_HIGHER), marker=MARKER,
            outcome=ExecutorOutcome("completed", outcome),
        )

    if case_id.startswith("marker_"):
        # Without the marker each lower body is a hollow shape of the higher body.
        for lower in (D4_MARKER_HOLLOW, D4_MARKER_ABSENT):
            assert _d4_columns(
                evaluate(observation(200, lower), observation(200, D4_MARKER_HIGHER))
            ) == D4_HOLLOW
    if case_id == "marker_present_in_hollow_body":
        result = marker_pair(D4_MARKER_HOLLOW, "observed")
        assert (result.row, result.verdict, result.evidence_state, result.reason) == (
            3, "finding", "verified", "marker_present",
        )
        assert result.marker_leak is True and result.candidate is False
        return
    if case_id == "marker_undetermined_in_hollow_body":
        result = marker_pair(D4_MARKER_HOLLOW, "inconclusive")
        assert (result.row, result.verdict, result.evidence_state, result.reason) == (
            5, "inconclusive", "inconclusive", "marker_undetermined",
        )
        return
    if case_id == "marker_absent_hollow_body":
        # P(lower) is undetermined for this body, so the pair is row 5; where the content
        # predicate can say the marker is absent, the pair is held on row 4. Never row 6.
        result = marker_pair(D4_MARKER_ABSENT, "blocked")
        assert (result.row, result.verdict, result.reason) == (5, "inconclusive", "marker_undetermined")
        result = marker_pair({**D4_MARKER_ABSENT, "visibility": "redacted"}, "blocked")
        assert (result.row, result.verdict, result.evidence_state, result.reason) == (
            4, "held", None, "marker_absent",
        )
        assert result.stores_finding is False
        return

    base_lower, base_higher, expected, _statuses, _method = D4_BY_ID[case_id]
    assert expected == D4_HOLLOW
    rows = set()
    for lower_status in (200, 201, 204, 299):
        for marker in (None, MARKER):
            # With a marker the higher body carries it; the lower body carries it, carries an
            # empty field, omits it, or is marked as a redacted view.
            pairs = [(base_lower, base_higher)] if marker is None else [
                ({**base_lower, **extra}, {**base_higher, "protected_canary": MARKER})
                for extra in (
                    {"protected_canary": MARKER}, {"protected_canary": ""}, {},
                    {"visibility": "redacted"},
                )
            ]
            for lower, higher in pairs:
                for outcome in ("observed", "blocked", "inconclusive"):
                    for method in ("GET", "HEAD"):
                        result = evaluate(
                            observation(lower_status, lower), observation(200, higher),
                            method=method, marker=marker,
                            outcome=ExecutorOutcome("completed", outcome),
                        )
                        rows.add(result.row)
                        assert result.evidence_state != "observed" and result.row != 6
                        assert result.body_superset is not True
                        assert result.candidate is (result.row == 8)
                        assert not result.candidate or method == "HEAD"
                        assert (result.verdict == "held") is (result.row == 4)
                        assert (result.evidence_state == "verified") is (result.row == 3)
                        if result.row == 3:
                            assert method == "GET" and outcome == "observed"
                            assert lower.get("protected_canary") == MARKER
                        if marker is None and method == "GET":
                            assert _d4_columns(result) == D4_HOLLOW
                            assert (result.verdict, result.stores_finding) == ("inconclusive", True)
                        if marker is None and method == "HEAD":
                            assert _d4_columns(result) == (8, "head_status_only", True, None, True)
    assert rows == {2, 3, 4, 5, 8, 9}


@pytest.mark.parametrize("case_id", ["bounds_wide_or_deep_body"])
def test_d4_bounds_leave_body_superset_undetermined(case_id, monkeypatch):
    status_only = (8, "status_only", True, None, True)
    for name, body in _d4_complex_bodies().items():
        for function in (key_paths, plan_differential.material_paths):
            with pytest.raises(plan_differential.BodyTooComplex):
                function(body)
        hollow = (
            {key: None for key in body} if name == "wide" else {"k": None}
        )
        # Either side, and a non-truthy lower body in the same over-bound pair: undetermined,
        # never hollow, never a finding.
        for lower, higher in ((body, body), (body, FULL), (FULL, body), (hollow, body)):
            result = evaluate(observation(200, lower), observation(200, higher))
            assert _d4_columns(result) == status_only, name
            assert result.evidence_state == "inconclusive"

    # A bound hit by the material walk alone has the same effect as one hit by key_paths.
    lower, higher = D4_BY_ID["null_key"][:2]
    assert _d4_columns(evaluate(observation(200, lower), observation(200, higher))) == D4_HOLLOW

    def too_complex(_value):
        raise plan_differential.BodyTooComplex("response body exceeds the key-path bound")

    monkeypatch.setattr(plan_differential, "material_paths", too_complex)
    for lower_body in (lower, higher):
        result = evaluate(observation(200, lower_body), observation(200, higher))
        assert _d4_columns(result) == status_only


@pytest.mark.parametrize("case_id", ["reflexive_guards", "FULL", "SUBSET", "protected", "empty_rows"])
def test_d4_reflexive_bodies_unchanged(case_id):
    bodies = {
        "reflexive_guards": D4_GUARD_BODIES, "FULL": [FULL], "SUBSET": [SUBSET],
        "protected": [protected()], "empty_rows": [{"rows": []}],
    }[case_id]
    assert len(D4_GUARD_BODIES) == 11
    for body in bodies:
        assert plan_differential.material_paths(body) <= key_paths(body)
        result = evaluate(observation(200, body), observation(200, body))
        assert (result.verdict, result.evidence_state) == ("finding", "observed")
        assert _d4_columns(result) == D4_OBSERVED
    # Every §8.6 body is observed against itself, hollow lower bodies included.
    for lower, higher, *_ in D4_BY_ID.values():
        for body in (lower, higher):
            if is_denial_envelope(body):
                continue
            result = evaluate(observation(200, body), observation(200, body))
            assert _d4_columns(result) == D4_OBSERVED, body
