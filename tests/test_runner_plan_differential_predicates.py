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

    # The list is closed: near-misses are not envelopes.
    for value in (
        {"error": ""}, {"error": None}, {"errors": []}, {"ok": True}, {"success": True},
        {"ok": 0}, {"denied": "true"}, {"forbidden": 1}, {"message": "upgrade"}, [], "error", None,
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
