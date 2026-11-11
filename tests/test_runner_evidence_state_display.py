"""G-ES: ``heel runner findings`` shows a derived, unsigned ``evidence_states`` display list.

The list is computed from the already store-verified terminal local view and sits beside it at
the top level. Every signed object (the findings projection with its five-field ``finding``,
the operational projection) is printed byte-for-byte as stored; nothing is added inside them.
Uses the real paired journey from ``tests/test_runner_paired_plan_differential.py``.
"""
from __future__ import annotations

import copy
import json

from heel.canary_contracts import canonical_bytes, validate_canary_findings
from heel.runner.regressions import evidence_states_for
from tests.test_runner_daemon import serve_harness  # noqa: F401 - fixture by name
from tests.test_runner_paired_plan_differential import (  # noqa: F401 - fixture by name
    CANARY, CANARY_ROUTE, FORBIDDEN_PROJECTION_TEXT, SCENARIO, customer,
)


def _shown(customer, mode):
    """Run one paired journey and return (raw stdout, parsed output, stored local view)."""
    _prepared, shown = customer.submit()
    customer.execute(shown, mode)
    code, output, error = customer.cli("runner", "findings", "--run", shown["run_id"])
    assert (code, error) == (0, "")
    stored = customer.store.load_final_projections(shown["run_id"])
    return output, json.loads(output), stored


def _assert_display_only(output, parsed, stored, expected_state):
    view = stored["local_view"]
    assert set(parsed) == set(view) | {"evidence_states"}
    # Signed objects are unchanged byte-for-byte (canonical form) and still validate.
    for key in ("findings_projection", "operational_projection"):
        assert canonical_bytes(parsed[key]) == canonical_bytes(view[key])
    assert canonical_bytes(parsed["findings_projection"]) == canonical_bytes(
        stored["findings_projection"])
    assert validate_canary_findings(parsed["findings_projection"]) == stored["findings_projection"]
    assert "evidence_state" not in json.dumps(parsed["findings_projection"])
    # Everything except the display key renders exactly as the pre-G-ES output did.
    rest = {key: value for key, value in parsed.items() if key != "evidence_states"}
    assert json.dumps(rest, sort_keys=True) == json.dumps(view, sort_keys=True)
    # Pure: deriving the list leaves the verified view untouched.
    before = copy.deepcopy(view)
    assert evidence_states_for(view) == parsed["evidence_states"]
    assert view == before
    (result,) = [item for item in parsed["evidence_states"] if item["scenario_id"] == SCENARIO]
    assert result == {"ordinal": result["ordinal"], "scenario_id": SCENARIO,
                      "evidence_state": expected_state}
    assert [item["ordinal"] for item in parsed["evidence_states"]] == [
        item["ordinal"] for item in view["findings_projection"]["scenario_results"]]
    for text in FORBIDDEN_PROJECTION_TEXT:
        assert text not in output
    assert "local_evidence_refs" not in json.dumps(parsed["evidence_states"])


def test_ordinary_markerless_observed_finding_displays_observed(customer):
    customer.configure()
    output, parsed, stored = _shown(customer, "vulnerable")
    _assert_display_only(output, parsed, stored, "observed")


def test_marker_bound_canary_finding_displays_verified(customer):
    customer.configure(route=CANARY_ROUTE, fixture=CANARY)
    output, parsed, stored = _shown(customer, "vulnerable")
    _assert_display_only(output, parsed, stored, "verified")


def test_patched_lower_plan_displays_held(customer):
    customer.configure()
    output, parsed, stored = _shown(customer, "patched")
    _assert_display_only(output, parsed, stored, "held")


def test_denial_envelope_displays_inconclusive(customer):
    customer.configure()
    output, parsed, stored = _shown(customer, "envelope")
    _assert_display_only(output, parsed, stored, "inconclusive")
