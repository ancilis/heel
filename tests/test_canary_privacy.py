from __future__ import annotations

import copy

import pytest

from heel.canary_contracts import canonical_bytes, canonical_digest

from canary_test_support import PROJECT, RUNNER, WORKSPACE
from test_canary_disclosure import (
    _findings,
    _permit,
    _preview,
    _terminal_setup,
    _upload,
)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("raw_traffic",), {"authorization": "Bearer private"}),
        (("scenario_results", 0, "credential_handle"), "cred_local"),
        (("scenario_results", 0, "fixture_bindings"), {"id": "customer-123"}),
        (("scenario_results", 0, "observations", 0, "response"), {"body": "private"}),
        (("scenario_results", 0, "local_evidence_refs"), ["/tmp/raw-response.json"]),
    ],
)
def test_findings_upload_recursively_rejects_raw_credential_fixture_and_local_path_leakage(
    path, value
):
    conn, _, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    permit = _permit(service, grant, _preview(service, grant, findings))
    changed = copy.deepcopy(findings)
    cursor = changed
    for component in path[:-1]:
        cursor = cursor[component]
    cursor[path[-1]] = value
    unsigned = {
        key: item
        for key, item in changed.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    changed["projection_digest"] = canonical_digest(unsigned)
    changed.update(runner.sign(canonical_bytes(unsigned)))

    with pytest.raises(ValueError) as failure:
        service.upload(
            WORKSPACE, PROJECT, grant["run_id"], RUNNER, _upload(grant, permit, changed)
        )
    assert failure.value.code == "invalid_canary_projection"
    assert (
        conn.execute("SELECT COUNT(*) FROM canary_findings_projections").fetchone()[0]
        == 0
    )


def test_operational_cloud_storage_cannot_be_repurposed_for_blocked_or_observed_assessment():
    conn, _, runner, service, grant, operational = _terminal_setup()
    serialized = conn.execute(
        "SELECT receipt_json FROM canary_operational_receipts WHERE run_id=?",
        (grant["run_id"],),
    ).fetchone()[0]
    assert "blocked" not in serialized
    assert "observed" not in serialized
    assert "assessment" not in serialized
    assert (
        conn.execute("SELECT COUNT(*) FROM canary_findings_projections").fetchone()[0]
        == 0
    )
