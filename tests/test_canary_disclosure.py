from __future__ import annotations

import base64
import copy

import pytest

from heel.canary_contracts import (
    CANARY_FINDINGS_SCHEMA,
    canonical_bytes,
    canonical_digest,
    validate_disclosure_permit,
)
from heel.crypto import SigningAuthority, verify_envelope

from canary_test_support import (
    Clock,
    ENVIRONMENT,
    NOW_MS,
    PROJECT,
    RUNNER,
    WORKSPACE,
    connect,
    operational_projection,
    seed_authority,
    submit_and_approve,
)


def _terminal_setup():
    from heel.saas.runner_auth import RunnerAuthStore, initialize_runner_auth_schema

    conn = connect()
    runner = seed_authority(conn)
    initialize_runner_auth_schema(conn)
    clock = Clock()
    auth = RunnerAuthStore(conn, pepper=b"d" * 32, now=clock)
    coordinator, _, approved = submit_and_approve(
        conn,
        clock,
        runner,
        runner_auth=auth,
    )
    coordinator.claim(WORKSPACE, RUNNER, runner.key_id)
    grant = approved["grant"]
    operational = operational_projection(
        runner,
        grant,
        sequence=0,
        phase="terminal",
        disposition="completed",
    )
    coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, operational)
    service = _service(conn, clock)
    return conn, clock, runner, service, grant, operational


def _service(conn, clock):
    from heel.saas.canary_disclosure import CanaryDisclosureService

    return CanaryDisclosureService(
        conn,
        signing=SigningAuthority.generate(),
        clock=clock,
    )


def _findings(runner, grant, operational, *, title="Canary boundary observed"):
    value = {
        "schema_version": CANARY_FINDINGS_SCHEMA,
        "projection_id": "cfp_canary",
        "run_id": grant["run_id"],
        "grant_id": grant["grant_id"],
        "workspace_id": WORKSPACE,
        "project_id": PROJECT,
        "environment_id": ENVIRONMENT,
        "manifest_digest": grant["approval"]["manifest_digest"],
        "approval_projection_digest": grant["approval"]["projection_digest"],
        "grant_digest": grant["grant_digest"],
        "engine_version": operational["versions"]["engine_version"],
        "adapter_versions": operational["versions"]["adapter_versions"],
        "started_at_ms": operational["timestamps"]["started_at_ms"],
        "finished_at_ms": operational["timestamps"]["terminal_at_ms"],
        "assessment_outcome": "observed",
        "scenario_results": [
            {
                "ordinal": 0,
                "scenario_id": "anonymous_authenticated_read",
                "adapter_version": "1.0.0",
                "assessment_outcome": "observed",
                "route": {"method": "GET", "route_template": "/api/canary"},
                "observations": [
                    {
                        "semantic_role": "anonymous",
                        "status_code": 200,
                        "body_shape": "json_object",
                        "truncation_state": "complete",
                    }
                ],
                "finding": {
                    "title": title,
                    "reachability_rationale": "The bounded canary read returned the protected shape.",
                    "confidence": "high",
                    "recommended_control": "Enforce tenant authorization before reading the object.",
                    "regression_suggestion": "Keep the canary ownership differential in CI.",
                },
                "containment_codes": operational["containment_codes"],
                "redaction_count": operational["redaction_count"],
                "local_evidence_refs": ["ev1_" + "a" * 64],
            }
        ],
        "containment_codes": operational["containment_codes"],
        "redaction_count": operational["redaction_count"],
    }
    value["projection_digest"] = canonical_digest(value)
    value.update(
        runner.sign(
            canonical_bytes(
                {key: item for key, item in value.items() if key != "projection_digest"}
            )
        )
    )
    return value


def _preview(service, grant, findings):
    return service.preview(
        WORKSPACE,
        PROJECT,
        grant["run_id"],
        runner_id=RUNNER,
        runner_key_id=findings["signing_key_id"],
        projection_schema_version=findings["schema_version"],
        projection_digest=findings["projection_digest"],
        byte_count=len(canonical_bytes(findings)),
        scenario_count=len(findings["scenario_results"]),
        finding_count=sum(
            item["finding"] is not None for item in findings["scenario_results"]
        ),
    )


def _permit(service, grant, preview, *, recent_auth_at_ms=NOW_MS):
    projection = preview["projection"]
    return service.permit(
        WORKSPACE,
        PROJECT,
        grant["run_id"],
        request_id=preview["request_id"],
        projection_schema_version=projection["schema_version"],
        projection_digest=projection["projection_digest"],
        byte_count=projection["byte_count"],
        scenario_count=projection["scenario_count"],
        finding_count=projection["finding_count"],
        actor="user_owner",
        role="owner",
        recent_auth_at_ms=recent_auth_at_ms,
    )


def _upload(grant, permit, findings):
    return {
        "schema_version": "heel.runner-findings-upload.v1",
        "run_id": grant["run_id"],
        "permit": permit,
        "findings_projection": findings,
    }


def test_preview_requires_terminal_operational_result_and_stores_metadata_only():
    from heel.saas.runner_auth import RunnerAuthStore, initialize_runner_auth_schema

    conn = connect()
    runner = seed_authority(conn)
    initialize_runner_auth_schema(conn)
    clock = Clock()
    coordinator, _, approved = submit_and_approve(
        conn,
        clock,
        runner,
        runner_auth=RunnerAuthStore(conn, pepper=b"d" * 32, now=clock),
    )
    service = _service(conn, clock)
    grant = approved["grant"]
    fake_operational = operational_projection(
        runner,
        grant,
        sequence=0,
        phase="terminal",
        disposition="completed",
    )
    findings = _findings(runner, grant, fake_operational)

    with pytest.raises(ValueError) as failure:
        _preview(service, grant, findings)
    assert failure.value.code == "canary_state_conflict"
    assert (
        conn.execute("SELECT COUNT(*) FROM canary_disclosure_requests").fetchone()[0]
        == 0
    )

    coordinator.claim(WORKSPACE, RUNNER, runner.key_id)
    coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, fake_operational)
    preview = _preview(service, grant, findings)

    assert preview == {
        "schema_version": "heel.canary-disclosure-preview.v1",
        "request_id": preview["request_id"],
        "run_id": grant["run_id"],
        "status": "local_result_ready",
        "projection": {
            "schema_version": CANARY_FINDINGS_SCHEMA,
            "projection_digest": findings["projection_digest"],
            "byte_count": len(canonical_bytes(findings)),
            "scenario_count": 1,
            "finding_count": 1,
        },
    }
    row = dict(conn.execute("SELECT * FROM canary_disclosure_requests").fetchone())
    serialized = canonical_bytes(row).decode()
    for private in (
        "assessment_outcome",
        "scenario_results",
        "Canary boundary observed",
    ):
        assert private not in serialized
    operational_json = conn.execute(
        "SELECT receipt_json FROM canary_operational_receipts"
    ).fetchone()[0]
    for private in ("assessment_outcome", "scenario_results", "finding"):
        assert private not in operational_json


def test_permit_rechecks_membership_recent_auth_and_signs_exact_metadata_only():
    conn, clock, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    preview = _preview(service, grant, findings)

    with pytest.raises(ValueError) as stale:
        service.permit(
            WORKSPACE,
            PROJECT,
            grant["run_id"],
            request_id=preview["request_id"],
            projection_schema_version=CANARY_FINDINGS_SCHEMA,
            projection_digest=findings["projection_digest"],
            byte_count=len(canonical_bytes(findings)),
            scenario_count=1,
            finding_count=1,
            actor="user_owner",
            role="owner",
            recent_auth_at_ms=NOW_MS - 900_001,
        )
    assert stale.value.code == "disclosure_permit_required"

    conn.execute(
        "UPDATE memberships SET role='member' WHERE workspace_id=? AND user_id=?",
        (WORKSPACE, "user_owner"),
    )
    conn.commit()
    with pytest.raises(ValueError) as wrong_role:
        _permit(service, grant, preview)
    assert wrong_role.value.code == "disclosure_permit_required"
    conn.execute(
        "UPDATE memberships SET role='owner' WHERE workspace_id=? AND user_id=?",
        (WORKSPACE, "user_owner"),
    )
    conn.commit()

    permit = validate_disclosure_permit(_permit(service, grant, preview))
    unsigned = {
        key: value
        for key, value in permit.items()
        if key not in {"permit_digest", "signing_key_id", "signature_b64"}
    }
    verify_envelope(
        {service.signing.key_id: service.signing.public_key},
        {
            "signing_key_id": permit["signing_key_id"],
            "signature_b64": permit["signature_b64"],
        },
        canonical_bytes(unsigned),
    )
    assert permit["projection"] == {
        "schema_version": CANARY_FINDINGS_SCHEMA,
        "projection_digest": findings["projection_digest"],
        "maximum_bytes": len(canonical_bytes(findings)),
        "scenario_count": 1,
        "finding_count": 1,
    }
    assert permit["expires_at_ms"] == permit["issued_at_ms"] + 600_000
    permit_json = canonical_bytes(permit).decode()
    assert "Canary boundary observed" not in permit_json
    assert (
        conn.execute("SELECT status FROM canary_disclosure_requests").fetchone()[0]
        == "permitted"
    )


def test_permit_retry_never_returns_a_corrupted_persisted_authority_envelope():
    conn, _, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    preview = _preview(service, grant, findings)
    permit = _permit(service, grant, preview)
    corrupted = copy.deepcopy(permit)
    corrupted["signature_b64"] = base64.b64encode(b"\x00" * 64).decode()
    conn.execute(
        "UPDATE canary_disclosure_permits SET permit_json=? WHERE permit_id=?",
        (canonical_bytes(corrupted).decode(), permit["permit_id"]),
    )
    conn.commit()

    with pytest.raises(ValueError) as failure:
        _permit(service, grant, preview)
    assert failure.value.code == "canary_authority_unavailable"


def test_upload_joins_outer_pop_transaction_and_returns_closed_receipt():
    conn, _, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    permit = _permit(service, grant, _preview(service, grant, findings))
    request = _upload(grant, permit, findings)

    conn.execute("BEGIN IMMEDIATE")
    receipt = service.upload(WORKSPACE, PROJECT, grant["run_id"], RUNNER, request)
    assert conn.in_transaction is True
    assert receipt["schema_version"] == "heel.canary-findings-receipt.v1"
    assert set(receipt) == {
        "schema_version",
        "receipt_id",
        "workspace_id",
        "project_id",
        "run_id",
        "grant_id",
        "permit_id",
        "projection_id",
        "projection_digest",
        "byte_count",
        "scenario_count",
        "finding_count",
        "accepted_at_ms",
        "status",
    }
    assert receipt["status"] == "synchronized"
    assert (
        conn.execute("SELECT status FROM canary_disclosure_permits").fetchone()[0]
        == "consumed"
    )
    conn.rollback()
    assert (
        conn.execute("SELECT COUNT(*) FROM canary_findings_projections").fetchone()[0]
        == 0
    )
    assert (
        conn.execute("SELECT status FROM canary_disclosure_permits").fetchone()[0]
        == "permitted"
    )

    accepted = service.upload(WORKSPACE, PROJECT, grant["run_id"], RUNNER, request)
    assert accepted["projection_digest"] == findings["projection_digest"]
    assert service.get(WORKSPACE, PROJECT, grant["run_id"]) == findings
    assert (
        conn.execute("SELECT status FROM canary_disclosure_requests").fetchone()[0]
        == "synchronized"
    )


def test_upload_rejects_expired_consumed_and_noncurrent_key_with_stable_codes():
    conn, clock, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    preview = _preview(service, grant, findings)
    permit = _permit(service, grant, preview)
    request = _upload(grant, permit, findings)

    clock.value += 601
    with pytest.raises(ValueError) as expired:
        service.upload(WORKSPACE, PROJECT, grant["run_id"], RUNNER, request)
    assert expired.value.code == "disclosure_permit_expired"
    clock.value -= 601

    service.upload(WORKSPACE, PROJECT, grant["run_id"], RUNNER, request)
    with pytest.raises(ValueError) as consumed_ceremony:
        _permit(service, grant, preview)
    assert consumed_ceremony.value.code == "permit_consumed"
    with pytest.raises(ValueError) as consumed:
        service.upload(WORKSPACE, PROJECT, grant["run_id"], RUNNER, request)
    assert consumed.value.code == "permit_consumed"

    conn2, _, runner2, service2, grant2, operational2 = _terminal_setup()
    findings2 = _findings(runner2, grant2, operational2)
    request2 = _upload(
        grant2,
        _permit(service2, grant2, _preview(service2, grant2, findings2)),
        findings2,
    )
    conn2.execute(
        "UPDATE canary_runner_keys SET status='revoked',revoked_at=1 WHERE workspace_id=? "
        "AND runner_id=? AND key_id=?",
        (WORKSPACE, RUNNER, runner2.key_id),
    )
    conn2.commit()
    with pytest.raises(ValueError) as inactive:
        service2.upload(WORKSPACE, PROJECT, grant2["run_id"], RUNNER, request2)
    assert inactive.value.code == "canary_authority_unavailable"


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("digest", "invalid_canary_projection"),
        ("bytes", "invalid_canary_projection"),
        ("counts", "invalid_canary_projection"),
        ("grant", "invalid_canary_projection"),
        ("environment", "invalid_canary_projection"),
        ("receipt", "invalid_canary_projection"),
    ],
)
def test_upload_rejects_exact_projection_and_run_binding_mismatches(mutation, expected):
    conn, _, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    preview = _preview(service, grant, findings)
    permit = _permit(service, grant, preview)
    request = _upload(grant, permit, findings)

    if mutation == "digest":
        request["findings_projection"]["projection_digest"] = "f" * 64
    elif mutation == "bytes":
        conn.execute(
            "UPDATE canary_disclosure_permits SET maximum_bytes=maximum_bytes+1 WHERE permit_id=?",
            (permit["permit_id"],),
        )
        request["permit"]["projection"]["maximum_bytes"] += 1
    elif mutation == "counts":
        conn.execute(
            "UPDATE canary_disclosure_permits SET finding_count=0 WHERE permit_id=?",
            (permit["permit_id"],),
        )
        request["permit"]["projection"]["finding_count"] = 0
    else:
        changed = request["findings_projection"]
        if mutation == "grant":
            changed["grant_digest"] = "f" * 64
        elif mutation == "environment":
            changed["environment_id"] = "env_other"
        else:
            changed["finished_at_ms"] += 1
        unsigned = {
            key: value
            for key, value in changed.items()
            if key not in {"projection_digest", "signing_key_id", "signature_b64"}
        }
        changed["projection_digest"] = canonical_digest(unsigned)
        changed.update(runner.sign(canonical_bytes(unsigned)))

    with pytest.raises(ValueError) as failure:
        service.upload(WORKSPACE, PROJECT, grant["run_id"], RUNNER, request)
    assert failure.value.code == expected
    assert (
        conn.execute("SELECT COUNT(*) FROM canary_findings_projections").fetchone()[0]
        == 0
    )
    assert (
        conn.execute("SELECT status FROM canary_disclosure_permits").fetchone()[0]
        == "permitted"
    )


def test_local_only_is_terminal_and_never_persists_findings():
    conn, _, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    preview = _preview(service, grant, findings)
    result = service.local_only(
        WORKSPACE,
        PROJECT,
        grant["run_id"],
        request_id=preview["request_id"],
        actor="user_owner",
    )
    assert result == {
        "schema_version": "heel.canary-disclosure-state.v1",
        "run_id": grant["run_id"],
        "status": "local_only",
    }
    assert (
        conn.execute("SELECT status FROM canary_disclosure_requests").fetchone()[0]
        == "local_only"
    )
    assert (
        conn.execute("SELECT COUNT(*) FROM canary_disclosure_permits").fetchone()[0]
        == 0
    )
    assert (
        conn.execute("SELECT COUNT(*) FROM canary_findings_projections").fetchone()[0]
        == 0
    )
    with pytest.raises(ValueError) as terminal:
        _permit(service, grant, preview)
    assert terminal.value.code == "canary_state_conflict"


def test_expired_permit_is_atomically_replaced_by_a_fresh_recent_owner_ceremony():
    conn, clock, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    preview = _preview(service, grant, findings)
    first = _permit(service, grant, preview)
    clock.value += 601

    replacement = _permit(
        service, grant, preview, recent_auth_at_ms=int(clock.value * 1000),
    )

    assert replacement["permit_id"] != first["permit_id"]
    assert conn.execute(
        "SELECT status FROM canary_disclosure_permits WHERE permit_id=?",
        (first["permit_id"],),
    ).fetchone()[0] == "expired"
    assert conn.execute(
        "SELECT status FROM canary_disclosure_permits WHERE permit_id=?",
        (replacement["permit_id"],),
    ).fetchone()[0] == "permitted"
    assert conn.execute(
        "SELECT status FROM canary_disclosure_requests WHERE request_id=?",
        (preview["request_id"],),
    ).fetchone()[0] == "permitted"


def test_local_only_remains_available_after_an_unused_permit_expires():
    conn, clock, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    preview = _preview(service, grant, findings)
    permit = _permit(service, grant, preview)
    clock.value += 601

    result = service.local_only(
        WORKSPACE, PROJECT, grant["run_id"],
        request_id=preview["request_id"], actor="user_owner",
    )

    assert result["status"] == "local_only"
    assert conn.execute(
        "SELECT status FROM canary_disclosure_permits WHERE permit_id=?",
        (permit["permit_id"],),
    ).fetchone()[0] == "expired"
    assert conn.execute(
        "SELECT status FROM canary_disclosure_requests WHERE request_id=?",
        (preview["request_id"],),
    ).fetchone()[0] == "local_only"


def test_legacy_findings_approval_never_substitutes_for_a_canary_permit():
    conn, _, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    permit = _permit(service, grant, _preview(service, grant, findings))
    conn.execute(
        "DELETE FROM canary_disclosure_permits WHERE permit_id=?",
        (permit["permit_id"],),
    )
    conn.execute(
        "INSERT INTO findings_sync_approvals VALUES(?,?,?,?,?,?,?)",
        (
            WORKSPACE,
            PROJECT,
            "legacy_approval",
            findings["projection_digest"],
            "user_owner",
            1.0,
            9_999_999_999.0,
        ),
    )
    conn.commit()

    with pytest.raises(ValueError) as missing:
        service.upload(
            WORKSPACE,
            PROJECT,
            grant["run_id"],
            RUNNER,
            _upload(grant, permit, findings),
        )
    assert missing.value.code == "disclosure_permit_required"


def test_synchronized_findings_are_tenant_bound_and_payload_purges_after_seven_days():
    conn, clock, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    permit = _permit(service, grant, _preview(service, grant, findings))
    service.upload(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, _upload(grant, permit, findings)
    )

    with pytest.raises(ValueError) as cross_tenant:
        service.get("ws_other", PROJECT, grant["run_id"])
    assert cross_tenant.value.code == "canary_run_not_found"

    clock.value += 7 * 24 * 60 * 60 + 1
    assert service.purge_expired_payloads() == 1
    assert (
        conn.execute(
            "SELECT projection_json FROM canary_findings_projections"
        ).fetchone()[0]
        is None
    )
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM canary_audit_records WHERE action='synchronized'"
        ).fetchone()[0]
        == 1
    )
    with pytest.raises(ValueError) as purged:
        service.get(WORKSPACE, PROJECT, grant["run_id"])
    assert purged.value.code == "canary_run_not_found"


def test_upload_rolls_back_permit_projection_receipt_state_and_audit_together():
    conn, _, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    permit = _permit(service, grant, _preview(service, grant, findings))
    conn.execute(
        "CREATE TRIGGER fail_sync_audit BEFORE INSERT ON canary_audit_records "
        "WHEN NEW.action='synchronized' BEGIN SELECT RAISE(ABORT,'injected'); END"
    )
    conn.commit()

    with pytest.raises(Exception):
        service.upload(
            WORKSPACE,
            PROJECT,
            grant["run_id"],
            RUNNER,
            _upload(grant, permit, findings),
        )
    assert (
        conn.execute("SELECT COUNT(*) FROM canary_findings_projections").fetchone()[0]
        == 0
    )
    assert (
        conn.execute("SELECT status FROM canary_disclosure_permits").fetchone()[0]
        == "permitted"
    )
    assert (
        conn.execute("SELECT status FROM canary_disclosure_requests").fetchone()[0]
        == "permitted"
    )


# --- H2 metadata-only disclosure poll (result-handoff-completion spec §3.3/§3.5) ---
#
# Contract under test (proposed in the accepted spec, implemented in task A):
# ``CanaryDisclosureService.poll(workspace_id, project_ref, run_id, runner_id, request,
# *, runner_key_id)`` runs inside the caller's PoP transaction, registers exactly the
# metadata ``preview`` registers, and answers either the closed disclosure state or the
# stored, byte-identical one-use permit.  No findings bytes travel on this call.

DISCLOSURE_STATE_SCHEMA = "heel.canary-disclosure-state.v1"
DISCLOSURE_POLL_SCHEMA = "heel.runner-disclosure-poll.v1"


def _poll_request(grant, findings, **overrides):
    projection = {
        "schema_version": findings["schema_version"],
        "projection_digest": findings["projection_digest"],
        "byte_count": len(canonical_bytes(findings)),
        "scenario_count": len(findings["scenario_results"]),
        "finding_count": sum(
            item["finding"] is not None for item in findings["scenario_results"]
        ),
    }
    projection.update(overrides)
    return {
        "schema_version": DISCLOSURE_POLL_SCHEMA,
        "run_id": grant["run_id"],
        "projection": projection,
    }


def _poll(service, grant, findings, *, workspace=WORKSPACE, runner_id=RUNNER,
          runner_key_id=None, **overrides):
    return service.poll(
        workspace,
        PROJECT,
        grant["run_id"],
        runner_id,
        _poll_request(grant, findings, **overrides),
        runner_key_id=runner_key_id or findings["signing_key_id"],
    )


def _state(grant, status):
    return {
        "schema_version": DISCLOSURE_STATE_SCHEMA,
        "run_id": grant["run_id"],
        "status": status,
    }


def test_disclosure_poll_registers_metadata_once_and_reports_state():
    conn, _, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)

    first = _poll(service, grant, findings)
    second = _poll(service, grant, findings)

    assert first == second == _state(grant, "local_result_ready")
    rows = conn.execute(
        "SELECT run_id,runner_id,runner_key_id,projection_digest,maximum_bytes,"
        "scenario_count,finding_count,status FROM canary_disclosure_requests"
    ).fetchall()
    assert [tuple(row) for row in rows] == [(
        grant["run_id"], RUNNER, runner.key_id, findings["projection_digest"],
        len(canonical_bytes(findings)), 1, 1, "local_result_ready",
    )]
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_audit_records WHERE action='local_result_ready'"
    ).fetchone()[0] == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_findings_projections"
    ).fetchone()[0] == 0
    # The human ceremony reads the very request the runner registered.
    preview = _preview(service, grant, findings)
    assert preview["status"] == "local_result_ready"
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_disclosure_requests"
    ).fetchone()[0] == 1


def test_disclosure_poll_returns_the_byte_identical_permit_until_consumed_then_synchronized():
    conn, _, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    assert _poll(service, grant, findings) == _state(grant, "local_result_ready")
    permit = _permit(service, grant, _preview(service, grant, findings))

    polled = _poll(service, grant, findings)
    replayed = _poll(service, grant, findings)

    assert validate_disclosure_permit(polled) == permit
    assert canonical_bytes(polled) == canonical_bytes(permit)
    assert canonical_bytes(replayed) == canonical_bytes(permit)
    assert canonical_bytes(polled).decode() == conn.execute(
        "SELECT permit_json FROM canary_disclosure_permits WHERE permit_id=?",
        (permit["permit_id"],),
    ).fetchone()[0]
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_disclosure_permits"
    ).fetchone()[0] == 1

    service.upload(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, _upload(grant, polled, findings),
    )
    assert _poll(service, grant, findings) == _state(grant, "synchronized")
    assert conn.execute(
        "SELECT status FROM canary_disclosure_permits"
    ).fetchone()[0] == "consumed"


def test_disclosure_poll_reports_local_only_and_never_a_permit():
    conn, _, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    preview = _preview(service, grant, findings)
    service.local_only(
        WORKSPACE, PROJECT, grant["run_id"],
        request_id=preview["request_id"], actor="user_owner",
    )

    assert _poll(service, grant, findings) == _state(grant, "local_only")
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_disclosure_permits"
    ).fetchone()[0] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_findings_projections"
    ).fetchone()[0] == 0


@pytest.mark.parametrize(
    "override",
    [
        {"projection_digest": "f" * 64},
        {"byte_count": 1},
        {"scenario_count": 2},
        {"finding_count": 0},
    ],
)
def test_disclosure_poll_refuses_metadata_that_differs_from_the_registered_request(override):
    conn, _, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    permit = _permit(service, grant, _preview(service, grant, findings))

    with pytest.raises(ValueError) as forged:
        _poll(service, grant, findings, **override)

    assert forged.value.code == "canary_state_conflict"
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_disclosure_requests"
    ).fetchone()[0] == 1
    assert conn.execute(
        "SELECT status FROM canary_disclosure_permits WHERE permit_id=?",
        (permit["permit_id"],),
    ).fetchone()[0] == "permitted"


def test_disclosure_poll_from_another_runner_key_or_workspace_is_not_found():
    conn, _, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    _permit(service, grant, _preview(service, grant, findings))

    with pytest.raises(ValueError) as other_workspace:
        _poll(service, grant, findings, workspace="ws_other")
    assert other_workspace.value.code == "canary_run_not_found"
    with pytest.raises(ValueError) as other_runner:
        _poll(service, grant, findings, runner_id="runr_other")
    assert other_runner.value.code == "canary_run_not_found"
    with pytest.raises(ValueError) as other_key:
        _poll(service, grant, findings, runner_key_id="key_other_runner_123456")
    assert other_key.value.code == "canary_authority_unavailable"
    with pytest.raises(ValueError) as foreign_run:
        service.poll(
            WORKSPACE, PROJECT, "crun_" + "0" * 32, RUNNER,
            _poll_request(grant, findings), runner_key_id=runner.key_id,
        )
    assert foreign_run.value.code in {"canary_run_not_found", "invalid_canary_projection"}


def test_disclosure_poll_after_key_revocation_or_before_terminal_result_is_refused():
    from heel.saas.runner_auth import RunnerAuthStore, initialize_runner_auth_schema

    conn = connect()
    runner = seed_authority(conn)
    initialize_runner_auth_schema(conn)
    clock = Clock()
    auth = RunnerAuthStore(conn, pepper=b"d" * 32, now=clock)
    coordinator, _, approved = submit_and_approve(conn, clock, runner, runner_auth=auth)
    coordinator.claim(WORKSPACE, RUNNER, runner.key_id)
    grant = approved["grant"]
    service = _service(conn, clock)
    terminal = operational_projection(
        runner, grant, sequence=0, phase="terminal", disposition="completed",
    )
    findings = _findings(runner, grant, terminal)
    with pytest.raises(ValueError) as early:
        _poll(service, grant, findings)
    assert early.value.code == "canary_state_conflict"
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_disclosure_requests"
    ).fetchone()[0] == 0

    conn2, _, runner2, service2, grant2, operational2 = _terminal_setup()
    findings2 = _findings(runner2, grant2, operational2)
    _permit(service2, grant2, _preview(service2, grant2, findings2))
    conn2.execute(
        "UPDATE canary_runner_keys SET status='revoked',revoked_at=1 WHERE workspace_id=? "
        "AND runner_id=? AND key_id=?",
        (WORKSPACE, RUNNER, runner2.key_id),
    )
    conn2.commit()
    with pytest.raises(ValueError) as revoked:
        _poll(service2, grant2, findings2)
    assert revoked.value.code == "canary_authority_unavailable"


def test_expired_permit_is_not_returned_and_a_fresh_human_permit_is_polled_next():
    conn, clock, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    preview = _preview(service, grant, findings)
    first = _permit(service, grant, preview)
    clock.value += 601

    assert _poll(service, grant, findings) == _state(
        grant, "awaiting_disclosure_approval",
    )
    assert conn.execute(
        "SELECT status FROM canary_disclosure_permits WHERE permit_id=?",
        (first["permit_id"],),
    ).fetchone()[0] == "expired"

    fresh = _permit(
        service, grant, preview, recent_auth_at_ms=int(clock.value * 1000),
    )
    polled = _poll(service, grant, findings)
    assert fresh["permit_id"] != first["permit_id"]
    assert canonical_bytes(polled) == canonical_bytes(fresh)


@pytest.mark.parametrize(
    "mutation",
    ["extra_key", "schema", "projection_extra", "bool_count", "run_mismatch"],
)
def test_disclosure_poll_request_validator_is_closed(mutation):
    from heel.canary_contracts import validate_runner_disclosure_poll_request

    conn, _, runner, service, grant, operational = _terminal_setup()
    findings = _findings(runner, grant, operational)
    request = _poll_request(grant, findings)
    assert validate_runner_disclosure_poll_request(copy.deepcopy(request)) == request
    if mutation == "extra_key":
        request["findings_projection"] = findings
    elif mutation == "schema":
        request["schema_version"] = "heel.runner-disclosure-poll.v2"
    elif mutation == "projection_extra":
        request["projection"]["scenario_results"] = []
    elif mutation == "bool_count":
        request["projection"]["finding_count"] = True
    if mutation == "run_mismatch":
        with pytest.raises(ValueError):
            service.poll(
                WORKSPACE, PROJECT, grant["run_id"], RUNNER,
                {**request, "run_id": "crun_" + "1" * 32}, runner_key_id=runner.key_id,
            )
        return
    with pytest.raises(ValueError):
        validate_runner_disclosure_poll_request(request)
