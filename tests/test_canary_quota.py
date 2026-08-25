from __future__ import annotations

import pytest

from canary_test_support import (
    NOW_MS,
    PROJECT,
    RUNNER,
    WORKSPACE,
    operational_projection,
)
from test_canary_lifecycle import running_setup


def ledger_kinds(conn):
    return [row[0] for row in conn.execute(
        "SELECT kind FROM usage_ledger WHERE meter='canary_runs' ORDER BY ts,entry_id"
    )]


def test_first_accepted_target_request_consumes_once_under_progress_race():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    projection = operational_projection(
        runner, grant, sequence=0, phase="running", requests_started=1,
        updated_at_ms=NOW_MS + 200,
    )
    coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, projection)
    coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, projection)
    assert ledger_kinds(conn) == ["reserve", "consume"]


def test_zero_request_terminal_refunds_reserved_unit():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.result(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=0, phase="terminal", requests_started=0,
            requests_completed=0, disposition="incomplete",
            error_category="containment_rejected", updated_at_ms=NOW_MS + 500,
        ),
    )
    assert ledger_kinds(conn) == ["reserve", "refund"]
    assert conn.execute("SELECT quota_state FROM canary_runs").fetchone()[0] == "refunded"


def test_consumed_platform_or_runner_fault_compensates_exactly_once():
    for reason in ("platform_fault", "runner_fault"):
        conn, _, runner, coordinator, approved, _ = running_setup()
        grant = approved["grant"]
        coordinator.progress(
            WORKSPACE, PROJECT, grant["run_id"], RUNNER,
            operational_projection(
                runner, grant, sequence=0, phase="running", requests_started=1,
                updated_at_ms=NOW_MS + 200,
            ),
        )
        terminal = operational_projection(
            runner, grant, sequence=1, phase="terminal", requests_started=1,
            requests_completed=0, disposition="failed", error_category=reason,
            updated_at_ms=NOW_MS + 500,
        )
        coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, terminal)
        assert ledger_kinds(conn) == ["reserve", "consume", "platform_fault_refund"]
        assert conn.execute("SELECT quota_state FROM canary_runs").fetchone()[0] == "compensated"
        assert coordinator.result(
            WORKSPACE, PROJECT, grant["run_id"], RUNNER, terminal,
        )["quota_state"] == "compensated"
        assert ledger_kinds(conn).count("platform_fault_refund") == 1


def test_expired_unclaimed_grant_refunds_and_reconciliation_is_idempotent():
    conn, clock, _, coordinator, approved, _ = running_setup()
    # Rewind the claim to emulate an issued grant that was never accepted by the runner.
    conn.execute("DELETE FROM canary_consumed_nonces")
    conn.execute("DELETE FROM canary_runner_nonce_chains WHERE chain_name!='claim'")
    conn.execute("DELETE FROM canary_runner_chain_cursors WHERE chain_name!='claim'")
    conn.execute("UPDATE canary_execution_grants SET status='issued',claimed_at=NULL")
    conn.execute("UPDATE canary_runs SET status='approved',claimed_at_ms=NULL")
    conn.commit()
    clock.value += 601
    first = coordinator.expire_and_reconcile()
    second = coordinator.expire_and_reconcile()
    assert first["expired_grants"] == 1
    assert second["expired_grants"] == 0
    assert ledger_kinds(conn) == ["reserve", "refund"]
    assert conn.execute("SELECT status FROM canary_runs").fetchone()[0] == "expired"


def test_revoked_runner_zero_request_claim_is_stopped_and_refunded_after_deadline():
    conn, clock, _, coordinator, approved, _ = running_setup()
    assert coordinator.runner_auth.revoke(
        WORKSPACE, RUNNER, actor="user_owner", reason_code="human_revocation",
    ) is True
    assert tuple(conn.execute(
        "SELECT status,stop_reason,quota_state FROM canary_runs"
    ).fetchone()) == ("stop_requested", "runner_revoked", "reserved")
    clock.value += 6
    first = coordinator.expire_and_reconcile()
    second = coordinator.expire_and_reconcile()
    assert first["finalized_orphans"] == 1
    assert second["finalized_orphans"] == 0
    assert tuple(conn.execute(
        "SELECT status,execution_disposition,stop_reason,quota_state FROM canary_runs"
    ).fetchone()) == ("terminal", "stopped", "runner_revoked", "refunded")
    assert conn.execute("SELECT status FROM canary_execution_grants").fetchone()[0] == "terminal"
    assert ledger_kinds(conn) == ["reserve", "refund"]


def test_unacknowledged_cloud_stop_finalizes_and_refunds_without_forging_receipt():
    conn, clock, _, coordinator, approved, _ = running_setup()
    coordinator.request_stop(
        WORKSPACE, PROJECT, approved["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    clock.value += 6
    assert coordinator.expire_and_reconcile()["finalized_orphans"] == 1
    assert tuple(conn.execute(
        "SELECT status,execution_disposition,quota_state FROM canary_runs"
    ).fetchone()) == ("terminal", "stopped", "refunded")
    assert conn.execute("SELECT COUNT(*) FROM canary_operational_receipts").fetchone()[0] == 0


def test_late_ack_cannot_introduce_traffic_after_reaper_refunded_terminal_run():
    conn, clock, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    clock.value += 6
    coordinator.expire_and_reconcile()
    late_with_traffic = operational_projection(
        runner, grant, sequence=0, phase="stop_requested", requests_started=1,
        stop_reason="cloud_stop", stop_requested_at_ms=NOW_MS,
        stop_acknowledged_at_ms=NOW_MS + 6000, updated_at_ms=NOW_MS + 6000,
    )
    with pytest.raises(ValueError):
        coordinator.ack_stop(
            WORKSPACE, PROJECT, grant["run_id"], RUNNER, late_with_traffic,
        )
    assert ledger_kinds(conn) == ["reserve", "refund"]
    assert tuple(conn.execute(
        "SELECT quota_state,stop_acknowledged_at_ms FROM canary_runs"
    ).fetchone()) == ("refunded", None)
