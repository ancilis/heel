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


def test_stop_is_idempotent_generation_bound_and_ack_deadline_is_durable():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.progress(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=0, phase="running", requests_started=1,
            updated_at_ms=NOW_MS + 200,
        ),
    )
    stop = coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    assert stop["stop_generation"] == 0
    assert stop["deadline_ms"] == NOW_MS + 5000
    assert coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    ) == stop

    acknowledgement = operational_projection(
        runner, grant, sequence=1, phase="stop_requested", requests_started=1,
        stop_reason="cloud_stop", stop_requested_at_ms=NOW_MS,
        stop_acknowledged_at_ms=NOW_MS + 4999, updated_at_ms=NOW_MS + 4999,
    )
    ack = coordinator.ack_stop(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, acknowledgement,
    )
    assert ack == {"accepted": True, "deadline_met": True, "late": False}
    stored = conn.execute(
        "SELECT stop_acknowledged_at_ms,stop_ack_late FROM canary_runs"
    ).fetchone()
    assert tuple(stored) == (NOW_MS + 4999, 0)


def test_late_stop_ack_succeeds_but_never_claims_deadline_met():
    _, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.progress(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=0, phase="running", requests_started=1,
            updated_at_ms=NOW_MS + 200,
        ),
    )
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    late = operational_projection(
        runner, grant, sequence=1, phase="stop_requested", requests_started=1,
        stop_reason="cloud_stop", stop_requested_at_ms=NOW_MS,
        stop_acknowledged_at_ms=NOW_MS + 5001, updated_at_ms=NOW_MS + 5001,
    )
    assert coordinator.ack_stop(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, late,
    ) == {"accepted": True, "deadline_met": False, "late": True}


def test_backdated_runner_ack_cannot_claim_a_missed_cloud_deadline():
    _, clock, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    clock.value += 100
    backdated = operational_projection(
        runner, grant, sequence=0, phase="stop_requested", stop_reason="cloud_stop",
        stop_requested_at_ms=NOW_MS, stop_acknowledged_at_ms=NOW_MS + 4999,
        updated_at_ms=NOW_MS + 100_000,
    )
    assert coordinator.ack_stop(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, backdated,
    ) == {"accepted": True, "deadline_met": False, "late": True}


def test_stop_ack_persists_when_heartbeat_already_accepted_the_same_snapshot():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    snapshot = operational_projection(
        runner, grant, sequence=0, phase="stop_requested", stop_reason="cloud_stop",
        stop_requested_at_ms=NOW_MS, stop_acknowledged_at_ms=NOW_MS + 300,
        updated_at_ms=NOW_MS + 300,
    )
    coordinator.heartbeat(WORKSPACE, PROJECT, grant["run_id"], RUNNER, snapshot)
    assert conn.execute(
        "SELECT stop_acknowledged_at_ms FROM canary_runs"
    ).fetchone()[0] is None
    assert coordinator.ack_stop(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, snapshot,
    ) == {"accepted": True, "deadline_met": True, "late": False}
    assert conn.execute(
        "SELECT stop_acknowledged_at_ms FROM canary_runs"
    ).fetchone()[0] == NOW_MS + 300
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_audit_records WHERE action='stop_acknowledged'"
    ).fetchone()[0] == 1


def test_stop_requested_cannot_regress_to_running():
    _, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.progress(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=0, phase="running", requests_started=1,
            updated_at_ms=NOW_MS + 200,
        ),
    )
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    with pytest.raises(ValueError):
        coordinator.progress(
            WORKSPACE, PROJECT, grant["run_id"], RUNNER,
            operational_projection(
                runner, grant, sequence=1, phase="running", requests_started=1,
                updated_at_ms=NOW_MS + 300,
            ),
        )
    assert coordinator.get_status(WORKSPACE, PROJECT, grant["run_id"])["status"] == "stop_requested"


def test_identical_stop_replay_survives_later_control_generation_change():
    conn, _, _, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    stop = coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    from heel.saas.ops import OpsStore
    OpsStore(conn).trip(WORKSPACE, actor="admin", reason="incident")
    assert coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    ) == stop


def test_new_late_ack_after_terminal_is_stored_without_rewriting_terminal_receipt():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.progress(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=0, phase="running", requests_started=1,
            updated_at_ms=NOW_MS + 200,
        ),
    )
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    terminal = operational_projection(
        runner, grant, sequence=1, phase="terminal", requests_started=1,
        disposition="stopped", stop_reason="cloud_stop",
        stop_requested_at_ms=NOW_MS, updated_at_ms=NOW_MS + 6000,
    )
    coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, terminal)
    before = tuple(conn.execute(
        "SELECT lifecycle_phase,execution_disposition,receipt_digest "
        "FROM canary_operational_receipts"
    ).fetchone())
    late = operational_projection(
        runner, grant, sequence=2, phase="stop_requested", requests_started=1,
        stop_reason="cloud_stop", stop_requested_at_ms=NOW_MS,
        stop_acknowledged_at_ms=NOW_MS + 7000, updated_at_ms=NOW_MS + 7000,
    )
    assert coordinator.ack_stop(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, late,
    ) == {"accepted": True, "deadline_met": False, "late": True}
    assert tuple(conn.execute(
        "SELECT lifecycle_phase,execution_disposition,receipt_digest "
        "FROM canary_operational_receipts"
    ).fetchone()) == before
    assert coordinator.get_status(
        WORKSPACE, PROJECT, grant["run_id"],
    )["execution_disposition"] == "stopped"


def test_terminal_result_cannot_clear_a_durable_cloud_stop():
    _, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    cleared = operational_projection(
        runner, grant, sequence=0, phase="terminal", requests_started=0,
        disposition="completed", stop_reason="none", updated_at_ms=NOW_MS + 500,
    )
    with pytest.raises(ValueError):
        coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, cleared)
    status = coordinator.get_status(WORKSPACE, PROJECT, grant["run_id"])
    assert status["status"] == "stop_requested"
    assert status["stop_reason"] == "cloud_stop"


def test_terminal_result_cannot_bypass_stop_ack_deadline_evidence():
    _, clock, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    clock.value += 100
    bypass = operational_projection(
        runner, grant, sequence=0, phase="terminal", requests_started=0,
        disposition="stopped", stop_reason="cloud_stop",
        stop_requested_at_ms=NOW_MS, stop_acknowledged_at_ms=NOW_MS + 4999,
        updated_at_ms=NOW_MS + 100_000,
    )
    with pytest.raises(ValueError):
        coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, bypass)


def test_first_stop_ack_is_immutable_except_for_exact_replay():
    _, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.progress(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=0, phase="running", requests_started=1,
            updated_at_ms=NOW_MS + 200,
        ),
    )
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    first = operational_projection(
        runner, grant, sequence=1, phase="stop_requested", requests_started=1,
        stop_reason="cloud_stop",
        stop_requested_at_ms=NOW_MS, stop_acknowledged_at_ms=NOW_MS + 300,
        updated_at_ms=NOW_MS + 300,
    )
    assert coordinator.ack_stop(WORKSPACE, PROJECT, grant["run_id"], RUNNER, first)[
        "deadline_met"
    ] is True
    assert coordinator.ack_stop(WORKSPACE, PROJECT, grant["run_id"], RUNNER, first)[
        "deadline_met"
    ] is True
    changed = operational_projection(
        runner, grant, sequence=2, phase="stop_requested", requests_started=1,
        stop_reason="cloud_stop",
        stop_requested_at_ms=NOW_MS, stop_acknowledged_at_ms=NOW_MS + 400,
        updated_at_ms=NOW_MS + 400,
    )
    with pytest.raises(ValueError):
        coordinator.ack_stop(WORKSPACE, PROJECT, grant["run_id"], RUNNER, changed)


def test_identical_stop_remains_idempotent_after_finalizing_ack():
    _, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.progress(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=0, phase="running", requests_started=1,
            updated_at_ms=NOW_MS + 200,
        ),
    )
    stop = coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    ack = operational_projection(
        runner, grant, sequence=1, phase="finalizing", requests_started=1,
        stop_reason="cloud_stop", stop_requested_at_ms=NOW_MS,
        stop_acknowledged_at_ms=NOW_MS + 300, updated_at_ms=NOW_MS + 300,
    )
    coordinator.ack_stop(WORKSPACE, PROJECT, grant["run_id"], RUNNER, ack)
    assert coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    ) == stop


def test_reaper_does_not_terminalize_acknowledged_fresh_finalizing_run_at_ack_deadline():
    _, clock, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.progress(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=0, phase="running", requests_started=1,
            updated_at_ms=NOW_MS + 200,
        ),
    )
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    acknowledged = operational_projection(
        runner, grant, sequence=1, phase="finalizing", requests_started=1,
        stop_reason="cloud_stop", stop_requested_at_ms=NOW_MS,
        stop_acknowledged_at_ms=NOW_MS + 300, updated_at_ms=NOW_MS + 300,
    )
    coordinator.ack_stop(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, acknowledged,
    )
    clock.value += 4
    coordinator.heartbeat(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=2, phase="finalizing", requests_started=1,
            stop_reason="cloud_stop", stop_requested_at_ms=NOW_MS,
            stop_acknowledged_at_ms=NOW_MS + 300, updated_at_ms=NOW_MS + 4000,
        ),
    )
    clock.value += 2
    assert coordinator.expire_and_reconcile()["finalized_orphans"] == 0
    assert coordinator.get_status(
        WORKSPACE, PROJECT, grant["run_id"],
    )["status"] == "finalizing"


def test_stop_generation_mismatch_and_terminal_stop_are_closed_conflicts():
    _, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    with pytest.raises(ValueError):
        coordinator.request_stop(
            WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
            reason="cloud_stop", expected_kill_switch_generation=1,
        )
    coordinator.result(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=0, phase="terminal", requests_started=0,
            requests_completed=0, disposition="incomplete", error_category="runner_fault",
            updated_at_ms=NOW_MS + 500,
        ),
    )
    with pytest.raises(ValueError):
        coordinator.request_stop(
            WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
            reason="cloud_stop", expected_kill_switch_generation=0,
        )


def test_kill_switch_generation_advances_and_gate_stops_old_grant():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    from heel.saas.ops import OpsStore
    ops = OpsStore(conn)
    ops.trip(WORKSPACE, actor="admin", reason="incident")
    gate = coordinator.heartbeat(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(runner, grant, sequence=0, phase="claimed"),
    )
    assert gate["active"] is False
    assert gate["kill_switch_generation"] == 1
    assert gate["stop_reason"] == "kill_switch"
    assert ops.control_generation() == 1
    ops.clear(WORKSPACE, actor="admin", reason="incident resolved")
    assert ops.control_generation() == 2
