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
    assert tuple(stored) == (NOW_MS, 0)


def test_late_stop_ack_succeeds_but_never_claims_deadline_met():
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
    late = operational_projection(
        runner, grant, sequence=1, phase="stop_requested", requests_started=1,
        stop_reason="cloud_stop", stop_requested_at_ms=NOW_MS,
        stop_acknowledged_at_ms=NOW_MS + 5001, updated_at_ms=NOW_MS + 5001,
    )
    clock.value += 6
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


def test_future_runner_stop_timestamp_is_evidence_not_cloud_liveness_authority():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    future = NOW_MS + 10 * 365 * 24 * 60 * 60 * 1000
    acknowledgement = operational_projection(
        runner, grant, sequence=0, phase="stop_requested", stop_reason="cloud_stop",
        stop_requested_at_ms=future, stop_acknowledged_at_ms=future,
        updated_at_ms=future,
    )
    assert coordinator.ack_stop(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, acknowledgement,
    ) == {"accepted": True, "deadline_met": True, "late": False}
    assert tuple(conn.execute(
        "SELECT stop_requested_at_ms,stop_acknowledged_at_ms,updated_at FROM canary_runs"
    ).fetchone()) == (NOW_MS, NOW_MS, NOW_MS)
    assert tuple(conn.execute(
        "SELECT created_at,updated_at FROM canary_operational_receipts"
    ).fetchone()) == (NOW_MS, NOW_MS)


def test_stop_ack_treats_runner_stop_timestamp_as_evidence_not_server_authority():
    _, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    runner_local_stop = operational_projection(
        runner, grant, sequence=0, phase="stop_requested", stop_reason="cloud_stop",
        stop_requested_at_ms=NOW_MS + 250,
        stop_acknowledged_at_ms=NOW_MS + 300, updated_at_ms=NOW_MS + 300,
    )
    assert coordinator.ack_stop(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, runner_local_stop,
    ) == {"accepted": True, "deadline_met": True, "late": False}


def test_local_emergency_ack_atomically_freezes_the_runner_originated_stop():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    acknowledgement = operational_projection(
        runner, grant, sequence=0, phase="stop_requested",
        stop_reason="local_emergency_stop", stop_requested_at_ms=NOW_MS + 300,
        stop_acknowledged_at_ms=NOW_MS + 300, updated_at_ms=NOW_MS + 300,
    )

    assert coordinator.ack_stop(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, acknowledgement,
    ) == {"accepted": True, "deadline_met": True, "late": False}
    assert tuple(conn.execute(
        "SELECT status,stop_reason,stop_requested_at_ms,stop_acknowledged_at_ms "
        "FROM canary_runs"
    ).fetchone()) == (
        "stop_requested", "local_emergency_stop", NOW_MS, NOW_MS,
    )
    actions = [row[0] for row in conn.execute(
        "SELECT action FROM canary_audit_records"
    ).fetchall()]
    assert actions.count("stop_requested") == 1
    assert actions.count("stop_acknowledged") == 1


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
    stored_ack = conn.execute(
        "SELECT stop_acknowledged_at_ms FROM canary_runs"
    ).fetchone()[0]
    assert NOW_MS <= stored_ack < NOW_MS + 300
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_audit_records WHERE action='stop_acknowledged'"
    ).fetchone()[0] == 1


def test_post_stop_running_progress_is_evidence_and_cannot_regress_durable_stop():
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
    in_flight = operational_projection(
        runner, grant, sequence=4, phase="running", requests_started=1,
        updated_at_ms=NOW_MS + 300,
    )
    status = coordinator.progress(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, in_flight,
    )
    assert status["status"] == "stop_requested"
    assert status["stop_reason"] == "cloud_stop"
    assert tuple(conn.execute(
        "SELECT status,stop_reason,source_event_sequence FROM canary_runs"
    ).fetchone()) == ("stop_requested", "cloud_stop", 4)


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
    conn, clock, runner, coordinator, approved, _ = running_setup()
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
    clock.value += 7
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


def test_stop_ack_joins_an_outer_pop_transaction_and_does_not_commit_it():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    acknowledgement = operational_projection(
        runner, grant, sequence=0, phase="stop_requested", requests_started=0,
        stop_reason="cloud_stop", stop_requested_at_ms=NOW_MS,
        stop_acknowledged_at_ms=NOW_MS + 300, updated_at_ms=NOW_MS + 300,
    )

    conn.execute("BEGIN IMMEDIATE")
    response = coordinator.ack_stop(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, acknowledgement,
    )

    assert conn.in_transaction is True
    assert response == {"accepted": True, "deadline_met": True, "late": False}
    conn.rollback()
    assert conn.execute(
        "SELECT stop_acknowledged_at_ms FROM canary_runs WHERE run_id=?",
        (grant["run_id"],),
    ).fetchone()[0] is None
