from __future__ import annotations

import json
import sqlite3

import pytest

from canary_test_support import (
    NOW_MS,
    PROJECT,
    RUNNER,
    WORKSPACE,
    operational_projection,
)
from test_canary_lifecycle import resign_operational, running_setup

from heel.canary_contracts import canonical_bytes, canonical_digest
from heel.saas.canary_runs import CanaryRunError


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


# --- D: an accepted stop acknowledgement whose response was lost ---------------------------
#
# Runner-local signed instants on the shared projection timeline (claimed NOW_MS + 100, started
# NOW_MS + 200).  The Cloud receipt clock is separate: running_setup's clock stays at NOW_MS.
_REQUESTED, _ACKED = NOW_MS + 300, NOW_MS + 400
_WITNESS = (
    "SELECT stop_ack_source_event_sequence,stop_ack_projection_digest,"
    "stop_ack_runner_local_at_ms FROM canary_runs"
)


def _acked_run(*, requests_started=0):
    """A cloud-stopped run whose signed acknowledgement (sequence 1) the Cloud accepted."""
    conn, clock, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    if requests_started:
        coordinator.progress(
            WORKSPACE, PROJECT, grant["run_id"], RUNNER,
            operational_projection(
                runner, grant, sequence=0, phase="running",
                requests_started=requests_started, updated_at_ms=NOW_MS + 200,
            ),
        )
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    ack = operational_projection(
        runner, grant, sequence=1, phase="stop_requested", requests_started=requests_started,
        stop_reason="cloud_stop", stop_requested_at_ms=_REQUESTED,
        stop_acknowledged_at_ms=_ACKED, updated_at_ms=_ACKED,
    )
    assert coordinator.ack_stop(WORKSPACE, PROJECT, grant["run_id"], RUNNER, ack) == {
        "accepted": True, "deadline_met": True, "late": False,
    }
    return conn, clock, runner, coordinator, grant, ack


def _terminal(
    runner, grant, *, acknowledged, sequence=2, requests_started=0, stop_reason="cloud_stop",
    disposition="stopped", updated_at_ms=NOW_MS + 1000, terminal_at_ms=None,
):
    value = operational_projection(
        runner, grant, sequence=sequence, phase="terminal", requests_started=requests_started,
        disposition=disposition, stop_reason=stop_reason, stop_requested_at_ms=_REQUESTED,
        stop_acknowledged_at_ms=acknowledged, updated_at_ms=updated_at_ms,
    )
    if terminal_at_ms is not None:
        value["timestamps"]["terminal_at_ms"] = terminal_at_ms
        value = resign_operational(value, runner)
    return value


def _refused(coordinator, grant, projection, code):
    with pytest.raises(CanaryRunError) as refused:
        coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, projection)
    assert refused.value.detail_code == code


def _audit_digests(conn, action):
    return [row[0] for row in conn.execute(
        "SELECT payload_digest FROM canary_audit_records WHERE action=? ORDER BY created_at,rowid",
        (action,),
    )]


def _ack_audit_payload(action, ack, *, server_ms, late):
    return {
        "action": action,
        "stop_ack_source_event_sequence": ack["event_sequence"],
        "stop_ack_projection_digest": ack["projection_digest"],
        "stop_ack_runner_local_at_ms": ack["timestamps"]["stop_acknowledged_at_ms"],
        "server_acknowledged_at_ms": server_ms,
        "stop_deadline_ms": NOW_MS + 5000,
        "stop_ack_late": int(late),  # canonical JSON has no booleans
    }


def _finalized_payload(disposition, reconciliation, witness, *, server_ms, late=False):
    sequence, digest, local = witness
    return {
        "execution_disposition": disposition,
        "ack_reconciliation": reconciliation,
        "stop_ack_source_event_sequence": sequence,
        "stop_ack_projection_digest": digest,
        "stop_ack_runner_local_at_ms": local,
        "server_acknowledged_at_ms": server_ms,
        "stop_ack_late": int(late),
    }


def _erase_witness_as_pre_v32(conn):
    """A pre-v32 acknowledgement leaves exactly these three migration-added columns NULL."""
    conn.execute(
        "UPDATE canary_runs SET stop_ack_source_event_sequence=NULL,"
        "stop_ack_projection_digest=NULL,stop_ack_runner_local_at_ms=NULL",
    )
    conn.commit()


def _state(conn):
    return tuple(conn.execute(
        "SELECT status,execution_disposition,stop_acknowledged_at_ms,stop_ack_late,"
        "source_event_sequence,source_projection_digest,quota_state,"
        "stop_ack_source_event_sequence,stop_ack_projection_digest,stop_ack_runner_local_at_ms "
        "FROM canary_runs"
    ).fetchone()) + tuple(conn.execute(
        "SELECT receipt_digest FROM canary_operational_receipts"
    ).fetchone() or (None,))


def test_ack_stop_persists_write_once_signed_ack_witness_and_hashed_audit_binding():
    conn, _, _, _, _, ack = _acked_run()
    row = conn.execute(
        "SELECT stop_acknowledged_at_ms,stop_ack_late FROM canary_runs"
    ).fetchone()
    # Server receipt time and the signed runner-local acknowledgement stay in separate columns.
    assert tuple(row) == (NOW_MS, 0)
    assert tuple(conn.execute(_WITNESS).fetchone()) == (1, ack["projection_digest"], _ACKED)
    assert _ACKED != NOW_MS
    assert _audit_digests(conn, "stop_acknowledged") == [canonical_digest(
        _ack_audit_payload("stop_acknowledged", ack, server_ms=NOW_MS, late=False),
    )]
    # The run event keeps its closed public shape and action.
    events = [item for item in conn.execute(
        "SELECT event_type,event_json FROM canary_run_events WHERE event_type='stop_acknowledged'"
    )]
    assert len(events) == 1
    assert set(json.loads(events[0]["event_json"])) == {
        "schema_version", "event_type", "status", "reason_code",
    }

    # A late acknowledgement records the same immutable witness and hashes its late status.
    late_conn, clock, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    late = operational_projection(
        runner, grant, sequence=3, phase="stop_requested", stop_reason="cloud_stop",
        stop_requested_at_ms=_REQUESTED, stop_acknowledged_at_ms=_ACKED,
        updated_at_ms=_ACKED,
    )
    clock.value += 6
    assert coordinator.ack_stop(WORKSPACE, PROJECT, grant["run_id"], RUNNER, late)["late"] is True
    assert tuple(late_conn.execute(_WITNESS).fetchone()) == (3, late["projection_digest"], _ACKED)
    assert late_conn.execute("SELECT stop_acknowledged_at_ms FROM canary_runs").fetchone()[0] == NOW_MS + 6000
    assert _audit_digests(late_conn, "stop_ack_late") == [canonical_digest(
        _ack_audit_payload("stop_ack_late", late, server_ms=NOW_MS + 6000, late=True),
    )]


def test_ack_stop_exact_replay_preserves_witness_and_changed_member_conflicts():
    conn, _, runner, coordinator, grant, ack = _acked_run()
    witness = tuple(conn.execute(_WITNESS).fetchone())
    audits = conn.execute("SELECT COUNT(*) FROM canary_audit_records").fetchone()[0]
    assert coordinator.ack_stop(WORKSPACE, PROJECT, grant["run_id"], RUNNER, ack)["accepted"] is True
    assert tuple(conn.execute(_WITNESS).fetchone()) == witness
    assert conn.execute("SELECT COUNT(*) FROM canary_audit_records").fetchone()[0] == audits

    changed = operational_projection(
        runner, grant, sequence=2, phase="stop_requested", stop_reason="cloud_stop",
        stop_requested_at_ms=_REQUESTED, stop_acknowledged_at_ms=_ACKED + 1,
        updated_at_ms=_ACKED + 1,
    )
    with pytest.raises(CanaryRunError) as refused:
        coordinator.ack_stop(WORKSPACE, PROJECT, grant["run_id"], RUNNER, changed)
    assert refused.value.detail_code == "stop_conflict"
    assert tuple(conn.execute(_WITNESS).fetchone()) == witness

    # A replay never repairs or accepts a changed or partial witness.
    for column, value in (
        ("stop_ack_runner_local_at_ms", _ACKED + 1),
        ("stop_ack_source_event_sequence", 0),
        ("stop_ack_projection_digest", "b" * 64),
        ("stop_ack_projection_digest", None),
        ("stop_ack_runner_local_at_ms", None),
    ):
        conn.execute(f"UPDATE canary_runs SET {column}=?", (value,))
        conn.commit()
        with pytest.raises(CanaryRunError) as refused:
            coordinator.ack_stop(WORKSPACE, PROJECT, grant["run_id"], RUNNER, ack)
        assert refused.value.detail_code == "stop_conflict"
        conn.execute(
            "UPDATE canary_runs SET stop_ack_source_event_sequence=?,stop_ack_projection_digest=?,"
            "stop_ack_runner_local_at_ms=?", witness,
        )
        conn.commit()

    # The columns themselves refuse malformed members.
    for column, value in (
        ("stop_ack_source_event_sequence", -1),
        ("stop_ack_runner_local_at_ms", -1),
        ("stop_ack_projection_digest", "A" * 64),
        ("stop_ack_projection_digest", "a" * 63),
    ):
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(f"UPDATE canary_runs SET {column}=?", (value,))
    conn.rollback()

    # The first acceptance is a conditional write-once update: a pre-existing tuple conflicts.
    fresh_conn, _, fresh_runner, fresh, approved, _ = running_setup()
    fresh_grant = approved["grant"]
    fresh.request_stop(
        WORKSPACE, PROJECT, fresh_grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    fresh_conn.execute(
        "UPDATE canary_runs SET stop_ack_source_event_sequence=0,stop_ack_projection_digest=?,"
        "stop_ack_runner_local_at_ms=1", ("c" * 64,),
    )
    fresh_conn.commit()
    before = _state(fresh_conn)
    first = operational_projection(
        fresh_runner, fresh_grant, sequence=1, phase="stop_requested", stop_reason="cloud_stop",
        stop_requested_at_ms=_REQUESTED, stop_acknowledged_at_ms=_ACKED, updated_at_ms=_ACKED,
    )
    with pytest.raises(CanaryRunError) as refused:
        fresh.ack_stop(WORKSPACE, PROJECT, fresh_grant["run_id"], RUNNER, first)
    assert refused.value.detail_code == "stop_conflict"
    assert _state(fresh_conn) == before


def test_terminal_receipt_upsert_cannot_erase_ack_witness():
    conn, _, runner, coordinator, grant, ack = _acked_run()
    witness = (1, ack["projection_digest"], _ACKED)
    coordinator.heartbeat(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=2, phase="stop_requested", stop_reason="cloud_stop",
            stop_requested_at_ms=_REQUESTED, stop_acknowledged_at_ms=_ACKED,
            updated_at_ms=_ACKED + 50,
        ),
    )
    assert tuple(conn.execute(_WITNESS).fetchone()) == witness
    terminal = _terminal(runner, grant, acknowledged=_ACKED, sequence=3)
    coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, terminal)
    assert conn.execute("SELECT receipt_digest FROM canary_operational_receipts").fetchone()[0] == terminal["projection_digest"]
    assert tuple(conn.execute(_WITNESS).fetchone()) == witness

    d_conn, _, d_runner, d_coordinator, d_grant, d_ack = _acked_run()
    lost = _terminal(d_runner, d_grant, acknowledged=None)
    d_coordinator.result(WORKSPACE, PROJECT, d_grant["run_id"], RUNNER, lost)
    receipt = d_conn.execute(
        "SELECT receipt_digest,receipt_json FROM canary_operational_receipts"
    ).fetchone()
    assert receipt["receipt_digest"] == lost["projection_digest"]
    assert receipt["receipt_json"] == canonical_bytes(lost).decode()
    assert tuple(d_conn.execute(_WITNESS).fetchone()) == (1, d_ack["projection_digest"], _ACKED)


def test_legacy_matching_non_null_ack_terminal_remains_accepted_without_v32_witness():
    conn, _, runner, coordinator, grant, _ = _acked_run()
    _erase_witness_as_pre_v32(conn)
    terminal = _terminal(runner, grant, acknowledged=_ACKED)
    status = coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, terminal)
    assert (status["status"], status["execution_disposition"]) == ("terminal", "stopped")
    assert status["stop_acknowledged_at_ms"] == NOW_MS
    assert tuple(conn.execute(_WITNESS).fetchone()) == (None, None, None)  # never backfilled
    assert _audit_digests(conn, "finalized") == [canonical_digest(_finalized_payload(
        "stopped", "none", (None, None, None), server_ms=NOW_MS,
    ))]


def test_d_reconciliation_rejects_wrong_non_null_ack():
    conn, _, runner, coordinator, grant, _ = _acked_run()
    before = _state(conn)
    for wrong in (_ACKED + 1, _ACKED - 1, _REQUESTED):
        _refused(coordinator, grant, _terminal(runner, grant, acknowledged=wrong), "stop_conflict")
        assert _state(conn) == before
    status = coordinator.result(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, _terminal(runner, grant, acknowledged=_ACKED),
    )
    assert status["status"] == "terminal"


def test_d_reconciliation_rejects_terminal_before_signed_ack_local_time():
    conn, _, runner, coordinator, grant, _ = _acked_run()
    before = _state(conn)
    # The null-ACK terminal cannot carry ordering against the ACK it never learned, so the
    # Cloud compares it to the durable signed runner-local ACK time in the same clock domain.
    early = _terminal(runner, grant, acknowledged=None, terminal_at_ms=_ACKED - 1)
    _refused(coordinator, grant, early, "stop_conflict")
    assert _state(conn) == before
    # A terminal carrying the ACK is held to the same order by the signed projection contract.
    ordered = _terminal(runner, grant, acknowledged=_ACKED, terminal_at_ms=_ACKED - 1)
    _refused(coordinator, grant, ordered, "invalid_operational_projection")
    assert _state(conn) == before
    at_ack = _terminal(runner, grant, acknowledged=None, terminal_at_ms=_ACKED)
    assert coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, at_ack)["status"] == "terminal"


def test_d_reconciliation_preserves_source_counter_and_timestamp_regression_rejections():
    conn, _, runner, coordinator, grant, ack = _acked_run(requests_started=1)
    before = _state(conn)
    assert before[6] == "consumed"
    cases = (
        (_terminal(runner, grant, acknowledged=None, sequence=1, requests_started=1), "source_sequence_conflict"),
        (_terminal(runner, grant, acknowledged=None, sequence=0, requests_started=1), "source_sequence_gap"),
        (_terminal(runner, grant, acknowledged=None, requests_started=0), "operational_counter_regression"),
        (_terminal(runner, grant, acknowledged=None, requests_started=1, updated_at_ms=_ACKED - 1), "operational_time_regression"),
    )
    for projection, code in cases:
        _refused(coordinator, grant, projection, code)
        assert _state(conn) == before
    lost = _terminal(runner, grant, acknowledged=None, requests_started=1)
    status = coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, lost)
    assert (status["status"], status["execution_disposition"], status["quota_state"]) == (
        "terminal", "stopped", "consumed",
    )
    assert status["source_event_sequence"] == 2
    assert _audit_digests(conn, "finalized") == [canonical_digest(_finalized_payload(
        "stopped", "cloud_recorded_client_unknown", (1, ack["projection_digest"], _ACKED),
        server_ms=NOW_MS,
    ))]
    # The settled quota decision is idempotent: an exact replay changes nothing.
    settled = _state(conn)
    assert coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, lost) == status
    assert _state(conn) == settled


def test_d_reconciliation_rejects_wrong_reason_nonstopped_and_no_witness():
    conn, _, runner, coordinator, grant, _ = _acked_run()
    before = _state(conn)
    _refused(coordinator, grant, _terminal(
        runner, grant, acknowledged=None, stop_reason="local_emergency_stop",
    ), "stop_conflict")
    _refused(coordinator, grant, _terminal(
        runner, grant, acknowledged=None, stop_reason="none", disposition="completed",
    ), "stop_conflict")
    _refused(coordinator, grant, _terminal(
        runner, grant, acknowledged=None, stop_reason="none", disposition="stopped",
    ), "illegal_run_transition")
    assert _state(conn) == before

    # A partial witness is unprovable and fails closed; it is never repaired.
    for column in (
        "stop_ack_source_event_sequence", "stop_ack_projection_digest", "stop_ack_runner_local_at_ms",
    ):
        partial_conn, _, partial_runner, partial, partial_grant, _ = _acked_run()
        partial_conn.execute(f"UPDATE canary_runs SET {column}=NULL")
        partial_conn.commit()
        partial_before = _state(partial_conn)
        _refused(partial, partial_grant, _terminal(partial_runner, partial_grant, acknowledged=None), "stop_conflict")
        assert _state(partial_conn) == partial_before

    # Runner ACK evidence that the Cloud never accepted is not a witness.
    unaccepted_conn, _, unaccepted_runner, unaccepted, approved, _ = running_setup()
    unaccepted_grant = approved["grant"]
    unaccepted.request_stop(
        WORKSPACE, PROJECT, unaccepted_grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    unaccepted.heartbeat(
        WORKSPACE, PROJECT, unaccepted_grant["run_id"], RUNNER,
        operational_projection(
            unaccepted_runner, unaccepted_grant, sequence=1, phase="stop_requested",
            stop_reason="cloud_stop", stop_requested_at_ms=_REQUESTED,
            stop_acknowledged_at_ms=_ACKED, updated_at_ms=_ACKED,
        ),
    )
    unaccepted_before = _state(unaccepted_conn)
    assert unaccepted_before[2] is None and unaccepted_before[7:10] == (None, None, None)
    _refused(unaccepted, unaccepted_grant, _terminal(
        unaccepted_runner, unaccepted_grant, acknowledged=None,
    ), "stop_conflict")
    assert _state(unaccepted_conn) == unaccepted_before


def test_legacy_d_null_terminal_without_complete_witness_fails_closed_but_legacy_valid_ack_paths_replay_exactly():
    conn, _, runner, coordinator, grant, ack = _acked_run()
    _erase_witness_as_pre_v32(conn)
    before = _state(conn)
    _refused(coordinator, grant, _terminal(runner, grant, acknowledged=None), "stop_conflict")
    assert _state(conn) == before
    # Legacy exact ACK replay is still accepted and does not backfill the witness.
    assert coordinator.ack_stop(WORKSPACE, PROJECT, grant["run_id"], RUNNER, ack) == {
        "accepted": True, "deadline_met": True, "late": False,
    }
    assert _state(conn) == before
    # The legacy matching non-null terminal and its exact replay keep their old behavior.
    terminal = _terminal(runner, grant, acknowledged=_ACKED)
    status = coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, terminal)
    assert status["status"] == "terminal"
    settled = _state(conn)
    assert coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, terminal) == status
    assert _state(conn) == settled
    assert settled[7:10] == (None, None, None)


def test_due_prune_never_substitutes_for_cloud_ack_and_c_pre_activation_remains_unresolved():
    def pruned(*, legacy):
        conn, clock, runner, coordinator, grant, ack = _acked_run()
        if legacy:
            _erase_witness_as_pre_v32(conn)
        conn.execute("UPDATE canary_operational_receipts SET purge_at=?", (NOW_MS,))
        conn.commit()
        assert coordinator.expire_and_reconcile()["purged_receipts"] == 1
        assert conn.execute("SELECT receipt_json FROM canary_operational_receipts").fetchone()[0] is None
        return conn, runner, coordinator, grant, ack

    # The pruned receipt no longer carries ACK evidence; the durable witness still decides.
    conn, runner, coordinator, grant, ack = pruned(legacy=False)
    before = _state(conn)
    _refused(coordinator, grant, _terminal(runner, grant, acknowledged=_ACKED + 1), "stop_conflict")
    _refused(coordinator, grant, _terminal(runner, grant, acknowledged=None, terminal_at_ms=_ACKED - 1), "stop_conflict")
    assert _state(conn) == before
    status = coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, _terminal(runner, grant, acknowledged=None))
    assert status["status"] == "terminal"
    assert _audit_digests(conn, "finalized") == [canonical_digest(_finalized_payload(
        "stopped", "cloud_recorded_client_unknown", (1, ack["projection_digest"], _ACKED),
        server_ms=NOW_MS,
    ))]

    # Without a complete witness, pruning cannot turn a recorded Cloud ACK into a NULL-ACK pass.
    legacy_conn, legacy_runner, legacy, legacy_grant, _ = pruned(legacy=True)
    legacy_before = _state(legacy_conn)
    _refused(legacy, legacy_grant, _terminal(legacy_runner, legacy_grant, acknowledged=None), "stop_conflict")
    assert _state(legacy_conn) == legacy_before

    # C stays unresolved: a stop with no authenticated ACK is closed by the reaper as missing,
    # without a fabricated witness or reconciliation, and a later runner terminal is refused.
    c_conn, clock, c_runner, c_coordinator, approved, _ = running_setup()
    c_grant = approved["grant"]
    c_coordinator.request_stop(
        WORKSPACE, PROJECT, c_grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    clock.value += 6
    assert c_coordinator.expire_and_reconcile()["finalized_orphans"] == 1
    c_state = _state(c_conn)
    assert c_state[:3] == ("terminal", "stopped", None)
    assert c_state[7:10] == (None, None, None)
    assert len(_audit_digests(c_conn, "stop_ack_late")) == 1
    _refused(c_coordinator, c_grant, _terminal(c_runner, c_grant, acknowledged=None), "illegal_run_transition")
    assert _state(c_conn) == c_state


# --- C2: server issuance of the inactive-claim attestation (C design §6, A1, clarification §1) ---

_ATTESTATION_WRITES = {
    18: "insert", 23: "update", 9: "delete",  # sqlite3.SQLITE_INSERT / _UPDATE / _DELETE
}


def _attestation_setup():
    """A claimed, never-started run whose Cloud stop is persisted (I1), on one shared Clock."""
    from canary_test_support import NOW

    conn, clock, runner, coordinator, approved, _ = running_setup()
    conn.execute(
        "INSERT INTO canary_runner_execution_protocols("
        "workspace_id,runner_id,protocol_version,control_protocol,exchange_digest,activated_at"
        ") VALUES(?,?,?,?,?,?)",
        (WORKSPACE, RUNNER, 3, "heel.runner-control.v2", "a" * 64, NOW),
    )
    conn.commit()
    grant = approved["grant"]
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    # Fractional seconds: a seconds/milliseconds mix cannot satisfy the exact equalities below.
    clock.value = NOW + 0.25
    return conn, clock, runner, coordinator, grant


def _attestation_call(conn, clock, runner, coordinator, grant, *, challenge=b"c" * 32, **overrides):
    import base64
    import hashlib

    from heel.canary_contracts import (
        RUNNER_INACTIVE_CLAIM_ATTESTATION_POP_DOMAIN,
        RUNNER_INACTIVE_CLAIM_ATTESTATION_PROOF_SCHEMA,
        RUNNER_INACTIVE_CLAIM_ATTESTATION_REQUEST_SCHEMA,
    )

    approval_id = conn.execute(
        "SELECT approval_id FROM canary_runs WHERE run_id=?", (grant["run_id"],),
    ).fetchone()[0]
    body = canonical_bytes({
        "schema_version": RUNNER_INACTIVE_CLAIM_ATTESTATION_REQUEST_SCHEMA,
        "run_id": grant["run_id"], "project_id": grant["project_id"],
        "grant_id": grant["grant_id"], "grant_digest": grant["grant_digest"],
        "approval_id": approval_id,
        "approval_projection_digest": grant["approval"]["projection_digest"],
        "bound_runner_key_id": runner.key_id,
        "client_challenge_b64": base64.b64encode(challenge).decode(),
        **overrides,
    })
    path = f"/v1/workspaces/{WORKSPACE}/runners/{RUNNER}/runs/{grant['run_id']}/inactive-claim-attestation"
    timestamp_ms = int(clock.value * 1000)
    proof = {
        "schema_version": RUNNER_INACTIVE_CLAIM_ATTESTATION_PROOF_SCHEMA, "workspace_id": WORKSPACE,
        "runner_id": RUNNER, "key_id": runner.key_id, "method": "POST", "path": path,
        "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp_ms": timestamp_ms,
    }
    signature = runner.private_key.sign(RUNNER_INACTIVE_CLAIM_ATTESTATION_POP_DOMAIN + canonical_bytes(proof))
    headers = {
        "X-Heel-Runner-Id": [RUNNER], "X-Heel-Runner-Key-Id": [runner.key_id],
        "X-Heel-Runner-Timestamp-Ms": [str(timestamp_ms)],
        "X-Heel-Runner-Signature": [base64.b64encode(signature).decode()],
        "X-Heel-Runner-Nonce": [], "X-Heel-Runner-Sequence": [], "Authorization": [], "Cookie": [],
    }
    return coordinator.runner_auth.attest_inactive_claim(
        workspace_id=WORKSPACE, runner_id=RUNNER, run_id=grant["run_id"], path=path,
        raw_body=body, headers=headers, runs=coordinator,
    )


def _all_rows(conn):
    tables = [row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )]
    return {table: sorted(map(tuple, conn.execute(f"SELECT * FROM {table}"))) for table in tables}


def test_inactive_claim_attestation_transaction_mutates_only_its_audit_table():
    from heel.canary_contracts import (
        inactive_claim_attestation_signing_payload, validate_inactive_claim_attestation,
    )
    from heel.crypto import verify_envelope
    from heel.saas.canary_runs import CanaryRunService, InactiveClaimAttestationRefused

    conn, clock, runner, coordinator, grant = _attestation_setup()
    before = _all_rows(conn)
    writes = []

    def authorizer(action, table, *_):
        if action in _ATTESTATION_WRITES:
            writes.append((_ATTESTATION_WRITES[action], table))
        return sqlite3.SQLITE_OK

    conn.set_authorizer(authorizer)
    try:
        record = _attestation_call(conn, clock, runner, coordinator, grant)
    finally:
        conn.set_authorizer(None)
    # Exactly one write, to the append-only audit table; nothing else (runs, grants, approvals,
    # receipts, quota ledger, nonce chains, cursors, request ledger, events, audit) is touched.
    assert writes == [("insert", "canary_inactive_claim_attestations")]
    after = _all_rows(conn)
    audit = after.pop("canary_inactive_claim_attestations")
    assert before.pop("canary_inactive_claim_attestations") == []
    assert after == before
    assert len(audit) == 1

    assert validate_inactive_claim_attestation(record) == record
    verify_envelope(
        {coordinator.signing.key_id: coordinator.signing.public_key},
        {"signing_key_id": record["signing_key_id"], "signature_b64": record["signature_b64"]},
        inactive_claim_attestation_signing_payload(record),
    )
    assert record["signing_key_id"] == coordinator.signing.key_id
    assert (record["workspace_id"], record["runner_id"], record["run_id"]) == (WORKSPACE, RUNNER, grant["run_id"])
    assert record["bound_runner_key_id"] == record["authenticated_runner_key_id"] == runner.key_id
    assert record["cloud"]["status"] == "stop_requested" and record["cloud"]["stop_reason"] == "cloud_stop"
    assert record["cloud"]["started_at_ms"] is None and record["cloud"]["stop_acknowledged_at_ms"] is None

    # A refusal rolls back and writes nothing at all.
    writes.clear()
    conn.set_authorizer(authorizer)
    try:
        with pytest.raises(InactiveClaimAttestationRefused) as refused:
            _attestation_call(conn, clock, runner, coordinator, grant, challenge=b"d" * 32, grant_digest="f" * 64)
    finally:
        conn.set_authorizer(None)
    assert refused.value.reason == "binding_mismatch"
    assert writes == []
    assert _all_rows(conn) == {**before, "canary_inactive_claim_attestations": audit}

    # The predicate must read inside the PoP transaction: a service on another connection is refused.
    other = sqlite3.connect(":memory:")
    try:
        foreign = CanaryRunService(other, signing=coordinator.signing, initialize_schema=False)
        with pytest.raises(TypeError):
            coordinator.runner_auth.attest_inactive_claim(
                workspace_id=WORKSPACE, runner_id=RUNNER, run_id=grant["run_id"], path="/",
                raw_body=b"{}", headers={}, runs=foreign,
            )
    finally:
        other.close()
    assert _all_rows(conn) == {**before, "canary_inactive_claim_attestations": audit}


def test_inactive_claim_attestation_rate_limits_at_three_per_minute_and_purges_with_audit_retention():
    from heel.saas.canary_runs import AUDIT_RETENTION_MS
    from heel.saas.runner_auth import RunnerAuthRateLimited

    conn, clock, runner, coordinator, grant = _attestation_setup()
    t0 = clock.value
    t0_ms = int(t0 * 1000)

    def rows():
        return [tuple(row) for row in conn.execute(
            "SELECT attestation_id,created_at_ms,purge_at FROM canary_inactive_claim_attestations "
            "ORDER BY created_at_ms,attestation_id"
        )]

    first = _attestation_call(conn, clock, runner, coordinator, grant, challenge=b"1" * 32)
    stored = rows()
    assert [(created, purge) for _, created, purge in stored] == [(t0_ms, t0_ms + AUDIT_RETENTION_MS)]
    assert all(type(created) is int and type(purge) is int for _, created, purge in stored)
    assert first["attested_at_ms"] == t0_ms == stored[0][1]
    assert stored[0][0] == first["attestation_id"]
    _attestation_call(conn, clock, runner, coordinator, grant, challenge=b"2" * 32)
    _attestation_call(conn, clock, runner, coordinator, grant, challenge=b"3" * 32)
    assert len(rows()) == 3

    # The window is open at its lower boundary: three at t0 refuse a fourth at t0+59 s and admit
    # the first one at exactly t0+60 s (created_at_ms > now_ms - 60000).
    clock.value = t0 + 59
    with pytest.raises(RunnerAuthRateLimited):
        _attestation_call(conn, clock, runner, coordinator, grant, challenge=b"4" * 32)
    assert len(rows()) == 3
    clock.value = t0 + 60
    late = _attestation_call(conn, clock, runner, coordinator, grant, challenge=b"5" * 32)
    assert late["attested_at_ms"] == t0_ms + 60_000
    assert len(rows()) == 4

    # Retention runs on the service's clock, which is the same Clock object.
    clock.value = t0 + 29 * 86400
    coordinator.expire_and_reconcile()
    assert len(rows()) == 4
    clock.value = t0 + 30 * 86400
    coordinator.expire_and_reconcile()
    assert [created for _, created, _ in rows()] == [t0_ms + 60_000]
    clock.value = t0 + 30 * 86400 + 60
    coordinator.expire_and_reconcile()
    assert rows() == []

    # The persisted columns hold portable integers only; a fractional seconds value is refused.
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO canary_inactive_claim_attestations VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("ica_" + "0" * 32, WORKSPACE, RUNNER, grant["run_id"], grant["grant_id"], runner.key_id,
             "a" * 64, "b" * 64, "terminal", t0, t0 + 1),
        )
