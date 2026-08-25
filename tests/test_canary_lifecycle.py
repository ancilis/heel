from __future__ import annotations

import copy
import json

import pytest

from heel.canary_contracts import canonical_bytes, canonical_digest

from canary_test_support import (
    Clock,
    NOW,
    NOW_MS,
    PROJECT,
    RUNNER,
    WORKSPACE,
    connect,
    operational_projection,
    seed_authority,
    submit_and_approve,
)


def running_setup():
    from heel.saas.runner_auth import RunnerAuthStore, initialize_runner_auth_schema

    conn = connect()
    runner = seed_authority(conn)
    initialize_runner_auth_schema(conn)
    clock = Clock()
    auth = RunnerAuthStore(conn, pepper=b"r" * 32, now=clock)
    coordinator, _, approved = submit_and_approve(conn, clock, runner, runner_auth=auth)
    claim = coordinator.claim(WORKSPACE, RUNNER, runner.key_id)
    return conn, clock, runner, coordinator, approved, claim


def resign_operational(value, signer):
    unsigned = {
        key: item for key, item in value.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    updated = dict(unsigned)
    updated["projection_digest"] = canonical_digest(unsigned)
    updated.update(signer.sign(canonical_bytes(unsigned)))
    return updated


def test_heartbeat_and_progress_validate_signature_binding_privacy_and_source_sequence():
    conn, clock, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    claimed = operational_projection(runner, grant, sequence=0, phase="claimed")
    first = coordinator.heartbeat(WORKSPACE, PROJECT, grant["run_id"], RUNNER, claimed)
    assert first["server_time_ms"] >= NOW_MS
    assert first["active"] is True

    running = operational_projection(
        runner, grant, sequence=1, phase="running", requests_started=1,
        updated_at_ms=NOW_MS + 1200,
    )
    second = coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, running)
    assert second["status"] == "running"
    assert conn.execute("SELECT quota_state FROM canary_runs").fetchone()[0] == "consumed"

    assert coordinator.progress(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, running,
    )["status"] == "running"
    changed = copy.deepcopy(running)
    changed["counters"]["response_bytes_read"] += 1
    with pytest.raises(ValueError):
        coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, changed)
    private = copy.deepcopy(running)
    private["assessment"] = "observed"
    with pytest.raises(ValueError):
        coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, private)


def test_counter_regression_and_sequence_gap_rollback_without_receipt_change():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    accepted = operational_projection(
        runner, grant, sequence=0, phase="running", requests_started=1,
        updated_at_ms=NOW_MS + 200,
    )
    coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, accepted)
    before = conn.execute(
        "SELECT source_event_sequence,receipt_digest FROM canary_operational_receipts"
    ).fetchone()
    gap = operational_projection(
        runner, grant, sequence=2, phase="running", requests_started=1,
        updated_at_ms=NOW_MS + 300,
    )
    with pytest.raises(ValueError):
        coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, gap)
    regressed = operational_projection(
        runner, grant, sequence=1, phase="running", requests_started=0,
        updated_at_ms=NOW_MS + 300,
    )
    with pytest.raises(ValueError):
        coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, regressed)
    after = conn.execute(
        "SELECT source_event_sequence,receipt_digest FROM canary_operational_receipts"
    ).fetchone()
    assert tuple(after) == tuple(before)


def test_result_appends_finalizing_then_terminal_and_closes_run():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.progress(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=0, phase="running", requests_started=1,
            updated_at_ms=NOW_MS + 200,
        ),
    )
    result = operational_projection(
        runner, grant, sequence=1, phase="terminal", requests_started=1,
        requests_completed=1, disposition="completed", updated_at_ms=NOW_MS + 500,
    )
    status = coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, result)
    assert status["status"] == "terminal"
    assert status["execution_disposition"] == "completed"
    event_types = [row[0] for row in conn.execute(
        "SELECT event_type FROM canary_run_events WHERE run_id=? ORDER BY sequence",
        (grant["run_id"],),
    )]
    assert event_types[-2:] == ["finalizing", "terminal"]
    assert conn.execute("SELECT status FROM canary_execution_grants").fetchone()[0] == "terminal"
    with pytest.raises(ValueError):
        coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, result)


def test_heartbeat_gate_uses_strictly_advancing_server_time_and_live_authority():
    conn, clock, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    projection = operational_projection(runner, grant, sequence=0, phase="claimed")
    first = coordinator.heartbeat(WORKSPACE, PROJECT, grant["run_id"], RUNNER, projection)
    clock.value -= 100
    projection = operational_projection(
        runner, grant, sequence=1, phase="claimed", updated_at_ms=NOW_MS + 1001,
    )
    second = coordinator.heartbeat(WORKSPACE, PROJECT, grant["run_id"], RUNNER, projection)
    assert second["server_time_ms"] == first["server_time_ms"] + 1
    conn.execute(
        "UPDATE canary_environments SET proof_expires_at=? WHERE environment_id=?",
        (clock.value - 1, grant["environment"]["environment_id"]),
    )
    conn.commit()
    projection = operational_projection(
        runner, grant, sequence=2, phase="claimed", updated_at_ms=NOW_MS + 1002,
    )
    gate = coordinator.heartbeat(WORKSPACE, PROJECT, grant["run_id"], RUNNER, projection)
    assert gate["active"] is False and gate["proof_state"] == "expired"


def test_gate_remains_active_while_runner_is_finalizing_local_result():
    _, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    coordinator.progress(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=0, phase="running", requests_started=1,
            updated_at_ms=NOW_MS + 200,
        ),
    )
    coordinator.progress(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=1, phase="finalizing", requests_started=1,
            updated_at_ms=NOW_MS + 300,
        ),
    )
    gate = coordinator.heartbeat(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=2, phase="finalizing", requests_started=1,
            updated_at_ms=NOW_MS + 400,
        ),
    )
    assert gate["active"] is True


def test_claimed_run_can_persist_direct_finalizing_transition():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    status = coordinator.progress(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER,
        operational_projection(
            runner, grant, sequence=0, phase="finalizing", requests_started=0,
            updated_at_ms=NOW_MS + 200,
        ),
    )
    assert status["status"] == "finalizing"
    assert conn.execute(
        "SELECT lifecycle_phase FROM canary_operational_receipts"
    ).fetchone()[0] == "finalizing"


def test_heartbeat_first_persists_lifecycle_transition_evidence():
    for phase, event_type, audit_action in (
        ("running", "run_started", "running"),
        ("finalizing", "finalizing", None),
    ):
        conn, _, runner, coordinator, approved, _ = running_setup()
        grant = approved["grant"]
        coordinator.heartbeat(
            WORKSPACE, PROJECT, grant["run_id"], RUNNER,
            operational_projection(
                runner, grant, sequence=0, phase=phase,
                requests_started=int(phase == "running"), updated_at_ms=NOW_MS + 200,
            ),
        )
        assert conn.execute(
            "SELECT 1 FROM canary_run_events WHERE event_type=?", (event_type,),
        ).fetchone()
        if audit_action is not None:
            assert conn.execute(
                "SELECT 1 FROM canary_audit_records WHERE action=?", (audit_action,),
            ).fetchone()


def test_heartbeat_records_and_advances_when_progress_already_accepted_same_snapshot():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    snapshot = operational_projection(
        runner, grant, sequence=0, phase="running", requests_started=1,
        updated_at_ms=NOW_MS + 200,
    )
    coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, snapshot)
    before = coordinator.get_status(WORKSPACE, PROJECT, grant["run_id"])
    gate = coordinator.heartbeat(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, snapshot,
    )
    stored = conn.execute(
        "SELECT last_heartbeat_at_ms,last_gate_at_ms FROM canary_runs"
    ).fetchone()
    assert stored["last_heartbeat_at_ms"] == NOW_MS
    assert stored["last_gate_at_ms"] == gate["server_time_ms"]
    assert gate["server_time_ms"] > NOW_MS
    assert coordinator.get_status(
        WORKSPACE, PROJECT, grant["run_id"],
    )["source_event_sequence"] == before["source_event_sequence"]
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_run_events WHERE event_type='heartbeat_accepted'"
    ).fetchone()[0] == 1


def test_delayed_older_heartbeat_advances_only_liveness_after_newer_progress():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    older = operational_projection(
        runner, grant, sequence=0, phase="running", requests_started=1,
        updated_at_ms=NOW_MS + 200,
    )
    coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, older)
    newer = operational_projection(
        runner, grant, sequence=1, phase="running", requests_started=1,
        requests_completed=1, updated_at_ms=NOW_MS + 300,
    )
    coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, newer)
    before = conn.execute(
        "SELECT status,source_event_sequence,source_projection_digest,last_heartbeat_at_ms "
        "FROM canary_runs WHERE run_id=?",
        (grant["run_id"],),
    ).fetchone()
    receipt_before = conn.execute(
        "SELECT source_event_sequence,receipt_digest,receipt_json "
        "FROM canary_operational_receipts WHERE run_id=?",
        (grant["run_id"],),
    ).fetchone()
    heartbeat_events = conn.execute(
        "SELECT COUNT(*) FROM canary_run_events WHERE run_id=? AND event_type='heartbeat_accepted'",
        (grant["run_id"],),
    ).fetchone()[0]

    gate = coordinator.heartbeat(WORKSPACE, PROJECT, grant["run_id"], RUNNER, older)

    after = conn.execute(
        "SELECT status,source_event_sequence,source_projection_digest,last_heartbeat_at_ms "
        "FROM canary_runs WHERE run_id=?",
        (grant["run_id"],),
    ).fetchone()
    receipt_after = conn.execute(
        "SELECT source_event_sequence,receipt_digest,receipt_json "
        "FROM canary_operational_receipts WHERE run_id=?",
        (grant["run_id"],),
    ).fetchone()
    assert gate["active"] is True
    assert tuple(after)[:3] == tuple(before)[:3]
    assert after["last_heartbeat_at_ms"] == NOW_MS
    assert tuple(receipt_after) == tuple(receipt_before)
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_run_events WHERE run_id=? AND event_type='heartbeat_accepted'",
        (grant["run_id"],),
    ).fetchone()[0] == heartbeat_events

    tampered = copy.deepcopy(older)
    tampered["counters"]["response_bytes_read"] += 1
    with pytest.raises(ValueError):
        coordinator.heartbeat(WORKSPACE, PROJECT, grant["run_id"], RUNNER, tampered)
    with pytest.raises(LookupError):
        coordinator.heartbeat(WORKSPACE, PROJECT, grant["run_id"], "runr_other", older)


def test_cloud_stop_accepts_exact_pre_stop_snapshot_only_as_liveness():
    conn, clock, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    running = operational_projection(
        runner, grant, sequence=0, phase="running", requests_started=1,
        updated_at_ms=NOW_MS + 200,
    )
    coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, running)
    coordinator.request_stop(
        WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
        reason="cloud_stop", expected_kill_switch_generation=0,
    )
    before = tuple(conn.execute(
        "SELECT source_event_sequence,source_projection_digest FROM canary_runs"
    ).fetchone())
    receipt_before = tuple(conn.execute(
        "SELECT source_event_sequence,receipt_digest,receipt_json "
        "FROM canary_operational_receipts"
    ).fetchone())
    clock.value += 1
    gate = coordinator.heartbeat(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, running,
    )
    assert gate["active"] is False and gate["stop_reason"] == "cloud_stop"
    assert tuple(conn.execute(
        "SELECT source_event_sequence,source_projection_digest FROM canary_runs"
    ).fetchone()) == before
    assert tuple(conn.execute(
        "SELECT source_event_sequence,receipt_digest,receipt_json "
        "FROM canary_operational_receipts"
    ).fetchone()) == receipt_before
    assert conn.execute(
        "SELECT last_heartbeat_at_ms FROM canary_runs"
    ).fetchone()[0] == NOW_MS + 1000

    changed = copy.deepcopy(running)
    changed["timestamps"]["updated_at_ms"] += 1
    changed = resign_operational(changed, runner)
    with pytest.raises(ValueError):
        coordinator.heartbeat(WORKSPACE, PROJECT, grant["run_id"], RUNNER, changed)


def test_environment_reproof_digest_replacement_permanently_closes_gate():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    snapshot = operational_projection(
        runner, grant, sequence=0, phase="running", requests_started=1,
        updated_at_ms=NOW_MS + 200,
    )
    coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, snapshot)
    conn.execute(
        "UPDATE canary_environments SET verification_record_digest=? WHERE environment_id=?",
        ("b" * 64, grant["environment"]["environment_id"]),
    )
    conn.commit()
    gate = coordinator.heartbeat(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, snapshot,
    )
    assert gate["active"] is False
    assert gate["stop_reason"] == "target_revoked"
    assert tuple(conn.execute(
        "SELECT status,stop_reason FROM canary_runs"
    ).fetchone()) == ("stop_requested", "target_revoked")

    conn.execute(
        "UPDATE canary_environments SET verification_record_digest=? WHERE environment_id=?",
        (grant["environment"]["verification_record_digest"], grant["environment"]["environment_id"]),
    )
    conn.commit()
    gate = coordinator.heartbeat(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, snapshot,
    )
    assert gate["active"] is False and gate["stop_reason"] == "target_revoked"


def test_cloud_lifecycle_timestamps_ignore_runner_future_clock():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    future = operational_projection(
        runner, grant, sequence=0, phase="running", requests_started=1,
        updated_at_ms=NOW_MS + 10 * 365 * 24 * 60 * 60 * 1000,
    )
    coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, future)
    run = conn.execute(
        "SELECT started_at_ms,updated_at FROM canary_runs"
    ).fetchone()
    receipt = conn.execute(
        "SELECT created_at,updated_at FROM canary_operational_receipts"
    ).fetchone()
    assert tuple(run) == (NOW_MS, NOW_MS)
    assert tuple(receipt) == (NOW_MS, NOW_MS)


@pytest.mark.parametrize("mutation", ["requests", "bytes", "retries", "wall", "equality"])
def test_operational_counters_are_bounded_by_exact_signed_grant_budget(mutation):
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    value = operational_projection(
        runner, grant, sequence=0, phase="running", requests_started=1,
        updated_at_ms=NOW_MS + 200,
    )
    value["counters"]["actions_contained"] = 1
    if mutation == "requests":
        value["counters"].update(requests_started=3, actions_contained=3, remaining_requests=0)
    elif mutation == "bytes":
        value["counters"].update(
            requests_completed=1, response_bytes_read=65537,
        )
    elif mutation == "retries":
        value["counters"].update(
            requests_started=2, actions_contained=1, retries_used=1, remaining_requests=0,
        )
    elif mutation == "wall":
        value["counters"]["remaining_wall_ms"] = 60_001
    else:
        value["counters"]["actions_contained"] = 0
    value = resign_operational(value, runner)
    with pytest.raises(ValueError):
        coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, value)
    assert conn.execute("SELECT quota_state FROM canary_runs").fetchone()[0] == "reserved"
    assert conn.execute("SELECT COUNT(*) FROM canary_operational_receipts").fetchone()[0] == 0


def test_terminal_stopped_disposition_requires_a_stop_reason():
    _, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    invalid = operational_projection(
        runner, grant, sequence=0, phase="terminal", requests_started=0,
        disposition="stopped", stop_reason="none", updated_at_ms=NOW_MS + 500,
    )
    with pytest.raises(ValueError):
        coordinator.result(WORKSPACE, PROJECT, grant["run_id"], RUNNER, invalid)


def test_stop_reason_and_phase_are_coupled_and_local_stop_is_durable():
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    invalid_running = operational_projection(
        runner, grant, sequence=0, phase="running", stop_reason="local_emergency_stop",
        requests_started=0, updated_at_ms=NOW_MS + 200,
    )
    with pytest.raises(ValueError):
        coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, invalid_running)
    invalid_stop = operational_projection(
        runner, grant, sequence=0, phase="stop_requested", stop_reason="none",
        stop_requested_at_ms=NOW_MS + 200, updated_at_ms=NOW_MS + 200,
    )
    with pytest.raises(ValueError):
        coordinator.progress(WORKSPACE, PROJECT, grant["run_id"], RUNNER, invalid_stop)

    local_stop = operational_projection(
        runner, grant, sequence=0, phase="stop_requested",
        stop_reason="local_emergency_stop", stop_requested_at_ms=NOW_MS + 200,
        updated_at_ms=NOW_MS + 200,
    )
    status = coordinator.progress(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, local_stop,
    )
    assert status["status"] == "stop_requested"
    assert status["stop_reason"] == "local_emergency_stop"
    assert tuple(conn.execute(
        "SELECT stop_requested_at_ms,stop_deadline_ms FROM canary_runs"
    ).fetchone()) == (NOW_MS, NOW_MS + 5000)


def test_cross_tenant_or_wrong_runner_never_reads_run_state():
    _, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    projection = operational_projection(runner, grant, sequence=0, phase="claimed")
    with pytest.raises(LookupError):
        coordinator.heartbeat("ws_other", PROJECT, grant["run_id"], RUNNER, projection)
    with pytest.raises(LookupError):
        coordinator.heartbeat(WORKSPACE, PROJECT, grant["run_id"], "runr_other", projection)


@pytest.mark.parametrize("operation", ["heartbeat", "progress", "result"])
def test_runner_lifecycle_mutations_join_an_outer_pop_transaction(operation):
    conn, _, runner, coordinator, approved, _ = running_setup()
    grant = approved["grant"]
    phase = "terminal" if operation == "result" else "running"
    projection = operational_projection(
        runner,
        grant,
        sequence=0,
        phase=phase,
        requests_started=1,
        requests_completed=1 if operation == "result" else 0,
        disposition="completed" if operation == "result" else None,
        updated_at_ms=NOW_MS + 200,
    )

    conn.execute("BEGIN IMMEDIATE")
    response = getattr(coordinator, operation)(
        WORKSPACE, PROJECT, grant["run_id"], RUNNER, projection,
    )

    assert conn.in_transaction is True
    assert isinstance(response, dict)
    conn.rollback()
    stored = conn.execute(
        "SELECT status,source_event_sequence FROM canary_runs WHERE run_id=?",
        (grant["run_id"],),
    ).fetchone()
    assert tuple(stored) == ("claimed", -1)
