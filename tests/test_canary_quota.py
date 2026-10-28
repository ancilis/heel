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


# --- C2: one CANARY_RUNS unit per discovery authorization (discovery contract §5) ---

import re
import tempfile
from pathlib import Path

from heel.saas.catalog import Meter

from test_canary_http import CanaryHttpFixture, DiscoveryDriver, _authorize, _candidates, _env_base, _refs


def _discovery_ledger(fixture):
    return [tuple(row) for row in fixture.cp.store.conn.execute(
        "SELECT kind,ref,amount FROM usage_ledger WHERE meter='canary_runs' ORDER BY ts,entry_id")]


def test_discovery_authorization_reserves_one_unit_for_all_rounds_under_retry():
    with tempfile.TemporaryDirectory() as directory:
        fixture = CanaryHttpFixture(Path(directory))
        try:
            driver = DiscoveryDriver(fixture)
            status, _, retried = _authorize(fixture, 1)
            assert status == 201 and retried["authorization_id"] == driver.authorization_id
            candidates = {round_number: _candidates(round_number, 20) for round_number in range(1, 5)}
            driver.run_round(1, None, candidates[1])
            for round_number in range(2, 6):
                driver.run_round(round_number, _refs(round_number - 1, candidates[round_number - 1]),
                                 candidates.get(round_number))
            assert driver.row()["rounds_issued"] == 5
            assert _discovery_ledger(fixture) == [
                ("reserve", driver.authorization_id, 1), ("consume", driver.authorization_id, 1)]
            usage = fixture.cp.ledger.usage(fixture.workspace, Meter.CANARY_RUNS,
                                            fixture.cp.store.conn.execute("SELECT period FROM usage_ledger").fetchone()[0])
            assert usage == 1
            # C2D D3: rounds hold no unit of their own; the grant names its parent in a namespace
            # the ledger cannot resolve, and every round run is unreserved.
            rows = fixture.cp.store.conn.execute(
                "SELECT g.reservation_id,r.reservation_id,r.quota_state,r.run_id FROM discovery_rounds d "
                "JOIN canary_execution_grants g ON g.grant_id=d.grant_id JOIN canary_runs r ON r.run_id=d.run_id").fetchall()
            assert len(rows) == 5
            for grant_reference, run_reservation, quota_state, run_id in rows:
                assert re.fullmatch(r"dauth:dau_[0-9a-f]{32}:r[1-5]", grant_reference)
                assert (run_reservation, quota_state) == (None, "unreserved")
                status, _, dashboard = fixture.request(
                    "GET", f"/v1/workspaces/{fixture.workspace}/projects/{fixture.project}/canary-runs/{run_id}",
                    headers=fixture.browser)
                assert status == 200 and dashboard["run"]["quota_state"] == "unreserved"
            assert fixture.cp.store.conn.execute(
                "SELECT COUNT(*) FROM usage_ledger WHERE reservation_id LIKE 'dauth:%'").fetchone()[0] == 0
        finally:
            fixture.close()


def test_discovery_authorization_refunds_only_when_no_round_issued():
    with tempfile.TemporaryDirectory() as directory:
        fixture = CanaryHttpFixture(Path(directory))
        try:
            status, _, untouched = _authorize(fixture, 1)
            revoke = _env_base(fixture) + "/discovery-authorizations/{}/revoke"
            status, _, revoked = fixture.request("POST", revoke.format(untouched["authorization_id"]), headers=fixture.browser)
            assert status == 200 and revoked["quota_state"] == "refunded"
            used = DiscoveryDriver(fixture, key=2)
            used.run_round(1, None, _candidates(1, 2))
            status, _, closed = fixture.request("POST", revoke.format(used.authorization_id), headers=fixture.browser)
            assert status == 200 and closed["quota_state"] == "consumed"
            assert _discovery_ledger(fixture) == [
                ("reserve", untouched["authorization_id"], 1), ("refund", untouched["authorization_id"], 1),
                ("reserve", used.authorization_id, 1), ("consume", used.authorization_id, 1),
            ]
            # The refunded key can never be replayed into a new charge-free row.
            status, _, data = _authorize(fixture, 1)
            assert (status, data["code"]) == (409, "idempotency_conflict")
            # An untouched authorization is expired and refunded by the reaper alone, once.
            idle = _authorize(fixture, 3)[2]
            fixture.cp.store.conn.execute(
                "UPDATE discovery_authorizations SET created_at_ms=created_at_ms-900001,expires_at_ms=expires_at_ms-900001 "
                "WHERE authorization_id=?", (idle["authorization_id"],))
            fixture.cp.store.conn.commit()
            for _ in range(2):
                fixture.cp.canary_runs.expire_and_reconcile()
            assert fixture.cp.store.conn.execute(
                "SELECT state,quota_state FROM discovery_authorizations WHERE authorization_id=?",
                (idle["authorization_id"],)).fetchone()[:] == ("expired", "refunded")
            assert _discovery_ledger(fixture)[-2:] == [("reserve", idle["authorization_id"], 1), ("refund", idle["authorization_id"], 1)]
        finally:
            fixture.close()


def test_discovery_round_runs_never_touch_the_ledger_through_run_settlement_paths():
    with tempfile.TemporaryDirectory() as directory:
        fixture = CanaryHttpFixture(Path(directory))
        try:
            driver = DiscoveryDriver(fixture)
            # Zero-request terminal: a scan run would refund its own unit here.
            assert driver.submit(driver.projection(1, None))[0] == 201
            claimed = driver.claim()
            assert driver.finish(claimed, _candidates(1, 4), completed=0, round_number=1,
                                 disposition="incomplete", error_category="target_unavailable")[0] == 200
            # Consumed platform fault: a scan run would be compensated here.
            assert driver.submit(driver.projection(2, _refs(1, _candidates(1, 4)[:2])))[0] == 201
            claimed = driver.claim()
            assert driver.finish(claimed, _candidates(2, 2), completed=0, started=1, round_number=2,
                                 disposition="failed", error_category="platform_fault")[0] == 200
            # Issued, never claimed, grant expires: a scan run would refund here.
            status, _, issued = driver.submit(driver.projection(3, _refs(2, _candidates(2, 2)[:1])))
            assert status == 201
            fixture.cp.store.conn.execute(
                "UPDATE canary_execution_grants SET issued_at=issued_at-601000,expires_at=expires_at-601000 WHERE grant_id=?",
                (issued["grant"]["grant_id"],))
            fixture.cp.store.conn.execute(
                "UPDATE discovery_rounds SET issued_at_ms=issued_at_ms-601000 WHERE grant_id=?", (issued["grant"]["grant_id"],))
            fixture.cp.store.conn.commit()
            fixture.cp.canary_runs.expire_and_reconcile()
            assert fixture.cp.store.conn.execute(
                "SELECT state FROM discovery_rounds WHERE authorization_id=? AND round=3",
                (driver.authorization_id,)).fetchone()[0] == "terminal"
            # Runner revocation mid-round on a second authorization: a scan run would refund here.
            later = DiscoveryDriver(fixture, key=2, chain=driver.chain, binding=driver.binding)
            assert later.submit(later.projection(1, None))[0] == 201
            claimed = later.claim()
            assert fixture.cp.runner_auth.revoke(fixture.workspace, fixture.runner_id, actor=fixture.user,
                                                 reason_code="human_revocation") is True
            fixture.cp.store.conn.execute("UPDATE canary_runs SET stop_deadline_ms=1 WHERE run_id=?", (claimed["run_id"],))
            fixture.cp.store.conn.commit()
            for _ in range(2):
                fixture.cp.canary_runs.expire_and_reconcile()
            assert fixture.cp.store.conn.execute(
                "SELECT state FROM discovery_rounds WHERE run_id=?", (claimed["run_id"],)).fetchone()[0] == "terminal"
            assert _discovery_ledger(fixture) == [
                ("reserve", driver.authorization_id, 1), ("consume", driver.authorization_id, 1),
                ("reserve", later.authorization_id, 1), ("consume", later.authorization_id, 1),
            ]
            assert {row[0] for row in fixture.cp.store.conn.execute(
                "SELECT r.quota_state FROM canary_runs r JOIN discovery_rounds d ON d.run_id=r.run_id")} == {"unreserved"}
        finally:
            fixture.close()


def test_discovery_close_proves_an_existing_ledger_refund_instead_of_wedging():
    with tempfile.TemporaryDirectory() as directory:
        fixture = CanaryHttpFixture(Path(directory))
        try:
            status, _, view = _authorize(fixture, 1)
            reservation = fixture.cp.store.conn.execute(
                "SELECT reservation_id FROM discovery_authorizations WHERE authorization_id=?",
                (view["authorization_id"],)).fetchone()[0]
            assert fixture.cp.ledger.refund(reservation) is True  # e.g. an operator reconcile repair
            revoke = _env_base(fixture) + "/discovery-authorizations/" + view["authorization_id"] + "/revoke"
            status, _, closed = fixture.request("POST", revoke, headers=fixture.browser)
            assert status == 200 and (closed["state"], closed["quota_state"]) == ("revoked", "refunded")
            assert [kind for kind, _, _ in _discovery_ledger(fixture)] == ["reserve", "refund"]
        finally:
            fixture.close()


def test_discovery_membership_close_refunds_only_a_zero_issued_authorization():
    """C2R1 F2: a role-loss close settles quota like any other close (§5), never twice."""
    with tempfile.TemporaryDirectory() as directory:
        fixture = CanaryHttpFixture(Path(directory))
        try:
            conn = fixture.cp.store.conn
            untouched = DiscoveryDriver(fixture, key=1)
            conn.execute("UPDATE memberships SET role='member' WHERE workspace_id=? AND user_id=?",
                         (fixture.workspace, fixture.user))
            conn.commit()
            projection = untouched.projection(1, None)
            for _ in range(2):
                status, _, data = untouched.submit(projection)
                assert (status, data["code"]) == (409, "authorization_closed")
            assert _discovery_ledger(fixture) == [
                ("reserve", untouched.authorization_id, 1), ("refund", untouched.authorization_id, 1)]
            conn.execute("UPDATE memberships SET role='owner' WHERE workspace_id=? AND user_id=?",
                         (fixture.workspace, fixture.user))
            conn.commit()
            used = DiscoveryDriver(fixture, key=2, chain=untouched.chain, binding=untouched.binding)
            candidates = _candidates(1, 2)
            used.run_round(1, None, candidates)
            conn.execute("UPDATE memberships SET role='member' WHERE workspace_id=? AND user_id=?",
                         (fixture.workspace, fixture.user))
            conn.commit()
            for _ in range(2):
                status, _, data = used.submit(used.projection(2, _refs(1, candidates[:1])))
                assert (status, data["code"]) == (409, "authorization_closed")
            assert used.row()["quota_state"] == "consumed"
            assert _discovery_ledger(fixture)[2:] == [
                ("reserve", used.authorization_id, 1), ("consume", used.authorization_id, 1)]
            period = conn.execute("SELECT period FROM usage_ledger LIMIT 1").fetchone()[0]
            assert fixture.cp.ledger.usage(fixture.workspace, Meter.CANARY_RUNS, period) == 1
        finally:
            fixture.close()
