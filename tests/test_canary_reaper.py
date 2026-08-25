"""Durable canary lifecycle/reaper integration tests."""
from __future__ import annotations

import sqlite3
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest

from heel.crypto import SigningAuthority
from heel.saas.canary_reaper import CanaryReaper
from heel.saas.runner_contexts import RunnerContextBindingService

from canary_test_support import (
    Clock,
    NOW_MS,
    PROJECT,
    RUNNER,
    WORKSPACE,
    approval_projection,
    connect,
    operational_projection,
    seed_authority,
    service,
)
from test_canary_lifecycle import resign_operational, running_setup


def _durable_running_setup(root: Path):
    source, clock, _runner, coordinator, approved, _claim = running_setup()
    database = root / "heel.sqlite3"
    durable = sqlite3.connect(database)
    source.backup(durable)
    durable.close()
    source.close()
    return database, clock, coordinator.signing, approved


def _durable_pending_setup(root: Path):
    source = connect()
    clock = Clock()
    runner = seed_authority(source)
    coordinator = service(source, clock)
    submitted = coordinator.submit_projection(
        approval_projection(runner), uploaded_by="user_owner",
    )
    database = root / "heel.sqlite3"
    durable = sqlite3.connect(database)
    source.backup(durable)
    durable.close()
    source.close()
    return database, clock, coordinator.signing, submitted


def test_context_expiry_cancels_linked_pending_run_before_generic_approval_expiry():
    with tempfile.TemporaryDirectory() as tmp:
        source = connect()
        clock = Clock()
        runner = seed_authority(source, proof_expires_at=clock.value + 48 * 60 * 60)
        signing = SigningAuthority.generate()
        contexts = RunnerContextBindingService(source, signing=signing, clock=clock)
        contexts.create(
            WORKSPACE, PROJECT,
            {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": "env_canary",
             "verification_record_digest": "a" * 64, "runner_id": RUNNER,
             "runner_key_id": runner.key_id}, actor="user_owner", role="owner",
        )
        binding = source.execute("SELECT * FROM canary_runner_context_bindings").fetchone()
        coordinator = service(source, clock, grant_signer=signing)
        projection = approval_projection(runner)
        source.execute("BEGIN IMMEDIATE")
        submitted = coordinator.submit_projection_from_runner_in_transaction(
            projection, binding, uploaded_by_runner_id=RUNNER,
        )
        source.commit()
        database = Path(tmp) / "heel.sqlite3"
        durable = sqlite3.connect(database)
        source.backup(durable)
        durable.close()
        source.close()
        clock.value += 25 * 60 * 60

        CanaryReaper(str(database), signing=signing, clock=clock).run_once()
        connection = sqlite3.connect(database)
        try:
            assert connection.execute(
                "SELECT status FROM canary_approval_projections WHERE approval_id=?", (submitted["approval_id"],),
            ).fetchone()[0] == "cancelled"
            assert connection.execute(
                "SELECT status FROM canary_runs WHERE run_id=?", (submitted["run_id"],),
            ).fetchone()[0] == "cancelled"
            assert connection.execute(
                "SELECT actor_class,actor_id,reason_code FROM canary_run_events "
                "WHERE run_id=? AND event_type='cancelled'", (submitted["run_id"],),
            ).fetchone() == ("system", "control-plane", "runner_context_expired")
            assert connection.execute(
                "SELECT COUNT(*) FROM canary_run_events WHERE run_id=? AND event_type='expired'", (submitted["run_id"],),
            ).fetchone()[0] == 0
        finally:
            connection.close()


def test_reaper_runs_on_the_exact_durable_database_and_stops_its_non_daemon_thread():
    with tempfile.TemporaryDirectory() as tmp:
        database, clock, signing, _approved = _durable_running_setup(Path(tmp))
        callback = threading.Event()
        reaper = CanaryReaper(
            str(database), signing=signing, clock=clock,
            interval_seconds=0.01, on_unexpected_death=lambda _error: callback.set(),
        )

        reaper.start()
        try:
            assert reaper.database_path == str(database)
            assert reaper.alive is True
            assert reaper.thread is not None
            assert reaper.thread.daemon is False
            control = sqlite3.connect(database)
            try:
                assert control.execute(
                    "SELECT last_run_at FROM canary_reaper_state WHERE singleton=1"
                ).fetchone()[0] == NOW_MS
            finally:
                control.close()
        finally:
            assert reaper.stop(timeout=2) is True

        assert reaper.alive is False
        assert callback.is_set() is False


def test_reaper_cycle_performs_no_network_io(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("reaper attempted network I/O")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    with tempfile.TemporaryDirectory() as tmp:
        database, clock, signing, _approved = _durable_running_setup(Path(tmp))
        CanaryReaper(str(database), signing=signing, clock=clock).run_once()


def test_reaper_yields_quickly_when_an_http_writer_holds_the_database_lock():
    with tempfile.TemporaryDirectory() as tmp:
        database, clock, signing, _approved = _durable_running_setup(Path(tmp))
        writer = sqlite3.connect(database)
        writer.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        try:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                CanaryReaper(str(database), signing=signing, clock=clock).run_once()
        finally:
            writer.rollback()
            writer.close()
        assert time.monotonic() - started < 1


def test_background_reaper_skips_one_routine_writer_lock_without_firing_death_callback():
    with tempfile.TemporaryDirectory() as tmp:
        database, clock, signing, _approved = _durable_running_setup(Path(tmp))
        callback_errors: list[BaseException] = []
        reaper = CanaryReaper(
            str(database), signing=signing, clock=clock,
            interval_seconds=0.01, on_unexpected_death=callback_errors.append,
        )
        reaper.start()
        writer = sqlite3.connect(database)
        try:
            writer.execute("BEGIN IMMEDIATE")
            time.sleep(0.40)
            assert reaper.alive is True
            assert callback_errors == []
        finally:
            writer.rollback()
            writer.close()
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline and reaper.failure is not None:
            time.sleep(0.01)
        try:
            assert reaper.alive is True
            assert reaper.failure is None
            assert callback_errors == []
        finally:
            assert reaper.stop(timeout=2) is True


def test_background_reaper_reports_only_after_bounded_consecutive_lock_failures(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        database, clock, signing, _approved = _durable_running_setup(Path(tmp))
        attempts = 0

        def always_locked(self, service, disclosure=None):
            nonlocal attempts
            attempts += 1
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(CanaryReaper, "_cycle", always_locked)
        callback = threading.Event()
        reaper = CanaryReaper(
            str(database), signing=signing, clock=clock,
            interval_seconds=0.01, on_unexpected_death=lambda _error: callback.set(),
        )
        with pytest.raises(Exception, match="startup failed"):
            reaper.start(timeout=2)
        assert callback.wait(1) is True
        assert attempts == reaper.MAX_CONSECUTIVE_LOCK_FAILURES
        assert isinstance(reaper.failure, sqlite3.OperationalError)


def test_repeated_cycles_never_run_schema_ddl_or_widen_connection_pragmas(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        database, clock, signing, _approved = _durable_running_setup(Path(tmp))
        real_connect = sqlite3.connect
        statements: list[str] = []
        authorizer_events: list[tuple[int, str | None, str | None]] = []

        def traced_connect(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            connection.set_trace_callback(statements.append)

            def authorize(action, arg1, arg2, _database, _trigger):
                authorizer_events.append((action, arg1, arg2))
                return sqlite3.SQLITE_OK

            connection.set_authorizer(authorize)
            return connection

        monkeypatch.setattr("heel.saas.canary_reaper.sqlite3.connect", traced_connect)
        reaper = CanaryReaper(str(database), signing=signing, clock=clock)
        reaper.run_once()
        reaper.run_once()

        ddl_actions = {
            sqlite3.SQLITE_ALTER_TABLE,
            sqlite3.SQLITE_CREATE_INDEX,
            sqlite3.SQLITE_CREATE_TABLE,
            sqlite3.SQLITE_CREATE_TEMP_INDEX,
            sqlite3.SQLITE_CREATE_TEMP_TABLE,
            sqlite3.SQLITE_CREATE_TEMP_TRIGGER,
            sqlite3.SQLITE_CREATE_TEMP_VIEW,
            sqlite3.SQLITE_CREATE_TRIGGER,
            sqlite3.SQLITE_CREATE_VIEW,
            sqlite3.SQLITE_DROP_INDEX,
            sqlite3.SQLITE_DROP_TABLE,
            sqlite3.SQLITE_DROP_TEMP_INDEX,
            sqlite3.SQLITE_DROP_TEMP_TABLE,
            sqlite3.SQLITE_DROP_TEMP_TRIGGER,
            sqlite3.SQLITE_DROP_TEMP_VIEW,
            sqlite3.SQLITE_DROP_TRIGGER,
            sqlite3.SQLITE_DROP_VIEW,
        }
        assert [event for event in authorizer_events if event[0] in ddl_actions] == []
        pragmas = [
            (str(name).lower(), None if value is None else str(value).lower())
            for action, name, value in authorizer_events
            if action == sqlite3.SQLITE_PRAGMA
        ]
        assert [item for item in pragmas if item[0] == "journal_mode"] == []
        assert pragmas.count(("foreign_keys", "on")) == 2
        assert len([item for item in pragmas if item == ("busy_timeout", "250")]) >= 2
        assert [
            item for item in pragmas
            if item[0] == "busy_timeout" and item[1] != "250"
        ] == []
        normalized = [statement.lstrip().upper() for statement in statements]
        assert not any(
            statement.startswith(("CREATE ", "ALTER ", "DROP "))
            for statement in normalized
        )


def test_stale_heartbeat_is_stopped_then_minimally_finalized_without_a_runner_receipt():
    with tempfile.TemporaryDirectory() as tmp:
        database, clock, signing, _approved = _durable_running_setup(Path(tmp))
        reaper = CanaryReaper(str(database), signing=signing, clock=clock)

        clock.value += 6
        first = reaper.run_once()
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(
                "SELECT status,error_category,stop_reason,stop_deadline_ms,quota_state "
                "FROM canary_runs"
            ).fetchone()
            assert tuple(row) == (
                "stop_requested", "cloud_disconnected", "cloud_stop",
                NOW_MS + 11_000, "reserved",
            )
            assert connection.execute(
                "SELECT COUNT(*) FROM canary_operational_receipts"
            ).fetchone()[0] == 0
            assert first["stale_heartbeats"] == 1
        finally:
            connection.close()

        clock.value += 6
        second = reaper.run_once()
        connection = sqlite3.connect(database)
        try:
            assert tuple(connection.execute(
                "SELECT status,execution_disposition,error_category,quota_state "
                "FROM canary_runs"
            ).fetchone()) == (
                "terminal", "stopped", "cloud_disconnected", "refunded",
            )
            assert connection.execute(
                "SELECT COUNT(*) FROM canary_operational_receipts"
            ).fetchone()[0] == 0
            assert second["finalized_orphans"] == 1
        finally:
            connection.close()


def test_acknowledged_finalizing_run_is_minimally_closed_only_after_heartbeat_disconnects():
    with tempfile.TemporaryDirectory() as tmp:
        source, clock, runner, coordinator, approved, _claim = running_setup()
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
        coordinator.ack_stop(
            WORKSPACE, PROJECT, grant["run_id"], RUNNER,
            operational_projection(
                runner, grant, sequence=1, phase="finalizing", requests_started=1,
                stop_reason="cloud_stop", stop_requested_at_ms=NOW_MS,
                stop_acknowledged_at_ms=NOW_MS + 300, updated_at_ms=NOW_MS + 300,
            ),
        )
        database = Path(tmp) / "heel.sqlite3"
        durable = sqlite3.connect(database)
        source.backup(durable)
        durable.close()
        source.close()
        clock.value += 6

        counts = CanaryReaper(
            str(database), signing=coordinator.signing, clock=clock,
        ).run_once()

        connection = sqlite3.connect(database)
        try:
            assert tuple(connection.execute(
                "SELECT status,execution_disposition,quota_state FROM canary_runs"
            ).fetchone()) == ("terminal", "stopped", "consumed")
            # The last validated runner receipt remains finalizing; the reaper did not forge a
            # terminal runner projection to match its minimal cloud lifecycle record.
            assert connection.execute(
                "SELECT lifecycle_phase FROM canary_operational_receipts"
            ).fetchone()[0] == "finalizing"
            assert counts["finalized_disconnected"] == 1
        finally:
            connection.close()


def test_live_authority_changes_request_a_bounded_stop_without_fabricating_outcome():
    cases = (
        ("UPDATE canary_runners SET status='revoked'", "runner_revoked", "none"),
        ("UPDATE canary_environments SET proof_expires_at=0", "target_revoked", "proof_expired"),
        (
            "INSERT INTO kill_switches(scope,reason,actor,tripped_at) "
            "VALUES('global','incident','admin',1)",
            "kill_switch", "none",
        ),
    )
    for statement, expected_stop, expected_error in cases:
        with tempfile.TemporaryDirectory() as tmp:
            database, clock, signing, _approved = _durable_running_setup(Path(tmp))
            connection = sqlite3.connect(database)
            connection.execute(statement)
            connection.commit()
            connection.close()

            counts = CanaryReaper(
                str(database), signing=signing, clock=clock,
            ).run_once()
            connection = sqlite3.connect(database)
            try:
                assert tuple(connection.execute(
                    "SELECT status,stop_reason,error_category,execution_disposition "
                    "FROM canary_runs"
                ).fetchone()) == (
                    "stop_requested", expected_stop, expected_error, None,
                )
                assert counts["authority_stops"] == 1
            finally:
                connection.close()


def test_reproof_digest_replacement_is_a_permanent_authority_stop():
    with tempfile.TemporaryDirectory() as tmp:
        database, clock, signing, approved = _durable_running_setup(Path(tmp))
        connection = sqlite3.connect(database)
        connection.execute(
            "UPDATE canary_environments SET verification_record_digest=?",
            ("b" * 64,),
        )
        connection.commit()
        connection.close()

        counts = CanaryReaper(str(database), signing=signing, clock=clock).run_once()
        connection = sqlite3.connect(database)
        try:
            assert tuple(connection.execute(
                "SELECT status,stop_reason FROM canary_runs"
            ).fetchone()) == ("stop_requested", "target_revoked")
            assert counts["authority_stops"] == 1
            connection.execute(
                "UPDATE canary_environments SET verification_record_digest=?",
                (approved["grant"]["environment"]["verification_record_digest"],),
            )
            connection.commit()
        finally:
            connection.close()

        CanaryReaper(str(database), signing=signing, clock=clock).run_once()
        connection = sqlite3.connect(database)
        try:
            assert tuple(connection.execute(
                "SELECT status,stop_reason FROM canary_runs"
            ).fetchone()) == ("stop_requested", "target_revoked")
        finally:
            connection.close()


def test_future_runner_receipt_time_cannot_hide_a_stale_active_claim():
    with tempfile.TemporaryDirectory() as tmp:
        source, clock, runner, coordinator, approved, _claim = running_setup()
        grant = approved["grant"]
        future = NOW_MS + 10 * 365 * 24 * 60 * 60 * 1000
        projection = operational_projection(
            runner, grant, sequence=0, phase="running", requests_started=1,
            updated_at_ms=future,
        )
        projection["timestamps"].update(
            claimed_at_ms=future, started_at_ms=future, updated_at_ms=future,
        )
        projection = resign_operational(projection, runner)
        coordinator.progress(
            WORKSPACE, PROJECT, grant["run_id"], RUNNER,
            projection,
        )
        database = Path(tmp) / "heel.sqlite3"
        durable = sqlite3.connect(database)
        source.backup(durable)
        durable.close()
        source.close()
        clock.value += 6

        counts = CanaryReaper(str(database), signing=coordinator.signing, clock=clock).run_once()
        connection = sqlite3.connect(database)
        try:
            assert tuple(connection.execute(
                "SELECT status,stop_reason,error_category FROM canary_runs"
            ).fetchone()) == ("stop_requested", "cloud_stop", "cloud_disconnected")
            assert counts["stale_heartbeats"] == 1
        finally:
            connection.close()


def test_future_runner_ack_time_cannot_evade_disconnected_finalization():
    with tempfile.TemporaryDirectory() as tmp:
        source, clock, runner, coordinator, approved, _claim = running_setup()
        grant = approved["grant"]
        coordinator.request_stop(
            WORKSPACE, PROJECT, grant["run_id"], actor="user_owner",
            reason="cloud_stop", expected_kill_switch_generation=0,
        )
        future = NOW_MS + 10 * 365 * 24 * 60 * 60 * 1000
        coordinator.ack_stop(
            WORKSPACE, PROJECT, grant["run_id"], RUNNER,
            operational_projection(
                runner, grant, sequence=0, phase="finalizing", requests_started=0,
                stop_reason="cloud_stop", stop_requested_at_ms=future,
                stop_acknowledged_at_ms=future, updated_at_ms=future,
            ),
        )
        database = Path(tmp) / "heel.sqlite3"
        durable = sqlite3.connect(database)
        source.backup(durable)
        durable.close()
        source.close()
        clock.value += 60

        counts = CanaryReaper(str(database), signing=coordinator.signing, clock=clock).run_once()
        connection = sqlite3.connect(database)
        try:
            assert connection.execute(
                "SELECT status FROM canary_runs"
            ).fetchone()[0] == "terminal"
            assert counts["finalized_disconnected"] == 1
        finally:
            connection.close()


def test_pending_projection_after_historical_trip_clear_uses_current_generation():
    with tempfile.TemporaryDirectory() as tmp:
        source = connect()
        clock = Clock()
        runner = seed_authority(source)
        source.execute(
            "INSERT INTO kill_switches(scope,reason,actor,tripped_at) VALUES('global','x','a',?)",
            (clock.value,),
        )
        source.execute("DELETE FROM kill_switches WHERE scope='global'")
        source.commit()
        coordinator = service(source, clock)
        submitted = coordinator.submit_projection(
            approval_projection(runner), uploaded_by="user_owner",
        )
        assert source.execute(
            "SELECT kill_switch_generation FROM canary_runs WHERE run_id=?",
            (submitted["run_id"],),
        ).fetchone()[0] == 2
        database = Path(tmp) / "heel.sqlite3"
        durable = sqlite3.connect(database)
        source.backup(durable)
        durable.close()
        source.close()

        counts = CanaryReaper(
            str(database), signing=coordinator.signing, clock=clock,
        ).run_once()
        connection = sqlite3.connect(database)
        try:
            assert connection.execute(
                "SELECT status FROM canary_runs WHERE run_id=?", (submitted["run_id"],),
            ).fetchone()[0] == "awaiting_execution_approval"
            assert counts["cancelled_projections"] == 0
        finally:
            connection.close()


def test_authority_loss_revokes_and_refunds_an_unclaimed_grant_in_the_same_cycle():
    with tempfile.TemporaryDirectory() as tmp:
        database, clock, signing, approved = _durable_running_setup(Path(tmp))
        connection = sqlite3.connect(database)
        connection.execute("DELETE FROM canary_consumed_nonces")
        connection.execute("DELETE FROM canary_runner_nonce_chains WHERE chain_name!='claim'")
        connection.execute("DELETE FROM canary_runner_chain_cursors WHERE chain_name!='claim'")
        connection.execute(
            "UPDATE canary_execution_grants SET status='issued',claimed_at=NULL"
        )
        connection.execute(
            "UPDATE canary_runs SET status='approved',claimed_at_ms=NULL"
        )
        connection.execute("UPDATE canary_runners SET status='revoked'")
        connection.commit()
        connection.close()

        counts = CanaryReaper(
            str(database), signing=signing, clock=clock,
        ).run_once()

        connection = sqlite3.connect(database)
        try:
            assert tuple(connection.execute(
                "SELECT status,quota_state,execution_disposition FROM canary_runs"
            ).fetchone()) == ("cancelled", "refunded", None)
            assert connection.execute(
                "SELECT status FROM canary_execution_grants"
            ).fetchone()[0] == "revoked"
            assert connection.execute(
                "SELECT COUNT(*) FROM usage_ledger WHERE reservation_id=? AND kind='refund'",
                (approved["reservation_id"],),
            ).fetchone()[0] == 1
            assert counts["authority_revocations"] == 1
        finally:
            connection.close()


def test_unclaimed_proof_expiry_is_audited_as_proof_expiry_not_runner_revocation():
    with tempfile.TemporaryDirectory() as tmp:
        database, clock, signing, _approved = _durable_running_setup(Path(tmp))
        connection = sqlite3.connect(database)
        connection.execute("DELETE FROM canary_consumed_nonces")
        connection.execute("DELETE FROM canary_runner_nonce_chains WHERE chain_name!='claim'")
        connection.execute("DELETE FROM canary_runner_chain_cursors WHERE chain_name!='claim'")
        connection.execute("UPDATE canary_execution_grants SET status='issued',claimed_at=NULL")
        connection.execute("UPDATE canary_runs SET status='approved',claimed_at_ms=NULL")
        connection.execute("UPDATE canary_environments SET proof_expires_at=0")
        connection.commit()
        connection.close()

        CanaryReaper(str(database), signing=signing, clock=clock).run_once()

        connection = sqlite3.connect(database)
        try:
            reasons = {
                row[0] for row in connection.execute(
                    "SELECT reason_code FROM canary_run_events WHERE reason_code IS NOT NULL"
                )
            }
            assert "proof_expired" in reasons
            assert "runner_revoked" not in reasons
        finally:
            connection.close()


def test_authority_loss_cancels_a_pending_projection_without_reserving_quota():
    with tempfile.TemporaryDirectory() as tmp:
        database, clock, signing, _submitted = _durable_pending_setup(Path(tmp))
        connection = sqlite3.connect(database)
        connection.execute("UPDATE canary_runners SET status='revoked'")
        connection.commit()
        connection.close()

        counts = CanaryReaper(
            str(database), signing=signing, clock=clock,
        ).run_once()

        connection = sqlite3.connect(database)
        try:
            assert connection.execute(
                "SELECT status FROM canary_approval_projections"
            ).fetchone()[0] == "cancelled"
            assert connection.execute(
                "SELECT status FROM canary_runs"
            ).fetchone()[0] == "cancelled"
            assert connection.execute(
                "SELECT COUNT(*) FROM usage_ledger WHERE meter='canary_runs'"
            ).fetchone()[0] == 0
            assert counts["cancelled_projections"] == 1
        finally:
            connection.close()


def test_reaper_purges_only_payloads_at_the_24_hour_and_7_day_boundaries():
    with tempfile.TemporaryDirectory() as tmp:
        database, clock, signing, _approved = _durable_running_setup(Path(tmp))
        purge_at = NOW_MS + 1
        clock.value += 2
        connection = sqlite3.connect(database)
        connection.execute(
            "UPDATE canary_approval_projections SET purge_at=?", (purge_at,),
        )
        connection.execute(
            "UPDATE canary_execution_grants SET purge_at=?", (purge_at,),
        )
        connection.execute(
            "INSERT INTO canary_operational_receipts("
            "run_id,workspace_id,project_ref,grant_id,runner_id,runner_key_id,"
            "source_event_sequence,lifecycle_phase,execution_disposition,error_category,"
            "stop_reason,receipt_digest,receipt_json,created_at,updated_at,purge_at) "
            "SELECT run_id,workspace_id,project_ref,grant_id,runner_id,runner_key_id,"
            "0,'claimed',NULL,'none','none',?, '{}',?,?,? FROM canary_runs",
            ("f" * 64, NOW_MS, NOW_MS, purge_at),
        )
        connection.commit()
        connection.close()

        CanaryReaper(str(database), signing=signing, clock=clock).run_once()
        connection = sqlite3.connect(database)
        try:
            assert connection.execute(
                "SELECT projection_json FROM canary_approval_projections"
            ).fetchone()[0] is None
            assert connection.execute(
                "SELECT grant_json FROM canary_execution_grants"
            ).fetchone()[0] is None
            assert connection.execute(
                "SELECT receipt_json FROM canary_operational_receipts"
            ).fetchone()[0] is None
            # The relational authority/accounting spine is retained.
            assert connection.execute("SELECT COUNT(*) FROM canary_runs").fetchone()[0] == 1
            assert connection.execute("SELECT COUNT(*) FROM usage_ledger").fetchone()[0] == 1
        finally:
            connection.close()
