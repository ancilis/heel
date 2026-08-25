"""Short, durable lifecycle reconciliation loop for verified canary runs.

The reaper owns one SQLite connection that is independent from the HTTP control plane.  A cycle
only evaluates durable authority and accounting state; it never performs DNS, HTTP, or other
network I/O and never invents a runner projection or customer finding.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable

from .canary_disclosure import CanaryDisclosureService
from .canary_runs import AUDIT_RETENTION_MS, PROJECTION_RETENTION_MS, CanaryRunService


_LOGGER = logging.getLogger("heel.saas.control_plane")
DEFAULT_INTERVAL_SECONDS = 2.0
HEARTBEAT_STALE_MS = 5_000
STOP_WINDOW_MS = 5_000
STARTUP_TIMEOUT_SECONDS = 5.0
STOP_TIMEOUT_SECONDS = 5.0


class CanaryReaperError(RuntimeError):
    """The production lifecycle coordinator could not start or stop safely."""


class CanaryReaper:
    """Run short lifecycle/retention transactions on one exact durable database."""

    def __init__(
        self,
        database_path: str,
        *,
        signing,
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.time,
        on_unexpected_death: Callable[[BaseException], None] | None = None,
    ):
        if not isinstance(database_path, str) or not database_path or database_path == ":memory:":
            raise ValueError("canary reaper requires an exact durable SQLite path")
        if not Path(database_path).is_absolute():
            raise ValueError("canary reaper requires an absolute SQLite path")
        if signing is None or not callable(getattr(signing, "sign", None)):
            raise TypeError("canary reaper requires the configured grant signing authority")
        if not isinstance(interval_seconds, (int, float)) or interval_seconds <= 0:
            raise ValueError("canary reaper interval must be positive")
        self.database_path = database_path
        self.signing = signing
        self.interval_seconds = float(interval_seconds)
        self.clock = clock
        self.on_unexpected_death = on_unexpected_death
        self._stop = threading.Event()
        self._startup = threading.Event()
        self._state_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._failure: BaseException | None = None

    @property
    def thread(self) -> threading.Thread | None:
        return self._thread

    @property
    def alive(self) -> bool:
        thread = self._thread
        return bool(thread is not None and thread.is_alive() and self._failure is None)

    @property
    def failure(self) -> BaseException | None:
        return self._failure

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=250")
        return connection

    def _service(self, connection: sqlite3.Connection) -> CanaryRunService:
        service = CanaryRunService(
            connection,
            signing=self.signing,
            clock=self.clock,
            initialize_schema=False,
        )
        # CanaryRunService defaults to a request-oriented wait.  The maintenance loop yields
        # quickly instead of holding shutdown/readiness behind another writer.
        connection.execute("PRAGMA busy_timeout=250")
        return service

    def _disclosure_service(
        self, connection: sqlite3.Connection,
    ) -> CanaryDisclosureService:
        service = CanaryDisclosureService(
            connection,
            signing=self.signing,
            clock=self.clock,
            initialize_schema=False,
        )
        connection.execute("PRAGMA busy_timeout=250")
        return service

    @staticmethod
    def _kill_active(connection: sqlite3.Connection, workspace_id: str) -> bool:
        return connection.execute(
            "SELECT 1 FROM kill_switches WHERE scope IN ('global',?) LIMIT 1",
            (workspace_id,),
        ).fetchone() is not None

    def _request_authority_stops(
        self,
        service: CanaryRunService,
        disclosure: CanaryDisclosureService,
        now_ms: int,
    ) -> dict[str, int]:
        connection = service.conn
        counts = {
            "authority_stops": 0,
            "authority_revocations": 0,
            "cancelled_projections": 0,
            "refunded_grants": 0,
            "stale_heartbeats": 0,
            "expired_disclosure_permits": 0,
            "finalized_disconnected": 0,
            "purged_findings": 0,
        }
        generation = int(connection.execute(
            "SELECT generation FROM canary_control_generation WHERE singleton=1"
        ).fetchone()[0])
        pending = connection.execute(
            "SELECT r.*,cr.status AS runner_status,k.status AS key_status,"
            "k.revoked_at AS key_revoked_at,e.status AS proof_status,"
            "e.proof_expires_at,e.revoked_at AS proof_revoked_at "
            "FROM canary_runs r JOIN canary_runners cr "
            "ON cr.workspace_id=r.workspace_id AND cr.runner_id=r.runner_id "
            "JOIN canary_runner_keys k ON k.workspace_id=r.workspace_id "
            "AND k.runner_id=r.runner_id AND k.key_id=r.runner_key_id "
            "JOIN canary_environments e ON e.workspace_id=r.workspace_id "
            "AND e.project_ref=r.project_ref AND e.environment_id=r.environment_id "
            "WHERE r.status='awaiting_execution_approval'"
        ).fetchall()
        for row in pending:
            detail_reason = None
            if (
                row["runner_status"] != "active"
                or row["key_status"] != "active"
                or row["key_revoked_at"] is not None
            ):
                detail_reason = "runner_revoked"
            elif (
                row["proof_status"] != "verified"
                or row["proof_revoked_at"] is not None
            ):
                detail_reason = "target_revoked"
            elif (
                row["proof_expires_at"] is None
                or int(float(row["proof_expires_at"]) * 1000) <= now_ms
            ):
                detail_reason = "proof_expired"
            elif (
                int(row["kill_switch_generation"]) != generation
                or self._kill_active(connection, row["workspace_id"])
            ):
                detail_reason = "kill_switch"
            if detail_reason is None:
                continue
            connection.execute(
                "UPDATE canary_approval_projections SET status='cancelled',purge_at=? "
                "WHERE workspace_id=? AND project_ref=? AND approval_id=? "
                "AND status='awaiting_execution_approval'",
                (
                    now_ms + PROJECTION_RETENTION_MS, row["workspace_id"],
                    row["project_ref"], row["approval_id"],
                ),
            )
            connection.execute(
                "UPDATE canary_runs SET status='cancelled',updated_at=max(updated_at,?) "
                "WHERE workspace_id=? AND project_ref=? AND run_id=? "
                "AND status='awaiting_execution_approval'",
                (now_ms, row["workspace_id"], row["project_ref"], row["run_id"]),
            )
            updated = service._run(row["workspace_id"], row["project_ref"], row["run_id"])
            service._append_event(
                updated, "cancelled", actor_class="system", actor_id="reaper",
                reason_code=detail_reason,
            )
            service._audit(
                updated, "cancelled", subject_ref=row["approval_id"],
                actor_class="system", actor_id="reaper", reason_code=detail_reason,
            )
            counts["cancelled_projections"] += 1
        unclaimed = connection.execute(
            "SELECT r.*,cr.status AS runner_status,k.status AS key_status,"
            "k.revoked_at AS key_revoked_at,e.status AS proof_status,"
            "e.proof_expires_at,e.revoked_at AS proof_revoked_at "
            "FROM canary_runs r JOIN canary_execution_grants g "
            "ON g.workspace_id=r.workspace_id AND g.project_ref=r.project_ref "
            "AND g.grant_id=r.grant_id JOIN canary_runners cr "
            "ON cr.workspace_id=r.workspace_id AND cr.runner_id=r.runner_id "
            "JOIN canary_runner_keys k ON k.workspace_id=r.workspace_id "
            "AND k.runner_id=r.runner_id AND k.key_id=r.runner_key_id "
            "JOIN canary_environments e ON e.workspace_id=r.workspace_id "
            "AND e.project_ref=r.project_ref AND e.environment_id=r.environment_id "
            "WHERE r.status='approved' AND g.status IN ('prepared','approved','issued')"
        ).fetchall()
        for row in unclaimed:
            detail_reason = None
            if (
                row["runner_status"] != "active"
                or row["key_status"] != "active"
                or row["key_revoked_at"] is not None
            ):
                detail_reason = "runner_revoked"
            elif row["proof_status"] != "verified" or row["proof_revoked_at"] is not None:
                detail_reason = "target_revoked"
            elif (
                row["proof_expires_at"] is None
                or int(float(row["proof_expires_at"]) * 1000) <= now_ms
            ):
                detail_reason = "proof_expired"
            elif (
                int(row["kill_switch_generation"]) != generation
                or self._kill_active(connection, row["workspace_id"])
            ):
                detail_reason = "kill_switch"
            if detail_reason is None:
                continue
            refunded = row["quota_state"] == "refunded"
            refund_created = False
            if row["quota_state"] == "reserved":
                refund_created = service.ledger._settle_in_transaction(
                    row["reservation_id"], "refund",
                )
                refunded = refund_created or connection.execute(
                    "SELECT 1 FROM usage_ledger WHERE reservation_id=? AND kind='refund'",
                    (row["reservation_id"],),
                ).fetchone() is not None
                if not refunded:
                    raise RuntimeError("unclaimed canary refund could not be proven")
            connection.execute(
                "UPDATE canary_execution_grants SET status='revoked',purge_at=? "
                "WHERE workspace_id=? AND project_ref=? AND grant_id=? "
                "AND status IN ('prepared','approved','issued')",
                (
                    now_ms + PROJECTION_RETENTION_MS, row["workspace_id"],
                    row["project_ref"], row["grant_id"],
                ),
            )
            connection.execute(
                "UPDATE canary_runs SET status='cancelled',quota_state=?,updated_at=max(updated_at,?) "
                "WHERE workspace_id=? AND project_ref=? AND run_id=? AND status='approved'",
                (
                    "refunded" if refunded else row["quota_state"], now_ms,
                    row["workspace_id"], row["project_ref"], row["run_id"],
                ),
            )
            connection.execute(
                "UPDATE canary_approval_projections SET purge_at=? WHERE workspace_id=? "
                "AND project_ref=? AND approval_id=?",
                (
                    now_ms + PROJECTION_RETENTION_MS, row["workspace_id"],
                    row["project_ref"], row["approval_id"],
                ),
            )
            updated = service._run(row["workspace_id"], row["project_ref"], row["run_id"])
            service._append_event(
                updated, "grant_revoked", actor_class="system", actor_id="reaper",
                reason_code=detail_reason,
            )
            if refund_created:
                service._append_event(
                    updated, "quota_refunded", actor_class="system", actor_id="quota",
                    reason_code=detail_reason,
                )
                service._audit(
                    updated, "quota_refunded", subject_ref=row["reservation_id"],
                    actor_class="system", actor_id="quota", reason_code=detail_reason,
                )
                counts["refunded_grants"] += 1
            service._append_event(
                updated, "cancelled", actor_class="system", actor_id="reaper",
                reason_code=detail_reason,
            )
            service._audit(
                updated, "cancelled", subject_ref=row["grant_id"],
                actor_class="system", actor_id="reaper", reason_code=detail_reason,
            )
            counts["authority_revocations"] += 1
        acknowledged = connection.execute(
            "SELECT r.*,o.receipt_json FROM canary_runs r "
            "LEFT JOIN canary_operational_receipts o ON o.workspace_id=r.workspace_id "
            "AND o.project_ref=r.project_ref AND o.run_id=r.run_id "
            "WHERE r.status='finalizing' AND r.stop_reason!='none' "
            "AND r.stop_acknowledged_at_ms IS NOT NULL "
            "AND COALESCE(r.last_heartbeat_at_ms,r.stop_acknowledged_at_ms,r.updated_at)<=?",
            (now_ms - HEARTBEAT_STALE_MS,),
        ).fetchall()
        for row in acknowledged:
            quota_state = row["quota_state"]
            refund_created = False
            if quota_state == "reserved" and row["receipt_json"] is not None:
                try:
                    receipt = json.loads(row["receipt_json"])
                    requests_started = receipt["counters"]["requests_started"]
                except (KeyError, TypeError, ValueError):
                    requests_started = None
                if type(requests_started) is int and requests_started == 0:
                    refund_created = service.ledger._settle_in_transaction(
                        row["reservation_id"], "refund",
                    )
                    if refund_created or connection.execute(
                        "SELECT 1 FROM usage_ledger WHERE reservation_id=? AND kind='refund'",
                        (row["reservation_id"],),
                    ).fetchone() is not None:
                        quota_state = "refunded"
            connection.execute(
                "UPDATE canary_runs SET status='terminal',execution_disposition='stopped',"
                "quota_state=?,terminal_at_ms=?,updated_at=max(updated_at,?),purge_at=? "
                "WHERE workspace_id=? AND project_ref=? AND run_id=? AND status='finalizing'",
                (
                    quota_state, now_ms, now_ms, now_ms + AUDIT_RETENTION_MS,
                    row["workspace_id"], row["project_ref"], row["run_id"],
                ),
            )
            connection.execute(
                "UPDATE canary_execution_grants SET status='terminal',purge_at=? "
                "WHERE workspace_id=? AND project_ref=? AND grant_id=?",
                (
                    now_ms + PROJECTION_RETENTION_MS, row["workspace_id"],
                    row["project_ref"], row["grant_id"],
                ),
            )
            connection.execute(
                "UPDATE canary_approval_projections SET purge_at=? WHERE workspace_id=? "
                "AND project_ref=? AND approval_id=?",
                (
                    now_ms + PROJECTION_RETENTION_MS, row["workspace_id"],
                    row["project_ref"], row["approval_id"],
                ),
            )
            updated = service._run(row["workspace_id"], row["project_ref"], row["run_id"])
            if refund_created:
                service._append_event(
                    updated, "quota_refunded", actor_class="system", actor_id="quota",
                    reason_code="disconnected_after_stop_ack",
                )
                service._audit(
                    updated, "quota_refunded", subject_ref=row["reservation_id"],
                    actor_class="system", actor_id="quota",
                    reason_code="disconnected_after_stop_ack",
                )
                counts["refunded_grants"] += 1
            service._append_event(
                updated, "terminal", actor_class="system", actor_id="reaper",
                reason_code="disconnected_after_stop_ack", status="terminal",
            )
            service._audit(
                updated, "finalized", subject_ref=row["run_id"],
                actor_class="system", actor_id="reaper",
                reason_code="disconnected_after_stop_ack",
                payload={"execution_disposition": "stopped"},
            )
            counts["finalized_disconnected"] += 1
        rows = connection.execute(
            "SELECT r.*,cr.status AS runner_status,k.status AS key_status,"
            "k.revoked_at AS key_revoked_at,e.status AS proof_status,"
            "e.proof_expires_at,e.revoked_at AS proof_revoked_at,g.status AS grant_status,"
            "g.expires_at AS grant_expires_at FROM canary_runs r "
            "JOIN canary_runners cr ON cr.workspace_id=r.workspace_id "
            "AND cr.runner_id=r.runner_id "
            "JOIN canary_runner_keys k ON k.workspace_id=r.workspace_id "
            "AND k.runner_id=r.runner_id AND k.key_id=r.runner_key_id "
            "JOIN canary_environments e ON e.workspace_id=r.workspace_id "
            "AND e.project_ref=r.project_ref AND e.environment_id=r.environment_id "
            "JOIN canary_execution_grants g ON g.workspace_id=r.workspace_id "
            "AND g.project_ref=r.project_ref AND g.grant_id=r.grant_id "
            "WHERE r.status IN ('claimed','running','finalizing') AND r.stop_reason='none'"
        ).fetchall()
        for row in rows:
            stop_reason = None
            detail_reason = None
            error_category = row["error_category"]
            if (
                row["runner_status"] != "active"
                or row["key_status"] != "active"
                or row["key_revoked_at"] is not None
            ):
                stop_reason = detail_reason = "runner_revoked"
            elif row["proof_revoked_at"] is not None or row["proof_status"] != "verified":
                stop_reason = detail_reason = "target_revoked"
            elif (
                row["proof_expires_at"] is None
                or int(float(row["proof_expires_at"]) * 1000) <= now_ms
            ):
                stop_reason, detail_reason = "target_revoked", "proof_expired"
                error_category = "proof_expired"
            elif (
                self._kill_active(connection, row["workspace_id"])
                or int(row["kill_switch_generation"]) != generation
            ):
                stop_reason = detail_reason = "kill_switch"
            elif row["grant_status"] != "claimed" or int(row["grant_expires_at"]) <= now_ms:
                stop_reason, detail_reason = "cloud_stop", "grant_expired"
            else:
                heartbeat_anchor = next((
                    int(value) for value in (
                        row["last_heartbeat_at_ms"], row["started_at_ms"], row["claimed_at_ms"],
                    ) if value is not None
                ), None)
                if heartbeat_anchor is not None and heartbeat_anchor <= now_ms - HEARTBEAT_STALE_MS:
                    stop_reason, detail_reason = "cloud_stop", "cloud_disconnected"
                    error_category = "cloud_disconnected"
                    counts["stale_heartbeats"] += 1
            if stop_reason is None:
                continue
            next_status = "finalizing" if row["status"] == "finalizing" else "stop_requested"
            connection.execute(
                "UPDATE canary_runs SET status=?,error_category=?,stop_reason=?,"
                "stop_generation=?,stop_requested_at_ms=COALESCE(stop_requested_at_ms,?),"
                "stop_deadline_ms=COALESCE(stop_deadline_ms,?),updated_at=max(updated_at,?) "
                "WHERE workspace_id=? AND project_ref=? AND run_id=? AND stop_reason='none'",
                (
                    next_status, error_category, stop_reason, generation, now_ms,
                    now_ms + STOP_WINDOW_MS, now_ms, row["workspace_id"],
                    row["project_ref"], row["run_id"],
                ),
            )
            updated = service._run(row["workspace_id"], row["project_ref"], row["run_id"])
            service._append_event(
                updated, "stop_requested", actor_class="system", actor_id="reaper",
                reason_code=detail_reason,
            )
            service._audit(
                updated, "stop_requested", subject_ref=row["run_id"],
                actor_class="system", actor_id="reaper", reason_code=detail_reason,
            )
            counts["authority_stops"] += 1

        cursor = connection.execute(
            "UPDATE canary_disclosure_permits SET status='expired' "
            "WHERE status='permitted' AND expires_at<=?", (now_ms,),
        )
        counts["expired_disclosure_permits"] = cursor.rowcount
        counts["purged_findings"] = disclosure.purge_expired_payloads(now_ms=now_ms)
        connection.execute(
            "UPDATE canary_reaper_state SET lease_owner=NULL,lease_expires_at=NULL,last_run_at=? "
            "WHERE singleton=1", (now_ms,),
        )
        return counts

    def _cycle(
        self,
        service: CanaryRunService,
        disclosure: CanaryDisclosureService | None = None,
    ) -> dict[str, int]:
        if disclosure is None:
            disclosure = self._disclosure_service(service.conn)
        counts = service.expire_and_reconcile()
        now_ms = max(0, int(float(self.clock()) * 1000))
        service.conn.execute("BEGIN IMMEDIATE")
        try:
            additional = self._request_authority_stops(service, disclosure, now_ms)
            service.conn.commit()
        except Exception:
            if service.conn.in_transaction:
                service.conn.rollback()
            raise
        for name, value in additional.items():
            counts[name] = counts.get(name, 0) + value
        return counts

    def run_once(self) -> dict[str, int]:
        """Run one bounded cycle on a fresh independent connection."""
        connection = self._connect()
        try:
            return self._cycle(
                self._service(connection), self._disclosure_service(connection),
            )
        finally:
            connection.close()

    def _run(self) -> None:
        connection: sqlite3.Connection | None = None
        failure: BaseException | None = None
        try:
            connection = self._connect()
            service = self._service(connection)
            disclosure = self._disclosure_service(connection)
            self._cycle(service, disclosure)
            self._startup.set()
            while not self._stop.wait(self.interval_seconds):
                self._cycle(service, disclosure)
        except BaseException as error:
            failure = error
            with self._state_lock:
                self._failure = error
            self._startup.set()
        finally:
            if connection is not None:
                connection.close()
        if failure is not None and not self._stop.is_set():
            _LOGGER.error(json.dumps({
                "event": "canary_reaper_died",
                "exception_type": type(failure).__name__,
            }, sort_keys=True, separators=(",", ":")))
            if self.on_unexpected_death is not None:
                self.on_unexpected_death(failure)

    def start(self, *, timeout: float = STARTUP_TIMEOUT_SECONDS) -> None:
        """Start and prove the first cycle before production can report readiness."""
        with self._state_lock:
            if self._thread is not None:
                raise CanaryReaperError("canary reaper already started")
            self._thread = threading.Thread(
                target=self._run, name="heel-canary-reaper", daemon=False,
            )
            self._thread.start()
        if not self._startup.wait(timeout):
            self._stop.set()
            self._thread.join(timeout=STOP_TIMEOUT_SECONDS)
            raise CanaryReaperError("canary reaper startup timed out")
        if self._failure is not None or not self._thread.is_alive():
            self._thread.join(timeout=STOP_TIMEOUT_SECONDS)
            raise CanaryReaperError("canary reaper startup failed") from self._failure

    def stop(self, *, timeout: float = STOP_TIMEOUT_SECONDS) -> bool:
        """Signal and join the non-daemon worker within a bounded shutdown window."""
        self._stop.set()
        thread = self._thread
        if thread is None:
            return True
        if thread is threading.current_thread():
            return False
        thread.join(timeout=timeout)
        return not thread.is_alive()
