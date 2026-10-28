"""Control-plane host-authority snapshot decision and its private listener service (H1A-2).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

``HostSnapshotDecider`` is the ``decide`` callable the frozen H1A-1 listener
(``heel.saas.host_authority``) was built to receive. Each request gets its own SQLite connection,
one ``BEGIN IMMEDIATE`` and one wall-clock sample inside it; the ledger of migration 31 is written
first, then the single active run of the request's workspace is selected, the request's issued
tuple is compared by exact equality, and only then is live state evaluated in one fixed
precedence. Every ledger outcome that must persist is a reply, so it commits with the reply; an
exception is raised only where nothing needs to persist, and the listener answers it with its
existing 500/no-body outcome.

``HostAuthorityService`` runs the listener on one non-daemon thread. ``stop()`` declares draining
before any cleanup, closes the listener, joins the thread and then quarantines the decider, so a
thread that outlives the join can never open the database again. It reports a ``StopResult``; the
caller releases database ownership only when the thread was joined.

Ledger rows are permanent: nothing here removes a row from ``host_authority_generations``.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable, NamedTuple
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from heel.crypto import load_public_key_base64

from .canary_runs import CanaryRunError, CanaryRunService
from .host_authority import (
    RESPONSE_SCHEMA, SAFE_INT, HostAuthorityConfig, HostAuthorityListener, request_digest, validate_response,
)

__all__ = (
    "HostAuthorityService", "HostAuthorityServiceError", "HostSnapshotDecider", "HostSnapshotError", "StopResult",
)

_LOGGER = logging.getLogger("heel.saas.control_plane")

LEDGER_TABLE = "host_authority_generations"
CP_GAP_TOLERANCE_MS = 500
MAX_EFFECTIVE_REMAINING_MS = 86_400_000  # host-side sanity bound (H1A-3); documented here, not applied
MAX_GRANT_REMAINING_MS = 600_000
MAX_BINDING_REMAINING_MS = 86_400_000
MAX_PROOF_REMAINING_MS = 2_592_000_000
MAX_GENERATION_ROWS = 65_536
SNAPSHOT_BUSY_TIMEOUT_MS = 250
STARTUP_TIMEOUT_SECONDS = 5.0
STOP_TIMEOUT_SECONDS = 6.0
QUARANTINE_TIMEOUT_SECONDS = 3.0

_SNAPSHOT_CODES = frozenset({
    "db_busy", "db_error", "malformed_state", "generation_capacity_exhausted", "service_stopped",
})
_SERVICE_CODES = frozenset({
    "thread_start_failed", "startup_timeout", "startup_failed", "listener_exited", "stop_timeout",
    "restart_refused",
})


def _log(document: dict) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


class HostSnapshotError(RuntimeError):
    """A decision that could not be made; the listener answers 500 with no body. Fixed code only."""

    def __init__(self, code: str):
        if code not in _SNAPSHOT_CODES:
            raise ValueError("unknown host snapshot error code")
        super().__init__(code)
        self.code = code


class StopResult(NamedTuple):
    stopped: bool
    quarantined: bool


class HostAuthorityServiceError(RuntimeError):
    """The host-authority listener could not start or stop safely. Fixed code only."""

    def __init__(self, code: str, *, stop_result: StopResult | None = None):
        if code not in _SERVICE_CODES:
            raise ValueError("unknown host authority service error code")
        super().__init__(code)
        self.code = code
        self.stop_result = stop_result


def _is_busy(error: sqlite3.Error) -> bool:
    code = getattr(error, "sqlite_errorcode", None)
    if type(code) is int and code & 0xFF in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
        return True
    text = str(error).lower()
    return "locked" in text or "busy" in text


def _error_code(error: Exception) -> str:
    if isinstance(error, HostSnapshotError):
        return error.code
    if isinstance(error, sqlite3.Error):
        return "db_busy" if isinstance(error, sqlite3.OperationalError) and _is_busy(error) else "db_error"
    # CanaryRunError, LookupError, ValueError, TypeError, KeyError, JSONDecodeError and any other
    # failure while reading authority state: the stored state cannot be decided on.
    return "malformed_state"


def _signed_verification_digest(document: object) -> object:
    try:
        return json.loads(document)["environment"]["verification_record_digest"]
    except (TypeError, ValueError, KeyError):
        return None


def _origin_host(origin: object) -> object:
    try:
        return urlsplit(origin).hostname if isinstance(origin, str) else None
    except ValueError:
        return None


_ISSUED_FIELDS = (
    "project_id", "environment_id", "runner_id", "runner_key_id", "run_id", "binding_id", "binding_digest",
    "grant_id", "grant_digest", "verification_record_digest",
)

_AUTHORITY_JOIN = (
    "SELECT r.run_id, r.workspace_id, r.project_ref, r.environment_id, r.runner_id, r.runner_key_id, r.grant_id,"
    " r.status AS run_status, r.stop_reason, r.kill_switch_generation,"
    " e.status AS proof_status, e.revoked_at AS proof_revoked_at, e.proof_expires_at, e.origin AS environment_origin,"
    " e.verification_record_digest AS live_verification_digest,"
    " cr.status AS runner_status, k.status AS key_status, k.revoked_at AS key_revoked_at, k.public_key,"
    " g.grant_digest, g.grant_json, g.status AS grant_status, g.expires_at AS grant_expires_at,"
    " g.runner_id AS grant_runner_id, g.runner_key_id AS grant_runner_key_id,"
    " g.environment_id AS grant_environment_id,"
    " a.projection_digest AS approval_projection_digest, a.manifest_digest, a.projection_json,"
    " l.rcb_id AS binding_id, l.binding_digest AS link_binding_digest,"
    " b.rcb_id AS binding_row_id, b.binding_digest, b.status AS binding_status,"
    " b.expires_at_ms AS binding_expires_at_ms, b.public_key_digest,"
    " b.verification_record_digest AS binding_verification_digest, b.environment_origin AS binding_origin,"
    " b.runner_id AS binding_runner_id, b.runner_key_id AS binding_runner_key_id,"
    " b.environment_id AS binding_environment_id"
    " FROM canary_runs r"
    " JOIN projects p ON p.workspace_id=r.workspace_id AND p.project_ref=r.project_ref"
    " JOIN canary_environments e ON e.workspace_id=r.workspace_id AND e.project_ref=r.project_ref"
    " AND e.environment_id=r.environment_id"
    " JOIN canary_runners cr ON cr.workspace_id=r.workspace_id AND cr.runner_id=r.runner_id"
    " JOIN canary_runner_keys k ON k.workspace_id=r.workspace_id AND k.runner_id=r.runner_id"
    " AND k.key_id=r.runner_key_id"
    " JOIN canary_execution_grants g ON g.workspace_id=r.workspace_id AND g.project_ref=r.project_ref"
    " AND g.grant_id=r.grant_id"
    " JOIN canary_approval_projections a ON a.workspace_id=r.workspace_id AND a.project_ref=r.project_ref"
    " AND a.approval_id=r.approval_id"
    " LEFT JOIN canary_runner_context_projection_links l ON l.workspace_id=r.workspace_id"
    " AND l.project_ref=r.project_ref AND l.approval_id=r.approval_id AND l.run_id=r.run_id"
    " LEFT JOIN canary_runner_context_bindings b ON b.workspace_id=l.workspace_id"
    " AND b.project_ref=l.project_ref AND b.environment_id=l.environment_id AND b.runner_id=l.runner_id"
    " AND b.runner_key_id=l.runner_key_id AND b.rcb_id=l.rcb_id AND b.binding_digest=l.binding_digest"
    " WHERE r.workspace_id=? AND r.run_id=?"
)


class HostSnapshotDecider:
    """The ``decide`` callable. Seams, each for the snapshot tests only and never passed by a
    production caller: ``_time_ns_for_tests`` (SEAM-CLOCK snapshot tests only),
    ``_connect_for_tests`` (SEAM-RECORDING-CONNECTION snapshot tests only),
    ``_max_generation_rows_for_tests`` (SEAM-CAPACITY snapshot tests only)."""

    def __init__(self, database_path: str, *, signing, draining: Callable[[], object],
                 _time_ns_for_tests: Callable[[], int] | None = None,
                 _connect_for_tests: Callable[[str], sqlite3.Connection] | None = None,
                 _max_generation_rows_for_tests: int | None = None):
        if not isinstance(database_path, str) or not database_path or not Path(database_path).is_absolute():
            raise ValueError("host snapshot decisions require an absolute SQLite path")
        if signing is None or not callable(getattr(signing, "sign", None)):
            raise TypeError("host snapshot decisions require the grant signing authority")
        if not callable(draining):
            raise TypeError("draining must be callable")
        self._database_path = database_path
        self._signing = signing
        self._draining = draining
        self._time_ns = _time_ns_for_tests or time.time_ns
        self._connect = _connect_for_tests or sqlite3.connect
        self._max_generation_rows = (
            MAX_GENERATION_ROWS if _max_generation_rows_for_tests is None else _max_generation_rows_for_tests
        )
        # The quarantine gate: the serving thread reaches the database only through this
        # decider, so holding the gate, or finding _quarantined set under it, is the whole
        # database-access control of a stopping or lingering service.
        self._db_gate = threading.Lock()
        self._stopping = threading.Event()
        self._quarantined = False  # written only under _db_gate
        self._counter_lock = threading.Lock()
        self.counters: dict[str, dict[str, int]] = {"reason": {}, "code": {}, "cleanup_failed": {}}

    @property
    def quarantined(self) -> bool:
        return self._quarantined

    def quarantine(self, timeout: float) -> bool:
        """Close the gate for good; ``False`` when a decision held it for the whole bound."""
        if not self._db_gate.acquire(timeout=timeout):
            return False
        try:
            self._quarantined = True
        finally:
            self._db_gate.release()
        return True

    def _count(self, family: str, key: str) -> None:
        with self._counter_lock:
            bucket = self.counters[family]
            bucket[key] = bucket.get(key, 0) + 1

    def _fail(self, code: str) -> HostSnapshotError:
        self._count("code", code)
        _LOGGER.error(_log({"code": code, "event": "host_snapshot_error"}))
        return HostSnapshotError(code)

    def _cleanup_failed(self, step: str) -> None:
        # The cleanup statement raised; it is counted and logged, never claimed as done.
        self._count("cleanup_failed", step)
        _LOGGER.error(_log({"event": "host_snapshot_cleanup_failed", "step": step}))

    def _reply(self, request: dict, reason: str, server_time_ms: int, generation: int) -> dict:
        self._count("reason", reason)
        return {
            "schema_version": RESPONSE_SCHEMA, "decision": "inactive", "reason": reason,
            "sequence": request["sequence"], "request_digest": request_digest(request),
            "server_time_ms": server_time_ms, "kill_switch_generation": generation,
        }

    def __call__(self, request: dict) -> dict:
        if self._draining() or self._stopping.is_set():
            # No database, no ledger write. Nothing was read, so the request's own generation is
            # echoed; the inactive decision is what the host acts on.
            return self._reply(request, "cp_draining", -(-self._time_ns() // 1_000_000),
                               request["kill_switch_generation"])
        with self._db_gate:
            if self._quarantined:
                raise self._fail("service_stopped")
            if self._stopping.is_set():
                return self._reply(request, "cp_draining", -(-self._time_ns() // 1_000_000),
                                   request["kill_switch_generation"])
            return self._transaction(request)

    def _transaction(self, request: dict) -> dict:
        try:
            conn = self._connect(self._database_path)
        except sqlite3.Error:
            raise self._fail("db_error") from None
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute(f"PRAGMA busy_timeout={SNAPSHOT_BUSY_TIMEOUT_MS}")
            conn.execute("BEGIN IMMEDIATE")
            now_ns = self._time_ns()  # the one sample, taken under the reserved lock
            if type(now_ns) is not int or now_ns < 0:
                raise HostSnapshotError("malformed_state")
            now_ceil = -(-now_ns // 1_000_000)
            service = CanaryRunService(
                conn, signing=self._signing, clock=lambda: now_ns / 1e9, initialize_schema=False,
            )
            reply = self._decide(conn, service, request, now_ceil)
            conn.commit()
        except BaseException as error:
            try:
                if conn.in_transaction:
                    conn.rollback()
            except sqlite3.Error:
                self._cleanup_failed("rollback")
            if not isinstance(error, Exception):
                raise
            raise self._fail(_error_code(error)) from None
        finally:
            try:
                conn.close()
            except sqlite3.Error:
                self._cleanup_failed("close")
        return reply

    # -----------------------------------------------------------------------------------------
    # One decision inside the request's transaction.

    def _decide(self, conn: sqlite3.Connection, service: CanaryRunService, request: dict, now_ceil: int) -> dict:
        generation = service._control_generation()
        if type(generation) is not int or not 0 <= generation <= SAFE_INT:
            raise HostSnapshotError("malformed_state")

        def inactive(reason: str) -> dict:
            return self._reply(request, reason, now_ceil, generation)

        ledger_reason = self._ledger(conn, request, now_ceil)
        if ledger_reason is not None:
            return inactive(ledger_reason)

        workspace_id = request["workspace_id"]
        if conn.execute("SELECT 1 FROM workspaces WHERE workspace_id=?", (workspace_id,)).fetchone() is None:
            return inactive("workspace_unknown")
        selected = conn.execute(
            "SELECT run_id FROM canary_runs WHERE workspace_id=? AND status IN ('claimed','running')"
            " AND stop_reason='none' ORDER BY run_id LIMIT 2",
            (workspace_id,),
        ).fetchall()
        if not selected:
            return inactive("no_active_run")
        if len(selected) > 1:
            return inactive("multiple_active_runs")
        row = conn.execute(_AUTHORITY_JOIN, (workspace_id, selected[0]["run_id"])).fetchone()
        if row is None:
            return inactive("invalid_grant")
        if not self._issued_tuple_matches(request, row):
            return inactive("tuple_mismatch")
        reason, values = self._live_state(service, request, row, generation, now_ceil)
        if reason is not None:
            return inactive(reason)

        proof_ms, binding_ms, grant_ms, egress_hostname = values
        reply = {
            "schema_version": RESPONSE_SCHEMA, "decision": "active", "reason": "none",
            "sequence": request["sequence"], "request_digest": request_digest(request),
            "server_time_ms": now_ceil, "kill_switch_generation": generation,
            "workspace_id": row["workspace_id"], "project_id": row["project_ref"],
            "environment_id": row["environment_id"], "verification_record_digest": row["live_verification_digest"],
            "runner_id": row["runner_id"], "runner_key_id": row["runner_key_id"],
            "public_key_digest": row["public_key_digest"], "binding_id": row["binding_id"],
            "binding_digest": row["binding_digest"], "run_id": row["run_id"], "run_status": row["run_status"],
            "stop_reason": row["stop_reason"], "grant_id": row["grant_id"], "grant_digest": row["grant_digest"],
            "egress_hostname": egress_hostname, "egress_port": 443, "proof_expires_at_ms": proof_ms,
            "binding_expires_at_ms": binding_ms, "grant_expires_at_ms": grant_ms,
        }
        if not validate_response(reply, request):
            raise HostSnapshotError("malformed_state")
        self._count("reason", "none")
        return reply

    @staticmethod
    def _issued_tuple_matches(request: dict, row: sqlite3.Row) -> bool:
        """Exact equality against immutable state; NULL on the authoritative side never matches."""
        expected = {
            "project_id": (row["project_ref"],),
            "environment_id": (row["environment_id"], row["grant_environment_id"], row["binding_environment_id"]),
            "runner_id": (row["runner_id"], row["grant_runner_id"], row["binding_runner_id"]),
            "runner_key_id": (row["runner_key_id"], row["grant_runner_key_id"], row["binding_runner_key_id"]),
            "run_id": (row["run_id"],),
            "binding_id": (row["binding_id"], row["binding_row_id"]),
            "binding_digest": (row["link_binding_digest"], row["binding_digest"]),
            "grant_id": (row["grant_id"],),
            "grant_digest": (row["grant_digest"],),
            "verification_record_digest": (
                row["binding_verification_digest"],
                _signed_verification_digest(row["projection_json"]),
                _signed_verification_digest(row["grant_json"]),
            ),
        }
        return all(
            all(type(value) is str and value == request[field] for value in expected[field])
            for field in _ISSUED_FIELDS
        )

    def _live_state(self, service: CanaryRunService, request: dict, row: sqlite3.Row, generation: int,
                    now_ceil: int) -> tuple[str | None, tuple]:
        """Live-state precedence; ``_gate(advance=False)`` is consulted last and its time is not read."""
        # (a) the immutable authority records are intact and bound to each other.
        try:
            context = service._context(row["workspace_id"], row["project_ref"], row["run_id"], row["runner_id"])
            approval, grant = service._stored_operational_authority(context)
            key_digest = hashlib.sha256(
                load_public_key_base64(row["public_key"]).public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).hexdigest()
            egress_hostname = grant["egress"]["hostname"]
            intact = (
                key_digest == row["public_key_digest"]
                and key_digest == grant["runner_binding"]["public_key_digest"]
                and isinstance(egress_hostname, str)
                and egress_hostname == _origin_host(row["binding_origin"])
                and egress_hostname == _origin_host(row["environment_origin"])
                and grant["egress"]["port"] == 443
                and type(grant["expires_at_ms"]) is int
                and grant["expires_at_ms"] == row["grant_expires_at"]
            )
        except (CanaryRunError, LookupError, TypeError, ValueError):
            intact = False
        if not intact:
            return "invalid_grant", ()
        # (b) the live environment digest still equals the signed records; a replacement is
        # persisted as a stop inside this transaction by the service's own gate.
        if not service._verification_digest_matches(context, approval, grant):
            service._gate(context, advance=False)
            return "verification_digest_replaced", ()
        if row["runner_status"] != "active":
            return "runner_revoked", ()
        if row["key_status"] != "active" or row["key_revoked_at"] is not None:
            return "key_revoked", ()
        if row["proof_revoked_at"] is not None or row["proof_status"] != "verified":
            return "proof_revoked", ()
        if row["binding_status"] != "active":
            return "binding_inactive", ()
        if row["grant_status"] != "claimed":
            return "grant_not_claimed", ()
        if service._kill_active(row["workspace_id"]):
            return "kill_switch_active", ()
        if generation != request["kill_switch_generation"] or generation != row["kill_switch_generation"]:
            return "kill_switch_generation_changed", ()
        # Stored futures are bounded per member before any arithmetic (hostile values fail closed).
        proof_ms = self._proof_ms(row["proof_expires_at"], now_ceil)
        binding_ms = self._bounded(row["binding_expires_at_ms"], now_ceil, MAX_BINDING_REMAINING_MS)
        grant_ms = self._bounded(row["grant_expires_at"], now_ceil, MAX_GRANT_REMAINING_MS)
        if proof_ms - now_ceil <= 0:
            return "proof_expired", ()
        if binding_ms - now_ceil <= 0:
            return "binding_expired", ()
        if grant_ms - now_ceil <= 0:
            return "grant_expired", ()
        if not service._gate(context, advance=False)["active"]:
            return "run_not_active", ()
        return None, (proof_ms, binding_ms, grant_ms, egress_hostname)

    @staticmethod
    def _bounded(value: object, now_ceil: int, maximum: int) -> int:
        if type(value) is not int or not 0 <= value <= SAFE_INT or value - now_ceil > maximum:
            raise HostSnapshotError("malformed_state")
        return value

    @staticmethod
    def _proof_ms(value: object, now_ceil: int) -> int:
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise HostSnapshotError("malformed_state")
        # floor, then one millisecond: the float product can round up at a boundary.
        result = math.floor(value * 1000) - 1
        if not 0 <= result <= SAFE_INT or result - now_ceil > MAX_PROOF_REMAINING_MS:
            raise HostSnapshotError("malformed_state")
        return result

    # -----------------------------------------------------------------------------------------
    # Ledger (migration 31). Every closure here is returned as a reply reason so it commits.

    def _close(self, conn: sqlite3.Connection, generation_row: sqlite3.Row, reason: str, now_ceil: int) -> None:
        conn.execute(
            f"UPDATE {LEDGER_TABLE} SET state='closed',close_reason=?,closed_cp_ms=?"
            " WHERE generation_id=? AND state='open'",
            (reason, max(now_ceil, generation_row["last_cp_ms"]), generation_row["generation_id"]),
        )

    def _require_capacity(self, conn: sqlite3.Connection) -> None:
        count = conn.execute(f"SELECT COUNT(*) FROM {LEDGER_TABLE}").fetchone()[0]
        if count >= self._max_generation_rows:
            raise HostSnapshotError("generation_capacity_exhausted")

    def _ledger(self, conn: sqlite3.Connection, request: dict, now_ceil: int) -> str | None:
        generation_id, boot, slot = request["generation_id"], request["host_boot_epoch"], request["slot_id"]
        sequence, monotonic = request["sequence"], request["monotonic_ms"]
        row = conn.execute(
            f"SELECT * FROM {LEDGER_TABLE} WHERE generation_id=?", (generation_id,),
        ).fetchone()
        if row is None:
            if sequence == 1:
                previous = conn.execute(
                    f"SELECT * FROM {LEDGER_TABLE} WHERE host_boot_epoch=? AND slot_id=? AND state='open'",
                    (boot, slot),
                ).fetchone()
                if previous is not None:
                    self._close(conn, previous, "superseded", now_ceil)
                self._require_capacity(conn)
                conn.execute(
                    f"INSERT INTO {LEDGER_TABLE}(generation_id,host_boot_epoch,slot_id,state,close_reason,"
                    "enrolled_cp_ms,last_sequence,last_monotonic_ms,last_cp_ms,requests,closed_cp_ms)"
                    " VALUES(?,?,?,'open',NULL,?,1,?,?,1,NULL)",
                    (generation_id, boot, slot, now_ceil, monotonic, now_ceil),
                )
                return None
            # A generation whose first request this ledger never saw can never open.
            self._require_capacity(conn)
            conn.execute(
                f"INSERT INTO {LEDGER_TABLE}(generation_id,host_boot_epoch,slot_id,state,close_reason,"
                "enrolled_cp_ms,last_sequence,last_monotonic_ms,last_cp_ms,requests,closed_cp_ms)"
                " VALUES(?,?,?,'closed','unenrolled',?,?,?,?,1,?)",
                (generation_id, boot, slot, now_ceil, sequence, monotonic, now_ceil, now_ceil),
            )
            return "replayed_sequence"
        if row["state"] != "open":
            return "replayed_sequence"  # closed never reopens
        if (row["host_boot_epoch"], row["slot_id"]) != (boot, slot):
            self._close(conn, row, "identity_mismatch", now_ceil)
            return "replayed_sequence"
        if sequence <= row["last_sequence"]:
            self._close(conn, row, "replayed_sequence", now_ceil)
            return "replayed_sequence"
        if now_ceil < row["last_cp_ms"] or monotonic < row["last_monotonic_ms"]:
            self._close(conn, row, "clock_gap", now_ceil)
            return "clock_gap"
        skew = (now_ceil - row["last_cp_ms"]) - (monotonic - row["last_monotonic_ms"])
        if not -CP_GAP_TOLERANCE_MS <= skew <= CP_GAP_TOLERANCE_MS:
            self._close(conn, row, "clock_gap", now_ceil)
            return "clock_gap"
        advanced = conn.execute(
            f"UPDATE {LEDGER_TABLE} SET last_sequence=?,last_monotonic_ms=?,last_cp_ms=?,requests=requests+1"
            " WHERE generation_id=? AND state='open' AND last_sequence<? AND last_cp_ms<=?",
            (sequence, monotonic, now_ceil, generation_id, sequence, now_ceil),
        )
        if advanced.rowcount != 1:
            self._close(conn, row, "replayed_sequence", now_ceil)
            return "replayed_sequence"
        return None


class HostAuthorityService:
    """The listener on one non-daemon thread with a bounded, reported stop.

    Phases: ``unstarted`` -> ``serving`` -> ``stopped``, or ``lingering`` when ``stop()`` could not
    join the thread (a later ``stop()`` may still reach ``stopped``). It is never restarted.

    Seams, each for the snapshot tests only and never passed by a production caller:
    ``_listener_for_tests`` (SEAM-LISTENER snapshot tests only; a factory ``(config, decide)``),
    ``_serve_for_tests`` (SEAM-SERVE-FAILURE snapshot tests only; replaces "mark serving, then
    serve_forever" with ``(listener, mark_serving)``), ``_thread_start_for_tests`` (SEAM-THREAD-START
    snapshot tests only; replaces ``Thread.start``), ``_stop_result_for_tests`` (SEAM-STOP-HANG
    snapshot tests only; may only report a joined thread as not joined)."""

    def __init__(self, config: HostAuthorityConfig, database_path: str, *, signing, draining: Callable[[], object],
                 on_unexpected_death: Callable[[BaseException], None] | None,
                 _listener_for_tests: Callable[[HostAuthorityConfig, Callable[[dict], dict]], object] | None = None,
                 _serve_for_tests: Callable[[object, Callable[[], None]], None] | None = None,
                 _thread_start_for_tests: Callable[[threading.Thread], None] | None = None,
                 _stop_result_for_tests: Callable[[], bool] | None = None):
        self.config = config
        self.decider = HostSnapshotDecider(database_path, signing=signing, draining=draining)
        self.on_unexpected_death = on_unexpected_death
        self._listener_factory = _listener_for_tests or HostAuthorityListener
        self._serve = _serve_for_tests
        self._thread_start = _thread_start_for_tests
        self._stop_hang = _stop_result_for_tests
        self._listener = None
        self._thread: threading.Thread | None = None
        self._serving = threading.Event()
        self._stopped = threading.Event()
        self._state_lock = threading.Lock()
        self._started = False
        self._phase = "unstarted"
        self._failure: BaseException | None = None
        self._quarantined = False

    @property
    def listener(self):
        return self._listener

    @property
    def thread(self) -> threading.Thread | None:
        return self._thread

    @property
    def phase(self) -> str:
        return self._phase

    @property
    def failure(self) -> BaseException | None:
        return self._failure

    @property
    def quarantined(self) -> bool:
        return self._quarantined

    @property
    def alive(self) -> bool:
        thread = self._thread
        return bool(thread is not None and thread.is_alive() and self._failure is None
                    and self._phase in {"unstarted", "serving"} and not self._stopped.is_set())

    def start(self) -> None:
        with self._state_lock:
            if self._started or self._phase != "unstarted":
                raise HostAuthorityServiceError("restart_refused")
            self._started = True
        listener = self._listener_factory(self.config, self.decider)
        try:
            listener.start()  # nothing is published on a refusal
        except BaseException:
            with self._state_lock:
                self._phase = "stopped"
            raise
        self._listener = listener
        thread = threading.Thread(target=self._run, name="heel-host-authority", daemon=False)
        try:
            if self._thread_start is not None:
                self._thread_start(thread)
            else:
                thread.start()
        except RuntimeError:
            listener.close()
            with self._state_lock:
                self._phase = "stopped"
                self._failure = HostAuthorityServiceError("thread_start_failed")
            raise HostAuthorityServiceError("thread_start_failed") from None
        self._thread = thread
        if not self._serving.wait(STARTUP_TIMEOUT_SECONDS):
            result = self.stop()
            raise HostAuthorityServiceError("startup_timeout", stop_result=result)
        with self._state_lock:
            failed = self._failure is not None or not thread.is_alive()
        if failed:
            result = self.stop()
            raise HostAuthorityServiceError("startup_failed", stop_result=result)
        with self._state_lock:
            if self._phase == "unstarted":
                self._phase = "serving"

    def _run(self) -> None:
        try:
            if self._serve is None:
                self._serving.set()
                self._listener.serve_forever()
            else:
                self._serve(self._listener, self._serving.set)
            if not self._stopped.is_set():
                raise HostAuthorityServiceError("listener_exited")
        except BaseException as error:
            with self._state_lock:
                if self._failure is None:
                    self._failure = error
            # Wake a start() still waiting for serving: its failure check (made after the
            # failure was recorded above) reports startup_failed instead of waiting out the bound.
            self._serving.set()
            self._listener.close()  # unlink only this listener's inode: no lingering path
            if not self._stopped.is_set():
                _LOGGER.error(_log({"event": "host_authority_died", "exception_type": type(error).__name__}))
                if self.on_unexpected_death is not None:
                    self.on_unexpected_death(error)

    def stop(self, timeout: float | None = None) -> StopResult:
        """Declare draining, close, join, quarantine; idempotent and repeatable."""
        timeout = STOP_TIMEOUT_SECONDS if timeout is None else timeout
        # 1. draining is declared before any cleanup.
        self.decider._stopping.set()
        self._stopped.set()
        # 2. the frozen close: stop accepting, unlink own inode.
        listener = self._listener
        if listener is not None:
            listener.close()
        # 3. join outside every lock.
        thread = self._thread
        joined = True
        if thread is not None:
            if thread is threading.current_thread():
                joined = False
            else:
                thread.join(timeout)
                joined = not thread.is_alive()
        if joined and self._stop_hang is not None:
            joined = bool(self._stop_hang())
        if joined:
            # 4. no thread runs: the gate is free and the quarantine is immediate.
            quarantined = self.decider.quarantine(QUARANTINE_TIMEOUT_SECONDS)
            with self._state_lock:
                self._quarantined = self._quarantined or quarantined
                self._phase = "stopped"
            return StopResult(True, quarantined)
        # 5. the thread outlived the join: close the gate if the bound allows.
        quarantined = self.decider.quarantine(QUARANTINE_TIMEOUT_SECONDS)
        with self._state_lock:
            self._quarantined = self._quarantined or quarantined
            self._phase = "lingering"
            if self._failure is None:
                self._failure = HostAuthorityServiceError("stop_timeout")
        _LOGGER.error(_log({"event": "host_authority_lingering", "quarantined": quarantined}))
        return StopResult(False, quarantined)
