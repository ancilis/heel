"""Atomic hosted persistence for privacy-minimized findings continuity.

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Only the closed ``heel.findings-sync.v1`` projection is accepted or stored. One caller-owned
transaction covers kill-switch admission, quota settlement, normalized findings, provenance,
receipt, and audit so partial syncs and partial charges are impossible.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import math
import re
import secrets
import sqlite3
import time
from typing import Any, Callable

from heel.findings_sync import (
    FINDINGS_SYNC_RECEIPT_SCHEMA_VERSION,
    findings_sync_request_digest,
    parse_findings_sync_receipt,
    stable_json,
    validate_findings_sync_receipt,
    validate_findings_sync_request,
)

from .catalog import Meter, Plan
from .ledger import UsageLedger
from .ops import OpsStore
from .projects import ProjectNotFound, ProjectStore
from .tenancy import Role, role_can


_SCHEMA = """
CREATE TABLE IF NOT EXISTS synced_reviews(
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  synced_review_id TEXT NOT NULL,
  projection_hash TEXT NOT NULL,
  projection_json TEXT NOT NULL,
  gate_status TEXT NOT NULL,
  findings_count INTEGER NOT NULL,
  blockers_count INTEGER NOT NULL,
  created_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, project_ref, synced_review_id),
  UNIQUE(workspace_id, project_ref, projection_hash),
  FOREIGN KEY(workspace_id, project_ref)
    REFERENCES projects(workspace_id, project_ref));
CREATE TABLE IF NOT EXISTS project_findings(
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  surface_ref TEXT NOT NULL,
  surface_type TEXT NOT NULL,
  risk_code TEXT NOT NULL,
  created_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, project_ref, finding_id),
  FOREIGN KEY(workspace_id, project_ref)
    REFERENCES projects(workspace_id, project_ref));
CREATE TABLE IF NOT EXISTS synced_review_findings(
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  synced_review_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  control_code TEXT NOT NULL,
  severity TEXT NOT NULL,
  reachable INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, project_ref, synced_review_id, finding_id),
  UNIQUE(workspace_id, project_ref, synced_review_id, ordinal),
  FOREIGN KEY(workspace_id, project_ref, synced_review_id)
    REFERENCES synced_reviews(workspace_id, project_ref, synced_review_id),
  FOREIGN KEY(workspace_id, project_ref, finding_id)
    REFERENCES project_findings(workspace_id, project_ref, finding_id));
CREATE TABLE IF NOT EXISTS findings_source_observations(
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  source_result_ref TEXT NOT NULL,
  synced_review_id TEXT NOT NULL,
  engine_version TEXT NOT NULL,
  execution_mode TEXT NOT NULL,
  observed_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, project_ref, source_result_ref),
  FOREIGN KEY(workspace_id, project_ref, synced_review_id)
    REFERENCES synced_reviews(workspace_id, project_ref, synced_review_id));
CREATE TABLE IF NOT EXISTS findings_sync_approvals(
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  approval_id TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  approved_by TEXT NOT NULL,
  approved_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, project_ref, approval_id),
  UNIQUE(approval_id),
  FOREIGN KEY(workspace_id, project_ref)
    REFERENCES projects(workspace_id, project_ref));
CREATE INDEX IF NOT EXISTS idx_findings_approvals_digest
  ON findings_sync_approvals(workspace_id, project_ref, request_digest, expires_at);
CREATE TABLE IF NOT EXISTS findings_sync_receipts(
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  request_json TEXT NOT NULL,
  receipt_id TEXT NOT NULL,
  synced_review_id TEXT NOT NULL,
  source_result_ref TEXT NOT NULL,
  approval_id TEXT NOT NULL,
  disposition TEXT NOT NULL,
  metered INTEGER NOT NULL,
  accepted_at TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  PRIMARY KEY(workspace_id, project_ref, request_digest),
  UNIQUE(receipt_id),
  FOREIGN KEY(workspace_id, project_ref, synced_review_id)
    REFERENCES synced_reviews(workspace_id, project_ref, synced_review_id));
CREATE TABLE IF NOT EXISTS findings_sync_audit(
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  event_id TEXT NOT NULL,
  action TEXT NOT NULL,
  actor_ref TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  synced_review_id TEXT,
  ts REAL NOT NULL,
  PRIMARY KEY(workspace_id, project_ref, event_id),
  UNIQUE(event_id),
  FOREIGN KEY(workspace_id, project_ref)
    REFERENCES projects(workspace_id, project_ref));
CREATE INDEX IF NOT EXISTS idx_synced_reviews_created
  ON synced_reviews(workspace_id, project_ref, created_at, synced_review_id);
CREATE INDEX IF NOT EXISTS idx_findings_sources_review
  ON findings_source_observations(workspace_id, project_ref, synced_review_id);
CREATE INDEX IF NOT EXISTS idx_findings_audit_project
  ON findings_sync_audit(workspace_id, project_ref, ts, event_id);
"""

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MAX_APPROVAL_SECONDS = 10 * 60


class FindingsSyncConflict(Exception):
    """A stable source, projection, or finding identity contradicts stored content."""


class ApprovalRequired(PermissionError):
    """No explicit human approval exists for the exact request digest."""


class ApprovalExpired(PermissionError):
    """Approvals exist for the digest, but none is still live."""


@dataclass(frozen=True)
class Approval:
    workspace_id: str
    project_ref: str
    approval_id: str
    request_digest: str
    approved_by: str
    approved_at: float
    expires_at: float


@dataclass(frozen=True)
class SyncPrincipal:
    """A principal already authenticated by the transport/control-plane boundary."""

    actor_ref: str
    role: Role
    channel: str


_SUBMISSION_CHANNELS = frozenset({"human_session", "device_session", "api_key"})
_HUMAN_APPROVAL_CHANNELS = frozenset({"human_session", "device_session"})


def _timestamp(value: float | None) -> float:
    result = time.time() if value is None else value
    if type(result) not in (int, float) or not math.isfinite(result) or result < 0:
        raise ValueError("timestamp must be a finite non-negative number")
    return float(result)


def _identity(value: str, label: str) -> str:
    if type(value) is not str or not value or len(value) > 256 or any(
        ord(character) < 0x20 for character in value
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _accepted_at(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def _period(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m")


def _authorize_principal(
    principal: SyncPrincipal,
    *,
    human_approval: bool = False,
) -> str:
    if not isinstance(principal, SyncPrincipal):
        raise PermissionError("an authenticated sync principal is required")
    actor_ref = _identity(principal.actor_ref, "principal actor_ref")
    if not isinstance(principal.role, Role) or not role_can(
        principal.role, "sync_findings"
    ):
        raise PermissionError("principal may not sync findings")
    allowed_channels = _HUMAN_APPROVAL_CHANNELS if human_approval else _SUBMISSION_CHANNELS
    if principal.channel not in allowed_channels:
        raise PermissionError(
            "findings sync approval requires an interactive human channel"
            if human_approval
            else "principal channel may not submit findings"
        )
    return actor_ref


def _projection_json(request: dict[str, Any]) -> str:
    return stable_json({
        "schema_version": request["schema_version"],
        "gate_status": request["gate_status"],
        "summary": request["summary"],
        "findings": request["findings"],
    })


def _rollback(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("ROLLBACK")
    except sqlite3.OperationalError:
        pass


class FindingsSyncService:
    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        projects: ProjectStore,
        ledger: UsageLedger,
        ops: OpsStore,
        plan_for_workspace: Callable[[str], Plan],
    ):
        self.conn = conn
        self.projects = projects
        self.ledger = ledger
        self.ops = ops
        self.plan_for_workspace = plan_for_workspace
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript(_SCHEMA)

    def _audit(
        self,
        workspace_id: str,
        project_ref: str,
        action: str,
        actor_ref: str,
        request_digest: str,
        synced_review_id: str | None,
        timestamp: float,
    ) -> None:
        self.conn.execute(
            "INSERT INTO findings_sync_audit VALUES(?,?,?,?,?,?,?,?)",
            (
                workspace_id, project_ref, f"fsa_{secrets.token_hex(16)}", action,
                actor_ref, request_digest, synced_review_id, timestamp,
            ),
        )

    def approve(
        self,
        workspace_id: str,
        project_ref: str,
        request_digest: str,
        *,
        principal: SyncPrincipal,
        now: float | None = None,
        expires_at: float,
    ) -> Approval:
        approved_at = _timestamp(now)
        expiry = _timestamp(expires_at)
        actor = _authorize_principal(principal, human_approval=True)
        if type(request_digest) is not str or _DIGEST.fullmatch(request_digest) is None:
            raise ValueError("request_digest is invalid")
        if expiry < approved_at or expiry - approved_at > _MAX_APPROVAL_SECONDS:
            raise ValueError("approval expiry must be within ten minutes")
        self.projects.get(workspace_id, project_ref)
        approval_id = f"fsauth_{secrets.token_hex(16)}"
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            if self.conn.execute(
                "SELECT 1 FROM projects WHERE workspace_id=? AND project_ref=?",
                (workspace_id, project_ref),
            ).fetchone() is None:
                raise ProjectNotFound("project not found")
            self.conn.execute(
                "INSERT INTO findings_sync_approvals VALUES(?,?,?,?,?,?,?)",
                (
                    workspace_id, project_ref, approval_id, request_digest, actor,
                    approved_at, expiry,
                ),
            )
            self._audit(
                workspace_id, project_ref, "approval_created", actor,
                request_digest, None, approved_at,
            )
            self.conn.execute("COMMIT")
        except Exception:
            _rollback(self.conn)
            raise
        return Approval(
            workspace_id, project_ref, approval_id, request_digest,
            actor, approved_at, expiry,
        )

    def _approval(
        self,
        workspace_id: str,
        project_ref: str,
        request_digest: str,
        now: float,
    ) -> sqlite3.Row:
        rows = self.conn.execute(
            """SELECT * FROM findings_sync_approvals
               WHERE workspace_id=? AND project_ref=? AND request_digest=?
               ORDER BY approved_at DESC, approval_id DESC""",
            (workspace_id, project_ref, request_digest),
        ).fetchall()
        if not rows:
            raise ApprovalRequired("explicit findings-sync approval is required")
        for row in rows:
            if row["approved_at"] <= now <= row["expires_at"]:
                return row
        raise ApprovalExpired("findings-sync approval expired")

    def accept(
        self,
        workspace_id: str,
        project_ref: str,
        request_value: Any,
        *,
        principal: SyncPrincipal,
        idempotency_key: str,
        now: float | None = None,
    ) -> dict[str, Any]:
        accepted_timestamp = _timestamp(now)
        submitting_actor = _authorize_principal(principal)
        namespace_key = self.projects.namespace_key(workspace_id, project_ref)
        request = validate_findings_sync_request(request_value, namespace_key)
        if request["project_ref"] != project_ref:
            raise FindingsSyncConflict("request project does not match its route")
        request_digest = findings_sync_request_digest(request, namespace_key)
        if idempotency_key != f"fs1-{request_digest}":
            raise FindingsSyncConflict("idempotency key does not match the request")
        request_json = stable_json(request)
        projection_json = _projection_json(request)
        source = request["source"]
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            existing_receipt = self.conn.execute(
                """SELECT request_json, receipt_json FROM findings_sync_receipts
                   WHERE workspace_id=? AND project_ref=? AND request_digest=?""",
                (workspace_id, project_ref, request_digest),
            ).fetchone()
            if existing_receipt is not None:
                if existing_receipt["request_json"] != request_json:
                    raise FindingsSyncConflict("request digest contradicts stored request bytes")
                receipt = parse_findings_sync_receipt(existing_receipt["receipt_json"])
                self.conn.execute("COMMIT")
                return receipt

            self.ops.check(workspace_id)
            if self.conn.execute(
                "SELECT 1 FROM projects WHERE workspace_id=? AND project_ref=?",
                (workspace_id, project_ref),
            ).fetchone() is None:
                raise ProjectNotFound("project not found")
            approval = self._approval(
                workspace_id, project_ref, request_digest, accepted_timestamp,
            )

            source_row = self.conn.execute(
                """SELECT synced_review_id, engine_version, execution_mode
                   FROM findings_source_observations
                   WHERE workspace_id=? AND project_ref=? AND source_result_ref=?""",
                (workspace_id, project_ref, source["result_ref"]),
            ).fetchone()
            synced_review_id: str
            new_review = False
            new_source = source_row is None
            if source_row is not None:
                if (
                    source_row["engine_version"] != source["engine_version"]
                    or source_row["execution_mode"] != source["execution_mode"]
                ):
                    raise FindingsSyncConflict(
                        "source result reference contradicts its stored provenance"
                    )
                synced_review_id = source_row["synced_review_id"]
                stored = self.conn.execute(
                    """SELECT projection_hash, projection_json FROM synced_reviews
                       WHERE workspace_id=? AND project_ref=? AND synced_review_id=?""",
                    (workspace_id, project_ref, synced_review_id),
                ).fetchone()
                if (
                    stored is None
                    or stored["projection_hash"] != request["projection_hash"]
                    or stored["projection_json"] != projection_json
                ):
                    raise FindingsSyncConflict(
                        "source result reference contradicts its stored projection"
                    )
            else:
                stored = self.conn.execute(
                    """SELECT synced_review_id, projection_json FROM synced_reviews
                       WHERE workspace_id=? AND project_ref=? AND projection_hash=?""",
                    (workspace_id, project_ref, request["projection_hash"]),
                ).fetchone()
                if stored is not None:
                    if stored["projection_json"] != projection_json:
                        raise FindingsSyncConflict(
                            "projection hash contradicts stored projection bytes"
                        )
                    synced_review_id = stored["synced_review_id"]
                else:
                    new_review = True
                    synced_review_id = f"synrev_{secrets.token_hex(16)}"
                    plan = self.plan_for_workspace(workspace_id)
                    if not isinstance(plan, Plan):
                        raise RuntimeError("workspace plan resolver returned an invalid plan")
                    reservation = self.ledger.reserve_in_transaction(
                        plan,
                        workspace_id,
                        Meter.SYNCED_REVIEWS,
                        1,
                        _period(accepted_timestamp),
                        idempotency_key=idempotency_key,
                        ref=synced_review_id,
                    )
                    self.conn.execute(
                        "INSERT INTO synced_reviews VALUES(?,?,?,?,?,?,?,?,?)",
                        (
                            workspace_id, project_ref, synced_review_id,
                            request["projection_hash"], projection_json,
                            request["gate_status"], request["summary"]["findings"],
                            request["summary"]["blockers"], accepted_timestamp,
                        ),
                    )
                    for ordinal, finding in enumerate(request["findings"]):
                        stored_finding = self.conn.execute(
                            """SELECT surface_ref, surface_type, risk_code
                               FROM project_findings
                               WHERE workspace_id=? AND project_ref=? AND finding_id=?""",
                            (workspace_id, project_ref, finding["finding_id"]),
                        ).fetchone()
                        material = (
                            finding["surface_ref"], finding["surface_type"],
                            finding["risk_code"],
                        )
                        if stored_finding is None:
                            self.conn.execute(
                                "INSERT INTO project_findings VALUES(?,?,?,?,?,?,?)",
                                (
                                    workspace_id, project_ref, finding["finding_id"],
                                    *material, accepted_timestamp,
                                ),
                            )
                        elif tuple(stored_finding) != material:
                            raise FindingsSyncConflict(
                                "finding identity contradicts stored finding content"
                            )
                        self.conn.execute(
                            "INSERT INTO synced_review_findings VALUES(?,?,?,?,?,?,?,?)",
                            (
                                workspace_id, project_ref, synced_review_id,
                                finding["finding_id"], ordinal, finding["control_code"],
                                finding["severity"], int(finding["reachable"]),
                            ),
                        )
                    self.ledger.consume_in_transaction(reservation.reservation_id)

            if new_source:
                self.conn.execute(
                    "INSERT INTO findings_source_observations VALUES(?,?,?,?,?,?,?)",
                    (
                        workspace_id, project_ref, source["result_ref"], synced_review_id,
                        source["engine_version"], source["execution_mode"],
                        accepted_timestamp,
                    ),
                )

            disposition = "created" if new_review else "reused"
            receipt = validate_findings_sync_receipt({
                "schema_version": FINDINGS_SYNC_RECEIPT_SCHEMA_VERSION,
                "receipt_id": f"fsr_{secrets.token_hex(16)}",
                "project_ref": project_ref,
                "request_digest": request_digest,
                "projection_hash": request["projection_hash"],
                "synced_review_id": synced_review_id,
                "disposition": disposition,
                "metered": new_review,
                "accepted_at": _accepted_at(accepted_timestamp),
            })
            receipt_json = stable_json(receipt)
            self.conn.execute(
                "INSERT INTO findings_sync_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    workspace_id, project_ref, request_digest, request_json,
                    receipt["receipt_id"], synced_review_id, source["result_ref"],
                    approval["approval_id"], disposition, int(new_review),
                    receipt["accepted_at"], receipt_json,
                ),
            )
            self._audit(
                workspace_id, project_ref,
                "sync_created" if new_review else "sync_reused",
                submitting_actor, request_digest, synced_review_id,
                accepted_timestamp,
            )
            self.conn.execute("COMMIT")
            return receipt
        except Exception:
            _rollback(self.conn)
            raise

    def list_reviews(self, workspace_id: str, project_ref: str) -> list[dict[str, Any]]:
        self.projects.get(workspace_id, project_ref)
        rows = self.conn.execute(
            """SELECT synced_review_id, projection_hash, gate_status,
                      findings_count, blockers_count, created_at
               FROM synced_reviews
               WHERE workspace_id=? AND project_ref=?
               ORDER BY created_at DESC, synced_review_id DESC""",
            (workspace_id, project_ref),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_review(
        self,
        workspace_id: str,
        project_ref: str,
        synced_review_id: str,
    ) -> dict[str, Any]:
        self.projects.get(workspace_id, project_ref)
        review = self.conn.execute(
            """SELECT synced_review_id, projection_hash, gate_status,
                      findings_count, blockers_count, created_at
               FROM synced_reviews
               WHERE workspace_id=? AND project_ref=? AND synced_review_id=?""",
            (workspace_id, project_ref, synced_review_id),
        ).fetchone()
        if review is None:
            raise ProjectNotFound("synced review not found")
        findings = self.conn.execute(
            """SELECT f.finding_id, f.surface_ref, f.surface_type, f.risk_code,
                      link.control_code, link.severity, link.reachable
               FROM synced_review_findings AS link
               JOIN project_findings AS f
                 ON f.workspace_id=link.workspace_id
                AND f.project_ref=link.project_ref
                AND f.finding_id=link.finding_id
               WHERE link.workspace_id=? AND link.project_ref=?
                 AND link.synced_review_id=?
               ORDER BY link.ordinal""",
            (workspace_id, project_ref, synced_review_id),
        ).fetchall()
        sources = self.conn.execute(
            """SELECT source_result_ref, engine_version, execution_mode, observed_at
               FROM findings_source_observations
               WHERE workspace_id=? AND project_ref=? AND synced_review_id=?
               ORDER BY observed_at, source_result_ref""",
            (workspace_id, project_ref, synced_review_id),
        ).fetchall()
        result = dict(review)
        result["findings"] = [
            {**dict(row), "reachable": bool(row["reachable"])} for row in findings
        ]
        result["sources"] = [dict(row) for row in sources]
        return result
