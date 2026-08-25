"""Separate, one-use authority for verified-canary findings disclosure.

Execution approval authorizes only the operational projection.  This service accepts findings
metadata for a local preview, mints a short-lived human-approved permit, and persists the exact
runner-signed findings projection only when that permit is consumed.  It deliberately has no
dependency on the legacy findings-sync approval path.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import re
import secrets
import sqlite3
import time
from typing import Callable, Iterator

from heel.canary_contracts import (
    CANARY_FINDINGS_SCHEMA,
    DISCLOSURE_PERMIT_SCHEMA,
    canonical_bytes,
    canonical_digest,
    validate_approval_projection,
    validate_canary_findings,
    validate_disclosure_permit,
    validate_execution_grant,
    validate_operational_run,
)
from heel.crypto import load_public_key_base64, verify_envelope

from .canary_store import CanaryStore


DISCLOSURE_REQUEST_TTL_MS = 24 * 60 * 60 * 1000
DISCLOSURE_PERMIT_TTL_MS = 10 * 60 * 1000
FINDINGS_RETENTION_MS = 7 * 24 * 60 * 60 * 1000
AUDIT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000
RECENT_AUTH_MS = 15 * 60 * 1000
MAX_UPLOAD_BYTES = 272 * 1024
RUNNER_FINDINGS_UPLOAD_SCHEMA = "heel.runner-findings-upload.v1"

_HASH = re.compile(r"^[0-9a-f]{64}$")
_PUBLIC_CODES = frozenset(
    {
        "invalid_canary_projection",
        "canary_state_conflict",
        "disclosure_permit_required",
        "disclosure_permit_expired",
        "permit_consumed",
        "canary_run_not_found",
        "canary_authority_unavailable",
    }
)


class CanaryDisclosureError(ValueError):
    """A closed service failure whose message contains only the frozen public code."""

    def __init__(self, code: str):
        if code not in _PUBLIC_CODES:
            code = "canary_state_conflict"
        self.code = code
        self.detail_code = code
        super().__init__(code)


def _identifier(value: object, *, code: str = "invalid_canary_projection") -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > 128
        or "\x00" in value
    ):
        raise CanaryDisclosureError(code)
    return value


class CanaryDisclosureService:
    """Tenant-bound disclosure coordinator sharing the control-plane SQLite connection."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        signing,
        clock: Callable[[], float] = time.time,
        initialize_schema: bool = True,
    ):
        if not isinstance(conn, sqlite3.Connection):
            raise TypeError("canary disclosure requires SQLite")
        if (
            signing is None
            or not callable(getattr(signing, "sign", None))
            or not isinstance(getattr(signing, "key_id", None), str)
            or getattr(signing, "public_key", None) is None
        ):
            raise TypeError("production disclosure signing authority is required")
        if type(initialize_schema) is not bool:
            raise TypeError("initialize_schema must be a boolean")
        self.conn = conn
        self.conn.row_factory = sqlite3.Row
        if initialize_schema:
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.execute("PRAGMA busy_timeout=5000")
            CanaryStore(conn)
        self.signing = signing
        self.clock = clock

    def _now_ms(self) -> int:
        return max(0, int(float(self.clock()) * 1000))

    @contextmanager
    def _write(self) -> Iterator[None]:
        """Join a runner-PoP transaction when one exists; otherwise own the write."""
        owns_transaction = not self.conn.in_transaction
        if owns_transaction:
            self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield
            if owns_transaction:
                self.conn.commit()
        except Exception:
            if owns_transaction and self.conn.in_transaction:
                self.conn.rollback()
            raise

    @staticmethod
    def _metadata(
        projection_schema_version: object,
        projection_digest: object,
        byte_count: object,
        scenario_count: object,
        finding_count: object,
    ) -> dict[str, object]:
        if projection_schema_version != CANARY_FINDINGS_SCHEMA:
            raise CanaryDisclosureError("invalid_canary_projection")
        if (
            type(projection_digest) is not str
            or _HASH.fullmatch(projection_digest) is None
        ):
            raise CanaryDisclosureError("invalid_canary_projection")
        if (
            type(byte_count) is not int
            or isinstance(byte_count, bool)
            or not 1 <= byte_count <= 262_144
            or type(scenario_count) is not int
            or isinstance(scenario_count, bool)
            or not 0 <= scenario_count <= 4
            or type(finding_count) is not int
            or isinstance(finding_count, bool)
            or not 0 <= finding_count <= scenario_count
        ):
            raise CanaryDisclosureError("invalid_canary_projection")
        return {
            "schema_version": projection_schema_version,
            "projection_digest": projection_digest,
            "byte_count": byte_count,
            "scenario_count": scenario_count,
            "finding_count": finding_count,
        }

    def _run_context(
        self,
        workspace_id: str,
        project_ref: str,
        run_id: str,
        *,
        runner_id: str | None = None,
    ) -> sqlite3.Row:
        params: list[object] = [workspace_id, project_ref, run_id]
        runner_clause = ""
        if runner_id is not None:
            runner_clause = " AND r.runner_id=?"
            params.append(runner_id)
        row = self.conn.execute(
            "SELECT r.run_id,r.workspace_id,r.project_ref,r.grant_id,r.environment_id,"
            "r.runner_id,r.runner_key_id,r.status AS run_status,r.execution_disposition,"
            "g.grant_digest,g.grant_json,g.status AS grant_status,"
            "a.projection_digest AS approval_projection_digest,a.manifest_digest,"
            "a.projection_json AS approval_projection_json,"
            "k.public_key,k.status AS key_status,k.revoked_at AS key_revoked_at,"
            "cr.status AS runner_status,o.lifecycle_phase AS receipt_phase,"
            "o.receipt_digest,o.receipt_json,o.runner_id AS receipt_runner_id,"
            "o.runner_key_id AS receipt_runner_key_id "
            "FROM canary_runs r "
            "JOIN canary_execution_grants g ON g.workspace_id=r.workspace_id "
            "AND g.project_ref=r.project_ref AND g.grant_id=r.grant_id "
            "JOIN canary_approval_projections a ON a.workspace_id=r.workspace_id "
            "AND a.project_ref=r.project_ref AND a.approval_id=r.approval_id "
            "JOIN canary_runners cr ON cr.workspace_id=r.workspace_id AND cr.runner_id=r.runner_id "
            "JOIN canary_runner_keys k ON k.workspace_id=r.workspace_id "
            "AND k.runner_id=r.runner_id AND k.key_id=r.runner_key_id "
            "LEFT JOIN canary_operational_receipts o ON o.workspace_id=r.workspace_id "
            "AND o.project_ref=r.project_ref AND o.run_id=r.run_id "
            "WHERE r.workspace_id=? AND r.project_ref=? AND r.run_id=?" + runner_clause,
            tuple(params),
        ).fetchone()
        if row is None:
            raise CanaryDisclosureError("canary_run_not_found")
        return row

    @staticmethod
    def _require_active_authority(row: sqlite3.Row) -> None:
        if (
            row["runner_status"] != "active"
            or row["key_status"] != "active"
            or row["key_revoked_at"] is not None
            or row["receipt_runner_id"] != row["runner_id"]
            or row["receipt_runner_key_id"] != row["runner_key_id"]
        ):
            raise CanaryDisclosureError("canary_authority_unavailable")

    @staticmethod
    def _require_terminal_result(row: sqlite3.Row) -> None:
        if (
            row["run_status"] != "terminal"
            or row["receipt_phase"] != "terminal"
            or row["receipt_json"] is None
            or row["execution_disposition"] is None
        ):
            raise CanaryDisclosureError("canary_state_conflict")

    def _audit(
        self,
        row: sqlite3.Row,
        action: str,
        *,
        subject_ref: str,
        actor_class: str,
        actor_id: str,
        payload: object,
        reason_code: str | None = None,
    ) -> None:
        now = self._now_ms()
        self.conn.execute(
            "INSERT INTO canary_audit_records("
            "audit_id,workspace_id,project_ref,run_id,subject_ref,action,actor_class,actor_id,"
            "reason_code,payload_digest,created_at,purge_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "cra_" + secrets.token_hex(16),
                row["workspace_id"],
                row["project_ref"],
                row["run_id"],
                subject_ref,
                action,
                actor_class,
                actor_id,
                reason_code,
                canonical_digest(payload),
                now,
                now + AUDIT_RETENTION_MS,
            ),
        )

    @staticmethod
    def _preview_response(
        request: sqlite3.Row | dict[str, object],
    ) -> dict[str, object]:
        return {
            "schema_version": "heel.canary-disclosure-preview.v1",
            "request_id": request["request_id"],
            "run_id": request["run_id"],
            "status": request["status"],
            "projection": {
                "schema_version": request["schema_version"],
                "projection_digest": request["projection_digest"],
                "byte_count": request["maximum_bytes"],
                "scenario_count": request["scenario_count"],
                "finding_count": request["finding_count"],
            },
        }

    def preview(
        self,
        workspace_id: str,
        project_ref: str,
        run_id: str,
        *,
        runner_id: str,
        runner_key_id: str,
        projection_schema_version: str,
        projection_digest: str,
        byte_count: int,
        scenario_count: int,
        finding_count: int,
    ) -> dict[str, object]:
        """Register only exact projection metadata after a mandatory terminal result."""
        workspace_id = _identifier(workspace_id)
        project_ref = _identifier(project_ref)
        run_id = _identifier(run_id)
        runner_id = _identifier(runner_id)
        runner_key_id = _identifier(runner_key_id)
        metadata = self._metadata(
            projection_schema_version,
            projection_digest,
            byte_count,
            scenario_count,
            finding_count,
        )
        with self._write():
            row = self._run_context(
                workspace_id,
                project_ref,
                run_id,
                runner_id=runner_id,
            )
            self._require_terminal_result(row)
            self._require_active_authority(row)
            if runner_key_id != row["runner_key_id"]:
                raise CanaryDisclosureError("canary_authority_unavailable")
            prior = self.conn.execute(
                "SELECT * FROM canary_disclosure_requests WHERE workspace_id=? "
                "AND project_ref=? AND run_id=?",
                (workspace_id, project_ref, run_id),
            ).fetchone()
            if prior is not None:
                expected = (
                    metadata["schema_version"],
                    metadata["projection_digest"],
                    metadata["byte_count"],
                    metadata["scenario_count"],
                    metadata["finding_count"],
                    runner_id,
                    runner_key_id,
                )
                actual = (
                    prior["schema_version"],
                    prior["projection_digest"],
                    prior["maximum_bytes"],
                    prior["scenario_count"],
                    prior["finding_count"],
                    prior["runner_id"],
                    prior["runner_key_id"],
                )
                if actual != expected:
                    raise CanaryDisclosureError("canary_state_conflict")
                return self._preview_response(prior)
            now = self._now_ms()
            request_id = "cdr_" + secrets.token_hex(16)
            request = {
                "request_id": request_id,
                "workspace_id": workspace_id,
                "project_ref": project_ref,
                "run_id": run_id,
                "grant_id": row["grant_id"],
                "runner_id": runner_id,
                "runner_key_id": runner_key_id,
                "schema_version": metadata["schema_version"],
                "projection_digest": metadata["projection_digest"],
                "maximum_bytes": metadata["byte_count"],
                "scenario_count": metadata["scenario_count"],
                "finding_count": metadata["finding_count"],
                "status": "local_result_ready",
            }
            self.conn.execute(
                "INSERT INTO canary_disclosure_requests("
                "request_id,workspace_id,project_ref,run_id,grant_id,runner_id,runner_key_id,"
                "schema_version,projection_digest,maximum_bytes,scenario_count,finding_count,status,"
                "created_at,expires_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    request_id,
                    workspace_id,
                    project_ref,
                    run_id,
                    row["grant_id"],
                    runner_id,
                    runner_key_id,
                    metadata["schema_version"],
                    metadata["projection_digest"],
                    metadata["byte_count"],
                    metadata["scenario_count"],
                    metadata["finding_count"],
                    "local_result_ready",
                    now,
                    now + DISCLOSURE_REQUEST_TTL_MS,
                    now,
                ),
            )
            self._audit(
                row,
                "local_result_ready",
                subject_ref=request_id,
                actor_class="runner",
                actor_id=runner_id,
                payload={"projection": metadata},
            )
            return self._preview_response(request)

    def local_only(
        self,
        workspace_id: str,
        project_ref: str,
        run_id: str,
        *,
        request_id: str,
        actor: str,
    ) -> dict[str, object]:
        """Record an explicit no-upload decision without accepting any findings bytes."""
        workspace_id = _identifier(workspace_id)
        project_ref = _identifier(project_ref)
        run_id = _identifier(run_id)
        request_id = _identifier(request_id, code="canary_state_conflict")
        actor = _identifier(actor, code="canary_authority_unavailable")
        with self._write():
            row = self._run_context(workspace_id, project_ref, run_id)
            membership = self.conn.execute(
                "SELECT role FROM memberships WHERE workspace_id=? AND user_id=?",
                (workspace_id, actor),
            ).fetchone()
            if membership is None or membership["role"] not in {"owner", "admin"}:
                raise CanaryDisclosureError("canary_authority_unavailable")
            request = self.conn.execute(
                "SELECT * FROM canary_disclosure_requests WHERE workspace_id=? AND project_ref=? "
                "AND run_id=? AND request_id=?",
                (workspace_id, project_ref, run_id, request_id),
            ).fetchone()
            if request is None:
                raise CanaryDisclosureError("canary_state_conflict")
            if request["status"] == "local_only":
                return {
                    "schema_version": "heel.canary-disclosure-state.v1",
                    "run_id": run_id,
                    "status": "local_only",
                }
            if request["status"] not in {
                "local_result_ready",
                "awaiting_disclosure_approval",
            }:
                raise CanaryDisclosureError("canary_state_conflict")
            now = self._now_ms()
            self.conn.execute(
                "UPDATE canary_disclosure_requests SET status='local_only',updated_at=? "
                "WHERE workspace_id=? AND project_ref=? AND request_id=?",
                (now, workspace_id, project_ref, request_id),
            )
            self._audit(
                row,
                "local_only",
                subject_ref=request_id,
                actor_class="human",
                actor_id=actor,
                payload={"status": "local_only"},
            )
            return {
                "schema_version": "heel.canary-disclosure-state.v1",
                "run_id": run_id,
                "status": "local_only",
            }

    def _existing_permit(
        self,
        request: sqlite3.Row,
        *,
        actor: str,
        now: int,
    ) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM canary_disclosure_permits WHERE workspace_id=? AND project_ref=? "
            "AND request_id=? AND run_id=?",
            (
                request["workspace_id"],
                request["project_ref"],
                request["request_id"],
                request["run_id"],
            ),
        ).fetchone()
        if row is None:
            return None
        if row["status"] == "consumed":
            raise CanaryDisclosureError("permit_consumed")
        if row["status"] == "expired" or row["expires_at"] <= now:
            raise CanaryDisclosureError("disclosure_permit_expired")
        if row["status"] != "permitted" or row["approved_by"] != actor:
            raise CanaryDisclosureError("canary_state_conflict")
        try:
            value = validate_disclosure_permit(json.loads(row["permit_json"]))
            self._verify_permit_signature(value)
            if (
                value["permit_id"] != row["permit_id"]
                or value["permit_digest"] != row["permit_digest"]
                or value["approved_by"] != row["approved_by"]
                or hashlib.sha256(value["permit_nonce"].encode("utf-8")).hexdigest()
                != row["nonce_hash"]
            ):
                raise ValueError("persisted permit binding mismatch")
            return value
        except (CanaryDisclosureError, TypeError, ValueError):
            raise CanaryDisclosureError("canary_authority_unavailable") from None

    def permit(
        self,
        workspace_id: str,
        project_ref: str,
        run_id: str,
        *,
        request_id: str,
        projection_schema_version: str,
        projection_digest: str,
        byte_count: int,
        scenario_count: int,
        finding_count: int,
        actor: str,
        role: str,
        recent_auth_at_ms: int,
    ) -> dict:
        """Mint one ten-minute permit from digest/count metadata, never findings bytes."""
        workspace_id = _identifier(workspace_id)
        project_ref = _identifier(project_ref)
        run_id = _identifier(run_id)
        request_id = _identifier(request_id, code="disclosure_permit_required")
        actor = _identifier(actor, code="disclosure_permit_required")
        metadata = self._metadata(
            projection_schema_version,
            projection_digest,
            byte_count,
            scenario_count,
            finding_count,
        )
        now = self._now_ms()
        if (
            role not in {"owner", "admin"}
            or type(recent_auth_at_ms) is not int
            or isinstance(recent_auth_at_ms, bool)
            or recent_auth_at_ms > now + 30_000
            or now - recent_auth_at_ms > RECENT_AUTH_MS
        ):
            raise CanaryDisclosureError("disclosure_permit_required")
        with self._write():
            row = self._run_context(workspace_id, project_ref, run_id)
            self._require_terminal_result(row)
            self._require_active_authority(row)
            membership = self.conn.execute(
                "SELECT role FROM memberships WHERE workspace_id=? AND user_id=?",
                (workspace_id, actor),
            ).fetchone()
            if (
                membership is None
                or membership["role"] not in {"owner", "admin"}
                or membership["role"] != role
            ):
                raise CanaryDisclosureError("disclosure_permit_required")
            request = self.conn.execute(
                "SELECT * FROM canary_disclosure_requests WHERE workspace_id=? AND project_ref=? "
                "AND run_id=? AND request_id=?",
                (workspace_id, project_ref, run_id, request_id),
            ).fetchone()
            if request is None:
                raise CanaryDisclosureError("disclosure_permit_required")
            exact = (
                request["schema_version"] == metadata["schema_version"]
                and request["projection_digest"] == metadata["projection_digest"]
                and request["maximum_bytes"] == metadata["byte_count"]
                and request["scenario_count"] == metadata["scenario_count"]
                and request["finding_count"] == metadata["finding_count"]
                and request["grant_id"] == row["grant_id"]
                and request["runner_id"] == row["runner_id"]
                and request["runner_key_id"] == row["runner_key_id"]
            )
            if not exact:
                raise CanaryDisclosureError("invalid_canary_projection")
            if request["expires_at"] <= now or request["status"] == "expired":
                raise CanaryDisclosureError("disclosure_permit_expired")
            if request["status"] in {"permitted", "synchronized"}:
                existing = self._existing_permit(request, actor=actor, now=now)
                if existing is not None:
                    return existing
                raise CanaryDisclosureError("canary_state_conflict")
            if request["status"] == "local_only":
                raise CanaryDisclosureError("canary_state_conflict")
            if request["status"] not in {
                "local_result_ready",
                "awaiting_disclosure_approval",
            }:
                raise CanaryDisclosureError("canary_state_conflict")
            self.conn.execute(
                "UPDATE canary_disclosure_requests SET status='awaiting_disclosure_approval',"
                "updated_at=? WHERE workspace_id=? AND project_ref=? AND request_id=?",
                (now, workspace_id, project_ref, request_id),
            )
            permit_id = "cdp_" + secrets.token_hex(16)
            nonce = secrets.token_urlsafe(32)
            unsigned = {
                "schema_version": DISCLOSURE_PERMIT_SCHEMA,
                "permit_id": permit_id,
                "workspace_id": workspace_id,
                "project_id": project_ref,
                "run_id": run_id,
                "grant_id": row["grant_id"],
                "runner_binding": {
                    "runner_id": row["runner_id"],
                    "runner_key_id": row["runner_key_id"],
                },
                "projection": {
                    "schema_version": metadata["schema_version"],
                    "projection_digest": metadata["projection_digest"],
                    "maximum_bytes": metadata["byte_count"],
                    "scenario_count": metadata["scenario_count"],
                    "finding_count": metadata["finding_count"],
                },
                "approved_by": actor,
                "approved_at_ms": now,
                "issued_at_ms": now,
                "expires_at_ms": now + DISCLOSURE_PERMIT_TTL_MS,
                "permit_nonce": nonce,
            }
            value = dict(unsigned)
            value["permit_digest"] = canonical_digest(unsigned)
            value.update(self.signing.sign(canonical_bytes(unsigned)))
            try:
                value = validate_disclosure_permit(value)
            except (TypeError, ValueError):
                raise CanaryDisclosureError("canary_authority_unavailable") from None
            serialized = canonical_bytes(value).decode("utf-8")
            self.conn.execute(
                "INSERT INTO canary_disclosure_permits("
                "permit_id,workspace_id,project_ref,request_id,run_id,grant_id,runner_id,runner_key_id,"
                "schema_version,projection_schema_version,projection_digest,permit_digest,permit_json,"
                "nonce_hash,maximum_bytes,scenario_count,finding_count,status,approved_by,approved_at,"
                "issued_at,expires_at,consumed_at,purge_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?)",
                (
                    permit_id,
                    workspace_id,
                    project_ref,
                    request_id,
                    run_id,
                    row["grant_id"],
                    row["runner_id"],
                    row["runner_key_id"],
                    DISCLOSURE_PERMIT_SCHEMA,
                    CANARY_FINDINGS_SCHEMA,
                    metadata["projection_digest"],
                    value["permit_digest"],
                    serialized,
                    hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
                    metadata["byte_count"],
                    metadata["scenario_count"],
                    metadata["finding_count"],
                    "permitted",
                    actor,
                    now,
                    now,
                    value["expires_at_ms"],
                    now + FINDINGS_RETENTION_MS,
                ),
            )
            self.conn.execute(
                "UPDATE canary_disclosure_requests SET status='permitted',updated_at=? "
                "WHERE workspace_id=? AND project_ref=? AND request_id=?",
                (now, workspace_id, project_ref, request_id),
            )
            self._audit(
                row,
                "disclosure_permitted",
                subject_ref=permit_id,
                actor_class="human",
                actor_id=actor,
                payload={
                    "permit_digest": value["permit_digest"],
                    "projection": metadata,
                },
            )
            return value

    @staticmethod
    def _verify_signed_record(record: dict, public_key: str, digest_field: str) -> None:
        unsigned = {
            key: value
            for key, value in record.items()
            if key not in {digest_field, "signing_key_id", "signature_b64"}
        }
        verify_envelope(
            {record["signing_key_id"]: load_public_key_base64(public_key)},
            {
                "signing_key_id": record["signing_key_id"],
                "signature_b64": record["signature_b64"],
            },
            canonical_bytes(unsigned),
        )

    def _validate_upload(self, request: object) -> tuple[dict, dict, dict]:
        if not isinstance(request, dict) or set(request) != {
            "schema_version",
            "run_id",
            "permit",
            "findings_projection",
        }:
            raise CanaryDisclosureError("invalid_canary_projection")
        if request.get("schema_version") != RUNNER_FINDINGS_UPLOAD_SCHEMA:
            raise CanaryDisclosureError("invalid_canary_projection")
        try:
            serialized = canonical_bytes(request)
            if len(serialized) > MAX_UPLOAD_BYTES:
                raise CanaryDisclosureError("invalid_canary_projection")
            run_id = _identifier(request["run_id"])
            permit = validate_disclosure_permit(request["permit"])
            findings = validate_canary_findings(request["findings_projection"])
        except CanaryDisclosureError:
            raise
        except (TypeError, ValueError):
            raise CanaryDisclosureError("invalid_canary_projection") from None
        return {"run_id": run_id}, permit, findings

    def _verify_permit_signature(self, permit: dict) -> None:
        if permit["signing_key_id"] != self.signing.key_id:
            raise CanaryDisclosureError("invalid_canary_projection")
        unsigned = {
            key: value
            for key, value in permit.items()
            if key not in {"permit_digest", "signing_key_id", "signature_b64"}
        }
        try:
            verify_envelope(
                {self.signing.key_id: self.signing.public_key},
                {
                    "signing_key_id": permit["signing_key_id"],
                    "signature_b64": permit["signature_b64"],
                },
                canonical_bytes(unsigned),
            )
        except (TypeError, ValueError):
            raise CanaryDisclosureError("invalid_canary_projection") from None

    def _verify_projection_bindings(
        self,
        row: sqlite3.Row,
        permit_row: sqlite3.Row,
        permit: dict,
        findings: dict,
    ) -> tuple[bytes, int, int]:
        projection_bytes = canonical_bytes(findings)
        scenario_count = len(findings["scenario_results"])
        finding_count = sum(
            item["finding"] is not None for item in findings["scenario_results"]
        )
        metadata_matches = (
            permit["projection"]["schema_version"] == findings["schema_version"]
            and permit["projection"]["projection_digest"]
            == findings["projection_digest"]
            and permit["projection"]["maximum_bytes"] == len(projection_bytes)
            and permit["projection"]["scenario_count"] == scenario_count
            and permit["projection"]["finding_count"] == finding_count
            and permit_row["projection_schema_version"] == findings["schema_version"]
            and permit_row["projection_digest"] == findings["projection_digest"]
            and permit_row["maximum_bytes"] == len(projection_bytes)
            and permit_row["scenario_count"] == scenario_count
            and permit_row["finding_count"] == finding_count
        )
        if not metadata_matches:
            raise CanaryDisclosureError("invalid_canary_projection")
        try:
            approval = validate_approval_projection(
                json.loads(row["approval_projection_json"])
            )
            grant = validate_execution_grant(json.loads(row["grant_json"]))
            receipt = validate_operational_run(json.loads(row["receipt_json"]))
            self._verify_signed_record(receipt, row["public_key"], "projection_digest")
        except (TypeError, ValueError):
            raise CanaryDisclosureError("invalid_canary_projection") from None
        expected_scenarios = [
            (item["scenario_id"], item["adapter_version"])
            for item in approval["scenarios"]
        ]
        actual_scenarios = [
            (item["scenario_id"], item["adapter_version"])
            for item in findings["scenario_results"]
        ]
        action_routes = {
            (
                item["scenario_id"],
                item["adapter_version"],
                item["method"],
                item["route_template"],
            )
            for item in approval["actions"]
        }
        routes_match = all(
            (
                item["scenario_id"],
                item["adapter_version"],
                item["route"]["method"],
                item["route"]["route_template"],
            )
            in action_routes
            for item in findings["scenario_results"]
        )
        bound = (
            findings["run_id"] == row["run_id"] == grant["run_id"] == receipt["run_id"]
            and findings["grant_id"]
            == row["grant_id"]
            == grant["grant_id"]
            == receipt["grant_id"]
            and findings["workspace_id"] == row["workspace_id"] == grant["workspace_id"]
            and findings["project_id"] == row["project_ref"] == grant["project_id"]
            and findings["environment_id"] == row["environment_id"]
            and findings["environment_id"] == grant["environment"]["environment_id"]
            and findings["manifest_digest"] == row["manifest_digest"]
            and findings["manifest_digest"] == grant["approval"]["manifest_digest"]
            and findings["manifest_digest"] == receipt["manifest_digest"]
            and findings["approval_projection_digest"]
            == row["approval_projection_digest"]
            and findings["approval_projection_digest"]
            == grant["approval"]["projection_digest"]
            and findings["approval_projection_digest"]
            == receipt["approval_projection_digest"]
            and findings["grant_digest"] == row["grant_digest"] == grant["grant_digest"]
            and findings["grant_digest"] == receipt["grant_digest"]
            and findings["engine_version"] == receipt["versions"]["engine_version"]
            and findings["adapter_versions"] == receipt["versions"]["adapter_versions"]
            and findings["adapter_versions"] == approval["runner"]["adapter_versions"]
            and findings["started_at_ms"] == receipt["timestamps"]["started_at_ms"]
            and findings["finished_at_ms"] == receipt["timestamps"]["terminal_at_ms"]
            and findings["containment_codes"] == receipt["containment_codes"]
            and findings["redaction_count"] == receipt["redaction_count"]
            and row["receipt_digest"] == receipt["projection_digest"]
            and expected_scenarios == actual_scenarios
            and routes_match
        )
        if not bound:
            raise CanaryDisclosureError("invalid_canary_projection")
        return projection_bytes, scenario_count, finding_count

    def upload(
        self,
        workspace_id: str,
        project_ref: str,
        run_id: str,
        runner_id: str,
        request: object,
    ) -> dict[str, object]:
        """Consume one permit and persist one exact projection in the caller's PoP transaction."""
        workspace_id = _identifier(workspace_id)
        project_ref = _identifier(project_ref)
        run_id = _identifier(run_id)
        runner_id = _identifier(runner_id)
        envelope, permit, findings = self._validate_upload(request)
        if envelope["run_id"] != run_id:
            raise CanaryDisclosureError("invalid_canary_projection")
        self._verify_permit_signature(permit)
        with self._write():
            row = self._run_context(
                workspace_id,
                project_ref,
                run_id,
                runner_id=runner_id,
            )
            self._require_terminal_result(row)
            self._require_active_authority(row)
            binding = permit["runner_binding"]
            if (
                permit["workspace_id"] != workspace_id
                or permit["project_id"] != project_ref
                or permit["run_id"] != run_id
                or permit["grant_id"] != row["grant_id"]
                or binding["runner_id"] != runner_id
                or binding["runner_key_id"] != row["runner_key_id"]
            ):
                raise CanaryDisclosureError("invalid_canary_projection")
            permit_row = self.conn.execute(
                "SELECT * FROM canary_disclosure_permits WHERE workspace_id=? AND project_ref=? "
                "AND permit_id=? AND run_id=? AND grant_id=? AND runner_id=? AND runner_key_id=?",
                (
                    workspace_id,
                    project_ref,
                    permit["permit_id"],
                    run_id,
                    row["grant_id"],
                    runner_id,
                    row["runner_key_id"],
                ),
            ).fetchone()
            if permit_row is None:
                raise CanaryDisclosureError("disclosure_permit_required")
            now = self._now_ms()
            if permit_row["status"] == "consumed":
                raise CanaryDisclosureError("permit_consumed")
            if permit_row["status"] == "expired" or permit_row["expires_at"] <= now:
                raise CanaryDisclosureError("disclosure_permit_expired")
            if permit_row["status"] != "permitted":
                raise CanaryDisclosureError("disclosure_permit_required")
            persisted_permit = canonical_bytes(json.loads(permit_row["permit_json"]))
            if (
                persisted_permit != canonical_bytes(permit)
                or permit_row["permit_digest"] != permit["permit_digest"]
                or permit_row["nonce_hash"]
                != hashlib.sha256(permit["permit_nonce"].encode("utf-8")).hexdigest()
            ):
                raise CanaryDisclosureError("invalid_canary_projection")
            request_row = self.conn.execute(
                "SELECT * FROM canary_disclosure_requests WHERE workspace_id=? AND project_ref=? "
                "AND request_id=? AND run_id=? AND grant_id=? AND runner_id=? AND runner_key_id=?",
                (
                    workspace_id,
                    project_ref,
                    permit_row["request_id"],
                    run_id,
                    row["grant_id"],
                    runner_id,
                    row["runner_key_id"],
                ),
            ).fetchone()
            if request_row is None or request_row["status"] != "permitted":
                raise CanaryDisclosureError("disclosure_permit_required")
            if findings["signing_key_id"] != row["runner_key_id"]:
                raise CanaryDisclosureError("invalid_canary_projection")
            try:
                self._verify_signed_record(
                    findings, row["public_key"], "projection_digest"
                )
            except (TypeError, ValueError):
                raise CanaryDisclosureError("invalid_canary_projection") from None
            projection_bytes, scenario_count, finding_count = (
                self._verify_projection_bindings(
                    row,
                    permit_row,
                    permit,
                    findings,
                )
            )
            receipt_id = "cfr_" + secrets.token_hex(16)
            receipt = {
                "schema_version": "heel.canary-findings-receipt.v1",
                "receipt_id": receipt_id,
                "workspace_id": workspace_id,
                "project_id": project_ref,
                "run_id": run_id,
                "grant_id": row["grant_id"],
                "permit_id": permit["permit_id"],
                "projection_id": findings["projection_id"],
                "projection_digest": findings["projection_digest"],
                "byte_count": len(projection_bytes),
                "scenario_count": scenario_count,
                "finding_count": finding_count,
                "accepted_at_ms": now,
                "status": "synchronized",
            }
            receipt_json = canonical_bytes(receipt).decode("utf-8")
            receipt_digest = canonical_digest(receipt)
            changed = self.conn.execute(
                "UPDATE canary_disclosure_permits SET status='consumed',consumed_at=? "
                "WHERE workspace_id=? AND project_ref=? AND permit_id=? AND status='permitted'",
                (now, workspace_id, project_ref, permit["permit_id"]),
            )
            if changed.rowcount != 1:
                raise CanaryDisclosureError("permit_consumed")
            self.conn.execute(
                "INSERT INTO canary_findings_projections("
                "finding_id,workspace_id,project_ref,run_id,grant_id,permit_id,runner_id,runner_key_id,"
                "schema_version,projection_digest,projection_json,byte_count,scenario_count,finding_count,"
                "receipt_id,receipt_digest,receipt_json,status,accepted_at,purge_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    findings["projection_id"],
                    workspace_id,
                    project_ref,
                    run_id,
                    row["grant_id"],
                    permit["permit_id"],
                    runner_id,
                    row["runner_key_id"],
                    findings["schema_version"],
                    findings["projection_digest"],
                    projection_bytes.decode("utf-8"),
                    len(projection_bytes),
                    scenario_count,
                    finding_count,
                    receipt_id,
                    receipt_digest,
                    receipt_json,
                    "synchronized",
                    now,
                    now + FINDINGS_RETENTION_MS,
                ),
            )
            self.conn.execute(
                "UPDATE canary_disclosure_requests SET status='synchronized',updated_at=? "
                "WHERE workspace_id=? AND project_ref=? AND request_id=? AND status='permitted'",
                (now, workspace_id, project_ref, request_row["request_id"]),
            )
            self._audit(
                row,
                "synchronized",
                subject_ref=receipt_id,
                actor_class="runner",
                actor_id=runner_id,
                payload={
                    "receipt_digest": receipt_digest,
                    "projection_digest": findings["projection_digest"],
                },
            )
            return receipt

    def get(self, workspace_id: str, project_ref: str, run_id: str) -> dict:
        """Return only the tenant-bound exact synchronized projection while retained."""
        workspace_id = _identifier(workspace_id)
        project_ref = _identifier(project_ref)
        run_id = _identifier(run_id)
        row = self.conn.execute(
            "SELECT f.*,k.public_key FROM canary_findings_projections f "
            "JOIN canary_runner_keys k ON k.workspace_id=f.workspace_id "
            "AND k.runner_id=f.runner_id AND k.key_id=f.runner_key_id "
            "WHERE f.workspace_id=? AND f.project_ref=? AND f.run_id=? "
            "AND f.status='synchronized' AND f.projection_json IS NOT NULL",
            (workspace_id, project_ref, run_id),
        ).fetchone()
        if row is None:
            raise CanaryDisclosureError("canary_run_not_found")
        try:
            value = validate_canary_findings(json.loads(row["projection_json"]))
            self._verify_signed_record(value, row["public_key"], "projection_digest")
        except (TypeError, ValueError):
            raise CanaryDisclosureError("canary_authority_unavailable") from None
        if (
            value["projection_digest"] != row["projection_digest"]
            or canonical_bytes(value).decode("utf-8") != row["projection_json"]
            or len(canonical_bytes(value)) != row["byte_count"]
            or len(value["scenario_results"]) != row["scenario_count"]
            or sum(item["finding"] is not None for item in value["scenario_results"])
            != row["finding_count"]
        ):
            raise CanaryDisclosureError("canary_authority_unavailable")
        return value

    def purge_expired_payloads(self, *, now_ms: int | None = None) -> int:
        """Remove seven-day findings bytes; 30-day minimal audit rows remain independently reaped."""
        if now_ms is None:
            now_ms = self._now_ms()
        if type(now_ms) is not int or isinstance(now_ms, bool) or now_ms < 0:
            raise ValueError("now_ms must be a non-negative integer")
        with self._write():
            changed = self.conn.execute(
                "UPDATE canary_findings_projections SET projection_json=NULL "
                "WHERE projection_json IS NOT NULL AND purge_at<=?",
                (now_ms,),
            )
            return changed.rowcount


__all__ = [
    "CanaryDisclosureError",
    "CanaryDisclosureService",
    "DISCLOSURE_PERMIT_TTL_MS",
    "FINDINGS_RETENTION_MS",
    "MAX_UPLOAD_BYTES",
    "RUNNER_FINDINGS_UPLOAD_SCHEMA",
]
