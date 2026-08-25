"""Transactional Cloud coordination for authorized verified-canary runs.

The service never sends target traffic and never accepts assessment content.  It coordinates one
immutable runner-signed approval projection, one human-approved execution grant, runner-bound
control chains, privacy-minimized operational receipts, stop state, and the canary-run ledger.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import time
import unicodedata
from typing import Callable, TypedDict

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from heel.canary_contracts import (
    canonical_bytes,
    canonical_digest,
    validate_approval_projection,
    validate_execution_grant,
    validate_operational_run,
)
from heel.crypto import load_public_key_base64, verify_envelope

from .canary_store import CanaryStore
from .catalog import Meter, get_plan
from .ledger import UsageLedger


APPROVAL_TTL_MS = 24 * 60 * 60 * 1000
PROJECTION_RETENTION_MS = 24 * 60 * 60 * 1000
OPERATIONAL_RETENTION_MS = 7 * 24 * 60 * 60 * 1000
AUDIT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000
RECENT_AUTH_MS = 15 * 60 * 1000
STOP_DEADLINE_MS = 5000
_IDEMPOTENCY = re.compile(r"^ca1-[0-9a-f]{64}$")
_STOP_REASONS = {
    "local_emergency_stop", "cloud_stop", "runner_revoked", "target_revoked", "kill_switch",
}
_FAULT_COMPENSATION = {"platform_fault", "runner_fault"}
_PUBLIC_ERROR_CODES = {
    "invalid_canary_projection": "invalid_canary_projection",
    "environment_not_executable": "environment_not_executable",
    "canary_authority_unavailable": "canary_authority_unavailable",
    "invalid_canary_approval": "invalid_canary_approval",
    "hostname_confirmation_mismatch": "hostname_confirmation_mismatch",
    "event_sequence_conflict": "event_sequence_conflict",
    "canary_state_conflict": "canary_state_conflict",
    "invalid_projection": "invalid_canary_projection",
    "invalid_projection_signature": "invalid_canary_projection",
    "projection_conflict": "invalid_canary_projection",
    "invalid_operational_projection": "invalid_canary_projection",
    "proof_not_executable": "environment_not_executable",
    "runner_unavailable": "canary_authority_unavailable",
    "runner_version_mismatch": "canary_authority_unavailable",
    "grant_unavailable": "canary_authority_unavailable",
    "invalid_grant": "canary_authority_unavailable",
    "operational_binding_mismatch": "canary_authority_unavailable",
    "owner_admin_required": "invalid_canary_approval",
    "approval_reason_required": "invalid_canary_approval",
    "hostname_confirmation_required": "invalid_canary_approval",
    "recent_auth_required": "invalid_canary_approval",
    "invalid_idempotency_key": "invalid_canary_approval",
    "idempotency_conflict": "invalid_canary_approval",
    "source_sequence_conflict": "event_sequence_conflict",
    "source_sequence_gap": "event_sequence_conflict",
    "operational_counter_regression": "event_sequence_conflict",
    "operational_time_regression": "event_sequence_conflict",
}


class CanaryRunError(ValueError):
    """A stable service-layer failure; HTTP maps the code without reflecting details."""

    def __init__(self, code: str):
        self.detail_code = code
        self.code = _PUBLIC_ERROR_CODES.get(code, "canary_state_conflict")
        super().__init__(self.code)


class CanaryGate(TypedDict):
    active: bool
    runner_state: str
    proof_state: str
    proof_expires_at_ms: int
    kill_switch_generation: int
    stop_reason: str
    server_time_ms: int


class CanaryClaim(TypedDict):
    schema_version: str
    run_id: str
    approval_projection: dict
    grant: dict
    chain_states: dict[str, dict[str, object]]
    gate: CanaryGate


def _identifier(value: object, code: str) -> str:
    if type(value) is not str or not value or value != value.strip() or len(value.encode()) > 128:
        raise CanaryRunError(code)
    return value


class CanaryRunService:
    """One-connection serialized coordinator; runner PoP supplies a dedicated connection."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        signing,
        runner_auth=None,
        ledger: UsageLedger | None = None,
        clock: Callable[[], float] = time.time,
        plan_for_workspace: Callable[[str], object] | None = None,
        global_cap: int | None = None,
        initialize_schema: bool = True,
    ):
        if not isinstance(conn, sqlite3.Connection):
            raise TypeError("canary coordination requires SQLite")
        if signing is None or not callable(getattr(signing, "sign", None)):
            raise TypeError("canary grant signing authority is required")
        if type(initialize_schema) is not bool:
            raise TypeError("initialize_schema must be a boolean")
        self.conn = conn
        self.conn.row_factory = sqlite3.Row
        if initialize_schema:
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.execute("PRAGMA busy_timeout=5000")
            CanaryStore(conn)
        self.signing = signing
        self.runner_auth = runner_auth
        if ledger is not None:
            self.ledger = ledger
        elif initialize_schema:
            self.ledger = UsageLedger(conn)
        else:
            # Request-scoped connections are already migration-validated.  Bind the ledger
            # methods to this exact transaction without re-running its startup DDL/pragmas.
            self.ledger = object.__new__(UsageLedger)
            self.ledger.conn = conn
        self.clock = clock
        self.plan_for_workspace = plan_for_workspace or self._workspace_plan
        self.global_cap = global_cap

    def _now_ms(self) -> int:
        return max(0, int(float(self.clock()) * 1000))

    def _server_receipt_time(self, row: sqlite3.Row) -> int:
        """Advance only from timestamps previously assigned by the control plane."""
        trusted_fields = {
            "created_at", "claimed_at_ms", "last_heartbeat_at_ms", "last_gate_at_ms",
            "stop_requested_at_ms", "stop_acknowledged_at_ms", "terminal_at_ms",
        }
        keys = set(row.keys())
        return max(
            [self._now_ms()]
            + [
                int(row[field]) for field in trusted_fields
                if field in keys and row[field] is not None
            ]
        )

    def _workspace_plan(self, workspace_id: str):
        row = self.conn.execute(
            "SELECT w.plan_id AS workspace_plan,w.catalog_version AS workspace_catalog,"
            "s.plan_id AS subscription_plan,s.catalog_version AS subscription_catalog "
            "FROM workspaces w LEFT JOIN subscriptions s ON s.workspace_id=w.workspace_id "
            "WHERE w.workspace_id=?",
            (workspace_id,),
        ).fetchone()
        if row is None:
            raise LookupError("canary run not found")
        return get_plan(
            row["subscription_plan"] or row["workspace_plan"],
            row["subscription_catalog"] or row["workspace_catalog"],
        )

    @staticmethod
    def _event_payload(event_type: str, *, status: str, reason_code: str | None = None) -> dict:
        return {
            "schema_version": "heel.canary-run-event.v1",
            "event_type": event_type,
            "status": status,
            "reason_code": reason_code,
        }

    def _append_event(
        self,
        row: sqlite3.Row,
        event_type: str,
        *,
        actor_class: str,
        actor_id: str,
        reason_code: str | None = None,
        source_event_sequence: int | None = None,
        status: str | None = None,
    ) -> int:
        current = self.conn.execute(
            "SELECT cloud_event_sequence,status FROM canary_runs "
            "WHERE workspace_id=? AND project_ref=? AND run_id=?",
            (row["workspace_id"], row["project_ref"], row["run_id"]),
        ).fetchone()
        if current is None:
            raise LookupError("canary run not found")
        sequence = int(current["cloud_event_sequence"])
        payload = self._event_payload(
            event_type, status=status or current["status"], reason_code=reason_code,
        )
        payload_json = canonical_bytes(payload).decode()
        self.conn.execute(
            "INSERT INTO canary_run_events("
            "event_id,workspace_id,project_ref,run_id,sequence,event_type,event_json,payload_digest,"
            "source_event_sequence,actor_class,actor_id,reason_code,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "cre_" + secrets.token_hex(16), row["workspace_id"], row["project_ref"],
                row["run_id"], sequence, event_type, payload_json, canonical_digest(payload),
                source_event_sequence, actor_class, actor_id, reason_code, self._now_ms(),
            ),
        )
        self.conn.execute(
            "UPDATE canary_runs SET cloud_event_sequence=cloud_event_sequence+1 "
            "WHERE workspace_id=? AND project_ref=? AND run_id=?",
            (row["workspace_id"], row["project_ref"], row["run_id"]),
        )
        return sequence

    def _audit(
        self,
        row: sqlite3.Row,
        action: str,
        *,
        subject_ref: str,
        actor_class: str,
        actor_id: str,
        reason_code: str | None = None,
        payload: object | None = None,
    ) -> None:
        now = self._now_ms()
        self.conn.execute(
            "INSERT INTO canary_audit_records("
            "audit_id,workspace_id,project_ref,run_id,subject_ref,action,actor_class,actor_id,"
            "reason_code,payload_digest,created_at,purge_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "cra_" + secrets.token_hex(16), row["workspace_id"], row["project_ref"],
                row["run_id"], subject_ref, action, actor_class, actor_id, reason_code,
                canonical_digest({"action": action} if payload is None else payload), now,
                now + AUDIT_RETENTION_MS,
            ),
        )

    @staticmethod
    def _verify_signature(record: dict, public_key: str, digest_field: str) -> None:
        payload = {
            key: value for key, value in record.items()
            if key not in {digest_field, "signing_key_id", "signature_b64"}
        }
        verify_envelope(
            {record["signing_key_id"]: load_public_key_base64(public_key)},
            {
                "signing_key_id": record["signing_key_id"],
                "signature_b64": record["signature_b64"],
            },
            canonical_bytes(payload),
        )

    def _projection_authority(self, projection: dict, now_ms: int) -> sqlite3.Row:
        env = projection["environment"]
        runner = projection["runner"]
        row = self.conn.execute(
            "SELECT e.*,k.public_key,k.status AS key_status,k.revoked_at AS key_revoked_at,"
            "r.status AS runner_status,i.identity_json "
            "FROM canary_environments e "
            "JOIN canary_runners r ON r.workspace_id=e.workspace_id AND r.runner_id=? "
            "JOIN canary_runner_keys k ON k.workspace_id=r.workspace_id AND k.runner_id=r.runner_id "
            " AND k.key_id=? "
            "LEFT JOIN canary_runner_identity_records i ON i.workspace_id=r.workspace_id "
            " AND i.runner_id=r.runner_id "
            "WHERE e.workspace_id=? AND e.project_ref=? AND e.environment_id=?",
            (
                runner["runner_id"], runner["runner_key_id"], projection["workspace_id"],
                projection["project_id"], env["environment_id"],
            ),
        ).fetchone()
        if row is None:
            raise LookupError("canary authority not found")
        if (
            row["origin"] != env["origin"]
            or row["environment_class"] != env["environment_class"]
            or row["verification_record_digest"] != env["verification_record_digest"]
            or row["status"] != "verified"
            or row["environment_class"] not in {"staging", "sandbox"}
            or row["revoked_at"] is not None
            or row["proof_expires_at"] is None
            or int(row["proof_expires_at"] * 1000) <= now_ms
        ):
            raise CanaryRunError("proof_not_executable")
        if (
            row["runner_status"] != "active"
            or row["key_status"] != "active"
            or row["key_revoked_at"] is not None
            or projection["signing_key_id"] != runner["runner_key_id"]
        ):
            raise CanaryRunError("runner_unavailable")
        try:
            identity = json.loads(row["identity_json"])
        except (TypeError, ValueError):
            raise CanaryRunError("runner_unavailable") from None
        if (
            identity.get("state") != "active"
            or identity.get("runner_version") != runner["runner_version"]
            or identity.get("public_key", {}).get("key_id") != runner["runner_key_id"]
            or identity.get("adapter_versions") != runner["adapter_versions"]
        ):
            raise CanaryRunError("runner_version_mismatch")
        versions = sorted({item["adapter_version"] for item in projection["scenarios"]})
        if versions != runner["adapter_versions"]:
            raise CanaryRunError("runner_version_mismatch")
        try:
            self._verify_signature(projection, row["public_key"], "projection_digest")
        except (TypeError, ValueError):
            raise CanaryRunError("invalid_projection_signature") from None
        return row

    def submit_projection(self, projection: object, *, uploaded_by: str) -> dict[str, object]:
        uploaded_by = _identifier(uploaded_by, "invalid_projection_actor")
        try:
            validated = validate_approval_projection(projection)
        except (TypeError, ValueError):
            raise CanaryRunError("invalid_projection") from None
        now = self._now_ms()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            authority = self._projection_authority(validated, now)
            control_generation = self._control_generation()
            if self._kill_active(validated["workspace_id"]):
                raise CanaryRunError("kill_switch_active")
            serialized = canonical_bytes(validated).decode()
            prior = self.conn.execute(
                "SELECT * FROM canary_approval_projections WHERE workspace_id=? AND project_ref=? "
                "AND (approval_id=? OR projection_digest=?)",
                (
                    validated["workspace_id"], validated["project_id"],
                    validated["projection_id"], validated["projection_digest"],
                ),
            ).fetchone()
            if prior is not None:
                if prior["projection_json"] != serialized:
                    raise CanaryRunError("projection_conflict")
                result = {
                    "schema_version": "heel.canary-projection-submitted.v1",
                    "approval_id": prior["approval_id"], "run_id": prior["run_id"],
                    "status": prior["status"], "projection_digest": prior["projection_digest"],
                }
                self.conn.commit()
                return result
            run_id = "crun_" + secrets.token_hex(16)
            expires = min(now + APPROVAL_TTL_MS, int(authority["proof_expires_at"] * 1000))
            if expires <= now:
                raise CanaryRunError("proof_not_executable")
            purge_at = expires + PROJECTION_RETENTION_MS
            scenario_ids = [item["scenario_id"] for item in validated["scenarios"]]
            self.conn.execute(
                "INSERT INTO canary_approval_projections("
                "approval_id,workspace_id,project_ref,run_id,environment_id,runner_id,runner_key_id,"
                "manifest_digest,projection_digest,signing_key_id,status,projection_json,scenario_ids_json,"
                "budgets_json,uploaded_by,created_at,expires_at,purge_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    validated["projection_id"], validated["workspace_id"], validated["project_id"],
                    run_id, validated["environment"]["environment_id"],
                    validated["runner"]["runner_id"], validated["runner"]["runner_key_id"],
                    validated["manifest_digest"], validated["projection_digest"],
                    validated["signing_key_id"], "awaiting_execution_approval", serialized,
                    canonical_bytes(scenario_ids).decode(), canonical_bytes(validated["budgets"]).decode(),
                    uploaded_by, now, expires, purge_at,
                ),
            )
            self.conn.execute(
                "INSERT INTO canary_runs("
                "run_id,workspace_id,project_ref,approval_id,grant_id,environment_id,runner_id,"
                "runner_key_id,status,execution_disposition,error_category,stop_reason,"
                "source_event_sequence,source_projection_digest,cloud_event_sequence,"
                "stop_generation,stop_ack_late,quota_state,kill_switch_generation,created_at,updated_at,purge_at) "
                "VALUES(?,?,?,?,NULL,?,?,?,?,NULL,'none','none',-1,NULL,0,0,0,'unreserved',?,?,?,?)",
                (
                    run_id, validated["workspace_id"], validated["project_id"],
                    validated["projection_id"], validated["environment"]["environment_id"],
                    validated["runner"]["runner_id"], validated["runner"]["runner_key_id"],
                    "prepared", control_generation, now, now, now + AUDIT_RETENTION_MS,
                ),
            )
            run = self._run(validated["workspace_id"], validated["project_id"], run_id)
            self._append_event(
                run, "prepared", actor_class="human", actor_id=uploaded_by,
            )
            self._audit(
                run, "prepared", subject_ref=validated["projection_id"],
                actor_class="human", actor_id=uploaded_by,
                payload={"projection_digest": validated["projection_digest"]},
            )
            self.conn.execute(
                "UPDATE canary_runs SET status='awaiting_execution_approval',updated_at=? "
                "WHERE workspace_id=? AND project_ref=? AND run_id=? AND status='prepared'",
                (now, validated["workspace_id"], validated["project_id"], run_id),
            )
            run = self._run(validated["workspace_id"], validated["project_id"], run_id)
            self._append_event(
                run, "awaiting_execution_approval", actor_class="human", actor_id=uploaded_by,
            )
            self._audit(
                run, "awaiting_execution_approval", subject_ref=validated["projection_id"],
                actor_class="human", actor_id=uploaded_by,
                payload={"projection_digest": validated["projection_digest"]},
            )
            self.conn.commit()
            return {
                "schema_version": "heel.canary-projection-submitted.v1",
                "approval_id": validated["projection_id"], "run_id": run_id,
                "status": "awaiting_execution_approval",
                "projection_digest": validated["projection_digest"],
            }
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise

    def _run(self, workspace_id: str, project_ref: str, run_id: str) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM canary_runs WHERE workspace_id=? AND project_ref=? AND run_id=?",
            (workspace_id, project_ref, run_id),
        ).fetchone()
        if row is None:
            raise LookupError("canary run not found")
        return row

    def _control_generation(self) -> int:
        row = self.conn.execute(
            "SELECT generation FROM canary_control_generation WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise RuntimeError("canary control generation unavailable")
        return int(row[0])

    def _kill_active(self, workspace_id: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM kill_switches WHERE scope IN ('global',?) LIMIT 1",
            (workspace_id,),
        ).fetchone() is not None

    @staticmethod
    def _grant_policy() -> dict:
        return {
            "schema_version": "heel.operational-run-projection.v1",
            "maximum_bytes": 32768,
            "allowed_error_categories": sorted({
                "none", "platform_fault", "runner_fault", "target_unavailable", "proof_expired",
                "dns_changed", "credential_unavailable", "version_mismatch", "budget_exhausted",
                "containment_rejected", "cloud_disconnected",
            }),
            "allowed_stop_reasons": sorted({
                "none", "local_emergency_stop", "cloud_stop", "runner_revoked",
                "target_revoked", "kill_switch",
            }),
            "allowed_containment_codes": sorted({
                "admitted", "action_started", "action_completed", "action_rejected",
                "budget_exhausted", "dns_changed", "stop_observed", "response_truncated", "redacted",
            }),
        }

    def approve(
        self,
        workspace_id: str,
        project_ref: str,
        run_id: str,
        *,
        projection_digest: str,
        actor: str,
        role: str,
        reason: str,
        exact_hostname: str,
        recent_auth_at_ms: int,
        idempotency_key: str,
        expected_kill_switch_generation: int,
    ) -> dict[str, object]:
        actor = _identifier(actor, "invalid_approval_actor")
        if (
            type(projection_digest) is not str or len(projection_digest) != 64
            or re.fullmatch(r"[0-9a-f]{64}", projection_digest) is None
        ):
            raise CanaryRunError("invalid_canary_approval")
        if role not in {"owner", "admin"}:
            raise CanaryRunError("owner_admin_required")
        if (
            type(reason) is not str or not reason.strip() or reason != reason.strip()
            or len(reason.encode()) > 500 or unicodedata.normalize("NFC", reason) != reason
            or any(unicodedata.category(character).startswith("C") for character in reason)
        ):
            raise CanaryRunError("approval_reason_required")
        if (
            type(exact_hostname) is not str or not exact_hostname
            or exact_hostname != exact_hostname.strip().lower()
            or not exact_hostname.isascii() or "\x00" in exact_hostname
        ):
            raise CanaryRunError("hostname_confirmation_required")
        if type(recent_auth_at_ms) is not int or isinstance(recent_auth_at_ms, bool):
            raise CanaryRunError("recent_auth_required")
        if type(idempotency_key) is not str or not _IDEMPOTENCY.fullmatch(idempotency_key):
            raise CanaryRunError("invalid_idempotency_key")
        if type(expected_kill_switch_generation) is not int or isinstance(
            expected_kill_switch_generation, bool
        ) or expected_kill_switch_generation < 0:
            raise CanaryRunError("kill_switch_changed")
        now = self._now_ms()
        if recent_auth_at_ms > now + 30_000 or now - recent_auth_at_ms > RECENT_AUTH_MS:
            raise CanaryRunError("recent_auth_required")
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            membership = self.conn.execute(
                "SELECT role FROM memberships WHERE workspace_id=? AND user_id=?",
                (workspace_id, actor),
            ).fetchone()
            if (
                membership is None or membership["role"] not in {"owner", "admin"}
                or membership["role"] != role
            ):
                raise CanaryRunError("owner_admin_required")
            authorized_role = membership["role"]
            run = self._run(workspace_id, project_ref, run_id)
            prior = self.conn.execute(
                "SELECT * FROM canary_execution_grants WHERE workspace_id=? AND meter=? "
                "AND idempotency_key=?",
                (workspace_id, Meter.CANARY_RUNS.value, idempotency_key),
            ).fetchone()
            if prior is not None:
                if prior["run_id"] != run_id:
                    raise CanaryRunError("idempotency_conflict")
                if prior["grant_json"] is None:
                    raise CanaryRunError("idempotency_conflict")
                grant = validate_execution_grant(json.loads(prior["grant_json"]))
                approval = self.conn.execute(
                    "SELECT approval_id,projection_digest,approved_by,reason "
                    "FROM canary_approval_projections "
                    "WHERE workspace_id=? AND project_ref=? AND run_id=?",
                    (workspace_id, project_ref, run_id),
                ).fetchone()
                if (
                    approval is None or approval["approved_by"] != actor
                    or approval["reason"] != reason
                    or prior["run_id"] != run_id
                    or prior["approval_id"] != approval["approval_id"]
                ):
                    raise CanaryRunError("idempotency_conflict")
                if (
                    approval["projection_digest"] != projection_digest
                    or grant["approval"]["projection_digest"] != projection_digest
                    or grant["egress"]["hostname"] != exact_hostname
                ):
                    raise CanaryRunError("idempotency_conflict")
                self.conn.commit()
                return {
                    "schema_version": "heel.execution-approved.v1", "run_id": run_id,
                    "grant_id": prior["grant_id"], "reservation_id": prior["reservation_id"],
                    "grant": grant,
                }
            approval = self.conn.execute(
                "SELECT * FROM canary_approval_projections WHERE workspace_id=? AND project_ref=? "
                "AND run_id=?",
                (workspace_id, project_ref, run_id),
            ).fetchone()
            if approval is None or approval["status"] != "awaiting_execution_approval":
                raise CanaryRunError("approval_state_conflict")
            if approval["projection_digest"] != projection_digest:
                raise CanaryRunError("invalid_canary_approval")
            if approval["expires_at"] <= now or approval["projection_json"] is None:
                raise CanaryRunError("approval_expired")
            projection = validate_approval_projection(json.loads(approval["projection_json"]))
            hostname = projection["egress"]["hostname"]
            if exact_hostname != hostname:
                raise CanaryRunError("hostname_confirmation_mismatch")
            authority = self._projection_authority(projection, now)
            generation = self._control_generation()
            if generation != expected_kill_switch_generation:
                raise CanaryRunError("kill_switch_changed")
            if self._kill_active(workspace_id):
                raise CanaryRunError("kill_switch_active")
            period = time.strftime("%Y-%m", time.gmtime(now / 1000))
            reservation = self.ledger.reserve_in_transaction(
                self.plan_for_workspace(workspace_id), workspace_id, Meter.CANARY_RUNS, 1, period,
                idempotency_key=idempotency_key, ref=run_id, global_cap=self.global_cap,
            )
            grant_id = "cgr_" + secrets.token_hex(16)
            nonce = secrets.token_urlsafe(32)
            issued_at = now
            expires_at = min(issued_at + 600_000, int(authority["proof_expires_at"] * 1000))
            if expires_at <= issued_at:
                raise CanaryRunError("proof_not_executable")
            public_key_bytes = load_public_key_base64(authority["public_key"]).public_bytes(
                Encoding.Raw, PublicFormat.Raw,
            )
            unsigned = {
                "schema_version": "heel.execution-grant.v1",
                "grant_id": grant_id,
                "run_id": run_id,
                "workspace_id": workspace_id,
                "project_id": project_ref,
                "approval": {
                    "projection_id": projection["projection_id"],
                    "projection_digest": projection["projection_digest"],
                    "manifest_digest": projection["manifest_digest"],
                },
                "environment": projection["environment"],
                "runner_binding": {
                    "runner_id": projection["runner"]["runner_id"],
                    "runner_key_id": projection["runner"]["runner_key_id"],
                    "public_key_digest": hashlib.sha256(public_key_bytes).hexdigest(),
                },
                "approval_actor": {"user_id": actor, "role": authorized_role},
                "approval_reason": reason,
                "consented_at_ms": now,
                "budgets": projection["budgets"],
                "egress": projection["egress"],
                "retry_policy": projection["retry_policy"],
                "grant_nonce": nonce,
                "kill_switch_generation": generation,
                "operational_receipt_policy": self._grant_policy(),
                "issued_at_ms": issued_at,
                "expires_at_ms": expires_at,
            }
            grant = dict(unsigned)
            grant["grant_digest"] = canonical_digest(unsigned)
            grant.update(self.signing.sign(canonical_bytes(unsigned)))
            grant = validate_execution_grant(grant)
            self.conn.execute(
                "UPDATE canary_approval_projections SET status='approved',approved_by=?,reason=?,"
                "approved_at=?,purge_at=? WHERE workspace_id=? AND project_ref=? AND run_id=? "
                "AND status='awaiting_execution_approval'",
                (
                    actor, reason, now, expires_at + PROJECTION_RETENTION_MS,
                    workspace_id, project_ref, run_id,
                ),
            )
            self.conn.execute(
                "INSERT INTO canary_execution_grants("
                "grant_id,workspace_id,project_ref,approval_id,run_id,environment_id,runner_id,"
                "runner_key_id,nonce_hash,grant_digest,grant_json,status,reservation_id,meter,period,"
                "idempotency_key,issued_at,expires_at,purge_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    grant_id, workspace_id, project_ref, approval["approval_id"], run_id,
                    approval["environment_id"], approval["runner_id"], approval["runner_key_id"],
                    hashlib.sha256(nonce.encode()).hexdigest(), grant["grant_digest"],
                    canonical_bytes(grant).decode(), "issued", reservation.reservation_id,
                    Meter.CANARY_RUNS.value, period, idempotency_key, issued_at, expires_at,
                    expires_at + PROJECTION_RETENTION_MS,
                ),
            )
            self.conn.execute(
                "UPDATE canary_runs SET grant_id=?,status='approved',reservation_id=?,"
                "quota_state='reserved',kill_switch_generation=?,updated_at=? "
                "WHERE workspace_id=? AND project_ref=? AND run_id=?",
                (
                    grant_id, reservation.reservation_id, generation, now,
                    workspace_id, project_ref, run_id,
                ),
            )
            run = self._run(workspace_id, project_ref, run_id)
            self._append_event(run, "quota_reserved", actor_class="system", actor_id="quota")
            self._audit(
                run, "quota_reserved", subject_ref=reservation.reservation_id,
                actor_class="system", actor_id="quota",
            )
            self._append_event(run, "approval_granted", actor_class="human", actor_id=actor)
            self._audit(
                run, "approved", subject_ref=approval["approval_id"],
                actor_class="human", actor_id=actor, payload={"reason": reason},
            )
            self._append_event(run, "grant_issued", actor_class="system", actor_id="control-plane")
            self.conn.commit()
            return {
                "schema_version": "heel.execution-approved.v1", "run_id": run_id,
                "grant_id": grant_id, "reservation_id": reservation.reservation_id,
                "grant": grant,
            }
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise

    def _validate_stored_grant(self, row: sqlite3.Row, now: int) -> dict:
        if row["grant_json"] is None:
            raise CanaryRunError("grant_unavailable")
        try:
            grant = validate_execution_grant(json.loads(row["grant_json"]))
            self._verify_signature(grant, self.signing.canonical_public_key, "grant_digest")
        except (TypeError, ValueError, AttributeError):
            raise CanaryRunError("invalid_grant") from None
        if (
            grant["grant_id"] != row["grant_id"]
            or grant["run_id"] != row["run_id"]
            or grant["workspace_id"] != row["workspace_id"]
            or grant["project_id"] != row["project_ref"]
            or grant["approval"]["projection_id"] != row["approval_id"]
            or grant["environment"]["environment_id"] != row["environment_id"]
            or grant["grant_digest"] != row["grant_digest"]
            or grant["runner_binding"]["runner_id"] != row["runner_id"]
            or grant["runner_binding"]["runner_key_id"] != row["runner_key_id"]
            or grant["issued_at_ms"] != row["issued_at"]
            or grant["expires_at_ms"] != row["expires_at"]
            or grant["expires_at_ms"] <= now
            or hashlib.sha256(grant["grant_nonce"].encode()).hexdigest() != row["nonce_hash"]
        ):
            raise CanaryRunError("invalid_grant")
        key = self.conn.execute(
            "SELECT public_key FROM canary_runner_keys WHERE workspace_id=? AND runner_id=? "
            "AND key_id=?",
            (row["workspace_id"], row["runner_id"], row["runner_key_id"]),
        ).fetchone()
        if key is None:
            raise CanaryRunError("invalid_grant")
        try:
            public_key_digest = hashlib.sha256(
                load_public_key_base64(key["public_key"]).public_bytes(
                    Encoding.Raw, PublicFormat.Raw,
                )
            ).hexdigest()
        except (TypeError, ValueError):
            raise CanaryRunError("invalid_grant") from None
        if grant["runner_binding"]["public_key_digest"] != public_key_digest:
            raise CanaryRunError("invalid_grant")
        return grant

    def claim(self, workspace_id: str, runner_id: str, runner_key_id: str) -> CanaryClaim | None:
        owns_transaction = not self.conn.in_transaction
        if owns_transaction:
            self.conn.execute("BEGIN IMMEDIATE")
        try:
            now = self._now_ms()
            row = self.conn.execute(
                "SELECT * FROM canary_execution_grants WHERE workspace_id=? AND runner_id=? "
                "AND runner_key_id=? AND status='issued' AND expires_at>? "
                "ORDER BY issued_at,grant_id LIMIT 1",
                (workspace_id, runner_id, runner_key_id, now),
            ).fetchone()
            if row is None:
                if owns_transaction:
                    self.conn.commit()
                return None
            grant = self._validate_stored_grant(row, now)
            approval = self.conn.execute(
                "SELECT * FROM canary_approval_projections WHERE workspace_id=? AND project_ref=? "
                "AND approval_id=? AND runner_id=? AND runner_key_id=?",
                (
                    workspace_id, row["project_ref"], row["approval_id"], runner_id,
                    runner_key_id,
                ),
            ).fetchone()
            if approval is None or approval["projection_json"] is None or approval["status"] != "approved":
                raise CanaryRunError("invalid_grant")
            projection = validate_approval_projection(json.loads(approval["projection_json"]))
            if (
                grant["approval"]["projection_id"] != projection["projection_id"]
                or grant["approval"]["projection_digest"] != approval["projection_digest"]
                or grant["approval"]["projection_digest"] != projection["projection_digest"]
                or grant["approval"]["manifest_digest"] != approval["manifest_digest"]
                or grant["approval"]["manifest_digest"] != projection["manifest_digest"]
                or grant["environment"] != projection["environment"]
                or grant["budgets"] != projection["budgets"]
                or grant["egress"] != projection["egress"]
                or grant["retry_policy"] != projection["retry_policy"]
                or grant["approval_actor"]["user_id"] != approval["approved_by"]
                or grant["approval_reason"] != approval["reason"]
                or grant["consented_at_ms"] != approval["approved_at"]
            ):
                raise CanaryRunError("invalid_grant")
            self._projection_authority(projection, now)
            generation = self._control_generation()
            if self._kill_active(workspace_id) or generation != grant["kill_switch_generation"]:
                raise CanaryRunError("kill_switch_changed")
            if self.runner_auth is None or self.runner_auth.conn is not self.conn:
                raise RuntimeError("runner authentication transaction is required")
            self.conn.execute(
                "INSERT INTO canary_consumed_nonces("
                "nonce_hash,workspace_id,project_ref,runner_id,run_id,grant_id,kind,consumed_at,expires_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    row["nonce_hash"], workspace_id, row["project_ref"], runner_id,
                    row["run_id"], row["grant_id"], "execution_grant", now, row["expires_at"],
                ),
            )
            chain_states = self.runner_auth.provision_run_chains_in_transaction(
                workspace_id, runner_id, row["run_id"],
            )
            changed = self.conn.execute(
                "UPDATE canary_execution_grants SET status='claimed',claimed_at=? "
                "WHERE workspace_id=? AND project_ref=? AND grant_id=? AND status='issued'",
                (now, workspace_id, row["project_ref"], row["grant_id"]),
            )
            if changed.rowcount != 1:
                raise CanaryRunError("grant_claim_conflict")
            run_changed = self.conn.execute(
                "UPDATE canary_runs SET status='claimed',claimed_at_ms=?,updated_at=? "
                "WHERE workspace_id=? AND project_ref=? AND run_id=? AND status='approved'",
                (now, now, workspace_id, row["project_ref"], row["run_id"]),
            )
            if run_changed.rowcount != 1:
                raise CanaryRunError("grant_claim_conflict")
            run = self._run(workspace_id, row["project_ref"], row["run_id"])
            self._append_event(run, "grant_claimed", actor_class="runner", actor_id=runner_id)
            self._audit(
                run, "claimed", subject_ref=row["grant_id"],
                actor_class="runner", actor_id=runner_id,
            )
            gate = self._gate(run, advance=True)
            result: CanaryClaim = {
                "schema_version": "heel.runner-claim-response.v1",
                "run_id": row["run_id"], "approval_projection": projection,
                "grant": grant, "chain_states": chain_states, "gate": gate,
            }
            if owns_transaction:
                self.conn.commit()
            return result
        except Exception:
            if owns_transaction and self.conn.in_transaction:
                self.conn.rollback()
            raise

    def _context(self, workspace_id: str, project_ref: str, run_id: str, runner_id: str) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT r.*,g.grant_digest,g.grant_json,g.status AS grant_status,g.expires_at AS grant_expires_at,"
            "a.projection_digest AS approval_projection_digest,a.manifest_digest,a.projection_json,"
            "e.status AS proof_status,e.proof_expires_at,e.revoked_at AS proof_revoked_at,"
            "e.verification_record_digest,k.public_key,k.status AS key_status,k.revoked_at AS key_revoked_at,"
            "cr.status AS runner_status "
            "FROM canary_runs r JOIN canary_execution_grants g ON "
            "g.workspace_id=r.workspace_id AND g.project_ref=r.project_ref AND g.grant_id=r.grant_id "
            "JOIN canary_approval_projections a ON a.workspace_id=r.workspace_id "
            "AND a.project_ref=r.project_ref AND a.approval_id=r.approval_id "
            "JOIN canary_environments e ON e.workspace_id=r.workspace_id "
            "AND e.project_ref=r.project_ref AND e.environment_id=r.environment_id "
            "JOIN canary_runner_keys k ON k.workspace_id=r.workspace_id AND k.runner_id=r.runner_id "
            "AND k.key_id=r.runner_key_id "
            "JOIN canary_runners cr ON cr.workspace_id=r.workspace_id AND cr.runner_id=r.runner_id "
            "WHERE r.workspace_id=? AND r.project_ref=? AND r.run_id=? AND r.runner_id=?",
            (workspace_id, project_ref, run_id, runner_id),
        ).fetchone()
        if row is None:
            raise LookupError("canary run not found")
        return row

    def _stored_operational_authority(self, row: sqlite3.Row) -> tuple[dict, dict]:
        """Verify and return the immutable runner approval and Cloud execution grant."""
        if row["projection_json"] is None or row["grant_json"] is None:
            raise CanaryRunError("operational_binding_mismatch")
        try:
            approval = validate_approval_projection(json.loads(row["projection_json"]))
            grant = validate_execution_grant(json.loads(row["grant_json"]))
            self._verify_signature(approval, row["public_key"], "projection_digest")
            self._verify_signature(grant, self.signing.canonical_public_key, "grant_digest")
        except (TypeError, ValueError, json.JSONDecodeError):
            raise CanaryRunError("operational_binding_mismatch") from None
        if (
            approval["projection_digest"] != row["approval_projection_digest"]
            or approval["manifest_digest"] != row["manifest_digest"]
            or approval["workspace_id"] != row["workspace_id"]
            or approval["project_id"] != row["project_ref"]
            or approval["runner"]["runner_id"] != row["runner_id"]
            or approval["runner"]["runner_key_id"] != row["runner_key_id"]
            or grant["grant_id"] != row["grant_id"]
            or grant["grant_digest"] != row["grant_digest"]
            or grant["run_id"] != row["run_id"]
            or grant["workspace_id"] != row["workspace_id"]
            or grant["project_id"] != row["project_ref"]
            or grant["approval"]["projection_digest"] != approval["projection_digest"]
            or grant["approval"]["manifest_digest"] != approval["manifest_digest"]
            or grant["runner_binding"]["runner_id"] != row["runner_id"]
            or grant["runner_binding"]["runner_key_id"] != row["runner_key_id"]
            or grant["environment"] != approval["environment"]
            or grant["budgets"] != approval["budgets"]
            or grant["retry_policy"] != approval["retry_policy"]
        ):
            raise CanaryRunError("operational_binding_mismatch")
        return approval, grant

    @staticmethod
    def _operational_within_budget(value: dict, approval: dict, grant: dict) -> bool:
        budgets = approval["budgets"]
        counters = value["counters"]
        requests_started = counters["requests_started"]
        return bool(
            grant["budgets"] == budgets
            and grant["retry_policy"] == approval["retry_policy"]
            and requests_started <= budgets["maximum_requests"]
            and counters["remaining_requests"] == budgets["maximum_requests"] - requests_started
            and counters["retries_used"] <= grant["retry_policy"]["maximum_retries"]
            and counters["actions_contained"] + counters["retries_used"] == requests_started
            and counters["response_bytes_read"]
            <= counters["requests_completed"] * budgets["maximum_response_bytes"]
            and counters["remaining_wall_ms"] <= budgets["wall_timeout_ms"]
        )

    @staticmethod
    def _verification_digest_matches(row: sqlite3.Row, approval: dict, grant: dict) -> bool:
        current = row["verification_record_digest"]
        return bool(
            type(current) is str
            and current == approval["environment"]["verification_record_digest"]
            and current == grant["environment"]["verification_record_digest"]
        )

    def _persist_authority_stop(
        self, row: sqlite3.Row, *, reason: str = "target_revoked",
        detail_reason: str = "verification_digest_replaced",
    ) -> sqlite3.Row:
        """Permanently close target authority using only the Cloud receipt clock."""
        if row["status"] in {"terminal", "cancelled", "expired"} or row["stop_reason"] != "none":
            return row
        now = self._server_receipt_time(row)
        next_status = "finalizing" if row["status"] == "finalizing" else "stop_requested"
        self.conn.execute(
            "UPDATE canary_runs SET status=?,error_category='version_mismatch',stop_reason=?,"
            "stop_generation=?,stop_requested_at_ms=?,stop_deadline_ms=?,updated_at=? "
            "WHERE workspace_id=? AND project_ref=? AND run_id=? AND stop_reason='none'",
            (
                next_status, reason, self._control_generation(), now, now + STOP_DEADLINE_MS,
                now, row["workspace_id"], row["project_ref"], row["run_id"],
            ),
        )
        updated = self._context(
            row["workspace_id"], row["project_ref"], row["run_id"], row["runner_id"],
        )
        self._append_event(
            updated, "stop_requested", actor_class="system", actor_id="control-plane",
            reason_code=detail_reason,
        )
        self._audit(
            updated, "stop_requested", subject_ref=row["run_id"],
            actor_class="system", actor_id="control-plane", reason_code=detail_reason,
        )
        return self._context(
            row["workspace_id"], row["project_ref"], row["run_id"], row["runner_id"],
        )

    def _validate_operational(self, row: sqlite3.Row, projection: object) -> dict:
        try:
            value = validate_operational_run(projection)
            self._verify_signature(value, row["public_key"], "projection_digest")
        except (TypeError, ValueError):
            raise CanaryRunError("invalid_operational_projection") from None
        if (
            row["runner_status"] != "active"
            or row["key_status"] != "active"
            or row["key_revoked_at"] is not None
            or value["signing_key_id"] != row["runner_key_id"]
            or value["run_id"] != row["run_id"]
            or value["grant_id"] != row["grant_id"]
            or value["workspace_id"] != row["workspace_id"]
            or value["project_id"] != row["project_ref"]
            or value["grant_digest"] != row["grant_digest"]
            or value["approval_projection_digest"] != row["approval_projection_digest"]
            or value["manifest_digest"] != row["manifest_digest"]
        ):
            raise CanaryRunError("operational_binding_mismatch")
        approval, grant = self._stored_operational_authority(row)
        if not self._operational_within_budget(value, approval, grant):
            raise CanaryRunError("invalid_operational_projection")
        return value

    def _source_state(self, row: sqlite3.Row, projection: dict) -> str:
        sequence = projection["event_sequence"]
        digest = projection["projection_digest"]
        if sequence == row["source_event_sequence"]:
            if digest == row["source_projection_digest"]:
                return "replay"
            raise CanaryRunError("source_sequence_conflict")
        if sequence != row["source_event_sequence"] + 1:
            raise CanaryRunError("source_sequence_gap")
        receipt = self.conn.execute(
            "SELECT receipt_json FROM canary_operational_receipts WHERE workspace_id=? "
            "AND project_ref=? AND run_id=?",
            (row["workspace_id"], row["project_ref"], row["run_id"]),
        ).fetchone()
        if receipt is not None and receipt["receipt_json"] is not None:
            previous = json.loads(receipt["receipt_json"])
            before, after = previous["counters"], projection["counters"]
            increasing = (
                "requests_started", "requests_completed", "response_bytes_read",
                "actions_contained", "retries_used",
            )
            decreasing = ("remaining_requests", "remaining_wall_ms")
            if any(after[name] < before[name] for name in increasing) or any(
                after[name] > before[name] for name in decreasing
            ) or projection["redaction_count"] < previous["redaction_count"]:
                raise CanaryRunError("operational_counter_regression")
            if projection["timestamps"]["updated_at_ms"] < previous["timestamps"]["updated_at_ms"]:
                raise CanaryRunError("operational_time_regression")
        return "new"

    def _store_receipt(
        self, row: sqlite3.Row, projection: dict, *, received_at_ms: int | None = None,
    ) -> None:
        now = self._server_receipt_time(row) if received_at_ms is None else received_at_ms
        serialized = canonical_bytes(projection).decode()
        self.conn.execute(
            "INSERT INTO canary_operational_receipts("
            "run_id,workspace_id,project_ref,grant_id,runner_id,runner_key_id,source_event_sequence,"
            "lifecycle_phase,execution_disposition,error_category,stop_reason,receipt_digest,"
            "receipt_json,created_at,updated_at,purge_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(run_id) DO UPDATE SET source_event_sequence=excluded.source_event_sequence,"
            "lifecycle_phase=excluded.lifecycle_phase,execution_disposition=excluded.execution_disposition,"
            "error_category=excluded.error_category,stop_reason=excluded.stop_reason,"
            "receipt_digest=excluded.receipt_digest,receipt_json=excluded.receipt_json,"
            "updated_at=excluded.updated_at,purge_at=excluded.purge_at",
            (
                row["run_id"], row["workspace_id"], row["project_ref"], row["grant_id"],
                row["runner_id"], row["runner_key_id"], projection["event_sequence"],
                projection["lifecycle_phase"], projection["execution_disposition"],
                projection["error_category"], projection["stop_reason"],
                projection["projection_digest"], serialized, now, now,
                now + OPERATIONAL_RETENTION_MS,
            ),
        )

    def _consume_if_started(self, row: sqlite3.Row, projection: dict) -> sqlite3.Row:
        if projection["counters"]["requests_started"] <= 0 or row["quota_state"] != "reserved":
            return row
        if not self.ledger.consume_in_transaction(row["reservation_id"]):
            raise CanaryRunError("quota_settlement_conflict")
        self.conn.execute(
            "UPDATE canary_runs SET quota_state='consumed' WHERE workspace_id=? AND project_ref=? AND run_id=?",
            (row["workspace_id"], row["project_ref"], row["run_id"]),
        )
        row = self._run(row["workspace_id"], row["project_ref"], row["run_id"])
        self._append_event(row, "quota_consumed", actor_class="system", actor_id="quota")
        self._audit(
            row, "quota_consumed", subject_ref=row["reservation_id"],
            actor_class="system", actor_id="quota",
        )
        return self._context(row["workspace_id"], row["project_ref"], row["run_id"], row["runner_id"])

    def _gate(self, row: sqlite3.Row, *, advance: bool) -> CanaryGate:
        context = self._context(row["workspace_id"], row["project_ref"], row["run_id"], row["runner_id"])
        now = self._now_ms()
        generation = self._control_generation()
        approval, grant = self._stored_operational_authority(context)
        verification_mismatch = not self._verification_digest_matches(
            context, approval, grant,
        )
        if verification_mismatch:
            context = self._persist_authority_stop(context)
        runner_state = context["runner_status"] if context["runner_status"] in {"active", "revoked", "replaced"} else "revoked"
        if verification_mismatch or context["proof_revoked_at"] is not None or context["proof_status"] == "revoked":
            proof_state = "revoked"
        elif context["proof_expires_at"] is None or int(context["proof_expires_at"] * 1000) <= now:
            proof_state = "expired"
        else:
            proof_state = "valid"
        if context["stop_reason"] != "none":
            stop_reason = context["stop_reason"]
        elif runner_state != "active":
            stop_reason = "runner_revoked"
        elif proof_state == "revoked":
            stop_reason = "target_revoked"
        elif self._kill_active(context["workspace_id"]) or generation != context["kill_switch_generation"]:
            stop_reason = "kill_switch"
        else:
            stop_reason = "none"
        active = bool(
            context["status"] in {"claimed", "running", "finalizing"}
            and runner_state == "active" and proof_state == "valid"
            and context["grant_status"] == "claimed" and context["grant_expires_at"] > now
            and generation == context["kill_switch_generation"]
            and not self._kill_active(context["workspace_id"]) and stop_reason == "none"
        )
        previous = context["last_gate_at_ms"]
        server_time = max(now, (int(previous) + 1) if previous is not None and advance else now)
        if not advance and previous is not None:
            server_time = int(previous)
        if advance:
            self.conn.execute(
                "UPDATE canary_runs SET last_gate_at_ms=?,updated_at=max(updated_at,?) "
                "WHERE workspace_id=? AND project_ref=? AND run_id=?",
                (server_time, server_time, context["workspace_id"], context["project_ref"], context["run_id"]),
            )
        return {
            "active": active,
            "runner_state": runner_state,
            "proof_state": proof_state,
            "proof_expires_at_ms": max(0, int((context["proof_expires_at"] or 0) * 1000)),
            "kill_switch_generation": generation,
            "stop_reason": stop_reason,
            "server_time_ms": server_time,
        }

    def _accept_operational(
        self,
        workspace_id: str,
        project_ref: str,
        run_id: str,
        runner_id: str,
        projection: object,
        *,
        operation: str,
    ) -> tuple[sqlite3.Row, dict, str]:
        row = self._context(workspace_id, project_ref, run_id, runner_id)
        approval, grant = self._stored_operational_authority(row)
        verification_mismatch = not self._verification_digest_matches(row, approval, grant)
        if verification_mismatch:
            row = self._persist_authority_stop(row)
        value = self._validate_operational(row, projection)
        phase = value["lifecycle_phase"]
        stop_reason = value["stop_reason"]
        if phase == "stop_requested" and stop_reason == "none":
            raise CanaryRunError("illegal_run_transition")
        if stop_reason != "none" and phase not in {"stop_requested", "finalizing"}:
            raise CanaryRunError("illegal_run_transition")
        if operation != "result" and phase == "terminal":
            raise CanaryRunError("illegal_run_transition")
        if operation == "result" and phase != "terminal":
            raise CanaryRunError("illegal_run_transition")
        # A post-stop heartbeat can legitimately carry the last exact pre-stop snapshot.  It is
        # Cloud liveness only: never overwrite the durable stop or runner receipt.  The shared
        # source check still rejects equal-sequence/different-digest projections.
        if operation == "heartbeat" and row["stop_reason"] != "none" and stop_reason == "none":
            source = self._source_state(row, value)
            if source == "replay":
                return row, value, "liveness"
            raise CanaryRunError("stop_conflict")
        if verification_mismatch and stop_reason == "none":
            return row, value, "authority_stop"
        # Heartbeat and progress use independent PoP chains while reporting one shared
        # operational sequence.  A delayed, still-authentic heartbeat is liveness evidence,
        # not authority to roll the durable lifecycle snapshot backwards.
        if operation == "heartbeat" and value["event_sequence"] < row["source_event_sequence"]:
            return row, value, "stale"
        if row["stop_reason"] != "none" and stop_reason != row["stop_reason"]:
            raise CanaryRunError("stop_conflict")
        source = self._source_state(row, value)
        if source == "replay":
            return row, value, source
        allowed = {
            "claimed": {"claimed", "running", "stop_requested", "finalizing"},
            "running": {"running", "stop_requested", "finalizing"},
            "stop_requested": {"stop_requested", "finalizing"},
            "finalizing": {"finalizing"},
            "terminal": {"terminal"},
        }
        if row["status"] not in allowed or phase not in allowed[row["status"]]:
            raise CanaryRunError("illegal_run_transition")
        old_status = row["status"]
        row = self._consume_if_started(row, value)
        received_at = self._server_receipt_time(row)
        self._store_receipt(row, value, received_at_ms=received_at)
        new_status = row["status"]
        if phase == "running" and row["status"] == "claimed":
            new_status = "running"
        elif phase == "stop_requested" and row["status"] in {"claimed", "running"}:
            new_status = "stop_requested"
        elif phase == "finalizing" and row["status"] in {"claimed", "running", "stop_requested"}:
            new_status = "finalizing"
        timestamps = value["timestamps"]
        entering_stop = stop_reason != "none" and row["stop_reason"] == "none"
        stop_requested_at = received_at if entering_stop else None
        stop_deadline = received_at + STOP_DEADLINE_MS if entering_stop else None
        stop_generation = self._control_generation() if entering_stop else row["stop_generation"]
        started_at = received_at if timestamps["started_at_ms"] is not None else None
        self.conn.execute(
            "UPDATE canary_runs SET status=?,source_event_sequence=?,source_projection_digest=?,"
            "error_category=?,stop_reason=CASE WHEN ?='none' THEN stop_reason ELSE ? END,"
            "started_at_ms=COALESCE(started_at_ms,?),"
            "stop_requested_at_ms=COALESCE(stop_requested_at_ms,?),"
            "stop_deadline_ms=COALESCE(stop_deadline_ms,?),stop_generation=?,updated_at=? "
            "WHERE workspace_id=? AND project_ref=? AND run_id=?",
            (
                new_status, value["event_sequence"], value["projection_digest"],
                value["error_category"], value["stop_reason"], value["stop_reason"],
                started_at, stop_requested_at, stop_deadline, stop_generation, received_at,
                workspace_id, project_ref, run_id,
            ),
        )
        row = self._context(workspace_id, project_ref, run_id, runner_id)
        if entering_stop:
            self._append_event(
                row, "stop_requested", actor_class="runner", actor_id=runner_id,
                reason_code=stop_reason, source_event_sequence=value["event_sequence"],
            )
            self._audit(
                row, "stop_requested", subject_ref=run_id, actor_class="runner",
                actor_id=runner_id, reason_code=stop_reason,
            )
            row = self._context(workspace_id, project_ref, run_id, runner_id)
        if new_status != old_status and new_status == "running":
            self._append_event(
                row, "run_started", actor_class="runner", actor_id=runner_id,
                source_event_sequence=value["event_sequence"],
            )
            self._audit(
                row, "running", subject_ref=run_id,
                actor_class="runner", actor_id=runner_id,
            )
            row = self._context(workspace_id, project_ref, run_id, runner_id)
        elif new_status != old_status and new_status == "finalizing":
            self._append_event(
                row, "finalizing", actor_class="runner", actor_id=runner_id,
                source_event_sequence=value["event_sequence"],
            )
            row = self._context(workspace_id, project_ref, run_id, runner_id)
        return row, value, source

    def heartbeat(
        self, workspace_id: str, project_ref: str, run_id: str, runner_id: str,
        projection: object,
    ) -> CanaryGate:
        owns_transaction = not self.conn.in_transaction
        if owns_transaction:
            self.conn.execute("BEGIN IMMEDIATE")
        try:
            row, value, source = self._accept_operational(
                workspace_id, project_ref, run_id, runner_id, projection, operation="heartbeat",
            )
            now = self._server_receipt_time(row)
            self.conn.execute(
                "UPDATE canary_runs SET last_heartbeat_at_ms=? WHERE workspace_id=? "
                "AND project_ref=? AND run_id=?",
                (now, workspace_id, project_ref, run_id),
            )
            row = self._context(workspace_id, project_ref, run_id, runner_id)
            if source in {"new", "replay"}:
                self._append_event(
                    row, "heartbeat_accepted", actor_class="runner", actor_id=runner_id,
                    source_event_sequence=value["event_sequence"],
                )
            gate = self._gate(row, advance=True)
            if owns_transaction:
                self.conn.commit()
            return gate
        except Exception:
            if owns_transaction and self.conn.in_transaction:
                self.conn.rollback()
            raise

    def progress(
        self, workspace_id: str, project_ref: str, run_id: str, runner_id: str,
        projection: object,
    ) -> dict[str, object]:
        owns_transaction = not self.conn.in_transaction
        if owns_transaction:
            self.conn.execute("BEGIN IMMEDIATE")
        try:
            row, value, source = self._accept_operational(
                workspace_id, project_ref, run_id, runner_id, projection, operation="progress",
            )
            if source == "new":
                self._append_event(
                    row, "progress_accepted", actor_class="runner", actor_id=runner_id,
                    source_event_sequence=value["event_sequence"],
                )
            status = self.get_status(workspace_id, project_ref, run_id)
            if owns_transaction:
                self.conn.commit()
            return status
        except Exception:
            if owns_transaction and self.conn.in_transaction:
                self.conn.rollback()
            raise

    def request_stop(
        self,
        workspace_id: str,
        project_ref: str,
        run_id: str,
        *,
        actor: str,
        reason: str,
        expected_kill_switch_generation: int,
    ) -> dict[str, object]:
        actor = _identifier(actor, "invalid_stop_actor")
        if reason not in _STOP_REASONS:
            raise CanaryRunError("invalid_stop_reason")
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._run(workspace_id, project_ref, run_id)
            if row["status"] != "terminal" and row["stop_requested_at_ms"] is not None:
                if (
                    row["stop_reason"] != reason
                    or row["stop_generation"] != expected_kill_switch_generation
                ):
                    raise CanaryRunError("stop_conflict")
                result = {
                    "schema_version": "heel.canary-stop-requested.v1",
                    "run_id": run_id, "stop_generation": row["stop_generation"],
                    "deadline_ms": row["stop_deadline_ms"], "reason": reason,
                }
                self.conn.commit()
                return result
            generation = self._control_generation()
            if generation != expected_kill_switch_generation:
                raise CanaryRunError("kill_switch_changed")
            if row["status"] not in {"claimed", "running"}:
                raise CanaryRunError("stop_conflict")
            now = self._server_receipt_time(row)
            deadline = now + STOP_DEADLINE_MS
            self.conn.execute(
                "UPDATE canary_runs SET status='stop_requested',stop_reason=?,stop_generation=?,"
                "stop_requested_at_ms=?,stop_deadline_ms=?,updated_at=? "
                "WHERE workspace_id=? AND project_ref=? AND run_id=?",
                (reason, generation, now, deadline, now, workspace_id, project_ref, run_id),
            )
            row = self._run(workspace_id, project_ref, run_id)
            self._append_event(
                row, "stop_requested", actor_class="human", actor_id=actor, reason_code=reason,
            )
            self._audit(
                row, "stop_requested", subject_ref=run_id, actor_class="human", actor_id=actor,
                reason_code=reason,
            )
            self.conn.commit()
            return {
                "schema_version": "heel.canary-stop-requested.v1", "run_id": run_id,
                "stop_generation": generation, "deadline_ms": deadline, "reason": reason,
            }
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise

    def ack_stop(
        self, workspace_id: str, project_ref: str, run_id: str, runner_id: str,
        projection: object,
    ) -> dict[str, bool]:
        owns_transaction = not self.conn.in_transaction
        if owns_transaction:
            self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._context(workspace_id, project_ref, run_id, runner_id)
            approval, grant = self._stored_operational_authority(row)
            if not self._verification_digest_matches(row, approval, grant):
                row = self._persist_authority_stop(row)
            value = self._validate_operational(row, projection)
            source = self._source_state(row, value)
            if source == "replay" and row["stop_acknowledged_at_ms"] is not None:
                late = bool(row["stop_ack_late"])
                if owns_transaction:
                    self.conn.commit()
                return {"accepted": True, "deadline_met": not late, "late": late}
            arrival = self._server_receipt_time(row)
            runner_originated_stop = bool(
                row["status"] in {"claimed", "running"}
                and value["lifecycle_phase"] == "stop_requested"
                and value["stop_reason"] == "local_emergency_stop"
            )
            if runner_originated_stop:
                generation = self._control_generation()
                self.conn.execute(
                    "UPDATE canary_runs SET status='stop_requested',error_category=?,"
                    "stop_reason='local_emergency_stop',stop_generation=?,"
                    "stop_requested_at_ms=?,stop_deadline_ms=?,updated_at=? "
                    "WHERE workspace_id=? AND project_ref=? AND run_id=? "
                    "AND status IN ('claimed','running') AND stop_reason='none'",
                    (
                        value["error_category"], generation, arrival,
                        arrival + STOP_DEADLINE_MS, arrival,
                        workspace_id, project_ref, run_id,
                    ),
                )
                row = self._context(workspace_id, project_ref, run_id, runner_id)
                self._append_event(
                    row, "stop_requested", actor_class="runner", actor_id=runner_id,
                    reason_code="local_emergency_stop",
                    source_event_sequence=value["event_sequence"],
                )
                self._audit(
                    row, "stop_requested", subject_ref=run_id,
                    actor_class="runner", actor_id=runner_id,
                    reason_code="local_emergency_stop",
                )
                row = self._context(workspace_id, project_ref, run_id, runner_id)
            if row["status"] not in {"stop_requested", "finalizing", "terminal"}:
                raise CanaryRunError("stop_conflict")
            if value["lifecycle_phase"] not in {"stop_requested", "finalizing"}:
                raise CanaryRunError("invalid_stop_ack")
            if row["stop_acknowledged_at_ms"] is not None:
                raise CanaryRunError("stop_conflict")
            acknowledged = value["timestamps"]["stop_acknowledged_at_ms"]
            if acknowledged is None or row["stop_deadline_ms"] is None:
                raise CanaryRunError("invalid_stop_ack")
            if value["stop_reason"] != row["stop_reason"]:
                raise CanaryRunError("invalid_stop_ack")
            # The Cloud receipt clock is deadline authority.  Runner-local stop/ack times stay
            # signed evidence, but skew or backdating can neither win nor lose the five-second SLA.
            late = arrival > row["stop_deadline_ms"]
            terminal_ack = row["status"] == "terminal"
            if (
                terminal_ack and row["quota_state"] == "refunded"
                and value["counters"]["requests_started"] > 0
            ):
                # Reconciliation may already have refunded a run that never reached target I/O.
                # A post-terminal acknowledgement is stop evidence only; it cannot introduce
                # newly claimed execution after the durable terminal/quota decision.
                raise CanaryRunError("stop_conflict")
            if not terminal_ack:
                row = self._consume_if_started(row, value)
                self._store_receipt(row, value, received_at_ms=arrival)
            next_status = (
                "terminal" if terminal_ack else
                "finalizing" if value["lifecycle_phase"] == "finalizing" else row["status"]
            )
            self.conn.execute(
                "UPDATE canary_runs SET status=?,source_event_sequence=?,source_projection_digest=?,"
                "stop_acknowledged_at_ms=?,stop_ack_late=?,updated_at=? "
                "WHERE workspace_id=? AND project_ref=? AND run_id=?",
                (
                    next_status, value["event_sequence"], value["projection_digest"], arrival,
                    int(late), arrival,
                    workspace_id, project_ref, run_id,
                ),
            )
            row = self._run(workspace_id, project_ref, run_id)
            self._append_event(
                row, "stop_acknowledged", actor_class="runner", actor_id=runner_id,
                reason_code="late" if late else "deadline_met",
                source_event_sequence=value["event_sequence"],
            )
            self._audit(
                row, "stop_ack_late" if late else "stop_acknowledged", subject_ref=run_id,
                actor_class="runner", actor_id=runner_id,
                reason_code="late" if late else "deadline_met",
            )
            if owns_transaction:
                self.conn.commit()
            return {"accepted": True, "deadline_met": not late, "late": late}
        except Exception:
            if owns_transaction and self.conn.in_transaction:
                self.conn.rollback()
            raise

    def _settle_terminal_quota(self, row: sqlite3.Row, projection: dict) -> sqlite3.Row:
        requests_started = projection["counters"]["requests_started"]
        state = row["quota_state"]
        if state == "reserved" and requests_started == 0:
            if not self.ledger._settle_in_transaction(row["reservation_id"], "refund"):
                raise CanaryRunError("quota_settlement_conflict")
            state, event, action = "refunded", "quota_refunded", "quota_refunded"
        elif state == "consumed" and projection["error_category"] in _FAULT_COMPENSATION:
            if self.ledger.refund_consumed_in_transaction(
                row["reservation_id"], projection["error_category"],
            ):
                state, event, action = "compensated", "quota_compensated", "quota_compensated"
            else:
                return row
        else:
            return row
        self.conn.execute(
            "UPDATE canary_runs SET quota_state=? WHERE workspace_id=? AND project_ref=? AND run_id=?",
            (state, row["workspace_id"], row["project_ref"], row["run_id"]),
        )
        row = self._run(row["workspace_id"], row["project_ref"], row["run_id"])
        self._append_event(
            row, event, actor_class="system", actor_id="quota",
            reason_code=projection["error_category"],
        )
        self._audit(
            row, action, subject_ref=row["reservation_id"], actor_class="system",
            actor_id="quota", reason_code=projection["error_category"],
        )
        return self._context(
            row["workspace_id"], row["project_ref"], row["run_id"], row["runner_id"],
        )

    def result(
        self, workspace_id: str, project_ref: str, run_id: str, runner_id: str,
        projection: object,
    ) -> dict[str, object]:
        owns_transaction = not self.conn.in_transaction
        if owns_transaction:
            self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._context(workspace_id, project_ref, run_id, runner_id)
            approval, grant = self._stored_operational_authority(row)
            verification_mismatch = not self._verification_digest_matches(row, approval, grant)
            if verification_mismatch:
                row = self._persist_authority_stop(row)
            value = self._validate_operational(row, projection)
            if verification_mismatch and value["stop_reason"] == "none":
                closed = self.get_status(workspace_id, project_ref, run_id)
                if owns_transaction:
                    self.conn.commit()
                return closed
            source = self._source_state(row, value)
            if source == "replay" and row["status"] == "terminal":
                result = self.get_status(workspace_id, project_ref, run_id)
                if owns_transaction:
                    self.conn.commit()
                return result
            if value["lifecycle_phase"] != "terminal" or row["status"] not in {
                "claimed", "running", "stop_requested", "finalizing",
            }:
                raise CanaryRunError("illegal_run_transition")
            timestamps = value["timestamps"]
            received_at = self._server_receipt_time(row)
            if (value["stop_reason"] != "none") != (
                value["execution_disposition"] == "stopped"
            ):
                raise CanaryRunError("illegal_run_transition")
            if row["stop_reason"] != "none" and (
                value["stop_reason"] != row["stop_reason"]
                or value["execution_disposition"] != "stopped"
            ):
                raise CanaryRunError("stop_conflict")
            prior_receipt = self.conn.execute(
                "SELECT receipt_json FROM canary_operational_receipts WHERE workspace_id=? "
                "AND project_ref=? AND run_id=?",
                (workspace_id, project_ref, run_id),
            ).fetchone()
            if prior_receipt is not None and prior_receipt["receipt_json"] is not None:
                try:
                    prior_value = validate_operational_run(
                        json.loads(prior_receipt["receipt_json"]),
                    )
                except (TypeError, ValueError, json.JSONDecodeError):
                    raise CanaryRunError("operational_binding_mismatch") from None
                prior_ack_evidence = prior_value["timestamps"]["stop_acknowledged_at_ms"]
                if (
                    prior_ack_evidence is not None
                    and timestamps["stop_acknowledged_at_ms"] != prior_ack_evidence
                ):
                    raise CanaryRunError("stop_conflict")
            if (
                row["stop_requested_at_ms"] is not None
                and row["stop_acknowledged_at_ms"] is None
                and timestamps["stop_acknowledged_at_ms"] is not None
            ):
                raise CanaryRunError("stop_conflict")
            row = self._consume_if_started(row, value)
            if row["status"] != "finalizing":
                self.conn.execute(
                    "UPDATE canary_runs SET status='finalizing',started_at_ms=COALESCE(started_at_ms,?),"
                    "updated_at=? WHERE workspace_id=? AND project_ref=? AND run_id=?",
                    (
                        received_at, received_at,
                        workspace_id, project_ref, run_id,
                    ),
                )
                row = self._context(workspace_id, project_ref, run_id, runner_id)
                self._append_event(
                    row, "finalizing", actor_class="runner", actor_id=runner_id,
                    source_event_sequence=value["event_sequence"],
                )
            row = self._settle_terminal_quota(row, value)
            self._store_receipt(row, value, received_at_ms=received_at)
            now = received_at
            received_stop = now if value["stop_reason"] != "none" else None
            self.conn.execute(
                "UPDATE canary_runs SET status='terminal',execution_disposition=?,error_category=?,"
                "stop_reason=?,source_event_sequence=?,source_projection_digest=?,"
                "started_at_ms=COALESCE(started_at_ms,?),stop_requested_at_ms=COALESCE(stop_requested_at_ms,?),"
                "stop_acknowledged_at_ms=COALESCE(stop_acknowledged_at_ms,?),terminal_at_ms=?,"
                "updated_at=?,purge_at=? WHERE workspace_id=? AND project_ref=? AND run_id=?",
                (
                    value["execution_disposition"], value["error_category"], value["stop_reason"],
                    value["event_sequence"], value["projection_digest"], now,
                    received_stop, None, now, now,
                    now + AUDIT_RETENTION_MS, workspace_id, project_ref, run_id,
                ),
            )
            self.conn.execute(
                "UPDATE canary_execution_grants SET status='terminal',purge_at=? "
                "WHERE workspace_id=? AND project_ref=? AND grant_id=?",
                (now + PROJECTION_RETENTION_MS, workspace_id, project_ref, row["grant_id"]),
            )
            self.conn.execute(
                "UPDATE canary_approval_projections SET purge_at=? "
                "WHERE workspace_id=? AND project_ref=? AND approval_id=?",
                (now + PROJECTION_RETENTION_MS, workspace_id, project_ref, row["approval_id"]),
            )
            row = self._run(workspace_id, project_ref, run_id)
            self._append_event(
                row, "terminal", actor_class="runner", actor_id=runner_id,
                source_event_sequence=value["event_sequence"], status="terminal",
            )
            self._audit(
                row, "finalized", subject_ref=run_id, actor_class="runner", actor_id=runner_id,
                reason_code=value["error_category"],
                payload={"execution_disposition": value["execution_disposition"]},
            )
            if owns_transaction:
                self.conn.commit()
            return self.get_status(workspace_id, project_ref, run_id)
        except Exception:
            if owns_transaction and self.conn.in_transaction:
                self.conn.rollback()
            raise

    def get_status(self, workspace_id: str, project_ref: str, run_id: str) -> dict[str, object]:
        row = self._run(workspace_id, project_ref, run_id)
        return {
            "schema_version": "heel.canary-run-status.v1",
            "run_id": row["run_id"], "approval_id": row["approval_id"],
            "grant_id": row["grant_id"], "status": row["status"],
            "execution_disposition": row["execution_disposition"],
            "error_category": row["error_category"], "stop_reason": row["stop_reason"],
            "source_event_sequence": row["source_event_sequence"],
            "quota_state": row["quota_state"],
            "kill_switch_generation": row["kill_switch_generation"],
            "stop_generation": row["stop_generation"],
            "stop_deadline_ms": row["stop_deadline_ms"],
            "stop_acknowledged_at_ms": row["stop_acknowledged_at_ms"],
            "stop_ack_late": bool(row["stop_ack_late"]),
        }

    def list_events(self, workspace_id: str, project_ref: str, run_id: str) -> list[dict]:
        self._run(workspace_id, project_ref, run_id)
        rows = self.conn.execute(
            "SELECT sequence,event_type,event_json,source_event_sequence,actor_class,actor_id,"
            "reason_code,created_at FROM canary_run_events WHERE workspace_id=? AND project_ref=? "
            "AND run_id=? ORDER BY sequence",
            (workspace_id, project_ref, run_id),
        ).fetchall()
        return [{
            "sequence": row["sequence"], "event_type": row["event_type"],
            "event": json.loads(row["event_json"]),
            "source_event_sequence": row["source_event_sequence"],
            "actor_class": row["actor_class"], "actor_id": row["actor_id"],
            "reason_code": row["reason_code"], "created_at_ms": row["created_at"],
        } for row in rows]

    def expire_and_reconcile(self) -> dict[str, int]:
        now = self._now_ms()
        counts = {
            "expired_approvals": 0, "expired_grants": 0, "refunded_grants": 0,
            "finalized_orphans": 0, "purged_projections": 0,
            "purged_receipts": 0, "purged_audit": 0,
        }
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            approvals = self.conn.execute(
                "SELECT * FROM canary_approval_projections WHERE status='awaiting_execution_approval' "
                "AND expires_at<=?",
                (now,),
            ).fetchall()
            for approval in approvals:
                run = self._run(approval["workspace_id"], approval["project_ref"], approval["run_id"])
                self.conn.execute(
                    "UPDATE canary_approval_projections SET status='expired' WHERE approval_id=?",
                    (approval["approval_id"],),
                )
                self.conn.execute(
                    "UPDATE canary_runs SET status='expired',updated_at=? WHERE run_id=?",
                    (now, approval["run_id"]),
                )
                run = self._run(approval["workspace_id"], approval["project_ref"], approval["run_id"])
                self._append_event(run, "expired", actor_class="system", actor_id="reaper", reason_code="approval_expired")
                self._audit(
                    run, "expired", subject_ref=approval["approval_id"],
                    actor_class="system", actor_id="reaper", reason_code="approval_expired",
                )
                counts["expired_approvals"] += 1
            grants = self.conn.execute(
                "SELECT g.*,r.status AS run_status,r.quota_state FROM canary_execution_grants g "
                "JOIN canary_runs r ON r.workspace_id=g.workspace_id AND r.project_ref=g.project_ref "
                "AND r.run_id=g.run_id WHERE (g.status='issued' AND g.expires_at<=?) OR "
                "(g.status='revoked' AND r.status='approved')",
                (now,),
            ).fetchall()
            for grant in grants:
                refunded = grant["quota_state"] == "refunded"
                if grant["quota_state"] == "reserved":
                    refund_created = self.ledger._settle_in_transaction(
                        grant["reservation_id"], "refund",
                    )
                    refunded = refund_created or self.conn.execute(
                        "SELECT 1 FROM usage_ledger WHERE reservation_id=? AND kind='refund'",
                        (grant["reservation_id"],),
                    ).fetchone() is not None
                    if not refunded:
                        raise CanaryRunError("quota_settlement_conflict")
                    if refund_created:
                        counts["refunded_grants"] += 1
                next_status = "expired" if grant["status"] == "issued" else "cancelled"
                self.conn.execute(
                    "UPDATE canary_execution_grants SET status=? WHERE grant_id=?",
                    ("expired" if grant["status"] == "issued" else "revoked", grant["grant_id"]),
                )
                self.conn.execute(
                    "UPDATE canary_runs SET status=?,quota_state=?,updated_at=? WHERE run_id=?",
                    (
                        next_status, "refunded" if refunded else grant["quota_state"],
                        now, grant["run_id"],
                    ),
                )
                self.conn.execute(
                    "UPDATE canary_approval_projections SET purge_at=? WHERE approval_id=?",
                    (max(now, grant["expires_at"]) + PROJECTION_RETENTION_MS, grant["approval_id"]),
                )
                run = self._run(grant["workspace_id"], grant["project_ref"], grant["run_id"])
                self._append_event(
                    run, "expired" if next_status == "expired" else "cancelled",
                    actor_class="system", actor_id="reaper",
                    reason_code="grant_expired" if next_status == "expired" else "runner_revoked",
                )
                self._audit(
                    run, "expired" if next_status == "expired" else "cancelled",
                    subject_ref=grant["grant_id"], actor_class="system", actor_id="reaper",
                    reason_code="grant_expired" if next_status == "expired" else "runner_revoked",
                )
                if refunded:
                    self._append_event(
                        run, "quota_refunded", actor_class="system", actor_id="quota",
                        reason_code="unclaimed",
                    )
                    self._audit(
                        run, "quota_refunded", subject_ref=grant["reservation_id"],
                        actor_class="system", actor_id="quota", reason_code="unclaimed",
                    )
                counts["expired_grants"] += int(next_status == "expired")
            orphans = self.conn.execute(
                "SELECT r.* FROM canary_runs r "
                "WHERE r.status IN ('stop_requested','finalizing') "
                "AND r.stop_reason!='none' AND r.stop_deadline_ms IS NOT NULL "
                "AND r.stop_acknowledged_at_ms IS NULL "
                "AND r.stop_deadline_ms<=?",
                (now,),
            ).fetchall()
            for orphan in orphans:
                row = orphan
                if row["status"] != "finalizing":
                    self.conn.execute(
                        "UPDATE canary_runs SET status='finalizing',updated_at=? "
                        "WHERE workspace_id=? AND project_ref=? AND run_id=?",
                        (now, row["workspace_id"], row["project_ref"], row["run_id"]),
                    )
                    row = self._run(row["workspace_id"], row["project_ref"], row["run_id"])
                    self._append_event(
                        row, "finalizing", actor_class="system", actor_id="reaper",
                        reason_code=row["stop_reason"],
                    )
                if row["quota_state"] == "reserved":
                    if self.ledger._settle_in_transaction(row["reservation_id"], "refund"):
                        counts["refunded_grants"] += 1
                    self.conn.execute(
                        "UPDATE canary_runs SET quota_state='refunded' WHERE workspace_id=? "
                        "AND project_ref=? AND run_id=?",
                        (row["workspace_id"], row["project_ref"], row["run_id"]),
                    )
                    row = self._run(row["workspace_id"], row["project_ref"], row["run_id"])
                    self._append_event(
                        row, "quota_refunded", actor_class="system", actor_id="quota",
                        reason_code=row["stop_reason"],
                    )
                    self._audit(
                        row, "quota_refunded", subject_ref=row["reservation_id"],
                        actor_class="system", actor_id="quota", reason_code=row["stop_reason"],
                    )
                self.conn.execute(
                    "UPDATE canary_runs SET status='terminal',execution_disposition='stopped',"
                    "terminal_at_ms=?,updated_at=?,purge_at=? WHERE workspace_id=? "
                    "AND project_ref=? AND run_id=?",
                    (
                        now, now, now + AUDIT_RETENTION_MS, row["workspace_id"],
                        row["project_ref"], row["run_id"],
                    ),
                )
                self.conn.execute(
                    "UPDATE canary_execution_grants SET status='terminal',purge_at=? "
                    "WHERE workspace_id=? AND project_ref=? AND grant_id=?",
                    (
                        now + PROJECTION_RETENTION_MS, row["workspace_id"],
                        row["project_ref"], row["grant_id"],
                    ),
                )
                self.conn.execute(
                    "UPDATE canary_approval_projections SET purge_at=? "
                    "WHERE workspace_id=? AND project_ref=? AND approval_id=?",
                    (
                        now + PROJECTION_RETENTION_MS, row["workspace_id"],
                        row["project_ref"], row["approval_id"],
                    ),
                )
                row = self._run(row["workspace_id"], row["project_ref"], row["run_id"])
                self._append_event(
                    row, "terminal", actor_class="system", actor_id="reaper",
                    reason_code=row["stop_reason"], status="terminal",
                )
                if row["stop_acknowledged_at_ms"] is None:
                    self._audit(
                        row, "stop_ack_late", subject_ref=row["run_id"],
                        actor_class="system", actor_id="reaper", reason_code="missing_ack",
                    )
                self._audit(
                    row, "finalized", subject_ref=row["run_id"], actor_class="system",
                    actor_id="reaper", reason_code=row["stop_reason"],
                    payload={"execution_disposition": "stopped"},
                )
                counts["finalized_orphans"] += 1
            cursor = self.conn.execute(
                "UPDATE canary_approval_projections SET projection_json=NULL "
                "WHERE projection_json IS NOT NULL AND purge_at<=?",
                (now,),
            )
            counts["purged_projections"] += cursor.rowcount
            cursor = self.conn.execute(
                "UPDATE canary_execution_grants SET grant_json=NULL "
                "WHERE grant_json IS NOT NULL AND purge_at<=?",
                (now,),
            )
            counts["purged_projections"] += cursor.rowcount
            cursor = self.conn.execute(
                "UPDATE canary_operational_receipts SET receipt_json=NULL "
                "WHERE receipt_json IS NOT NULL AND purge_at<=?",
                (now,),
            )
            counts["purged_receipts"] = cursor.rowcount
            cursor = self.conn.execute("DELETE FROM canary_audit_records WHERE purge_at<=?", (now,))
            counts["purged_audit"] = cursor.rowcount
            self.conn.commit()
            return counts
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise
