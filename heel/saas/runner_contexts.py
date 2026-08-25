"""Cloud-signed, browser-authorized runner context bindings.

The tables in migration 16 are intentionally separate from grants and nonce chains.  A
binding can create an awaiting-approval projection, but cannot reserve quota, issue a
grant, claim a run, or authorize target traffic.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from typing import Callable

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from heel.canary_contracts import (
    canonical_bytes,
    canonical_digest,
    validate_runner_context_binding,
    validate_runner_context_create,
    validate_runner_context_revoke,
    validate_runner_context_claim,
)
from heel.crypto import load_public_key_base64


CONTEXT_DOMAIN = b"heel.runner-context-binding.v1\0"
CONTEXT_TTL_MS = 24 * 60 * 60 * 1000
CONTEXT_MIN_TTL_MS = 60 * 1000
CONTEXT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000


class RunnerContextError(ValueError):
    """Stable error detail for HTTP's closed runner-context error envelope."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class RunnerContextBindingService:
    """Persistence coordinator for the strictly pairing-only context capability."""

    def __init__(self, conn: sqlite3.Connection, *, signing, clock: Callable[[], float] = time.time):
        if not isinstance(conn, sqlite3.Connection):
            raise TypeError("runner context bindings require SQLite")
        if signing is None or not callable(getattr(signing, "sign", None)):
            raise TypeError("cloud signing authority is required")
        self.conn = conn
        self.conn.row_factory = sqlite3.Row
        self.signing = signing
        self.clock = clock

    def _now_ms(self) -> int:
        return max(0, int(float(self.clock()) * 1000))

    @staticmethod
    def _require_actor(actor: object, role: object) -> tuple[str, str]:
        if type(actor) is not str or not actor or actor != actor.strip() or len(actor.encode()) > 128:
            raise RunnerContextError("invalid_runner_context_binding")
        if role not in {"owner", "admin"}:
            raise RunnerContextError("invalid_runner_context_binding")
        return actor, role

    def _assert_membership(self, workspace_id: str, actor: str, role: str) -> str:
        row = self.conn.execute(
            "SELECT role FROM memberships WHERE workspace_id=? AND user_id=?",
            (workspace_id, actor),
        ).fetchone()
        if row is None or row["role"] not in {"owner", "admin"} or row["role"] != role:
            raise RunnerContextError("same_origin_required")
        return row["role"]

    def _event(self, row: sqlite3.Row, action: str, actor_class: str, actor_id: str, *, reason: str | None = None) -> None:
        now = self._now_ms()
        self.conn.execute(
            "INSERT INTO canary_runner_context_events("
            "rce_id,workspace_id,project_ref,environment_id,runner_id,runner_key_id,rcb_id,"
            "action,actor_class,actor_id,reason_code,binding_digest,created_at_ms,purge_at_ms) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "rce_" + secrets.token_hex(16), row["workspace_id"], row["project_ref"],
                row["environment_id"], row["runner_id"], row["runner_key_id"], row["rcb_id"],
                action, actor_class, actor_id, reason, row["binding_digest"], now,
                now + CONTEXT_RETENTION_MS,
            ),
        )

    def _expire_in_transaction(self, now: int) -> tuple[int, int]:
        rows = self.conn.execute(
            "SELECT * FROM canary_runner_context_bindings WHERE status='active' AND expires_at_ms<=?",
            (now,),
        ).fetchall()
        cancelled = 0
        for row in rows:
            cancelled += self._cancel_linked_pending_in_transaction(
                row, actor_class="system", actor_id="control-plane",
                reason_code="runner_context_expired", now_ms=now,
            )
            self.conn.execute("UPDATE canary_runner_context_bindings SET status='expired' WHERE rcb_id=?", (row["rcb_id"],))
            self._event(row, "expired", "system", "control-plane", reason="ttl_elapsed")
        return len(rows), cancelled

    def _cancel_linked_pending_in_transaction(
        self, row: sqlite3.Row, *, actor_class: str, actor_id: str, reason_code: str, now_ms: int,
    ) -> int:
        """Use the Task-7 append-only event/audit writer on this exact transaction."""
        if not self.conn.in_transaction:
            raise RuntimeError("runner context cancellation requires caller transaction")
        # This import is deliberately lazy: the two services share a transaction but do not
        # own each other's initialization path or recursively apply schema.
        from .canary_runs import CanaryRunService

        runs = CanaryRunService(
            self.conn, signing=self.signing, clock=self.clock, initialize_schema=False,
        )
        return runs.cancel_context_pending_in_transaction(
            row, actor_class=actor_class, actor_id=actor_id, reason_code=reason_code,
            now_ms=now_ms,
        )

    def expire_and_purge_in_transaction(self, now_ms: int, *, limit: int = 128) -> dict:
        """Expire first, then remove a bounded batch of fully retained terminal context state."""
        if not self.conn.in_transaction:
            raise RuntimeError("runner context expiry requires caller transaction")
        if type(now_ms) is not int or isinstance(now_ms, bool) or now_ms < 0:
            raise ValueError("invalid runner context expiry time")
        if type(limit) is not int or isinstance(limit, bool) or not 1 <= limit <= 128:
            raise ValueError("invalid runner context purge limit")
        expired, cancelled = self._expire_in_transaction(now_ms)
        rows = self.conn.execute(
            "SELECT * FROM canary_runner_context_bindings "
            "WHERE status IN ('expired','revoked') AND purge_at_ms<=? "
            "ORDER BY purge_at_ms,rcb_id LIMIT ?",
            (now_ms, limit + 1),
        ).fetchall()
        selected = rows[:limit]
        counts: dict[str, int | dict | None] = {
            "expired_bindings": expired,
            "cancelled_projections": cancelled,
            "purged_links": 0,
            "purged_events": 0,
            "purged_bindings": 0,
            "next_cursor": (
                {"purge_at_ms": selected[-1]["purge_at_ms"], "rcb_id": selected[-1]["rcb_id"]}
                if len(rows) > limit and selected else None
            ),
        }
        for row in selected:
            live_event = self.conn.execute(
                "SELECT 1 FROM canary_runner_context_events WHERE workspace_id=? AND project_ref=? "
                "AND rcb_id=? AND binding_digest=? AND purge_at_ms>? LIMIT 1",
                (row["workspace_id"], row["project_ref"], row["rcb_id"], row["binding_digest"], now_ms),
            ).fetchone()
            if live_event is not None:
                raise RuntimeError("runner context purge has live event retention")
            pregrant = self.conn.execute(
                "SELECT 1 FROM canary_runner_context_projection_links l "
                "JOIN canary_approval_projections a ON a.workspace_id=l.workspace_id AND a.project_ref=l.project_ref "
                "AND a.approval_id=l.approval_id AND a.run_id=l.run_id "
                "JOIN canary_runs r ON r.workspace_id=l.workspace_id AND r.project_ref=l.project_ref AND r.run_id=l.run_id "
                "WHERE l.workspace_id=? AND l.project_ref=? AND l.rcb_id=? AND l.binding_digest=? "
                "AND (a.status='awaiting_execution_approval' OR r.status IN ('prepared','awaiting_execution_approval')) LIMIT 1",
                (row["workspace_id"], row["project_ref"], row["rcb_id"], row["binding_digest"]),
            ).fetchone()
            if pregrant is not None:
                raise RuntimeError("runner context purge has linked pregrant authority")
            links = self.conn.execute(
                "DELETE FROM canary_runner_context_projection_links WHERE workspace_id=? AND project_ref=? "
                "AND rcb_id=? AND binding_digest=?",
                (row["workspace_id"], row["project_ref"], row["rcb_id"], row["binding_digest"]),
            )
            events = self.conn.execute(
                "DELETE FROM canary_runner_context_events WHERE workspace_id=? AND project_ref=? "
                "AND rcb_id=? AND binding_digest=?",
                (row["workspace_id"], row["project_ref"], row["rcb_id"], row["binding_digest"]),
            )
            bindings = self.conn.execute(
                "DELETE FROM canary_runner_context_bindings WHERE rcb_id=? AND status IN ('expired','revoked')",
                (row["rcb_id"],),
            )
            if bindings.rowcount != 1:
                raise RuntimeError("runner context purge lost serialization")
            counts["purged_links"] += links.rowcount
            counts["purged_events"] += events.rowcount
            counts["purged_bindings"] += bindings.rowcount
        return counts

    def create(self, workspace_id: str, project_id: str, request: object, *, actor: object, role: object) -> dict:
        actor, role = self._require_actor(actor, role)
        try:
            request = validate_runner_context_create(request)
        except (TypeError, ValueError):
            raise RunnerContextError("invalid_runner_context_binding") from None
        now = self._now_ms()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            authorized_role = self._assert_membership(workspace_id, actor, role)
            self._expire_in_transaction(now)
            row = self.conn.execute(
                "SELECT e.origin,e.environment_class,e.status AS environment_status,e.revoked_at,"
                "e.proof_expires_at,e.verification_record_digest,k.public_key,k.status AS key_status,"
                "k.revoked_at AS key_revoked_at,r.status AS runner_status "
                "FROM canary_environments e JOIN canary_runners r "
                "ON r.workspace_id=e.workspace_id AND r.runner_id=? "
                "JOIN canary_runner_keys k ON k.workspace_id=r.workspace_id AND k.runner_id=r.runner_id AND k.key_id=? "
                "WHERE e.workspace_id=? AND e.project_ref=? AND e.environment_id=?",
                (request["runner_id"], request["runner_key_id"], workspace_id, project_id, request["environment_id"]),
            ).fetchone()
            if row is None or (
                row["environment_status"] != "verified" or row["environment_class"] not in {"staging", "sandbox"}
                or row["revoked_at"] is not None or row["proof_expires_at"] is None
                or int(row["proof_expires_at"] * 1000) <= now
                or row["verification_record_digest"] != request["verification_record_digest"]
                or row["runner_status"] != "active" or row["key_status"] != "active" or row["key_revoked_at"] is not None
            ):
                raise RunnerContextError("conflict")
            if self.conn.execute(
                "SELECT 1 FROM canary_runner_context_bindings WHERE workspace_id=? "
                "AND runner_id=? AND status='active'",
                (workspace_id, request["runner_id"]),
            ).fetchone() is not None:
                raise RunnerContextError("conflict")
            public_key = load_public_key_base64(row["public_key"]).public_bytes(Encoding.Raw, PublicFormat.Raw)
            expires = min(now + CONTEXT_TTL_MS, int(row["proof_expires_at"] * 1000))
            if expires - now < CONTEXT_MIN_TTL_MS:
                raise RunnerContextError("expired")
            unsigned = {
                "schema_version": "heel.runner-context-binding.v1", "binding_id": "rcb_" + secrets.token_hex(16), "workspace_id": workspace_id,
                "project_id": project_id,
                "environment": {"environment_id": request["environment_id"], "origin": row["origin"],
                                "environment_class": row["environment_class"],
                                "verification_record_digest": row["verification_record_digest"]},
                "runner_binding": {"runner_id": request["runner_id"], "runner_key_id": request["runner_key_id"],
                                   "public_key_digest": hashlib.sha256(public_key).hexdigest()},
                "authorization": {"user_id": actor, "role": authorized_role},
                "issued_at_ms": now, "expires_at_ms": expires,
            }
            artifact = dict(unsigned)
            artifact["binding_digest"] = canonical_digest(unsigned)
            artifact.update(self.signing.sign(CONTEXT_DOMAIN + canonical_bytes(unsigned)))
            artifact = validate_runner_context_binding(artifact)
            serialized = canonical_bytes(artifact).decode()
            try:
                self.conn.execute(
                    "INSERT INTO canary_runner_context_bindings("
                    "rcb_id,workspace_id,project_ref,environment_id,runner_id,runner_key_id,environment_origin,environment_class,"
                    "binding_digest,public_key_digest,verification_record_digest,binding_json,status,created_by,created_role,"
                    "issued_at_ms,expires_at_ms,first_claimed_at_ms,revoked_by,revoked_at_ms,revoke_reason,purge_at_ms) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,?)",
                    (
                        artifact["binding_id"], workspace_id, project_id, request["environment_id"], request["runner_id"],
                        request["runner_key_id"], row["origin"], row["environment_class"], artifact["binding_digest"],
                        artifact["runner_binding"]["public_key_digest"], row["verification_record_digest"], serialized,
                        "active", actor, authorized_role, now, expires, expires + CONTEXT_RETENTION_MS,
                    ),
                )
            except sqlite3.IntegrityError:
                raise RunnerContextError("conflict") from None
            stored = self.conn.execute("SELECT * FROM canary_runner_context_bindings WHERE rcb_id=?", (artifact["binding_id"],)).fetchone()
            self._event(stored, "created", "human", actor)
            self.conn.commit()
            return artifact
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise

    def revoke(self, workspace_id: str, project_id: str, binding_id: str, *, actor: object, role: object, request: object | None = None) -> dict:
        actor, role = self._require_actor(actor, role)
        if request is not None:
            try:
                validate_runner_context_revoke(request)
            except (TypeError, ValueError):
                raise RunnerContextError("invalid_runner_context_binding") from None
        now = self._now_ms()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._assert_membership(workspace_id, actor, role)
            self._expire_in_transaction(now)
            row = self.conn.execute(
                "SELECT * FROM canary_runner_context_bindings WHERE workspace_id=? AND project_ref=? AND rcb_id=?",
                (workspace_id, project_id, binding_id),
            ).fetchone()
            if row is None:
                raise RunnerContextError("runner_context_binding_not_found")
            if row["status"] != "active":
                raise RunnerContextError("conflict")
            self._cancel_linked_pending_in_transaction(
                row, actor_class="human", actor_id=actor,
                reason_code="runner_context_revoked", now_ms=now,
            )
            self.conn.execute(
                "UPDATE canary_runner_context_bindings SET status='revoked',revoked_by=?,revoked_at_ms=?,revoke_reason='operator_requested' WHERE rcb_id=?",
                (actor, now, binding_id),
            )
            changed = self.conn.execute("SELECT * FROM canary_runner_context_bindings WHERE rcb_id=?", (binding_id,)).fetchone()
            self._event(changed, "revoked", "human", actor, reason="operator_requested")
            self.conn.commit()
            return {"schema_version": "heel.runner-context-binding-revoked.v1", "binding_id": binding_id, "status": "revoked", "revoked_at_ms": now}
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise

    def list_for_human(self, workspace_id: str, project_id: str, *, actor: object) -> dict:
        """Session-only dashboard view; reading has no recent-auth or origin requirement."""
        if type(actor) is not str or not actor:
            raise RunnerContextError("runner_context_binding_not_found")
        membership = self.conn.execute(
            "SELECT 1 FROM memberships WHERE workspace_id=? AND user_id=?", (workspace_id, actor),
        ).fetchone()
        if membership is None:
            raise RunnerContextError("runner_context_binding_not_found")
        if self.conn.execute(
            "SELECT 1 FROM projects WHERE workspace_id=? AND project_ref=?", (workspace_id, project_id),
        ).fetchone() is None:
            raise RunnerContextError("runner_context_binding_not_found")
        now = self._now_ms()
        runner_rows = self.conn.execute(
            "SELECT r.runner_id,r.display_name,k.key_id,k.public_key,i.identity_json "
            "FROM canary_runners r JOIN canary_runner_keys k ON k.workspace_id=r.workspace_id AND k.runner_id=r.runner_id "
            "JOIN canary_runner_identity_records i ON i.workspace_id=r.workspace_id AND i.runner_id=r.runner_id "
            "WHERE r.workspace_id=? AND r.status='active' AND k.status='active' AND k.revoked_at IS NULL "
            "ORDER BY r.runner_id,k.key_id LIMIT 17", (workspace_id,),
        ).fetchall()
        binding_rows = self.conn.execute(
            "SELECT * FROM canary_runner_context_bindings WHERE workspace_id=? AND project_ref=? "
            "ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END,issued_at_ms DESC,rcb_id DESC LIMIT 65",
            (workspace_id, project_id),
        ).fetchall()
        if len(runner_rows) > 16:
            raise RunnerContextError("canary_authority_unavailable")
        runners: list[dict] = []
        for row in runner_rows:
            try:
                identity = json.loads(row["identity_json"])
                public = load_public_key_base64(row["public_key"]).public_bytes(Encoding.Raw, PublicFormat.Raw)
            except (TypeError, ValueError):
                raise RunnerContextError("canary_authority_unavailable") from None
            if identity.get("state") != "active" or identity.get("public_key", {}).get("key_id") != row["key_id"]:
                raise RunnerContextError("canary_authority_unavailable")
            runners.append({"runner_id": row["runner_id"], "runner_key_id": row["key_id"],
                "display_name": row["display_name"], "fingerprint": hashlib.sha256(public).hexdigest(),
                "runner_version": identity.get("runner_version", ""), "adapter_versions": identity.get("adapter_versions", []), "status": "active"})
        result = {"schema_version": "heel.runner-context-binding-dashboard.v1", "server_time_ms": now,
                "runners": runners, "bindings": [{"binding_id": row["rcb_id"], "binding_digest": row["binding_digest"],
                    "environment_id": row["environment_id"], "origin": row["environment_origin"],
                    "environment_class": row["environment_class"], "verification_record_digest": row["verification_record_digest"],
                    "runner_id": row["runner_id"], "runner_key_id": row["runner_key_id"], "status": ("expired" if row["status"] == "active" and row["expires_at_ms"] <= now else row["status"]),
                    "issued_at_ms": row["issued_at_ms"], "expires_at_ms": row["expires_at_ms"],
                    "first_claimed_at_ms": row["first_claimed_at_ms"]} for row in binding_rows[:64]]}
        if len(canonical_bytes(result)) > 192 * 1024:
            raise RunnerContextError("canary_authority_unavailable")
        return result

    def list_for_runner_in_transaction(self, workspace_id: str, runner_id: str, runner_key_id: str) -> dict:
        if not self.conn.in_transaction:
            raise RuntimeError("runner context list requires caller transaction")
        now = self._now_ms()
        self._expire_in_transaction(now)
        rows = self.conn.execute(
            "SELECT b.*,k.public_key,i.identity_json FROM canary_runner_context_bindings b "
            "JOIN canary_environments e ON e.workspace_id=b.workspace_id AND e.project_ref=b.project_ref AND e.environment_id=b.environment_id "
            "JOIN canary_runners r ON r.workspace_id=b.workspace_id AND r.runner_id=b.runner_id "
            "JOIN canary_runner_keys k ON k.workspace_id=b.workspace_id AND k.runner_id=b.runner_id AND k.key_id=b.runner_key_id "
            "JOIN canary_runner_identity_records i ON i.workspace_id=b.workspace_id AND i.runner_id=b.runner_id "
            "WHERE b.workspace_id=? AND b.runner_id=? AND b.runner_key_id=? AND b.status='active' AND b.expires_at_ms>? "
            "AND e.status='verified' AND e.revoked_at IS NULL AND e.proof_expires_at IS NOT NULL AND e.proof_expires_at*1000>? "
            "AND e.origin=b.environment_origin AND e.environment_class=b.environment_class AND e.verification_record_digest=b.verification_record_digest "
            "AND r.status='active' AND k.status='active' AND k.revoked_at IS NULL ORDER BY b.issued_at_ms,b.rcb_id LIMIT 17",
            (workspace_id, runner_id, runner_key_id, now, now),
        ).fetchall()
        if len(rows) > 1:
            raise RunnerContextError("conflict")
        contexts = []
        for row in rows[:16]:
            # Listing is discovery metadata only. The signed artifact is released only by
            # the PoP-protected claim response, so a list cannot become an install channel.
            try:
                artifact = validate_runner_context_binding(json.loads(row["binding_json"]))
                self._assert_artifact_matches_row(artifact, row)
                public = load_public_key_base64(row["public_key"]).public_bytes(Encoding.Raw, PublicFormat.Raw)
                identity = json.loads(row["identity_json"])
            except (TypeError, ValueError):
                raise RunnerContextError("runner_context_binding_not_found") from None
            if (hashlib.sha256(public).hexdigest() != row["public_key_digest"] or identity.get("state") != "active"
                    or identity.get("runner_id") != runner_id or identity.get("workspace_id") != workspace_id
                    or identity.get("public_key", {}).get("key_id") != runner_key_id
                    or artifact["binding_id"] != row["rcb_id"] or artifact["binding_digest"] != row["binding_digest"]):
                raise RunnerContextError("runner_context_binding_not_found")
            contexts.append({
                "binding_id": row["rcb_id"], "binding_digest": row["binding_digest"],
                "project_id": row["project_ref"], "environment_id": row["environment_id"],
                "origin": row["environment_origin"], "environment_class": row["environment_class"],
                "verification_record_digest": row["verification_record_digest"], "expires_at_ms": row["expires_at_ms"],
                "claimed": row["first_claimed_at_ms"] is not None,
            })
        return {"schema_version": "heel.runner-context-list-result.v1", "server_time_ms": now, "contexts": contexts, "has_more": len(rows) > 16}

    def claim_in_transaction(self, workspace_id: str, runner_id: str, runner_key_id: str, binding_id: str, request: object) -> dict:
        """Mark the first accepted runner claim exactly once and return the signed artifact."""
        if not self.conn.in_transaction:
            raise RuntimeError("runner context claim requires caller transaction")
        try:
            request = validate_runner_context_claim(request)
        except (TypeError, ValueError):
            raise RunnerContextError("invalid_runner_context_binding") from None
        if request["binding_id"] != binding_id:
            raise RunnerContextError("invalid_runner_context_binding")
        now = self._now_ms()
        row = self.active_binding_for_projection_in_transaction(
            workspace_id, runner_id, runner_key_id, binding_id, request["binding_digest"],
        )
        try:
            artifact = validate_runner_context_binding(json.loads(row["binding_json"]))
            self._assert_artifact_matches_row(artifact, row)
        except (TypeError, ValueError):
            raise RunnerContextError("runner_context_binding_not_found") from None
        if row["first_claimed_at_ms"] is None:
            self.conn.execute(
                "UPDATE canary_runner_context_bindings SET first_claimed_at_ms=? WHERE rcb_id=? AND first_claimed_at_ms IS NULL",
                (now, binding_id),
            )
            self._event(row, "claimed", "runner", runner_id)
        return {"schema_version": "heel.runner-context-claim-result.v1", "context_binding": artifact, "claimed_at_ms": now}

    @staticmethod
    def _assert_artifact_matches_row(artifact: dict, row: sqlite3.Row) -> None:
        """Reject any denormalized binding row that cannot describe its signed artifact."""
        environment = artifact["environment"]
        runner = artifact["runner_binding"]
        if (
            artifact["binding_id"] != row["rcb_id"]
            or artifact["binding_digest"] != row["binding_digest"]
            or artifact["workspace_id"] != row["workspace_id"]
            or artifact["project_id"] != row["project_ref"]
            or environment["environment_id"] != row["environment_id"]
            or environment["origin"] != row["environment_origin"]
            or environment["environment_class"] != row["environment_class"]
            or environment["verification_record_digest"] != row["verification_record_digest"]
            or runner["runner_id"] != row["runner_id"]
            or runner["runner_key_id"] != row["runner_key_id"]
            or runner["public_key_digest"] != row["public_key_digest"]
            or artifact["issued_at_ms"] != row["issued_at_ms"]
            or artifact["expires_at_ms"] != row["expires_at_ms"]
        ):
            raise ValueError("runner context binding denormalization mismatch")

    def active_binding_for_projection_in_transaction(
        self, workspace_id: str, runner_id: str, runner_key_id: str, binding_id: str, binding_digest: str,
    ) -> sqlite3.Row:
        """Return the current row only after every mutable authority has been rechecked."""
        if not self.conn.in_transaction:
            raise RuntimeError("runner context validation requires caller transaction")
        now = self._now_ms()
        self._expire_in_transaction(now)
        row = self.conn.execute(
            "SELECT b.*,k.public_key,i.identity_json FROM canary_runner_context_bindings b "
            "JOIN canary_environments e ON e.workspace_id=b.workspace_id AND e.project_ref=b.project_ref AND e.environment_id=b.environment_id "
            "JOIN canary_runners r ON r.workspace_id=b.workspace_id AND r.runner_id=b.runner_id "
            "JOIN canary_runner_keys k ON k.workspace_id=b.workspace_id AND k.runner_id=b.runner_id AND k.key_id=b.runner_key_id "
            "JOIN canary_runner_identity_records i ON i.workspace_id=b.workspace_id AND i.runner_id=b.runner_id "
            "WHERE b.workspace_id=? AND b.runner_id=? AND b.runner_key_id=? AND b.rcb_id=? AND b.binding_digest=? "
            "AND b.status='active' AND b.expires_at_ms>? AND e.status='verified' AND e.revoked_at IS NULL "
            "AND e.proof_expires_at IS NOT NULL AND e.proof_expires_at*1000>? "
            "AND e.origin=b.environment_origin AND e.environment_class=b.environment_class "
            "AND e.verification_record_digest=b.verification_record_digest "
            "AND r.status='active' AND k.status='active' AND k.revoked_at IS NULL",
            (workspace_id, runner_id, runner_key_id, binding_id, binding_digest, now, now),
        ).fetchone()
        if row is None:
            raise RunnerContextError("runner_context_binding_not_found")
        try:
            artifact = validate_runner_context_binding(json.loads(row["binding_json"]))
            self._assert_artifact_matches_row(artifact, row)
            public = load_public_key_base64(row["public_key"]).public_bytes(Encoding.Raw, PublicFormat.Raw)
            identity = json.loads(row["identity_json"])
        except (TypeError, ValueError):
            raise RunnerContextError("runner_context_binding_not_found") from None
        if (
            hashlib.sha256(public).hexdigest() != row["public_key_digest"]
            or identity.get("state") != "active"
            or identity.get("runner_id") != runner_id
            or identity.get("workspace_id") != workspace_id
            or identity.get("public_key", {}).get("key_id") != runner_key_id
        ):
            raise RunnerContextError("runner_context_binding_not_found")
        return row
