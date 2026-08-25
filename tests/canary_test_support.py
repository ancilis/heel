from __future__ import annotations

import hashlib
import json
import sqlite3

from heel.canary_contracts import (
    APPROVAL_PROJECTION_SCHEMA,
    OPERATIONAL_RUN_SCHEMA,
    canonical_bytes,
    canonical_digest,
)
from heel.crypto import SigningAuthority
from heel.saas.catalog import CATALOG_VERSION
from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator


NOW = 1_800_000_000.0
NOW_MS = int(NOW * 1000)
WORKSPACE = "ws_canary"
PROJECT = "prj_canary"
ENVIRONMENT = "env_canary"
RUNNER = "runr_canary"
VERIFICATION_DIGEST = "a" * 64


class Clock:
    def __init__(self, value: float = NOW):
        self.value = value

    def __call__(self) -> float:
        return self.value


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
    conn.execute("INSERT INTO orgs VALUES(?,?,?)", ("org_canary", "Canary", NOW))
    conn.execute(
        "INSERT INTO workspaces VALUES(?,?,?,?,?,?)",
        (WORKSPACE, "org_canary", "Canary", "free", CATALOG_VERSION, NOW),
    )
    conn.execute(
        "INSERT INTO projects VALUES(?,?,?,?,?)",
        (WORKSPACE, PROJECT, "Canary", "user_owner", NOW),
    )
    conn.execute("INSERT INTO users VALUES(?,?,?)", ("user_owner", "owner@canary.test", NOW))
    conn.execute(
        "INSERT INTO memberships VALUES(?,?,?,?)",
        (WORKSPACE, "user_owner", "owner", NOW),
    )
    conn.commit()
    return conn


def seed_authority(
    conn: sqlite3.Connection,
    *,
    workspace_id: str = WORKSPACE,
    project_ref: str = PROJECT,
    environment_id: str = ENVIRONMENT,
    runner_id: str = RUNNER,
    origin: str = "https://canary.acme.dev",
    proof_expires_at: float = NOW + 3600,
) -> SigningAuthority:
    signer = SigningAuthority.generate()
    conn.execute(
        "INSERT INTO canary_environments("
        "environment_id,workspace_id,project_ref,origin,environment_class,status,created_at,"
        "attestation_text,attestation_version,attestation_acknowledgement,attested_by,attested_at,"
        "proof_method,proof_version,normalization_version,challenge_generation,last_check_at,"
        "verified_at,proof_expires_at,verification_record_digest) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            environment_id, workspace_id, project_ref, origin, "staging", "verified", NOW,
            "ownership verified; environment classification supplied by you", "v1", "accepted",
            "user_owner", NOW, "https-file", "https-file.v1", "exact-origin.v1", 1, NOW,
            NOW, proof_expires_at, VERIFICATION_DIGEST,
        ),
    )
    conn.execute(
        "INSERT INTO canary_runners VALUES(?,?,?,?,?)",
        (runner_id, workspace_id, "Canary runner", "active", NOW),
    )
    conn.execute(
        "INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)",
        (signer.key_id, workspace_id, runner_id, signer.canonical_public_key, "active", NOW),
    )
    identity = {
        "schema_version": "heel.runner-identity.v1",
        "runner_id": runner_id,
        "workspace_id": workspace_id,
        "public_key": {
            "algorithm": "Ed25519", "key_id": signer.key_id,
            "public_key_b64": signer.canonical_public_key,
        },
        "fingerprint": hashlib.sha256(signer.public_key_bytes).hexdigest(),
        "runner_version": "1.0.0",
        "adapter_versions": ["1.0.0"],
        "capabilities": [
            "runner_claim", "runner_heartbeat", "runner_progress", "runner_result",
        ],
        "pairing": {
            "paired_by": "user_owner", "paired_at_ms": NOW_MS,
            "fingerprint_confirmation": "confirmed", "phrase_confirmation": "confirmed",
        },
        "last_heartbeat_at_ms": NOW_MS,
        "state": "active",
        "rotation": {
            "previous_key_ids": [], "rotated_at_ms": None,
            "verification_overlap_ends_at_ms": None,
        },
        "revocation": {"revoked_at_ms": None, "revoked_by": None, "reason_code": None},
    }
    identity["identity_digest"] = canonical_digest(identity)
    conn.execute(
        "INSERT INTO canary_runner_identity_records VALUES(?,?,?,?,?)",
        (workspace_id, runner_id, canonical_bytes(identity).decode(), identity["identity_digest"], NOW),
    )
    conn.commit()
    return signer


def approval_projection(
    signer: SigningAuthority,
    *,
    workspace_id: str = WORKSPACE,
    project_ref: str = PROJECT,
    environment_id: str = ENVIRONMENT,
    runner_id: str = RUNNER,
    verification_digest: str = VERIFICATION_DIGEST,
) -> dict:
    value = {
        "schema_version": APPROVAL_PROJECTION_SCHEMA,
        "projection_id": "ap_canary",
        "workspace_id": workspace_id,
        "project_id": project_ref,
        "environment": {
            "environment_id": environment_id,
            "verification_record_digest": verification_digest,
            "origin": "https://canary.acme.dev",
            "environment_class": "staging",
        },
        "runner": {
            "runner_id": runner_id,
            "runner_key_id": signer.key_id,
            "runner_version": "1.0.0",
            "adapter_versions": ["1.0.0"],
        },
        "compiler": {"compiler_version": "1", "engine_version": "1"},
        "scenarios": [{
            "ordinal": 0,
            "scenario_id": "anonymous_authenticated_read",
            "adapter_version": "1.0.0",
        }],
        "actions": [{
            "ordinal": 0,
            "scenario_id": "anonymous_authenticated_read",
            "adapter_version": "1.0.0",
            "method": "GET",
            "route_template": "/api/canary",
            "semantic_auth_role": "anonymous",
            "assertion_class": "anonymous_authenticated",
            "allowed_status_codes": [200, 401, 403],
            "allowed_body_shapes": ["absent", "json_object"],
            "side_effect_class": "read_only",
        }],
        "budgets": {
            "maximum_requests": 2,
            "maximum_concurrency": 1,
            "action_timeout_ms": 5000,
            "wall_timeout_ms": 60000,
            "maximum_response_bytes": 65536,
        },
        "egress": {
            "hostname": "canary.acme.dev", "port": 443, "redirect_policy": "deny",
        },
        "retry_policy": {"maximum_retries": 0, "retryable_failure_codes": []},
        "compiled_at_ms": NOW_MS,
        "manifest_digest": canonical_digest({"local": "manifest"}),
    }
    value["projection_digest"] = canonical_digest(value)
    value.update(signer.sign(canonical_bytes({
        key: item for key, item in value.items() if key != "projection_digest"
    })))
    return value


def operational_projection(
    signer: SigningAuthority,
    grant: dict,
    *,
    sequence: int,
    phase: str,
    requests_started: int = 0,
    requests_completed: int = 0,
    error_category: str = "none",
    stop_reason: str = "none",
    disposition: str | None = None,
    updated_at_ms: int = NOW_MS + 1000,
    stop_requested_at_ms: int | None = None,
    stop_acknowledged_at_ms: int | None = None,
) -> dict:
    claimed_at = NOW_MS + 100
    started_at = NOW_MS + 200 if phase in {
        "running", "stop_requested", "finalizing", "terminal",
    } else None
    if phase == "stop_requested" and stop_requested_at_ms is None:
        stop_requested_at_ms = NOW_MS + 300
    if phase not in {"stop_requested", "finalizing", "terminal"}:
        stop_requested_at_ms = None
        stop_acknowledged_at_ms = None
    terminal_at = updated_at_ms if phase == "terminal" else None
    value = {
        "schema_version": OPERATIONAL_RUN_SCHEMA,
        "run_id": grant["run_id"],
        "grant_id": grant["grant_id"],
        "workspace_id": grant["workspace_id"],
        "project_id": grant["project_id"],
        "manifest_digest": grant["approval"]["manifest_digest"],
        "approval_projection_digest": grant["approval"]["projection_digest"],
        "grant_digest": grant["grant_digest"],
        "event_sequence": sequence,
        "lifecycle_phase": phase,
        "execution_disposition": disposition,
        "timestamps": {
            "claimed_at_ms": claimed_at,
            "started_at_ms": started_at,
            "updated_at_ms": updated_at_ms,
            "stop_requested_at_ms": stop_requested_at_ms,
            "stop_acknowledged_at_ms": stop_acknowledged_at_ms,
            "terminal_at_ms": terminal_at,
        },
        "counters": {
            "requests_started": requests_started,
            "requests_completed": requests_completed,
            "response_bytes_read": requests_completed * 10,
            "actions_contained": requests_started,
            "retries_used": 0,
            "remaining_requests": 2 - requests_started,
            "remaining_wall_ms": max(0, 60000 - sequence),
        },
        "versions": {
            "runner_version": "1.0.0",
            "engine_version": "1",
            "adapter_versions": ["1.0.0"],
        },
        "error_category": error_category,
        "stop_reason": stop_reason,
        "containment_codes": ["admitted"] if requests_started else [],
        "redaction_count": 0,
    }
    value["projection_digest"] = canonical_digest(value)
    value.update(signer.sign(canonical_bytes({
        key: item for key, item in value.items() if key != "projection_digest"
    })))
    return value


def service(conn: sqlite3.Connection, clock: Clock, *, grant_signer=None, runner_auth=None):
    from heel.saas.canary_runs import CanaryRunService

    return CanaryRunService(
        conn,
        signing=grant_signer or SigningAuthority.generate(),
        runner_auth=runner_auth,
        clock=clock,
    )


def submit_and_approve(conn, clock, runner_signer, *, runner_auth=None, idem_char="b"):
    coordinator = service(conn, clock, runner_auth=runner_auth)
    projection = approval_projection(runner_signer)
    submitted = coordinator.submit_projection(
        projection, uploaded_by="user_owner",
    )
    approved = coordinator.approve(
        WORKSPACE,
        PROJECT,
        submitted["run_id"],
        projection_digest=projection["projection_digest"],
        actor="user_owner",
        role="owner",
        reason="Run the bounded canary rehearsal",
        exact_hostname="canary.acme.dev",
        recent_auth_at_ms=NOW_MS,
        idempotency_key="ca1-" + idem_char * 64,
        expected_kill_switch_generation=0,
    )
    return coordinator, submitted, approved
