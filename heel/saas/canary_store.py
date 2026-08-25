"""Tenant-bound persistence primitives for verified canary control data.

This module deliberately owns the SQL used by migration 6 and by an in-memory ``ControlPlane``.
Keeping one schema literal prevents an un-migrated unit instance from drifting from production.
"""
from __future__ import annotations

import sqlite3


CANARY_STORE_SCHEMA = """
CREATE TABLE IF NOT EXISTS canary_environments(
  environment_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  origin TEXT NOT NULL,
  environment_class TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at REAL NOT NULL,
  UNIQUE(workspace_id, project_ref, environment_id),
  FOREIGN KEY(workspace_id, project_ref)
    REFERENCES projects(workspace_id, project_ref));
CREATE TABLE IF NOT EXISTS canary_runners(
  runner_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at REAL NOT NULL,
  UNIQUE(workspace_id, runner_id),
  FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id));
CREATE TABLE IF NOT EXISTS canary_runner_keys(
  key_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  runner_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at REAL NOT NULL,
  revoked_at REAL,
  UNIQUE(workspace_id, key_id),
  UNIQUE(public_key),
  FOREIGN KEY(workspace_id, runner_id)
    REFERENCES canary_runners(workspace_id, runner_id));
CREATE TABLE IF NOT EXISTS canary_consumed_nonces(
  nonce_hash TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  runner_id TEXT NOT NULL,
  consumed_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  UNIQUE(workspace_id, runner_id, nonce_hash),
  FOREIGN KEY(workspace_id, runner_id)
    REFERENCES canary_runners(workspace_id, runner_id));
CREATE TABLE IF NOT EXISTS canary_approval_projections(
  approval_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  runner_id TEXT NOT NULL,
  projection_digest TEXT NOT NULL,
  projection_json TEXT NOT NULL,
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  UNIQUE(workspace_id, project_ref, projection_digest),
  UNIQUE(workspace_id, project_ref, approval_id),
  UNIQUE(workspace_id, project_ref, approval_id, environment_id, runner_id),
  FOREIGN KEY(workspace_id, project_ref, environment_id)
    REFERENCES canary_environments(workspace_id, project_ref, environment_id),
  FOREIGN KEY(workspace_id, runner_id)
    REFERENCES canary_runners(workspace_id, runner_id));
CREATE TABLE IF NOT EXISTS canary_execution_grants(
  grant_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  approval_id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  runner_id TEXT NOT NULL,
  nonce_hash TEXT NOT NULL,
  grant_digest TEXT NOT NULL,
  status TEXT NOT NULL,
  expires_at REAL NOT NULL,
  created_at REAL NOT NULL,
  UNIQUE(nonce_hash),
  UNIQUE(workspace_id, project_ref, grant_id),
  UNIQUE(workspace_id, project_ref, grant_id, environment_id, runner_id),
  FOREIGN KEY(workspace_id, project_ref, approval_id)
    REFERENCES canary_approval_projections(workspace_id, project_ref, approval_id),
  FOREIGN KEY(workspace_id, project_ref, environment_id)
    REFERENCES canary_environments(workspace_id, project_ref, environment_id),
  FOREIGN KEY(workspace_id, runner_id)
    REFERENCES canary_runners(workspace_id, runner_id),
  FOREIGN KEY(workspace_id, project_ref, approval_id, environment_id, runner_id)
    REFERENCES canary_approval_projections(
      workspace_id, project_ref, approval_id, environment_id, runner_id));
CREATE TABLE IF NOT EXISTS canary_runs(
  run_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  runner_id TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  UNIQUE(workspace_id, project_ref, run_id),
  FOREIGN KEY(workspace_id, project_ref, grant_id)
    REFERENCES canary_execution_grants(workspace_id, project_ref, grant_id),
  FOREIGN KEY(workspace_id, project_ref, environment_id)
    REFERENCES canary_environments(workspace_id, project_ref, environment_id),
  FOREIGN KEY(workspace_id, runner_id)
    REFERENCES canary_runners(workspace_id, runner_id),
  FOREIGN KEY(workspace_id, project_ref, grant_id, environment_id, runner_id)
    REFERENCES canary_execution_grants(
      workspace_id, project_ref, grant_id, environment_id, runner_id));
CREATE TABLE IF NOT EXISTS canary_run_events(
  event_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  run_id TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence >= 0),
  event_type TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  created_at REAL NOT NULL,
  UNIQUE(run_id, sequence),
  FOREIGN KEY(workspace_id, project_ref, run_id)
    REFERENCES canary_runs(workspace_id, project_ref, run_id));
CREATE TABLE IF NOT EXISTS canary_operational_receipts(
  run_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  receipt_digest TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  UNIQUE(workspace_id, project_ref, run_id),
  FOREIGN KEY(workspace_id, project_ref, run_id)
    REFERENCES canary_runs(workspace_id, project_ref, run_id));
CREATE TABLE IF NOT EXISTS canary_disclosure_permits(
  permit_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  run_id TEXT NOT NULL,
  projection_digest TEXT NOT NULL,
  status TEXT NOT NULL,
  expires_at REAL NOT NULL,
  created_at REAL NOT NULL,
  UNIQUE(workspace_id, project_ref, permit_id),
  FOREIGN KEY(workspace_id, project_ref, run_id)
    REFERENCES canary_runs(workspace_id, project_ref, run_id));
CREATE TABLE IF NOT EXISTS canary_findings_projections(
  finding_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  run_id TEXT NOT NULL,
  projection_digest TEXT NOT NULL UNIQUE,
  projection_json TEXT NOT NULL,
  created_at REAL NOT NULL,
  UNIQUE(workspace_id, project_ref, finding_id),
  FOREIGN KEY(workspace_id, project_ref, run_id)
    REFERENCES canary_runs(workspace_id, project_ref, run_id));
CREATE TABLE IF NOT EXISTS canary_audit_records(
  audit_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  run_id TEXT NOT NULL,
  subject_ref TEXT NOT NULL,
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  created_at REAL NOT NULL,
  UNIQUE(workspace_id, project_ref, audit_id),
  FOREIGN KEY(workspace_id, project_ref, run_id)
    REFERENCES canary_runs(workspace_id, project_ref, run_id));
"""

# Migration 7 deliberately extends the original Task-2 identity table rather than introducing a
# second environment identity.  Keep ``CANARY_STORE_SCHEMA`` above byte-stable: it is migration 6.
CANARY_ENVIRONMENT_VERIFICATION_MIGRATION = """
ALTER TABLE canary_environments ADD COLUMN attestation_text TEXT;
ALTER TABLE canary_environments ADD COLUMN attestation_version TEXT;
ALTER TABLE canary_environments ADD COLUMN attested_by TEXT;
ALTER TABLE canary_environments ADD COLUMN attested_at REAL;
ALTER TABLE canary_environments ADD COLUMN proof_method TEXT;
ALTER TABLE canary_environments ADD COLUMN proof_version TEXT;
ALTER TABLE canary_environments ADD COLUMN normalization_version TEXT;
ALTER TABLE canary_environments ADD COLUMN challenge_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE canary_environments ADD COLUMN challenge_digest TEXT;
ALTER TABLE canary_environments ADD COLUMN challenge_token TEXT;
ALTER TABLE canary_environments ADD COLUMN challenge_created_at REAL;
ALTER TABLE canary_environments ADD COLUMN challenge_expires_at REAL;
ALTER TABLE canary_environments ADD COLUMN last_check_at REAL;
ALTER TABLE canary_environments ADD COLUMN last_failure_code TEXT;
ALTER TABLE canary_environments ADD COLUMN verified_at REAL;
ALTER TABLE canary_environments ADD COLUMN proof_expires_at REAL;
ALTER TABLE canary_environments ADD COLUMN revoked_at REAL;
ALTER TABLE canary_environments ADD COLUMN revoked_by TEXT;
ALTER TABLE canary_environments ADD COLUMN revoked_reason TEXT;
CREATE INDEX IF NOT EXISTS idx_canary_environment_project
  ON canary_environments(workspace_id, project_ref, origin);
"""

_ENVIRONMENT_COLUMNS = (
    "attestation_text", "attestation_version", "attested_by", "attested_at", "proof_method",
    "proof_version", "normalization_version", "challenge_generation", "challenge_digest",
    "challenge_token", "challenge_created_at", "challenge_expires_at", "last_check_at",
    "last_failure_code", "verified_at", "proof_expires_at", "revoked_at", "revoked_by",
    "revoked_reason",
)


def ensure_canary_environment_schema(conn: sqlite3.Connection) -> None:
    """Bring direct in-process construction to migration-7 schema parity.

    Migrated production databases take the same statements through ``Migrator``.  Unit/control
    plane construction intentionally owns a runtime schema too, so add only missing columns here.
    """
    present = {row[1] for row in conn.execute("PRAGMA table_info(canary_environments)")}
    for statement in CANARY_ENVIRONMENT_VERIFICATION_MIGRATION.strip().split(";"):
        statement = statement.strip()
        if not statement:
            continue
        if statement.startswith("ALTER TABLE"):
            column = statement.split()[5]
            if column in present:
                continue
            conn.execute(statement)
            present.add(column)
        else:
            conn.execute(statement)


class CanaryStore:
    """Typed schema owner. Higher canary services are added in later packets."""

    def __init__(self, conn: sqlite3.Connection):
        if not isinstance(conn, sqlite3.Connection):
            raise TypeError("CanaryStore requires the ControlPlane SQLite connection")
        self.conn = conn
        self.conn.executescript(CANARY_STORE_SCHEMA)
        ensure_canary_environment_schema(conn)
