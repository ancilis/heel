"""
Heel hosted — versioned schema migrations, SQLite-first / Postgres-portable (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Migrations are ordered, append-only, and recorded in `schema_migrations`. They are written in a
dialect-neutral SQL subset; `translate()` rewrites the few constructs that differ so the same
migration list provisions Postgres when the owner supplies a live DSN. Data export uses parametrized
inserts against any DB-API connection — no string-spliced SQL.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sqlite3
import time
from dataclasses import dataclass

from .canary_store import (
    CANARY_ENVIRONMENT_ATTESTATION_ACK_MIGRATION, CANARY_ENVIRONMENT_VERIFICATION_MIGRATION,
    CANARY_STORE_SCHEMA,
)
from .runner_auth import RUNNER_AUTH_SCHEMA

_TRACKING = """
CREATE TABLE IF NOT EXISTS schema_migrations(
  version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at REAL NOT NULL);
"""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str   # dialect-neutral subset; ';'-separated statements


class MigrationError(Exception):
    pass


def translate(sql: str, dialect: str) -> str:
    """Rewrite the dialect-neutral subset for the target. Supported: 'sqlite', 'postgres'."""
    if dialect == "sqlite":
        return sql
    if dialect == "postgres":
        out = re.sub(r"\bREAL\b", "DOUBLE PRECISION", sql)
        out = re.sub(r"\bAUTOINCREMENT\b", "", out)
        return out
    raise MigrationError(f"unknown dialect {dialect!r}")


class Migrator:
    """Applies pending migrations in order, one transaction per migration."""

    def __init__(self, conn, migrations: list[Migration], *, dialect: str = "sqlite"):
        versions = [m.version for m in migrations]
        if versions != sorted(versions) or len(set(versions)) != len(versions):
            raise MigrationError("migration versions must be strictly increasing and unique")
        self.conn = conn
        self.migrations = migrations
        self.dialect = dialect
        for stmt in _TRACKING.strip().split(";"):
            if stmt.strip():
                self.conn.execute(translate(stmt, dialect))
        self.conn.commit()

    def current_version(self) -> int:
        row = self.conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        return row[0] or 0

    def pending(self) -> list[Migration]:
        cur = self.current_version()
        return [m for m in self.migrations if m.version > cur]

    def apply_all(self) -> list[int]:
        """Apply every pending migration; returns applied versions. Idempotent."""
        applied = []
        for m in self.pending():
            try:
                self.conn.execute("BEGIN IMMEDIATE" if self.dialect == "sqlite" else "BEGIN")
                for stmt in translate(m.sql, self.dialect).split(";"):
                    if stmt.strip():
                        self.conn.execute(stmt)
                self.conn.execute(
                    "INSERT INTO schema_migrations VALUES(?,?,?)",
                    (m.version, m.name, time.time()))
                self.conn.commit()
            except Exception as e:
                self.conn.rollback()
                raise MigrationError(f"migration {m.version} ({m.name}) failed: {e}") from e
            applied.append(m.version)
        return applied


def read_current_version(conn) -> int:
    """Read schema state without creating the migration tracker."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    if row is None:
        return 0
    current = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    return int(current or 0)


def copy_table(src: sqlite3.Connection, dst, table: str, *, placeholder: str = "?") -> int:
    """Copy all rows of `table` from a SQLite source into any DB-API destination connection
    (use placeholder='%s' for Postgres). Destination schema must already exist (run the same
    Migrator against it first). Returns the row count."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table):
        raise MigrationError(f"invalid table name {table!r}")
    cols = [r[1] for r in src.execute(f"PRAGMA table_info({table})")]
    if not cols:
        raise MigrationError(f"table {table!r} not found in source")
    col_list = ", ".join(cols)
    marks = ", ".join([placeholder] * len(cols))
    n = 0
    for row in src.execute(f"SELECT {col_list} FROM {table}"):
        dst.execute(f"INSERT INTO {table} ({col_list}) VALUES ({marks})", tuple(row))
        n += 1
    dst.commit()
    return n


# The consolidated control-plane schema as the v1 baseline. New tables/columns arrive as
# NEW migrations appended here — never edit an applied migration.
CONTROL_PLANE_MIGRATIONS = [
    Migration(1, "tenancy", """
CREATE TABLE IF NOT EXISTS orgs(
  org_id TEXT PRIMARY KEY, name TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS workspaces(
  workspace_id TEXT PRIMARY KEY, org_id TEXT NOT NULL, name TEXT, plan_id TEXT NOT NULL,
  catalog_version TEXT NOT NULL, created_at REAL);
CREATE TABLE IF NOT EXISTS users(
  user_id TEXT PRIMARY KEY, email TEXT UNIQUE, created_at REAL);
CREATE TABLE IF NOT EXISTS memberships(
  workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, created_at REAL,
  PRIMARY KEY(workspace_id, user_id));
CREATE TABLE IF NOT EXISTS invites(
  invite_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, email TEXT, role TEXT,
  token_hash TEXT NOT NULL, created_at REAL, accepted_at REAL);
CREATE TABLE IF NOT EXISTS api_keys(
  key_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, role TEXT NOT NULL, name TEXT,
  key_hash TEXT NOT NULL, created_at REAL, revoked_at REAL, last_used_at REAL)
"""),
    Migration(2, "auth", """
CREATE TABLE IF NOT EXISTS credentials(
  user_id TEXT PRIMARY KEY, salt TEXT NOT NULL, pw_hash TEXT NOT NULL,
  iterations INTEGER NOT NULL, updated_at REAL);
CREATE TABLE IF NOT EXISTS sessions(
  session_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL,
  created_at REAL, last_seen_at REAL, revoked_at REAL);
CREATE TABLE IF NOT EXISTS login_failures(
  email TEXT PRIMARY KEY, count INTEGER NOT NULL, first_at REAL, last_at REAL)
"""),
    Migration(3, "findings_sync_continuity", """
CREATE TABLE IF NOT EXISTS projects(
  workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, name TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, project_ref),
  UNIQUE(project_ref),
  FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id));
CREATE TABLE IF NOT EXISTS project_namespace_keys(
  workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, namespace_key_hex TEXT NOT NULL,
  created_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, project_ref),
  FOREIGN KEY(workspace_id, project_ref) REFERENCES projects(workspace_id, project_ref));
CREATE TABLE IF NOT EXISTS synced_reviews(
  workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, synced_review_id TEXT NOT NULL,
  projection_hash TEXT NOT NULL, projection_json TEXT NOT NULL, gate_status TEXT NOT NULL,
  findings_count INTEGER NOT NULL, blockers_count INTEGER NOT NULL, created_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, project_ref, synced_review_id),
  UNIQUE(workspace_id, project_ref, projection_hash),
  FOREIGN KEY(workspace_id, project_ref) REFERENCES projects(workspace_id, project_ref));
CREATE TABLE IF NOT EXISTS project_findings(
  workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, finding_id TEXT NOT NULL,
  surface_ref TEXT NOT NULL, surface_type TEXT NOT NULL, risk_code TEXT NOT NULL,
  created_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, project_ref, finding_id),
  FOREIGN KEY(workspace_id, project_ref) REFERENCES projects(workspace_id, project_ref));
CREATE TABLE IF NOT EXISTS synced_review_findings(
  workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, synced_review_id TEXT NOT NULL,
  finding_id TEXT NOT NULL, ordinal INTEGER NOT NULL, control_code TEXT NOT NULL,
  severity TEXT NOT NULL, reachable INTEGER NOT NULL,
  PRIMARY KEY(workspace_id, project_ref, synced_review_id, finding_id),
  UNIQUE(workspace_id, project_ref, synced_review_id, ordinal),
  FOREIGN KEY(workspace_id, project_ref, synced_review_id)
    REFERENCES synced_reviews(workspace_id, project_ref, synced_review_id),
  FOREIGN KEY(workspace_id, project_ref, finding_id)
    REFERENCES project_findings(workspace_id, project_ref, finding_id));
CREATE TABLE IF NOT EXISTS findings_source_observations(
  workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, source_result_ref TEXT NOT NULL,
  synced_review_id TEXT NOT NULL, engine_version TEXT NOT NULL, execution_mode TEXT NOT NULL,
  observed_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, project_ref, source_result_ref),
  FOREIGN KEY(workspace_id, project_ref, synced_review_id)
    REFERENCES synced_reviews(workspace_id, project_ref, synced_review_id));
CREATE TABLE IF NOT EXISTS findings_sync_approvals(
  workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, approval_id TEXT NOT NULL,
  request_digest TEXT NOT NULL, approved_by TEXT NOT NULL, approved_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, project_ref, approval_id),
  UNIQUE(approval_id),
  FOREIGN KEY(workspace_id, project_ref) REFERENCES projects(workspace_id, project_ref));
CREATE TABLE IF NOT EXISTS findings_sync_receipts(
  workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, request_digest TEXT NOT NULL,
  request_json TEXT NOT NULL, receipt_id TEXT NOT NULL, synced_review_id TEXT NOT NULL,
  source_result_ref TEXT NOT NULL, approval_id TEXT NOT NULL,
  disposition TEXT NOT NULL, metered INTEGER NOT NULL, accepted_at TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  PRIMARY KEY(workspace_id, project_ref, request_digest),
  UNIQUE(receipt_id),
  FOREIGN KEY(workspace_id, project_ref, synced_review_id)
    REFERENCES synced_reviews(workspace_id, project_ref, synced_review_id));
CREATE TABLE IF NOT EXISTS findings_sync_audit(
  workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, event_id TEXT NOT NULL,
  action TEXT NOT NULL, actor_ref TEXT NOT NULL, request_digest TEXT NOT NULL,
  synced_review_id TEXT, ts REAL NOT NULL,
  PRIMARY KEY(workspace_id, project_ref, event_id),
  UNIQUE(event_id),
  FOREIGN KEY(workspace_id, project_ref) REFERENCES projects(workspace_id, project_ref));
CREATE INDEX IF NOT EXISTS idx_projects_workspace
  ON projects(workspace_id, created_at, project_ref);
CREATE INDEX IF NOT EXISTS idx_sync_reviews_project
  ON synced_reviews(workspace_id, project_ref, created_at, synced_review_id);
CREATE INDEX IF NOT EXISTS idx_sync_sources_review
  ON findings_source_observations(workspace_id, project_ref, synced_review_id);
CREATE INDEX IF NOT EXISTS idx_sync_approvals_digest
  ON findings_sync_approvals(workspace_id, project_ref, request_digest, expires_at);
CREATE INDEX IF NOT EXISTS idx_sync_audit_project
  ON findings_sync_audit(workspace_id, project_ref, ts, event_id)
"""),
    Migration(4, "device_authorization", """
CREATE TABLE IF NOT EXISTS device_authorizations(
  grant_id TEXT PRIMARY KEY,
  device_code_hash TEXT NOT NULL UNIQUE,
  user_code_hash TEXT NOT NULL UNIQUE,
  device_name TEXT NOT NULL,
  device_challenge TEXT NOT NULL,
  client_key TEXT NOT NULL,
  requested_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  poll_interval INTEGER NOT NULL,
  last_polled_at REAL,
  status TEXT NOT NULL,
  inspected_by TEXT,
  confirmation_nonce_hash TEXT,
  confirmation_expires_at REAL,
  approved_user_id TEXT,
  workspace_id TEXT,
  approved_at REAL,
  consumed_at REAL);
CREATE TABLE IF NOT EXISTS device_credentials(
  device_id TEXT PRIMARY KEY,
  family_id TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  created_at REAL NOT NULL,
  refresh_absolute_expires_at REAL NOT NULL,
  last_refreshed_at REAL NOT NULL,
  revoked_at REAL);
CREATE TABLE IF NOT EXISTS device_access_tokens(
  token_hash TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  issued_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  revoked_at REAL,
  FOREIGN KEY(device_id) REFERENCES device_credentials(device_id));
CREATE TABLE IF NOT EXISTS device_refresh_tokens(
  token_hash TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  family_id TEXT NOT NULL,
  issued_at REAL NOT NULL,
  absolute_expires_at REAL NOT NULL,
  idle_expires_at REAL NOT NULL,
  consumed_at REAL,
  FOREIGN KEY(device_id) REFERENCES device_credentials(device_id));
CREATE INDEX IF NOT EXISTS idx_device_access_device
  ON device_access_tokens(device_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_device_refresh_family
  ON device_refresh_tokens(family_id, issued_at);
CREATE INDEX IF NOT EXISTS idx_device_authorization_client
  ON device_authorizations(client_key, requested_at)
"""),
    Migration(5, "complete_runtime_schema", """
CREATE TABLE IF NOT EXISTS signup_events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, email TEXT, ts REAL NOT NULL);
CREATE INDEX IF NOT EXISTS idx_signup_ip ON signup_events(ip, ts);
CREATE TABLE IF NOT EXISTS subscriptions(
  workspace_id TEXT PRIMARY KEY,
  provider_customer_id TEXT, provider_subscription_id TEXT,
  plan_id TEXT NOT NULL, state TEXT NOT NULL, catalog_version TEXT NOT NULL,
  interval TEXT, version INTEGER NOT NULL DEFAULT 0,
  current_period_end REAL, cancel_at_period_end INTEGER DEFAULT 0, updated_at REAL);
CREATE TABLE IF NOT EXISTS billing_events(
  event_id TEXT PRIMARY KEY, type TEXT, received_at REAL, applied INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS usage_ledger(
  entry_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  meter TEXT NOT NULL,
  period TEXT NOT NULL,
  kind TEXT NOT NULL,
  amount INTEGER NOT NULL,
  reservation_id TEXT,
  idempotency_key TEXT,
  ref TEXT,
  ts REAL NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_idem
  ON usage_ledger(workspace_id, meter, idempotency_key)
  WHERE idempotency_key IS NOT NULL AND kind='reserve';
CREATE INDEX IF NOT EXISTS idx_ledger_usage ON usage_ledger(workspace_id, meter, period);
CREATE INDEX IF NOT EXISTS idx_ledger_resv ON usage_ledger(reservation_id);
CREATE TABLE IF NOT EXISTS verified_targets(
  target_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, hostname TEXT NOT NULL,
  method TEXT, token TEXT NOT NULL, created_at REAL,
  verified_at REAL, revoked_at REAL,
  UNIQUE(workspace_id, hostname));
CREATE INDEX IF NOT EXISTS idx_vt_ws ON verified_targets(workspace_id);
CREATE TABLE IF NOT EXISTS jobs(
  job_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, kind TEXT NOT NULL,
  state TEXT NOT NULL, target TEXT, scope_ref TEXT, budget TEXT NOT NULL,
  reservations TEXT NOT NULL, created_at REAL, claimed_at REAL, lease_until REAL,
  worker_id TEXT, finished_at REAL, outcome TEXT, idempotency_key TEXT);
CREATE INDEX IF NOT EXISTS idx_jobs_ws ON jobs(workspace_id);
CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state);
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_idem
  ON jobs(workspace_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS kill_switches(
  scope TEXT PRIMARY KEY,
  reason TEXT NOT NULL, actor TEXT NOT NULL, tripped_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS admin_audit(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL, action TEXT NOT NULL, subject TEXT, reason TEXT, ts REAL NOT NULL)
"""),
    Migration(6, "verified_canary_persistence", CANARY_STORE_SCHEMA + """
ALTER TABLE usage_ledger ADD COLUMN reason TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_canary_fault_refund
  ON usage_ledger(reservation_id) WHERE kind='platform_fault_refund';
"""),
    Migration(7, "verified_canary_environment_proofs", CANARY_ENVIRONMENT_VERIFICATION_MIGRATION),
    Migration(8, "verified_canary_environment_attestation_ack", CANARY_ENVIRONMENT_ATTESTATION_ACK_MIGRATION),
    Migration(9, "verified_canary_runner_pairing", RUNNER_AUTH_SCHEMA),
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply or inspect Heel SQLite schema migrations")
    parser.add_argument("command", choices=("status", "up"))
    parser.add_argument("database", help="absolute path to the control-plane SQLite database")
    args = parser.parse_args(argv)
    path = Path(args.database)
    if not path.is_absolute() or not path.parent.is_dir() or path.is_symlink():
        parser.error("database must be a non-symlink absolute path below an existing directory")
    target = CONTROL_PLANE_MIGRATIONS[-1].version
    if args.command == "status":
        if not path.is_file():
            parser.error("status requires an existing database file")
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            current = read_current_version(connection)
        finally:
            connection.close()
        print(f"current={current} target={target}")
        return 0 if current == target else 1

    connection = sqlite3.connect(str(path))
    try:
        migrator = Migrator(connection, CONTROL_PLANE_MIGRATIONS)
        applied = migrator.apply_all()
        print("applied=" + (",".join(str(version) for version in applied) or "none"))
        print(f"current={migrator.current_version()} target={target}")
    finally:
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
