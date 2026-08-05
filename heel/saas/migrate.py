"""
Heel hosted — versioned schema migrations, SQLite-first / Postgres-portable (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Migrations are ordered, append-only, and recorded in `schema_migrations`. They are written in a
dialect-neutral SQL subset; `translate()` rewrites the few constructs that differ so the same
migration list provisions Postgres when the owner supplies a live DSN. Data export uses parametrized
inserts against any DB-API connection — no string-spliced SQL.
"""
from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass

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
]
