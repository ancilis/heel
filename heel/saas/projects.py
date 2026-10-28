"""Tenant-scoped hosted projects and immutable findings namespace keys.

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Project namespace keys are server-generated, fixed for the life of a project, and returned only
through an already-authorized caller. They are deliberately kept out of project list records,
receipts, audit rows, and findings-sync request bodies.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import re
import secrets
import sqlite3
import time


_SCHEMA = """
CREATE TABLE IF NOT EXISTS projects(
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  name TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, project_ref),
  UNIQUE(project_ref),
  FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id));
CREATE TABLE IF NOT EXISTS project_namespace_keys(
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  namespace_key_hex TEXT NOT NULL,
  created_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, project_ref),
  FOREIGN KEY(workspace_id, project_ref)
    REFERENCES projects(workspace_id, project_ref));
CREATE INDEX IF NOT EXISTS idx_projects_workspace_created
  ON projects(workspace_id, created_at, project_ref);
"""

_PROJECT_REF = re.compile(r"prj_[0-9a-f]{32}\Z")


class ProjectNotFound(LookupError):
    """The project does not exist inside the requested workspace."""


@dataclass(frozen=True)
class Project:
    workspace_id: str
    project_ref: str
    name: str
    created_by: str
    created_at: float


def _timestamp(value: float | None) -> float:
    result = time.time() if value is None else value
    if type(result) not in (int, float) or not math.isfinite(result) or result < 0:
        raise ValueError("project timestamp must be a finite non-negative number")
    return float(result)


def _identity(value: str, label: str) -> str:
    if type(value) is not str or not value or len(value) > 256 or any(
        ord(character) < 0x20 for character in value
    ):
        raise ValueError(f"{label} is invalid")
    return value


class ProjectStore:
    """Project metadata and the separate namespace-key vault on one shared connection."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript(_SCHEMA)

    def create(
        self,
        workspace_id: str,
        name: str,
        *,
        created_by: str,
        now: float | None = None,
    ) -> Project:
        workspace = _identity(workspace_id, "workspace_id")
        actor = _identity(created_by, "created_by")
        project_name = _identity(name.strip(), "project name")
        created_at = _timestamp(now)
        project_ref = f"prj_{secrets.token_hex(16)}"
        namespace_key_hex = secrets.token_bytes(32).hex()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            if self.conn.execute(
                "SELECT 1 FROM workspaces WHERE workspace_id=?", (workspace,)
            ).fetchone() is None:
                raise ProjectNotFound("workspace not found")
            self.conn.execute(
                "INSERT INTO projects VALUES(?,?,?,?,?)",
                (workspace, project_ref, project_name, actor, created_at),
            )
            self.conn.execute(
                "INSERT INTO project_namespace_keys VALUES(?,?,?,?)",
                (workspace, project_ref, namespace_key_hex, created_at),
            )
            self.conn.execute("COMMIT")
        except Exception:
            try:
                self.conn.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
            raise
        return Project(workspace, project_ref, project_name, actor, created_at)

    def get(self, workspace_id: str, project_ref: str) -> Project:
        row = self.conn.execute(
            """SELECT workspace_id, project_ref, name, created_by, created_at
               FROM projects WHERE workspace_id=? AND project_ref=?""",
            (workspace_id, project_ref),
        ).fetchone()
        if row is None:
            raise ProjectNotFound("project not found")
        return Project(
            row["workspace_id"], row["project_ref"], row["name"],
            row["created_by"], float(row["created_at"]),
        )

    def list(self, workspace_id: str) -> list[Project]:
        rows = self.conn.execute(
            """SELECT workspace_id, project_ref, name, created_by, created_at
               FROM projects WHERE workspace_id=?
               ORDER BY created_at, project_ref""",
            (workspace_id,),
        ).fetchall()
        return [
            Project(
                row["workspace_id"], row["project_ref"], row["name"],
                row["created_by"], float(row["created_at"]),
            )
            for row in rows
        ]

    def namespace_key(self, workspace_id: str, project_ref: str) -> bytes:
        if type(project_ref) is not str or _PROJECT_REF.fullmatch(project_ref) is None:
            raise ProjectNotFound("project not found")
        row = self.conn.execute(
            """SELECT namespace_key_hex FROM project_namespace_keys
               WHERE workspace_id=? AND project_ref=?""",
            (workspace_id, project_ref),
        ).fetchone()
        if row is None:
            raise ProjectNotFound("project not found")
        try:
            key = bytes.fromhex(row["namespace_key_hex"])
        except (TypeError, ValueError):
            raise RuntimeError("project namespace key storage is invalid") from None
        if len(key) != 32:
            raise RuntimeError("project namespace key storage is invalid")
        return key
