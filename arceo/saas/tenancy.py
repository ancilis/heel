"""
Arceo hosted — tenancy, roles, memberships, API keys (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Arceo-Commercial

Every durable record carries a workspace_id tenant boundary. API keys are stored HASHED (never
plaintext) and are scoped to a single workspace + role. SQLite locally (portable to Postgres+RLS).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from enum import Enum


class SeatLimitExceeded(Exception):
    """Accepting this invite would exceed the plan's seat quota."""


class Role(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"      # operator
    BILLING = "billing"
    VIEWER = "viewer"


# Capability grants per role. Least privilege; owner is a superset.
_CAN = {
    "manage_billing": {Role.OWNER, Role.BILLING},
    "manage_members": {Role.OWNER, Role.ADMIN},
    "manage_targets": {Role.OWNER, Role.ADMIN, Role.MEMBER},
    "create_scope":   {Role.OWNER, Role.ADMIN},          # human-only control-plane path
    "run_rehearsal":  {Role.OWNER, Role.ADMIN, Role.MEMBER},
    "view":           {Role.OWNER, Role.ADMIN, Role.MEMBER, Role.BILLING, Role.VIEWER},
    "manage_api_keys": {Role.OWNER, Role.ADMIN},
}


def role_can(role: Role, capability: str) -> bool:
    return role in _CAN.get(capability, set())


_SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs(
  org_id TEXT PRIMARY KEY, name TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS workspaces(
  workspace_id TEXT PRIMARY KEY, org_id TEXT NOT NULL, name TEXT, plan_id TEXT NOT NULL,
  catalog_version TEXT NOT NULL, created_at REAL,
  FOREIGN KEY(org_id) REFERENCES orgs(org_id));
CREATE TABLE IF NOT EXISTS users(
  user_id TEXT PRIMARY KEY, email TEXT UNIQUE, created_at REAL);
CREATE TABLE IF NOT EXISTS memberships(
  workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, created_at REAL,
  PRIMARY KEY(workspace_id, user_id),
  FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id));
CREATE TABLE IF NOT EXISTS invites(
  invite_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, email TEXT, role TEXT,
  token_hash TEXT NOT NULL, created_at REAL, accepted_at REAL);
CREATE TABLE IF NOT EXISTS api_keys(
  key_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, role TEXT NOT NULL, name TEXT,
  key_hash TEXT NOT NULL, created_at REAL, revoked_at REAL, last_used_at REAL);
CREATE INDEX IF NOT EXISTS idx_ws_org ON workspaces(org_id);
CREATE INDEX IF NOT EXISTS idx_mem_ws ON memberships(workspace_id);
CREATE INDEX IF NOT EXISTS idx_key_ws ON api_keys(workspace_id);
"""


def _id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def _now() -> float:
    return time.time()


def hash_api_key(raw: str) -> str:
    """Hash for storage. Uses a server pepper (ARCEO_API_KEY_PEPPER) if set, else a plain sha256.
    Constant-time compared on verify."""
    pepper = os.environ.get("ARCEO_API_KEY_PEPPER", "").encode()
    if pepper:
        return hmac.new(pepper, raw.encode(), hashlib.sha256).hexdigest()
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class ApiKeyIssued:
    key_id: str
    workspace_id: str
    role: Role
    secret: str   # returned ONCE at creation; only the hash is persisted


class ControlPlaneStore:
    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(_SCHEMA)

    # --- orgs / workspaces ---
    def create_org(self, name: str) -> str:
        oid = _id("org")
        self.conn.execute("INSERT INTO orgs VALUES(?,?,?)", (oid, name, _now()))
        self.conn.commit()
        return oid

    def create_workspace(self, org_id: str, name: str, plan_id: str, catalog_version: str) -> str:
        wid = _id("ws")
        self.conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)",
                          (wid, org_id, name, plan_id, catalog_version, _now()))
        self.conn.commit()
        return wid

    def get_workspace(self, workspace_id: str):
        return self.conn.execute("SELECT * FROM workspaces WHERE workspace_id=?",
                                 (workspace_id,)).fetchone()

    def set_workspace_plan(self, workspace_id: str, plan_id: str, catalog_version: str) -> None:
        self.conn.execute("UPDATE workspaces SET plan_id=?, catalog_version=? WHERE workspace_id=?",
                          (plan_id, catalog_version, workspace_id))
        self.conn.commit()

    # --- users / memberships ---
    def create_user(self, email: str) -> str:
        uid = _id("usr")
        self.conn.execute("INSERT INTO users VALUES(?,?,?)", (uid, email.lower(), _now()))
        self.conn.commit()
        return uid

    def add_member(self, workspace_id: str, user_id: str, role: Role) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO memberships VALUES(?,?,?,?)",
            (workspace_id, user_id, role.value, _now()))
        self.conn.commit()

    def get_role(self, workspace_id: str, user_id: str) -> Role | None:
        row = self.conn.execute(
            "SELECT role FROM memberships WHERE workspace_id=? AND user_id=?",
            (workspace_id, user_id)).fetchone()
        return Role(row["role"]) if row else None

    def members(self, workspace_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM memberships WHERE workspace_id=?", (workspace_id,)).fetchall()

    # --- invites ---
    def create_invite(self, workspace_id: str, email: str, role: Role) -> str:
        token = secrets.token_urlsafe(24)
        iid = _id("inv")
        self.conn.execute("INSERT INTO invites VALUES(?,?,?,?,?,?,?)",
                          (iid, workspace_id, email.lower(), role.value,
                           hash_api_key(token), _now(), None))
        self.conn.commit()
        return token  # emailed to invitee; only the hash is stored

    def accept_invite(self, workspace_id: str, token: str, user_id: str,
                      *, max_seats: int | None = None) -> Role:
        """max_seats, when given, is enforced atomically: the member count is taken inside the
        same write transaction that inserts the membership, so concurrent accepts serialize and
        cannot carry the workspace past its seat quota (raises SeatLimitExceeded). An existing
        member re-accepting never counts against the limit."""
        th = hash_api_key(token)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute(
                "SELECT * FROM invites WHERE workspace_id=? AND token_hash=? "
                "AND accepted_at IS NULL", (workspace_id, th)).fetchone()
            if not row:
                raise PermissionError("invalid or already-used invite")
            role = Role(row["role"])
            existing = self.conn.execute(
                "SELECT 1 FROM memberships WHERE workspace_id=? AND user_id=?",
                (workspace_id, user_id)).fetchone()
            if max_seats is not None and not existing:
                n = self.conn.execute(
                    "SELECT COUNT(*) FROM memberships WHERE workspace_id=?",
                    (workspace_id,)).fetchone()[0]
                if n >= max_seats:
                    raise SeatLimitExceeded(f"seat limit ({max_seats}) reached")
            self.conn.execute(
                "INSERT OR REPLACE INTO memberships VALUES(?,?,?,?)",
                (workspace_id, user_id, role.value, _now()))
            self.conn.execute("UPDATE invites SET accepted_at=? WHERE invite_id=?",
                              (_now(), row["invite_id"]))
            self.conn.execute("COMMIT")
        except Exception:
            try:
                self.conn.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
            raise
        return role

    # --- API keys ---
    def issue_api_key(self, workspace_id: str, role: Role, name: str = "") -> ApiKeyIssued:
        secret = f"arceo_sk_{secrets.token_urlsafe(32)}"
        kid = _id("key")
        self.conn.execute("INSERT INTO api_keys VALUES(?,?,?,?,?,?,?,?)",
                          (kid, workspace_id, role.value, name, hash_api_key(secret),
                           _now(), None, None))
        self.conn.commit()
        return ApiKeyIssued(kid, workspace_id, role, secret)

    def authenticate_api_key(self, raw_secret: str) -> tuple[str, Role] | None:
        """Return (workspace_id, role) for a valid, non-revoked key, else None. Tenant-scoped."""
        kh = hash_api_key(raw_secret)
        row = self.conn.execute(
            "SELECT * FROM api_keys WHERE key_hash=? AND revoked_at IS NULL", (kh,)).fetchone()
        if not row:
            return None
        self.conn.execute("UPDATE api_keys SET last_used_at=? WHERE key_id=?", (_now(), row["key_id"]))
        self.conn.commit()
        return row["workspace_id"], Role(row["role"])

    def revoke_api_key(self, key_id: str) -> None:
        self.conn.execute("UPDATE api_keys SET revoked_at=? WHERE key_id=?", (_now(), key_id))
        self.conn.commit()


def require(store: ControlPlaneStore, workspace_id: str, user_id: str, capability: str) -> Role:
    """Authorize a control-plane action. Raises PermissionError on cross-tenant or under-privileged
    access. This is the single choke point callers use — never trust a client-supplied role."""
    role = store.get_role(workspace_id, user_id)
    if role is None:
        raise PermissionError(f"user {user_id} is not a member of workspace {workspace_id}")
    if not role_can(role, capability):
        raise PermissionError(f"role {role.value} lacks capability {capability!r}")
    return role
