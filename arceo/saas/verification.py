"""
Arceo hosted — target ownership verification (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Arceo-Commercial

No real-target run at any tier without proof of control. Two challenge methods:
- DNS TXT: `arceo-verify=<token>` on `_arceo.<domain>`
- HTTP file: GET https://<domain>/.well-known/arceo-verify.txt containing the token

Resolution is injected (callables), so this module is fully offline-testable and the production
resolver/fetcher swap in without code change. Challenges expire; verified status is periodically
re-checkable and revocable.
"""
from __future__ import annotations

import os
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Callable

CHALLENGE_TTL = 24 * 3600
REVERIFY_AFTER = 30 * 24 * 3600   # verified targets should be re-proven monthly

_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS verified_targets(
  target_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, hostname TEXT NOT NULL,
  method TEXT, token TEXT NOT NULL, created_at REAL,
  verified_at REAL, revoked_at REAL,
  UNIQUE(workspace_id, hostname));
CREATE INDEX IF NOT EXISTS idx_vt_ws ON verified_targets(workspace_id);
"""


def _now() -> float:
    return time.time()


def valid_hostname(hostname: str) -> bool:
    """Public DNS names only — no IPs, localhost, ports, schemes, or internal single labels."""
    h = hostname.strip().lower().rstrip(".")
    if not _HOST_RE.match(h):
        return False
    if re.fullmatch(r"[0-9.]+", h) or ":" in h:
        return False
    return h not in ("localhost",) and not h.endswith((".local", ".internal", ".localhost"))


class TargetLimitExceeded(Exception):
    """Verifying this target would exceed the plan's verified-target quota."""


class HostnameReuseExceeded(Exception):
    """This hostname is already actively verified in too many other workspaces. Caps the
    trial-farming pattern of one controlled target funding verified runs across an unbounded
    number of Free workspaces; legitimate multi-workspace use (consultancies) fits under the
    cap or goes through support."""


# Distinct workspaces one hostname may be actively verified in (env-tunable per deployment).
MAX_WORKSPACES_PER_HOSTNAME = 3


@dataclass
class Challenge:
    target_id: str
    hostname: str
    token: str
    dns_record: str    # what to publish for the DNS method
    http_url: str      # where to publish for the HTTP method


class TargetVerifier:
    """dns_txt(name) -> list[str]; http_get(url) -> str. Both injected."""

    def __init__(self, conn: sqlite3.Connection, *,
                 dns_txt: Callable[[str], list] | None = None,
                 http_get: Callable[[str], str] | None = None,
                 max_workspaces_per_hostname: int | None = None):
        self.conn = conn
        self.conn.executescript(_SCHEMA)
        self.dns_txt = dns_txt
        self.http_get = http_get
        self.max_workspaces_per_hostname = (
            max_workspaces_per_hostname if max_workspaces_per_hostname is not None
            else int(os.environ.get("ARCEO_MAX_WORKSPACES_PER_HOSTNAME",
                                    MAX_WORKSPACES_PER_HOSTNAME)))

    def start(self, workspace_id: str, hostname: str) -> Challenge:
        h = hostname.strip().lower().rstrip(".")
        if not valid_hostname(h):
            raise ValueError(f"not a verifiable public hostname: {hostname!r}")
        token = secrets.token_urlsafe(24)
        tid = f"tgt_{secrets.token_hex(8)}"
        # restart replaces any prior (unverified or expired) challenge for this pair
        self.conn.execute(
            "INSERT INTO verified_targets(target_id,workspace_id,hostname,method,token,"
            "created_at,verified_at,revoked_at) VALUES(?,?,?,?,?,?,NULL,NULL) "
            "ON CONFLICT(workspace_id,hostname) DO UPDATE SET "
            "token=excluded.token, created_at=excluded.created_at, method=NULL, "
            "verified_at=NULL, revoked_at=NULL",
            (tid, workspace_id, h, None, token, _now()))
        self.conn.commit()
        row = self.conn.execute(
            "SELECT target_id FROM verified_targets WHERE workspace_id=? AND hostname=?",
            (workspace_id, h)).fetchone()
        return Challenge(row[0], h, token,
                         dns_record=f"_arceo.{h} TXT \"arceo-verify={token}\"",
                         http_url=f"https://{h}/.well-known/arceo-verify.txt")

    def _row(self, workspace_id: str, hostname: str):
        return self.conn.execute(
            "SELECT * FROM verified_targets WHERE workspace_id=? AND hostname=?",
            (workspace_id, hostname.strip().lower().rstrip("."))).fetchone()

    def check(self, workspace_id: str, hostname: str, *,
              max_verified: int | None = None) -> bool:
        """Attempt verification via whichever methods have injected resolvers.

        max_verified, when given, is enforced atomically at the write: the count of currently
        verified targets is taken inside the same write transaction that records this
        verification, so concurrent checks serialize and cannot verify past the quota
        (raises TargetLimitExceeded). Re-verifying an already-verified target never counts
        against the limit."""
        row = self._row(workspace_id, hostname)
        if not row or row["revoked_at"]:
            return False
        if _now() - row["created_at"] > CHALLENGE_TTL and not row["verified_at"]:
            return False
        token, h = row["token"], row["hostname"]
        method = None
        if self.dns_txt is not None:
            try:
                if any(f"arceo-verify={token}" in str(r) for r in self.dns_txt(f"_arceo.{h}")):
                    method = "dns_txt"
            except Exception:
                pass
        if method is None and self.http_get is not None:
            try:
                if token in self.http_get(f"https://{h}/.well-known/arceo-verify.txt"):
                    method = "http_file"
            except Exception:
                pass
        if method is None:
            return False
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            fresh = self.conn.execute(
                "SELECT verified_at FROM verified_targets WHERE target_id=?",
                (row["target_id"],)).fetchone()
            already = fresh and fresh["verified_at"] and \
                _now() - fresh["verified_at"] <= REVERIFY_AFTER
            if max_verified is not None and not already:
                if self._verified_count_locked(workspace_id) >= max_verified:
                    self.conn.execute("ROLLBACK")
                    raise TargetLimitExceeded(
                        f"verified target limit ({max_verified}) reached")
            if not already and self.max_workspaces_per_hostname >= 0:
                others = self.conn.execute(
                    "SELECT COUNT(DISTINCT workspace_id) AS n FROM verified_targets "
                    "WHERE hostname=? AND workspace_id!=? AND revoked_at IS NULL "
                    "AND verified_at IS NOT NULL AND verified_at > ?",
                    (h, workspace_id, _now() - REVERIFY_AFTER)).fetchone()["n"]
                if others >= self.max_workspaces_per_hostname:
                    self.conn.execute("ROLLBACK")
                    raise HostnameReuseExceeded(
                        f"{h} is already verified in {others} other workspaces; "
                        "contact support to raise this limit")
            self.conn.execute(
                "UPDATE verified_targets SET verified_at=?, method=? WHERE target_id=?",
                (_now(), method, row["target_id"]))
            self.conn.execute("COMMIT")
        except (HostnameReuseExceeded, TargetLimitExceeded):
            raise
        except Exception:
            try:
                self.conn.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass
            raise
        return True

    def is_verified(self, workspace_id: str, hostname: str) -> bool:
        row = self._row(workspace_id, hostname)
        if not row or row["revoked_at"] or not row["verified_at"]:
            return False
        return _now() - row["verified_at"] <= REVERIFY_AFTER

    def revoke(self, workspace_id: str, hostname: str) -> None:
        self.conn.execute(
            "UPDATE verified_targets SET revoked_at=? WHERE workspace_id=? AND hostname=?",
            (_now(), workspace_id, hostname.strip().lower().rstrip(".")))
        self.conn.commit()

    def _verified_count_locked(self, workspace_id: str) -> int:
        """Count of CURRENTLY verified targets (fresh within the re-verify window) — the same
        predicate as is_verified, so a stale target frees its quota slot for re-verification."""
        return self.conn.execute(
            "SELECT COUNT(*) FROM verified_targets WHERE workspace_id=? AND revoked_at IS NULL "
            "AND verified_at IS NOT NULL AND verified_at > ?",
            (workspace_id, _now() - REVERIFY_AFTER)).fetchone()[0]

    def verified_count(self, workspace_id: str) -> int:
        return self._verified_count_locked(workspace_id)
