"""
Heel hosted — target ownership verification (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

No real-target run at any tier without proof of control. Two challenge methods:
- DNS TXT: `heel-verify=<token>` on `_heel.<domain>`
- HTTP file: GET https://<domain>/.well-known/heel-verify.txt containing the token

Resolution is injected (callables), so this module is fully offline-testable and the production
resolver/fetcher swap in without code change. Challenges expire; verified status is periodically
re-checkable and revocable.
"""
from __future__ import annotations

import os
import re
import secrets
import hashlib
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Callable

from heel.canary_contracts import canonical_digest

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
            else int(os.environ.get("HEEL_MAX_WORKSPACES_PER_HOSTNAME",
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
                         dns_record=f"_heel.{h} TXT \"heel-verify={token}\"",
                         http_url=f"https://{h}/.well-known/heel-verify.txt")

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
                if any(f"heel-verify={token}" in str(r) for r in self.dns_txt(f"_heel.{h}")):
                    method = "dns_txt"
            except Exception:
                pass
        if method is None and self.http_get is not None:
            try:
                if token in self.http_get(f"https://{h}/.well-known/heel-verify.txt"):
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


# VerifiedEnvironment.v1 is intentionally separate from the legacy hostname-only target flow.
# Legacy /targets remains compatible and has its own meter; canary execution consumes only this
# project-bound exact-origin record.
VERIFIED_ENVIRONMENT_SCHEMA_VERSION = "VerifiedEnvironment.v1"
VERIFICATION_RECORD_SCHEMA_VERSION = "heel.environment-verification-record.v1"
NORMALIZATION_VERSION = "exact-origin.v1"
HTTPS_PROOF_VERSION = "https-file.v1"
DNS_PROOF_VERSION = "dns-txt.v1"
OWNERSHIP_ATTESTATION = "ownership verified; environment classification supplied by you"
ATTESTATION_VERSION = "v1"
ATTESTATION_ACKNOWLEDGEMENT = "accepted"
ENVIRONMENT_CHALLENGE_TTL = 24 * 3600
ENVIRONMENT_PROOF_TTL = 30 * 24 * 3600
ENVIRONMENT_CHECK_COOLDOWN = 5
_ENVIRONMENT_CLASSES = frozenset({"staging", "sandbox", "production"})
_FAILURE_CODES = frozenset({
    "challenge_expired", "challenge_missing", "challenge_replaced", "cooldown",
    "dns_proof_mismatch", "https_proof_mismatch", "network_rejected", "network_timeout",
    "proof_revoked", "quota_exceeded", "hostname_reuse_exceeded", "internal_error",
})


class EnvironmentNotFound(LookupError):
    pass


class EnvironmentCooldown(Exception):
    pass


@dataclass(frozen=True)
class EnvironmentChallenge:
    environment_id: str
    workspace_id: str
    project_ref: str
    origin: str
    environment_class: str
    token: str
    generation: int
    expires_at: float
    attestation: str = OWNERSHIP_ATTESTATION

    @property
    def http_url(self) -> str:
        return self.origin + "/.well-known/heel-verify.txt"


class VerifiedEnvironmentService:
    """Project-scoped environment proof state with snapshot/network/finalize semantics."""
    def __init__(self, conn: sqlite3.Connection, *, https_verifier=None, dns_txt=None,
                 max_workspaces_per_hostname: int | None = None, clock: Callable[[], float] = _now,
                 lock: threading.RLock | None = None):
        from .canary_store import CanaryStore
        self.conn = conn
        CanaryStore(conn)  # install the exact runtime/migration schema without a second identity
        self.https_verifier = https_verifier
        self.dns_txt = dns_txt
        self.clock = clock
        self._db_lock = lock if lock is not None else threading.RLock()
        self.max_workspaces_per_hostname = (
            MAX_WORKSPACES_PER_HOSTNAME if max_workspaces_per_hostname is None
            else max_workspaces_per_hostname
        )

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    @staticmethod
    def _origin_host(origin: str) -> str:
        return origin[len("https://"):]

    def _now(self) -> float:
        return float(self.clock())

    def _row(self, workspace_id: str, project_ref: str, environment_id: str):
        with self._db_lock:
            return self.conn.execute(
                "SELECT * FROM canary_environments WHERE workspace_id=? AND project_ref=? AND environment_id=?",
                (workspace_id, project_ref, environment_id),
            ).fetchone()

    def start(self, workspace_id: str, project_ref: str, origin: str, environment_class: str,
              *, actor: str, attestation_text: str, attestation_version: str,
              attestation_acknowledgement: str, proof_method: str = "https-file") -> EnvironmentChallenge:
        from .network_guard import OriginValidationError, normalize_verified_origin
        if type(environment_class) is not str or environment_class not in _ENVIRONMENT_CLASSES:
            raise ValueError("environment_class must be staging, sandbox, or production")
        if proof_method not in {"https-file", "dns-txt"}:
            raise ValueError("proof_method is invalid")
        if (attestation_text != OWNERSHIP_ATTESTATION or attestation_version != ATTESTATION_VERSION
                or attestation_acknowledgement != ATTESTATION_ACKNOWLEDGEMENT):
            raise ValueError("exact ownership attestation is required")
        try:
            normalized = normalize_verified_origin(origin)
        except OriginValidationError as exc:
            raise ValueError("origin must be an exact public https origin") from exc
        if type(actor) is not str or not actor or len(actor) > 256:
            raise ValueError("actor is invalid")
        now = self._now()
        token = secrets.token_urlsafe(32)
        digest = self._digest(token)
        expires_at = now + ENVIRONMENT_CHALLENGE_TTL
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            project = self.conn.execute(
                "SELECT 1 FROM projects WHERE workspace_id=? AND project_ref=?", (workspace_id, project_ref)
            ).fetchone()
            if project is None:
                raise EnvironmentNotFound("project not found")
            existing = self.conn.execute(
                "SELECT * FROM canary_environments WHERE workspace_id=? AND project_ref=? AND origin=?",
                (workspace_id, project_ref, normalized),
            ).fetchone()
            if existing is None:
                environment_id = f"env_{secrets.token_hex(16)}"
                generation = 1
                self.conn.execute(
                    "INSERT INTO canary_environments(environment_id,workspace_id,project_ref,origin,environment_class,status,created_at,"
                    "attestation_text,attestation_version,attestation_acknowledgement,attested_by,attested_at,proof_method,proof_version,normalization_version,"
                    "challenge_generation,challenge_digest,challenge_token,challenge_created_at,challenge_expires_at,last_failure_code,"
                    "verified_at,proof_expires_at,revoked_at,revoked_by,revoked_reason) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (environment_id, workspace_id, project_ref, normalized, environment_class, "pending", now,
                     attestation_text, attestation_version, attestation_acknowledgement, actor, now, proof_method,
                     HTTPS_PROOF_VERSION if proof_method == "https-file" else DNS_PROOF_VERSION, NORMALIZATION_VERSION,
                     generation, digest, token, now, expires_at, None, None, None, None, None, None),
                )
            else:
                environment_id = existing["environment_id"]
                generation = int(existing["challenge_generation"] or 0) + 1
                self.conn.execute(
                    "UPDATE canary_environments SET environment_class=?,status='pending',attestation_text=?,"
                    "attestation_version=?,attestation_acknowledgement=?,attested_by=?,attested_at=?,proof_method=?,proof_version=?,normalization_version=?,"
                    "challenge_generation=?,challenge_digest=?,challenge_token=?,challenge_created_at=?,challenge_expires_at=?,"
                    "last_check_at=NULL,last_failure_code='challenge_replaced',verified_at=NULL,proof_expires_at=NULL,revoked_at=NULL,"
                    "revoked_by=NULL,revoked_reason=NULL,verification_record_digest=NULL "
                    "WHERE workspace_id=? AND project_ref=? AND environment_id=?",
                    (environment_class, attestation_text, attestation_version, attestation_acknowledgement, actor, now,
                     proof_method, HTTPS_PROOF_VERSION if proof_method == "https-file" else DNS_PROOF_VERSION,
                     NORMALIZATION_VERSION, generation, digest, token, now, expires_at,
                     workspace_id, project_ref, environment_id),
                )
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.rollback()
            raise
        return EnvironmentChallenge(environment_id, workspace_id, project_ref, normalized, environment_class,
                                    token, generation, expires_at)

    def _record_failure(self, workspace_id: str, project_ref: str, environment_id: str,
                        generation: int, code: str, *, expected_digest: str | None = None,
                        token: str | None = None) -> None:
        if code not in _FAILURE_CODES:
            code = "internal_error"
        if (expected_digest is None) != (token is None):
            raise ValueError("failure challenge identity must include digest and token together")
        with self._db_lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                identity_clause = ""
                values: list[object] = [code, self._now(), workspace_id, project_ref, environment_id, generation]
                if expected_digest is not None:
                    identity_clause = " AND challenge_digest=? AND challenge_token=?"
                    values.extend((expected_digest, token))
                self.conn.execute(
                    "UPDATE canary_environments SET last_failure_code=?,last_check_at=? "
                    "WHERE workspace_id=? AND project_ref=? AND environment_id=? AND challenge_generation=? "
                    "AND status='pending' AND revoked_at IS NULL" + identity_clause,
                    values,
                )
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.rollback()
                raise

    def check(self, workspace_id: str, project_ref: str, environment_id: str, *,
              max_verified: int | None = None) -> bool:
        """Network proof is deliberately outside any SQLite transaction or HTTP request lock."""
        row = self._row(workspace_id, project_ref, environment_id)
        if row is None:
            raise EnvironmentNotFound("environment not found")
        now = self._now()
        if row["revoked_at"] is not None:
            self._record_failure(workspace_id, project_ref, environment_id, row["challenge_generation"], "proof_revoked")
            return False
        if row["status"] != "pending" or not row["challenge_token"]:
            self._record_failure(workspace_id, project_ref, environment_id, row["challenge_generation"], "challenge_missing")
            return False
        if now >= row["challenge_expires_at"]:
            self._record_failure(workspace_id, project_ref, environment_id, row["challenge_generation"], "challenge_expired")
            return False
        # Claim the cooldown before network I/O. This is intentionally a short transaction, then
        # released: concurrent check callers cannot fan out identical proof requests.
        with self._db_lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                fresh = self._row(workspace_id, project_ref, environment_id)
                if (fresh is None or fresh["challenge_generation"] != row["challenge_generation"]
                        or fresh["status"] != "pending" or fresh["revoked_at"] is not None
                        or fresh["challenge_token"] != row["challenge_token"]
                        or fresh["challenge_expires_at"] <= now):
                    self.conn.execute("ROLLBACK")
                    return False
                if fresh["last_check_at"] is not None and now - fresh["last_check_at"] < ENVIRONMENT_CHECK_COOLDOWN:
                    self.conn.execute("ROLLBACK")
                    raise EnvironmentCooldown("environment check is cooling down")
                self.conn.execute(
                    "UPDATE canary_environments SET last_check_at=? WHERE workspace_id=? AND project_ref=? "
                    "AND environment_id=? AND challenge_generation=?",
                    (now, workspace_id, project_ref, environment_id, fresh["challenge_generation"]),
                )
                self.conn.execute("COMMIT")
                row = fresh
            except EnvironmentCooldown:
                raise
            except Exception:
                self.conn.rollback()
                raise
        generation, expected_digest, token = row["challenge_generation"], row["challenge_digest"], row["challenge_token"]
        try:
            if row["proof_method"] == "dns-txt":
                if self.dns_txt is None:
                    observed = []
                elif hasattr(self.dns_txt, "txt"):
                    observed = self.dns_txt.txt(self._origin_host(row["origin"]))
                else:
                    observed = self.dns_txt("_heel." + self._origin_host(row["origin"]))
                valid = any(str(value) == "heel-verify=" + token for value in observed)
                failure = "dns_proof_mismatch"
            else:
                observed = self.https_verifier.verify(row["origin"]) if self.https_verifier else None
                valid = type(observed) is str and hashlib.sha256(observed.encode("ascii")).hexdigest() == expected_digest
                failure = "https_proof_mismatch"
        except TimeoutError:
            valid, failure = False, "network_timeout"
        except Exception as exc:
            if type(exc).__name__ in {"VerificationTimeout", "DNSResolutionTimeout", "LifetimeTimeout", "Timeout"}:
                valid, failure = False, "network_timeout"
            else:
                valid, failure = False, "network_rejected"
        if not valid:
            self._record_failure(workspace_id, project_ref, environment_id, generation, failure)
            return False
        return self._finalize_success(workspace_id, project_ref, environment_id, generation,
                                      expected_digest, token, max_verified)

    def _finalize_success(self, workspace_id: str, project_ref: str, environment_id: str,
                          generation: int, expected_digest: str, token: str,
                          max_verified: int | None) -> bool:
        """The second half of check: one short, serializable DB transaction after network I/O."""
        with self._db_lock:
            now = self._now()
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                fresh = self._row(workspace_id, project_ref, environment_id)
                failure_code: str | None = None
                if fresh is None:
                    failure_code = "challenge_missing"
                elif fresh["revoked_at"] is not None:
                    failure_code = "proof_revoked"
                elif fresh["status"] != "pending" or not fresh["challenge_token"]:
                    failure_code = "challenge_missing"
                elif (fresh["challenge_generation"] != generation
                      or fresh["challenge_digest"] != expected_digest
                      or fresh["challenge_token"] != token):
                    failure_code = "challenge_replaced"
                elif fresh["challenge_expires_at"] <= now:
                    failure_code = "challenge_expired"
                elif (fresh["attestation_text"] != OWNERSHIP_ATTESTATION
                      or fresh["attestation_version"] != ATTESTATION_VERSION
                      or fresh["attestation_acknowledgement"] != ATTESTATION_ACKNOWLEDGEMENT):
                    failure_code = "internal_error"
                if failure_code is not None:
                    self.conn.execute("ROLLBACK")
                    self._record_failure(
                        workspace_id, project_ref, environment_id, generation, failure_code,
                        expected_digest=expected_digest, token=token,
                    )
                    return False
                if max_verified is not None and self._active_count_locked(workspace_id, project_ref, now) >= max_verified:
                    self.conn.execute("ROLLBACK")
                    raise TargetLimitExceeded("verified environment limit reached")
                hostname = self._origin_host(fresh["origin"])
                if self.max_workspaces_per_hostname >= 0:
                    other_count = self.conn.execute(
                        "SELECT COUNT(DISTINCT workspace_id) AS n FROM canary_environments WHERE origin=? "
                        "AND workspace_id!=? AND status='verified' AND revoked_at IS NULL AND proof_expires_at>?",
                        (fresh["origin"], workspace_id, now),
                    ).fetchone()["n"]
                    if other_count >= self.max_workspaces_per_hostname:
                        self.conn.execute("ROLLBACK")
                        raise HostnameReuseExceeded(f"{hostname} is already verified in other workspaces")
                proof_expires_at = now + ENVIRONMENT_PROOF_TTL
                verification_record = {
                    "schema_version": VERIFICATION_RECORD_SCHEMA_VERSION,
                    "workspace_id": workspace_id,
                    "project_id": project_ref,
                    "environment_id": environment_id,
                    "origin": fresh["origin"],
                    "environment_class": fresh["environment_class"],
                    "attestation_text": fresh["attestation_text"],
                    "attestation_version": fresh["attestation_version"],
                    "attestation_acknowledgement": fresh["attestation_acknowledgement"],
                    "proof_method": fresh["proof_method"],
                    "proof_version": fresh["proof_version"],
                    "normalization_version": fresh["normalization_version"],
                    "challenge_generation": int(generation),
                    "verified_at_ms": max(0, int(now * 1000)),
                    "proof_expires_at_ms": max(0, int(proof_expires_at * 1000)),
                }
                verification_record_digest = canonical_digest(verification_record)
                self.conn.execute(
                    "UPDATE canary_environments SET status='verified',verified_at=?,proof_expires_at=?,"
                    "challenge_token=NULL,last_check_at=?,last_failure_code=NULL,verification_record_digest=? "
                    "WHERE workspace_id=? AND project_ref=? "
                    "AND environment_id=? AND challenge_generation=?",
                    (now, proof_expires_at, now, verification_record_digest,
                     workspace_id, project_ref, environment_id, generation),
                )
                self.conn.execute("COMMIT")
                return True
            except TargetLimitExceeded:
                self._record_failure(
                    workspace_id, project_ref, environment_id, generation, "quota_exceeded",
                    expected_digest=expected_digest, token=token,
                )
                raise
            except HostnameReuseExceeded:
                self._record_failure(
                    workspace_id, project_ref, environment_id, generation, "hostname_reuse_exceeded",
                    expected_digest=expected_digest, token=token,
                )
                raise
            except Exception:
                self.conn.rollback()
                raise

    def revoke(self, workspace_id: str, project_ref: str, environment_id: str, *, actor: str, reason: str) -> bool:
        now = self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = self.conn.execute(
                "UPDATE canary_environments SET status='revoked',revoked_at=?,revoked_by=?,revoked_reason=?,"
                "challenge_token=NULL,last_failure_code='proof_revoked' WHERE workspace_id=? AND project_ref=? "
                "AND environment_id=? AND revoked_at IS NULL",
                (now, actor, reason[:512], workspace_id, project_ref, environment_id),
            )
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.rollback()
            raise
        return cursor.rowcount == 1

    def is_executable(self, workspace_id: str, project_ref: str, environment_id: str) -> bool:
        row = self._row(workspace_id, project_ref, environment_id)
        return bool(row and row["environment_class"] in {"staging", "sandbox"} and row["status"] == "verified"
                    and row["attestation_text"] == OWNERSHIP_ATTESTATION
                    and row["attestation_version"] == ATTESTATION_VERSION
                    and row["attestation_acknowledgement"] == ATTESTATION_ACKNOWLEDGEMENT
                    and row["verification_record_digest"] is not None
                    and row["revoked_at"] is None
                    and row["verified_at"] is not None and row["proof_expires_at"] is not None
                    and row["proof_expires_at"] > self._now())

    def list(self, workspace_id: str, project_ref: str) -> list[dict[str, object]]:
        rows = self.conn.execute(
            "SELECT * FROM canary_environments WHERE workspace_id=? AND project_ref=? ORDER BY created_at,environment_id",
            (workspace_id, project_ref),
        ).fetchall()
        return [self.public_record(row) for row in rows]

    @staticmethod
    def public_record(row) -> dict[str, object]:
        return {
            "schema_version": VERIFIED_ENVIRONMENT_SCHEMA_VERSION,
            "environment_id": row["environment_id"], "origin": row["origin"],
            "environment_class": row["environment_class"], "status": row["status"],
            "attestation": row["attestation_text"], "attestation_version": row["attestation_version"],
            "attestation_acknowledgement": row["attestation_acknowledgement"],
            "proof_method": row["proof_method"], "proof_version": row["proof_version"],
            "normalization_version": row["normalization_version"], "challenge_generation": row["challenge_generation"],
            "challenge_expires_at": row["challenge_expires_at"], "last_failure_code": row["last_failure_code"],
            "verified_at": row["verified_at"], "proof_expires_at": row["proof_expires_at"],
            "verification_record_digest": row["verification_record_digest"],
            "revoked_at": row["revoked_at"], "is_executable": False,
        }

    def _active_count_locked(self, workspace_id: str, project_ref: str, now: float) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) FROM canary_environments WHERE workspace_id=? "
            "AND status='verified' AND revoked_at IS NULL AND proof_expires_at>?",
            (workspace_id, now),
        ).fetchone()[0]


# A concise public name for consumers that should not learn implementation details.
VerifiedEnvironment = VerifiedEnvironmentService
