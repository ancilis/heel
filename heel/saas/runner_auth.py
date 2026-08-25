"""Runner pairing and rotating proof-of-possession authentication.

This is intentionally separate from browser, API-key, and device authentication.
Runner requests prove control of an Ed25519 key for one fixed route and then consume
a one-time, domain-hashed nonce in the same small database transaction as the action.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from heel.canary_contracts import (
    canonical_bytes, canonical_digest, parse_json, validate_runner_identity,
)
from heel.crypto import ed25519_key_id, load_public_key_base64
from heel.runner.identity import runner_phrase_words, validate_pairing_phrase


PAIRING_TTL = 10 * 60
NONCE_TTL = 60
CLOCK_SKEW_MS = 30_000
MAX_RUNNER_BODY = 64 * 1024
RUNNER_CAPABILITIES = ("runner_claim", "runner_heartbeat", "runner_progress", "runner_result")


RUNNER_AUTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS canary_runner_pairings(
  pairing_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  invitation_hash TEXT NOT NULL UNIQUE, phrase TEXT, public_key TEXT, fingerprint TEXT,
  key_id TEXT, runner_version TEXT, adapters_json TEXT, activation_challenge TEXT,
  status TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
  approved_at REAL, activated_at REAL, approved_by TEXT,
  UNIQUE(workspace_id, runner_id));
CREATE TABLE IF NOT EXISTS canary_runner_nonce_chains(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
  nonce_hash TEXT NOT NULL, next_sequence INTEGER NOT NULL, expires_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, runner_id, chain_name));
CREATE TABLE IF NOT EXISTS canary_runner_request_ledger(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
  sequence INTEGER NOT NULL, request_digest TEXT NOT NULL, response_json TEXT NOT NULL,
  next_nonce TEXT NOT NULL, created_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, runner_id, chain_name, sequence));
CREATE INDEX IF NOT EXISTS idx_canary_runner_pairings_expiry
 ON canary_runner_pairings(expires_at);
CREATE INDEX IF NOT EXISTS idx_canary_runner_ledger_cleanup
 ON canary_runner_request_ledger(created_at);
CREATE TABLE IF NOT EXISTS canary_runner_rotations(
  pairing_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  phrase TEXT NOT NULL, public_key TEXT NOT NULL, fingerprint TEXT NOT NULL, key_id TEXT NOT NULL,
  runner_version TEXT NOT NULL, adapters_json TEXT NOT NULL, activation_challenge TEXT,
  status TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
  approved_at REAL, activated_at REAL, approved_by TEXT);
"""

# Migration nine established the isolated tables.  Migration ten only appends columns: it
# never rewrites that applied schema, and makes a replay receipt attest the entire verified
# request rather than merely its body.
RUNNER_AUTH_HARDENING_MIGRATION = """
ALTER TABLE canary_runner_request_ledger ADD COLUMN nonce_hash TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN key_id TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN capability TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN method TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN path TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN timestamp_ms INTEGER;
ALTER TABLE canary_runner_request_ledger ADD COLUMN signed_request_digest TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN body_digest TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN response_ciphertext TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN next_nonce_ciphertext TEXT;
"""

# Migration eleven intentionally leaves migrations 9 and 10 byte-stable.  The runner tables
# below are rebuilt where SQLite permits it, adding tenant FKs and vocabulary checks; the
# identity/audit tables are new immutable lifecycle projections.
RUNNER_AUTH_LIFECYCLE_MIGRATION = """
ALTER TABLE canary_runner_pairings RENAME TO canary_runner_pairings_v10;
CREATE TABLE canary_runner_pairings(
  pairing_id TEXT PRIMARY KEY CHECK(length(pairing_id) BETWEEN 1 AND 128),
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  invitation_hash TEXT NOT NULL UNIQUE CHECK(length(invitation_hash)=64 AND invitation_hash NOT GLOB '*[^0-9a-f]*'),
  phrase TEXT, public_key TEXT, fingerprint TEXT, key_id TEXT, runner_version TEXT,
  adapters_json TEXT, activation_challenge TEXT,
  status TEXT NOT NULL CHECK(status IN ('invited','pending','approved','activated','expired')),
  created_at REAL NOT NULL, expires_at REAL NOT NULL, approved_at REAL, activated_at REAL, approved_by TEXT,
  UNIQUE(workspace_id, runner_id), FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id));
INSERT INTO canary_runner_pairings SELECT * FROM canary_runner_pairings_v10;
DROP TABLE canary_runner_pairings_v10;
ALTER TABLE canary_runner_nonce_chains RENAME TO canary_runner_nonce_chains_v10;
CREATE TABLE canary_runner_nonce_chains(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
  nonce_hash TEXT NOT NULL CHECK(length(nonce_hash)=64 AND nonce_hash NOT GLOB '*[^0-9a-f]*'),
  next_sequence INTEGER NOT NULL CHECK(next_sequence >= 1), expires_at REAL NOT NULL,
  PRIMARY KEY(workspace_id,runner_id,chain_name),
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
INSERT INTO canary_runner_nonce_chains SELECT * FROM canary_runner_nonce_chains_v10;
DROP TABLE canary_runner_nonce_chains_v10;
ALTER TABLE canary_runner_request_ledger RENAME TO canary_runner_request_ledger_v10;
CREATE TABLE canary_runner_request_ledger(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence >= 1), request_digest TEXT NOT NULL,
  response_json TEXT NOT NULL, next_nonce TEXT NOT NULL, created_at REAL NOT NULL,
  nonce_hash TEXT, key_id TEXT, capability TEXT CHECK(capability IN ('runner_claim','runner_heartbeat','runner_progress','runner_result')),
  method TEXT CHECK(method='POST'), path TEXT, timestamp_ms INTEGER CHECK(timestamp_ms >= 0),
  signed_request_digest TEXT, body_digest TEXT, response_ciphertext TEXT, next_nonce_ciphertext TEXT,
  PRIMARY KEY(workspace_id,runner_id,chain_name,sequence),
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
INSERT INTO canary_runner_request_ledger SELECT * FROM canary_runner_request_ledger_v10;
DROP TABLE canary_runner_request_ledger_v10;
ALTER TABLE canary_runner_rotations RENAME TO canary_runner_rotations_v10;
CREATE TABLE canary_runner_rotations(
  pairing_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  phrase TEXT NOT NULL, public_key TEXT NOT NULL, fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64 AND fingerprint NOT GLOB '*[^0-9a-f]*'),
  key_id TEXT NOT NULL, runner_version TEXT NOT NULL, adapters_json TEXT NOT NULL, activation_challenge TEXT,
  status TEXT NOT NULL CHECK(status IN ('rotation_pending','rotation_approved','rotated','expired')),
  created_at REAL NOT NULL, expires_at REAL NOT NULL, approved_at REAL, activated_at REAL, approved_by TEXT,
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
INSERT INTO canary_runner_rotations SELECT * FROM canary_runner_rotations_v10;
DROP TABLE canary_runner_rotations_v10;
CREATE TABLE IF NOT EXISTS canary_runner_identity_records(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, identity_json TEXT NOT NULL,
  identity_digest TEXT NOT NULL CHECK(length(identity_digest)=64 AND identity_digest NOT GLOB '*[^0-9a-f]*'),
  updated_at REAL NOT NULL, PRIMARY KEY(workspace_id,runner_id), UNIQUE(identity_digest),
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
CREATE TABLE IF NOT EXISTS canary_runner_audit_records(
  audit_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('runner_revoked','runner_rotated','runner_activated')),
  actor TEXT NOT NULL, reason_code TEXT, created_at REAL NOT NULL,
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
UPDATE canary_runners SET status='disabled' WHERE status='active';
"""

# A new in-process ControlPlane has no runner-auth rows to preserve.  Build its tables directly
# at the v11 shape instead of creating v9 then replaying a destructive rename/copy migration.
# Existing durable databases are upgraded exclusively by the append-only migration list above.
RUNNER_AUTH_RUNTIME_SCHEMA = """
CREATE TABLE IF NOT EXISTS canary_runner_pairings(
  pairing_id TEXT PRIMARY KEY CHECK(length(pairing_id) BETWEEN 1 AND 128),
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  invitation_hash TEXT NOT NULL UNIQUE CHECK(length(invitation_hash)=64 AND invitation_hash NOT GLOB '*[^0-9a-f]*'),
  phrase TEXT, public_key TEXT, fingerprint TEXT, key_id TEXT, runner_version TEXT,
  adapters_json TEXT, activation_challenge TEXT,
  status TEXT NOT NULL CHECK(status IN ('invited','pending','approved','activated','expired')),
  created_at REAL NOT NULL, expires_at REAL NOT NULL, approved_at REAL, activated_at REAL, approved_by TEXT,
  UNIQUE(workspace_id, runner_id), FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id));
CREATE TABLE IF NOT EXISTS canary_runner_nonce_chains(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
  nonce_hash TEXT NOT NULL CHECK(length(nonce_hash)=64 AND nonce_hash NOT GLOB '*[^0-9a-f]*'),
  next_sequence INTEGER NOT NULL CHECK(next_sequence >= 1), expires_at REAL NOT NULL,
  PRIMARY KEY(workspace_id,runner_id,chain_name),
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
CREATE TABLE IF NOT EXISTS canary_runner_request_ledger(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence >= 1), request_digest TEXT NOT NULL,
  response_json TEXT NOT NULL, next_nonce TEXT NOT NULL, created_at REAL NOT NULL,
  nonce_hash TEXT, key_id TEXT, capability TEXT CHECK(capability IN ('runner_claim','runner_heartbeat','runner_progress','runner_result')),
  method TEXT CHECK(method='POST'), path TEXT, timestamp_ms INTEGER CHECK(timestamp_ms >= 0),
  signed_request_digest TEXT, body_digest TEXT, response_ciphertext TEXT, next_nonce_ciphertext TEXT,
  PRIMARY KEY(workspace_id,runner_id,chain_name,sequence),
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
CREATE TABLE IF NOT EXISTS canary_runner_rotations(
  pairing_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  phrase TEXT NOT NULL, public_key TEXT NOT NULL, fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64 AND fingerprint NOT GLOB '*[^0-9a-f]*'),
  key_id TEXT NOT NULL, runner_version TEXT NOT NULL, adapters_json TEXT NOT NULL, activation_challenge TEXT,
  status TEXT NOT NULL CHECK(status IN ('rotation_pending','rotation_approved','rotated','expired')),
  created_at REAL NOT NULL, expires_at REAL NOT NULL, approved_at REAL, activated_at REAL, approved_by TEXT,
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
CREATE TABLE IF NOT EXISTS canary_runner_identity_records(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, identity_json TEXT NOT NULL,
  identity_digest TEXT NOT NULL CHECK(length(identity_digest)=64 AND identity_digest NOT GLOB '*[^0-9a-f]*'),
  updated_at REAL NOT NULL, PRIMARY KEY(workspace_id,runner_id), UNIQUE(identity_digest),
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
CREATE TABLE IF NOT EXISTS canary_runner_audit_records(
  audit_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('runner_revoked','runner_rotated','runner_activated')),
  actor TEXT NOT NULL, reason_code TEXT, created_at REAL NOT NULL,
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
"""


class RunnerAuthError(PermissionError):
    """Uniform external runner-auth failure."""


@dataclass(frozen=True)
class PairingInvitation:
    token: str
    expires_at: float


@dataclass(frozen=True)
class PairingView:
    pairing_id: str
    runner_id: str
    phrase: str
    fingerprint: str
    status: str
    expires_at: float
    activation_challenge: str | None = None


def _now() -> float:
    return time.time()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _token() -> str:
    return _b64(secrets.token_bytes(32))


WORDS = runner_phrase_words()


def _ensure_hardened_ledger_schema(conn: sqlite3.Connection) -> None:
    present = {row[1] for row in conn.execute("PRAGMA table_info(canary_runner_request_ledger)")}
    for statement in RUNNER_AUTH_HARDENING_MIGRATION.strip().split(";"):
        statement = statement.strip()
        if not statement:
            continue
        column = statement.split()[5]
        if column not in present:
            conn.execute(statement)
            present.add(column)


def _ensure_lifecycle_tables(conn: sqlite3.Connection) -> None:
    """Install v11's additive identity/audit tables for direct runtime construction.

    The migration owns the constrained table rebuild; direct in-memory ControlPlane instances
    start from an empty v9 schema and require the same observable table/column shape without
    replaying a destructive migration.
    """
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS canary_runner_identity_records(
      workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, identity_json TEXT NOT NULL,
      identity_digest TEXT NOT NULL CHECK(length(identity_digest)=64 AND identity_digest NOT GLOB '*[^0-9a-f]*'),
      updated_at REAL NOT NULL, PRIMARY KEY(workspace_id,runner_id), UNIQUE(identity_digest));
    CREATE TABLE IF NOT EXISTS canary_runner_audit_records(
      audit_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
      action TEXT NOT NULL CHECK(action IN ('runner_revoked','runner_rotated','runner_activated')),
      actor TEXT NOT NULL, reason_code TEXT, created_at REAL NOT NULL);
    """)


_RUNNER_AUTH_TABLES = ("canary_runner_pairings", "canary_runner_nonce_chains", "canary_runner_request_ledger", "canary_runner_rotations", "canary_runner_identity_records", "canary_runner_audit_records")


def validate_runner_auth_schema(conn: sqlite3.Connection) -> None:
    """Read-only exact v11 schema validation; startup must migrate rather than repair."""
    if not isinstance(conn, sqlite3.Connection):
        raise TypeError("runner authentication requires a SQLite connection")
    expected = sqlite3.connect(":memory:")
    try:
        expected.executescript(RUNNER_AUTH_RUNTIME_SCHEMA)
        for table in _RUNNER_AUTH_TABLES:
            actual = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            wanted = expected.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            if actual is None or wanted is None or "".join(actual[0].split()) != "".join(wanted[0].split()):
                raise RuntimeError("runner authentication schema is not current")
            for pragma in ("foreign_key_list", "index_list"):
                if [tuple(row) for row in conn.execute(f"PRAGMA {pragma}({table})")] != [tuple(row) for row in expected.execute(f"PRAGMA {pragma}({table})")]:
                    raise RuntimeError("runner authentication schema is not current")
        if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise RuntimeError("runner authentication schema has foreign-key violations")
    finally:
        expected.close()


def initialize_runner_auth_schema(conn: sqlite3.Connection) -> None:
    """Startup-only creation for a fresh local ControlPlane; never repairs old databases."""
    if not isinstance(conn, sqlite3.Connection):
        raise TypeError("runner authentication requires a SQLite connection")
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='canary_runner_pairings'").fetchone() is None:
        conn.executescript(RUNNER_AUTH_RUNTIME_SCHEMA)
    validate_runner_auth_schema(conn)


class RunnerAuthStore:
    def __init__(self, conn: sqlite3.Connection, *, pepper: bytes, now: Callable[[], float] = _now):
        if not isinstance(pepper, bytes) or not 32 <= len(pepper) <= 64:
            raise ValueError("runner authentication pepper must be 32 to 64 bytes")
        self.conn, self._pepper, self._now = conn, pepper, now
        self.conn.row_factory = sqlite3.Row

    def _ensure_hardened_ledger(self) -> None:
        _ensure_hardened_ledger_schema(self.conn)

    def _ensure_lifecycle_schema(self) -> None:
        """Runtime parity for new databases; migrated production gets these through v11."""
        _ensure_lifecycle_tables(self.conn)

    def _seal(self, value: str, *, aad: bytes) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        key = hashlib.sha256(b"heel.runner-ledger-aead.v1\0" + self._pepper).digest()
        nonce = secrets.token_bytes(12)
        return _b64(nonce + ChaCha20Poly1305(key).encrypt(nonce, value.encode("utf-8"), aad))

    def _open(self, value: str, *, aad: bytes) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        raw = base64.b64decode(value, validate=True)
        if len(raw) < 29:
            raise ValueError
        key = hashlib.sha256(b"heel.runner-ledger-aead.v1\0" + self._pepper).digest()
        return ChaCha20Poly1305(key).decrypt(raw[:12], raw[12:], aad).decode("utf-8")

    def _hash(self, domain: str, value: str) -> str:
        return hmac.new(self._pepper, domain.encode("ascii") + b"\0" + value.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _milliseconds(instant: float) -> int:
        return max(0, int(instant * 1000))

    def _identity_record(self, *, workspace_id: str, runner_id: str, public_key: str,
                         fingerprint: str, key_id: str, runner_version: str,
                         adapters_json: str, paired_by: str, paired_at: float,
                         heartbeat_at: float, state: str = "active",
                         previous_key_ids: list[str] | None = None,
                         rotated_at: float | None = None,
                         overlap_ends_at: float | None = None,
                         revoked_at: float | None = None, revoked_by: str | None = None,
                         reason_code: str | None = None) -> dict:
        try:
            adapters = json.loads(adapters_json or "{}")
            versions = sorted(set(adapters.values()))
        except (TypeError, ValueError):
            raise RunnerAuthError("invalid runner identity") from None
        base = {
            "schema_version": "heel.runner-identity.v1", "runner_id": runner_id,
            "workspace_id": workspace_id,
            "public_key": {"algorithm": "Ed25519", "key_id": key_id,
                           "public_key_b64": public_key},
            "fingerprint": fingerprint, "runner_version": runner_version,
            "adapter_versions": versions,
            "capabilities": list(RUNNER_CAPABILITIES),
            "pairing": {"paired_by": paired_by, "paired_at_ms": self._milliseconds(paired_at),
                        "fingerprint_confirmation": "confirmed", "phrase_confirmation": "confirmed"},
            "last_heartbeat_at_ms": self._milliseconds(heartbeat_at), "state": state,
            "rotation": {"previous_key_ids": sorted(previous_key_ids or []),
                         "rotated_at_ms": None if rotated_at is None else self._milliseconds(rotated_at),
                         "verification_overlap_ends_at_ms": None if overlap_ends_at is None else self._milliseconds(overlap_ends_at)},
            "revocation": {"revoked_at_ms": None if revoked_at is None else self._milliseconds(revoked_at),
                           "revoked_by": revoked_by, "reason_code": reason_code},
        }
        base["identity_digest"] = canonical_digest(base)
        return validate_runner_identity(base)

    def _save_identity(self, record: dict, *, instant: float) -> dict:
        validated = validate_runner_identity(record)
        self.conn.execute(
            "INSERT OR REPLACE INTO canary_runner_identity_records(workspace_id,runner_id,identity_json,identity_digest,updated_at) VALUES(?,?,?,?,?)",
            (validated["workspace_id"], validated["runner_id"], canonical_bytes(validated).decode("utf-8"),
             validated["identity_digest"], instant),
        )
        return validated

    def _load_identity(self, workspace_id: str, runner_id: str) -> dict:
        row = self.conn.execute("SELECT identity_json FROM canary_runner_identity_records WHERE workspace_id=? AND runner_id=?", (workspace_id, runner_id)).fetchone()
        if row is None:
            raise RunnerAuthError("invalid runner identity")
        try:
            return validate_runner_identity(json.loads(row["identity_json"]))
        except (TypeError, ValueError):
            raise RunnerAuthError("invalid runner identity") from None

    def _save_changed_identity(self, identity: dict, *, instant: float) -> dict:
        identity["identity_digest"] = canonical_digest({key: value for key, value in identity.items() if key != "identity_digest"})
        return self._save_identity(identity, instant=instant)

    def identity(self, workspace_id: str, runner_id: str) -> dict:
        """Return a detached validated cloud identity projection, never local key material."""
        return self._load_identity(workspace_id, runner_id)

    @staticmethod
    def _identifier(value: object, field: str) -> str:
        if type(value) is not str or not value or len(value.encode("utf-8")) > 128 or value.strip() != value:
            raise ValueError(f"invalid {field}")
        return value

    @staticmethod
    def _phrase(value: object) -> str:
        return validate_pairing_phrase(value)

    def invite(self, workspace_id: str) -> PairingInvitation:
        self._identifier(workspace_id, "workspace")
        token, instant = _token(), self._now()
        # Invitation is intentionally a pairing row only after runner exchange, so it is
        # returned exactly once and the raw value never reaches persistent storage.
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.execute("DELETE FROM canary_runner_pairings WHERE expires_at<?", (instant,))
            self.conn.execute(
                "INSERT INTO canary_runner_pairings(pairing_id,workspace_id,runner_id,invitation_hash,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?)",
                ("pending_" + secrets.token_hex(16), workspace_id, "", self._hash("invitation", token), "invited", instant, instant + PAIRING_TTL),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise
        return PairingInvitation(token, instant + PAIRING_TTL)

    def exchange(self, invitation: str, public_key_b64: str, phrase: str, *, runner_id: str,
                 runner_version: str, adapters: Mapping[str, str]) -> PairingView:
        runner_id = self._identifier(runner_id, "runner")
        self._identifier(runner_version, "runner version")
        phrase = self._phrase(phrase)
        if not isinstance(adapters, Mapping) or not all(type(k) is str and type(v) is str for k, v in adapters.items()):
            raise ValueError("invalid runner adapters")
        try:
            key = load_public_key_base64(public_key_b64)
        except ValueError as error:
            raise ValueError("invalid runner public key") from error
        raw_key = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        key_id, fingerprint, instant = ed25519_key_id(raw_key), hashlib.sha256(raw_key).hexdigest(), self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT * FROM canary_runner_pairings WHERE invitation_hash=?", (self._hash("invitation", invitation),)).fetchone()
            if row is None or row["status"] != "invited" or row["expires_at"] <= instant:
                raise RunnerAuthError("invalid pairing")
            duplicate = self.conn.execute("SELECT 1 FROM canary_runners WHERE workspace_id=? AND runner_id=?", (row["workspace_id"], runner_id)).fetchone()
            if duplicate:
                raise RunnerAuthError("invalid pairing")
            challenge = _token()
            self.conn.execute("UPDATE canary_runner_pairings SET runner_id=?, invitation_hash=?, phrase=?, public_key=?, fingerprint=?, key_id=?, runner_version=?, adapters_json=?, activation_challenge=?, status='pending' WHERE pairing_id=?",
                              (runner_id, self._hash("consumed-invitation", row["pairing_id"]), phrase, public_key_b64, fingerprint, key_id, runner_version, canonical_bytes(dict(adapters)).decode(), challenge, row["pairing_id"]))
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise
        return PairingView(row["pairing_id"], runner_id, phrase, fingerprint, "pending", row["expires_at"], challenge)

    def inspect(self, workspace_id: str, pairing_id: str) -> PairingView:
        row = self.conn.execute("SELECT * FROM canary_runner_pairings WHERE workspace_id=? AND pairing_id=?", (workspace_id, pairing_id)).fetchone()
        if row is None or row["status"] not in {"pending", "approved"} or not row["phrase"] or not row["fingerprint"]:
            raise RunnerAuthError("invalid pairing")
        return PairingView(row["pairing_id"], row["runner_id"], row["phrase"], row["fingerprint"], row["status"], row["expires_at"])

    def approve(self, workspace_id: str, pairing_id: str, *, phrase: str, fingerprint: str, actor: str) -> None:
        phrase = self._phrase(phrase)
        if type(fingerprint) is not str or len(fingerprint) != 64 or fingerprint != fingerprint.lower():
            raise ValueError("invalid runner fingerprint")
        instant = self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT * FROM canary_runner_pairings WHERE workspace_id=? AND pairing_id=?", (workspace_id, pairing_id)).fetchone()
            if row is None or row["status"] != "pending" or row["expires_at"] <= instant or not hmac.compare_digest(row["phrase"], phrase) or not hmac.compare_digest(row["fingerprint"], fingerprint):
                raise RunnerAuthError("invalid pairing")
            self.conn.execute("UPDATE canary_runner_pairings SET status='approved', approved_at=?, approved_by=? WHERE pairing_id=?", (instant, actor, pairing_id))
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise

    def activate(self, pairing_id: str, signature_b64: str, *, max_active: int | None = None) -> tuple[str, str, str]:
        instant = self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT * FROM canary_runner_pairings WHERE pairing_id=?", (pairing_id,)).fetchone()
            if row is None or row["status"] != "approved" or row["expires_at"] <= instant:
                raise RunnerAuthError("invalid pairing")
            try:
                signature = base64.b64decode(signature_b64, validate=True)
                if len(signature) != 64 or _b64(signature) != signature_b64:
                    raise ValueError
                key = load_public_key_base64(row["public_key"])
                proof = b"heel.runner-pairing-activate.v1\0" + canonical_bytes({"pairing_id": pairing_id, "challenge": row["activation_challenge"]})
                key.verify(signature, proof)
            except (ValueError, InvalidSignature):
                raise RunnerAuthError("invalid pairing") from None
            current = self.conn.execute("SELECT COUNT(*) FROM canary_runners WHERE workspace_id=? AND status='active'", (row["workspace_id"],)).fetchone()[0]
            if max_active is not None and current >= max_active:
                raise RunnerAuthError("runner quota exceeded")
            self.conn.execute("INSERT INTO canary_runners(runner_id,workspace_id,display_name,status,created_at) VALUES(?,?,?,?,?)", (row["runner_id"], row["workspace_id"], row["runner_id"], "active", instant))
            self.conn.execute("INSERT INTO canary_runner_keys(key_id,workspace_id,runner_id,public_key,status,created_at,revoked_at) VALUES(?,?,?,?,?,?,NULL)", (row["key_id"], row["workspace_id"], row["runner_id"], row["public_key"], "active", instant))
            nonce = _token()
            self.conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", (row["workspace_id"], row["runner_id"], "claim", self._hash("nonce", nonce), 1, instant + NONCE_TTL))
            self._save_identity(self._identity_record(
                workspace_id=row["workspace_id"], runner_id=row["runner_id"], public_key=row["public_key"],
                fingerprint=row["fingerprint"], key_id=row["key_id"], runner_version=row["runner_version"],
                adapters_json=row["adapters_json"], paired_by=row["approved_by"],
                paired_at=row["approved_at"], heartbeat_at=instant), instant=instant)
            self.conn.execute("INSERT INTO canary_runner_audit_records(audit_id,workspace_id,runner_id,action,actor,reason_code,created_at) VALUES(?,?,?,?,?,?,?)", ("runner_audit_" + secrets.token_hex(16), row["workspace_id"], row["runner_id"], "runner_activated", row["approved_by"], None, instant))
            self.conn.execute("UPDATE canary_runner_pairings SET status='activated', phrase=NULL, activation_challenge=NULL, activated_at=? WHERE pairing_id=?", (instant, pairing_id))
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise
        return row["workspace_id"], row["runner_id"], nonce

    def provision_run_chain(self, workspace_id: str, runner_id: str, capability: str, run_id: str) -> str:
        """Issue the first nonce for one run/capability chain (called by the run allocator)."""
        if capability not in {"runner_heartbeat", "runner_progress", "runner_result"}:
            raise ValueError("invalid runner capability")
        self._identifier(run_id, "run")
        nonce, instant = _token(), self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT 1 FROM canary_runners WHERE workspace_id=? AND runner_id=? AND status='active'", (workspace_id, runner_id)).fetchone()
            if row is None:
                raise RunnerAuthError("invalid runner")
            self.conn.execute("INSERT OR REPLACE INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", (workspace_id, runner_id, f"{capability}:{run_id}", self._hash("nonce", nonce), 1, instant + NONCE_TTL))
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise
        return nonce

    def revoke(self, workspace_id: str, runner_id: str, *, actor: str, reason_code: str = "human_revocation") -> bool:
        """Human-authorized revocation preserves historical runs but ends every control chain."""
        self._identifier(actor, "actor")
        instant = self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT 1 FROM canary_runners WHERE workspace_id=? AND runner_id=? AND status='active'", (workspace_id, runner_id)).fetchone()
            if row is None:
                self.conn.rollback(); return False
            self._identifier(reason_code, "revocation reason")
            self.conn.execute("UPDATE canary_runners SET status='revoked' WHERE workspace_id=? AND runner_id=?", (workspace_id, runner_id))
            self.conn.execute("UPDATE canary_runner_keys SET status='revoked', revoked_at=? WHERE workspace_id=? AND runner_id=? AND revoked_at IS NULL", (instant, workspace_id, runner_id))
            self.conn.execute("DELETE FROM canary_runner_nonce_chains WHERE workspace_id=? AND runner_id=?", (workspace_id, runner_id))
            # A runner loss invalidates only work which has not been claimed; historical and
            # in-flight records remain evidence and are settled by Task 7's lifecycle service.
            self.conn.execute("UPDATE canary_execution_grants SET status='revoked' WHERE workspace_id=? AND runner_id=? AND status IN ('prepared','approved','issued')", (workspace_id, runner_id))
            identity = self._load_identity(workspace_id, runner_id)
            identity["state"] = "revoked"
            identity["revocation"] = {"revoked_at_ms": self._milliseconds(instant), "revoked_by": actor, "reason_code": reason_code}
            self._save_changed_identity(identity, instant=instant)
            self.conn.execute("INSERT INTO canary_runner_audit_records(audit_id,workspace_id,runner_id,action,actor,reason_code,created_at) VALUES(?,?,?,?,?,?,?)", ("runner_audit_" + secrets.token_hex(16), workspace_id, runner_id, "runner_revoked", actor, reason_code, instant))
            self.conn.commit()
        except Exception:
            if self.conn.in_transaction: self.conn.rollback()
            raise
        return True

    def start_rotation(self, workspace_id: str, runner_id: str, *, previous_fingerprint: str,
                       public_key_b64: str, phrase: str, runner_version: str, adapters: Mapping[str, str]) -> PairingView:
        """Begin a fresh visible-key rotation; old control remains active until new-key PoP."""
        phrase = self._phrase(phrase)
        self._identifier(runner_version, "runner version")
        if not isinstance(adapters, Mapping) or not all(type(k) is str and type(v) is str for k, v in adapters.items()):
            raise ValueError("invalid runner adapters")
        try:
            key = load_public_key_base64(public_key_b64)
        except ValueError as error:
            raise ValueError("invalid runner public key") from error
        raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        key_id, fingerprint, instant = ed25519_key_id(raw), hashlib.sha256(raw).hexdigest(), self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            old = self.conn.execute("SELECT public_key FROM canary_runner_keys WHERE workspace_id=? AND runner_id=? AND status='active' AND revoked_at IS NULL", (workspace_id, runner_id)).fetchone()
            if old is None:
                raise RunnerAuthError("invalid rotation")
            old_raw = load_public_key_base64(old["public_key"]).public_bytes(Encoding.Raw, PublicFormat.Raw)
            if not hmac.compare_digest(hashlib.sha256(old_raw).hexdigest(), previous_fingerprint):
                raise RunnerAuthError("invalid rotation")
            pairing_id, challenge = "rotation_" + secrets.token_hex(16), _token()
            self.conn.execute("INSERT INTO canary_runner_rotations(pairing_id,workspace_id,runner_id,phrase,public_key,fingerprint,key_id,runner_version,adapters_json,activation_challenge,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (pairing_id, workspace_id, runner_id, phrase, public_key_b64, fingerprint, key_id, runner_version, canonical_bytes(dict(adapters)).decode(), challenge, "rotation_pending", instant, instant + PAIRING_TTL))
            identity = self._load_identity(workspace_id, runner_id)
            identity["state"] = "rotating"
            self._save_changed_identity(identity, instant=instant)
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise
        return PairingView(pairing_id, runner_id, phrase, fingerprint, "rotation_pending", instant + PAIRING_TTL)

    def approve_rotation(self, workspace_id: str, pairing_id: str, *, phrase: str, fingerprint: str, actor: str) -> None:
        phrase, instant = self._phrase(phrase), self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT * FROM canary_runner_rotations WHERE workspace_id=? AND pairing_id=?", (workspace_id, pairing_id)).fetchone()
            if row is None or row["status"] != "rotation_pending" or row["expires_at"] <= instant or not hmac.compare_digest(row["phrase"], phrase) or not hmac.compare_digest(row["fingerprint"], fingerprint):
                raise RunnerAuthError("invalid rotation")
            self.conn.execute("UPDATE canary_runner_rotations SET status='rotation_approved',approved_at=?,approved_by=? WHERE pairing_id=?", (instant, actor, pairing_id))
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise

    def rotation_activation_challenge(self, pairing_id: str) -> str:
        row = self.conn.execute("SELECT activation_challenge,status,expires_at FROM canary_runner_rotations WHERE pairing_id=?", (pairing_id,)).fetchone()
        if row is None or row["status"] != "rotation_approved" or row["expires_at"] <= self._now() or not row["activation_challenge"]:
            raise RunnerAuthError("invalid rotation")
        return row["activation_challenge"]

    def activate_rotation(self, pairing_id: str, signature_b64: str, *, overlap_seconds: int = 300) -> tuple[str, str, str]:
        if not isinstance(overlap_seconds, int) or not 1 <= overlap_seconds <= 3600:
            raise ValueError("invalid key overlap")
        instant = self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT * FROM canary_runner_rotations WHERE pairing_id=?", (pairing_id,)).fetchone()
            if row is None or row["status"] != "rotation_approved" or row["expires_at"] <= instant:
                raise RunnerAuthError("invalid rotation")
            try:
                signature = base64.b64decode(signature_b64, validate=True)
                if len(signature) != 64 or _b64(signature) != signature_b64: raise ValueError
                load_public_key_base64(row["public_key"]).verify(signature, b"heel.runner-rotation-activate.v1\0" + canonical_bytes({"pairing_id": pairing_id, "challenge": row["activation_challenge"]}))
            except (ValueError, InvalidSignature):
                raise RunnerAuthError("invalid rotation") from None
            self.conn.execute("UPDATE canary_runner_keys SET status='verification_only',revoked_at=? WHERE workspace_id=? AND runner_id=? AND status='active'", (instant + overlap_seconds, row["workspace_id"], row["runner_id"]))
            self.conn.execute("INSERT INTO canary_runner_keys(key_id,workspace_id,runner_id,public_key,status,created_at,revoked_at) VALUES(?,?,?,?,?,?,NULL)", (row["key_id"], row["workspace_id"], row["runner_id"], row["public_key"], "active", instant))
            self.conn.execute("DELETE FROM canary_runner_nonce_chains WHERE workspace_id=? AND runner_id=?", (row["workspace_id"], row["runner_id"]))
            nonce = _token()
            self.conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", (row["workspace_id"], row["runner_id"], "claim", self._hash("nonce", nonce), 1, instant + NONCE_TTL))
            identity = self._load_identity(row["workspace_id"], row["runner_id"])
            previous = sorted(set(identity["rotation"]["previous_key_ids"] + [identity["public_key"]["key_id"]]))
            identity["public_key"] = {"algorithm": "Ed25519", "key_id": row["key_id"], "public_key_b64": row["public_key"]}
            identity["fingerprint"] = row["fingerprint"]
            identity["runner_version"] = row["runner_version"]
            identity["adapter_versions"] = sorted(set(json.loads(row["adapters_json"]).values()))
            identity["state"] = "active"
            identity["rotation"] = {"previous_key_ids": previous, "rotated_at_ms": self._milliseconds(instant), "verification_overlap_ends_at_ms": self._milliseconds(instant + overlap_seconds)}
            self._save_changed_identity(identity, instant=instant)
            self.conn.execute("INSERT INTO canary_runner_audit_records(audit_id,workspace_id,runner_id,action,actor,reason_code,created_at) VALUES(?,?,?,?,?,?,?)", ("runner_audit_" + secrets.token_hex(16), row["workspace_id"], row["runner_id"], "runner_rotated", row["approved_by"], None, instant))
            self.conn.execute("UPDATE canary_runner_rotations SET status='rotated',activation_challenge=NULL,activated_at=? WHERE pairing_id=?", (instant, pairing_id))
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise
        return row["workspace_id"], row["runner_id"], nonce

    def authenticate_and_consume(self, *, workspace_id: str, runner_id: str, capability: str, path: str,
                                 raw_body: bytes, headers: Mapping[str, list[str]], action: Callable[[], dict]) -> tuple[dict, str]:
        """Verify a fixed request then atomically record it, rotate its nonce, and act."""
        required = ("X-Heel-Runner-Id", "X-Heel-Runner-Key-Id", "X-Heel-Runner-Timestamp-Ms", "X-Heel-Runner-Nonce", "X-Heel-Runner-Sequence", "X-Heel-Runner-Signature")
        try:
            if capability not in RUNNER_CAPABILITIES or any(len(headers.get(name, ())) != 1 for name in required):
                raise RunnerAuthError("invalid runner authentication")
            if headers.get("Authorization") or headers.get("Cookie"):
                raise RunnerAuthError("invalid runner authentication")
            values = {name: headers[name][0] for name in required}
            if values["X-Heel-Runner-Id"] != runner_id or not values["X-Heel-Runner-Nonce"] or not values["X-Heel-Runner-Key-Id"]:
                raise RunnerAuthError("invalid runner authentication")
            timestamp, sequence = values["X-Heel-Runner-Timestamp-Ms"], values["X-Heel-Runner-Sequence"]
            if not timestamp.isascii() or not sequence.isascii() or not timestamp.isdecimal() or not sequence.isdecimal() or (len(timestamp) > 1 and timestamp.startswith("0")) or (len(sequence) > 1 and sequence.startswith("0")):
                raise RunnerAuthError("invalid runner authentication")
            timestamp, sequence = int(timestamp), int(sequence)
            if sequence < 1 or abs(int(self._now() * 1000) - timestamp) > CLOCK_SKEW_MS:
                raise RunnerAuthError("invalid runner authentication")
            parsed = parse_json(raw_body, max_bytes=MAX_RUNNER_BODY)
            if canonical_bytes(parsed) != raw_body:
                raise RunnerAuthError("invalid runner authentication")
            body_digest = hashlib.sha256(raw_body).hexdigest()
            self.conn.execute("BEGIN IMMEDIATE")
            row = self.conn.execute("SELECT * FROM canary_runner_keys WHERE workspace_id=? AND runner_id=? AND key_id=? AND status='active' AND revoked_at IS NULL", (workspace_id, runner_id, values["X-Heel-Runner-Key-Id"])).fetchone()
            if row is None:
                raise RunnerAuthError("invalid runner authentication")
            chain = "claim" if capability == "runner_claim" else f"{capability}:{parsed.get('run_id', '')}"
            proof = {"schema_version":"heel.runner-request-proof.v1", "workspace_id":workspace_id, "runner_id":runner_id, "key_id":values["X-Heel-Runner-Key-Id"], "capability":capability, "method":"POST", "path":path, "body_sha256":body_digest, "timestamp_ms":timestamp, "server_nonce":values["X-Heel-Runner-Nonce"], "sequence":sequence}
            proof_bytes = b"heel.runner-pop.v1\0" + canonical_bytes(proof)
            try:
                signature = base64.b64decode(values["X-Heel-Runner-Signature"], validate=True)
                if len(signature) != 64 or _b64(signature) != values["X-Heel-Runner-Signature"]:
                    raise ValueError
                load_public_key_base64(row["public_key"]).verify(signature, proof_bytes)
            except (ValueError, InvalidSignature):
                raise RunnerAuthError("invalid runner authentication") from None
            # Crucially, no receipt lookup occurs until all closed request material and PoP
            # have authenticated. A sequence collision alone is never a replay credential.
            signed_digest = hashlib.sha256(proof_bytes + signature).hexdigest()
            nonce_hash = self._hash("nonce", values["X-Heel-Runner-Nonce"])
            state = self.conn.execute("SELECT * FROM canary_runner_nonce_chains WHERE workspace_id=? AND runner_id=? AND chain_name=?", (workspace_id, runner_id, chain)).fetchone()
            if state is None or state["expires_at"] <= self._now() or sequence != state["next_sequence"] or not hmac.compare_digest(state["nonce_hash"], nonce_hash):
                prior = self.conn.execute("SELECT * FROM canary_runner_request_ledger WHERE workspace_id=? AND runner_id=? AND chain_name=? AND sequence=?", (workspace_id, runner_id, chain, sequence)).fetchone()
                if prior is not None and all((
                    hmac.compare_digest(prior["signed_request_digest"] or "", signed_digest),
                    hmac.compare_digest(prior["nonce_hash"] or "", nonce_hash),
                    hmac.compare_digest(prior["key_id"] or "", values["X-Heel-Runner-Key-Id"]),
                    hmac.compare_digest(prior["capability"] or "", capability),
                    prior["method"] == "POST", prior["path"] == path,
                    prior["timestamp_ms"] == timestamp,
                    hmac.compare_digest(prior["body_digest"] or "", body_digest),
                )):
                    try:
                        aad = f"{workspace_id}\0{runner_id}\0{chain}\0{sequence}".encode()
                        response = json_load(self._open(prior["response_ciphertext"], aad=aad))
                        nonce = self._open(prior["next_nonce_ciphertext"], aad=aad)
                    except (TypeError, ValueError):
                        raise RunnerAuthError("invalid runner authentication") from None
                    self.conn.rollback(); return response, nonce
                raise RunnerAuthError("invalid runner authentication")
            response = action()
            if not isinstance(response, dict):
                raise ValueError("runner action must return a response object")
            if capability == "runner_heartbeat":
                identity = self._load_identity(workspace_id, runner_id)
                identity["last_heartbeat_at_ms"] = self._milliseconds(self._now())
                self._save_changed_identity(identity, instant=self._now())
            nonce = _token()
            aad = f"{workspace_id}\0{runner_id}\0{chain}\0{sequence}".encode()
            response_json = canonical_bytes(response).decode("utf-8")
            response_ciphertext = self._seal(response_json, aad=aad)
            nonce_ciphertext = self._seal(nonce, aad=aad)
            self.conn.execute("UPDATE canary_runner_nonce_chains SET nonce_hash=?,next_sequence=?,expires_at=? WHERE workspace_id=? AND runner_id=? AND chain_name=?", (self._hash("nonce", nonce), sequence + 1, self._now() + NONCE_TTL, workspace_id, runner_id, chain))
            self.conn.execute("INSERT INTO canary_runner_request_ledger(workspace_id,runner_id,chain_name,sequence,request_digest,response_json,next_nonce,created_at,nonce_hash,key_id,capability,method,path,timestamp_ms,signed_request_digest,body_digest,response_ciphertext,next_nonce_ciphertext) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (workspace_id, runner_id, chain, sequence, signed_digest, "sealed", self._hash("next-nonce", nonce), self._now(), nonce_hash, values["X-Heel-Runner-Key-Id"], capability, "POST", path, timestamp, signed_digest, body_digest, response_ciphertext, nonce_ciphertext))
            self.conn.execute("DELETE FROM canary_runner_request_ledger WHERE created_at<?", (self._now() - 3600,))
            self.conn.commit()
            return response, nonce
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise


def json_load(value: str) -> dict:
    import json
    decoded = json.loads(value)
    if not isinstance(decoded, dict):
        raise RunnerAuthError("invalid runner authentication")
    return decoded
