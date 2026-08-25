"""Runner pairing and rotating proof-of-possession authentication.

This is intentionally separate from browser, API-key, and device authentication.
Runner requests prove control of an Ed25519 key for one fixed route and then consume
a one-time, domain-hashed nonce in the same small database transaction as the action.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from heel.canary_contracts import canonical_bytes, parse_json
from heel.crypto import ed25519_key_id, load_public_key_base64


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


def _phrase_words() -> tuple[str, ...]:
    # 32 * 16 * 4 deterministic pseudo-words: no external word-list licensing.
    onset = ("b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t", "v",
             "w", "z", "br", "cl", "dr", "fr", "gr", "kr", "pl", "pr", "sk", "sl", "st", "tr", "vr", "zl")
    vowel = ("a", "e", "i", "o", "u", "ae", "ai", "ao", "ea", "ei", "ia", "io", "oa", "oi", "ua", "ui")
    tail = ("n", "r", "l", "m")
    return tuple(a + b + c for a in onset for b in vowel for c in tail)


WORDS = _phrase_words()


class RunnerAuthStore:
    def __init__(self, conn: sqlite3.Connection, *, pepper: bytes, now: Callable[[], float] = _now):
        if not isinstance(pepper, bytes) or not 32 <= len(pepper) <= 64:
            raise ValueError("runner authentication pepper must be 32 to 64 bytes")
        self.conn, self._pepper, self._now = conn, pepper, now
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(RUNNER_AUTH_SCHEMA)
        self._ensure_hardened_ledger()

    def _ensure_hardened_ledger(self) -> None:
        present = {row[1] for row in self.conn.execute("PRAGMA table_info(canary_runner_request_ledger)")}
        for statement in RUNNER_AUTH_HARDENING_MIGRATION.strip().split(";"):
            statement = statement.strip()
            if not statement:
                continue
            column = statement.split()[5]
            if column not in present:
                self.conn.execute(statement)
                present.add(column)

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
    def _identifier(value: object, field: str) -> str:
        if type(value) is not str or not value or len(value.encode("utf-8")) > 128 or value.strip() != value:
            raise ValueError(f"invalid {field}")
        return value

    @staticmethod
    def _phrase(value: object) -> str:
        if type(value) is not str or value != value.lower() or value != " ".join(value.split()):
            raise ValueError("invalid pairing phrase")
        words = value.split(" ")
        if len(words) != 6 or any(word not in WORDS for word in words):
            raise ValueError("invalid pairing phrase")
        return value

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

    def revoke(self, workspace_id: str, runner_id: str, *, actor: str) -> bool:
        """Human-authorized revocation preserves historical runs but ends every control chain."""
        self._identifier(actor, "actor")
        instant = self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT 1 FROM canary_runners WHERE workspace_id=? AND runner_id=? AND status='active'", (workspace_id, runner_id)).fetchone()
            if row is None:
                self.conn.rollback(); return False
            self.conn.execute("UPDATE canary_runners SET status='revoked' WHERE workspace_id=? AND runner_id=?", (workspace_id, runner_id))
            self.conn.execute("UPDATE canary_runner_keys SET status='revoked', revoked_at=? WHERE workspace_id=? AND runner_id=? AND revoked_at IS NULL", (instant, workspace_id, runner_id))
            self.conn.execute("DELETE FROM canary_runner_nonce_chains WHERE workspace_id=? AND runner_id=?", (workspace_id, runner_id))
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

    def activate_rotation(self, pairing_id: str, signature_b64: str, *, overlap_seconds: int = 300) -> str:
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
            self.conn.execute("UPDATE canary_runner_rotations SET status='rotated',activation_challenge=NULL,activated_at=? WHERE pairing_id=?", (instant, pairing_id))
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise
        return nonce

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
