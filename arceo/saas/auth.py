"""
Arceo hosted — password auth, sessions, login throttling (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Arceo-Commercial

Passwords are PBKDF2-HMAC-SHA256 with per-user salt; only the derived hash is stored. Sessions are
opaque bearer tokens stored HASHED with absolute + idle expiry. Login failures are throttled per
email to slow credential stuffing. No third-party identity dependency; an SSO adapter can replace
`verify_password` behind the same session issuance path later.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import time
from dataclasses import dataclass

from .tenancy import hash_api_key

PBKDF2_ITERATIONS = 600_000
SESSION_TTL = 12 * 3600          # absolute lifetime
SESSION_IDLE = 2 * 3600          # sliding idle timeout
LOCKOUT_THRESHOLD = 5            # consecutive failures before lockout
LOCKOUT_WINDOW = 15 * 60         # seconds locked out / failure-counting window

_SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials(
  user_id TEXT PRIMARY KEY, salt TEXT NOT NULL, pw_hash TEXT NOT NULL,
  iterations INTEGER NOT NULL, updated_at REAL);
CREATE TABLE IF NOT EXISTS sessions(
  session_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL,
  created_at REAL, last_seen_at REAL, revoked_at REAL);
CREATE TABLE IF NOT EXISTS login_failures(
  email TEXT PRIMARY KEY, count INTEGER NOT NULL, first_at REAL, last_at REAL);
CREATE INDEX IF NOT EXISTS idx_sess_token ON sessions(token_hash);
"""


def _now() -> float:
    return time.time()


def hash_password(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations).hex()


class ThrottledError(Exception):
    """Too many recent failures for this email; retry after the lockout window."""


@dataclass
class Session:
    session_id: str
    user_id: str
    token: str   # returned ONCE at creation; only the hash is persisted


class AuthStore:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)

    # --- passwords ---
    def set_password(self, user_id: str, password: str) -> None:
        if len(password) < 10:
            raise ValueError("password must be at least 10 characters")
        salt = secrets.token_bytes(16)
        self.conn.execute(
            "INSERT OR REPLACE INTO credentials VALUES(?,?,?,?,?)",
            (user_id, salt.hex(), hash_password(password, salt), PBKDF2_ITERATIONS, _now()))
        self.conn.commit()

    def verify_password(self, user_id: str, password: str) -> bool:
        row = self.conn.execute(
            "SELECT * FROM credentials WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            # burn comparable time so absent users are indistinguishable
            hash_password(password, b"\x00" * 16, PBKDF2_ITERATIONS)
            return False
        got = hash_password(password, bytes.fromhex(row["salt"]), row["iterations"])
        return hmac.compare_digest(got, row["pw_hash"])

    # --- throttling ---
    def check_throttle(self, email: str) -> None:
        row = self.conn.execute(
            "SELECT * FROM login_failures WHERE email=?", (email.lower(),)).fetchone()
        if row and row["count"] >= LOCKOUT_THRESHOLD and _now() - row["last_at"] < LOCKOUT_WINDOW:
            raise ThrottledError("too many failed attempts; try again later")

    def record_failure(self, email: str) -> None:
        email = email.lower()
        row = self.conn.execute(
            "SELECT * FROM login_failures WHERE email=?", (email,)).fetchone()
        now = _now()
        if row and now - row["first_at"] < LOCKOUT_WINDOW:
            self.conn.execute(
                "UPDATE login_failures SET count=count+1, last_at=? WHERE email=?", (now, email))
        else:
            self.conn.execute(
                "INSERT OR REPLACE INTO login_failures VALUES(?,?,?,?)", (email, 1, now, now))
        self.conn.commit()

    def clear_failures(self, email: str) -> None:
        self.conn.execute("DELETE FROM login_failures WHERE email=?", (email.lower(),))
        self.conn.commit()

    # --- sessions ---
    def create_session(self, user_id: str) -> Session:
        token = f"arceo_ses_{secrets.token_urlsafe(32)}"
        sid = f"ses_{secrets.token_hex(8)}"
        now = _now()
        self.conn.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)",
                          (sid, user_id, hash_api_key(token), now, now, None))
        self.conn.commit()
        return Session(sid, user_id, token)

    def resolve_session(self, token: str) -> str | None:
        """Return the user_id for a live session, refreshing the idle clock; else None."""
        row = self.conn.execute(
            "SELECT * FROM sessions WHERE token_hash=? AND revoked_at IS NULL",
            (hash_api_key(token),)).fetchone()
        if not row:
            return None
        now = _now()
        if now - row["created_at"] > SESSION_TTL or now - row["last_seen_at"] > SESSION_IDLE:
            self.conn.execute("UPDATE sessions SET revoked_at=? WHERE session_id=?",
                              (now, row["session_id"]))
            self.conn.commit()
            return None
        self.conn.execute("UPDATE sessions SET last_seen_at=? WHERE session_id=?",
                          (now, row["session_id"]))
        self.conn.commit()
        return row["user_id"]

    def revoke_session(self, token: str) -> None:
        self.conn.execute("UPDATE sessions SET revoked_at=? WHERE token_hash=?",
                          (_now(), hash_api_key(token)))
        self.conn.commit()

    def revoke_all(self, user_id: str) -> None:
        self.conn.execute(
            "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
            (_now(), user_id))
        self.conn.commit()

    # --- the one login entry point ---
    def login(self, email: str, user_id: str | None, password: str) -> Session:
        """Throttle-checked login. `user_id` is the id looked up from `email` by the caller
        (None if the email is unknown — still burns a hash and counts a failure)."""
        self.check_throttle(email)
        if user_id is not None and self.verify_password(user_id, password):
            self.clear_failures(email)
            return self.create_session(user_id)
        if user_id is None:
            hash_password(password, b"\x00" * 16, PBKDF2_ITERATIONS)
        self.record_failure(email)
        raise PermissionError("invalid email or password")
