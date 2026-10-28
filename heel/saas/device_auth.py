"""Heel hosted device authorization and rotating machine credentials (commercial layer).

The flow is deliberately narrower than general OAuth: first-party ``heel-agent`` clients,
one workspace per device family, and only findings-sync/read capabilities. Device authorization
grants account access; it never grants the separate, short-lived human approval required to send
findings. All bearer material is stored as a domain-separated HMAC digest.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass


DEVICE_GRANT_TTL = 10 * 60
DEVICE_POLL_INTERVAL = 5
ACCESS_TTL = 15 * 60
REFRESH_ABSOLUTE_TTL = 30 * 24 * 3600
REFRESH_IDLE_TTL = 7 * 24 * 3600
DEVICE_CAPABILITIES = ("sync_findings", "view_synced_reviews")

_B64_32 = re.compile(r"[A-Za-z0-9_-]{43}\Z", flags=re.ASCII)
_DEVICE_VERIFIER = re.compile(r"heel_dv_[A-Za-z0-9_-]{43}\Z", flags=re.ASCII)
_DEVICE_CODE = re.compile(r"heel_dev_[A-Za-z0-9_-]{43}\Z", flags=re.ASCII)
_ACCESS_TOKEN = re.compile(r"heel_at_[A-Za-z0-9_-]{43}\Z", flags=re.ASCII)
_REFRESH_TOKEN = re.compile(r"heel_rt_[A-Za-z0-9_-]{64}\Z", flags=re.ASCII)
_USER_CODE = re.compile(r"[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}\Z", flags=re.ASCII)
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

_SCHEMA = """
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
  ON device_authorizations(client_key, requested_at);
"""


class DevicePending(Exception):
    """The human has not decided yet."""


class DeviceDenied(Exception):
    """The human denied this device grant."""


class DeviceExpired(Exception):
    """The device grant or credential expired."""


class RefreshReuseDetected(Exception):
    """A consumed refresh token was replayed; its complete family is revoked."""


class SlowDown(Exception):
    """The device polled sooner than the server-provided interval."""

    def __init__(self, interval: int):
        super().__init__("device polling must slow down")
        self.interval = interval


class DeviceRateLimited(Exception):
    """The client has created too many recent device authorizations."""


@dataclass(frozen=True)
class DeviceStart:
    device_code: str
    user_code: str
    expires_in: int = DEVICE_GRANT_TTL
    interval: int = DEVICE_POLL_INTERVAL


@dataclass(frozen=True)
class DeviceClaim:
    device_name: str
    device_fingerprint: str
    confirmation_nonce: str
    expires_in: int


@dataclass(frozen=True)
class DevicePoll:
    status: str
    interval: int
    expires_in: int | None


@dataclass(frozen=True)
class DeviceTokens:
    access_token: str
    expires_in: int
    refresh_token: str
    refresh_expires_in: int
    device_id: str
    workspace_id: str
    capabilities: tuple[str, ...] = DEVICE_CAPABILITIES


@dataclass(frozen=True)
class DevicePrincipal:
    device_id: str
    user_id: str
    workspace_id: str


def _now() -> float:
    return time.time()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_b64_32(value: str) -> bytes:
    if type(value) is not str or _B64_32.fullmatch(value) is None:
        raise ValueError("invalid device proof")
    try:
        raw = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError("invalid device proof") from None
    if len(raw) != 32:
        raise ValueError("invalid device proof")
    return raw


class DeviceAuthStore:
    """Persistence and atomic transitions for first-party device authorization."""

    def __init__(self, conn: sqlite3.Connection, *, pepper: bytes | None = None):
        self.conn = conn
        self.conn.row_factory = sqlite3.Row
        if pepper is None:
            configured = os.environ.get("HEEL_DEVICE_TOKEN_PEPPER_B64", "")
            if not configured or "=" in configured:
                raise RuntimeError(
                    "device authorization requires HEEL_DEVICE_TOKEN_PEPPER_B64"
                )
            try:
                pepper = base64.b64decode(
                    configured + "=" * ((4 - len(configured) % 4) % 4),
                    altchars=b"-_",
                    validate=True,
                )
            except (ValueError, base64.binascii.Error):
                raise RuntimeError("HEEL_DEVICE_TOKEN_PEPPER_B64 is invalid") from None
            if _b64(pepper) != configured:
                raise RuntimeError("HEEL_DEVICE_TOKEN_PEPPER_B64 is not canonical")
        if not 32 <= len(pepper) <= 64:
            raise ValueError("device token pepper must be 32 to 64 bytes")
        self._pepper = pepper
        self.conn.executescript(_SCHEMA)

    def _hash(self, domain: str, value: str) -> str:
        return hmac.new(
            self._pepper,
            domain.encode("ascii") + b"\0" + value.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def _authorization(self, device_code: str) -> sqlite3.Row | None:
        if type(device_code) is not str or _DEVICE_CODE.fullmatch(device_code) is None:
            return None
        return self.conn.execute(
            "SELECT * FROM device_authorizations WHERE device_code_hash=?",
            (self._hash("device-code", device_code),),
        ).fetchone()

    @staticmethod
    def _validate_device_name(device_name: str) -> None:
        if (
            type(device_name) is not str
            or not 1 <= len(device_name) <= 64
            or device_name != device_name.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in device_name)
        ):
            raise ValueError("invalid device name")

    @staticmethod
    def _proof_matches(row: sqlite3.Row, verifier: str) -> bool:
        if type(verifier) is not str or _DEVICE_VERIFIER.fullmatch(verifier) is None:
            return False
        got = _b64(hashlib.sha256(verifier.encode("utf-8")).digest())
        return hmac.compare_digest(got, row["device_challenge"])

    def start(
        self,
        device_name: str,
        device_challenge: str,
        *,
        client_key: str = "0" * 64,
        now: float | None = None,
    ) -> DeviceStart:
        self._validate_device_name(device_name)
        _decode_b64_32(device_challenge)
        if type(client_key) is not str or re.fullmatch(r"[0-9a-f]{64}", client_key) is None:
            raise ValueError("invalid device client key")
        instant = _now() if now is None else now
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            recent = self.conn.execute(
                "SELECT COUNT(*) AS n FROM device_authorizations "
                "WHERE client_key=? AND requested_at>?",
                (client_key, instant - 600),
            ).fetchone()["n"]
            active = self.conn.execute(
                "SELECT COUNT(*) AS n FROM device_authorizations WHERE client_key=? "
                "AND device_challenge=? AND status='pending' AND expires_at>?",
                (client_key, device_challenge, instant),
            ).fetchone()["n"]
            if recent >= 10 or active >= 3:
                raise DeviceRateLimited("too many device authorization starts")
            for _ in range(8):
                device_code = "heel_dev_" + _b64(secrets.token_bytes(32))
                compact_user_code = "".join(secrets.choice(_CROCKFORD) for _ in range(8))
                user_code = compact_user_code[:4] + "-" + compact_user_code[4:]
                self.conn.execute(
                    "INSERT INTO device_authorizations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "dgr_" + secrets.token_hex(16),
                        self._hash("device-code", device_code),
                        self._hash("user-code", user_code),
                        device_name,
                        device_challenge,
                        client_key,
                        instant,
                        instant + DEVICE_GRANT_TTL,
                        DEVICE_POLL_INTERVAL,
                        None,
                        "pending",
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                )
                self.conn.commit()
                return DeviceStart(device_code, user_code)
            raise RuntimeError("could not allocate a unique device authorization")
        except sqlite3.IntegrityError:
            self.conn.rollback()
            return self.start(
                device_name, device_challenge, client_key=client_key, now=instant
            )
        except Exception:
            self.conn.rollback()
            raise

    def poll(self, device_code: str, verifier: str, *, now: float | None = None) -> DevicePoll:
        row = self._authorization(device_code)
        if row is None or not self._proof_matches(row, verifier):
            raise PermissionError("invalid device authorization")
        instant = _now() if now is None else now
        if instant > row["expires_at"]:
            self.conn.execute(
                "UPDATE device_authorizations SET status='expired' WHERE grant_id=?",
                (row["grant_id"],),
            )
            self.conn.commit()
            return DevicePoll("expired", row["poll_interval"], None)
        if (
            row["last_polled_at"] is not None
            and instant - row["last_polled_at"] < row["poll_interval"]
        ):
            interval = min(30, row["poll_interval"] + 5)
            self.conn.execute(
                "UPDATE device_authorizations SET poll_interval=?, last_polled_at=? WHERE grant_id=?",
                (interval, instant, row["grant_id"]),
            )
            self.conn.commit()
            raise SlowDown(interval)
        self.conn.execute(
            "UPDATE device_authorizations SET last_polled_at=? WHERE grant_id=?",
            (instant, row["grant_id"]),
        )
        self.conn.commit()
        status = row["status"]
        if status == "consumed":
            status = "approved"
        return DevicePoll(
            status,
            row["poll_interval"],
            max(0, int(row["expires_at"] - instant)) if status == "pending" else None,
        )

    def inspect(self, user_code: str, user_id: str, *, now: float | None = None) -> DeviceClaim:
        if type(user_code) is not str or _USER_CODE.fullmatch(user_code) is None:
            raise PermissionError("invalid device authorization")
        instant = _now() if now is None else now
        row = self.conn.execute(
            "SELECT * FROM device_authorizations WHERE user_code_hash=?",
            (self._hash("user-code", user_code),),
        ).fetchone()
        if row is None or row["status"] != "pending":
            raise PermissionError("invalid device authorization")
        if instant > row["expires_at"]:
            self.conn.execute(
                "UPDATE device_authorizations SET status='expired' WHERE grant_id=?",
                (row["grant_id"],),
            )
            self.conn.commit()
            raise DeviceExpired("device authorization expired")
        nonce = "heel_dcn_" + _b64(secrets.token_bytes(32))
        self.conn.execute(
            "UPDATE device_authorizations SET inspected_by=?, confirmation_nonce_hash=?, "
            "confirmation_expires_at=? "
            "WHERE grant_id=?",
            (
                user_id,
                self._hash("confirmation-nonce", nonce),
                min(row["expires_at"], instant + 300),
                row["grant_id"],
            ),
        )
        self.conn.commit()
        digest = hashlib.sha256(
            (row["grant_id"] + "\0" + row["device_challenge"]).encode("ascii")
        ).digest()
        number = int.from_bytes(digest[:5], "big")
        compact = "".join(
            _CROCKFORD[(number >> shift) & 31] for shift in range(35, -1, -5)
        )
        fingerprint = compact[:4] + "-" + compact[4:]
        return DeviceClaim(
            row["device_name"],
            fingerprint,
            nonce,
            max(0, int(row["expires_at"] - instant)),
        )

    def decide(
        self,
        user_code: str,
        confirmation_nonce: str,
        user_id: str,
        *,
        action: str,
        workspace_id: str | None = None,
        now: float | None = None,
    ) -> None:
        if (
            type(user_code) is not str
            or _USER_CODE.fullmatch(user_code) is None
            or type(confirmation_nonce) is not str
            or not confirmation_nonce.startswith("heel_dcn_")
            or action not in {"approve", "deny"}
            or (action == "approve" and not workspace_id)
            or (action == "deny" and workspace_id is not None)
        ):
            raise PermissionError("invalid device authorization decision")
        instant = _now() if now is None else now
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute(
                "SELECT * FROM device_authorizations WHERE user_code_hash=?",
                (self._hash("user-code", user_code),),
            ).fetchone()
            valid_nonce = (
                row is not None
                and row["confirmation_nonce_hash"] is not None
                and hmac.compare_digest(
                    row["confirmation_nonce_hash"],
                    self._hash("confirmation-nonce", confirmation_nonce),
                )
            )
            if (
                row is None
                or row["status"] != "pending"
                or row["inspected_by"] != user_id
                or not valid_nonce
                or row["confirmation_expires_at"] is None
                or instant > row["confirmation_expires_at"]
                or instant > row["expires_at"]
            ):
                raise PermissionError("invalid device authorization decision")
            self.conn.execute(
                "UPDATE device_authorizations SET status=?, confirmation_nonce_hash=NULL, "
                "confirmation_expires_at=NULL, "
                "approved_user_id=?, workspace_id=?, approved_at=? WHERE grant_id=?",
                (
                    "approved" if action == "approve" else "denied",
                    user_id,
                    workspace_id,
                    instant if action == "approve" else None,
                    row["grant_id"],
                ),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def _mint_pair(
        self,
        *,
        device_id: str,
        workspace_id: str,
        absolute_expires_at: float,
        now: float,
    ) -> DeviceTokens:
        access_token = "heel_at_" + _b64(secrets.token_bytes(32))
        refresh_token = "heel_rt_" + _b64(secrets.token_bytes(48))
        credential = self.conn.execute(
            "SELECT family_id FROM device_credentials WHERE device_id=?", (device_id,)
        ).fetchone()
        if credential is None:
            raise RuntimeError("device credential disappeared")
        idle_expires_at = min(absolute_expires_at, now + REFRESH_IDLE_TTL)
        self.conn.execute(
            "INSERT INTO device_access_tokens VALUES(?,?,?,?,NULL)",
            (self._hash("access-token", access_token), device_id, now, now + ACCESS_TTL),
        )
        self.conn.execute(
            "INSERT INTO device_refresh_tokens VALUES(?,?,?,?,?,?,NULL)",
            (
                self._hash("refresh-token", refresh_token),
                device_id,
                credential["family_id"],
                now,
                absolute_expires_at,
                idle_expires_at,
            ),
        )
        return DeviceTokens(
            access_token=access_token,
            expires_in=ACCESS_TTL,
            refresh_token=refresh_token,
            refresh_expires_in=max(0, int(absolute_expires_at - now)),
            device_id=device_id,
            workspace_id=workspace_id,
        )

    def exchange(self, device_code: str, verifier: str, *, now: float | None = None) -> DeviceTokens:
        instant = _now() if now is None else now
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._authorization(device_code)
            if row is None or not self._proof_matches(row, verifier):
                raise PermissionError("invalid device authorization")
            if instant > row["expires_at"] or row["status"] == "expired":
                raise DeviceExpired("device authorization expired")
            if row["status"] == "pending":
                raise DevicePending("authorization pending")
            if row["status"] == "denied":
                raise DeviceDenied("device authorization denied")
            if row["status"] != "approved":
                raise PermissionError("device authorization already consumed")
            device_id = "dev_" + secrets.token_hex(16)
            family_id = "dfm_" + secrets.token_hex(16)
            absolute_expires_at = instant + REFRESH_ABSOLUTE_TTL
            self.conn.execute(
                "INSERT INTO device_credentials VALUES(?,?,?,?,?,?,?,NULL)",
                (
                    device_id,
                    family_id,
                    row["approved_user_id"],
                    row["workspace_id"],
                    instant,
                    absolute_expires_at,
                    instant,
                ),
            )
            tokens = self._mint_pair(
                device_id=device_id,
                workspace_id=row["workspace_id"],
                absolute_expires_at=absolute_expires_at,
                now=instant,
            )
            self.conn.execute(
                "UPDATE device_authorizations SET status='consumed', consumed_at=? WHERE grant_id=?",
                (instant, row["grant_id"]),
            )
            self.conn.commit()
            return tokens
        except Exception:
            self.conn.rollback()
            raise

    def resolve_access(self, access_token: str, *, now: float | None = None) -> DevicePrincipal | None:
        if type(access_token) is not str or _ACCESS_TOKEN.fullmatch(access_token) is None:
            return None
        instant = _now() if now is None else now
        row = self.conn.execute(
            "SELECT c.device_id,c.user_id,c.workspace_id,c.revoked_at,a.expires_at,a.revoked_at AS "
            "access_revoked FROM device_access_tokens a JOIN device_credentials c "
            "ON c.device_id=a.device_id WHERE a.token_hash=?",
            (self._hash("access-token", access_token),),
        ).fetchone()
        if (
            row is None
            or row["revoked_at"] is not None
            or row["access_revoked"] is not None
            or instant > row["expires_at"]
        ):
            return None
        return DevicePrincipal(row["device_id"], row["user_id"], row["workspace_id"])

    def _revoke_family(self, family_id: str, now: float) -> None:
        self.conn.execute(
            "UPDATE device_credentials SET revoked_at=COALESCE(revoked_at,?) WHERE family_id=?",
            (now, family_id),
        )
        self.conn.execute(
            "UPDATE device_access_tokens SET revoked_at=COALESCE(revoked_at,?) WHERE device_id IN "
            "(SELECT device_id FROM device_credentials WHERE family_id=?)",
            (now, family_id),
        )

    def refresh(self, refresh_token: str, *, now: float | None = None) -> DeviceTokens:
        if type(refresh_token) is not str or _REFRESH_TOKEN.fullmatch(refresh_token) is None:
            raise PermissionError("invalid refresh token")
        instant = _now() if now is None else now
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute(
                "SELECT r.*,c.workspace_id,c.revoked_at FROM device_refresh_tokens r "
                "JOIN device_credentials c ON c.device_id=r.device_id WHERE r.token_hash=?",
                (self._hash("refresh-token", refresh_token),),
            ).fetchone()
            if row is None:
                raise PermissionError("invalid refresh token")
            if row["consumed_at"] is not None:
                self._revoke_family(row["family_id"], instant)
                self.conn.commit()
                raise RefreshReuseDetected("refresh token reuse detected")
            if (
                row["revoked_at"] is not None
                or instant > row["absolute_expires_at"]
                or instant > row["idle_expires_at"]
            ):
                self._revoke_family(row["family_id"], instant)
                self.conn.commit()
                raise PermissionError("invalid refresh token")
            self.conn.execute(
                "UPDATE device_refresh_tokens SET consumed_at=? WHERE token_hash=?",
                (instant, row["token_hash"]),
            )
            self.conn.execute(
                "UPDATE device_access_tokens SET revoked_at=COALESCE(revoked_at,?) "
                "WHERE device_id=?",
                (instant, row["device_id"]),
            )
            self.conn.execute(
                "UPDATE device_credentials SET last_refreshed_at=? WHERE device_id=?",
                (instant, row["device_id"]),
            )
            tokens = self._mint_pair(
                device_id=row["device_id"],
                workspace_id=row["workspace_id"],
                absolute_expires_at=row["absolute_expires_at"],
                now=instant,
            )
            self.conn.commit()
            return tokens
        except RefreshReuseDetected:
            raise
        except Exception:
            self.conn.rollback()
            raise

    def revoke(self, refresh_token: str, *, now: float | None = None) -> None:
        if type(refresh_token) is not str or _REFRESH_TOKEN.fullmatch(refresh_token) is None:
            return
        instant = _now() if now is None else now
        row = self.conn.execute(
            "SELECT family_id FROM device_refresh_tokens WHERE token_hash=?",
            (self._hash("refresh-token", refresh_token),),
        ).fetchone()
        if row is None:
            return
        self._revoke_family(row["family_id"], instant)
        self.conn.commit()
