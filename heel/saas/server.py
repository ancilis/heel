"""Fail-closed production entrypoint for Heel's private single-node control plane.

SPDX-License-Identifier: LicenseRef-Heel-Commercial

The public Cloudflare Worker is the only supported Internet edge. This process serves a private
VPC/Tunnel listener, persists to one SQLite volume, and launches the usable free tier with paid
checkout explicitly disabled until a verified live billing adapter is configured.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import errno
import json
import logging
import os
from pathlib import Path
import signal
import sqlite3
import stat
import threading
from typing import Mapping
from urllib.parse import urlsplit

from .billing import DisabledBilling
from heel.crypto import SigningAuthority, load_private_key_base64, load_public_key_set
from .http_api import ControlPlane, serve
from .migrate import CONTROL_PLANE_MIGRATIONS, Migrator

_LOGGER = logging.getLogger("heel.saas.control_plane")

try:
    import fcntl
except ImportError:  # pragma: no cover - production is explicitly POSIX-only
    fcntl = None


class ProductionConfigurationError(RuntimeError):
    """A required production invariant is absent or unsafe."""


class _SingleProcessDatabaseLock:
    def __init__(self, descriptor: int):
        self._descriptor = descriptor

    @classmethod
    def acquire(cls, database_path: str) -> "_SingleProcessDatabaseLock":
        if fcntl is None:
            raise ProductionConfigurationError(
                "production SQLite ownership requires POSIX file locking"
            )
        lock_path = database_path + ".lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if not nofollow:
            raise ProductionConfigurationError(
                "production SQLite ownership requires no-follow file opens"
            )
        try:
            descriptor = os.open(lock_path, flags | nofollow, 0o600)
        except OSError as error:
            raise ProductionConfigurationError("HEEL_DATABASE_PATH lock is unsafe") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ProductionConfigurationError("HEEL_DATABASE_PATH lock is unsafe")
            os.fchmod(descriptor, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in {errno.EACCES, errno.EAGAIN}:
                    raise ProductionConfigurationError(
                        "HEEL_DATABASE_PATH already has a live process owner"
                    ) from None
                raise
            return cls(descriptor)
        except Exception:
            os.close(descriptor)
            raise

    def close(self) -> None:
        if self._descriptor < 0:
            return
        descriptor, self._descriptor = self._descriptor, -1
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _canonical_pepper(value: str, name: str) -> bytes:
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        raise ProductionConfigurationError(f"{name} must be canonical base64url") from None
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != value or not 32 <= len(decoded) <= 64:
        raise ProductionConfigurationError(
            f"{name} must encode 32 to 64 bytes in canonical base64url"
        )
    return decoded


@dataclass(frozen=True)
class ProductionConfiguration:
    database_path: str
    public_origin: str
    device_token_pepper: bytes
    api_key_pepper: str
    edge_auth_secret: str
    host: str
    port: int
    billing_mode: str
    grant_authority: SigningAuthority
    grant_trusted_keys: dict[str, object]

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None,
    ) -> "ProductionConfiguration":
        env = os.environ if environment is None else environment
        database_value = env.get("HEEL_DATABASE_PATH", "").strip()
        database = Path(database_value) if database_value else Path("")
        if (
            not database_value
            or database_value == ":memory:"
            or not database.is_absolute()
            or not database.parent.is_dir()
        ):
            raise ProductionConfigurationError(
                "HEEL_DATABASE_PATH must be an absolute file below an existing durable volume"
            )

        public_origin = env.get("HEEL_PUBLIC_ORIGIN", "").strip()
        try:
            parsed = urlsplit(public_origin)
        except ValueError:
            parsed = urlsplit("")
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or public_origin != f"{parsed.scheme}://{parsed.netloc}"
        ):
            raise ProductionConfigurationError(
                "HEEL_PUBLIC_ORIGIN must be one canonical HTTPS origin"
            )

        device_pepper = _canonical_pepper(
            env.get("HEEL_DEVICE_TOKEN_PEPPER_B64", "").strip(),
            "HEEL_DEVICE_TOKEN_PEPPER_B64",
        )
        api_pepper = env.get("HEEL_API_KEY_PEPPER", "")
        if (
            len(api_pepper) < 32
            or len(api_pepper) > 256
            or api_pepper != api_pepper.strip()
            or any(ord(character) < 33 or ord(character) == 127 for character in api_pepper)
        ):
            raise ProductionConfigurationError(
                "HEEL_API_KEY_PEPPER must be a 32 to 256 character secret"
            )
        edge_auth_value = env.get("HEEL_EDGE_AUTH_SECRET_B64", "").strip()
        _canonical_pepper(edge_auth_value, "HEEL_EDGE_AUTH_SECRET_B64")

        host = env.get("HEEL_CONTROL_PLANE_HOST", "127.0.0.1").strip()
        if host not in {"127.0.0.1", "::1", "localhost", "0.0.0.0", "::"}:
            raise ProductionConfigurationError(
                "HEEL_CONTROL_PLANE_HOST must be loopback or an explicit private-network bind"
            )
        if host in {"0.0.0.0", "::"} and env.get("HEEL_PRIVATE_NETWORK_ACK") != "private-vpc-only":
            raise ProductionConfigurationError(
                "HEEL_PRIVATE_NETWORK_ACK=private-vpc-only is required for a non-loopback bind"
            )
        port_value = env.get("HEEL_CONTROL_PLANE_PORT", "8080")
        try:
            port = int(port_value)
        except ValueError:
            port = 0
        if not 1 <= port <= 65_535:
            raise ProductionConfigurationError(
                "HEEL_CONTROL_PLANE_PORT must be an integer from 1 to 65535"
            )

        billing_mode = env.get("HEEL_BILLING_MODE", "free_launch").strip()
        if billing_mode != "free_launch":
            raise ProductionConfigurationError(
                "HEEL_BILLING_MODE must be free_launch until a live adapter is installed"
            )
        private_key_value = env.get("HEEL_GRANT_SIGNING_PRIVATE_KEY_B64", "").strip()
        key_id = env.get("HEEL_GRANT_SIGNING_KEY_ID", "").strip()
        trusted_value = env.get("HEEL_GRANT_TRUSTED_PUBLIC_KEYS", "").strip()
        if not private_key_value:
            raise ProductionConfigurationError("HEEL_GRANT_SIGNING_PRIVATE_KEY_B64 is required")
        if not key_id:
            raise ProductionConfigurationError("HEEL_GRANT_SIGNING_KEY_ID is required")
        if not trusted_value:
            raise ProductionConfigurationError("HEEL_GRANT_TRUSTED_PUBLIC_KEYS is required")
        try:
            authority = SigningAuthority.from_private_key(
                load_private_key_base64(private_key_value), key_id,
            )
        except (TypeError, ValueError) as error:
            raise ProductionConfigurationError(
                "HEEL_GRANT_SIGNING_PRIVATE_KEY_B64 or HEEL_GRANT_SIGNING_KEY_ID is invalid"
            ) from error
        try:
            trusted_keys = load_public_key_set(trusted_value)
        except (TypeError, ValueError) as error:
            raise ProductionConfigurationError(
                "HEEL_GRANT_TRUSTED_PUBLIC_KEYS is invalid"
            ) from error
        trusted_public = trusted_keys.get(authority.key_id)
        if trusted_public is None:
            raise ProductionConfigurationError(
                "HEEL_GRANT_TRUSTED_PUBLIC_KEYS must contain the configured signing key"
            )
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        if trusted_public.public_bytes(Encoding.Raw, PublicFormat.Raw) != authority.public_key_bytes:
            raise ProductionConfigurationError(
                "HEEL_GRANT_TRUSTED_PUBLIC_KEYS must contain the configured signing key"
            )
        return cls(
            str(database), public_origin, device_pepper, api_pepper, edge_auth_value,
            host, port, billing_mode, authority, trusted_keys,
        )


def build_server(config: ProductionConfiguration):
    """Construct the private listener after every production invariant has passed."""
    database_lock = _SingleProcessDatabaseLock.acquire(config.database_path)
    control_plane = None
    try:
        migration_connection = sqlite3.connect(config.database_path)
        try:
            migration_connection.execute("PRAGMA foreign_keys=ON")
            migration_connection.execute("PRAGMA busy_timeout=5000")
            migrator = Migrator(migration_connection, CONTROL_PLANE_MIGRATIONS)
            migrator.apply_all()
            if migrator.current_version() != CONTROL_PLANE_MIGRATIONS[-1].version:
                raise ProductionConfigurationError("control-plane schema is not current")
        finally:
            migration_connection.close()

        control_plane = ControlPlane(
            config.database_path,
            device_token_pepper=config.device_token_pepper,
            enable_device_auth=True,
            public_origin=config.public_origin,
            billing=DisabledBilling(),
            trust_edge_client_key=True,
            edge_auth_secret=config.edge_auth_secret,
            grant_authority=config.grant_authority,
            grant_trusted_keys=config.grant_trusted_keys,
        )
        # One process owns this database. WAL keeps reads responsive; FULL preserves accepted
        # findings and auth state across an abrupt host restart on a durable volume.
        control_plane.store.conn.execute("PRAGMA journal_mode=WAL")
        control_plane.store.conn.execute("PRAGMA synchronous=FULL")
        control_plane.required_schema_version = CONTROL_PLANE_MIGRATIONS[-1].version
        server = serve(control_plane, config.host, config.port)
        server.add_close_callback(database_lock.close)
        return server
    except Exception:
        if control_plane is not None:
            control_plane.close()
        database_lock.close()
        raise


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    config = ProductionConfiguration.from_environment()
    server = build_server(config)
    _LOGGER.info(json.dumps({
        "billing_mode": config.billing_mode,
        "event": "control_plane_started",
        "host": config.host,
        "port": server.server_address[1],
        "schema_version": CONTROL_PLANE_MIGRATIONS[-1].version,
    }, sort_keys=True, separators=(",", ":")))

    def stop(_signum, _frame) -> None:
        # ThreadingHTTPServer.shutdown must run from a thread other than serve_forever.
        server.control_plane.draining = True
        _LOGGER.info(json.dumps({
            "event": "control_plane_draining",
            "signal": signal.Signals(_signum).name,
        }, sort_keys=True, separators=(",", ":")))
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
