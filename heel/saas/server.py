"""Fail-closed production entrypoint for Heel's private single-node control plane.

SPDX-License-Identifier: LicenseRef-Heel-Commercial

The public Cloudflare Worker is the only supported Internet edge. This process serves a private
VPC/Tunnel listener, persists to one SQLite volume, and launches the usable free tier with paid
checkout explicitly disabled until a verified live billing adapter is configured.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import errno
import json
import logging
import os
from pathlib import Path
import re
import signal
import sqlite3
import stat
import threading
from types import MethodType
from typing import Mapping
from urllib.parse import urlsplit

from .billing import DisabledBilling
from .canary_reaper import CanaryReaper, CanaryReaperError
from heel.crypto import SigningAuthority, load_private_key_base64, load_public_key_set
from .host_authority import HostAuthorityConfig, PeerProfile
from .host_snapshot import HostAuthorityService, HostAuthorityServiceError
from .http_api import ControlPlane, serve
from .migrate import CONTROL_PLANE_MIGRATIONS, Migrator

_LOGGER = logging.getLogger("heel.saas.control_plane")

try:
    import fcntl
except ImportError:  # pragma: no cover - production is explicitly POSIX-only
    fcntl = None


class ProductionConfigurationError(RuntimeError):
    """A required production invariant is absent or unsafe."""


@dataclass(eq=False)
class _RetainedOwnership:
    reason: str
    server: object
    control_plane: object
    database_lock: object
    reaper: object
    host_authority: object = field(default=None)


# Database ownership this process could not release safely: a worker thread (host-authority
# listener or canary reaper) outlived its bounded stop.  Each record keeps strong references to
# the server, control plane, process lock, reaper and host-authority service, so neither garbage
# collection nor a lost exception frame can close the lock descriptor or the shared connection
# while that worker may still run.  A record is added when a start or close path retains
# ownership and is removed only when a later production ``server_close`` on the same server
# completes (both workers joined, everything released by that close).  Nothing here releases
# or restarts a retained owner automatically, even after its thread ends; a ``build_server`` that
# raised never returned a handle, so its record lives until the process exits and the kernel
# releases the lock (supervisor recovery).
_RETAINED_OWNERSHIP: list[_RetainedOwnership] = []
_RETAINED_OWNERSHIP_LOCK = threading.Lock()


def _retain_ownership(record: _RetainedOwnership) -> _RetainedOwnership:
    with _RETAINED_OWNERSHIP_LOCK:
        if not any(existing is record for existing in _RETAINED_OWNERSHIP):
            _RETAINED_OWNERSHIP.append(record)
    _LOGGER.error(json.dumps({
        "event": "control_plane_ownership_retained", "reason": record.reason,
    }, sort_keys=True, separators=(",", ":")))
    return record


def _forget_retained_ownership(record: _RetainedOwnership) -> None:
    with _RETAINED_OWNERSHIP_LOCK:
        _RETAINED_OWNERSHIP[:] = [existing for existing in _RETAINED_OWNERSHIP if existing is not record]


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
    runner_auth_pepper: bytes
    api_key_pepper: str
    edge_auth_secret: str
    host: str
    port: int
    billing_mode: str
    grant_authority: SigningAuthority
    grant_trusted_keys: dict[str, object]
    host_authority: HostAuthorityConfig | None = None
    managed_host: bool = False

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
        runner_pepper = _canonical_pepper(
            env.get("HEEL_RUNNER_AUTH_PEPPER_B64", "").strip(),
            "HEEL_RUNNER_AUTH_PEPPER_B64",
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
        host_authority, managed_host = _host_authority_from_environment(env, database)
        return cls(
            str(database), public_origin, device_pepper, runner_pepper, api_pepper, edge_auth_value,
            host, port, billing_mode, authority, trusted_keys, host_authority, managed_host,
        )


def _host_authority_from_environment(
    env: Mapping[str, str], database: Path,
) -> tuple[HostAuthorityConfig | None, bool]:
    """The private host-authority listener: off unless configured, mandatory on a managed host."""
    managed_value = env.get("HEEL_MANAGED_HOST")
    if managed_value is None:
        managed = False
    elif managed_value == "1":
        managed = True
    else:
        raise ProductionConfigurationError("HEEL_MANAGED_HOST must be 1 when set")
    socket_value = env.get("HEEL_HOST_AUTHORITY_SOCKET", "").strip()
    uid_value = env.get("HEEL_HOST_AUTHORITY_PEER_UID", "").strip()
    profile_value = env.get("HEEL_HOST_AUTHORITY_PEER_PROFILE", "").strip()
    if managed:
        if not socket_value:
            raise ProductionConfigurationError("HEEL_MANAGED_HOST=1 requires HEEL_HOST_AUTHORITY_SOCKET")
        if uid_value != "0":
            raise ProductionConfigurationError("HEEL_MANAGED_HOST=1 requires HEEL_HOST_AUTHORITY_PEER_UID=0")
        if profile_value != PeerProfile.EXTERNAL_PIDNS.value:
            raise ProductionConfigurationError(
                "HEEL_MANAGED_HOST=1 requires HEEL_HOST_AUTHORITY_PEER_PROFILE=external-pidns"
            )
    if not socket_value:
        if uid_value or profile_value:
            raise ProductionConfigurationError(
                "HEEL_HOST_AUTHORITY_SOCKET is required when a host authority peer is configured"
            )
        return None, managed
    volume = os.path.dirname(str(database))
    socket_directory = os.path.dirname(socket_value)
    if (
        "\0" in socket_value
        or not os.path.isabs(socket_value)
        or os.path.normpath(socket_value) != socket_value
        or not (socket_directory == volume or socket_directory.startswith(volume.rstrip("/") + "/"))
        or socket_value in {
            str(database), str(database) + ".lock", str(database) + "-wal", str(database) + "-shm",
            str(database) + "-journal",
        }
    ):
        raise ProductionConfigurationError(
            "HEEL_HOST_AUTHORITY_SOCKET must be an absolute path below the database volume"
        )
    if not re.fullmatch(r"[0-9]{1,10}", uid_value) or not 0 <= int(uid_value) < 2 ** 32 - 1:
        raise ProductionConfigurationError("HEEL_HOST_AUTHORITY_PEER_UID must be an integer uid")
    try:
        profile = PeerProfile(profile_value)
    except ValueError:
        raise ProductionConfigurationError(
            "HEEL_HOST_AUTHORITY_PEER_PROFILE must be external-pidns or shared-pidns"
        ) from None
    return HostAuthorityConfig(socket_value, int(uid_value), profile), managed


def build_server(config: ProductionConfiguration):
    """Construct the private listener after every production invariant has passed."""
    # Resolve the explicitly pinned control-plane dependency before we acquire the durable
    # database process lock or bind a listener. A deployment missing the safe resolver is not a
    # partially usable live-verification deployment.
    try:
        from .network_guard import BoundedDNSResolver, PinnedHTTPSVerifier
        environment_resolver = BoundedDNSResolver()
        environment_verifier = PinnedHTTPSVerifier(resolver=environment_resolver)
    except Exception as exc:
        raise ProductionConfigurationError(
            "verified environments require the pinned dnspython==2.8.0 control-plane dependency"
        ) from exc
    database_lock = _SingleProcessDatabaseLock.acquire(config.database_path)
    control_plane = None
    server = None
    reaper = None
    host_authority = None
    ownership_retained = False
    try:
        migration_connection = sqlite3.connect(config.database_path)
        try:
            migration_connection.execute("PRAGMA foreign_keys=ON")
            migration_connection.execute("PRAGMA busy_timeout=5000")
            migrator = Migrator(migration_connection, CONTROL_PLANE_MIGRATIONS)
            migrator.apply_all()
            if migrator.current_version() != CONTROL_PLANE_MIGRATIONS[-1].version:
                raise ProductionConfigurationError("control-plane schema is not current")
            from .runner_auth import validate_runner_auth_schema
            validate_runner_auth_schema(migration_connection)
        finally:
            migration_connection.close()

        control_plane = ControlPlane(
            config.database_path,
            device_token_pepper=config.device_token_pepper,
            runner_auth_pepper=config.runner_auth_pepper,
            enable_device_auth=True,
            public_origin=config.public_origin,
            billing=DisabledBilling(),
            trust_edge_client_key=True,
            edge_auth_secret=config.edge_auth_secret,
            grant_authority=config.grant_authority,
            grant_trusted_keys=config.grant_trusted_keys,
            environment_https_verifier=environment_verifier,
            environment_dns_txt=environment_resolver,
        )
        # One process owns this database. WAL keeps reads responsive; FULL preserves accepted
        # findings and auth state across an abrupt host restart on a durable volume.
        control_plane.store.conn.execute("PRAGMA journal_mode=WAL")
        control_plane.store.conn.execute("PRAGMA synchronous=FULL")
        control_plane.required_schema_version = CONTROL_PLANE_MIGRATIONS[-1].version
        server = serve(control_plane, config.host, config.port)
        server.reaper_failure = None
        server.reaper_ready = False

        def reaper_failed(error: BaseException) -> None:
            # The existing readiness endpoint already fails closed while draining.  Marking the
            # whole node draining also prevents a dead lifecycle authority from accepting new
            # grants before an operator restarts the single-node deployment.
            server.reaper_failure = error
            server.reaper_ready = False
            control_plane.draining = True

        reaper = CanaryReaper(
            config.database_path,
            signing=config.grant_authority,
            runner_auth_pepper=config.runner_auth_pepper,
            on_unexpected_death=reaper_failed,
        )
        server.canary_reaper = reaper
        try:
            reaper.start()
        except Exception as error:
            # The listener has only been bound, never returned as ready.  Its ordinary close path
            # owns the control plane until the production lifecycle wrapper is installed.
            server.server_close()
            server = None
            control_plane = None
            raise ProductionConfigurationError(
                "canary lifecycle coordinator failed to start"
            ) from error
        server.reaper_ready = True
        server.ready_lock = threading.Lock()
        server.host_authority = None
        server.host_authority_ready = False
        server.host_authority_failure = None
        if config.host_authority is not None:
            owned_server, owned_control_plane = server, control_plane

            def host_authority_failed(error: BaseException) -> None:
                # Runs on the listener thread after its state lock was released; never stops it.
                with owned_server.ready_lock:
                    owned_server.host_authority_failure = error
                    owned_server.host_authority_ready = False
                    reaper_failed(error)

            host_authority = HostAuthorityService(
                config.host_authority,
                config.database_path,
                signing=config.grant_authority,
                draining=lambda: owned_control_plane.draining,
                on_unexpected_death=host_authority_failed,
            )
            try:
                host_authority.start()
                with server.ready_lock:
                    # Readiness only from ``alive`` under the lock the death callback takes, so a
                    # death before or after this assignment can never leave it True.
                    server.host_authority_ready = host_authority.alive
                    ready = server.host_authority_ready
                if not ready:
                    raise HostAuthorityServiceError("startup_failed")
            except Exception as error:
                # start() already stopped on its own failures; never stop (or start) twice.
                result = getattr(error, "stop_result", None) or host_authority.stop()
                # Joining the reaper releases nothing; it lets the process end once the last
                # worker ends instead of reconciling forever behind a failed start.
                reaper_stopped = reaper.stop()
                if not result.stopped:
                    ownership_retained = True
                    server.host_authority_failure = error
                    raise HostAuthorityServiceError("stop_timeout", stop_result=result) from error
                if not reaper_stopped:
                    ownership_retained = True
                    raise CanaryReaperError(
                        "canary lifecycle coordinator did not stop within the shutdown bound"
                    ) from error
                server.server_close()
                server = None
                control_plane = None
                raise ProductionConfigurationError("host authority listener failed to start") from error
            server.host_authority = host_authority
        _install_production_close(server, reaper, database_lock, host_authority)
        return server
    except Exception as error:
        if ownership_retained:
            # A worker outlived its bounded stop: release nothing, keep every owned resource
            # strongly referenced until the process exits (supervisor recovery).
            _retain_ownership(_RetainedOwnership(
                reason=getattr(error, "code", None) or "reaper_stop_timeout",
                server=server, control_plane=control_plane, database_lock=database_lock,
                reaper=reaper, host_authority=host_authority,
            ))
            raise
        if server is not None:
            server.server_close()
        elif control_plane is not None:
            control_plane.close()
        database_lock.close()
        raise


def _install_production_close(
    server, reaper: CanaryReaper, database_lock, host_authority: HostAuthorityService | None = None,
) -> None:
    """Install the production-only close order without changing direct/test ControlPlane use.

    Order: draining, TCP close and drain, host-authority stop, reaper stop, checkpoint, control
    plane, callbacks, process lock.  A worker that does not stop raises before any release and
    leaves ``closed`` False, so a repeated ``server_close`` is a retry.
    """
    close_lock = threading.Lock()
    closed = False
    retained: list[_RetainedOwnership] = []

    def retain(reason: str) -> None:
        with server.ready_lock:
            server.host_authority_ready = False
            server.reaper_ready = False
        if not retained:
            retained.append(_RetainedOwnership(
                reason=reason, server=server, control_plane=server.control_plane,
                database_lock=database_lock, reaper=reaper, host_authority=host_authority,
            ))
        _retain_ownership(retained[0])

    def production_server_close(bound_server) -> None:
        nonlocal closed
        with close_lock:
            if closed:
                return
            bound_server.control_plane.draining = True
            # Close the listener first, then wait for accepted request handlers.  Calling the
            # direct base implementation avoids http_api's generic owner close, which would close
            # SQLite before the reaper is joined.
            from socketserver import TCPServer
            TCPServer.server_close(bound_server)
            drained = bound_server.wait_for_request_drain()
            if not drained:
                _LOGGER.error(json.dumps({
                    "event": "control_plane_drain_timeout",
                }, sort_keys=True, separators=(",", ":")))
            if host_authority is not None:
                result = host_authority.stop()
                if not result.stopped:
                    retain("stop_timeout")
                    raise HostAuthorityServiceError("stop_timeout", stop_result=result)
            if not reaper.stop():
                retain("reaper_stop_timeout")
                raise CanaryReaperError(
                    "canary lifecycle coordinator did not stop within the shutdown bound"
                )
            bound_server.reaper_ready = False
            bound_server.host_authority_ready = False
            try:
                try:
                    bound_server.control_plane.store.conn.execute(
                        "PRAGMA wal_checkpoint(TRUNCATE)"
                    )
                except Exception:
                    pass
                bound_server.control_plane.close()
                bound_server._owns_control_plane = False
                callbacks, bound_server._close_callbacks = bound_server._close_callbacks, []
                for callback in reversed(callbacks):
                    callback()
            finally:
                database_lock.close()
            closed = True
            if retained:
                _forget_retained_ownership(retained[0])

    server.server_close = MethodType(production_server_close, server)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    config = ProductionConfiguration.from_environment()
    server = build_server(config)
    _LOGGER.info(json.dumps({
        "billing_mode": config.billing_mode,
        "event": "control_plane_started",
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
