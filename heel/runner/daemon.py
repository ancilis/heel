"""Runner-side pairing lifecycle: ``heel runner pair``, ``status`` and ``unpair``.

This module only composes existing authority. The ceremony is the server's
invite → exchange → human approve (phrase + fingerprint) → activate protocol; the signed
local journal, paired identity and runtime cursor are the existing ``RunnerStore`` and
``RunnerRuntimeState`` records; the Ed25519 seed lives only in the OS secret store behind
``SystemSecureSigner``; every network call is ``HTTPSControlTransport`` to one origin.

The small daemon record (``$HEEL_HOME/runner-daemon/pairing.json``) holds only public
coordinates: the pinned origin, the random installation ID that names the OS secret-store
account, and the IDs the cloud assigned. It never holds key material, tokens or labels.

``serve`` keeps the paired runner online over the existing ``RunnerService`` /
``RunnerCoordinator`` / ``RunnerControlClient`` composition. One serve per ``HEEL_HOME`` holds a
non-blocking kernel lock on ``.serve.lock``; its visible state is ``serve-state.json`` (public
coordinates only). There is no target execution bridge yet: any claimed lease ends the serve with
the closed ``execution_unavailable`` code and no target traffic.

Test code may inject a secret backend or an explicit CA bundle through the constructor; the CLI
never passes either.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from heel.canary_contracts import canonical_bytes
from heel.crypto import ed25519_key_id, load_public_key_base64
from heel.scope import heel_home

from . import identity as _identity
from .catalog import CATALOG
from .control_client import RunnerControlClient
from .control_transport import (
    CONTROL_TIMEOUT_SECONDS, ControlTransportError, HTTPSControlTransport, validate_control_origin,
)
from .identity import (
    LinuxSecretServiceBackend, MacOSKeychainSecretBackend, OSSecretBackend, SystemSecureSigner,
    create_runner_pairing_material, runner_pairing_signer_label,
)
from .coordinator import RunnerCoordinator
from .runtime import RunnerRuntimeState, RunnerRuntimeStateError, RunnerRuntimeUnavailable
from .service import RunnerService
from .store import (
    _LOCK_FLAGS, PLAN_LABEL_ROLES, RunnerStore, RunnerStoreError, _flock, _open_child, _read_json,
    _secure_directory, _secure_regular, _write_json,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - the runner store already requires fcntl
    fcntl = None  # type: ignore[assignment]


_DAEMON_DIRECTORY = "runner-daemon"
_DAEMON_RECORD = "pairing.json"
_DAEMON_RECORD_SCHEMA = "heel.runner-daemon-pairing.v1"
_RUNTIME_FILENAME = "runtime.sqlite3"
_STORE_PAIRING_FILES = (
    "paired-identity.json", "pairing-activation.json", "pairing-activation-abort-request.json",
)
_INVITATION = re.compile(r"^[A-Za-z0-9+/]{43}=$", flags=re.ASCII)
_PAIRING_ID = re.compile(r"^pending_[0-9a-f]{32}$", flags=re.ASCII)
_RUNNER_ID = re.compile(r"^runr_[0-9a-f]{32}$", flags=re.ASCII)
_PENDING_V3_FIELDS = frozenset({
    "schema_version", "pairing_id", "runner_id", "fingerprint", "status",
    "activation_challenge", "control_protocol", "pairing_exchange_digest",
    "challenge_expires_at_ms",
})
_RECORD_FIELDS = frozenset({
    "schema_version", "state", "origin", "installation_id", "display_name", "created_at_ms",
    "pairing_id", "runner_id", "workspace_id", "runner_key_id", "fingerprint",
})
# Written with an active record from a v4 activation. A record without both (paired before the
# grant-authority bootstrap) stays loadable so it can be inspected and unpaired.
_AUTHORITY_FIELDS = frozenset({"grant_authority_key_id", "grant_authority_public_key_b64"})
_REPAIR_STEPS = ["heel runner unpair", "heel runner pair --origin <origin> --invite <new token>"]
_PLAN_ROLES = ("lower_plan", "higher_plan")
DEFAULT_POLL_INTERVAL_SECONDS = 2.0
NO_SECRET_SERVICE = "no supported runner OS secret service"
_SERVE_LOCK = ".serve.lock"
_SERVE_STATE = "serve-state.json"
_SERVE_STATE_SCHEMA = "heel.runner-serve-state.v1"
_SERVE_STATES = frozenset({"starting", "online", "offline", "revoked", "stopped", "failed"})
_SERVE_STATE_FIELDS = frozenset({
    "schema_version", "state", "runner_id", "since_ms", "updated_at_ms", "last_error_code",
    "binding_id", "access", "pid",
})
# Answers of a live edge whose upstream control plane is unreachable (the Worker's 502/503).
_UPSTREAM_UNAVAILABLE = frozenset({502, 503, 504})
SERVE_IDLE_POLL_SECONDS = 2.0
SERVE_BACKOFF_SECONDS = (2.0, 60.0)
_SERVE_STATE_REFRESH_SECONDS = 15.0
# Exit codes of ``heel runner serve``: stopped, offline (``--once`` only), failed, revoked.
SERVE_EXIT_CODES = {"stopped": 0, "offline": 1, "failed": 2, "revoked": 3}


class RunnerPairingError(RuntimeError):
    """A closed, secret-free pairing lifecycle failure."""

    def __init__(self, code: str, message: str | None = None):
        super().__init__(message or code)
        self.code = code


class _RecordOwnershipLost(RunnerPairingError):
    """The daemon record no longer names this pair attempt (unpaired or replaced meanwhile)."""

    def __init__(self):
        super().__init__("local_state_invalid")


class RunnerServeError(RunnerPairingError):
    """A closed ``serve`` outcome; ``state`` is the serve state it ended in."""

    def __init__(self, code: str, *, state: str = "failed"):
        super().__init__(code)
        self.state = state


class _ControlCallRejected(RuntimeError):
    """Raised from the one control call that received this answer.

    Classifying from the exception the failing call raised (never from transport attributes that
    the heartbeat, stop-ack and polling threads share) keeps an older or concurrent 503 from turning
    a malformed or unauthorized answer into an offline retry.
    """

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _AttributedTransport:
    """``HTTPSControlTransport`` whose availability and authority refusals raise per call."""

    def __init__(self, transport: HTTPSControlTransport):
        self._transport = transport

    def post(self, path: str, *, headers: Mapping[str, str] | None = None, body: bytes = b""):
        status, response_headers, payload = self._transport.post(path, headers=headers, body=body)
        code = payload.get("code") if isinstance(payload, dict) else None
        if status in _UPSTREAM_UNAVAILABLE:
            raise _ControlCallRejected("upstream_unavailable")
        if status == 401 and code == "invalid_runner_auth":
            raise _ControlCallRejected("runner_revoked")
        if status == 403 and code == "runner_protocol_upgrade_required":
            raise _ControlCallRejected("protocol_upgrade_required")
        return status, response_headers, payload


def _serve_failure(error: BaseException) -> tuple[str, str]:
    """Map one cycle failure to ``(serve state, closed code)`` from its own ``__cause__`` chain."""
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen and len(seen) < 32:
        seen.add(id(current))
        if isinstance(current, _ControlCallRejected):
            if current.code == "upstream_unavailable":
                return "offline", current.code
            return ("revoked" if current.code == "runner_revoked" else "failed"), current.code
        if isinstance(current, ControlTransportError):
            if current.code in {"connection_failed", "timeout"}:
                return "offline", current.code
            return "failed", current.code
        if isinstance(current, RunnerServeError):
            return current.state, current.code
        if isinstance(current, (RunnerStoreError, RunnerRuntimeStateError, RunnerRuntimeUnavailable)):
            return "failed", "local_state_invalid"
        # Only an explicit ``raise … from`` cause belongs to this failure; an implicit context is
        # whatever an unrelated handler happened to be processing.
        current = current.__cause__
    # Malformed, replayed-time or regressed-generation answers end as decoding errors: closed.
    if isinstance(error, (ValueError, TypeError, KeyError)):
        return "failed", "response_rejected"
    return "failed", "local_state_invalid"


def _open_serve_lock(directory: int) -> int:
    """Open the instance lock: no symlink, one link, owner-only, never unlinked (stable inode)."""
    # Concurrent first ``O_CREAT`` opens can fail with ENOENT on macOS (the R-A ``openat`` race);
    # retry a few times, then let the caller fail closed.
    for attempt in range(8):
        try:
            descriptor = os.open(_SERVE_LOCK, _LOCK_FLAGS, 0o600, dir_fd=directory)
            break
        except FileNotFoundError:
            if attempt == 7:
                raise
            time.sleep(0.005 * (attempt + 1))
    try:
        _secure_regular(os.fstat(descriptor), "runner serve lock")
        os.fchmod(descriptor, 0o600)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _try_flock(descriptor: int, operation: int) -> bool:
    assert fcntl is not None
    try:
        fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _release_serve_lock(descriptor: int) -> None:
    assert fcntl is not None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _random_nonce(_key: object) -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def _adapter_versions() -> dict[str, str]:
    return {entry["scenario_id"]: entry["adapter_version"] for entry in CATALOG}


def _delete_signer_seed(backend: OSSecretBackend, label: str) -> None:
    """Remove one pairing seed; a missing seed is already removed."""
    delete = getattr(backend, "delete", None)
    if callable(delete):
        delete(label)
        return
    if isinstance(backend, MacOSKeychainSecretBackend):
        result = _identity._run_bounded_security(
            ("delete-generic-password", "-s", backend.service, "-a", backend._label(label)),
            payload=None, popen=backend._popen,
        )
        if result.returncode not in (0, 44):
            raise RuntimeError("runner OS secret service unavailable")
        return
    if isinstance(backend, LinuxSecretServiceBackend):
        result = _identity._run_bounded_secret_tool(
            ("clear", "heel", "runner", "label", backend._label(label)),
            payload=None, popen=backend._popen,
        )
        if result.returncode != 0:
            raise RuntimeError("runner OS secret service unavailable")
        return
    raise RuntimeError("runner signing key cannot be removed")


def self_serve_access(store: RunnerStore) -> dict[str, Any]:
    """Report whether both plan roles carry operator plan labels (labels only, never handles)."""
    records: list[dict[str, Any]] = []
    if store.is_context_bound:
        records = [item for item in store.list_credentials() if item["state"] == "active"]
    by_role = {item["semantic_role"]: item for item in records if item["semantic_role"] in PLAN_LABEL_ROLES}
    labels = [
        {"role": role, "label": by_role[role]["plan_label"]}
        for role in _PLAN_ROLES if role in by_role and "plan_label" in by_role[role]
    ]
    if len(labels) == len(_PLAN_ROLES):
        return {"state": "access.ready", "plan_labels": labels}
    missing_credential = [role for role in _PLAN_ROLES if role not in by_role]
    return {
        "state": "access.incomplete",
        "reason": "credential_missing" if missing_credential else "plan_label_missing",
        "plan_labels": labels,
        "next_steps": [
            f"heel runner credential add --role {role} --plan-label <your {role.replace('_', '-')} name>"
            " --profile <bearer|cookie_jar|x_api_key> --backend <keychain|secret-service>"
            for role in _PLAN_ROLES if role in missing_credential
        ],
    }


class _ExecutionUnavailable:
    """The ``serve`` executor until the plan-differential bridge exists: never executes."""

    def execute(self, lease, *, cancellation, on_progress):
        raise RunnerServeError("execution_unavailable")


class _ServeCoordinator:
    """``RunnerService`` adapter owned by one serve cycle.

    Every service worker (idle loop, maintenance, heartbeat, stop control) reaches the runner only
    through this object, so it is the cycle's explicit ownership gate: ``close`` refuses any later
    call and waits for calls in flight, before the runtime closes and the instance lock is
    released. It also reports each authenticated poll and refuses every lease before the service
    starts its heartbeat worker, so nothing is acknowledged, heartbeated as running or
    terminalized; the server's reaper ends the claimed run.
    """

    def __init__(self, coordinator: RunnerCoordinator, on_contact: Callable[[], None]):
        self._coordinator = coordinator
        self._on_contact = on_contact
        self._calls = threading.Condition()
        self._in_flight = 0
        self._closed = False

    def _enter(self) -> None:
        with self._calls:
            if self._closed:
                raise RunnerServeError("local_state_invalid")
            self._in_flight += 1

    def _leave(self) -> None:
        with self._calls:
            self._in_flight -= 1
            self._calls.notify_all()

    def close(self) -> None:
        """No further call; return once every call already in flight has finished."""
        with self._calls:
            self._closed = True
            while self._in_flight:
                self._calls.wait()

    def ensure_runner_context(self) -> bool:
        self._enter()
        try:
            bound = self._coordinator.ensure_runner_context()
            self._on_contact()
            return bound
        finally:
            self._leave()

    def claim(self):
        self._enter()
        try:
            runtime = self._coordinator.control.runtime
            before = {item.run_id for item in runtime.load_active_run_controls(limit=64)}
            try:
                lease = self._coordinator.claim()
            except Exception:
                # The claim response arrived and was recorded, but the lease cannot even be
                # decoded locally (a legacy catalog projection has no local approved pair).
                if {item.run_id for item in runtime.load_active_run_controls(limit=64)} - before:
                    raise RunnerServeError("execution_unavailable") from None
                raise
            if lease is None:
                self._on_contact()
                return None
            raise RunnerServeError("execution_unavailable")
        finally:
            self._leave()

    def maintenance_once(self, *, limit: int):
        self._enter()
        try:
            return self._coordinator.maintenance_once(limit=limit)
        finally:
            self._leave()

    def heartbeat(self, run_id, operational_projection):
        raise RunnerServeError("execution_unavailable")

    progress = result = heartbeat

    def stop_ack(self, run_id, operational_projection, *, deadline):
        raise RunnerServeError("execution_unavailable")


class RunnerDaemon:
    """Pair, inspect, serve and unpair the one local runner identity under ``HEEL_HOME``."""

    def __init__(
        self, root: Path | str | None = None, *,
        secret_backend: OSSecretBackend | None = None,
        ca_bundle: Path | str | None = None,
        clock_ms: Callable[[], int] = _now_ms,
        sleep: Callable[[float], None] = time.sleep,
        poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
        transport_timeout_seconds: float | None = None,
        serve_idle_poll_seconds: float = SERVE_IDLE_POLL_SECONDS,
        serve_backoff_seconds: tuple[float, float] = SERVE_BACKOFF_SECONDS,
    ):
        self.root = Path(heel_home()) if root is None else Path(root)
        self._secret_backend = secret_backend
        self._ca_bundle = ca_bundle
        self._clock_ms = clock_ms
        self._sleep = sleep
        self._poll_interval = poll_interval_seconds
        self._transport_timeout = transport_timeout_seconds
        self._serve_idle_poll = serve_idle_poll_seconds
        self._serve_backoff = serve_backoff_seconds
        self._shutdown = threading.Event()
        self._cycle_stop: threading.Event | None = None
        self._service: RunnerService | None = None

    # ------------------------------------------------------------------ local state
    def _store(self) -> RunnerStore:
        return RunnerStore(self.root)

    @property
    def runtime_path(self) -> Path:
        return self._store().root / "runner" / _RUNTIME_FILENAME

    def _transport(self, origin: str) -> HTTPSControlTransport:
        options: dict[str, Any] = {"ca_bundle": self._ca_bundle}
        if self._transport_timeout is not None:
            options["timeout_seconds"] = self._transport_timeout
        return HTTPSControlTransport(origin, **options)

    def _backend(self) -> OSSecretBackend:
        try:
            return SystemSecureSigner._backend(self._secret_backend)
        except RuntimeError:
            raise RunnerPairingError("no_supported_secret_service", NO_SECRET_SERVICE) from None

    def _daemon_fd(self, store: RunnerStore, *, create: bool) -> int | None:
        root_fd = store._open_root(create=create)
        if root_fd is None:
            return None
        try:
            directory = _open_child(root_fd, _DAEMON_DIRECTORY, create=create)
            if directory is not None:
                _secure_directory(directory, "Heel runner daemon directory")
            return directory
        finally:
            os.close(root_fd)

    def _load_record(self, store: RunnerStore) -> dict[str, Any] | None:
        directory = self._daemon_fd(store, create=False)
        if directory is None:
            return None
        try:
            with _flock(directory, ".daemon.lock", exclusive=False):
                value = _read_json(directory, _DAEMON_RECORD, None)
        finally:
            os.close(directory)
        if value is None:
            return None
        return self._validate_record(value)

    @staticmethod
    def _validate_record(value: object) -> dict[str, Any]:
        if not isinstance(value, Mapping) or set(value) not in (_RECORD_FIELDS, _RECORD_FIELDS | _AUTHORITY_FIELDS):
            raise RunnerPairingError("local_state_invalid")
        record = dict(value)
        if _AUTHORITY_FIELDS <= set(record) and (
            record["state"] != "active"
            or not all(type(record[field]) is str for field in _AUTHORITY_FIELDS)
        ):
            raise RunnerPairingError("local_state_invalid")
        try:
            validate_control_origin(record["origin"])
            runner_pairing_signer_label(record["installation_id"])
        except (ControlTransportError, ValueError):
            raise RunnerPairingError("local_state_invalid") from None
        if (
            record["schema_version"] != _DAEMON_RECORD_SCHEMA
            or record["state"] not in {"preparing", "exchanged", "active"}
            or type(record["created_at_ms"]) is not int
            or type(record["display_name"]) is not str
        ):
            raise RunnerPairingError("local_state_invalid")
        if record["state"] == "active" and not all(
            type(record[field]) is str and record[field]
            for field in ("pairing_id", "runner_id", "workspace_id", "runner_key_id", "fingerprint")
        ):
            raise RunnerPairingError("local_state_invalid")
        return record

    @staticmethod
    def _grant_authority(record: Mapping[str, Any]) -> dict[str, str] | None:
        """The record's cloud grant-signing key, or None when absent or inconsistent."""
        if not _AUTHORITY_FIELDS <= set(record):
            return None
        key_id, public_key_b64 = record["grant_authority_key_id"], record["grant_authority_public_key_b64"]
        try:
            if len(public_key_b64) != 44:
                return None
            load_public_key_base64(public_key_b64)
            if ed25519_key_id(base64.b64decode(public_key_b64, validate=True)) != key_id:
                return None
        except (TypeError, ValueError):
            return None
        return {"key_id": key_id, "public_key_b64": public_key_b64}

    def _reserve_record(self, store: RunnerStore, record: Mapping[str, Any]) -> None:
        """Check for local pairing state and write this attempt's record in one critical section."""
        validated = self._validate_record(record)
        directory = self._daemon_fd(store, create=True)
        assert directory is not None
        try:
            with _flock(directory, ".daemon.lock", exclusive=True):
                existing = _read_json(directory, _DAEMON_RECORD, None)
                if existing is not None:
                    existing = self._validate_record(existing)
                    raise RunnerPairingError(
                        "already_paired" if existing["state"] == "active" else "pairing_incomplete",
                    )
                if self._store_pairing_files(store) or store.is_context_bound:
                    raise RunnerPairingError("local_state_invalid")
                _write_json(directory, _DAEMON_RECORD, validated)
        finally:
            os.close(directory)

    def _write_record(self, store: RunnerStore, record: Mapping[str, Any]) -> None:
        """Update this attempt's record; never write over another attempt's or a removed one."""
        validated = self._validate_record(record)
        directory = self._daemon_fd(store, create=False)
        if directory is None:
            raise _RecordOwnershipLost()
        try:
            with _flock(directory, ".daemon.lock", exclusive=True):
                current = _read_json(directory, _DAEMON_RECORD, None)
                if not isinstance(current, Mapping) or current.get("installation_id") != validated["installation_id"]:
                    raise _RecordOwnershipLost()
                _write_json(directory, _DAEMON_RECORD, validated)
        finally:
            os.close(directory)

    def _remove_record(self, store: RunnerStore, installation_id: str) -> bool:
        """Remove the record only while it still names ``installation_id``."""
        directory = self._daemon_fd(store, create=False)
        if directory is None:
            return False
        try:
            with _flock(directory, ".daemon.lock", exclusive=True):
                current = _read_json(directory, _DAEMON_RECORD, None)
                if not isinstance(current, Mapping) or current.get("installation_id") != installation_id:
                    return False
                os.unlink(_DAEMON_RECORD, dir_fd=directory)
                os.fsync(directory)
                return True
        finally:
            os.close(directory)

    @staticmethod
    def _store_pairing_files(store: RunnerStore) -> list[str]:
        with store._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=False):
                return [name for name in _STORE_PAIRING_FILES if _read_json(runner_fd, name, None) is not None]

    # ------------------------------------------------------------------ serve instance
    def _lock_grace_seconds(self) -> float:
        # A status probe holds the lock shared for at most one bounded control call.
        return (self._transport_timeout or CONTROL_TIMEOUT_SECONDS) + 1.0

    def _acquire_serve_lock(self, directory: int, *, refusal: str) -> int:
        """Hold ``.serve.lock`` exclusively, or refuse at once while another serve/unpair holds it.

        Kernel ``flock`` ownership ends with the process (SIGKILL included), so no PID or state
        file is ever consulted. Shared holders are ``status`` probes; wait for those briefly.
        """
        assert fcntl is not None
        deadline = time.monotonic() + self._lock_grace_seconds()
        descriptor = _open_serve_lock(directory)
        try:
            while not _try_flock(descriptor, fcntl.LOCK_EX):
                probe = _open_serve_lock(directory)
                try:
                    shared_only = _try_flock(probe, fcntl.LOCK_SH)
                finally:
                    os.close(probe)
                if not shared_only or time.monotonic() >= deadline:
                    raise RunnerServeError(refusal)
                time.sleep(0.02)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _probe_serve_lock(self, directory: int) -> int | None:
        """Hold ``.serve.lock`` shared when no serve runs (keeps one serve off the claim chain)."""
        assert fcntl is not None
        descriptor = _open_serve_lock(directory)
        if _try_flock(descriptor, fcntl.LOCK_SH):
            return descriptor
        os.close(descriptor)
        return None

    @staticmethod
    def _read_serve_state(directory: int, runner_id: str) -> dict[str, Any] | None:
        """The last serve state written for this pairing; anything else is not authority."""
        try:
            value = _read_json(directory, _SERVE_STATE, None)
        except (RunnerStoreError, OSError):
            return None
        if (
            not isinstance(value, Mapping) or set(value) != _SERVE_STATE_FIELDS
            or value["schema_version"] != _SERVE_STATE_SCHEMA or value["state"] not in _SERVE_STATES
            or value["runner_id"] != runner_id
        ):
            return None
        return dict(value)

    def _serve_view(self, directory: int, record: Mapping[str, Any], *, running: bool) -> dict[str, Any]:
        state = self._read_serve_state(directory, record["runner_id"])
        if not running:
            # The file may be left by a serve that crashed or was killed: report it as history.
            view: dict[str, Any] = {"state": "not_running"}
            if state is not None:
                view.update(last_state=state["state"], last_error_code=state["last_error_code"],
                            updated_at_ms=state["updated_at_ms"])
            return view
        if state is None:
            return {"state": "starting"}
        return {key: state[key] for key in (
            "state", "since_ms", "updated_at_ms", "last_error_code", "binding_id", "pid",
        )}

    def request_stop(self) -> None:
        """Stop ``serve`` from any thread: end the cycle and cancel any in-flight work locally."""
        self._shutdown.set()
        cycle = self._cycle_stop
        if cycle is not None:
            cycle.set()
        service = self._service
        if service is not None:
            service.request_local_stop()

    def serve(
        self, *, once: bool = False, emit: Callable[[dict[str, Any]], None] = lambda _event: None,
    ) -> dict[str, Any]:
        """Poll the control plane as the paired runner until stopped, revoked or failed closed."""
        store = self._store()
        directory = self._daemon_fd(store, create=False)
        if directory is None:
            raise RunnerServeError("unpaired")
        lock: int | None = None
        try:
            lock = self._acquire_serve_lock(directory, refusal="already_serving")
            # Read the pairing only under instance ownership: an unpair or re-pair that finished
            # before this point is what we serve; neither can run while the lock is held.
            record = self._load_record(store)
            if record is None:
                raise RunnerServeError("unpaired")
            if record["state"] != "active":
                raise RunnerServeError("pairing_incomplete")
            return _ServeSession(self, directory, record, once=once, emit=emit).run()
        except RunnerServeError:
            raise
        except RunnerPairingError as error:
            raise RunnerServeError(error.code) from None
        except (OSError, RunnerStoreError):
            raise RunnerServeError("local_state_invalid") from None
        finally:
            if lock is not None:
                _release_serve_lock(lock)
            os.close(directory)

    # ------------------------------------------------------------------ pair
    def pair(
        self, origin: str, invitation_token: str, *, display_name: str | None = None,
        emit: Callable[[dict[str, Any]], None] = lambda _event: None,
    ) -> dict[str, Any]:
        try:
            origin = validate_control_origin(origin)[0]
        except ControlTransportError:
            raise RunnerPairingError("invalid_origin") from None
        if type(invitation_token) is not str or _INVITATION.fullmatch(invitation_token) is None:
            raise RunnerPairingError("invalid_invitation")
        name = display_name or "Heel runner"
        store = self._store()
        existing = self._load_record(store)
        if existing is not None:
            raise RunnerPairingError(
                "already_paired" if existing["state"] == "active" else "pairing_incomplete",
            )
        if self._store_pairing_files(store) or store.is_context_bound:
            raise RunnerPairingError("local_state_invalid")
        backend = self._backend()
        transport = self._transport(origin)
        installation_id = secrets.token_hex(16)
        label = runner_pairing_signer_label(installation_id)
        record: dict[str, Any] = {
            "schema_version": _DAEMON_RECORD_SCHEMA, "state": "preparing", "origin": origin,
            "installation_id": installation_id, "display_name": name,
            "created_at_ms": self._clock_ms(), "pairing_id": None, "runner_id": None,
            "workspace_id": None, "runner_key_id": None, "fingerprint": None,
        }
        # The record is reserved before the seed so an interrupted pair can always be unpaired,
        # and a concurrent pair on this HEEL_HOME either sees it or is seen by it.
        self._reserve_record(store, record)
        exchanged = seed_created = False
        try:
            try:
                signer = SystemSecureSigner.create_new(label, backend=backend)
            except (RuntimeError, ValueError):
                raise RunnerPairingError("no_supported_secret_service", NO_SECRET_SERVICE) from None
            seed_created = True
            # Pair only a key the OS store can give back: a seed that does not reload to the same
            # key would activate a runner whose identity is lost on the next restart.
            try:
                reloaded = SystemSecureSigner.load_existing(label, backend=backend)
            except (RuntimeError, ValueError):
                reloaded = None
            if reloaded is None or reloaded.key_id != signer.key_id:
                raise RunnerPairingError("secret_store_unverified")
            from heel import __version__
            material = create_runner_pairing_material(
                name, __version__, _adapter_versions(), signer,
            )
            exchange = material.executable_exchange_request(invitation_token)
            exchange_bytes = canonical_bytes(exchange)
            pending = self._exchange(transport, exchange_bytes, material.fingerprint)
            exchanged = True
            record.update(state="exchanged", pairing_id=pending["pairing_id"], runner_id=pending["runner_id"])
            self._write_record(store, record)
            emit({
                "event": "pairing_pending", "pairing_id": pending["pairing_id"],
                "pairing_phrase": " ".join(material.pairing_phrase),
                "fingerprint": material.fingerprint,
                "approve_before_ms": pending["challenge_expires_at_ms"],
            })
            try:
                activation = material.prepare_executable_activation(
                    pending, store=store, now_ms=self._clock_ms(),
                )
            except (RunnerStoreError, ValueError):
                raise RunnerPairingError("local_state_invalid") from None
            response = self._await_activation(
                transport, pending["pairing_id"], canonical_bytes(dict(activation.request)),
                deadline_ms=pending["challenge_expires_at_ms"],
            )
            try:
                identity = store.accept_pairing_activation(activation, response, now_ms=self._clock_ms())
                runtime = RunnerRuntimeState(self.runtime_path, identity, signer)
                try:
                    store.finish_pairing_activation(runtime)
                finally:
                    runtime.close()
            except (RunnerStoreError, RunnerRuntimeStateError, ValueError):
                raise RunnerPairingError("response_rejected") from None
            # ``accept_pairing_activation`` validated this exact response (v4 only), including the
            # derived key ID; the record keeps the same public key for status and serve.
            authority = response["grant_authority"]
            authority = self._grant_authority({
                "grant_authority_key_id": authority["key_id"],
                "grant_authority_public_key_b64": authority["public_key_b64"],
            })
            if authority is None:
                raise RunnerPairingError("response_rejected")
        except BaseException as error:
            if not exchanged or isinstance(error, _RecordOwnershipLost):
                # Nothing reached the cloud's pairing state, or no record names this seed any more
                # (a concurrent unpair removed it): drop the seed, then our record if it is still
                # ours. If the seed cannot be removed the record stays so unpair can retry.
                try:
                    if seed_created:
                        _delete_signer_seed(backend, label)
                    self._remove_record(store, installation_id)
                except Exception:
                    pass
            raise
        record.update(
            state="active", workspace_id=identity.workspace_id, runner_id=identity.runner_id,
            runner_key_id=identity.key_id, fingerprint=identity.fingerprint,
            grant_authority_key_id=authority["key_id"],
            grant_authority_public_key_b64=authority["public_key_b64"],
        )
        try:
            self._write_record(store, record)
        except _RecordOwnershipLost:
            try:
                _delete_signer_seed(backend, label)
            except Exception:
                pass
            raise
        result = {
            "event": "paired", "state": "active", "origin": origin,
            "workspace_id": identity.workspace_id, "runner_id": identity.runner_id,
            "runner_key_id": identity.key_id, "fingerprint": identity.fingerprint,
        }
        emit(result)
        return result

    @staticmethod
    def _exchange(transport: HTTPSControlTransport, body: bytes, fingerprint: str) -> dict[str, Any]:
        try:
            status, _headers, payload = transport.post(
                "/v1/runner-pairings/exchange", headers={"Content-Type": "application/json"}, body=body,
            )
        except ControlTransportError as error:
            raise RunnerPairingError(error.code) from None
        if status == 400:
            # One-time, expired, wrong-workspace or reused invitations are indistinguishable.
            raise RunnerPairingError("invitation_rejected")
        if (
            status != 201 or not isinstance(payload, dict) or set(payload) != _PENDING_V3_FIELDS
            or payload["schema_version"] != "heel.runner-pairing-pending.v3"
            or type(payload["pairing_id"]) is not str or _PAIRING_ID.fullmatch(payload["pairing_id"]) is None
            or type(payload["runner_id"]) is not str or _RUNNER_ID.fullmatch(payload["runner_id"]) is None
            or payload["fingerprint"] != fingerprint or payload["status"] != "pending"
            or payload["control_protocol"] != "heel.runner-control.v2"
            or payload["pairing_exchange_digest"] != hashlib.sha256(body).hexdigest()
            or type(payload["challenge_expires_at_ms"]) is not int
            or payload["challenge_expires_at_ms"] <= 0
        ):
            raise RunnerPairingError("response_rejected")
        return dict(payload)

    def _await_activation(
        self, transport: HTTPSControlTransport, pairing_id: str, body: bytes, *, deadline_ms: int,
    ) -> dict[str, Any]:
        """Resend the one sealed activation until the human approves or the challenge expires."""
        path = f"/v1/runner-pairings/{pairing_id}/activate"
        while True:
            try:
                status, _headers, payload = transport.post(
                    path, headers={"Content-Type": "application/json"}, body=body,
                )
            except ControlTransportError as error:
                if error.code not in {"connection_failed", "timeout"}:
                    raise RunnerPairingError(error.code) from None
                status, payload = None, None
            if status == 200 and isinstance(payload, dict):
                return payload
            if status not in {None, 400}:
                raise RunnerPairingError("approval_timeout" if status == 410 else "response_rejected")
            if self._clock_ms() >= deadline_ms:
                raise RunnerPairingError("approval_timeout")
            self._sleep(self._poll_interval)

    # ------------------------------------------------------------------ status
    def _active_identity(self, store: RunnerStore, record: Mapping[str, Any]):
        label = runner_pairing_signer_label(record["installation_id"])
        backend = self._backend()
        try:
            signer = SystemSecureSigner.load_existing(label, backend=backend)
        except (RuntimeError, ValueError):
            raise RunnerPairingError("local_identity_unavailable") from None
        if signer.key_id != record["runner_key_id"]:
            raise RunnerPairingError("local_identity_unavailable")
        with store._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=False):
                paired = _read_json(runner_fd, "paired-identity.json", None)
        try:
            if not isinstance(paired, Mapping):
                raise RunnerStoreError("paired runner identity requires recovery")
            identity = RunnerStore._rotation_identity_from_record(paired.get("identity"), pairing_phrase=())
            RunnerStore._verify_paired_rotation_identity(paired, identity=identity, signer=signer)
        except RunnerStoreError:
            raise RunnerPairingError("local_identity_unavailable") from None
        if (
            identity.runner_id != record["runner_id"] or identity.workspace_id != record["workspace_id"]
            or identity.fingerprint != record["fingerprint"]
        ):
            raise RunnerPairingError("local_identity_unavailable")
        return identity, signer

    def status(self, *, check_control_plane: bool = True) -> dict[str, Any]:
        store = self._store()
        record = self._load_record(store)
        if record is None:
            return {"state": "unpaired"}
        if record["state"] != "active":
            return {
                "state": "pairing_incomplete", "origin": record["origin"],
                "next_steps": list(_REPAIR_STEPS),
            }
        coordinates = {
            "origin": record["origin"], "workspace_id": record["workspace_id"],
            "runner_id": record["runner_id"], "runner_key_id": record["runner_key_id"],
            "fingerprint": record["fingerprint"],
        }
        authority = self._grant_authority(record)
        if authority is None:
            # Paired before the grant-authority bootstrap (or the key is inconsistent): nothing the
            # cloud signs can be verified, so no secret store or network is touched. Re-pair.
            return {"state": "cloud_authority_missing", **coordinates, "next_steps": list(_REPAIR_STEPS)}
        coordinates["grant_authority_key_id"] = authority["key_id"]
        try:
            identity, signer = self._active_identity(store, record)
        except RunnerPairingError as error:
            return {"state": error.code, **coordinates}
        result: dict[str, Any] = {"state": "active", **coordinates}
        try:
            result["access"] = self_serve_access(store)
        except (RunnerStoreError, ValueError):
            result["access"] = {"state": "access.incomplete", "reason": "local_state_invalid"}
        directory = self._daemon_fd(store, create=False)
        if directory is None:
            raise RunnerPairingError("local_state_invalid")
        probe: int | None = None
        try:
            try:
                probe = self._probe_serve_lock(directory)
            except OSError:
                raise RunnerPairingError("local_state_invalid") from None
            # Only the lock says whether a serve runs; the state file alone is history.
            result["serve"] = self._serve_view(directory, record, running=probe is None)
            if probe is None:
                # A running serve owns the signed claim chain; a second client would fork it.
                result["control_plane"] = {"state": "not_checked", "reason": "serve_running"}
                if result["serve"]["state"] == "offline":
                    result["state"] = "offline"
                return result
            if not check_control_plane:
                result["control_plane"] = {"state": "not_checked"}
                return result
            try:
                runtime = RunnerRuntimeState(self.runtime_path, identity, signer)
            except RunnerRuntimeStateError:
                return {"state": "local_identity_unavailable", **coordinates}
            try:
                result["control_plane"] = self._live_check(record, identity, signer, runtime)
            finally:
                runtime.close()
        finally:
            if probe is not None:
                _release_serve_lock(probe)
            os.close(directory)
        if result["control_plane"]["state"] == "rejected" and result["control_plane"].get("reason") == "runner_revoked":
            result["state"] = "runner_revoked"
        elif result["control_plane"]["state"] == "unreachable":
            result["state"] = "offline"
        return result

    def _live_check(self, record, identity, signer, runtime) -> dict[str, Any]:
        transport = self._transport(record["origin"])
        try:
            client = RunnerControlClient(
                origin=record["origin"], workspace_id=identity.workspace_id,
                runner_id=identity.runner_id, signer=signer, clock=self._clock_ms,
                transport=transport, nonce_source=_random_nonce, runtime=runtime,
            )
            if runtime.load_pending_calls():
                client.replay_all_pending(now_ms=self._clock_ms())
            listed = client.list_contexts()
        except ControlTransportError as error:
            if error.code in {"connection_failed", "timeout"}:
                return {"state": "unreachable", "reason": error.code}
            return {"state": "rejected", "reason": error.code}
        except (ValueError, RunnerRuntimeStateError):
            if transport.last_status == 401 and transport.last_error_code == "invalid_runner_auth":
                # The control plane no longer accepts this key: revoked (or never known).
                return {"state": "rejected", "reason": "runner_revoked"}
            if transport.last_status == 403 and transport.last_error_code == "runner_protocol_upgrade_required":
                return {"state": "rejected", "reason": "protocol_upgrade_required"}
            return {"state": "rejected", "reason": "response_rejected"}
        return {
            "state": "confirmed", "server_time_ms": listed["server_time_ms"],
            "context_bindings": len(listed["contexts"]),
        }

    # ------------------------------------------------------------------ unpair
    def unpair(self) -> dict[str, Any]:
        """Forget the local identity and remove its OS-stored seed; the owner revokes in Cloud."""
        store = self._store()
        directory = self._daemon_fd(store, create=False)
        lock: int | None = None
        try:
            if directory is not None:
                try:
                    lock = self._acquire_serve_lock(directory, refusal="serve_running")
                except OSError:
                    raise RunnerPairingError("local_state_invalid") from None
            result = self._unpair_locked(store)
            if directory is not None and result["removed"]:
                try:
                    os.unlink(_SERVE_STATE, dir_fd=directory)
                    os.fsync(directory)
                except FileNotFoundError:
                    pass
            return result
        finally:
            if lock is not None:
                _release_serve_lock(lock)
            if directory is not None:
                os.close(directory)

    def _unpair_locked(self, store: RunnerStore) -> dict[str, Any]:
        record = self._load_record(store)
        files = self._store_pairing_files(store)
        if record is None and not files:
            return {"state": "unpaired", "removed": False}
        if store.is_context_bound:
            raise RunnerPairingError("context_bound")
        with store._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=True):
                try:
                    RunnerStore._assert_no_context_authority_locked(runner_fd)
                except RunnerStoreError:
                    raise RunnerPairingError("context_bound") from None
                for name in (*_STORE_PAIRING_FILES, _RUNTIME_FILENAME,
                             *(_RUNTIME_FILENAME + suffix for suffix in ("-wal", "-shm", "-journal"))):
                    try:
                        os.unlink(name, dir_fd=runner_fd)
                    except FileNotFoundError:
                        pass
                os.fsync(runner_fd)
        if record is not None:
            backend = self._backend()
            try:
                _delete_signer_seed(backend, runner_pairing_signer_label(record["installation_id"]))
            except (RuntimeError, ValueError):
                raise RunnerPairingError("secret_removal_failed") from None
            # A record written by a newer pair attempt after our read is left alone.
            self._remove_record(store, record["installation_id"])
        result = {"state": "unpaired", "removed": True}
        if record is not None and record.get("runner_id"):
            result["runner_id"] = record["runner_id"]
            result["next_steps"] = ["Revoke this runner in the Heel dashboard if it is still listed."]
        return result


class _ServeSession:
    """One ``serve`` invocation, run while it holds the instance lock."""

    def __init__(self, daemon: RunnerDaemon, directory: int, record: Mapping[str, Any], *,
                 once: bool, emit: Callable[[dict[str, Any]], None]):
        self.daemon, self.directory, self.record = daemon, directory, record
        self.once, self.emit = once, emit
        self.binding_id: str | None = None
        self.access: dict[str, Any] | None = None
        self.state: str | None = None
        self.since_ms = 0
        self.attempt = 0
        self._last_key: tuple | None = None
        self._last_write = 0.0

    def _publish(self, state: str, *, error_code: str | None = None, force: bool = False) -> None:
        now = self.daemon._clock_ms()
        if state != self.state:
            self.since_ms = now
        key = (state, error_code, self.binding_id, self.access)
        if not force and key == self._last_key and time.monotonic() - self._last_write < _SERVE_STATE_REFRESH_SECONDS:
            return
        _write_json(self.directory, _SERVE_STATE, {
            "schema_version": _SERVE_STATE_SCHEMA, "state": state, "runner_id": self.record["runner_id"],
            "since_ms": self.since_ms, "updated_at_ms": now, "last_error_code": error_code,
            "binding_id": self.binding_id, "access": self.access, "pid": os.getpid(),
        })
        if key != self._last_key:
            self.emit({"event": "serve_state", "state": state, "last_error_code": error_code,
                       "binding_id": self.binding_id, "access": self.access})
        self.state, self._last_key, self._last_write = state, key, time.monotonic()

    def _end(self, state: str, code: str) -> RunnerServeError:
        self._publish(state, error_code=code, force=True)
        return RunnerServeError(code, state=state)

    def _stopped(self) -> dict[str, Any]:
        self._publish("stopped", force=True)
        return {"event": "serve_stopped", "state": "stopped", "binding_id": self.binding_id,
                "access": self.access}

    def _backoff(self) -> float:
        initial, cap = self.daemon._serve_backoff
        self.attempt += 1
        delay = min(cap, initial * 2 ** min(self.attempt - 1, 16))
        return delay * (0.75 + 0.5 * secrets.SystemRandom().random())

    def _contact(self, coordinator: RunnerCoordinator) -> None:
        """An authenticated poll answered: online. Binding and labels are re-read, never cached."""
        self.attempt = 0
        store = coordinator.store
        if store.is_context_bound:
            try:
                self.binding_id = store.verify_cloud_context_binding(
                    identity=self.identity, trusted_cloud_keys=self.trusted, now_ms=self.daemon._clock_ms(),
                )["binding_id"]
            except RunnerStoreError:
                self.binding_id = None
            try:
                self.access = self_serve_access(store)
            except (RunnerStoreError, ValueError):
                self.access = {"state": "access.incomplete", "reason": "local_state_invalid"}
        else:
            self.binding_id, self.access = None, None
        self._publish("online")

    def run(self) -> dict[str, Any]:
        daemon = self.daemon
        authority = daemon._grant_authority(self.record)
        if authority is None:
            # Nothing the cloud signs could be verified: no secret store, no network. Re-pair.
            raise self._end("failed", "cloud_authority_missing")
        try:
            self.identity, self.signer = daemon._active_identity(daemon._store(), self.record)
        except RunnerPairingError as error:
            raise self._end("failed", error.code) from None
        # The only trust anchor is the key validated at pairing and persisted in the record.
        self.trusted = {authority["key_id"]: load_public_key_base64(authority["public_key_b64"])}
        self._publish("starting", force=True)
        while True:
            if daemon._shutdown.is_set():
                return self._stopped()
            try:
                self._cycle()
            except Exception as error:
                state, code = _serve_failure(error)
                if state == "offline" and not self.once:
                    # Fresh authority is required again: the next cycle rebuilds the coordinator,
                    # replays staged calls and is online only after a new authenticated answer.
                    self._publish("offline", error_code=code)
                    if daemon._shutdown.wait(self._backoff()):
                        return self._stopped()
                    continue
                raise self._end(state, code) from None
            if self.once or daemon._shutdown.is_set():
                return self._stopped()

    def _cycle(self) -> None:
        daemon, origin = self.daemon, self.record["origin"]
        # Before every cycle's first network call: the record must still name this pairing.
        if daemon._load_record(daemon._store()) != self.record:
            raise RunnerServeError("local_state_invalid")
        runtime = RunnerRuntimeState(daemon.runtime_path, self.identity, self.signer)
        owner: _ServeCoordinator | None = None
        try:
            control = RunnerControlClient(
                origin=origin, workspace_id=self.identity.workspace_id,
                runner_id=self.identity.runner_id, signer=self.signer, clock=daemon._clock_ms,
                transport=_AttributedTransport(daemon._transport(origin)), nonce_source=_random_nonce,
                runtime=runtime, trusted_disclosure_keys=self.trusted,
            )
            # The constructor is the restart path: it replays staged calls and recovers runs.
            coordinator = RunnerCoordinator(
                control=control, store=daemon._store(), identity=self.identity, signer=self.signer,
                trusted_grant_keys=self.trusted, clock_ms=daemon._clock_ms,
            )
            owner = _ServeCoordinator(coordinator, lambda: self._contact(coordinator))
            service = RunnerService(
                coordinator=owner,
                executor=_ExecutionUnavailable(), idle_poll_interval=daemon._serve_idle_poll,
                clock_ms=daemon._clock_ms,
            )
            cycle = threading.Event()
            daemon._service, daemon._cycle_stop = service, cycle
            if daemon._shutdown.is_set():
                cycle.set()
            if self.once:
                service.run_once()
            elif not cycle.is_set():
                service.serve(cycle)
        finally:
            daemon._service = daemon._cycle_stop = None
            # Keep the runtime open and the instance lock held until no worker of this cycle can
            # issue a call or write state: a stop during a control call waits for that bounded
            # call here; nothing is detached.
            if owner is not None:
                owner.close()
            runtime.close()


__all__ = [
    "NO_SECRET_SERVICE", "SERVE_EXIT_CODES", "RunnerDaemon", "RunnerPairingError",
    "RunnerServeError", "self_serve_access",
]
