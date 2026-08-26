"""Context-bound, descriptor-anchored state for the customer-local runner."""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass
try:
    import fcntl
except ImportError:  # pragma: no cover - POSIX capability gate rejects first
    fcntl = None  # type: ignore[assignment]
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import secrets
import stat
import unicodedata
from typing import Any, Iterator, Mapping
from urllib.parse import urlsplit

from heel.canary_contracts import (
    canonical_bytes,
    canonical_digest,
    validate_approval_projection,
    validate_canary_findings,
    validate_execution_grant,
    validate_operational_run,
    validate_runner_result_request,
    validate_test_manifest,
    validate_runner_context_binding,
)
from heel.crypto import ed25519_key_id, load_public_key_base64, verify_envelope
from heel.runner.identity import (
    AcceptedRotationAbortTombstone, AcceptedRotationJournal, PendingPairingActivation, PendingRotationActivation,
    RunnerIdentity, RunnerPairingMaterial, SecureSigner,
)
from heel.runner.runtime import (
    PendingResultReplayAuthority, PendingSignedCall, RunnerRuntimeState,
)
from heel.scope import heel_home

from .catalog import CATALOG_BY_ID, NONANONYMOUS_AUTH_PROFILES, SEMANTIC_ROLES
from .openapi_routes import normalize_route_template


class UnsupportedSecureStorageError(RuntimeError):
    """Live execution cannot proceed without every required secure credential."""


class RunnerStoreError(ValueError):
    """Runner state is corrupt, unsafe, or belongs to another target context."""


_DIRECTORY_FLAGS = (
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = (
    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_WRITE_FLAGS = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_LOCK_FLAGS = (
    os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_BINARY_WRITE_FLAGS = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_MAX_METADATA_BYTES = 256 * 1024
_HANDLE = re.compile(r"^[0-9a-f]{32}$", flags=re.ASCII)
_DIGEST = re.compile(r"^[0-9a-f]{64}$", flags=re.ASCII)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$", flags=re.ASCII)
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$", flags=re.ASCII)
_BACKENDS = frozenset({
    "macos_keychain", "linux_secret_service", "ephemeral_env", "ephemeral_fd",
})
_STATES = frozenset({"pending", "active", "orphaned"})
_RUN_STATES = frozenset({"verified", "running", "stop_requested", "finalizing", "terminal"})
_RUN_TRANSITIONS = {
    "verified": frozenset({"running", "finalizing"}),
    "running": frozenset({"stop_requested", "finalizing"}),
    "stop_requested": frozenset({"finalizing"}),
    "finalizing": frozenset({"terminal"}),
    "terminal": frozenset(),
}
_RUN_FILENAME = re.compile(r"^[0-9a-f]{64}$", flags=re.ASCII)
_RUN_RESERVATION_FILENAME = re.compile(r"^grant-([0-9a-f]{64})\.json$", flags=re.ASCII)
_EVENT_FILENAME = re.compile(r"^[0-9]{20}\.json$", flags=re.ASCII)
_CREATE_TEMP_FILENAME = re.compile(r"^\..+\.[0-9a-f]{24}\.tmp$", flags=re.ASCII)
_EVIDENCE_REF = re.compile(r"^ev1_[0-9a-f]{64}$", flags=re.ASCII)
_MAX_EVIDENCE_HEADER_BYTES = 16 * 1024
_MAX_EVIDENCE_BODY_BYTES = 256 * 1024
_RESERVATION_SCHEMA = "heel.local-grant-consumption.v2"
_FINALS_SCHEMA = "heel.local-final-projections.v1"
_CONTEXT_DOMAIN = b"heel.runner-context-binding.v1\0"
_CLOUD_CONTEXT_PROVENANCE_SCHEMA = "heel.cloud-context-provenance.v1"
_CLOUD_CONTEXT_AUTHORITY_COMMIT_SCHEMA = "heel.cloud-context-authority-commit.v1"
_CLOUD_CONTEXT_AUTHORITY_COMMIT_DOMAIN = b"heel.cloud-context-authority-commit.v1\0"
_ACTIVE_CONTEXT_CLOUD_SCHEMA = "heel.active-runner-context.v2"
_ACTIVE_CONTEXT_CLOUD_DOMAIN = b"heel.active-runner-context.v2\0"
_CONTEXT_ROLLOVER_SCHEMA = "heel.runner-context-rollover.v2"
_CONTEXT_INSTALL_SCHEMA = "heel.runner-context-install.v2"
_PAIRING_ACTIVATION_JOURNAL_SCHEMA = "heel.runner-pairing-activation-journal.v1"
_PAIRED_RUNNER_IDENTITY_SCHEMA = "heel.local-paired-runner.v1"
_ROTATION_ACTIVATION_JOURNAL_SCHEMA = "heel.runner-rotation-activation-journal.v1"
_ROTATION_RUNTIME_INTENT_SCHEMA = "heel.runner-rotation-runtime-intent.v1"
_PAIRING_ACTIVATION_JOURNAL_DOMAIN = b"heel.runner-pairing-activation-journal.v1\0"
_PAIRED_RUNNER_IDENTITY_DOMAIN = b"heel.local-paired-runner.v1\0"
_ROTATION_ACTIVATION_JOURNAL_DOMAIN = b"heel.runner-rotation-activation-journal.v1\0"
_ROTATION_RUNTIME_INTENT_DOMAIN = b"heel.runner-rotation-runtime-intent.v1\0"
_ROTATION_ACTIVATION_JOURNAL_DIGEST_DOMAIN = b"heel.runner-rotation-activation-journal-digest.v1\0"
_PAIRING_ACTIVATION_JOURNAL_FILENAME = "pairing-activation.json"
_PAIRED_RUNNER_IDENTITY_FILENAME = "paired-identity.json"
_ROTATION_ACTIVATION_JOURNAL_FILENAME = "rotation-activation.json"
_ACTIVATION_TOMBSTONES_DIRECTORY = "activation-tombstones"
_PAIRING_ABORT_TOMBSTONE_SCHEMA = "heel.runner-pairing-activation-abort-tombstone.v1"
_PAIRING_ABORT_TOMBSTONE_DOMAIN = b"heel.runner-pairing-activation-abort-tombstone.v1\0"
_ROTATION_ABORT_TOMBSTONE_SCHEMA = "heel.runner-rotation-activation-abort-tombstone.v1"
_ROTATION_ABORT_TOMBSTONE_OLD_DOMAIN = b"heel.runner-rotation-activation-abort-tombstone.v1.old\0"
_ROTATION_ABORT_TOMBSTONE_NEW_DOMAIN = b"heel.runner-rotation-activation-abort-tombstone.v1.new\0"
_RUN_AUTHORITY_INDEX_SCHEMA = "heel.local-run-authority-index.v1"
_RUN_RESERVATION_RECORD_SCHEMA = "heel.local-run-reservation.v1"
_RUN_TERMINAL_RECORD_SCHEMA = "heel.local-run-terminal.v1"
_RUN_TERMINAL_DETACHED_RECORD_SCHEMA = "heel.local-run-terminal-detached.v1"
_RUN_PRUNED_RECORD_SCHEMA = "heel.local-run-pruned.v1"
_RUN_RUNTIME_PRUNED_RECORD_SCHEMA = "heel.local-run-pruned.v2"
_RUN_RUNTIME_PRUNED_RECORD_DOMAIN = b"heel.local-run-pruned.v2\0"
_RUN_AUTHORITY_MUTATION_SCHEMA = "heel.local-run-authority-mutation.v1"
_RUN_AUTHORITY_INDEX_FILENAME = "run-authority-index.json"
_RUN_AUTHORITY_JOURNAL_FILENAME = "run-authority-journal.json"
_RUN_AUTHORITY_MAX_RECORD_BYTES = 16 * 1024
_RUN_AUTHORITY_MAX_JOURNAL_BYTES = 128 * 1024
_RUN_AUTHORITY_MAX_TRACKED = 64
_RUN_AUTHORITY_MAX_NONTERMINAL = _RUN_AUTHORITY_MAX_TRACKED
_RUN_PRUNE_BATCH = 16
_RUN_AUTHORITY_ZERO_HEAD = "0" * 64
_RUN_AUTHORITY_DOMAINS = {
    _RUN_AUTHORITY_INDEX_SCHEMA: b"heel.local-run-authority-index.v1\0",
    _RUN_RESERVATION_RECORD_SCHEMA: b"heel.local-run-reservation.v1\0",
    _RUN_TERMINAL_RECORD_SCHEMA: b"heel.local-run-terminal.v1\0",
    _RUN_TERMINAL_DETACHED_RECORD_SCHEMA: b"heel.local-run-terminal-detached.v1\0",
    _RUN_PRUNED_RECORD_SCHEMA: b"heel.local-run-pruned.v1\0",
    _RUN_RUNTIME_PRUNED_RECORD_SCHEMA: _RUN_RUNTIME_PRUNED_RECORD_DOMAIN,
    _RUN_AUTHORITY_MUTATION_SCHEMA: b"heel.local-run-authority-mutation.v1\0",
}


@dataclass(frozen=True, slots=True)
class VerifiedPrunedRunReceipt:
    """An authenticated v2 tombstone handed to the runtime for its final CAS delete."""

    record: Mapping[str, object]


class _PendingResultReplayVerifier:
    """Store-owned nominal issuer for one exact terminal request replay."""

    __slots__ = ("_store", "_runtime", "_identity", "_token", "_consumed")

    def __init__(self, store: "RunnerStore", runtime: RunnerRuntimeState, identity: RunnerIdentity) -> None:
        self._store = store
        self._runtime = runtime
        self._identity = identity
        self._token = object()
        self._consumed: list[PendingResultReplayAuthority] = []

    def authorize_pending_result_replay(
        self, pending: PendingSignedCall, *, now_ms: int,
    ) -> PendingResultReplayAuthority:
        return self._store._authorize_pending_result_replay(
            pending, runtime=self._runtime, now_ms=now_ms, issuer=self._token,
        )

    def consume(
        self, authority: PendingResultReplayAuthority, *, expected_fields: Mapping[str, object],
    ) -> None:
        fields = {
            "call_id", "pending_state_digest", "run_id", "body_sha256",
            "active_state_digest", "runtime_terminal_state_digest",
            "terminal_record_digest", "terminal_projection_digest",
            "retention_expires_at_ms",
        }
        if (
            not isinstance(authority, PendingResultReplayAuthority)
            or authority._issuer is not self._token
            or set(expected_fields) != fields
            or any(getattr(authority, name) != expected_fields[name] for name in fields)
            or any(item is authority for item in self._consumed)
        ):
            raise RunnerStoreError("local pending terminal replay authority is invalid")
        self._consumed.append(authority)


def _require_capabilities() -> None:
    required = (os.open, os.mkdir, os.stat, os.unlink)
    try:
        replace = inspect.signature(os.replace).parameters
    except (TypeError, ValueError):
        replace = {}
    if not (
        os.name == "posix"
        and fcntl is not None
        and getattr(os, "O_DIRECTORY", 0)
        and getattr(os, "O_NOFOLLOW", 0)
        and all(function in os.supports_dir_fd for function in required)
        and os.stat in os.supports_follow_symlinks
        and {"src_dir_fd", "dst_dir_fd"} <= set(replace)
    ):
        raise UnsupportedSecureStorageError(
            "runner state requires POSIX dir_fd, O_NOFOLLOW, and flock"
        )


def _id(value: object, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"invalid {label}")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"invalid {label}")
    return value


def _label(value: object) -> str:
    if type(value) is not str:
        raise ValueError("credential label must be text")
    normalized = unicodedata.normalize("NFC", value.strip())
    if _LABEL.fullmatch(normalized) is None:
        raise ValueError("credential label must be bounded local text")
    return normalized


def _handle(value: object) -> str:
    if type(value) is not str or _HANDLE.fullmatch(value) is None:
        raise ValueError("invalid credential handle")
    return value


def _origin(value: object) -> str:
    if type(value) is not str or value != value.lower() or len(value.encode("utf-8")) > 1024:
        raise ValueError("invalid exact target origin")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("invalid exact target origin") from None
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.hostname != parsed.hostname.lower()
        or parsed.hostname.endswith(".")
    ):
        raise ValueError("invalid exact target origin")
    return value


@dataclass(frozen=True)
class RunnerContext:
    workspace_id: str
    project_id: str
    environment_id: str
    origin: str
    verification_record_digest: str
    environment_class: str

    def __post_init__(self) -> None:
        _id(self.workspace_id, "workspace ID")
        _id(self.project_id, "project ID")
        _id(self.environment_id, "environment ID")
        _origin(self.origin)
        _digest(self.verification_record_digest, "verification record digest")
        if self.environment_class not in {"staging", "sandbox"}:
            raise ValueError("invalid environment class")

    @property
    def namespace(self) -> str:
        encoded = (
            self.workspace_id.encode("utf-8") + b"\0"
            + self.project_id.encode("utf-8") + b"\0"
            + self.environment_id.encode("utf-8")
        )
        return hashlib.sha256(encoded).hexdigest()

    def as_dict(self) -> dict[str, str]:
        return {
            "workspace_id": self.workspace_id,
            "project_id": self.project_id,
            "environment_id": self.environment_id,
            "origin": self.origin,
            "verification_record_digest": self.verification_record_digest,
            "environment_class": self.environment_class,
        }


@dataclass(frozen=True)
class RunnerContextRolloverEvidence:
    """Closed observation that permits only a forward proof-generation rollover."""

    old_binding_id: str
    old_binding_digest: str
    new_binding_id: str
    new_binding_digest: str
    observed_server_time_ms: int

    def __post_init__(self) -> None:
        _id(self.old_binding_id, "old context binding ID")
        _digest(self.old_binding_digest, "old context binding digest")
        _id(self.new_binding_id, "new context binding ID")
        _digest(self.new_binding_digest, "new context binding digest")
        if type(self.observed_server_time_ms) is not int or self.observed_server_time_ms < 0:
            raise ValueError("invalid rollover observation time")


def _context_from_dict(value: Any) -> RunnerContext:
    fields = {
        "workspace_id", "project_id", "environment_id", "origin",
        "verification_record_digest", "environment_class",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RunnerStoreError("invalid runner context")
    try:
        return RunnerContext(**dict(value))
    except (TypeError, ValueError):
        raise RunnerStoreError("invalid runner context") from None


def _absolute(path: Path) -> Path:
    result = Path(os.path.normpath(os.path.abspath(os.fspath(path.expanduser()))))
    if result == Path(result.anchor) or any(part in {".", ".."} for part in result.parts):
        raise ValueError("unsafe runner home")
    return result


def _open_child(parent_fd: int, name: str, *, create: bool) -> int | None:
    try:
        return os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            return None
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
        return os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        try:
            status = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            raise error
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            raise OSError(error.errno, "unsafe runner state directory") from error
        raise


def _secure_directory(descriptor: int, label: str) -> None:
    status = os.fstat(descriptor)
    if not stat.S_ISDIR(status.st_mode) or status.st_uid != os.geteuid():
        raise PermissionError(f"{label} must be an owner-controlled directory")
    os.fchmod(descriptor, 0o700)
    if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o700:
        raise PermissionError(f"{label} must have mode 0700")


def _secure_regular(status: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != os.geteuid()
        or status.st_nlink != 1
    ):
        raise OSError(f"{label} must be an owner-controlled single-link regular file")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise RunnerStoreError("duplicate runner state key")
        output[key] = value
    return output


def _read_json(directory_fd: int, filename: str, default: Any) -> Any:
    try:
        descriptor = os.open(filename, _READ_FLAGS, dir_fd=directory_fd)
    except FileNotFoundError:
        return default
    try:
        status = os.fstat(descriptor)
        _secure_regular(status, "runner state")
        if status.st_size > _MAX_METADATA_BYTES:
            raise RunnerStoreError("runner state exceeds size limit")
        os.fchmod(descriptor, 0o600)
        chunks: list[bytes] = []
        remaining = _MAX_METADATA_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > _MAX_METADATA_BYTES:
            raise RunnerStoreError("runner state exceeds size limit")
    finally:
        os.close(descriptor)
    try:
        return json.loads(payload.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise RunnerStoreError("runner state is invalid") from None


def _safe_target(directory_fd: int, filename: str) -> None:
    try:
        status = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    _secure_regular(status, "runner state target")


def _write_json(directory_fd: int, filename: str, value: Any) -> None:
    payload = canonical_bytes(value)
    if len(payload) > _MAX_METADATA_BYTES:
        raise RunnerStoreError("runner state exceeds size limit")
    _safe_target(directory_fd, filename)
    temporary = f".{filename}.{secrets.token_hex(12)}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(temporary, _WRITE_FLAGS, 0o600, dir_fd=directory_fd)
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise OSError("short runner state write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        _safe_target(directory_fd, filename)
        os.replace(temporary, filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise


def _create_json(directory_fd: int, filename: str, value: Any) -> None:
    """Publish one complete immutable record atomically under the store flock."""
    payload = canonical_bytes(value)
    if len(payload) > _MAX_METADATA_BYTES:
        raise RunnerStoreError("runner state exceeds size limit")
    temporary_prefix = f".{filename}."
    removed_stale = False
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            name = entry.name
            if not name.startswith(temporary_prefix) or _CREATE_TEMP_FILENAME.fullmatch(name) is None:
                continue
            _secure_regular(
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False),
                "unfinished runner state",
            )
            os.unlink(name, dir_fd=directory_fd)
            removed_stale = True
    if removed_stale:
        os.fsync(directory_fd)
    temporary = temporary_prefix + secrets.token_hex(12) + ".tmp"
    descriptor = -1
    try:
        descriptor = os.open(temporary, _WRITE_FLAGS, 0o600, dir_fd=directory_fd)
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise OSError("short runner state write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            status = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _secure_regular(status, "runner state target")
            raise FileExistsError(filename)
        os.rename(temporary, filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise


@contextmanager
def _flock(directory_fd: int, filename: str, *, exclusive: bool) -> Iterator[None]:
    assert fcntl is not None
    descriptor = os.open(filename, _LOCK_FLAGS, 0o600, dir_fd=directory_fd)
    locked = False
    try:
        _secure_regular(os.fstat(descriptor), "runner mutation lock")
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.fsync(directory_fd)
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        locked = True
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _identity_record(identity: RunnerIdentity, signer: SecureSigner) -> dict[str, Any]:
    if not isinstance(identity, RunnerIdentity) or not isinstance(signer, SecureSigner):
        raise ValueError("actual paired RunnerIdentity and SecureSigner are required")
    try:
        public_key = base64.b64decode(identity.public_key_b64, validate=True)
    except (TypeError, ValueError):
        raise ValueError("runner identity public key is invalid") from None
    if signer.key_id != identity.key_id or signer.public_key != public_key:
        raise ValueError("runner signer does not match paired identity")
    if hashlib.sha256(signer.public_key).hexdigest() != identity.fingerprint:
        raise ValueError("runner signer fingerprint mismatch")
    adapters = dict(sorted(identity.adapter_versions.items()))
    if not adapters or any(
        type(key) is not str or type(value) is not str or not key or not value
        for key, value in adapters.items()
    ):
        raise ValueError("paired runner adapter versions are invalid")
    return {
        "runner_id": _id(identity.runner_id, "runner ID"),
        "workspace_id": _id(identity.workspace_id, "runner workspace ID"),
        "runner_version": _id(identity.runner_version, "runner version"),
        "adapter_versions": adapters,
        "public_key_b64": identity.public_key_b64,
        "fingerprint": _digest(identity.fingerprint, "runner fingerprint"),
        "runner_key_id": _id(identity.key_id, "runner key ID"),
    }


class _IdentityPublicSigner(SecureSigner):
    """Verification-only view of a paired identity for crash recovery journals."""

    def __init__(self, identity: RunnerIdentity):
        self.key_id = identity.key_id
        self.public_key = base64.b64decode(identity.public_key_b64, validate=True)

    def sign(self, payload: bytes) -> bytes:  # pragma: no cover - recovery must never sign.
        del payload
        raise RunnerStoreError("recovery signer cannot sign")


def _stored_identity_record(value: Any) -> dict[str, Any]:
    fields = {
        "runner_id", "workspace_id", "runner_version", "adapter_versions",
        "public_key_b64", "fingerprint", "runner_key_id",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RunnerStoreError("invalid bound runner identity")
    adapters = value["adapter_versions"]
    if not isinstance(adapters, Mapping) or not adapters or any(
        type(key) is not str or type(item) is not str or not key or not item
        for key, item in adapters.items()
    ):
        raise RunnerStoreError("invalid bound runner identity")
    try:
        public_key = base64.b64decode(value["public_key_b64"], validate=True)
    except (TypeError, ValueError):
        raise RunnerStoreError("invalid bound runner identity") from None
    if (
        len(public_key) != 32
        or hashlib.sha256(public_key).hexdigest() != value["fingerprint"]
        or ed25519_key_id(public_key) != value["runner_key_id"]
    ):
        raise RunnerStoreError("invalid bound runner identity")
    return {
        "runner_id": _id(value["runner_id"], "runner ID"),
        "workspace_id": _id(value["workspace_id"], "runner workspace ID"),
        "runner_version": _id(value["runner_version"], "runner version"),
        "adapter_versions": dict(sorted(adapters.items())),
        "public_key_b64": value["public_key_b64"],
        "fingerprint": _digest(value["fingerprint"], "runner fingerprint"),
        "runner_key_id": _id(value["runner_key_id"], "runner key ID"),
    }


def _credential_record(value: Any) -> dict[str, Any]:
    fields = {
        "credential_handle_id", "semantic_role", "auth_profile", "label",
        "backend", "source_kind", "state",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RunnerStoreError("invalid credential metadata")
    role = value["semantic_role"]
    profile = value["auth_profile"]
    backend = value["backend"]
    source_kind = value["source_kind"]
    state = value["state"]
    if role not in SEMANTIC_ROLES - {"anonymous"}:
        raise RunnerStoreError("invalid credential semantic role")
    if profile not in NONANONYMOUS_AUTH_PROFILES:
        raise RunnerStoreError("invalid credential auth profile")
    if backend not in _BACKENDS or state not in _STATES:
        raise RunnerStoreError("invalid credential backend state")
    expected_source = (
        "environment" if backend == "ephemeral_env"
        else "inherited_fd" if backend == "ephemeral_fd"
        else None
    )
    if source_kind != expected_source:
        raise RunnerStoreError("invalid credential source convention")
    return {
        "credential_handle_id": _handle(value["credential_handle_id"]),
        "semantic_role": role,
        "auth_profile": profile,
        "label": _label(value["label"]),
        "backend": backend,
        "source_kind": source_kind,
        "state": state,
    }


def _route_record(value: Any, *, require_canonical: bool) -> dict[str, Any]:
    fields = {"method", "route_template", "operation_id", "placeholders"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RunnerStoreError("invalid route metadata")
    method = value["method"]
    if method not in {"GET", "HEAD"}:
        raise RunnerStoreError("invalid route method")
    route, placeholders = normalize_route_template(value["route_template"])
    if require_canonical and route != value["route_template"]:
        raise RunnerStoreError("route metadata is not NFC canonical")
    if value["placeholders"] != placeholders:
        raise RunnerStoreError("route placeholder metadata mismatch")
    return {
        "method": method,
        "route_template": route,
        "operation_id": _id(value["operation_id"], "operation ID"),
        "placeholders": placeholders,
    }


def _fixture_bindings(value: Mapping[str, str] | None) -> list[dict[str, str]]:
    supplied = {} if value is None else value
    if not isinstance(supplied, Mapping) or len(supplied) > 20:
        raise ValueError("fixture bindings must be a bounded object")
    result = []
    for name, fixture_id in supplied.items():
        result.append({
            "parameter_name": _id(name, "fixture parameter"),
            "fixture_id": _id(fixture_id, "fixture ID"),
        })
    result.sort(key=lambda item: (item["parameter_name"], item["fixture_id"]))
    return result


def _mapping_record(value: Any) -> dict[str, Any]:
    fields = {"scenario_id", "method", "route_template", "fixture_bindings"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RunnerStoreError("invalid scenario mapping")
    scenario_id = value["scenario_id"]
    if scenario_id not in CATALOG_BY_ID:
        raise RunnerStoreError("unknown scenario mapping")
    if value["method"] not in {"GET", "HEAD"}:
        raise RunnerStoreError("invalid scenario mapping method")
    route, placeholders = normalize_route_template(value["route_template"])
    bindings = value["fixture_bindings"]
    if not isinstance(bindings, list) or len(bindings) > 20:
        raise RunnerStoreError("invalid scenario fixture bindings")
    table: dict[str, str] = {}
    for binding in bindings:
        if not isinstance(binding, Mapping) or set(binding) != {"parameter_name", "fixture_id"}:
            raise RunnerStoreError("invalid scenario fixture binding")
        name = _id(binding["parameter_name"], "fixture parameter")
        if name in table:
            raise RunnerStoreError("duplicate scenario fixture binding")
        table[name] = _id(binding["fixture_id"], "fixture ID")
    if set(table) != set(placeholders):
        raise RunnerStoreError("scenario mapping requires exact route fixture bindings")
    return {
        "scenario_id": scenario_id,
        "method": value["method"],
        "route_template": route,
        "fixture_bindings": _fixture_bindings(table),
    }


class RunnerStore:
    """One local store instance pinned to one immutable namespace after binding."""

    def __init__(self, root: Path | None = None):
        _require_capabilities()
        self.root = _absolute(Path(heel_home()) if root is None else Path(root))
        self._namespace: str | None = None
        self._runtime_authority: tuple[RunnerIdentity, SecureSigner] | None = None
        self._rotation_token = object()
        self._pending_result_replay_verifier: _PendingResultReplayVerifier | None = None
        with self._open_runner(create=True):
            pass
        self._select_active_if_present()

    @classmethod
    def for_runtime(
        cls, root: Path | None = None, *, identity: RunnerIdentity, signer: SecureSigner,
    ) -> "RunnerStore":
        """Open a store whose mutation authority is pinned to one paired identity."""
        store = cls(root)
        store._pin_runtime_authority(identity, signer)
        return store

    def _pin_runtime_authority(self, identity: RunnerIdentity, signer: SecureSigner) -> None:
        record = _identity_record(identity, signer)
        existing = self._runtime_authority
        if existing is not None:
            if _identity_record(*existing) != record:
                raise RunnerStoreError("authenticated runner store identity changed")
            return
        if self._namespace is not None:
            with self._transaction(
                exclusive=False, allow_rollover_journal=True, allow_cloud_install_journal=True,
            ) as context_fd:
                if self._binding_locked(context_fd, validate_cloud=False)["identity"] != record:
                    raise RunnerStoreError("authenticated runner store identity differs from bound context")
        self._runtime_authority = (identity, signer)

    def _require_runtime_authority(self) -> tuple[RunnerIdentity, SecureSigner]:
        authority = self._runtime_authority
        if authority is None:
            raise RunnerStoreError("authenticated runner store is required")
        _identity_record(*authority)
        return authority

    def _assert_runtime_authority(self, identity: RunnerIdentity, signer: SecureSigner) -> None:
        expected = _identity_record(identity, signer)
        actual = self._require_runtime_authority()
        if _identity_record(*actual) != expected:
            raise RunnerStoreError("authenticated runner store identity changed")

    def pending_result_replay_verifier(
        self, runtime: RunnerRuntimeState,
    ) -> _PendingResultReplayVerifier:
        """Bind exactly one opaque terminal-replay issuer to this Store/runtime pair."""
        identity, signer = self._require_runtime_authority()
        if not self._runtime_matches_identity(runtime, identity=identity, signer=signer):
            raise RunnerStoreError("local pending terminal replay authority is unavailable")
        verifier = self._pending_result_replay_verifier
        if verifier is None:
            verifier = _PendingResultReplayVerifier(self, runtime, identity)
            self._pending_result_replay_verifier = verifier
        elif verifier._runtime is not runtime or verifier._identity != identity:
            raise RunnerStoreError("local pending terminal replay authority is unavailable")
        return verifier

    @staticmethod
    def _pairing_time(value: object, label: str) -> int:
        if type(value) is not int or not 0 <= value <= 9_007_199_254_740_991:
            raise RunnerStoreError(f"invalid {label}")
        return value

    @staticmethod
    def _pairing_nonce(value: object, label: str) -> str:
        if type(value) is not str:
            raise RunnerStoreError(f"invalid {label}")
        try:
            raw = base64.b64decode(value, validate=True)
        except (TypeError, ValueError):
            raise RunnerStoreError(f"invalid {label}") from None
        if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
            raise RunnerStoreError(f"invalid {label}")
        return value

    @staticmethod
    def _pairing_signed_value(
        core: Mapping[str, Any], *, signer: SecureSigner, domain: bytes, digest_field: str,
    ) -> dict[str, Any]:
        unsigned = dict(core)
        unsigned[digest_field] = hashlib.sha256(domain + canonical_bytes(unsigned)).hexdigest()
        signature = signer.sign(domain + canonical_bytes(unsigned))
        if type(signature) is not bytes or len(signature) != 64:
            raise RunnerStoreError("runner signer returned an invalid pairing signature")
        return {
            **unsigned, "signing_key_id": signer.key_id,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }

    @staticmethod
    def _verify_pairing_signed_value(
        value: object, *, identity: RunnerIdentity, domain: bytes, digest_field: str,
        fields: set[str], label: str,
    ) -> dict[str, Any]:
        if not isinstance(value, Mapping) or set(value) != fields | {digest_field, "signing_key_id", "signature_b64"}:
            raise RunnerStoreError(f"invalid {label}")
        if value.get("signing_key_id") != identity.key_id:
            raise RunnerStoreError(f"invalid {label}")
        unsigned = {key: value[key] for key in fields | {digest_field}}
        core = {key: value[key] for key in fields}
        if value[digest_field] != hashlib.sha256(domain + canonical_bytes(core)).hexdigest():
            raise RunnerStoreError(f"invalid {label}")
        try:
            public = load_public_key_base64(identity.public_key_b64)
            verify_envelope(
                {identity.key_id: public},
                {"signing_key_id": value["signing_key_id"], "signature_b64": value["signature_b64"]},
                domain + canonical_bytes(unsigned),
            )
        except (TypeError, ValueError):
            raise RunnerStoreError(f"invalid {label}") from None
        return dict(value)

    @classmethod
    def _pairing_pending(cls, value: Mapping[str, object]) -> dict[str, object]:
        fields = {
            "schema_version", "pairing_id", "runner_id", "fingerprint", "status",
            "activation_challenge", "control_protocol", "pairing_exchange_digest",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise RunnerStoreError("invalid executable pairing pending response")
        if (
            value["schema_version"] != "heel.runner-pairing-pending.v2"
            or value["status"] != "pending"
            or value["control_protocol"] != "heel.runner-control.v2"
        ):
            raise RunnerStoreError("invalid executable pairing pending response")
        return {
            "schema_version": value["schema_version"],
            "pairing_id": _id(value["pairing_id"], "pairing ID"),
            "runner_id": _id(value["runner_id"], "runner ID"),
            "fingerprint": _digest(value["fingerprint"], "runner fingerprint"),
            "status": value["status"],
            "activation_challenge": cls._pairing_nonce(value["activation_challenge"], "pairing activation challenge"),
            "control_protocol": value["control_protocol"],
            "pairing_exchange_digest": _digest(value["pairing_exchange_digest"], "pairing exchange digest"),
        }

    @classmethod
    def _activation_response(
        cls, value: Mapping[str, object], *, material: RunnerPairingMaterial,
        pending: Mapping[str, object],
    ) -> tuple[dict[str, object], RunnerIdentity]:
        fields = {
            "schema_version", "workspace_id", "runner_id", "runner_key_id",
            "pairing_exchange_digest", "initial_claim_nonce", "initial_claim_sequence",
            "initial_claim_generation", "capabilities", "control_protocol", "activated_at_ms",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise RunnerStoreError("invalid executable pairing activation response")
        if (
            value["schema_version"] != "heel.runner-pairing-activated.v3"
            or value["runner_id"] != pending["runner_id"]
            or value["runner_key_id"] != material.key_id
            or value["pairing_exchange_digest"] != pending["pairing_exchange_digest"]
            or value["control_protocol"] != "heel.runner-control.v2"
            or value["capabilities"] != ["runner_claim", "runner_heartbeat", "runner_progress", "runner_result"]
            or value["initial_claim_sequence"] != 1
            or value["initial_claim_generation"] != 0
        ):
            raise RunnerStoreError("invalid executable pairing activation response")
        identity = RunnerIdentity(
            runner_id=_id(value["runner_id"], "runner ID"),
            workspace_id=_id(value["workspace_id"], "runner workspace ID"),
            runner_version=material.runner_version, adapter_versions=dict(material.adapters),
            public_key_b64=material.public_key_b64, fingerprint=material.fingerprint,
            key_id=material.key_id, pairing_phrase=material.pairing_phrase,
        )
        return ({
            "schema_version": value["schema_version"], "workspace_id": identity.workspace_id,
            "runner_id": identity.runner_id, "runner_key_id": identity.key_id,
            "pairing_exchange_digest": pending["pairing_exchange_digest"],
            "initial_claim_nonce": cls._pairing_nonce(value["initial_claim_nonce"], "initial claim nonce"),
            "initial_claim_sequence": 1, "initial_claim_generation": 0,
            "capabilities": list(value["capabilities"]), "control_protocol": value["control_protocol"],
            "activated_at_ms": cls._pairing_time(value["activated_at_ms"], "pairing activation time"),
        }, identity)

    def _prepare_pairing_activation(
        self, material: RunnerPairingMaterial, pending_v2: Mapping[str, object], *, now_ms: int,
        random_source: Any,
    ) -> PendingPairingActivation:
        if not isinstance(material, RunnerPairingMaterial):
            raise RunnerStoreError("runner pairing material is required")
        pending = self._pairing_pending(pending_v2)
        if pending["fingerprint"] != material.fingerprint:
            raise RunnerStoreError("executable pairing identity mismatch")
        now_ms = self._pairing_time(now_ms, "pairing preparation time")
        nonce = random_source(32)
        if type(nonce) is not bytes or len(nonce) != 32:
            raise RunnerStoreError("runner activation random source returned an invalid nonce")
        nonce_b64 = base64.b64encode(nonce).decode("ascii")
        proof = {
            "pairing_id": pending["pairing_id"], "activation_challenge": pending["activation_challenge"],
            "pairing_exchange_digest": pending["pairing_exchange_digest"],
            "client_activation_nonce_b64": nonce_b64, "control_protocol": "heel.runner-control.v2",
        }
        signature = material._signer.sign(b"heel.runner-pairing-activate.v3\0" + canonical_bytes(proof))
        if type(signature) is not bytes or len(signature) != 64:
            raise RunnerStoreError("runner signer returned an invalid pairing activation signature")
        request = {
            "schema_version": "heel.runner-pairing-activate.v3", "client_activation_nonce_b64": nonce_b64,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }
        core = {
            "schema_version": _PAIRING_ACTIVATION_JOURNAL_SCHEMA, "state": "prepared",
            "pairing_id": pending["pairing_id"], "runner_id": pending["runner_id"],
            "pairing_exchange_digest": pending["pairing_exchange_digest"],
            "activation_challenge": pending["activation_challenge"], "client_activation_nonce_b64": nonce_b64,
            "activation_request": request, "activation_response": None, "identity": None,
            "created_at_ms": now_ms, "updated_at_ms": now_ms,
        }
        journal = self._pairing_signed_value(
            core, signer=material._signer, domain=_PAIRING_ACTIVATION_JOURNAL_DOMAIN,
            digest_field="journal_digest",
        )
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=True):
                existing = _read_json(runner_fd, _PAIRING_ACTIVATION_JOURNAL_FILENAME, None)
                if existing is None:
                    if _read_json(runner_fd, _PAIRED_RUNNER_IDENTITY_FILENAME, None) is not None:
                        raise RunnerStoreError("runner pairing activation is already complete")
                    _write_json(runner_fd, _PAIRING_ACTIVATION_JOURNAL_FILENAME, journal)
                elif existing != journal:
                    raise RunnerStoreError("runner pairing activation requires recovery")
        return PendingPairingActivation(dict(pending), dict(request), material)

    def accept_pairing_activation(
        self, pending: PendingPairingActivation, response_v3: Mapping[str, object], *, now_ms: int,
    ) -> RunnerIdentity:
        if not isinstance(pending, PendingPairingActivation):
            raise RunnerStoreError("prepared runner pairing activation is required")
        if (
            not isinstance(pending.pending, Mapping) or not isinstance(pending.request, Mapping)
            or not isinstance(pending._material, RunnerPairingMaterial)
        ):
            raise RunnerStoreError("prepared runner pairing activation is invalid")
        pending_record = self._pairing_pending(pending.pending)
        material = pending._material
        now_ms = self._pairing_time(now_ms, "pairing activation acceptance time")
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=True):
                journal = _read_json(runner_fd, _PAIRING_ACTIVATION_JOURNAL_FILENAME, None)
                if not isinstance(journal, Mapping) or journal.get("state") != "prepared":
                    raise RunnerStoreError("runner pairing activation requires recovery")
                journal_identity = RunnerIdentity(
                    runner_id=_id(journal.get("runner_id"), "runner ID"), workspace_id="pending",
                    runner_version=material.runner_version, adapter_versions=dict(material.adapters),
                    public_key_b64=material.public_key_b64, fingerprint=material.fingerprint,
                    key_id=material.key_id, pairing_phrase=material.pairing_phrase,
                )
                journal_fields = {
                    "schema_version", "state", "pairing_id", "runner_id", "pairing_exchange_digest",
                    "activation_challenge", "client_activation_nonce_b64", "activation_request",
                    "activation_response", "identity", "created_at_ms", "updated_at_ms",
                }
                self._verify_pairing_signed_value(
                    journal, identity=journal_identity, domain=_PAIRING_ACTIVATION_JOURNAL_DOMAIN,
                    digest_field="journal_digest", fields=journal_fields,
                    label="runner pairing activation journal",
                )
                request = journal.get("activation_request")
                if (
                    journal.get("schema_version") != _PAIRING_ACTIVATION_JOURNAL_SCHEMA
                    or journal.get("pairing_id") != pending_record["pairing_id"]
                    or journal.get("runner_id") != pending_record["runner_id"]
                    or journal.get("pairing_exchange_digest") != pending_record["pairing_exchange_digest"]
                    or journal.get("activation_challenge") != pending_record["activation_challenge"]
                    or request != dict(pending.request)
                    or journal.get("created_at_ms") != journal.get("updated_at_ms")
                ):
                    raise RunnerStoreError("runner pairing activation request changed")
                identity_value = journal.get("identity")
                if identity_value is not None or journal.get("activation_response") is not None:
                    raise RunnerStoreError("runner pairing activation requires recovery")
                response, identity = self._activation_response(
                    response_v3, material=material, pending=pending_record,
                )
                accepted_core = {
                    "schema_version": _PAIRING_ACTIVATION_JOURNAL_SCHEMA, "state": "accepted",
                    "pairing_id": pending_record["pairing_id"], "runner_id": pending_record["runner_id"],
                    "pairing_exchange_digest": pending_record["pairing_exchange_digest"],
                    "activation_challenge": pending_record["activation_challenge"],
                    "client_activation_nonce_b64": journal["client_activation_nonce_b64"],
                    "activation_request": dict(pending.request), "activation_response": response,
                    "identity": _identity_record(identity, material._signer),
                    "created_at_ms": journal["created_at_ms"], "updated_at_ms": now_ms,
                }
                accepted = self._pairing_signed_value(
                    accepted_core, signer=material._signer, domain=_PAIRING_ACTIVATION_JOURNAL_DOMAIN,
                    digest_field="journal_digest",
                )
                _write_json(runner_fd, _PAIRING_ACTIVATION_JOURNAL_FILENAME, accepted)
        self._pin_runtime_authority(identity, material._signer)
        return identity

    @staticmethod
    def _pairing_abort_tombstone_filename(pairing_id: str) -> str:
        return f"pairing-{hashlib.sha256(pairing_id.encode('utf-8')).hexdigest()}.json"

    @classmethod
    def _pairing_abort_tombstone(
        cls, value: object, *, material: RunnerPairingMaterial,
    ) -> dict[str, object]:
        fields = {
            "schema_version", "workspace_id", "runner_id", "pairing_id",
            "prepared_journal_digest", "activation_request_digest", "abort_request_digest",
            "abort_response_digest", "challenge_expires_at_ms", "aborted_at_ms",
        }
        if not isinstance(value, Mapping) or set(value) != fields | {"signing_key_id", "signature_b64"}:
            raise RunnerStoreError("invalid runner pairing activation abort tombstone")
        if value.get("schema_version") != _PAIRING_ABORT_TOMBSTONE_SCHEMA or value.get("signing_key_id") != material.key_id:
            raise RunnerStoreError("invalid runner pairing activation abort tombstone")
        core = {key: value[key] for key in fields}
        try:
            for field in ("workspace_id", "runner_id", "pairing_id"):
                _id(core[field], f"pairing abort {field}")
            for field in (
                "prepared_journal_digest", "activation_request_digest", "abort_request_digest",
                "abort_response_digest",
            ):
                _digest(core[field], f"pairing abort {field}")
            cls._pairing_time(core["challenge_expires_at_ms"], "pairing abort challenge expiry")
            cls._pairing_time(core["aborted_at_ms"], "pairing abort time")
            verify_envelope(
                {material.key_id: load_public_key_base64(material.public_key_b64)},
                {"signing_key_id": value["signing_key_id"], "signature_b64": value["signature_b64"]},
                _PAIRING_ABORT_TOMBSTONE_DOMAIN + canonical_bytes(core),
            )
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid runner pairing activation abort tombstone") from None
        return dict(value)

    def complete_pairing_activation_abort(
        self, pending: PendingPairingActivation, abort_request: Mapping[str, object],
        abort_response: Mapping[str, object],
    ) -> None:
        """Persist the Cloud-proven pairing abort before releasing its prepared journal."""
        if not isinstance(pending, PendingPairingActivation) or not isinstance(pending._material, RunnerPairingMaterial):
            raise RunnerStoreError("prepared runner pairing activation is required")
        material = pending._material
        pending_record = self._pairing_pending(pending.pending)
        journal_fields = {
            "schema_version", "state", "pairing_id", "runner_id", "pairing_exchange_digest",
            "activation_challenge", "client_activation_nonce_b64", "activation_request",
            "activation_response", "identity", "created_at_ms", "updated_at_ms",
        }
        abort_fields = {
            "schema_version", "pairing_id", "runner_id", "pairing_exchange_digest",
            "activation_request_digest", "challenge_expires_at_ms", "reason_code", "signature_b64",
        }
        response_fields = {
            "schema_version", "workspace_id", "runner_id", "pairing_id",
            "activation_request_digest", "status", "aborted_at_ms",
        }
        if (
            not isinstance(abort_request, Mapping) or set(abort_request) != abort_fields
            or abort_request.get("schema_version") != "heel.runner-pairing-activation-abort.v1"
            or abort_request.get("pairing_id") != pending_record["pairing_id"]
            or abort_request.get("runner_id") != pending_record["runner_id"]
            or abort_request.get("pairing_exchange_digest") != pending_record["pairing_exchange_digest"]
            or abort_request.get("reason_code") != "activation_challenge_expired"
            or not _digest(abort_request.get("activation_request_digest"), "pairing abort request digest")
            or not isinstance(abort_response, Mapping) or set(abort_response) != response_fields
            or abort_response.get("schema_version") != "heel.runner-pairing-activation-aborted.v1"
            or abort_response.get("runner_id") != pending_record["runner_id"]
            or abort_response.get("pairing_id") != pending_record["pairing_id"]
            or abort_response.get("activation_request_digest") != abort_request["activation_request_digest"]
            or abort_response.get("status") != "expired"
        ):
            raise RunnerStoreError("invalid runner pairing activation abort")
        challenge_expiry = self._pairing_time(
            abort_request.get("challenge_expires_at_ms"), "pairing abort challenge expiry",
        )
        aborted_at = self._pairing_time(abort_response.get("aborted_at_ms"), "pairing abort time")
        if aborted_at < challenge_expiry:
            raise RunnerStoreError("invalid runner pairing activation abort")
        _id(abort_response.get("workspace_id"), "pairing abort workspace")
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=True):
                journal = _read_json(runner_fd, _PAIRING_ACTIVATION_JOURNAL_FILENAME, None)
                pseudo_identity = RunnerIdentity(
                    runner_id=pending_record["runner_id"], workspace_id="pending",
                    runner_version=material.runner_version, adapter_versions=dict(material.adapters),
                    public_key_b64=material.public_key_b64, fingerprint=material.fingerprint,
                    key_id=material.key_id, pairing_phrase=material.pairing_phrase,
                )
                verified = self._verify_pairing_signed_value(
                    journal, identity=pseudo_identity, domain=_PAIRING_ACTIVATION_JOURNAL_DOMAIN,
                    digest_field="journal_digest", fields=journal_fields,
                    label="runner pairing activation journal",
                )
                if (
                    verified.get("state") != "prepared"
                    or verified.get("activation_response") is not None or verified.get("identity") is not None
                    or verified.get("activation_request") != dict(pending.request)
                    or verified.get("pairing_id") != pending_record["pairing_id"]
                    or verified.get("runner_id") != pending_record["runner_id"]
                ):
                    raise RunnerStoreError("runner pairing activation requires recovery")
                if abort_request["activation_request_digest"] != hashlib.sha256(canonical_bytes(dict(pending.request))).hexdigest():
                    raise RunnerStoreError("invalid runner pairing activation abort")
                core = {
                    "schema_version": _PAIRING_ABORT_TOMBSTONE_SCHEMA,
                    "workspace_id": abort_response["workspace_id"], "runner_id": pending_record["runner_id"],
                    "pairing_id": pending_record["pairing_id"], "prepared_journal_digest": verified["journal_digest"],
                    "activation_request_digest": abort_request["activation_request_digest"],
                    "abort_request_digest": hashlib.sha256(canonical_bytes(dict(abort_request))).hexdigest(),
                    "abort_response_digest": hashlib.sha256(canonical_bytes(dict(abort_response))).hexdigest(),
                    "challenge_expires_at_ms": challenge_expiry, "aborted_at_ms": aborted_at,
                }
                signature = material._signer.sign(_PAIRING_ABORT_TOMBSTONE_DOMAIN + canonical_bytes(core))
                if type(signature) is not bytes or len(signature) != 64:
                    raise RunnerStoreError("runner signer returned an invalid pairing activation signature")
                tombstone = {
                    **core, "signing_key_id": material.key_id,
                    "signature_b64": base64.b64encode(signature).decode("ascii"),
                }
                tombstones_fd = _open_child(runner_fd, _ACTIVATION_TOMBSTONES_DIRECTORY, create=True)
                assert tombstones_fd is not None
                try:
                    filename = self._pairing_abort_tombstone_filename(pending_record["pairing_id"])
                    existing = _read_json(tombstones_fd, filename, None)
                    if existing is None:
                        _write_json(tombstones_fd, filename, tombstone)
                    elif self._pairing_abort_tombstone(existing, material=material) != tombstone:
                        raise RunnerStoreError("runner pairing activation abort changed")
                finally:
                    os.close(tombstones_fd)
                os.unlink(_PAIRING_ACTIVATION_JOURNAL_FILENAME, dir_fd=runner_fd)
                os.fsync(runner_fd)

    def finish_pairing_activation(self, runtime_state: object) -> RunnerIdentity:
        """Publish paired v3 identity and its server cursor, then clear the accepted journal."""
        identity, signer = self._require_runtime_authority()
        if not self._runtime_matches_identity(runtime_state, identity=identity, signer=signer):
            raise RunnerStoreError("runner runtime identity does not match pairing activation")
        journal_fields = {
            "schema_version", "state", "pairing_id", "runner_id", "pairing_exchange_digest",
            "activation_challenge", "client_activation_nonce_b64", "activation_request",
            "activation_response", "identity", "created_at_ms", "updated_at_ms",
        }
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=True):
                journal = _read_json(runner_fd, _PAIRING_ACTIVATION_JOURNAL_FILENAME, None)
                if not isinstance(journal, Mapping) or journal.get("state") != "accepted":
                    raise RunnerStoreError("runner pairing activation requires recovery")
                self._verify_pairing_signed_value(
                    journal, identity=identity, domain=_PAIRING_ACTIVATION_JOURNAL_DOMAIN,
                    digest_field="journal_digest", fields=journal_fields,
                    label="runner pairing activation journal",
                )
                if journal.get("identity") != _identity_record(identity, signer):
                    raise RunnerStoreError("runner pairing activation identity changed")
                response = journal.get("activation_response")
                if (
                    journal.get("runner_id") != identity.runner_id
                    or not isinstance(response, Mapping)
                    or response.get("runner_id") != identity.runner_id
                ):
                    raise RunnerStoreError("invalid runner pairing activation journal")
                nonce = self._pairing_nonce(response.get("initial_claim_nonce"), "initial claim nonce")
                if response.get("initial_claim_sequence") != 1 or response.get("initial_claim_generation") != 0:
                    raise RunnerStoreError("invalid runner pairing activation journal")
                paired_core = {
                    "schema_version": _PAIRED_RUNNER_IDENTITY_SCHEMA,
                    "identity": _identity_record(identity, signer), "pairing_protocol_version": 3,
                    "control_protocol": "heel.runner-control.v2", "pairing_id": journal["pairing_id"],
                    "pairing_exchange_digest": journal["pairing_exchange_digest"],
                    "activated_at_ms": response.get("activated_at_ms"),
                    "activation_response_digest": hashlib.sha256(canonical_bytes(response)).hexdigest(),
                }
                paired = self._pairing_signed_value(
                    paired_core, signer=signer, domain=_PAIRED_RUNNER_IDENTITY_DOMAIN,
                    digest_field="record_digest",
                )
                existing_paired = _read_json(runner_fd, _PAIRED_RUNNER_IDENTITY_FILENAME, None)
                if existing_paired is None:
                    _write_json(runner_fd, _PAIRED_RUNNER_IDENTITY_FILENAME, paired)
                elif existing_paired != paired:
                    raise RunnerStoreError("paired runner identity changed")
                install = getattr(runtime_state, "install_chain", None)
                load = getattr(runtime_state, "load_chain", None)
                if not callable(install) or not callable(load):
                    raise RunnerStoreError("runner runtime state is invalid")
                cursor = install(
                    operation="claim", run_id=None, next_nonce_b64=nonce,
                    next_sequence=1, generation=0, now_ms=response["activated_at_ms"],
                )
                if cursor.next_nonce_b64 != nonce or cursor.next_sequence != 1 or cursor.generation != 0:
                    raise RunnerStoreError("runner runtime pairing cursor changed")
                verified = load("claim", None)
                if verified != cursor:
                    raise RunnerStoreError("runner runtime pairing cursor is unavailable")
                os.unlink(_PAIRING_ACTIVATION_JOURNAL_FILENAME, dir_fd=runner_fd)
                os.fsync(runner_fd)
        return identity

    def recover_pairing_activation(
        self, material: RunnerPairingMaterial, runtime_path: Path | str,
    ) -> PendingPairingActivation | RunnerIdentity | None:
        """Complete exactly one signed local pairing prefix without discovering state."""
        if not isinstance(material, RunnerPairingMaterial):
            raise RunnerStoreError("runner pairing material is required")
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=False):
                journal = _read_json(runner_fd, _PAIRING_ACTIVATION_JOURNAL_FILENAME, None)
        if journal is None:
            return None
        if not isinstance(journal, Mapping):
            raise RunnerStoreError("invalid runner pairing activation journal")
        state = journal.get("state")
        if state not in {"prepared", "accepted"}:
            raise RunnerStoreError("invalid runner pairing activation journal")
        basic_fields = {
            "schema_version", "state", "pairing_id", "runner_id", "pairing_exchange_digest",
            "activation_challenge", "client_activation_nonce_b64", "activation_request",
            "activation_response", "identity", "created_at_ms", "updated_at_ms",
        }
        pending = self._pairing_pending({
            "schema_version": "heel.runner-pairing-pending.v2", "pairing_id": journal.get("pairing_id"),
            "runner_id": journal.get("runner_id"),
            "fingerprint": material.fingerprint, "status": "pending",
            "activation_challenge": journal.get("activation_challenge"),
            "control_protocol": "heel.runner-control.v2",
            "pairing_exchange_digest": journal.get("pairing_exchange_digest"),
        })
        if state == "prepared":
            pseudo_identity = RunnerIdentity(
                runner_id=pending["runner_id"], workspace_id="pending", runner_version=material.runner_version,
                adapter_versions=dict(material.adapters), public_key_b64=material.public_key_b64,
                fingerprint=material.fingerprint, key_id=material.key_id,
                pairing_phrase=material.pairing_phrase,
            )
            verified_journal = self._verify_pairing_signed_value(
                journal, identity=pseudo_identity, domain=_PAIRING_ACTIVATION_JOURNAL_DOMAIN,
                digest_field="journal_digest", fields=basic_fields,
                label="runner pairing activation journal",
            )
            request = journal.get("activation_request")
            if journal.get("activation_response") is not None or journal.get("identity") is not None or not isinstance(request, Mapping):
                raise RunnerStoreError("invalid runner pairing activation journal")
            with self._open_runner(create=True) as runner_fd:
                assert runner_fd is not None
                with _flock(runner_fd, ".runner.lock", exclusive=True):
                    tombstones_fd = _open_child(runner_fd, _ACTIVATION_TOMBSTONES_DIRECTORY, create=False)
                    tombstone = None
                    if tombstones_fd is not None:
                        try:
                            tombstone = _read_json(
                                tombstones_fd,
                                self._pairing_abort_tombstone_filename(pending["pairing_id"]), None,
                            )
                        finally:
                            os.close(tombstones_fd)
                    if tombstone is not None:
                        verified_tombstone = self._pairing_abort_tombstone(tombstone, material=material)
                        if (
                            verified_tombstone["pairing_id"] != pending["pairing_id"]
                            or verified_tombstone["runner_id"] != pending["runner_id"]
                            or verified_tombstone["prepared_journal_digest"] != verified_journal["journal_digest"]
                            or verified_tombstone["activation_request_digest"]
                                != hashlib.sha256(canonical_bytes(dict(request))).hexdigest()
                        ):
                            raise RunnerStoreError("invalid runner pairing activation abort tombstone")
                        if _read_json(runner_fd, _PAIRING_ACTIVATION_JOURNAL_FILENAME, None) != journal:
                            raise RunnerStoreError("runner pairing activation requires recovery")
                        os.unlink(_PAIRING_ACTIVATION_JOURNAL_FILENAME, dir_fd=runner_fd)
                        os.fsync(runner_fd)
                        return None
            return PendingPairingActivation(dict(pending), dict(request), material)
        if not isinstance(journal.get("identity"), Mapping) or not isinstance(journal.get("activation_response"), Mapping):
            raise RunnerStoreError("invalid runner pairing activation journal")
        identity_record = _stored_identity_record(journal["identity"])
        if (
            identity_record["public_key_b64"] != material.public_key_b64
            or identity_record["fingerprint"] != material.fingerprint
            or identity_record["runner_key_id"] != material.key_id
        ):
            raise RunnerStoreError("runner pairing activation identity changed")
        identity = RunnerIdentity(
            runner_id=identity_record["runner_id"], workspace_id=identity_record["workspace_id"],
            runner_version=identity_record["runner_version"], adapter_versions=identity_record["adapter_versions"],
            public_key_b64=identity_record["public_key_b64"], fingerprint=identity_record["fingerprint"],
            key_id=identity_record["runner_key_id"], pairing_phrase=material.pairing_phrase,
        )
        self._verify_pairing_signed_value(
            journal, identity=identity, domain=_PAIRING_ACTIVATION_JOURNAL_DOMAIN,
            digest_field="journal_digest", fields=basic_fields,
            label="runner pairing activation journal",
        )
        response = journal["activation_response"]
        if (
            journal.get("runner_id") != identity.runner_id
            or response.get("runner_id") != identity.runner_id
            or response.get("workspace_id") != identity.workspace_id
        ):
            raise RunnerStoreError("invalid runner pairing activation journal")
        self._pin_runtime_authority(identity, material._signer)
        from heel.runner.runtime import RunnerRuntimeState
        runtime = RunnerRuntimeState(runtime_path, identity, material._signer)
        return self.finish_pairing_activation(runtime)

    @classmethod
    def _rotation_pending(cls, value: Mapping[str, object]) -> dict[str, object]:
        fields = {"schema_version", "pairing_id", "activation_challenge"}
        if not isinstance(value, Mapping) or set(value) != fields or value.get("schema_version") != "heel.runner-rotation-activation-challenge.v1":
            raise RunnerStoreError("invalid runner rotation activation challenge")
        return {
            "schema_version": value["schema_version"],
            "pairing_id": _id(value["pairing_id"], "rotation pairing ID"),
            "activation_challenge": cls._pairing_nonce(value["activation_challenge"], "rotation activation challenge"),
        }

    @classmethod
    def _rotation_response(
        cls, value: Mapping[str, object], *, identity: RunnerIdentity,
    ) -> dict[str, object]:
        fields = {
            "schema_version", "workspace_id", "runner_id", "initial_claim_nonce",
            "initial_claim_sequence", "initial_claim_generation",
        }
        if not isinstance(value, Mapping) or set(value) != fields or (
            value.get("schema_version") != "heel.runner-rotation-activated.v2"
            or value.get("workspace_id") != identity.workspace_id
            or value.get("runner_id") != identity.runner_id
        ):
            raise RunnerStoreError("invalid runner rotation activation response")
        sequence = value["initial_claim_sequence"]
        generation = value["initial_claim_generation"]
        if (
            type(sequence) is not int or not 1 <= sequence <= 9_007_199_254_740_991
            or type(generation) is not int or not 0 <= generation <= 9_007_199_254_740_991
        ):
            raise RunnerStoreError("invalid runner rotation activation response")
        return {
            "schema_version": value["schema_version"], "workspace_id": identity.workspace_id,
            "runner_id": identity.runner_id,
            "initial_claim_nonce": cls._pairing_nonce(value["initial_claim_nonce"], "rotation claim nonce"),
            "initial_claim_sequence": sequence, "initial_claim_generation": generation,
        }

    @classmethod
    def _rotation_intent_core(
        cls, *, pairing_id: object, old_identity: RunnerIdentity, new_identity: RunnerIdentity,
        activation_request: Mapping[str, object], activation_challenge: object,
        new_signer_label: object, authority_epoch: object,
        authority_identity_digest: object, claim_state_digest: object, prepared_at_ms: object,
    ) -> dict[str, object]:
        request = dict(activation_request)
        challenge = cls._pairing_nonce(activation_challenge, "rotation activation challenge")
        epoch = cls._pairing_time(authority_epoch, "runtime authority epoch")
        if epoch < 1:
            raise RunnerStoreError("invalid runner rotation activation journal")
        return {
            "schema_version": _ROTATION_RUNTIME_INTENT_SCHEMA,
            "workspace_id": old_identity.workspace_id,
            "runner_id": old_identity.runner_id,
            "old_runner_key_id": old_identity.key_id,
            "new_runner_key_id": new_identity.key_id,
            "pairing_id": _id(pairing_id, "rotation pairing ID"),
            "activation_request_digest": hashlib.sha256(canonical_bytes(request)).hexdigest(),
            "activation_challenge_digest": hashlib.sha256(base64.b64decode(challenge, validate=True)).hexdigest(),
            "new_signer_label": _id(new_signer_label, "rotation signer label"),
            "runtime_authority_epoch": epoch,
            "runtime_authority_identity_digest": _digest(
                authority_identity_digest, "runtime authority identity digest",
            ),
            "runtime_claim_state_digest": _digest(claim_state_digest, "runtime claim state digest"),
            "prepared_at_ms": cls._pairing_time(prepared_at_ms, "rotation preparation time"),
        }

    @staticmethod
    def _rotation_intent_digest(core: Mapping[str, object]) -> str:
        return hashlib.sha256(_ROTATION_RUNTIME_INTENT_DOMAIN + canonical_bytes(dict(core))).hexdigest()

    @classmethod
    def _signed_rotation_journal(
        cls, core: Mapping[str, object], *, old_signer: SecureSigner, new_signer: SecureSigner,
    ) -> dict[str, object]:
        digest = hashlib.sha256(
            _ROTATION_ACTIVATION_JOURNAL_DIGEST_DOMAIN + canonical_bytes(dict(core))
        ).hexdigest()
        unsigned = {**core, "journal_digest": digest}
        old_signature = old_signer.sign(_ROTATION_ACTIVATION_JOURNAL_DOMAIN + canonical_bytes(unsigned))
        new_signature = new_signer.sign(_ROTATION_ACTIVATION_JOURNAL_DOMAIN + canonical_bytes(unsigned))
        if (
            type(old_signature) is not bytes or len(old_signature) != 64
            or type(new_signature) is not bytes or len(new_signature) != 64
        ):
            raise RunnerStoreError("runner signer returned an invalid rotation signature")
        return {
            **unsigned,
            "old_signing_key_id": old_signer.key_id,
            "old_signature_b64": base64.b64encode(old_signature).decode("ascii"),
            "new_signing_key_id": new_signer.key_id,
            "new_signature_b64": base64.b64encode(new_signature).decode("ascii"),
        }

    @classmethod
    def _verify_rotation_journal(
        cls, value: object, *, old_identity: RunnerIdentity, new_identity: RunnerIdentity,
    ) -> dict[str, object]:
        fields = {
            "schema_version", "state", "pairing_id", "old_identity", "new_identity",
            "new_signer_label", "activation_challenge", "activation_request", "activation_response",
            "created_at_ms", "updated_at_ms", "workspace_id", "runner_id",
            "old_runner_key_id", "new_runner_key_id",
            "activation_request_digest", "activation_challenge_digest", "runtime_authority_epoch",
            "runtime_authority_identity_digest", "runtime_claim_state_digest",
            "runtime_rotation_intent_digest", "prepared_at_ms",
        }
        signature_fields = {
            "journal_digest", "old_signing_key_id", "old_signature_b64",
            "new_signing_key_id", "new_signature_b64",
        }
        if not isinstance(value, Mapping):
            raise RunnerStoreError("invalid runner rotation activation journal")
        if value.get("state") == "accepted":
            fields.add("prepared_journal_digest")
        if set(value) != fields | signature_fields:
            raise RunnerStoreError("invalid runner rotation activation journal")
        if value.get("schema_version") != _ROTATION_ACTIVATION_JOURNAL_SCHEMA or value.get("state") not in {"prepared", "accepted"}:
            raise RunnerStoreError("invalid runner rotation activation journal")
        core = {key: value[key] for key in fields}
        if value["journal_digest"] != hashlib.sha256(
            _ROTATION_ACTIVATION_JOURNAL_DIGEST_DOMAIN + canonical_bytes(core)
        ).hexdigest():
            raise RunnerStoreError("invalid runner rotation activation journal")
        if (
            value["old_identity"] != _identity_record(old_identity, _IdentityPublicSigner(old_identity))
            or value["new_identity"] != _identity_record(new_identity, _IdentityPublicSigner(new_identity))
            or value["old_signing_key_id"] != old_identity.key_id
            or value["new_signing_key_id"] != new_identity.key_id
        ):
            raise RunnerStoreError("invalid runner rotation activation journal")
        try:
            unsigned = {**core, "journal_digest": value["journal_digest"]}
            verify_envelope(
                {old_identity.key_id: load_public_key_base64(old_identity.public_key_b64)},
                {"signing_key_id": value["old_signing_key_id"], "signature_b64": value["old_signature_b64"]},
                _ROTATION_ACTIVATION_JOURNAL_DOMAIN + canonical_bytes(unsigned),
            )
            verify_envelope(
                {new_identity.key_id: load_public_key_base64(new_identity.public_key_b64)},
                {"signing_key_id": value["new_signing_key_id"], "signature_b64": value["new_signature_b64"]},
                _ROTATION_ACTIVATION_JOURNAL_DOMAIN + canonical_bytes(unsigned),
            )
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid runner rotation activation journal") from None
        if (
            type(value["pairing_id"]) is not str or _id(value["pairing_id"], "rotation pairing ID") != value["pairing_id"]
            or type(value["new_signer_label"]) is not str or _id(value["new_signer_label"], "rotation signer label") != value["new_signer_label"]
            or cls._pairing_nonce(value["activation_challenge"], "rotation activation challenge") != value["activation_challenge"]
            or cls._pairing_time(value["created_at_ms"], "rotation creation time") > cls._pairing_time(value["updated_at_ms"], "rotation update time")
        ):
            raise RunnerStoreError("invalid runner rotation activation journal")
        request = value["activation_request"]
        if not isinstance(request, Mapping) or set(request) != {"schema_version", "signature_b64"} or request.get("schema_version") != "heel.runner-rotation-activate.v2":
            raise RunnerStoreError("invalid runner rotation activation journal")
        intent = cls._rotation_intent_core(
            pairing_id=value["pairing_id"], old_identity=old_identity, new_identity=new_identity,
            activation_request=request, activation_challenge=value["activation_challenge"],
            new_signer_label=value["new_signer_label"], authority_epoch=value["runtime_authority_epoch"],
            authority_identity_digest=value["runtime_authority_identity_digest"],
            claim_state_digest=value["runtime_claim_state_digest"],
            prepared_at_ms=value["prepared_at_ms"],
        )
        if (
            value["old_runner_key_id"] != old_identity.key_id
            or value["new_runner_key_id"] != new_identity.key_id
            or value["workspace_id"] != old_identity.workspace_id
            or value["runner_id"] != old_identity.runner_id
            or value["activation_request_digest"] != intent["activation_request_digest"]
            or value["activation_challenge_digest"] != intent["activation_challenge_digest"]
            or value["runtime_rotation_intent_digest"] != cls._rotation_intent_digest(intent)
            or value["prepared_at_ms"] != value["created_at_ms"]
        ):
            raise RunnerStoreError("invalid runner rotation activation journal")
        if value["state"] == "prepared":
            if value["activation_response"] is not None or value["created_at_ms"] != value["updated_at_ms"]:
                raise RunnerStoreError("invalid runner rotation activation journal")
        else:
            if (
                _digest(value["prepared_journal_digest"], "rotation prepared journal digest") != value["prepared_journal_digest"]
                or cls._rotation_response(value["activation_response"], identity=new_identity) != value["activation_response"]
            ):
                raise RunnerStoreError("invalid runner rotation activation journal")
        return dict(value)

    @classmethod
    def _accepted_rotation_journal(
        cls, value: Mapping[str, object], *, old_identity: RunnerIdentity, new_identity: RunnerIdentity,
    ) -> AcceptedRotationJournal:
        verified = cls._verify_rotation_journal(value, old_identity=old_identity, new_identity=new_identity)
        if verified["state"] != "accepted":
            raise RunnerStoreError("runner rotation activation requires recovery")
        return AcceptedRotationJournal(
            pairing_id=verified["pairing_id"], old_identity=old_identity, new_identity=new_identity,
            activation_challenge=verified["activation_challenge"],
            activation_request=dict(verified["activation_request"]),
            activation_response=dict(verified["activation_response"]),
            created_at_ms=verified["created_at_ms"], updated_at_ms=verified["updated_at_ms"],
            new_signer_label=verified["new_signer_label"],
            prepared_journal_digest=verified["prepared_journal_digest"],
            runtime_rotation_intent_digest=verified["runtime_rotation_intent_digest"],
        )

    @staticmethod
    def _rotation_identity_from_record(value: object, *, pairing_phrase: tuple[str, ...]) -> RunnerIdentity:
        record = _stored_identity_record(value)
        return RunnerIdentity(
            runner_id=record["runner_id"], workspace_id=record["workspace_id"],
            runner_version=record["runner_version"], adapter_versions=record["adapter_versions"],
            public_key_b64=record["public_key_b64"], fingerprint=record["fingerprint"],
            key_id=record["runner_key_id"], pairing_phrase=pairing_phrase,
        )

    @classmethod
    def _verify_paired_rotation_identity(
        cls, value: object, *, identity: RunnerIdentity, signer: SecureSigner,
        required_signer_label: str | None = None,
    ) -> dict[str, object]:
        fields = {
            "schema_version", "identity", "pairing_protocol_version", "control_protocol",
            "pairing_id", "pairing_exchange_digest", "activated_at_ms", "activation_response_digest",
        }
        if not isinstance(value, Mapping):
            raise RunnerStoreError("paired runner identity requires recovery")
        if "signer_label" in value:
            fields.add("signer_label")
        verified = cls._verify_pairing_signed_value(
            value, identity=identity, domain=_PAIRED_RUNNER_IDENTITY_DOMAIN,
            digest_field="record_digest", fields=fields, label="paired runner identity",
        )
        if (
            verified["schema_version"] != _PAIRED_RUNNER_IDENTITY_SCHEMA
            or verified["identity"] != _identity_record(identity, signer)
            or verified["pairing_protocol_version"] != 3
            or verified["control_protocol"] != "heel.runner-control.v2"
        ):
            raise RunnerStoreError("paired runner identity requires recovery")
        _id(verified["pairing_id"], "paired runner pairing ID")
        _digest(verified["pairing_exchange_digest"], "paired runner exchange digest")
        _digest(verified["activation_response_digest"], "paired runner activation digest")
        cls._pairing_time(verified["activated_at_ms"], "paired runner activation time")
        actual_label = verified.get("signer_label")
        if actual_label is not None:
            actual_label = _id(actual_label, "paired runner signer label")
        if required_signer_label is not None and actual_label != required_signer_label:
            raise RunnerStoreError("paired runner identity requires recovery")
        return verified

    def prepare_rotation_activation(
        self, pending: Mapping[str, object], *, old_identity: RunnerIdentity, old_signer: SecureSigner,
        new_identity: RunnerIdentity, new_signer: SecureSigner, new_signer_label: str,
        runtime_state: object, now_ms: int,
    ) -> PendingRotationActivation:
        """Persist the dual-signed rotation request before it can reach the control plane."""
        pending_value = self._rotation_pending(pending)
        now_ms = self._pairing_time(now_ms, "rotation preparation time")
        if (
            not isinstance(old_identity, RunnerIdentity) or not isinstance(new_identity, RunnerIdentity)
            or not isinstance(old_signer, SecureSigner) or not isinstance(new_signer, SecureSigner)
            or old_identity.workspace_id != new_identity.workspace_id
            or old_identity.runner_id != new_identity.runner_id
            or old_identity.key_id == new_identity.key_id
        ):
            raise RunnerStoreError("invalid runner rotation identity")
        old_record = _identity_record(old_identity, old_signer)
        new_record = _identity_record(new_identity, new_signer)
        new_signer_label = _id(new_signer_label, "rotation signer label")
        if self._namespace is not None:
            raise RunnerStoreError("runner rotation requires re-pairing")
        authority = self._runtime_authority
        if authority is None:
            self._runtime_authority = (old_identity, old_signer)
        elif _identity_record(*authority) != old_record:
            raise RunnerStoreError("authenticated runner store identity changed")
        from heel.runner.runtime import RunnerRuntimeConflict, RunnerRuntimeState
        if not isinstance(runtime_state, RunnerRuntimeState) or not runtime_state._same_identity(
            runtime_state.identity, old_identity,
        ):
            raise RunnerStoreError("runner runtime state is invalid")
        # This read-only probe happens before request signing or journal creation.  Its
        # sealed claim cursor is folded into the signed intent and rechecked by the CAS.
        try:
            probe = runtime_state.probe_rotation_eligible(old_identity=old_identity)
        except RunnerRuntimeConflict as exc:
            raise RunnerStoreError("runner rotation is unavailable") from exc
        proof = {"pairing_id": pending_value["pairing_id"], "challenge": pending_value["activation_challenge"]}
        signature = new_signer.sign(b"heel.runner-rotation-activate.v2\0" + canonical_bytes(proof))
        if type(signature) is not bytes or len(signature) != 64:
            raise RunnerStoreError("runner signer returned an invalid rotation signature")
        request = {
            "schema_version": "heel.runner-rotation-activate.v2",
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }
        intent = self._rotation_intent_core(
            pairing_id=pending_value["pairing_id"], old_identity=old_identity, new_identity=new_identity,
            activation_request=request, activation_challenge=pending_value["activation_challenge"],
            new_signer_label=new_signer_label, authority_epoch=probe.authority_epoch,
            authority_identity_digest=probe.authority_identity_digest,
            claim_state_digest=probe.claim_state_digest, prepared_at_ms=now_ms,
        )
        core = {
            "schema_version": _ROTATION_ACTIVATION_JOURNAL_SCHEMA, "state": "prepared",
            "pairing_id": pending_value["pairing_id"], "old_identity": old_record, "new_identity": new_record,
            "new_signer_label": new_signer_label, "activation_challenge": pending_value["activation_challenge"],
            "activation_request": request, "activation_response": None,
            "created_at_ms": now_ms, "updated_at_ms": now_ms,
            **{key: value for key, value in intent.items() if key != "schema_version"},
            "runtime_rotation_intent_digest": self._rotation_intent_digest(intent),
        }
        journal = self._signed_rotation_journal(core, old_signer=old_signer, new_signer=new_signer)
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=True):
                existing = _read_json(runner_fd, _ROTATION_ACTIVATION_JOURNAL_FILENAME, None)
                if existing is None:
                    _write_json(runner_fd, _ROTATION_ACTIVATION_JOURNAL_FILENAME, journal)
                elif existing != journal:
                    raise RunnerStoreError("runner rotation activation requires recovery")
        try:
            eligibility = runtime_state.assert_rotation_eligible(
                old_identity=old_identity, probe=probe, prepared_journal_digest=journal["journal_digest"],
                runtime_rotation_intent_digest=journal["runtime_rotation_intent_digest"], now_ms=now_ms,
            )
        except RunnerRuntimeConflict as exc:
            epoch, identity_digest, fence = runtime_state.rotation_fence_snapshot()
            if (
                epoch == probe.authority_epoch and identity_digest == probe.authority_identity_digest
                and fence is None
            ):
                with self._open_runner(create=True) as runner_fd:
                    assert runner_fd is not None
                    with _flock(runner_fd, ".runner.lock", exclusive=True):
                        if _read_json(runner_fd, _ROTATION_ACTIVATION_JOURNAL_FILENAME, None) == journal:
                            os.unlink(_ROTATION_ACTIVATION_JOURNAL_FILENAME, dir_fd=runner_fd)
                            os.fsync(runner_fd)
                raise RunnerStoreError("runner rotation is unavailable") from exc
            raise RunnerStoreError("runner rotation activation requires recovery") from exc
        return PendingRotationActivation(
            dict(pending_value), dict(request), old_identity, new_identity, new_signer_label,
            new_signer, self._rotation_token, eligibility,
        )

    def accept_rotation_activation(
        self, pending: PendingRotationActivation, response: Mapping[str, object], *, now_ms: int,
    ) -> AcceptedRotationJournal:
        if not isinstance(pending, PendingRotationActivation) or pending._store_token is not self._rotation_token:
            raise RunnerStoreError("prepared runner rotation activation is required")
        pending_value = self._rotation_pending(pending.pending)
        now_ms = self._pairing_time(now_ms, "rotation activation acceptance time")
        old_identity, old_signer = self._require_runtime_authority()
        if _identity_record(old_identity, old_signer) != _identity_record(
            pending.old_identity, _IdentityPublicSigner(pending.old_identity),
        ):
            raise RunnerStoreError("runner rotation activation identity changed")
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=True):
                journal = _read_json(runner_fd, _ROTATION_ACTIVATION_JOURNAL_FILENAME, None)
                if not isinstance(journal, Mapping):
                    raise RunnerStoreError("runner rotation activation requires recovery")
                verified = self._verify_rotation_journal(
                    journal, old_identity=pending.old_identity, new_identity=pending.new_identity,
                )
                if verified["state"] != "prepared" or (
                    verified["pairing_id"] != pending_value["pairing_id"]
                    or verified["activation_challenge"] != pending_value["activation_challenge"]
                    or verified["activation_request"] != dict(pending.request)
                    or verified["new_signer_label"] != pending.new_signer_label
                ):
                    raise RunnerStoreError("runner rotation activation requires recovery")
                activated = self._rotation_response(response, identity=pending.new_identity)
                core = {
                    "schema_version": _ROTATION_ACTIVATION_JOURNAL_SCHEMA, "state": "accepted",
                    "pairing_id": verified["pairing_id"], "old_identity": verified["old_identity"],
                    "new_identity": verified["new_identity"], "new_signer_label": verified["new_signer_label"],
                    "activation_challenge": verified["activation_challenge"],
                    "activation_request": verified["activation_request"], "activation_response": activated,
                    "created_at_ms": verified["created_at_ms"], "updated_at_ms": now_ms,
                    "workspace_id": verified["workspace_id"], "runner_id": verified["runner_id"],
                    "old_runner_key_id": verified["old_runner_key_id"],
                    "new_runner_key_id": verified["new_runner_key_id"],
                    "activation_request_digest": verified["activation_request_digest"],
                    "activation_challenge_digest": verified["activation_challenge_digest"],
                    "runtime_authority_epoch": verified["runtime_authority_epoch"],
                    "runtime_authority_identity_digest": verified["runtime_authority_identity_digest"],
                    "runtime_claim_state_digest": verified["runtime_claim_state_digest"],
                    "runtime_rotation_intent_digest": verified["runtime_rotation_intent_digest"],
                    "prepared_at_ms": verified["prepared_at_ms"],
                    "prepared_journal_digest": verified["journal_digest"],
                }
                accepted = self._signed_rotation_journal(
                    core, old_signer=old_signer,
                    new_signer=pending._new_signer,
                )
                _write_json(runner_fd, _ROTATION_ACTIVATION_JOURNAL_FILENAME, accepted)
        return self._accepted_rotation_journal(
            accepted, old_identity=pending.old_identity, new_identity=pending.new_identity,
        )

    @staticmethod
    def _rotation_abort_tombstone_filename(pairing_id: str) -> str:
        return f"rotation-{hashlib.sha256(pairing_id.encode('utf-8')).hexdigest()}.json"

    @classmethod
    def _rotation_abort_tombstone(
        cls, value: object, *, old_identity: RunnerIdentity, new_identity: RunnerIdentity,
        prepared_journal: Mapping[str, object],
    ) -> AcceptedRotationAbortTombstone:
        """Open one exact dual-signed abort proof; never infer an abort from local time."""
        fields = {
            "schema_version", "workspace_id", "runner_id", "pairing_id", "old_runner_key_id",
            "new_runner_key_id", "prepared_journal_digest", "runtime_rotation_intent_digest",
            "runtime_authority_epoch", "runtime_authority_identity_digest",
            "activation_request_digest", "activation_challenge_digest", "abort_request_digest",
            "abort_response_digest", "challenge_expires_at_ms", "aborted_at_ms",
            "old_signing_key_id", "old_signature_b64", "new_signing_key_id", "new_signature_b64",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise RunnerStoreError("invalid runner rotation activation abort tombstone")
        if (
            value.get("schema_version") != _ROTATION_ABORT_TOMBSTONE_SCHEMA
            or value.get("workspace_id") != old_identity.workspace_id
            or value.get("runner_id") != old_identity.runner_id
            or value.get("pairing_id") != prepared_journal["pairing_id"]
            or value.get("old_runner_key_id") != old_identity.key_id
            or value.get("new_runner_key_id") != new_identity.key_id
            or value.get("prepared_journal_digest") != prepared_journal["journal_digest"]
            or value.get("runtime_rotation_intent_digest")
                != prepared_journal["runtime_rotation_intent_digest"]
            or value.get("runtime_authority_epoch") != prepared_journal["runtime_authority_epoch"]
            or value.get("runtime_authority_identity_digest")
                != prepared_journal["runtime_authority_identity_digest"]
            or value.get("activation_request_digest") != prepared_journal["activation_request_digest"]
            or value.get("activation_challenge_digest") != prepared_journal["activation_challenge_digest"]
            or value.get("old_signing_key_id") != old_identity.key_id
            or value.get("new_signing_key_id") != new_identity.key_id
        ):
            raise RunnerStoreError("invalid runner rotation activation abort tombstone")
        for name in (
            "prepared_journal_digest", "runtime_rotation_intent_digest",
            "runtime_authority_identity_digest", "activation_request_digest",
            "activation_challenge_digest", "abort_request_digest", "abort_response_digest",
        ):
            _digest(value.get(name), f"rotation abort tombstone {name}")
        challenge_expiry = cls._pairing_time(
            value.get("challenge_expires_at_ms"), "rotation abort tombstone challenge expiry",
        )
        if cls._pairing_time(value.get("aborted_at_ms"), "rotation abort tombstone time") < challenge_expiry:
            raise RunnerStoreError("invalid runner rotation activation abort tombstone")
        core = {name: value[name] for name in fields - {
            "old_signing_key_id", "old_signature_b64", "new_signing_key_id", "new_signature_b64",
        }}
        try:
            verify_envelope(
                {old_identity.key_id: load_public_key_base64(old_identity.public_key_b64)},
                {"signing_key_id": value["old_signing_key_id"], "signature_b64": value["old_signature_b64"]},
                _ROTATION_ABORT_TOMBSTONE_OLD_DOMAIN + canonical_bytes(core),
            )
            verify_envelope(
                {new_identity.key_id: load_public_key_base64(new_identity.public_key_b64)},
                {"signing_key_id": value["new_signing_key_id"], "signature_b64": value["new_signature_b64"]},
                _ROTATION_ABORT_TOMBSTONE_NEW_DOMAIN + canonical_bytes(core),
            )
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid runner rotation activation abort tombstone") from None
        return AcceptedRotationAbortTombstone(
            pairing_id=value["pairing_id"], old_identity=old_identity, new_identity=new_identity,
            prepared_journal_digest=value["prepared_journal_digest"],
            runtime_rotation_intent_digest=value["runtime_rotation_intent_digest"], record=dict(value),
        )

    def complete_rotation_activation_abort(
        self, pending: PendingRotationActivation, abort_request: Mapping[str, object],
        abort_response: Mapping[str, object], *, runtime_state: object,
    ) -> None:
        """Persist both abort signatures, clear the exact runtime fence, then unlink."""
        if not isinstance(pending, PendingRotationActivation) or pending._store_token is not self._rotation_token:
            raise RunnerStoreError("prepared runner rotation activation is required")
        from heel.runner.runtime import RunnerRuntimeState
        if not isinstance(runtime_state, RunnerRuntimeState):
            raise RunnerStoreError("runner runtime state is invalid")
        request_fields = {
            "schema_version", "workspace_id", "runner_id", "pairing_id", "old_runner_key_id",
            "new_runner_key_id", "activation_request_digest", "activation_challenge_digest",
            "challenge_expires_at_ms", "reason_code", "old_signature_b64", "new_signature_b64",
        }
        response_fields = {
            "schema_version", "workspace_id", "runner_id", "pairing_id", "old_runner_key_id",
            "new_runner_key_id", "activation_request_digest", "status", "aborted_at_ms",
        }
        if (
            not isinstance(abort_request, Mapping) or set(abort_request) != request_fields
            or abort_request.get("schema_version") != "heel.runner-rotation-activation-abort.v1"
            or abort_request.get("pairing_id") != pending.pending["pairing_id"]
            or abort_request.get("workspace_id") != pending.old_identity.workspace_id
            or abort_request.get("runner_id") != pending.old_identity.runner_id
            or abort_request.get("old_runner_key_id") != pending.old_identity.key_id
            or abort_request.get("new_runner_key_id") != pending.new_identity.key_id
            or abort_request.get("reason_code") != "activation_challenge_expired"
            or not isinstance(abort_response, Mapping) or set(abort_response) != response_fields
            or abort_response.get("schema_version") != "heel.runner-rotation-activation-aborted.v1"
            or abort_response.get("workspace_id") != pending.old_identity.workspace_id
            or abort_response.get("runner_id") != pending.old_identity.runner_id
            or abort_response.get("pairing_id") != pending.pending["pairing_id"]
            or abort_response.get("old_runner_key_id") != pending.old_identity.key_id
            or abort_response.get("new_runner_key_id") != pending.new_identity.key_id
            or abort_response.get("activation_request_digest") != abort_request.get("activation_request_digest")
            or abort_response.get("status") != "expired"
        ):
            raise RunnerStoreError("invalid runner rotation activation abort")
        for name in ("activation_request_digest", "activation_challenge_digest"):
            _digest(abort_request.get(name), f"rotation abort {name}")
        challenge_expiry = self._pairing_time(abort_request.get("challenge_expires_at_ms"), "rotation abort challenge expiry")
        aborted_at = self._pairing_time(abort_response.get("aborted_at_ms"), "rotation abort time")
        if aborted_at < challenge_expiry:
            raise RunnerStoreError("invalid runner rotation activation abort")
        core_request = {key: abort_request[key] for key in request_fields - {"old_signature_b64", "new_signature_b64"}}
        try:
            verify_envelope(
                {pending.old_identity.key_id: load_public_key_base64(pending.old_identity.public_key_b64)},
                {"signing_key_id": pending.old_identity.key_id, "signature_b64": abort_request["old_signature_b64"]},
                b"heel.runner-rotation-activation-abort.v1.old\0" + canonical_bytes(core_request),
            )
            verify_envelope(
                {pending.new_identity.key_id: load_public_key_base64(pending.new_identity.public_key_b64)},
                {"signing_key_id": pending.new_identity.key_id, "signature_b64": abort_request["new_signature_b64"]},
                b"heel.runner-rotation-activation-abort.v1.new\0" + canonical_bytes(core_request),
            )
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid runner rotation activation abort") from None
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=True):
                journal = _read_json(runner_fd, _ROTATION_ACTIVATION_JOURNAL_FILENAME, None)
                verified = self._verify_rotation_journal(
                    journal, old_identity=pending.old_identity, new_identity=pending.new_identity,
                )
                if (
                    verified["state"] != "prepared"
                    or verified["pairing_id"] != pending.pending["pairing_id"]
                    or verified["activation_request"] != dict(pending.request)
                    or verified["runtime_rotation_intent_digest"]
                        != pending._eligibility.runtime_rotation_intent_digest
                    or verified["journal_digest"] != pending._eligibility.prepared_journal_digest
                ):
                    raise RunnerStoreError("runner rotation activation requires recovery")
                if abort_request["activation_request_digest"] != hashlib.sha256(canonical_bytes(dict(pending.request))).hexdigest():
                    raise RunnerStoreError("invalid runner rotation activation abort")
                core = {
                    "schema_version": _ROTATION_ABORT_TOMBSTONE_SCHEMA,
                    "workspace_id": pending.old_identity.workspace_id, "runner_id": pending.old_identity.runner_id,
                    "pairing_id": pending.pending["pairing_id"], "old_runner_key_id": pending.old_identity.key_id,
                    "new_runner_key_id": pending.new_identity.key_id,
                    "prepared_journal_digest": verified["journal_digest"],
                    "runtime_rotation_intent_digest": verified["runtime_rotation_intent_digest"],
                    "runtime_authority_epoch": verified["runtime_authority_epoch"],
                    "runtime_authority_identity_digest": verified["runtime_authority_identity_digest"],
                    "activation_request_digest": abort_request["activation_request_digest"],
                    "activation_challenge_digest": abort_request["activation_challenge_digest"],
                    "abort_request_digest": hashlib.sha256(canonical_bytes(dict(abort_request))).hexdigest(),
                    "abort_response_digest": hashlib.sha256(canonical_bytes(dict(abort_response))).hexdigest(),
                    "challenge_expires_at_ms": challenge_expiry, "aborted_at_ms": aborted_at,
                }
                old_signer = self._require_runtime_authority()[1]
                old_signature = old_signer.sign(
                    _ROTATION_ABORT_TOMBSTONE_OLD_DOMAIN + canonical_bytes(core),
                )
                new_signature = pending._new_signer.sign(
                    _ROTATION_ABORT_TOMBSTONE_NEW_DOMAIN + canonical_bytes(core),
                )
                if (
                    type(old_signature) is not bytes or len(old_signature) != 64
                    or type(new_signature) is not bytes or len(new_signature) != 64
                ):
                    raise RunnerStoreError("runner signer returned an invalid rotation signature")
                tombstone = {
                    **core, "old_signing_key_id": pending.old_identity.key_id,
                    "old_signature_b64": base64.b64encode(old_signature).decode("ascii"),
                    "new_signing_key_id": pending.new_identity.key_id,
                    "new_signature_b64": base64.b64encode(new_signature).decode("ascii"),
                }
                tombstones_fd = _open_child(runner_fd, _ACTIVATION_TOMBSTONES_DIRECTORY, create=True)
                assert tombstones_fd is not None
                try:
                    filename = self._rotation_abort_tombstone_filename(pending.pending["pairing_id"])
                    existing = _read_json(tombstones_fd, filename, None)
                    if existing is None:
                        _write_json(tombstones_fd, filename, tombstone)
                    elif existing != tombstone:
                        raise RunnerStoreError("runner rotation activation abort changed")
                finally:
                    os.close(tombstones_fd)
                receipt = self._rotation_abort_tombstone(
                    tombstone, old_identity=pending.old_identity, new_identity=pending.new_identity,
                    prepared_journal=verified,
                )
                runtime_state.abort_rotation(eligibility=pending._eligibility, abort_tombstone=receipt)
                os.unlink(_ROTATION_ACTIVATION_JOURNAL_FILENAME, dir_fd=runner_fd)
                os.fsync(runner_fd)

    def finish_rotation_activation(self, pending: PendingRotationActivation, runtime_state: object) -> RunnerIdentity:
        """Commit the accepted runtime rewrap, publish the new selector, then unlink the journal."""
        if not isinstance(pending, PendingRotationActivation) or pending._store_token is not self._rotation_token:
            raise RunnerStoreError("prepared runner rotation activation is required")
        old_identity, old_signer = self._require_runtime_authority()
        if _identity_record(old_identity, old_signer) != _identity_record(
            pending.old_identity, _IdentityPublicSigner(pending.old_identity),
        ):
            raise RunnerStoreError("runner rotation activation identity changed")
        from heel.runner.runtime import RunnerRuntimeState
        if not isinstance(runtime_state, RunnerRuntimeState):
            raise RunnerStoreError("runner runtime state is invalid")
        runtime_record = _identity_record(runtime_state.identity, runtime_state.signer)
        old_record = _identity_record(pending.old_identity, _IdentityPublicSigner(pending.old_identity))
        new_record = _identity_record(pending.new_identity, pending._new_signer)
        runtime_is_old = runtime_record == old_record
        runtime_is_new = runtime_record == new_record
        if runtime_is_old == runtime_is_new:
            raise RunnerStoreError("runner runtime rotation identity requires recovery")
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=True):
                journal = _read_json(runner_fd, _ROTATION_ACTIVATION_JOURNAL_FILENAME, None)
                accepted = self._accepted_rotation_journal(
                    journal, old_identity=pending.old_identity, new_identity=pending.new_identity,
                )
                existing = _read_json(runner_fd, _PAIRED_RUNNER_IDENTITY_FILENAME, None)
                if not isinstance(existing, Mapping):
                    raise RunnerStoreError("paired runner identity requires recovery")
                if existing.get("identity") == old_record:
                    existing = self._verify_paired_rotation_identity(
                        existing, identity=pending.old_identity, signer=old_signer,
                    )
                elif existing.get("identity") == new_record:
                    if runtime_is_old:
                        raise RunnerStoreError("paired runner identity requires recovery")
                    existing = self._verify_paired_rotation_identity(
                        existing, identity=pending.new_identity, signer=pending._new_signer,
                        required_signer_label=accepted.new_signer_label,
                    )
                else:
                    raise RunnerStoreError("paired runner identity requires recovery")
                cursor = runtime_state.finish_rotation(
                    accepted, new_identity=pending.new_identity, new_signer=pending._new_signer,
                    eligibility=pending._eligibility,
                )
                if (
                    cursor.next_nonce_b64 != accepted.activation_response["initial_claim_nonce"]
                    or cursor.next_sequence != accepted.activation_response["initial_claim_sequence"]
                    or cursor.generation != accepted.activation_response["initial_claim_generation"]
                ):
                    raise RunnerStoreError("runner rotation activation cursor changed")
                paired_core = {
                    "schema_version": _PAIRED_RUNNER_IDENTITY_SCHEMA,
                    "identity": _identity_record(pending.new_identity, pending._new_signer),
                    "pairing_protocol_version": 3, "control_protocol": "heel.runner-control.v2",
                    "pairing_id": existing["pairing_id"],
                    "pairing_exchange_digest": existing["pairing_exchange_digest"],
                    "activated_at_ms": existing["activated_at_ms"],
                    "activation_response_digest": existing["activation_response_digest"],
                    "signer_label": accepted.new_signer_label,
                }
                paired = self._pairing_signed_value(
                    paired_core, signer=pending._new_signer, domain=_PAIRED_RUNNER_IDENTITY_DOMAIN,
                    digest_field="record_digest",
                )
                if existing != paired:
                    _write_json(runner_fd, _PAIRED_RUNNER_IDENTITY_FILENAME, paired)
                os.unlink(_ROTATION_ACTIVATION_JOURNAL_FILENAME, dir_fd=runner_fd)
                os.fsync(runner_fd)
        self._runtime_authority = (pending.new_identity, pending._new_signer)
        return pending.new_identity

    def recover_rotation_activation(
        self, *, old_identity: RunnerIdentity, old_signer: SecureSigner, signer_provider: object,
        runtime_path: Path | str,
    ) -> PendingRotationActivation | RunnerIdentity | None:
        """Recover only an exact local rotation prefix before any control client exists.

        A prepared journal yields the already-signed request capability.  An accepted journal
        is completed entirely locally with a provider that may *only* load the named signer.
        """
        if not isinstance(old_identity, RunnerIdentity) or not isinstance(old_signer, SecureSigner):
            raise RunnerStoreError("runner rotation recovery identity is invalid")
        self._pin_runtime_authority(old_identity, old_signer)
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=False):
                journal = _read_json(runner_fd, _ROTATION_ACTIVATION_JOURNAL_FILENAME, None)
        if journal is None:
            return None
        if not isinstance(journal, Mapping):
            raise RunnerStoreError("invalid runner rotation activation journal")
        new_identity = self._rotation_identity_from_record(
            journal.get("new_identity"), pairing_phrase=old_identity.pairing_phrase,
        )
        if (
            new_identity.workspace_id != old_identity.workspace_id
            or new_identity.runner_id != old_identity.runner_id
            or new_identity.key_id == old_identity.key_id
        ):
            raise RunnerStoreError("invalid runner rotation activation journal")
        verified = self._verify_rotation_journal(
            journal, old_identity=old_identity, new_identity=new_identity,
        )
        load_existing = getattr(signer_provider, "load_existing", None)
        if not callable(load_existing):
            raise RunnerStoreError("runner rotation signer provider is invalid")
        try:
            new_signer = load_existing(verified["new_signer_label"])
        except Exception as exc:
            raise RunnerStoreError("runner rotation signing identity is unavailable") from exc
        if not isinstance(new_signer, SecureSigner):
            raise RunnerStoreError("runner rotation signing identity is unavailable")
        try:
            if _identity_record(new_identity, new_signer) != verified["new_identity"]:
                raise RunnerStoreError("runner rotation signing identity is unavailable")
        except (TypeError, ValueError):
            raise RunnerStoreError("runner rotation signing identity is unavailable") from None
        path = Path(runtime_path)
        try:
            runtime_status = os.lstat(path)
        except OSError as exc:
            raise RunnerStoreError("runner rotation runtime requires recovery") from exc
        if stat.S_ISLNK(runtime_status.st_mode) or not stat.S_ISREG(runtime_status.st_mode):
            raise RunnerStoreError("runner rotation runtime requires recovery")
        from heel.runner.runtime import (
            RotationEligibility, RotationEligibilityProbe, RunnerRuntimeConflict,
            RunnerRuntimeCorrupt, RunnerRuntimeState,
        )
        try:
            runtime = RunnerRuntimeState(path, old_identity, old_signer, _allow_rotation_recovery=True)
        except RunnerRuntimeCorrupt as old_error:
            if str(old_error) != "runtime state belongs to another runner identity":
                raise RunnerStoreError("runner rotation runtime requires recovery") from old_error
            try:
                runtime = RunnerRuntimeState(path, new_identity, new_signer, _allow_rotation_recovery=True)
            except RunnerRuntimeCorrupt as new_error:
                raise RunnerStoreError("runner rotation runtime requires recovery") from new_error
        probe = RotationEligibilityProbe(
            authority_epoch=verified["runtime_authority_epoch"],
            authority_identity_digest=verified["runtime_authority_identity_digest"],
            claim_state_digest=verified["runtime_claim_state_digest"],
        )
        tombstone_value: Mapping[str, object] | None = None
        tombstone: AcceptedRotationAbortTombstone | None = None
        if verified["state"] == "prepared":
            with self._open_runner(create=True) as runner_fd:
                assert runner_fd is not None
                with _flock(runner_fd, ".runner.lock", exclusive=False):
                    tombstones_fd = _open_child(runner_fd, _ACTIVATION_TOMBSTONES_DIRECTORY, create=False)
                    if tombstones_fd is not None:
                        try:
                            candidate = _read_json(
                                tombstones_fd,
                                self._rotation_abort_tombstone_filename(verified["pairing_id"]), None,
                            )
                        finally:
                            os.close(tombstones_fd)
                        if candidate is not None:
                            if not isinstance(candidate, Mapping):
                                raise RunnerStoreError("invalid runner rotation activation abort tombstone")
                            tombstone_value = dict(candidate)
                            tombstone = self._rotation_abort_tombstone(
                                tombstone_value, old_identity=old_identity, new_identity=new_identity,
                                prepared_journal=verified,
                            )
        runtime_is_old = runtime._same_identity(runtime.identity, old_identity)
        if tombstone is not None:
            if not runtime_is_old:
                raise RunnerStoreError("runner rotation activation requires recovery")
            eligibility = RotationEligibility(
                authority_epoch=probe.authority_epoch,
                authority_identity_digest=probe.authority_identity_digest,
                claim_state_digest=probe.claim_state_digest,
                runtime_rotation_intent_digest=verified["runtime_rotation_intent_digest"],
                prepared_journal_digest=verified["journal_digest"],
            )
            epoch, identity_digest, fence = runtime.rotation_fence_snapshot()
            if epoch != probe.authority_epoch or identity_digest != probe.authority_identity_digest:
                raise RunnerStoreError("runner rotation activation requires recovery")
            if fence == eligibility.runtime_rotation_intent_digest:
                runtime.abort_rotation(eligibility=eligibility, abort_tombstone=tombstone)
            elif fence is not None:
                raise RunnerStoreError("runner rotation activation requires recovery")
            # A NULL fence with this exact signed tombstone is the safe suffix after a
            # crash immediately after runtime abort and before unlinking the journal.
            with self._open_runner(create=True) as runner_fd:
                assert runner_fd is not None
                with _flock(runner_fd, ".runner.lock", exclusive=True):
                    if _read_json(runner_fd, _ROTATION_ACTIVATION_JOURNAL_FILENAME, None) != journal:
                        raise RunnerStoreError("runner rotation activation requires recovery")
                    tombstones_fd = _open_child(runner_fd, _ACTIVATION_TOMBSTONES_DIRECTORY, create=False)
                    if tombstones_fd is None:
                        raise RunnerStoreError("runner rotation activation requires recovery")
                    try:
                        current_tombstone = _read_json(
                            tombstones_fd,
                            self._rotation_abort_tombstone_filename(verified["pairing_id"]), None,
                        )
                    finally:
                        os.close(tombstones_fd)
                    if current_tombstone != tombstone_value:
                        raise RunnerStoreError("runner rotation activation requires recovery")
                    os.unlink(_ROTATION_ACTIVATION_JOURNAL_FILENAME, dir_fd=runner_fd)
                    os.fsync(runner_fd)
            return None
        if runtime_is_old:
            try:
                eligibility = runtime.assert_rotation_eligible(
                    old_identity=old_identity, probe=probe,
                    prepared_journal_digest=(
                        verified["journal_digest"] if verified["state"] == "prepared"
                        else verified["prepared_journal_digest"]
                    ),
                    runtime_rotation_intent_digest=verified["runtime_rotation_intent_digest"],
                    now_ms=verified["prepared_at_ms"],
                )
            except RunnerRuntimeConflict as exc:
                epoch, identity_digest, fence = runtime.rotation_fence_snapshot()
                if (
                    epoch == probe.authority_epoch and identity_digest == probe.authority_identity_digest
                    and fence is None and verified["state"] == "prepared"
                ):
                    with self._open_runner(create=True) as runner_fd:
                        assert runner_fd is not None
                        with _flock(runner_fd, ".runner.lock", exclusive=True):
                            if _read_json(runner_fd, _ROTATION_ACTIVATION_JOURNAL_FILENAME, None) == journal:
                                os.unlink(_ROTATION_ACTIVATION_JOURNAL_FILENAME, dir_fd=runner_fd)
                                os.fsync(runner_fd)
                    return None
                raise RunnerStoreError("runner rotation activation requires recovery") from exc
        else:
            eligibility = RotationEligibility(
                authority_epoch=probe.authority_epoch,
                authority_identity_digest=probe.authority_identity_digest,
                claim_state_digest=probe.claim_state_digest,
                runtime_rotation_intent_digest=verified["runtime_rotation_intent_digest"],
                prepared_journal_digest=(
                    verified["journal_digest"] if verified["state"] == "prepared"
                    else verified["prepared_journal_digest"]
                ),
            )
        pending = PendingRotationActivation(
            self._rotation_pending({
                "schema_version": "heel.runner-rotation-activation-challenge.v1",
                "pairing_id": verified["pairing_id"],
                "activation_challenge": verified["activation_challenge"],
            }),
            dict(verified["activation_request"]), old_identity, new_identity,
            verified["new_signer_label"], new_signer, self._rotation_token, eligibility,
        )
        if verified["state"] == "prepared":
            return pending
        accepted = self._accepted_rotation_journal(
            verified, old_identity=old_identity, new_identity=new_identity,
        )
        # Re-read the accepted object through the closed parser before mutating durable runtime
        # state, so a future change cannot accidentally let an unvalidated mapping through.
        if accepted.new_signer_label != pending.new_signer_label:
            raise RunnerStoreError("invalid runner rotation activation journal")
        return self.finish_rotation_activation(pending, runtime)

    @staticmethod
    def _signed_run_authority_value(
        core: Mapping[str, Any], *, signer: SecureSigner, record_digest: bool,
    ) -> dict[str, Any]:
        schema = core.get("schema_version") if isinstance(core, Mapping) else None
        if schema not in _RUN_AUTHORITY_DOMAINS:
            raise ValueError("invalid local run authority schema")
        unsigned = dict(core)
        if record_digest:
            unsigned["record_digest"] = canonical_digest(unsigned)
        signature = signer.sign(_RUN_AUTHORITY_DOMAINS[schema] + canonical_bytes(unsigned))
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise RunnerStoreError("runner signer returned an invalid local authority signature")
        return {
            **unsigned,
            "signing_key_id": signer.key_id,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }

    @staticmethod
    def _runtime_pruned_record(
        *, context: RunnerContext, identity: RunnerIdentity, signer: SecureSigner,
        run_id: str, grant: Mapping[str, Any], index: Mapping[str, Any],
        terminal: Mapping[str, Any], detached: Mapping[str, Any], runtime_state: object,
        pruned_at_ms: int,
    ) -> dict[str, Any]:
        run_hash = RunnerStore._run_hash(run_id)
        try:
            runtime_digest = _digest(
                getattr(runtime_state, "state_digest"), "runtime prune state digest",
            )
            retention = getattr(runtime_state, "retention_expires_at_ms")
            terminal_at = getattr(runtime_state, "terminal_at_ms")
        except (TypeError, ValueError, AttributeError) as exc:
            raise RunnerStoreError("local terminal prune authority is invalid") from exc
        if (
            type(retention) is not int or type(terminal_at) is not int
            or type(pruned_at_ms) is not int or not terminal_at <= retention <= pruned_at_ms
        ):
            raise RunnerStoreError("local terminal prune authority is invalid")
        core = {
            "schema_version": _RUN_RUNTIME_PRUNED_RECORD_SCHEMA,
            "namespace": context.namespace, "workspace_id": identity.workspace_id,
            "runner_id": identity.runner_id, "runner_key_id": identity.key_id,
            "run_id": run_id, "run_hash": run_hash,
            "grant_id": _id(grant["grant_id"], "local grant ID"),
            "grant_digest": _digest(grant["grant_digest"], "local grant digest"),
            "retention_expires_at_ms": retention,
            "prior_head_digest": _digest(index["head_digest"], "local authority head digest"),
            "terminal_record_digest": _digest(terminal["record_digest"], "local terminal record digest"),
            "terminal_projection_digest": _digest(
                terminal["terminal_projection_digest"], "local terminal projection digest",
            ),
            "terminal_at_ms": terminal_at,
            "detached_record_digest": _digest(detached["record_digest"], "local detached record digest"),
            "runtime_state_schema": "heel.runner-terminal-disclosure-state.v1",
            "runtime_prune_pending_state_digest": runtime_digest,
            "pruned_at_ms": pruned_at_ms,
        }
        digest = hashlib.sha256(_RUN_RUNTIME_PRUNED_RECORD_DOMAIN + canonical_bytes(core)).hexdigest()
        unsigned = {**core, "record_digest": digest}
        signature = signer.sign(_RUN_RUNTIME_PRUNED_RECORD_DOMAIN + canonical_bytes(unsigned))
        if type(signature) is not bytes or len(signature) != 64:
            raise RunnerStoreError("runner signer returned an invalid local authority signature")
        return {
            **unsigned, "signing_key_id": signer.key_id,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }

    @staticmethod
    def _verify_runtime_pruned_record(value: object, *, identity: RunnerIdentity) -> dict[str, Any]:
        fields = {
            "schema_version", "namespace", "workspace_id", "runner_id", "runner_key_id",
            "run_id", "run_hash", "grant_id", "grant_digest", "retention_expires_at_ms",
            "prior_head_digest", "terminal_record_digest", "terminal_projection_digest",
            "terminal_at_ms", "detached_record_digest", "runtime_state_schema",
            "runtime_prune_pending_state_digest", "pruned_at_ms", "record_digest",
            "signing_key_id", "signature_b64",
        }
        if not isinstance(value, Mapping) or set(value) != fields or (
            value.get("schema_version") != _RUN_RUNTIME_PRUNED_RECORD_SCHEMA
            or value.get("workspace_id") != identity.workspace_id
            or value.get("runner_id") != identity.runner_id
            or value.get("runner_key_id") != identity.key_id
            or value.get("signing_key_id") != identity.key_id
            or value.get("runtime_state_schema") != "heel.runner-terminal-disclosure-state.v1"
        ):
            raise RunnerStoreError("invalid local runtime prune receipt")
        try:
            run_id = _id(value["run_id"], "run ID")
            if RunnerStore._run_hash(run_id) != value["run_hash"]:
                raise ValueError
            for field in (
                "run_hash", "grant_digest", "prior_head_digest", "terminal_record_digest",
                "terminal_projection_digest", "detached_record_digest", "runtime_prune_pending_state_digest",
                "record_digest",
            ):
                _digest(value[field], "local runtime prune digest")
            if (
                type(value["retention_expires_at_ms"]) is not int
                or type(value["terminal_at_ms"]) is not int
                or type(value["pruned_at_ms"]) is not int
                or not value["terminal_at_ms"] <= value["retention_expires_at_ms"] <= value["pruned_at_ms"]
            ):
                raise ValueError
            core = {key: value[key] for key in fields - {"record_digest", "signing_key_id", "signature_b64"}}
            if value["record_digest"] != hashlib.sha256(
                _RUN_RUNTIME_PRUNED_RECORD_DOMAIN + canonical_bytes(core)
            ).hexdigest():
                raise ValueError
            unsigned = {**core, "record_digest": value["record_digest"]}
            verify_envelope(
                {identity.key_id: load_public_key_base64(identity.public_key_b64)},
                {"signing_key_id": value["signing_key_id"], "signature_b64": value["signature_b64"]},
                _RUN_RUNTIME_PRUNED_RECORD_DOMAIN + canonical_bytes(unsigned),
            )
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid local runtime prune receipt") from None
        return dict(value)

    @staticmethod
    def _verify_signed_run_authority_value(
        value: object, *, identity: RunnerIdentity, schema: str, record_digest: bool,
        max_bytes: int,
    ) -> dict[str, Any]:
        if schema not in _RUN_AUTHORITY_DOMAINS or not isinstance(value, Mapping):
            raise RunnerStoreError("invalid local run authority record")
        fields = set(value)
        required = {"schema_version", "signing_key_id", "signature_b64"}
        if record_digest:
            required.add("record_digest")
        if not required <= fields or value.get("schema_version") != schema:
            raise RunnerStoreError("invalid local run authority record")
        record_fields = {
            _RUN_RESERVATION_RECORD_SCHEMA: {
                "schema_version", "namespace", "workspace_id", "runner_id", "runner_key_id",
                "run_hash", "grant_id", "grant_digest", "initial_state_digest",
                "retention_expires_at_ms", "created_at_ms", "prior_head_digest", "record_digest",
                "signing_key_id", "signature_b64",
            },
            _RUN_TERMINAL_RECORD_SCHEMA: {
                "schema_version", "namespace", "workspace_id", "runner_id", "runner_key_id",
                "run_hash", "grant_id", "grant_digest", "reservation_record_digest",
                "terminal_state_digest", "terminal_projection_digest", "retention_expires_at_ms",
                "terminal_at_ms", "prior_head_digest", "record_digest", "signing_key_id", "signature_b64",
            },
            _RUN_TERMINAL_DETACHED_RECORD_SCHEMA: {
                "schema_version", "namespace", "workspace_id", "runner_id", "runner_key_id",
                "run_hash", "grant_id", "grant_digest", "terminal_record_digest",
                "terminal_projection_digest", "terminal_at_ms", "retention_expires_at_ms",
                "runtime_state_schema", "runtime_state", "runtime_state_digest", "detached_at_ms",
                "prior_head_digest", "record_digest", "signing_key_id", "signature_b64",
            },
            _RUN_PRUNED_RECORD_SCHEMA: {
                "schema_version", "namespace", "workspace_id", "runner_id", "runner_key_id",
                "run_hash", "grant_id", "grant_digest", "terminal_record_digest",
                "terminal_projection_digest", "retention_expires_at_ms", "terminal_at_ms", "pruned_at_ms",
                "prior_head_digest", "record_digest", "signing_key_id", "signature_b64",
            },
        }.get(schema)
        if record_fields is not None and fields != record_fields:
            raise RunnerStoreError("invalid local run authority record")
        try:
            unsigned = {
                key: value[key] for key in fields - {"signing_key_id", "signature_b64"}
            }
            if record_digest:
                digest = _digest(unsigned.pop("record_digest"), "local run authority digest")
                if digest != canonical_digest(unsigned):
                    raise ValueError
                unsigned["record_digest"] = digest
            payload = canonical_bytes(unsigned)
            if len(payload) > max_bytes:
                raise ValueError
            signature_b64 = value["signature_b64"]
            if type(signature_b64) is not str or base64.b64encode(
                base64.b64decode(signature_b64, validate=True)
            ).decode("ascii") != signature_b64:
                raise ValueError
            verify_envelope(
                {identity.key_id: load_public_key_base64(identity.public_key_b64)},
                {"signing_key_id": value["signing_key_id"], "signature_b64": signature_b64},
                _RUN_AUTHORITY_DOMAINS[schema] + payload,
            )
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid local run authority record") from None
        return dict(value)

    def _zero_run_authority_index(
        self, *, context: RunnerContext, identity: RunnerIdentity, signer: SecureSigner,
    ) -> dict[str, Any]:
        return self._signed_run_authority_value({
            "schema_version": _RUN_AUTHORITY_INDEX_SCHEMA,
            "namespace": context.namespace,
            "workspace_id": context.workspace_id,
            "runner_id": identity.runner_id,
            "runner_key_id": identity.key_id,
            "generation": 0,
            "nonterminal_count": 0,
            "nonterminal_runs": [],
            "terminal_queue": [],
            "head_digest": _RUN_AUTHORITY_ZERO_HEAD,
        }, signer=signer, record_digest=False)

    def _initialize_run_authority_index_locked(
        self, context_fd: int, *, context: RunnerContext, identity: RunnerIdentity,
        signer: SecureSigner, initial_bind: bool,
    ) -> None:
        runs_fd = _open_child(context_fd, "runs", create=True)
        assert runs_fd is not None
        try:
            _secure_directory(runs_fd, "Heel runner runs directory")
            zero = self._zero_run_authority_index(
                context=context, identity=identity, signer=signer,
            )
            existing = _read_json(runs_fd, _RUN_AUTHORITY_INDEX_FILENAME, None)
            if existing is None:
                if not initial_bind:
                    raise RunnerStoreError("local run authority index requires explicit upgrade")
                with os.scandir(runs_fd) as entries:
                    if any(entry.name != _RUN_AUTHORITY_INDEX_FILENAME for entry in entries):
                        raise RunnerStoreError("local run authority index requires explicit upgrade")
                _create_json(runs_fd, _RUN_AUTHORITY_INDEX_FILENAME, zero)
            else:
                checked = self._verify_signed_run_authority_value(
                    existing, identity=identity, schema=_RUN_AUTHORITY_INDEX_SCHEMA,
                    record_digest=False, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                )
                if (
                    set(checked) != set(zero)
                    or any(checked[field] != zero[field] for field in (
                        "schema_version", "namespace", "workspace_id", "runner_id", "runner_key_id",
                    ))
                    or type(checked["generation"]) is not int or checked["generation"] < 0
                    or type(checked["nonterminal_count"]) is not int
                    or not 0 <= checked["nonterminal_count"] <= _RUN_AUTHORITY_MAX_NONTERMINAL
                    or checked["nonterminal_runs"] != []
                    or not isinstance(checked["terminal_queue"], list)
                    or len(checked["terminal_queue"]) > _RUN_AUTHORITY_MAX_TRACKED
                    or _DIGEST.fullmatch(checked["head_digest"]) is None
                ):
                    raise RunnerStoreError("local run authority index differs from bound context")
            os.fsync(runs_fd)
        finally:
            os.close(runs_fd)

    @staticmethod
    def _run_authority_index_digest(index: Mapping[str, Any]) -> str:
        return canonical_digest(dict(index))

    def _validate_run_authority_index_value(
        self, value: object, *, identity: RunnerIdentity,
    ) -> dict[str, Any]:
        checked = self._verify_signed_run_authority_value(
            value, identity=identity, schema=_RUN_AUTHORITY_INDEX_SCHEMA,
            record_digest=False, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
        )
        if (
            set(checked) != {
                "schema_version", "namespace", "workspace_id", "runner_id", "runner_key_id",
                "generation", "nonterminal_count", "nonterminal_runs", "terminal_queue", "head_digest", "signing_key_id", "signature_b64",
            }
            or checked["namespace"] != self.namespace
            or checked["workspace_id"] != identity.workspace_id
            or checked["runner_id"] != identity.runner_id
            or checked["runner_key_id"] != identity.key_id
            or type(checked["generation"]) is not int or checked["generation"] < 0
            or type(checked["nonterminal_count"]) is not int
            or not 0 <= checked["nonterminal_count"] <= _RUN_AUTHORITY_MAX_NONTERMINAL
            or not isinstance(checked["nonterminal_runs"], list)
            or len(checked["nonterminal_runs"]) != checked["nonterminal_count"]
            or len(checked["nonterminal_runs"]) > _RUN_AUTHORITY_MAX_TRACKED
            or not isinstance(checked["terminal_queue"], list)
            or len(checked["terminal_queue"]) > _RUN_AUTHORITY_MAX_TRACKED
            or _DIGEST.fullmatch(checked["head_digest"]) is None
        ):
            raise RunnerStoreError("local run authority index is invalid")
        previous_run: str | None = None
        nonterminal_hashes: set[str] = set()
        for item in checked["nonterminal_runs"]:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"run_hash", "reservation_record_digest"}
                or _RUN_FILENAME.fullmatch(item["run_hash"]) is None
                or _DIGEST.fullmatch(item["reservation_record_digest"]) is None
                or item["run_hash"] in nonterminal_hashes
                or (previous_run is not None and item["run_hash"] <= previous_run)
            ):
                raise RunnerStoreError("local run authority index is invalid")
            nonterminal_hashes.add(item["run_hash"])
            previous_run = item["run_hash"]
        previous: tuple[int, str] | None = None
        seen_hashes: set[str] = set()
        for item in checked["terminal_queue"]:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"retention_expires_at_ms", "run_hash", "terminal_record_digest"}
                or type(item["retention_expires_at_ms"]) is not int
                or item["retention_expires_at_ms"] < 0
                or _RUN_FILENAME.fullmatch(item["run_hash"]) is None
                or _DIGEST.fullmatch(item["terminal_record_digest"]) is None
                or item["run_hash"] in seen_hashes
                or item["run_hash"] in nonterminal_hashes
                or (previous is not None and (item["retention_expires_at_ms"], item["run_hash"]) <= previous)
            ):
                raise RunnerStoreError("local run authority index is invalid")
            seen_hashes.add(item["run_hash"])
            previous = (item["retention_expires_at_ms"], item["run_hash"])
        return checked

    def _run_authority_index_locked(
        self, runs_fd: int, *, identity: RunnerIdentity,
    ) -> dict[str, Any]:
        value = _read_json(runs_fd, _RUN_AUTHORITY_INDEX_FILENAME, None)
        if value is None:
            raise RunnerStoreError("local run authority index is unavailable")
        return self._validate_run_authority_index_value(value, identity=identity)

    def _next_run_authority_index(
        self, index: Mapping[str, Any], *, signer: SecureSigner, delta: int, head_digest: str,
        nonterminal_runs: list[dict[str, Any]] | None = None,
        terminal_queue: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        next_count = index["nonterminal_count"] + delta
        nonterminal = list(index["nonterminal_runs"] if nonterminal_runs is None else nonterminal_runs)
        queue = list(index["terminal_queue"] if terminal_queue is None else terminal_queue)
        if (
            next_count != len(nonterminal) or not 0 <= next_count <= _RUN_AUTHORITY_MAX_NONTERMINAL
            or len(queue) > _RUN_AUTHORITY_MAX_TRACKED
        ):
            raise RunnerStoreError("local run authority capacity is exhausted")
        return self._signed_run_authority_value({
            "schema_version": _RUN_AUTHORITY_INDEX_SCHEMA,
            "namespace": index["namespace"], "workspace_id": index["workspace_id"],
            "runner_id": index["runner_id"], "runner_key_id": index["runner_key_id"],
            "generation": index["generation"] + 1, "nonterminal_count": next_count,
            "nonterminal_runs": nonterminal,
            "terminal_queue": queue,
            "head_digest": _digest(head_digest, "local run authority head"),
        }, signer=signer, record_digest=False)

    @staticmethod
    def _run_authority_record_filename(kind: str, run_hash: str) -> str:
        if _RUN_FILENAME.fullmatch(run_hash) is None:
            raise RunnerStoreError("invalid local run authority hash")
        prefix = {
            "reserve": "reservation-", "terminal": "terminal-", "detach_terminal": "detached-",
            "prune": "pruned-",
        }.get(kind)
        if prefix is None:
            raise RunnerStoreError("invalid local run authority operation")
        return f"{prefix}{run_hash}.json"

    def _run_authority_record(
        self, *, operation: str, context: RunnerContext, identity: RunnerIdentity,
        signer: SecureSigner, run_hash: str, grant: Mapping[str, Any], state: Mapping[str, Any],
        index: Mapping[str, Any], terminal: Mapping[str, Any] | None = None,
        pruned_at_ms: int | None = None, detached_at_ms: int | None = None,
    ) -> dict[str, Any]:
        header = {
            "namespace": context.namespace, "workspace_id": context.workspace_id,
            "runner_id": identity.runner_id, "runner_key_id": identity.key_id,
            "run_hash": run_hash, "grant_id": grant["grant_id"], "grant_digest": grant["grant_digest"],
            "retention_expires_at_ms": state["retention_expires_at_ms"],
            "prior_head_digest": index["head_digest"],
        }
        if operation == "reserve":
            core = {
                "schema_version": _RUN_RESERVATION_RECORD_SCHEMA, **header,
                "initial_state_digest": canonical_digest(dict(state)),
                "created_at_ms": grant["issued_at_ms"],
            }
        elif operation == "terminal":
            if terminal is None:
                raise RunnerStoreError("local terminal authority requires final projections")
            core = {
                "schema_version": _RUN_TERMINAL_RECORD_SCHEMA, **header,
                "reservation_record_digest": _digest(
                    terminal["reservation_record_digest"], "local reservation record digest",
                ),
                "terminal_state_digest": canonical_digest(dict(state)),
                "terminal_projection_digest": _digest(
                    terminal["terminal_projection_digest"], "local terminal projection digest",
                ),
                "terminal_at_ms": state["updated_at_ms"],
            }
        elif operation == "detach_terminal":
            if terminal is None or detached_at_ms is None:
                raise RunnerStoreError("local terminal detach requires terminal authority")
            terminal_at_ms = terminal.get("terminal_at_ms")
            runtime_state_digest = terminal.get("runtime_state_digest")
            if (
                type(terminal_at_ms) is not int or terminal_at_ms < 0
                or type(detached_at_ms) is not int or detached_at_ms < terminal_at_ms
                or not isinstance(runtime_state_digest, str)
            ):
                raise RunnerStoreError("local terminal detach requires terminal authority")
            core = {
                "schema_version": _RUN_TERMINAL_DETACHED_RECORD_SCHEMA, **header,
                "terminal_record_digest": _digest(
                    terminal["terminal_record_digest"], "local terminal record digest",
                ),
                "terminal_projection_digest": _digest(
                    terminal["terminal_projection_digest"], "local terminal projection digest",
                ),
                "terminal_at_ms": terminal_at_ms,
                "runtime_state_schema": "heel.runner-terminal-disclosure-state.v1",
                "runtime_state": "local_terminal",
                "runtime_state_digest": _digest(
                    runtime_state_digest, "local terminal runtime state digest",
                ),
                "detached_at_ms": detached_at_ms,
            }
        elif operation == "prune":
            if terminal is None or pruned_at_ms is None:
                raise RunnerStoreError("local prune authority requires terminal record")
            core = {
                "schema_version": _RUN_PRUNED_RECORD_SCHEMA, **header,
                "terminal_record_digest": _digest(
                    terminal["terminal_record_digest"], "local terminal record digest",
                ),
                "terminal_projection_digest": _digest(
                    terminal["terminal_projection_digest"], "local terminal projection digest",
                ),
                "terminal_at_ms": terminal["terminal_at_ms"], "pruned_at_ms": pruned_at_ms,
            }
        else:
            raise RunnerStoreError("invalid local run authority operation")
        return self._signed_run_authority_value(core, signer=signer, record_digest=True)

    def _run_authority_journal(
        self, *, context: RunnerContext, identity: RunnerIdentity, signer: SecureSigner,
        operation: str, run_hash: str, index: Mapping[str, Any], next_index: Mapping[str, Any],
        record: Mapping[str, Any], recovery: Mapping[str, Any], created_at_ms: int,
    ) -> dict[str, Any]:
        if operation not in {"reserve", "terminal", "detach_terminal", "prune"}:
            raise RunnerStoreError("invalid local run authority operation")
        core = {
            "schema_version": _RUN_AUTHORITY_MUTATION_SCHEMA, "namespace": context.namespace,
            "workspace_id": context.workspace_id, "runner_id": identity.runner_id,
            "runner_key_id": identity.key_id, "operation": operation, "run_hash": run_hash,
            "old_index_digest": self._run_authority_index_digest(index),
            "next_index": dict(next_index), "record": dict(record), "recovery": dict(recovery),
            "created_at_ms": created_at_ms,
        }
        value = self._signed_run_authority_value(core, signer=signer, record_digest=False)
        if len(canonical_bytes(value)) > _RUN_AUTHORITY_MAX_JOURNAL_BYTES:
            raise RunnerStoreError("local run authority journal exceeds size limit")
        return value

    def _validate_run_authority_journal(
        self, value: object, *, identity: RunnerIdentity,
    ) -> dict[str, Any]:
        checked = self._verify_signed_run_authority_value(
            value, identity=identity, schema=_RUN_AUTHORITY_MUTATION_SCHEMA,
            record_digest=False, max_bytes=_RUN_AUTHORITY_MAX_JOURNAL_BYTES,
        )
        fields = {
            "schema_version", "namespace", "workspace_id", "runner_id", "runner_key_id", "operation",
            "run_hash", "old_index_digest", "next_index", "record", "recovery", "created_at_ms",
            "signing_key_id", "signature_b64",
        }
        if (
            set(checked) != fields or checked["namespace"] != self.namespace
            or checked["workspace_id"] != identity.workspace_id or checked["runner_id"] != identity.runner_id
            or checked["runner_key_id"] != identity.key_id or checked["operation"] not in {"reserve", "terminal", "detach_terminal", "prune"}
            or _RUN_FILENAME.fullmatch(checked["run_hash"]) is None
            or _DIGEST.fullmatch(checked["old_index_digest"]) is None
            or type(checked["created_at_ms"]) is not int or checked["created_at_ms"] < 0
            or not isinstance(checked["next_index"], Mapping) or not isinstance(checked["record"], Mapping)
            or not isinstance(checked["recovery"], Mapping)
        ):
            raise RunnerStoreError("local run authority journal is invalid")
        return checked

    @staticmethod
    def _ensure_json_exact(directory_fd: int, filename: str, value: Mapping[str, Any]) -> None:
        existing = _read_json(directory_fd, filename, None)
        if existing is None:
            _create_json(directory_fd, filename, dict(value))
        elif existing != dict(value):
            raise RunnerStoreError("local run authority record collision")

    def _complete_run_authority_journal_locked(
        self, context_fd: int, runs_fd: int, *, identity: RunnerIdentity,
        runtime: object | None = None,
    ) -> bool:
        """Roll one signed run-authority mutation forward; never scan or roll back."""
        journal_value = _read_json(runs_fd, _RUN_AUTHORITY_JOURNAL_FILENAME, None)
        if journal_value is None:
            return False
        journal = self._validate_run_authority_journal(journal_value, identity=identity)
        current = self._run_authority_index_locked(runs_fd, identity=identity)
        next_index = self._validate_run_authority_index_value(
            journal["next_index"], identity=identity,
        )
        if self._run_authority_index_digest(current) not in {
            journal["old_index_digest"], self._run_authority_index_digest(next_index),
        }:
            raise RunnerStoreError("local run authority journal index changed")
        operation = journal["operation"]
        run_hash = journal["run_hash"]
        record_schema = {
            "reserve": _RUN_RESERVATION_RECORD_SCHEMA,
            "terminal": _RUN_TERMINAL_RECORD_SCHEMA,
            "detach_terminal": _RUN_TERMINAL_DETACHED_RECORD_SCHEMA,
            "prune": _RUN_PRUNED_RECORD_SCHEMA,
        }[operation]
        if operation == "prune" and journal["record"].get("schema_version") == _RUN_RUNTIME_PRUNED_RECORD_SCHEMA:
            record = self._verify_runtime_pruned_record(journal["record"], identity=identity)
        else:
            record = self._verify_signed_run_authority_value(
                journal["record"], identity=identity, schema=record_schema,
                record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
            )
        if record.get("run_hash") != run_hash:
            raise RunnerStoreError("local run authority journal record changed")
        next_nonterminal = next(
            (item for item in next_index["nonterminal_runs"] if item["run_hash"] == run_hash),
            None,
        )
        next_terminal = next(
            (item for item in next_index["terminal_queue"] if item["run_hash"] == run_hash),
            None,
        )
        if operation == "reserve":
            if (
                next_nonterminal is None
                or next_nonterminal["reservation_record_digest"] != record["record_digest"]
                or next_terminal is not None
            ):
                raise RunnerStoreError("local run authority journal index changed")
        elif operation == "terminal":
            if (
                next_nonterminal is not None
                or next_terminal is None
                or next_terminal["terminal_record_digest"] != record["record_digest"]
            ):
                raise RunnerStoreError("local run authority journal index changed")
        elif operation == "detach_terminal":
            if next_nonterminal is not None or next_terminal is not None:
                raise RunnerStoreError("local run authority journal index changed")
            if self._run_authority_index_digest(current) == journal["old_index_digest"]:
                matches = [
                    item for item in current["terminal_queue"]
                    if item["run_hash"] == run_hash
                ]
                if (
                    len(matches) != 1
                    or matches[0]["terminal_record_digest"] != record.get("terminal_record_digest")
                    or matches[0]["retention_expires_at_ms"] != record.get("retention_expires_at_ms")
                ):
                    raise RunnerStoreError("local run authority journal index changed")
            elif any(item["run_hash"] == run_hash for item in current["terminal_queue"]):
                raise RunnerStoreError("local run authority journal index changed")
        elif next_nonterminal is not None or next_terminal is not None:
            raise RunnerStoreError("local run authority journal index changed")
        recovery = journal["recovery"]
        if operation == "reserve":
            try:
                grant = validate_execution_grant(recovery["grant"])
            except (KeyError, TypeError, ValueError):
                raise RunnerStoreError("local run authority reservation recovery is invalid") from None
            state = recovery.get("initial_state")
            if (
                not isinstance(state, Mapping) or grant["run_id"] != state.get("run_id")
                or record.get("grant_id") != grant["grant_id"]
                or record.get("grant_digest") != grant["grant_digest"]
                or record.get("initial_state_digest") != canonical_digest(dict(state))
            ):
                raise RunnerStoreError("local run authority reservation recovery is invalid")
            self._ensure_json_exact(runs_fd, f"grant-{grant['grant_digest']}.json", {
                "schema_version": _RESERVATION_SCHEMA, "grant": grant, "initial_state": dict(state),
            })
            run_fd = _open_child(runs_fd, run_hash, create=True)
            assert run_fd is not None
            try:
                _secure_directory(run_fd, "Heel local run directory")
                self._ensure_json_exact(run_fd, "grant.json", grant)
                self._ensure_json_exact(run_fd, "state.json", dict(state))
            finally:
                os.close(run_fd)
            self._ensure_json_exact(
                runs_fd, self._run_authority_record_filename("reserve", run_hash), record,
            )
        elif operation == "terminal":
            state = recovery.get("terminal_state")
            if not isinstance(state, Mapping) or state.get("state") != "terminal":
                raise RunnerStoreError("local run authority terminal recovery is invalid")
            run_fd = _open_child(runs_fd, run_hash, create=False)
            if run_fd is None:
                raise RunnerStoreError("local run authority terminal recovery is invalid")
            try:
                _secure_directory(run_fd, "Heel local run directory")
                stored_state = _read_json(run_fd, "state.json", None)
                if stored_state is None or stored_state != dict(state):
                    _write_json(run_fd, "state.json", dict(state))
            finally:
                os.close(run_fd)
            self._ensure_json_exact(
                runs_fd, self._run_authority_record_filename("terminal", run_hash), record,
            )
        elif operation == "detach_terminal":
            if runtime is None:
                raise RunnerStoreError("local terminal detach recovery is required")
            expected_recovery = {
                "runtime_state_schema", "runtime_state", "runtime_state_digest",
                "terminal_record_digest", "retention_expires_at_ms",
            }
            if (
                set(recovery) != expected_recovery
                or recovery["runtime_state_schema"] != "heel.runner-terminal-disclosure-state.v1"
                or recovery["runtime_state"] != "local_terminal"
                or recovery["runtime_state_digest"] != record.get("runtime_state_digest")
                or recovery["terminal_record_digest"] != record.get("terminal_record_digest")
                or recovery["retention_expires_at_ms"] != record.get("retention_expires_at_ms")
                or recovery["runtime_state_digest"] is None
            ):
                raise RunnerStoreError("local terminal detach recovery is invalid")
            _identity, _signer = self._require_runtime_authority()
            if not self._runtime_matches_identity(runtime, identity=_identity, signer=_signer):
                raise RunnerStoreError("local terminal detach recovery is required")
            try:
                state = runtime.load_terminal_state(
                    self._run_id_from_hash_locked(runs_fd, run_hash),
                )
            except (AttributeError, TypeError, ValueError) as exc:
                raise RunnerStoreError("local terminal detach recovery is required") from exc
            if (
                state is None
                or state.run_hash != run_hash
                or state.terminal_record_digest != record.get("terminal_record_digest")
                or state.retention_expires_at_ms != record.get("retention_expires_at_ms")
                or state.terminal_projection_digest != record.get("terminal_projection_digest")
                or not (
                    state.state == "local_terminal"
                    and state.state_digest == record.get("runtime_state_digest")
                    or state.state == "available"
                    and state.prior_state_digest == record.get("runtime_state_digest")
                    and state.revision == 2
                )
            ):
                raise RunnerStoreError("local terminal detach recovery is invalid")
            self._ensure_json_exact(
                runs_fd, self._run_authority_record_filename("detach_terminal", run_hash), record,
            )
        else:
            legacy_recovery = {"retention_expires_at_ms"}
            runtime_recovery = {
                "retention_expires_at_ms", "runtime_prune_pending_state_digest",
                "detached_record_digest",
            }
            if set(recovery) == legacy_recovery:
                if recovery["retention_expires_at_ms"] != record.get("retention_expires_at_ms"):
                    raise RunnerStoreError("local run authority prune recovery is invalid")
            elif set(recovery) == runtime_recovery:
                if runtime is None:
                    raise RunnerStoreError("local terminal prune recovery is required")
                _identity, _signer = self._require_runtime_authority()
                if not self._runtime_matches_identity(runtime, identity=_identity, signer=_signer):
                    raise RunnerStoreError("local terminal prune recovery is required")
                try:
                    run_id = self._run_id_from_hash_locked(runs_fd, run_hash)
                    state = runtime.load_terminal_state(run_id)
                except (AttributeError, TypeError, ValueError) as exc:
                    raise RunnerStoreError("local terminal prune recovery is required") from exc
                detached_value = _read_json(
                    runs_fd, self._run_authority_record_filename("detach_terminal", run_hash), None,
                )
                if detached_value is None:
                    raise RunnerStoreError("local terminal prune recovery is invalid")
                detached = self._verify_signed_run_authority_value(
                    detached_value, identity=identity,
                    schema=_RUN_TERMINAL_DETACHED_RECORD_SCHEMA,
                    record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                )
                if (
                    state is None or state.state != "prune_pending"
                    or state.state_digest != recovery["runtime_prune_pending_state_digest"]
                    or state.retention_expires_at_ms != record.get("retention_expires_at_ms")
                    or detached["record_digest"] != recovery["detached_record_digest"]
                    or detached["terminal_record_digest"] != record.get("terminal_record_digest")
                ):
                    raise RunnerStoreError("local terminal prune recovery is invalid")
                if record.get("schema_version") == _RUN_RUNTIME_PRUNED_RECORD_SCHEMA and (
                    record.get("runtime_prune_pending_state_digest") != state.state_digest
                    or record.get("detached_record_digest") != detached["record_digest"]
                    or record.get("run_id") != run_id
                    or record.get("pruned_at_ms") != journal["created_at_ms"]
                ):
                    raise RunnerStoreError("local terminal prune recovery is invalid")
            else:
                raise RunnerStoreError("local run authority prune recovery is invalid")
            self._ensure_json_exact(
                runs_fd, self._run_authority_record_filename("prune", run_hash), record,
            )
            run_fd = _open_child(runs_fd, run_hash, create=False)
            if run_fd is not None:
                try:
                    _secure_directory(run_fd, "Heel retained local run directory")
                    self._delete_directory_contents(run_fd)
                finally:
                    os.close(run_fd)
                os.rmdir(run_hash, dir_fd=runs_fd)
        if self._run_authority_index_digest(current) == journal["old_index_digest"]:
            _write_json(runs_fd, _RUN_AUTHORITY_INDEX_FILENAME, next_index)
        os.unlink(_RUN_AUTHORITY_JOURNAL_FILENAME, dir_fd=runs_fd)
        os.fsync(runs_fd)
        return True

    @staticmethod
    def _runtime_matches_identity(
        runtime: object, *, identity: RunnerIdentity, signer: SecureSigner,
    ) -> bool:
        try:
            return _identity_record(
                getattr(runtime, "identity"), getattr(runtime, "signer"),
            ) == _identity_record(identity, signer)
        except (AttributeError, TypeError, ValueError):
            return False

    @staticmethod
    def _run_id_from_hash_locked(runs_fd: int, run_hash: str) -> str:
        """Resolve one indexed run hash through its retained, signed grant only."""
        run_fd = _open_child(runs_fd, run_hash, create=False)
        if run_fd is None:
            raise RunnerStoreError("local terminal authority run is unavailable")
        try:
            _secure_directory(run_fd, "Heel retained local run directory")
            try:
                grant = validate_execution_grant(_read_json(run_fd, "grant.json", None))
            except (TypeError, ValueError):
                raise RunnerStoreError("invalid stored execution grant") from None
            if RunnerStore._run_hash(grant["run_id"]) != run_hash:
                raise RunnerStoreError("local terminal authority run is unavailable")
            return grant["run_id"]
        finally:
            os.close(run_fd)

    @property
    def namespace(self) -> str:
        if self._namespace is None:
            raise RunnerStoreError("runner has no bound context")
        return self._namespace

    @property
    def is_context_bound(self) -> bool:
        """Whether a local context namespace was selected without opening it."""
        return self._namespace is not None

    def _open_root(self, *, create: bool) -> int | None:
        current = os.open(self.root.anchor, _DIRECTORY_FLAGS)
        try:
            for part in self.root.parts[1:]:
                child = _open_child(current, part, create=create)
                if child is None:
                    os.close(current)
                    return None
                os.close(current)
                current = child
            _secure_directory(current, "Heel home")
            return current
        except BaseException:
            try:
                os.close(current)
            except OSError:
                pass
            raise

    @contextmanager
    def _open_runner(self, *, create: bool) -> Iterator[int | None]:
        root_fd = self._open_root(create=create)
        if root_fd is None:
            yield None
            return
        runner_fd = -1
        try:
            opened = _open_child(root_fd, "runner", create=create)
            if opened is None:
                yield None
                return
            runner_fd = opened
            _secure_directory(runner_fd, "Heel runner directory")
            yield runner_fd
        finally:
            if runner_fd >= 0:
                os.close(runner_fd)
            os.close(root_fd)

    @contextmanager
    def _open_context(self, *, create: bool) -> Iterator[int]:
        namespace = self.namespace
        with self._open_runner(create=create) as runner_fd:
            if runner_fd is None:
                raise RunnerStoreError("runner context is unavailable")
            contexts_fd = _open_child(runner_fd, "contexts", create=create)
            if contexts_fd is None:
                raise RunnerStoreError("runner context is unavailable")
            context_fd = -1
            try:
                _secure_directory(contexts_fd, "Heel runner contexts directory")
                opened = _open_child(contexts_fd, namespace, create=create)
                if opened is None:
                    raise RunnerStoreError("runner context is unavailable")
                context_fd = opened
                _secure_directory(context_fd, "Heel runner context directory")
                yield context_fd
            finally:
                if context_fd >= 0:
                    os.close(context_fd)
                os.close(contexts_fd)

    @contextmanager
    def _transaction(
        self, *, exclusive: bool, allow_rollover_journal: bool = False,
        allow_cloud_install_journal: bool = False,
    ) -> Iterator[int]:
        with self._open_context(create=False) as context_fd:
            with _flock(context_fd, ".metadata.lock", exclusive=exclusive):
                if (
                    not allow_rollover_journal
                    and _read_json(context_fd, "context-rollover.json", None) is not None
                ):
                    raise RunnerStoreError("cloud context rollover requires recovery")
                self._binding_locked(context_fd, validate_cloud=not allow_cloud_install_journal)
                yield context_fd

    def _select_active_if_present(self) -> None:
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=False):
                active = _read_json(runner_fd, "active-context.json", None)
        if active is None:
            if self._unselected_cloud_context_exists():
                raise RunnerStoreError("cloud context authority is incomplete")
            return
        if not isinstance(active, Mapping):
            raise RunnerStoreError("invalid active runner context")
        if active.get("schema_version") == "heel.active-runner-context.v1":
            if set(active) != {"schema_version", "namespace"}:
                raise RunnerStoreError("invalid active runner context")
            self._namespace = _digest(active["namespace"], "runner namespace")
            with self._transaction(
                exclusive=False, allow_rollover_journal=True, allow_cloud_install_journal=True,
            ) as context_fd:
                binding = self._binding_locked(context_fd, validate_cloud=False)
                if binding["schema_version"] == "heel.bound-runner-context.v2" and self._selected_rollover_prefix_locked(
                    context_fd, active=active, binding=binding,
                ):
                    return
                if binding["schema_version"] != "heel.bound-runner-context.v1":
                    raise RunnerStoreError("cloud context authority is incomplete")
                # A static v1 pair is legal only while this namespace has never
                # committed Cloud authority.  This is evidence detection, not
                # artifact discovery: no commit found here is opened or adopted.
                if self._cloud_context_evidence_locked(context_fd):
                    raise RunnerStoreError("cloud context authority is incomplete")
            return
        if active.get("schema_version") != _ACTIVE_CONTEXT_CLOUD_SCHEMA:
            raise RunnerStoreError("invalid active runner context")
        self._namespace = _digest(active.get("namespace"), "runner namespace")
        with self._transaction(
            exclusive=False, allow_rollover_journal=True, allow_cloud_install_journal=True,
        ) as context_fd:
            binding = self._binding_locked(context_fd, validate_cloud=False)
            if binding["schema_version"] != "heel.bound-runner-context.v2":
                raise RunnerStoreError("cloud context authority is incomplete")
            self._validate_cloud_active_context_record(active, binding=binding, allow_prior_commit=True)
            try:
                self._validate_cloud_context_authority_locked(context_fd, binding)
                tuple_complete = True
            except RunnerStoreError:
                tuple_complete = False
            if not tuple_complete and not self._selected_rollover_prefix_locked(
                context_fd, active=active, binding=binding,
            ):
                raise RunnerStoreError("cloud context authority is incomplete")
            if active["authority_commit_digest"] != binding["authority_commit_digest"] and not self._selected_rollover_prefix_locked(
                context_fd, active=active, binding=binding,
            ):
                raise RunnerStoreError("cloud context authority is incomplete")

    def _unselected_cloud_context_exists(self) -> bool:
        """Detect Cloud-mode loss without adopting any namespace by directory scan."""
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=False):
                if _read_json(runner_fd, "context-install.json", None) is not None:
                    # A signed root intent owns the only legal unselected
                    # first-install prefixes and is recovered explicitly.
                    return False
                contexts_fd = _open_child(runner_fd, "contexts", create=False)
                if contexts_fd is None:
                    return False
                try:
                    _secure_directory(contexts_fd, "Heel runner contexts directory")
                    for entry in os.scandir(contexts_fd):
                        if _DIGEST.fullmatch(entry.name) is None:
                            continue
                        context_fd = _open_child(contexts_fd, entry.name, create=False)
                        if context_fd is None:
                            continue
                        try:
                            _secure_directory(context_fd, "Heel runner context directory")
                            binding = _read_json(context_fd, "binding.json", None)
                            if isinstance(binding, Mapping) and binding.get("schema_version") == "heel.bound-runner-context.v2":
                                return True
                            if (
                                _read_json(context_fd, "cloud-context-binding.json", None) is not None
                                or _read_json(context_fd, "cloud-context-provenance.json", None) is not None
                                or _read_json(context_fd, "context-rollover.json", None) is not None
                            ):
                                return True
                        finally:
                            os.close(context_fd)
                finally:
                    os.close(contexts_fd)
        return False

    @staticmethod
    def _cloud_context_evidence_locked(context_fd: int) -> bool:
        """Return whether a namespace contains a Cloud-mode marker.

        This deliberately detects only immutable commit filenames and the exact
        mutable Cloud artifacts.  It never parses or selects a discovered
        commitment, so a tampered namespace cannot be adopted by a static
        selector rollback.
        """
        if any(
            _read_json(context_fd, filename, None) is not None
            for filename in (
                "cloud-context-binding.json", "cloud-context-provenance.json",
                "context-rollover.json",
            )
        ):
            return True
        prefix = "cloud-authority-commit-"
        suffix = ".json"
        with os.scandir(context_fd) as entries:
            for entry in entries:
                name = entry.name
                if (
                    name.startswith(prefix) and name.endswith(suffix)
                    and _DIGEST.fullmatch(name[len(prefix):-len(suffix)]) is not None
                ):
                    return True
        return False

    def _has_pending_cloud_install(self) -> bool:
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=False):
                return _read_json(runner_fd, "context-install.json", None) is not None

    def _context_install_journal(
        self, *, binding: Mapping[str, Any], context: RunnerContext,
        identity: RunnerIdentity, signer: SecureSigner, authority_commit: Mapping[str, Any],
    ) -> dict[str, Any]:
        identity_record = _identity_record(identity, signer)
        unsigned = {
            "schema_version": _CONTEXT_INSTALL_SCHEMA, "namespace": context.namespace,
            "context": context.as_dict(), "artifact": dict(binding), "identity": identity_record,
            "authority_commit": dict(authority_commit),
        }
        return {
            **unsigned, "signing_key_id": signer.key_id,
            "signature_b64": base64.b64encode(signer.sign(canonical_bytes(unsigned))).decode("ascii"),
        }

    def _stage_context_install_journal(
        self, *, binding: Mapping[str, Any], context: RunnerContext,
        identity: RunnerIdentity, signer: SecureSigner, authority_commit: Mapping[str, Any],
    ) -> dict[str, Any]:
        journal = self._context_install_journal(
            binding=binding, context=context, identity=identity, signer=signer,
            authority_commit=authority_commit,
        )
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=True):
                active = _read_json(runner_fd, "active-context.json", None)
                if active is not None:
                    raise RunnerStoreError("cloud context binding cannot replace active context")
                existing = _read_json(runner_fd, "context-install.json", None)
                if existing is None:
                    _write_json(runner_fd, "context-install.json", journal)
                elif existing != journal:
                    raise RunnerStoreError("cloud context installation requires recovery")
        return journal

    def _finish_context_install_journal(
        self, *, context: RunnerContext, journal: Mapping[str, Any],
        identity: RunnerIdentity, signer: SecureSigner,
    ) -> None:
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=True):
                if _read_json(runner_fd, "context-install.json", None) != dict(journal):
                    raise RunnerStoreError("cloud context installation journal changed")
                authority_commit = journal.get("authority_commit")
                if not isinstance(authority_commit, Mapping):
                    raise RunnerStoreError("invalid cloud context installation journal")
                expected_active = self._cloud_active_context_record(
                    context=context, identity=identity, signer=signer,
                    authority_commit_digest=authority_commit.get("record_digest"),
                )
                active = _read_json(runner_fd, "active-context.json", None)
                if active is not None and active != expected_active:
                    raise RunnerStoreError("cloud context binding cannot replace active context")
                if active is None:
                    _write_json(runner_fd, "active-context.json", expected_active)
                os.unlink("context-install.json", dir_fd=runner_fd)
                os.fsync(runner_fd)

    def _publish_cloud_active_context(
        self, *, context: RunnerContext, identity: RunnerIdentity, signer: SecureSigner,
        authority_commit_digest: str,
    ) -> None:
        """Publish the signed Cloud selector only after the namespace tuple is complete."""
        expected = self._cloud_active_context_record(
            context=context, identity=identity, signer=signer,
            authority_commit_digest=authority_commit_digest,
        )
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=True):
                active = _read_json(runner_fd, "active-context.json", None)
                static = {
                    "schema_version": "heel.active-runner-context.v1",
                    "namespace": context.namespace,
                }
                if active is not None and active not in (static, expected):
                    if not isinstance(active, Mapping) or active.get("schema_version") != _ACTIVE_CONTEXT_CLOUD_SCHEMA:
                        raise RunnerStoreError("cloud context binding cannot replace active context")
                    if active.get("namespace") != context.namespace:
                        raise RunnerStoreError("cloud context binding cannot replace active context")
                if active != expected:
                    _write_json(runner_fd, "active-context.json", expected)

    def _pending_cloud_context_install_for_recovery(
        self, *, identity: RunnerIdentity, signer: SecureSigner,
    ) -> tuple[dict[str, Any], RunnerContext, dict[str, Any]] | None:
        """Private root-journal reader; no namespace scan can adopt an orphan."""
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=False):
                value = _read_json(runner_fd, "context-install.json", None)
        if value is None:
            return None
        fields = {
            "schema_version", "namespace", "context", "artifact", "identity",
            "authority_commit", "signing_key_id", "signature_b64",
        }
        if not isinstance(value, Mapping) or set(value) != fields or value["schema_version"] != _CONTEXT_INSTALL_SCHEMA:
            raise RunnerStoreError("invalid cloud context installation journal")
        try:
            context = _context_from_dict(value["context"])
            if value["namespace"] != context.namespace or value["identity"] != _identity_record(identity, signer):
                raise ValueError
            public = load_public_key_base64(identity.public_key_b64)
            unsigned = {key: value[key] for key in fields - {"signing_key_id", "signature_b64"}}
            verify_envelope(
                {identity.key_id: public},
                {"signing_key_id": value["signing_key_id"], "signature_b64": value["signature_b64"]},
                canonical_bytes(unsigned),
            )
            artifact = validate_runner_context_binding(value["artifact"])
            commit = self._validate_cloud_authority_commit(
                value["authority_commit"], expected_digest=value["authority_commit"]["record_digest"],
                namespace=context.namespace, context=context, identity=_identity_record(identity, signer),
            )
            if (
                commit["binding_id"] != artifact["binding_id"]
                or commit["binding_digest"] != artifact["binding_digest"]
            ):
                raise ValueError
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid cloud context installation journal") from None
        return artifact, context, dict(value)

    def bind_context(
        self, context: RunnerContext, *, identity: RunnerIdentity, signer: SecureSigner, signer_label: str,
    ) -> None:
        """Bind the original static/local context contract; Cloud staging is private."""
        if self._has_pending_cloud_install():
            raise RunnerStoreError("cloud context installation requires recovery")
        self._bind_context(
            context, identity=identity, signer=signer, signer_label=signer_label, publish_active=True,
        )
        self._pin_runtime_authority(identity, signer)

    def _bind_context(
        self,
        context: RunnerContext,
        *,
        identity: RunnerIdentity,
        signer: SecureSigner,
        signer_label: str,
        publish_active: bool,
        install_journal: Mapping[str, Any] | None = None,
        authority_commit: Mapping[str, Any] | None = None,
        cloud_binding: Mapping[str, Any] | None = None,
    ) -> None:
        if not isinstance(context, RunnerContext):
            raise ValueError("RunnerContext is required")
        identity_record = _identity_record(identity, signer)
        if identity_record["workspace_id"] != context.workspace_id:
            raise ValueError("runner identity workspace does not match target context")
        signer_label = _id(signer_label, "runner signer label")
        namespace = context.namespace
        if (authority_commit is None) != (cloud_binding is None):
            raise RunnerStoreError("cloud context authority is incomplete")
        if authority_commit is None:
            binding = {
                "schema_version": "heel.bound-runner-context.v1",
                "namespace": namespace,
                "context": context.as_dict(),
                "identity": identity_record,
                "signer_label": signer_label,
            }
        else:
            binding = self._cloud_bound_context_record(
                context=context, identity=identity, signer=signer, signer_label=signer_label,
                authority_commit=authority_commit,
            )
        previous = self._namespace
        self._namespace = namespace
        try:
            with self._open_runner(create=True) as runner_fd:
                assert runner_fd is not None
                with _flock(runner_fd, ".runner.lock", exclusive=True):
                    root_install = _read_json(runner_fd, "context-install.json", None)
                    if install_journal is None:
                        if root_install is not None:
                            raise RunnerStoreError("cloud context installation requires recovery")
                    elif root_install != dict(install_journal):
                        raise RunnerStoreError("local run authority index is unavailable")
                    contexts_fd = _open_child(runner_fd, "contexts", create=True)
                    assert contexts_fd is not None
                    context_fd = -1
                    try:
                        _secure_directory(contexts_fd, "Heel runner contexts directory")
                        opened_context = _open_child(contexts_fd, namespace, create=True)
                        if opened_context is None:
                            raise RunnerStoreError("could not create runner context")
                        context_fd = opened_context
                        _secure_directory(context_fd, "Heel runner context directory")
                        with _flock(context_fd, ".metadata.lock", exclusive=True):
                            existing = _read_json(context_fd, "binding.json", None)
                            if existing is not None and existing != binding:
                                raise ValueError(
                                    "bound context cannot be rebound to another runner or target"
                                )
                            runs_fd = _open_child(context_fd, "runs", create=True)
                            assert runs_fd is not None
                            try:
                                _secure_directory(runs_fd, "Heel runner runs directory")
                                index = _read_json(runs_fd, _RUN_AUTHORITY_INDEX_FILENAME, None)
                                metadata_names = {entry.name for entry in os.scandir(context_fd)}
                                expected_metadata = {".metadata.lock", "binding.json", "runs"}
                                run_names = {entry.name for entry in os.scandir(runs_fd)}
                                zero = self._zero_run_authority_index(
                                    context=context, identity=identity, signer=signer,
                                )

                                def exact_zero(value: object) -> bool:
                                    if value is None:
                                        return False
                                    try:
                                        checked = self._verify_signed_run_authority_value(
                                            value, identity=identity,
                                            schema=_RUN_AUTHORITY_INDEX_SCHEMA,
                                            record_digest=False,
                                            max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                                        )
                                    except RunnerStoreError:
                                        return False
                                    return (
                                        set(checked) == set(zero)
                                        and checked["namespace"] == zero["namespace"]
                                        and checked["workspace_id"] == zero["workspace_id"]
                                        and checked["runner_id"] == zero["runner_id"]
                                        and checked["runner_key_id"] == zero["runner_key_id"]
                                        and checked["generation"] == 0
                                        and checked["nonterminal_count"] == 0
                                        and checked["nonterminal_runs"] == []
                                        and checked["terminal_queue"] == []
                                        and checked["head_digest"] == _RUN_AUTHORITY_ZERO_HEAD
                                    )

                                clean_metadata = metadata_names <= expected_metadata
                                empty_runs = run_names == set()
                                zero_only_runs = run_names == {_RUN_AUTHORITY_INDEX_FILENAME}
                                if existing is None and index is None:
                                    # Fresh authority publishes the signed zero index first.  A
                                    # retry after an interrupted index write sees this same empty
                                    # footprint and is safe to repeat.
                                    if not clean_metadata or not empty_runs:
                                        raise RunnerStoreError("local run authority index is unavailable")
                                    self._initialize_run_authority_index_locked(
                                        context_fd, context=context, identity=identity, signer=signer,
                                        initial_bind=True,
                                    )
                                    if authority_commit is not None:
                                        self._ensure_json_exact(
                                            context_fd,
                                            self._cloud_authority_commit_filename(authority_commit["record_digest"]),
                                            authority_commit,
                                        )
                                    _write_json(context_fd, "binding.json", binding)
                                elif existing is None and exact_zero(index):
                                    # The only accepted index-first crash prefix is the exact
                                    # signed zero for this caller, with no sidecars or history.
                                    if not clean_metadata or not zero_only_runs:
                                        raise RunnerStoreError("local run authority index is unavailable")
                                    self._initialize_run_authority_index_locked(
                                        context_fd, context=context, identity=identity, signer=signer,
                                        initial_bind=False,
                                    )
                                    if authority_commit is not None:
                                        self._ensure_json_exact(
                                            context_fd,
                                            self._cloud_authority_commit_filename(authority_commit["record_digest"]),
                                            authority_commit,
                                        )
                                    _write_json(context_fd, "binding.json", binding)
                                elif existing == binding and index is None:
                                    # Compatibility repair for the historic binding-first
                                    # prefix.  It is deliberately narrower than legacy upgrade:
                                    # no active selection of this namespace, Cloud artifacts, or
                                    # retained run state may be present.
                                    active = _read_json(runner_fd, "active-context.json", None)
                                    expected_active = {
                                        "schema_version": "heel.active-runner-context.v1",
                                        "namespace": namespace,
                                    }
                                    if (
                                        not clean_metadata or not empty_runs
                                        or active == expected_active
                                    ):
                                        raise RunnerStoreError("local run authority index is unavailable")
                                    self._initialize_run_authority_index_locked(
                                        context_fd, context=context, identity=identity, signer=signer,
                                        initial_bind=True,
                                    )
                                elif existing == binding and index is not None:
                                    self._initialize_run_authority_index_locked(
                                        context_fd, context=context, identity=identity, signer=signer,
                                        initial_bind=False,
                                    )
                                else:
                                    raise RunnerStoreError("local run authority index is unavailable")
                                if authority_commit is not None:
                                    self._ensure_json_exact(
                                        context_fd,
                                        self._cloud_authority_commit_filename(authority_commit["record_digest"]),
                                        authority_commit,
                                    )
                                    provenance = {
                                        "schema_version": _CLOUD_CONTEXT_PROVENANCE_SCHEMA,
                                        "binding_id": cloud_binding["binding_id"],
                                        "binding_digest": cloud_binding["binding_digest"],
                                    }
                                    _write_json(context_fd, "cloud-context-provenance.json", provenance)
                                    _write_json(context_fd, "cloud-context-binding.json", dict(cloud_binding))
                                os.fsync(runs_fd)
                                os.fsync(context_fd)
                            finally:
                                os.close(runs_fd)
                        if publish_active:
                            if authority_commit is None:
                                _write_json(runner_fd, "active-context.json", {
                                    "schema_version": "heel.active-runner-context.v1",
                                    "namespace": namespace,
                                })
                            else:
                                _write_json(runner_fd, "active-context.json", self._cloud_active_context_record(
                                    context=context, identity=identity, signer=signer,
                                    authority_commit_digest=authority_commit["record_digest"],
                                ))
                    finally:
                        if context_fd >= 0:
                            os.close(context_fd)
                        os.close(contexts_fd)
        except BaseException:
            self._namespace = previous
            raise

    def install_cloud_context_binding(
        self, artifact: object, *, identity: RunnerIdentity, signer: SecureSigner,
        signer_label: str, trusted_cloud_keys: Mapping[str, object], now_ms: int,
        rollover_evidence: RunnerContextRolloverEvidence | None = None,
    ) -> RunnerContext:
        """Install first/idempotent/expired authority; current rollover is coordinator-only."""
        self._pin_runtime_authority(identity, signer)
        context = self._install_cloud_context_binding(
            artifact, identity=identity, signer=signer, signer_label=signer_label,
            trusted_cloud_keys=trusted_cloud_keys, now_ms=now_ms,
            rollover_evidence=rollover_evidence, rollover_receipt=None,
        )
        self._pin_runtime_authority(identity, signer)
        return context

    def _install_cloud_context_binding_from_control(
        self, artifact: object, *, identity: RunnerIdentity, signer: SecureSigner,
        signer_label: str, trusted_cloud_keys: Mapping[str, object], now_ms: int,
        rollover_receipt: object,
    ) -> RunnerContext:
        """Internal coordinator path for a one-use authenticated list→claim receipt."""
        self._pin_runtime_authority(identity, signer)
        try:
            from heel.runner.control_client import _registered_rollover_receipt
            _registered_rollover_receipt(rollover_receipt, self)
        except (ImportError, ValueError):
            raise RunnerStoreError("cloud context rollover receipt is invalid") from None
        context = self._install_cloud_context_binding(
            artifact, identity=identity, signer=signer, signer_label=signer_label,
            trusted_cloud_keys=trusted_cloud_keys, now_ms=now_ms,
            rollover_evidence=None, rollover_receipt=rollover_receipt,
        )
        self._pin_runtime_authority(identity, signer)
        return context

    def _install_cloud_context_binding(
        self, artifact: object, *, identity: RunnerIdentity, signer: SecureSigner,
        signer_label: str, trusted_cloud_keys: Mapping[str, object], now_ms: int,
        rollover_evidence: RunnerContextRolloverEvidence | None,
        rollover_receipt: object | None,
    ) -> RunnerContext:
        """Verify and atomically retain a Cloud authorization beside the immutable context."""
        binding, context = self._validated_cloud_context_binding(
            artifact, identity=identity, trusted_cloud_keys=trusted_cloud_keys, now_ms=now_ms,
        )
        # Never create/select a namespace before proving that an existing local
        # Cloud context permits this exact renewal.  A signed artifact is not a
        # general rebind capability.
        previous_namespace = self._namespace
        was_bound = self.is_context_bound
        pending_journal: dict[str, Any] | None = None
        pending_install: tuple[dict[str, Any], RunnerContext, dict[str, Any]] | None = None
        if was_bound:
            try:
                active_context = self.load_context()
            except RunnerStoreError:
                with self._transaction(
                    exclusive=False, allow_rollover_journal=True, allow_cloud_install_journal=True,
                ) as context_fd:
                    raw_journal = _read_json(context_fd, "context-rollover.json", None)
                    if raw_journal is None:
                        raise
                    pending_journal = self._validate_context_rollover_journal(
                        raw_journal, identity=identity, expected_artifact=binding,
                        expected_evidence=rollover_evidence, expected_context=context,
                    )
                    active_context = _context_from_dict(
                        self._binding_locked(context_fd, validate_cloud=False)["context"],
                    )
            pending_install = self._pending_cloud_context_install_for_recovery(
                identity=identity, signer=signer,
            )
            if pending_install is not None and pending_install[1] != active_context and not self._is_proof_generation_rollover(
                pending_install[1], active_context,
            ):
                raise RunnerStoreError("cloud context installation journal does not match active context")
        else:
            pending_install = self._pending_cloud_context_install_for_recovery(
                identity=identity, signer=signer,
            )
            if pending_install is None:
                active_context = None
            else:
                pending_artifact, active_context, _pending_install_journal = pending_install
                self._namespace = active_context.namespace
                # A first-install crash can leave the root old-authority intent
                # while a later, receipt-authorized proof rollover has already
                # written its signed journal and replacement binding.  Resume
                # that exact forward state rather than recreating the old
                # binding over it.  Nothing without both locally signed
                # journals is adopted.
                try:
                    with self._transaction(
                        exclusive=False, allow_rollover_journal=True,
                        allow_cloud_install_journal=True,
                    ) as context_fd:
                        raw_journal = _read_json(context_fd, "context-rollover.json", None)
                        if raw_journal is not None:
                            pending_journal = self._validate_context_rollover_journal(
                                raw_journal, identity=identity, expected_artifact=binding,
                                expected_evidence=None, expected_context=context,
                            )
                            local = self._binding_locked(context_fd, validate_cloud=False)
                            if (
                                pending_journal["old_binding_id"] != pending_artifact["binding_id"]
                                or pending_journal["old_binding_digest"] != pending_artifact["binding_digest"]
                                or not self._is_proof_generation_rollover(active_context, context)
                                or local["identity"] != _identity_record(identity, signer)
                                or local["context"] not in (active_context.as_dict(), context.as_dict())
                            ):
                                raise RunnerStoreError("cloud context installation recovery state is inconsistent")
                except BaseException:
                    self._namespace = previous_namespace
                    raise
        rollover = (active_context is not None and active_context != context) or pending_journal is not None
        if rollover and rollover_receipt is None and not (
            isinstance(rollover_evidence, RunnerContextRolloverEvidence)
            and (pending_journal is not None or self._is_proof_generation_rollover(active_context, context))
        ):
            self._namespace = previous_namespace
            raise RunnerStoreError("cloud context binding cannot be installed over an active context")
        provenance = {
            "schema_version": _CLOUD_CONTEXT_PROVENANCE_SCHEMA,
            "binding_id": binding["binding_id"],
            "binding_digest": binding["binding_digest"],
        }
        # The immutable signed commit is written before the local Cloud binding
        # and is the durable mode marker.  A caller never chooses it from disk.
        # A recovery must reuse the signed root intent verbatim rather than
        # manufacture a second first-commit at a later local clock value.
        new_authority_commit: dict[str, Any] | None = (
            None if was_bound else (
                dict(pending_install[2]["authority_commit"])
                if pending_install is not None and binding == pending_install[0]
                else self._cloud_authority_commit(
                    binding=binding, context=context, identity=identity, signer=signer,
                    committed_at_ms=now_ms,
                    prior_commit_digest=(
                        pending_install[2]["authority_commit"]["record_digest"]
                        if pending_install is not None else None
                    ),
                )
            )
        )
        install_journal: dict[str, Any] | None = pending_install[2] if pending_install is not None else None
        static_to_cloud = False
        transitioned_cloud = False
        try:
            # A first Cloud installation never publishes the active selector
            # until the signed sidecar is durably present and revalidated.
            if not was_bound:
                if pending_install is None:
                    install_journal = self._stage_context_install_journal(
                        binding=binding, context=context, identity=identity, signer=signer,
                        authority_commit=new_authority_commit,
                    )
                    self._bind_context(
                        context, identity=identity, signer=signer, signer_label=signer_label,
                        publish_active=False, install_journal=install_journal,
                        authority_commit=new_authority_commit, cloud_binding=binding,
                    )
                else:
                    install_journal = pending_install[2]
                    # The root intent can be the only durable record when a
                    # crash lands between journal publication and binding.json.
                    # Recreate only its exact locally signed namespace record
                    # when no later signed rollover is present; no directory
                    # scan or caller-selected context is adopted.
                    if pending_journal is None:
                        self._bind_context(
                            pending_install[1], identity=identity, signer=signer,
                            signer_label=signer_label, publish_active=False,
                            install_journal=pending_install[2],
                            authority_commit=pending_install[2]["authority_commit"],
                            cloud_binding=pending_install[0],
                        )
            receipt_consumed = False
            with self._transaction(
                exclusive=True, allow_rollover_journal=rollover,
                allow_cloud_install_journal=rollover,
            ) as context_fd:
                existing = _read_json(context_fd, "cloud-context-binding.json", None)
                local_before = self._binding_locked(context_fd, validate_cloud=not rollover)
                if new_authority_commit is None:
                    if pending_journal is not None:
                        new_authority_commit = dict(pending_journal["new_authority_commit"])
                    else:
                        prior_commit = (
                            local_before["authority_commit_digest"]
                            if local_before["schema_version"] == "heel.bound-runner-context.v2"
                            else None
                        )
                        new_authority_commit = self._cloud_authority_commit(
                            binding=binding, context=context, identity=identity, signer=signer,
                            committed_at_ms=now_ms, prior_commit_digest=prior_commit,
                        )
                if existing is None and local_before["schema_version"] == "heel.bound-runner-context.v1":
                    static_to_cloud = True
                    transitioned_cloud = True
                    if pending_journal is None:
                        _write_json(
                            context_fd, "context-rollover.json",
                            self._context_rollover_journal(
                                old=None, new=binding, context=context, evidence=None,
                                identity=identity, signer=signer,
                                old_authority_commit_digest=None,
                                new_authority_commit=new_authority_commit,
                            ),
                        )
                    self._ensure_json_exact(
                        context_fd,
                        self._cloud_authority_commit_filename(new_authority_commit["record_digest"]),
                        new_authority_commit,
                    )
                    _write_json(context_fd, "binding.json", self._cloud_bound_context_record(
                        context=context, identity=identity, signer=signer, signer_label=signer_label,
                        authority_commit=new_authority_commit,
                    ))
                if existing != binding and (
                    existing is not None or (pending_install is not None and binding != pending_install[0])
                ):
                    old_source = existing if existing is not None else pending_install[0]
                    old, old_context = self._validated_cloud_context_binding(
                        old_source, identity=identity, trusted_cloud_keys=trusted_cloud_keys, now_ms=now_ms,
                        require_current=False,
                    )
                    # A public sidecar install may only replace expired local
                    # authority.  The immediate revoke/create path is available
                    # solely through an opaque receipt minted by this runner's
                    # authenticated list→claim control flow.
                    if now_ms < old["expires_at_ms"] and rollover_receipt is None:
                        raise RunnerStoreError("cloud context binding cannot be replaced")
                    if rollover_receipt is not None:
                        rollover_evidence = self._consume_control_rollover_receipt(
                            rollover_receipt, old=old, new=binding, now_ms=now_ms,
                        )
                        receipt_consumed = True
                    valid_forward = self._rollover_evidence_matches(
                        rollover_evidence, old=old, new=binding,
                    )
                    valid_rollover = valid_forward and self._is_proof_generation_rollover(old_context, context)
                    if (not valid_forward or (old_context != context and not valid_rollover)) or (
                        binding["binding_id"] == old["binding_id"]
                        or binding["binding_digest"] == old["binding_digest"]
                        or binding["issued_at_ms"] <= old["issued_at_ms"]
                        or binding["expires_at_ms"] < old["expires_at_ms"]
                        or (binding["expires_at_ms"] == old["expires_at_ms"] and not receipt_consumed)
                    ):
                        raise RunnerStoreError("cloud context binding cannot be replaced")
                    if rollover or local_before["schema_version"] == "heel.bound-runner-context.v2":
                        local = self._binding_locked(context_fd, validate_cloud=not rollover)
                        if self._has_nonterminal_local_run(context_fd):
                            raise RunnerStoreError("cloud context rollover requires terminal local runs")
                        if local["schema_version"] != "heel.bound-runner-context.v2":
                            raise RunnerStoreError("cloud context rollover requires prior cloud authority")
                        replacement = self._cloud_bound_context_record(
                            context=context, identity=identity, signer=signer,
                            signer_label=local["signer_label"], authority_commit=new_authority_commit,
                        )
                        if pending_journal is None:
                            _write_json(
                                context_fd, "context-rollover.json",
                                self._context_rollover_journal(
                                    old=old, new=binding, context=context,
                                    evidence=rollover_evidence, identity=identity, signer=signer,
                                    old_authority_commit_digest=local["authority_commit_digest"],
                                    new_authority_commit=new_authority_commit,
                                ),
                            )
                        self._ensure_json_exact(
                            context_fd,
                            self._cloud_authority_commit_filename(new_authority_commit["record_digest"]),
                            new_authority_commit,
                        )
                        _write_json(context_fd, "binding.json", replacement)
                        transitioned_cloud = True
                elif rollover:
                    # A fault can occur after every new record is durable but before
                    # the journal unlink.  Complete that exact signed new/new state
                    # only; a missing provenance, a changed local binding, or live
                    # run authority is a mixed state and remains fail-closed.
                    if pending_journal is None:
                        raise RunnerStoreError("cloud context rollover requires prior cloud authority")
                    local = self._binding_locked(context_fd)
                    if (
                        local["context"] != context.as_dict()
                        or local["identity"] != _identity_record(identity, signer)
                        or self._has_nonterminal_local_run(context_fd)
                    ):
                        raise RunnerStoreError("cloud context rollover finalizer state is inconsistent")
                    if _read_json(context_fd, "cloud-context-provenance.json", None) != provenance:
                        raise RunnerStoreError("cloud context rollover finalizer state is inconsistent")
                    if rollover_receipt is not None:
                        self._consume_control_rollover_receipt(
                            rollover_receipt,
                            old={
                                "binding_id": pending_journal["old_binding_id"],
                                "binding_digest": pending_journal["old_binding_digest"],
                            },
                            new=binding, now_ms=now_ms,
                        )
                        receipt_consumed = True
                existing_provenance = _read_json(context_fd, "cloud-context-provenance.json", None)
                if existing_provenance is not None and existing_provenance != provenance:
                    checked_provenance = self._validate_cloud_context_provenance(existing_provenance)
                    if (
                        existing is None
                        or checked_provenance["binding_id"] != existing.get("binding_id")
                        or checked_provenance["binding_digest"] != existing.get("binding_digest")
                    ):
                        raise RunnerStoreError("cloud context provenance does not match sidecar")
                _write_json(context_fd, "cloud-context-provenance.json", provenance)
                if existing != binding:
                    _write_json(context_fd, "cloud-context-binding.json", binding)
                stored = _read_json(context_fd, "cloud-context-binding.json", None)
                stored_provenance = _read_json(context_fd, "cloud-context-provenance.json", None)
                if stored != binding or stored_provenance != provenance:
                    raise RunnerStoreError("cloud context binding was not durably installed")
                self._validated_cloud_context_binding(
                    stored, identity=identity, trusted_cloud_keys=trusted_cloud_keys, now_ms=now_ms,
                )
                # R remains until its matching v2 root selector is durable.
            if rollover_receipt is not None and not receipt_consumed:
                raise RunnerStoreError("cloud context rollover receipt was not consumed")
            if transitioned_cloud and install_journal is None:
                self._publish_cloud_active_context(
                    context=context, identity=identity, signer=signer,
                    authority_commit_digest=new_authority_commit["record_digest"],
                )
                with self._transaction(exclusive=True, allow_rollover_journal=True) as context_fd:
                    raw_journal = _read_json(context_fd, "context-rollover.json", None)
                    if raw_journal is None:
                        raise RunnerStoreError("cloud context rollover journal disappeared")
                    self._validate_context_rollover_journal(
                        raw_journal, identity=identity, expected_artifact=binding,
                        expected_evidence=None, expected_context=context,
                    )
                    os.unlink("context-rollover.json", dir_fd=context_fd)
                    os.fsync(context_fd)
            if install_journal is not None:
                self._finish_context_install_journal(
                    context=context, journal=install_journal, identity=identity, signer=signer,
                )
                if rollover:
                    with self._transaction(exclusive=True, allow_rollover_journal=True) as context_fd:
                        raw_journal = _read_json(context_fd, "context-rollover.json", None)
                        if raw_journal is None:
                            raise RunnerStoreError("cloud context rollover journal disappeared")
                        self._validate_context_rollover_journal(
                            raw_journal, identity=identity, expected_artifact=binding,
                            expected_evidence=None, expected_context=context,
                        )
                        os.unlink("context-rollover.json", dir_fd=context_fd)
                        os.fsync(context_fd)
        except BaseException:
            self._namespace = previous_namespace
            raise
        return context

    @staticmethod
    def _is_proof_generation_rollover(old: RunnerContext, new: RunnerContext) -> bool:
        return (
            old.workspace_id == new.workspace_id and old.project_id == new.project_id
            and old.environment_id == new.environment_id and old.origin == new.origin
            and old.environment_class == new.environment_class
            and old.namespace == new.namespace
            and old.verification_record_digest != new.verification_record_digest
        )

    @staticmethod
    def _rollover_evidence_matches(
        evidence: RunnerContextRolloverEvidence | None, *, old: Mapping[str, Any], new: Mapping[str, Any],
    ) -> bool:
        return bool(
            isinstance(evidence, RunnerContextRolloverEvidence)
            and evidence.old_binding_id == old["binding_id"]
            and evidence.old_binding_digest == old["binding_digest"]
            and evidence.new_binding_id == new["binding_id"]
            and evidence.new_binding_digest == new["binding_digest"]
            and new["issued_at_ms"] <= evidence.observed_server_time_ms + 30_000
        )

    def _consume_control_rollover_receipt(
        self, receipt: object, *, old: Mapping[str, Any], new: Mapping[str, Any], now_ms: int,
    ) -> RunnerContextRolloverEvidence:
        """Turn the client-private one-use receipt into journal-safe closed fields."""
        try:
            from heel.runner.control_client import _consume_registered_rollover_receipt
            observed = _consume_registered_rollover_receipt(
                receipt, self, old_binding_id=old["binding_id"], old_binding_digest=old["binding_digest"],
                new_binding_id=new["binding_id"], new_binding_digest=new["binding_digest"],
            )
            observed_at = observed["observed_server_time_ms"]
            if (
                type(now_ms) is not int or type(observed_at) is not int
                or not new["issued_at_ms"] <= observed_at < new["expires_at_ms"]
                or abs(now_ms - observed_at) > 30_000
            ):
                raise ValueError
            return RunnerContextRolloverEvidence(
                old_binding_id=observed["old_binding_id"],
                old_binding_digest=observed["old_binding_digest"],
                new_binding_id=observed["new_binding_id"],
                new_binding_digest=observed["new_binding_digest"],
                observed_server_time_ms=observed_at,
            )
        except (ImportError, KeyError, TypeError, ValueError):
            raise RunnerStoreError("cloud context rollover receipt is invalid") from None

    @staticmethod
    def _rollover_evidence_dict(evidence: RunnerContextRolloverEvidence) -> dict[str, Any]:
        return {
            "old_binding_id": evidence.old_binding_id,
            "old_binding_digest": evidence.old_binding_digest,
            "new_binding_id": evidence.new_binding_id,
            "new_binding_digest": evidence.new_binding_digest,
            "observed_server_time_ms": evidence.observed_server_time_ms,
        }

    def _context_rollover_journal(
        self, *, old: Mapping[str, Any] | None, new: Mapping[str, Any], context: RunnerContext,
        evidence: RunnerContextRolloverEvidence | None, identity: RunnerIdentity, signer: SecureSigner,
        old_authority_commit_digest: str | None, new_authority_commit: Mapping[str, Any],
    ) -> dict[str, Any]:
        if old is None:
            if evidence is not None or old_authority_commit_digest is not None:
                raise RunnerStoreError("cloud context rollover requires evidence")
            old_binding_id: str | None = None
            old_binding_digest: str | None = None
        else:
            if not isinstance(evidence, RunnerContextRolloverEvidence) or old_authority_commit_digest is None:
                raise RunnerStoreError("cloud context rollover requires evidence")
            old_binding_id = old["binding_id"]
            old_binding_digest = old["binding_digest"]
            old_authority_commit_digest = _digest(
                old_authority_commit_digest, "prior cloud authority commit digest",
            )
        commit = self._validate_cloud_authority_commit(
            new_authority_commit, expected_digest=new_authority_commit.get("record_digest"),
            namespace=context.namespace, context=context,
            identity=_identity_record(identity, signer),
        )
        if (
            commit["binding_id"] != new["binding_id"]
            or commit["binding_digest"] != new["binding_digest"]
            or commit["prior_commit_digest"] != old_authority_commit_digest
        ):
            raise RunnerStoreError("cloud context rollover requires evidence")
        _identity_record(identity, signer)
        unsigned = {
            "schema_version": _CONTEXT_ROLLOVER_SCHEMA,
            "old_binding_id": old_binding_id, "old_binding_digest": old_binding_digest,
            "new_binding_id": new["binding_id"], "new_binding_digest": new["binding_digest"],
            "context": context.as_dict(), "artifact": dict(new),
            "evidence": self._rollover_evidence_dict(evidence) if evidence is not None else None,
            "old_authority_commit_digest": old_authority_commit_digest,
            "new_authority_commit": commit,
        }
        return {
            **unsigned, "signing_key_id": signer.key_id,
            "signature_b64": base64.b64encode(signer.sign(canonical_bytes(unsigned))).decode("ascii"),
        }

    def _has_nonterminal_local_run(self, context_fd: int) -> bool:
        identity, _signer = self._require_runtime_authority()
        runs_fd = _open_child(context_fd, "runs", create=False)
        if runs_fd is None:
            raise RunnerStoreError("local run authority index is unavailable")
        try:
            _secure_directory(runs_fd, "Heel runner runs directory")
            self._complete_run_authority_journal_locked(
                context_fd, runs_fd, identity=identity,
            )
            return self._run_authority_index_locked(
                runs_fd, identity=identity,
            )["nonterminal_count"] != 0
        finally:
            os.close(runs_fd)

    def _validate_context_rollover_journal(
        self, value: object, *, identity: RunnerIdentity, expected_artifact: Mapping[str, Any],
        expected_evidence: RunnerContextRolloverEvidence | None, expected_context: RunnerContext,
    ) -> dict[str, Any]:
        fields = {
            "schema_version", "old_binding_id", "old_binding_digest", "new_binding_id",
            "new_binding_digest", "context", "artifact", "evidence", "old_authority_commit_digest",
            "new_authority_commit", "signing_key_id", "signature_b64",
        }
        if not isinstance(value, Mapping) or set(value) != fields or value["schema_version"] != _CONTEXT_ROLLOVER_SCHEMA:
            raise RunnerStoreError("invalid cloud context rollover journal")
        try:
            is_static_transition = value["old_binding_id"] is None and value["old_binding_digest"] is None
            if is_static_transition:
                if value["evidence"] is not None or value["old_authority_commit_digest"] is not None:
                    raise ValueError
                evidence = None
            else:
                if value["old_binding_id"] is None or value["old_binding_digest"] is None:
                    raise ValueError
                evidence = RunnerContextRolloverEvidence(**dict(value["evidence"]))
                _digest(value["old_authority_commit_digest"], "prior cloud authority commit digest")
            public = load_public_key_base64(identity.public_key_b64)
            unsigned = {key: value[key] for key in fields - {"signing_key_id", "signature_b64"}}
            verify_envelope(
                {identity.key_id: public},
                {"signing_key_id": value["signing_key_id"], "signature_b64": value["signature_b64"]},
                canonical_bytes(unsigned),
            )
            commit = self._validate_cloud_authority_commit(
                value["new_authority_commit"],
                expected_digest=value["new_authority_commit"]["record_digest"],
                namespace=expected_context.namespace, context=expected_context,
                identity=_identity_record(identity, _IdentityPublicSigner(identity)),
            )
            if (
                commit["binding_id"] != expected_artifact["binding_id"]
                or commit["binding_digest"] != expected_artifact["binding_digest"]
                or commit["prior_commit_digest"] != value["old_authority_commit_digest"]
            ):
                raise ValueError
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid cloud context rollover journal") from None
        if (
            value["artifact"] != dict(expected_artifact)
            or _context_from_dict(value["context"]) != expected_context
            or (expected_evidence is not None and evidence != expected_evidence)
            or value["new_binding_id"] != expected_artifact["binding_id"]
            or value["new_binding_digest"] != expected_artifact["binding_digest"]
        ):
            raise RunnerStoreError("cloud context rollover journal does not match recovery")
        return dict(value)

    def _pending_context_rollover_for_recovery(self, *, identity: RunnerIdentity) -> dict[str, Any] | None:
        """Private signed old→new correlation for a restart after rollover publication."""
        with self._transaction(exclusive=False, allow_rollover_journal=True) as context_fd:
            value = _read_json(context_fd, "context-rollover.json", None)
            if value is None:
                return None
            if not isinstance(value, Mapping):
                raise RunnerStoreError("invalid cloud context rollover journal")
            try:
                artifact = validate_runner_context_binding(value["artifact"])
                context = _context_from_dict(value["context"])
            except (KeyError, TypeError, ValueError):
                raise RunnerStoreError("invalid cloud context rollover journal") from None
            return self._validate_context_rollover_journal(
                value, identity=identity, expected_artifact=artifact,
                expected_evidence=None, expected_context=context,
            )

    def finish_pending_context_rollover(
        self, *, identity: RunnerIdentity, trusted_cloud_keys: Mapping[str, object], now_ms: int,
    ) -> dict[str, Any] | None:
        """Complete a signed A→B local journal before any fresh Cloud discovery.

        This is intentionally not an install API: it can only write the exact B
        already authenticated into the locally signed rollover journal.  A later
        Cloud C is therefore always a new B→C control receipt, never an A→C jump.
        """
        previous_namespace = self._namespace
        runtime_identity, recovery_signer = self._require_runtime_authority()
        if _identity_record(runtime_identity, recovery_signer) != _identity_record(identity, recovery_signer):
            raise RunnerStoreError("authenticated runner store identity changed")
        pending_install = self._pending_cloud_context_install_for_recovery(
            identity=identity, signer=recovery_signer,
        ) if not self.is_context_bound else None
        if pending_install is not None:
            self._namespace = pending_install[1].namespace
        if self._namespace is None:
            return None
        try:
            with self._transaction(
                exclusive=True, allow_rollover_journal=True, allow_cloud_install_journal=True,
            ) as context_fd:
                raw_journal = _read_json(context_fd, "context-rollover.json", None)
                if raw_journal is None:
                    self._namespace = previous_namespace
                    return None
                try:
                    raw_artifact = validate_runner_context_binding(raw_journal["artifact"])
                    new, new_context = self._validated_cloud_context_binding(
                        raw_artifact, identity=identity, trusted_cloud_keys=trusted_cloud_keys,
                        now_ms=now_ms, require_current=False,
                    )
                    journal = self._validate_context_rollover_journal(
                        raw_journal, identity=identity, expected_artifact=new,
                        expected_evidence=None, expected_context=new_context,
                    )
                    evidence = (
                        RunnerContextRolloverEvidence(**dict(journal["evidence"]))
                        if journal["evidence"] is not None else None
                    )
                    local = self._binding_locked(context_fd, validate_cloud=False)
                    provenance_value = _read_json(context_fd, "cloud-context-provenance.json", None)
                    sidecar_value = _read_json(context_fd, "cloud-context-binding.json", None)
                    sidecar = (
                        validate_runner_context_binding(sidecar_value)
                        if sidecar_value is not None else None
                    )
                    new_provenance = {
                        "schema_version": _CLOUD_CONTEXT_PROVENANCE_SCHEMA,
                        "binding_id": new["binding_id"], "binding_digest": new["binding_digest"],
                    }
                    sidecar_is_new = sidecar == new
                    provenance_is_new = provenance_value == new_provenance
                    local_is_new = local["context"] == new_context.as_dict()
                    prefix = (local_is_new, provenance_is_new, sidecar_is_new)
                    if prefix not in {(False, False, False), (True, False, False), (True, True, False), (True, True, True)}:
                        raise ValueError
                    if local["identity"] != _identity_record(identity, recovery_signer):
                        raise ValueError
                    if self._has_nonterminal_local_run(context_fd):
                        raise RunnerStoreError("cloud context rollover requires terminal local runs")
                    if not sidecar_is_new and journal["old_binding_id"] is not None:
                        old, old_context = self._validated_cloud_context_binding(
                            sidecar, identity=identity, trusted_cloud_keys=trusted_cloud_keys,
                            now_ms=now_ms, require_current=False,
                        )
                        if (
                            old["binding_id"] != journal["old_binding_id"]
                            or old["binding_digest"] != journal["old_binding_digest"]
                            or not self._rollover_evidence_matches(evidence, old=old, new=new)
                            or (old_context != new_context and not self._is_proof_generation_rollover(old_context, new_context))
                        ):
                            raise ValueError
                    elif not sidecar_is_new:
                        if evidence is not None or journal["old_binding_digest"] is not None:
                            raise ValueError
                    elif (
                        journal["new_binding_id"] != new["binding_id"]
                        or journal["new_binding_digest"] != new["binding_digest"]
                    ):
                        raise ValueError
                    if pending_install is not None and (
                        pending_install[0]["binding_id"] != journal["old_binding_id"]
                        or pending_install[0]["binding_digest"] != journal["old_binding_digest"]
                    ):
                        raise ValueError
                except RunnerStoreError:
                    raise
                except (KeyError, TypeError, ValueError):
                    raise RunnerStoreError("cloud context installation recovery state is inconsistent") from None

                if not local_is_new:
                    _write_json(context_fd, "binding.json", self._cloud_bound_context_record(
                        context=new_context, identity=identity, signer=recovery_signer,
                        signer_label=local["signer_label"], authority_commit=journal["new_authority_commit"],
                    ))
                if not provenance_is_new:
                    _write_json(context_fd, "cloud-context-provenance.json", new_provenance)
                if not sidecar_is_new:
                    _write_json(context_fd, "cloud-context-binding.json", new)
                if (
                    _read_json(context_fd, "cloud-context-binding.json", None) != new
                    or _read_json(context_fd, "cloud-context-provenance.json", None) != new_provenance
                    or self._binding_locked(context_fd)["context"] != new_context.as_dict()
                ):
                    raise RunnerStoreError("cloud context installation recovery state is inconsistent")
                # Keep R through publication of the v2 root selector.
            if pending_install is None:
                self._publish_cloud_active_context(
                    context=new_context, identity=identity, signer=recovery_signer,
                    authority_commit_digest=journal["new_authority_commit"]["record_digest"],
                )
                with self._transaction(exclusive=True, allow_rollover_journal=True) as context_fd:
                    raw_journal = _read_json(context_fd, "context-rollover.json", None)
                    if raw_journal is None:
                        raise RunnerStoreError("cloud context rollover journal disappeared")
                    self._validate_context_rollover_journal(
                        raw_journal, identity=identity, expected_artifact=new,
                        expected_evidence=None, expected_context=new_context,
                    )
                    os.unlink("context-rollover.json", dir_fd=context_fd)
                    os.fsync(context_fd)
            if pending_install is not None:
                self._finish_context_install_journal(
                    context=new_context, journal=pending_install[2],
                    identity=identity, signer=recovery_signer,
                )
                with self._transaction(exclusive=True, allow_rollover_journal=True) as context_fd:
                    raw_journal = _read_json(context_fd, "context-rollover.json", None)
                    if raw_journal is None:
                        raise RunnerStoreError("cloud context rollover journal disappeared")
                    self._validate_context_rollover_journal(
                        raw_journal, identity=identity, expected_artifact=new,
                        expected_evidence=None, expected_context=new_context,
                    )
                    os.unlink("context-rollover.json", dir_fd=context_fd)
                    os.fsync(context_fd)
            return new
        except BaseException:
            self._namespace = previous_namespace
            raise

    @staticmethod
    def _validate_cloud_context_provenance(value: object) -> dict[str, str]:
        fields = {"schema_version", "binding_id", "binding_digest"}
        if not isinstance(value, Mapping) or set(value) != fields:
            raise RunnerStoreError("invalid cloud context provenance")
        if value["schema_version"] != _CLOUD_CONTEXT_PROVENANCE_SCHEMA:
            raise RunnerStoreError("invalid cloud context provenance")
        return {
            "schema_version": _CLOUD_CONTEXT_PROVENANCE_SCHEMA,
            "binding_id": _id(value["binding_id"], "cloud context binding ID"),
            "binding_digest": _digest(value["binding_digest"], "cloud context binding digest"),
        }

    @staticmethod
    def _cloud_authority_commit_filename(record_digest: str) -> str:
        return f"cloud-authority-commit-{_digest(record_digest, 'cloud authority commit digest')}.json"

    def _cloud_authority_commit(
        self, *, binding: Mapping[str, Any], context: RunnerContext,
        identity: RunnerIdentity, signer: SecureSigner, committed_at_ms: int,
        prior_commit_digest: str | None,
    ) -> dict[str, Any]:
        """Build the immutable local commitment that makes Cloud mode non-downgradeable."""
        if type(committed_at_ms) is not int or not 0 <= committed_at_ms <= 9_007_199_254_740_991:
            raise RunnerStoreError("invalid cloud context time")
        if prior_commit_digest is not None:
            prior_commit_digest = _digest(prior_commit_digest, "prior cloud authority commit digest")
        if not (
            binding["issued_at_ms"] <= committed_at_ms < binding["expires_at_ms"]
        ):
            raise RunnerStoreError("cloud context binding does not match local runner")
        core = {
            "schema_version": _CLOUD_CONTEXT_AUTHORITY_COMMIT_SCHEMA,
            "namespace": context.namespace,
            "context": context.as_dict(),
            "identity": _identity_record(identity, signer),
            "binding_id": binding["binding_id"],
            "binding_digest": binding["binding_digest"],
            "committed_at_ms": committed_at_ms,
            "prior_commit_digest": prior_commit_digest,
        }
        record_digest = hashlib.sha256(
            _CLOUD_CONTEXT_AUTHORITY_COMMIT_DOMAIN + canonical_bytes(core)
        ).hexdigest()
        signed = {**core, "record_digest": record_digest}
        return {
            **signed,
            "signing_key_id": signer.key_id,
            "signature_b64": base64.b64encode(
                signer.sign(_CLOUD_CONTEXT_AUTHORITY_COMMIT_DOMAIN + canonical_bytes(signed))
            ).decode("ascii"),
        }

    @staticmethod
    def _validate_cloud_authority_commit(
        value: object, *, expected_digest: str, namespace: str,
        context: RunnerContext, identity: Mapping[str, Any],
    ) -> dict[str, Any]:
        fields = {
            "schema_version", "namespace", "context", "identity", "binding_id", "binding_digest",
            "committed_at_ms", "prior_commit_digest", "record_digest", "signing_key_id", "signature_b64",
        }
        try:
            if (
                not isinstance(value, Mapping) or set(value) != fields
                or value["schema_version"] != _CLOUD_CONTEXT_AUTHORITY_COMMIT_SCHEMA
                or value["namespace"] != namespace
                or value["record_digest"] != _digest(expected_digest, "cloud authority commit digest")
                or _context_from_dict(value["context"]) != context
                or _stored_identity_record(value["identity"]) != dict(identity)
                or type(value["committed_at_ms"]) is not int
                or not 0 <= value["committed_at_ms"] <= 9_007_199_254_740_991
            ):
                raise ValueError
            prior = value["prior_commit_digest"]
            if prior is not None:
                _digest(prior, "prior cloud authority commit digest")
            _id(value["binding_id"], "cloud context binding ID")
            _digest(value["binding_digest"], "cloud context binding digest")
            core = {key: value[key] for key in fields - {"record_digest", "signing_key_id", "signature_b64"}}
            digest = hashlib.sha256(
                _CLOUD_CONTEXT_AUTHORITY_COMMIT_DOMAIN + canonical_bytes(core)
            ).hexdigest()
            if digest != value["record_digest"]:
                raise ValueError
            public = load_public_key_base64(identity["public_key_b64"])
            verify_envelope(
                {identity["runner_key_id"]: public},
                {"signing_key_id": value["signing_key_id"], "signature_b64": value["signature_b64"]},
                _CLOUD_CONTEXT_AUTHORITY_COMMIT_DOMAIN + canonical_bytes({**core, "record_digest": digest}),
            )
        except (KeyError, TypeError, ValueError):
            raise RunnerStoreError("cloud context authority is incomplete") from None
        return dict(value)

    @staticmethod
    def _cloud_bound_context_record(
        *, context: RunnerContext, identity: RunnerIdentity, signer: SecureSigner,
        signer_label: str, authority_commit: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "schema_version": "heel.bound-runner-context.v2",
            "namespace": context.namespace,
            "context": context.as_dict(),
            "identity": _identity_record(identity, signer),
            "signer_label": _id(signer_label, "runner signer label"),
            "authority_mode": "cloud",
            "authority_commit_digest": _digest(
                authority_commit["record_digest"], "cloud authority commit digest",
            ),
        }

    @staticmethod
    def _cloud_active_context_record(
        *, context: RunnerContext, identity: RunnerIdentity, signer: SecureSigner,
        authority_commit_digest: str,
    ) -> dict[str, Any]:
        core = {
            "schema_version": _ACTIVE_CONTEXT_CLOUD_SCHEMA,
            "namespace": context.namespace,
            "workspace_id": identity.workspace_id,
            "runner_id": identity.runner_id,
            "runner_key_id": identity.key_id,
            "authority_mode": "cloud",
            "authority_commit_digest": _digest(
                authority_commit_digest, "cloud authority commit digest",
            ),
        }
        return {
            **core, "signing_key_id": signer.key_id,
            "signature_b64": base64.b64encode(
                signer.sign(_ACTIVE_CONTEXT_CLOUD_DOMAIN + canonical_bytes(core))
            ).decode("ascii"),
        }

    @staticmethod
    def _validate_cloud_active_context_record(
        value: object, *, binding: Mapping[str, Any], allow_prior_commit: bool = False,
    ) -> None:
        fields = {
            "schema_version", "namespace", "workspace_id", "runner_id", "runner_key_id",
            "authority_mode", "authority_commit_digest", "signing_key_id", "signature_b64",
        }
        try:
            if (
                not isinstance(value, Mapping) or set(value) != fields
                or value["schema_version"] != _ACTIVE_CONTEXT_CLOUD_SCHEMA
                or value["authority_mode"] != "cloud"
                or value["namespace"] != binding["namespace"]
                or (not allow_prior_commit and value["authority_commit_digest"] != binding["authority_commit_digest"])
            ):
                raise ValueError
            identity = binding["identity"]
            if (
                value["workspace_id"] != identity["workspace_id"]
                or value["runner_id"] != identity["runner_id"]
                or value["runner_key_id"] != identity["runner_key_id"]
            ):
                raise ValueError
            core = {key: value[key] for key in fields - {"signing_key_id", "signature_b64"}}
            verify_envelope(
                {identity["runner_key_id"]: load_public_key_base64(identity["public_key_b64"])},
                {"signing_key_id": value["signing_key_id"], "signature_b64": value["signature_b64"]},
                _ACTIVE_CONTEXT_CLOUD_DOMAIN + canonical_bytes(core),
            )
        except (KeyError, TypeError, ValueError):
            raise RunnerStoreError("cloud context authority is incomplete") from None

    def _selected_rollover_prefix_locked(
        self, context_fd: int, *, active: Mapping[str, Any], binding: Mapping[str, Any],
    ) -> bool:
        """Allow only the signed selector-old/binding-new recovery prefix."""
        try:
            if binding["schema_version"] != "heel.bound-runner-context.v2":
                return False
            identity = self._rotation_identity_from_record(
                binding["identity"], pairing_phrase=(),
            )
            context = _context_from_dict(binding["context"])
            raw_journal = _read_json(context_fd, "context-rollover.json", None)
            if not isinstance(raw_journal, Mapping):
                return False
            artifact = validate_runner_context_binding(raw_journal["artifact"])
            journal = self._validate_context_rollover_journal(
                raw_journal,
                identity=identity, expected_artifact=artifact,
                expected_evidence=None, expected_context=context,
            )
            if journal["new_authority_commit"]["record_digest"] != binding["authority_commit_digest"]:
                return False
            if active.get("schema_version") == "heel.active-runner-context.v1":
                return (
                    active == {"schema_version": "heel.active-runner-context.v1", "namespace": binding["namespace"]}
                    and journal["old_authority_commit_digest"] is None
                    and journal["old_binding_id"] is None
                    and journal["old_binding_digest"] is None
                )
            return (
                active.get("schema_version") == _ACTIVE_CONTEXT_CLOUD_SCHEMA
                and active.get("authority_commit_digest") == journal["old_authority_commit_digest"]
                and active.get("namespace") == binding["namespace"]
            )
        except (KeyError, TypeError, ValueError, RunnerStoreError):
            return False

    def _validate_cloud_context_authority_locked(
        self, context_fd: int, binding: Mapping[str, Any],
    ) -> None:
        """Validate the independent durable Cloud tuple, never a file-existence hint."""
        try:
            context = _context_from_dict(binding["context"])
            identity = _stored_identity_record(binding["identity"])
            commit_digest = _digest(binding["authority_commit_digest"], "cloud authority commit digest")
            if binding.get("authority_mode") != "cloud":
                raise ValueError
            commit = self._validate_cloud_authority_commit(
                _read_json(context_fd, self._cloud_authority_commit_filename(commit_digest), None),
                expected_digest=commit_digest, namespace=self.namespace,
                context=context, identity=identity,
            )
            sidecar = validate_runner_context_binding(
                _read_json(context_fd, "cloud-context-binding.json", None),
            )
            provenance = self._validate_cloud_context_provenance(
                _read_json(context_fd, "cloud-context-provenance.json", None),
            )
            if (
                commit["binding_id"] != sidecar["binding_id"]
                or commit["binding_digest"] != sidecar["binding_digest"]
                or provenance["binding_id"] != commit["binding_id"]
                or provenance["binding_digest"] != commit["binding_digest"]
                or commit["context"] != binding["context"]
                or commit["identity"] != binding["identity"]
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError, RunnerStoreError):
            raise RunnerStoreError("cloud context authority is incomplete") from None

    def _validated_cloud_context_binding(
        self, artifact: object, *, identity: RunnerIdentity, trusted_cloud_keys: Mapping[str, object],
        now_ms: int, require_current: bool = True,
    ) -> tuple[dict[str, Any], RunnerContext]:
        try:
            binding = validate_runner_context_binding(artifact)
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid cloud context binding") from None
        if not isinstance(trusted_cloud_keys, Mapping) or not trusted_cloud_keys:
            raise RunnerStoreError("cloud context authority is unavailable")
        if type(now_ms) is not int or isinstance(now_ms, bool):
            raise RunnerStoreError("invalid cloud context time")
        unsigned = {key: binding[key] for key in ("schema_version", "binding_id", "workspace_id", "project_id", "environment", "runner_binding", "authorization", "issued_at_ms", "expires_at_ms")}
        try:
            verify_envelope(dict(trusted_cloud_keys), {"signing_key_id": binding["signing_key_id"], "signature_b64": binding["signature_b64"]}, _CONTEXT_DOMAIN + canonical_bytes(unsigned))
            public = base64.b64decode(identity.public_key_b64, validate=True)
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid cloud context signature") from None
        runner, environment = binding["runner_binding"], binding["environment"]
        if (binding["workspace_id"] != identity.workspace_id or runner["runner_id"] != identity.runner_id
                or runner["runner_key_id"] != identity.key_id or len(public) != 32
                or hashlib.sha256(public).hexdigest() != runner["public_key_digest"]
                or binding["issued_at_ms"] > now_ms + 30_000
                or (require_current and now_ms >= binding["expires_at_ms"])):
            raise RunnerStoreError("cloud context binding does not match local runner")
        return binding, RunnerContext(workspace_id=binding["workspace_id"], project_id=binding["project_id"], environment_id=environment["environment_id"], origin=environment["origin"], verification_record_digest=environment["verification_record_digest"], environment_class=environment["environment_class"])

    def load_cloud_context_binding(self) -> dict[str, Any]:
        with self._transaction(exclusive=False) as context_fd:
            value = _read_json(context_fd, "cloud-context-binding.json", None)
            try:
                return validate_runner_context_binding(value)
            except (TypeError, ValueError):
                raise RunnerStoreError("invalid cloud context binding") from None

    def load_cloud_context_binding_for_recovery(self) -> dict[str, Any]:
        """Read a sidecar only to correlate a signed journal recovery; never for execution."""
        with self._transaction(exclusive=False, allow_rollover_journal=True) as context_fd:
            value = _read_json(context_fd, "cloud-context-binding.json", None)
            try:
                return validate_runner_context_binding(value)
            except (TypeError, ValueError):
                raise RunnerStoreError("invalid cloud context binding") from None

    def has_cloud_context_binding(self) -> bool:
        with self._transaction(exclusive=False) as context_fd:
            return _read_json(context_fd, "cloud-context-binding.json", None) is not None

    def has_cloud_context_provenance(self) -> bool:
        """Return Cloud mode only after validating its complete durable tuple."""
        with self._transaction(exclusive=False, allow_rollover_journal=True) as context_fd:
            binding = self._binding_locked(context_fd)
            if binding["schema_version"] == "heel.bound-runner-context.v2":
                # `_binding_locked` has already validated commit, sidecar and provenance.
                return True
            if (
                _read_json(context_fd, "cloud-context-provenance.json", None) is not None
                or _read_json(context_fd, "cloud-context-binding.json", None) is not None
                or _read_json(context_fd, "context-rollover.json", None) is not None
            ):
                raise RunnerStoreError("cloud context authority is incomplete")
            return False

    def verify_cloud_context_binding(
        self, *, identity: RunnerIdentity, trusted_cloud_keys: Mapping[str, object], now_ms: int,
    ) -> dict[str, Any]:
        """Reverify the sidecar at every use; disk contents are never a trust decision."""
        binding = self.load_cloud_context_binding()
        with self._transaction(exclusive=False) as context_fd:
            provenance = _read_json(context_fd, "cloud-context-provenance.json", None)
        if provenance is not None:
            checked_provenance = self._validate_cloud_context_provenance(provenance)
            if (
                checked_provenance["binding_id"] != binding["binding_id"]
                or checked_provenance["binding_digest"] != binding["binding_digest"]
            ):
                raise RunnerStoreError("cloud context provenance does not match sidecar")
        if not isinstance(trusted_cloud_keys, Mapping) or not trusted_cloud_keys:
            raise RunnerStoreError("cloud context authority is unavailable")
        if type(now_ms) is not int or isinstance(now_ms, bool):
            raise RunnerStoreError("invalid cloud context time")
        unsigned = {key: binding[key] for key in (
            "schema_version", "binding_id", "workspace_id", "project_id", "environment",
            "runner_binding", "authorization", "issued_at_ms", "expires_at_ms",
        )}
        try:
            verify_envelope(dict(trusted_cloud_keys), {
                "signing_key_id": binding["signing_key_id"], "signature_b64": binding["signature_b64"],
            }, _CONTEXT_DOMAIN + canonical_bytes(unsigned))
            public = base64.b64decode(identity.public_key_b64, validate=True)
            context = self.load_context()
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid cloud context binding") from None
        runner = binding["runner_binding"]
        environment = binding["environment"]
        if (
            binding["workspace_id"] != identity.workspace_id or runner["runner_id"] != identity.runner_id
            or runner["runner_key_id"] != identity.key_id or len(public) != 32
            or hashlib.sha256(public).hexdigest() != runner["public_key_digest"]
            or binding["issued_at_ms"] > now_ms + 30_000 or now_ms >= binding["expires_at_ms"]
            or context != RunnerContext(workspace_id=binding["workspace_id"], project_id=binding["project_id"],
                                        environment_id=environment["environment_id"], origin=environment["origin"],
                                        verification_record_digest=environment["verification_record_digest"],
                                        environment_class=environment["environment_class"])
        ):
            raise RunnerStoreError("cloud context binding does not match local runner")
        return binding

    def _binding_locked(self, context_fd: int, *, validate_cloud: bool = True) -> dict[str, Any]:
        value = _read_json(context_fd, "binding.json", None)
        static_fields = {"schema_version", "namespace", "context", "identity", "signer_label"}
        cloud_fields = static_fields | {"authority_mode", "authority_commit_digest"}
        if not isinstance(value, Mapping):
            raise RunnerStoreError("invalid bound runner context")
        schema = value.get("schema_version")
        if schema == "heel.bound-runner-context.v1":
            if set(value) != static_fields:
                raise RunnerStoreError("invalid bound runner context")
        elif schema == "heel.bound-runner-context.v2":
            if set(value) != cloud_fields or value.get("authority_mode") != "cloud":
                raise RunnerStoreError("invalid bound runner context")
        else:
            raise RunnerStoreError("invalid bound runner context")
        if value["namespace"] != self.namespace:
            raise RunnerStoreError("runner namespace mismatch")
        context = _context_from_dict(value["context"])
        if context.namespace != self.namespace:
            raise RunnerStoreError("runner context namespace mismatch")
        identity = _stored_identity_record(value["identity"])
        if identity["workspace_id"] != context.workspace_id:
            raise RunnerStoreError("runner identity context mismatch")
        signer_label = _id(value["signer_label"], "runner signer label")
        result = {**dict(value), "identity": identity, "signer_label": signer_label}
        if schema == "heel.bound-runner-context.v2" and validate_cloud:
            self._validate_cloud_context_authority_locked(context_fd, result)
        return result

    def _validate_binding_locked(self, context_fd: int) -> None:
        self._binding_locked(context_fd)

    def load_context(self) -> RunnerContext:
        with self._transaction(exclusive=False) as context_fd:
            return _context_from_dict(self._binding_locked(context_fd)["context"])

    def load_binding(self) -> dict[str, Any]:
        with self._transaction(exclusive=False) as context_fd:
            return self._binding_locked(context_fd)

    def _envelope(
        self, context_fd: int, schema: str, payload_field: str, payload: Any,
    ) -> dict[str, Any]:
        context = _context_from_dict(self._binding_locked(context_fd)["context"])
        return {
            "schema_version": schema,
            "namespace": self.namespace,
            "origin": context.origin,
            "verification_record_digest": context.verification_record_digest,
            payload_field: payload,
        }

    def _validate_envelope(
        self, context_fd: int, value: Any, *, schema: str, payload_field: str,
    ) -> Any:
        fields = {
            "schema_version", "namespace", "origin", "verification_record_digest", payload_field,
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise RunnerStoreError("invalid context-bound runner state")
        context = _context_from_dict(self._binding_locked(context_fd)["context"])
        if (
            value["schema_version"] != schema
            or value["namespace"] != self.namespace
            or value["origin"] != context.origin
            or value["verification_record_digest"] != context.verification_record_digest
        ):
            raise RunnerStoreError("runner state context mismatch")
        return value[payload_field]

    def replace_routes(self, routes: list[Mapping[str, Any]], *, source_digest: str) -> None:
        source_digest = _digest(source_digest, "OpenAPI source digest")
        normalized = [_route_record(route, require_canonical=False) for route in routes]
        normalized.sort(key=lambda item: (item["route_template"], item["method"], item["operation_id"]))
        coordinates = [(item["method"], item["route_template"]) for item in normalized]
        if len(normalized) > 2000 or len(coordinates) != len(set(coordinates)):
            raise ValueError("invalid read route inventory")
        payload = {"source_digest": source_digest, "routes": normalized}
        with self._transaction(exclusive=True) as context_fd:
            envelope = self._envelope(
                context_fd, "heel.runner-route-inventory.v1", "inventory", payload,
            )
            _write_json(context_fd, "routes.json", envelope)

    def list_routes(self) -> list[dict[str, Any]]:
        with self._transaction(exclusive=False) as context_fd:
            return self._routes_locked(context_fd)

    def _routes_locked(self, context_fd: int) -> list[dict[str, Any]]:
        value = _read_json(context_fd, "routes.json", None)
        if value is None:
            return []
        payload = self._validate_envelope(
            context_fd, value,
            schema="heel.runner-route-inventory.v1", payload_field="inventory",
        )
        if not isinstance(payload, Mapping) or set(payload) != {"source_digest", "routes"}:
            raise RunnerStoreError("invalid route inventory")
        _digest(payload["source_digest"], "OpenAPI source digest")
        if not isinstance(payload["routes"], list) or len(payload["routes"]) > 2000:
            raise RunnerStoreError("invalid route inventory")
        result = [_route_record(route, require_canonical=True) for route in payload["routes"]]
        expected = sorted(result, key=lambda item: (item["route_template"], item["method"], item["operation_id"]))
        if result != expected:
            raise RunnerStoreError("route inventory is not canonical")
        return result

    def save_mapping(
        self,
        scenario_id: str,
        *,
        method: str,
        route_template: str,
        fixture_bindings: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        route, placeholders = normalize_route_template(route_template)
        bindings = _fixture_bindings(fixture_bindings)
        if {item["parameter_name"] for item in bindings} != set(placeholders):
            raise ValueError("mapping requires exact fixture bindings")
        record = _mapping_record({
            "scenario_id": scenario_id,
            "method": method,
            "route_template": route,
            "fixture_bindings": bindings,
        })
        with self._transaction(exclusive=True) as context_fd:
            routes = {
                (item["method"], item["route_template"])
                for item in self._routes_locked(context_fd)
            }
            if (method, route) not in routes:
                raise ValueError("mapping route is not in the bound inventory")
            normalized = self._mappings_locked(context_fd)
            normalized = [item for item in normalized if item["scenario_id"] != scenario_id]
            normalized.append(record)
            normalized.sort(key=lambda item: CATALOG_BY_ID[item["scenario_id"]]["ordinal"])
            envelope = self._envelope(
                context_fd, "heel.runner-mappings.v1", "mappings", normalized,
            )
            _write_json(context_fd, "mappings.json", envelope)
        return record

    def list_mappings(self) -> list[dict[str, Any]]:
        with self._transaction(exclusive=False) as context_fd:
            return self._mappings_locked(context_fd)

    def _mappings_locked(self, context_fd: int) -> list[dict[str, Any]]:
        raw = _read_json(context_fd, "mappings.json", None)
        if raw is None:
            return []
        records = self._validate_envelope(
            context_fd, raw,
            schema="heel.runner-mappings.v1", payload_field="mappings",
        )
        if not isinstance(records, list) or len(records) > 4:
            raise RunnerStoreError("invalid scenario mappings")
        result = [_mapping_record(item) for item in records]
        expected = sorted(result, key=lambda item: CATALOG_BY_ID[item["scenario_id"]]["ordinal"])
        if result != expected or len({item["scenario_id"] for item in result}) != len(result):
            raise RunnerStoreError("scenario mappings are not canonical")
        return result

    def _credentials_locked(self, context_fd: int) -> list[dict[str, Any]]:
        raw = _read_json(context_fd, "credentials.json", None)
        if raw is None:
            return []
        records = self._validate_envelope(
            context_fd, raw,
            schema="heel.runner-credentials.v1", payload_field="credentials",
        )
        if not isinstance(records, list) or len(records) > 20:
            raise RunnerStoreError("invalid credential metadata")
        result = [_credential_record(item) for item in records]
        expected = sorted(result, key=lambda item: item["semantic_role"])
        if result != expected:
            raise RunnerStoreError("credential metadata is not canonical")
        if len({item["semantic_role"] for item in result}) != len(result):
            raise RunnerStoreError("duplicate credential semantic role")
        if len({item["credential_handle_id"] for item in result}) != len(result):
            raise RunnerStoreError("duplicate credential handle")
        return result

    def _write_credentials_locked(self, context_fd: int, records: list[dict[str, Any]]) -> None:
        records.sort(key=lambda item: item["semantic_role"])
        envelope = self._envelope(
            context_fd, "heel.runner-credentials.v1", "credentials", records,
        )
        _write_json(context_fd, "credentials.json", envelope)

    def list_credentials(self) -> list[dict[str, Any]]:
        with self._transaction(exclusive=False) as context_fd:
            return self._credentials_locked(context_fd)

    @staticmethod
    def _new_credential(
        *, semantic_role: str, auth_profile: str, label: str,
        backend: str, source_kind: str | None, state: str,
    ) -> dict[str, Any]:
        return _credential_record({
            "credential_handle_id": secrets.token_hex(16),
            "semantic_role": semantic_role,
            "auth_profile": auth_profile,
            "label": label,
            "backend": backend,
            "source_kind": source_kind,
            "state": state,
        })

    def register_ephemeral_credential(
        self,
        *,
        semantic_role: str,
        auth_profile: str,
        source_kind: str,
        label: str,
    ) -> dict[str, Any]:
        backend = {"environment": "ephemeral_env", "inherited_fd": "ephemeral_fd"}.get(source_kind)
        if backend is None:
            raise ValueError("ephemeral source must be environment or inherited_fd")
        record = self._new_credential(
            semantic_role=semantic_role, auth_profile=auth_profile, label=label,
            backend=backend, source_kind=source_kind, state="active",
        )
        with self._transaction(exclusive=True) as context_fd:
            records = self._credentials_locked(context_fd)
            if any(item["semantic_role"] == semantic_role for item in records):
                raise ValueError("credential semantic role already registered")
            records.append(record)
            self._write_credentials_locked(context_fd, records)
        return record

    def reserve_os_credential(
        self,
        *, semantic_role: str,
        auth_profile: str,
        label: str,
        backend: str,
    ) -> dict[str, Any]:
        if backend not in {"macos_keychain", "linux_secret_service"}:
            raise ValueError("invalid OS credential backend")
        record = self._new_credential(
            semantic_role=semantic_role, auth_profile=auth_profile, label=label,
            backend=backend, source_kind=None, state="pending",
        )
        with self._transaction(exclusive=True) as context_fd:
            records = self._credentials_locked(context_fd)
            if any(item["semantic_role"] == semantic_role for item in records):
                raise ValueError("credential semantic role already registered")
            records.append(record)
            self._write_credentials_locked(context_fd, records)
        return record

    def _set_credential_state(self, handle_id: str, state: str | None) -> dict[str, Any] | None:
        handle_id = _handle(handle_id)
        if state is not None and state not in _STATES:
            raise ValueError("invalid credential state")
        with self._transaction(exclusive=True) as context_fd:
            records = self._credentials_locked(context_fd)
            found = next((item for item in records if item["credential_handle_id"] == handle_id), None)
            if found is None:
                raise ValueError("credential handle is not registered")
            records = [item for item in records if item["credential_handle_id"] != handle_id]
            if state is not None:
                found = {**found, "state": state}
                records.append(found)
            self._write_credentials_locked(context_fd, records)
            return found

    def activate_credential(self, handle_id: str) -> dict[str, Any]:
        record = self._set_credential_state(handle_id, "active")
        assert record is not None
        return record

    def create_os_credential(
        self,
        *,
        semantic_role: str,
        auth_profile: str,
        label: str,
        vault: object,
        secret: bytes,
    ) -> dict[str, Any]:
        backend = getattr(vault, "backend_id", None)
        if backend not in {"macos_keychain", "linux_secret_service"}:
            raise UnsupportedSecureStorageError("unsupported OS credential vault")
        record = self._new_credential(
            semantic_role=semantic_role,
            auth_profile=auth_profile,
            label=label,
            backend=backend,
            source_kind=None,
            state="pending",
        )
        handle_id = record["credential_handle_id"]
        with self._transaction(exclusive=True) as context_fd:
            records = self._credentials_locked(context_fd)
            if any(item["semantic_role"] == semantic_role for item in records):
                raise ValueError("credential semantic role already registered")
            records.append(record)
            self._write_credentials_locked(context_fd, records)
            attempted = False
            try:
                attempted = True
                vault.store(handle_id, secret)
                active = {**record, "state": "active"}
                records = [
                    active if item["credential_handle_id"] == handle_id else item
                    for item in records
                ]
                self._write_credentials_locked(context_fd, records)
                return active
            except BaseException as primary:
                orphaned = False
                if attempted:
                    try:
                        vault.delete(handle_id)
                    except BaseException as cleanup_error:
                        orphaned = True
                        primary.add_note(f"credential vault rollback failed: {cleanup_error}")
                if orphaned:
                    replacement = {**record, "state": "orphaned"}
                    records = [
                        replacement if item["credential_handle_id"] == handle_id else item
                        for item in records
                    ]
                else:
                    records = [
                        item for item in records
                        if item["credential_handle_id"] != handle_id
                    ]
                try:
                    self._write_credentials_locked(context_fd, records)
                except BaseException as state_error:
                    primary.add_note(f"credential lifecycle persistence failed: {state_error}")
                raise

    def recover_credentials(self, vaults: Mapping[str, object]) -> None:
        for record in list(self.list_credentials()):
            if record["state"] not in {"pending", "orphaned"}:
                continue
            vault = vaults.get(record["backend"])
            if vault is None or getattr(vault, "supported", False) is not True:
                continue
            handle_id = record["credential_handle_id"]
            if record["state"] == "pending":
                if vault.exists(handle_id):
                    self.activate_credential(handle_id)
                else:
                    self._set_credential_state(handle_id, None)
            else:
                try:
                    vault.delete(handle_id)
                except Exception:
                    continue
                self._set_credential_state(handle_id, None)

    def _assert_contract_context(self, manifest: Mapping[str, Any], projection: Mapping[str, Any]) -> None:
        context = self.load_context()
        binding = self.load_binding()["identity"]
        expected_environment = {
            "environment_id": context.environment_id,
            "verification_record_digest": context.verification_record_digest,
            "origin": context.origin,
            "environment_class": context.environment_class,
        }
        if (
            manifest["workspace_id"] != context.workspace_id
            or manifest["project_id"] != context.project_id
            or manifest["environment"] != expected_environment
            or projection["workspace_id"] != context.workspace_id
            or projection["project_id"] != context.project_id
            or projection["environment"] != expected_environment
            or manifest["runner"]["runner_id"] != binding["runner_id"]
            or manifest["runner"]["runner_key_id"] != binding["runner_key_id"]
            or projection["runner"]["runner_id"] != binding["runner_id"]
            or projection["runner"]["runner_key_id"] != binding["runner_key_id"]
            or manifest["runner"]["minimum_runner_version"] != binding["runner_version"]
            or projection["runner"]["runner_version"] != binding["runner_version"]
            or manifest["compiler"] != {"compiler_version": "1", "engine_version": "1"}
            or projection["compiler"] != manifest["compiler"]
        ):
            raise RunnerStoreError("compiled pair does not match bound runner context")
        expected_adapters = []
        for scenario in manifest["scenarios"]:
            expected = binding["adapter_versions"].get(scenario["scenario_id"])
            if expected is None or scenario["adapter_version"] != expected:
                raise RunnerStoreError("compiled pair adapter version mismatch")
            expected_adapters.append(expected)
        if projection["scenarios"] != manifest["scenarios"] or projection["runner"][
            "adapter_versions"
        ] != sorted(set(expected_adapters)):
            raise RunnerStoreError("compiled pair adapter version mismatch")
        expected_actions = [{
            key: value
            for key, value in action.items()
            if key not in {"fixture_bindings", "auth_profile"}
        } for action in manifest["actions"]]
        if (
            projection["actions"] != expected_actions
            or projection["budgets"] != manifest["budgets"]
            or projection["egress"] != manifest["egress"]
            or projection["retry_policy"] != manifest["retry_policy"]
            or projection["compiled_at_ms"] != manifest["compiled_at_ms"]
        ):
            raise RunnerStoreError("approval projection is not derived from full manifest")
        unsigned = {
            key: value for key, value in projection.items()
            if key not in {"projection_digest", "signing_key_id", "signature_b64"}
        }
        try:
            public_key = load_public_key_base64(binding["public_key_b64"])
            verify_envelope(
                {binding["runner_key_id"]: public_key},
                {
                    "signing_key_id": projection["signing_key_id"],
                    "signature_b64": projection["signature_b64"],
                },
                canonical_bytes(unsigned),
            )
        except (TypeError, ValueError):
            raise RunnerStoreError("approval projection signature is invalid") from None

    def save_approved_pair(self, manifest: Mapping[str, Any], projection: Mapping[str, Any]) -> None:
        manifest = validate_test_manifest(manifest)
        projection = validate_approval_projection(projection)
        if projection["manifest_digest"] != manifest["manifest_digest"]:
            raise ValueError("approval projection does not bind the full manifest")
        self._assert_contract_context(manifest, projection)
        manifest_digest = manifest["manifest_digest"]
        projection_id = _id(projection["projection_id"], "projection ID")
        with self._transaction(exclusive=True) as context_fd:
            manifests_fd = _open_child(context_fd, "manifests", create=True)
            projections_fd = _open_child(context_fd, "projections", create=True)
            assert manifests_fd is not None and projections_fd is not None
            try:
                _secure_directory(manifests_fd, "Heel runner manifests directory")
                _secure_directory(projections_fd, "Heel runner projections directory")
                manifest_wrapper = self._envelope(
                    context_fd, "heel.stored-test-manifest.v1", "manifest", manifest,
                )
                projection_wrapper = self._envelope(
                    context_fd, "heel.stored-approval-projection.v1", "projection", projection,
                )
                for directory_fd, filename, wrapper in (
                    (manifests_fd, f"{manifest_digest}.json", manifest_wrapper),
                    (projections_fd, f"{projection_id}.json", projection_wrapper),
                ):
                    existing = _read_json(directory_fd, filename, None)
                    if existing is not None and existing != wrapper:
                        raise RunnerStoreError("immutable compiled artifact collision")
                    if existing is None:
                        _write_json(directory_fd, filename, wrapper)
            finally:
                os.close(manifests_fd)
                os.close(projections_fd)

    def load_manifest(self, manifest_digest: str) -> dict[str, Any]:
        manifest_digest = _digest(manifest_digest, "manifest digest")
        with self._transaction(exclusive=False) as context_fd:
            directory_fd = _open_child(context_fd, "manifests", create=False)
            if directory_fd is None:
                raise RunnerStoreError("manifest is not stored")
            try:
                wrapper = _read_json(directory_fd, f"{manifest_digest}.json", None)
                if wrapper is not None:
                    manifest = self._validate_envelope(
                        context_fd, wrapper,
                        schema="heel.stored-test-manifest.v1", payload_field="manifest",
                    )
            finally:
                os.close(directory_fd)
        if wrapper is None:
            raise RunnerStoreError("manifest is not stored")
        manifest = validate_test_manifest(manifest)
        if manifest["manifest_digest"] != manifest_digest:
            raise RunnerStoreError("stored manifest digest mismatch")
        return manifest

    def load_projection(self, projection_id: str) -> dict[str, Any]:
        projection_id = _id(projection_id, "projection ID")
        with self._transaction(exclusive=False) as context_fd:
            directory_fd = _open_child(context_fd, "projections", create=False)
            if directory_fd is None:
                raise RunnerStoreError("projection is not stored")
            try:
                wrapper = _read_json(directory_fd, f"{projection_id}.json", None)
                if wrapper is not None:
                    projection = self._validate_envelope(
                        context_fd, wrapper,
                        schema="heel.stored-approval-projection.v1", payload_field="projection",
                    )
            finally:
                os.close(directory_fd)
        if wrapper is None:
            raise RunnerStoreError("projection is not stored")
        projection = validate_approval_projection(projection)
        if projection["projection_id"] != projection_id:
            raise RunnerStoreError("stored projection ID mismatch")
        return projection

    def load_approved_pair(self, projection_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        projection = self.load_projection(projection_id)
        manifest = self.load_manifest(projection["manifest_digest"])
        self._assert_contract_context(manifest, projection)
        return manifest, projection

    @staticmethod
    def _run_hash(run_id: str) -> str:
        return hashlib.sha256(_id(run_id, "run ID").encode("utf-8")).hexdigest()

    def run_path(self, run_id: str) -> Path:
        """Return the opaque local run path; no customer-controlled name becomes a path segment."""
        return (
            self.root / "runner" / "contexts" / self.namespace / "runs"
            / self._run_hash(run_id)
        )

    @contextmanager
    def _open_run(self, context_fd: int, run_id: str, *, create: bool) -> Iterator[int]:
        run_hash = self._run_hash(run_id)
        runs_fd = _open_child(context_fd, "runs", create=create)
        if runs_fd is None:
            raise RunnerStoreError("local run is unavailable")
        run_fd = -1
        try:
            _secure_directory(runs_fd, "Heel runner runs directory")
            opened = _open_child(runs_fd, run_hash, create=create)
            if opened is None:
                raise RunnerStoreError("local run is unavailable")
            run_fd = opened
            _secure_directory(run_fd, "Heel local run directory")
            yield run_fd
        finally:
            if run_fd >= 0:
                os.close(run_fd)
            os.close(runs_fd)

    def _run_state_locked(self, run_fd: int, run_id: str) -> dict[str, Any]:
        value = _read_json(run_fd, "state.json", None)
        fields = {
            "schema_version", "run_id", "grant_id", "grant_digest", "manifest_digest",
            "runner_authority", "state", "retention_expires_at_ms", "updated_at_ms",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise RunnerStoreError("invalid local run state")
        if (
            value["schema_version"] != "heel.local-run-state.v1"
            or value["run_id"] != run_id
            or value["state"] not in _RUN_STATES
        ):
            raise RunnerStoreError("invalid local run state")
        _id(value["grant_id"], "grant ID")
        _digest(value["grant_digest"], "grant digest")
        _digest(value["manifest_digest"], "manifest digest")
        authority = value["runner_authority"]
        if not isinstance(authority, Mapping) or set(authority) != {
            "runner_key_id", "public_key_b64", "public_key_digest",
        }:
            raise RunnerStoreError("invalid reserved runner authority")
        try:
            public_key = base64.b64decode(authority["public_key_b64"], validate=True)
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid reserved runner authority") from None
        if (
            len(public_key) != 32
            or _id(authority["runner_key_id"], "runner key ID")
            != ed25519_key_id(public_key)
            or _digest(authority["public_key_digest"], "runner public key digest")
            != hashlib.sha256(public_key).hexdigest()
        ):
            raise RunnerStoreError("invalid reserved runner authority")
        for field in ("retention_expires_at_ms", "updated_at_ms"):
            moment = value[field]
            if isinstance(moment, bool) or not isinstance(moment, int) or moment < 0:
                raise RunnerStoreError("invalid local run timestamp")
        return dict(value)

    def reserve_run(
        self, grant: Mapping[str, Any], *, retention_expires_at_ms: int,
    ) -> dict[str, Any]:
        """Atomically consume one exact grant into a new local run namespace."""
        identity, signer = self._require_runtime_authority()
        grant = validate_execution_grant(grant)
        if (
            isinstance(retention_expires_at_ms, bool)
            or not isinstance(retention_expires_at_ms, int)
            or retention_expires_at_ms <= grant["issued_at_ms"]
        ):
            raise ValueError("invalid local run retention")
        manifest, projection = self.load_approved_pair(grant["approval"]["projection_id"])
        context = self.load_context()
        binding = self.load_binding()["identity"]
        if (
            grant["workspace_id"] != context.workspace_id
            or grant["project_id"] != context.project_id
            or grant["environment"] != manifest["environment"]
            or grant["approval"] != {
                "projection_id": projection["projection_id"],
                "projection_digest": projection["projection_digest"],
                "manifest_digest": manifest["manifest_digest"],
            }
            or grant["runner_binding"]["runner_id"] != binding["runner_id"]
            or grant["runner_binding"]["runner_key_id"] != binding["runner_key_id"]
        ):
            raise RunnerStoreError("execution grant does not match bound local artifacts")
        run_id = grant["run_id"]
        state = {
            "schema_version": "heel.local-run-state.v1",
            "run_id": run_id,
            "grant_id": grant["grant_id"],
            "grant_digest": grant["grant_digest"],
            "manifest_digest": manifest["manifest_digest"],
            "runner_authority": {
                "runner_key_id": binding["runner_key_id"],
                "public_key_b64": binding["public_key_b64"],
                "public_key_digest": binding["fingerprint"],
            },
            "state": "verified",
            "retention_expires_at_ms": retention_expires_at_ms,
            "updated_at_ms": grant["issued_at_ms"],
        }
        with self._transaction(exclusive=True) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=True)
            assert runs_fd is not None
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                self._complete_run_authority_journal_locked(
                    context_fd, runs_fd, identity=identity,
                )
                index = self._run_authority_index_locked(runs_fd, identity=identity)
                run_hash = self._run_hash(run_id)
                consumed_name = f"grant-{grant['grant_digest']}.json"
                marker = {
                    "schema_version": _RESERVATION_SCHEMA,
                    "grant": grant,
                    "initial_state": state,
                }
                existing_marker = _read_json(runs_fd, consumed_name, None)
                reservation_name = self._run_authority_record_filename("reserve", run_hash)
                if existing_marker is not None:
                    if existing_marker != marker:
                        raise ValueError("execution grant was already consumed")
                    record = _read_json(runs_fd, reservation_name, None)
                    if record is None:
                        raise RunnerStoreError("local run authority reservation is unavailable")
                    record = self._verify_signed_run_authority_value(
                        record, identity=identity, schema=_RUN_RESERVATION_RECORD_SCHEMA,
                        record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                    )
                    tracked = next(
                        (item for item in index["nonterminal_runs"] if item["run_hash"] == run_hash),
                        None,
                    )
                    terminal = next(
                        (item for item in index["terminal_queue"] if item["run_hash"] == run_hash),
                        None,
                    )
                    if (
                        tracked is None
                        or tracked["reservation_record_digest"] != record["record_digest"]
                        or terminal is not None
                    ):
                        raise RunnerStoreError("local run authority reservation is unavailable")
                    with self._open_run(context_fd, run_id, create=False) as run_fd:
                        current = self._run_state_locked(run_fd, run_id)
                        if current["state"] not in {"verified", "running", "stop_requested", "finalizing"}:
                            raise RunnerStoreError("local run authority reservation is unavailable")
                        return current
                if len(index["nonterminal_runs"]) >= _RUN_AUTHORITY_MAX_NONTERMINAL:
                    raise RunnerStoreError("local run authority capacity is exhausted")
                record = self._run_authority_record(
                    operation="reserve", context=context, identity=identity, signer=signer,
                    run_hash=run_hash, grant=grant, state=state, index=index,
                )
                next_index = self._next_run_authority_index(
                    index, signer=signer, delta=1, head_digest=record["record_digest"],
                    nonterminal_runs=sorted([
                        *index["nonterminal_runs"],
                        {
                            "run_hash": run_hash,
                            "reservation_record_digest": record["record_digest"],
                        },
                    ], key=lambda item: item["run_hash"]),
                )
                journal = self._run_authority_journal(
                    context=context, identity=identity, signer=signer, operation="reserve",
                    run_hash=run_hash, index=index, next_index=next_index, record=record,
                    recovery={"grant": grant, "initial_state": state},
                    created_at_ms=grant["issued_at_ms"],
                )
                _write_json(runs_fd, _RUN_AUTHORITY_JOURNAL_FILENAME, journal)
                self._ensure_json_exact(runs_fd, consumed_name, marker)
                run_fd = _open_child(runs_fd, run_hash, create=True)
                assert run_fd is not None
                try:
                    _secure_directory(run_fd, "Heel local run directory")
                    self._ensure_json_exact(run_fd, "grant.json", grant)
                    self._ensure_json_exact(run_fd, "state.json", state)
                finally:
                    os.close(run_fd)
                self._ensure_json_exact(runs_fd, reservation_name, record)
                _write_json(runs_fd, _RUN_AUTHORITY_INDEX_FILENAME, next_index)
                os.unlink(_RUN_AUTHORITY_JOURNAL_FILENAME, dir_fd=runs_fd)
                os.fsync(runs_fd)
            finally:
                os.close(runs_fd)
        return state

    def recover_run_reservation(self, run_id: str) -> dict[str, Any]:
        """Read committed run authority; only a still-present reserve journal may repair files."""
        run_id = _id(run_id, "run ID")
        identity, _signer = self._require_runtime_authority()
        with self._transaction(exclusive=True) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=False)
            if runs_fd is None:
                raise RunnerStoreError("local run reservation is unavailable")
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                self._complete_run_authority_journal_locked(
                    context_fd, runs_fd, identity=identity,
                )
                index = self._run_authority_index_locked(runs_fd, identity=identity)
                run_hash = self._run_hash(run_id)
                reservation_value = _read_json(
                    runs_fd, self._run_authority_record_filename("reserve", run_hash), None,
                )
                if reservation_value is None:
                    raise RunnerStoreError("local run reservation is unavailable")
                reservation = self._verify_signed_run_authority_value(
                    reservation_value, identity=identity, schema=_RUN_RESERVATION_RECORD_SCHEMA,
                    record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                )
                marker = _read_json(runs_fd, f"grant-{reservation.get('grant_digest')}.json", None)
                if (
                    not isinstance(marker, Mapping) or set(marker) != {
                        "schema_version", "grant", "initial_state",
                    } or marker["schema_version"] != _RESERVATION_SCHEMA
                ):
                    raise RunnerStoreError("invalid local run reservation journal")
                try:
                    grant = validate_execution_grant(marker["grant"])
                except (TypeError, ValueError):
                    raise RunnerStoreError("invalid local run reservation journal") from None
                initial_state = marker["initial_state"]
                if (
                    grant["run_id"] != run_id or reservation.get("run_hash") != run_hash
                    or reservation.get("grant_id") != grant["grant_id"]
                    or reservation.get("grant_digest") != grant["grant_digest"]
                    or not isinstance(initial_state, Mapping) or initial_state.get("run_id") != run_id
                    or initial_state.get("state") != "verified"
                    or reservation.get("initial_state_digest") != canonical_digest(dict(initial_state))
                ):
                    raise RunnerStoreError("invalid local run reservation journal")

                terminal_value = _read_json(
                    runs_fd, self._run_authority_record_filename("terminal", run_hash), None,
                )
                pruned_value = _read_json(
                    runs_fd, self._run_authority_record_filename("prune", run_hash), None,
                )
                nonterminal = next(
                    (item for item in index["nonterminal_runs"] if item["run_hash"] == run_hash),
                    None,
                )
                terminal_item = next(
                    (item for item in index["terminal_queue"] if item["run_hash"] == run_hash),
                    None,
                )
                if pruned_value is not None:
                    pruned = self._verify_signed_run_authority_value(
                        pruned_value, identity=identity, schema=_RUN_PRUNED_RECORD_SCHEMA,
                        record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                    )
                    pruned_run_fd = _open_child(runs_fd, run_hash, create=False)
                    if pruned_run_fd is not None:
                        os.close(pruned_run_fd)
                        raise RunnerStoreError("local run authority recovery is invalid")
                    if terminal_value is None or nonterminal is not None or terminal_item is not None:
                        raise RunnerStoreError("local run authority recovery is invalid")
                    terminal = self._verify_signed_run_authority_value(
                        terminal_value, identity=identity, schema=_RUN_TERMINAL_RECORD_SCHEMA,
                        record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                    )
                    if (
                        terminal.get("reservation_record_digest") != reservation["record_digest"]
                        or pruned.get("terminal_record_digest") != terminal["record_digest"]
                        or pruned.get("terminal_projection_digest") != terminal.get("terminal_projection_digest")
                        or pruned.get("run_hash") != run_hash
                    ):
                        raise RunnerStoreError("local run authority recovery is invalid")
                    raise RunnerStoreError("local run reservation is unavailable")

                if terminal_value is not None:
                    terminal = self._verify_signed_run_authority_value(
                        terminal_value, identity=identity, schema=_RUN_TERMINAL_RECORD_SCHEMA,
                        record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                    )
                    if (
                        nonterminal is not None or terminal_item is None
                        or terminal_item["terminal_record_digest"] != terminal["record_digest"]
                        or terminal.get("reservation_record_digest") != reservation["record_digest"]
                    ):
                        raise RunnerStoreError("local run authority recovery is invalid")
                    run_fd = _open_child(runs_fd, run_hash, create=False)
                    if run_fd is None:
                        raise RunnerStoreError("terminal local run is unavailable")
                    try:
                        _secure_directory(run_fd, "Heel terminal local run directory")
                        if _read_json(run_fd, "grant.json", None) != grant:
                            raise RunnerStoreError("terminal local run is unavailable")
                        recovered = self._run_state_locked(run_fd, run_id)
                        finals = _read_json(run_fd, "finals.json", None)
                        final_fields = {
                            "schema_version", "operational_projection", "findings_projection",
                            "local_view", "disclosure_preview", "finals_digest",
                        }
                        if (
                            recovered["state"] != "terminal"
                            or not isinstance(finals, Mapping) or set(finals) != final_fields
                            or finals.get("schema_version") != _FINALS_SCHEMA
                            or finals.get("finals_digest") != canonical_digest({
                                key: finals[key] for key in finals if key != "finals_digest"
                            })
                            or terminal.get("terminal_state_digest") != canonical_digest(recovered)
                        ):
                            raise RunnerStoreError("terminal local run is unavailable")
                        try:
                            operational = validate_operational_run(finals["operational_projection"])
                        except (TypeError, ValueError):
                            raise RunnerStoreError("terminal local run is unavailable") from None
                        if terminal.get("terminal_projection_digest") != operational["projection_digest"]:
                            raise RunnerStoreError("terminal local run is unavailable")
                        return recovered
                    finally:
                        os.close(run_fd)

                if (
                    nonterminal is None
                    or nonterminal["reservation_record_digest"] != reservation["record_digest"]
                    or terminal_item is not None
                ):
                    raise RunnerStoreError("local run authority recovery is invalid")
                run_fd = _open_child(runs_fd, run_hash, create=False)
                if run_fd is None:
                    raise RunnerStoreError("local run reservation is unavailable")
                try:
                    _secure_directory(run_fd, "Heel local run directory")
                    if _read_json(run_fd, "grant.json", None) != grant:
                        raise RunnerStoreError("local run reservation is unavailable")
                    recovered = self._run_state_locked(run_fd, run_id)
                    if recovered["state"] not in {"verified", "running", "stop_requested", "finalizing"}:
                        raise RunnerStoreError("local run reservation is unavailable")
                    return recovered
                finally:
                    os.close(run_fd)
            finally:
                os.close(runs_fd)

    def upgrade_legacy_run_authority_index(self) -> None:
        """Perform the one explicit, authenticated audit for a pre-ledger run tree."""
        identity, signer = self._require_runtime_authority()
        with self._transaction(exclusive=True) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=False)
            if runs_fd is None:
                raise RunnerStoreError("local run authority index is unavailable")
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                if _read_json(runs_fd, _RUN_AUTHORITY_JOURNAL_FILENAME, None) is not None:
                    raise RunnerStoreError("local run authority upgrade requires journal recovery")
                existing_index = _read_json(runs_fd, _RUN_AUTHORITY_INDEX_FILENAME, None)
                if existing_index is not None:
                    self._run_authority_index_locked(runs_fd, identity=identity)
                    return
                with os.scandir(runs_fd) as entries:
                    names = sorted(entry.name for entry in entries)
                marker_names: list[str] = []
                run_names: set[str] = set()
                for name in names:
                    if name.startswith("grant-") and name.endswith(".json"):
                        digest = name[6:-5]
                        if _DIGEST.fullmatch(digest) is None:
                            raise RunnerStoreError("legacy local run authority is invalid")
                        marker_names.append(name)
                    elif _RUN_FILENAME.fullmatch(name) is not None:
                        status = os.stat(name, dir_fd=runs_fd, follow_symlinks=False)
                        if not stat.S_ISDIR(status.st_mode):
                            raise RunnerStoreError("legacy local run authority is invalid")
                        run_names.add(name)
                    elif (
                        name.startswith(("reservation-", "terminal-", "pruned-"))
                        and name.endswith(".json")
                    ):
                        continue
                    else:
                        raise RunnerStoreError("legacy local run authority is invalid")

                context = _context_from_dict(self._binding_locked(context_fd)["context"])
                index = self._zero_run_authority_index(
                    context=context, identity=identity, signer=signer,
                )
                seen_runs: set[str] = set()
                terminal_items: list[dict[str, Any]] = []
                for marker_name in marker_names:
                    marker = _read_json(runs_fd, marker_name, None)
                    if not isinstance(marker, Mapping) or set(marker) != {
                        "schema_version", "grant", "initial_state",
                    } or marker["schema_version"] != _RESERVATION_SCHEMA:
                        raise RunnerStoreError("legacy local run authority is invalid")
                    try:
                        grant = validate_execution_grant(marker["grant"])
                    except (TypeError, ValueError):
                        raise RunnerStoreError("legacy local run authority is invalid") from None
                    run_hash = self._run_hash(grant["run_id"])
                    if run_hash not in run_names or run_hash in seen_runs or marker_name != f"grant-{grant['grant_digest']}.json":
                        raise RunnerStoreError("legacy local run authority is invalid")
                    seen_runs.add(run_hash)
                    initial_state = marker["initial_state"]
                    if (
                        not isinstance(initial_state, Mapping)
                        or set(initial_state) != {
                            "schema_version", "run_id", "grant_id", "grant_digest", "manifest_digest",
                            "runner_authority", "state", "retention_expires_at_ms", "updated_at_ms",
                        }
                        or initial_state.get("schema_version") != "heel.local-run-state.v1"
                        or initial_state.get("run_id") != grant["run_id"]
                        or initial_state.get("grant_id") != grant["grant_id"]
                        or initial_state.get("grant_digest") != grant["grant_digest"]
                        or initial_state.get("manifest_digest") != grant["approval"]["manifest_digest"]
                        or initial_state.get("state") != "verified"
                        or any(
                            type(initial_state.get(field)) is not int or initial_state[field] < 0
                            for field in ("retention_expires_at_ms", "updated_at_ms")
                        )
                    ):
                        raise RunnerStoreError("legacy local run authority is invalid")
                    run_fd = _open_child(runs_fd, run_hash, create=False)
                    if run_fd is None:
                        raise RunnerStoreError("legacy local run authority is invalid")
                    try:
                        _secure_directory(run_fd, "Heel legacy local run directory")
                        current_state = self._run_state_locked(run_fd, grant["run_id"])
                        if (
                            current_state["grant_id"] != grant["grant_id"]
                            or current_state["grant_digest"] != grant["grant_digest"]
                            or current_state["manifest_digest"] != initial_state["manifest_digest"]
                            or current_state["runner_authority"] != initial_state["runner_authority"]
                            or current_state["retention_expires_at_ms"] != initial_state["retention_expires_at_ms"]
                        ):
                            raise RunnerStoreError("legacy local run authority is invalid")
                        reservation = self._run_authority_record(
                            operation="reserve", context=context, identity=identity, signer=signer,
                            run_hash=run_hash, grant=grant, state=initial_state, index=index,
                        )
                        self._ensure_json_exact(
                            runs_fd, self._run_authority_record_filename("reserve", run_hash), reservation,
                        )
                        index = self._next_run_authority_index(
                            index, signer=signer, delta=1, head_digest=reservation["record_digest"],
                            nonterminal_runs=sorted([
                                *index["nonterminal_runs"],
                                {
                                    "run_hash": run_hash,
                                    "reservation_record_digest": reservation["record_digest"],
                                },
                            ], key=lambda item: item["run_hash"]),
                        )
                        if current_state["state"] == "terminal":
                            finals = _read_json(run_fd, "finals.json", None)
                            if (
                                not isinstance(finals, Mapping)
                                or set(finals) != {
                                    "schema_version", "operational_projection", "findings_projection",
                                    "local_view", "disclosure_preview", "finals_digest",
                                }
                                or finals["schema_version"] != _FINALS_SCHEMA
                            ):
                                raise RunnerStoreError("legacy terminal local run is invalid")
                            final_core = {
                                key: finals[key] for key in finals if key != "finals_digest"
                            }
                            if finals["finals_digest"] != canonical_digest(final_core):
                                raise RunnerStoreError("legacy terminal local run is invalid")
                            operational = validate_operational_run(finals["operational_projection"])
                            terminal = self._run_authority_record(
                                operation="terminal", context=context, identity=identity, signer=signer,
                                run_hash=run_hash, grant=grant, state=current_state, index=index,
                                terminal={
                                    "reservation_record_digest": reservation["record_digest"],
                                    "terminal_projection_digest": operational["projection_digest"],
                                },
                            )
                            self._ensure_json_exact(
                                runs_fd, self._run_authority_record_filename("terminal", run_hash), terminal,
                            )
                            terminal_items.append({
                                "retention_expires_at_ms": current_state["retention_expires_at_ms"],
                                "run_hash": run_hash,
                                "terminal_record_digest": terminal["record_digest"],
                            })
                            index = self._next_run_authority_index(
                                index, signer=signer, delta=-1, head_digest=terminal["record_digest"],
                                nonterminal_runs=[
                                    item for item in index["nonterminal_runs"] if item["run_hash"] != run_hash
                                ],
                                terminal_queue=sorted(
                                    terminal_items,
                                    key=lambda item: (item["retention_expires_at_ms"], item["run_hash"]),
                                ),
                            )
                    finally:
                        os.close(run_fd)
                if run_names != seen_runs:
                    raise RunnerStoreError("legacy local run authority is invalid")
                _write_json(runs_fd, _RUN_AUTHORITY_INDEX_FILENAME, index)
            finally:
                os.close(runs_fd)

    def load_run(self, run_id: str) -> dict[str, Any]:
        with self._transaction(exclusive=False) as context_fd:
            with self._open_run(context_fd, run_id, create=False) as run_fd:
                return self._run_state_locked(run_fd, run_id)

    def load_run_trusted_keys(self, run_id: str) -> dict[str, object]:
        state = self.load_run(run_id)
        authority = state["runner_authority"]
        binding = self.load_binding()["identity"]
        if authority != {
            "runner_key_id": binding["runner_key_id"],
            "public_key_b64": binding["public_key_b64"],
            "public_key_digest": binding["fingerprint"],
        }:
            raise RunnerStoreError("reserved runner authority differs from the bound identity")
        try:
            key = load_public_key_base64(authority["public_key_b64"])
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid reserved runner verification key") from None
        return {authority["runner_key_id"]: key}

    def load_run_grant(self, run_id: str) -> dict[str, Any]:
        with self._transaction(exclusive=False) as context_fd:
            with self._open_run(context_fd, run_id, create=False) as run_fd:
                self._run_state_locked(run_fd, run_id)
                grant = _read_json(run_fd, "grant.json", None)
        try:
            return validate_execution_grant(grant)
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid stored execution grant") from None

    def transition_run(self, run_id: str, next_state: str, *, now_ms: int) -> dict[str, Any]:
        identity, signer = self._require_runtime_authority()
        if next_state not in _RUN_STATES:
            raise ValueError("invalid local run state")
        if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms < 0:
            raise ValueError("invalid local run timestamp")
        terminal_projection_digest: str | None = None
        bound_context: RunnerContext | None = None
        if next_state == "terminal":
            terminal_projection_digest = self.load_final_projections(run_id)["operational_projection"]["projection_digest"]
            bound_context = self.load_context()
        with self._transaction(exclusive=True) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=False)
            if runs_fd is None:
                raise RunnerStoreError("local run is unavailable")
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                self._complete_run_authority_journal_locked(
                    context_fd, runs_fd, identity=identity,
                )
                index = self._run_authority_index_locked(runs_fd, identity=identity)
                run_hash = self._run_hash(run_id)
                run_fd = _open_child(runs_fd, run_hash, create=False)
                if run_fd is None:
                    raise RunnerStoreError("local run is unavailable")
                try:
                    _secure_directory(run_fd, "Heel local run directory")
                    current = self._run_state_locked(run_fd, run_id)
                    if next_state not in _RUN_TRANSITIONS[current["state"]]:
                        raise RunnerStoreError("illegal local run transition")
                    if now_ms < current["updated_at_ms"]:
                        raise RunnerStoreError("local run timestamp moved backward")
                    updated = {**current, "state": next_state, "updated_at_ms": now_ms}
                    if next_state != "terminal":
                        _write_json(run_fd, "state.json", updated)
                        return updated
                    existing_terminal = next(
                        (item for item in index["terminal_queue"] if item["run_hash"] == run_hash),
                        None,
                    )
                    if existing_terminal is not None:
                        existing_record = _read_json(
                            runs_fd,
                            self._run_authority_record_filename("terminal", run_hash),
                            None,
                        )
                        if existing_record is None:
                            raise RunnerStoreError("local run authority terminal queue is invalid")
                        existing_record = self._verify_signed_run_authority_value(
                            existing_record, identity=identity, schema=_RUN_TERMINAL_RECORD_SCHEMA,
                            record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                        )
                        if (
                            existing_record["record_digest"] != existing_terminal["terminal_record_digest"]
                            or existing_record.get("terminal_projection_digest") != terminal_projection_digest
                            or existing_record.get("terminal_state_digest") != canonical_digest(current)
                            or existing_record.get("grant_id") != current["grant_id"]
                            or existing_record.get("grant_digest") != current["grant_digest"]
                            or existing_record.get("retention_expires_at_ms")
                            != current["retention_expires_at_ms"]
                            or existing_record.get("terminal_at_ms") != current["updated_at_ms"]
                        ):
                            raise RunnerStoreError("local run authority terminal queue is invalid")
                        return current
                    reservation = _read_json(
                        runs_fd, self._run_authority_record_filename("reserve", run_hash), None,
                    )
                    if reservation is None:
                        raise RunnerStoreError("local run authority reservation is unavailable")
                    reservation = self._verify_signed_run_authority_value(
                        reservation, identity=identity, schema=_RUN_RESERVATION_RECORD_SCHEMA,
                        record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                    )
                    tracked_reservation = next(
                        (item for item in index["nonterminal_runs"] if item["run_hash"] == run_hash),
                        None,
                    )
                    if (
                        tracked_reservation is None
                        or tracked_reservation["reservation_record_digest"] != reservation["record_digest"]
                    ):
                        raise RunnerStoreError("local run authority reservation is unavailable")
                    grant = _read_json(run_fd, "grant.json", None)
                    try:
                        grant = validate_execution_grant(grant)
                    except (TypeError, ValueError):
                        raise RunnerStoreError("invalid stored execution grant") from None
                    terminal = {
                        "reservation_record_digest": reservation["record_digest"],
                        "terminal_projection_digest": terminal_projection_digest,
                    }
                    record = self._run_authority_record(
                        operation="terminal", context=bound_context, identity=identity, signer=signer,
                        run_hash=run_hash, grant=grant, state=updated, index=index, terminal=terminal,
                    )
                    queue_item = {
                        "retention_expires_at_ms": updated["retention_expires_at_ms"],
                        "run_hash": run_hash, "terminal_record_digest": record["record_digest"],
                    }
                    terminal_queue = sorted(
                        [*index["terminal_queue"], queue_item],
                        key=lambda item: (item["retention_expires_at_ms"], item["run_hash"]),
                    )
                    next_index = self._next_run_authority_index(
                        index, signer=signer, delta=-1, head_digest=record["record_digest"],
                        nonterminal_runs=[
                            item for item in index["nonterminal_runs"] if item["run_hash"] != run_hash
                        ],
                        terminal_queue=terminal_queue,
                    )
                    journal = self._run_authority_journal(
                        context=bound_context, identity=identity, signer=signer, operation="terminal",
                        run_hash=run_hash, index=index, next_index=next_index, record=record,
                        recovery={"terminal_state": updated}, created_at_ms=now_ms,
                    )
                    _write_json(runs_fd, _RUN_AUTHORITY_JOURNAL_FILENAME, journal)
                    _write_json(run_fd, "state.json", updated)
                    self._ensure_json_exact(
                        runs_fd, self._run_authority_record_filename("terminal", run_hash), record,
                    )
                    _write_json(runs_fd, _RUN_AUTHORITY_INDEX_FILENAME, next_index)
                    os.unlink(_RUN_AUTHORITY_JOURNAL_FILENAME, dir_fd=runs_fd)
                    os.fsync(runs_fd)
                    return updated
                finally:
                    os.close(run_fd)
            finally:
                os.close(runs_fd)

    def _runtime_terminal_anchor(self, run_id: str, *, runtime: object | None = None) -> dict[str, Any]:
        """Return one runtime-disclosure anchor from committed local terminal authority."""
        identity, _signer = self._require_runtime_authority()
        run_id = _id(run_id, "run ID")
        try:
            finals = self.load_final_projections(run_id)
        except RunnerStoreError as exc:
            raise RunnerStoreError("local terminal authority is unavailable") from exc
        operational = finals["operational_projection"]
        with self._transaction(exclusive=True) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=False)
            if runs_fd is None:
                raise RunnerStoreError("local terminal authority is unavailable")
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                self._complete_run_authority_journal_locked(
                    context_fd, runs_fd, identity=identity, runtime=runtime,
                )
                index = self._run_authority_index_locked(runs_fd, identity=identity)
                run_hash = self._run_hash(run_id)
                queued = next(
                    (item for item in index["terminal_queue"] if item["run_hash"] == run_hash),
                    None,
                )
                if queued is None:
                    raise RunnerStoreError("local terminal authority is unavailable")
                record = _read_json(
                    runs_fd, self._run_authority_record_filename("terminal", run_hash), None,
                )
                if record is None:
                    raise RunnerStoreError("local terminal authority is unavailable")
                record = self._verify_signed_run_authority_value(
                    record, identity=identity, schema=_RUN_TERMINAL_RECORD_SCHEMA,
                    record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                )
                with self._open_run(context_fd, run_id, create=False) as run_fd:
                    state = self._run_state_locked(run_fd, run_id)
                    grant = _read_json(run_fd, "grant.json", None)
                try:
                    grant = validate_execution_grant(grant)
                except (TypeError, ValueError):
                    raise RunnerStoreError("invalid stored execution grant") from None
                if (
                    state["state"] != "terminal"
                    or queued["terminal_record_digest"] != record["record_digest"]
                    or queued["retention_expires_at_ms"] != state["retention_expires_at_ms"]
                    or record["run_hash"] != run_hash
                    or record["grant_id"] != grant["grant_id"]
                    or record["grant_digest"] != grant["grant_digest"]
                    or record["terminal_state_digest"] != canonical_digest(state)
                    or record["terminal_projection_digest"] != operational["projection_digest"]
                    or record["terminal_at_ms"] != state["updated_at_ms"]
                    or record["retention_expires_at_ms"] != state["retention_expires_at_ms"]
                    or operational["run_id"] != run_id
                    or operational["grant_id"] != grant["grant_id"]
                    or operational["workspace_id"] != grant["workspace_id"]
                    or operational["project_id"] != grant["project_id"]
                    or operational["approval_projection_digest"]
                    != grant["approval"]["projection_digest"]
                ):
                    raise RunnerStoreError("local terminal authority is invalid")
                return {
                    "run_id": run_id, "project_id": grant["project_id"],
                    "grant_id": grant["grant_id"],
                    "approval_projection_digest": grant["approval"]["projection_digest"],
                    "terminal_projection_digest": record["terminal_projection_digest"],
                    "terminal_record_digest": record["record_digest"],
                    "terminal_at_ms": record["terminal_at_ms"],
                    "retention_expires_at_ms": record["retention_expires_at_ms"],
                }
            finally:
                os.close(runs_fd)

    def detach_terminal(
        self,
        run_id: str,
        *,
        runtime: object,
        expected_local_state_digest: str,
        now_ms: int,
    ) -> str:
        """Durably detach a local terminal from the live-run claim ledger."""
        run_id = _id(run_id, "run ID")
        expected_local_state_digest = _digest(
            expected_local_state_digest, "local terminal runtime state digest",
        )
        if type(now_ms) is not int or now_ms < 0:
            raise ValueError("invalid local run timestamp")
        identity, signer = self._require_runtime_authority()
        if not self._runtime_matches_identity(runtime, identity=identity, signer=signer):
            raise RunnerStoreError("local terminal detach recovery is required")

        # A completed detach has intentionally removed q, so discover the named
        # immutable record before asking the q-backed pre-detach anchor again.
        run_hash = self._run_hash(run_id)
        with self._transaction(exclusive=True) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=False)
            if runs_fd is None:
                raise RunnerStoreError("local terminal authority is unavailable")
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                self._complete_run_authority_journal_locked(
                    context_fd, runs_fd, identity=identity, runtime=runtime,
                )
                index = self._run_authority_index_locked(runs_fd, identity=identity)
                existing = _read_json(
                    runs_fd, self._run_authority_record_filename("detach_terminal", run_hash), None,
                )
                if existing is not None:
                    if any(item["run_hash"] == run_hash for item in index["terminal_queue"]):
                        raise RunnerStoreError("local terminal authority is invalid")
                    detached = self._verify_signed_run_authority_value(
                        existing, identity=identity,
                        schema=_RUN_TERMINAL_DETACHED_RECORD_SCHEMA,
                        record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                    )
                    try:
                        state = runtime.load_terminal_state(run_id)
                    except (AttributeError, TypeError, ValueError) as exc:
                        raise RunnerStoreError("local terminal detach recovery is required") from exc
                    if (
                        state is None or state.run_hash != run_hash
                        or state.terminal_record_digest != detached["terminal_record_digest"]
                        or state.terminal_projection_digest != detached["terminal_projection_digest"]
                        or state.retention_expires_at_ms != detached["retention_expires_at_ms"]
                        or not (
                            state.state == "local_terminal"
                            and state.state_digest == detached["runtime_state_digest"]
                            or state.state == "available"
                            and state.revision == 2
                            and state.prior_state_digest == detached["runtime_state_digest"]
                        )
                    ):
                        raise RunnerStoreError("local terminal authority is invalid")
                    return detached["record_digest"]
            finally:
                os.close(runs_fd)
        return self._detach_terminal_after_precheck(
            run_id, runtime=runtime,
            expected_local_state_digest=expected_local_state_digest, now_ms=now_ms,
            identity=identity, signer=signer,
        )

    def load_terminal_disclosure_anchor(
        self,
        run_id: str,
        *,
        runtime: object,
        expected_runtime_state_digest: str,
    ) -> dict[str, Any]:
        """Rehydrate disclosure authority from sealed runtime and detached records."""
        run_id = _id(run_id, "run ID")
        expected_runtime_state_digest = _digest(
            expected_runtime_state_digest, "runtime terminal state digest",
        )
        identity, signer = self._require_runtime_authority()
        if not self._runtime_matches_identity(runtime, identity=identity, signer=signer):
            raise RunnerStoreError("local terminal disclosure authority is unavailable")
        try:
            runtime_state = runtime.load_terminal_state(run_id)
        except (AttributeError, TypeError, ValueError) as exc:
            raise RunnerStoreError("local terminal disclosure authority is unavailable") from exc
        if (
            runtime_state is None or runtime_state.state != "available"
            or runtime_state.revision != 2
            or runtime_state.state_digest != expected_runtime_state_digest
        ):
            raise RunnerStoreError("local terminal disclosure authority is unavailable")
        run_hash = self._run_hash(run_id)
        with self._transaction(exclusive=True) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=False)
            if runs_fd is None:
                raise RunnerStoreError("local terminal disclosure authority is unavailable")
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                self._complete_run_authority_journal_locked(
                    context_fd, runs_fd, identity=identity, runtime=runtime,
                )
                index = self._run_authority_index_locked(runs_fd, identity=identity)
                if any(item["run_hash"] == run_hash for item in index["terminal_queue"]):
                    raise RunnerStoreError("local terminal disclosure authority is unavailable")
                detached_value = _read_json(
                    runs_fd, self._run_authority_record_filename("detach_terminal", run_hash), None,
                )
                terminal_value = _read_json(
                    runs_fd, self._run_authority_record_filename("terminal", run_hash), None,
                )
                if detached_value is None or terminal_value is None:
                    raise RunnerStoreError("local terminal disclosure authority is unavailable")
                detached = self._verify_signed_run_authority_value(
                    detached_value, identity=identity,
                    schema=_RUN_TERMINAL_DETACHED_RECORD_SCHEMA,
                    record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                )
                terminal = self._verify_signed_run_authority_value(
                    terminal_value, identity=identity,
                    schema=_RUN_TERMINAL_RECORD_SCHEMA,
                    record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                )
                run_fd = _open_child(runs_fd, run_hash, create=False)
                if run_fd is None:
                    raise RunnerStoreError("local terminal disclosure authority is unavailable")
                try:
                    _secure_directory(run_fd, "Heel terminal local run directory")
                    state = self._run_state_locked(run_fd, run_id)
                    try:
                        grant = validate_execution_grant(_read_json(run_fd, "grant.json", None))
                    except (TypeError, ValueError):
                        raise RunnerStoreError("invalid stored execution grant") from None
                    finals = _read_json(run_fd, "finals.json", None)
                finally:
                    os.close(run_fd)
                try:
                    operational = validate_operational_run(finals["operational_projection"])
                except (KeyError, TypeError, ValueError):
                    raise RunnerStoreError("local terminal disclosure authority is unavailable") from None
                if (
                    state["state"] != "terminal"
                    or grant["run_id"] != run_id
                    or terminal["run_hash"] != run_hash
                    or terminal["grant_id"] != grant["grant_id"]
                    or terminal["grant_digest"] != grant["grant_digest"]
                    or terminal["terminal_state_digest"] != canonical_digest(state)
                    or terminal["terminal_projection_digest"] != operational["projection_digest"]
                    or detached["run_hash"] != run_hash
                    or detached["grant_id"] != grant["grant_id"]
                    or detached["grant_digest"] != grant["grant_digest"]
                    or detached["terminal_record_digest"] != terminal["record_digest"]
                    or detached["terminal_projection_digest"] != terminal["terminal_projection_digest"]
                    or detached["terminal_at_ms"] != terminal["terminal_at_ms"]
                    or detached["retention_expires_at_ms"] != terminal["retention_expires_at_ms"]
                    or runtime_state.run_hash != run_hash
                    or runtime_state.project_id != grant["project_id"]
                    or runtime_state.grant_id != grant["grant_id"]
                    or runtime_state.approval_projection_digest != grant["approval"]["projection_digest"]
                    or runtime_state.terminal_projection_digest != detached["terminal_projection_digest"]
                    or runtime_state.terminal_record_digest != detached["terminal_record_digest"]
                    or runtime_state.terminal_at_ms != detached["terminal_at_ms"]
                    or runtime_state.retention_expires_at_ms != detached["retention_expires_at_ms"]
                    or runtime_state.prior_state_digest != detached["runtime_state_digest"]
                ):
                    raise RunnerStoreError("local terminal disclosure authority is invalid")
                return {
                    "run_id": run_id, "project_id": grant["project_id"],
                    "grant_id": grant["grant_id"],
                    "approval_projection_digest": grant["approval"]["projection_digest"],
                    "terminal_projection_digest": terminal["terminal_projection_digest"],
                    "terminal_record_digest": terminal["record_digest"],
                    "terminal_at_ms": terminal["terminal_at_ms"],
                    "retention_expires_at_ms": terminal["retention_expires_at_ms"],
                }
            finally:
                os.close(runs_fd)

    def authorize_pending_result_replay(
        self,
        pending: PendingSignedCall,
        *,
        runtime: RunnerRuntimeState,
        now_ms: int,
    ) -> PendingResultReplayAuthority:
        """Compatibility entry point; production retains the single opaque verifier."""
        return self.pending_result_replay_verifier(runtime).authorize_pending_result_replay(
            pending, now_ms=now_ms,
        )

    def _authorize_pending_result_replay(
        self,
        pending: PendingSignedCall,
        *,
        runtime: RunnerRuntimeState,
        now_ms: int,
        issuer: object,
    ) -> PendingResultReplayAuthority:
        """Read-only cross-store proof for one byte-identical terminal request."""
        if type(now_ms) is not int or now_ms < 0 or not isinstance(pending, PendingSignedCall):
            raise RunnerStoreError("local pending terminal replay authority is unavailable")
        identity, signer = self._require_runtime_authority()
        if not self._runtime_matches_identity(runtime, identity=identity, signer=signer):
            raise RunnerStoreError("local pending terminal replay authority is unavailable")
        if (
            pending.request_operation != "result" or pending.chain_operation != "result"
            or pending.run_id is None
        ):
            raise RunnerStoreError("local pending terminal replay authority is unavailable")
        run_id = pending.run_id
        try:
            current = runtime.get_pending_call(pending.call_id)
            runtime_state = runtime.load_terminal_state(run_id)
            active_rows = runtime.load_active_run_controls(limit=64)
        except (TypeError, ValueError) as exc:
            raise RunnerStoreError("local pending terminal replay authority is unavailable") from exc
        if current != pending or runtime_state is None or runtime_state.state != "local_terminal":
            raise RunnerStoreError("local pending terminal replay authority is unavailable")
        if now_ms >= runtime_state.retention_expires_at_ms:
            raise RunnerStoreError("local pending terminal replay authority is unavailable")
        active = [item for item in active_rows if item.run_id == run_id]
        if len(active) != 1:
            raise RunnerStoreError("local pending terminal replay authority is unavailable")
        active_state = active[0]
        cursor = active_state.chains.get("result")
        body_sha256 = hashlib.sha256(pending.body).hexdigest()
        try:
            request = json.loads(pending.body.decode("utf-8"))
            if (
                canonical_bytes(request) != pending.body
                or validate_runner_result_request(request) != request
                or request["run_id"] != run_id
            ):
                raise ValueError
        except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            raise RunnerStoreError("local pending terminal replay authority is unavailable") from None
        if (
            cursor is None
            or pending.prior_chain_state_digest != cursor.state_digest
            or (pending.sequence, pending.generation, pending.headers.get("X-Heel-Runner-Nonce"))
            != (cursor.next_sequence, cursor.generation, cursor.next_nonce_b64)
            or pending.headers.get("X-Heel-Runner-Sequence") != str(cursor.next_sequence)
            or runtime_state.run_hash != self._run_hash(run_id)
            or runtime_state.project_id != active_state.project_id
            or runtime_state.grant_id != active_state.grant_id
            or runtime_state.approval_projection_digest != active_state.approval_projection_digest
        ):
            raise RunnerStoreError("local pending terminal replay authority is unavailable")
        finals = self.load_final_projections(run_id)
        operational = finals["operational_projection"]
        if request["operational_projection"] != operational:
            raise RunnerStoreError("local pending terminal replay authority is invalid")

        run_hash = self._run_hash(run_id)
        with self._transaction(exclusive=False) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=False)
            if runs_fd is None:
                raise RunnerStoreError("local pending terminal replay authority is unavailable")
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                if _read_json(runs_fd, _RUN_AUTHORITY_JOURNAL_FILENAME, None) is not None:
                    raise RunnerStoreError("local pending terminal replay authority is unavailable")
                index = self._run_authority_index_locked(runs_fd, identity=identity)
                if any(item["run_hash"] == run_hash for item in index["terminal_queue"]):
                    raise RunnerStoreError("local pending terminal replay authority is unavailable")
                detached_value = _read_json(
                    runs_fd, self._run_authority_record_filename("detach_terminal", run_hash), None,
                )
                terminal_value = _read_json(
                    runs_fd, self._run_authority_record_filename("terminal", run_hash), None,
                )
                if detached_value is None or terminal_value is None:
                    raise RunnerStoreError("local pending terminal replay authority is unavailable")
                detached = self._verify_signed_run_authority_value(
                    detached_value, identity=identity,
                    schema=_RUN_TERMINAL_DETACHED_RECORD_SCHEMA,
                    record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                )
                terminal = self._verify_signed_run_authority_value(
                    terminal_value, identity=identity, schema=_RUN_TERMINAL_RECORD_SCHEMA,
                    record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                )
                run_fd = _open_child(runs_fd, run_hash, create=False)
                if run_fd is None:
                    raise RunnerStoreError("local pending terminal replay authority is unavailable")
                try:
                    _secure_directory(run_fd, "Heel retained local run directory")
                    state = self._run_state_locked(run_fd, run_id)
                    grant = validate_execution_grant(_read_json(run_fd, "grant.json", None))
                except (TypeError, ValueError) as exc:
                    raise RunnerStoreError("local pending terminal replay authority is unavailable") from exc
                finally:
                    os.close(run_fd)
                if (
                    state["state"] != "terminal"
                    or state["grant_id"] != grant["grant_id"]
                    or state["grant_digest"] != grant["grant_digest"]
                    or active_state.approval_projection != self.load_projection(grant["approval"]["projection_id"])
                    or active_state.grant != grant
                    or active_state.project_id != grant["project_id"]
                    or active_state.grant_id != grant["grant_id"]
                    or active_state.grant_digest != grant["grant_digest"]
                    or active_state.approval_projection_digest != grant["approval"]["projection_digest"]
                    or terminal["run_hash"] != run_hash
                    or terminal["grant_id"] != grant["grant_id"]
                    or terminal["grant_digest"] != grant["grant_digest"]
                    or terminal["terminal_state_digest"] != canonical_digest(state)
                    or terminal["terminal_projection_digest"] != operational["projection_digest"]
                    or detached["run_hash"] != run_hash
                    or detached["grant_id"] != grant["grant_id"]
                    or detached["grant_digest"] != grant["grant_digest"]
                    or detached["terminal_record_digest"] != terminal["record_digest"]
                    or detached["terminal_projection_digest"] != terminal["terminal_projection_digest"]
                    or detached["terminal_at_ms"] != terminal["terminal_at_ms"]
                    or detached["retention_expires_at_ms"] != terminal["retention_expires_at_ms"]
                    or detached["runtime_state_schema"] != "heel.runner-terminal-disclosure-state.v1"
                    or detached["runtime_state"] != "local_terminal"
                    or detached["runtime_state_digest"] != runtime_state.state_digest
                    or runtime_state.terminal_record_digest != terminal["record_digest"]
                    or runtime_state.terminal_projection_digest != terminal["terminal_projection_digest"]
                    or runtime_state.terminal_at_ms != terminal["terminal_at_ms"]
                    or runtime_state.retention_expires_at_ms != terminal["retention_expires_at_ms"]
                ):
                    raise RunnerStoreError("local pending terminal replay authority is invalid")
                return PendingResultReplayAuthority(
                    call_id=pending.call_id, pending_state_digest=pending.pending_state_digest,
                    run_id=run_id, body_sha256=body_sha256,
                    active_state_digest=active_state.state_digest,
                    runtime_terminal_state_digest=runtime_state.state_digest,
                    terminal_record_digest=terminal["record_digest"],
                    detached_record_digest=detached["record_digest"],
                    terminal_projection_digest=terminal["terminal_projection_digest"],
                    retention_expires_at_ms=terminal["retention_expires_at_ms"],
                    _issuer=issuer,
                )
            finally:
                os.close(runs_fd)

    def recover_terminal_detaches(
        self,
        *,
        runtime: object,
        now_ms: int,
        limit: int = 64,
    ) -> int:
        """Drain only the signed terminal queue; never enumerate retained runs."""
        if type(now_ms) is not int or now_ms < 0:
            raise ValueError("invalid local run timestamp")
        if type(limit) is not int or not 1 <= limit <= _RUN_AUTHORITY_MAX_TRACKED:
            raise ValueError("invalid local terminal detach limit")
        identity, signer = self._require_runtime_authority()
        if not self._runtime_matches_identity(runtime, identity=identity, signer=signer):
            raise RunnerStoreError("local terminal detach recovery is required")
        recovered = 0
        for _ in range(limit):
            with self._transaction(exclusive=True) as context_fd:
                runs_fd = _open_child(context_fd, "runs", create=False)
                if runs_fd is None:
                    return recovered
                try:
                    _secure_directory(runs_fd, "Heel runner runs directory")
                    self._complete_run_authority_journal_locked(
                        context_fd, runs_fd, identity=identity, runtime=runtime,
                    )
                    index = self._run_authority_index_locked(runs_fd, identity=identity)
                    if not index["terminal_queue"]:
                        return recovered
                    run_id = self._run_id_from_hash_locked(
                        runs_fd, index["terminal_queue"][0]["run_hash"],
                    )
                finally:
                    os.close(runs_fd)
            anchor = self._runtime_terminal_anchor(run_id, runtime=runtime)
            try:
                state = runtime.load_terminal_state(run_id)
            except (AttributeError, TypeError, ValueError) as exc:
                raise RunnerStoreError("local terminal detach recovery is required") from exc
            if state is None:
                try:
                    state = runtime.register_local_terminal(**anchor)
                except (AttributeError, TypeError, ValueError) as exc:
                    raise RunnerStoreError("local terminal detach recovery is required") from exc
            elif (
                state.state != "local_terminal"
                or state.run_hash != self._run_hash(run_id)
                or state.project_id != anchor["project_id"]
                or state.grant_id != anchor["grant_id"]
                or state.approval_projection_digest != anchor["approval_projection_digest"]
                or state.terminal_projection_digest != anchor["terminal_projection_digest"]
                or state.terminal_record_digest != anchor["terminal_record_digest"]
                or state.terminal_at_ms != anchor["terminal_at_ms"]
                or state.retention_expires_at_ms != anchor["retention_expires_at_ms"]
            ):
                raise RunnerStoreError("local terminal detach recovery is required")
            self.detach_terminal(
                run_id, runtime=runtime, expected_local_state_digest=state.state_digest,
                now_ms=now_ms,
            )
            recovered += 1
        return recovered

    def prune_runtime_terminal(
        self,
        run_id: str,
        *,
        runtime: object,
        expected_runtime_state_digest: str,
        now_ms: int,
    ) -> VerifiedPrunedRunReceipt:
        """Write the signed prune tombstone before the runtime row is removed."""
        run_id = _id(run_id, "run ID")
        expected_runtime_state_digest = _digest(
            expected_runtime_state_digest, "runtime prune state digest",
        )
        if type(now_ms) is not int or now_ms < 0:
            raise ValueError("invalid local run timestamp")
        identity, signer = self._require_runtime_authority()
        if not self._runtime_matches_identity(runtime, identity=identity, signer=signer):
            raise RunnerStoreError("local terminal prune recovery is required")
        try:
            runtime_state = runtime.load_terminal_state(run_id)
        except (AttributeError, TypeError, ValueError) as exc:
            raise RunnerStoreError("local terminal prune recovery is required") from exc
        if (
            runtime_state is None or runtime_state.state != "prune_pending"
            or runtime_state.state_digest != expected_runtime_state_digest
            or now_ms < runtime_state.retention_expires_at_ms
        ):
            raise RunnerStoreError("local terminal prune authority is unavailable")
        run_hash = self._run_hash(run_id)
        with self._transaction(exclusive=True) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=False)
            if runs_fd is None:
                raise RunnerStoreError("local terminal prune authority is unavailable")
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                self._complete_run_authority_journal_locked(
                    context_fd, runs_fd, identity=identity, runtime=runtime,
                )
                index = self._run_authority_index_locked(runs_fd, identity=identity)
                if any(item["run_hash"] == run_hash for item in index["terminal_queue"]):
                    raise RunnerStoreError("local terminal prune authority is unavailable")
                detached_value = _read_json(
                    runs_fd, self._run_authority_record_filename("detach_terminal", run_hash), None,
                )
                terminal_value = _read_json(
                    runs_fd, self._run_authority_record_filename("terminal", run_hash), None,
                )
                if detached_value is None or terminal_value is None:
                    raise RunnerStoreError("local terminal prune authority is unavailable")
                detached = self._verify_signed_run_authority_value(
                    detached_value, identity=identity,
                    schema=_RUN_TERMINAL_DETACHED_RECORD_SCHEMA,
                    record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                )
                terminal = self._verify_signed_run_authority_value(
                    terminal_value, identity=identity,
                    schema=_RUN_TERMINAL_RECORD_SCHEMA,
                    record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                )
                existing_pruned = _read_json(
                    runs_fd, self._run_authority_record_filename("prune", run_hash), None,
                )
                if existing_pruned is not None:
                    pruned = self._verify_runtime_pruned_record(existing_pruned, identity=identity)
                    if (
                        pruned["terminal_record_digest"] != terminal["record_digest"]
                        or pruned["terminal_projection_digest"] != terminal["terminal_projection_digest"]
                        or pruned["retention_expires_at_ms"] != runtime_state.retention_expires_at_ms
                        or pruned["runtime_prune_pending_state_digest"] != expected_runtime_state_digest
                    ):
                        raise RunnerStoreError("local terminal prune authority is invalid")
                    return VerifiedPrunedRunReceipt(record=pruned)
                run_fd = _open_child(runs_fd, run_hash, create=False)
                if run_fd is None:
                    raise RunnerStoreError("local terminal prune authority is unavailable")
                try:
                    _secure_directory(run_fd, "Heel retained local run directory")
                    state = self._run_state_locked(run_fd, run_id)
                    try:
                        grant = validate_execution_grant(_read_json(run_fd, "grant.json", None))
                    except (TypeError, ValueError):
                        raise RunnerStoreError("invalid stored execution grant") from None
                    finals = _read_json(run_fd, "finals.json", None)
                    try:
                        operational = validate_operational_run(finals["operational_projection"])
                    except (KeyError, TypeError, ValueError):
                        raise RunnerStoreError("local terminal prune authority is unavailable") from None
                    if (
                        state["state"] != "terminal"
                        or state["retention_expires_at_ms"] != runtime_state.retention_expires_at_ms
                        or terminal["run_hash"] != run_hash
                        or terminal["grant_id"] != grant["grant_id"]
                        or terminal["grant_digest"] != grant["grant_digest"]
                        or terminal["terminal_state_digest"] != canonical_digest(state)
                        or terminal["terminal_projection_digest"] != operational["projection_digest"]
                        or detached["terminal_record_digest"] != terminal["record_digest"]
                        or detached["terminal_projection_digest"] != terminal["terminal_projection_digest"]
                        or detached["runtime_state_digest"] != runtime_state.prior_state_digest
                        or runtime_state.terminal_record_digest != terminal["record_digest"]
                        or runtime_state.terminal_projection_digest != terminal["terminal_projection_digest"]
                        or runtime_state.grant_id != grant["grant_id"]
                    ):
                        raise RunnerStoreError("local terminal prune authority is invalid")
                    context = _context_from_dict(self._binding_locked(context_fd)["context"])
                    record = self._runtime_pruned_record(
                        context=context, identity=identity, signer=signer, run_id=run_id,
                        grant=grant, index=index, terminal=terminal, detached=detached,
                        runtime_state=runtime_state, pruned_at_ms=now_ms,
                    )
                    next_index = self._next_run_authority_index(
                        index, signer=signer, delta=0, head_digest=record["record_digest"],
                    )
                    journal = self._run_authority_journal(
                        context=context, identity=identity, signer=signer, operation="prune",
                        run_hash=run_hash, index=index, next_index=next_index, record=record,
                        recovery={
                            "retention_expires_at_ms": runtime_state.retention_expires_at_ms,
                            "runtime_prune_pending_state_digest": expected_runtime_state_digest,
                            "detached_record_digest": detached["record_digest"],
                        },
                        created_at_ms=now_ms,
                    )
                    _write_json(runs_fd, _RUN_AUTHORITY_JOURNAL_FILENAME, journal)
                    self._ensure_json_exact(
                        runs_fd, self._run_authority_record_filename("prune", run_hash), record,
                    )
                    self._delete_directory_contents(run_fd)
                finally:
                    os.close(run_fd)
                os.rmdir(run_hash, dir_fd=runs_fd)
                _write_json(runs_fd, _RUN_AUTHORITY_INDEX_FILENAME, next_index)
                os.unlink(_RUN_AUTHORITY_JOURNAL_FILENAME, dir_fd=runs_fd)
                os.fsync(runs_fd)
                return VerifiedPrunedRunReceipt(record=record)
            finally:
                os.close(runs_fd)

    def load_pruned_run_receipt(
        self,
        run_id: str,
        *,
        expected_runtime_state_digest: str,
    ) -> VerifiedPrunedRunReceipt:
        """Load only an already-durable v2 prune receipt for the exact runtime state."""
        run_id = _id(run_id, "run ID")
        expected_runtime_state_digest = _digest(
            expected_runtime_state_digest, "runtime prune state digest",
        )
        identity, _signer = self._require_runtime_authority()
        run_hash = self._run_hash(run_id)
        with self._transaction(exclusive=True) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=False)
            if runs_fd is None:
                raise RunnerStoreError("local runtime prune receipt is unavailable")
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                # A journal means only prune_runtime_terminal may roll the mutation forward;
                # no caller may finish the runtime row from a merely prepared receipt.
                if _read_json(runs_fd, _RUN_AUTHORITY_JOURNAL_FILENAME, None) is not None:
                    raise RunnerStoreError("local runtime prune receipt is unavailable")
                value = _read_json(
                    runs_fd, self._run_authority_record_filename("prune", run_hash), None,
                )
                if value is None:
                    raise RunnerStoreError("local runtime prune receipt is unavailable")
                record = self._verify_runtime_pruned_record(value, identity=identity)
                if (
                    record["run_id"] != run_id
                    or record["run_hash"] != run_hash
                    or record["runtime_prune_pending_state_digest"] != expected_runtime_state_digest
                ):
                    raise RunnerStoreError("local terminal prune authority is invalid")
                return VerifiedPrunedRunReceipt(record=record)
            finally:
                os.close(runs_fd)

    def _detach_terminal_after_precheck(
        self, run_id: str, *, runtime: object, expected_local_state_digest: str,
        now_ms: int, identity: RunnerIdentity, signer: SecureSigner,
    ) -> str:
        # This opens the retained terminal files, validates q, grant, state and finals,
        # and also finishes a preceding detach journal with the concrete runtime.
        anchor = self._runtime_terminal_anchor(run_id, runtime=runtime)
        try:
            runtime_state = runtime.load_terminal_state(run_id)
        except (AttributeError, TypeError, ValueError) as exc:
            raise RunnerStoreError("local terminal detach recovery is required") from exc
        if (
            runtime_state is None
            or runtime_state.state != "local_terminal"
            or runtime_state.state_digest != expected_local_state_digest
            or runtime_state.run_hash != self._run_hash(run_id)
            or any(runtime_state_value != anchor[key] for runtime_state_value, key in (
                (runtime_state.project_id, "project_id"),
                (runtime_state.grant_id, "grant_id"),
                (runtime_state.approval_projection_digest, "approval_projection_digest"),
                (runtime_state.terminal_projection_digest, "terminal_projection_digest"),
                (runtime_state.terminal_record_digest, "terminal_record_digest"),
                (runtime_state.terminal_at_ms, "terminal_at_ms"),
                (runtime_state.retention_expires_at_ms, "retention_expires_at_ms"),
            ))
        ):
            raise RunnerStoreError("local terminal authority is invalid")

        with self._transaction(exclusive=True) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=False)
            if runs_fd is None:
                raise RunnerStoreError("local terminal authority is unavailable")
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                self._complete_run_authority_journal_locked(
                    context_fd, runs_fd, identity=identity, runtime=runtime,
                )
                index = self._run_authority_index_locked(runs_fd, identity=identity)
                run_hash = self._run_hash(run_id)
                queued = [item for item in index["terminal_queue"] if item["run_hash"] == run_hash]
                detached_name = self._run_authority_record_filename("detach_terminal", run_hash)
                existing = _read_json(runs_fd, detached_name, None)
                if not queued:
                    if existing is None:
                        raise RunnerStoreError("local terminal authority is unavailable")
                    detached = self._verify_signed_run_authority_value(
                        existing, identity=identity,
                        schema=_RUN_TERMINAL_DETACHED_RECORD_SCHEMA,
                        record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                    )
                    try:
                        state = runtime.load_terminal_state(run_id)
                    except (AttributeError, TypeError, ValueError) as exc:
                        raise RunnerStoreError("local terminal detach recovery is required") from exc
                    if (
                        state is None
                        or state.run_hash != run_hash
                        or state.terminal_record_digest != detached["terminal_record_digest"]
                        or state.terminal_projection_digest != detached["terminal_projection_digest"]
                        or state.retention_expires_at_ms != detached["retention_expires_at_ms"]
                        or not (
                            state.state == "local_terminal"
                            and state.state_digest == detached["runtime_state_digest"]
                            or state.state == "available"
                            and state.revision == 2
                            and state.prior_state_digest == detached["runtime_state_digest"]
                        )
                    ):
                        raise RunnerStoreError("local terminal authority is invalid")
                    return detached["record_digest"]
                if len(queued) != 1 or existing is not None:
                    raise RunnerStoreError("local terminal authority is invalid")
                terminal_value = _read_json(
                    runs_fd, self._run_authority_record_filename("terminal", run_hash), None,
                )
                if terminal_value is None:
                    raise RunnerStoreError("local terminal authority is unavailable")
                terminal = self._verify_signed_run_authority_value(
                    terminal_value, identity=identity, schema=_RUN_TERMINAL_RECORD_SCHEMA,
                    record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                )
                run_fd = _open_child(runs_fd, run_hash, create=False)
                if run_fd is None:
                    raise RunnerStoreError("local terminal authority run is unavailable")
                try:
                    _secure_directory(run_fd, "Heel terminal local run directory")
                    try:
                        grant = validate_execution_grant(_read_json(run_fd, "grant.json", None))
                    except (TypeError, ValueError):
                        raise RunnerStoreError("invalid stored execution grant") from None
                finally:
                    os.close(run_fd)
                if (
                    queued[0]["terminal_record_digest"] != terminal["record_digest"]
                    or queued[0]["retention_expires_at_ms"] != anchor["retention_expires_at_ms"]
                    or terminal["grant_id"] != grant["grant_id"]
                    or terminal["grant_digest"] != grant["grant_digest"]
                    or terminal["terminal_projection_digest"] != anchor["terminal_projection_digest"]
                    or terminal["terminal_at_ms"] != anchor["terminal_at_ms"]
                    or terminal["retention_expires_at_ms"] != anchor["retention_expires_at_ms"]
                ):
                    raise RunnerStoreError("local terminal authority is invalid")
                context = _context_from_dict(self._binding_locked(context_fd)["context"])
                detached = self._run_authority_record(
                    operation="detach_terminal", context=context, identity=identity, signer=signer,
                    run_hash=run_hash, grant=grant,
                    state={
                        "retention_expires_at_ms": anchor["retention_expires_at_ms"],
                        "updated_at_ms": anchor["terminal_at_ms"],
                    },
                    index=index,
                    terminal={
                        "terminal_record_digest": terminal["record_digest"],
                        "terminal_projection_digest": terminal["terminal_projection_digest"],
                        "terminal_at_ms": terminal["terminal_at_ms"],
                        "runtime_state_digest": expected_local_state_digest,
                    },
                    detached_at_ms=now_ms,
                )
                next_index = self._next_run_authority_index(
                    index, signer=signer, delta=0, head_digest=detached["record_digest"],
                    terminal_queue=[
                        item for item in index["terminal_queue"] if item["run_hash"] != run_hash
                    ],
                )
                journal = self._run_authority_journal(
                    context=context, identity=identity, signer=signer, operation="detach_terminal",
                    run_hash=run_hash, index=index, next_index=next_index, record=detached,
                    recovery={
                        "runtime_state_schema": "heel.runner-terminal-disclosure-state.v1",
                        "runtime_state": "local_terminal",
                        "runtime_state_digest": expected_local_state_digest,
                        "terminal_record_digest": terminal["record_digest"],
                        "retention_expires_at_ms": anchor["retention_expires_at_ms"],
                    },
                    created_at_ms=now_ms,
                )
                _write_json(runs_fd, _RUN_AUTHORITY_JOURNAL_FILENAME, journal)
                self._ensure_json_exact(runs_fd, detached_name, detached)
                _write_json(runs_fd, _RUN_AUTHORITY_INDEX_FILENAME, next_index)
                os.unlink(_RUN_AUTHORITY_JOURNAL_FILENAME, dir_fd=runs_fd)
                os.fsync(runs_fd)
                return detached["record_digest"]
            finally:
                os.close(runs_fd)

    def load_run_events(self, run_id: str) -> list[dict[str, Any]]:
        with self._transaction(exclusive=False) as context_fd:
            with self._open_run(context_fd, run_id, create=False) as run_fd:
                self._run_state_locked(run_fd, run_id)
                events_fd = _open_child(run_fd, "events", create=False)
                if events_fd is None:
                    return []
                try:
                    _secure_directory(events_fd, "Heel containment events directory")
                    entries = sorted(os.listdir(events_fd))
                    if any(
                        _EVENT_FILENAME.fullmatch(name) is None
                        and _CREATE_TEMP_FILENAME.fullmatch(name) is None
                        for name in entries
                    ):
                        raise RunnerStoreError("invalid containment event filename")
                    for name in entries:
                        if _CREATE_TEMP_FILENAME.fullmatch(name) is not None:
                            _secure_regular(
                                os.stat(name, dir_fd=events_fd, follow_symlinks=False),
                                "unfinished containment event",
                            )
                    names = [name for name in entries if _EVENT_FILENAME.fullmatch(name)]
                    return [_read_json(events_fd, name, None) for name in names]
                finally:
                    os.close(events_fd)

    def _verified_containment_summary(
        self,
        run_id: str,
        operational: Mapping[str, Any],
        findings: Mapping[str, Any],
    ) -> dict[str, Any]:
        from heel.runner.containment import (
            ContainmentError,
            operational_containment_codes,
            verify_containment_chain,
        )

        state = self.load_run(run_id)
        grant = self.load_run_grant(run_id)
        keys = self.load_run_trusted_keys(run_id)
        key_id, public_key = next(iter(keys.items()))
        try:
            events = verify_containment_chain(
                self.load_run_events(run_id),
                public_key=public_key,
                runner_key_id=key_id,
                run_id=run_id,
                grant_id=state["grant_id"],
                manifest_digest=state["manifest_digest"],
            )
        except (ContainmentError, TypeError, ValueError):
            raise RunnerStoreError("stored containment chain is invalid") from None
        event_sequence = operational["event_sequence"]
        final_event = events[event_sequence] if events and event_sequence < len(events) else None
        exact_projection_binding = all(
            record["run_id"] == run_id
            and record["grant_id"] == state["grant_id"] == grant["grant_id"]
            and record["grant_digest"] == state["grant_digest"] == grant["grant_digest"]
            and record["manifest_digest"] == state["manifest_digest"]
            == grant["approval"]["manifest_digest"]
            and record["workspace_id"] == grant["workspace_id"]
            and record["project_id"] == grant["project_id"]
            and record["approval_projection_digest"]
            == grant["approval"]["projection_digest"]
            for record in (operational, findings)
        )
        if (
            not events
            or event_sequence >= len(events)
            or final_event is None
            or final_event["event_code"] != "run_finalized"
            or final_event["detail_code"] != operational["execution_disposition"]
            or final_event["counters"] != {
                key: operational["counters"][key] for key in final_event["counters"]
            }
            or not exact_projection_binding
            or findings["environment_id"] != grant["environment"]["environment_id"]
            or operational["containment_codes"]
            != operational_containment_codes(events[:event_sequence + 1])
            or findings["containment_codes"] != operational["containment_codes"]
            or findings["redaction_count"] != operational["redaction_count"]
            or sum(
                item["redaction_count"] for item in findings["scenario_results"]
            ) != operational["redaction_count"]
        ):
            raise RunnerStoreError("stored containment chain projection mismatch")
        return {
            "event_count": len(events),
            "head_digest": events[-1]["event_digest"],
            "codes": sorted({event["event_code"] for event in events}),
            "redaction_count": operational["redaction_count"],
        }

    def append_run_event(self, run_id: str, event: Mapping[str, Any]) -> None:
        sequence = event.get("sequence") if isinstance(event, Mapping) else None
        if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence < 100_000:
            raise ValueError("invalid containment event sequence")
        filename = f"{sequence:020d}.json"
        with self._transaction(exclusive=True) as context_fd:
            with self._open_run(context_fd, run_id, create=False) as run_fd:
                self._run_state_locked(run_fd, run_id)
                events_fd = _open_child(run_fd, "events", create=True)
                assert events_fd is not None
                try:
                    _secure_directory(events_fd, "Heel containment events directory")
                    entries = sorted(os.listdir(events_fd))
                    if any(
                        _EVENT_FILENAME.fullmatch(name) is None
                        and _CREATE_TEMP_FILENAME.fullmatch(name) is None
                        for name in entries
                    ):
                        raise RunnerStoreError("invalid containment event filename")
                    for name in entries:
                        if _CREATE_TEMP_FILENAME.fullmatch(name) is not None:
                            _secure_regular(
                                os.stat(name, dir_fd=events_fd, follow_symlinks=False),
                                "unfinished containment event",
                            )
                    names = [name for name in entries if _EVENT_FILENAME.fullmatch(name)]
                    if sequence != len(names):
                        raise RunnerStoreError("containment event sequence is not append-only")
                    try:
                        _create_json(events_fd, filename, dict(event))
                    except FileExistsError:
                        raise RunnerStoreError("containment event already exists") from None
                finally:
                    os.close(events_fd)

    def save_final_projections(
        self,
        run_id: str,
        operational_projection: Mapping[str, Any],
        findings_projection: Mapping[str, Any],
        local_view: Mapping[str, Any],
        disclosure_preview: Mapping[str, Any],
    ) -> None:
        from heel.runner.companion import validate_disclosure_preview, validate_local_result_view

        identity, _signer = self._require_runtime_authority()
        operational = validate_operational_run(operational_projection)
        findings = validate_canary_findings(findings_projection)
        keys = self.load_run_trusted_keys(run_id)
        try:
            for record in (operational, findings):
                unsigned = {
                    key: value for key, value in record.items()
                    if key not in {"projection_digest", "signing_key_id", "signature_b64"}
                }
                verify_envelope(
                    keys,
                    {"signing_key_id": record["signing_key_id"],
                     "signature_b64": record["signature_b64"]},
                    canonical_bytes(unsigned),
                )
        except (TypeError, ValueError):
            raise RunnerStoreError("local final projection signature is invalid") from None
        safe_view = validate_local_result_view(local_view, trusted_runner_keys=keys)
        safe_disclosure = validate_disclosure_preview(
            disclosure_preview, trusted_runner_keys=keys,
        )
        expected_summary = self._verified_containment_summary(
            run_id, operational, findings,
        )
        if (
            operational["run_id"] != run_id
            or findings["run_id"] != run_id
            or operational["grant_id"] != findings["grant_id"]
            or safe_view["operational_projection"] != operational
            or safe_view["findings_projection"] != findings
            or safe_disclosure["projection"] != findings
        ):
            raise ValueError("final projections do not bind the local run")
        if safe_view["containment_summary"] != expected_summary:
            raise RunnerStoreError("local containment summary does not match signed events")
        final_core = {
            "schema_version": _FINALS_SCHEMA,
            "operational_projection": operational,
            "findings_projection": findings,
            "local_view": safe_view,
            "disclosure_preview": safe_disclosure,
        }
        envelope = {**final_core, "finals_digest": canonical_digest(final_core)}
        with self._transaction(exclusive=True) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=False)
            if runs_fd is None:
                raise RunnerStoreError("local run is unavailable")
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                self._complete_run_authority_journal_locked(
                    context_fd, runs_fd, identity=identity,
                )
                index = self._run_authority_index_locked(runs_fd, identity=identity)
                run_hash = self._run_hash(run_id)
                terminal = next(
                    (item for item in index["terminal_queue"] if item["run_hash"] == run_hash),
                    None,
                )
                if terminal is not None:
                    record = _read_json(
                        runs_fd, self._run_authority_record_filename("terminal", run_hash), None,
                    )
                    if record is None:
                        raise RunnerStoreError("local run authority terminal queue is invalid")
                    record = self._verify_signed_run_authority_value(
                        record, identity=identity, schema=_RUN_TERMINAL_RECORD_SCHEMA,
                        record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                    )
                    if (
                        record["record_digest"] != terminal["terminal_record_digest"]
                        or record["terminal_projection_digest"] != operational["projection_digest"]
                    ):
                        raise RunnerStoreError("local run authority terminal queue is invalid")
                with self._open_run(context_fd, run_id, create=False) as run_fd:
                    self._run_state_locked(run_fd, run_id)
                    try:
                        _create_json(run_fd, "finals.json", envelope)
                    except FileExistsError:
                        if _read_json(run_fd, "finals.json", None) != envelope:
                            raise RunnerStoreError("immutable final projection collision") from None
            finally:
                os.close(runs_fd)

    def load_final_projections(self, run_id: str) -> dict[str, Any]:
        with self._transaction(exclusive=False) as context_fd:
            with self._open_run(context_fd, run_id, create=False) as run_fd:
                self._run_state_locked(run_fd, run_id)
                envelope = _read_json(run_fd, "finals.json", None)
                if envelope is not None:
                    fields = {
                        "schema_version", "operational_projection", "findings_projection",
                        "local_view", "disclosure_preview", "finals_digest",
                    }
                    if (
                        not isinstance(envelope, Mapping)
                        or set(envelope) != fields
                        or envelope["schema_version"] != _FINALS_SCHEMA
                    ):
                        raise RunnerStoreError("local final projection envelope is invalid")
                    core = {
                        key: envelope[key] for key in fields if key != "finals_digest"
                    }
                    if envelope["finals_digest"] != canonical_digest(core):
                        raise RunnerStoreError("local final projection envelope digest mismatch")
                    result = {
                        key: envelope[key]
                        for key in (
                            "operational_projection", "findings_projection",
                            "local_view", "disclosure_preview",
                        )
                    }
                else:
                    result = {
                        name: _read_json(run_fd, filename, None)
                        for name, filename in (
                            ("operational_projection", "operational.json"),
                            ("findings_projection", "findings.json"),
                            ("local_view", "local-view.json"),
                            ("disclosure_preview", "disclosure-preview.json"),
                        )
                    }
        if any(value is None for value in result.values()):
            raise RunnerStoreError("local final projections are unavailable")
        result["operational_projection"] = validate_operational_run(
            result["operational_projection"]
        )
        result["findings_projection"] = validate_canary_findings(result["findings_projection"])
        from heel.runner.companion import validate_disclosure_preview, validate_local_result_view
        keys = self.load_run_trusted_keys(run_id)
        try:
            for record in (result["operational_projection"], result["findings_projection"]):
                unsigned = {
                    key: value for key, value in record.items()
                    if key not in {"projection_digest", "signing_key_id", "signature_b64"}
                }
                verify_envelope(
                    keys,
                    {"signing_key_id": record["signing_key_id"],
                     "signature_b64": record["signature_b64"]},
                    canonical_bytes(unsigned),
                )
        except (TypeError, ValueError):
            raise RunnerStoreError("local final projection signature is invalid") from None
        result["local_view"] = validate_local_result_view(
            result["local_view"], trusted_runner_keys=keys,
        )
        result["disclosure_preview"] = validate_disclosure_preview(
            result["disclosure_preview"], trusted_runner_keys=keys,
        )
        expected_summary = self._verified_containment_summary(
            run_id, result["operational_projection"], result["findings_projection"],
        )
        if (
            result["local_view"]["operational_projection"] != result["operational_projection"]
            or result["local_view"]["findings_projection"] != result["findings_projection"]
            or result["disclosure_preview"]["projection"] != result["findings_projection"]
        ):
            raise RunnerStoreError("local final projection binding mismatch")
        if result["local_view"]["containment_summary"] != expected_summary:
            raise RunnerStoreError("local containment summary does not match signed events")
        return result

    def store_response_evidence(
        self,
        run_id: str,
        *,
        action_ordinal: int,
        attempt: int,
        status_code: int,
        raw_headers: bytes,
        raw_body: bytes,
        expires_at_ms: int,
    ) -> str:
        values = (action_ordinal, attempt, status_code, expires_at_ms)
        if (
            any(isinstance(value, bool) or not isinstance(value, int) for value in values)
            or not 0 <= action_ordinal < 20
            or not 1 <= attempt <= 2
            or not 100 <= status_code <= 599
            or expires_at_ms < 0
        ):
            raise ValueError("invalid local evidence metadata")
        if not isinstance(raw_headers, bytes) or not isinstance(raw_body, bytes):
            raise TypeError("local response evidence must be bytes")
        if len(raw_headers) > _MAX_EVIDENCE_HEADER_BYTES or len(raw_body) > _MAX_EVIDENCE_BODY_BYTES:
            raise ValueError("local response evidence exceeds bound")
        payload = len(raw_headers).to_bytes(4, "big") + raw_headers + raw_body
        content_sha256 = hashlib.sha256(payload).hexdigest()
        with self._transaction(exclusive=True) as context_fd:
            with self._open_run(context_fd, run_id, create=False) as run_fd:
                state = self._run_state_locked(run_fd, run_id)
                if expires_at_ms > state["retention_expires_at_ms"]:
                    raise ValueError("evidence expiry exceeds manifest retention")
                evidence_fd = _open_child(run_fd, "evidence", create=True)
                assert evidence_fd is not None
                try:
                    _secure_directory(evidence_fd, "Heel local evidence directory")
                    descriptor = -1
                    reference = ""
                    for _ in range(8):
                        candidate = "ev1_" + secrets.token_hex(32)
                        try:
                            os.stat(
                                candidate + ".meta", dir_fd=evidence_fd,
                                follow_symlinks=False,
                            )
                        except FileNotFoundError:
                            pass
                        else:
                            continue
                        try:
                            descriptor = os.open(
                                candidate + ".bin", _BINARY_WRITE_FLAGS, 0o600,
                                dir_fd=evidence_fd,
                            )
                        except FileExistsError:
                            continue
                        reference = candidate
                        break
                    if descriptor < 0:
                        raise RunnerStoreError("local evidence reference allocation failed")
                    try:
                        os.fchmod(descriptor, 0o600)
                        view = memoryview(payload)
                        while view:
                            written = os.write(descriptor, view)
                            if written < 1:
                                raise OSError("short evidence write")
                            view = view[written:]
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    _create_json(evidence_fd, reference + ".meta", {
                        "schema_version": "heel.local-evidence-metadata.v1",
                        "reference": reference,
                        "action_ordinal": action_ordinal,
                        "attempt": attempt,
                        "status_code": status_code,
                        "expires_at_ms": expires_at_ms,
                        "content_sha256": content_sha256,
                    })
                    os.fsync(evidence_fd)
                finally:
                    os.close(evidence_fd)
        return reference

    def load_response_evidence(
        self, run_id: str, reference: str, *, now_ms: int,
    ) -> tuple[bytes, bytes]:
        if type(reference) is not str or _EVIDENCE_REF.fullmatch(reference) is None:
            raise ValueError("invalid local evidence reference")
        if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms < 0:
            raise ValueError("invalid local evidence read time")
        with self._transaction(exclusive=False) as context_fd:
            with self._open_run(context_fd, run_id, create=False) as run_fd:
                self._run_state_locked(run_fd, run_id)
                evidence_fd = _open_child(run_fd, "evidence", create=False)
                if evidence_fd is None:
                    raise RunnerStoreError("local evidence is unavailable")
                try:
                    _secure_directory(evidence_fd, "Heel local evidence directory")
                    metadata = _read_json(evidence_fd, reference + ".meta", None)
                    if (
                        not isinstance(metadata, Mapping)
                        or set(metadata) != {
                            "schema_version", "reference", "action_ordinal", "attempt",
                            "status_code", "expires_at_ms", "content_sha256",
                        }
                        or metadata["schema_version"] != "heel.local-evidence-metadata.v1"
                        or metadata["reference"] != reference
                        or any(
                            isinstance(metadata[field], bool)
                            or not isinstance(metadata[field], int)
                            for field in ("action_ordinal", "attempt", "status_code")
                        )
                        or not 0 <= metadata["action_ordinal"] < 20
                        or not 1 <= metadata["attempt"] <= 2
                        or not 100 <= metadata["status_code"] <= 599
                        or type(metadata["content_sha256"]) is not str
                        or _DIGEST.fullmatch(metadata["content_sha256"]) is None
                        or isinstance(metadata["expires_at_ms"], bool)
                        or not isinstance(metadata["expires_at_ms"], int)
                        or now_ms >= metadata["expires_at_ms"]
                    ):
                        raise RunnerStoreError("local evidence is expired or invalid")
                    descriptor = os.open(reference + ".bin", _READ_FLAGS, dir_fd=evidence_fd)
                    try:
                        status = os.fstat(descriptor)
                        _secure_regular(status, "local response evidence")
                        if status.st_size > 4 + _MAX_EVIDENCE_HEADER_BYTES + _MAX_EVIDENCE_BODY_BYTES:
                            raise RunnerStoreError("local evidence exceeds bound")
                        payload = bytearray()
                        while len(payload) <= 4 + _MAX_EVIDENCE_HEADER_BYTES + _MAX_EVIDENCE_BODY_BYTES:
                            chunk = os.read(descriptor, 64 * 1024)
                            if not chunk:
                                break
                            payload.extend(chunk)
                    finally:
                        os.close(descriptor)
                finally:
                    os.close(evidence_fd)
        if len(payload) < 4:
            raise RunnerStoreError("local evidence is invalid")
        header_length = int.from_bytes(payload[:4], "big")
        if header_length > _MAX_EVIDENCE_HEADER_BYTES:
            raise RunnerStoreError("local evidence is invalid")
        headers = bytes(payload[4:4 + header_length])
        body = bytes(payload[4 + header_length:])
        if len(body) > _MAX_EVIDENCE_BODY_BYTES:
            raise RunnerStoreError("local evidence is invalid")
        if hashlib.sha256(bytes(payload)).hexdigest() != metadata["content_sha256"]:
            raise RunnerStoreError("local evidence digest mismatch")
        return headers, body

    @staticmethod
    def _delete_directory_contents(directory_fd: int) -> None:
        """Delete only validated owner-controlled files/directories below an anchored fd."""
        with os.scandir(directory_fd) as entries:
            names = [entry.name for entry in entries]
        for name in names:
            if name in {".", ".."} or "/" in name or "\x00" in name:
                raise RunnerStoreError("unsafe local retention entry")
            status = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(status.st_mode):
                child = os.open(name, _DIRECTORY_FLAGS, dir_fd=directory_fd)
                try:
                    _secure_directory(child, "Heel retained run directory")
                    RunnerStore._delete_directory_contents(child)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=directory_fd)
            else:
                _secure_regular(status, "Heel retained run file")
                os.unlink(name, dir_fd=directory_fd)

    def prune_expired_evidence(self, *, now_ms: int) -> int:
        """Prune evidence by its own TTL even when the containing run is nonterminal."""
        if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms < 0:
            raise ValueError("invalid local evidence retention time")
        removed = 0
        with self._transaction(exclusive=True) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=False)
            if runs_fd is None:
                return 0
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                for run_name in sorted(os.listdir(runs_fd)):
                    if _RUN_FILENAME.fullmatch(run_name) is None:
                        continue
                    run_fd = os.open(run_name, _DIRECTORY_FLAGS, dir_fd=runs_fd)
                    try:
                        _secure_directory(run_fd, "Heel retained local run directory")
                        evidence_fd = _open_child(run_fd, "evidence", create=False)
                        if evidence_fd is None:
                            continue
                        try:
                            _secure_directory(evidence_fd, "Heel local evidence directory")
                            names = set(os.listdir(evidence_fd))
                            removed_temporary = False
                            for name in tuple(names):
                                if _CREATE_TEMP_FILENAME.fullmatch(name) is None:
                                    continue
                                _secure_regular(
                                    os.stat(name, dir_fd=evidence_fd, follow_symlinks=False),
                                    "unfinished local evidence metadata",
                                )
                                os.unlink(name, dir_fd=evidence_fd)
                                names.remove(name)
                                removed_temporary = True
                            references: set[str] = set()
                            for name in names:
                                suffix = ".meta" if name.endswith(".meta") else ".bin" if name.endswith(".bin") else None
                                reference = name[:-len(suffix)] if suffix is not None else ""
                                if suffix is None or _EVIDENCE_REF.fullmatch(reference) is None:
                                    raise RunnerStoreError("invalid local evidence retention entry")
                                references.add(reference)
                            for reference in sorted(references):
                                metadata_name = reference + ".meta"
                                binary_name = reference + ".bin"
                                metadata = (
                                    _read_json(evidence_fd, metadata_name, None)
                                    if metadata_name in names else None
                                )
                                expires = metadata.get("expires_at_ms") if isinstance(metadata, Mapping) else None
                                expired = (
                                    metadata is None
                                    or binary_name not in names
                                    or isinstance(expires, bool)
                                    or not isinstance(expires, int)
                                    or expires <= now_ms
                                )
                                if not expired:
                                    continue
                                for filename in (binary_name, metadata_name):
                                    if filename not in names:
                                        continue
                                    status = os.stat(
                                        filename, dir_fd=evidence_fd, follow_symlinks=False,
                                    )
                                    _secure_regular(status, "Heel local evidence retention file")
                                    os.unlink(filename, dir_fd=evidence_fd)
                                removed += 1
                            if removed or removed_temporary:
                                os.fsync(evidence_fd)
                        finally:
                            os.close(evidence_fd)
                    finally:
                        os.close(run_fd)
            finally:
                os.close(runs_fd)
        return removed

    def prune_expired_runs(self, *, now_ms: int) -> int:
        # Terminal retention is now anchored in the authenticated runtime ledger.
        # A queue-only caller cannot prove the corresponding durable runtime CAS.
        raise RunnerStoreError("runtime terminal prune is required")
        identity, signer = self._require_runtime_authority()
        if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms < 0:
            raise ValueError("invalid local retention time")
        removed = 0
        with self._transaction(exclusive=True) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=False)
            if runs_fd is None:
                return 0
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                self._complete_run_authority_journal_locked(
                    context_fd, runs_fd, identity=identity,
                )
                for _ in range(_RUN_PRUNE_BATCH):
                    index = self._run_authority_index_locked(runs_fd, identity=identity)
                    if not index["terminal_queue"] or index["terminal_queue"][0]["retention_expires_at_ms"] > now_ms:
                        break
                    queue_item = index["terminal_queue"][0]
                    run_hash = queue_item["run_hash"]
                    terminal_record = _read_json(
                        runs_fd, self._run_authority_record_filename("terminal", run_hash), None,
                    )
                    if terminal_record is None:
                        raise RunnerStoreError("local terminal authority record is unavailable")
                    terminal_record = self._verify_signed_run_authority_value(
                        terminal_record, identity=identity, schema=_RUN_TERMINAL_RECORD_SCHEMA,
                        record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                    )
                    if terminal_record.get("record_digest") != queue_item["terminal_record_digest"]:
                        raise RunnerStoreError("local terminal authority queue is invalid")
                    run_fd = _open_child(runs_fd, run_hash, create=False)
                    if run_fd is None:
                        raise RunnerStoreError("local terminal authority run is unavailable")
                    try:
                        _secure_directory(run_fd, "Heel retained local run directory")
                        grant = _read_json(run_fd, "grant.json", None)
                        try:
                            grant = validate_execution_grant(grant)
                        except (TypeError, ValueError):
                            raise RunnerStoreError("invalid stored execution grant") from None
                        state = self._run_state_locked(run_fd, grant["run_id"])
                        finals = _read_json(run_fd, "finals.json", None)
                        if (
                            state["state"] != "terminal"
                            or state["retention_expires_at_ms"] != queue_item["retention_expires_at_ms"]
                            or not isinstance(finals, Mapping)
                            or finals.get("schema_version") != _FINALS_SCHEMA
                            or terminal_record.get("terminal_state_digest") != canonical_digest(state)
                            or terminal_record.get("terminal_projection_digest")
                            != finals.get("operational_projection", {}).get("projection_digest")
                        ):
                            raise RunnerStoreError("local terminal authority state is invalid")
                        context = _context_from_dict(self._binding_locked(context_fd)["context"])
                        record = self._run_authority_record(
                            operation="prune", context=context, identity=identity, signer=signer,
                            run_hash=run_hash, grant=grant, state=state, index=index,
                            terminal={
                                "terminal_record_digest": terminal_record["record_digest"],
                                "terminal_projection_digest": terminal_record["terminal_projection_digest"],
                                "terminal_at_ms": terminal_record["terminal_at_ms"],
                            }, pruned_at_ms=now_ms,
                        )
                        next_index = self._next_run_authority_index(
                            index, signer=signer, delta=0, head_digest=record["record_digest"],
                            terminal_queue=list(index["terminal_queue"])[1:],
                        )
                        journal = self._run_authority_journal(
                            context=context, identity=identity, signer=signer, operation="prune",
                            run_hash=run_hash, index=index, next_index=next_index, record=record,
                            recovery={"retention_expires_at_ms": state["retention_expires_at_ms"]},
                            created_at_ms=now_ms,
                        )
                        _write_json(runs_fd, _RUN_AUTHORITY_JOURNAL_FILENAME, journal)
                        self._ensure_json_exact(
                            runs_fd, self._run_authority_record_filename("prune", run_hash), record,
                        )
                        self._delete_directory_contents(run_fd)
                    finally:
                        os.close(run_fd)
                    os.rmdir(run_hash, dir_fd=runs_fd)
                    _write_json(runs_fd, _RUN_AUTHORITY_INDEX_FILENAME, next_index)
                    os.unlink(_RUN_AUTHORITY_JOURNAL_FILENAME, dir_fd=runs_fd)
                    os.fsync(runs_fd)
                    removed += 1
            finally:
                os.close(runs_fd)
        return removed


def new_credential_handle_id() -> str:
    """Compatibility helper; CLI intentionally never accepts or displays its result."""
    return secrets.token_hex(16)
