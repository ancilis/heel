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
    validate_test_manifest,
    validate_runner_context_binding,
)
from heel.crypto import ed25519_key_id, load_public_key_base64, verify_envelope
from heel.runner.identity import RunnerIdentity, SecureSigner
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
_CONTEXT_ROLLOVER_SCHEMA = "heel.runner-context-rollover.v1"
_CONTEXT_INSTALL_SCHEMA = "heel.runner-context-install.v1"
_RUN_AUTHORITY_INDEX_SCHEMA = "heel.local-run-authority-index.v1"
_RUN_RESERVATION_RECORD_SCHEMA = "heel.local-run-reservation.v1"
_RUN_TERMINAL_RECORD_SCHEMA = "heel.local-run-terminal.v1"
_RUN_PRUNED_RECORD_SCHEMA = "heel.local-run-pruned.v1"
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
    _RUN_PRUNED_RECORD_SCHEMA: b"heel.local-run-pruned.v1\0",
    _RUN_AUTHORITY_MUTATION_SCHEMA: b"heel.local-run-authority-mutation.v1\0",
}


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
            with self._transaction(exclusive=False, allow_rollover_journal=True) as context_fd:
                if self._binding_locked(context_fd)["identity"] != record:
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
                "generation", "nonterminal_count", "terminal_queue", "head_digest", "signing_key_id", "signature_b64",
            }
            or checked["namespace"] != self.namespace
            or checked["workspace_id"] != identity.workspace_id
            or checked["runner_id"] != identity.runner_id
            or checked["runner_key_id"] != identity.key_id
            or type(checked["generation"]) is not int or checked["generation"] < 0
            or type(checked["nonterminal_count"]) is not int
            or not 0 <= checked["nonterminal_count"] <= _RUN_AUTHORITY_MAX_NONTERMINAL
            or not isinstance(checked["terminal_queue"], list)
            or len(checked["terminal_queue"]) > _RUN_AUTHORITY_MAX_TRACKED
            or checked["nonterminal_count"] + len(checked["terminal_queue"]) > _RUN_AUTHORITY_MAX_TRACKED
            or _DIGEST.fullmatch(checked["head_digest"]) is None
        ):
            raise RunnerStoreError("local run authority index is invalid")
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
        terminal_queue: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        next_count = index["nonterminal_count"] + delta
        queue = list(index["terminal_queue"] if terminal_queue is None else terminal_queue)
        if not 0 <= next_count or next_count + len(queue) > _RUN_AUTHORITY_MAX_TRACKED:
            raise RunnerStoreError("local run authority capacity is exhausted")
        return self._signed_run_authority_value({
            "schema_version": _RUN_AUTHORITY_INDEX_SCHEMA,
            "namespace": index["namespace"], "workspace_id": index["workspace_id"],
            "runner_id": index["runner_id"], "runner_key_id": index["runner_key_id"],
            "generation": index["generation"] + 1, "nonterminal_count": next_count,
            "terminal_queue": queue,
            "head_digest": _digest(head_digest, "local run authority head"),
        }, signer=signer, record_digest=False)

    @staticmethod
    def _run_authority_record_filename(kind: str, run_hash: str) -> str:
        if _RUN_FILENAME.fullmatch(run_hash) is None:
            raise RunnerStoreError("invalid local run authority hash")
        prefix = {
            "reserve": "reservation-", "terminal": "terminal-", "prune": "pruned-",
        }.get(kind)
        if prefix is None:
            raise RunnerStoreError("invalid local run authority operation")
        return f"{prefix}{run_hash}.json"

    def _run_authority_record(
        self, *, operation: str, context: RunnerContext, identity: RunnerIdentity,
        signer: SecureSigner, run_hash: str, grant: Mapping[str, Any], state: Mapping[str, Any],
        index: Mapping[str, Any], terminal: Mapping[str, Any] | None = None,
        pruned_at_ms: int | None = None,
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
        if operation not in {"reserve", "terminal", "prune"}:
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
            or checked["runner_key_id"] != identity.key_id or checked["operation"] not in {"reserve", "terminal", "prune"}
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
            "prune": _RUN_PRUNED_RECORD_SCHEMA,
        }[operation]
        record = self._verify_signed_run_authority_value(
            journal["record"], identity=identity, schema=record_schema,
            record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
        )
        if record.get("run_hash") != run_hash:
            raise RunnerStoreError("local run authority journal record changed")
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
        else:
            if set(recovery) != {"retention_expires_at_ms"} or recovery["retention_expires_at_ms"] != record.get("retention_expires_at_ms"):
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
    def _transaction(self, *, exclusive: bool, allow_rollover_journal: bool = False) -> Iterator[int]:
        with self._open_context(create=False) as context_fd:
            with _flock(context_fd, ".metadata.lock", exclusive=exclusive):
                if (
                    not allow_rollover_journal
                    and _read_json(context_fd, "context-rollover.json", None) is not None
                ):
                    raise RunnerStoreError("cloud context rollover requires recovery")
                self._validate_binding_locked(context_fd)
                yield context_fd

    def _select_active_if_present(self) -> None:
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=False):
                active = _read_json(runner_fd, "active-context.json", None)
        if active is None:
            return
        if not isinstance(active, Mapping) or set(active) != {"schema_version", "namespace"}:
            raise RunnerStoreError("invalid active runner context")
        if active["schema_version"] != "heel.active-runner-context.v1":
            raise RunnerStoreError("invalid active runner context")
        self._namespace = _digest(active["namespace"], "runner namespace")
        with self._transaction(exclusive=False, allow_rollover_journal=True):
            pass

    def _has_pending_cloud_install(self) -> bool:
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=False):
                return _read_json(runner_fd, "context-install.json", None) is not None

    def _context_install_journal(
        self, *, binding: Mapping[str, Any], context: RunnerContext,
        identity: RunnerIdentity, signer: SecureSigner,
    ) -> dict[str, Any]:
        identity_record = _identity_record(identity, signer)
        unsigned = {
            "schema_version": _CONTEXT_INSTALL_SCHEMA, "namespace": context.namespace,
            "context": context.as_dict(), "artifact": dict(binding), "identity": identity_record,
        }
        return {
            **unsigned, "signing_key_id": signer.key_id,
            "signature_b64": base64.b64encode(signer.sign(canonical_bytes(unsigned))).decode("ascii"),
        }

    def _stage_context_install_journal(
        self, *, binding: Mapping[str, Any], context: RunnerContext,
        identity: RunnerIdentity, signer: SecureSigner,
    ) -> dict[str, Any]:
        journal = self._context_install_journal(
            binding=binding, context=context, identity=identity, signer=signer,
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

    def _finish_context_install_journal(self, *, context: RunnerContext, journal: Mapping[str, Any]) -> None:
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            with _flock(runner_fd, ".runner.lock", exclusive=True):
                if _read_json(runner_fd, "context-install.json", None) != dict(journal):
                    raise RunnerStoreError("cloud context installation journal changed")
                expected_active = {
                    "schema_version": "heel.active-runner-context.v1", "namespace": context.namespace,
                }
                active = _read_json(runner_fd, "active-context.json", None)
                if active is not None and active != expected_active:
                    raise RunnerStoreError("cloud context binding cannot replace active context")
                if active is None:
                    _write_json(runner_fd, "active-context.json", expected_active)
                os.unlink("context-install.json", dir_fd=runner_fd)
                os.fsync(runner_fd)

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
            "signing_key_id", "signature_b64",
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
    ) -> None:
        if not isinstance(context, RunnerContext):
            raise ValueError("RunnerContext is required")
        identity_record = _identity_record(identity, signer)
        if identity_record["workspace_id"] != context.workspace_id:
            raise ValueError("runner identity workspace does not match target context")
        signer_label = _id(signer_label, "runner signer label")
        namespace = context.namespace
        binding = {
            "schema_version": "heel.bound-runner-context.v1",
            "namespace": namespace,
            "context": context.as_dict(),
            "identity": identity_record,
            "signer_label": signer_label,
        }
        previous = self._namespace
        self._namespace = namespace
        try:
            with self._open_runner(create=True) as runner_fd:
                assert runner_fd is not None
                with _flock(runner_fd, ".runner.lock", exclusive=True):
                    if publish_active and _read_json(runner_fd, "context-install.json", None) is not None:
                        raise RunnerStoreError("cloud context installation requires recovery")
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
                            initial_bind = existing is None
                            if existing is None:
                                _write_json(context_fd, "binding.json", binding)
                            self._initialize_run_authority_index_locked(
                                context_fd, context=context, identity=identity, signer=signer,
                                initial_bind=initial_bind,
                            )
                        if publish_active:
                            _write_json(runner_fd, "active-context.json", {
                                "schema_version": "heel.active-runner-context.v1",
                                "namespace": namespace,
                            })
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
                with self._transaction(exclusive=False, allow_rollover_journal=True) as context_fd:
                    raw_journal = _read_json(context_fd, "context-rollover.json", None)
                    if raw_journal is None:
                        raise
                    pending_journal = self._validate_context_rollover_journal(
                        raw_journal, identity=identity, expected_artifact=binding,
                        expected_evidence=rollover_evidence, expected_context=context,
                    )
                    active_context = _context_from_dict(self._binding_locked(context_fd)["context"])
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
                    with self._transaction(exclusive=False, allow_rollover_journal=True) as context_fd:
                        raw_journal = _read_json(context_fd, "context-rollover.json", None)
                        if raw_journal is not None:
                            pending_journal = self._validate_context_rollover_journal(
                                raw_journal, identity=identity, expected_artifact=binding,
                                expected_evidence=None, expected_context=context,
                            )
                            local = self._binding_locked(context_fd)
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
        install_journal: dict[str, Any] | None = pending_install[2] if pending_install is not None else None
        try:
            # A first Cloud installation never publishes the active selector
            # until the signed sidecar is durably present and revalidated.
            if not was_bound:
                if pending_install is None:
                    install_journal = self._stage_context_install_journal(
                        binding=binding, context=context, identity=identity, signer=signer,
                    )
                    self._bind_context(
                        context, identity=identity, signer=signer, signer_label=signer_label,
                        publish_active=False,
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
                        )
            receipt_consumed = False
            with self._transaction(exclusive=True, allow_rollover_journal=rollover) as context_fd:
                existing = _read_json(context_fd, "cloud-context-binding.json", None)
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
                    if rollover:
                        local = self._binding_locked(context_fd)
                        if self._has_nonterminal_local_run(context_fd):
                            raise RunnerStoreError("cloud context rollover requires terminal local runs")
                        replacement = {
                            "schema_version": local["schema_version"], "namespace": local["namespace"],
                            "context": context.as_dict(), "identity": local["identity"],
                            "signer_label": local["signer_label"],
                        }
                        if pending_journal is None:
                            _write_json(
                                context_fd, "context-rollover.json",
                                self._context_rollover_journal(
                                    old=old, new=binding, context=context,
                                    evidence=rollover_evidence, identity=identity, signer=signer,
                                ),
                            )
                        _write_json(context_fd, "binding.json", replacement)
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
                # A first-install root journal must remain paired with this
                # signed rollover journal until the root active selector is
                # durable.  Otherwise a selector-write crash leaves a coherent
                # new namespace that cannot prove how it advanced from the
                # root journal's old artifact on restart.
                if rollover and install_journal is None:
                    try:
                        os.unlink("context-rollover.json", dir_fd=context_fd)
                    except FileNotFoundError:
                        raise RunnerStoreError("cloud context rollover journal disappeared") from None
                    os.fsync(context_fd)
            if rollover_receipt is not None and not receipt_consumed:
                raise RunnerStoreError("cloud context rollover receipt was not consumed")
            if install_journal is not None:
                self._finish_context_install_journal(context=context, journal=install_journal)
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
        self, *, old: Mapping[str, Any], new: Mapping[str, Any], context: RunnerContext,
        evidence: RunnerContextRolloverEvidence | None, identity: RunnerIdentity, signer: SecureSigner,
    ) -> dict[str, Any]:
        if not isinstance(evidence, RunnerContextRolloverEvidence):
            raise RunnerStoreError("cloud context rollover requires evidence")
        _identity_record(identity, signer)
        unsigned = {
            "schema_version": _CONTEXT_ROLLOVER_SCHEMA,
            "old_binding_id": old["binding_id"], "old_binding_digest": old["binding_digest"],
            "new_binding_id": new["binding_id"], "new_binding_digest": new["binding_digest"],
            "context": context.as_dict(), "artifact": dict(new),
            "evidence": self._rollover_evidence_dict(evidence),
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
            "new_binding_digest", "context", "artifact", "evidence", "signing_key_id", "signature_b64",
        }
        if not isinstance(value, Mapping) or set(value) != fields or value["schema_version"] != _CONTEXT_ROLLOVER_SCHEMA:
            raise RunnerStoreError("invalid cloud context rollover journal")
        try:
            evidence = RunnerContextRolloverEvidence(**dict(value["evidence"]))
            public = load_public_key_base64(identity.public_key_b64)
            unsigned = {key: value[key] for key in fields - {"signing_key_id", "signature_b64"}}
            verify_envelope(
                {identity.key_id: public},
                {"signing_key_id": value["signing_key_id"], "signature_b64": value["signature_b64"]},
                canonical_bytes(unsigned),
            )
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
        recovery_signer = _IdentityPublicSigner(identity)
        pending_install = self._pending_cloud_context_install_for_recovery(
            identity=identity, signer=recovery_signer,
        ) if not self.is_context_bound else None
        if pending_install is not None:
            self._namespace = pending_install[1].namespace
        if self._namespace is None:
            return None
        try:
            with self._transaction(exclusive=True, allow_rollover_journal=True) as context_fd:
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
                    evidence = RunnerContextRolloverEvidence(**dict(journal["evidence"]))
                    local = self._binding_locked(context_fd)
                    provenance_value = _read_json(context_fd, "cloud-context-provenance.json", None)
                    sidecar_value = _read_json(context_fd, "cloud-context-binding.json", None)
                    sidecar = validate_runner_context_binding(sidecar_value)
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
                    if not sidecar_is_new:
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
                    _write_json(context_fd, "binding.json", {
                        "schema_version": local["schema_version"], "namespace": local["namespace"],
                        "context": new_context.as_dict(), "identity": local["identity"],
                        "signer_label": local["signer_label"],
                    })
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
                # A root first-install intent has not committed until its
                # active selector is durable.  Keep the signed A→B journal
                # through that root commit so a second selector-write crash
                # can still prove how the unselected namespace advanced.
                if pending_install is None:
                    os.unlink("context-rollover.json", dir_fd=context_fd)
                    os.fsync(context_fd)
            if pending_install is not None:
                self._finish_context_install_journal(context=new_context, journal=pending_install[2])
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
        """Whether an active local context was ever selected for Cloud authority."""
        with self._transaction(exclusive=False, allow_rollover_journal=True) as context_fd:
            provenance = _read_json(context_fd, "cloud-context-provenance.json", None)
            if provenance is not None:
                return True
            return _read_json(context_fd, "cloud-context-binding.json", None) is not None

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

    def _binding_locked(self, context_fd: int) -> dict[str, Any]:
        value = _read_json(context_fd, "binding.json", None)
        fields = {"schema_version", "namespace", "context", "identity", "signer_label"}
        if not isinstance(value, Mapping) or set(value) != fields:
            raise RunnerStoreError("invalid bound runner context")
        if value["schema_version"] != "heel.bound-runner-context.v1":
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
        return {**dict(value), "identity": identity, "signer_label": signer_label}

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
                    self._verify_signed_run_authority_value(
                        record, identity=identity, schema=_RUN_RESERVATION_RECORD_SCHEMA,
                        record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                    )
                    with self._open_run(context_fd, run_id, create=False) as run_fd:
                        return self._run_state_locked(run_fd, run_id)
                if index["nonterminal_count"] + len(index["terminal_queue"]) >= _RUN_AUTHORITY_MAX_TRACKED:
                    raise RunnerStoreError("local run authority capacity is exhausted")
                record = self._run_authority_record(
                    operation="reserve", context=context, identity=identity, signer=signer,
                    run_hash=run_hash, grant=grant, state=state, index=index,
                )
                next_index = self._next_run_authority_index(
                    index, signer=signer, delta=1, head_digest=record["record_digest"],
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
        """Reconstruct the run namespace from its immutable consumption journal."""
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
                self._run_authority_index_locked(runs_fd, identity=identity)
                run_hash = self._run_hash(run_id)
                if _read_json(runs_fd, self._run_authority_record_filename("prune", run_hash), None) is not None:
                    raise RunnerStoreError("local run reservation is unavailable")
                record = _read_json(
                    runs_fd, self._run_authority_record_filename("reserve", run_hash), None,
                )
                if record is None:
                    raise RunnerStoreError("local run reservation is unavailable")
                checked = self._verify_signed_run_authority_value(
                    record, identity=identity, schema=_RUN_RESERVATION_RECORD_SCHEMA,
                    record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                )
                marker = _read_json(runs_fd, f"grant-{checked.get('grant_digest')}.json", None)
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
                state = marker["initial_state"]
                if (
                    grant["run_id"] != run_id or checked.get("run_hash") != run_hash
                    or checked.get("grant_id") != grant["grant_id"]
                    or checked.get("grant_digest") != grant["grant_digest"]
                    or not isinstance(state, Mapping) or state.get("run_id") != run_id
                    or state.get("state") != "verified" or checked.get("initial_state_digest") != canonical_digest(dict(state))
                ):
                    raise RunnerStoreError("invalid local run reservation journal")
                run_fd = _open_child(runs_fd, self._run_hash(run_id), create=True)
                assert run_fd is not None
                try:
                    _secure_directory(run_fd, "Heel local run directory")
                    stored_grant = _read_json(run_fd, "grant.json", None)
                    if stored_grant is None:
                        _create_json(run_fd, "grant.json", grant)
                    elif stored_grant != grant:
                        raise RunnerStoreError("immutable local run grant collision")
                    stored_state = _read_json(run_fd, "state.json", None)
                    if stored_state is None:
                        _create_json(run_fd, "state.json", dict(state))
                    recovered = self._run_state_locked(run_fd, run_id)
                    os.fsync(run_fd)
                finally:
                    os.close(run_fd)
                os.fsync(runs_fd)
                return recovered
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
                        ):
                            raise RunnerStoreError("local run authority terminal queue is invalid")
                        # A crash can leave the durable authority terminal record/index ahead of
                        # the mutable run state.  The immutable record is the commitment; restore
                        # only the state marker instead of minting a second terminal record.
                        _write_json(run_fd, "state.json", updated)
                        return updated
                    reservation = _read_json(
                        runs_fd, self._run_authority_record_filename("reserve", run_hash), None,
                    )
                    if reservation is None:
                        raise RunnerStoreError("local run authority reservation is unavailable")
                    reservation = self._verify_signed_run_authority_value(
                        reservation, identity=identity, schema=_RUN_RESERVATION_RECORD_SCHEMA,
                        record_digest=True, max_bytes=_RUN_AUTHORITY_MAX_RECORD_BYTES,
                    )
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
