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
_EVENT_FILENAME = re.compile(r"^[0-9]{20}\.json$", flags=re.ASCII)
_CREATE_TEMP_FILENAME = re.compile(r"^\..+\.[0-9a-f]{24}\.tmp$", flags=re.ASCII)
_EVIDENCE_REF = re.compile(r"^ev1_[0-9a-f]{64}$", flags=re.ASCII)
_MAX_EVIDENCE_HEADER_BYTES = 16 * 1024
_MAX_EVIDENCE_BODY_BYTES = 256 * 1024
_RESERVATION_SCHEMA = "heel.local-grant-consumption.v2"
_FINALS_SCHEMA = "heel.local-final-projections.v1"
_CONTEXT_DOMAIN = b"heel.runner-context-binding.v1\0"


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
    for name in os.listdir(directory_fd):
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
        with self._open_runner(create=True):
            pass
        self._select_active_if_present()

    @property
    def namespace(self) -> str:
        if self._namespace is None:
            raise RunnerStoreError("runner has no bound context")
        return self._namespace

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
    def _transaction(self, *, exclusive: bool) -> Iterator[int]:
        with self._open_context(create=False) as context_fd:
            with _flock(context_fd, ".metadata.lock", exclusive=exclusive):
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
        with self._transaction(exclusive=False):
            pass

    def bind_context(
        self,
        context: RunnerContext,
        *,
        identity: RunnerIdentity,
        signer: SecureSigner,
        signer_label: str,
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
                            if existing is None:
                                _write_json(context_fd, "binding.json", binding)
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
    ) -> RunnerContext:
        """Verify and atomically retain a Cloud authorization beside the immutable context."""
        try:
            binding = validate_runner_context_binding(artifact)
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid cloud context binding") from None
        if not isinstance(trusted_cloud_keys, Mapping) or not trusted_cloud_keys:
            raise RunnerStoreError("cloud context authority is unavailable")
        if type(now_ms) is not int or isinstance(now_ms, bool):
            raise RunnerStoreError("invalid cloud context time")
        unsigned = {key: binding[key] for key in (
            "schema_version", "binding_id", "workspace_id", "project_id", "environment", "runner_binding",
            "authorization", "issued_at_ms", "expires_at_ms",
        )}
        try:
            verify_envelope(dict(trusted_cloud_keys), {
                "signing_key_id": binding["signing_key_id"], "signature_b64": binding["signature_b64"],
            }, _CONTEXT_DOMAIN + canonical_bytes(unsigned))
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid cloud context signature") from None
        runner = binding["runner_binding"]
        try:
            public = base64.b64decode(identity.public_key_b64, validate=True)
        except (TypeError, ValueError):
            raise RunnerStoreError("invalid local runner identity") from None
        if (
            binding["workspace_id"] != identity.workspace_id or runner["runner_id"] != identity.runner_id
            or runner["runner_key_id"] != identity.key_id or hashlib.sha256(public).hexdigest() != runner["public_key_digest"]
            or binding["issued_at_ms"] > now_ms + 30_000 or now_ms >= binding["expires_at_ms"]
        ):
            raise RunnerStoreError("cloud context binding does not match local runner")
        environment = binding["environment"]
        context = RunnerContext(
            workspace_id=binding["workspace_id"], project_id=binding["project_id"],
            environment_id=environment["environment_id"], origin=environment["origin"],
            verification_record_digest=environment["verification_record_digest"],
            environment_class=environment["environment_class"],
        )
        self.bind_context(context, identity=identity, signer=signer, signer_label=signer_label)
        with self._transaction(exclusive=True) as context_fd:
            existing = _read_json(context_fd, "cloud-context-binding.json", None)
            if existing is not None and existing != binding:
                raise RunnerStoreError("cloud context binding cannot be replaced")
            if existing is None:
                _write_json(context_fd, "cloud-context-binding.json", binding)
        return context

    def load_cloud_context_binding(self) -> dict[str, Any]:
        with self._transaction(exclusive=False) as context_fd:
            value = _read_json(context_fd, "cloud-context-binding.json", None)
            try:
                return validate_runner_context_binding(value)
            except (TypeError, ValueError):
                raise RunnerStoreError("invalid cloud context binding") from None

    def has_cloud_context_binding(self) -> bool:
        with self._transaction(exclusive=False) as context_fd:
            return _read_json(context_fd, "cloud-context-binding.json", None) is not None

    def verify_cloud_context_binding(
        self, *, identity: RunnerIdentity, trusted_cloud_keys: Mapping[str, object], now_ms: int,
    ) -> dict[str, Any]:
        """Reverify the sidecar at every use; disk contents are never a trust decision."""
        binding = self.load_cloud_context_binding()
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
                consumed_name = f"grant-{grant['grant_digest']}.json"
                try:
                    _create_json(runs_fd, consumed_name, {
                        "schema_version": _RESERVATION_SCHEMA,
                        "grant": grant,
                        "initial_state": state,
                    })
                except FileExistsError:
                    raise ValueError("execution grant was already consumed") from None
                run_fd = -1
                try:
                    opened = _open_child(runs_fd, self._run_hash(run_id), create=True)
                    assert opened is not None
                    run_fd = opened
                    _secure_directory(run_fd, "Heel local run directory")
                    if _read_json(run_fd, "state.json", None) is not None:
                        raise RunnerStoreError("immutable local run collision")
                    _create_json(run_fd, "grant.json", grant)
                    _create_json(run_fd, "state.json", state)
                finally:
                    if run_fd >= 0:
                        os.close(run_fd)
            finally:
                os.close(runs_fd)
        return state

    def recover_run_reservation(self, run_id: str) -> dict[str, Any]:
        """Reconstruct the run namespace from its immutable consumption journal."""
        run_id = _id(run_id, "run ID")
        with self._transaction(exclusive=True) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=False)
            if runs_fd is None:
                raise RunnerStoreError("local run reservation is unavailable")
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                matching: list[tuple[dict[str, Any], dict[str, Any]]] = []
                legacy_seen = False
                for name in sorted(os.listdir(runs_fd)):
                    if not name.startswith("grant-") or not name.endswith(".json"):
                        continue
                    value = _read_json(runs_fd, name, None)
                    if (
                        isinstance(value, Mapping)
                        and value.get("schema_version") == "heel.local-grant-consumption.v1"
                        and value.get("run_id") == run_id
                    ):
                        legacy_seen = True
                        continue
                    if (
                        not isinstance(value, Mapping)
                        or set(value) != {"schema_version", "grant", "initial_state"}
                        or value["schema_version"] != _RESERVATION_SCHEMA
                    ):
                        continue
                    try:
                        grant = validate_execution_grant(value["grant"])
                    except (TypeError, ValueError):
                        raise RunnerStoreError("invalid local run reservation journal") from None
                    state = value["initial_state"]
                    if grant["run_id"] != run_id:
                        continue
                    if (
                        not isinstance(state, Mapping)
                        or state.get("run_id") != run_id
                        or state.get("state") != "verified"
                        or state.get("grant_id") != grant["grant_id"]
                        or state.get("grant_digest") != grant["grant_digest"]
                        or state.get("manifest_digest") != grant["approval"]["manifest_digest"]
                    ):
                        raise RunnerStoreError("invalid local run reservation journal")
                    matching.append((grant, dict(state)))
                if len(matching) != 1:
                    if legacy_seen:
                        raise RunnerStoreError(
                            "legacy grant marker cannot reconstruct missing run state"
                        )
                    raise RunnerStoreError("local run reservation is unavailable")
                grant, state = matching[0]
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
                        _create_json(run_fd, "state.json", state)
                    recovered = self._run_state_locked(run_fd, run_id)
                    os.fsync(run_fd)
                finally:
                    os.close(run_fd)
                os.fsync(runs_fd)
                return recovered
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
        if next_state not in _RUN_STATES:
            raise ValueError("invalid local run state")
        if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms < 0:
            raise ValueError("invalid local run timestamp")
        with self._transaction(exclusive=True) as context_fd:
            with self._open_run(context_fd, run_id, create=False) as run_fd:
                current = self._run_state_locked(run_fd, run_id)
                if next_state not in _RUN_TRANSITIONS[current["state"]]:
                    raise RunnerStoreError("illegal local run transition")
                if now_ms < current["updated_at_ms"]:
                    raise RunnerStoreError("local run timestamp moved backward")
                updated = {**current, "state": next_state, "updated_at_ms": now_ms}
                _write_json(run_fd, "state.json", updated)
                return updated

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
            with self._open_run(context_fd, run_id, create=False) as run_fd:
                self._run_state_locked(run_fd, run_id)
                try:
                    _create_json(run_fd, "finals.json", envelope)
                except FileExistsError:
                    if _read_json(run_fd, "finals.json", None) != envelope:
                        raise RunnerStoreError("immutable final projection collision") from None

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
        for name in os.listdir(directory_fd):
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
        if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms < 0:
            raise ValueError("invalid local retention time")
        removed = 0
        with self._transaction(exclusive=True) as context_fd:
            runs_fd = _open_child(context_fd, "runs", create=False)
            if runs_fd is None:
                return 0
            try:
                _secure_directory(runs_fd, "Heel runner runs directory")
                for name in sorted(os.listdir(runs_fd)):
                    if _RUN_FILENAME.fullmatch(name) is None:
                        continue  # immutable grant-consumption markers intentionally remain
                    run_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=runs_fd)
                    try:
                        _secure_directory(run_fd, "Heel retained local run directory")
                        state = _read_json(run_fd, "state.json", None)
                        if (
                            not isinstance(state, Mapping)
                            or state.get("state") != "terminal"
                            or isinstance(state.get("retention_expires_at_ms"), bool)
                            or not isinstance(state.get("retention_expires_at_ms"), int)
                            or state["retention_expires_at_ms"] > now_ms
                        ):
                            continue
                        self._delete_directory_contents(run_fd)
                    finally:
                        os.close(run_fd)
                    os.rmdir(name, dir_fd=runs_fd)
                    removed += 1
                if removed:
                    os.fsync(runs_fd)
            finally:
                os.close(runs_fd)
        return removed


def new_credential_handle_id() -> str:
    """Compatibility helper; CLI intentionally never accepts or displays its result."""
    return secrets.token_hex(16)
