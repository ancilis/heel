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
    validate_approval_projection,
    validate_test_manifest,
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
_MAX_METADATA_BYTES = 256 * 1024
_HANDLE = re.compile(r"^[0-9a-f]{32}$", flags=re.ASCII)
_DIGEST = re.compile(r"^[0-9a-f]{64}$", flags=re.ASCII)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$", flags=re.ASCII)
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$", flags=re.ASCII)
_BACKENDS = frozenset({
    "macos_keychain", "linux_secret_service", "ephemeral_env", "ephemeral_fd",
})
_STATES = frozenset({"pending", "active", "orphaned"})


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


def new_credential_handle_id() -> str:
    """Compatibility helper; CLI intentionally never accepts or displays its result."""
    return secrets.token_hex(16)
