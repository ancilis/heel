"""Descriptor-anchored, owner-only metadata storage for the local Heel runner.

Only route inventory, opaque credential handles, and explicit scenario mappings live
here. Credential values and imported OpenAPI documents are deliberately outside this
store's data model.
"""
from __future__ import annotations

from contextlib import contextmanager
import inspect
import json
import os
from pathlib import Path
import re
import secrets
import stat
import unicodedata
from typing import Any, Iterator, Mapping

from heel.canary_contracts import canonical_bytes
from heel.scope import heel_home


class UnsupportedSecureStorageError(RuntimeError):
    """Live canary preparation cannot proceed without a secure vault."""


class RunnerStoreError(ValueError):
    """Runner metadata is malformed or violates the local storage contract."""


_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_MAX_METADATA_BYTES = 256 * 1024
_HANDLE = re.compile(r"^[0-9a-f]{32}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ROUTE = re.compile(r"^/[^\x00-\x1f\x7f?#]*$")
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_PROFILES = frozenset({"anonymous", "bearer", "cookie_jar", "x_api_key"})


def _require_capabilities() -> None:
    needed = (os.open, os.mkdir, os.stat, os.unlink)
    try:
        replace = inspect.signature(os.replace).parameters
    except (TypeError, ValueError):
        replace = {}
    if not (
        os.name == "posix"
        and getattr(os, "O_DIRECTORY", 0)
        and getattr(os, "O_NOFOLLOW", 0)
        and all(function in os.supports_dir_fd for function in needed)
        and os.stat in os.supports_follow_symlinks
        and {"src_dir_fd", "dst_dir_fd"} <= set(replace)
    ):
        raise UnsupportedSecureStorageError(
            "runner metadata requires POSIX dir_fd and O_NOFOLLOW support"
        )


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
            raise OSError(error.errno, "unsafe runner store component") from error
        raise


def _owner_only_directory(descriptor: int, label: str) -> None:
    status = os.fstat(descriptor)
    if not stat.S_ISDIR(status.st_mode) or status.st_uid != os.geteuid():
        raise PermissionError(f"{label} must be an owner-controlled directory")
    os.fchmod(descriptor, 0o700)
    if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o700:
        raise PermissionError(f"{label} must have mode 0700")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RunnerStoreError("duplicate runner metadata key")
        result[key] = value
    return result


def _read_json(directory_fd: int, filename: str, default: Any) -> Any:
    try:
        descriptor = os.open(filename, _READ_FLAGS, dir_fd=directory_fd)
    except FileNotFoundError:
        return default
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.geteuid()
            or status.st_size > _MAX_METADATA_BYTES
        ):
            raise OSError("unsafe runner metadata target")
        os.fchmod(descriptor, 0o600)
        chunks: list[bytes] = []
        remaining = _MAX_METADATA_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_METADATA_BYTES:
            raise RunnerStoreError("runner metadata exceeds size limit")
    finally:
        os.close(descriptor)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise RunnerStoreError("runner metadata is invalid") from None


def _target_is_safe(directory_fd: int, filename: str) -> None:
    try:
        status = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(status.st_mode) or status.st_uid != os.geteuid():
        raise OSError("unsafe runner metadata target")


def _write_json(directory_fd: int, filename: str, value: Any) -> None:
    payload = canonical_bytes(value)
    if len(payload) > _MAX_METADATA_BYTES:
        raise RunnerStoreError("runner metadata exceeds size limit")
    _target_is_safe(directory_fd, filename)
    temporary = f".{filename}.{secrets.token_hex(12)}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(temporary, _WRITE_FLAGS, 0o600, dir_fd=directory_fd)
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise OSError("short runner metadata write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        _target_is_safe(directory_fd, filename)
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


def _label(value: object) -> str:
    if type(value) is not str:
        raise ValueError("credential label must be text")
    normalized = unicodedata.normalize("NFC", value.strip().lower())
    output: list[str] = []
    for character in normalized:
        if character.isascii() and (character.isalnum() or character in {"-", "_"}):
            output.append(character)
        elif character.isspace():
            output.append("-")
        else:
            raise ValueError("credential label contains unsupported characters")
    result = "-".join(part for part in "".join(output).split("-") if part)
    if not result or len(result) > 64:
        raise ValueError("credential label must be between 1 and 64 characters")
    return result


def _handle(value: object) -> str:
    if type(value) is not str or _HANDLE.fullmatch(value) is None:
        raise ValueError("credential handle ID must be 32 lowercase hex characters")
    return value


def _profile(value: object) -> str:
    if value not in _PROFILES:
        raise ValueError("invalid auth profile")
    return str(value)


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"invalid {label}")
    return value


def _route_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "method", "route_template", "operation_id", "placeholders"
    }:
        raise RunnerStoreError("invalid runner route metadata")
    method = value["method"]
    route = value["route_template"]
    placeholders = value["placeholders"]
    if method not in {"GET", "HEAD"} or type(route) is not str or _ROUTE.fullmatch(route) is None:
        raise RunnerStoreError("invalid runner route metadata")
    _identifier(value["operation_id"], "operation ID")
    if (
        not isinstance(placeholders, list)
        or placeholders != sorted(set(placeholders))
        or any(type(item) is not str or _IDENTIFIER.fullmatch(item) is None for item in placeholders)
    ):
        raise RunnerStoreError("invalid runner route metadata")
    actual_placeholders = _PLACEHOLDER.findall(route)
    if (
        placeholders != sorted(actual_placeholders)
        or route.count("{") != len(actual_placeholders)
        or route.count("}") != len(actual_placeholders)
    ):
        raise ValueError("route placeholder metadata does not match its template")
    return {
        "method": method,
        "route_template": route,
        "operation_id": value["operation_id"],
        "placeholders": list(placeholders),
    }


def _credential_record(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {
        "label", "credential_handle_id", "auth_profile"
    }:
        raise RunnerStoreError("invalid credential metadata")
    return {
        "label": _label(value["label"]),
        "credential_handle_id": _handle(value["credential_handle_id"]),
        "auth_profile": _profile(value["auth_profile"]),
    }


def _mapping_record(value: Any) -> dict[str, Any]:
    fields = {
        "scenario_id", "method", "route_template", "semantic_auth_role",
        "auth_profile", "credential_handle_id", "fixture_bindings",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RunnerStoreError("invalid scenario mapping metadata")
    scenario_id = _identifier(value["scenario_id"], "scenario ID")
    method = value["method"]
    route = value["route_template"]
    handle = value["credential_handle_id"]
    if method not in {"GET", "HEAD"} or type(route) is not str or _ROUTE.fullmatch(route) is None:
        raise RunnerStoreError("invalid scenario mapping metadata")
    if handle is not None:
        _handle(handle)
    bindings = value["fixture_bindings"]
    if not isinstance(bindings, list) or len(bindings) > 20:
        raise RunnerStoreError("invalid scenario fixture bindings")
    normalized: list[dict[str, str]] = []
    for binding in bindings:
        if not isinstance(binding, Mapping) or set(binding) != {"parameter_name", "fixture_id"}:
            raise RunnerStoreError("invalid scenario fixture bindings")
        normalized.append({
            "parameter_name": _identifier(binding["parameter_name"], "fixture parameter"),
            "fixture_id": _identifier(binding["fixture_id"], "fixture ID"),
        })
    normalized.sort(key=lambda item: (item["parameter_name"], item["fixture_id"]))
    if len({item["parameter_name"] for item in normalized}) != len(normalized):
        raise RunnerStoreError("duplicate scenario fixture binding")
    return {
        "scenario_id": scenario_id,
        "method": method,
        "route_template": route,
        "semantic_auth_role": _identifier(value["semantic_auth_role"], "semantic role"),
        "auth_profile": _profile(value["auth_profile"]),
        "credential_handle_id": handle,
        "fixture_bindings": normalized,
    }


class RunnerStore:
    """Local runner metadata rooted below one securely opened Heel home."""

    def __init__(self, root: Path | None = None):
        _require_capabilities()
        self.root = _absolute(Path(heel_home()) if root is None else Path(root))
        with self._open_runner(create=True):
            pass

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
            _owner_only_directory(current, "Heel home")
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
            _owner_only_directory(runner_fd, "Heel runner directory")
            os.fsync(root_fd)
            yield runner_fd
        finally:
            if runner_fd >= 0:
                os.close(runner_fd)
            os.close(root_fd)

    def list_credentials(self) -> list[dict[str, str]]:
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            values = _read_json(runner_fd, "credentials.json", [])
        if not isinstance(values, list) or len(values) > 100:
            raise RunnerStoreError("invalid credential metadata")
        result = [_credential_record(value) for value in values]
        if result != sorted(result, key=lambda item: (item["label"], item["credential_handle_id"])):
            raise RunnerStoreError("credential metadata is not canonical")
        if len({item["credential_handle_id"] for item in result}) != len(result):
            raise RunnerStoreError("duplicate credential handle")
        return result

    def add_credential(
        self,
        *,
        label: str,
        auth_profile: str,
        handle_id: str,
        secret: bytes | None = None,
    ) -> dict[str, str]:
        # Kept as a compatibility keyword so callers cannot accidentally serialize a
        # supplied secret by passing a broader record to the metadata layer.
        del secret
        record = _credential_record({
            "label": label,
            "credential_handle_id": handle_id,
            "auth_profile": auth_profile,
        })
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            values = _read_json(runner_fd, "credentials.json", [])
            records = [_credential_record(value) for value in values]
            if any(item["credential_handle_id"] == record["credential_handle_id"] for item in records):
                raise ValueError("credential handle already exists")
            records.append(record)
            records.sort(key=lambda item: (item["label"], item["credential_handle_id"]))
            _write_json(runner_fd, "credentials.json", records)
        return dict(record)

    def replace_routes(self, routes: list[Mapping[str, Any]], *, source_digest: str) -> None:
        if type(source_digest) is not str or _DIGEST.fullmatch(source_digest) is None:
            raise ValueError("invalid OpenAPI source digest")
        normalized = [_route_record(route) for route in routes]
        if len(normalized) > 2000:
            raise ValueError("runner route inventory exceeds limit")
        normalized.sort(key=lambda item: (item["route_template"], item["method"], item["operation_id"]))
        if len({(item["method"], item["route_template"]) for item in normalized}) != len(normalized):
            raise ValueError("duplicate runner route")
        envelope = {
            "schema_version": "heel.runner-route-inventory.v1",
            "source_digest": source_digest,
            "routes": normalized,
        }
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            _write_json(runner_fd, "routes.json", envelope)

    def list_routes(self) -> list[dict[str, Any]]:
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            value = _read_json(runner_fd, "routes.json", None)
        if value is None:
            return []
        if not isinstance(value, Mapping) or set(value) != {"schema_version", "source_digest", "routes"}:
            raise RunnerStoreError("invalid runner route inventory")
        if value["schema_version"] != "heel.runner-route-inventory.v1":
            raise RunnerStoreError("invalid runner route inventory")
        if type(value["source_digest"]) is not str or _DIGEST.fullmatch(value["source_digest"]) is None:
            raise RunnerStoreError("invalid runner route inventory")
        routes = value["routes"]
        if not isinstance(routes, list) or len(routes) > 2000:
            raise RunnerStoreError("invalid runner route inventory")
        result = [_route_record(route) for route in routes]
        if result != sorted(result, key=lambda item: (item["route_template"], item["method"], item["operation_id"])):
            raise RunnerStoreError("runner route inventory is not canonical")
        return result

    def save_mapping(self, mapping: Mapping[str, Any]) -> dict[str, Any]:
        record = _mapping_record(mapping)
        routes = {(item["method"], item["route_template"]) for item in self.list_routes()}
        if (record["method"], record["route_template"]) not in routes:
            raise ValueError("scenario mapping route is not in the local inventory")
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            values = _read_json(runner_fd, "mappings.json", [])
            if not isinstance(values, list) or len(values) > 4:
                raise RunnerStoreError("invalid scenario mappings")
            records = [_mapping_record(value) for value in values]
            records = [item for item in records if item["scenario_id"] != record["scenario_id"]]
            records.append(record)
            records.sort(key=lambda item: item["scenario_id"])
            _write_json(runner_fd, "mappings.json", records)
        return dict(record)

    def list_mappings(self) -> list[dict[str, Any]]:
        with self._open_runner(create=True) as runner_fd:
            assert runner_fd is not None
            values = _read_json(runner_fd, "mappings.json", [])
        if not isinstance(values, list) or len(values) > 4:
            raise RunnerStoreError("invalid scenario mappings")
        records = [_mapping_record(value) for value in values]
        if records != sorted(records, key=lambda item: item["scenario_id"]):
            raise RunnerStoreError("scenario mappings are not canonical")
        if len({item["scenario_id"] for item in records}) != len(records):
            raise RunnerStoreError("duplicate scenario mapping")
        return records

    @staticmethod
    def require_live_vault(vault: object | None) -> None:
        if vault is None or getattr(vault, "supported", False) is not True:
            raise UnsupportedSecureStorageError(
                "live preparation requires a supported secure credential vault"
            )


def new_credential_handle_id() -> str:
    return secrets.token_hex(16)
