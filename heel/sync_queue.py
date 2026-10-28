"""Immutable, privacy-minimized local retries for approved findings sync requests."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass

try:
    import fcntl
except ImportError:  # pragma: no cover - capability check rejects non-POSIX hosts
    fcntl = None  # type: ignore[assignment]
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any, Callable, Iterator, Literal, Mapping

from .findings_sync import (
    FINDINGS_SYNC_SCHEMA_VERSION,
    MAX_FINDINGS_SYNC_BYTES,
    findings_sync_request_digest,
    validate_findings_sync_receipt,
    validate_findings_sync_request,
)
from .review_contract import stable_json
from .scope import heel_home


SYNC_QUEUE_SCHEMA_VERSION = "heel.sync-queue-record.v1"
MAX_APPROVAL_SECONDS = 10 * 60
MAX_LEASE_SECONDS = 5 * 60
DEFAULT_LEASE_SECONDS = 30
MAX_RECORD_BYTES = MAX_FINDINGS_SYNC_BYTES + 32 * 1024

_WORKSPACE = re.compile(r"ws_[0-9a-f]{16}\Z", flags=re.ASCII)
_PROJECT = re.compile(r"prj_[0-9a-f]{32}\Z", flags=re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", flags=re.ASCII)
_LEASE_TOKEN = re.compile(r"fsl_[0-9a-f]{32}\Z", flags=re.ASCII)
_PERMIT_TOKEN = re.compile(r"fst_[0-9a-f]{32}\Z", flags=re.ASCII)
_APPROVAL_ID = re.compile(r"fsauth_[0-9a-f]{32}\Z", flags=re.ASCII)
_RETRY_ERROR_CODES = frozenset(
    {"transport_error", "server_rejected", "approval_expired"}
)
_RECORD_FIELDS = (
    "schema_version",
    "workspace_ref",
    "project_ref",
    "request_digest",
    "request_json",
    "human_approval",
    "transport_approval",
    "transmission",
    "retry",
    "receipt",
)
_REQUEST_FIELDS = (
    "schema_version",
    "project_ref",
    "source",
    "gate_status",
    "summary",
    "findings",
    "projection_hash",
)

_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_LOCK_FLAGS = (
    os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
)


class SecureQueueStorageUnavailable(RuntimeError):
    """The host cannot provide the descriptor-anchored queue contract."""


class StoredSyncQueueError(ValueError):
    """A persisted queue record is corrupt, unsafe, or outside the closed schema."""


class ImmutableQueueConflict(RuntimeError):
    """An existing digest key contradicts immutable request or approval bytes."""


@dataclass(frozen=True)
class HumanSyncApproval:
    workspace_ref: str
    project_ref: str
    request_digest: str
    approved_at: float
    expires_at: float


@dataclass(frozen=True)
class StoredHumanApproval:
    approved_at: float
    expires_at: float


@dataclass(frozen=True)
class StoredTransportApproval:
    approval_id: str
    request_digest: str
    approved_at: float
    expires_at: float


@dataclass(frozen=True)
class StoredTransmission:
    permit_token: str
    lease_token: str
    request_digest: str
    begun_at: float
    effective_expires_at: float


@dataclass(frozen=True)
class RetryState:
    attempts: int
    next_attempt_at: float | None
    last_error_code: str | None
    lease_token: str | None
    lease_expires_at: float | None


@dataclass(frozen=True)
class SyncRecord:
    schema_version: Literal["heel.sync-queue-record.v1"]
    workspace_ref: str
    project_ref: str
    request_digest: str
    request_json: str
    human_approval: StoredHumanApproval | None
    transport_approval: StoredTransportApproval | None
    transmission: StoredTransmission | None
    retry: RetryState
    receipt: dict[str, Any] | None


@dataclass(frozen=True)
class SyncLease:
    lease_token: str
    lease_expires_at: float
    record: SyncRecord


@dataclass(frozen=True)
class SyncTransmissionPermit:
    permit_token: str
    begun_at: float
    effective_expires_at: float
    record: SyncRecord


def _require_secure_storage_capabilities() -> None:
    required_dir_fd = (os.open, os.mkdir, os.stat, os.unlink)
    try:
        replace_parameters = inspect.signature(os.replace).parameters
    except (TypeError, ValueError):
        replace_parameters = {}
    if not (
        os.name == "posix"
        and fcntl is not None
        and bool(getattr(os, "O_DIRECTORY", 0))
        and bool(getattr(os, "O_NOFOLLOW", 0))
        and all(function in os.supports_dir_fd for function in required_dir_fd)
        and os.stat in os.supports_follow_symlinks
        and os.listdir in os.supports_fd
        and {"src_dir_fd", "dst_dir_fd"} <= set(replace_parameters)
    ):
        raise SecureQueueStorageUnavailable(
            "secure sync queue requires POSIX dir_fd and O_NOFOLLOW support"
        )


def _timestamp(value: Any, label: str) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
        raise ValueError(f"{label} must be a finite non-negative timestamp")
    return float(value)


def _pattern(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.normpath(os.path.abspath(os.fspath(path.expanduser()))))


def _raise_unsafe_component(parent_fd: int, name: str, error: OSError) -> None:
    try:
        status = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        raise error
    if stat.S_ISLNK(status.st_mode):
        raise ValueError("Heel home path must not contain a symbolic link") from error
    if not stat.S_ISDIR(status.st_mode):
        raise ValueError("Heel home path components must be directories") from error
    raise error


def _open_child_directory(parent_fd: int, name: str, *, create: bool) -> int | None:
    try:
        return os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            return None
        created = False
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            pass
        if created:
            os.fsync(parent_fd)
        try:
            return os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        except OSError as error:
            _raise_unsafe_component(parent_fd, name, error)
    except OSError as error:
        _raise_unsafe_component(parent_fd, name, error)
    raise AssertionError("unreachable")


def _enforce_mode(descriptor: int, expected: int, label: str) -> None:
    os.fchmod(descriptor, expected)
    actual = stat.S_IMODE(os.fstat(descriptor).st_mode)
    if actual != expected:
        raise PermissionError(
            f"{label} must have mode {expected:#06o}; observed {actual:#06o}"
        )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("stored sync queue contains duplicate JSON fields")
        result[key] = value
    return result


def _record_mapping(record: SyncRecord) -> dict[str, Any]:
    return {
        "schema_version": record.schema_version,
        "workspace_ref": record.workspace_ref,
        "project_ref": record.project_ref,
        "request_digest": record.request_digest,
        "request_json": record.request_json,
        "human_approval": None
        if record.human_approval is None
        else {
            "approved_at": record.human_approval.approved_at,
            "expires_at": record.human_approval.expires_at,
        },
        "transport_approval": None
        if record.transport_approval is None
        else {
            "approval_id": record.transport_approval.approval_id,
            "request_digest": record.transport_approval.request_digest,
            "approved_at": record.transport_approval.approved_at,
            "expires_at": record.transport_approval.expires_at,
        },
        "transmission": None
        if record.transmission is None
        else {
            "permit_token": record.transmission.permit_token,
            "lease_token": record.transmission.lease_token,
            "request_digest": record.transmission.request_digest,
            "begun_at": record.transmission.begun_at,
            "effective_expires_at": record.transmission.effective_expires_at,
        },
        "retry": {
            "attempts": record.retry.attempts,
            "next_attempt_at": record.retry.next_attempt_at,
            "last_error_code": record.retry.last_error_code,
            "lease_token": record.retry.lease_token,
            "lease_expires_at": record.retry.lease_expires_at,
        },
        "receipt": record.receipt,
    }


def _exact_mapping(value: Any, fields: tuple[str, ...], label: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != frozenset(fields):
        raise ValueError(f"{label} must contain exactly the closed fields")
    return value


def _parse_json_text(source: Any, *, maximum_bytes: int, label: str) -> Any:
    if type(source) is not str:
        raise ValueError(f"{label} must be JSON text")
    try:
        payload = source.encode("utf-8")
    except UnicodeError:
        raise ValueError(f"{label} contains invalid Unicode") from None
    if len(payload) > maximum_bytes:
        raise ValueError(f"{label} exceeds its size limit")
    try:
        return json.loads(
            source,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON")
            ),
        )
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError):
        raise ValueError(f"{label} is invalid") from None


def _validate_request_without_namespace_key(
    request_json: Any, project_ref: str, request_digest: str
) -> tuple[str, dict[str, Any]]:
    request = _exact_mapping(
        _parse_json_text(
            request_json,
            maximum_bytes=MAX_FINDINGS_SYNC_BYTES,
            label="stored findings request",
        ),
        _REQUEST_FIELDS,
        "stored findings request",
    )
    if (
        request["schema_version"] != FINDINGS_SYNC_SCHEMA_VERSION
        or request["project_ref"] != project_ref
        or _PROJECT.fullmatch(project_ref) is None
        or type(request["projection_hash"]) is not str
        or _DIGEST.fullmatch(request["projection_hash"]) is None
    ):
        raise ValueError("stored findings request binding is invalid")
    source = _exact_mapping(
        request["source"],
        ("engine_version", "execution_mode", "result_ref"),
        "stored findings source",
    )
    if (
        type(source["engine_version"]) is not str
        or type(source["execution_mode"]) is not str
        or type(source["result_ref"]) is not str
        or re.fullmatch(r"src1_[0-9a-f]{64}", source["result_ref"]) is None
    ):
        raise ValueError("stored findings source is invalid")
    summary = _exact_mapping(
        request["summary"], ("findings", "blockers"), "stored findings summary"
    )
    if (
        type(summary["findings"]) is not int
        or type(summary["blockers"]) is not int
        or summary["findings"] < 0
        or summary["blockers"] < 0
    ):
        raise ValueError("stored findings summary is invalid")
    if type(request["findings"]) is not list:
        raise ValueError("stored findings must be an array")
    for finding in request["findings"]:
        item = _exact_mapping(
            finding,
            (
                "finding_id",
                "surface_ref",
                "surface_type",
                "risk_code",
                "control_code",
                "severity",
                "reachable",
            ),
            "stored finding",
        )
        if (
            type(item["finding_id"]) is not str
            or re.fullmatch(r"find1_[0-9a-f]{64}", item["finding_id"]) is None
            or type(item["surface_ref"]) is not str
            or re.fullmatch(r"surf1_[0-9a-f]{64}", item["surface_ref"]) is None
            or type(item["surface_type"]) is not str
            or type(item["risk_code"]) is not str
            or type(item["control_code"]) is not str
            or type(item["severity"]) is not str
            or type(item["reachable"]) is not bool
        ):
            raise ValueError("stored finding is invalid")
    if summary["findings"] != len(request["findings"]):
        raise ValueError("stored findings summary does not match")
    canonical = stable_json(request)
    if canonical != request_json:
        raise ValueError("stored findings request is not canonical")
    actual_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if actual_digest != request_digest:
        raise ValueError("stored findings request digest does not match")
    return canonical, request


def _parse_record_mapping(
    value: Any,
    *,
    expected_workspace: str,
    expected_project: str,
    expected_digest: str,
) -> SyncRecord:
    item = _exact_mapping(value, _RECORD_FIELDS, "sync queue record")
    if (
        item["schema_version"] != SYNC_QUEUE_SCHEMA_VERSION
        or item["workspace_ref"] != expected_workspace
        or item["project_ref"] != expected_project
        or item["request_digest"] != expected_digest
    ):
        raise ValueError("sync queue record key binding is invalid")
    _pattern(expected_workspace, _WORKSPACE, "workspace_ref")
    _pattern(expected_project, _PROJECT, "project_ref")
    _pattern(expected_digest, _DIGEST, "request_digest")
    request_json, request = _validate_request_without_namespace_key(
        item["request_json"], expected_project, expected_digest
    )

    human_value = item["human_approval"]
    human: StoredHumanApproval | None
    if human_value is None:
        human = None
    else:
        shaped = _exact_mapping(
            human_value, ("approved_at", "expires_at"), "human approval"
        )
        approved_at = _timestamp(shaped["approved_at"], "approved_at")
        expires_at = _timestamp(shaped["expires_at"], "expires_at")
        if expires_at <= approved_at or expires_at - approved_at > MAX_APPROVAL_SECONDS:
            raise ValueError("stored human approval is invalid")
        human = StoredHumanApproval(approved_at, expires_at)

    transport_value = item["transport_approval"]
    transport: StoredTransportApproval | None
    if transport_value is None:
        transport = None
    else:
        shaped = _exact_mapping(
            transport_value,
            ("approval_id", "request_digest", "approved_at", "expires_at"),
            "transport approval",
        )
        approved_at = _timestamp(shaped["approved_at"], "approved_at")
        expires_at = _timestamp(shaped["expires_at"], "expires_at")
        if (
            _APPROVAL_ID.fullmatch(shaped["approval_id"] or "") is None
            or shaped["request_digest"] != expected_digest
            or expires_at <= approved_at
            or expires_at - approved_at > MAX_APPROVAL_SECONDS
        ):
            raise ValueError("stored transport approval is invalid")
        transport = StoredTransportApproval(
            shaped["approval_id"], expected_digest, approved_at, expires_at
        )

    transmission_value = item["transmission"]
    transmission: StoredTransmission | None
    if transmission_value is None:
        transmission = None
    else:
        shaped = _exact_mapping(
            transmission_value,
            (
                "permit_token",
                "lease_token",
                "request_digest",
                "begun_at",
                "effective_expires_at",
            ),
            "transmission permit",
        )
        permit_token = _pattern(shaped["permit_token"], _PERMIT_TOKEN, "permit_token")
        transmission_lease = _pattern(
            shaped["lease_token"], _LEASE_TOKEN, "transmission lease_token"
        )
        begun_at = _timestamp(shaped["begun_at"], "begun_at")
        effective_expires_at = _timestamp(
            shaped["effective_expires_at"], "effective_expires_at"
        )
        if (
            shaped["request_digest"] != expected_digest
            or effective_expires_at <= begun_at
        ):
            raise ValueError("stored transmission permit is invalid")
        transmission = StoredTransmission(
            permit_token,
            transmission_lease,
            expected_digest,
            begun_at,
            effective_expires_at,
        )

    retry_value = _exact_mapping(
        item["retry"],
        (
            "attempts",
            "next_attempt_at",
            "last_error_code",
            "lease_token",
            "lease_expires_at",
        ),
        "retry state",
    )
    attempts = retry_value["attempts"]
    if type(attempts) is not int or attempts < 0 or attempts > 2**53 - 1:
        raise ValueError("retry attempts is invalid")
    next_attempt = retry_value["next_attempt_at"]
    if next_attempt is not None:
        next_attempt = _timestamp(next_attempt, "next_attempt_at")
    last_error = retry_value["last_error_code"]
    if last_error is not None and last_error not in _RETRY_ERROR_CODES:
        raise ValueError("retry error code is invalid")
    lease_token = retry_value["lease_token"]
    lease_expires = retry_value["lease_expires_at"]
    if (lease_token is None) != (lease_expires is None):
        raise ValueError("stored lease is incomplete")
    if lease_token is not None:
        _pattern(lease_token, _LEASE_TOKEN, "lease_token")
        lease_expires = _timestamp(lease_expires, "lease_expires_at")

    if transmission is not None:
        if (
            human is None
            or transport is None
            or lease_token is None
            or lease_expires is None
            or transmission.lease_token != lease_token
            or transmission.begun_at < human.approved_at
            or transmission.begun_at < transport.approved_at
            or transmission.effective_expires_at
            != min(human.expires_at, transport.expires_at, lease_expires)
            or transmission.begun_at >= transmission.effective_expires_at
        ):
            raise ValueError("stored transmission permit binding is invalid")

    receipt_value = item["receipt"]
    receipt: dict[str, Any] | None
    if receipt_value is None:
        receipt = None
    else:
        receipt = validate_findings_sync_receipt(receipt_value)
        if (
            receipt["project_ref"] != expected_project
            or receipt["request_digest"] != expected_digest
            or receipt["projection_hash"] != request["projection_hash"]
        ):
            raise ValueError("stored receipt does not match the request")
    if human is None:
        if (
            transport is not None
            or transmission is not None
            or next_attempt is not None
            or attempts != 0
            or last_error is not None
            or lease_token is not None
            or receipt is not None
        ):
            raise ValueError("prepared queue record contains authority or retry state")
    elif receipt is None and next_attempt is None:
        raise ValueError("approved queue record has no retry schedule")
    elif receipt is not None and (
        next_attempt is not None
        or lease_token is not None
        or lease_expires is not None
        or transmission is not None
    ):
        raise ValueError("completed queue record remains claimable")
    return SyncRecord(
        SYNC_QUEUE_SCHEMA_VERSION,
        expected_workspace,
        expected_project,
        expected_digest,
        request_json,
        human,
        transport,
        transmission,
        RetryState(attempts, next_attempt, last_error, lease_token, lease_expires),
        receipt,
    )


class SyncQueue:
    """One descriptor-anchored queue with immutable records and fenced leases."""

    def __init__(
        self,
        root: Path | None = None,
        *,
        lease_seconds: float = DEFAULT_LEASE_SECONDS,
        now: Callable[[], float] = time.time,
        token: Callable[[], str] | None = None,
    ):
        _require_secure_storage_capabilities()
        selected = Path(heel_home()) if root is None else Path(root)
        self.root = _absolute_without_resolving(selected)
        if self.root == Path(self.root.anchor):
            raise ValueError("Heel home must not be a filesystem root")
        self.queue_path = self.root / "sync-queue"
        self._lease_seconds = _timestamp(lease_seconds, "lease_seconds")
        if not 0 < self._lease_seconds <= MAX_LEASE_SECONDS:
            raise ValueError("lease_seconds is outside the closed queue limit")
        if not callable(now) or (token is not None and not callable(token)):
            raise ValueError("queue clock and token source must be callable")
        self._now = now
        self._token = token or (lambda: f"fsl_{secrets.token_hex(16)}")

    def _open_root(self, *, create: bool) -> int | None:
        current = os.open(self.root.anchor, _DIRECTORY_FLAGS)
        anchor_status = os.fstat(current)
        try:
            for part in self.root.parts[1:]:
                child = _open_child_directory(current, part, create=create)
                if child is None:
                    os.close(current)
                    current = -1
                    return None
                os.close(current)
                current = child
            root_status = os.fstat(current)
            if (root_status.st_dev, root_status.st_ino) == (
                anchor_status.st_dev,
                anchor_status.st_ino,
            ):
                raise ValueError("Heel home must not be a filesystem root")
            return current
        except BaseException:
            if current >= 0:
                os.close(current)
            raise

    @contextmanager
    def _open_queue(self, *, create: bool) -> Iterator[int | None]:
        root_fd = self._open_root(create=create)
        if root_fd is None:
            yield None
            return
        queue_fd = -1
        try:
            opened = _open_child_directory(root_fd, "sync-queue", create=create)
            if opened is None:
                yield None
                return
            queue_fd = opened
            _enforce_mode(root_fd, 0o700, "Heel home")
            os.fsync(root_fd)
            _enforce_mode(queue_fd, 0o700, "Heel sync queue directory")
            os.fsync(queue_fd)
            yield queue_fd
        finally:
            if queue_fd >= 0:
                os.close(queue_fd)
            os.close(root_fd)

    @contextmanager
    def _locked_queue(self, *, create: bool) -> Iterator[int | None]:
        with self._open_queue(create=create) as queue_fd:
            if queue_fd is None:
                yield None
                return
            try:
                descriptor = os.open(".queue.lock", _LOCK_FLAGS, 0o600, dir_fd=queue_fd)
            except OSError as error:
                try:
                    status = os.stat(
                        ".queue.lock", dir_fd=queue_fd, follow_symlinks=False
                    )
                except OSError:
                    raise error
                if stat.S_ISLNK(status.st_mode):
                    raise ValueError(
                        "sync queue lock must not be a symbolic link"
                    ) from error
                if not stat.S_ISREG(status.st_mode):
                    raise ValueError(
                        "sync queue lock must be a regular file"
                    ) from error
                raise error
            locked = False
            try:
                lock_status = os.fstat(descriptor)
                if not stat.S_ISREG(lock_status.st_mode) or lock_status.st_nlink != 1:
                    raise ValueError("sync queue lock must be a regular file")
                _enforce_mode(descriptor, 0o600, "sync queue lock")
                os.fsync(descriptor)
                os.fsync(queue_fd)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                locked = True
                yield queue_fd
            finally:
                if locked:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    @contextmanager
    def _open_workspace(
        self, queue_fd: int, workspace_ref: str, *, create: bool
    ) -> Iterator[int | None]:
        workspace_fd = _open_child_directory(queue_fd, workspace_ref, create=create)
        if workspace_fd is None:
            yield None
            return
        try:
            _enforce_mode(workspace_fd, 0o700, "sync queue workspace directory")
            os.fsync(workspace_fd)
            yield workspace_fd
        finally:
            os.close(workspace_fd)

    @staticmethod
    def _filename(project_ref: str, request_digest: str) -> str:
        return f"{project_ref}.{request_digest}.json"

    @staticmethod
    def _target_status(workspace_fd: int, filename: str) -> os.stat_result | None:
        try:
            return os.stat(filename, dir_fd=workspace_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    @staticmethod
    def _reject_unsafe_target(workspace_fd: int, filename: str) -> None:
        status = SyncQueue._target_status(workspace_fd, filename)
        if status is None:
            return
        if stat.S_ISLNK(status.st_mode):
            raise ValueError("sync queue record must not be a symbolic link")
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise ValueError("sync queue record must be a regular file")

    @staticmethod
    def _create_temporary(workspace_fd: int, filename: str) -> tuple[int, str]:
        for _ in range(100):
            temporary = f".{filename}.{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    temporary, _WRITE_FLAGS, 0o600, dir_fd=workspace_fd
                )
            except FileExistsError:
                continue
            try:
                status = os.fstat(descriptor)
                if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                    raise ValueError(
                        "temporary sync queue record must be an unlinked regular file"
                    )
                _enforce_mode(descriptor, 0o600, "temporary sync queue record")
            except BaseException as error:
                os.close(descriptor)
                try:
                    os.unlink(temporary, dir_fd=workspace_fd)
                except OSError:
                    pass
                raise error
            return descriptor, temporary
        raise FileExistsError("could not allocate an exclusive sync queue temp file")

    def _write_record(
        self, workspace_fd: int, filename: str, record: SyncRecord
    ) -> None:
        payload = stable_json(_record_mapping(record)) + "\n"
        if len(payload.encode("utf-8")) > MAX_RECORD_BYTES:
            raise ValueError("sync queue record exceeds its size limit")
        self._reject_unsafe_target(workspace_fd, filename)
        descriptor, temporary = self._create_temporary(workspace_fd, filename)
        primary_error: BaseException | None = None
        try:
            with os.fdopen(
                descriptor,
                "w",
                encoding="utf-8",
                newline="\n",
                closefd=False,
            ) as stream:
                stream.write(payload)
                stream.flush()
            os.fsync(descriptor)
            try:
                os.replace(
                    temporary,
                    filename,
                    src_dir_fd=workspace_fd,
                    dst_dir_fd=workspace_fd,
                )
            except (TypeError, NotImplementedError) as error:
                raise SecureQueueStorageUnavailable(
                    "secure sync queue requires anchored replace support"
                ) from error
            temporary = ""
            _enforce_mode(descriptor, 0o600, "sync queue record")
            os.fsync(descriptor)
            os.fsync(workspace_fd)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            try:
                os.close(descriptor)
            except BaseException as close_error:
                if primary_error is None:
                    raise
                primary_error.add_note(
                    f"sync queue descriptor close failed: {close_error}"
                )
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=workspace_fd)
                    os.fsync(workspace_fd)
                except BaseException as cleanup_error:
                    if primary_error is None:
                        raise
                    primary_error.add_note(
                        f"sync queue temporary cleanup failed: {cleanup_error}"
                    )

    def _read_record(
        self,
        workspace_fd: int,
        filename: str,
        *,
        workspace_ref: str,
        project_ref: str,
        request_digest: str,
    ) -> SyncRecord:
        try:
            self._reject_unsafe_target(workspace_fd, filename)
            descriptor = os.open(filename, _READ_FLAGS, dir_fd=workspace_fd)
            try:
                status = os.fstat(descriptor)
                if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                    raise ValueError("sync queue record must be a regular file")
                if status.st_size > MAX_RECORD_BYTES:
                    raise ValueError("sync queue record exceeds its size limit")
                _enforce_mode(descriptor, 0o600, "sync queue record")
                with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                    descriptor = -1
                    source = stream.read(MAX_RECORD_BYTES + 1)
                if len(source.encode("utf-8")) > MAX_RECORD_BYTES:
                    raise ValueError("sync queue record exceeds its size limit")
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            value = _parse_json_text(
                source, maximum_bytes=MAX_RECORD_BYTES, label="stored sync queue record"
            )
            return _parse_record_mapping(
                value,
                expected_workspace=workspace_ref,
                expected_project=project_ref,
                expected_digest=request_digest,
            )
        except (OSError, UnicodeError, ValueError) as error:
            raise StoredSyncQueueError(
                "stored sync queue record is corrupt or unsafe"
            ) from error

    @staticmethod
    def _validate_human_approval(
        approval: HumanSyncApproval, record: SyncRecord, now: float
    ) -> StoredHumanApproval:
        if type(approval) is not HumanSyncApproval:
            raise ValueError("approval must be a HumanSyncApproval value")
        approved_at = _timestamp(approval.approved_at, "approved_at")
        expires_at = _timestamp(approval.expires_at, "expires_at")
        if (
            approval.workspace_ref != record.workspace_ref
            or approval.project_ref != record.project_ref
            or approval.request_digest != record.request_digest
            or approved_at > now
            or expires_at <= now
            or expires_at < approved_at
            or expires_at - approved_at > MAX_APPROVAL_SECONDS
        ):
            raise ValueError("human approval does not bind the live exact request")
        return StoredHumanApproval(approved_at, expires_at)

    def prepare(
        self,
        request: Mapping[str, Any],
        namespace_key: bytes,
        workspace_ref: str,
    ) -> SyncRecord:
        workspace = _pattern(workspace_ref, _WORKSPACE, "workspace_ref")
        validated = validate_findings_sync_request(request, namespace_key)
        request_json = stable_json(validated)
        request_digest = findings_sync_request_digest(validated, namespace_key)
        record = SyncRecord(
            SYNC_QUEUE_SCHEMA_VERSION,
            workspace,
            validated["project_ref"],
            request_digest,
            request_json,
            None,
            None,
            None,
            RetryState(0, None, None, None, None),
            None,
        )
        filename = self._filename(record.project_ref, record.request_digest)
        with self._locked_queue(create=True) as queue_fd:
            if queue_fd is None:
                raise SecureQueueStorageUnavailable("could not create sync queue")
            with self._open_workspace(queue_fd, workspace, create=True) as workspace_fd:
                if workspace_fd is None:
                    raise SecureQueueStorageUnavailable(
                        "could not create sync queue workspace"
                    )
                if self._target_status(workspace_fd, filename) is not None:
                    existing = self._read_record(
                        workspace_fd,
                        filename,
                        workspace_ref=workspace,
                        project_ref=record.project_ref,
                        request_digest=request_digest,
                    )
                    if existing.request_json != request_json:
                        raise ImmutableQueueConflict(
                            "request digest contradicts stored immutable bytes"
                        )
                    return existing
                self._write_record(workspace_fd, filename, record)
        return record

    def record_human_approval(self, approval: HumanSyncApproval) -> SyncRecord:
        if type(approval) is not HumanSyncApproval:
            raise ValueError("approval must be a HumanSyncApproval value")
        workspace = _pattern(approval.workspace_ref, _WORKSPACE, "workspace_ref")
        project = _pattern(approval.project_ref, _PROJECT, "project_ref")
        digest = _pattern(approval.request_digest, _DIGEST, "request_digest")
        filename = self._filename(project, digest)
        with self._locked_queue(create=False) as queue_fd:
            if queue_fd is None:
                raise KeyError("prepared sync queue record does not exist")
            with self._open_workspace(
                queue_fd, workspace, create=False
            ) as workspace_fd:
                if (
                    workspace_fd is None
                    or self._target_status(workspace_fd, filename) is None
                ):
                    raise KeyError("prepared sync queue record does not exist")
                current = self._read_record(
                    workspace_fd,
                    filename,
                    workspace_ref=workspace,
                    project_ref=project,
                    request_digest=digest,
                )
                now = _timestamp(self._now(), "current time")
                approved = self._validate_human_approval(approval, current, now)
                if current.receipt is not None:
                    return current
                if current.human_approval is not None:
                    if current.human_approval == approved:
                        return current
                    if current.human_approval.expires_at > now:
                        raise ImmutableQueueConflict(
                            "a different live human approval is already recorded"
                        )
                updated = SyncRecord(
                    current.schema_version,
                    current.workspace_ref,
                    current.project_ref,
                    current.request_digest,
                    current.request_json,
                    approved,
                    None,
                    None,
                    RetryState(0, now, None, None, None),
                    None,
                )
                self._write_record(workspace_fd, filename, updated)
                return updated

    def enqueue_approved(
        self,
        request: Mapping[str, Any],
        namespace_key: bytes,
        approval: HumanSyncApproval,
    ) -> SyncRecord:
        self.prepare(request, namespace_key, approval.workspace_ref)
        return self.record_human_approval(approval)

    def get(
        self, workspace_ref: str, project_ref: str, request_digest: str
    ) -> SyncRecord | None:
        workspace = _pattern(workspace_ref, _WORKSPACE, "workspace_ref")
        project = _pattern(project_ref, _PROJECT, "project_ref")
        digest = _pattern(request_digest, _DIGEST, "request_digest")
        filename = self._filename(project, digest)
        with self._locked_queue(create=False) as queue_fd:
            if queue_fd is None:
                return None
            with self._open_workspace(
                queue_fd, workspace, create=False
            ) as workspace_fd:
                if (
                    workspace_fd is None
                    or self._target_status(workspace_fd, filename) is None
                ):
                    return None
                try:
                    return self._read_record(
                        workspace_fd,
                        filename,
                        workspace_ref=workspace,
                        project_ref=project,
                        request_digest=digest,
                    )
                except StoredSyncQueueError:
                    return None

    def list(self, workspace_ref: str) -> list[SyncRecord]:
        workspace = _pattern(workspace_ref, _WORKSPACE, "workspace_ref")
        records: list[SyncRecord] = []
        pattern = re.compile(r"(prj_[0-9a-f]{32})\.([0-9a-f]{64})\.json\Z")
        with self._locked_queue(create=False) as queue_fd:
            if queue_fd is None:
                return records
            with self._open_workspace(
                queue_fd, workspace, create=False
            ) as workspace_fd:
                if workspace_fd is None:
                    return records
                for filename in sorted(os.listdir(workspace_fd)):
                    match = pattern.fullmatch(filename)
                    if match is None:
                        continue
                    project, digest = match.groups()
                    try:
                        record = self._read_record(
                            workspace_fd,
                            filename,
                            workspace_ref=workspace,
                            project_ref=project,
                            request_digest=digest,
                        )
                    except StoredSyncQueueError:
                        continue
                    records.append(record)
        records.sort(key=lambda record: (record.project_ref, record.request_digest))
        return records

    def delete(self, workspace_ref: str, project_ref: str, request_digest: str) -> bool:
        if (
            type(workspace_ref) is not str
            or _WORKSPACE.fullmatch(workspace_ref) is None
            or type(project_ref) is not str
            or _PROJECT.fullmatch(project_ref) is None
            or type(request_digest) is not str
            or _DIGEST.fullmatch(request_digest) is None
        ):
            return False
        filename = self._filename(project_ref, request_digest)
        with self._locked_queue(create=False) as queue_fd:
            if queue_fd is None:
                return False
            with self._open_workspace(
                queue_fd, workspace_ref, create=False
            ) as workspace_fd:
                if (
                    workspace_fd is None
                    or self._target_status(workspace_fd, filename) is None
                ):
                    return False
                self._reject_unsafe_target(workspace_fd, filename)
                try:
                    os.unlink(filename, dir_fd=workspace_fd)
                except FileNotFoundError:
                    return False
                os.fsync(workspace_fd)
                return True

    def _new_lease_token(self, previous: str | None = None) -> str:
        token = self._token()
        candidate = _pattern(token, _LEASE_TOKEN, "generated lease token")
        if candidate != previous:
            return candidate
        while True:
            candidate = f"fsl_{secrets.token_hex(16)}"
            if candidate != previous:
                return candidate

    @staticmethod
    def _claimable(record: SyncRecord, now: float) -> bool:
        return (
            record.human_approval is not None
            and record.human_approval.expires_at > now
            and record.receipt is None
            and (
                record.transmission is None
                or record.transmission.effective_expires_at <= now
            )
            and record.retry.next_attempt_at is not None
            and record.retry.next_attempt_at <= now
            and record.retry.attempts < 2**53 - 1
            and (
                record.retry.lease_expires_at is None
                or record.retry.lease_expires_at <= now
            )
        )

    def _claim_locked(
        self,
        workspace_fd: int,
        filename: str,
        record: SyncRecord,
        now: float,
    ) -> SyncLease | None:
        if not self._claimable(record, now):
            return None
        token = self._new_lease_token(record.retry.lease_token)
        lease_expires_at = now + self._lease_seconds
        updated = SyncRecord(
            record.schema_version,
            record.workspace_ref,
            record.project_ref,
            record.request_digest,
            record.request_json,
            record.human_approval,
            None,
            None,
            RetryState(
                record.retry.attempts + 1,
                record.retry.next_attempt_at,
                record.retry.last_error_code,
                token,
                lease_expires_at,
            ),
            None,
        )
        self._write_record(workspace_fd, filename, updated)
        return SyncLease(token, lease_expires_at, updated)

    def claim(
        self, workspace_ref: str, project_ref: str, request_digest: str
    ) -> SyncLease | None:
        workspace = _pattern(workspace_ref, _WORKSPACE, "workspace_ref")
        project = _pattern(project_ref, _PROJECT, "project_ref")
        digest = _pattern(request_digest, _DIGEST, "request_digest")
        filename = self._filename(project, digest)
        with self._locked_queue(create=False) as queue_fd:
            if queue_fd is None:
                return None
            with self._open_workspace(
                queue_fd, workspace, create=False
            ) as workspace_fd:
                if (
                    workspace_fd is None
                    or self._target_status(workspace_fd, filename) is None
                ):
                    return None
                try:
                    current = self._read_record(
                        workspace_fd,
                        filename,
                        workspace_ref=workspace,
                        project_ref=project,
                        request_digest=digest,
                    )
                except StoredSyncQueueError:
                    return None
                now = _timestamp(self._now(), "current time")
                return self._claim_locked(workspace_fd, filename, current, now)

    def claim_next(self, workspace_ref: str) -> SyncLease | None:
        workspace = _pattern(workspace_ref, _WORKSPACE, "workspace_ref")
        filename_pattern = re.compile(r"(prj_[0-9a-f]{32})\.([0-9a-f]{64})\.json\Z")
        with self._locked_queue(create=False) as queue_fd:
            if queue_fd is None:
                return None
            with self._open_workspace(
                queue_fd, workspace, create=False
            ) as workspace_fd:
                if workspace_fd is None:
                    return None
                records: list[tuple[str, str, str, SyncRecord]] = []
                for filename in os.listdir(workspace_fd):
                    match = filename_pattern.fullmatch(filename)
                    if match is None:
                        continue
                    project, digest = match.groups()
                    try:
                        record = self._read_record(
                            workspace_fd,
                            filename,
                            workspace_ref=workspace,
                            project_ref=project,
                            request_digest=digest,
                        )
                    except StoredSyncQueueError:
                        continue
                    records.append((project, digest, filename, record))
                now = _timestamp(self._now(), "current time")
                candidates: list[tuple[float, str, str, str, SyncRecord]] = []
                for project, digest, filename, record in records:
                    if not self._claimable(record, now):
                        continue
                    assert record.retry.next_attempt_at is not None
                    candidates.append(
                        (
                            record.retry.next_attempt_at,
                            project,
                            digest,
                            filename,
                            record,
                        )
                    )
                if not candidates:
                    return None
                _due, _project, _digest, filename, record = min(candidates)
                return self._claim_locked(workspace_fd, filename, record, now)

    @staticmethod
    def _validate_lease_handle(lease: SyncLease) -> None:
        if type(lease) is not SyncLease or type(lease.record) is not SyncRecord:
            raise ValueError("lease must be a SyncLease value")
        _pattern(lease.lease_token, _LEASE_TOKEN, "lease_token")
        expires_at = _timestamp(lease.lease_expires_at, "lease_expires_at")
        if (
            lease.record.retry.lease_token != lease.lease_token
            or lease.record.retry.lease_expires_at != expires_at
            or lease.record.transmission is not None
        ):
            raise ValueError("lease handle is internally inconsistent")

    @staticmethod
    def _lease_matches(current: SyncRecord, lease: SyncLease, now: float) -> bool:
        return (
            current.workspace_ref == lease.record.workspace_ref
            and current.project_ref == lease.record.project_ref
            and current.request_digest == lease.record.request_digest
            and current.request_json == lease.record.request_json
            and current.human_approval == lease.record.human_approval
            and current.transport_approval == lease.record.transport_approval
            and current.transmission == lease.record.transmission
            and current.retry == lease.record.retry
            and current.receipt == lease.record.receipt
            and current.receipt is None
            and current.retry.lease_token == lease.lease_token
            and current.retry.lease_expires_at == lease.lease_expires_at
            and lease.lease_expires_at > now
        )

    def _update_live_lease(
        self,
        lease: SyncLease,
        update: Callable[[SyncRecord, float], SyncRecord | None],
    ) -> tuple[SyncRecord, float] | None:
        self._validate_lease_handle(lease)
        record = lease.record
        filename = self._filename(record.project_ref, record.request_digest)
        with self._locked_queue(create=False) as queue_fd:
            if queue_fd is None:
                return None
            with self._open_workspace(
                queue_fd, record.workspace_ref, create=False
            ) as workspace_fd:
                if (
                    workspace_fd is None
                    or self._target_status(workspace_fd, filename) is None
                ):
                    return None
                try:
                    current = self._read_record(
                        workspace_fd,
                        filename,
                        workspace_ref=record.workspace_ref,
                        project_ref=record.project_ref,
                        request_digest=record.request_digest,
                    )
                except StoredSyncQueueError:
                    return None
                now = _timestamp(self._now(), "current time")
                if not self._lease_matches(current, lease, now):
                    return None
                updated = update(current, now)
                if updated is None:
                    return None
                self._write_record(workspace_fd, filename, updated)
                return updated, now

    def renew(self, lease: SyncLease) -> SyncLease | None:
        new_token = self._new_lease_token(lease.lease_token)

        def update(current: SyncRecord, now: float) -> SyncRecord | None:
            if (
                current.human_approval is None
                or current.human_approval.expires_at <= now
            ):
                return None
            new_expiry = now + self._lease_seconds
            transport = current.transport_approval
            if transport is not None and transport.expires_at <= now:
                transport = None
            return SyncRecord(
                current.schema_version,
                current.workspace_ref,
                current.project_ref,
                current.request_digest,
                current.request_json,
                current.human_approval,
                transport,
                None,
                RetryState(
                    current.retry.attempts,
                    current.retry.next_attempt_at,
                    current.retry.last_error_code,
                    new_token,
                    new_expiry,
                ),
                None,
            )

        result = self._update_live_lease(lease, update)
        if result is None:
            return None
        updated, _now = result
        assert updated.retry.lease_expires_at is not None
        return SyncLease(new_token, updated.retry.lease_expires_at, updated)

    def schedule_retry(
        self,
        authority: SyncLease | SyncTransmissionPermit,
        next_attempt_at: float,
        error_code: str,
    ) -> bool:
        due = _timestamp(next_attempt_at, "next_attempt_at")
        if error_code not in _RETRY_ERROR_CODES:
            raise ValueError("retry schedule is outside the closed queue contract")

        def update(current: SyncRecord, now: float) -> SyncRecord:
            if due < now:
                raise ValueError("retry schedule is outside the closed queue contract")
            return SyncRecord(
                current.schema_version,
                current.workspace_ref,
                current.project_ref,
                current.request_digest,
                current.request_json,
                current.human_approval,
                None,
                None,
                RetryState(
                    current.retry.attempts,
                    due,
                    error_code,
                    None,
                    None,
                ),
                None,
            )

        if type(authority) is SyncLease:
            return self._update_live_lease(authority, update) is not None
        if type(authority) is SyncTransmissionPermit:
            return self._update_current_permit(authority, update) is not None
        raise ValueError("retry authority must be a lease or transmission permit")

    def bind_transport_approval(
        self, lease: SyncLease, approval: Any
    ) -> SyncLease | None:
        from .cloud_client import TransportApproval

        self._validate_lease_handle(lease)
        if type(approval) is not TransportApproval:
            raise ValueError("transport approval must be a TransportApproval value")
        approved_at = _timestamp(approval.approved_at, "approved_at")
        expires_at = _timestamp(approval.expires_at, "expires_at")
        if (
            approval.workspace_ref != lease.record.workspace_ref
            or approval.project_ref != lease.record.project_ref
            or approval.request_digest != lease.record.request_digest
            or _APPROVAL_ID.fullmatch(approval.approval_id or "") is None
            or type(approval.approved_by) is not str
            or not approval.approved_by
            or len(approval.approved_by) > 256
            or any(ord(character) < 32 for character in approval.approved_by)
            or expires_at <= approved_at
            or expires_at - approved_at > MAX_APPROVAL_SECONDS
        ):
            raise ValueError("transport approval does not bind the live exact request")
        stored = StoredTransportApproval(
            approval.approval_id,
            approval.request_digest,
            approved_at,
            expires_at,
        )

        def update(current: SyncRecord, now: float) -> SyncRecord:
            if (
                current.human_approval is None
                or current.human_approval.expires_at <= now
            ):
                raise ValueError(
                    "human approval expired before transport authorization"
                )
            if (
                approved_at > now
                or expires_at <= now
                or expires_at <= approved_at
                or expires_at - approved_at > MAX_APPROVAL_SECONDS
            ):
                raise ValueError(
                    "transport approval does not bind the live exact request"
                )
            return SyncRecord(
                current.schema_version,
                current.workspace_ref,
                current.project_ref,
                current.request_digest,
                current.request_json,
                current.human_approval,
                stored,
                None,
                current.retry,
                None,
            )

        result = self._update_live_lease(lease, update)
        if result is None:
            return None
        updated, _now = result
        return SyncLease(lease.lease_token, lease.lease_expires_at, updated)

    def _new_permit_token(self) -> str:
        return f"fst_{secrets.token_hex(16)}"

    def begin_transmission(self, lease: SyncLease) -> SyncTransmissionPermit | None:
        permit_token = self._new_permit_token()

        def update(current: SyncRecord, now: float) -> SyncRecord:
            human = current.human_approval
            transport = current.transport_approval
            lease_expires = current.retry.lease_expires_at
            if human is None or human.approved_at > now or human.expires_at <= now:
                raise ValueError("human approval expired before transmission")
            if (
                transport is None
                or transport.approved_at > now
                or transport.expires_at <= now
            ):
                raise ValueError("fresh transport approval is required")
            if lease_expires is None:
                raise ValueError("transmission requires a live fenced lease")
            effective_expires_at = min(
                human.expires_at, transport.expires_at, lease_expires
            )
            if effective_expires_at <= now:
                raise ValueError("transmission authority expired before use")
            transmission = StoredTransmission(
                permit_token,
                lease.lease_token,
                current.request_digest,
                now,
                effective_expires_at,
            )
            return SyncRecord(
                current.schema_version,
                current.workspace_ref,
                current.project_ref,
                current.request_digest,
                current.request_json,
                human,
                transport,
                transmission,
                current.retry,
                None,
            )

        result = self._update_live_lease(lease, update)
        if result is None:
            return None
        updated, begun_at = result
        transmission = updated.transmission
        assert transmission is not None
        return SyncTransmissionPermit(
            permit_token,
            begun_at,
            transmission.effective_expires_at,
            updated,
        )

    @staticmethod
    def _validate_permit_handle(permit: SyncTransmissionPermit) -> None:
        if (
            type(permit) is not SyncTransmissionPermit
            or type(permit.record) is not SyncRecord
        ):
            raise ValueError("completion requires a SyncTransmissionPermit value")
        permit_token = _pattern(permit.permit_token, _PERMIT_TOKEN, "permit_token")
        begun_at = _timestamp(permit.begun_at, "begun_at")
        effective_expires_at = _timestamp(
            permit.effective_expires_at, "effective_expires_at"
        )
        transmission = permit.record.transmission
        if (
            transmission is None
            or transmission.permit_token != permit_token
            or transmission.begun_at != begun_at
            or transmission.effective_expires_at != effective_expires_at
            or transmission.request_digest != permit.record.request_digest
            or transmission.lease_token != permit.record.retry.lease_token
        ):
            raise ValueError("transmission permit is internally inconsistent")

    @staticmethod
    def _permit_matches(current: SyncRecord, permit: SyncTransmissionPermit) -> bool:
        return (
            current == permit.record
            and current.receipt is None
            and current.transmission is not None
            and current.transmission.permit_token == permit.permit_token
        )

    def _update_current_permit(
        self,
        permit: SyncTransmissionPermit,
        update: Callable[[SyncRecord, float], SyncRecord | None],
    ) -> tuple[SyncRecord, float] | None:
        self._validate_permit_handle(permit)
        record = permit.record
        filename = self._filename(record.project_ref, record.request_digest)
        with self._locked_queue(create=False) as queue_fd:
            if queue_fd is None:
                return None
            with self._open_workspace(
                queue_fd, record.workspace_ref, create=False
            ) as workspace_fd:
                if (
                    workspace_fd is None
                    or self._target_status(workspace_fd, filename) is None
                ):
                    return None
                try:
                    current = self._read_record(
                        workspace_fd,
                        filename,
                        workspace_ref=record.workspace_ref,
                        project_ref=record.project_ref,
                        request_digest=record.request_digest,
                    )
                except StoredSyncQueueError:
                    return None
                now = _timestamp(self._now(), "current time")
                if not self._permit_matches(current, permit):
                    return None
                updated = update(current, now)
                if updated is None:
                    return None
                self._write_record(workspace_fd, filename, updated)
                return updated, now

    def complete(self, permit: SyncTransmissionPermit, receipt_value: Any) -> bool:
        self._validate_permit_handle(permit)
        record = permit.record
        if (
            record.human_approval is None
            or record.transport_approval is None
            or record.transmission is None
        ):
            raise ValueError("completion requires a begun transmission")
        try:
            receipt = validate_findings_sync_receipt(receipt_value)
            _request_json, request = _validate_request_without_namespace_key(
                record.request_json,
                record.project_ref,
                record.request_digest,
            )
        except ValueError:
            raise ValueError(
                "receipt does not match the exact queued request"
            ) from None
        if (
            receipt["project_ref"] != record.project_ref
            or receipt["request_digest"] != record.request_digest
            or receipt["projection_hash"] != request["projection_hash"]
            or record.transport_approval.request_digest != record.request_digest
        ):
            raise ValueError("receipt does not match the exact queued request")

        def update(current: SyncRecord, _now: float) -> SyncRecord:
            if current.transport_approval is None or current.transmission is None:
                raise ValueError("completion requires a begun transmission")
            return SyncRecord(
                current.schema_version,
                current.workspace_ref,
                current.project_ref,
                current.request_digest,
                current.request_json,
                current.human_approval,
                current.transport_approval,
                None,
                RetryState(
                    current.retry.attempts,
                    None,
                    None,
                    None,
                    None,
                ),
                receipt,
            )

        return self._update_current_permit(permit, update) is not None
