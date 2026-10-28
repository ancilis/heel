"""Secure local storage for Heel device credentials.

On macOS credentials live in the login Keychain. Other POSIX platforms use a
descriptor-anchored, owner-only file below ``HEEL_HOME``. The stored document is a
closed transport credential schema; arbitrary metadata is never accepted.
"""
from __future__ import annotations

from contextlib import contextmanager
try:
    import fcntl
except ImportError:  # pragma: no cover - secure fallback already rejects non-POSIX hosts
    fcntl = None  # type: ignore[assignment]
import hashlib
import inspect
import json
import os
from dataclasses import dataclass
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import threading
from typing import Any, Iterator, Literal, Mapping
from urllib.parse import urlsplit

from .scope import heel_home


_SCHEMA_VERSION = "heel.device-credentials.v1"
_STORED_SCHEMA_VERSION = "heel.stored-device-credentials.v1"
_KEYCHAIN_SERVICE = "io.ancilis.heel.cloud.v1"
_SECURITY_PATH = Path("/usr/bin/security")
_MAX_CREDENTIAL_BYTES = 16 * 1024
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
    os.O_RDWR
    | os.O_CREAT
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_DEVICE_ID = re.compile(r"dev_[0-9a-f]{32}\Z", flags=re.ASCII)
_ACCESS_TOKEN = re.compile(r"heel_at_[A-Za-z0-9_-]{43}\Z", flags=re.ASCII)
_REFRESH_TOKEN = re.compile(r"heel_rt_[A-Za-z0-9_-]{64}\Z", flags=re.ASCII)
_CREDENTIAL_FIELDS = (
    "schema_version",
    "cloud_base_url",
    "device_id",
    "access_token",
    "access_expires_at",
    "refresh_token",
    "refresh_expires_at",
)
_STORED_CREDENTIAL_FIELDS = (
    "schema_version",
    "cloud_base_url",
    "device_id",
    "refresh_token",
    "refresh_expires_at",
)
_CREDENTIAL_FIELD_SET = frozenset(_CREDENTIAL_FIELDS)
_STORED_CREDENTIAL_FIELD_SET = frozenset(_STORED_CREDENTIAL_FIELDS)


class SecureCredentialStorageUnavailable(RuntimeError):
    """The platform cannot provide Heel's secure fallback persistence contract."""


class StoredCredentialError(ValueError):
    """Persisted credentials are corrupt, unsafe, or violate the closed schema."""


class CredentialStoreError(RuntimeError):
    """The selected credential backend could not complete an operation."""


@dataclass(frozen=True)
class _ProcessResult:
    returncode: int
    stdout: bytes


@dataclass(frozen=True)
class DeviceCredentials:
    schema_version: Literal["heel.device-credentials.v1"]
    cloud_base_url: str
    device_id: str
    access_token: str
    access_expires_at: int
    refresh_token: str
    refresh_expires_at: int


@dataclass(frozen=True)
class StoredDeviceCredentials:
    """Refresh material that may cross the durable-storage boundary."""

    schema_version: Literal["heel.stored-device-credentials.v1"]
    cloud_base_url: str
    device_id: str
    refresh_token: str
    refresh_expires_at: int


@dataclass(frozen=True)
class CredentialStatus:
    authenticated: bool
    backend: Literal["macos_keychain", "restricted_file"]
    cloud_base_url: str | None
    device_id: str | None
    refresh_expires_at: int | None


def _validate_cloud_base_url(value: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 2048
        or value != value.strip()
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
    ):
        raise ValueError("invalid cloud base URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("invalid cloud base URL")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("invalid cloud base URL") from None
    hostname = parsed.hostname.lower()
    if hostname.endswith("."):
        raise ValueError("invalid cloud base URL")
    if parsed.scheme == "http" and hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("cloud base URL must use HTTPS")
    host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and not (
        (parsed.scheme == "https" and port == 443)
        or (parsed.scheme == "http" and port == 80)
    ):
        host += f":{port}"
    return f"{parsed.scheme}://{host}"


def _macos_keychain_available() -> bool:
    if sys.platform != "darwin":
        return False
    try:
        status = _SECURITY_PATH.stat()
    except OSError:
        return False
    return stat.S_ISREG(status.st_mode) and os.access(_SECURITY_PATH, os.X_OK)


def _require_secure_storage_capabilities() -> None:
    required_dir_fd = (os.open, os.mkdir, os.stat, os.unlink)
    try:
        replace_parameters = inspect.signature(os.replace).parameters
    except (TypeError, ValueError):
        replace_parameters = {}
    if not (
        os.name == "posix"
        and bool(getattr(os, "O_DIRECTORY", 0))
        and bool(getattr(os, "O_NOFOLLOW", 0))
        and all(function in os.supports_dir_fd for function in required_dir_fd)
        and os.stat in os.supports_follow_symlinks
        and {"src_dir_fd", "dst_dir_fd"} <= set(replace_parameters)
    ):
        raise SecureCredentialStorageUnavailable(
            "secure credential fallback requires POSIX dir_fd and O_NOFOLLOW support"
        )


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
            raise ValueError("credential document contains duplicate JSON keys")
        result[key] = value
    return result


def _validate_timestamp(value: Any) -> int:
    if type(value) is not int or not 0 < value <= 9_007_199_254_740_991:
        raise ValueError("invalid credential expiry")
    return value


def _validate_credentials(
    value: Mapping[str, Any] | DeviceCredentials,
    *,
    expected_base_url: str,
) -> DeviceCredentials:
    if isinstance(value, DeviceCredentials):
        fields: Mapping[str, Any] = {
            name: getattr(value, name) for name in _CREDENTIAL_FIELDS
        }
    elif type(value) is dict:
        fields = value
    else:
        raise ValueError("invalid credential document")
    if frozenset(fields) != _CREDENTIAL_FIELD_SET:
        raise ValueError("invalid credential document fields")
    if fields["schema_version"] != _SCHEMA_VERSION:
        raise ValueError("unsupported credential schema")
    cloud_base_url = _validate_cloud_base_url(fields["cloud_base_url"])
    if cloud_base_url != expected_base_url or fields["cloud_base_url"] != cloud_base_url:
        raise ValueError("credential cloud origin mismatch")
    device_id = fields["device_id"]
    access_token = fields["access_token"]
    refresh_token = fields["refresh_token"]
    if type(device_id) is not str or _DEVICE_ID.fullmatch(device_id) is None:
        raise ValueError("invalid device credential")
    if type(access_token) is not str or _ACCESS_TOKEN.fullmatch(access_token) is None:
        raise ValueError("invalid access credential")
    if type(refresh_token) is not str or _REFRESH_TOKEN.fullmatch(refresh_token) is None:
        raise ValueError("invalid refresh credential")
    access_expires_at = _validate_timestamp(fields["access_expires_at"])
    refresh_expires_at = _validate_timestamp(fields["refresh_expires_at"])
    if access_expires_at > refresh_expires_at:
        raise ValueError("credential expiry order is invalid")
    return DeviceCredentials(
        schema_version=_SCHEMA_VERSION,
        cloud_base_url=cloud_base_url,
        device_id=device_id,
        access_token=access_token,
        access_expires_at=access_expires_at,
        refresh_token=refresh_token,
        refresh_expires_at=refresh_expires_at,
    )


def _stored_credentials(credentials: DeviceCredentials) -> StoredDeviceCredentials:
    return StoredDeviceCredentials(
        schema_version=_STORED_SCHEMA_VERSION,
        cloud_base_url=credentials.cloud_base_url,
        device_id=credentials.device_id,
        refresh_token=credentials.refresh_token,
        refresh_expires_at=credentials.refresh_expires_at,
    )


def _validate_stored_credentials(
    value: Mapping[str, Any] | StoredDeviceCredentials,
    *,
    expected_base_url: str,
) -> StoredDeviceCredentials:
    if isinstance(value, StoredDeviceCredentials):
        fields: Mapping[str, Any] = {
            name: getattr(value, name) for name in _STORED_CREDENTIAL_FIELDS
        }
    elif type(value) is dict:
        fields = value
    else:
        raise ValueError("invalid stored credential document")
    if frozenset(fields) != _STORED_CREDENTIAL_FIELD_SET:
        raise ValueError("invalid stored credential document fields")
    if fields["schema_version"] != _STORED_SCHEMA_VERSION:
        raise ValueError("unsupported stored credential schema")
    cloud_base_url = _validate_cloud_base_url(fields["cloud_base_url"])
    if cloud_base_url != expected_base_url or fields["cloud_base_url"] != cloud_base_url:
        raise ValueError("credential cloud origin mismatch")
    device_id = fields["device_id"]
    refresh_token = fields["refresh_token"]
    if type(device_id) is not str or _DEVICE_ID.fullmatch(device_id) is None:
        raise ValueError("invalid device credential")
    if type(refresh_token) is not str or _REFRESH_TOKEN.fullmatch(refresh_token) is None:
        raise ValueError("invalid refresh credential")
    return StoredDeviceCredentials(
        schema_version=_STORED_SCHEMA_VERSION,
        cloud_base_url=cloud_base_url,
        device_id=device_id,
        refresh_token=refresh_token,
        refresh_expires_at=_validate_timestamp(fields["refresh_expires_at"]),
    )


def _canonical_credentials(credentials: StoredDeviceCredentials) -> str:
    return json.dumps(
        {
            name: getattr(credentials, name) for name in _STORED_CREDENTIAL_FIELDS
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ) + "\n"


def _cleanup_temporary(
    cloud_fd: int, filename: str, primary_error: BaseException | None = None
) -> None:
    try:
        os.unlink(filename, dir_fd=cloud_fd)
    except FileNotFoundError:
        return
    except BaseException as cleanup_error:
        if primary_error is None:
            raise
        primary_error.add_note(f"temporary credential cleanup failed: {cleanup_error}")
        return
    try:
        os.fsync(cloud_fd)
    except BaseException as cleanup_error:
        if primary_error is None:
            raise
        primary_error.add_note(
            f"temporary credential cleanup directory fsync failed: {cleanup_error}"
        )


def _run_bounded_process(
    command: list[str], *, payload: bytes | None
) -> _ProcessResult:
    """Run a fixed helper while retaining no more than one bounded response document."""
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            bufsize=0,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except OSError as error:
        raise CredentialStoreError("macOS Keychain operation failed") from error
    if process.stdin is None or process.stdout is None:  # pragma: no cover - Popen contract
        process.kill()
        process.wait()
        raise CredentialStoreError("macOS Keychain operation failed")

    retained = bytearray()
    worker_errors: list[BaseException] = []

    def write_input() -> None:
        try:
            if payload is not None:
                process.stdin.write(payload)
                process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as error:
            worker_errors.append(error)
        finally:
            try:
                process.stdin.close()
            except (OSError, ValueError):
                pass

    def drain_output() -> None:
        try:
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    return
                remaining = _MAX_CREDENTIAL_BYTES + 1 - len(retained)
                if remaining > 0:
                    retained.extend(chunk[:remaining])
        except (OSError, ValueError) as error:
            worker_errors.append(error)

    writer = threading.Thread(target=write_input, daemon=True)
    reader = threading.Thread(target=drain_output, daemon=True)
    writer.start()
    reader.start()
    try:
        returncode = process.wait(timeout=15)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()
        raise CredentialStoreError("macOS Keychain operation timed out") from error
    finally:
        writer.join(1)
        reader.join(1)
        try:
            process.stdout.close()
        except (OSError, ValueError):
            pass
    if writer.is_alive() or reader.is_alive() or worker_errors:
        raise CredentialStoreError("macOS Keychain operation failed")
    return _ProcessResult(returncode, bytes(retained))


class CredentialStore:
    """Store credentials for exactly one cloud origin."""

    def __init__(self, cloud_base_url: str, root: Path | None = None):
        self.cloud_base_url = _validate_cloud_base_url(cloud_base_url)
        selected = Path(heel_home()) if root is None else Path(root)
        self.root = _absolute_without_resolving(selected)
        if self.root == Path(self.root.anchor):
            raise ValueError("Heel home must not be a filesystem root")
        self.backend: Literal["macos_keychain", "restricted_file"] = (
            "macos_keychain" if _macos_keychain_available() else "restricted_file"
        )
        self._keychain_account = hashlib.sha256(
            self.cloud_base_url.encode("utf-8")
        ).hexdigest()
        self._credential_filename = f"credentials-{self._keychain_account}.json"
        self._lock_filename = f"refresh-{self._keychain_account}.lock"
        self.credentials_path = self.root / "cloud" / self._credential_filename
        if self.backend == "restricted_file":
            _require_secure_storage_capabilities()

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
    def _open_cloud(self, *, create: bool) -> Iterator[int | None]:
        root_fd = self._open_root(create=create)
        if root_fd is None:
            yield None
            return
        cloud_fd = -1
        try:
            opened = _open_child_directory(root_fd, "cloud", create=create)
            if opened is None:
                yield None
                return
            cloud_fd = opened
            _enforce_mode(root_fd, 0o700, "Heel home")
            os.fsync(root_fd)
            _enforce_mode(cloud_fd, 0o700, "Heel cloud directory")
            os.fsync(cloud_fd)
            yield cloud_fd
        finally:
            if cloud_fd >= 0:
                os.close(cloud_fd)
            os.close(root_fd)

    def _target_status(self, cloud_fd: int) -> os.stat_result | None:
        try:
            return os.stat(
                self._credential_filename,
                dir_fd=cloud_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return None

    def _reject_unsafe_target(self, cloud_fd: int) -> None:
        status = self._target_status(cloud_fd)
        if status is None:
            return
        if stat.S_ISLNK(status.st_mode):
            raise ValueError("credential target must not be a symbolic link")
        if not stat.S_ISREG(status.st_mode):
            raise ValueError("credential target must be a regular file")

    def _create_temporary(self, cloud_fd: int) -> tuple[int, str]:
        for _ in range(100):
            filename = (
                f".{self._credential_filename}.{secrets.token_hex(16)}.tmp"
            )
            try:
                descriptor = os.open(filename, _WRITE_FLAGS, 0o600, dir_fd=cloud_fd)
            except FileExistsError:
                continue
            try:
                _enforce_mode(descriptor, 0o600, "temporary credential file")
            except BaseException as error:
                os.close(descriptor)
                _cleanup_temporary(cloud_fd, filename, error)
                raise
            return descriptor, filename
        raise FileExistsError("could not allocate an exclusive credential temp file")

    def _load_restricted_file(self) -> StoredDeviceCredentials | None:
        with self._open_cloud(create=False) as cloud_fd:
            if cloud_fd is None or self._target_status(cloud_fd) is None:
                return None
            try:
                self._reject_unsafe_target(cloud_fd)
                descriptor = os.open(
                    self._credential_filename, _READ_FLAGS, dir_fd=cloud_fd
                )
                try:
                    status = os.fstat(descriptor)
                    if not stat.S_ISREG(status.st_mode):
                        raise ValueError("credential target must be a regular file")
                    if status.st_size > _MAX_CREDENTIAL_BYTES:
                        raise ValueError("credential document is too large")
                    _enforce_mode(descriptor, 0o600, "credential file")
                    with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                        descriptor = -1
                        raw = stream.read(_MAX_CREDENTIAL_BYTES + 1)
                    if len(raw.encode("utf-8")) > _MAX_CREDENTIAL_BYTES:
                        raise ValueError("credential document is too large")
                    document = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
                    return _validate_stored_credentials(
                        document, expected_base_url=self.cloud_base_url
                    )
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
            except (OSError, UnicodeError, ValueError) as error:
                raise StoredCredentialError(
                    "stored device credentials are corrupt or unsafe"
                ) from error

    def _save_restricted_file(self, credentials: StoredDeviceCredentials) -> Path:
        payload = _canonical_credentials(credentials)
        with self._open_cloud(create=True) as cloud_fd:
            if cloud_fd is None:
                raise SecureCredentialStorageUnavailable(
                    "could not create the secure cloud credential directory"
                )
            self._reject_unsafe_target(cloud_fd)
            descriptor, temporary = self._create_temporary(cloud_fd)
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
                        self._credential_filename,
                        src_dir_fd=cloud_fd,
                        dst_dir_fd=cloud_fd,
                    )
                except (TypeError, NotImplementedError) as error:
                    raise SecureCredentialStorageUnavailable(
                        "secure credential fallback requires anchored replace support"
                    ) from error
                temporary = ""
                _enforce_mode(descriptor, 0o600, "credential file")
                os.fsync(descriptor)
                os.fsync(cloud_fd)
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
                        f"temporary credential descriptor close failed: {close_error}"
                    )
                if temporary:
                    _cleanup_temporary(cloud_fd, temporary, primary_error)
        return self.credentials_path

    def _delete_restricted_file(self) -> None:
        with self._open_cloud(create=False) as cloud_fd:
            if cloud_fd is None or self._target_status(cloud_fd) is None:
                return
            self._reject_unsafe_target(cloud_fd)
            try:
                os.unlink(self._credential_filename, dir_fd=cloud_fd)
            except FileNotFoundError:
                return
            os.fsync(cloud_fd)

    @contextmanager
    def refresh_lock(self) -> Iterator[None]:
        """Serialize one origin's load -> remote refresh -> save transaction."""
        if fcntl is None:
            raise SecureCredentialStorageUnavailable(
                "credential refresh serialization requires POSIX flock"
            )
        _require_secure_storage_capabilities()
        with self._open_cloud(create=True) as cloud_fd:
            if cloud_fd is None:
                raise SecureCredentialStorageUnavailable(
                    "could not create the credential refresh lock"
                )
            try:
                descriptor = os.open(
                    self._lock_filename, _LOCK_FLAGS, 0o600, dir_fd=cloud_fd
                )
            except OSError as error:
                try:
                    status = os.stat(
                        self._lock_filename,
                        dir_fd=cloud_fd,
                        follow_symlinks=False,
                    )
                except OSError:
                    raise error
                if stat.S_ISLNK(status.st_mode):
                    raise ValueError(
                        "credential refresh lock must not be a symbolic link"
                    ) from error
                if not stat.S_ISREG(status.st_mode):
                    raise ValueError(
                        "credential refresh lock must be a regular file"
                    ) from error
                raise error
            locked = False
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise ValueError("credential refresh lock must be a regular file")
                _enforce_mode(descriptor, 0o600, "credential refresh lock")
                os.fsync(descriptor)
                os.fsync(cloud_fd)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                locked = True
                yield
            finally:
                if locked:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def _run_keychain(
        self, operation: str, *, payload: bytes | None = None
    ) -> _ProcessResult:
        if operation == "save":
            command = [
                os.fspath(_SECURITY_PATH),
                "add-generic-password",
                "-U",
                "-a",
                self._keychain_account,
                "-s",
                _KEYCHAIN_SERVICE,
                "-w",
            ]
        elif operation == "load":
            command = [
                os.fspath(_SECURITY_PATH),
                "find-generic-password",
                "-a",
                self._keychain_account,
                "-s",
                _KEYCHAIN_SERVICE,
                "-w",
            ]
        elif operation == "delete":
            command = [
                os.fspath(_SECURITY_PATH),
                "delete-generic-password",
                "-a",
                self._keychain_account,
                "-s",
                _KEYCHAIN_SERVICE,
            ]
        else:
            raise AssertionError("unknown Keychain operation")
        return _run_bounded_process(command, payload=payload)

    def _load_keychain(self) -> StoredDeviceCredentials | None:
        result = self._run_keychain("load")
        if result.returncode == 44:
            return None
        if result.returncode != 0:
            raise CredentialStoreError("macOS Keychain read failed")
        if len(result.stdout) > _MAX_CREDENTIAL_BYTES:
            raise StoredCredentialError("stored device credentials are corrupt or unsafe")
        try:
            document = json.loads(
                result.stdout.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
            )
            return _validate_stored_credentials(
                document, expected_base_url=self.cloud_base_url
            )
        except (UnicodeError, ValueError) as error:
            raise StoredCredentialError(
                "stored device credentials are corrupt or unsafe"
            ) from error

    def _save_keychain(self, credentials: StoredDeviceCredentials) -> None:
        payload = _canonical_credentials(credentials).encode("utf-8")
        result = self._run_keychain("save", payload=payload)
        if result.returncode != 0:
            raise CredentialStoreError("macOS Keychain write failed")

    def load(self) -> StoredDeviceCredentials | None:
        if self.backend == "macos_keychain":
            return self._load_keychain()
        return self._load_restricted_file()

    def save(self, credentials: DeviceCredentials) -> Path | None:
        if type(credentials) is not DeviceCredentials:
            raise ValueError("credentials must be a DeviceCredentials value")
        validated = _validate_credentials(
            credentials, expected_base_url=self.cloud_base_url
        )
        stored = _stored_credentials(validated)
        if self.backend == "macos_keychain":
            self._save_keychain(stored)
            return None
        return self._save_restricted_file(stored)

    def delete(self) -> None:
        if self.backend == "macos_keychain":
            result = self._run_keychain("delete")
            if result.returncode not in {0, 44}:
                raise CredentialStoreError("macOS Keychain delete failed")
            return
        self._delete_restricted_file()

    def status(self) -> CredentialStatus:
        credentials = self.load()
        if credentials is None:
            return CredentialStatus(False, self.backend, None, None, None)
        return CredentialStatus(
            True,
            self.backend,
            credentials.cloud_base_url,
            credentials.device_id,
            credentials.refresh_expires_at,
        )
