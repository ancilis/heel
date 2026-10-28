"""Fail-closed adapters for runner-local canary credentials."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import select
import stat
import subprocess
import threading
import time
from typing import Any, Callable, Mapping

from .identity import security_interactive_add_command

MAX_SECRET_BYTES = 16 * 1024
MAX_COMMAND_OUTPUT_BYTES = 4 * 1024
_HANDLE = re.compile(r"^[0-9a-f]{32}$", flags=re.ASCII)
_MACOS_SECURITY = "/usr/bin/security"
_LINUX_SECRET_TOOLS = frozenset({"/usr/bin/secret-tool"})
_MINIMAL_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
_KEYCHAIN_CHUNK_CHARS = 3072
_KEYCHAIN_HEADER = re.compile(rb"^v2\.([1-9][0-9]{0,4})\.([1-8])\.([0-9a-f]{32})$", flags=re.ASCII)


def _encoded_length(length: int) -> int:
    return 4 * ((length + 2) // 3)


def _chunk_count(encoded_length: int) -> int:
    return (encoded_length + _KEYCHAIN_CHUNK_CHARS - 1) // _KEYCHAIN_CHUNK_CHARS


def _keychain_tag(secret: bytes) -> str:
    return hashlib.sha256(secret).hexdigest()[:32]


_KEYCHAIN_MAX_CHUNKS = _chunk_count(_encoded_length(MAX_SECRET_BYTES))


class SecretTooLargeError(ValueError):
    """A secret exceeded the fixed local credential ceiling."""


class VaultUnavailable(RuntimeError):
    """The selected secure credential provider cannot complete the operation."""


class UnavailableVault:
    backend_id = "unavailable"
    supported = False

    def load(self, handle_id: str) -> bytes:
        del handle_id
        raise VaultUnavailable("secure credential vault unavailable")

    def store(self, handle_id: str, secret: bytes) -> None:
        del handle_id, secret
        raise VaultUnavailable("secure credential vault unavailable")

    def exists(self, handle_id: str) -> bool:
        del handle_id
        return False

    def delete(self, handle_id: str) -> None:
        del handle_id
        raise VaultUnavailable("secure credential vault unavailable")


def _handle(value: object) -> str:
    if type(value) is not str or _HANDLE.fullmatch(value) is None:
        raise ValueError("invalid credential handle")
    return value


def _secret(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError("secret must be bytes")
    if not value:
        raise ValueError("secret must not be empty")
    if len(value) > MAX_SECRET_BYTES:
        raise SecretTooLargeError("secret exceeds the 16 KiB limit")
    return value


def _timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 10:
        raise ValueError("vault timeout must be between zero and ten seconds")
    return float(value)


def _verify_executable(path: str, *, allowed_paths: frozenset[str], platform_name: str) -> str:
    del platform_name
    if (
        type(path) is not str
        or not os.path.isabs(path)
        or os.path.normpath(path) != path
        or path not in allowed_paths
    ):
        raise VaultUnavailable("secure credential executable is not allowlisted")
    try:
        status = os.stat(path, follow_symlinks=False)
    except OSError:
        raise VaultUnavailable("secure credential vault unavailable") from None
    if not stat.S_ISREG(status.st_mode) or not os.access(path, os.X_OK):
        raise VaultUnavailable("secure credential vault unavailable")
    return path


def _run_bounded_process(
    command: tuple[str, ...],
    *,
    payload: bytes | None,
    timeout_seconds: float,
    popen: Callable[..., object] = subprocess.Popen,
) -> subprocess.CompletedProcess:
    """Drain all output while retaining only the fixed sentinel-bounded prefix."""
    timeout = _timeout(timeout_seconds)
    if not isinstance(command, tuple) or not command or any(type(item) is not str for item in command):
        raise VaultUnavailable("secure credential vault unavailable")
    if payload is not None:
        payload = _secret(payload)
    try:
        process = popen(
            command,
            stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            bufsize=0,
            env=dict(_MINIMAL_ENV),
        )
        output = process.stdout
        process_input = process.stdin if payload is not None else None
    except (AttributeError, OSError, TypeError, ValueError):
        raise VaultUnavailable("secure credential vault unavailable") from None
    if output is None or (payload is not None and process_input is None):
        try:
            process.kill()
            process.wait()
        except Exception:
            pass
        raise VaultUnavailable("secure credential vault unavailable")

    retained = bytearray()
    failed = threading.Event()

    def write_input() -> None:
        if process_input is None:
            return
        try:
            process_input.write(payload)
            process_input.flush()
        except (BrokenPipeError, OSError, TypeError, ValueError):
            failed.set()
        finally:
            try:
                process_input.close()
            except (OSError, ValueError):
                pass

    def read_output() -> None:
        try:
            while True:
                chunk = output.read(64 * 1024)
                if not chunk:
                    return
                remaining = MAX_COMMAND_OUTPUT_BYTES + 1 - len(retained)
                if remaining > 0:
                    retained.extend(chunk[:remaining])
        except (OSError, TypeError, ValueError):
            failed.set()

    writer = threading.Thread(target=write_input, daemon=True)
    reader = threading.Thread(target=read_output, daemon=True)
    writer.start()
    reader.start()
    try:
        returncode = process.wait(timeout=timeout)
    except (OSError, TypeError, ValueError, subprocess.SubprocessError):
        try:
            process.kill()
            process.wait()
        except Exception:
            pass
        raise VaultUnavailable("secure credential vault unavailable") from None
    finally:
        writer.join(1)
        reader.join(1)
        try:
            output.close()
        except (OSError, ValueError):
            pass
    if writer.is_alive() or reader.is_alive() or failed.is_set():
        try:
            process.kill()
            process.wait()
        except Exception:
            pass
        raise VaultUnavailable("secure credential vault unavailable")
    return subprocess.CompletedProcess(command, returncode, bytes(retained), None)


def ephemeral_environment_name(handle_id: str, *, source_kind: str) -> str:
    handle = _handle(handle_id).upper()
    if source_kind == "environment":
        return f"HEEL_RUNNER_CREDENTIAL_{handle}"
    if source_kind == "inherited_fd":
        return f"HEEL_RUNNER_CREDENTIAL_{handle}_FD"
    raise ValueError("invalid ephemeral credential source")


def read_inherited_secret(descriptor: int, *, timeout_seconds: float = 2) -> bytes:
    """Read one bounded secret from an explicitly inherited descriptor."""
    timeout = _timeout(timeout_seconds)
    if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 3:
        raise VaultUnavailable("inherited credential descriptor is unavailable")
    try:
        os.fstat(descriptor)
        if not os.get_inheritable(descriptor):
            raise VaultUnavailable("inherited credential descriptor is unavailable")
        duplicate = os.dup(descriptor)
    except OSError:
        raise VaultUnavailable("inherited credential descriptor is unavailable") from None
    try:
        os.set_inheritable(duplicate, False)
        deadline = time.monotonic() + timeout
        retained = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VaultUnavailable("inherited credential descriptor timed out")
            ready, _, _ = select.select([duplicate], [], [], remaining)
            if not ready:
                raise VaultUnavailable("inherited credential descriptor timed out")
            chunk = os.read(duplicate, min(4096, MAX_SECRET_BYTES + 1 - len(retained)))
            if not chunk:
                break
            retained.extend(chunk)
            if len(retained) > MAX_SECRET_BYTES:
                raise SecretTooLargeError("secret exceeds the 16 KiB limit")
        return _secret(bytes(retained))
    finally:
        os.close(duplicate)


class EphemeralVault:
    """Consume the exact per-handle environment or inherited-FD convention once."""

    supported = True

    def __init__(
        self,
        handle_id: str,
        *,
        source_kind: str,
        timeout_seconds: float = 2,
    ):
        if source_kind not in {"environment", "inherited_fd"}:
            raise ValueError("invalid ephemeral credential source")
        self.handle_id = _handle(handle_id)
        self.source_kind = source_kind
        self.timeout_seconds = _timeout(timeout_seconds)

    def _variable(self, handle_id: str) -> str:
        if handle_id != self.handle_id:
            raise ValueError("ephemeral credential handle mismatch")
        return ephemeral_environment_name(handle_id, source_kind=self.source_kind)

    def load(self, handle_id: str | None = None) -> bytes:
        selected = self.handle_id if handle_id is None else _handle(handle_id)
        variable = self._variable(selected)
        other_kind = (
            "inherited_fd" if self.source_kind == "environment" else "environment"
        )
        other_variable = ephemeral_environment_name(selected, source_kind=other_kind)
        if other_variable in os.environ:
            os.environ.pop(other_variable, None)
            os.environ.pop(variable, None)
            raise VaultUnavailable("ephemeral credential source must be exact and exclusive")
        if self.source_kind == "environment":
            value = os.environ.pop(variable, None)
            if value is None:
                raise VaultUnavailable("ephemeral credential is unavailable")
            try:
                return _secret(value.encode("utf-8"))
            finally:
                value = ""

        descriptor_text = os.environ.pop(variable, None)
        if descriptor_text is None or not descriptor_text.isascii() or not descriptor_text.isdecimal():
            raise VaultUnavailable("ephemeral credential is unavailable")
        descriptor = int(descriptor_text, 10)
        descriptor_text = ""
        return read_inherited_secret(descriptor, timeout_seconds=self.timeout_seconds)

    def store(self, handle_id: str, secret: bytes) -> None:
        _handle(handle_id)
        _secret(secret)
        raise VaultUnavailable("ephemeral vault never persists secrets")


class _CommandVault:
    supported = True

    def __init__(
        self,
        *,
        executable_path: str,
        allowed_paths: frozenset[str],
        required_platform: str,
        runner: Callable[..., Any] = _run_bounded_process,
        verifier: Callable[..., str] = _verify_executable,
        platform_name: str | None = None,
        timeout_seconds: float = 2,
    ):
        current_platform = platform.system() if platform_name is None else platform_name
        if current_platform != required_platform:
            raise VaultUnavailable("secure credential vault unavailable on this platform")
        if (
            not os.path.isabs(executable_path)
            or os.path.normpath(executable_path) != executable_path
            or executable_path not in allowed_paths
        ):
            raise VaultUnavailable("secure credential executable is not allowlisted")
        self.executable = verifier(
            executable_path, allowed_paths=allowed_paths, platform_name=current_platform,
        )
        self._runner = runner
        self.timeout_seconds = _timeout(timeout_seconds)

    def _run(self, arguments: tuple[str, ...], *, payload: bytes | None = None):
        try:
            result = self._runner(
                (self.executable, *arguments),
                payload=payload,
                timeout_seconds=self.timeout_seconds,
            )
        except (OSError, subprocess.SubprocessError):
            raise VaultUnavailable("secure credential vault unavailable") from None
        if not all(hasattr(result, field) for field in ("returncode", "stdout")):
            raise VaultUnavailable("secure credential vault unavailable")
        if not isinstance(result.stdout, bytes) or len(result.stdout) > MAX_COMMAND_OUTPUT_BYTES:
            raise VaultUnavailable("secure credential vault unavailable")
        return result


class KeychainVault(_CommandVault):
    """macOS Keychain credential vault, format v2 (chunked, header-committed).

    Measured ``/usr/bin/security`` limits (macOS 15.1): the prompted ``add-generic-password -w``
    keeps at most 128 bytes and needs the value twice (given once it stored an EMPTY item with
    exit 0); a ``security -i`` command line of more than 4095 bytes is cut, stores a truncated
    value and the rest runs as further commands; ``-i`` exits with the status of its LAST command
    only. A 16 KiB credential (21 848 base64 characters) therefore cannot be one item.

    v2 stores the base64 text in chunk items ``<handle>.0`` .. ``<handle>.<count-1>`` (3072
    characters each, the last 1..3072) and commits them with the header item ``<handle>`` =
    ``v2.<len>.<count>.<sha256 prefix>``, written LAST. Every item is one ``security -i``
    invocation holding one command line on stdin (never argv, never ``-U``); a duplicate (exit
    45) means another writer owns the slot and aborts the store without touching it. The tag
    only detects truncated, swapped or stale chunks; the Keychain ACL is the boundary.

    Items under the earlier v1 service (raw value) are only read and deleted, never written or
    migrated; an empty one (what every v1 store produced) fails closed.
    """

    backend_id = "macos_keychain"
    service = "heel.runner.canary.v2"
    legacy_service = "heel.runner.canary.v1"

    def __init__(self, **kwargs):
        super().__init__(
            executable_path=_MACOS_SECURITY,
            allowed_paths=frozenset({_MACOS_SECURITY}),
            required_platform="Darwin",
            **kwargs,
        )

    def _find(self, service: str, account: str, *, reveal: bool = False):
        suffix = ("-w",) if reveal else ()
        return self._run(("find-generic-password", "-s", service, "-a", account, *suffix))

    @staticmethod
    def _found(result) -> bool:
        if result.returncode == 0:
            return True
        if result.returncode == 44:
            return False
        raise VaultUnavailable("secure credential vault unavailable")

    def _remove(self, service: str, account: str) -> bool:
        try:
            return self._run(("delete-generic-password", "-s", service, "-a", account)).returncode in {0, 44}
        except VaultUnavailable:
            return False

    def exists(self, handle_id: str) -> bool:
        """A committed v2 header or a v1 item; chunks without a header are not a credential."""
        handle_id = _handle(handle_id)
        return (
            self._found(self._find(self.service, handle_id))
            or self._found(self._find(self.legacy_service, handle_id))
        )

    def load(self, handle_id: str) -> bytes:
        handle_id = _handle(handle_id)
        header = self._find(self.service, handle_id, reveal=True)
        if self._found(header):
            # Once a v2 header exists the legacy item is never consulted, even on failure.
            return self._load_v2(handle_id, header.stdout.removesuffix(b"\n"))
        legacy = self._find(self.legacy_service, handle_id, reveal=True)
        if not self._found(legacy):
            raise VaultUnavailable("secure credential was not found")
        value = legacy.stdout.removesuffix(b"\n")
        if not value:
            raise VaultUnavailable("secure credential is empty; remove it and add it again")
        return _secret(value)

    def _load_v2(self, handle_id: str, header: bytes) -> bytes:
        invalid = VaultUnavailable("secure credential vault returned invalid material")
        match = _KEYCHAIN_HEADER.fullmatch(header)
        if match is None:
            raise invalid
        length, count, tag = int(match.group(1)), int(match.group(2)), match.group(3).decode("ascii")
        encoded_length = _encoded_length(length)
        if length > MAX_SECRET_BYTES or count != _chunk_count(encoded_length):
            raise invalid
        encoded = bytearray()
        for index in range(count):
            expected = min(_KEYCHAIN_CHUNK_CHARS, encoded_length - index * _KEYCHAIN_CHUNK_CHARS)
            chunk = self._find(self.service, f"{handle_id}.{index}", reveal=True)
            if chunk.returncode != 0:
                raise invalid
            value = chunk.stdout.removesuffix(b"\n")
            if len(value) != expected:
                raise invalid
            encoded.extend(value)
        try:
            secret = base64.b64decode(bytes(encoded), validate=True)
        except ValueError:
            raise invalid from None
        if len(secret) != length or _keychain_tag(secret) != tag:
            raise invalid
        return _secret(secret)

    def store(self, handle_id: str, secret: bytes) -> None:
        handle_id = _handle(handle_id)
        secret = _secret(secret)
        encoded = base64.b64encode(secret)
        count = _chunk_count(len(encoded))
        if count > _KEYCHAIN_MAX_CHUNKS:
            raise SecretTooLargeError("secret exceeds the 16 KiB limit")
        items = [
            (f"{handle_id}.{index}", encoded[index * _KEYCHAIN_CHUNK_CHARS:(index + 1) * _KEYCHAIN_CHUNK_CHARS])
            for index in range(count)
        ]
        items.append((handle_id, f"v2.{len(secret)}.{count}.{_keychain_tag(secret)}".encode("ascii")))
        commands = [security_interactive_add_command(self.service, account, value) for account, value in items]
        if self.exists(handle_id):
            raise VaultUnavailable("secure credential already exists")
        created: list[str] = []
        try:
            for (account, _value), command in zip(items, commands):
                returncode = self._run(("-i",), payload=command).returncode
                if returncode == 45:
                    # Another writer owns this slot: never touch it, only what this call created.
                    raise VaultUnavailable("secure credential already exists")
                if returncode != 0:
                    raise VaultUnavailable("secure credential vault unavailable")
                created.append(account)
            # ``security -i`` exit 0 is not proof of the write: the header commit must read back.
            try:
                verified = self.load(handle_id) == secret
            except VaultUnavailable:
                verified = False
            if not verified:
                raise VaultUnavailable("secure credential vault unavailable")
        except VaultUnavailable as error:
            # Header (last created) first, so a partly removed credential is already unreadable.
            if not all([self._remove(self.service, account) for account in reversed(created)]):
                error.add_note("secure credential cleanup incomplete")
            raise

    def delete(self, handle_id: str) -> None:
        handle_id = _handle(handle_id)
        accounts = [(self.service, handle_id)]
        accounts += [(self.service, f"{handle_id}.{index}") for index in range(_KEYCHAIN_MAX_CHUNKS)]
        accounts.append((self.legacy_service, handle_id))
        # Header first makes the credential unreadable at once; every slot is still attempted.
        if not all([self._remove(service, account) for service, account in accounts]):
            raise VaultUnavailable("secure credential vault unavailable")


class SecretServiceVault(_CommandVault):
    backend_id = "linux_secret_service"

    def __init__(self, *, executable_path: str = "/usr/bin/secret-tool", **kwargs):
        super().__init__(
            executable_path=executable_path,
            allowed_paths=_LINUX_SECRET_TOOLS,
            required_platform="Linux",
            **kwargs,
        )

    def _lookup(self, handle_id: str):
        return self._run(("lookup", "heel", "canary", "handle", _handle(handle_id)))

    def exists(self, handle_id: str) -> bool:
        result = self._lookup(handle_id)
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        raise VaultUnavailable("secure credential vault unavailable")

    def load(self, handle_id: str) -> bytes:
        result = self._lookup(handle_id)
        if result.returncode == 1:
            raise VaultUnavailable("secure credential was not found")
        if result.returncode != 0:
            raise VaultUnavailable("secure credential vault unavailable")
        return _secret(result.stdout.removesuffix(b"\n"))

    def store(self, handle_id: str, secret: bytes) -> None:
        handle_id = _handle(handle_id)
        if self.exists(handle_id):
            raise VaultUnavailable("secure credential already exists")
        result = self._run((
            "store", "--label=Heel canary credential", "heel", "canary", "handle", handle_id,
        ), payload=_secret(secret))
        if result.returncode != 0:
            raise VaultUnavailable("secure credential vault unavailable")

    def delete(self, handle_id: str) -> None:
        result = self._run(("clear", "heel", "canary", "handle", _handle(handle_id)))
        if result.returncode not in {0, 1}:
            raise VaultUnavailable("secure credential vault unavailable")


def _closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate cookie jar key")
        result[key] = value
    return result


def validate_credential_secret(auth_profile: str, value: bytes, origin: str) -> bytes:
    secret = _secret(value)
    if auth_profile in {"bearer", "x_api_key"}:
        if any(byte < 0x21 or byte == 0x7F for byte in secret):
            raise ValueError("credential token contains invalid bytes")
        return secret
    if auth_profile != "cookie_jar":
        raise ValueError("invalid credential auth profile")
    try:
        decoded = json.loads(secret.decode("utf-8"), object_pairs_hook=_closed_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise ValueError("invalid closed cookie jar") from None
    if not isinstance(decoded, Mapping) or set(decoded) != {"schema_version", "cookies"}:
        raise ValueError("invalid closed cookie jar")
    if decoded["schema_version"] != "heel.cookie-jar.v1":
        raise ValueError("invalid closed cookie jar")
    cookies = decoded["cookies"]
    if not isinstance(cookies, list) or not 1 <= len(cookies) <= 20:
        raise ValueError("invalid closed cookie jar")
    names: set[str] = set()
    for cookie in cookies:
        if not isinstance(cookie, Mapping) or set(cookie) != {
            "name", "value", "path", "secure", "http_only", "same_site",
        }:
            raise ValueError("invalid closed cookie jar")
        name, cookie_value = cookie["name"], cookie["value"]
        if (
            type(name) is not str or not name or len(name.encode()) > 128
            or type(cookie_value) is not str or not cookie_value or len(cookie_value.encode()) > 4096
            or name in names or any(ord(char) < 0x21 or ord(char) == 0x7F for char in name + cookie_value)
            or cookie["path"] != "/" or cookie["secure"] is not True
            or cookie["http_only"] is not True or cookie["same_site"] not in {"strict", "lax"}
        ):
            raise ValueError("invalid closed cookie jar")
        names.add(name)
    if type(origin) is not str or not origin.startswith("https://"):
        raise ValueError("invalid closed cookie jar origin")
    return json.dumps(
        decoded, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def select_vault(
    kind: str,
    *,
    handle_id: str | None = None,
    source_kind: str | None = None,
    runner: Callable[..., Any] = _run_bounded_process,
):
    if kind in {"ephemeral-env", "ephemeral_env"}:
        if handle_id is None:
            raise ValueError("credential handle is required")
        return EphemeralVault(handle_id, source_kind=source_kind or "environment")
    if kind in {"ephemeral-fd", "ephemeral_fd"}:
        if handle_id is None:
            raise ValueError("credential handle is required")
        return EphemeralVault(handle_id, source_kind=source_kind or "inherited_fd")
    if kind in {"keychain", "macos_keychain"}:
        return KeychainVault(runner=runner)
    if kind in {"secret-service", "linux_secret_service"}:
        return SecretServiceVault(runner=runner)
    if kind == "unavailable":
        return UnavailableVault()
    raise ValueError("unsupported secure credential vault")
