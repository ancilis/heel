"""Closed adapters for runner-local canary credentials.

There is intentionally no plaintext implementation and no automatic fallback. OS
commands receive secrets on stdin, never in argv, and ephemeral sources are one-shot.
"""
from __future__ import annotations

import os
import re
import select
import subprocess
import time
from typing import Any, Callable


MAX_SECRET_BYTES = 16 * 1024
MAX_COMMAND_OUTPUT_BYTES = 4 * 1024
_HANDLE = re.compile(r"^[0-9a-f]{32}$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")


class SecretTooLargeError(ValueError):
    """A secret exceeded the fixed local credential ceiling."""


class VaultUnavailable(RuntimeError):
    """The selected secure credential provider cannot complete the operation."""


class UnavailableVault:
    supported = False

    def load(self, handle_id: str) -> bytes:
        del handle_id
        raise VaultUnavailable("secure credential vault unavailable")

    def store(self, handle_id: str, secret: bytes) -> None:
        del handle_id, secret
        raise VaultUnavailable("secure credential vault unavailable")


def _handle(value: object) -> str:
    if type(value) is not str or _HANDLE.fullmatch(value) is None:
        raise ValueError("credential handle ID must be 32 lowercase hex characters")
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


def _bounded_result(result: object) -> subprocess.CompletedProcess:
    if not isinstance(result, subprocess.CompletedProcess):
        # Scripted CompletedProcess-like test adapters remain acceptable, but only with
        # the exact bounded attributes used below.
        if not all(hasattr(result, field) for field in ("returncode", "stdout", "stderr")):
            raise VaultUnavailable("secure credential command failed")
    stdout = getattr(result, "stdout", b"")
    stderr = getattr(result, "stderr", b"")
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise VaultUnavailable("secure credential command returned invalid output")
    if len(stdout) > MAX_COMMAND_OUTPUT_BYTES or len(stderr) > MAX_COMMAND_OUTPUT_BYTES:
        raise VaultUnavailable("secure credential command output was not bounded")
    return result  # type: ignore[return-value]


class EphemeralVault:
    """Resolve exactly one environment or inherited-FD secret without persistence."""

    supported = True

    def __init__(
        self,
        *,
        env_name: str | None = None,
        fd: int | None = None,
        timeout_seconds: float = 2,
    ):
        if (env_name is None) == (fd is None):
            raise ValueError("ephemeral vault requires exactly one environment name or inherited FD")
        self.timeout_seconds = _timeout(timeout_seconds)
        if env_name is not None:
            if type(env_name) is not str or _ENVIRONMENT_NAME.fullmatch(env_name) is None:
                raise ValueError("invalid ephemeral environment variable name")
        if fd is not None:
            if isinstance(fd, bool) or not isinstance(fd, int) or fd < 3:
                raise ValueError("ephemeral secret FD must be an inherited descriptor")
            try:
                inherited = os.get_inheritable(fd)
                os.fstat(fd)
            except OSError:
                raise ValueError("ephemeral secret FD must be an inherited descriptor") from None
            if not inherited:
                raise ValueError("ephemeral secret FD must be inherited")
        self.env_name = env_name
        self.fd = fd

    def load(self, handle_id: str) -> bytes:
        _handle(handle_id)
        if self.env_name is not None:
            value = os.environ.pop(self.env_name, None)
            if value is None:
                raise VaultUnavailable("ephemeral environment secret is unavailable")
            try:
                return _secret(value.encode("utf-8"))
            finally:
                # ``pop`` above removes the inherited environment copy as early as
                # Python can; replacing ``value`` avoids retaining it on this object.
                value = ""

        assert self.fd is not None
        duplicate = os.dup(self.fd)
        try:
            os.set_inheritable(duplicate, False)
            deadline = time.monotonic() + self.timeout_seconds
            chunks: list[bytes] = []
            total = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise VaultUnavailable("ephemeral secret FD timed out")
                ready, _, _ = select.select([duplicate], [], [], remaining)
                if not ready:
                    raise VaultUnavailable("ephemeral secret FD timed out")
                chunk = os.read(duplicate, min(4096, MAX_SECRET_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_SECRET_BYTES:
                    raise SecretTooLargeError("secret exceeds the 16 KiB limit")
            return _secret(b"".join(chunks))
        finally:
            os.close(duplicate)

    def store(self, handle_id: str, secret: bytes) -> None:
        _handle(handle_id)
        _secret(secret)
        raise VaultUnavailable("ephemeral vault never persists secrets")


class _CommandVault:
    supported = True

    def __init__(
        self,
        *,
        command: Callable[..., Any] = subprocess.run,
        timeout_seconds: float = 2,
    ):
        self._command = command
        self.timeout_seconds = _timeout(timeout_seconds)

    def _run(self, argv: tuple[str, ...], *, secret: bytes | None = None):
        kwargs = {
            "capture_output": True,
            "check": False,
            "shell": False,
            "timeout": self.timeout_seconds,
        }
        if secret is not None:
            kwargs = {"input": _secret(secret), **kwargs}
        try:
            result = self._command(argv, **kwargs)
        except (OSError, subprocess.SubprocessError):
            raise VaultUnavailable("secure credential vault unavailable") from None
        return _bounded_result(result)


class KeychainVault(_CommandVault):
    service = "heel.runner.canary.v1"

    def _lookup(self, handle_id: str):
        return self._run((
            "security", "find-generic-password", "-s", self.service,
            "-a", _handle(handle_id),
        ))

    def load(self, handle_id: str) -> bytes:
        result = self._run((
            "security", "find-generic-password", "-s", self.service,
            "-a", _handle(handle_id), "-w",
        ))
        if result.returncode == 44:
            raise VaultUnavailable("secure credential was not found")
        if result.returncode != 0:
            raise VaultUnavailable("secure credential vault unavailable")
        return _secret(result.stdout.removesuffix(b"\n"))

    def store(self, handle_id: str, secret: bytes) -> None:
        handle_id = _handle(handle_id)
        existing = self._lookup(handle_id)
        if existing.returncode == 0:
            raise VaultUnavailable("secure credential already exists")
        if existing.returncode != 44:
            raise VaultUnavailable("secure credential vault unavailable")
        created = self._run((
            "security", "add-generic-password", "-s", self.service,
            "-a", handle_id, "-w",
        ), secret=secret)
        if created.returncode != 0:
            raise VaultUnavailable("secure credential vault unavailable")


class SecretServiceVault(_CommandVault):
    def _lookup(self, handle_id: str):
        return self._run((
            "secret-tool", "lookup", "heel", "canary", "handle", _handle(handle_id),
        ))

    def load(self, handle_id: str) -> bytes:
        result = self._lookup(handle_id)
        if result.returncode == 1:
            raise VaultUnavailable("secure credential was not found")
        if result.returncode != 0:
            raise VaultUnavailable("secure credential vault unavailable")
        return _secret(result.stdout.removesuffix(b"\n"))

    def store(self, handle_id: str, secret: bytes) -> None:
        handle_id = _handle(handle_id)
        existing = self._lookup(handle_id)
        if existing.returncode == 0:
            raise VaultUnavailable("secure credential already exists")
        if existing.returncode != 1:
            raise VaultUnavailable("secure credential vault unavailable")
        created = self._run((
            "secret-tool", "store", "--label=Heel canary credential",
            "heel", "canary", "handle", handle_id,
        ), secret=secret)
        if created.returncode != 0:
            raise VaultUnavailable("secure credential vault unavailable")


def select_vault(
    kind: str,
    *,
    env_name: str | None = None,
    fd: int | None = None,
    command: Callable[..., Any] = subprocess.run,
):
    if kind == "ephemeral-env":
        return EphemeralVault(env_name=env_name)
    if kind == "ephemeral-fd":
        return EphemeralVault(fd=fd)
    if kind == "keychain":
        return KeychainVault(command=command)
    if kind == "secret-service":
        return SecretServiceVault(command=command)
    if kind == "unavailable":
        return UnavailableVault()
    raise ValueError("unsupported secure credential vault")
