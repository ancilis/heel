"""Runner-local identity primitives.

Private material intentionally stays behind :class:`SecureSigner`; this module only
ever moves a public key and signatures across the runner/control-plane boundary.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import stat
import subprocess
import threading
import unicodedata
from dataclasses import dataclass
from typing import Callable, Protocol, Sequence

from heel.crypto import ed25519_key_id


RUNNER_CAPABILITIES = (
    "runner_claim", "runner_heartbeat", "runner_progress", "runner_result",
)
_MACOS_SECURITY_PATH = "/usr/bin/security"
_KEYCHAIN_TIMEOUT_SECONDS = 5
_MAX_KEYCHAIN_OUTPUT_BYTES = 1024


def _phrase_words() -> tuple[str, ...]:
    """Return Heel's stable public 2,048-word pairing vocabulary.

    This is intentionally generated rather than read from a private server module: a local
    runner must be able to validate the phrase it displays without receiving any cloud secret.
    """
    onset = ("b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t", "v",
             "w", "z", "br", "cl", "dr", "fr", "gr", "kr", "pl", "pr", "sk", "sl", "st", "tr", "vr", "zl")
    vowel = ("a", "e", "i", "o", "u", "ae", "ai", "ao", "ea", "ei", "ia", "io", "oa", "oi", "ua", "ui")
    tail = ("n", "r", "l", "m")
    return tuple(a + b + c for a in onset for b in vowel for c in tail)


_RUNNER_PHRASE_WORDS = _phrase_words()


def runner_phrase_words() -> tuple[str, ...]:
    """The immutable public vocabulary used by every pairing surface."""
    return _RUNNER_PHRASE_WORDS


def validate_pairing_phrase(value: object) -> str:
    if type(value) is not str or value != value.lower() or value != " ".join(value.split()):
        raise ValueError("invalid pairing phrase")
    words = value.split(" ")
    if len(words) != 6 or any(word not in _RUNNER_PHRASE_WORDS for word in words):
        raise ValueError("invalid pairing phrase")
    return value


class SecureSigner:
    """Minimal key-store interface; implementations must not expose a private seed."""

    # Attributes (rather than abstract @properties) keep key-store test doubles simple while
    # still documenting the deliberately tiny interface.
    key_id: str
    public_key: bytes

    def sign(self, payload: bytes) -> bytes:
        raise NotImplementedError


class OSSecretBackend(Protocol):
    """Private key seed storage boundary. It deliberately has no list/export operation."""

    def load(self, label: str) -> bytes | None: ...
    def store(self, label: str, seed: bytes) -> None: ...


class InMemorySecretBackend:
    """Explicit test-only backend; production callers must inject an OS-backed implementation."""

    def __init__(self):
        self._values: dict[str, bytes] = {}

    def load(self, label: str) -> bytes | None:
        value = self._values.get(label)
        return None if value is None else bytes(value)

    def store(self, label: str, seed: bytes) -> None:
        if label in self._values:
            raise ValueError("runner signing identity already exists")
        self._values[label] = bytes(seed)


class _CommandSecretBackend:
    """Narrow subprocess adapter shared by macOS Keychain and Linux Secret Service."""

    def __init__(self, *, command: Callable[..., subprocess.CompletedProcess] = subprocess.run):
        self._command = command

    @staticmethod
    def _label(label: str) -> str:
        if type(label) is not str or not label or len(label) > 128 or "\x00" in label:
            raise ValueError("invalid runner signing label")
        return label


def _verified_security_path() -> str:
    """Return the one fixed macOS helper only when it is a regular executable."""
    path = _MACOS_SECURITY_PATH
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise RuntimeError("runner OS secret service unavailable")
    try:
        status = os.stat(path, follow_symlinks=False)
    except OSError:
        raise RuntimeError("runner OS secret service unavailable") from None
    if not stat.S_ISREG(status.st_mode) or not os.access(path, os.X_OK):
        raise RuntimeError("runner OS secret service unavailable")
    return path


def _run_bounded_security(
    arguments: tuple[str, ...], *, payload: bytes | None, popen: Callable[..., object],
) -> subprocess.CompletedProcess:
    """Run macOS Keychain with bounded capture and secret input isolated to stdin."""
    argv = (_verified_security_path(), *arguments)
    try:
        process = popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            bufsize=0,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        process_stdin = process.stdin
        process_stdout = process.stdout
    except (AttributeError, OSError, TypeError, ValueError):
        raise RuntimeError("runner OS secret service unavailable") from None
    if process_stdin is None or process_stdout is None:
        try:
            process.kill()
            process.wait()
        except (AttributeError, OSError, subprocess.SubprocessError):
            pass
        raise RuntimeError("runner OS secret service unavailable")

    retained = bytearray()
    worker_failed = threading.Event()

    def write_input() -> None:
        try:
            if payload is not None:
                process_stdin.write(payload)
                process_stdin.flush()
        except (BrokenPipeError, OSError, TypeError, ValueError):
            worker_failed.set()
        finally:
            try:
                process_stdin.close()
            except (OSError, ValueError):
                pass

    def read_output() -> None:
        try:
            while True:
                chunk = process_stdout.read(4096)
                if not chunk:
                    return
                remaining = _MAX_KEYCHAIN_OUTPUT_BYTES + 1 - len(retained)
                if remaining > 0:
                    retained.extend(chunk[:remaining])
        except (OSError, TypeError, ValueError):
            worker_failed.set()

    writer = threading.Thread(target=write_input, daemon=True)
    reader = threading.Thread(target=read_output, daemon=True)
    writer.start()
    reader.start()
    try:
        returncode = process.wait(timeout=_KEYCHAIN_TIMEOUT_SECONDS)
    except (OSError, TypeError, ValueError, subprocess.SubprocessError):
        try:
            process.kill()
            process.wait()
        except (AttributeError, OSError, subprocess.SubprocessError):
            pass
        raise RuntimeError("runner OS secret service unavailable") from None
    finally:
        writer.join(1)
        reader.join(1)
        try:
            process_stdout.close()
        except (OSError, ValueError):
            pass
    if writer.is_alive() or reader.is_alive() or worker_failed.is_set():
        try:
            process.kill()
            process.wait()
        except (AttributeError, OSError, subprocess.SubprocessError):
            pass
        raise RuntimeError("runner OS secret service unavailable")
    return subprocess.CompletedProcess(argv, returncode, bytes(retained), None)


class MacOSKeychainSecretBackend:
    """macOS Keychain adapter. Errors intentionally look like key-store failure, never data."""

    service = "heel.runner.ed25519.v1"

    def __init__(self, *, popen: Callable[..., object] = subprocess.Popen):
        self._popen = popen

    @staticmethod
    def _label(label: str) -> str:
        return _CommandSecretBackend._label(label)

    def load(self, label: str) -> bytes | None:
        label = self._label(label)
        result = _run_bounded_security(
            ("find-generic-password", "-s", self.service, "-a", label, "-w"),
            payload=None,
            popen=self._popen,
        )
        if result.returncode == 44:
            return None
        if result.returncode != 0:
            raise RuntimeError("runner OS secret service unavailable")
        try:
            seed = base64.b64decode(result.stdout.strip(), validate=True)
        except (TypeError, ValueError):
            raise RuntimeError("runner OS secret service returned invalid material") from None
        return seed

    def store(self, label: str, seed: bytes) -> None:
        label = self._label(label)
        if not isinstance(seed, bytes) or len(seed) != 32:
            raise RuntimeError("runner OS secret service returned invalid material")
        encoded = base64.b64encode(seed)
        result = _run_bounded_security(
            ("add-generic-password", "-U", "-s", self.service, "-a", label, "-w"),
            payload=encoded,
            popen=self._popen,
        )
        if result.returncode != 0:
            raise RuntimeError("runner OS secret service unavailable")


class LinuxSecretServiceBackend(_CommandSecretBackend):
    """Freedesktop Secret Service adapter via ``secret-tool`` (no filesystem fallback)."""

    def load(self, label: str) -> bytes | None:
        label = self._label(label)
        result = self._command(["secret-tool", "lookup", "heel", "runner", "label", label],
                               capture_output=True, check=False)
        if result.returncode == 1:
            return None
        if result.returncode != 0:
            raise RuntimeError("runner OS secret service unavailable")
        try:
            return base64.b64decode(result.stdout.strip(), validate=True)
        except (TypeError, ValueError):
            raise RuntimeError("runner OS secret service returned invalid material") from None

    def store(self, label: str, seed: bytes) -> None:
        label = self._label(label)
        result = self._command(["secret-tool", "store", "--label=Heel runner signing key",
                                "heel", "runner", "label", label], input=base64.b64encode(seed),
                               capture_output=True, check=False)
        if result.returncode != 0:
            raise RuntimeError("runner OS secret service unavailable")


class SystemSecureSigner(SecureSigner):
    """Ed25519 signer whose seed is generated and kept in an injected OS secret backend."""

    def __init__(self, label: str, *, backend: OSSecretBackend | None = None):
        if backend is None:
            if os.name == "posix" and __import__("platform").system() == "Darwin":
                backend = MacOSKeychainSecretBackend()
            elif os.name == "posix":
                backend = LinuxSecretServiceBackend()
            else:
                raise RuntimeError("no supported runner OS secret service")
        if isinstance(backend, InMemorySecretBackend) and os.environ.get("PYTEST_CURRENT_TEST") is None:
            raise RuntimeError("in-memory runner secret backend is test-only")
        if type(label) is not str or not label or len(label) > 128 or "\x00" in label:
            raise ValueError("invalid runner signing label")
        seed = backend.load(label)
        if seed is None:
            seed = secrets.token_bytes(32)
            backend.store(label, seed)
        if not isinstance(seed, bytes) or len(seed) != 32:
            raise RuntimeError("runner OS secret service returned invalid material")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        self._private = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = ed25519_key_id(self.public_key)

    def sign(self, payload: bytes) -> bytes:
        if not isinstance(payload, bytes):
            raise TypeError("runner signing payload must be bytes")
        return self._private.sign(payload)

    def __repr__(self) -> str:
        return f"SystemSecureSigner(key_id={self.key_id!r})"


@dataclass(frozen=True, repr=False)
class RunnerIdentity:
    runner_id: str
    workspace_id: str
    runner_version: str
    adapter_versions: dict[str, str]
    public_key_b64: str
    fingerprint: str
    key_id: str
    pairing_phrase: tuple[str, ...]
    capabilities: tuple[str, ...] = RUNNER_CAPABILITIES

    def __repr__(self) -> str:
        return (
            "RunnerIdentity(runner_id={!r}, workspace_id={!r}, key_id={!r}, "
            "fingerprint={!r})"
        ).format(self.runner_id, self.workspace_id, self.key_id, self.fingerprint)


@dataclass(frozen=True, repr=False)
class RunnerPairingMaterial:
    """Public pairing payload prepared before the cloud allocates a runner ID.

    The signer remains an opaque local capability; callers can display and send the
    public fields, but cannot derive or export its private material.
    """

    display_name: str
    runner_version: str
    adapters: dict[str, str]
    public_key_b64: str
    fingerprint: str
    key_id: str
    pairing_phrase: tuple[str, ...]
    _signer: SecureSigner

    def exchange_request(self, invitation_token: str) -> dict[str, object]:
        if type(invitation_token) is not str or not invitation_token:
            raise ValueError("invitation token is required")
        return {
            "schema_version": "heel.runner-pairing-exchange.v2",
            "invitation_token": invitation_token,
            "public_key_b64": self.public_key_b64,
            "pairing_phrase": " ".join(self.pairing_phrase),
            "display_name": self.display_name,
            "runner_version": self.runner_version,
            "adapters": dict(self.adapters),
        }


def _display_name(value: object) -> str:
    if type(value) is not str:
        raise ValueError("runner display name is required")
    normalized = unicodedata.normalize("NFC", value)
    if (not 1 <= len(normalized) <= 64 or len(normalized.encode("utf-8")) > 128
            or normalized != normalized.strip()
            or any(unicodedata.category(char) == "Cc" or 0xD800 <= ord(char) <= 0xDFFF
                   for char in normalized)):
        raise ValueError("invalid runner display name")
    return normalized


def create_runner_pairing_material(
    display_name: str,
    runner_version: str,
    adapters: dict[str, str],
    signer: SecureSigner,
    *,
    words: Sequence[str] | None = None,
    random_source: Callable[[int], bytes] = secrets.token_bytes,
) -> RunnerPairingMaterial:
    """Prepare v2 exchange material before the control plane allocates ``runner_id``."""
    display_name = _display_name(display_name)
    if type(runner_version) is not str or not runner_version:
        raise ValueError("runner version is required")
    if not isinstance(adapters, dict) or not all(type(k) is str and k and type(v) is str and v
                                                 for k, v in adapters.items()):
        raise ValueError("adapters must be a string map")
    vocabulary = _validate_words(runner_phrase_words() if words is None else words)
    public_key = signer.public_key
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("runner signer must expose a 32-byte Ed25519 public key")
    key_id = ed25519_key_id(public_key)
    if signer.key_id != key_id:
        raise ValueError("runner signer key ID does not match its public key")
    entropy = random_source(12)
    if not isinstance(entropy, bytes) or len(entropy) != 12:
        raise ValueError("runner random source must return exactly requested bytes")
    phrase = tuple(vocabulary[int.from_bytes(entropy[index:index + 2], "big") % 2048]
                   for index in range(0, 12, 2))
    return RunnerPairingMaterial(
        display_name=display_name, runner_version=runner_version, adapters=dict(sorted(adapters.items())),
        public_key_b64=base64.b64encode(public_key).decode("ascii"),
        fingerprint=hashlib.sha256(public_key).hexdigest(), key_id=key_id,
        pairing_phrase=phrase, _signer=signer,
    )


def bind_runner_identity(material: RunnerPairingMaterial, *, workspace_id: str, runner_id: str) -> RunnerIdentity:
    """Bind server-issued identity coordinates only after successful activation."""
    if not isinstance(material, RunnerPairingMaterial):
        raise ValueError("runner pairing material is required")
    if not all(type(item) is str and item for item in (workspace_id, runner_id)):
        raise ValueError("runner identity fields must be non-empty strings")
    return RunnerIdentity(
        runner_id=runner_id, workspace_id=workspace_id, runner_version=material.runner_version,
        adapter_versions=dict(material.adapters), public_key_b64=material.public_key_b64,
        fingerprint=material.fingerprint, key_id=material.key_id,
        pairing_phrase=material.pairing_phrase,
    )


def _validate_words(words: Sequence[str]) -> tuple[str, ...]:
    values = tuple(words)
    if len(values) != 2048:
        raise ValueError("runner phrase word list must contain exactly 2048 words")
    if len(set(values)) != len(values):
        raise ValueError("runner phrase word list must contain unique words")
    if any(type(word) is not str or not word or word != word.lower() or " " in word for word in values):
        raise ValueError("runner phrase words must be lowercase non-empty atoms")
    return values


def create_runner_identity(
    runner_id: str,
    workspace_id: str,
    runner_version: str,
    adapter_versions: dict[str, str],
    signer: SecureSigner,
    words: Sequence[str],
    random_source: Callable[[int], bytes],
) -> RunnerIdentity:
    """Create public pairing material and a six-word (66-bit) human comparison cue."""
    if not all(type(item) is str and item for item in (runner_id, workspace_id, runner_version)):
        raise ValueError("runner identity fields must be non-empty strings")
    if not isinstance(adapter_versions, dict) or not all(
        type(key) is str and type(value) is str for key, value in adapter_versions.items()
    ):
        raise ValueError("adapter versions must be a string map")
    vocabulary = _validate_words(words)
    public_key = signer.public_key
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("runner signer must expose a 32-byte Ed25519 public key")
    key_id = ed25519_key_id(public_key)
    if signer.key_id != key_id:
        raise ValueError("runner signer key ID does not match its public key")
    entropy = random_source(12)
    if not isinstance(entropy, bytes) or len(entropy) != 12:
        raise ValueError("runner random source must return exactly requested bytes")
    phrase = tuple(vocabulary[int.from_bytes(entropy[index:index + 2], "big") % 2048]
                   for index in range(0, 12, 2))
    return RunnerIdentity(
        runner_id=runner_id,
        workspace_id=workspace_id,
        runner_version=runner_version,
        adapter_versions=dict(adapter_versions),
        public_key_b64=base64.b64encode(public_key).decode("ascii"),
        fingerprint=hashlib.sha256(public_key).hexdigest(),
        key_id=key_id,
        pairing_phrase=phrase,
    )
