"""Runner-local identity primitives.

Private material intentionally stays behind :class:`SecureSigner`; this module only
ever moves a public key and signatures across the runner/control-plane boundary.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import subprocess
from dataclasses import dataclass
from typing import Callable, Protocol, Sequence

from heel.crypto import ed25519_key_id


RUNNER_CAPABILITIES = (
    "runner_claim", "runner_heartbeat", "runner_progress", "runner_result",
)


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


class MacOSKeychainSecretBackend(_CommandSecretBackend):
    """macOS Keychain adapter. Errors intentionally look like key-store failure, never data."""

    service = "heel.runner.ed25519.v1"

    def load(self, label: str) -> bytes | None:
        label = self._label(label)
        result = self._command(["security", "find-generic-password", "-s", self.service,
                                "-a", label, "-w"], capture_output=True, check=False)
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
        encoded = base64.b64encode(seed).decode("ascii")
        result = self._command(["security", "add-generic-password", "-U", "-s", self.service,
                                "-a", label, "-w", encoded], capture_output=True, check=False)
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
