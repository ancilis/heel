"""Runner-local identity primitives.

Private material intentionally stays behind :class:`SecureSigner`; this module only
ever moves a public key and signatures across the runner/control-plane boundary.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Callable, Sequence

from heel.crypto import ed25519_key_id


RUNNER_CAPABILITIES = (
    "runner_claim", "runner_heartbeat", "runner_progress", "runner_result",
)


class SecureSigner:
    """Minimal key-store interface; implementations must not expose a private seed."""

    # Attributes (rather than abstract @properties) keep key-store test doubles simple while
    # still documenting the deliberately tiny interface.
    key_id: str
    public_key: bytes

    def sign(self, payload: bytes) -> bytes:
        raise NotImplementedError


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
