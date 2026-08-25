import hashlib

import pytest

from heel.crypto import ed25519_key_id
from heel.runner.identity import (
    InMemorySecretBackend,
    SecureSigner,
    SystemSecureSigner,
    create_runner_identity,
    runner_phrase_words,
    validate_pairing_phrase,
)


WORDS = [f"word{i:04d}" for i in range(2048)]


class FakeRandom:
    def __init__(self, seed):
        self.state = seed.to_bytes(32, "big")

    def bytes(self, count):
        import hashlib

        output = bytearray()
        counter = 0
        while len(output) < count:
            output.extend(hashlib.sha256(self.state + counter.to_bytes(4, "big")).digest())
            counter += 1
        self.state = hashlib.sha256(bytes(output)).digest()
        return bytes(output[:count])


class FakeSecureSigner(SecureSigner):
    def __init__(self, key_id="k_fake", public_key=b"0123456789abcdef0123456789abcdef"):
        self.key_id = key_id
        self.public_key = public_key
        self.payloads = []

    def sign(self, payload):
        self.payloads.append(payload)
        return b"\x11" * 64


def test_identity_uses_exact_public_formats_and_capabilities():
    signer = FakeSecureSigner(key_id=ed25519_key_id(FakeSecureSigner().public_key))
    identity = create_runner_identity(
        runner_id="runner-1", workspace_id="workspace-1",
        runner_version="runner-v1", adapter_versions={"adapter": "1.2.3"},
        signer=signer, words=WORDS, random_source=FakeRandom(7).bytes,
    )
    assert identity.public_key_b64 == "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    assert identity.fingerprint == hashlib.sha256(signer.public_key).hexdigest()
    assert len(identity.fingerprint) == 64 and identity.fingerprint == identity.fingerprint.lower()
    assert identity.key_id == ed25519_key_id(signer.public_key)
    assert identity.capabilities == (
        "runner_claim", "runner_heartbeat", "runner_progress", "runner_result"
    )
    assert identity.adapter_versions == {"adapter": "1.2.3"}


def test_identity_phrase_is_cryptographically_indexed_and_validated():
    signer = FakeSecureSigner(key_id=ed25519_key_id(b"0123456789abcdef0123456789abcdef"))
    entropy = bytes(range(32))
    identity = create_runner_identity(
        runner_id="r", workspace_id="w", runner_version="v",
        adapter_versions={}, signer=signer, words=WORDS,
        random_source=lambda count: entropy[:count],
    )
    indices = [int.from_bytes(entropy[i * 2:i * 2 + 2], "big") % 2048 for i in range(6)]
    assert identity.pairing_phrase == tuple(WORDS[index] for index in indices)
    assert not any(word in str(identity) for word in WORDS)

    with pytest.raises(ValueError, match="exactly 2048"):
        create_runner_identity("r", "w", "v", {}, signer, WORDS[:-1], lambda n: b"\0" * n)
    duplicate = list(WORDS)
    duplicate[1] = duplicate[0]
    with pytest.raises(ValueError, match="unique"):
        create_runner_identity("r", "w", "v", {}, signer, duplicate, lambda n: b"\0" * n)


def test_public_phrase_vocabulary_is_exact_and_runner_auth_can_share_it():
    words = runner_phrase_words()
    assert len(words) == 2048 and len(set(words)) == 2048
    phrase = " ".join(words[:6])
    assert validate_pairing_phrase(phrase) == phrase
    with pytest.raises(ValueError, match="pairing phrase"):
        validate_pairing_phrase("not a valid pairing phrase")


def test_system_secure_signer_persists_only_behind_explicit_secret_backend():
    backend = InMemorySecretBackend()
    first = SystemSecureSigner("heel-test-runner", backend=backend)
    second = SystemSecureSigner("heel-test-runner", backend=backend)
    assert first.key_id == second.key_id
    assert first.public_key == second.public_key
    assert first.sign(b"control") == second.sign(b"control")
    assert "seed" not in repr(first).lower()
