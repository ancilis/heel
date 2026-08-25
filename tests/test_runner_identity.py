import base64
import hashlib
import io
import subprocess

import pytest

from heel.crypto import ed25519_key_id
from heel.runner.identity import (
    InMemorySecretBackend,
    LinuxSecretServiceBackend,
    MacOSKeychainSecretBackend,
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


class _InputRecorder:
    def __init__(self): self.data = bytearray(); self.closed = False
    def write(self, value): self.data.extend(value); return len(value)
    def flush(self): return None
    def close(self): self.closed = True


class _FakeProcess:
    def __init__(self, argv, *, returncode, stdout):
        self.argv = tuple(argv)
        self.returncode = returncode
        self.stdin = _InputRecorder()
        self.stdout = io.BytesIO(stdout)
        self.wait_timeouts = []
        self.killed = False

    def wait(self, timeout=None):
        self.wait_timeouts.append(timeout)
        return self.returncode

    def kill(self): self.killed = True


def test_macos_first_create_never_places_ed25519_seed_in_process_argv(monkeypatch):
    expected_seed = b"k" * 32
    encoded_seed = base64.b64encode(expected_seed)
    calls = []

    def popen(argv, **kwargs):
        process = _FakeProcess(
            argv, returncode=44 if argv[1] == "find-generic-password" else 0,
            stdout=b"",
        )
        calls.append((tuple(argv), kwargs, process))
        return process

    monkeypatch.setattr("heel.runner.identity._verified_security_path",
                        lambda: "/usr/bin/security")
    monkeypatch.setattr("heel.runner.identity.secrets.token_bytes", lambda count: expected_seed)
    signer = SystemSecureSigner(
        "runner-one", backend=MacOSKeychainSecretBackend(popen=popen),
    )
    assert signer.public_key and encoded_seed not in repr(signer).encode()
    assert len(calls) == 2
    for argv, kwargs, process in calls:
        assert argv[0] == "/usr/bin/security" and argv[-1] == "-w"
        assert encoded_seed.decode() not in argv
        assert kwargs == {
            "stdin": subprocess.PIPE, "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL, "shell": False, "bufsize": 0,
            "env": {"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        }
        assert process.wait_timeouts == [5]
    assert bytes(calls[0][2].stdin.data) == b""
    assert bytes(calls[1][2].stdin.data) == encoded_seed


def test_macos_load_is_bounded_and_never_exposes_helper_output(monkeypatch):
    secret_marker = b"private-helper-output"
    calls = []

    def popen(argv, **kwargs):
        process = _FakeProcess(argv, returncode=0, stdout=secret_marker * 100)
        calls.append((tuple(argv), kwargs, process))
        return process

    monkeypatch.setattr("heel.runner.identity._verified_security_path",
                        lambda: "/usr/bin/security")
    backend = MacOSKeychainSecretBackend(popen=popen)
    with pytest.raises(RuntimeError, match="invalid material") as caught:
        backend.load("runner-one")
    assert calls[0][0] == (
        "/usr/bin/security", "find-generic-password", "-s",
        "heel.runner.ed25519.v1", "-a", "runner-one", "-w",
    )
    assert secret_marker.decode() not in str(caught.value)


def test_macos_first_create_never_overwrites_a_racing_keychain_account(monkeypatch):
    generated_seed = b"n" * 32
    existing_seed = b"e" * 32
    persisted = bytearray(existing_seed)
    calls = []

    def popen(argv, **kwargs):
        if argv[1] == "find-generic-password":
            process = _FakeProcess(argv, returncode=44, stdout=b"")
        else:
            if "-U" in argv:
                persisted[:] = generated_seed
                process = _FakeProcess(argv, returncode=0, stdout=b"")
            else:
                process = _FakeProcess(argv, returncode=45, stdout=b"")
        calls.append((tuple(argv), kwargs, process))
        return process

    monkeypatch.setattr("heel.runner.identity._verified_security_path",
                        lambda: "/usr/bin/security")
    monkeypatch.setattr("heel.runner.identity.secrets.token_bytes", lambda count: generated_seed)

    with pytest.raises(RuntimeError, match="runner OS secret service unavailable") as caught:
        SystemSecureSigner("runner-race", backend=MacOSKeychainSecretBackend(popen=popen))

    store_argv, _, store_process = calls[1]
    assert store_argv == (
        "/usr/bin/security", "add-generic-password", "-s",
        "heel.runner.ed25519.v1", "-a", "runner-race", "-w",
    )
    assert bytes(store_process.stdin.data) == base64.b64encode(generated_seed)
    assert bytes(persisted) == existing_seed
    assert base64.b64encode(generated_seed).decode() not in str(caught.value)


def test_linux_first_create_uses_only_verified_helper_and_stdin_for_seed(monkeypatch):
    expected_seed = b"l" * 32
    encoded_seed = base64.b64encode(expected_seed)
    calls = []

    def popen(argv, **kwargs):
        process = _FakeProcess(
            argv, returncode=1 if argv[1] == "lookup" else 0, stdout=b"",
        )
        calls.append((tuple(argv), kwargs, process))
        return process

    monkeypatch.setattr("heel.runner.identity._verified_secret_tool_path",
                        lambda: "/usr/bin/secret-tool")
    monkeypatch.setattr("heel.runner.identity.secrets.token_bytes", lambda count: expected_seed)
    signer = SystemSecureSigner(
        "runner-linux", backend=LinuxSecretServiceBackend(popen=popen),
    )

    assert signer.public_key and encoded_seed not in repr(signer).encode()
    assert [call[0] for call in calls] == [
        ("/usr/bin/secret-tool", "lookup", "heel", "runner", "label", "runner-linux"),
        ("/usr/bin/secret-tool", "store", "--label=Heel runner signing key",
         "heel", "runner", "label", "runner-linux"),
    ]
    for argv, kwargs, process in calls:
        assert encoded_seed.decode() not in argv
        assert kwargs == {
            "stdin": subprocess.PIPE, "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL, "shell": False, "bufsize": 0,
            "env": {"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        }
        assert process.wait_timeouts == [5]
    assert bytes(calls[0][2].stdin.data) == b""
    assert bytes(calls[1][2].stdin.data) == encoded_seed


def test_linux_helper_output_is_bounded_and_never_exposed(monkeypatch):
    secret_marker = b"linux-private-helper-output"

    def popen(argv, **kwargs):
        return _FakeProcess(argv, returncode=0, stdout=secret_marker * 100)

    monkeypatch.setattr("heel.runner.identity._verified_secret_tool_path",
                        lambda: "/usr/bin/secret-tool")
    backend = LinuxSecretServiceBackend(popen=popen)
    with pytest.raises(RuntimeError, match="invalid material") as caught:
        backend.load("runner-linux")
    assert secret_marker.decode() not in str(caught.value)


@pytest.mark.parametrize("helper_path", ["secret-tool", "/tmp/not-allowlisted-secret-tool"])
def test_linux_helper_rejects_path_resolution_before_process_launch(
    monkeypatch, tmp_path, helper_path,
):
    calls = []
    if helper_path.startswith("/"):
        helper = tmp_path / "secret-tool"
        helper.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        helper.chmod(0o700)
        helper_path = str(helper)
    monkeypatch.setattr("heel.runner.identity._LINUX_SECRET_TOOL_PATH", helper_path)
    backend = LinuxSecretServiceBackend(popen=lambda *args, **kwargs: calls.append(args))

    with pytest.raises(RuntimeError, match="secret service unavailable"):
        backend.load("runner-linux")
    assert calls == []
