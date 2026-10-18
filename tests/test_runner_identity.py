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


def test_system_secure_signer_rotation_provider_distinguishes_create_from_recovery_load():
    backend = InMemorySecretBackend()
    created = SystemSecureSigner.create_new("heel-rotation-new", backend=backend)
    loaded = SystemSecureSigner.load_existing("heel-rotation-new", backend=backend)
    assert loaded.public_key == created.public_key
    with pytest.raises(RuntimeError, match="signing identity is unavailable"):
        SystemSecureSigner.load_existing("heel-rotation-missing", backend=backend)
    assert "heel-rotation-missing" not in backend._values
    with pytest.raises(ValueError, match="already exists"):
        SystemSecureSigner.create_new("heel-rotation-new", backend=backend)


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


def _scripted_keychain(monkeypatch, *, persisted, add_returncode=0, stored_value=None):
    """Fake ``security``: find/-i add/delete against one dict, recording argv and stdin."""
    calls = []

    def popen(argv, **kwargs):
        argv = tuple(argv)
        if argv[1] == "find-generic-password":
            account = argv[argv.index("-a") + 1]
            found = account in persisted
            process = _FakeProcess(argv, returncode=0 if found else 44,
                                   stdout=persisted.get(account, b"") + b"\n" if found else b"")
        elif argv[1] == "delete-generic-password":
            account = argv[argv.index("-a") + 1]
            process = _FakeProcess(argv, returncode=0 if persisted.pop(account, None) is not None else 44,
                                   stdout=b"")
        else:
            process = _FakeProcess(argv, returncode=add_returncode, stdout=b"")
            original_close = process.stdin.close

            def close():
                tokens = bytes(process.stdin.data).split()
                if add_returncode == 0 and len(tokens) == 7:
                    persisted[tokens[4].decode()] = tokens[6] if stored_value is None else stored_value
                original_close()
            process.stdin.close = close
        calls.append((argv, kwargs, process))
        return process

    monkeypatch.setattr("heel.runner.identity._verified_security_path",
                        lambda: "/usr/bin/security")
    return popen, calls


def test_macos_first_create_never_places_ed25519_seed_in_process_argv(monkeypatch):
    expected_seed = b"k" * 32
    encoded_seed = base64.b64encode(expected_seed)
    persisted = {}
    popen, calls = _scripted_keychain(monkeypatch, persisted=persisted)
    monkeypatch.setattr("heel.runner.identity.secrets.token_bytes", lambda count: expected_seed)
    signer = SystemSecureSigner(
        "runner-one", backend=MacOSKeychainSecretBackend(popen=popen),
    )
    assert signer.public_key and encoded_seed not in repr(signer).encode()
    assert [argv for argv, _, _ in calls] == [
        ("/usr/bin/security", "find-generic-password", "-s", "heel.runner.ed25519.v1", "-a", "runner-one", "-w"),
        ("/usr/bin/security", "-i"),
        ("/usr/bin/security", "find-generic-password", "-s", "heel.runner.ed25519.v1", "-a", "runner-one", "-w"),
    ]
    for argv, kwargs, process in calls:
        assert encoded_seed.decode() not in " ".join(argv)
        assert kwargs == {
            "stdin": subprocess.PIPE, "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL, "shell": False, "bufsize": 0,
            "env": {"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        }
        assert process.wait_timeouts == [5]
    assert bytes(calls[0][2].stdin.data) == b""
    # Exactly one documented interactive command line, no -U, the seed only on stdin.
    assert bytes(calls[1][2].stdin.data) == (
        b"add-generic-password -s heel.runner.ed25519.v1 -a runner-one -w " + encoded_seed + b"\n"
    )
    assert persisted == {"runner-one": encoded_seed}


def test_macos_store_deletes_its_item_and_fails_when_the_value_does_not_read_back(monkeypatch):
    seed = b"t" * 32
    for stored_value in (b"", base64.b64encode(b"x" * 32), base64.b64encode(seed)[:40]):
        persisted = {}
        popen, calls = _scripted_keychain(monkeypatch, persisted=persisted, stored_value=stored_value)
        with pytest.raises(RuntimeError, match="runner OS secret service unavailable") as caught:
            MacOSKeychainSecretBackend(popen=popen).store("runner-trunc", seed)
        assert persisted == {}
        assert calls[-1][0] == (
            "/usr/bin/security", "delete-generic-password", "-s", "heel.runner.ed25519.v1", "-a", "runner-trunc",
        )
        assert base64.b64encode(seed).decode() not in str(caught.value)


def test_macos_legacy_empty_or_short_items_fail_closed_and_are_never_rewritten(monkeypatch):
    for legacy in (b"", base64.b64encode(b"s" * 16)):
        persisted = {"runner-legacy": legacy}
        popen, calls = _scripted_keychain(monkeypatch, persisted=persisted)
        backend = MacOSKeychainSecretBackend(popen=popen)
        with pytest.raises(RuntimeError, match="invalid material"):
            backend.load("runner-legacy")
        with pytest.raises(RuntimeError):
            SystemSecureSigner.create_new("runner-legacy", backend=backend)
        with pytest.raises(RuntimeError):
            SystemSecureSigner("runner-legacy", backend=backend)
        assert persisted == {"runner-legacy": legacy}
        assert all(argv[1] == "find-generic-password" for argv, _, _ in calls)
    valid = base64.b64encode(b"v" * 32)
    persisted = {"runner-valid": valid}
    popen, _ = _scripted_keychain(monkeypatch, persisted=persisted)
    assert MacOSKeychainSecretBackend(popen=popen).load("runner-valid") == b"v" * 32


@pytest.mark.parametrize("label", [
    "runner one", "runner\none", "-U", "runner;one", "runner\"one", "runner'one", "runner#one", "ü",
])
def test_macos_store_refuses_labels_outside_the_interactive_token_alphabet_before_any_process(
    monkeypatch, label,
):
    popen, calls = _scripted_keychain(monkeypatch, persisted={})
    with pytest.raises(ValueError, match="invalid runner signing label"):
        MacOSKeychainSecretBackend(popen=popen).store(label, b"q" * 32)
    assert calls == []


def test_security_interactive_command_is_one_bounded_line_of_inert_tokens():
    from heel.runner.identity import SECURITY_INTERACTIVE_MAX_LINE_BYTES, security_interactive_add_command

    line = security_interactive_add_command("svc.v1", "acct_.:-1", b"+/=AZaz09")
    assert line == b"add-generic-password -s svc.v1 -a acct_.:-1 -w +/=AZaz09\n"
    for bad in (b"", b"a b", b"a\nb", b"a\rb", b"-w", b"a\x00", b"a'b", b'a"b', b"a\\b", b"a#b", b"a" * 3201):
        with pytest.raises(ValueError):
            security_interactive_add_command("svc", "acct", bad)
    with pytest.raises(ValueError, match="line limit"):
        security_interactive_add_command("s" * 200, "a" * 200, b"v" * 3200)
    assert len(security_interactive_add_command("s", "a", b"v" * 3000)) <= SECURITY_INTERACTIVE_MAX_LINE_BYTES


def test_macos_delete_tolerates_a_missing_item_and_fails_closed_otherwise(monkeypatch):
    persisted = {"runner-del": base64.b64encode(b"d" * 32)}
    popen, calls = _scripted_keychain(monkeypatch, persisted=persisted)
    backend = MacOSKeychainSecretBackend(popen=popen)
    backend.delete("runner-del")
    backend.delete("runner-del")
    assert persisted == {}
    failing = lambda argv, **kwargs: _FakeProcess(argv, returncode=1, stdout=b"")
    with pytest.raises(RuntimeError, match="unavailable"):
        MacOSKeychainSecretBackend(popen=failing).delete("runner-del")


@pytest.mark.skipif(
    __import__("platform").system() != "Darwin" or not __import__("os").path.isfile("/usr/bin/security"),
    reason="real macOS Keychain only",
)
def test_real_macos_keychain_round_trips_a_dummy_seed_and_removes_it():
    import secrets as _secrets

    backend = MacOSKeychainSecretBackend()
    label = "heel-test-" + _secrets.token_hex(12)
    try:
        signer = SystemSecureSigner.create_new(label, backend=backend)
        assert SystemSecureSigner.load_existing(label, backend=backend).key_id == signer.key_id
        with pytest.raises(ValueError, match="already exists"):
            SystemSecureSigner.create_new(label, backend=backend)
    finally:
        backend.delete(label)
    assert backend.load(label) is None


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
    existing_seed = base64.b64encode(b"e" * 32)
    persisted = {}
    popen, calls = _scripted_keychain(monkeypatch, persisted=persisted, add_returncode=45)
    monkeypatch.setattr("heel.runner.identity.secrets.token_bytes", lambda count: generated_seed)
    # The racing writer's item appears between our lookup and our add; add (no -U) fails with 45.
    original = popen

    def racing(argv, **kwargs):
        if argv[1] == "-i":
            persisted["runner-race"] = existing_seed
        return original(argv, **kwargs)

    with pytest.raises(RuntimeError, match="runner OS secret service unavailable") as caught:
        SystemSecureSigner("runner-race", backend=MacOSKeychainSecretBackend(popen=racing))

    store_argv, _, store_process = calls[1]
    assert store_argv == ("/usr/bin/security", "-i")
    assert b" -U" not in bytes(store_process.stdin.data)
    assert bytes(store_process.stdin.data).endswith(b" -w " + base64.b64encode(generated_seed) + b"\n")
    assert persisted == {"runner-race": existing_seed}
    assert len(calls) == 2
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


def test_pairing_signer_label_namespace_is_fixed_bounded_and_random_id_only():
    from heel.runner.identity import RUNNER_PAIRING_SIGNER_LABEL_PREFIX, runner_pairing_signer_label

    label = runner_pairing_signer_label("0123456789abcdef0123456789abcdef")
    assert label == RUNNER_PAIRING_SIGNER_LABEL_PREFIX + "0123456789abcdef0123456789abcdef"
    assert len(label) <= 128 and SystemSecureSigner._label(label) == label
    for bad in ("", "0" * 31, "0" * 33, "0123456789ABCDEF0123456789abcdef", "g" * 32, None, b"0" * 32,
                "../" + "0" * 29, "0" * 31 + "\x00"):
        with pytest.raises(ValueError):
            runner_pairing_signer_label(bad)
