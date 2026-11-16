"""E2-NUM1: a local expected scalar is ingested and loaded exactly, or refused before storage.

Real: ``heel.cli.main`` (``runner input add``), the real JSON scalar decoder, ``RunnerStore``
create/load, and the real E1 evaluator (``resolve_local_fixtures`` + ``observe_live_read``).
Seams (labelled where used):
  SEAM-VAULT  the OS vault is the in-memory ``MemoryOSVault`` carrying the OS backend id;
  SEAM-TTY    ``sys.stdin.isatty`` and ``getpass.getpass`` are replaced for the prompt path;
  SEAM-FD     the ``--secret-fd`` path reads a real inherited ``os.pipe`` descriptor.
The final public-installed OS-vault journey is E4, not this file.
"""
from __future__ import annotations

import json
import os

import pytest

from heel import cli
from heel.runner.content_assertion import (
    LiveReadAssertion,
    LiveReadResponse,
    observe_live_read,
    resolve_local_fixtures,
)
from heel.runner.store import LiveInputUnavailable, _live_input_value
from heel.runner.vault import MAX_SECRET_BYTES
from tests.test_runner_configured_live_tests import World

# The three reported tokens: each silently rounded by a default float parse.
REPORTED = ("1.0000000000000000001", "1e-10000", "9007199254740993.0")
# Non-finite, overflowing and extreme-exponent tokens.
NONFINITE = (
    "NaN", "Infinity", "-Infinity", "1e400", "-1e400", "1e999999999999999999999",
    "1e-999999999999999999999", "4.9e-325",
)
# Other refused shapes: malformed, out of integer bounds, non-scalars, deep, empty.
MALFORMED = (
    "1.0.0", "01", "1 2", "+1", ".5", "1.", "0x10", "'x'", str(2 ** 63), str(-(2 ** 63)),
    "9" * 5000, "[1]", '{"a":1}', "[" * 50_000, "{" * 50_000, '"\\ud800"', "", "   ",
    '"' + "x" * 3000 + '"',
)
# Ordinary values that must remain valid, with the E1 body token each must equal.
ACCEPTED = (
    ("0.1", "0.1"), ("1.0", "1"), ("1e0", "1.0"), ("-0.0", "0"), ("2.5e-3", "0.0025"),
    ("1.7976931348623157e308", "1.7976931348623157e308"), ("5e-324", "5e-324"),
    ("42", "42.0"), (str(2 ** 63 - 1), str(2 ** 63 - 1)), (str(-(2 ** 63 - 1)), str(-(2 ** 63 - 1))),
    ('"abc"', '"abc"'), ('"\\u00e9"', '"é"'), ("true", "true"), ("false", "false"),
    ("null", "null"), (" 0.1\n", "0.1"),
)



def short(token: str) -> str:
    return f"{token[:24]}~{len(token)}" if len(token) > 24 else token


ASSERTION = LiveReadAssertion(
    ("marker",), "witness", "json_scalar_equals_fixture", ("amount",), "expected",
)


@pytest.fixture
def world(tmp_path, monkeypatch):
    import heel.runner.vault as vault_module

    built = World(tmp_path)
    monkeypatch.setenv("HEEL_HOME", str(built.store.root))
    # SEAM-VAULT: the CLI selects the in-memory OS-backend vault.
    monkeypatch.setattr(vault_module, "select_vault", lambda kind, **_: built.vault)
    return built


def snapshot(world):
    return (
        json.dumps(world.store.list_live_inputs(), sort_keys=True),
        dict(world.vault.items),
    )


def add_via_fd(raw: bytes) -> int:
    """SEAM-FD: a real inherited pipe descriptor through the actual ``cli.main``."""
    read, write = os.pipe()
    try:
        os.write(write, raw)
        os.close(write)
        write = -1
        os.set_inheritable(read, True)
        return cli.main(["runner", "input", "add", "--name", "amount", "--backend", "keychain",
                         "--secret-fd", str(read)])
    finally:
        os.close(read)
        if write != -1:
            os.close(write)


def add_via_prompt(monkeypatch, text: str) -> int:
    """SEAM-TTY: a terminal is present and the hidden prompt returns ``text``."""

    class _TTY:
        def isatty(self):
            return True

    prompts = []
    monkeypatch.setattr(cli.sys, "stdin", _TTY())
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or text)
    code = cli.main(["runner", "input", "add", "--name", "amount", "--backend", "keychain"])
    assert prompts == ["Expected value (JSON scalar): "]
    return code


def assert_refused_generic(code, capsys, token):
    out, err = capsys.readouterr()
    assert code == 2
    assert out == ""
    assert err == cli._SAFE_RUNNER_INPUT_FAILURE + "\n"
    if token.strip():
        assert token.strip() not in out + err


def observe(expected, body_token: str) -> str:
    """The real E1 evaluator against an exact response body token."""
    expectations = resolve_local_fixtures(ASSERTION, {"witness": "ok", "expected": expected})
    body = ('{"marker":"ok","amount":' + body_token + "}").encode()
    return observe_live_read(
        LiveReadResponse(200, body), method="GET", assertion=ASSERTION, expectations=expectations,
    ).state


# --------------------------------------------------------------------------- #
# Refusal before any handle or record exists
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("token", REPORTED + NONFINITE, ids=short)
def test_fd_ingestion_refuses_inexact_and_nonfinite_numbers_before_storage(world, capsys, token):
    before = snapshot(world)
    code = add_via_fd(token.encode())
    assert_refused_generic(code, capsys, token)
    assert snapshot(world) == before


@pytest.mark.parametrize("token", REPORTED + NONFINITE, ids=short)
def test_prompt_ingestion_refuses_inexact_and_nonfinite_numbers_before_storage(
    world, capsys, monkeypatch, token,
):
    before = snapshot(world)
    code = add_via_prompt(monkeypatch, token)
    assert_refused_generic(code, capsys, token)
    assert snapshot(world) == before


@pytest.mark.parametrize("token", MALFORMED, ids=short)
def test_malformed_deep_and_out_of_bound_input_is_refused_generically(world, capsys, monkeypatch, token):
    before = snapshot(world)
    assert_refused_generic(add_via_fd(token.encode()), capsys, token)
    assert_refused_generic(add_via_prompt(monkeypatch, token), capsys, token)
    assert snapshot(world) == before


def test_prompt_input_is_bounded_like_the_fd_cap(world, capsys, monkeypatch):
    before = snapshot(world)
    # Valid JSON scalars only in the padding, so only the size bound can refuse them.
    oversized = "0.1" + " " * MAX_SECRET_BYTES
    assert_refused_generic(add_via_prompt(monkeypatch, oversized), capsys, "0.1")
    assert_refused_generic(add_via_fd(oversized.encode()), capsys, "0.1")
    assert snapshot(world) == before


# --------------------------------------------------------------------------- #
# Stored vault bytes decode with the same strict decoder
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("token", REPORTED + NONFINITE + MALFORMED, ids=short)
def test_vault_decode_and_load_refuse_the_same_tokens_without_reflecting_them(world, token):
    with pytest.raises(ValueError) as caught:
        _live_input_value(token.encode())
    assert str(caught.value) == "local input is invalid"
    assert caught.value.__cause__ is None and caught.value.__suppress_context__
    if token.strip():
        assert token.strip() not in repr(caught.value)
    # SEAM-VAULT: a record whose OS-vault bytes are the raw token (as if written out of band).
    handle = world.inputs["export_ok"]["input_handle_id"]
    world.vault.items[handle] = token.encode()
    with pytest.raises(LiveInputUnavailable) as unavailable:
        world.store.load_live_input_values({"export_ok": handle}, vaults={"macos_keychain": world.vault})
    assert str(unavailable.value) == "local input is unavailable"


# --------------------------------------------------------------------------- #
# Ordinary values remain valid, exact, and E1 semantics are unchanged
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(("token", "same"), ACCEPTED)
def test_ordinary_scalars_are_accepted_and_compare_exactly_as_entered(world, capsys, monkeypatch, token, same):
    for add in (lambda: add_via_fd(token.encode()), lambda: add_via_prompt(monkeypatch, token)):
        code = add()
        out, err = capsys.readouterr()
        assert code == 0, err
        handle = json.loads(out)["input_handle"]
        assert set(json.loads(out)) == {"input_handle", "name", "selection"}
        loaded = world.store.load_live_input_values(
            {"expected": handle}, vaults={"macos_keychain": world.vault},
        )["expected"]
        # The exact entered token and its numerically equal spelling both match.
        assert observe(loaded, token.strip()) == "condition_true"
        assert observe(loaded, same) == "condition_true"
        # A different value does not.
        assert observe(loaded, '"different"') == "condition_false"
    current = [item for item in world.store.list_live_inputs() if item["name"] == "amount"]
    # Same immutable-handle rotation: two handles, the latest is current, the earlier retained.
    assert [item["selection"] for item in current] == ["retained", "current"]


@pytest.mark.parametrize("value", [0.1, 1.0, 1e-300, -2.5, 5e-324, 1.7976931348623157e308, 10 ** 18, "x", True, None])
def test_e1_store_api_finite_float_semantics_are_unchanged(world, value):
    record = world.store.create_live_input(name="api_value", value=value, vault=world.vault)
    loaded = world.store.load_live_input_values(
        {"expected": record["input_handle_id"]}, vaults={"macos_keychain": world.vault},
    )["expected"]
    assert type(loaded) is type(value) and loaded == value
    assert observe(loaded, json.dumps(value)) == observe(value, json.dumps(value)) == "condition_true"
