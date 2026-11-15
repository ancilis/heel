"""E3 focused units: live-test authoring validation, configured delivery contracts, guided local
input entry and the v6 -> v7 runner runtime registration of ``configured-plan-sync``."""
from __future__ import annotations

import contextlib
import copy
import io
import os
import sqlite3

import pytest

import heel.runner.runtime as runtime_module
from heel import cli
from heel.canary_contracts import (
    ContractError,
    canonical_bytes,
    configured_plan_snapshot,
    validate_configured_plan_request,
    validate_runner_configured_plan_sync,
)
from heel.runner.runtime import RunnerRuntimeState
from heel.saas.scenario_library import ScenarioLibraryError, validate_live_test
from tests.test_runner_runtime import _claim_runtime, _semantic_rows, _stage_on_claim_chain

ASSERTION = {
    "schema_version": "heel.live-read-assertion.v1",
    "success_witness": {"path": ["meta", "state"], "expected_fixture": "export_ok"},
    "condition": {"kind": "json_field_present", "path": ["export", 0, "x.y"]},
}
LIVE = {"schema_version": "heel.custom-live-test.v1", "scenario_id": "plan_entitlement_read",
        "method": "GET", "route_template": "/billing/features", "assertion": ASSERTION}


# --- authoring -------------------------------------------------------------------------------

def test_valid_live_test_is_returned_canonical_and_keeps_literal_key_types():
    assert validate_live_test(copy.deepcopy(LIVE)) == LIVE


@pytest.mark.parametrize("change", [
    {"scenario_id": []}, {"scenario_id": {}}, {"route_template": "/x\ud800"}, {"method": ["GET"]},
    {"scenario_id": "tenant_isolation_read"}, {"method": "POST"}, {"route_template": "billing"},
    {"route_template": "/a//b"}, {"route_template": "/a?b=1"},
])
def test_malformed_live_test_fields_are_a_closed_400_never_a_crash(change):
    with pytest.raises(ScenarioLibraryError) as refused:
        validate_live_test({**LIVE, **change})
    assert (refused.value.status, refused.value.code) == (400, "invalid_live_test")


def test_parameterized_route_has_its_own_explicit_unsupported_reason():
    with pytest.raises(ScenarioLibraryError) as refused:
        validate_live_test({**LIVE, "route_template": "/items/{item_id}"})
    assert refused.value.code == "live_test_route_unsupported"


def test_non_nfc_field_names_are_refused_not_normalized():
    decomposed = "café"
    with pytest.raises(ScenarioLibraryError):
        validate_live_test({**LIVE, "assertion": {**ASSERTION, "condition": {
            "kind": "json_field_present", "path": [decomposed]}}})


# --- delivery contracts ----------------------------------------------------------------------

def test_plan_request_versions_and_shapes_are_closed():
    good = {"schema_version": "heel.configured-plan-request.v1", "plan_kind": "configured_live_read",
            "tests": [{"source_scenario_id": "sc.internal.a", "source_revision": 1}], "plan_labels": []}
    assert validate_configured_plan_request(good) == good
    for bad in (
        {**good, "schema_version": "heel.configured-plan-request.v2"},
        {**good, "tests": []},
        {**good, "tests": good["tests"] * 2},
        {**good, "expected_value": "x"},
        {**good, "tests": [{"source_scenario_id": "sc.internal.a", "source_revision": 0}]},
    ):
        with pytest.raises(ContractError):
            validate_configured_plan_request(bad)


def test_runner_sync_refuses_unknown_capability_and_unbounded_readiness():
    base = {"schema_version": "heel.runner-configured-plan-sync.v1", "binding_id": "rcb_" + "a" * 32,
            "binding_digest": "b" * 64, "capability": "heel.configured-live-read.v1", "readiness": None}
    assert validate_runner_configured_plan_sync(base) == base
    readiness = {"plan_request_id": "cpr_" + "c" * 32, "plan_request_nonce": "n" * 43, "instances": [{
        "test_instance_id": "lti_" + "d" * 32,
        "requirements": [{"kind": "local_input", "subject": "secret_hint", "state": "missing"}]}]}
    assert validate_runner_configured_plan_sync({**base, "readiness": readiness})["readiness"] == readiness
    for bad in (
        {**base, "capability": "heel.configured-live-read.v2"},
        {**base, "readiness": {**readiness, "instances": [{**readiness["instances"][0], "requirements": [
            {"kind": "vault_contents", "subject": None, "state": "ready"}]}]}},
        {**base, "readiness": {**readiness, "instances": [{**readiness["instances"][0], "requirements": [
            {"kind": "local_input", "subject": "a value with spaces", "state": "missing"}]}]}},
    ):
        with pytest.raises(ContractError):
            validate_runner_configured_plan_sync(bad)


def test_a_live_snapshot_never_carries_frozen_handles_and_a_replay_always_does():
    from heel.runner.content_assertion import live_read_assertion_digest, validate_live_read_assertion

    instance = {
        "test_instance_id": "lti_" + "e" * 32, "scenario_id": "plan_entitlement_read",
        "source": {"source_scenario_id": "sc.internal.a", "source_revision": 1}, "method": "GET",
        "route_template": "/billing/features", "assertion": ASSERTION,
        "assertion_digest": live_read_assertion_digest(validate_live_read_assertion(ASSERTION)),
        "local_input_refs": ["export_ok"], "local_input_binding_digest": None,
    }
    labels = [{"role": "higher_plan", "plan_label": "Pro"}, {"role": "lower_plan", "plan_label": "Free"}]
    snapshot = {"plan_request_id": "cpr_" + "c" * 32, "plan_request_nonce": "n" * 43,
                "plan_kind": "configured_live_read", "instances": [instance], "plan_labels": labels,
                "source_run_id": None, "expires_at_ms": 1}
    assert configured_plan_snapshot(snapshot) == snapshot
    with pytest.raises(ContractError):
        configured_plan_snapshot({**snapshot, "instances": [{**instance, "local_input_binding_digest": "f" * 64}]})
    with pytest.raises(ContractError):
        configured_plan_snapshot({**snapshot, "plan_kind": "configured_regression", "source_run_id": "crun_" + "1" * 32})
    with pytest.raises(ContractError):
        configured_plan_snapshot({**snapshot, "plan_labels": []})  # a plan comparison needs operator labels


# --- guided local input entry ------------------------------------------------------------------

class _Vault:
    supported = True
    backend_id = "macos_keychain"

    def __init__(self):
        self.items = {}

    def store(self, handle, secret):
        self.items[handle] = bytes(secret)

    def delete(self, handle):
        self.items.pop(handle, None)


def _add(monkeypatch, store, vault, kind, raw: bytes):
    monkeypatch.setattr(cli, "_runner_store", lambda: store)
    monkeypatch.setattr("heel.runner.vault.select_vault", lambda backend: vault)
    read, write = os.pipe()
    os.set_inheritable(read, True)
    try:
        os.write(write, raw)
        os.close(write)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["runner", "input", "add", "--name", "secret_hint", "--backend", "keychain",
                             "--type", kind, "--secret-fd", str(read)])
    finally:
        os.close(read)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def local_store(tmp_path):
    from tests.test_runner_configured_live_tests import World

    return World(tmp_path).store


@pytest.mark.parametrize(("kind", "raw", "stored"), [
    ("text", b"plain text, no quotes\n", b'"plain text, no quotes"'),
    ("text", b'"quoted"', b'"\\"quoted\\""'),
    ("number", b"42", b"42"),
    ("number", b"1E5", b"100000.0"),
    ("boolean", b"true", b"true"),
    ("null", b"", b"null"),
    ("json", b'"legacy"', b'"legacy"'),
])
def test_guided_value_kinds_store_exact_scalars_without_echo(monkeypatch, local_store, kind, raw, stored):
    vault = _Vault()
    code, out, err = _add(monkeypatch, local_store, vault, kind, raw)
    assert (code, err) == (0, "")
    assert list(vault.items.values()) == [stored]
    assert raw.strip().decode() not in out or kind in {"null", "boolean", "number"}


@pytest.mark.parametrize(("kind", "raw"), [
    ("number", b"1.0000000000000000001"), ("number", b"9007199254740993.0"), ("number", b"1e-10000"),
    ("number", b'"42"'), ("number", b"true"), ("boolean", b"yes"), ("text", b"\xff\xfe"),
    ("text", b"x" * 3000),
])
def test_inexact_or_mistyped_values_are_refused_before_any_handle(monkeypatch, local_store, kind, raw):
    vault = _Vault()
    existing = local_store.list_live_inputs()
    code, out, err = _add(monkeypatch, local_store, vault, kind, raw)
    assert code == 2 and out == "" and vault.items == {}
    assert raw.decode("utf-8", "replace")[:12] not in err
    assert local_store.list_live_inputs() == existing


# --- runner runtime v6 -> v7 -----------------------------------------------------------------

def test_runtime_v6_to_v7_registers_configured_plan_sync_and_keeps_every_row(tmp_path):
    runtime, signer, identity = _claim_runtime(tmp_path)
    staged = _stage_on_claim_chain(
        runtime, signer, identity, "list-contexts", canonical_bytes({"schema_version": "heel.runner-context-list.v1"}),
    )
    runtime.close()
    with contextlib.closing(sqlite3.connect(runtime.path)) as conn:
        conn.execute("DROP INDEX idx_pending_calls_created")
        conn.execute("DROP INDEX idx_pending_calls_run_operation")
        conn.execute("ALTER TABLE pending_calls RENAME TO pending_calls_v7")
        conn.execute(runtime_module._V6_PENDING_SQL)
        for statement in runtime_module._PENDING_INDEX_SQL:
            conn.execute(statement)
        conn.execute("INSERT INTO pending_calls SELECT * FROM pending_calls_v7")
        conn.execute("DROP TABLE pending_calls_v7")
        conn.execute("ALTER TABLE metadata RENAME TO metadata_v7")
        conn.execute(runtime_module._V6_METADATA_SQL)
        conn.execute(
            "INSERT INTO metadata SELECT singleton,'heel.runner-runtime-state.v6',workspace_id,runner_id,"
            "runner_key_id,public_key_digest,authority_epoch,authority_identity_digest,"
            "rotation_fence_digest,state_key_ciphertext FROM metadata_v7"
        )
        conn.execute("DROP TABLE metadata_v7")
        conn.commit()
        assert RunnerRuntimeState._schema_matches(conn, runtime_module._V6_SCHEMA_SQL)
        with pytest.raises(sqlite3.IntegrityError):  # a v6 table refuses the new operation
            conn.execute("INSERT INTO pending_calls VALUES(?,?,?,?,?,?,?,?)",
                         ("f" * 64, "e" * 64, None, "configured-plan-sync", 1, 0, b"\0" * 29, 1))
    before = _semantic_rows(runtime.path)
    upgraded = RunnerRuntimeState(runtime.path, identity, signer)
    after = _semantic_rows(runtime.path)
    assert after["metadata"][0][1] == "heel.runner-runtime-state.v7"
    assert after["metadata"][0][2:] == before["metadata"][0][2:]
    assert all(after[table] == before[table] for table in before if table != "metadata")
    with contextlib.closing(sqlite3.connect(runtime.path)) as conn:
        assert RunnerRuntimeState._schema_matches(conn, runtime_module._V7_SCHEMA_SQL)
    assert upgraded.load_pending_calls() == (staged,)
