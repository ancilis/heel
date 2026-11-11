"""Local signed findings inspection and saved regression definitions (paired runner store).

Every source is a real RunnerStore run committed by the LocalCanaryExecutor; nothing here
prepares, serves, replays or contacts a network.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import socket
from pathlib import Path

import pytest

from heel import cli
from heel.canary_contracts import canonical_bytes, canonical_digest
from heel.crypto import SigningAuthority
from heel.runner.execution import ExecutionBundle, LocalCanaryExecutor
from heel.runner.http_transport import BoundedResponseEvidence, TargetResponse
from heel.runner.regressions import (
    MAX_SAVED_REGRESSIONS,
    derive_saved_regression,
    regression_id_for,
)
from heel.runner.store import RunnerStore, RunnerStoreError
from tests.test_runner_compiler import CanaryCompiler, add_roles, bound_store, context
from tests.test_runner_stop import StaticVault, active_gate, signed_grant


MARKER = "heel-canary-item-0137"
PROTECTED = json.dumps({"protected_canary": MARKER}).encode()
OWNERSHIP = "object_ownership_read"
ANONYMOUS = "anonymous_authenticated_read"
SECRET_NAME = "sk_live_DO_NOT_ECHO"


class BodyTransport:
    """Scripted target that returns exact (status, body) pairs in action order."""

    def __init__(self, responses):
        self.responses = list(responses)

    def request(
        self, action, *, credential, cancellation, retry_policy, remaining_requests,
        before_attempt, evidence_context, evidence_sink, redactor,
    ):
        del credential, cancellation, retry_policy, remaining_requests, redactor
        before_attempt(1, None)
        status, body = self.responses.pop(0)
        if action.method == "HEAD":
            body = b""
        reference = evidence_sink(BoundedResponseEvidence(
            action_ordinal=evidence_context.action_ordinal,
            scenario_id=action.scenario_id,
            semantic_auth_role=action.semantic_auth_role,
            method=action.method,
            route_template=evidence_context.route_template,
            attempt=1,
            status_code=status,
            raw_headers=b"Content-Type: application/json\r\nX-Raw-Header: RAW-HEADER-VALUE",
            raw_body=body,
        ))
        return TargetResponse(
            status, "json_object" if body else "absent", len(body), 1, reference, 0,
        )


def committed_run(tmp_path, *, lower=(200, PROTECTED), terminal=True, monkeypatch=None):
    """One real signed run: anonymous HEAD (inconclusive) + ownership GET (per ``lower``)."""
    store, identity, signer = bound_store(tmp_path)
    store.save_mapping(ANONYMOUS, method="HEAD", route_template="/health")
    store.save_mapping(
        OWNERSHIP, method="GET", route_template="/items/{item_id}",
        fixture_bindings={"item_id": MARKER},
    )
    add_roles(store)
    compiled = CanaryCompiler(
        store=store, identity=identity, signer=signer, now_ms=1_000,
    ).compile([ANONYMOUS, OWNERSHIP])
    authority = SigningAuthority.generate()
    grant = signed_grant(compiled.manifest, compiled.projection, identity, authority)
    if not terminal:
        original = store.transition_run

        def hold_before_terminal(run_id, next_state, *, now_ms):
            if next_state == "terminal":
                return store.load_run(run_id)
            return original(run_id, next_state, now_ms=now_ms)

        monkeypatch.setattr(store, "transition_run", hold_before_terminal)
    LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(compiled.manifest, compiled.projection, grant),
        transport=BodyTransport([(401, b""), (200, b""), (200, PROTECTED), lower]),
        gate_source=active_gate,
    )
    return store, grant["run_id"], compiled.manifest, grant


def invoke(*arguments):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main(list(arguments))
    return code, stdout.getvalue(), stderr.getvalue()


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("network")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


def use_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HEEL_HOME", str(tmp_path / "heel-home"))


def regressions_file(store: RunnerStore) -> Path:
    return store.root / "runner" / "contexts" / store.namespace / "regressions.json"


def state_bytes(store: RunnerStore) -> bytes | None:
    path = regressions_file(store)
    return path.read_bytes() if path.exists() else None


def assert_quiet(text: str, *secrets: str) -> None:
    for value in (MARKER, "RAW-HEADER-VALUE", "protected_canary", SECRET_NAME, *secrets):
        assert value not in text


# --- findings inspection -------------------------------------------------------------------


def test_findings_renders_only_the_verified_signed_redacted_local_view(
    tmp_path, monkeypatch, no_network,
):
    store, run_id, _manifest, _grant = committed_run(tmp_path)
    use_home(monkeypatch, tmp_path)

    code, output, error = invoke("runner", "findings", "--run", run_id)

    assert (code, error) == (0, "")
    view = json.loads(output)
    assert view == store.load_final_projections(run_id)["local_view"]
    outcomes = {
        item["scenario_id"]: item["assessment_outcome"]
        for item in view["findings_projection"]["scenario_results"]
    }
    assert outcomes == {ANONYMOUS: "inconclusive", OWNERSHIP: "observed"}
    # Raw response bytes, raw headers and fixture values never reach stdout.
    assert_quiet(output)
    assert str(store.root) not in output


@pytest.mark.parametrize("arguments", [
    ("--run", "crun_" + "f" * 32),
    ("--run", "../../etc/" + SECRET_NAME),
    ("--run", SECRET_NAME),
])
def test_findings_unknown_or_hostile_run_fails_with_fixed_copy(
    tmp_path, monkeypatch, no_network, arguments,
):
    committed_run(tmp_path)
    use_home(monkeypatch, tmp_path)

    code, output, error = invoke("runner", "findings", *arguments)

    assert (code, output) == (2, "")
    assert error == "Heel runner findings are unavailable.\n"


def test_findings_refuses_a_nonterminal_run(tmp_path, monkeypatch, no_network):
    store, run_id, _manifest, _grant = committed_run(
        tmp_path, terminal=False, monkeypatch=monkeypatch,
    )
    assert store.load_run(run_id)["state"] != "terminal"
    use_home(monkeypatch, tmp_path)

    code, output, error = invoke("runner", "findings", "--run", run_id)

    assert (code, output) == (2, "")
    assert error == "Heel runner findings are unavailable.\n"


def _resign_findings_with_foreign_key(store: RunnerStore, run_id: str) -> None:
    path = store.run_path(run_id) / "finals.json"
    envelope = json.loads(path.read_bytes())
    foreign = SigningAuthority.generate()
    findings = envelope["findings_projection"]
    unsigned = {
        key: value for key, value in findings.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    resigned = {
        **unsigned,
        "projection_digest": canonical_digest(unsigned),
        **foreign.sign(canonical_bytes(unsigned)),
    }
    envelope["findings_projection"] = resigned
    envelope["local_view"]["findings_projection"] = resigned
    envelope["disclosure_preview"]["projection"] = resigned
    envelope["disclosure_preview"]["projection_digest"] = resigned["projection_digest"]
    core = {key: value for key, value in envelope.items() if key != "finals_digest"}
    envelope["finals_digest"] = canonical_digest(core)
    path.write_bytes(canonical_bytes(envelope))


def test_findings_and_add_reject_foreign_signed_finals(tmp_path, monkeypatch, no_network):
    store, run_id, _manifest, _grant = committed_run(tmp_path)
    _resign_findings_with_foreign_key(store, run_id)
    use_home(monkeypatch, tmp_path)

    code, output, error = invoke("runner", "findings", "--run", run_id)
    assert (code, output, error) == (2, "", "Heel runner findings are unavailable.\n")

    code, output, error = invoke(
        "runner", "regress", "add", "--run", run_id, "--scenario", OWNERSHIP,
        "--name", "ownership",
    )
    assert (code, output) == (2, "")
    assert error == "Heel runner regression could not be saved safely.\n"
    assert state_bytes(store) is None


# --- saved regression add / list -----------------------------------------------------------


def test_add_persists_a_bounded_context_bound_definition_across_reopen(
    tmp_path, monkeypatch, no_network,
):
    store, run_id, manifest, grant = committed_run(tmp_path)
    use_home(monkeypatch, tmp_path)
    finals = store.load_final_projections(run_id)

    code, output, error = invoke(
        "runner", "regress", "add", "--run", run_id, "--scenario", OWNERSHIP,
        "--name", "Ownership read regression",
    )

    assert (code, error) == (0, "")
    added = json.loads(output)
    assert added["created"] is True
    record = added["regression"]
    bindings = next(
        action["fixture_bindings"] for action in manifest["actions"]
        if action["scenario_id"] == OWNERSHIP
    )
    expected_ctx = context()
    binding = store.load_binding()["identity"]
    assert record == {
        "regression_id": "rreg_" + hashlib.sha256(
            f"{run_id}:{OWNERSHIP}".encode()
        ).hexdigest()[:24],
        "name": "Ownership read regression",
        "source_run_id": run_id,
        "scenario_id": OWNERSHIP,
        "adapter_version": next(
            item["adapter_version"] for item in manifest["scenarios"]
            if item["scenario_id"] == OWNERSHIP
        ),
        "method": "GET",
        "route_template": "/items/{item_id}",
        "fixture_bindings_sha256": canonical_digest({
            "domain": "heel.runner-regression-fixture-bindings.v1",
            "fixture_bindings": bindings,
        }),
        "findings_projection_digest": finals["findings_projection"]["projection_digest"],
        "approval_projection_digest": grant["approval"]["projection_digest"],
        "manifest_digest": manifest["manifest_digest"],
        "grant_id": grant["grant_id"],
        "grant_digest": grant["grant_digest"],
        "workspace_id": expected_ctx.workspace_id,
        "project_id": expected_ctx.project_id,
        "environment_id": expected_ctx.environment_id,
        "origin": expected_ctx.origin,
        "runner_id": binding["runner_id"],
        "runner_key_id": binding["runner_key_id"],
        "expected_outcome": "blocked",
        "created_at_ms": record["created_at_ms"],
    }
    assert record["regression_id"] == regression_id_for(run_id, OWNERSHIP)
    assert isinstance(record["created_at_ms"], int) and record["created_at_ms"] > 0
    # No raw fixture value, body, header, credential handle or private path is duplicated.
    raw = regressions_file(store).read_bytes()
    assert_quiet(raw.decode())
    for credential in store.list_credentials():
        assert credential["credential_handle_id"] not in raw.decode()
    assert str(store.root).encode() not in raw
    assert os.stat(regressions_file(store)).st_mode & 0o777 == 0o600

    reopened = RunnerStore(tmp_path / "heel-home")
    assert reopened.list_saved_regressions() == [record]
    code, output, error = invoke("runner", "regress", "list")
    assert (code, error) == (0, "")
    assert json.loads(output) == {
        "regression_count": 1, "regressions": [record], "result_count": 0, "results": [],
    }


def test_duplicate_add_is_deterministic_and_never_rewrites(tmp_path, monkeypatch, no_network):
    store, run_id, _manifest, _grant = committed_run(tmp_path)
    use_home(monkeypatch, tmp_path)
    arguments = (
        "runner", "regress", "add", "--run", run_id, "--scenario", OWNERSHIP, "--name", "first",
    )
    code, output, _ = invoke(*arguments)
    assert code == 0
    first = json.loads(output)["regression"]
    before = state_bytes(store)

    code, output, error = invoke(*arguments)
    assert (code, error) == (0, "")
    assert json.loads(output) == {"created": False, "regression": first}
    assert state_bytes(store) == before

    code, output, error = invoke(
        "runner", "regress", "add", "--run", run_id, "--scenario", OWNERSHIP,
        "--name", "renamed",
    )
    assert (code, output) == (2, "")
    assert error == "Heel runner regression could not be saved safely.\n"
    assert state_bytes(store) == before


@pytest.mark.parametrize("lower", [
    (403, b""),  # blocked
    (403, b'{"error": "upgrade required"}'),  # denial envelope: inconclusive
])
def test_add_refuses_blocked_or_inconclusive_ownership(tmp_path, monkeypatch, no_network, lower):
    store, run_id, _manifest, _grant = committed_run(tmp_path, lower=lower)
    outcome = next(
        item["assessment_outcome"]
        for item in store.load_final_projections(run_id)["findings_projection"]["scenario_results"]
        if item["scenario_id"] == OWNERSHIP
    )
    assert outcome == ("blocked" if lower[1] == b"" else "inconclusive")
    use_home(monkeypatch, tmp_path)

    code, output, error = invoke(
        "runner", "regress", "add", "--run", run_id, "--scenario", OWNERSHIP, "--name", "x",
    )
    assert (code, output) == (2, "")
    assert error == "Heel runner regression could not be saved safely.\n"
    assert state_bytes(store) is None


@pytest.mark.parametrize("scenario", [ANONYMOUS, "role_bound_read", SECRET_NAME])
def test_add_refuses_inconclusive_absent_or_unknown_scenarios(
    tmp_path, monkeypatch, no_network, scenario,
):
    store, run_id, _manifest, _grant = committed_run(tmp_path)
    use_home(monkeypatch, tmp_path)

    code, output, error = invoke(
        "runner", "regress", "add", "--run", run_id, "--scenario", scenario, "--name", "x",
    )
    assert (code, output) == (2, "")
    assert error == "Heel runner regression could not be saved safely.\n"
    assert state_bytes(store) is None


def test_add_refuses_unknown_or_nonterminal_source_runs(tmp_path, monkeypatch, no_network):
    store, run_id, _manifest, _grant = committed_run(
        tmp_path, terminal=False, monkeypatch=monkeypatch,
    )
    use_home(monkeypatch, tmp_path)
    for candidate in (run_id, "crun_" + "b" * 32, "../" + SECRET_NAME):
        code, output, error = invoke(
            "runner", "regress", "add", "--run", candidate, "--scenario", OWNERSHIP,
            "--name", "x",
        )
        assert (code, output) == (2, "")
        assert error == "Heel runner regression could not be saved safely.\n"
        assert_quiet(error, candidate)
    assert state_bytes(store) is None


@pytest.mark.parametrize("name", [
    "", " leading", "x" * 65, "line\nbreak", "tab\tname", "quote\"name", "slash/name",
    "éclair", SECRET_NAME + "\x1b[31m",
])
def test_add_rejects_unsafe_names_without_echo(tmp_path, monkeypatch, no_network, name):
    store, run_id, _manifest, _grant = committed_run(tmp_path)
    use_home(monkeypatch, tmp_path)

    code, output, error = invoke(
        "runner", "regress", "add", "--run", run_id, "--scenario", OWNERSHIP, "--name", name,
    )
    assert (code, output) == (2, "")
    assert error == "Heel runner regression could not be saved safely.\n"
    assert state_bytes(store) is None


def _tamper_grant(store: RunnerStore, run_id: str, mutate) -> None:
    path = store.run_path(run_id) / "grant.json"
    grant = json.loads(path.read_bytes())
    mutate(grant)
    # Re-digest so only the cross-artifact binding (not the grant digest) can refuse it.
    unsigned = {
        key: value for key, value in grant.items()
        if key not in {"grant_digest", "signing_key_id", "signature_b64"}
    }
    grant["grant_digest"] = canonical_digest(unsigned)
    path.write_bytes(canonical_bytes(grant))


@pytest.mark.parametrize("mutate", [
    lambda grant: grant["environment"].__setitem__("environment_id", "env_999999999"),
    lambda grant: grant["environment"].__setitem__("origin", "https://other.acme.dev"),
    lambda grant: grant["approval"].__setitem__("projection_digest", "e" * 64),
    lambda grant: grant.__setitem__("grant_id", "grant_999999999"),
    lambda grant: grant["runner_binding"].__setitem__("runner_id", "runner_999999999"),
    lambda grant: grant.__setitem__("workspace_id", "ws_999999999"),
])
def test_add_refuses_inconsistent_manifest_grant_or_final_binding(
    tmp_path, monkeypatch, no_network, mutate,
):
    store, run_id, _manifest, _grant = committed_run(tmp_path)
    _tamper_grant(store, run_id, mutate)
    use_home(monkeypatch, tmp_path)

    code, output, error = invoke(
        "runner", "regress", "add", "--run", run_id, "--scenario", OWNERSHIP, "--name", "x",
    )
    assert (code, output) == (2, "")
    assert error == "Heel runner regression could not be saved safely.\n"
    assert state_bytes(store) is None


def test_add_refuses_a_substituted_grant_even_when_local_run_state_agrees(
    tmp_path, monkeypatch, no_network,
):
    store, run_id, _manifest, _grant = committed_run(tmp_path)
    # A self-consistent grant + unsigned local state rewrite: only the signed finals disagree.
    _tamper_grant(
        store, run_id, lambda grant: grant.__setitem__("grant_id", "grant_999999999"),
    )
    substituted = store.load_run_grant(run_id)
    state_path = store.run_path(run_id) / "state.json"
    state = json.loads(state_path.read_bytes())
    state.update(grant_id=substituted["grant_id"], grant_digest=substituted["grant_digest"])
    state_path.write_bytes(canonical_bytes(state))
    assert store.load_run(run_id)["grant_digest"] == substituted["grant_digest"]
    use_home(monkeypatch, tmp_path)

    code, output, error = invoke(
        "runner", "regress", "add", "--run", run_id, "--scenario", OWNERSHIP, "--name", "x",
    )
    assert (code, output) == (2, "")
    assert error == "Heel runner regression could not be saved safely.\n"
    assert state_bytes(store) is None


def test_derivation_never_trusts_a_route_match_without_the_source_manifest(tmp_path):
    store, run_id, manifest, _grant = committed_run(tmp_path)
    # Remove the stored manifest: the route in the finals alone must not establish context.
    manifest_path = (
        store.root / "runner" / "contexts" / store.namespace / "manifests"
        / f"{manifest['manifest_digest']}.json"
    )
    manifest_path.unlink()
    with pytest.raises((RunnerStoreError, ValueError)):
        derive_saved_regression(
            store, run_id=run_id, scenario_id=OWNERSHIP, name="x", now_ms=5_000,
        )


def _seed(store: RunnerStore, records: list[dict]) -> None:
    from heel.runner.store import _write_json

    with store._transaction(exclusive=True) as context_fd:
        envelope = store._envelope(
            context_fd, "heel.runner-saved-regressions.v1", "regressions", records,
        )
        _write_json(context_fd, "regressions.json", envelope)


def _synthetic_records(template: dict, count: int) -> list[dict]:
    records = []
    for index in range(count):
        source = "crun_" + f"{index:032x}"
        records.append({
            **template,
            "source_run_id": source,
            "regression_id": regression_id_for(source, template["scenario_id"]),
            "name": f"seeded {index}",
        })
    return sorted(records, key=lambda item: item["regression_id"])


def test_saved_regressions_are_bounded_and_full_store_is_unchanged(
    tmp_path, monkeypatch, no_network,
):
    store, run_id, _manifest, _grant = committed_run(tmp_path)
    template = derive_saved_regression(
        store, run_id=run_id, scenario_id=OWNERSHIP, name="template", now_ms=5_000,
    )
    _seed(store, _synthetic_records(template, MAX_SAVED_REGRESSIONS))
    assert len(store.list_saved_regressions()) == MAX_SAVED_REGRESSIONS == 100
    before = state_bytes(store)
    use_home(monkeypatch, tmp_path)

    code, output, error = invoke(
        "runner", "regress", "add", "--run", run_id, "--scenario", OWNERSHIP, "--name", "x",
    )
    assert (code, output) == (2, "")
    assert error == "Heel runner regression could not be saved safely.\n"
    assert state_bytes(store) == before


def test_saved_regressions_are_bound_to_the_store_context(tmp_path, monkeypatch, no_network):
    store, run_id, _manifest, _grant = committed_run(tmp_path)
    store.add_saved_regression(run_id=run_id, scenario_id=OWNERSHIP, name="x", now_ms=5_000)
    copied = state_bytes(store)

    other, _identity, _signer = bound_store(
        tmp_path / "other", selected_context=context("env_987654321"),
    )
    target = regressions_file(other)
    target.write_bytes(copied)
    os.chmod(target, 0o600)
    with pytest.raises(RunnerStoreError):
        other.list_saved_regressions()

    monkeypatch.setenv("HEEL_HOME", str(tmp_path / "other" / "heel-home"))
    code, output, error = invoke("runner", "regress", "list")
    assert (code, output) == (2, "")
    assert error == "Heel runner regressions are unavailable.\n"
    assert target.read_bytes() == copied


def test_tampered_saved_record_fails_closed(tmp_path, monkeypatch, no_network):
    store, run_id, _manifest, _grant = committed_run(tmp_path)
    record, _created = store.add_saved_regression(
        run_id=run_id, scenario_id=OWNERSHIP, name="x", now_ms=5_000,
    )
    for field, value in (
        ("regression_id", "rreg_" + "0" * 24),
        ("expected_outcome", "observed"),
        ("runner_key_id", "k" * 16),
        ("workspace_id", "ws_000000000"),
    ):
        _seed(store, [{**record, field: value}])
        with pytest.raises(RunnerStoreError):
            store.list_saved_regressions()


def test_symlinked_regression_state_is_refused(tmp_path, monkeypatch, no_network):
    store, run_id, _manifest, _grant = committed_run(tmp_path)
    decoy = tmp_path / "decoy.json"
    decoy.write_bytes(b"{}")
    regressions_file(store).symlink_to(decoy)
    use_home(monkeypatch, tmp_path)

    code, output, error = invoke(
        "runner", "regress", "add", "--run", run_id, "--scenario", OWNERSHIP, "--name", "x",
    )
    assert (code, output) == (2, "")
    assert decoy.read_bytes() == b"{}"
    code, output, error = invoke("runner", "regress", "list")
    assert (code, output, error) == (2, "", "Heel runner regressions are unavailable.\n")


def test_failed_atomic_write_leaves_prior_state_intact(tmp_path, monkeypatch, no_network):
    import heel.runner.store as store_module

    store, run_id, _manifest, _grant = committed_run(tmp_path)
    template = derive_saved_regression(
        store, run_id=run_id, scenario_id=OWNERSHIP, name="template", now_ms=5_000,
    )
    _seed(store, _synthetic_records(template, 1))
    before = state_bytes(store)

    def crash_on_replace(*_args, **_kwargs):
        raise OSError("simulated crash before publish")

    monkeypatch.setattr(store_module.os, "replace", crash_on_replace)
    with pytest.raises(OSError):
        store.add_saved_regression(run_id=run_id, scenario_id=OWNERSHIP, name="x", now_ms=5_000)
    monkeypatch.undo()
    assert state_bytes(store) == before
    directory = regressions_file(store).parent
    assert not [name for name in os.listdir(directory) if name.startswith(".regressions.json.")]


def test_list_on_a_fresh_bound_store_is_empty(tmp_path, monkeypatch, no_network):
    bound_store(tmp_path)
    use_home(monkeypatch, tmp_path)
    code, output, error = invoke("runner", "regress", "list")
    assert (code, error) == (0, "")
    assert json.loads(output) == {
        "regression_count": 0, "regressions": [], "result_count": 0, "results": [],
    }


def test_saved_definition_is_data_with_no_authority_fields(tmp_path):
    store, run_id, _manifest, grant = committed_run(tmp_path)
    record, _ = store.add_saved_regression(
        run_id=run_id, scenario_id=OWNERSHIP, name="x", now_ms=5_000,
    )
    serialized = json.dumps(record)
    for forbidden in (
        "signature_b64", "grant_nonce", "credential_handle", "fixture_id", "auth_profile",
        grant["signature_b64"], grant["grant_nonce"],
    ):
        assert forbidden not in serialized
    assert copy.deepcopy(record) == store.list_saved_regressions()[0]
