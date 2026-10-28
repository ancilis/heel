from __future__ import annotations

import base64
import copy
import hashlib
import os
import shutil
from types import SimpleNamespace
import threading

import pytest

from heel.crypto import SigningAuthority
from heel.canary_contracts import (
    CANARY_FINDINGS_SCHEMA, DISCLOSURE_PERMIT_SCHEMA, canonical_bytes,
    canonical_digest, validate_operational_run,
)
from heel.runner.control_client import _RunGuard, RunnerControlClient
from heel.runner.coordinator import RunnerCoordinator, RunnerExecutionAdapter
from heel.runner.http_transport import CancellationToken
from heel.runner.execution import (
    ExecutionBundle, ExecutionGate, UnactivatedExecution, ValidatedExecutionBundle,
)
from heel.runner.service import ClaimLease, RunnerService
from heel.runner.store import RunnerStore, RunnerStoreError
from heel.runner.runtime import (
    PendingResultReplayAuthority, RunnerRuntimeConflict, RunnerRuntimeState,
)
import heel.runner.store as runner_store_module
from tests.test_runner_stop import (
    BlockingExecutor, LocalCanaryExecutor, ScriptedTransport, StaticVault,
    StopCoordinator, active_gate, compiled_pair, signed_grant,
)


def _nonce(byte: bytes) -> str:
    return base64.b64encode(byte * 32).decode("ascii")


def _control_runtime(path, identity, signer):
    """Every executable client fixture starts from its durable pairing-v3 cursor."""
    runtime = RunnerRuntimeState(path, identity, signer)
    runtime.install_chain(
        operation="claim", run_id=None, next_nonce_b64=_nonce(b"c"),
        next_sequence=1, generation=0, now_ms=0,
    )
    return runtime


class ScriptedControlTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def post(self, path, *, headers, body):
        self.requests.append((path, dict(headers), body))
        return self.responses.pop(0)


def test_claimed_rollover_receipt_is_discarded_when_registration_fails():
    discarded = []

    class Control:
        def _bind_rollover_receipt_to_store(self, receipt, store):
            del receipt, store
            raise RuntimeError("injected registration fault")

        def _discard_rollover_receipt(self, receipt, store):
            discarded.append((receipt, store))

    coordinator = SimpleNamespace(control=Control(), store=object())
    receipt = object()
    with pytest.raises(RuntimeError, match="injected registration fault"):
        RunnerCoordinator._install_claimed_rollover(coordinator, {"context_binding": {}}, receipt)
    assert discarded == [(receipt, coordinator.store)]


def _gate(
    *, server_time_ms=2_000, generation=7, stop_reason="none", active=True,
    proof_expires_at_ms=20_000,
):
    return {
        "active": active,
        "runner_state": "active",
        "proof_state": "valid",
        "proof_expires_at_ms": proof_expires_at_ms,
        "kill_switch_generation": generation,
        "stop_reason": stop_reason,
        "server_time_ms": server_time_ms,
    }


def _status(
    run_id, *, approval_id="approval_123456789", grant_id="grant_123456789",
    status="running",
):
    return {
        "schema_version": "heel.canary-run-status.v1",
        "run_id": run_id,
        "approval_id": approval_id,
        "grant_id": grant_id,
        "status": status,
        "execution_disposition": "completed" if status == "terminal" else None,
        "error_category": "none",
        "stop_reason": "none",
        "source_event_sequence": 0,
        "quota_state": "reserved",
        "kill_switch_generation": 7,
        "stop_generation": 0,
        "stop_deadline_ms": None,
        "stop_acknowledged_at_ms": None,
        "stop_ack_late": False,
    }


def _phase(projection, signer, phase, *, run_id=None):
    unsigned = {
        key: copy.deepcopy(value) for key, value in projection.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    unsigned["event_sequence"] += 1
    if run_id is not None:
        unsigned["run_id"] = run_id
    unsigned["lifecycle_phase"] = phase
    unsigned["timestamps"]["updated_at_ms"] = 2_000
    if phase in {"running", "stop_requested", "terminal"}:
        unsigned["timestamps"]["started_at_ms"] = 2_000
    if phase == "stop_requested":
        unsigned["stop_reason"] = "cloud_stop"
        unsigned["timestamps"]["stop_requested_at_ms"] = 2_000
    if phase == "terminal":
        unsigned["execution_disposition"] = "completed"
        unsigned["timestamps"]["terminal_at_ms"] = 2_000
    signature = signer.sign(canonical_bytes(unsigned))
    return validate_operational_run({
        **unsigned,
        "projection_digest": canonical_digest(unsigned),
        "signing_key_id": signer.key_id,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    })


def _claim(manifest, projection, grant):
    return {
        "schema_version": "heel.runner-claim-response.v1",
        "run_id": grant["run_id"],
        "approval_projection": copy.deepcopy(projection),
        "grant": copy.deepcopy(grant),
        "chain_states": {
            operation: {
                "next_nonce_b64": _nonce(marker),
                "next_sequence": sequence,
                "generation": 3,
            }
            for operation, marker, sequence in (
                ("heartbeat", b"h", 4),
                ("progress", b"p", 5),
                ("result", b"r", 6),
                ("stop-ack", b"s", 7),
            )
        },
        "gate": _gate(),
    }


def _findings_projection(coordinator, manifest, projection, grant):
    unsigned = {
        "schema_version": CANARY_FINDINGS_SCHEMA,
        "projection_id": "cfp_runner_upload",
        "run_id": grant["run_id"], "grant_id": grant["grant_id"],
        "workspace_id": grant["workspace_id"], "project_id": grant["project_id"],
        "environment_id": grant["environment"]["environment_id"],
        "manifest_digest": manifest["manifest_digest"],
        "approval_projection_digest": projection["projection_digest"],
        "grant_digest": grant["grant_digest"],
        "engine_version": manifest["compiler"]["engine_version"],
        "adapter_versions": sorted({
            item["adapter_version"] for item in manifest["scenarios"]
        }),
        "started_at_ms": 2_000, "finished_at_ms": 2_000,
        "assessment_outcome": "inconclusive", "scenario_results": [],
        "containment_codes": [], "redaction_count": 0,
    }
    return {
        **unsigned,
        "projection_digest": canonical_digest(unsigned),
        "signing_key_id": coordinator.signer.key_id,
        "signature_b64": base64.b64encode(
            coordinator.signer.sign(canonical_bytes(unsigned))
        ).decode("ascii"),
    }


def _permit(
    authority, coordinator, grant, findings, *, issued_at_ms=2_000,
    expires_at_ms=602_000, scenario_count=0, finding_count=0,
):
    projection_bytes = len(canonical_bytes(findings))
    unsigned = {
        "schema_version": DISCLOSURE_PERMIT_SCHEMA,
        "permit_id": "cdp_runner_upload",
        "workspace_id": grant["workspace_id"], "project_id": grant["project_id"],
        "run_id": grant["run_id"], "grant_id": grant["grant_id"],
        "runner_binding": {
            "runner_id": coordinator.identity.runner_id,
            "runner_key_id": coordinator.identity.key_id,
        },
        "projection": {
            "schema_version": findings["schema_version"],
            "projection_digest": findings["projection_digest"],
            "maximum_bytes": projection_bytes,
            "scenario_count": scenario_count, "finding_count": finding_count,
        },
        "approved_by": "user_owner_123", "approved_at_ms": 2_000,
        "issued_at_ms": issued_at_ms, "expires_at_ms": expires_at_ms,
        "permit_nonce": "permit_nonce_runner_upload",
    }
    return {
        **unsigned,
        "permit_digest": canonical_digest(unsigned),
        **authority.sign(canonical_bytes(unsigned)),
    }


def _install_terminal_anchor(coordinator, grant, terminal):
    """Install the closed store authority fixture for coordinator-only tests."""
    anchor = {
        "run_id": grant["run_id"],
        "project_id": grant["project_id"],
        "grant_id": grant["grant_id"],
        "approval_projection_digest": grant["approval"]["projection_digest"],
        "terminal_projection_digest": terminal["projection_digest"],
        "terminal_record_digest": "e" * 64,
        "terminal_at_ms": terminal["timestamps"]["terminal_at_ms"],
        "retention_expires_at_ms": grant["expires_at_ms"],
    }
    coordinator.store._runtime_terminal_anchor = lambda run_id: (
        anchor if run_id == grant["run_id"] else (_ for _ in ()).throw(
            RunnerStoreError("local terminal authority is unavailable")
        )
    )
    # Coordinator-only control tests do not construct an executor-owned terminal
    # queue.  Keep their fixture authority closed while integration tests cover
    # the real signed detach ledger.
    coordinator.store.detach_terminal = lambda run_id, **_kwargs: (
        "a" * 64 if run_id == grant["run_id"] else (_ for _ in ()).throw(
            RunnerStoreError("local terminal authority is unavailable")
        )
    )
    coordinator.store.load_terminal_disclosure_anchor = lambda run_id, **_kwargs: (
        anchor if run_id == grant["run_id"] else (_ for _ in ()).throw(
            RunnerStoreError("local terminal authority is unavailable")
        )
    )
    return anchor


def _coordinator(tmp_path, responses, *, monotonic=lambda: 1.0):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    transport = ScriptedControlTransport(responses(manifest, projection, grant))
    client = RunnerControlClient(
        origin="https://control.example",
        workspace_id=identity.workspace_id,
        runner_id=identity.runner_id,
        signer=signer,
        clock=lambda: 2_000,
        transport=transport,
        nonce_source=lambda key: _nonce(b"c"),
        trusted_disclosure_keys={authority.key_id: authority.public_key},
        runtime=_control_runtime(tmp_path / "runtime.sqlite3", identity, signer),
    )
    coordinator = RunnerCoordinator(
        control=client,
        store=store,
        identity=identity,
        signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        clock_ms=lambda: 2_000,
        monotonic=monotonic,
    )
    return coordinator, client, transport, manifest, projection, grant, authority


def test_startup_finalizes_pruned_compaction_before_other_runtime_recovery(tmp_path, monkeypatch):
    coordinator, client, transport, _manifest, _projection, _grant, authority = _coordinator(
        tmp_path, lambda *_: [],
    )
    calls = []

    def recover(*, runtime):
        calls.append(runtime)
        return 0

    monkeypatch.setattr(coordinator.store, "recover_pruned_compaction_finalizers", recover)
    restarted = RunnerControlClient(
        origin=client.origin, workspace_id=client.workspace_id, runner_id=client.runner_id,
        signer=client.signer, clock=client.clock, transport=transport,
        nonce_source=client.nonce_source, trusted_disclosure_keys={authority.key_id: authority.public_key},
        runtime=client.runtime,
    )
    RunnerCoordinator(
        control=restarted, store=coordinator.store, identity=coordinator.identity,
        signer=coordinator.signer, trusted_grant_keys=coordinator.trusted_grant_keys,
        clock_ms=lambda: 2_000, monotonic=lambda: 1.0,
    )
    assert calls == [restarted.runtime]


def test_first_cloud_context_acquisition_lists_before_binding_a_namespace(tmp_path):
    _bound, identity, signer, _manifest, _projection = compiled_pair(tmp_path / "fixture")
    store = RunnerStore(tmp_path / "unbound")
    authority = SigningAuthority.generate()
    unsigned = {
        "schema_version": "heel.runner-context-binding.v1",
        "binding_id": "rcb_" + "a" * 32,
        "workspace_id": identity.workspace_id,
        "project_id": "prj_123456789",
        "environment": {
            "environment_id": "env_123456789", "origin": "https://staging.acme.dev",
            "environment_class": "staging", "verification_record_digest": "0" * 64,
        },
        "runner_binding": {
            "runner_id": identity.runner_id, "runner_key_id": identity.key_id,
            "public_key_digest": identity.fingerprint,
        },
        "authorization": {"user_id": "owner", "role": "owner"},
        "issued_at_ms": 1, "expires_at_ms": 60_001,
    }
    artifact = {
        **unsigned, "binding_digest": canonical_digest(unsigned),
        **authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(unsigned)),
    }

    calls: list[str] = []

    class Transport:
        def post(self, path, *, headers, body):
            if path.endswith("/contexts/list"):
                assert not store.is_context_bound
                calls.append("list")
                return 200, {"X-Heel-Runner-Next-Nonce": _nonce(b"l")}, {
                    "schema_version": "heel.runner-context-list-result.v1", "server_time_ms": 2_000,
                    "contexts": [{
                        "binding_id": unsigned["binding_id"], "binding_digest": artifact["binding_digest"],
                        "project_id": unsigned["project_id"], "environment_id": unsigned["environment"]["environment_id"],
                        "origin": unsigned["environment"]["origin"], "environment_class": "staging",
                        "verification_record_digest": "0" * 64, "expires_at_ms": 60_001, "claimed": False,
                    }], "has_more": False,
                }
            assert path.endswith(f"/contexts/{unsigned['binding_id']}/claim")
            assert calls == ["list"]
            calls.append("claim")
            return 200, {"X-Heel-Runner-Next-Nonce": _nonce(b"m")}, {
                "schema_version": "heel.runner-context-claim-result.v1", "context_binding": artifact,
                "claimed_at_ms": 2_000,
            }

    control = RunnerControlClient(
        origin="https://control.example", workspace_id=identity.workspace_id,
        runner_id=identity.runner_id, signer=signer, clock=lambda: 2_000,
        transport=Transport(), nonce_source=lambda _chain: _nonce(b"c"),
        trusted_disclosure_keys={authority.key_id: authority.public_key},
        runtime=_control_runtime(tmp_path / "context-runtime.sqlite3", identity, signer),
    )
    coordinator = RunnerCoordinator(
        control=control, store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key}, clock_ms=lambda: 2_000,
    )

    assert coordinator.ensure_runner_context() is True
    assert calls == ["list", "claim"]
    assert store.is_context_bound
    # The coordinator records the actual local signer identity, not a generic
    # Cloud label that would make a resumed binding ambiguous.
    assert store.load_binding()["signer_label"] == identity.key_id


def test_incomplete_cloud_tuple_never_falls_back_to_context_discovery(tmp_path):
    coordinator, _client, transport, _manifest, _projection, _grant, authority = _coordinator(
        tmp_path, lambda _manifest, _projection, _grant: [],
    )
    context = coordinator.store.load_context()
    unsigned = {
        "schema_version": "heel.runner-context-binding.v1",
        "binding_id": "rcb_" + "f" * 32,
        "workspace_id": coordinator.identity.workspace_id,
        "project_id": context.project_id,
        "environment": {
            "environment_id": context.environment_id, "origin": context.origin,
            "environment_class": context.environment_class,
            "verification_record_digest": context.verification_record_digest,
        },
        "runner_binding": {
            "runner_id": coordinator.identity.runner_id,
            "runner_key_id": coordinator.identity.key_id,
            "public_key_digest": coordinator.identity.fingerprint,
        },
        "authorization": {"user_id": "owner", "role": "owner"},
        "issued_at_ms": 1, "expires_at_ms": 60_001,
    }
    artifact = {
        **unsigned, "binding_digest": canonical_digest(unsigned),
        **authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(unsigned)),
    }
    coordinator.store.install_cloud_context_binding(
        artifact, identity=coordinator.identity, signer=coordinator.signer,
        signer_label=coordinator.identity.key_id,
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=2_000,
    )
    with coordinator.store._transaction(exclusive=True) as context_fd:
        os.unlink("cloud-context-provenance.json", dir_fd=context_fd)
        os.fsync(context_fd)

    with pytest.raises(RunnerStoreError, match="cloud context authority is incomplete"):
        coordinator.ensure_runner_context()
    assert transport.requests == []


def test_pending_first_install_rolls_forward_only_from_fresh_singleton_claim(tmp_path, monkeypatch):
    bound, identity, signer, _manifest, _projection = compiled_pair(tmp_path / "fixture")
    context = bound.load_context()
    store = RunnerStore(tmp_path / "fresh")
    authority = SigningAuthority.generate()

    def artifact(binding_id, verification_digest, issued_at, expires_at):
        unsigned = {
            "schema_version": "heel.runner-context-binding.v1", "binding_id": binding_id,
            "workspace_id": identity.workspace_id, "project_id": context.project_id,
            "environment": {"environment_id": context.environment_id, "origin": context.origin,
                            "environment_class": context.environment_class,
                            "verification_record_digest": verification_digest},
            "runner_binding": {"runner_id": identity.runner_id, "runner_key_id": identity.key_id,
                               "public_key_digest": identity.fingerprint},
            "authorization": {"user_id": "owner", "role": "owner"},
            "issued_at_ms": issued_at, "expires_at_ms": expires_at,
        }
        return {**unsigned, "binding_digest": canonical_digest(unsigned),
                **authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(unsigned))}

    old = artifact("rcb_" + "1" * 32, context.verification_record_digest, 1, 60_001)
    new = artifact("rcb_" + "2" * 32, "2" * 64, 2, 120_002)
    original_write = runner_store_module._write_json

    def fail_active(directory_fd, filename, value):
        if filename == "active-context.json":
            raise OSError("injected active selector failure")
        return original_write(directory_fd, filename, value)

    monkeypatch.setattr(runner_store_module, "_write_json", fail_active)
    with pytest.raises(OSError, match="active selector"):
        store.install_cloud_context_binding(
            old, identity=identity, signer=signer, signer_label=identity.key_id,
            trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
        )
    monkeypatch.setattr(runner_store_module, "_write_json", original_write)
    restarted = RunnerStore(tmp_path / "fresh")
    assert not restarted.is_context_bound
    calls: list[str] = []

    class Transport:
        def post(self, path, *, headers, body):
            if path.endswith("/contexts/list"):
                calls.append("list")
                return 200, {"X-Heel-Runner-Next-Nonce": _nonce(b"a")}, {
                    "schema_version": "heel.runner-context-list-result.v1", "server_time_ms": 2,
                    "contexts": [{"binding_id": new["binding_id"], "binding_digest": new["binding_digest"],
                                  "project_id": context.project_id, "environment_id": context.environment_id,
                                  "origin": context.origin, "environment_class": context.environment_class,
                                  "verification_record_digest": "2" * 64, "expires_at_ms": 120_002,
                                  "claimed": False}], "has_more": False,
                }
            calls.append("claim")
            assert path.endswith(f"/contexts/{new['binding_id']}/claim")
            return 200, {"X-Heel-Runner-Next-Nonce": _nonce(b"b")}, {
                "schema_version": "heel.runner-context-claim-result.v1", "context_binding": new,
                "claimed_at_ms": 2,
            }

    control = RunnerControlClient(
        origin="https://control.example", workspace_id=identity.workspace_id, runner_id=identity.runner_id,
        signer=signer, clock=lambda: 2, transport=Transport(), nonce_source=lambda _chain: _nonce(b"c"),
        trusted_disclosure_keys={authority.key_id: authority.public_key},
        runtime=_control_runtime(tmp_path / "recovery-runtime.sqlite3", identity, signer),
    )
    coordinator = RunnerCoordinator(
        control=control, store=restarted, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key}, clock_ms=lambda: 2,
    )
    # The root first-install journal is still old here.  A subsequent Cloud
    # proof-generation rollover can finish its namespaced records but fault
    # before the root active selector is published.  Its signed rollover
    # journal must remain durable until that final root commit.
    def fail_successor_active(directory_fd, filename, value):
        if filename == "active-context.json":
            raise OSError("injected successor active selector failure")
        return original_write(directory_fd, filename, value)

    monkeypatch.setattr(runner_store_module, "_write_json", fail_successor_active)
    with pytest.raises(OSError, match="successor active selector"):
        coordinator.ensure_runner_context()
    monkeypatch.setattr(runner_store_module, "_write_json", original_write)
    assert not restarted.is_context_bound
    restarted._namespace = context.namespace
    with restarted._transaction(exclusive=False, allow_rollover_journal=True) as context_fd:
        assert runner_store_module._read_json(context_fd, "context-rollover.json", None) is not None
    restarted._namespace = None

    def recovery_coordinator(directory, token):
        recovery_store = RunnerStore(directory)
        recovery_control = RunnerControlClient(
            origin="https://control.example", workspace_id=identity.workspace_id, runner_id=identity.runner_id,
            signer=signer, clock=lambda: 2, transport=Transport(), nonce_source=lambda _chain: _nonce(token),
            trusted_disclosure_keys={authority.key_id: authority.public_key},
            runtime=_control_runtime(directory / "runtime.sqlite3", identity, signer),
        )
        return recovery_store, RunnerCoordinator(
            control=recovery_control, store=recovery_store, identity=identity, signer=signer,
            trusted_grant_keys={authority.key_id: authority.public_key}, clock_ms=lambda: 2,
        )

    # Neither a tampered signed journal nor a durable local binding for a third
    # context is recoverable.  Both retain the exact root old intent, proving
    # that recovery cannot adopt arbitrary orphaned namespace state.
    tampered = tmp_path / "tampered"
    shutil.copytree(tmp_path / "fresh", tampered)
    tampered_store = RunnerStore(tampered)
    tampered_store._namespace = context.namespace
    with tampered_store._transaction(exclusive=True, allow_rollover_journal=True) as context_fd:
        journal = runner_store_module._read_json(context_fd, "context-rollover.json", None)
        journal["signature_b64"] = "A" * 88
        runner_store_module._write_json(context_fd, "context-rollover.json", journal)
    _tampered_store, tampered_coordinator = recovery_coordinator(tampered, b"e")
    with pytest.raises(RunnerStoreError, match="invalid cloud context rollover journal"):
        tampered_coordinator.ensure_runner_context()

    mixed = tmp_path / "mixed"
    shutil.copytree(tmp_path / "fresh", mixed)
    mixed_store = RunnerStore(mixed)
    mixed_store._namespace = context.namespace
    with mixed_store._transaction(exclusive=True, allow_rollover_journal=True) as context_fd:
        local = mixed_store._binding_locked(context_fd)
        local["context"] = {**local["context"], "verification_record_digest": "3" * 64}
        runner_store_module._write_json(context_fd, "binding.json", local)
    _mixed_store, mixed_coordinator = recovery_coordinator(mixed, b"f")
    with pytest.raises(RunnerStoreError, match="installation recovery state is inconsistent"):
        mixed_coordinator.ensure_runner_context()

    # A recovery can itself fault at the root selector after it has made every
    # B namespaced record durable.  The root A intent still needs the signed
    # A→B journal until its final selector write commits; otherwise this second
    # crash strands an unbound runner whose next B claim cannot be correlated.
    recovery_store, recovery = recovery_coordinator(tmp_path / "fresh", b"d")
    monkeypatch.setattr(runner_store_module, "_write_json", fail_successor_active)
    with pytest.raises(OSError, match="successor active selector"):
        recovery.ensure_runner_context()
    monkeypatch.setattr(runner_store_module, "_write_json", original_write)
    assert not recovery_store.is_context_bound
    recovery_store._namespace = context.namespace
    with recovery_store._transaction(exclusive=False, allow_rollover_journal=True) as context_fd:
        assert runner_store_module._read_json(context_fd, "context-rollover.json", None) is not None
    recovery_store._namespace = None

    recovered_store, recovered = recovery_coordinator(tmp_path / "fresh", b"g")
    assert recovered.ensure_runner_context() is True
    # Recovery completes the locally signed A→B journal before asking Cloud.
    # The sole later poll observes B exactly; tampered/mixed copies never poll.
    assert calls == ["list", "claim", "list"]
    assert recovered_store.load_context().verification_record_digest == "2" * 64
    assert recovered_store.load_cloud_context_binding()["binding_id"] == new["binding_id"]
    with recovered_store._open_runner(create=False) as runner_fd:
        assert runner_fd is not None
        assert runner_store_module._read_json(runner_fd, "context-install.json", None) is None
    recovered_store._namespace = context.namespace
    with recovered_store._transaction(exclusive=False, allow_rollover_journal=True) as context_fd:
        assert runner_store_module._read_json(context_fd, "context-rollover.json", None) is None
    recovered_store._namespace = None


def test_failed_cloud_install_provenance_never_downgrades_to_static_context(tmp_path, monkeypatch):
    store, identity, signer, _manifest, _projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    unsigned = {
        "schema_version": "heel.runner-context-binding.v1", "binding_id": "rcb_" + "d" * 32,
        "workspace_id": identity.workspace_id, "project_id": store.load_context().project_id,
        "environment": {
            "environment_id": store.load_context().environment_id,
            "origin": store.load_context().origin,
            "environment_class": store.load_context().environment_class,
            "verification_record_digest": store.load_context().verification_record_digest,
        },
        "runner_binding": {"runner_id": identity.runner_id, "runner_key_id": identity.key_id, "public_key_digest": identity.fingerprint},
        "authorization": {"user_id": "owner", "role": "owner"}, "issued_at_ms": 1, "expires_at_ms": 60_001,
    }
    artifact = {**unsigned, "binding_digest": canonical_digest(unsigned)}
    artifact.update(authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(unsigned)))
    original_write = runner_store_module._write_json

    def fail_sidecar(directory_fd, filename, value):
        if filename == "cloud-context-binding.json":
            raise OSError("injected sidecar failure")
        return original_write(directory_fd, filename, value)

    monkeypatch.setattr(runner_store_module, "_write_json", fail_sidecar)
    with pytest.raises(OSError, match="injected sidecar failure"):
        store.install_cloud_context_binding(
            artifact, identity=identity, signer=signer, signer_label="test-signer",
            trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=2_000,
        )
    monkeypatch.setattr(runner_store_module, "_write_json", original_write)

    calls = []

    class Transport:
        def post(self, path, *, headers, body):
            assert path.endswith("/contexts/list")
            calls.append(path)
            return 200, {"X-Heel-Runner-Next-Nonce": _nonce(b"p")}, {
                "schema_version": "heel.runner-context-list-result.v1", "server_time_ms": 2_000,
                "contexts": [], "has_more": False,
            }

    control = RunnerControlClient(
        origin="https://control.example", workspace_id=identity.workspace_id,
        runner_id=identity.runner_id, signer=signer, clock=lambda: 2_000,
        transport=Transport(), nonce_source=lambda _chain: _nonce(b"c"),
        trusted_disclosure_keys={authority.key_id: authority.public_key},
        runtime=_control_runtime(tmp_path / "pending-runtime.sqlite3", identity, signer),
    )
    coordinator = RunnerCoordinator(
        control=control, store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key}, clock_ms=lambda: 2_000,
    )

    assert coordinator.ensure_runner_context() is False
    assert len(calls) == 1


def test_coordinator_rolls_forward_only_from_one_fresh_list_and_matching_claim(tmp_path):
    store, identity, signer, _manifest, _projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    context = store.load_context()

    def artifact(binding_id, verification_digest, issued_at, expires_at):
        unsigned = {
            "schema_version": "heel.runner-context-binding.v1", "binding_id": binding_id,
            "workspace_id": identity.workspace_id, "project_id": context.project_id,
            "environment": {
                "environment_id": context.environment_id, "origin": context.origin,
                "environment_class": context.environment_class,
                "verification_record_digest": verification_digest,
            },
            "runner_binding": {
                "runner_id": identity.runner_id, "runner_key_id": identity.key_id,
                "public_key_digest": identity.fingerprint,
            },
            "authorization": {"user_id": "owner", "role": "owner"},
            "issued_at_ms": issued_at, "expires_at_ms": expires_at,
        }
        return {
            **unsigned, "binding_digest": canonical_digest(unsigned),
            **authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(unsigned)),
        }

    old = artifact("rcb_" + "7" * 32, context.verification_record_digest, 1, 60_001)
    new = artifact("rcb_" + "8" * 32, "8" * 64, 2, 120_003)
    store.install_cloud_context_binding(
        old, identity=identity, signer=signer, signer_label="test-signer",
        trusted_cloud_keys={authority.key_id: authority.public_key}, now_ms=1,
    )
    calls = []

    class Transport:
        def post(self, path, *, headers, body):
            if path.endswith("/contexts/list"):
                calls.append("list")
                return 200, {"X-Heel-Runner-Next-Nonce": _nonce(b"r")}, {
                    "schema_version": "heel.runner-context-list-result.v1", "server_time_ms": 2,
                    "contexts": [{
                        "binding_id": new["binding_id"], "binding_digest": new["binding_digest"],
                        "project_id": context.project_id, "environment_id": context.environment_id,
                        "origin": context.origin, "environment_class": context.environment_class,
                        "verification_record_digest": "8" * 64, "expires_at_ms": 120_003,
                        "claimed": False,
                    }], "has_more": False,
                }
            assert path.endswith(f"/contexts/{new['binding_id']}/claim")
            calls.append("claim")
            return 200, {"X-Heel-Runner-Next-Nonce": _nonce(b"s")}, {
                "schema_version": "heel.runner-context-claim-result.v1",
                "context_binding": new, "claimed_at_ms": 2,
            }

    control = RunnerControlClient(
        origin="https://control.example", workspace_id=identity.workspace_id,
        runner_id=identity.runner_id, signer=signer, clock=lambda: 2,
        transport=Transport(), nonce_source=lambda _chain: _nonce(b"q"),
        trusted_disclosure_keys={authority.key_id: authority.public_key},
        runtime=_control_runtime(tmp_path / "rollover-runtime.sqlite3", identity, signer),
    )
    coordinator = RunnerCoordinator(
        control=control, store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key}, clock_ms=lambda: 2,
    )

    assert coordinator.ensure_runner_context() is True
    assert calls == ["list", "claim"]
    assert store.load_context().verification_record_digest == "8" * 64
    assert store.load_cloud_context_binding()["binding_id"] == new["binding_id"]


def test_claim_decodes_closed_bundle_installs_all_run_chains_and_builds_safe_projection(tmp_path):
    coordinator, client, transport, manifest, projection, grant, _ = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"z")},
             _gate(server_time_ms=2_001)),
        ],
    )

    lease = coordinator.claim()
    assert lease is not None
    assert lease.run_id == grant["run_id"]
    assert lease.bundle == ExecutionBundle(manifest, projection, grant)
    assert lease.operational_projection["lifecycle_phase"] == "claimed"
    assert lease.operational_projection["counters"] == {
        "requests_started": 0,
        "requests_completed": 0,
        "response_bytes_read": 0,
        "actions_contained": 0,
        "retries_used": 0,
        "remaining_requests": manifest["budgets"]["maximum_requests"],
        "remaining_wall_ms": manifest["budgets"]["wall_timeout_ms"],
    }
    active = client.runtime.load_active_run_controls()
    assert len(active) == 1
    assert active[0].run_id == grant["run_id"]
    assert set(active[0].chains) == {"heartbeat", "progress", "result", "stop-ack"}
    restarted = RunnerControlClient(
        origin=client.origin, workspace_id=client.workspace_id, runner_id=client.runner_id,
        signer=client.signer, clock=client.clock, transport=transport,
        nonce_source=client.nonce_source, trusted_disclosure_keys=client._trusted_disclosure_keys,
        runtime=client.runtime,
    )
    assert restarted._tracked_runs == {grant["run_id"]}
    assert grant["run_id"] in restarted._run_guards

    gate = coordinator.heartbeat(lease.run_id, lease.operational_projection)
    assert gate == ExecutionGate(**_gate(server_time_ms=2_001))
    assert transport.requests[-1][1]["X-Heel-Runner-Nonce"] == _nonce(b"h")
    assert transport.requests[-1][1]["X-Heel-Runner-Sequence"] == "4"
    active = client.runtime.load_active_run_controls()
    assert active[0].revision == 2 and active[0].gate["server_time_ms"] == 2_001


def test_restart_coordinator_rehydrates_active_binding_but_requires_fresh_heartbeat(tmp_path):
    coordinator, client, transport, _manifest, projection, grant, authority = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"z")},
             _gate(server_time_ms=2_001)),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None

    restarted_control = RunnerControlClient(
        origin=client.origin, workspace_id=client.workspace_id, runner_id=client.runner_id,
        signer=client.signer, clock=client.clock, transport=transport,
        nonce_source=client.nonce_source, trusted_disclosure_keys=client._trusted_disclosure_keys,
        runtime=client.runtime,
    )
    restarted = RunnerCoordinator(
        control=restarted_control, store=coordinator.store,
        identity=coordinator.identity, signer=coordinator.signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        clock_ms=lambda: 2_000, monotonic=lambda: 1.0,
    )

    assert restarted._bindings[grant["run_id"]] == (
        grant["grant_id"], projection["projection_id"], projection["projection_digest"],
    )
    assert restarted._gates[grant["run_id"]] == ExecutionGate(**_gate())
    with pytest.raises(ValueError, match="active runner claim is required"):
        restarted.execution_gate(grant["run_id"])

    gate = restarted.heartbeat(lease.run_id, lease.operational_projection)
    assert gate == ExecutionGate(**_gate(server_time_ms=2_001))
    assert restarted.execution_gate(grant["run_id"]) == gate


def test_concurrent_heartbeats_publish_the_latest_durable_stop_gate(tmp_path):
    coordinator, client, _transport, _manifest, _projection, grant, _authority = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None

    first_entered = threading.Event()
    release_first = threading.Event()
    first_published = threading.Event()
    call_lock = threading.Lock()
    call_count = [0]

    class GateMap(dict):
        def __setitem__(self, key, value):
            super().__setitem__(key, value)
            if value.server_time_ms == 2_001:
                first_published.set()

    class Transport:
        def post(self, path, *, headers, body):
            del path, headers, body
            with call_lock:
                call_count[0] += 1
                ordinal = call_count[0]
            if ordinal == 1:
                first_entered.set()
                assert release_first.wait(1)
                return 200, {"X-Heel-Runner-Next-Nonce": _nonce(b"a")}, _gate(
                    server_time_ms=2_001,
                )
            assert first_published.wait(1)
            return 200, {"X-Heel-Runner-Next-Nonce": _nonce(b"b")}, _gate(
                server_time_ms=2_002, generation=8, active=False,
                stop_reason="cloud_stop",
            )

    client.transport = Transport()
    coordinator._gates = GateMap(coordinator._gates)
    results = []
    failures = []

    def heartbeat() -> None:
        try:
            results.append(coordinator.heartbeat(lease.run_id, lease.operational_projection))
        except BaseException as exc:  # test records both racing outcomes
            failures.append(exc)

    first = threading.Thread(target=heartbeat)
    second = threading.Thread(target=heartbeat)
    first.start()
    assert first_entered.wait(1)
    second.start()
    release_first.set()
    first.join(2)
    second.join(2)

    assert not first.is_alive() and not second.is_alive()
    assert failures == []
    assert [gate.server_time_ms for gate in results] == [2_001, 2_002]
    assert coordinator._gates[lease.run_id] == ExecutionGate(**_gate(
        server_time_ms=2_002, generation=8, active=False, stop_reason="cloud_stop",
    ))
    active = client.runtime.load_active_run_controls()
    assert active[0].revision == 3
    assert active[0].gate == _gate(
        server_time_ms=2_002, generation=8, active=False, stop_reason="cloud_stop",
    )
    with pytest.raises(ValueError, match="denies execution"):
        coordinator.execution_gate(lease.run_id)


def test_restart_replays_staged_heartbeat_with_the_original_signed_request(tmp_path, monkeypatch):
    coordinator, client, transport, _manifest, _projection, grant, _authority = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"z")},
             _gate(server_time_ms=2_001)),
            # The control plane's immutable receipt returns this exact response
            # when the runner replays after losing the first response locally.
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"z")},
             _gate(server_time_ms=2_001)),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None

    real_commit = client.runtime.commit_call
    monkeypatch.setattr(client.runtime, "commit_call", lambda *args, **kwargs: (
        (_ for _ in ()).throw(RuntimeError("lost response before runtime commit"))
    ))
    with pytest.raises(RuntimeError, match="lost response"):
        client._heartbeat_closed(lease.run_id, lease.operational_projection)
    staged_path, staged_headers, staged_body = transport.requests[-1]
    staged = client.runtime.load_pending_calls()
    assert len(staged) == 1 and staged[0].request_operation == "heartbeat"
    monkeypatch.setattr(client.runtime, "commit_call", real_commit)

    restarted = RunnerControlClient(
        origin=client.origin, workspace_id=client.workspace_id, runner_id=client.runner_id,
        signer=client.signer, clock=client.clock, transport=transport,
        nonce_source=client.nonce_source, trusted_disclosure_keys=client._trusted_disclosure_keys,
        runtime=client.runtime,
    )
    with pytest.raises(ValueError, match="pending replay"):
        restarted._heartbeat_closed(lease.run_id, lease.operational_projection)

    outcomes = restarted.replay_all_pending(now_ms=2_000)
    assert [(item.request_operation, item.status) for item in outcomes] == [("heartbeat", 200)]
    assert transport.requests[-1] == (staged_path, staged_headers, staged_body)
    assert restarted.runtime.load_pending_calls() == ()
    active = restarted.runtime.load_active_run_controls()
    assert active[0].revision == 2
    assert active[0].gate["server_time_ms"] == 2_001


def test_restart_replays_staged_progress_with_the_original_signed_request(tmp_path, monkeypatch):
    coordinator, client, transport, _manifest, projection, grant, _authority = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"z")},
             _status(grant["run_id"], approval_id=projection["projection_id"], grant_id=grant["grant_id"])),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"z")},
             _status(grant["run_id"], approval_id=projection["projection_id"], grant_id=grant["grant_id"])),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None

    real_commit = client.runtime.commit_call
    monkeypatch.setattr(client.runtime, "commit_call", lambda *args, **kwargs: (
        (_ for _ in ()).throw(RuntimeError("lost response before runtime commit"))
    ))
    with pytest.raises(RuntimeError, match="lost response"):
        client._progress_closed(lease.run_id, lease.operational_projection)
    staged_request = transport.requests[-1]
    monkeypatch.setattr(client.runtime, "commit_call", real_commit)

    restarted = RunnerControlClient(
        origin=client.origin, workspace_id=client.workspace_id, runner_id=client.runner_id,
        signer=client.signer, clock=client.clock, transport=transport,
        nonce_source=client.nonce_source, trusted_disclosure_keys=client._trusted_disclosure_keys,
        runtime=client.runtime,
    )
    assert [(item.request_operation, item.status) for item in restarted.replay_all_pending(now_ms=2_000)] == [
        ("progress", 200),
    ]
    assert transport.requests[-1] == staged_request
    assert restarted.runtime.load_pending_calls() == ()


def test_restart_replays_staged_stop_ack_with_the_original_signed_request(tmp_path, monkeypatch):
    coordinator, client, transport, _manifest, _projection, _grant, _authority = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"z")},
             {"accepted": True, "deadline_met": True, "late": False}),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"z")},
             {"accepted": True, "deadline_met": True, "late": False}),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None
    stopped = _phase(lease.operational_projection, coordinator.signer, "stop_requested")
    stopped = _phase(stopped, coordinator.signer, "stop_requested")
    stopped_unsigned = {
        key: copy.deepcopy(value) for key, value in stopped.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    stopped_unsigned["timestamps"]["stop_acknowledged_at_ms"] = 2_000
    stopped = validate_operational_run({
        **stopped_unsigned,
        "projection_digest": canonical_digest(stopped_unsigned),
        "signing_key_id": coordinator.signer.key_id,
        "signature_b64": base64.b64encode(
            coordinator.signer.sign(canonical_bytes(stopped_unsigned))
        ).decode("ascii"),
    })

    real_commit = client.runtime.commit_call
    monkeypatch.setattr(client.runtime, "commit_call", lambda *args, **kwargs: (
        (_ for _ in ()).throw(RuntimeError("lost response before runtime commit"))
    ))
    with pytest.raises(RuntimeError, match="lost response"):
        client._stop_ack_closed(lease.run_id, stopped)
    staged_request = transport.requests[-1]
    monkeypatch.setattr(client.runtime, "commit_call", real_commit)

    restarted = RunnerControlClient(
        origin=client.origin, workspace_id=client.workspace_id, runner_id=client.runner_id,
        signer=client.signer, clock=client.clock, transport=transport,
        nonce_source=client.nonce_source, trusted_disclosure_keys=client._trusted_disclosure_keys,
        runtime=client.runtime,
    )
    assert [(item.request_operation, item.status) for item in restarted.replay_all_pending(now_ms=2_000)] == [
        ("stop-ack", 200),
    ]
    assert transport.requests[-1] == staged_request
    assert restarted.runtime.load_pending_calls() == ()


def test_client_only_restart_never_replays_a_pending_terminal_result(tmp_path):
    coordinator, client, transport, _manifest, _projection, grant, _authority = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"x")}, {"malformed": True}),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None
    terminal = _phase(lease.operational_projection, coordinator.signer, "terminal")
    _install_terminal_anchor(coordinator, grant, terminal)

    with pytest.raises(ValueError, match="invalid runner result response"):
        coordinator.result(grant["run_id"], terminal)
    (pending,) = client.runtime.load_pending_calls()
    assert pending.request_operation == "result"
    before = len(transport.requests)

    restarted = RunnerControlClient(
        origin=client.origin, workspace_id=client.workspace_id, runner_id=client.runner_id,
        signer=client.signer, clock=client.clock, transport=transport,
        nonce_source=client.nonce_source, trusted_disclosure_keys=client._trusted_disclosure_keys,
        runtime=client.runtime,
    )
    with pytest.raises(RunnerRuntimeConflict, match="terminal result recovery is required"):
        restarted.replay_pending_call(pending, now_ms=2_000)
    assert len(transport.requests) == before


def test_store_verifier_replays_only_the_detached_pending_terminal_request(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path / "store")
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    terminal = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    ).operational_projection
    transport = ScriptedControlTransport([
        (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")}, _claim(manifest, projection, grant)),
        (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"x")}, {"malformed": True}),
        (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"x")}, _status(
            grant["run_id"], approval_id=projection["projection_id"], status="terminal",
        )),
    ])
    client = RunnerControlClient(
        origin="https://control.example", workspace_id=identity.workspace_id,
        runner_id=identity.runner_id, signer=signer, clock=lambda: 2_000,
        transport=transport, nonce_source=lambda _key: _nonce(b"c"),
        trusted_disclosure_keys={authority.key_id: authority.public_key},
        runtime=_control_runtime(tmp_path / "runtime.sqlite3", identity, signer),
    )
    assert client._claim_closed()["run_id"] == grant["run_id"]

    def prepare() -> None:
        anchor = store._runtime_terminal_anchor(grant["run_id"])
        state = client._register_runtime_local_terminal(anchor)
        store.detach_terminal(
            grant["run_id"], runtime=client.runtime,
            expected_local_state_digest=state.state_digest, now_ms=2_000,
        )

    with pytest.raises(ValueError, match="invalid runner result response"):
        client._result_closed(grant["run_id"], terminal, before_transport=prepare)
    (pending,) = client.runtime.load_pending_calls()
    staged_request = transport.requests[-1]
    verifier = store.pending_result_replay_verifier(client.runtime)
    issued = verifier.authorize_pending_result_replay(pending, now_ms=2_000)
    (active,) = client.runtime.load_active_run_controls()
    local = client.runtime.load_terminal_state(grant["run_id"])
    assert local is not None
    detached_path = store.run_path(grant["run_id"]).parent / (
        "detached-" + store._run_hash(grant["run_id"]) + ".json"
    )
    detached_bytes = detached_path.read_bytes()
    detached_path.write_bytes(b"{}")
    with pytest.raises(RunnerStoreError, match="invalid local run authority record"):
        verifier.consume(issued, pending=pending, now_ms=2_000)
    detached_path.write_bytes(detached_bytes)
    verifier.consume(issued, pending=pending, now_ms=2_000)
    with pytest.raises(RunnerStoreError, match="pending terminal replay authority"):
        verifier.consume(issued, pending=pending, now_ms=2_000)
    forged = PendingResultReplayAuthority(
        call_id=issued.call_id, pending_state_digest=issued.pending_state_digest,
        run_id=issued.run_id, body_sha256=issued.body_sha256,
        active_state_digest=issued.active_state_digest,
        runtime_terminal_state_digest=issued.runtime_terminal_state_digest,
        terminal_record_digest=issued.terminal_record_digest,
        detached_record_digest=issued.detached_record_digest,
        terminal_projection_digest=issued.terminal_projection_digest,
        retention_expires_at_ms=issued.retention_expires_at_ms, _issuer=object(),
    )
    with pytest.raises(RunnerStoreError, match="pending terminal replay authority"):
        verifier.consume(forged, pending=pending, now_ms=2_000)
    assert transport.requests[-1] == staged_request

    restarted = RunnerControlClient(
        origin=client.origin, workspace_id=identity.workspace_id, runner_id=identity.runner_id,
        signer=signer, clock=lambda: 2_000, transport=transport,
        nonce_source=client.nonce_source, trusted_disclosure_keys=client._trusted_disclosure_keys,
        runtime=client.runtime,
    )
    recovered = RunnerCoordinator(
        control=restarted, store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        clock_ms=lambda: 2_000, monotonic=lambda: 1.0,
    )

    assert transport.requests[-1] == staged_request
    assert restarted.runtime.load_pending_calls() == ()
    assert restarted.runtime.load_active_run_controls() == ()
    assert recovered._gates == {}
    assert recovered._gate_receipts == {}
    assert recovered._bindings == {}


def test_restart_stages_a_detached_local_terminal_before_replaying_control(tmp_path):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path / "store")
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    terminal = LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    ).operational_projection
    transport = ScriptedControlTransport([
        (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")}, _claim(manifest, projection, grant)),
        (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"x")}, _status(
            grant["run_id"], approval_id=projection["projection_id"], status="terminal",
        )),
    ])
    client = RunnerControlClient(
        origin="https://control.example", workspace_id=identity.workspace_id,
        runner_id=identity.runner_id, signer=signer, clock=lambda: 2_000,
        transport=transport, nonce_source=lambda _key: _nonce(b"c"),
        trusted_disclosure_keys={authority.key_id: authority.public_key},
        runtime=_control_runtime(tmp_path / "runtime.sqlite3", identity, signer),
    )
    assert client._claim_closed()["run_id"] == grant["run_id"]
    anchor = store._runtime_terminal_anchor(grant["run_id"])
    local = client._register_runtime_local_terminal(anchor)
    store.detach_terminal(
        grant["run_id"], runtime=client.runtime,
        expected_local_state_digest=local.state_digest, now_ms=2_000,
    )
    assert client.runtime.load_pending_calls() == ()

    restarted = RunnerControlClient(
        origin=client.origin, workspace_id=client.workspace_id, runner_id=client.runner_id,
        signer=signer, clock=lambda: 2_000, transport=transport,
        nonce_source=client.nonce_source, trusted_disclosure_keys=client._trusted_disclosure_keys,
        runtime=client.runtime,
    )
    recovered = RunnerCoordinator(
        control=restarted, store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        clock_ms=lambda: 2_000, monotonic=lambda: 1.0,
    )

    assert len(transport.requests) == 2
    assert restarted.runtime.load_pending_calls() == ()
    state = restarted.runtime.load_terminal_state(grant["run_id"])
    assert state is not None and state.state == "available"
    assert recovered._bindings == {}


def test_restart_rehydrates_authority_after_replaying_a_lost_claim_response(tmp_path):
    coordinator, client, transport, manifest, projection, grant, _authority = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")}, {"malformed": True}),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")}, _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"z")}, _gate(server_time_ms=2_001)),
        ],
    )
    with pytest.raises(ValueError, match="invalid runner claim response"):
        client._claim_closed()
    assert [item.request_operation for item in client.runtime.load_pending_calls()] == ["claim"]

    restarted = RunnerControlClient(
        origin=client.origin, workspace_id=client.workspace_id, runner_id=client.runner_id,
        signer=client.signer, clock=client.clock, transport=transport,
        nonce_source=client.nonce_source, trusted_disclosure_keys=client._trusted_disclosure_keys,
        runtime=client.runtime,
    )
    recovered = RunnerCoordinator(
        control=restarted, store=coordinator.store, identity=coordinator.identity,
        signer=coordinator.signer, trusted_grant_keys=coordinator.trusted_grant_keys,
        clock_ms=lambda: 2_000, monotonic=lambda: 1.0,
    )

    assert restarted.runtime.load_pending_calls() == ()
    assert [active.run_id for active in restarted.runtime.load_active_run_controls()] == [grant["run_id"]]
    assert grant["run_id"] in restarted._tracked_runs
    assert grant["run_id"] in recovered._gates
    assert grant["run_id"] in recovered._bindings
    operational = recovered._claimed_projection(
        manifest, projection, grant, claimed_at_ms=2_000,
    )
    assert recovered.heartbeat(grant["run_id"], operational) == ExecutionGate(**_gate(server_time_ms=2_001))


def test_idle_claim_requires_exact_204_empty_body_and_advances_only_claim_chain(tmp_path):
    coordinator, client, _, _, _, _, _ = _coordinator(
        tmp_path,
        lambda *_: [(204, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")}, None)],
    )
    assert coordinator.claim() is None
    assert client._chains == {"claim": (_nonce(b"n"), 2, 0)}


@pytest.mark.parametrize("mutation", [
    lambda response: response.update(extra="unknown"),
    lambda response: response["chain_states"]["heartbeat"].update(next_sequence=True),
    lambda response: response["gate"].update(server_time_ms="2000"),
    lambda response: response.update(run_id="run_other"),
])
def test_malformed_claim_fails_before_any_local_nonce_state_is_installed(tmp_path, mutation):
    def responses(manifest, projection, grant):
        response = _claim(manifest, projection, grant)
        mutation(response)
        return [(200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")}, response)]

    coordinator, client, _, _, _, _, _ = _coordinator(tmp_path, responses)
    initial = dict(client._chains)
    with pytest.raises(ValueError, match="invalid runner claim response"):
        coordinator.claim()
    assert client._chains == initial


def test_live_gate_rejects_replayed_server_time_and_regressed_control_generation(tmp_path):
    coordinator, client, _, _, _, _, _ = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"a")}, _gate()),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None
    with pytest.raises(ValueError, match="did not advance"):
        coordinator.heartbeat(lease.run_id, lease.operational_projection)
    active = client.runtime.load_active_run_controls()
    assert active[0].revision == 1 and active[0].gate["server_time_ms"] == 2_000
    assert [call.request_operation for call in client.runtime.load_pending_calls()] == ["heartbeat"]

    regressed, regressed_client, _, _, _, _, _ = _coordinator(
        tmp_path / "regressed",
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"b")},
             _gate(server_time_ms=2_001, generation=6)),
        ],
    )
    regressed_lease = regressed.claim()
    assert regressed_lease is not None
    with pytest.raises(ValueError, match="generation regressed"):
        regressed.heartbeat(regressed_lease.run_id, regressed_lease.operational_projection)
    active = regressed_client.runtime.load_active_run_controls()
    assert active[0].revision == 1 and active[0].gate["kill_switch_generation"] == 7


@pytest.mark.parametrize("response", [
    (201, {"X-Heel-Runner-Next-Nonce": _nonce(b"a")}, _gate(server_time_ms=2_001)),
    (200, {"X-Heel-Runner-Next-Nonce": "not-base64"}, _gate(server_time_ms=2_001)),
    (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"a")}, {
        **_gate(server_time_ms=2_001), "unknown": "field",
    }),
])
def test_invalid_gate_status_header_or_body_never_mutates_local_chain_state(
    tmp_path, response,
):
    coordinator, client, _, _, _, _, _ = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None
    before = dict(client._chains)
    accepted_calls = list(client.calls)
    client.transport = ScriptedControlTransport([response])
    with pytest.raises(ValueError):
        coordinator.heartbeat(lease.run_id, lease.operational_projection)
    assert client._chains == before
    assert client.calls == accepted_calls


def test_progress_result_and_stop_ack_decode_only_exact_service_responses(tmp_path):
    now = [1.0]
    coordinator, _, _, _, _, grant, _ = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"a")}, _status(
                grant["run_id"], approval_id=projection["projection_id"],
            )),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"d")},
             {"accepted": True, "deadline_met": True, "late": False}),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"b")},
             _status(
                 grant["run_id"], approval_id=projection["projection_id"], status="terminal",
             )),
        ],
        monotonic=lambda: now[0],
    )
    lease = coordinator.claim()
    assert lease is not None
    running = _phase(lease.operational_projection, coordinator.signer, "running")
    stopping = _phase(lease.operational_projection, coordinator.signer, "stop_requested")
    terminal = _phase(lease.operational_projection, coordinator.signer, "terminal")
    _install_terminal_anchor(coordinator, grant, terminal)
    assert coordinator.progress(grant["run_id"], running)["status"] == "running"
    acknowledgement = coordinator.stop_ack(
        grant["run_id"], stopping, deadline=2.0,
    )
    assert (
        acknowledgement.accepted is True
        and acknowledgement.deadline_met is True
        and acknowledgement.late is False
        and acknowledgement.acknowledged_at_ms == 2_000
    )
    assert coordinator.result(grant["run_id"], terminal)["status"] == "terminal"

    now[0] = 2.0
    with pytest.raises(ValueError, match="active runner claim is required"):
        coordinator.stop_ack(grant["run_id"], stopping, deadline=2.0)


def test_terminal_result_requires_a_verified_local_terminal_anchor_before_transport(tmp_path):
    coordinator, client, transport, _, _, grant, _ = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None
    terminal = _phase(lease.operational_projection, coordinator.signer, "terminal")

    with pytest.raises(RunnerStoreError, match="local terminal authority"):
        coordinator.result(grant["run_id"], terminal)

    assert len(transport.requests) == 1


def test_terminal_detach_failure_stages_no_result_transport_or_pending_call(tmp_path):
    coordinator, client, transport, _, projection, grant, _ = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None
    terminal = _phase(lease.operational_projection, coordinator.signer, "terminal")
    _install_terminal_anchor(coordinator, grant, terminal)
    coordinator.store.detach_terminal = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RunnerStoreError("injected local detach failure")
    )

    with pytest.raises(RunnerStoreError, match="injected local detach failure"):
        coordinator.result(grant["run_id"], terminal)

    assert len(transport.requests) == 1
    assert client.runtime.load_pending_calls() == ()


def test_second_coordinator_terminal_result_waiter_never_reaches_transport(tmp_path):
    coordinator, client, _transport, _, projection, grant, _ = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None
    terminal = _phase(lease.operational_projection, coordinator.signer, "terminal")
    _install_terminal_anchor(coordinator, grant, terminal)
    started, release = threading.Event(), threading.Event()

    class BlockingResultTransport:
        def __init__(self):
            self.calls = 0

        def post(self, path, *, headers, body):
            del path, headers, body
            self.calls += 1
            started.set()
            assert release.wait(1)
            return 200, {"X-Heel-Runner-Next-Nonce": _nonce(b"x")}, _status(
                grant["run_id"], approval_id=projection["projection_id"], status="terminal",
            )

    transport = BlockingResultTransport()
    client.transport = transport
    failures = []

    def send_result():
        try:
            coordinator.result(grant["run_id"], terminal)
        except BaseException as exc:
            failures.append(exc)

    first = threading.Thread(target=send_result)
    second = threading.Thread(target=send_result)
    first.start()
    assert started.wait(1)
    second.start()
    assert transport.calls == 1
    release.set()
    first.join(1)
    second.join(1)

    assert transport.calls == 1
    assert len(failures) == 1
    assert isinstance(failures[0], ValueError)
    assert "active runner claim is required" in str(failures[0])


def test_execution_adapter_supplies_only_the_live_claim_gate_and_fixed_local_transport(tmp_path):
    coordinator, _, _, _, _, grant, _ = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None
    target_transport = object()

    class LocalExecutor:
        def execute(self, bundle, *, transport, gate_source, cancellation, on_progress):
            assert bundle is lease.bundle
            assert transport is target_transport
            assert isinstance(cancellation, CancellationToken)
            assert callable(on_progress)
            assert gate_source() == ExecutionGate(**_gate())
            return {"operational_projection": lease.operational_projection}

        def prepare_stop_ack(self, run_id, *, stop_reason, proposed_at_ms):
            return (run_id, stop_reason, proposed_at_ms)

    adapter = RunnerExecutionAdapter(
        coordinator=coordinator, executor=LocalExecutor(), transport=target_transport,
    )
    cancellation = CancellationToken()
    assert adapter.execute(
        lease, cancellation=cancellation, on_progress=lambda _: None,
    )["operational_projection"] == lease.operational_projection
    assert adapter.prepare_stop_ack(
        lease, lease.operational_projection, "cloud_stop", 2_000,
    ) == (grant["run_id"], "cloud_stop", 2_000)


def test_supervisor_uses_the_exact_timestamp_signed_by_the_concrete_stop_ack():
    observed = []
    lease = ClaimLease("run_123456789", object(), {
        "run_id": "run_123456789", "lifecycle_phase": "running",
    })

    class AckCoordinator(StopCoordinator):
        def stop_ack(self, run_id, operational_projection, *, deadline):
            super().stop_ack(run_id, operational_projection, deadline=deadline)
            return SimpleNamespace(acknowledged_at_ms=1_777)

    class AckExecutor(BlockingExecutor):
        def execute(self, lease, *, cancellation, on_progress):
            del lease, on_progress
            while not cancellation.cancelled:
                pass
            assert cancellation.stop_ack_event.wait(1)
            observed.append(cancellation.stop_acknowledged_at_ms)
            return {"operational_projection": {}}

        def prepare_stop_ack(self, lease, projection, stop_reason, proposed_at_ms):
            return {**projection, "stop_reason": stop_reason, "proposed_at_ms": proposed_at_ms}

    RunnerService(
        coordinator=AckCoordinator(lease), executor=AckExecutor(),
        heartbeat_interval=0.05, idle_poll_interval=2.0, clock_ms=lambda: 9_999,
    ).run_once()
    assert observed == [1_777]


def test_control_for_distinct_runs_remains_concurrent(tmp_path):
    coordinator, client, transport, manifest, projection, grant, authority = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None
    second_run_id = "crun_" + "b" * 32
    second_unsigned = {
        key: copy.deepcopy(value) for key, value in grant.items()
        if key not in {"grant_digest", "signing_key_id", "signature_b64"}
    }
    second_unsigned.update({
        "run_id": second_run_id,
        "grant_id": "grant_987654321",
        "grant_nonce": "nonce_987654321",
    })
    second_grant = {
        **second_unsigned,
        "grant_digest": canonical_digest(second_unsigned),
        **authority.sign(canonical_bytes(second_unsigned)),
    }
    transport.responses.append((
        200, {"X-Heel-Runner-Next-Nonce": _nonce(b"m")},
        _claim(manifest, projection, second_grant),
    ))
    assert client._claim_closed()["run_id"] == second_run_id
    barrier = threading.Barrier(2)

    class ConcurrentTransport:
        def post(self, path, *, headers, body):
            del headers, body
            barrier.wait(1)
            if path.endswith("/heartbeat"):
                return 200, {"X-Heel-Runner-Next-Nonce": _nonce(b"a")}, _gate(
                    server_time_ms=2_001,
                )
            return 200, {"X-Heel-Runner-Next-Nonce": _nonce(b"b")}, _status(
                second_run_id, approval_id=projection["projection_id"],
                grant_id=second_grant["grant_id"],
            )

    client.transport = ConcurrentTransport()
    running = _phase(lease.operational_projection, coordinator.signer, "running")
    second_running = _phase(
        lease.operational_projection, coordinator.signer, "running", run_id=second_run_id,
    )
    second_running_unsigned = {
        key: copy.deepcopy(value) for key, value in second_running.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    second_running_unsigned["grant_id"] = second_grant["grant_id"]
    second_running_unsigned["grant_digest"] = second_grant["grant_digest"]
    second_running = validate_operational_run({
        **second_running_unsigned,
        "projection_digest": canonical_digest(second_running_unsigned),
        "signing_key_id": coordinator.signer.key_id,
        "signature_b64": base64.b64encode(
            coordinator.signer.sign(canonical_bytes(second_running_unsigned))
        ).decode("ascii"),
    })
    failures = []

    def call(method, run_id, current):
        try:
            method(run_id, current)
        except BaseException as exc:
            failures.append(exc)

    threads = [
        threading.Thread(target=call, args=(client._heartbeat_closed, grant["run_id"], running)),
        threading.Thread(target=call, args=(client._progress_closed, second_run_id, second_running)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2)
    assert all(not thread.is_alive() for thread in threads)
    assert failures == []
    assert client._chains[f"heartbeat:{grant['run_id']}"][1] == 5
    assert client._chains[f"progress:{second_run_id}"][1] == 6


def test_findings_upload_is_closed_bounded_and_continues_the_terminal_result_chain(tmp_path):
    receipt_holder = {}

    def responses(manifest, projection, grant):
        return [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"x")}, _status(
                grant["run_id"], approval_id=projection["projection_id"], status="terminal",
            )),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"y")}, receipt_holder),
        ]

    coordinator, client, transport, manifest, projection, grant, authority = _coordinator(
        tmp_path, responses,
    )
    lease = coordinator.claim()
    assert lease is not None
    terminal = _phase(lease.operational_projection, coordinator.signer, "terminal")
    _install_terminal_anchor(coordinator, grant, terminal)
    coordinator.result(grant["run_id"], terminal)
    assert grant["run_id"] not in coordinator._gates
    assert grant["run_id"] not in coordinator._gate_receipts
    assert grant["run_id"] not in coordinator._bindings
    assert grant["run_id"] not in coordinator._terminal_runs
    assert client._tracked_runs == set()
    assert not {chain for chain in client._chains if chain.endswith(":" + grant["run_id"])}
    findings = _findings_projection(coordinator, manifest, projection, grant)
    permit = _permit(authority, coordinator, grant, findings)
    receipt_holder.update({
        "schema_version": "heel.canary-findings-receipt.v1",
        "receipt_id": "cfr_runner_upload",
        "workspace_id": grant["workspace_id"], "project_id": grant["project_id"],
        "run_id": grant["run_id"], "grant_id": grant["grant_id"],
        "permit_id": permit["permit_id"], "projection_id": findings["projection_id"],
        "projection_digest": findings["projection_digest"],
        "byte_count": len(canonical_bytes(findings)),
        "scenario_count": 0, "finding_count": 0,
        "accepted_at_ms": 2_001, "status": "synchronized",
    })

    receipt = coordinator.upload_findings(
        grant["run_id"], permit=permit, findings_projection=findings,
    )
    assert receipt == receipt_holder
    assert grant["run_id"] not in client._tracked_runs
    assert not any(chain.endswith(":" + grant["run_id"]) for chain in client._chains)
    assert grant["run_id"] not in coordinator._bindings
    assert grant["run_id"] not in coordinator._terminal_runs
    path, headers, body = transport.requests[-1]
    assert path.endswith(f"/runs/{grant['run_id']}/result-projection")
    assert headers["X-Heel-Runner-Nonce"] == _nonce(b"x")
    assert headers["X-Heel-Runner-Sequence"] == "7"
    assert body == canonical_bytes({
        "schema_version": "heel.runner-findings-upload.v1",
        "run_id": grant["run_id"], "permit": permit,
        "findings_projection": findings,
    })


def test_terminal_disclosure_replays_the_sealed_pending_request_after_client_restart(tmp_path):
    receipt_holder = {}

    def responses(manifest, projection, grant):
        return [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"x")}, _status(
                grant["run_id"], approval_id=projection["projection_id"], status="terminal",
            )),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"y")}, {"malformed": True}),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"y")}, receipt_holder),
        ]

    coordinator, client, transport, manifest, projection, grant, authority = _coordinator(
        tmp_path, responses,
    )
    lease = coordinator.claim()
    assert lease is not None
    terminal = _phase(lease.operational_projection, coordinator.signer, "terminal")
    _install_terminal_anchor(coordinator, grant, terminal)
    coordinator.result(grant["run_id"], terminal)
    findings = _findings_projection(coordinator, manifest, projection, grant)
    permit = _permit(authority, coordinator, grant, findings)
    receipt_holder.update({
        "schema_version": "heel.canary-findings-receipt.v1",
        "receipt_id": "cfr_runner_upload", "workspace_id": grant["workspace_id"],
        "project_id": grant["project_id"], "run_id": grant["run_id"],
        "grant_id": grant["grant_id"], "permit_id": permit["permit_id"],
        "projection_id": findings["projection_id"],
        "projection_digest": findings["projection_digest"],
        "byte_count": len(canonical_bytes(findings)), "scenario_count": 0,
        "finding_count": 0, "accepted_at_ms": 2_001, "status": "synchronized",
    })

    with pytest.raises(ValueError, match="invalid runner findings receipt"):
        coordinator.upload_findings(
            grant["run_id"], permit=permit, findings_projection=findings,
        )
    pending = client.runtime.load_pending_calls()
    assert len(pending) == 1 and pending[0].request_operation == "upload-findings"
    first_body = pending[0].body

    restarted = RunnerControlClient(
        origin="https://control.example", workspace_id=coordinator.identity.workspace_id,
        runner_id=coordinator.identity.runner_id, signer=coordinator.signer,
        clock=lambda: 2_000, transport=transport, nonce_source=lambda _chain: _nonce(b"z"),
        trusted_disclosure_keys=dict(coordinator.trusted_grant_keys), runtime=client.runtime,
    )
    receipt = restarted.upload_findings(
        run_id=grant["run_id"], permit=permit, findings_projection=findings,
    )
    assert receipt["status"] == "synchronized"
    assert client.runtime.load_pending_calls() == ()
    assert transport.requests[-1][2] == first_body


def test_coordinator_startup_replays_real_detached_findings_pending_request(tmp_path):
    receipt_holder = {}

    def responses(manifest, projection, grant):
        return [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"x")}, _status(
                grant["run_id"], approval_id=projection["projection_id"], status="terminal",
            )),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"y")}, {"malformed": True}),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"y")}, receipt_holder),
        ]

    coordinator, client, transport, manifest, projection, grant, authority = _coordinator(
        tmp_path, responses,
    )
    lease = coordinator.claim()
    assert lease is not None
    completed = LocalCanaryExecutor(
        store=coordinator.store, identity=coordinator.identity, signer=coordinator.signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        lease.bundle, transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    coordinator.result(grant["run_id"], completed.operational_projection)
    findings = _findings_projection(coordinator, manifest, projection, grant)
    permit = _permit(authority, coordinator, grant, findings)
    receipt_holder.update({
        "schema_version": "heel.canary-findings-receipt.v1",
        "receipt_id": "cfr_runner_recovered_upload",
        "workspace_id": grant["workspace_id"], "project_id": grant["project_id"],
        "run_id": grant["run_id"], "grant_id": grant["grant_id"],
        "permit_id": permit["permit_id"], "projection_id": findings["projection_id"],
        "projection_digest": findings["projection_digest"],
        "byte_count": len(canonical_bytes(findings)), "scenario_count": 0,
        "finding_count": 0, "accepted_at_ms": 2_001, "status": "synchronized",
    })
    with pytest.raises(ValueError, match="invalid runner findings receipt"):
        coordinator.upload_findings(
            grant["run_id"], permit=permit, findings_projection=findings,
        )
    (pending,) = client.runtime.load_pending_calls()
    assert pending.request_operation == "upload-findings"
    sealed_body = pending.body

    restarted = RunnerControlClient(
        origin=client.origin, workspace_id=client.workspace_id, runner_id=client.runner_id,
        signer=client.signer, clock=client.clock, transport=transport,
        nonce_source=client.nonce_source, trusted_disclosure_keys=client._trusted_disclosure_keys,
        runtime=client.runtime,
    )
    recovered = RunnerCoordinator(
        control=restarted, store=coordinator.store, identity=coordinator.identity,
        signer=coordinator.signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        clock_ms=lambda: 2_000, monotonic=lambda: 1.0,
    )

    assert transport.requests[-1][2] == sealed_body
    assert restarted.runtime.load_pending_calls() == ()
    assert restarted.runtime.load_terminal_state(grant["run_id"]).state == "consumed"
    assert recovered._bindings == {}


def test_real_detached_terminal_rehydrates_available_disclosure_and_rejects_missing_sides(tmp_path):
    receipt_holder = {}

    def responses(manifest, projection, grant):
        return [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"x")}, _status(
                grant["run_id"], approval_id=projection["projection_id"], status="terminal",
            )),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"y")}, receipt_holder),
        ]

    coordinator, client, _transport, manifest, projection, grant, authority = _coordinator(
        tmp_path, responses,
    )
    lease = coordinator.claim()
    assert lease is not None
    completed = LocalCanaryExecutor(
        store=coordinator.store, identity=coordinator.identity, signer=coordinator.signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        lease.bundle, transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )

    coordinator.result(grant["run_id"], completed.operational_projection)
    available = client.runtime.load_terminal_state(grant["run_id"])
    assert available is not None and available.state == "available"
    anchor = coordinator.store.load_terminal_disclosure_anchor(
        grant["run_id"], runtime=client.runtime,
        expected_runtime_state_digest=available.state_digest,
    )
    assert anchor["grant_id"] == grant["grant_id"]
    assert anchor["terminal_projection_digest"] == completed.operational_projection["projection_digest"]

    detached_path = coordinator.store.run_path(grant["run_id"]).parent / (
        "detached-" + coordinator.store._run_hash(grant["run_id"]) + ".json"
    )
    detached_bytes = detached_path.read_bytes()
    detached_path.unlink()
    with pytest.raises(RunnerStoreError, match="local terminal disclosure authority"):
        coordinator.store.load_terminal_disclosure_anchor(
            grant["run_id"], runtime=client.runtime,
            expected_runtime_state_digest=available.state_digest,
        )
    detached_path.write_bytes(detached_bytes)
    detached_path.write_bytes(b"{}")
    with pytest.raises(RunnerStoreError, match="invalid local run authority record"):
        coordinator.store.load_terminal_disclosure_anchor(
            grant["run_id"], runtime=client.runtime,
            expected_runtime_state_digest=available.state_digest,
        )
    detached_path.write_bytes(detached_bytes)

    missing_runtime = RunnerRuntimeState(
        tmp_path / "missing-runtime.sqlite3", coordinator.identity, coordinator.signer,
    )
    with pytest.raises(RunnerStoreError, match="local terminal disclosure authority"):
        coordinator.store.load_terminal_disclosure_anchor(
            grant["run_id"], runtime=missing_runtime,
            expected_runtime_state_digest=available.state_digest,
        )


def test_delayed_execution_rejects_stale_authenticated_claim_gate_before_executor_use(tmp_path):
    now = [1.0]
    coordinator, _, _, _, _, _, _ = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
        ],
        monotonic=lambda: now[0],
    )
    lease = coordinator.claim()
    assert lease is not None
    now[0] = 1.501
    with pytest.raises(ValueError, match="gate is stale"):
        coordinator.execution_gate(lease.run_id)

    entered = []

    class DelayedExecutor:
        def execute(self, bundle, *, transport, gate_source, cancellation, on_progress):
            del bundle, transport, cancellation, on_progress
            entered.append(True)
            gate_source()

    adapter = RunnerExecutionAdapter(
        coordinator=coordinator, executor=DelayedExecutor(), transport=object(),
    )
    with pytest.raises(ValueError, match="gate is stale"):
        adapter.execute(
            lease, cancellation=CancellationToken(), on_progress=lambda _: None,
        )
    assert entered == [True]


def test_execution_adapter_builds_a_lease_transport_only_from_the_revalidated_claim(tmp_path):
    """Unit (scripted control transport, recording executor): the metadata precheck runs after the
    fresh coordinator gate and the exact bundle check, before the executor; the lazy factory is
    handed to the executor, which calls it only after its own local activation. Both see only the
    validated bundle, and the factory's transport is the one the executor uses."""
    coordinator, _, _, manifest, projection, grant, _ = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None
    order: list[str] = []
    built = object()
    real_gate = coordinator.execution_gate

    def gate(run_id):
        order.append("gate")
        return real_gate(run_id)

    coordinator.execution_gate = gate

    def factory(validated):
        order.append("factory")
        assert isinstance(validated, ValidatedExecutionBundle)
        assert validated.manifest == manifest and validated.projection == projection
        assert validated.grant == grant
        return built

    def precheck(validated):
        order.append("precheck")
        assert isinstance(validated, ValidatedExecutionBundle) and validated.grant == grant

    class LocalExecutor:
        def execute(self, bundle, *, transport_factory, gate_source, cancellation, on_progress):
            order.append("execute")
            assert bundle is lease.bundle
            assert gate_source() == ExecutionGate(**_gate())
            assert transport_factory() is built  # after the executor's own activation
            return {"operational_projection": lease.operational_projection}

    adapter = RunnerExecutionAdapter(
        coordinator=coordinator, executor=LocalExecutor(), transport_factory=factory,
        transport_precheck=precheck,
    )
    adapter.execute(lease, cancellation=CancellationToken(), on_progress=lambda _: None)
    assert order == ["gate", "precheck", "execute", "gate", "factory"]
    for arguments in ({}, {"transport": object(), "transport_factory": factory},
                      {"transport_factory": "not callable"}):
        with pytest.raises(TypeError, match="target transport is required"):
            RunnerExecutionAdapter(coordinator=coordinator, executor=LocalExecutor(), **arguments)
    for arguments in ({"transport": object(), "transport_precheck": precheck},
                      {"transport_factory": factory, "transport_precheck": "not callable"}):
        with pytest.raises(TypeError, match="precheck requires a lazy target transport"):
            RunnerExecutionAdapter(coordinator=coordinator, executor=LocalExecutor(), **arguments)

    # A metadata refusal is final before the executor: nothing is reserved or built.
    order.clear()

    def refusing(validated):
        order.append("precheck")
        raise ValueError("credential metadata refused")

    with pytest.raises(ValueError, match="credential metadata refused"):
        RunnerExecutionAdapter(
            coordinator=coordinator, executor=LocalExecutor(), transport_factory=factory,
            transport_precheck=refusing,
        ).execute(lease, cancellation=CancellationToken(), on_progress=lambda _: None)
    assert order == ["gate", "precheck"]

    # An authenticated stop already chosen for the lease ends it before any gate or executor.
    order.clear()
    stopped = CancellationToken()
    stopped.stop_reason = "cloud_stop"
    outcome = adapter.execute(lease, cancellation=stopped, on_progress=lambda _: None)
    assert isinstance(outcome, UnactivatedExecution) and outcome.stop_reason == "cloud_stop"
    assert outcome.operational_projection is None and order == []


_REFUSALS = {
    "stale": "gate is stale",
    "revoked": "gate denies execution",
    "unknown-run": "active runner claim is required",
    "mismatched-bundle": "lease differs from the active claim",
    "expired": "grant is expired",
}


@pytest.mark.parametrize("case", ["stale", "revoked", "unknown-run", "mismatched-bundle", "expired"])
def test_execution_adapter_never_builds_transport_for_a_stale_revoked_or_mismatched_lease(
    tmp_path, case,
):
    """Unit (scripted control transport): every refused authority fails before the factory, so
    no resolver, socket or executor is reached."""
    now = [1.0]
    clock = [2_000]

    def responses(manifest, projection, grant):
        return [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")}, _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"a")},
             _gate(server_time_ms=2_001, stop_reason="runner_revoked", active=False)),
        ]

    coordinator, _, _, manifest, projection, grant, authority = _coordinator(
        tmp_path, responses, monotonic=lambda: now[0],
    )
    coordinator.clock_ms = lambda: clock[0]
    lease = coordinator.claim()
    assert lease is not None
    if case == "stale":
        now[0] = 1.501
    elif case == "revoked":
        coordinator.heartbeat(lease.run_id, lease.operational_projection)
    elif case == "unknown-run":
        lease = ClaimLease("crun_" + "f" * 32, lease.bundle, lease.operational_projection)
    elif case == "mismatched-bundle":
        other = copy.deepcopy(dict(grant))
        other["grant_id"] = "grant_987654321"
        unsigned = {
            key: value for key, value in other.items()
            if key not in {"grant_digest", "signing_key_id", "signature_b64"}
        }
        other = {**unsigned, "grant_digest": canonical_digest(unsigned),
                 **authority.sign(canonical_bytes(unsigned))}
        lease = ClaimLease(
            lease.run_id, ExecutionBundle(manifest, projection, other),
            lease.operational_projection,
        )
    else:
        clock[0] = grant["expires_at_ms"]
    reached: list[str] = []

    class Executor:
        def execute(self, *_args, **_kwargs):
            reached.append("execute")

    adapter = RunnerExecutionAdapter(
        coordinator=coordinator, executor=Executor(),
        transport_factory=lambda validated: reached.append("factory"),
    )
    with pytest.raises(ValueError, match=_REFUSALS[case]):
        adapter.execute(lease, cancellation=CancellationToken(), on_progress=lambda _: None)
    assert reached == []


def test_authenticated_gate_cannot_outlive_proof_horizon_by_local_elapsed_time(tmp_path):
    now = [1.0]

    def responses(manifest, projection, grant):
        response = _claim(manifest, projection, grant)
        response["gate"] = _gate(proof_expires_at_ms=2_100)
        return [(200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")}, response)]

    coordinator, _, _, _, _, _, _ = _coordinator(
        tmp_path, responses, monotonic=lambda: now[0],
    )
    lease = coordinator.claim()
    assert lease is not None
    now[0] = 1.1
    with pytest.raises(ValueError, match="proof has expired"):
        coordinator.execution_gate(lease.run_id)


@pytest.mark.parametrize("kind", ["forged", "expired", "wrong-key", "wrong-binding"])
def test_public_findings_upload_reverifies_permit_before_any_transport(
    tmp_path, kind,
):
    coordinator, client, transport, manifest, projection, grant, authority = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"x")}, _status(
                grant["run_id"], approval_id=projection["projection_id"], status="terminal",
            )),
        ],
    )
    lease = coordinator.claim()
    terminal = _phase(lease.operational_projection, coordinator.signer, "terminal")
    _install_terminal_anchor(coordinator, grant, terminal)
    coordinator.result(grant["run_id"], terminal)
    findings = _findings_projection(coordinator, manifest, projection, grant)
    if kind == "forged":
        permit = _permit(authority, coordinator, grant, findings)
        permit["permit_nonce"] = "forged_permit_nonce"
    elif kind == "expired":
        permit = _permit(
            authority, coordinator, grant, findings,
            issued_at_ms=1_000, expires_at_ms=2_000,
        )
    elif kind == "wrong-key":
        permit = _permit(SigningAuthority.generate(), coordinator, grant, findings)
    else:
        unsigned_findings = {
            key: copy.deepcopy(value) for key, value in findings.items()
            if key not in {"projection_digest", "signing_key_id", "signature_b64"}
        }
        unsigned_findings["grant_id"] = "grant_other_123456789"
        findings = {
            **unsigned_findings,
            "projection_digest": canonical_digest(unsigned_findings),
            "signing_key_id": coordinator.signer.key_id,
            "signature_b64": base64.b64encode(
                coordinator.signer.sign(canonical_bytes(unsigned_findings))
            ).decode("ascii"),
        }
        permit = _permit(
            authority, coordinator,
            {**grant, "grant_id": "grant_other_123456789"}, findings,
        )
    before = len(transport.requests)
    with pytest.raises(ValueError):
        client.upload_findings(
            run_id=grant["run_id"], permit=permit, findings_projection=findings,
        )
    assert len(transport.requests) == before


def test_default_heartbeat_cadence_has_margin_below_gate_staleness_limit():
    service = RunnerService(
        coordinator=object(), executor=object(), idle_poll_interval=2.0,
    )
    assert service.heartbeat_interval <= 0.4


def test_runner_service_does_not_claim_work_until_context_acquisition_is_ready():
    class PendingContextCoordinator:
        def __init__(self): self.claims = 0
        def ensure_runner_context(self): return False
        def claim(self): self.claims += 1; return None
    coordinator = PendingContextCoordinator()
    assert RunnerService(coordinator=coordinator, executor=object(), idle_poll_interval=2.0).run_once() is False
    assert coordinator.claims == 0


def test_stopped_valid_terminal_projection_is_sent_after_bounded_ack_and_unwind(tmp_path):
    coordinator, _, _, _, _, _, _ = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
        ],
    )
    lease = coordinator.claim()
    results = []

    class StoppingCoordinator:
        def claim(self):
            return lease

        def heartbeat(self, run_id, projection):
            del run_id, projection
            return ExecutionGate(True, "active", "valid", 20_000, 7, "cloud_stop", 2_001)

        def progress(self, run_id, projection):
            del run_id, projection

        def stop_ack(self, run_id, projection, *, deadline):
            del run_id, projection, deadline

        def result(self, run_id, projection):
            results.append((run_id, validate_operational_run(projection)))

    class StoppedExecutor:
        def execute(self, claimed, *, cancellation, on_progress):
            del on_progress
            assert claimed is lease
            while not cancellation.cancelled:
                pass
            assert cancellation.stop_ack_event.wait(1)
            stopping = _phase(
                lease.operational_projection, coordinator.signer, "stop_requested",
            )
            unsigned = {
                key: copy.deepcopy(value) for key, value in stopping.items()
                if key not in {"projection_digest", "signing_key_id", "signature_b64"}
            }
            unsigned["event_sequence"] += 1
            unsigned["lifecycle_phase"] = "terminal"
            unsigned["execution_disposition"] = "stopped"
            unsigned["timestamps"]["stop_acknowledged_at_ms"] = 2_000
            unsigned["timestamps"]["terminal_at_ms"] = 2_000
            signature = coordinator.signer.sign(canonical_bytes(unsigned))
            return {"operational_projection": validate_operational_run({
                **unsigned, "projection_digest": canonical_digest(unsigned),
                "signing_key_id": coordinator.signer.key_id,
                "signature_b64": base64.b64encode(signature).decode("ascii"),
            })}

        def prepare_stop_ack(self, claimed, projection, stop_reason, proposed_at_ms):
            del claimed, projection, stop_reason, proposed_at_ms
            return _phase(
                lease.operational_projection, coordinator.signer, "stop_requested",
            )

    RunnerService(
        coordinator=StoppingCoordinator(), executor=StoppedExecutor(),
        heartbeat_interval=0.05, idle_poll_interval=2.0,
    ).run_once()
    assert len(results) == 1
    assert results[0][0] == lease.run_id
    assert results[0][1]["execution_disposition"] == "stopped"


@pytest.mark.parametrize("variant", ["completed", "other-reason", "missing-ack"])
def test_no_non_stopped_or_mismatched_terminal_is_sent_after_an_acknowledged_stop(tmp_path, variant):
    """After an accepted cloud_stop acknowledgement the only permitted result is the stopped
    terminal for that exact reason carrying an acknowledgement timestamp; a completed terminal, a
    different stop reason or a missing timestamp is never sent."""
    coordinator, _, _, _, _, _, _ = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
        ],
    )
    lease = coordinator.claim()
    results = []

    class StoppingCoordinator:
        def claim(self):
            return lease

        def heartbeat(self, run_id, projection):
            return ExecutionGate(True, "active", "valid", 20_000, 7, "cloud_stop", 2_001)

        def progress(self, run_id, projection):
            return None

        def stop_ack(self, run_id, projection, *, deadline):
            return SimpleNamespace(accepted=True, acknowledged_at_ms=2_000)

        def result(self, run_id, projection):
            results.append(projection)

    class Executor:
        def execute(self, claimed, *, cancellation, on_progress):
            while not cancellation.cancelled:
                time.sleep(0.005)
            assert cancellation.stop_ack_event.wait(1)
            unsigned = {
                key: copy.deepcopy(value)
                for key, value in _phase(lease.operational_projection, coordinator.signer, "terminal").items()
                if key not in {"projection_digest", "signing_key_id", "signature_b64"}
            }
            if variant != "completed":
                unsigned["execution_disposition"] = "stopped"
                unsigned["stop_reason"] = "kill_switch" if variant == "other-reason" else "cloud_stop"
                unsigned["timestamps"]["stop_requested_at_ms"] = 2_000
                unsigned["timestamps"]["stop_acknowledged_at_ms"] = None if variant == "missing-ack" else 2_000
            signature = coordinator.signer.sign(canonical_bytes(unsigned))
            return {"operational_projection": validate_operational_run({
                **unsigned, "projection_digest": canonical_digest(unsigned),
                "signing_key_id": coordinator.signer.key_id,
                "signature_b64": base64.b64encode(signature).decode("ascii"),
            })}

        def prepare_stop_ack(self, claimed, projection, stop_reason, proposed_at_ms):
            return _phase(lease.operational_projection, coordinator.signer, "stop_requested")

    RunnerService(
        coordinator=StoppingCoordinator(), executor=Executor(),
        heartbeat_interval=0.05, idle_poll_interval=2.0,
    ).run_once()
    assert results == []


# ---------------------------------------------------------------------------
# T2b2R1: coordinator startup replay and context acquisition recover lost claim-chain authority
# through the control client's one resync path (scripted transport; the HTTP gates are in
# tests/test_runner_daemon.py).

from heel.runner.control_client import RunnerChainRecoveryRequired  # noqa: E402

_AUTH_REFUSED = (401, {}, {"schema_version": "heel.runner-error.v1", "code": "invalid_runner_auth"})


class _DownOnce(ConnectionError):
    pass


def _signed_context_binding(identity, authority):
    unsigned = {
        "schema_version": "heel.runner-context-binding.v1",
        "binding_id": "rcb_" + "a" * 32,
        "workspace_id": identity.workspace_id,
        "project_id": "prj_123456789",
        "environment": {
            "environment_id": "env_123456789", "origin": "https://staging.acme.dev",
            "environment_class": "staging", "verification_record_digest": "0" * 64,
        },
        "runner_binding": {
            "runner_id": identity.runner_id, "runner_key_id": identity.key_id,
            "public_key_digest": identity.fingerprint,
        },
        "authorization": {"user_id": "owner", "role": "owner"},
        "issued_at_ms": 1, "expires_at_ms": 60_001,
    }
    return {
        **unsigned, "binding_digest": canonical_digest(unsigned),
        **authority.sign(b"heel.runner-context-binding.v1\0" + canonical_bytes(unsigned)),
    }


class _RecoveryRoutes:
    """Route-suffix scripted control plane recording the order of calls."""

    def __init__(self, identity, artifact, *, fail_first=None):
        self.identity, self.artifact = identity, artifact
        self.fail_first = fail_first
        self.calls: list[str] = []
        self.refuse: list[str] = []
        self.sequence = 1  # the server's claim-chain next sequence while the staged call is unrecorded

    def post(self, path, *, headers, body):
        name = path.rsplit("/", 1)[1] if "/resync/" not in path else "resync-" + path.rsplit("/", 1)[1]
        name = "list" if path.endswith("/contexts/list") else name
        self.calls.append(name)
        if self.fail_first == name:
            self.fail_first = None
            raise _DownOnce()
        if self.refuse and self.refuse[0] == name:
            self.refuse.pop(0)
            return _AUTH_REFUSED
        if name == "resync-start":
            return 200, {}, {
                "schema_version": "heel.runner-resync-challenge.v2", "challenge_id": "rrs_" + "c" * 32,
                "chain": {"operation": "claim", "run_id": None}, "server_challenge_b64": _nonce(b"s"),
                "next_sequence": self.sequence, "expires_at_ms": 65_000, "generation": 0,
            }
        if name == "resync-complete":
            return 200, {}, {
                "schema_version": "heel.runner-resync-completed.v2", "chain": {"operation": "claim", "run_id": None},
                "next_sequence": self.sequence, "next_nonce_b64": _nonce(b"r"), "expires_at_ms": 65_000, "generation": 1,
            }
        if name == "list":
            item = self.artifact
            return 200, {"X-Heel-Runner-Next-Nonce": _nonce(bytes([65 + len(self.calls)]))}, {
                "schema_version": "heel.runner-context-list-result.v1", "server_time_ms": 2_000,
                "contexts": [] if item is None else [{
                    "binding_id": item["binding_id"], "binding_digest": item["binding_digest"],
                    "project_id": item["project_id"], "environment_id": item["environment"]["environment_id"],
                    "origin": item["environment"]["origin"], "environment_class": "staging",
                    "verification_record_digest": "0" * 64, "expires_at_ms": 60_001, "claimed": False,
                }], "has_more": False,
            }
        if path.endswith("/runners/" + self.identity.runner_id + "/claim"):
            return 204, {"X-Heel-Runner-Next-Nonce": _nonce(b"j")}, None
        assert path.endswith("/claim")
        return 200, {"X-Heel-Runner-Next-Nonce": _nonce(bytes([97 + len(self.calls)]))}, {
            "schema_version": "heel.runner-context-claim-result.v1", "context_binding": self.artifact,
            "claimed_at_ms": 2_000,
        }


def _recovering_pair(tmp_path, *, with_binding):
    _bound, identity, signer, _manifest, _projection = compiled_pair(tmp_path / "fixture")
    store = RunnerStore(tmp_path / "unbound")
    authority = SigningAuthority.generate()
    artifact = _signed_context_binding(identity, authority) if with_binding else None
    runtime = _control_runtime(tmp_path / "recovery-runtime.sqlite3", identity, signer)

    def build(transport):
        control = RunnerControlClient(
            origin="https://control.example", workspace_id=identity.workspace_id,
            runner_id=identity.runner_id, signer=signer, clock=lambda: 2_000,
            transport=transport, nonce_source=lambda _chain: _nonce(b"c"),
            resync_random_source=lambda count: b"k" * count,
            trusted_disclosure_keys={authority.key_id: authority.public_key}, runtime=runtime,
        )
        return control, (lambda: RunnerCoordinator(
            control=control, store=store, identity=identity, signer=signer,
            trusted_grant_keys={authority.key_id: authority.public_key}, clock_ms=lambda: 2_000,
        ))

    return identity, store, artifact, runtime, build


def test_startup_replay_supersedes_a_stale_staged_list_then_discovers_contexts(tmp_path):
    identity, store, artifact, runtime, build = _recovering_pair(tmp_path, with_binding=False)
    first = _RecoveryRoutes(identity, None, fail_first="list")
    control, _coordinator_factory = build(first)
    with pytest.raises(_DownOnce):
        control.list_contexts()
    assert [item.request_operation for item in runtime.load_pending_calls()] == ["list-contexts"]

    routes = _RecoveryRoutes(identity, None)
    routes.refuse = ["list"]  # the staged proof is now outside the server's window
    _control, factory = build(routes)
    coordinator = factory()  # constructor: replay -> refused -> one resync -> superseded
    assert routes.calls == ["list", "resync-start", "resync-complete"]
    assert coordinator.ensure_runner_context() is False
    assert routes.calls[-1] == "list" and runtime.load_pending_calls() == ()
    assert [item.request_operation for item in runtime.load_superseded_calls()] == ["list-contexts"]


def test_startup_supersedes_a_lost_claim_context_and_reclaims_the_same_binding_once(tmp_path):
    identity, store, artifact, runtime, build = _recovering_pair(tmp_path, with_binding=True)
    control, _factory = build(_RecoveryRoutes(identity, artifact, fail_first="claim"))
    control.list_contexts()
    with pytest.raises(_DownOnce):
        control.claim_context(artifact["binding_id"], artifact["binding_digest"])
    assert [item.request_operation for item in runtime.load_pending_calls()] == ["claim-context"]

    routes = _RecoveryRoutes(identity, artifact)
    routes.refuse, routes.sequence = ["claim"], 2  # the first list was recorded
    _control, factory = build(routes)
    coordinator = factory()
    assert coordinator.ensure_runner_context() is True
    assert routes.calls == ["claim", "resync-start", "resync-complete", "list", "claim"]
    assert store.is_context_bound
    assert store.verify_cloud_context_binding(
        identity=identity, trusted_cloud_keys=coordinator.trusted_grant_keys, now_ms=2_000,
    )["binding_id"] == artifact["binding_id"]
    assert [item.request_operation for item in runtime.load_superseded_calls()] == ["claim-context"]
    assert runtime.load_pending_calls() == ()


def test_startup_supersedes_a_never_recorded_job_claim_and_the_next_poll_is_fresh(tmp_path):
    identity, store, artifact, runtime, build = _recovering_pair(tmp_path, with_binding=False)
    first = _RecoveryRoutes(identity, None, fail_first="claim")
    control, _factory = build(first)
    with pytest.raises(_DownOnce):
        control.claim()
    (staged,) = runtime.load_pending_calls()

    routes = _RecoveryRoutes(identity, None)
    routes.refuse = ["claim"]
    control, factory = build(routes)
    coordinator = factory()  # replay -> refused -> resync proves N == S -> superseded, not re-issued
    assert routes.calls == ["claim", "resync-start", "resync-complete"]
    assert [item.call_id for item in runtime.load_superseded_calls()] == [staged.call_id]
    assert coordinator.claim() is None  # the loop's next poll: a new signed claim, idle
    assert routes.calls[-1] == "claim" and runtime.load_pending_calls() == ()


def test_startup_keeps_a_job_claim_whose_sequence_the_server_consumed(tmp_path):
    identity, store, artifact, runtime, build = _recovering_pair(tmp_path, with_binding=False)
    control, _factory = build(_RecoveryRoutes(identity, None, fail_first="claim"))
    with pytest.raises(_DownOnce):
        control.claim()
    (staged,) = runtime.load_pending_calls()
    routes = _RecoveryRoutes(identity, None)
    routes.refuse, routes.sequence = ["claim"], 2  # the server cursor moved past the staged claim
    _control, factory = build(routes)
    with pytest.raises(RunnerChainRecoveryRequired) as raised:
        factory()
    assert (raised.value.operation, raised.value.reason) == ("claim", "claim_sequence_consumed")
    assert runtime.load_pending_calls() == (staged,) and runtime.load_superseded_calls() == ()


# --- PENDING-BODY-CAP T-P7: coordinator startup replay of a findings upload over 3 072 B ---------------

_FINDINGS_SHAPES = {
    "representative": {"scenarios": 2, "observations": 2, "text": 200, "title": 60},
    "maximal": {"scenarios": 4, "observations": 5, "text": 2000, "title": 160},
}


def _findings_projection_with_scenarios(coordinator, manifest, projection, grant, *, scenarios, observations,
                                        text, title):
    base = _findings_projection(coordinator, manifest, projection, grant)
    unsigned = {
        key: value for key, value in base.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    unsigned["assessment_outcome"] = "observed"
    unsigned["scenario_results"] = [
        {
            "ordinal": index, "scenario_id": f"scenario_{index}", "adapter_version": unsigned["adapter_versions"][0],
            "assessment_outcome": "observed",
            "route": {"method": "GET", "route_template": f"/api/canary/{index}"},
            "observations": [
                {"semantic_role": f"role{item:02d}", "status_code": 200, "body_shape": "json_object",
                 "truncation_state": "complete"}
                for item in range(observations)
            ],
            "finding": {
                "title": "T" * title, "reachability_rationale": "r" * text, "confidence": "high",
                "recommended_control": "c" * text, "regression_suggestion": "s" * text,
            },
            "containment_codes": [], "redaction_count": 0, "local_evidence_refs": ["ev1_" + "a" * 64],
        }
        for index in range(scenarios)
    ]
    return {
        **unsigned,
        "projection_digest": canonical_digest(unsigned),
        "signing_key_id": coordinator.signer.key_id,
        "signature_b64": base64.b64encode(coordinator.signer.sign(canonical_bytes(unsigned))).decode("ascii"),
    }


@pytest.mark.parametrize("shape", sorted(_FINDINGS_SHAPES))
def test_coordinator_startup_replays_a_representative_findings_upload_over_3072_bytes_byte_identically(
    tmp_path, capsys, shape,
):
    """T-P7: the coordinator path with a scripted transport (labelled as such, not HTTP): a findings
    upload over 3 072 B whose answer was malformed is sealed, survives a client restart and is sent
    again byte-identically exactly once by coordinator startup."""
    receipt_holder = {}

    def responses(manifest, projection, grant):
        return [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"x")}, _status(
                grant["run_id"], approval_id=projection["projection_id"], status="terminal",
            )),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"y")}, {"malformed": True}),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"y")}, receipt_holder),
        ]

    coordinator, client, transport, manifest, projection, grant, authority = _coordinator(
        tmp_path, responses,
    )
    lease = coordinator.claim()
    assert lease is not None
    completed = LocalCanaryExecutor(
        store=coordinator.store, identity=coordinator.identity, signer=coordinator.signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        lease.bundle, transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    coordinator.result(grant["run_id"], completed.operational_projection)
    findings = _findings_projection_with_scenarios(
        coordinator, manifest, projection, grant, **_FINDINGS_SHAPES[shape],
    )
    count = _FINDINGS_SHAPES[shape]["scenarios"]
    permit = _permit(authority, coordinator, grant, findings, scenario_count=count, finding_count=count)
    receipt_holder.update({
        "schema_version": "heel.canary-findings-receipt.v1",
        "receipt_id": "cfr_runner_recovered_upload",
        "workspace_id": grant["workspace_id"], "project_id": grant["project_id"],
        "run_id": grant["run_id"], "grant_id": grant["grant_id"],
        "permit_id": permit["permit_id"], "projection_id": findings["projection_id"],
        "projection_digest": findings["projection_digest"],
        "byte_count": len(canonical_bytes(findings)), "scenario_count": count,
        "finding_count": count, "accepted_at_ms": 2_001, "status": "synchronized",
    })
    with pytest.raises(ValueError, match="invalid runner findings receipt"):
        coordinator.upload_findings(
            grant["run_id"], permit=permit, findings_projection=findings,
        )
    (pending,) = client.runtime.load_pending_calls()
    assert pending.request_operation == "upload-findings"
    sealed_body = pending.body
    assert len(sealed_body) > 3072 and sealed_body == transport.requests[-1][2]
    assert sealed_body == canonical_bytes({
        "schema_version": "heel.runner-findings-upload.v1", "run_id": grant["run_id"], "permit": permit,
        "findings_projection": findings,
    })
    sends_before_restart = len(transport.requests)

    restarted = RunnerControlClient(
        origin=client.origin, workspace_id=client.workspace_id, runner_id=client.runner_id,
        signer=client.signer, clock=client.clock, transport=transport,
        nonce_source=client.nonce_source, trusted_disclosure_keys=client._trusted_disclosure_keys,
        runtime=client.runtime,
    )
    recovered = RunnerCoordinator(
        control=restarted, store=coordinator.store, identity=coordinator.identity,
        signer=coordinator.signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        clock_ms=lambda: 2_000, monotonic=lambda: 1.0,
    )

    assert len(transport.requests) == sends_before_restart + 1
    assert transport.requests[-1] == transport.requests[-2]
    assert transport.requests[-1][2] == sealed_body
    assert restarted.runtime.load_pending_calls() == ()
    assert restarted.runtime.load_terminal_state(grant["run_id"]).state == "consumed"
    assert recovered._bindings == {}
    with capsys.disabled():
        print(f"\n[T-P7 {shape}] findings upload body {len(sealed_body)} B replayed once after restart")


# ---------------------------------------------------------------------------
# R2 inactive-claim recovery (POSTRESET §5-§11, LOAD-GUARD T-W3, PRUNING C3/C4) over the REAL
# in-process control plane: real HTTP server, ControlPlane, CanaryRunService approval and grant
# signing, RunnerAuthStore PoP, and the real RunnerRuntimeState, RunnerStore, RunnerControlClient
# and RunnerCoordinator.  Labelled seams only:
#   PAIRING SEED   the runner identity, key and claim-chain cursor are inserted exactly as pairing
#                  activation stores them (no pairing ceremony runs here);
#   CLOCK SEAM     the runner's local clock (coordinator, executor, Store) may run ahead of the
#                  server; PoP timestamps always use the real wall clock; the monotonic gate clock
#                  is a constant so an execution gate is fresh;
#   FAULTY SERVER  a named test rewrites one real answer (status, headers, body) after the real
#                  server produced it;
#   TARGET SEAM    honest execution talks to the stop-test ScriptedTransport, never the network.

import http.client
import json
import socket
import sqlite3
import time
from contextlib import closing
from pathlib import Path

import heel.runner.daemon as daemon_module
from heel.canary_contracts import (
    INACTIVE_CLAIM_ATTESTATION_SCHEMA, inactive_claim_attestation_signing_payload,
    validate_inactive_claim_attestation,
)
from heel.crypto import verify_envelope
import heel.runner.control_client as control_module
from heel.runner.control_client import RunnerAuthenticationRejected, RunnerChainRecoveryDeferred
from heel.runner.control_transport import ControlTransportError
from heel.runner.coordinator import _signed_projection
from tests.test_runner_stop import resign_grant

_R2_GUARDED_TABLES = (
    "canary_runs", "canary_execution_grants", "canary_approval_projections", "canary_operational_receipts",
    "usage_ledger", "canary_runner_nonce_chains", "canary_runner_chain_cursors", "canary_runner_request_ledger",
    "canary_run_events", "canary_audit_records", "canary_runner_keys", "canary_runner_resync_challenges",
)
_R2_RUNTIME_TABLES = (
    "active_runs", "control_chains", "pending_calls", "terminal_disclosures", "chain_recovery", "retired_claims",
)


class _R2Http:
    """Real loopback HTTP to the in-process control plane; it records every exchange it carries.

    ``refuse`` fails one operation before it leaves (``ControlTransportError('connection_failed')``,
    as the production transport reports it); ``lose`` drops one answer after the server committed
    it; ``rewrite`` is the FAULTY SERVER hook and is set only by tests that say so.
    """

    def __init__(self, port):
        self.port = port
        self.sent: list[tuple[str, dict, bytes]] = []
        self.answers: list[tuple[str, int, bytes]] = []
        self.refuse: list[str] = []
        self.lose: list[str] = []
        self.rewrite: dict[str, object] = {}

    @staticmethod
    def operation(path):
        return path.rsplit("/", 1)[1]

    def post(self, path, *, headers=None, body=b""):
        operation = self.operation(path)
        self.sent.append((path, dict(headers or {}), body))
        if operation in self.refuse:
            self.refuse.remove(operation)
            raise ControlTransportError("connection_failed")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("POST", path, body, dict(headers or {}))
            response = conn.getresponse()
            raw = response.read()
            selected = {
                key: value for key, value in response.getheaders()
                if key in {"X-Heel-Runner-Next-Nonce", "Retry-After"}
            }
        finally:
            conn.close()
        self.answers.append((operation, response.status, raw))
        if operation in self.lose:
            self.lose.remove(operation)
            raise ControlTransportError("timeout")
        answer = (response.status, selected, json.loads(raw) if raw else None)
        rewrite = self.rewrite.pop(operation, None)
        return answer if rewrite is None else rewrite(*answer)

    def post_bounded(self, path, *, headers=None, body=b"", max_response_bytes):
        """The bounded read through the LOOPBACK DECODER ADAPTER (production ``_decode``): genuine wire bytes."""
        from tests.test_runner_control_http import _loopback_bounded

        operation = self.operation(path)
        assert operation not in self.rewrite  # no FAULTY SERVER rewrite of a bounded read here
        self.sent.append((path, dict(headers or {}), body))
        if operation in self.refuse:
            self.refuse.remove(operation)
            raise ControlTransportError("connection_failed")
        bounded = _loopback_bounded(self.port, path, headers=headers, body=body, max_response_bytes=max_response_bytes)
        self.answers.append((operation, bounded.status, bounded.body))
        if operation in self.lose:
            self.lose.remove(operation)
            raise ControlTransportError("timeout")
        return bounded

    def operations(self, since=0):
        return [self.operation(path) for path, _headers, _body in self.sent[since:]]


class _R2ProductionTransport:
    """The production pair: ``_AttributedTransport(HTTPSControlTransport)`` to the TLS edge harness.

    It only records what it carried (``answers`` hold the bounded reads' exact bodies)."""

    def __init__(self, edge):
        from heel.runner.control_transport import HTTPSControlTransport

        self.transport = daemon_module._AttributedTransport(HTTPSControlTransport(edge.origin, ca_bundle=edge.ca.ca_path))
        self.sent, self.answers = [], []

    def post(self, path, *, headers=None, body=b""):
        self.sent.append((path, dict(headers or {}), body))
        return self.transport.post(path, headers=headers, body=body)

    def post_bounded(self, path, *, headers=None, body=b"", max_response_bytes):
        self.sent.append((path, dict(headers or {}), body))
        bounded = self.transport.post_bounded(path, headers=headers, body=body, max_response_bytes=max_response_bytes)
        self.answers.append((_R2Http.operation(path), bounded.status, bounded.body))
        return bounded

    def operations(self, since=0):
        return [_R2Http.operation(path) for path, _headers, _body in self.sent[since:]]


class _R2Cloud:
    """One locally compiled approval pair, approved and granted by the real control plane.

    ``edge=True`` serves the same control plane behind the Python TLS edge harness and talks to it
    with the production transport pair; the workspace ID then has the edge's ``ws_`` + 16 hex shape.
    """

    def __init__(self, tmp_path, *, edge=False):
        import dataclasses

        from heel.saas.canary_runs import CanaryRunService
        from heel.saas.catalog import CATALOG_VERSION
        from heel.saas.runner_auth import NONCE_TTL
        from heel.saas.server import ControlPlane, serve
        from tests.test_runner_compiler import CanaryCompiler, add_roles, bound_store, context, map_scenarios
        from tests.test_runner_control_http import _enable_executable_protocol

        self.tmp = tmp_path
        self.edge = None
        if edge:
            from tests.support.edge_tls_harness import EdgeTLSHarness

            self.store, self.identity, self.signer = bound_store(
                tmp_path, selected_context=dataclasses.replace(context(), workspace_id="ws_0123456789abcdef"),
            )
            map_scenarios(self.store)
            add_roles(self.store)
            compiled = CanaryCompiler(
                store=self.store, identity=self.identity, signer=self.signer, now_ms=1_000,
            ).compile(["anonymous_authenticated_read", "object_ownership_read"])
            self.manifest, self.projection = compiled.manifest, compiled.projection
            authority = SigningAuthority.generate()
            self.edge = EdgeTLSHarness(
                tmp_path / "edge", grant_authority=authority,
                grant_trusted_keys={authority.key_id: authority.public_key},
            )
            self.cp = cp = self.edge.control_plane
            self.server = None
            self.http = _R2ProductionTransport(self.edge)
        else:
            self.store, self.identity, self.signer, self.manifest, self.projection = compiled_pair(tmp_path)
            self.cp = cp = ControlPlane(
                str(tmp_path / "control.sqlite"), runner_auth_pepper=b"r" * 32,
                grant_authority=SigningAuthority.generate(),
            )
            self.server = serve(cp)
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
            self.http = _R2Http(self.server.server_address[1])
        self.home = self.store.root
        self.runtime_path = self.home / "runner" / daemon_module._RUNTIME_FILENAME
        conn, now = cp.store.conn, time.time()
        self.workspace, self.runner_id = self.manifest["workspace_id"], self.identity.runner_id
        self.project = self.manifest["project_id"]
        conn.execute("INSERT INTO orgs VALUES(?,?,?)", ("org_canary", "org", now))
        conn.execute("INSERT INTO workspaces VALUES(?,?,?,?,?,?)",
                     (self.workspace, "org_canary", "Executor", "free", CATALOG_VERSION, now))
        conn.execute("INSERT INTO users VALUES(?,?,?)", ("user_owner", "owner@example.test", now))
        conn.execute("INSERT INTO memberships VALUES(?,?,?,?)", (self.workspace, "user_owner", "owner", now))
        conn.execute("INSERT INTO projects VALUES(?,?,?,?,?)", (self.workspace, self.project, "Executor", "user_owner", now))
        environment = self.manifest["environment"]
        conn.execute(
            "INSERT INTO canary_environments(environment_id,workspace_id,project_ref,origin,environment_class,"
            "status,created_at,attestation_text,attestation_version,attestation_acknowledgement,attested_by,"
            "attested_at,proof_method,proof_version,normalization_version,challenge_generation,last_check_at,"
            "verified_at,proof_expires_at,verification_record_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (environment["environment_id"], self.workspace, self.project, environment["origin"],
             environment["environment_class"], "verified", now,
             "ownership verified; environment classification supplied by you", "v1", "accepted", "user_owner",
             now, "https-file", "https-file.v1", "exact-origin.v1", 1, now, now, now + 86_400,
             environment["verification_record_digest"]),
        )
        # PAIRING SEED: the rows and claim cursor pairing activation stores (runner_auth.py activate).
        public_key = base64.b64encode(self.signer.public_key).decode("ascii")
        conn.execute("INSERT INTO canary_runners VALUES(?,?,?,?,?)", (self.runner_id, self.workspace, "Executor", "active", now))
        conn.execute("INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)",
                     (self.identity.key_id, self.workspace, self.runner_id, public_key, "active", now))
        auth = cp.runner_auth
        auth._save_identity(auth._identity_record(
            workspace_id=self.workspace, runner_id=self.runner_id, public_key=public_key,
            fingerprint=self.identity.fingerprint, key_id=self.identity.key_id,
            runner_version=self.identity.runner_version, adapters_json=json.dumps(self.identity.adapter_versions),
            paired_by="user_owner", paired_at=now, heartbeat_at=now,
        ), instant=now)
        _enable_executable_protocol(conn, self.workspace, self.runner_id)
        self.claim_nonce = base64.b64encode(os.urandom(32)).decode("ascii")
        conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)",
                     (self.workspace, self.runner_id, "claim", auth._hash("nonce", self.claim_nonce), 1, now + NONCE_TTL))
        conn.execute("INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)",
                     (self.workspace, self.runner_id, "claim", 1, 0, now))
        conn.commit()
        self.runs = CanaryRunService(conn, signing=cp.grant_authority, runner_auth=auth, initialize_schema=False)
        self.trusted = {cp.grant_authority.key_id: cp.grant_authority.public_key}
        self.offset_ms = 0
        self.runtime = None
        self.client = None
        self.coordinator = None
        self.challenges: list[bytes] = []

    # -- runner side ---------------------------------------------------------------------------
    def now_ms(self):
        """CLOCK SEAM: the runner's local clock; PoP timestamps use the real clock below."""
        return int(time.time() * 1000) + self.offset_ms

    def _random(self, size):
        value = os.urandom(size)
        self.challenges.append(value)
        return value

    def start(self, *, transport=None):
        """One runner process start: open the runtime by path, then the client, then the coordinator."""
        if self.runtime is not None:
            self.runtime.close()
        self.runtime = RunnerRuntimeState(self.runtime_path, self.identity, self.signer)
        if self.runtime.load_chain("claim", None) is None:
            self.runtime.install_chain(
                operation="claim", run_id=None, next_nonce_b64=self.claim_nonce,
                next_sequence=1, generation=0, now_ms=self.now_ms(),
            )
        self.store = RunnerStore(self.home)
        self.client = RunnerControlClient(
            origin="http://127.0.0.1", workspace_id=self.workspace, runner_id=self.runner_id,
            signer=self.signer, clock=lambda: int(time.time() * 1000),
            transport=self.http if transport is None else transport,
            nonce_source=lambda _key: (_ for _ in ()).throw(AssertionError("claim chains are Cloud-issued")),
            resync_random_source=self._random, trusted_disclosure_keys=self.trusted, runtime=self.runtime,
        )
        self.coordinator = None
        self.coordinator = RunnerCoordinator(
            control=self.client, store=self.store, identity=self.identity, signer=self.signer,
            trusted_grant_keys=self.trusted, clock_ms=self.now_ms, monotonic=lambda: 1.0,
        )
        return self.client, self.coordinator

    def runtime_rows(self):
        with closing(sqlite3.connect(self.runtime_path)) as conn:
            return {
                table: sorted(map(tuple, conn.execute(f"SELECT * FROM {table}"))) for table in _R2_RUNTIME_TABLES
            }

    def raw_group(self, run_id):
        """The exact sealed bytes of one run's active row, four chains and pending calls."""
        run_hash = hashlib.sha256(run_id.encode()).hexdigest()
        with closing(sqlite3.connect(self.runtime_path)) as conn:
            active = conn.execute("SELECT sealed_blob FROM active_runs WHERE run_hash=?", (run_hash,)).fetchall()
            chains = conn.execute(
                "SELECT operation,sealed_blob FROM control_chains WHERE run_hash=? ORDER BY operation", (run_hash,),
            ).fetchall()
            pending = conn.execute(
                "SELECT call_id,sealed_blob FROM pending_calls WHERE run_hash=? ORDER BY call_id", (run_hash,),
            ).fetchall()
        return [bytes(row[0]) for row in active], {row[0]: bytes(row[1]) for row in chains}, [
            (row[0], bytes(row[1])) for row in pending
        ]

    def store_tree(self):
        from tests.test_runner_store_probe import _context_path, _tree

        return _tree(_context_path(self.store))

    # -- cloud side ----------------------------------------------------------------------------
    def approve(self, *, projection=None):
        projection = self.projection if projection is None else projection
        submitted = self.runs.submit_projection(projection, uploaded_by="user_owner")
        return self.runs.approve(
            self.workspace, self.project, submitted["run_id"],
            projection_digest=projection["projection_digest"], actor="user_owner", role="owner",
            reason="Exercise inactive claim recovery over the real control plane",
            exact_hostname=self.manifest["egress"]["hostname"], recent_auth_at_ms=int(time.time() * 1000),
            idempotency_key="ca1-" + hashlib.sha256(projection["projection_digest"].encode()).hexdigest(),
            expected_kill_switch_generation=0,
        )["grant"]

    def request_stop(self, run_id):
        self.runs.request_stop(
            self.workspace, self.project, run_id, actor="user_owner", reason="cloud_stop",
            expected_kill_switch_generation=0,
        )

    def reap(self, seconds):
        """The reaper's orphan path at a later server instant (missing ACK -> terminal/stopped)."""
        from canary_test_support import Clock
        from heel.saas.canary_runs import CanaryRunService

        clock = Clock(time.time() + seconds)
        CanaryRunService(
            self.cp.store.conn, signing=self.cp.grant_authority, clock=clock, initialize_schema=False,
        ).expire_and_reconcile()

    def row(self, run_id):
        return tuple(self.cp.store.conn.execute(
            "SELECT status,execution_disposition,stop_reason,started_at_ms,stop_acknowledged_at_ms "
            "FROM canary_runs WHERE run_id=?", (run_id,),
        ).fetchone())

    def guarded(self):
        conn = self.cp.store.conn
        return {table: sorted(map(tuple, conn.execute(f"SELECT * FROM {table}"))) for table in _R2_GUARDED_TABLES}

    def audit(self):
        return [tuple(row) for row in self.cp.store.conn.execute(
            "SELECT run_id,authenticated_key_id,cloud_status FROM canary_inactive_claim_attestations "
            "ORDER BY created_at_ms,attestation_id",
        )]

    def close(self):
        if self.runtime is not None:
            self.runtime.close()
        if self.edge is not None:
            self.edge.close()
            return
        self.server.shutdown()
        self.server.server_close()
        self.cp.close()


@pytest.fixture
def r2_cloud(tmp_path):
    cloud = _R2Cloud(tmp_path)
    try:
        yield cloud
    finally:
        cloud.close()


def _r2_running(lease, signer, at_ms):
    """The runner's own signed running projection after ``lease``'s claimed projection."""
    unsigned = {
        key: copy.deepcopy(value) for key, value in lease.operational_projection.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    unsigned["event_sequence"] += 1
    unsigned["lifecycle_phase"] = "running"
    unsigned["timestamps"]["started_at_ms"] = at_ms
    unsigned["timestamps"]["updated_at_ms"] = at_ms
    return _signed_projection(unsigned, signer)


def _r2_activity_guards(monkeypatch, cloud):
    """Record every name resolution and refuse every vault, factory, DNS, reservation or executor use."""
    from heel.runner.execution import LocalCanaryExecutor as Executor

    seen = {"hosts": [], "forbidden": []}
    real_getaddrinfo = socket.getaddrinfo

    def getaddrinfo(host, *args, **kwargs):
        seen["hosts"].append(host)
        return real_getaddrinfo(host, *args, **kwargs)

    def forbidden(name):
        def refuse(*_args, **_kwargs):
            seen["forbidden"].append(name)
            raise AssertionError(f"{name} must not run during inactive-claim recovery")
        return refuse

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    for name in ("select_vault", "BoundedResolver", "TargetHTTPSClient"):
        monkeypatch.setattr(daemon_module, name, forbidden(name))
    monkeypatch.setattr(RunnerStore, "reserve_run", forbidden("reserve_run"))
    monkeypatch.setattr(RunnerStore, "recover_run_reservation", forbidden("recover_run_reservation"))
    monkeypatch.setattr(Executor, "execute", forbidden("LocalCanaryExecutor.execute"))
    return seen


def _r2_stuck_preactivation(cloud, *, stop=True, heartbeat_stop=True):
    """A real claim that never activated; the Cloud then stops it and the stopped gate is durable."""
    cloud.approve()
    cloud.start()
    lease = cloud.coordinator.claim()
    assert lease is not None
    if stop:
        cloud.request_stop(lease.run_id)
    if stop and heartbeat_stop:
        gate = cloud.coordinator.heartbeat(lease.run_id, lease.operational_projection)
        assert (gate.active, gate.stop_reason) == (False, "cloud_stop")
    return lease


def _r2_assert_retired_verbatim(cloud, run_id, before_group, *, pending_uncertain=0):
    record = cloud.runtime.load_retired_claim(run_id, authenticate_components=True)
    assert record is not None and record.reason == "cloud_inactive_attested"
    assert record.local_observations == {"reservation": "absent", "terminal": "absent"}
    active, chains, pending = before_group
    assert [base64.b64decode(record.active["sealed_blob_b64"])] == active
    assert {item["index"]["operation"]: base64.b64decode(item["sealed_blob_b64"]) for item in record.chains} == chains
    assert [(item["index"]["call_id"], base64.b64decode(item["sealed_blob_b64"])) for item in record.pending] == pending
    assert [item["delivery"] for item in record.pending] == ["uncertain"] * pending_uncertain
    # The archived response is the exact wire answer: a pinned-grant-authority signed attestation.
    archived = base64.b64decode(record.attestation["response"]["body_b64"])
    wire = [raw for operation, status, raw in cloud.http.answers if operation == "inactive-claim-attestation" and status == 200]
    assert wire and archived == wire[-1] and archived == json.dumps(json.loads(archived)).encode()
    response = json.loads(archived)
    request = json.loads(base64.b64decode(record.attestation["request"]["body_b64"]))
    assert validate_inactive_claim_attestation(response) == response
    verify_envelope(
        dict(cloud.trusted), {"signing_key_id": response["signing_key_id"], "signature_b64": response["signature_b64"]},
        inactive_claim_attestation_signing_payload(response),
    )
    assert response["schema_version"] == INACTIVE_CLAIM_ATTESTATION_SCHEMA
    assert response["run_id"] == request["run_id"] == run_id
    assert response["client_challenge_b64"] == request["client_challenge_b64"]
    assert record.attestation["request"]["path"].endswith(f"/runs/{run_id}/inactive-claim-attestation")
    return record, response


def test_fresh_coordinator_reconciles_preactivation_stop_then_claims_with_zero_vault_factory_dns_socket_or_target_activity(
    r2_cloud, monkeypatch,
):
    cloud = r2_cloud
    lease = _r2_stuck_preactivation(cloud)
    run_id = lease.run_id
    assert cloud.row(run_id)[:3] == ("stop_requested", None, "cloud_stop")
    group = cloud.raw_group(run_id)
    tree, guarded, sent = cloud.store_tree(), cloud.guarded(), len(cloud.http.sent)
    assert cloud.store.probe_run_reservation(run_id).value == "absent"
    seen = _r2_activity_guards(monkeypatch, cloud)

    client, coordinator = cloud.start()

    # Exactly one network exchange, the attestation, before any hydration or replay.
    assert cloud.http.operations(sent) == ["inactive-claim-attestation"]
    path, headers, body = cloud.http.sent[sent]
    assert set(headers) == {
        "Content-Type", "X-Heel-Runner-Id", "X-Heel-Runner-Key-Id", "X-Heel-Runner-Timestamp-Ms",
        "X-Heel-Runner-Signature",
    }
    request = json.loads(body)
    assert canonical_bytes(request) == body and len(body) <= 2048
    assert request["client_challenge_b64"] == base64.b64encode(cloud.challenges[-1]).decode("ascii")
    record, response = _r2_assert_retired_verbatim(cloud, run_id, group)
    assert response["cloud"]["status"] == "stop_requested" and response["cloud"]["stop_reason"] == "cloud_stop"
    # Nothing else: no runtime group, no tracking, no gate, no reservation, Store files unchanged.
    assert cloud.runtime.load_active_run_controls() == () and cloud.runtime.load_pending_calls() == ()
    assert all(cloud.runtime.load_chain(op, run_id) is None for op in ("heartbeat", "progress", "result", "stop-ack"))
    assert run_id not in client._tracked_runs and run_id not in client._run_guards
    assert not any(name.endswith(run_id) for name in client._chains)
    assert run_id not in coordinator._gates and run_id not in coordinator._bindings
    assert run_id not in coordinator._gate_receipts
    assert cloud.store_tree() == tree
    assert cloud.store.probe_run_reservation(run_id).value == "absent"
    # The Cloud wrote only its audit row; its stop actor and reason are preserved.
    assert cloud.guarded() == guarded and cloud.audit() == [(run_id, cloud.identity.key_id, "stop_requested")]
    with pytest.raises(ValueError, match="active runner claim is required"):
        coordinator.execution_gate(run_id)
    # Normal claiming continues: the idle poll is the next and only other request.
    assert coordinator.claim() is None
    assert cloud.http.operations(sent) == ["inactive-claim-attestation", "claim"]
    assert set(seen["hosts"]) == {"127.0.0.1"} and seen["forbidden"] == []
    assert record.created_at_ms <= cloud.now_ms()


def test_fresh_coordinator_crash_before_retirement_commit_reattests_with_a_new_challenge_and_changes_nothing_else(
    r2_cloud, monkeypatch,
):
    cloud = r2_cloud
    run_id = _r2_stuck_preactivation(cloud).run_id
    group, rows, tree = cloud.raw_group(run_id), cloud.runtime_rows(), cloud.store_tree()
    sent = len(cloud.http.sent)
    real_retire = RunnerRuntimeState.retire_inactive_claim

    def crash_before_commit(self, *args, **kwargs):
        raise KeyboardInterrupt("synthetic process death before the retirement transaction")

    monkeypatch.setattr(RunnerRuntimeState, "retire_inactive_claim", crash_before_commit)
    with pytest.raises(KeyboardInterrupt):
        cloud.start()
    first = json.loads(cloud.http.sent[sent][2])["client_challenge_b64"]
    assert cloud.http.operations(sent) == ["inactive-claim-attestation"]
    assert cloud.runtime_rows() == rows and cloud.store_tree() == tree

    monkeypatch.setattr(RunnerRuntimeState, "retire_inactive_claim", real_retire)
    cloud.start()
    second = json.loads(cloud.http.sent[sent + 1][2])["client_challenge_b64"]
    assert cloud.http.operations(sent) == ["inactive-claim-attestation"] * 2 and second != first
    _r2_assert_retired_verbatim(cloud, run_id, group)
    assert len(cloud.audit()) == 2 and cloud.store_tree() == tree


def test_fresh_coordinator_crash_after_retirement_commit_before_the_cache_drop_restarts_clean(r2_cloud, monkeypatch):
    cloud = r2_cloud
    run_id = _r2_stuck_preactivation(cloud).run_id
    group = cloud.raw_group(run_id)
    real_retire = RunnerRuntimeState.retire_inactive_claim

    def crash_after_commit(self, *args, **kwargs):
        real_retire(self, *args, **kwargs)
        raise KeyboardInterrupt("synthetic process death after commit, before the client cache drop")

    monkeypatch.setattr(RunnerRuntimeState, "retire_inactive_claim", crash_after_commit)
    with pytest.raises(KeyboardInterrupt):
        cloud.start()
    monkeypatch.setattr(RunnerRuntimeState, "retire_inactive_claim", real_retire)
    sent = len(cloud.http.sent)
    client, coordinator = cloud.start()
    assert cloud.http.operations(sent) == []  # nothing left to attest, nothing replayed
    _r2_assert_retired_verbatim(cloud, run_id, group)
    assert client._tracked_runs == set() and coordinator._gates == {}
    assert coordinator.claim() is None


_R2_BLOCKED = {
    # case: (stop the run first, expected daemon (state, code), exception type)
    "401-revoked": (True, ("rejected", "runner_authentication_rejected"), "RunnerAuthenticationRejected"),
    "401-rotated": (True, ("rejected", "runner_authentication_rejected"), "RunnerAuthenticationRejected"),
    "403-legacy-protocol": (True, ("failed", "protocol_upgrade_required"), "_ControlCallRejected"),
    "409-run-live": (False, ("offline", "inactive_claim_waiting_for_cloud"), "RunnerInactiveClaimRecoveryWaiting"),
    "409-binding-mismatch": (True, ("failed", "recovery_required"), "RunnerInactiveClaimRecoveryBlocked"),
    "409-cloud-observed-execution": (True, ("failed", "recovery_required"), "RunnerInactiveClaimRecoveryBlocked"),
    "429-rate-limited": (True, ("offline", "recovery_rate_limited"), "RunnerChainRecoveryDeferred"),
    "transport-failure": (True, ("offline", "connection_failed"), "ControlTransportError"),
}


@pytest.mark.parametrize("case", sorted(_R2_BLOCKED))
def test_fresh_coordinator_recovery_blocked_states_keep_the_active_group_for_401_403_409_429_and_transport_failure(
    r2_cloud, case,
):
    cloud = r2_cloud
    stop, expected, error_name = _R2_BLOCKED[case]
    error_type = {"_ControlCallRejected": daemon_module._ControlCallRejected,
                  "ControlTransportError": ControlTransportError}.get(error_name) or getattr(control_module, error_name)
    lease = _r2_stuck_preactivation(cloud, stop=False)
    run_id = lease.run_id
    conn = cloud.cp.store.conn
    if case == "409-cloud-observed-execution":
        cloud.coordinator.heartbeat(run_id, _r2_running(lease, cloud.signer, lease.operational_projection["timestamps"]["claimed_at_ms"] + 1))
        assert cloud.row(run_id)[3] is not None
    if stop:
        cloud.request_stop(run_id)
    cloud.offset_ms = 601_000  # CLOCK SEAM: the local grant has expired (L2) without a local stop gate
    if case == "401-revoked":
        conn.execute("UPDATE canary_runner_keys SET status='revoked',revoked_at=? WHERE key_id=?", (time.time(), cloud.identity.key_id))
    elif case == "401-rotated":
        conn.execute("UPDATE canary_runner_keys SET status='verification_only' WHERE key_id=?", (cloud.identity.key_id,))
    elif case == "403-legacy-protocol":
        conn.execute("DELETE FROM canary_runner_execution_protocols WHERE workspace_id=? AND runner_id=?",
                     (cloud.workspace, cloud.runner_id))
    elif case == "409-binding-mismatch":
        conn.execute("UPDATE canary_execution_grants SET grant_digest=? WHERE run_id=?", ("f" * 64, run_id))
    elif case == "429-rate-limited":
        for index in range(3):
            conn.execute(
                "INSERT INTO canary_inactive_claim_attestations VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                ("ica_" + f"{index:032x}", cloud.workspace, cloud.runner_id, run_id, "grant_seed",
                 cloud.identity.key_id, "a" * 64, "b" * 64, "stop_requested", int(time.time() * 1000),
                 int(time.time() * 1000) + 1),
            )
    elif case == "transport-failure":
        cloud.http.refuse.append("inactive-claim-attestation")
    conn.commit()
    rows, tree, sent = cloud.runtime_rows(), cloud.store_tree(), len(cloud.http.sent)
    audit = cloud.audit()

    with pytest.raises(error_type) as blocked:
        cloud.start(transport=daemon_module._AttributedTransport(cloud.http))

    assert daemon_module._serve_failure(blocked.value) == expected
    if case == "409-run-live":
        assert blocked.value.retry_after_ms >= 1_000
    if case in {"409-binding-mismatch", "409-cloud-observed-execution"}:
        assert blocked.value.reason == case.split("-", 1)[1].replace("-", "_")
    assert cloud.http.operations(sent) == ["inactive-claim-attestation"]
    assert cloud.runtime_rows() == rows and cloud.store_tree() == tree
    assert cloud.runtime.load_retired_claim(run_id) is None
    assert cloud.audit() == audit


def test_grant_expired_unstopped_claim_waits_for_cloud_then_recovers_without_new_target_traffic(r2_cloud, monkeypatch):
    from heel.saas.canary_reaper import CanaryReaper

    cloud = r2_cloud
    run_id = _r2_stuck_preactivation(cloud, stop=False).run_id
    group = cloud.raw_group(run_id)
    cloud.offset_ms = 601_000  # CLOCK SEAM: the local grant expired; the Cloud has not reaped yet
    seen = _r2_activity_guards(monkeypatch, cloud)
    with pytest.raises(control_module.RunnerInactiveClaimRecoveryWaiting):
        cloud.start(transport=daemon_module._AttributedTransport(cloud.http))
    assert cloud.runtime.load_active_run_controls()[0].run_id == run_id
    # One reaper cycle persists the stop for the expired grant; no runner action is involved.
    reaper = CanaryReaper(
        str(cloud.tmp / "control.sqlite"), signing=cloud.cp.grant_authority,
        runner_auth_pepper=b"r" * 32, clock=lambda: time.time() + 700,
    )
    assert reaper.run_once()["authority_stops"] == 1
    assert cloud.row(run_id)[:4] == ("stop_requested", None, "cloud_stop", None)
    sent = len(cloud.http.sent)
    cloud.start(transport=daemon_module._AttributedTransport(cloud.http))
    _r2_assert_retired_verbatim(cloud, run_id, group)
    assert cloud.coordinator.claim() is None
    assert cloud.http.operations(sent) == ["inactive-claim-attestation", "claim"]
    assert set(seen["hosts"]) == {"127.0.0.1"} and seen["forbidden"] == []


@pytest.mark.parametrize("loss", ["lost-response", "ledger-expired"])
def test_fresh_coordinator_recovery_seals_lost_response_and_ledger_expired_pending_heartbeats_as_uncertain(
    r2_cloud, monkeypatch, loss,
):
    from canary_test_support import Clock
    from heel.saas.runner_auth import RunnerAuthStore

    cloud = r2_cloud
    lease = _r2_stuck_preactivation(cloud, stop=False)
    run_id = lease.run_id
    # The pre-activation heartbeat is accepted by the Cloud, but its answer never arrives.
    cloud.http.lose.append("heartbeat")
    with pytest.raises(ControlTransportError):
        cloud.coordinator.heartbeat(run_id, lease.operational_projection)
    (pending,) = cloud.runtime.load_pending_calls()
    assert (pending.request_operation, pending.run_id) == ("heartbeat", run_id)
    assert cloud.http.answers[-1][:2] == ("heartbeat", 200)  # the Cloud accepted it; the answer was lost
    cloud.request_stop(run_id)
    if loss == "ledger-expired":
        auth = RunnerAuthStore(cloud.cp.store.conn, pepper=b"r" * 32, now=Clock(time.time() + 31 * 86_400))
        while auth.purge_runner_request_receipts(time.time() + 31 * 86_400)[1]:
            pass
        assert cloud.cp.store.conn.execute("SELECT COUNT(*) FROM canary_runner_request_ledger").fetchone()[0] == 0
    cloud.offset_ms = 601_000  # CLOCK SEAM: L2 by local expiry; the durable gate is still the claim gate
    group = cloud.raw_group(run_id)
    ledger = cloud.guarded()["canary_runner_request_ledger"]
    sent = len(cloud.http.sent)
    seen = _r2_activity_guards(monkeypatch, cloud)

    cloud.start()

    # The old heartbeat is never resent: the pending bytes are archived as delivery-uncertain.
    assert cloud.http.operations(sent) == ["inactive-claim-attestation"]
    record, _response = _r2_assert_retired_verbatim(cloud, run_id, group, pending_uncertain=1)
    assert record.pending[0]["index"]["operation"] == "heartbeat"
    assert cloud.runtime.load_pending_calls() == ()
    assert cloud.guarded()["canary_runner_request_ledger"] == ledger
    assert cloud.coordinator.claim() is None
    assert seen["forbidden"] == []


def _r2_old_claim_body(cloud):
    (raw,) = [raw for operation, status, raw in cloud.http.answers if operation == "claim" and status == 200]
    return json.loads(raw)


def _r2_faulty_claim_replay(body):
    """FAULTY SERVER: answer a fresh, really consumed claim poll with an OLD, already-signed claim body."""
    def rewrite(status, headers, payload):
        assert status in {200, 204}  # the real server answered (and advanced the claim chain)
        return 200, headers, copy.deepcopy(body)
    return rewrite


def test_fresh_coordinator_rejects_a_claim_response_naming_the_retired_run_and_exposes_no_gate(r2_cloud):
    """LOAD-GUARD T-W3 over real HTTP; the replayed body is a FAULTY SERVER fixture."""
    cloud = r2_cloud
    run_id = _r2_stuck_preactivation(cloud).run_id
    old = _r2_old_claim_body(cloud)
    client, coordinator = cloud.start()
    assert cloud.runtime.load_retired_claim(run_id) is not None
    tree = cloud.store_tree()
    cloud.http.rewrite["claim"] = _r2_faulty_claim_replay(old)

    with pytest.raises(ValueError):
        coordinator.claim()

    with pytest.raises(ValueError, match="active runner claim is required"):
        coordinator.execution_gate(run_id)
    assert run_id not in coordinator._gates and run_id not in client._tracked_runs
    assert cloud.runtime.load_active_run_controls() == ()
    assert [(item.request_operation, item.run_id) for item in cloud.runtime.load_pending_calls()] == [("claim", None)]
    assert cloud.store_tree() == tree and cloud.store.probe_run_reservation(run_id).value == "absent"


def _r2_honest_execution(cloud, lease, *, observed):
    """The run executes honestly against the TARGET SEAM; ``observed`` sends one running heartbeat."""
    executor = LocalCanaryExecutor(
        store=cloud.store, identity=cloud.identity, signer=cloud.signer, trusted_grant_keys=cloud.trusted,
        vaults={"ephemeral_env": StaticVault()}, clock_ms=cloud.now_ms, monotonic=lambda: 1.0,
    )
    progress = []
    target = ScriptedTransport([401, 200, 200, 403])
    outcome = RunnerExecutionAdapter(coordinator=cloud.coordinator, executor=executor, transport=target).execute(
        lease, cancellation=CancellationToken(), on_progress=progress.append,
    )
    assert outcome.operational_projection["execution_disposition"] == "completed"
    assert len(target.calls) == 4
    if observed:
        running = next(item for item in progress if item["lifecycle_phase"] == "running")
        cloud.coordinator.heartbeat(lease.run_id, running)
        assert cloud.row(lease.run_id)[3] is not None  # the Cloud observed the start
    return target


def _r2_prune(cloud, run_id):
    """Real local terminal -> detach -> due prune -> Store prune -> finish -> compaction."""
    runtime, store = cloud.runtime, cloud.store
    local = runtime.register_local_terminal(**store._runtime_terminal_anchor(run_id))
    store.detach_terminal(run_id, runtime=runtime, expected_local_state_digest=local.state_digest, now_ms=cloud.now_ms())
    retention = store.load_run(run_id)["retention_expires_at_ms"]
    cloud.offset_ms = retention - int(time.time() * 1000)  # CLOCK SEAM: the local clock reaches retention
    pending = runtime.claim_due_prune(now_ms=retention)[0]
    receipt = store.prune_runtime_terminal(
        run_id, runtime=runtime, expected_runtime_state_digest=pending.state_digest, now_ms=retention,
    )
    completion = runtime.finish_prune(receipt=receipt, expected_prune_pending_state_digest=pending.state_digest)
    store.finish_pruned_compaction(completion, runtime=runtime)
    assert store.probe_run_reservation(run_id).value == "absent"
    return retention


def _r2_resurrect(cloud, old):
    """Restart, then a FAULTY SERVER answers the fresh claim with the pruned run's old signed body."""
    cloud.offset_ms += 1_000
    client, coordinator = cloud.start()
    assert cloud.runtime.load_active_run_controls() == ()
    cloud.http.rewrite["claim"] = _r2_faulty_claim_replay(old)
    with pytest.raises(ValueError, match="execution grant is expired or not yet valid"):
        coordinator.claim()
    return client, coordinator


@pytest.mark.parametrize("observed", [True, False], ids=["cloud-observed-execution", "cloud-saw-no-execution"])
def test_coordinator_fails_closed_when_a_claim_response_resurrects_a_pruned_run(r2_cloud, observed):
    """PRUNING C3 over real HTTP: the replayed claim body is a FAULTY SERVER fixture."""
    cloud = r2_cloud
    cloud.approve()
    cloud.start()
    lease = cloud.coordinator.claim()
    run_id = lease.run_id
    old = _r2_old_claim_body(cloud)
    target = _r2_honest_execution(cloud, lease, observed=observed)
    _r2_prune(cloud, run_id)
    tree = cloud.store_tree()

    client, coordinator = _r2_resurrect(cloud, old)

    # commit_call installed the group before bundle validation refused it; nothing else happened.
    assert [item.run_id for item in cloud.runtime.load_active_run_controls()] == [run_id]
    assert run_id not in coordinator._gates
    with pytest.raises(ValueError, match="active runner claim is required"):
        coordinator.execution_gate(run_id)
    assert cloud.store_tree() == tree and cloud.store.probe_run_reservation(run_id).value == "absent"
    assert len(target.calls) == 4
    group = cloud.raw_group(run_id)

    # Reconstruction: the real Cloud decides.  Observed execution keeps the row; otherwise retire.
    cloud.request_stop(run_id)
    if observed:
        rows = cloud.runtime_rows()
        with pytest.raises(control_module.RunnerInactiveClaimRecoveryBlocked) as blocked:
            cloud.start()
        assert blocked.value.reason == "cloud_observed_execution"
        assert cloud.runtime_rows() == rows and cloud.runtime.load_retired_claim(run_id) is None
    else:
        cloud.reap(3_600)
        assert cloud.row(run_id)[:3] == ("terminal", "stopped", "cloud_stop")
        cloud.start()
        _r2_assert_retired_verbatim(cloud, run_id, group)
        assert cloud.runtime.load_active_run_controls() == ()
    assert cloud.store_tree() == tree and len(target.calls) == 4


def test_fresh_claim_replaying_a_pruned_runs_signed_body_cannot_lease_reserve_or_execute(r2_cloud, monkeypatch):
    """PRUNING C4 over real HTTP: compiler pair, 600 s Cloud grant, honest execution, real prune and
    compaction, restart, then a FAULTY SERVER replays the old signed claim body on a fresh claim."""
    cloud = r2_cloud
    cloud.approve()
    cloud.start()
    lease = cloud.coordinator.claim()
    run_id = lease.run_id
    assert lease.bundle.grant["expires_at_ms"] - lease.bundle.grant["issued_at_ms"] == 600_000
    assert cloud.manifest["local_evidence_policy"]["retention_seconds"] == 86_400
    old = _r2_old_claim_body(cloud)
    target = _r2_honest_execution(cloud, lease, observed=False)
    retention = _r2_prune(cloud, run_id)
    runs = cloud.store.run_path(run_id).parent
    assert {path.name for path in runs.iterdir()} == {"run-authority-checkpoint.json", "run-authority-index.json"}
    floor = json.loads((runs / "run-authority-checkpoint.json").read_bytes())
    floor = floor.get("time_floor_ms", floor.get("core", {}).get("time_floor_ms"))
    assert floor >= lease.bundle.grant["expires_at_ms"]

    client, coordinator = _r2_resurrect(cloud, old)

    # No lease, gate, reservation or target request; tracking staleness carries no authority.
    assert run_id in client._tracked_runs and run_id not in coordinator._gates
    with pytest.raises(ValueError, match="active runner claim is required"):
        coordinator.execution_gate(run_id)
    with pytest.raises(ValueError, match="active runner claim is required"):
        coordinator.heartbeat(run_id, lease.operational_projection)
    with pytest.raises(ValueError):
        cloud.store.reserve_run(lease.bundle.grant, retention_expires_at_ms=retention + 86_400_000)
    assert {path.name for path in runs.iterdir()} == {"run-authority-checkpoint.json", "run-authority-index.json"}
    assert len(target.calls) == 4
    # The stuck row is exactly C's eligible state (L2 expiry, L3 absent, L4, L5): a restart asks the
    # Cloud for an attestation and changes nothing locally when the request cannot leave.
    rows = cloud.runtime_rows()
    sent = len(cloud.http.sent)
    cloud.http.refuse.append("inactive-claim-attestation")
    with pytest.raises(ControlTransportError):
        cloud.start()
    assert cloud.http.operations(sent) == ["inactive-claim-attestation"]
    assert cloud.runtime_rows() == rows


def test_short_retention_prune_refusal_keeps_its_roots_and_a_second_honest_run_and_maintenance_proceed(tmp_path):
    """PRUNING INFERRED gate (TAMPERED, NON-COMPILER pair, labelled): after the refused compaction the
    first restart fails closed once; later restarts, a second honest run and maintenance proceed."""
    from heel.canary_contracts import validate_approval_projection, validate_test_manifest
    from tests.test_runner_stop import _install_runtime_active_claim

    store, identity, signer, compiled_manifest, compiled_projection = compiled_pair(tmp_path)
    tampered = copy.deepcopy(compiled_manifest)
    tampered.pop("manifest_digest")
    tampered["local_evidence_policy"]["retention_seconds"] = 60
    tampered["manifest_digest"] = canonical_digest(tampered)
    manifest = validate_test_manifest(tampered)
    unsigned = {
        key: copy.deepcopy(value) for key, value in compiled_projection.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    unsigned["manifest_digest"] = manifest["manifest_digest"]
    unsigned["projection_id"] = f"projection_{manifest['manifest_digest'][:24]}"
    projection = validate_approval_projection({
        **unsigned, "projection_digest": canonical_digest(unsigned), "signing_key_id": identity.key_id,
        "signature_b64": base64.b64encode(signer.sign(canonical_bytes(unsigned))).decode("ascii"),
    })
    store.save_approved_pair(manifest, projection)
    authority = SigningAuthority.generate()
    trusted = {authority.key_id: authority.public_key}
    grant = signed_grant(manifest, projection, identity, authority, expires=601_000)
    run_id = grant["run_id"]

    def executor(clock):
        return LocalCanaryExecutor(
            store=store, identity=identity, signer=signer, trusted_grant_keys=trusted,
            vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: clock, monotonic=lambda: 1.0,
        )

    executor(2_000).execute(ExecutionBundle(manifest, projection, grant), transport=ScriptedTransport([401, 200, 200, 403]),
                            gate_source=active_gate)
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    _install_runtime_active_claim(runtime, identity, signer, projection, grant)
    local = runtime.register_local_terminal(**store._runtime_terminal_anchor(run_id))
    store.detach_terminal(run_id, runtime=runtime, expected_local_state_digest=local.state_digest, now_ms=2_000)
    retention = store.load_run(run_id)["retention_expires_at_ms"]
    pending = runtime.claim_due_prune(now_ms=retention)[0]
    with pytest.raises(RunnerStoreError, match="local run authority compaction entry is invalid"):
        store.prune_runtime_terminal(run_id, runtime=runtime, expected_runtime_state_digest=pending.state_digest, now_ms=retention)
    roots = {
        f"grant-{grant['grant_digest']}.json",
        store._run_authority_record_filename("reserve", run_hash := store._run_hash(run_id)),
        store._run_authority_record_filename("terminal", run_hash),
        store._run_authority_record_filename("detach_terminal", run_hash),
        store._run_authority_record_filename("prune", run_hash),
    }
    runs = store.run_path(run_id).parent

    def restart(clock, responses=()):
        transport = ScriptedControlTransport(list(responses))
        client = RunnerControlClient(
            origin="https://control.example", workspace_id=identity.workspace_id, runner_id=identity.runner_id,
            signer=signer, clock=lambda: clock, transport=transport, nonce_source=lambda _key: _nonce(b"c"),
            trusted_disclosure_keys=trusted, runtime=runtime,
        )
        return RunnerCoordinator(
            control=client, store=store, identity=identity, signer=signer, trusted_grant_keys=trusted,
            clock_ms=lambda: clock, monotonic=lambda: 1.0,
        ), transport

    # Observed (pre-existing, tampered state only): the first restart finishes the runtime prune
    # and then fails closed on the invalid compaction entry; nothing of the roots is removed.
    with pytest.raises(RunnerStoreError, match="local run authority compaction completion is unavailable"):
        restart(retention + 10)
    assert roots <= {path.name for path in runs.iterdir()}
    coordinator, _transport = restart(retention + 20)
    assert coordinator.maintenance_once(now_ms=retention + 30).processed == 0
    assert store.probe_run_reservation(run_id).value == "reserved"
    # A second honest run (distinct grant, real claim decode, real executor) and maintenance proceed.
    second = dict(signed_grant(compiled_manifest, compiled_projection, identity, authority,
                               issued=retention + 40, expires=retention + 600_040))
    second.update(run_id="crun_" + "b" * 32, grant_id="grant_987654321")
    second = resign_grant(second, authority)
    claim = _claim(compiled_manifest, compiled_projection, second)
    claim["gate"] = _gate(server_time_ms=retention + 50, generation=7, proof_expires_at_ms=retention + 100_000)
    coordinator, _transport = restart(retention + 50, [(200, {"X-Heel-Runner-Next-Nonce": _nonce(b"m")}, claim)])
    lease = coordinator.claim()
    target = ScriptedTransport([401, 200, 200, 403])
    outcome = RunnerExecutionAdapter(coordinator=coordinator, executor=executor(retention + 50), transport=target).execute(
        lease, cancellation=CancellationToken(), on_progress=lambda _projection: None,
    )
    assert outcome.operational_projection["execution_disposition"] == "completed" and len(target.calls) == 4
    assert coordinator.maintenance_once(now_ms=retention + 60).processed == 0
    assert roots <= {path.name for path in runs.iterdir()}
    assert store.probe_run_reservation(run_id).value == "reserved"


def test_serve_cycle_composition_reconciles_before_hydration_then_polls(r2_cloud, monkeypatch):
    """The daemon's own serve cycle (runtime by path -> client -> coordinator -> RunnerService) over
    loopback, so the recovery runs in the production startup order, not a hand-ordered fixture."""
    cloud = r2_cloud
    run_id = _r2_stuck_preactivation(cloud).run_id
    group = cloud.raw_group(run_id)
    cloud.runtime.close()
    cloud.runtime = None
    seen = _r2_activity_guards(monkeypatch, cloud)
    sent = len(cloud.http.sent)
    record = {"origin": "http://127.0.0.1", "runner_id": cloud.runner_id}

    class LoopbackDaemon(daemon_module.RunnerDaemon):
        def _transport(self, origin):
            assert origin == record["origin"]
            return cloud.http

        def _load_record(self, store):
            return record

    daemon = LoopbackDaemon(cloud.home, clock_ms=cloud.now_ms)
    directory = os.open(cloud.tmp, os.O_RDONLY | os.O_DIRECTORY)
    try:
        session = daemon_module._ServeSession(daemon, directory, record, once=True, emit=lambda _event: None)
        session.identity, session.signer, session.trusted = cloud.identity, cloud.signer, dict(cloud.trusted)
        session._cycle()
    finally:
        os.close(directory)
    assert cloud.http.operations(sent) == ["inactive-claim-attestation", "claim"]
    cloud.runtime = RunnerRuntimeState(cloud.runtime_path, cloud.identity, cloud.signer)
    _r2_assert_retired_verbatim(cloud, run_id, group)
    assert set(seen["hosts"]) == {"127.0.0.1"} and seen["forbidden"] == []


def test_attestation_without_a_bounded_transport_fails_closed_and_keeps_the_claim(r2_cloud):
    """Design test 6: a post-only adapter never falls back to ``post``; the sealed group is kept."""
    cloud = r2_cloud
    run_id = _r2_stuck_preactivation(cloud).run_id
    rows, tree, sent = cloud.runtime_rows(), cloud.store_tree(), len(cloud.http.sent)

    class PostOnly:
        def post(self, path, *, headers=None, body=b""):
            return cloud.http.post(path, headers=headers, body=body)

    with pytest.raises(control_module.RunnerInactiveClaimRecoveryBlocked) as blocked:
        cloud.start(transport=PostOnly())
    assert blocked.value.reason == "transport_capability_missing"
    assert daemon_module._serve_failure(blocked.value) == ("failed", "recovery_required")
    assert cloud.http.operations(sent) == [] and cloud.audit() == []
    assert cloud.runtime_rows() == rows and cloud.store_tree() == tree
    assert cloud.runtime.load_retired_claim(run_id) is None


def test_tls_edge_recovery_uses_the_production_transport_and_archives_the_edge_wire_bytes(tmp_path, monkeypatch):
    """One real recovery exchange: HTTPSControlTransport + _AttributedTransport -> Python TLS edge
    harness -> real control plane.  The Cloudflare Worker itself is not exercised here."""
    cloud = _R2Cloud(tmp_path, edge=True)
    try:
        run_id = _r2_stuck_preactivation(cloud).run_id
        group = cloud.raw_group(run_id)
        seen = _r2_activity_guards(monkeypatch, cloud)
        sent = len(cloud.http.sent)
        cloud.start()
        assert cloud.http.operations(sent) == ["inactive-claim-attestation"]
        record, response = _r2_assert_retired_verbatim(cloud, run_id, group)
        archived = base64.b64decode(record.attestation["response"]["body_b64"])
        assert archived != canonical_bytes(response)
        assert ("POST", f"/v1/workspaces/{cloud.workspace}/runners/{cloud.runner_id}/runs/{run_id}/inactive-claim-attestation") \
            in cloud.edge.forwarded
        assert cloud.coordinator.claim() is None
        assert set(seen["hosts"]) <= {"localhost", "127.0.0.1"} and seen["forbidden"] == []  # client and edge hop
    finally:
        cloud.close()
