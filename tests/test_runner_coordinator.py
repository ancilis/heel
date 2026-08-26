from __future__ import annotations

import base64
import copy
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
from heel.runner.execution import ExecutionBundle, ExecutionGate
from heel.runner.service import ClaimLease, RunnerService
from heel.runner.store import RunnerStore, RunnerStoreError
from heel.runner.runtime import RunnerRuntimeState
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
    expires_at_ms=602_000,
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
            "scenario_count": 0, "finding_count": 0,
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
    coordinator, _, transport, manifest, projection, grant, _ = _coordinator(
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

    gate = coordinator.heartbeat(lease.run_id, lease.operational_projection)
    assert gate == ExecutionGate(**_gate(server_time_ms=2_001))
    assert transport.requests[-1][1]["X-Heel-Runner-Nonce"] == _nonce(b"h")
    assert transport.requests[-1][1]["X-Heel-Runner-Sequence"] == "4"


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
    coordinator, _, _, _, _, _, _ = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"a")}, _gate()),
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"b")},
             _gate(server_time_ms=2_001, generation=6)),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None
    with pytest.raises(ValueError, match="did not advance"):
        coordinator.heartbeat(lease.run_id, lease.operational_projection)
    with pytest.raises(ValueError, match="generation regressed"):
        coordinator.heartbeat(lease.run_id, lease.operational_projection)


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
    coordinator, client, _, _, projection, grant, _ = _coordinator(
        tmp_path,
        lambda manifest, projection, grant: [
            (200, {"X-Heel-Runner-Next-Nonce": _nonce(b"n")},
             _claim(manifest, projection, grant)),
        ],
    )
    lease = coordinator.claim()
    assert lease is not None
    second_run_id = "crun_" + "b" * 32
    with client._state_lock:
        client._tracked_runs.add(second_run_id)
        client._run_guards[second_run_id] = _RunGuard(threading.Lock(), object())
        for operation, marker, sequence in (
            ("heartbeat", b"h", 4), ("progress", b"p", 5),
            ("result", b"r", 6), ("stop-ack", b"s", 7),
        ):
            client._chains[f"{operation}:{second_run_id}"] = (_nonce(marker), sequence, 3)
            client.runtime.install_chain(
                operation=operation, run_id=second_run_id, next_nonce_b64=_nonce(marker),
                next_sequence=sequence, generation=3, now_ms=2_000,
            )
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
            )

    client.transport = ConcurrentTransport()
    running = _phase(lease.operational_projection, coordinator.signer, "running")
    second_running = _phase(
        lease.operational_projection, coordinator.signer, "running", run_id=second_run_id,
    )
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
