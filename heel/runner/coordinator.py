"""Fail-closed bridge from the local runner supervisor to fixed PoP control calls."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import math
import threading
import time
from types import MappingProxyType
from typing import Any, Callable, Mapping

from heel.canary_contracts import (
    OPERATIONAL_RUN_SCHEMA,
    canonical_bytes,
    canonical_digest,
    validate_canary_findings,
    validate_disclosure_permit,
    validate_operational_run,
)
from heel.crypto import verify_envelope
from heel.runner.control_client import RunnerControlClient
from heel.runner.execution import (
    ExecutionBundle,
    ExecutionGate,
    validate_execution_bundle,
)
from heel.runner.identity import RunnerIdentity, SecureSigner
from heel.runner.service import ClaimLease
from heel.runner.store import RunnerContext, RunnerStore, RunnerStoreError


_MAX_AUTHENTICATED_GATE_AGE_SECONDS = 0.5


def _signed_projection(unsigned: dict[str, Any], signer: SecureSigner) -> dict[str, Any]:
    signature = signer.sign(canonical_bytes(unsigned))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("runner signer returned an invalid projection signature")
    return validate_operational_run({
        **unsigned,
        "projection_digest": canonical_digest(unsigned),
        "signing_key_id": signer.key_id,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    })


@dataclass(frozen=True, slots=True)
class RunnerStopAcknowledgement:
    accepted: bool
    deadline_met: bool
    late: bool
    acknowledged_at_ms: int


@dataclass(frozen=True, slots=True)
class RunnerMaintenanceResult:
    """The bounded work completed by one terminal-maintenance tick."""

    processed: int
    has_more: bool


class RunnerCoordinator:
    """Decode only launch control contracts and expose the Task 6 coordinator protocol."""

    def __init__(
        self,
        *,
        control: RunnerControlClient,
        store: RunnerStore,
        identity: RunnerIdentity,
        signer: SecureSigner,
        trusted_grant_keys: Mapping[str, object],
        clock_ms=lambda: int(time.time() * 1000),
        monotonic=time.monotonic,
    ):
        if not isinstance(control, RunnerControlClient):
            raise TypeError("fixed runner control client is required")
        if not isinstance(store, RunnerStore) or not isinstance(identity, RunnerIdentity):
            raise TypeError("bound runner context is required")
        if (
            not isinstance(signer, SecureSigner)
            or signer.key_id != identity.key_id
            or control.workspace_id != identity.workspace_id
            or control.runner_id != identity.runner_id
            or control.signer is not signer
        ):
            raise ValueError("runner coordinator identity binding is invalid")
        if not isinstance(trusted_grant_keys, Mapping) or not trusted_grant_keys:
            raise ValueError("trusted grant authority is required")
        if not callable(clock_ms) or not callable(monotonic):
            raise TypeError("runner coordinator clocks are required")
        # A coordinator is the authenticated runtime boundary for a store opened
        # during restart recovery.  Pin once here; the store rejects a different
        # identity on every later mutation.
        store._pin_runtime_authority(identity, signer)
        self.control = control
        self.store = store
        self.identity = identity
        self.signer = signer
        self.store._pin_runtime_authority(identity, signer)
        trust = dict(trusted_grant_keys)
        if dict(control._trusted_disclosure_keys) != trust:
            raise ValueError("runner control disclosure authority binding is invalid")
        self.trusted_grant_keys = MappingProxyType(trust)
        self.clock_ms = clock_ms
        self.monotonic = monotonic
        self._gates: dict[str, ExecutionGate] = {}
        self._gate_receipts: dict[str, float] = {}
        self._bindings: dict[str, tuple[str, str, str]] = {}
        self._terminal_runs: set[str] = set()
        self._lock = threading.Lock()
        # The client serializes its signed chain, but the coordinator also owns
        # the in-memory gate snapshot.  Keep the read -> signed heartbeat ->
        # publish transition serialized per run so a newer durable stop gate
        # can never lose a race to an older coordinator snapshot.
        self._heartbeat_guards: dict[str, threading.Lock] = {}
        self._maintenance_lock = threading.Lock()
        self._pending_result_replay_verifier = store.pending_result_replay_verifier(control.runtime)
        try:
            self._recover_terminal_runtime_state()
            self._recover_active_runtime_state()
            self._stage_unstaged_terminal_results()
            self._replay_pending_calls()
            # A replayed claim may atomically install its active row and four
            # cursors after the first hydration pass.  Re-open that sealed
            # authority before exposing the coordinator; otherwise the client
            # tracks the run while the coordinator has no grant/binding/gate.
            self._recover_active_runtime_state()
        except RunnerStoreError as exc:
            # A signed Cloud rollover is completed by ensure_runner_context
            # before any terminal/run recovery can touch the namespace.
            if str(exc) != "cloud context rollover requires recovery":
                raise

    def _replay_pending_calls(self) -> None:
        """Drain durable calls before exposing a coordinator to polling or execution."""
        while True:
            pending = self.control.runtime.load_pending_calls(limit=74)
            if not pending:
                # The client owns the startup-barrier bit; let its zero-pending
                # path clear that bit without generating a transport request.
                self.control.replay_all_pending(
                    now_ms=self._now_ms(), result_verifier=self._pending_result_replay_verifier,
                )
                break
            for item in pending:
                if item.request_operation == "upload-findings":
                    # Findings recovery remains lease/permit bound.  Re-enter
                    # the coordinator rather than allowing the client to infer
                    # disclosure authority from an available runtime row alone.
                    try:
                        request = json.loads(item.body.decode("utf-8"))
                        if (
                            canonical_bytes(request) != item.body
                            or not isinstance(request, dict)
                            or set(request) != {
                                "schema_version", "run_id", "permit", "findings_projection",
                            }
                            or request["schema_version"] != "heel.runner-findings-upload.v1"
                            or request["run_id"] != item.run_id
                        ):
                            raise ValueError
                    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
                        raise RunnerStoreError("local findings replay authority is invalid") from None
                    self.upload_findings(
                        item.run_id, permit=request["permit"],
                        findings_projection=request["findings_projection"],
                    )
                    continue
                self.control.replay_pending_call(
                    item, now_ms=self._now_ms(),
                    result_verifier=self._pending_result_replay_verifier,
                )
        active_ids = {
            item.run_id for item in self.control.runtime.load_active_run_controls(limit=64)
        }
        with self._lock:
            for run_id in set(self._gates) | set(self._gate_receipts) | set(self._bindings):
                if run_id not in active_ids:
                    self._gates.pop(run_id, None)
                    self._gate_receipts.pop(run_id, None)
                    self._bindings.pop(run_id, None)
                    self._heartbeat_guards.pop(run_id, None)
            self._terminal_runs.intersection_update(active_ids)

    def _recover_active_runtime_state(self) -> None:
        """Rebuild live coordinator authority from sealed runtime controls.

        A runtime active row is the restart source for the Cloud grant, approval
        projection and last gate.  The locally signed reservation is re-opened
        (or deterministically completed) before those values are exposed to
        the coordinator.  Its gate intentionally remains receipt-stale: only
        a post-restart heartbeat may authorize execution.
        """
        for active in self.control.runtime.load_active_run_controls(limit=64):
            projection = dict(active.approval_projection)
            grant = dict(active.grant)
            manifest, local_projection = self.store.load_approved_pair(active.approval_id)
            if local_projection != projection:
                raise RunnerStoreError("runtime active approval authority is unavailable")
            gate = ExecutionGate(**dict(active.gate))
            try:
                validate_execution_bundle(
                    ExecutionBundle(manifest, projection, grant), store=self.store,
                    identity=self.identity, trusted_grant_keys=self.trusted_grant_keys,
                    now_ms=self._now_ms(), gate=gate,
                )
            except (TypeError, ValueError) as exc:
                raise RunnerStoreError("runtime active grant authority is unavailable") from exc
            terminal = self.control.runtime.load_terminal_state(active.run_id)
            if terminal is None:
                retention_expires_at_ms = (
                    active.claimed_at_ms
                    + manifest["local_evidence_policy"]["retention_seconds"] * 1000
                )
                try:
                    recovered = self.store.reserve_run(
                        grant, retention_expires_at_ms=retention_expires_at_ms,
                    )
                    if recovered.get("run_id") != active.run_id:
                        raise RunnerStoreError("runtime active reservation is unavailable")
                    self.store.recover_run_reservation(active.run_id)
                except (TypeError, ValueError, RunnerStoreError) as exc:
                    if isinstance(exc, RunnerStoreError):
                        raise
                    raise RunnerStoreError("runtime active reservation is unavailable") from exc
            elif terminal.state == "local_terminal":
                pending = tuple(
                    item for item in self.control.runtime.load_pending_calls(limit=74)
                    if item.run_id == active.run_id
                )
                if len(pending) > 1 or (
                    pending and pending[0].request_operation != "result"
                ):
                    raise RunnerStoreError("runtime active terminal recovery is unavailable")
            else:
                raise RunnerStoreError("runtime active terminal recovery is unavailable")
            binding = (
                active.grant_id, active.approval_id,
                active.approval_projection_digest,
            )
            with self._lock:
                self._gates[active.run_id] = gate
                # A memory receipt is deliberately never reconstructed.  The
                # persisted gate is only a heartbeat precondition after restart.
                self._gate_receipts.pop(active.run_id, None)
                self._bindings[active.run_id] = binding

    def _stage_unstaged_terminal_results(self) -> None:
        """Durably reconstruct only Store-proven terminal requests before replay.

        The only admissible zero-pending terminal prefix is a signed detach
        followed by a crash before result call staging.  The Store verifier
        reconstructs that one request; the control client merely signs and
        persists it while holding its usual run guard.
        """
        while True:
            batch = self.control.runtime.load_unstaged_local_terminals(limit=16)
            for terminal in batch.items:
                now_ms = self._now_ms()
                evidence = self._pending_result_replay_verifier.authorize_unstaged_terminal_result(
                    terminal.run_id, now_ms=now_ms,
                )
                self.control.stage_recovered_result(
                    evidence, verifier=self._pending_result_replay_verifier, now_ms=now_ms,
                )
            if not batch.has_more:
                return

    def _now_ms(self) -> int:
        value = self.clock_ms()
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("runner clock returned an invalid timestamp")
        return value

    def _now_monotonic(self) -> float:
        value = self.monotonic()
        if (
            isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value < 0
        ):
            raise ValueError("runner monotonic clock returned an invalid timestamp")
        return float(value)

    def _finish_prune_states(self, states: tuple[object, ...], *, now_ms: int) -> int:
        """Finish only already-authenticated bounded runtime prune ownership."""
        processed = 0
        for pending in states:
            run_id = getattr(pending, "run_id", None)
            state_digest = getattr(pending, "state_digest", None)
            if type(run_id) is not str or type(state_digest) is not str:
                raise RunnerStoreError("local runtime prune authority is invalid")
            try:
                receipt = self.store.load_pruned_run_receipt(
                    run_id, expected_runtime_state_digest=state_digest,
                )
            except RunnerStoreError as exc:
                if str(exc) != "local runtime prune receipt is unavailable":
                    raise
                receipt = self.store.prune_runtime_terminal(
                    run_id, runtime=self.control.runtime,
                    expected_runtime_state_digest=state_digest, now_ms=now_ms,
                )
            completion = self.control.runtime.finish_prune(
                receipt=receipt, expected_prune_pending_state_digest=state_digest,
            )
            self.store.finish_pruned_compaction(completion, runtime=self.control.runtime)
            processed += 1
        return processed

    def maintenance_once(
        self, *, now_ms: int | None = None, limit: int = 16,
    ) -> RunnerMaintenanceResult:
        """Perform one capped passive terminal-retention pass.

        A tick resumes durable ownership before it claims fresh work and never
        spends more than one shared 1..16 item budget.  It deliberately does
        not loop: availability is independent of passive retained history.
        """
        if type(limit) is not int or not 1 <= limit <= 16:
            raise ValueError("runner maintenance limit must be between 1 and 16")
        if now_ms is None:
            now_ms = self._now_ms()
        elif type(now_ms) is not int or now_ms < 0:
            raise ValueError("runner maintenance time is invalid")
        with self._maintenance_lock:
            remaining = limit
            # A previous signed local activation-tombstone journal is a hard
            # suffix.  It is finished before runtime retention work, but it
            # consumes from this tick's one shared budget.
            activation_resumed = self.store._resume_activation_tombstone_prune(
                limit=remaining,
            )
            processed = activation_resumed.pruned
            remaining -= processed
            if remaining:
                resumed = self.control.runtime.load_prune_pending(limit=remaining)
                resumed_count = self._finish_prune_states(resumed.items, now_ms=now_ms)
                processed += resumed_count
                remaining -= resumed_count
                has_more = activation_resumed.has_more or resumed.has_more
            else:
                # The shared budget is exhausted before we can probe the next
                # retention lane; schedule the 1-second catch-up tick rather
                # than claiming there is no remaining work.
                has_more = True
            if remaining and not has_more:
                claimed = self.control.runtime.claim_due_prune(
                    now_ms=now_ms, limit=remaining,
                )
                claimed_count = self._finish_prune_states(claimed.items, now_ms=now_ms)
                processed += claimed_count
                remaining -= claimed_count
                has_more = claimed.has_more
            if remaining and not has_more:
                tombstones = self.store.prune_activation_tombstones(
                    now_ms=now_ms, limit=remaining,
                )
                processed += tombstones.pruned
                has_more = tombstones.has_more
            return RunnerMaintenanceResult(processed=processed, has_more=has_more)

    def _recover_terminal_runtime_state(self) -> None:
        """Complete detached terminal authority before any control transport."""
        if not self.store.is_context_bound:
            return
        now_ms = self._now_ms()
        # The signed compaction queue is the first run-authority suffix: it
        # retires only already-CASed runtime prune rows, before detach recovery
        # or any pending/active authority can be hydrated.
        self.store.recover_pruned_compaction_finalizers(runtime=self.control.runtime)
        self.store.recover_terminal_detaches(
            runtime=self.control.runtime, now_ms=now_ms,
        )
        # Pre-existing claimed work is a hard startup suffix.  The runtime
        # invariant admits at most one 16-item batch; a seventeenth row is not
        # backlog but durable corruption.
        pending = self.control.runtime.load_prune_pending(limit=16)
        if pending.has_more:
            raise RunnerStoreError("runtime prune pending capacity is corrupt")
        self._finish_prune_states(pending.items, now_ms=now_ms)

        # An expired run reachable through the bounded active/pending control
        # sets must never enter hydration or replay.  Point-claim its exact
        # state before the one passive due batch below.
        run_ids = {
            active.run_id
            for active in self.control.runtime.load_active_run_controls(limit=64)
        }
        run_ids.update(
            item.run_id for item in self.control.runtime.load_pending_calls(limit=74)
            if item.run_id is not None
        )
        blockers: list[object] = []
        for run_id in sorted(run_ids):
            terminal = self.control.runtime.load_terminal_state(run_id)
            if terminal is not None and terminal.retention_expires_at_ms <= now_ms:
                blockers.append(self.control.runtime.claim_specific_due_prune(
                    run_id, expected_state_digest=terminal.state_digest, now_ms=now_ms,
                ))
        self._finish_prune_states(tuple(blockers), now_ms=now_ms)

        # Passive history is intentionally one bounded batch only.  Periodic
        # maintenance provides liveness after authority becomes available.
        claimed = self.control.runtime.claim_due_prune(now_ms=now_ms, limit=16)
        self._finish_prune_states(claimed.items, now_ms=now_ms)

    def claim(self) -> ClaimLease | None:
        response = self.control._claim_closed()
        received_at = self._now_monotonic()
        if response is None:
            return None
        grant = response["grant"]
        projection = response["approval_projection"]
        manifest, local_projection = self.store.load_approved_pair(
            grant["approval"]["projection_id"]
        )
        if local_projection != projection:
            raise ValueError("runner claim differs from the immutable local approval")
        gate = ExecutionGate(**response["gate"])
        bundle = ExecutionBundle(manifest, projection, grant)
        now = self._now_ms()
        validate_execution_bundle(
            bundle,
            store=self.store,
            identity=self.identity,
            trusted_grant_keys=self.trusted_grant_keys,
            now_ms=now,
            gate=gate,
        )
        claimed = self._claimed_projection(manifest, projection, grant, claimed_at_ms=now)
        with self._lock:
            if response["run_id"] in self._gates:
                raise ValueError("runner returned an already active claim")
            self._gates[response["run_id"]] = gate
            self._gate_receipts[response["run_id"]] = received_at
            self._bindings[response["run_id"]] = (
                grant["grant_id"], projection["projection_id"],
                projection["projection_digest"],
            )
        return ClaimLease(response["run_id"], bundle, claimed)

    def install_cloud_context_binding(self, artifact: object, *, signer_label: str) -> RunnerContext:
        """Install only a Cloud-signed pairing authorization; it grants no execution lease."""
        return self.store.install_cloud_context_binding(
            artifact, identity=self.identity, signer=self.signer, signer_label=signer_label,
            trusted_cloud_keys=self.trusted_grant_keys, now_ms=self._now_ms(),
        )

    def _install_claimed_rollover(self, claimed: dict, receipt: object) -> None:
        """Consume or discard every control-minted receipt on every local outcome."""
        try:
            self.control._bind_rollover_receipt_to_store(receipt, self.store)
            self.store._install_cloud_context_binding_from_control(
                claimed["context_binding"], identity=self.identity, signer=self.signer,
                signer_label=self.signer.key_id, trusted_cloud_keys=self.trusted_grant_keys,
                now_ms=self._now_ms(), rollover_receipt=receipt,
            )
        finally:
            self.control._discard_rollover_receipt(receipt, self.store)

    def ensure_runner_context(self) -> bool:
        """Acquire one Cloud authorization before work polling, without synthesizing context."""
        # A durable signed A→B journal is local authority already accepted by a
        # prior list/claim receipt.  Finish it before issuing any Cloud request;
        # otherwise a server that has advanced to C would tempt an unsafe A→C jump.
        self.store.finish_pending_context_rollover(
            identity=self.identity, trusted_cloud_keys=self.trusted_grant_keys, now_ms=self._now_ms(),
        )
        # First pairing has no local namespace: list before touching a namespaced sidecar.
        if not self.store.is_context_bound:
            pending_install = self.store._pending_cloud_context_install_for_recovery(
                identity=self.identity, signer=self.signer,
            )
            if pending_install is not None:
                old, _context, _journal = pending_install
                acquired = self.control._claim_single_context_for_rollover(
                    old["binding_id"], old["binding_digest"],
                )
                if acquired is None:
                    return False
                if acquired is False:
                    self.install_cloud_context_binding(old, signer_label=self.signer.key_id)
                    return True
                claimed, receipt = acquired
                self._install_claimed_rollover(claimed, receipt)
                return True
            listed = self.control.list_contexts()
            contexts = listed["contexts"]
            if len(contexts) == 0:
                return False
            if len(contexts) != 1:
                raise ValueError("ambiguous cloud runner contexts")
            item = contexts[0]
            claimed = self.control.claim_context(item["binding_id"], item["binding_digest"])
            self.install_cloud_context_binding(
                claimed["context_binding"], signer_label=self.signer.key_id,
            )
            return True
        try:
            current = self.store.verify_cloud_context_binding(
                identity=self.identity, trusted_cloud_keys=self.trusted_grant_keys, now_ms=self._now_ms(),
            )
            acquired = self.control._claim_single_context_for_rollover(
                current["binding_id"], current["binding_digest"],
            )
            if acquired is None:
                return False
            if acquired is False:
                # A crash after active-context publication but before the root
                # journal cleanup is an already-authorized exact install, not a
                # static fallback.  Re-enter the closed idempotent path to finish it.
                self.install_cloud_context_binding(current, signer_label=self.signer.key_id)
                return True
            claimed, receipt = acquired
            self._install_claimed_rollover(claimed, receipt)
            return True
        except RunnerStoreError:
            if self.store.has_cloud_context_provenance():
                try:
                    pending_rollover = self.store._pending_context_rollover_for_recovery(identity=self.identity)
                    old = (
                        {"binding_id": pending_rollover["old_binding_id"],
                         "binding_digest": pending_rollover["old_binding_digest"]}
                        if pending_rollover is not None
                        else self.store.load_cloud_context_binding_for_recovery()
                    )
                except RunnerStoreError:
                    old = None
                if old is None:
                    listed = self.control.list_contexts()
                    if len(listed["contexts"]) == 0:
                        return False
                    raise ValueError("cloud context binding no longer verifies")
                acquired = self.control._claim_single_context_for_rollover(
                    old["binding_id"], old["binding_digest"],
                )
                if acquired is None:
                    return False
                if acquired is False:
                    raise ValueError("cloud context binding no longer verifies")
                claimed, receipt = acquired
                try:
                    self._install_claimed_rollover(claimed, receipt)
                except RunnerStoreError:
                    raise ValueError("cloud context binding no longer verifies") from None
                return True
            # A pre-existing static context remains a deliberate local-only workflow.
            try:
                self.store.load_context()
            except RunnerStoreError:
                pass
            else:
                return True
        listed = self.control.list_contexts()
        contexts = listed["contexts"]
        if len(contexts) == 0:
            return False
        if len(contexts) != 1:
            raise ValueError("ambiguous cloud runner contexts")
        item = contexts[0]
        claimed = self.control.claim_context(item["binding_id"], item["binding_digest"])
        self.install_cloud_context_binding(
            claimed["context_binding"], signer_label=self.signer.key_id,
        )
        return True

    def submit_cloud_context_approval(self, approval_projection: object) -> dict[str, Any]:
        """Use the serialized claim chain to submit a plan bound to the installed Cloud artifact."""
        binding = self.store.verify_cloud_context_binding(
            identity=self.identity, trusted_cloud_keys=self.trusted_grant_keys, now_ms=self._now_ms(),
        )
        return self.control.submit_context_approval_projection(
            binding["binding_id"], binding["binding_digest"], approval_projection,
        )

    def _claimed_projection(
        self, manifest: dict[str, Any], projection: dict[str, Any], grant: dict[str, Any],
        *, claimed_at_ms: int,
    ) -> dict[str, Any]:
        unsigned = {
            "schema_version": OPERATIONAL_RUN_SCHEMA,
            "run_id": grant["run_id"], "grant_id": grant["grant_id"],
            "workspace_id": grant["workspace_id"], "project_id": grant["project_id"],
            "manifest_digest": manifest["manifest_digest"],
            "approval_projection_digest": projection["projection_digest"],
            "grant_digest": grant["grant_digest"],
            "event_sequence": 0, "lifecycle_phase": "claimed",
            "execution_disposition": None,
            "timestamps": {
                "claimed_at_ms": claimed_at_ms, "started_at_ms": None,
                "updated_at_ms": claimed_at_ms, "stop_requested_at_ms": None,
                "stop_acknowledged_at_ms": None, "terminal_at_ms": None,
            },
            "counters": {
                "requests_started": 0, "requests_completed": 0,
                "response_bytes_read": 0, "actions_contained": 0, "retries_used": 0,
                "remaining_requests": manifest["budgets"]["maximum_requests"],
                "remaining_wall_ms": manifest["budgets"]["wall_timeout_ms"],
            },
            "versions": {
                "runner_version": self.identity.runner_version,
                "engine_version": manifest["compiler"]["engine_version"],
                "adapter_versions": sorted({
                    item["adapter_version"] for item in manifest["scenarios"]
                }),
            },
            "error_category": "none", "stop_reason": "none",
            "containment_codes": [], "redaction_count": 0,
        }
        return _signed_projection(unsigned, self.signer)

    def _known_run(self, run_id: str) -> ExecutionGate:
        if type(run_id) is not str or not run_id:
            raise ValueError("active runner claim is required")
        with self._lock:
            gate = self._gates.get(run_id)
        if gate is None:
            raise ValueError("active runner claim is required")
        return gate

    def _heartbeat_guard(self, run_id: str) -> threading.Lock:
        """Return the coordinator-side serialization guard for one live run."""
        with self._lock:
            guard = self._heartbeat_guards.get(run_id)
            if guard is None:
                guard = threading.Lock()
                self._heartbeat_guards[run_id] = guard
            return guard

    def execution_gate(self, run_id: str) -> ExecutionGate:
        """Return the latest authenticated gate snapshot for local attempt authorization."""
        if type(run_id) is not str or not run_id:
            raise ValueError("active runner claim is required")
        with self._lock:
            gate = self._gates.get(run_id)
            received_at = self._gate_receipts.get(run_id)
        if gate is None or received_at is None:
            raise ValueError("active runner claim is required")
        if gate.active is not True or gate.stop_reason != "none":
            raise ValueError("authenticated runner gate denies execution")
        elapsed = self._now_monotonic() - received_at
        if elapsed < 0 or elapsed > _MAX_AUTHENTICATED_GATE_AGE_SECONDS:
            raise ValueError("authenticated runner gate is stale")
        if elapsed * 1000 >= gate.proof_expires_at_ms - gate.server_time_ms:
            raise ValueError("authenticated runner gate proof has expired")
        return gate

    def heartbeat(
        self, run_id: str, operational_projection: dict[str, Any],
    ) -> ExecutionGate:
        with self._heartbeat_guard(run_id):
            previous = self._known_run(run_id)
            response = self.control._heartbeat_closed(run_id, operational_projection)
            received_at = self._now_monotonic()
            gate = ExecutionGate(**response)
            if gate.server_time_ms <= previous.server_time_ms:
                raise ValueError("runner gate server time did not advance")
            if gate.kill_switch_generation < previous.kill_switch_generation:
                raise ValueError("runner gate control generation regressed")
            with self._lock:
                # This equality is retained as a fail-closed check against a
                # result/retirement race; other heartbeat calls are held by
                # this guard from their initial gate read through publication.
                if self._gates.get(run_id) != previous:
                    raise ValueError("active runner claim is required")
                self._gates[run_id] = gate
                self._gate_receipts[run_id] = received_at
            return gate

    def progress(self, run_id: str, operational_projection: dict[str, Any]) -> object:
        self._known_run(run_id)
        response = self.control._progress_closed(run_id, operational_projection)
        self._validate_status_binding(run_id, response)
        return response

    def result(self, run_id: str, operational_projection: dict[str, Any]) -> object:
        self._known_run(run_id)
        try:
            projection = validate_operational_run(operational_projection)
            self.control._verify_projection_signature(projection)
        except (TypeError, ValueError):
            raise ValueError("runner terminal projection is invalid") from None

        def prepare_terminal_authority() -> None:
            # This callback executes under the control client's exact per-run
            # guard.  It is deliberately before call staging/transport: a
            # failed local anchor or detach can never create a pending request.
            anchor = self.store._runtime_terminal_anchor(run_id)
            with self._lock:
                binding = self._bindings.get(run_id)
                gate = self._gates.get(run_id)
            if (
                gate is None
                or binding is None
                or projection["run_id"] != run_id
                or projection["lifecycle_phase"] != "terminal"
                or projection["workspace_id"] != self.identity.workspace_id
                or projection["project_id"] != anchor["project_id"]
                or projection["grant_id"] != anchor["grant_id"]
                or projection["approval_projection_digest"]
                != anchor["approval_projection_digest"]
                or projection["projection_digest"] != anchor["terminal_projection_digest"]
                or projection["timestamps"]["terminal_at_ms"] != anchor["terminal_at_ms"]
                or binding != (
                    anchor["grant_id"], binding[1], anchor["approval_projection_digest"],
                )
            ):
                raise RunnerStoreError("local terminal authority is invalid")
            state = self.control._register_runtime_local_terminal(anchor)
            self.store.detach_terminal(
                run_id, runtime=self.control.runtime,
                expected_local_state_digest=state.state_digest, now_ms=self._now_ms(),
            )

        response = self.control._result_closed(
            run_id, operational_projection, before_transport=prepare_terminal_authority,
        )
        self._validate_status_binding(run_id, response)
        if response["status"] != "terminal":
            raise ValueError("runner result did not reach terminal state")
        with self._lock:
            self._gates.pop(run_id, None)
            self._gate_receipts.pop(run_id, None)
            self._bindings.pop(run_id, None)
            self._terminal_runs.discard(run_id)
            self._heartbeat_guards.pop(run_id, None)
        return response

    def _validate_status_binding(self, run_id: str, response: dict[str, Any]) -> None:
        with self._lock:
            binding = self._bindings.get(run_id)
        if binding is None or (
            response["grant_id"] != binding[0] or response["approval_id"] != binding[1]
        ):
            raise ValueError("runner status differs from the active claim")

    def stop_ack(
        self,
        run_id: str,
        operational_projection: dict[str, Any],
        *,
        deadline: float,
    ) -> object:
        self._known_run(run_id)
        if (
            isinstance(deadline, bool) or not isinstance(deadline, (int, float))
            or not math.isfinite(deadline)
        ):
            raise ValueError("stop acknowledgement deadline is invalid")
        if self.monotonic() >= deadline:
            raise TimeoutError("stop acknowledgement deadline elapsed")
        value = validate_operational_run(operational_projection)
        if (
            value["run_id"] != run_id
            or value["lifecycle_phase"] not in {"stop_requested", "finalizing"}
            or value["stop_reason"] == "none"
            or value["timestamps"]["stop_requested_at_ms"] is None
        ):
            raise ValueError("stop acknowledgement projection is invalid")
        if value["timestamps"]["stop_acknowledged_at_ms"] is None:
            unsigned = {
                key: copy_value for key, copy_value in value.items()
                if key not in {"projection_digest", "signing_key_id", "signature_b64"}
            }
            timestamp = max(
                self._now_ms(),
                unsigned["timestamps"]["updated_at_ms"],
                unsigned["timestamps"]["stop_requested_at_ms"],
            )
            unsigned["timestamps"] = {
                **unsigned["timestamps"],
                "updated_at_ms": timestamp,
                "stop_acknowledged_at_ms": timestamp,
            }
            value = _signed_projection(unsigned, self.signer)
        response = self.control._stop_ack_closed(run_id, value)
        if self.monotonic() > deadline:
            raise TimeoutError("stop acknowledgement deadline elapsed")
        return RunnerStopAcknowledgement(
            accepted=response["accepted"],
            deadline_met=response["deadline_met"],
            late=response["late"],
            acknowledged_at_ms=value["timestamps"]["stop_acknowledged_at_ms"],
        )

    def upload_findings(
        self, run_id: str, *, permit: object, findings_projection: object,
    ) -> dict[str, Any]:
        if type(run_id) is not str or not run_id:
            raise ValueError("active runner claim is required")
        try:
            permit_value = validate_disclosure_permit(permit)
            findings = validate_canary_findings(findings_projection)
        except (TypeError, ValueError):
            raise ValueError("invalid runner findings upload") from None
        unsigned = {
            key: value for key, value in permit_value.items()
            if key not in {"permit_digest", "signing_key_id", "signature_b64"}
        }
        now = self._now_ms()
        try:
            runtime_terminal = self.control.runtime.load_terminal_state(run_id)
            if runtime_terminal is None:
                raise RunnerStoreError("local terminal disclosure authority is unavailable")
            anchor = self.store.load_terminal_disclosure_anchor(
                run_id, runtime=self.control.runtime,
                expected_runtime_state_digest=runtime_terminal.state_digest,
            )
        except (RunnerStoreError, ValueError) as exc:
            raise ValueError("terminal runner result is required before disclosure") from exc
        if (
            permit_value["workspace_id"] != self.identity.workspace_id
            or permit_value["run_id"] != run_id
            or permit_value["project_id"] != anchor["project_id"]
            or permit_value["grant_id"] != anchor["grant_id"]
            or findings["workspace_id"] != self.identity.workspace_id
            or findings["run_id"] != run_id
            or findings["project_id"] != anchor["project_id"]
            or findings["grant_id"] != anchor["grant_id"]
            or findings["approval_projection_digest"]
            != anchor["approval_projection_digest"]
        ):
            raise ValueError("invalid runner findings upload")
        if not permit_value["issued_at_ms"] <= now < permit_value["expires_at_ms"]:
            raise ValueError("disclosure permit is expired or not yet valid")
        try:
            verify_envelope(
                dict(self.trusted_grant_keys),
                {
                    "signing_key_id": permit_value["signing_key_id"],
                    "signature_b64": permit_value["signature_b64"],
                },
                canonical_bytes(unsigned),
            )
        except (TypeError, ValueError):
            raise ValueError("invalid disclosure permit authority") from None
        receipt = self.control.upload_findings(
            run_id=run_id, permit=permit_value, findings_projection=findings,
        )
        return receipt


class RunnerExecutionAdapter:
    """Bind Task 6 execution to one coordinator gate source and one local target transport."""

    def __init__(self, *, coordinator: RunnerCoordinator, executor: object, transport: object):
        if not isinstance(coordinator, RunnerCoordinator):
            raise TypeError("runner coordinator is required")
        if not callable(getattr(executor, "execute", None)):
            raise TypeError("local canary executor is required")
        if transport is None:
            raise TypeError("bounded local target transport is required")
        self.coordinator = coordinator
        self.executor = executor
        self.transport = transport

    def execute(
        self,
        lease: ClaimLease,
        *,
        cancellation: object,
        on_progress: Callable[[dict[str, Any]], None],
    ) -> object:
        if not isinstance(lease, ClaimLease):
            raise ValueError("runner claim lease is required")
        return self.executor.execute(
            lease.bundle,
            transport=self.transport,
            gate_source=lambda: self.coordinator.execution_gate(lease.run_id),
            cancellation=cancellation,
            on_progress=on_progress,
        )

    def prepare_stop_ack(
        self,
        lease: ClaimLease,
        projection: dict[str, Any],
        stop_reason: str,
        proposed_at_ms: int,
    ) -> object:
        del projection
        if not isinstance(lease, ClaimLease):
            raise ValueError("runner claim lease is required")
        prepare = getattr(self.executor, "prepare_stop_ack", None)
        if not callable(prepare):
            raise TypeError("local canary executor cannot prepare stop acknowledgement")
        return prepare(
            lease.run_id, stop_reason=stop_reason, proposed_at_ms=proposed_at_ms,
        )


__all__ = [
    "RunnerCoordinator", "RunnerExecutionAdapter", "RunnerStopAcknowledgement",
]
