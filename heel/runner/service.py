"""Outbound-only runner supervisor with independent heartbeat and stop control."""
from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Any, Callable, Protocol, runtime_checkable

from heel.canary_contracts import validate_operational_run
from heel.runner.execution import ExecutionGate
from heel.runner.http_transport import CancellationToken


_CONTROL_STOP_REASONS = frozenset({
    "local_emergency_stop", "cloud_stop", "runner_revoked",
    "target_revoked", "kill_switch",
})


@dataclass(frozen=True, slots=True)
class ClaimLease:
    run_id: str
    bundle: object
    operational_projection: dict[str, Any]


@runtime_checkable
class Coordinator(Protocol):
    """Task 7 supplies the network-backed implementation of these named operations."""

    def claim(self) -> ClaimLease | None: ...
    def heartbeat(self, run_id: str, operational_projection: dict[str, Any]) -> ExecutionGate: ...
    def progress(self, run_id: str, operational_projection: dict[str, Any]) -> object: ...
    def result(self, run_id: str, operational_projection: dict[str, Any]) -> object: ...
    def stop_ack(
        self,
        run_id: str,
        operational_projection: dict[str, Any],
        *,
        deadline: float,
    ) -> object: ...


@runtime_checkable
class LeaseExecutor(Protocol):
    def execute(
        self,
        lease: ClaimLease,
        *,
        cancellation: CancellationToken,
        on_progress: Callable[[dict[str, Any]], None],
    ) -> object: ...


class _StopController:
    """Choose one stop reason, cancel immediately, and acknowledge on a bounded worker."""

    def __init__(
        self,
        *,
        lease: ClaimLease,
        coordinator: Coordinator,
        executor: LeaseExecutor,
        cancellation: CancellationToken,
        snapshot: Callable[[], dict[str, Any]],
        accept_projection: Callable[[dict[str, Any]], None],
        monotonic: Callable[[], float],
        clock_ms: Callable[[], int],
    ):
        self.lease = lease
        self.coordinator = coordinator
        self.executor = executor
        self.cancellation = cancellation
        self.snapshot = snapshot
        self.accept_projection = accept_projection
        self.monotonic = monotonic
        self.clock_ms = clock_ms
        self.initiated = threading.Event()
        self.completed = threading.Event()
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None

    def request(self, reason: str, *, deadline: float | None = None) -> bool:
        if reason not in _CONTROL_STOP_REASONS:
            raise ValueError("invalid runner stop reason")
        with self._lock:
            if self.initiated.is_set():
                return False
            absolute_deadline = self.monotonic() + 5.0 if deadline is None else deadline
            proposed_at_ms = self.clock_ms()
            self.cancellation.stop_reason = reason
            self.cancellation.stop_requested_at_ms = proposed_at_ms
            self.cancellation.stop_ack_deadline = absolute_deadline
            self.cancellation.stop_ack_event = self.completed
            self.initiated.set()
            self.cancellation.cancel()
            self._worker = threading.Thread(
                target=self._acknowledge,
                args=(reason, proposed_at_ms, absolute_deadline),
                daemon=True,
                name="heel-runner-stop-controller",
            )
            self._worker.start()
            return True

    def _acknowledge(self, reason: str, proposed_at_ms: int, deadline: float) -> None:
        try:
            prepare = getattr(self.executor, "prepare_stop_ack", None)
            acknowledgement = (
                self.snapshot()
                if prepare is None
                else prepare(self.lease, self.snapshot(), reason, proposed_at_ms)
            )
            if not isinstance(acknowledgement, dict):
                return
            if self.monotonic() >= deadline:
                return
            call_completed = threading.Event()
            failure: list[BaseException] = []
            completion_monotonic: list[float] = []
            acknowledged_at_ms: list[int] = []

            def call() -> None:
                try:
                    response = self.coordinator.stop_ack(
                        self.lease.run_id, acknowledgement, deadline=deadline,
                    )
                    exact_timestamp = getattr(response, "acknowledged_at_ms", None)
                    if exact_timestamp is None:
                        exact_timestamp = self.clock_ms()
                    if (
                        isinstance(exact_timestamp, bool)
                        or not isinstance(exact_timestamp, int)
                        or exact_timestamp < 0
                    ):
                        raise ValueError("invalid stop acknowledgement timestamp")
                    acknowledged_at_ms.append(exact_timestamp)
                except BaseException as exc:
                    failure.append(exc)
                finally:
                    completion_monotonic.append(self.monotonic())
                    call_completed.set()

            threading.Thread(
                target=call, daemon=True, name="heel-runner-stop-ack",
            ).start()
            call_completed.wait(max(0.0, deadline - self.monotonic()))
            if (
                call_completed.is_set()
                and not failure
                and completion_monotonic
                and completion_monotonic[0] <= deadline
                and acknowledged_at_ms
            ):
                self.cancellation.stop_acknowledged_at_ms = acknowledged_at_ms[0]
                self.accept_projection(acknowledgement)
        finally:
            self.completed.set()

    def join(self, timeout: float = 5.1) -> None:
        with self._lock:
            worker = self._worker
        if worker is not None:
            worker.join(timeout)


class RunnerService:
    """Keep Cloud coordination responsive while target execution occupies another call stack."""

    def __init__(
        self,
        *,
        coordinator: Coordinator,
        executor: LeaseExecutor,
        heartbeat_interval: float = 0.25,
        idle_poll_interval: float = 2.0,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        clock_ms: Callable[[], int] = lambda: int(time.time() * 1000),
    ):
        if not isinstance(heartbeat_interval, (int, float)) or isinstance(heartbeat_interval, bool):
            raise ValueError("heartbeat interval must be numeric")
        if not 0 < heartbeat_interval <= 0.4:
            raise ValueError("active heartbeat interval must be no more than 0.4 seconds")
        if not isinstance(idle_poll_interval, (int, float)) or isinstance(idle_poll_interval, bool):
            raise ValueError("idle poll interval must be numeric")
        if idle_poll_interval < 2.0:
            raise ValueError("idle claim polling must not exceed 0.5 Hz")
        self.coordinator = coordinator
        self.executor = executor
        self.heartbeat_interval = float(heartbeat_interval)
        self.idle_poll_interval = float(idle_poll_interval)
        self.sleeper = sleeper
        self.monotonic = monotonic
        self.clock_ms = clock_ms
        self._active_lock = threading.Lock()
        self._active_cancellation: CancellationToken | None = None
        self._active_stop_controller: _StopController | None = None

    def request_local_stop(self) -> bool:
        """Cancel any in-flight target socket immediately; no coordinator call is awaited."""
        with self._active_lock:
            controller = self._active_stop_controller
        if controller is None:
            return False
        return controller.request("local_emergency_stop") or controller.initiated.is_set()

    def run_once(self) -> bool:
        lease = self.coordinator.claim()
        if lease is None:
            return False
        if not isinstance(lease, ClaimLease) or type(lease.run_id) is not str or not lease.run_id:
            raise ValueError("coordinator returned an invalid claim lease")
        cancellation = CancellationToken()
        finished = threading.Event()
        heartbeat_failure: list[BaseException] = []
        projection_lock = threading.Lock()
        current_projection = [lease.operational_projection]

        def snapshot() -> dict[str, Any]:
            with projection_lock:
                return current_projection[0]

        def update_projection(value: dict[str, Any]) -> None:
            if not isinstance(value, dict):
                raise ValueError("executor progress projection must be an object")
            with projection_lock:
                current_projection[0] = value
            response = self.coordinator.progress(lease.run_id, value)
            if isinstance(response, dict) and response.get("status") == "stop_requested":
                stop_reason = response.get("stop_reason")
                if stop_reason not in _CONTROL_STOP_REASONS:
                    raise ValueError("coordinator progress stop response is invalid")
                # The closed progress response is authenticated control state.  Initiate the
                # same bounded controller synchronously so a last-action stop cannot wait for
                # the independent heartbeat loop.
                stop_controller.request(stop_reason)

        def accept_projection(value: dict[str, Any]) -> None:
            with projection_lock:
                current_projection[0] = value

        stop_controller = _StopController(
            lease=lease,
            coordinator=self.coordinator,
            executor=self.executor,
            cancellation=cancellation,
            snapshot=snapshot,
            accept_projection=accept_projection,
            monotonic=self.monotonic,
            clock_ms=self.clock_ms,
        )
        with self._active_lock:
            if self._active_cancellation is not None:
                raise RuntimeError("runner already has an active lease")
            self._active_cancellation = cancellation
            self._active_stop_controller = stop_controller

        def heartbeats() -> None:
            # Once stop control owns the run, target cancellation and the bounded ack worker
            # are authoritative.  Continuing heartbeats can race the ack's timestamp re-signing
            # and replay a pre-ack digest at the same containment sequence.
            while not finished.is_set() and not stop_controller.initiated.is_set():
                cycle = self.monotonic()
                try:
                    gate = self.coordinator.heartbeat(lease.run_id, snapshot())
                    if not isinstance(gate, ExecutionGate):
                        raise ValueError("coordinator returned an invalid execution gate")
                    if (
                        gate.stop_reason != "none"
                        or not gate.active
                        or gate.runner_state != "active"
                        or gate.proof_state != "valid"
                        or gate.proof_expires_at_ms <= gate.server_time_ms
                    ):
                        actual_stop = (
                            gate.stop_reason != "none"
                            or gate.runner_state != "active"
                            or gate.proof_state == "revoked"
                            or not gate.active
                        )
                        if gate.stop_reason != "none":
                            requested_stop_reason = gate.stop_reason
                        elif gate.runner_state != "active":
                            requested_stop_reason = "runner_revoked"
                            cancellation.control_error = "runner_fault"
                        elif gate.proof_state == "revoked":
                            requested_stop_reason = "target_revoked"
                            cancellation.control_error = "proof_expired"
                        elif gate.proof_state != "valid" or gate.proof_expires_at_ms <= gate.server_time_ms:
                            requested_stop_reason = "none"
                            cancellation.control_error = "proof_expired"
                        elif not gate.active:
                            requested_stop_reason = "kill_switch"
                        else:
                            requested_stop_reason = "none"
                        if actual_stop:
                            stop_controller.request(
                                requested_stop_reason, deadline=cycle + 5.0,
                            )
                        else:
                            cancellation.cancel()
                except BaseException as exc:
                    heartbeat_failure.append(exc)
                    cancellation.control_error = "cloud_disconnected"
                    cancellation.cancel()
                    return
                remaining = self.heartbeat_interval - (self.monotonic() - cycle)
                if remaining > 0:
                    finished.wait(remaining)

        heartbeat_thread = threading.Thread(
            target=heartbeats, daemon=True, name="heel-runner-heartbeat",
        )
        heartbeat_thread.start()
        result = None
        try:
            result = self.executor.execute(
                lease, cancellation=cancellation, on_progress=update_projection,
            )
            if isinstance(result, dict):
                final_projection = result.get("operational_projection")
            else:
                final_projection = getattr(result, "operational_projection", None)
            if isinstance(final_projection, dict):
                with projection_lock:
                    current_projection[0] = final_projection
        finally:
            finished.set()
            heartbeat_thread.join(5.1)
            stop_controller.join()
            with self._active_lock:
                self._active_cancellation = None
                self._active_stop_controller = None
        if heartbeat_thread.is_alive():
            raise RuntimeError("runner heartbeat worker did not stop")
        stopped = stop_controller.initiated.is_set()
        if not stopped and heartbeat_failure:
            raise RuntimeError("runner heartbeat failed closed") from heartbeat_failure[0]
        if not stopped:
            self.coordinator.result(lease.run_id, snapshot())
        else:
            try:
                terminal = validate_operational_run(snapshot())
            except (TypeError, ValueError):
                terminal = None
            if (
                terminal is not None
                and terminal["run_id"] == lease.run_id
                and terminal["lifecycle_phase"] == "terminal"
            ):
                self.coordinator.result(lease.run_id, terminal)
        return True

    def serve(self, stop_event: threading.Event) -> None:
        if not isinstance(stop_event, threading.Event):
            raise ValueError("runner service stop event is required")
        while not stop_event.is_set():
            claimed = self.run_once()
            if not claimed:
                stop_event.wait(self.idle_poll_interval)


__all__ = ["ClaimLease", "Coordinator", "LeaseExecutor", "RunnerService"]
