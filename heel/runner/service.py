"""Outbound-only runner supervisor with independent heartbeat and stop control."""
from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Any, Callable, Protocol, runtime_checkable

from heel.runner.execution import ExecutionGate
from heel.runner.http_transport import CancellationToken


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


class RunnerService:
    """Keep Cloud coordination responsive while target execution occupies another call stack."""

    def __init__(
        self,
        *,
        coordinator: Coordinator,
        executor: LeaseExecutor,
        heartbeat_interval: float = 1.0,
        idle_poll_interval: float = 2.0,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        clock_ms: Callable[[], int] = lambda: int(time.time() * 1000),
    ):
        if not isinstance(heartbeat_interval, (int, float)) or isinstance(heartbeat_interval, bool):
            raise ValueError("heartbeat interval must be numeric")
        if not 0 < heartbeat_interval <= 1.0:
            raise ValueError("active heartbeat interval must be no more than one second")
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

    def request_local_stop(self) -> bool:
        """Cancel any in-flight target socket immediately; no coordinator call is awaited."""
        with self._active_lock:
            cancellation = self._active_cancellation
        if cancellation is None:
            return False
        cancellation.cancel()
        return True

    def run_once(self) -> bool:
        lease = self.coordinator.claim()
        if lease is None:
            return False
        if not isinstance(lease, ClaimLease) or type(lease.run_id) is not str or not lease.run_id:
            raise ValueError("coordinator returned an invalid claim lease")
        cancellation = CancellationToken()
        with self._active_lock:
            if self._active_cancellation is not None:
                raise RuntimeError("runner already has an active lease")
            self._active_cancellation = cancellation
        finished = threading.Event()
        stop_received = threading.Event()
        heartbeat_failure: list[BaseException] = []
        projection_lock = threading.Lock()
        current_projection = [lease.operational_projection]
        stop_ack_failure: list[BaseException] = []

        def snapshot() -> dict[str, Any]:
            with projection_lock:
                return current_projection[0]

        def update_projection(value: dict[str, Any]) -> None:
            if not isinstance(value, dict):
                raise ValueError("executor progress projection must be an object")
            with projection_lock:
                current_projection[0] = value
            self.coordinator.progress(lease.run_id, value)

        def issue_stop_ack(stop_reason: str, *, deadline: float) -> None:
            """Cancel first, then bound one coordinator acknowledgement independently."""
            proposed_at_ms = self.clock_ms()
            cancellation.stop_reason = stop_reason
            cancellation.stop_requested_at_ms = proposed_at_ms
            cancellation.stop_ack_deadline = deadline
            cancellation.stop_ack_event = threading.Event()
            cancellation.cancel()
            stop_received.set()
            prepare = getattr(self.executor, "prepare_stop_ack", None)
            try:
                if prepare is None:
                    acknowledgement = snapshot()
                else:
                    acknowledgement = prepare(
                        lease, snapshot(), stop_reason, proposed_at_ms,
                    )
                if not isinstance(acknowledgement, dict):
                    raise ValueError("executor stop acknowledgement must be an object")
            except BaseException as exc:
                stop_ack_failure.append(exc)
                cancellation.stop_ack_event.set()
                return

            completed = threading.Event()
            failed: list[BaseException] = []

            def acknowledge() -> None:
                try:
                    self.coordinator.stop_ack(
                        lease.run_id, acknowledgement, deadline=deadline,
                    )
                except BaseException as exc:
                    failed.append(exc)
                finally:
                    completed.set()

            worker = threading.Thread(
                target=acknowledge, daemon=True, name="heel-runner-stop-ack",
            )
            worker.start()
            completed.wait(max(0.0, deadline - self.monotonic()))
            acknowledged_in_time = completed.is_set() and self.monotonic() <= deadline
            if acknowledged_in_time and not failed:
                cancellation.stop_acknowledged_at_ms = self.clock_ms()
                with projection_lock:
                    current_projection[0] = acknowledgement
            else:
                if failed:
                    stop_ack_failure.extend(failed)
                else:
                    stop_ack_failure.append(TimeoutError("stop acknowledgement timed out"))
            cancellation.stop_ack_event.set()

        def heartbeats() -> None:
            while not finished.is_set():
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
                        if actual_stop and not stop_received.is_set():
                            issue_stop_ack(requested_stop_reason, deadline=cycle + 5.0)
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
            with self._active_lock:
                self._active_cancellation = None
        if heartbeat_thread.is_alive():
            raise RuntimeError("runner heartbeat worker did not stop")
        if not stop_received.is_set() and heartbeat_failure:
            raise RuntimeError("runner heartbeat failed closed") from heartbeat_failure[0]
        elif not stop_received.is_set():
            self.coordinator.result(lease.run_id, snapshot())
        return True

    def serve(self, stop_event: threading.Event) -> None:
        if not isinstance(stop_event, threading.Event):
            raise ValueError("runner service stop event is required")
        while not stop_event.is_set():
            claimed = self.run_once()
            if not claimed:
                stop_event.wait(self.idle_poll_interval)


__all__ = ["ClaimLease", "Coordinator", "LeaseExecutor", "RunnerService"]
