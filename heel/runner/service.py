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
    def stop_ack(self, run_id: str, operational_projection: dict[str, Any]) -> object: ...


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
        stop_received_at = [None]

        def snapshot() -> dict[str, Any]:
            with projection_lock:
                return current_projection[0]

        def update_projection(value: dict[str, Any]) -> None:
            if not isinstance(value, dict):
                raise ValueError("executor progress projection must be an object")
            with projection_lock:
                current_projection[0] = value
            self.coordinator.progress(lease.run_id, value)

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
                        if actual_stop and not stop_received.is_set():
                            stop_received_at[0] = self.monotonic()
                            stop_received.set()
                        if gate.stop_reason != "none":
                            cancellation.stop_reason = gate.stop_reason
                        elif gate.runner_state != "active":
                            cancellation.stop_reason = "runner_revoked"
                            cancellation.control_error = "runner_fault"
                        elif gate.proof_state == "revoked":
                            cancellation.stop_reason = "target_revoked"
                            cancellation.control_error = "proof_expired"
                        elif gate.proof_state != "valid" or gate.proof_expires_at_ms <= gate.server_time_ms:
                            cancellation.control_error = "proof_expired"
                        elif not gate.active:
                            cancellation.stop_reason = "kill_switch"
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
            heartbeat_thread.join(2)
            with self._active_lock:
                self._active_cancellation = None
        if heartbeat_thread.is_alive():
            raise RuntimeError("runner heartbeat worker did not stop")
        if stop_received.is_set():
            before = self.monotonic()
            self.coordinator.stop_ack(lease.run_id, snapshot())
            received = stop_received_at[0]
            if received is None or before - received > 5.0:
                raise RuntimeError("runner stop acknowledgement exceeded five seconds")
        elif heartbeat_failure:
            raise RuntimeError("runner heartbeat failed closed") from heartbeat_failure[0]
        else:
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
