# Optional local runner execution bridge — October 24, 2026

`heel runner serve` can now execute one previously approved, Cloud-signed scan lease for a locally paired,
context-bound runner whose environment is `staging` or `sandbox`. This is the optional private
connector. It is not the default managed journey, and it does not provide generalized plan-differential
coverage beyond the closed canary actions the existing compiler and adapter produce.

## The implemented seam

1. `RunnerCoordinator.claim` loads the immutable local approved pair, validates the signed bundle against
   the fresh gate and returns a `ClaimLease`. A claim that is recorded but cannot be decoded locally still
   ends serve with `execution_unavailable` and sends no target traffic.
2. `RunnerService` owns the lifecycle: claim, then heartbeat/progress during execution, then `result`, or
   the bounded `stop_ack`. The serve-cycle owner forwards each call to the coordinator and waits for calls
   in flight before the runtime closes.
3. For each lease, `RunnerExecutionAdapter` rechecks `execution_gate(run_id)`, revalidates the exact
   claimed bundle and its active-claim binding, and only then calls the daemon's transport factory. A
   stale, revoked, expired, unknown or mismatched lease never reaches DNS, sockets or secrets.
4. The factory first requires every signed credential binding to name an active local record in an OS
   secret store (`macos_keychain` or `linux_secret_service`). It refuses env and fd handles from metadata
   alone, with `credential_unavailable`, so the executor's ephemeral fallback cannot run under serve.
   Vault objects come only from `select_vault`, and the daemon loads no secret.
5. The factory resolves the full public address set of the validated manifest origin once and builds a
   direct `TargetHTTPSClient` pinned to it. The client re-resolves before every attempt and refuses a
   changed set. Nothing from the CLI, the daemon record, plan labels or responses chooses the origin, the
   resolver, the port (443), headers or TLS. A preflight DNS failure ends serve with `target_unavailable`.
6. `LocalCanaryExecutor` reserves the run, writes containment and raw response evidence only to the local
   `RunnerStore`, and signs redacted operational and findings projections. It chooses one terminal instant
   and uses it both for the signed projections and for the stored terminal transition, so the
   coordinator's exact terminal-authority check passes under a real clock. Recovery of persisted finals
   terminalizes at the instant they sign, or fails closed.

## Evidence classes

Focused tests (`tests/test_runner_daemon.py`, `tests/test_runner_coordinator.py`, `tests/test_runner_stop.py`)
use real stores, runtime, coordinator, control client, service, executor and `TargetHTTPSClient` on the
real wall clock. They also include one owned-loopback HTTPS target with real TLS verification of the
manifest host. The control plane answers through a scripted transport, OS vaults are test doubles behind
the vault factory, and the resolver, socket and TLS collaborators are injected through constructor-only
test seams that the CLI never passes. This is synthetic, local evidence. It is not deployed or customer
evidence.

## Still gated

Default managed admission (H2/H3/H6), hosted credential and raw-body custody, remote evidence sync, browser
or UI-abuse coverage, discovery, `login_exchange` and the C3 parser/provider work remain blocked by their
own decisions. A stop that arrives while the transport factory is still resolving DNS, before any target
socket exists, has no local run to acknowledge. Serve then fails closed and the server's reaper ends the
run.
