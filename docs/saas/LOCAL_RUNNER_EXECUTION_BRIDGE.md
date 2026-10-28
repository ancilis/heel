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
   claimed bundle and its active-claim binding, and only then runs the daemon's credential precheck. A
   stale, revoked, expired, unknown or mismatched lease never reaches DNS, sockets or secrets. A stop
   already chosen for the lease ends it here with no local work.
4. The precheck requires every signed credential binding to name an active local record in an OS secret
   store (`macos_keychain` or `linux_secret_service`). It refuses env and fd handles from metadata alone,
   with `credential_unavailable` and before any local reservation, so the executor's ephemeral fallback
   cannot run under serve. Vault objects come only from `select_vault`, and the daemon loads no secret.
5. `LocalCanaryExecutor` then activates the run in one step under its stop lock: it reserves the one-shot
   grant, starts the containment log, moves the local run to `running` and publishes its active context.
   This is the linearization point. A stop chosen before it reserves, loads and dials nothing and sends no
   acknowledgement or result. A stop chosen after it finds a durable running run to acknowledge.
6. Only an activated run calls the transport factory. The factory resolves the full public address set of
   the validated manifest origin once and builds a direct `TargetHTTPSClient` pinned to it. The client
   re-resolves before every attempt and refuses a changed set. Nothing from the CLI, the daemon record,
   plan labels or responses chooses the origin, the resolver, the port (443), headers or TLS. A preflight
   DNS failure finalizes that run as `incomplete`/`target_unavailable` with zero requests and no secret
   load, and its one terminal result lets the Cloud refund the zero-request run. The executor checks for
   a stop again after the factory returns, before any secret load, and before every attempt.
7. The executor writes containment and raw response evidence only to the local `RunnerStore`, and signs
   redacted operational and findings projections. It chooses one terminal instant and uses it both for the
   signed projections and for the stored terminal transition, so the coordinator's exact
   terminal-authority check passes under a real clock. Recovery of persisted finals terminalizes at the
   instant they sign, or fails closed. Recovery of an activated run that crashed before or inside the
   factory finalizes it with zero requests, without the factory, a secret load or a target request.

## Stop outcomes

Local stop (including `SIGTERM` and `request_stop`), Cloud stop, runner revocation, target revocation and
the kill switch share one first-winner stop controller. It records exactly one outcome and never lets a
worker exception escape:

| Outcome | When | What is sent |
| --- | --- | --- |
| `not_active` | no locally activated run (stop before activation, or after local finalization) | nothing further; the Cloud stop and its reaper own the run |
| `acknowledged` | one signed `stop_ack` for the activated run was accepted inside the 5 s deadline | that acknowledgement, then one stopped terminal carrying its accepted timestamp |
| `unacknowledged` | preparation failed, or the call failed, was not accepted or finished late | any attempted acknowledgement, then one stopped terminal with `stop_acknowledged_at_ms: null` |

The only result after a stop is the activated run's own signed `stopped` terminal for the chosen reason. A
null acknowledgement timestamp means "acknowledgement not established", not "acknowledged". The runner
never infers acceptance from an error or timeout, never invents or re-signs the timestamp, and never sends
a completed result after a stop. Over the real HTTP boundary the Cloud accepts that null-ack terminal when
its acknowledgement never arrived, and refuses an invented timestamp (`canary_state_conflict`).

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
own decisions. Two stop cases remain unresolved and fail closed; neither replays the factory, DNS, a secret
load or target traffic:

- **Pre-activation stop (`not_active`).** The claim's Cloud and runtime record has no local reservation
  and no locally signed terminal. A later serve cycle's coordinator restart refuses to rehydrate the
  stop-gated runtime row (`runtime active grant authority is unavailable`). The runner neither fabricates
  a local run nor hides the record. Reconciling it needs an authenticated, server-backed design.
- **Accepted-remote acknowledgement whose answer was lost or late.** The Cloud already holds the
  acknowledgement, so it refuses the runner's null-ack stopped terminal (`canary_state_conflict`). The
  result call fails closed, its exact request stays staged behind the registered local terminal, and
  restart refuses the stop-gated runtime row as above.

A stopped terminal that the Cloud accepts retires the runtime row, and a fresh coordinator then restarts
cleanly over the same store and runtime.
