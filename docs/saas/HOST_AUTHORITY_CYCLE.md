# Host authority cycle (H1A3-1)

Status: source candidate. It is component evidence only: no runtime verdict, no deployment and no
launch claim. `deploy/host/cycle.py` is a library used by its tests (and, in H1A3-2, by the Linux
proof). It is not wired into `build_server`, installs no production rules (H2), manages no executor
(H3), qualifies no provider (H6) and enables no customer workload. The only admission is
`Enablement.NON_CUSTOMER`; there is no environment variable, flag, entry point or systemd unit.

## What the cycle does

One `HostCycle(slot_id, cp_socket, cp_uid, slot_src=…, slot_dst=…, admission=Enablement.NON_CUSTOMER)`
owns one generation at a time. A generation is one `LeaseDomain` (one namespace held by descriptor,
one private mark counter); it carries **one context** and is never reopened.

- `install_signal_context()` (main thread, once, before `start()`), then `start()`:
  `verify_signal_context()` → `LeaseDomain.create()` → `generation_self_test(domain)` (throwaway
  namespaces only) → `profile.grade_self_test(report) == ("pinned", [])` → K9 sleep enforcement
  (every sleep unit `masked`, the drop-in `all_disabled`, hibernation disabled) → witness baseline →
  `ready`. The `ready` transition is H2's hook to install the gate table in the generation's
  namespace (B1). Before any of this: the process-wide budget (8 generations, 10 s apart) and the
  registry rule (any uncertainty quarantines; handed-off children are left to drain first).
- `install_context(CycleContext)` → `serving`. `CycleContext` is a frozen, slotted, keyword-only
  record of the eleven request identity strings, the grant's `public_key_digest` and
  `egress_hostname`, `kill_switch_generation` and `egress_port` (443), validated against the request
  codec and the active-reply grammar. It holds ids and digests only.
- `tick()` (main thread, at `INTERVAL_MS`): stop flag → registry rule → witness →
  `prepare(src, dst, 3000)` → stop flag → request (`sequence + 1`, fresh nonce,
  `monotonic_ms = t_start // 10⁶`) → one exchange under `min(t_start + 1000 ms, E_lower)` →
  codec, canonical bytes and context equality → stop flag → registry rule → witness → activate iff
  the inequality holds → the new handle becomes `current`, the previous one `retired`.
- `stop()` and `stop_context()` are poll points themselves: an orderly end (rows 23, 24) runs at once.
- `status()` and one JSON log line per transition on logger `heel.host.cycle`; `on_transition`
  callbacks receive `(event, status)` outside the cycle lock.

Nothing is learned or adopted from a reply, no request is built from a reply, and a sequence is
consumed when the request is built: it is never resent, whatever happens to the reply. One request is
outstanding per slot, ever.

## The inequality

All times are `CLOCK_MONOTONIC` nanoseconds; `T = LEASE_MS = 3000` ms; `tick = ceil(10⁹ / CONFIG_HZ)`
from the self-test's `config_hz` (unknown HZ is unpinned and refused).

| Symbol | Definition |
|---|---|
| `t_p0` | the handle's `prepared_monotonic_ns`, sampled before the installer child |
| `t_p1` | sampled right after `prepare()` returned (the commit happened before) |
| `E_lower = t_p0 + T − 2·tick` | end of the window in which the accepted evidence measured the element live. A liveness gate only: the cycle stops *attempting* activation at `E_lower`; **no availability claim** is derived from it |
| `E_upper = t_p1 + T + tick` | the latest instant the kernel can admit a packet on the element |
| `t_start` | sampled after `t_p1`, before the request; `request_gap_ms = (t_start − t_p1) // 10⁶` |
| `rem` | `min(expires_i − server_time_ms)` over proof, binding and grant of the same reply, each `0 < rem_i ≤ bound_i` (`2 592 000 000`, `86 400 000`, `600 000` ms) and `rem ≤ 86 400 000` |
| `D = t_start + rem` | the authority deadline, anchored at `t_start`, never at the reply |

Activate at `t_act` iff `t_act < E_lower` (else `key_expiring`) and `E_upper ≤ D` (else
`authority_too_short`), the reply passed every check and the registry and witness are clear.
Activation writes no lifetime, so no packet is admitted on the slot's tuple after `min(E_upper, D)`
of the cycle that proved it, unless a later cycle proves the inequality again with a new key. For an
activated key `min(E_upper, D) = E_upper` (activation requires `E_upper ≤ D`). If `activate()` returns
at or after `E_lower` the outcome is `activation_late` (`authorized = unknown`); the next cycle re-proves.

## Renewal and `close`

`close(handle)` destroys the slot's `activated` entry **by tuple**, not by mark: closing a superseded
handle after the swap would destroy the new activation. Exactly one `current` handle exists per slot;
a superseded handle is `retired` and never closed (its element expires by its own `E_upper`). `close`
runs only on `current`, at a context end. `MAX_CYCLES_PER_GENERATION = 2²⁰` bounds the retired
reservations (row 25).

## The transition table

Classes. **A — orderly end**: `close(current)` if a handle was activated, then `close_generation`
(flush of the generation's own `activated` map, descriptor closed); generation `closed`; a new
generation is allowed within the budget. **B — kernel state unproven**: `close_generation` only;
generation `closed`; the namespace is never served again. **C — quarantine**: at most one
best-effort `close_generation` inside `except BaseException`, then `quarantined(code)`,
`exit_required`, no further domain call and no new generation in this process. **K — key outcome**:
this cycle ends without activation; the context and the previous window continue. **N** — progress.
Every context end closes the generation (a replacement context needs `start()` and a new domain).

| # | Trigger | Detected at | Class | Admission afterwards |
|---|---|---|---|---|
| 1 | `active`, every rule holds | after reply | N `activated`, swap | new window until `min(E_upper, D)` |
| 2 | `active`, `t_act ≥ E_lower` | before activate | K `key_expiring` (3 consecutive with row 3 → A `authority_unusable`) | previous window to its bound |
| 3 | `active`, `E_upper > D` | before activate | K `authority_too_short` (same counter) | previous window to its bound |
| 4 | `active` differs from the context in any context string, `kill_switch_generation` or `egress_port` | validation | A `context_mismatch` | ≤ `min(E_upper, D)` until `close` returns; then rule R |
| 5 | `active` with `rem_i ≤ 0`, `rem_i > bound_i`, a non-integer, or `rem > 86 400 000` | validation | A `stale_durations` | as 4 |
| 6 | `inactive` with any of the 23 reasons `workspace_unknown`, `project_unknown`, `no_active_run`, `multiple_active_runs`, `run_not_active`, `stop_requested`, `grant_not_claimed`, `grant_expired`, `invalid_grant`, `proof_expired`, `proof_revoked`, `verification_digest_replaced`, `runner_revoked`, `key_revoked`, `binding_inactive`, `binding_expired`, `kill_switch_active`, `kill_switch_generation_changed`, `tuple_mismatch`, `malformed_request`, `cp_draining`, `replayed_sequence`, `clock_gap` | reply | A `<reason>` | as 4 |
| 7 | no reply / `cp_timeout` / `cp_unavailable` / `malformed_reply` / `late_reply` / `peer_identity` / `connect_failed` | exchange | K `<code>`; 3 consecutive → A `cp_unreachable` | previous window to its bound; no replay |
| 8 | `prepare` → `installer_refused` (generic: EEXIST, a missing table, a permission or anything else) | prepare | A `prepare_refused` (generation-terminal) | previous window (R) |
| 9 | `prepare` → `installer_timeout` (child killed, maybe handed off) | prepare | K `prepare_uncertain`; with row 10, 3 consecutive → A `key_failures` | previous window (R) |
| 10 | `prepare` → `installer_error` | prepare | K `prepare_error` (same counter) | previous window (R) |
| 11 | `prepare` → `DomainExhausted` | prepare | A `domain_exhausted` | previous window (R) |
| 12 | `activate` → `installer_refused` | activate | A `activate_refused` | previous window (R) |
| 13 | `activate` → `installer_timeout` (the killed `nft` may have committed, or may commit later) | activate | B `activation_uncertain` | `R_bound` (rule R), even after the flush returned |
| 14 | `activate` → `installer_error` | activate | B `activation_error` | as 13 |
| 15 | `activate()` returns at or after `E_lower` | after activate | N `activation_late` (`authorized = unknown`) | ≤ `min(E_upper, D)` |
| 16 | `close(current)` fails during a class-A end | close | B `close_failed` | `R_bound` |
| 17 | `close_generation` → `flush_timeout`/`flush_refused` in any class | flush | C `flush_failed` (descriptor already closed) | `R_bound` |
| 18 | witness `sleep_gap`/`wall_gap` before prepare or before activate | witness | B `clock_gap_host` (detection, not safety) | `R_bound` |
| 19 | registry `owned + looking + sweeping + uncertain + other ≥ 1` | each tick, before prepare and activate, at start | C `child_uncertain` | `R_bound`; flush attempted once |
| 20 | registry `handed_off + reaped ≥ 1` (and no uncertainty) | same | `draining`: only `sweep_unresolved_children()` per tick; cleared → `serving`; 5 draining ticks → C `child_stranded` | current window to its bound |
| 21 | any `BaseException` escapes a domain call, the exchange or the cycle's own code | the method's outer handler | C `operation_interrupted`, re-raised after recording | `R_bound`; no zero claim in this process again |
| 22 | `ForeignProcess`, `ForeignHandle`, `DomainClosed`, `HandleState` | any domain call | C `domain_invariant` | as the domain left it |
| 23 | stop flag set by a signal, or `stop()` | the three poll points, or `stop()` itself | A `stop_requested` (`exit_required` false) | 0 after close/flush only under rule R |
| 24 | `stop_context()` | itself | A `context_replaced` | as 23 |
| 25 | `MAX_CYCLES_PER_GENERATION` reached | tick entry | A `generation_rotated` | as 23 |
| 26 | start refusals: `signal_context_invalid`, a `DomainUnavailable` code, `selftest_failed`, `profile_unpinned`, `sleep_capable`, `clock_unavailable`, `boot_epoch_unavailable` | start | the domain (if created) is closed; `generation_class_end = start_refused`; counts against the budget | none (nothing was prepared) |
| 27 | budget: a ninth generation in the process, or spacing < 10 s | start | C `generation_budget` | none |

Counters: rows 2/3 share `MAX_CONSECUTIVE_UNUSABLE = 3`, row 7 `MAX_CONSECUTIVE_UNAVAILABLE = 3`,
rows 9/10 `MAX_CONSECUTIVE_KEY_FAILURES = 3`; rows 8, 11 and 12 are terminal at once. No row loops to
the 12-day rotation. `closed` and `quarantined` are terminal for the generation; a new context never
enters a namespace that may retain an activation.

### Rule R (residual)

A `close` or flush child that returned 0 removes the map entry only with respect to writers that have
already finished. While any child is unresolved anywhere in the process (`owned`, `looking`,
`handed_off`, `sweeping`, `uncertain`, `other`), or a child was lost to an escaped exception (row 21),
a late commit may re-add an entry after the close or flush. The residual bound is the union of the
windows of every key handed to `activate`: `R_bound = max_i min(E_upper_i, D_i)` (kept as a running
maximum, never "≤ new and ≤ previous": the new window normally outlives the previous one). "0 after
close/flush" is claimed (`residual = zero`) only for a class-A end whose close and flush returned 0
while the **process-global** registry was empty, with no lost child in the process and no earlier
unproven residual still running. The registry carries no namespace identity, so the cycle never
attributes an entry to a namespace: any entry anywhere keeps the residual `bounded`. Status reports
`residual` (`none`, `zero`, `bounded`, `expired`, decided on exact nanoseconds), `residual_bound_ms`
(display only, floored) and the global `unresolved_children` counts. A rounded millisecond never
decides authorization or the absence of residual traffic. The namespace is never reused; it dies
only when H3 has stopped/detached its executors and released every reference (descriptor dups,
attached processes, sockets, interfaces); the residual expires by itself at `R_bound` regardless.

## Signals and the asynchronous-exception contract

- The handler for `SIGTERM`, `SIGINT` and `SIGHUP` is one attribute store
  (`_STATE.stop_requested = True`): no lock, no `Event`, no logging, no callback, no domain call (an
  `Event.set` in a handler can deadlock against a held condition lock). The owner thread polls the
  flag at tick entry, after `prepare` and after the reply, and performs row 23 itself.
- `install_signal_context()` runs on the main thread and refuses before changing anything: a
  `SIG_IGN` `SIGCHLD` (`sigchld_ignored`), a Python `SIGCHLD` handler (`sigchld_custom_handler`), a
  Python handler on any other valid signal (`foreign_signal_handler`; for the three stop signals only
  the interpreter's default `SIGINT` handler is replaced), or a call off the main thread
  (`not_main_thread`). `SIGPIPE` stays as the interpreter set it. `verify_signal_context()`
  re-reads every valid signal at each generation start and refuses `signal_context_invalid` on any
  difference.
- **Bounded claim**: while the verified picture holds, no signal raises a Python exception on any
  thread. Nothing is claimed for a process whose verification failed or whose handlers changed after
  the last verification (detected only at the next generation start), nor for an interrupt raised
  before installation, `SystemExit`/`MemoryError`/`RecursionError` raised by code, a handler
  installed later, `_thread.interrupt_main`, or interpreter shutdown.
- No recovery API: if a `BaseException` escapes a domain call or the exchange, `_run`'s cleanup may
  itself have been cut short and a child may be unregistered. The single reaction is row 21: record
  `operation_interrupted`, one best-effort `close_generation`, `exit_required`, re-raise. No retry, no
  pid ever leaves `authority.py`, no wait-any.
- **Fork-to-record** (carried, not closed): `os.register_at_fork` protects a forked *copy*; the parent
  gap between `os.fork()` returning and the `_Child` record is not closed by anything here, so an
  exception landing there leaves a child no reader reports. **Repeated interruption** (carried): the
  row-21 cleanup, record and re-raise are Python and can be interrupted again; they are not promised
  to complete. The safety argument for both is the kernel bound (`R_bound`) and the terminal process
  policy (`exit_required`; H3 exits; H6 decides the restart policy), not registry completeness.
  `cycle.py` never forks; H3 may fork only to `exec`.

## The registry rule

`authority.unresolved_children()` returns the fixed seven keys (`owned`, `looking`, `reaped`,
`handed_off`, `sweeping`, `uncertain`, `other`) counted under the registry lock over the whole process,
with no `waitpid`, no signal and no pid in the result. `owned`/`looking` entries exist when
`_kill_and_reap` was interrupted between its registry insert and its state store; `sweeping` is an
interrupted sweep look; `reaped` is a discard cut short. `authority.sweep_unresolved_children()` is one
non-blocking sweep of handed-off holders followed by the reader: the drain boundary, the only call a
draining generation makes. Admission: any uncertainty → row 19; otherwise any `handed_off`/`reaped` →
row 20. No state is ever polled or signalled by the cycle.

## Status keys

`generation_phase` (`created`, `bootstrapping` (H2-A registered mode only), `ready`, `serving`, `draining`,
`closing`, `closed`, `quarantined`),
`generation_id`, `generation_class_end` (`none`, `A`, `B`, `C`, `start_refused`), `context_state`,
`context_end_reason`, `sequence`, `cycles`, `last_decision`, `last_reason`, `consecutive_unavailable`,
`consecutive_unusable`, `consecutive_key_failures`, `authorized` (`true`, `false`, `unknown`),
`deadline_remaining_ms`, `residual`, `residual_bound_ms`, `request_gap_ms`, `unresolved_children`,
`unresolved_handed_off`, `unresolved_uncertain`, `drain_ticks`, `witness_gaps`, `quarantine_code`,
`kernel_profile`, `runtime_assumption` (`running-kernel`), `exit_required`, `generations`,
`enablement` (`non_customer`), `workspace_id`, `run_id`, `slot_id`. Values are fixed tokens, integers
and booleans; never a request or reply body, nonce, digest, path, pid or exception text.

## Interfaces and what later gates must do

- **H2 (B1)**: install `heel_lease` with the `prepared`/`activated` lookups and `meta mark set 0` in
  the generation's namespace before `ready` (`ns_fd`, dup only); never write elements. Until then a
  bare namespace refuses `prepare` (row 8). The public pre-ready boundary is H2-A
  (`docs/saas/H2A_BOOTSTRAP_CONTRACT.md`): `register_bootstrap(BootstrapChannel)` before each
  `start()` makes `ready` wait for the bootstrap worker's exact receipt (the namespace duplicate goes
  by `SCM_RIGHTS`, outside the cycle lock, under `BOOTSTRAP_DEADLINE_MS`); any other result revokes
  through the root controller and ends `start_refused` with reason `h2_bootstrap_failed`, or
  quarantines `bootstrap_unresolved`. A cycle that never registers keeps the behaviour above
  (legacy `NON_CUSTOMER` callers); once registered, a start without a new registration raises
  `bootstrap_unregistered`. H3 must require the registered mode.
- **H3 (B2)**: deliver the claim-derived `CycleContext` (including the grant's `public_key_digest` and
  `egress_hostname`) and the slot's `slot_src`/`slot_dst` over a root-owned channel; run `tick()` on
  the main thread at 1 Hz; stop/detach the executor on `closing`, `closed`, `quarantined` and every
  context end; never reattach; release every reference to the namespace; exit on `exit_required` and
  on any exception from the cycle; never run cycle or domain code in a forked copy.
- **H6 (B3)**: qualify the exact host, provider, SKU and kernel profile; only a reviewed change
  carrying that qualification may add an `Enablement` member.
- The cycle writes nothing to the control plane. A stopped executor's heartbeats stop and the existing
  reaper moves the run to `stop_requested / cloud_stop / cloud_disconnected`.

## Limits

- Running-kernel assumption: grading describes the kernel the self-test ran on; it qualifies no
  provider, SKU or host, and nothing here proves pause, save/restore, migration or clone behaviour.
- No packet-path claim: the tests use a recorded installer (no nft, no namespace); the Linux
  real-control-plane tests prove the decision path only. The kernel/timing path is H1A3-2's scripted
  proof.
- Component evidence only: neither this unit nor H1A3-2 is the journey. **H1A3-A** (combined
  acceptance: real control plane, real `LeaseDomain` on the qualified profile, H2 rules, H3 executor,
  customer-facing acceptance, no mocked decider or recorded installer) runs after H2/H3/H6 and before
  H-B.
- The parent fork-to-record gap and repeated interruption remain carried limitations (above).
