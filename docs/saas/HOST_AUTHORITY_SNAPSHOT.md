# Host authority snapshot (H1A-2)

H1A-1 shipped the private host-authority listener (`heel/saas/host_authority.py`: AF_UNIX
publication, kernel peer rule, closed request/response codec, closed reason set) with a `decide`
callable left open. H1A-2 adds the real decision, `heel/saas/host_snapshot.py`, and wires the
listener into `build_server`. The listener, codec, reason set, peer rule and the H1A-1 proof files
are unchanged. There is no public route, no TCP path and no header-based authority path.

## States

None of the three states below is customer readiness. H1A-3 (host consumption: the
effective-minimum bound and the `t_start` anchor), H6 (host identity, provisioning, pause/restore
qualification) and H-B (customer enablement) remain mandatory and unchanged.

| State | When | What the control plane does |
|---|---|---|
| **Default off** | `HEEL_HOST_AUTHORITY_SOCKET` unset | No endpoint is published; `build_server` constructs what it constructed before plus three inert server attributes (`host_authority = None`, `host_authority_ready = False`, `host_authority_failure = None`). This is the shipped state of H1A-2. |
| **Enabled and serving** | socket, peer uid and profile configured | The private endpoint answers decisions from real state. Readiness (`host_authority_ready`) is set only under the server's `ready_lock` from the service's `alive`. |
| **Fail-closed quarantine** | the listener thread outlived its bounded stop (`lingering`) or died unexpectedly | `host_authority_ready = False`, `reaper_ready = False`, `draining = True`, a fixed log line. An actionable operational state (restart the process through the supervisor); never reported as healthy and not "default off". |

## Configuration

| Variable | Rule |
|---|---|
| `HEEL_HOST_AUTHORITY_SOCKET` | Absent or empty: feature off. Otherwise an absolute, normalized path without NUL whose directory is the database directory or below it, and not one of the database, lock, WAL, SHM or journal paths. |
| `HEEL_HOST_AUTHORITY_PEER_UID` | Required with the socket; decimal uid, `0 <= uid < 2^32 - 1`. |
| `HEEL_HOST_AUTHORITY_PEER_PROFILE` | Required with the socket; `external-pidns` or `shared-pidns`. |
| `HEEL_MANAGED_HOST` | Absent: not managed. `1`: managed; the socket is mandatory, the profile must be `external-pidns` and the peer uid `0`. Any other value is refused. |

Every refusal is a `ProductionConfigurationError` from `ProductionConfiguration.from_environment`,
naming the variable, raised before the process lock is taken or anything binds. A peer uid or
profile without a socket is refused. The socket path is never logged.

## Decision

Each request gets its own SQLite connection (`busy_timeout` 250 ms), exactly one `BEGIN IMMEDIATE`
and exactly one wall-clock sample taken inside it. The order is fixed:

```
0  draining, or the service is stopping   -> inactive cp_draining (no connection, no ledger write)
   under the decider's gate: quarantined  -> 500, no body (service_stopped)
1  connect; BEGIN IMMEDIATE; one time sample; now_ceil, now_floor
2  ledger                                  -> may answer inactive replayed_sequence | clock_gap (committed)
3  workspace row exists                    -> else workspace_unknown
4  single active run of the workspace      -> 0: no_active_run; 2 or more: multiple_active_runs
5  authoritative join for that run         -> absent: invalid_grant
6  issued-tuple equality                   -> first inequality: tuple_mismatch (field never named)
7  live state, first match wins (below)
8  COMMIT; reply
```

Selection is `status IN ('claimed','running') AND stop_reason='none'`, so stop-requested and
finalizing runs are `no_active_run` by definition.

The issued tuple (`project_id`, `environment_id`, `runner_id`, `runner_key_id`, `run_id`,
`binding_id`, `binding_digest`, `grant_id`, `grant_digest`, `verification_record_digest`) is compared
by exact equality with the immutable columns of the run, grant, link and binding, and the
verification digest also with the digest inside the signed approval and grant. NULL on the
authoritative side never matches, so a run without a runner-context link is `tuple_mismatch`, never
`binding_inactive`. A signed record whose JSON lacks the digest is also an issued-tuple inequality.

Live-state precedence (evaluated only after the tuple matched):

| # | Condition | Reason |
|---|---|---|
| a | signed approval/grant fail verification, or key digest, egress host/port or stored grant expiry disagree with them | `invalid_grant` |
| b | the live environment digest differs from the signed records; the stop is persisted in this transaction through the service's own `_gate(advance=False)` | `verification_digest_replaced` |
| c | runner not active | `runner_revoked` |
| d | key not active or revoked | `key_revoked` |
| e | environment revoked or not verified | `proof_revoked` |
| f | binding not active | `binding_inactive` |
| g | grant not claimed | `grant_not_claimed` |
| h | kill switch active | `kill_switch_active` |
| i | control generation differs from the request or the run | `kill_switch_generation_changed` |
| j–l | remaining life `<= 0`, in the order proof, binding, grant | `proof_expired`, `binding_expired`, `grant_expired` |
| m | `_gate(advance=False)` inactive with none of a–l | `run_not_active` (defence in depth; not expected) |

`_gate`'s `server_time_ms` is never read. Reply integers: `server_time_ms = ceil(now)`; grant and
binding expiries as stored (integer ms); proof expiry `floor(proof_expires_at * 1000) - 1`. Each
stored future is bounded per member before any arithmetic (grant 10 minutes, binding 24 hours, proof
30 days from `now_ceil`, and `0 <= value <= 2^53`); a value outside its bound is a fault, 500 with no
body. Since the signed grant cannot exceed ten minutes, a stored grant expiry beyond it disagrees with
the signed record and is `invalid_grant` first.

Host side (accepted Astra amendment of H1A2D §5.3, implemented by H1A-3, not here): the host
validates each remaining life against the member-specific bound above, takes the effective minimum,
rejects it when `<= 0` or above 24 hours (a sanity bound; the grant bound makes it at most ten
minutes in every valid reply) and anchors the deadline at its own `t_start`, recorded before the
request was sent.

Faults (`db_busy`, `db_error`, `malformed_state`, `generation_capacity_exhausted`,
`service_stopped`) are raised as `HostSnapshotError` with the code only, answered by the listener's
existing 500/no-body outcome, counted by code and logged as one fixed JSON line. No exception text,
SQL or path leaves the module.

Transaction discipline: after the first failure no further business statement or COMMIT runs; the
cleanup may run one ROLLBACK (a failed COMMIT needs it) and the connection is closed on every path
after `connect` returned, including `KeyboardInterrupt`, which is re-raised unchanged. A failing
ROLLBACK or close is counted (`cleanup_failed`) and logged, never claimed as done. A reply is
returned only when COMMIT returned.

## Ledger (migration 31, `host_authority_generations`)

Migration 31 is additive: one table and one partial unique index (one open generation per
`(host_boot_epoch, slot_id)`); no existing table is altered. Rules, inside the request's
transaction and before selection:

- Enrolment only at `sequence == 1` for an unknown `generation_id`; it supersedes the open
  generation of the same `(host_boot_epoch, slot_id)`.
- An unknown generation at any other sequence is inserted closed (`unenrolled`) and answered
  `replayed_sequence`; it can never open.
- A closed generation never reopens: `replayed_sequence` whatever the sequence or identity.
- An open generation presented with a different `(host_boot_epoch, slot_id)` is closed
  (`identity_mismatch`) and answered `replayed_sequence`; a sequence at or below the last one closes
  it (`replayed_sequence`); CP time going backward, host monotonic time going backward, or CP and
  monotonic elapsed time differing by more than 500 ms closes it (`clock_gap`).
- Every closure is a reply, so it commits with the reply. Closure timestamps are never below the
  row's last CP time; the last CP time advances only on the pass path.

**No row ever leaves the table while the database file exists.** Capacity is 65 536 rows
(`MAX_GENERATION_ROWS`, a module constant, no runtime knob) and saturation is fail-closed: every new
generation is refused with `generation_capacity_exhausted` (500), while open generations keep
advancing. Recovery is only a reviewed release that raises the constant with every row preserved;
the constant may never be lowered below a deployed file's row count. Any future compaction, archival
or reset requires its own design establishing independent durable anti-replay (for example a CP
incarnation bound by the host) and its own qualification before it may run against any file.

A host supervisor in a crash loop enrols one row per restart (about 18 hours to saturation at one
restart per second); the host-side restart backoff belongs to H1A-3.

## Rollback

`build_server` applies migration 31 automatically on the first start of this code, and the previous
code refuses a database at version 31. The only documented rollback of a deployed file is: stop the
control plane, restore the pre-upgrade database copy, start the old binary. The old binary wires no
host-authority endpoint, so the host finds none and its own fail-closed rule applies; stale
authority is never admitted after rollback (H1A-3 host rule: a lease issued before the rollback ends
at its already-computed effective expiry at the latest and is never extended).

Restoring the pre-upgrade copy is safe only with hosted execution disabled on the old binary. It
does not make a later re-upgrade safe to re-enable: the restored file has no record of generations
closed after the copy was taken, so any re-enablement must preserve or restore the latest
anti-replay ledger, or satisfy a separately reviewed incarnation/reset protocol. There is no down
migration and no ledger removal procedure. H1A-2 mutates no production database.

## Lifecycle

`HostAuthorityService` runs the listener on one non-daemon thread named `heel-host-authority`.
Phases: `unstarted` → `serving` → `stopped`, or `lingering`. It is never restarted
(`restart_refused`); `build_server` never calls `start()` twice.

`start()` publishes the listener on the caller's thread, starts the thread and waits up to 5 s for
it to reach `serve_forever`. A death before that wakes the wait and is reported as `startup_failed`;
an expired wait is `startup_timeout`. On either, `start()` first calls `stop()` and attaches its
`StopResult` to the error.

`stop()` (bound 6 s, quarantine bound 3 s), in this order:

1. sets the decider's stopping flag (draining is declared before any cleanup);
2. closes the listener (stops accepting, unlinks its own inode);
3. joins the thread outside every lock;
4. joined: closes the decider's gate for good and returns `(stopped=True, quarantined=True)`;
5. not joined: tries the gate within 3 s and returns `(stopped=False, quarantined=<bool>)`, phase
   `lingering`, failure `stop_timeout`, one log line `host_authority_lingering` with `quarantined`.

`stop()` is idempotent and repeatable: a later call can move `lingering` to `stopped` once the
thread ended. Lock order is `ready_lock` → the service's state lock; the decider's gate is never
taken while holding either, and the death callback runs after the state lock was released and never
calls `stop()`.

What the quarantine proves. `quarantined=True` means the gate was closed while no decision held it:
the thread is not inside a transaction and can never open the database again; such a lingering
thread is inert. `quarantined=False` means a transaction did not finish within the bound (for example
stalled I/O on the volume); then ownership stays retained, SQLite's atomic commit and recovery decide
whether that one transaction committed, and the process remains unhealthy. The quarantine does not
make a supervisor kill incapable of interrupting a ledger write in that case.

**Ownership rule.** This process releases database ownership (control-plane connection, process
lock, and the pre-production close) only when both workers are joined: `host_authority.stop()` is
`stopped` and the reaper stopped. Production close order: draining → TCP close and request drain
(30 s) → host-authority stop → reaper stop → checkpoint → control plane → callbacks → lock. If the
host-authority stop is not `stopped`, `server_close` raises `HostAuthorityServiceError("stop_timeout")`
before the reaper stop and before any release, `closed` stays false, and a repeated `server_close`
on the same handle is the retry that completes once the thread ended.

On a start failure that leaves the thread lingering, `build_server` raises
`HostAuthorityServiceError("stop_timeout")` (a reaper that does not stop raises
`CanaryReaperError`), releases nothing, and logs `control_plane_ownership_retained` with the reason.
On that start path the reaper is joined before the raise (joining releases nothing; otherwise no
caller would ever stop it and the process could not end when the listener thread ends). Every
retained owner (server, control plane, lock, reaper, service) is kept strongly referenced in a
process-owned holder in `server.py`; nothing there releases, replaces or restarts it automatically,
even after its thread ended. A `build_server` that raised never returned a handle, so recovery is the
supervisor restarting the process.

Process exit, stated as measured: an exception escaping `main()` does not end a process that still
has a live non-daemon thread. In the `lingering` state the process keeps the `flock` and the one
accepted connection until the thread ends (the peer finishes or disconnects) or the supervisor kills
it; a client disconnect alone releases nothing while the process keeps running. The kernel releases
the lock and the connection when the process actually exits. Same-process reacquisition stays
refused.

Bound interaction (an acknowledged later operational gate, not provider qualification): the
pathological shutdown sum 30 s drain + 6 s stop + 3 s quarantine (+5 s) = 44 s exceeds the
deployment's 35 s `stop_grace_period`, so a kill may precede the lingering log line in that case.

Trickle-peer limit: the frozen listener applies its 5 s timeout to each `recv`, not to a whole
request, so an admitted peer that keeps sending bytes slowly can hold the serving thread far longer
than the stop bound (up to `(8192 + 2048)` one-byte receives). That peer is the configured host
supervisor inside the trust boundary; H1A-2 does not reopen the frozen listener to add a wall-clock
bound. Such a stop ends in the quarantined `lingering` state above.

## Tests

`tests/test_host_snapshot.py` covers the decision on real SQLite reached through the product's own
paths, the ledger, the faults and connection discipline, configuration, and the lifecycle with real
AF_UNIX clients. Seams are labelled (`SEAM-CLOCK`, `SEAM-RECORDING-CONNECTION`, `SEAM-CAPACITY`,
`SEAM-LISTENER`, `SEAM-SERVE-FAILURE`, `SEAM-THREAD-START`, `SEAM-STOP-HANG`) and pinned as unused by
production modules; hand-altered rows are labelled `STATE-INJECTION`. Only the Linux test
`test_end_to_end_over_real_af_unix_with_peer_credentials` exercises `check_startup` and the kernel
peer rule; the other AF_UNIX tests use `SEAM-LISTENER` and do not claim that path.
