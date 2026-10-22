# Host authority proof (H1A-1, `authority-v1`)

Status: source candidate. Runtime verdict: NOT RUN. The Linux run happens only after independent
review, on one manual dispatch of the exact reviewed SHA on the literal branch
`codex/self-serve-host-authority-proof`. H1A-1 is one host-control component: it is not wired into
`build_server`, holds no control-plane decision, runs no supervisor cycle, enforces no clock or
admission check, isolates no executor traffic (H2), manages no executor lifecycle (H3) and enables
no customer workload. It is not a deployment or a launch claim.

## What the unit is

`deploy/host/authority.py` is the kernel-lifetime generation domain of H1AD/H1ADR:

- `LeaseDomain.create()` forks a helper that unshares a network namespace; the parent opens
  `/proc/<helper>/ns/net` once and from then on holds the namespace only by descriptor. Nothing
  names, mounts or re-resolves it.
- A private counter starts at 1, is strictly increasing, refuses past `0xFFFF_FFFF` and is never
  persisted or returned. There is no public mark parameter anywhere.
- `prepare(src, dst, timeout_ms)` reserves the next mark under the domain lock **before** any child
  runs, writes the frozen `create element … timeout <T>ms` batch (EXCL, never `add`) and returns an
  opaque frozen `PreparedKey`. Failure, timeout (the child is killed and reaped), cancellation or
  any uncertain outcome consumes the mark for good. States are one-way:
  `RESERVED → PREPARED → ACTIVATED → CLOSED` and `{RESERVED, PREPARED, ACTIVATED} → CONSUMED`.
- `activate(handle)` accepts only the identical handle object this domain issued (a copy, a
  replacement, a pickled copy, another domain's or a hand-built handle is foreign) and writes
  `destroy element; add element` into the timeout-free map with no lifetime. A second activation is
  refused. `close(handle)` destroys the reference; `close_generation()` refuses everything from then
  on, consumes every open handle and flushes the map in its own namespace only.
- Every mutating operation holds the domain lock for its whole duration, child wait included, so a
  concurrent second activation, a racing `close_generation` or a racing prepare is serialized and
  then refused; a late child can never publish a usable handle or reopen a closed domain.
- Every kernel write is a forked child that enters the namespace by descriptor (`setns`), takes the
  frozen batch on stdin and `execve`s `nft -f -`; no Python runs after the exec and no
  `subprocess`/`multiprocessing` is used for batches.
- Bounded waits: one 1000 ms monotonic deadline per installer child covers draining its output
  **and** collecting its exit status. EOF alone completes nothing, and an exit observed after the
  deadline is uncertain (`installer_timeout`/`flush_timeout`), never a success. On expiry the
  owned child is SIGKILLed and given a finite 250 ms reap grace; a child still unreaped after that
  (for example stuck in the kernel) stays uncertain and is handed to a non-blocking sweep that reaps
  it later and never signals it. Once the launching operation has reaped its child or handed it off,
  its cleanup never polls or signals that pid again, even after an interruption, after the sweep
  dropped the entry or after the pid was reused; a status look cut short by an interruption is
  recorded uncertain and never retried (that child may still run or remain a zombie; it stays in
  the record). The namespace helper must report ready within 2000 ms or it is killed and creation
  refuses (`namespace_ready_timeout`; `namespace_helper_unreaped` if its release cannot be
  reaped). A mutating call therefore holds the domain lock for at most about 1250 ms. These are
  monotonic budgets, not hard real-time guarantees under a stalled or descheduled kernel.
- Ownership: the creating pid plus a per-process token that `os.register_at_fork` re-mints in every
  forked copy. Every public operation and the counter itself refuse in a forked copy before taking
  any lock. There is no override, argument, environment variable or flag. A legitimate new
  generation after a fork needs a fresh interpreter (`execve`).
- `generation_self_test(domain)` measures H1AD section 5.2 K1–K6 and K8 through the same API in
  throwaway namespaces (a veth pair, 200 ms keys), the A8-style re-add observation and
  `CONFIG_HZ`/`overflowuid`; any failure raises `HostQuarantined` with fixed tokens. Its duplicate
  create, expired-key recreate and non-EXCL re-add are labelled self-test fixtures that touch only
  its own throwaway namespaces.
- `verify_cp_socket(path, cp_uid)` is the supervisor's client-side check (initial user and PID
  namespaces, socket and directory profile, `SO_PEERCRED` uid and non-zero pid).
- `ClockWitness`/`detect_gap` (W-1/W-2) and `sleep_capability_report` (A-1/A-2) are diagnostic
  readers only. Nothing in H1A-1 calls or enforces them.

`heel/saas/host_authority.py` is the host-only listener: `AF_UNIX`, HTTP/1.1, one request per
connection, `POST /host/v1/authority-snapshot` only, body at most 2048 bytes of canonical JSON in
the closed `heel.host-authority-request.v1` schema (the H1D fields plus `generation_id`, `sequence`
and `monotonic_ms`), a closed `heel.host-authority-snapshot.v1` response with `Cache-Control:
no-store` and the H1D reason set plus `replayed_sequence` and `clock_gap`. The peer rule runs on
`SO_PEERCRED` before any byte is read: `external-pidns` requires the configured uid and pid 0,
`shared-pidns` requires a non-zero pid, `overflowuid` is never admitted, a refused peer gets no body.
Startup refuses a non-identity `uid_map`, a peer uid equal to `overflowuid`, an unknown profile or
peer uid, a missing platform capability and a socket directory that is not a `0700` directory
owned by the listener. The decision is injected; nothing here opens a database or reads
`Authorization`, cookies or the edge header.

Publication order is fixed: bind, chmod and verify, listen, rename, verify. The socket is bound to
`<path>.<pid>.<random>.tmp` under umask `0177`, set to `0600` and checked, put into the listening
state, and only then renamed onto the final path, which is written exactly once. A listen failure
removes only the temporary inode; `close()` unlinks the final path only while it is still this
listener's inode.

## Unit evidence (any OS)

`tests/test_host_authority.py` covers the reservation set U-1..U-10, the counter bound, the
concurrency races (deterministic: a signalling lock and pipe barriers order the threads), the
fresh-interpreter topology, the peer rule, startup refusals, the closed codec, header blindness,
publication order and own-inode unlinking on real `AF_UNIX` sockets, the diagnostic readers and the
workflow mutation matrix. Tests that use an installer double, explicit `(pid, uid)` pairs, a socket
double or clock samples are labelled `STATE-MACHINE ONLY` and claim nothing about namespaces, peer
credentials, expiry or packets.

## The Linux proof

Run from the repository root as exactly `python scripts/host_authority_proof.py`. The launcher
mirrors H1F and imports H1F's pytest closure by path; since H1A3-2 the supported-kernel pin,
`READD_EXPECTED` and `kernel_profile` come from the production `deploy/host/profile.py`, also by
path (equal to the H1F pin, a static test checks both). It refuses a dirty checkout, stages exactly
fourteen tracked files (the seven H1A-1 files plus `scripts/host_lease_feasibility.py`,
`scripts/host_ingress_proof.py`, `deploy/host/ingress/runtime-lock.json`, `tests/linux/__init__.py`
and the three H1A3 files `deploy/host/cycle.py`, `deploy/host/profile.py` and
`tests/test_host_cycle.py`, the last for provenance only) and records each SHA-256 and
`proof_file_count 14` in `summary.json`. It runs `tests/linux/test_host_authority_proof.py` as root
inside an outer network+mount+PID namespace with only loopback, under
`HEEL_REQUIRE_HOST_AUTHORITY_PROOF=1`, so every skip is a failure. Probes are H1F's: a datagram every
10 ms whose admission is the `sendto` verdict inside its own `[t_before, t_after]` bracket; a stale
or refused path is graded with no allowance. Process spawns are counted by PID allocation inside
the private PID namespace.

| Case | Oracle |
|---|---|
| **K8** | `generation_self_test` passes on the captured kernel; a key in a second throwaway namespace is not visible in the first; identities distinct; records the profile fields |
| **D1** | Two generations both issue mark 1. A stale writer holding generation 1's descriptor activates `S.D:1` after its key expired: generation 1's path and generation 2's path admit 0; generation 2's map stays empty; then generation 2's own activation delivers. Generation 1's next prepare gets mark 2 and re-activating the old handle is refused |
| **D2** | Negative control: the same writer resolves a namespace by name, re-pointed at generation 2: revival must be shown (≥ 50 admitted) |
| **D3** | Counter seam at `0xFFFF_FFFE`: `0xFFFF_FFFE` and `0xFFFF_FFFF` install and the last one delivers; the next two prepares raise `DomainExhausted` with zero processes spawned and no element changed |
| **D4** | A stopped helper of a killed first generation still holds its namespace (inode differs from generation 2); after `SIGCONT` its write lands only in the first generation's namespace |
| **D5** | Construction with a descriptor, `create` with a descriptor or a path, and another domain's or a copied handle are refused with zero processes spawned and no element changed; the domain's own handle delivers |
| **D6** | A non-exec forked copy (holding an inherited, locked domain lock) gets `ForeignProcess` from `prepare`, `activate(H1)`, `close_generation`, the counter, `close` and `create`, exits with the encoded status and spawns 0 processes; generation 1's next mark is `H1.mark + 1`; after `H1` expires, re-activation is refused without a fork and a burst admits 0 while a fresh key delivers |
| **T1** | Real listener as uid 10001, pid 1 of a child PID namespace, `external-pidns`, production permissions: the root client outside is answered (`inactive`, `no-store`) and sees uid 10001 and the outer pid; `verify_cp_socket` passes; uid 10002 gets `EACCES`; a root client inside the PID namespace (pid ≠ 0) gets no body |
| **T2** | Same listener, `shared-pidns`: the outside root client (pid 0) gets no body; the inside client is answered |
| **T3** | Refusals: user namespace with a non-identity map, peer uid = `overflowuid`, a `0755` directory, a symlinked directory, an unknown profile, a missing peer uid; a correct configuration publishes |
| **T4** | Connector loop (≥ 2000 attempts and ≥ 20 successes from a second process, before and after publication, paced as below): `ECONNREFUSED` 0, `EAGAIN` 0, other 0, unanswered 0, `ENOENT` ≥ 1, success ≥ 1, totals reconciled; published inode = bound inode with production permissions; no `*.tmp` during or after; the path is gone after `close()` |
| **T4N** | Negative control with the test's own wrong-order publisher and the same connector: `ECONNREFUSED` ≥ 1, `ENOENT` ≥ 1, success ≥ 1, ≥ 2000 attempts, with `EAGAIN`, other and unanswered 0 and totals reconciled; otherwise the probe cannot discriminate and the case fails |
| **T4F** | Injected listen failure with a working endpoint at the path: exception, final inode unchanged, endpoint still accepts, no `*.tmp` |
| **T4R** | The final path is replaced by another listening socket; `close()` leaves it, and it still accepts |
| **T4S** | A stale socket file is replaced by a listening inode (the bound inode, not the stale one); after the first connect no `ECONNREFUSED`, `EAGAIN` or other; over the whole run no `EAGAIN`, other or unanswered, totals reconciled; no `*.tmp`; the path is gone after `close()` |
| **S1** | The H1A3-1 `HostCycle` on this kernel (see below): three ticks 1 s apart against active replies with 60 s of authority each return `serving`/`activated` with `authorized true`; each key delivers (≥ 95 %) over `[t_after_tick, t_before_tick + T − 2·tick)`; `E_upper − D < 0` from the conservative estimates; after the last key's `t_after_tick + T + tick` (+ one tick) no probe is admitted while the activated map still lists exactly mark 3; sequence 3, the first generation of the process (budget delta 1). Records the runner's nine real K9 tokens `k9_<key>`, `k9_satisfied` and `k9_path` |
| **S2** | The decider answers 1500 ms late (500 ms past the 1000 ms request budget): the client gives up with `cp_timeout`, `last_decision no_reply`, `consecutive_unavailable 1`, the generation stays `serving`, `authorized false`; exactly one process (the prepare) is spawned, no activate, the activated map stays empty and nothing is admitted over the key's whole life `[t_before_tick, t_after_tick + T + tick]`. `late_reply` (a complete reply after the deadline) is proven by `tests/test_host_cycle.py`, not here |
| **S3** | A reply with 2 s of authority is refused `authority_too_short` (`consecutive_unusable 1`, no activation, lower `E_upper` − upper `D` ≥ 500 ms); the next tick with 10 s activates and delivers (upper `E_upper` − lower `D` ≤ −500 ms); both request gaps < 100 ms; nothing is admitted after that key's bound |
| **S4** | After one activation that delivers, `inactive key_revoked` closes the generation: phase `closed`, class end `A`, context ended with `key_revoked`, `authorized false`, the activated map read back through the gate's own descriptor is empty and nothing is admitted after the closing tick; a further tick makes no request (the listener saw exactly two). No restart |
| **S5** | `inactive replayed_sequence` closes the generation after one activation (map flushed); after the real 10 s spacing the same cycle starts a new generation (new `generation_id`, compared in the test, never recorded), whose first request has sequence 1 and activates and delivers on the new namespace. The one positive restart control: budget delta 2 |
| **S6** | After one activation the decider returns the previous reply verbatim: the real listener's own validation refuses it (`decide_failed 1`, status 500, no body), the client reports `cp_unavailable` (`consecutive_unavailable 1`, sequence 2, no new activation, the first key keeps delivering); the next fresh reply activates (sequence 3, mark 3). The client-side `malformed_reply` checks for a wrong digest or sequence are unit-proven in `tests/test_host_cycle.py` |
| **C2** | No gate, child, socket, domain, mount, link or other process survives, and the process-wide cleanup registry of `authority.py` is empty; records the cycles and scripted deciders created |

The T4-family connector paces itself by acceptance, not by time. A connect counts as a success only
once the peer has closed it (EOF) within one absolute 2 s drain deadline, read in bounded chunks that
are never kept; otherwise it is unanswered. EOF is the acceptance signal only because of this
topology: the real listener refuses the same-PID-namespace connector before reading a byte, and the
plain acceptors close on accept. So at most one of its connections ever waits in the listener's
queue, and it cannot overflow the 64-entry backlog it is measuring. Failed connects are not paced:
the pre-publication and wrong-order windows are sampled as densely as before. Each attempt has one
outcome: `enoent`, `econnrefused`, `eacces`, `eagain` (a `BlockingIOError` with `EAGAIN`, a full
Linux accept queue), `other`, `success` or `unanswered`. `attempts` is their sum and the `after_*`
outcomes are exactly the attempts after `first_success`, the first connect that did not fail. The
T4, T4N and T4S records carry every one of these counts, `totals_reconciled`, the inode, `*.tmp`
and path values their oracle reads, and the tokens `other_first_errno` and `unanswered_first`. Each
token is `none` or a fixed value: a lower-case standard errno name, `timeout`, `deadline`,
`deadline_after_data` or `unknown`. A token never holds exception text or received bytes. The
workload is unchanged (2000 attempts, 20 successes, 20 s, no sleep, no retry, no allowance), and
so is the production backlog.

Labelled seams, each confined by a static test to its case:

- `SEAM-COUNTER-START d3 only`: the `_counter` start value, never ownership or reservation;
- `SEAM-NAMED-NAMESPACE d2 negative only`: a stale writer that resolves a namespace by name;
- `SEAM-WRONG-ORDER t4n negative only`: the test's own wrong-order publisher;
- `SEAM-LISTEN-FAILURE t4f only`: an injected `listen` that raises;
- `SEAM-SCRIPTED-DECIDER s-cases only`: the listener's `decide` callable returns scripted
  codec-valid replies, one per request; S6's deliberately stale reply is rejected by the real
  listener's own validation;
- `SEAM-CYCLE-SLEEP-REPORT s-cases only`: the fixed all-disabled A-1/A-2 report, substituted only
  when the recorded real report fails K9; it proves nothing about this host's power policy;
- `SEAM-CYCLE-DOMAIN-REGISTER s-cases only`: the real `LeaseDomain.create`, wrapped only to register
  the domain for C2.

No production code sets any of them.

The S cases drive the real `deploy/host/cycle.py` `HostCycle` (admission `NON_CUSTOMER`) through
`start()`, `install_context()`, `tick()` and `stop()`: its own registry sweep, generation budget,
signal context, real `LeaseDomain`, real generation self-test and grading, K9 check, clock witness,
nft children, `connect_cp` and exchange, against the real listener as uid 10001, pid 1 of a child
PID namespace with production permissions (as T1). The proof module registers its own
`authority.py`, `profile.py` and listener modules under the names `cycle.py` loads, so the cycle and
C2 read one cleanup registry (a static test checks the identity). Before the first start the
fixture installs the signal context once, reads `sleep_capability_report()` once and records it,
and requires the registry to be `clear` (at most 5 × 200 ms of drain); a refusal records the case as
failed with a fixed token. The gate table is installed when `start()` returns `ready`, before the
context. Timing uses one clock (`time.monotonic_ns`) and brackets each tick: a live window ends at
`t_before_tick + T − 2·tick` (no later than the real `E_lower`), an admission bound is
`t_after_tick + T + tick` (no earlier than the real `E_upper`), and `D` is estimated from either
bracket edge, whichever is conservative for the sign asserted. The exact boundaries remain the
injected-clock unit tests. The budget is the production one and is never reset: the six cases use
seven real generations of the process's eight, each start at least 10 s after the previous one.

Result rule (as H1F): PASS only if every case ran, every record holds, host fingerprints are
unchanged and `kernel_profile pinned` (supported tag, nft 1.0.9, known HZ, self-test pass and the
re-add observation matching `READD_EXPECTED`); a clean run outside the pin is INCOMPLETE; anything
else is FAIL. The artifact `host-authority-proof` has five bounded files and 3-day retention.

## Limits

- The job runs under the running-kernel assumption and prints `runtime_assumption running-kernel`.
  That is a declared limitation, not a claim about the CI host: the captured clocks and behaviour
  are the only evidence. The job proves uniqueness U and the transport unit. It proves nothing
  about elapsed authority lifetime L under the gap modes M3 (guest suspend/hibernate), M4
  (hypervisor pause), M5 (memory restore) or M6 (cloned timelines), and nothing about provider
  pause/restore behaviour. An admission file, disabled sleep settings or a release label cannot
  establish those; H6/H-B must qualify the exact host profile and keep customer enablement off
  without that evidence.
- Not accepted by H1A-1: the admission contract A-1..A-6, W-1/W-2 enforcement, R-1 closing in a
  cycle, the CP sequence check C-1, the CP snapshot decision (H1A-2), the supervisor cycle (H1A-3),
  H2, H3, the five-second product bound, hosted enablement, launch.
- The re-add observation is graded by the launcher against the production profile pin (equal to
  H1F's source-tag pin); the production self-test records it without grading.
- The S cases use a scripted decider. The real control-plane decision path is proven by
  `tests/test_host_cycle.py` on ordinary Linux CI, not here. They record the runner's real nine K9
  tokens and prove nothing about its power policy; the K9 refusal itself is `STATE-MACHINE ONLY` in
  `tests/test_host_cycle.py`, and H6/H-B qualify hosts. Because the generation budget is
  process-wide, one run holds seven real generations with real 10 s spacing. H1A3-A (real control
  plane, kernel, executor and customer flow, with no seam) is the combined gate; nothing here
  substitutes for it.
- The T4 family's pacing holds only for its topology (a refused peer, or an acceptor that closes on
  accept). It is not a client for an admitted peer that waits for a request body. macOS cannot run
  the family: Darwin reports a full accept queue as `ECONNREFUSED`, which looks the same as the
  refused window. `tests/test_host_authority.py` runs the connector program on any OS only against
  the test's own slow acceptor, and claims no publication result. Run `39636350344` on `2542b1a`
  stays FAIL: its unpaced connector overflowed the backlog itself and recorded only `other`, with no
  errno.
