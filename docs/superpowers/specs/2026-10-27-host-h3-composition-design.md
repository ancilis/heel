# Host H3 controller/worker composition — reality audit and bounded design

Date: 2026-10-27. Author: Claude Fable 5.1, fresh interactive design session (H3-COMPOSITION-DESIGN),
design and security review only. Worktree `.worktrees/heel-h3-design`, branch `codex/host-h3-design`,
base `43a3b7616aa3a6e8686cb266686c30fa05e6a634` (base tree `100e81ba56ff6b42019f669c94ce25ccc889f010`;
CONFIRMED `git rev-parse HEAD^ HEAD^^{tree}` from the candidate). **No product, test, workflow,
deployment, provider, namespace or customer state was changed.** This file is the only tracked write
of the session. Evidence folder: `.worktrees/heel-task-evidence/H3-COMPOSITION-DESIGN/`.

> **Revision 1 (2026-10-27, after independent review round 1, `H3-COMPOSITION-SPEC-REVIEW/REPORT.md`,
> and Astra's `ASTRA-REVISION-1-GRANT.md`).** The original candidate `c502e1ca` is preserved and is not
> accepted. This revision resolves blockers B-1…B-6 and the safety-relevant advisories A-1…A-12 as
> follows: **B-1** revocation is defined against the real H0 grammar (§4.6 "revoke": `stopping` plus
> emptied `projects`/`contexts`/`runs` and a new `config_generation`; `resync`, `context_list` and
> retained pairing routes stay admitted and why that is acceptable; a failed registry write sends no
> `revoked` ack); **B-2** the endings are split into **F** (the worker's own `sendmsg` failed) and
> **R′** (receipt read or queued, then revoked), `cleanup()` runs only on F, the named test 2 is
> rewritten to the F scenario and a new R′ test asserts no `delete table` (§4.7, §6.1); **B-3** the
> pinned resolver is withdrawn: the executor keeps the unchanged client's per-attempt A+AAAA
> re-validation through a **supervisor-side constrained resolution channel** that resolves only the
> generation's pinned origin with the unchanged `BoundedResolver` and returns the raw answer, so
> `dns_changed`/`unsafe_dns` stay reachable exactly as P4 proved them (§2.3, §4.3-4.5, §6.3 L1);
> **B-4** H3-1's integration gate waits for H2-3's accepted interface, the binding-generation test and
> the `control_only` pin field are an H3-1b hunk gated on H2-3, the worker omits the keyword unless
> true, and the fourth H2-3 code site (`_readback` empty-set precondition) is listed (§8.1-8.2);
> **B-5** the registry `runner` record comes only from the root-owned slot configuration written by
> C4's pairing ceremony, never from the executor link, and the supervisor refuses attach without it
> (§4.5, §4.6, §9.1); **B-6** `pin` is sent by the controller thread on `arm` (where the generation id
> and fence first exist) before `armed`, and the supervisor lock is never held across `start()`,
> `tick()`, `stop()` or a controller reply (§4.2, §4.4, §4.6). Advisories: A-1/A-2 exact H2-3 readback
> invariants and gateway packet cases (§8.1); A-3 the worker runs in its own process group, the group is
> killed, and `reaped` is defined truthfully (§4.6); A-4 the flush runs even when the executor is
> unresolved (§4.7); A-5 the veth is created after `ready` (§4.6); A-6/A-7/A-12 names, counts and
> paths corrected; A-8 the managed identity backend is a named C4 input and H3-1's real-daemon case
> passes `secret_backend` (§4.5, §9.1); A-9 the control-name mapping caps H3 at one slot per host
> (§2.4); A-10 the pre-corroboration DNS side channel and churn bound are stated (§2.3); A-11 §9.2
> names tests. New §2.4 states the threaded-supervisor qualification for H1's fork-to-exec against the
> actual callers. The CodeQL alerts 98/99 found on `scripts/host_h2_policy_proof.py` are an
> independent prerequisite for any H2-3/H3 implementation grant (§11); they do not change this design.

Tags: **CONFIRMED** (command, artifact or `file:line` at this tree) or **INFERRED** (with the exact
confirming action). Every `file:line` below is in tree `100e81ba…` unless a path starts with
`.git/self-serve-launch/` or `.worktrees/heel-task-evidence/` (evidence, read-only).

Normative words: **MUST**, **MUST NOT**, **MAY**.

## 0. Disposition

**READY for Astra and a fresh independent spec review (round 2); NOT an implementation grant.**

1. **The accepted H2 generation table cannot host a managed executor as it stands.** The accepted host
   design routes the executor's control-plane traffic through its own gateway on TCP 443 inside the
   executor namespace (`.git/self-serve-launch/sessions/H1AD-review/C8DRA-design.md:38,59,85`), and
   the H1 lease exists only while one claimed run is active (`heel/saas/host_snapshot.py` selection,
   `docs/saas/HOST_AUTHORITY_SNAPSHOT.md` "single active run"). The accepted H2 table has exactly one
   `accept`, to the IPv4 target set, under a live lease (`deploy/host/h2_policy.py:179-202`;
   `docs/saas/H2_POLICY_INSTALLATION.md:58` "No … second accept"; `nft` evaluates every base chain, so
   a `policy drop` output chain drops what it does not accept). An executor inside such a namespace has
   no control access before a run is claimed, so nothing can ever claim one. Round 1 independently
   confirmed this (REPORT §2). §2.1 states it with witnesses; §3.2 compares the three ways out and
   recommends a bounded H2 amendment (**H2-3**: one fixed control accept, a control-only shape, exact
   readback invariants, gateway packet cases; same installer; re-proved by the existing H2-2 job). The
   fixed gateway exception is a candidate for this demonstrated gap only, not a general egress
   exception and not an implementation grant.
2. **One generation = one authorization context = one executor instance.** The cycle closes the
   generation at every context end and never reopens a namespace (`deploy/host/cycle.py:1206-1224`,
   `docs/saas/HOST_AUTHORITY_CYCLE.md` "Every context end closes the generation"), so the executor
   process is created per generation and ended with it. A supervisor process may start at most eight
   generations, ten seconds apart (`cycle.py:70-71`), then exits for the H6 restart policy.
3. **The slot's root `enabled` marker is the ingress registry entry, with the admission it really
   has.** The H0 grammar has no non-admitting phase that keeps a pairing record (`policy.js:886-905`,
   `POP_PHASES` 1096): `stopping` refuses `claim` only (1144) and every identity-bearing route is
   refused through the per-slot `runs`/`contexts` lookups (1103-1113). "Absent" therefore means
   `stopping` **and** `projects: []`, `contexts: []`, `runs: []` under a new `config_generation`; what
   stays admitted for the paired identity (`resync`, `context_list`, retained pairing receipt routes)
   reaches a control plane that authenticates proof-of-possession and holds no active run (§4.6). The
   registry's production supplier was already assigned to H3 (`docs/saas/HOST_INGRESS_PROOF.md:243`,
   `.git/self-serve-launch/sessions/H1AD-review/H1D-design.md:53`); the `runner` record it needs
   before the executor's first request has a trusted supplier outside H3: C4's pairing ceremony writes
   the root-owned slot configuration (§4.5, §9.1).
4. **No `cleanup()` after a successful generation, and `cleanup()` only on a proven failed send.**
   Deleting `inet heel_lease` removes the only `policy drop` chain and makes the namespace
   default-allow (§4.7). The table dies with the namespace. The worker calls `cleanup()` exactly once,
   only when its own `sendmsg` of the receipt returned an error (ending **F**); a receipt the cycle read
   or queued and then revoked (ending **R′**) never cleans: the worker is killed under the burned nonce
   and the table dies with the namespace. The worker never infers F from a missing `release`.
5. **Per-attempt DNS re-validation is preserved, not replaced.** The executor's unchanged client keeps
   calling its resolver before every attempt and keeps refusing `dns_changed`/`unsafe_dns`; the
   resolver is a bounded channel to the supervisor, which resolves only the generation's pinned
   origin with the unchanged `BoundedResolver` from the host namespace and returns the raw answer
   (§4.5). A constant resolver is not used and is not claimed equivalent to P4.
6. The five mandatory H2 design §4.8 obligations are carried verbatim into §4.9 with their named tests
   (§6.1), each exercised against the real `HostCycle` wire, the real worker process and the real
   `h2_policy` state machine; the Linux proof (§6.3) runs them with the real kernel.
7. Bounded, dependency-ordered backlog (§8): **H2-3** (Opus → fresh Fable → Astra dispatch of the
   existing `host-h2-policy-proof` job → runtime review), **H3-1** (supervisor, worker, executor entry,
   link codecs, offline suite; coding may overlap H2-3, its integration gate waits for H2-3's accepted
   interface), **H3-2** (isolated Linux lifecycle proof, seventh workflow job), **H3-3** (managed
   executor end to end; depends on C4 and H6). None is customer admission, deployment or launch, and
   no implementation is granted until the CodeQL 98/99 prerequisite is dispositioned (§11).

## 1. Reality audit at `43a3b76`

### 1.1 Method

Graph: project `Volumes-MiniAlbus-hellohelloalbus-home-heel` is indexed (`index_status` → 10 662 nodes,
33 882 edges, `ready`; CONFIRMED). It indexes the primary checkout (`6a2923b`, branch
`feat/plan-differential-runner`), which has **no** `deploy/host/`, `tests/linux/` or host docs
(CONFIRMED: reads of those paths from the primary root fail with "No such file"), so every host-side
fact below was read from the fixed `43a3b76` source with `sed`/`grep` (the permitted fallback); the
graph was not refreshed. No test, probe or product code was executed.

Accepted evidence re-verified in the task folder: H2-2 runtime cycle 2 (run 40564023989, 18/18, zero
skips, `ASTRA-ACCEPTANCE.md`: "Astra accepts this H2 generation-policy primitive for the H3 integration
design … H3 must carry all … 4.8 obligations and prove lifecycle ordering against real
HostCycle/LeaseDomain"), H2-2-RUNTIME-F1 source review, H2-POLICY-FABLE-REFRESH `DECISION.md`
revision 5 (SHA-256 `b54893ba…`, per `ASTRA-DESIGN-DISPOSITION.md`). CI 40559139756 / CodeQL
40559139843 green at the reviewed tree (`ASTRA-START-CHECKPOINT.md`). The human approval of 2026-10-26
(`.worktrees/heel-task-evidence/CUSTOMER-PARALLEL-2026-10-24/HUMAN-APPROVAL-2026-10-26.json`, verbatim "I approve everything what
else is needed to keep going") approves the hosted vault / bounded transit / ≤7-day private evidence /
bounded authorized `login_exchange` POST bundle and the 29 USD/month DigitalOcean baseline; it still
requires actual DO account access, C3 resolution through the supported path, H2/H3/H6 + safety tests +
independent acceptance before customer execution. No DO host exists; no provider action was taken.

### 1.2 The managed customer goal (preserved, not narrowed)

`docs/superpowers/specs/2026-10-19-customer-ready-self-serve-launch.md` §0 row 4, §2.4, §5.2: a new
customer signs up over public HTTPS, enters the SaaS URL, credentials and explicit authorization; Heel's
**managed executor** (the existing runner code run by Heel in an isolated per-workspace executor that
pairs through the existing runner protocol) performs discovery and the read-only GET/HEAD scan plus
exactly one authorized `login_exchange` POST per identity per discovery authorization or scan run;
the customer reviews the dry run, receives undeclared observed/verified findings, sees redacted evidence
and live failures, saves and replays regressions, and revokes. No mandatory source checkout, OpenAPI
document, manual runner or admin artifact copy; the customer-local connector stays optional
(`docs/saas/LOCAL_RUNNER_EXECUTION_BRIDGE.md:1-5`). Status-only and error-envelope responses stay
inconclusive. H3 is the host-side composition that lets that managed executor exist inside the H1/H2
isolation; it adds no customer-facing surface and changes none of the twelve safety properties (§9.2
names which component owns each).

### 1.3 Current-state / reuse-gap matrix (file:line witnesses)

| # | Capability H3 needs | Exists at `43a3b76` (CONFIRMED) | Reuse | Gap H3 owns |
|---|---|---|---|---|
| 1 | Generation namespace by descriptor, prepare/activate/close/flush, process-global child registry | `deploy/host/authority.py:534-695` (`LeaseDomain`, `ns_fd` 589-595 "dup it; never a path", `close_generation` 673-695 flushes `activated` and closes the owner fd, leaves the table); `unresolved_children`/`sweep_unresolved_children` 392-409; `_spawn` forks only to exec 262-296 | as-is | none |
| 2 | Authorization cycle with the H2-A pre-ready bootstrap | `deploy/host/cycle.py`: `CycleContext` 111-151 (13 strings + `kill_switch_generation` + `egress_port == 443`), `BootstrapChannel` (two distinct connected `AF_UNIX` `SOCK_DGRAM` sockets, adopted), `GenerationBootstrap` 450-471, `_Handoff.run/commit/cancel/abandon` 604-673, `register_bootstrap`, `start()` runs the hand-off outside the lock, `_finish_bootstrap` 1006-1023, `_close_generation` / `_quarantine` 1206-1245, `status()` tokens only; `BOOTSTRAP_DEADLINE_MS` 5000 (404), `REVOKE_DEADLINE_MS` 1000, `INTERVAL_MS` 1000 (64), `MAX_GENERATIONS_PER_PROCESS` 8 / `MIN_GENERATION_SPACING_MS` 10 000 (70-71) | as-is; H3 is the caller `HOST_AUTHORITY_CYCLE.md` B2 names | H3 process that owns it (§4.1) |
| 3 | Control-plane authority channel | `authority.verify_cp_socket`/`connect_cp` 974-1044 (initial user and PID namespaces, 0600 socket in a 0700 directory owned by `cp_uid`, `SO_PEERCRED` uid = `cp_uid`, pid ≠ 0); CP side `heel/saas/host_authority.py` (`ROUTE` 39, `_STRINGS` 58-75, `_ACTIVE_STRINGS` 79-87), `heel/saas/host_snapshot.py:173-339` (decision from real CP state; `egress_hostname` from the authoritative join, 328-339); managed-host env rules `heel/saas/server.py:292-309` (`HEEL_MANAGED_HOST=1` ⇒ socket mandatory, peer uid 0, `external-pidns`) | as-is | none; H3's supervisor runs as uid 0 outside the CP container's PID namespace |
| 4 | Generation policy install/readback/receipt/cleanup | `deploy/host/h2_policy.py`: public surface exactly six names (58), `H2PolicyInput` 121-165, `install` 514-560 (single use, receipt only on `receipt_ready`), `cleanup` 591-615 (only after `receipt_ready`, no-op otherwise), `unresolved_helpers` 618-622, execed helper constant 81-99, `_PLATFORM_OK` 76 | as-is **plus H2-3** (§3.2) | the caller (worker), the trusted constructor (§4.3) |
| 5 | Unchanged client, canonical public tuple, per-attempt re-resolution | `heel/runner/http_transport.py`: `select_public_addresses` 165-172, `_is_public` 157-162, `BoundedResolver` 178-210 (real `getaddrinfo`), `TargetHTTPSClient.__init__` 640-676 (`resolver`/`sockets`/`tls` seams), `_gate_and_resolve` 699-720 (`dns_changed` on any set change) | as-is; the resolver seam with a mutable answer is the proven P4 configuration (`tests/linux/test_host_h2_policy.py:1754-1835`) | supervisor-side preflight (§4.3) and the constrained resolver channel the executor's resolver seam talks to (§4.5) |
| 6 | Executor process and runner protocol | `heel/runner/daemon.py`: `RunnerDaemon.__init__` 567-588 (`root`, `ca_bundle`, `target_network` constructor seam 578, "never passed by the CLI"), `_transport` 603-604, `serve` 836-865, `_ServeSession.run` 1431-1448, `_ServeExecution` 386-462 (`_target` 420-437 resolves the manifest origin once and pins the client; `execute` 439-454 wires `RunnerExecutionAdapter(transport_precheck=…, transport_factory=…)`), construction at 1472-1474, `once` 1482-1483; `heel/runner/coordinator.py:902-1000` (`_validated_lease` 941-959 re-validates the exact claimed bundle and active binding before the factory) | as-is | a **managed entry** that passes the resolver channel, the supervisor link and the identity backend through the existing constructor and adapter seams (§4.5, §7) |
| 7 | Validated signed bundle, grant, context binding | `heel/runner/execution.py:96-100` (`ValidatedExecutionBundle`), `validate_execution_bundle` 235-311 (signature, immutable local pair, binding equality 265-282, grant lifetime 311); `heel/canary_contracts.py:593-600` (grant keys incl. `run_id`, `workspace_id`, `project_id`, `environment`, `runner_binding{runner_id,runner_key_id,public_key_digest}`, `kill_switch_generation`, `grant_id`, `grant_digest`, `expires_at_ms ≤ issued + 600 000`); `heel/runner/store.py:379-394` (`RunnerContext` with `origin`, `verification_record_digest`) | as-is | the field map from these to `CycleContext` (§4.3) |
| 8 | Root-owned slot admission (the `enabled` marker) and per-slot runner listener | `deploy/host/ingress/policy.js`: registry schema 907-945 (`schema_version`, `host_boot_epoch`, `config_generation`, `public_origin`, `backend`, `management`, `expires_at_ms`, `slots`), slot record 830-905 (`slot_id`, `listener`, `peer`, `namespace_id` label ≤ 32 chars (59), `workspace_id`, `phase` ∈ 35, `runner`, `projects`, `contexts`, `runs` with `admitted ≤ 1`), loader 958-984 (fixed path, owner, unexpired, generation never older than one already admitted), listener identity from the local socket 985-993, phase gates 1099-1164; `deploy/host/ingress/nginx.conf:114-118` slot map; fixture writer pattern `tests/support/host_ingress_harness.py:310-367` (temp file, fsync, chmod, `os.replace`) | as-is | H3 is the production registry writer (§4.6) |
| 9 | Slot veth by descriptor | none in product; the fixture pattern (`tests/linux/test_host_h2_policy.py:1267-1300`: raw `RTM_NEWLINK` with `IFLA_NET_NS_FD`, addresses/routes/neighbours by `ip` entered through `setns` on a descriptor) and the H2-A addendum §4 (`.git/self-serve-launch/sessions/H2A-contract-terra/H2A-design-addendum.md`) | pattern | the production link writer (§4.6) |
| 10 | Worker and root controller processes | none ("exist in no production code today", `docs/saas/H2A_BOOTSTRAP_CONTRACT.md` boundary statements); contract fakes `tests/test_host_cycle.py:1644-1720`; a real unprivileged `python -I` child receives the descriptor by `SCM_RIGHTS` 2301-2341 | test patterns | **H3's core** (§4) |
| 11 | Offline cycle harness | `tests/test_host_cycle.py:239-280` (`Harness`: real `HostCycle`, recorded installer, regular-file namespace stand-in, offset clock, scripted exchange); `_holders` 1579-1588 counts descriptor holders by identity | as-is for H3-1 | — |
| 12 | Isolated Linux proof pattern | `scripts/host_h2_policy_proof.py` (fixed profile 51, literal ref 52, `STAGE_FILES` 66-72, `HEEL_TREE_FILES` 74-119, eight-wheel closure, `sudo -n` child 500, `REQUIRED_CASES` 121), `tests/linux/test_host_h2_policy.py` (`Fixture` 1237-1330, `_fixture` 1462-1480, `TLSPeer` 1157, `Resolver` 1754), six-job `codeql.yml` (216 lines; jobs at 12/30/66/104/142/180) pinned by four oracles (`tests/linux/test_host_h2_policy.py:129,222,639`; `tests/linux/test_host_lease_key_shape.py:100,193,665`; `tests/linux/test_host_authority_proof.py:110,205,449`; `tests/test_host_h2_policy_proof.py:239`) | pattern | the seventh job and its oracle hunks (§8.3) |
| 13 | Host egress policy, provisioning, restart policy, executor uid/prefix/volume | none (H6; `docs/saas/HOST_AUTHORITY_CYCLE.md` B3; H2 design §7 "H6 … host-level egress policy at the host") | — | not H3 (§9.1) |
| 14 | Service-driven pairing of the managed executor, credential intake, `envelope` vault | none (customer spec §5.2 C4, §5.3 C5); `LinuxSecretServiceBackend` is a `secret-tool` adapter with no filesystem fallback (`heel/runner/identity.py:336-355`) | — | not H3; H3-3 depends on C4 (§9.1) |

### 1.4 Lineage inconsistencies found (stated, not silently resolved)

| # | Statement A | Statement B | Resolution in this design |
|---|---|---|---|
| L1 | C8DRA: executor → own gateway :443 (runner-only ingress listener) "under a live control lease"; idle executors "have control access only" (`C8DRA-design.md:38,59,85`) | Accepted H2 table: one accept, targets only, lease-gated (`h2_policy.py:179-202`); the lease exists only for an active claimed run (`host_snapshot.py` selection) | A lease-gated control path and idle control access cannot both hold. Control access is gated by the **registry** (root), target egress by the **lease** (kernel): H2-3 adds one unconditional control accept to the slot gateway on TCP 443 (§3.2) |
| L2 | H2-A addendum §4: "a dedicated H3 root-controller process" creates the veth by `IFLA_NET_NS_FD` | H2-A contract: the namespace descriptor "goes to the worker only. Handing it to the root controller … is H3 work" | The worker forwards exactly one duplicate to the controller role after `receipt_ready` (§4.4); the controller never reaches into the cycle's private domain |
| L3 | H2 design §4.8 item 3: "call `cleanup()` after a successful generation only in the order H3's lifecycle contract fixes" | `close_generation` leaves the table (`authority.py:673-695`); deleting it is default-allow | The contracted order is "never after an executor was attached"; the success path has no `cleanup()` (§4.7) |
| L4 | `H2A_BOOTSTRAP_CONTRACT.md:3-5` says "HOLD … awaiting independent re-review" | H2-A re-review and Linux gate passed (H2 design §2) | Historical wording; H3 consumes the accepted wire unchanged |

## 2. Facts that bind every approach

### 2.1 Control-plane reachability of the executor (the blocker, with witnesses)

- The executor must run inside a generation namespace: H1AD interface rule I4 "H3 attaches an executor
  only to a namespace of the current generation" (`.git/self-serve-launch/sessions/H1AD-review/
  H1AD-design.md:170`), C8DRA executor-namespace topology (`C8DRA-design.md:34-38`), and the ingress
  proof's G9 "no sibling/CP/management reach from a slot" (`docs/saas/HOST_INGRESS_PROOF.md:235`).
- From inside that namespace the only IP traffic the accepted table admits is TCP 443 to the pinned
  IPv4 targets while a prepared element is live (`h2_policy.py:179-202`; proved by H2-2 P2/P4: every
  other kind, including the loopback-free UDP 53 and port 8443 probes, is denied). Loopback is not
  exempt: the output hook sees loopback packets and the chain has no `oif lo` rule.
- The executor's control transport dials the control origin by TCP (`heel/runner/control_transport.py:
  236-248`, `getaddrinfo` + `connect`) to the per-slot listener bound on the slot gateway
  (`nginx.conf:114-118`; `policy.js:985-993` requires `remoteAddress == slot.peer`), and the runner
  service claims a run only through that transport (`heel/runner/service.py:228-240`).
- Therefore, with the accepted table, an executor can neither claim nor heartbeat. No seam, mode,
  descriptor-passing trick or registry setting changes this: a connected TCP socket created in the host
  namespace has a host source address and fails the ingress peer rule, and an `AF_UNIX` control
  listener has no `remoteAddress` for that rule (both would reopen H0). §3.2 chooses.

### 2.2 Generation, context and executor cardinality

- `install_context` is accepted only in `ready`; every context end (orderly, unproven, quarantine)
  closes the generation; a new context needs `start()` and a new domain (`cycle.py` `_close_generation`,
  `HOST_AUTHORITY_CYCLE.md`). A process starts at most 8 generations, ≥ 10 s apart. Hence: executor
  instance per generation; one admitted run per slot at a time (registry `admitted ≤ 1`,
  `policy.js:884`); supervisor process lifetime ≤ 8 generations, then `exit_required`-style exit and the
  H6 restart policy (the authority ledger enrols one row per generation, capacity 65 536,
  `HOST_AUTHORITY_SNAPSHOT.md` "Ledger").
- The H2 input needs `egress_hostname` and the observed tuple **before** `ready`, but the run (and its
  `CycleContext`) is claimed by the executor **after** `ready`. The target of a generation is therefore
  the slot's **bound environment origin**, which is stable across runs of one context binding
  (`RunnerContext.origin`, `store.py:379-394`; `validate_execution_bundle` requires the grant's
  environment to equal the bound context, `execution.py:265-282`). The first generation of a slot whose
  origin is not yet known is a **binding generation** with a control-only table (H2-3), in which the
  executor binds its context and reports the origin but is not allowed to claim (§4.5). A run whose
  origin differs from the generation's pinned origin is never authorized; the generation ends and the
  next one is pinned to the reported origin.

### 2.3 Trust boundaries that already exist and are kept

- The CP authenticates the context: an `active` reply must equal all 13 context strings,
  `kill_switch_generation` and `egress_port` (`cycle.py` `_cycle`, `context_mismatch`), and the CP
  compares the issued tuple field by field (`tuple_mismatch`, `HOST_AUTHORITY_SNAPSHOT.md` step 6;
  `host_snapshot.py:326-340`). Anything the executor reports about its claim is therefore a **hint**
  the CP corroborates before any key is activated; a wrong hint ends the context, never widens
  authority. **Side effect of a hint, stated (A-10):** before corroboration the supervisor resolves a
  reported origin from the host namespace and renders the next generation's table to it. That is a
  bounded DNS side channel (one `BoundedResolver` query per reported origin, only names that pass the
  active-grammar hostname check) and a churn lever (alternating origins end generations), bounded by
  the 8-generation / 10-second budget. Once C4 supplies the CP-bound environment origin in the
  root-owned slot configuration, the supervisor accepts a reported origin only if it equals it.
- The kernel pins the install-time IPv4 set; the unchanged client re-resolves the origin before every
  attempt and refuses any membership change (`http_transport.py:699-720`). Both stay in force: the
  executor's resolver is a channel to the supervisor (§4.5), which answers only for the generation's
  pinned origin, so a DNS membership change during a run is `dns_changed` at the client (the accepted
  P4 behaviour, run 40564023989 `resolver_calls 11`), and a reassigned address can never be reached
  because the kernel set is fixed. Staleness between install and claim is bounded by a re-resolution
  at `claim_request` that must canonicalise equal to the install-time tuple (§4.5 item 4).
- The receipt is bound by the connected socketpair and the per-generation fence
  (`H2A_BOOTSTRAP_CONTRACT.md` boundary statements), not by a signature; H3 keeps the worker end of the
  cycle's socketpair in the worker process only (§4.4).

### 2.4 Threaded supervisor, H1's fork-to-exec, and the one-slot-per-host consequence

- H1 forks only to exec: `authority._spawn` (`authority.py:262-296`) forks, and the child runs
  `_exec_child` (`setns`, `dup2`, `execve`) or `_exit(127)`; `_Namespace` forks a helper that
  `unshare`s and blocks (476-532). `HostCycle` never forks (`HOST_AUTHORITY_CYCLE.md` "`cycle.py`
  never forks; H3 may fork only to `exec`"). The H2 design withdrew raw-fork preconditions for H2-1
  because H2-1 uses `Popen` (DECISION §4.3); it did not and could not withdraw H1's own fork.
- The supervisor is a threaded process (controller thread, §4.2) that calls `domain.prepare/activate/
  close/close_generation` from the main thread, so H1's fork runs with another Python thread alive.
  Qualification, not a new claim: the accepted H1A3-2 Linux proof already ran the real `HostCycle`
  against the real `LeaseDomain` with live threads in the same process (listener and pump threads,
  `tests/linux/test_host_authority_proof.py:836,998,1062,1204,1815,1840`; `HostCycle(` at 2240; run
  39885541424, 32 tests), and H2-2 ran `install` and `prepare/activate` with fixture threads (run
  40564023989). The child between `fork` and `execve` executes only `os.setns`, `os.dup2`,
  `os.execve`, `os._exit` under CPython's post-fork child state; it takes no lock the controller
  thread can hold (the controller thread never calls into `authority`/`cycle`). `authority._FORKED`
  stays `False` in the supervisor because every H3 child is a `Popen` without `preexec_fn` (no
  `register_at_fork` hook fires; H2 design §4.3 probe), and the static test in §6.1 pins "no
  `os.fork`, no `preexec_fn`" in the three H3 modules. H3-2 L1 re-exercises the real cycle ticks with
  the controller thread alive. No H1 change is proposed.
- The executor's control transport resolves the control name with the system resolver
  (`control_transport.py:240`); inside the namespace no DNS packet can leave, so the name must be
  answered by `/etc/hosts` in the executor's view. The host's global `/etc/hosts` holds one mapping
  per name, so **this design supports one slot per host**. A per-slot mapping (bind-mounted hosts file
  per executor mount namespace, or C8DRA's per-gateway `:53` responder, `C8DRA-design.md:55,75`) is a
  later H6/H3 change, not assumed here. That the slot listener presents a certificate valid for the
  control name to a `check_hostname` client is an H0 deployment fact (INFERRED I-10).

## 3. Approaches

### 3.1 Process topology (three viable shapes)

| | A — one root supervisor hosting the controller role (recommended) | B — separate root-controller process | C — worker does everything |
|---|---|---|---|
| Processes per slot | supervisor (root, long-lived, ≤ 8 generations) + per generation: worker (root, short-lived) + executor (unprivileged) | supervisor + controller (root, long-lived) + worker + executor | supervisor + worker (root; also creates the link and spawns the executor) + executor |
| H2-A peers | worker end of the worker socketpair → worker process; controller end stays in the supervisor, served by a dedicated controller thread | controller end sent to the controller process by `SCM_RIGHTS` | controller role in the supervisor; worker also owns link/executor |
| Namespace descriptor holders | cycle's domain fd (private); worker's received dup; one dup the worker forwards to the supervisor after `receipt_ready` | + controller's dup | worker only |
| Why / why not | Fewest processes and descriptors; the cycle already runs the hand-off and the revoke outside its lock, so an in-process controller thread can answer; the supervisor is already uid 0 (CP peer rule), so no privilege is added. The controller thread never calls a cycle method; the cycle owner stays the main thread. | Matches the addendum's wording; costs a second long-lived root process, a second descriptor path and a second IPC to supervise, with no isolation gain (both are root in the init namespaces). | Violates the worker's reason to exist (end at revoke under the burned nonce; §4.8 item 4) and puts link and executor lifetime inside a process the controller must be able to kill at any moment. |
| Verdict | **selected** | acceptable fallback if a reviewer requires process separation of the controller role; the contract in §4 is unchanged except that the controller end travels by `SCM_RIGHTS` | rejected |

### 3.2 The executor's control path (the H2 amendment)

| | B1 — H2-3: one unconditional control accept in the generation table (recommended) | B2 — `AF_UNIX` control transport + ingress unix listener | B3 — supervisor-side TCP connector proxy |
|---|---|---|---|
| Change | `render_table` gains one rule before the target accept: `ip saddr <slot_hop_src> ip daddr <slot_hop_dst> tcp dport 443 accept`; the target accept may be omitted when the input carries **no** target (binding generation; `build_input` accepts an empty tuple for that one shape); readback oracle and H2-2 cases extended (§8.1) | `control_transport.py` connect seam, `daemon.py` plumbing, nginx `listen unix:` per slot, `policy.js` listener/peer identity for unix peers, H0 runtime lock, H0 oracles and Linux proof | supervisor opens TCP to the slot listener on the executor's behalf and hands fds over `AF_UNIX`; needs a per-slot source address on the host side, an ingress peer change, and a root process that forwards executor-chosen connections |
| Kernel claim | unchanged primitive, one extra accept whose destination is the slot gateway only; the host-side INPUT restriction to that gateway and port is H6's `inet heel_exec` chain (`C8DRA-design.md:55-59`); the generation chain keeps `policy drop` for everything else | H2 unchanged | H2 unchanged |
| SSRF boundary | the gateway listener forwards only `/v1…` runner routes to the fixed backend with registry-bound identity (H0 proven, `HOST_INGRESS_PROOF.md:16-20`); nothing executor-chosen leaves the namespace except to pinned targets | same | the root process becomes a connection forwarder: exactly what the assignment forbids |
| Re-proof cost | existing `host-h2-policy-proof` job on a new candidate, one cycle | H0 job (nginx/njs build) + H0 oracle rewrite + new peer model | new ingress identity model |
| Verdict | **selected**: smallest change, consistent with the accepted host design's control/target split, re-proved by an existing job | rejected (reopens H0 and the registry identity model) | rejected (root forwarder) |

B1 does not weaken the H2 argument: the control accept has no mark condition, no set, no lease and one
fixed destination tuple; the target accept, the typed gateway key, the single table and the exact
readback are untouched. It is an amendment the accepted design itself anticipated as "host-level
egress policy" for the control origin (customer spec §2.4 "allowing 443 to the verified origin's
pinned addresses plus the control plane origin only").

## 4. The contract

### 4.1 Processes, identities and fixed launch

| Process | Module (proposed, `deploy/host/`) | uid / namespaces | Lifetime | Launch |
|---|---|---|---|---|
| **supervisor** (`heel-host-supervisor`) | `supervisor.py` | uid 0, initial user/PID/net namespaces (CP peer rule `authority.py:991-1013`); owns one `HostCycle` per slot (one slot per process in H3; multi-slot is a later H6 decision) | until `exit_required`, 8 generations, or a stop signal | systemd unit (H6): `NoNewPrivileges=yes`, `KillMode=control-group`, restart delay ≥ 10 s (INFERRED I-1) |
| **worker** (per generation) | `worker.py` | uid 0 (nft/`setns` need `CAP_NET_ADMIN`/`CAP_SYS_ADMIN` in the init user namespace) | from `arm` to `release` or revoke | `Popen([sys.executable, "-I", "-S", "-B", str(_HERE / "worker.py"), <worker_fd>, <link_fd>], close_fds=True, pass_fds=(worker_fd, link_fd), cwd="/", env={PATH, LC_ALL=C}, stdin/stdout/stderr=DEVNULL)` (the file path, not `-m`: `deploy/host` is not a package on `sys.path`); no `preexec_fn`, never `os.fork` |
| **executor** (per generation) | `executor.py` (managed entry) run inside the generation namespace | dedicated unprivileged uid/gid per slot (H6 provisions; INFERRED I-2), no supplementary groups, `no_new_privs` inherited, `HEEL_HOME` = root-provisioned per-slot volume owned by that uid | from `ready` to context end | execed helper (§4.5): `[sys.executable, "-I", "-S", "-B", "-c", _EXECUTOR_HELPER, <ns_fd>, <link_fd>, <uid>, <gid>, <prefix_python>, <entry_path>, <home>, <slot_id>]`, `close_fds=True`, `pass_fds=(ns_fd, link_fd)`, `cwd="/"`, `env={PATH, LC_ALL=C}`, stdio `DEVNULL` |

Rules (all processes): no Python `preexec_fn`; no `os.fork` anywhere in `supervisor.py`/`worker.py`/
`executor.py` (static test); every child is a `subprocess.Popen` with `close_fds=True` and an explicit
`pass_fds`; every argv is fixed and built from validated tokens; the environment is exactly `PATH` and
`LC_ALL`; nothing received on any socket is logged, kept beyond its use or raised; logs carry fixed
tokens, integers and booleans. The executor prefix (`<prefix_python>`, `<entry_path>`) is a root-owned,
read-only install of the open-core wheel plus the `runner` extra whose manifest hash the supervisor
compares to a root-owned pin before every launch (`refused_prefix` otherwise; H6 provisions the prefix
and the pin).

### 4.2 Supervisor roles and threads

| Thread | Does | Never does |
|---|---|---|
| main | `install_signal_context()` once; per generation: build channel and link sockets, spawn the worker (own process group), `register_bootstrap`, `start()` (the hand-off runs outside the cycle lock), executor attach after `ready`, `tick()` at 1 Hz, `stop()`/`stop_context()` at context ends, executor detach, worker release, `status()` → tokens | blocks on a child; reads a cycle private; forks; holds the supervisor lock while inside `start()`, `tick()`, `stop()`, `stop_context()` or any blocking wait |
| controller | serves the controller end of the H2-A channel (`arm` → `pin` to the worker → `armed`; `revoke` → §4.6 → `revoked`), the worker link (`fd_forward`, `state`, `release`), the executor link (`bound`/`claim_request`/`claimed`/`resolve`/`released`), the registry writer, the link writer, the constrained resolver, and child reaping on request from main | calls any `HostCycle` method; sends a receipt; runs nft; waits on the main thread |

**Lock discipline (B-6).** The per-generation record is protected by one supervisor lock used only
for short, non-blocking critical sections (read or write a field, swap a descriptor). The main thread
takes it before and after a cycle call, never across one; the controller thread takes it to read the
current operation and to record `armed`/`revoked`, never while sending, receiving, resolving or
writing the registry. Every controller reply is therefore bounded by its own socket deadline, not by
the main thread's progress, and the cycle's `BOOTSTRAP_POLL_MS` slices (`cycle.py:_send/_receive`)
see an answer within one slice or cancel by their own deadline.

### 4.3 Trusted constructor (validated inputs → `CycleContext`, `H2PolicyInput`, resolver channel)

No field is invented; every field traces to an existing validator, and the CP's active reply must
equal the context before any key is activated (`cycle.py` `_cycle`).

| Target field | Source (validated by) | Where it is validated again |
|---|---|---|
| `CycleContext.workspace_id`, `project_id`, `run_id`, `grant_id`, `grant_digest`, `kill_switch_generation`, `public_key_digest`, `runner_id`, `runner_key_id` | executor link `claimed` message, copied from `ValidatedExecutionBundle.grant` (`validate_execution_grant`, `canary_contracts.py:593-600`; `runner_binding` equality `execution.py:282`) | `CycleContext.__post_init__` (request codec + active grammar, `cycle.py:139-151`); CP `tuple_mismatch`/`context_mismatch`; `runner_id`/`runner_key_id`/`public_key_digest` must also equal the root-owned slot configuration's runner record (§4.5 item 5) or the claim is refused (`runner_mismatch`) |
| `environment_id`, `verification_record_digest`, `binding_id`, `binding_digest` | `claimed` message, from the executor's bound `RunnerContext` and active claim binding (`coordinator.py:952-958`, `execution.py:265-282`) | same |
| `egress_hostname` | the generation's pinned origin (§2.2) — must equal `normalize_target_origin(manifest.environment.origin)` of the claim or the claim is refused (`origin_mismatch`) | `_ACTIVE_STRINGS["egress_hostname"]`; CP reply equality |
| `egress_port` | constant 443 | `cycle.py:150` |
| `H2PolicyInput.generation_id`, `namespace_identity`, `slot_id`, `slot_hop_src`, `slot_hop_dst`, `bootstrap_fence` | the H2-A request datagram received by the worker (`GenerationBootstrap.request()`, `cycle.py:461-466`), after `fstat` of the received descriptor equals `(namespace_dev, namespace_ino)` | `build_input` (`h2_policy.py:133-165`); `install` identity checks |
| `H2PolicyInput.egress_hostname`, `egress_port` | supervisor → worker link `pin` message sent by the controller thread on `arm` (B-6): the pinned origin's hostname and 443; or `control_only: true` for a binding generation (H2-3) | `build_input`; the worker refuses a request whose `generation_id`/`bootstrap_fence` differ from the `pin` |
| `H2PolicyInput.observed_public_addresses` | supervisor preflight in the host namespace: `select_public_addresses(BoundedResolver()(hostname, deadline=now+5 s))`, unmodified (`http_transport.py:165-210`); serialized in `pin` as exact strings, parsed back with `ipaddress.ip_address` before `build_input` | `build_input` shape check; the kernel set is the IPv4 members |
| Executor resolver answers | the supervisor's constrained resolution channel (§4.5 item 3): per executor request, `BoundedResolver()(pinned_hostname, deadline)` in the host namespace, raw answer strings returned | the unchanged client runs `select_public_addresses` on every answer and compares it to its own preflight set (`http_transport.py:672,699-720`) |

The supervisor refuses to start a generation when the preflight fails (`unsafe_dns`, timeout, > 16
answers): no table, no worker, no executor (`start_refused:preflight`). Private, loopback and
documentation addresses never reach the input because the unchanged validator refuses them first.

### 4.4 Wire protocols (closed, canonical JSON, ≤ 1024 bytes, fixed tokens)

- **H2-A channel**: unchanged (`heel.h2a.controller.v1`, `heel.h2a.bootstrap.v1`, `heel.h2a.receipt.v1`).
- **Worker link** `heel.h3.worker-link.v1` (`AF_UNIX` `SOCK_DGRAM` socketpair; supervisor end in the
  controller thread, worker end passed at spawn): supervisor → worker `pin {generation_id,
  bootstrap_fence, egress_hostname, observed_public_addresses[]}` plus `control_only: true` only in a
  binding generation (the key is omitted otherwise, B-4) — **sent by the controller thread when the
  `arm` datagram arrives and before it answers `armed`** (the `arm` carries `generation_id` and
  `bootstrap_fence`, `cycle.py:530-533,614-617`; nothing earlier knows them, B-6); the worker reads `pin`
  before the request (the cycle sends the request only after `armed`, `cycle.py:604-633`) and refuses
  a request whose ids differ; `release {generation_id}`; worker → supervisor `fd_forward
  {generation_id, bootstrap_fence}` + exactly one `SCM_RIGHTS` duplicate (only after `receipt_ready`,
  before the receipt is sent), `state {generation_id, state, send, unresolved}` (`state` the fixed
  H2-1 token, `send ∈ {sent, failed, not_attempted}`, `unresolved = unresolved_helpers()["unreaped"]`;
  sent once after the receipt step and once at exit).
- **Executor link** `heel.h3.executor-link.v1` (`AF_UNIX` `SOCK_SEQPACKET` socketpair, executor end
  passed at launch): executor → supervisor `bound {binding_id, binding_digest, project_id,
  environment_id, verification_record_digest, origin}`, `claim_request {origin}`, `claimed {13
  context strings, kill_switch_generation, projection_id, approval_projection_digest,
  manifest_digest}`, `resolve {hostname, deadline_ms}`, `released {run_id, disposition}`;
  supervisor → executor `claim_reply {allow|defer}`, `authorized {run_id}` (after the cycle's first
  `activated` event for that context), `refused {run_id, reason}`, `resolved {answers[]}` or
  `resolve_refused {reason ∈ unsafe_dns|timeout|not_pinned|budget}`, `stop`. The executor side
  blocks on `authorized` inside the adapter's `transport_precheck` (bounded by the grant's remaining
  life) before any socket to a target.

Every datagram is matched exactly (schema, keys, types, grammar from `heel/saas/host_authority.py`
`_STRINGS`/`_ACTIVE_STRINGS`; `answers[]` ≤ 16 strings each ≤ 45 ASCII characters parseable by
`ipaddress.ip_address`); a mismatch is a fixed refusal token and, for the links, ends the generation
(`link_invalid`). Received descriptors on any message other than `fd_forward` are closed unread and
refuse the message, as the cycle does (`cycle.py:_close_received`).

### 4.5 Executor attachment (after `ready`) and the managed entry

1. The supervisor has the forwarded namespace duplicate (`fd_forward`), the link socketpair, the
   per-slot volume, uid/gid, prefix pin, the root-owned slot configuration and the preflight tuple.
   It writes the executor's **launch input** (`heel.h3.executor-input.v1`: `slot_id`,
   `generation_id`, `egress_hostname` or `control_only`, `control_origin` (`https://H`), link fd
   number, `phase ∈ {bind, run}`) to a root-owned, 0640 file in the per-slot volume readable by the
   executor uid; no secret and no address list is in it (addresses come only through the resolver
   channel, so the client's preflight is a real resolution).
2. The execed helper (`_EXECUTOR_HELPER`, `os`/`sys` only, pinned hash, exit codes 124 argv / 125
   `setns` / 126 privilege drop / 127 exec): `setns(ns_fd, CLONE_NEWNET)` → `close(ns_fd)` →
   `setgroups([])` → `setresgid(gid)` → `setresuid(uid)` → verify `getresuid()/getresgid()` → `execve(
   prefix_python, ["python", "-I", "-S", "-B", entry_path, home, input_path, link_fd], {PATH, LC_ALL})`.
   The namespace descriptor is closed before the privilege drop and never reaches the executor; the
   link fd is the only inherited descriptor besides stdio (`/dev/null`).
3. **Constrained resolution channel (B-3).** `deploy/host/executor.py` builds
   `LinkResolver(link, pinned_hostname)` and passes it as `target_network={"resolver": …}`
   (`daemon.py:100,578`). The unchanged client calls it before every attempt and once for the preflight
   (`daemon.py:429`, `http_transport.py:706`). `LinkResolver.__call__(hostname, *, deadline)`: if
   `hostname != pinned_hostname` → `TransportFailure("unsafe_dns")` without any message; otherwise one
   `resolve {hostname, deadline_ms}` datagram, one reply before the caller's deadline; `resolved` →
   return `answers` as a list of strings (the client then runs `select_public_addresses` and its
   equality check itself, `http_transport.py:699-720`); `resolve_refused unsafe_dns|not_pinned` →
   `TransportFailure("unsafe_dns")`; `timeout`/no reply → `TransportFailure("timeout")`. The supervisor
   side answers only when `hostname == pinned_hostname` of the live generation, runs the unchanged
   `BoundedResolver()(hostname, deadline=min(requested, now + 5 s))` in the host namespace (which
   itself refuses non-public answers, `http_transport.py:209`), returns the raw strings, and bounds
   the channel: one outstanding request per executor, at most 64 requests per generation (the client
   needs ≤ 1 + `maximum_requests` 20 + retries), `budget` refusal beyond. Properties kept: real
   per-attempt resolution, full A+AAAA set, `dns_changed` on membership change, `unsafe_dns` on an
   unsafe member, `resolver_calls == attempts + 1`; properties added: the supervisor resolves no name
   other than the authorized origin, so the channel is not a DNS oracle for the executor. The kernel
   set stays the install-time IPv4 members: a membership change makes the attempt `dns_changed`
   (refused before any socket), never a reach to a new address. This is the P4 configuration with the
   mutable answer supplied by a real resolver instead of a scripted one; it is not a constant.
4. `daemon.py` changes are exactly: a `managed_link` constructor seam (like `target_network`, never
   passed by the CLI); in `_ServeSession.run`, after the context is ensured and before
   `service.run_once()`, `link.claim_request(origin)` → `defer` returns the loop to its offline path
   (no claim); on `allow` the supervisor has re-resolved the pinned origin and found the canonical set
   equal to the install-time tuple (otherwise it answers `defer`, ends the generation `pin_stale` and
   the next generation pins the current set — the staleness bound); `_ServeExecution.execute`
   composes `transport_precheck = chain(link.await_authorized, _require_os_credentials)` and emits
   `claimed` before waiting; on terminal result or stop it emits `released`. No other runner module
   changes. `_require_os_credentials` passes with zero credential bindings (CONFIRMED by round 1,
   `daemon.py:360-383`), so H3 adds no credential path. The `run`-phase daemon is built with
   `secret_backend=<managed backend>` (the `RunnerDaemon` constructor seam, `daemon.py:569`): on a
   headless host the default is the `secret-tool` adapter with no fallback (`identity.py:336-355`),
   so the managed identity backend is an explicit **C4 input** of H3-3 (§9.1); H3-1's real-daemon case
   passes a test backend through the same seam and says so.
5. **Registry record sources (B-5).** The slot's `runner` record (`runner_id`, `runner_key_id`,
   `public_key_digest`; `policy.js:793-798`) is load-bearing for the ingress (every proof route needs
   it, 1098-1101; the CP's grant `runner_binding` is compared to it, 1582-1584) and must exist before
   the executor's first request. Its only trusted source is the **root-owned slot configuration**
   `/etc/heel/slots/<slot>.json` written by C4's service-driven pairing ceremony (the service actor
   that generated and verified the fingerprint, customer spec §5.2) and validated by the supervisor
   against the H0 grammar; the supervisor refuses attach without it (`runner_record_missing`) and
   refuses a `claimed` whose runner fields differ from it (`runner_mismatch`). It is never taken from
   the executor link. `projects`/`contexts` (from `bound`) and `runs` (from `claimed`) are hints the
   ingress narrows on and the CP fail-closes at `policy.js:1587` (project/environment/verification
   digest must match the grant). At attach the supervisor writes `phase: active`, `namespace_id:
   generation_id`, `runner` from the slot configuration, `projects`/`contexts` from `bound`,
   `runs: []`; on `claimed` it adds the run record `admitted`; on `released` it marks it `retained`;
   on detach and on revoke it writes the non-admitting shape of §4.6. Between generations the slot
   stays in that shape (`stopping`, empty lists; `namespace_id` keeps the last generation id — the
   grammar does not bind it to a live namespace, `policy.js:838`; INFERRED I-3 is resolved as this
   reading and is pinned by the registry test's `validate_registry` call).

### 4.6 Root controller duties (controller thread)

| Duty | Mechanism | Fail-closed outcome |
|---|---|---|
| `arm` | record `(generation_id, namespace_identity, bootstrap_fence, operation_nonce, deadline_monotonic_ns)` as the current operation for the slot; send `pin` to the worker (B-6); then answer `armed`. The worker was spawned before `register_bootstrap`, so the arm names a worker that exists | a second `arm` while one is current, a mismatched identity, or a failed `pin` send is not answered (the cycle cancels by deadline and revokes) |
| worker spawn | `Popen(..., start_new_session=True)` so the worker and every H2-1 helper it starts share one process group (H2-1 helpers keep `start_new_session=False`, `h2_policy.py:383-385`, so they inherit it) | — |
| slot veth | **after `ready`** (A-5), at attach, from the forwarded dup: `RTM_NEWLINK` veth from a `NETLINK_ROUTE` socket opened in the host namespace with peer `IFLA_NET_NS_FD = <dup>`; host side `slot_hop_dst/32`, `slot_hop_src/32` plus routes/neighbours inside the generation through `ip` entered by `setns` on the dup (the H2-2 fixture pattern by descriptor, `tests/linux/test_host_h2_policy.py:1267-1300`); the dup is closed after the netlink ack, the `ip` steps and the executor helper's `Popen` | any step failing → `link_failed`: `stop()` before any executor exists; no table is deleted |
| registry | render `heel.ingress-registry.v1` from the root-owned slot configuration + the per-slot dynamic record; write temp file + fsync + chmod 0644 + `os.replace`, `config_generation` strictly increasing, `expires_at_ms` bounded (`tests/support/host_ingress_harness.py:339-367` pattern; production code in `supervisor.py`; validated with the harness's `validate_registry`, 241) | a write failure refuses attach (`registry_failed`) |
| `revoke` (B-1) | (1) registry: the slot record becomes **`phase: stopping`, `projects: []`, `contexts: []`, `runs: []`** under a new `config_generation` (`runner`/`pairing` kept, as the grammar requires for a paired slot, `policy.js:897-903`); (2) close the forwarded dup if held; (3) `killpg(SIGKILL)` on the worker's group, `waitpid(worker)` within `CHILD_REAP_GRACE_MS`, then (Linux) scan `/proc/*/stat` for the group id within the same grace; (4) answer `revoked {enabled: absent, worker: reaped|unresolved}` under the armed nonce only; (5) burn the nonce. `reaped` means: worker status collected **and** no process of its group remains; otherwise `unresolved` (A-3) | **a failed registry write sends no ack**: the cycle's `REVOKE_DEADLINE_MS` passes, it quarantines `bootstrap_unresolved`, the process exits; an unreaped worker or a surviving helper is `unresolved`, never `reaped` |
| what "absent" admits afterwards (B-1, truthful) | with empty `runs`/`contexts`, every `run_operation`, `result_projection`, `context_claim` and `context_submit` is refused `identity` (1103-1113) and `claim` is refused `phase` (1144); still admitted for the paired identity: `context_list` (proof route without id lookup), `resync` (1085, `PROOF4`) and the retained pairing receipt routes (1154-1159). They reach the CP, which authenticates proof-of-possession, holds no active run for this slot after the cycle's end, and answers from its own state. This is the strongest meaning the H0 grammar offers; a non-admitting paired phase would be an H0 grammar change (own task, not proposed) | — |
| executor stop | `stop` on the link, SIGTERM, 2000 ms, SIGKILL, `waitpid` within `CHILD_REAP_GRACE_MS` | unreaped executor → `executor_unresolved`: the flush of S still runs (A-4), no further generation in this process, `exit_required` |
| worker release | `release` on the link after the executor is reaped and `close_generation` returned; the worker closes its dup and exits 0; `waitpid`; group scan as above | unreaped worker or surviving helper → `worker_unresolved`, same policy |

### 4.7 Teardown: why no path creates default-allow while anything can still use the namespace

Facts: the generation table's chain is the only `policy drop` on the namespace's output hook
(`h2_policy.py:179-202`); `close_generation` flushes `activated` and closes the owner descriptor but
leaves the table (`authority.py:673-695`); `cleanup()` deletes the table and acts only after a
`receipt_ready` install of the same input (`h2_policy.py:591-615`); a namespace lives while any
descriptor, attached process or socket references it (`H2A_BOOTSTRAP_CONTRACT.md` "not a claim that the
namespace is destroyed"); the veth ends die with it (INFERRED I-4, proved by H3-2 L7). Residual
admission after a failed flush is bounded by the prepared element's own `timeout` (the admit rule
references `@prepared`, which carries `flags timeout`, `h2_policy.py:187-195`), as rule R of the
cycle doc states.

**Wire fact that fixes the endings (B-2).** `_Handoff.run` sends the request and then reads **one**
datagram (`cycle.py:604-633`); the worker's `sendmsg` of the receipt succeeds whenever the cycle's
worker socket is still open, including when the cycle later times out, reads it late, or revokes
because a stop was recorded before the lock-held decision (`tests/test_host_cycle.py:2234` is such a
*successful* send). The send fails only when the cycle closed the worker socket **before** the
worker sent, i.e. `cancel()` ran (`cycle.py:641-647`) while the worker was still inside `install()`
(deadline passed, or stop/arm failure before the request was answered). The worker therefore learns F
from exactly one thing: the `OSError` returned by its own `sendmsg` (INFERRED I-9: `ECONNREFUSED`
on Linux for a connected `AF_UNIX` datagram socket whose peer closed; any `OSError` is treated as F).
It never infers F from a missing `release`, a closed link, or a signal.

**Invariant T.** `delete table inet heel_lease` runs in a generation namespace only from
`worker.cleanup()` on ending **F**, at a moment when (a) the cycle never reached `ready` for that
generation, so no executor was attached and the registry never admitted the slot for it; (b) the
cycle's duplicate is burned (`_Handoff.cancel` → `_drop_fd`) or already closed after its one
`sendmsg`; (c) the only holders are the worker's own descriptor and, possibly, the cycle's domain
owner descriptor whose flush has already run or refuses harmlessly (`_refuse_start` tolerates
`InstallerFailed`, `cycle.py:1032-1041`). After the success path, and on **R′**, the table is
**never** deleted: it is destroyed with the namespace when the last holder goes.

Contracted order per ending (H3 tests in §6.1 pin every step; "reaped" means `waitpid` collected
the status and, for the worker, its process group is empty):

| Ending | Order | Why no default-allow and no stale authority |
|---|---|---|
| **S — success, orderly end** (`stop_context`/`stop` after `released`, or any class-A/B reason) | 1 `stop` on the link, SIGTERM → SIGKILL, executor **reaped** (or `executor_unresolved` after the grace, A-4: continue); 2 registry non-admitting shape (new generation); 3 cycle ends the context: `close(current)` then `close_generation` (flush, owner fd closed) — **always**, also after `executor_unresolved`; 4 `release` to the worker → worker closes its dup, exits, **reaped**; 5 the supervisor holds no namespace fd after the attach step | the table is intact while the executor exists (1 before 3); the flush (3) removes every live key before any holder is released (4), so a socket that outlived the executor (TIME_WAIT) can only retransmit into a dropped chain; no `cleanup()`; the namespace and its veth die at 4 |
| **F — failed send** (the worker's own `sendmsg` of the receipt raised; reachable only when the cycle closed the worker socket before the send: deadline during a slow `install()`, or an earlier cancel) | worker: 1 no retry, no second `install()`; 2 `cleanup(fd, input)` once (best effort); 3 `state {send: failed}` on the link; 4 close its dup; 5 exit 0. Cycle: `cancel()` already ran → `revoke` → controller §4.6 (the worker may already have exited; `reaped` then needs only `waitpid`) | no executor exists (`ready` never happened); T(a)-(c) hold; the H2 single-use rule refuses a second install (`refused_reused_input`) |
| **R′ — receipt read or queued, then revoked** (stop before the lock-held decision; a late receipt after the deadline; a malformed-after-valid sequence) | cycle: `_finish_bootstrap` → `revoke` → `cancel()` closes the worker socket with the datagram read or unread, sends `revoke`; controller §4.6: registry non-admitting, forwarded dup closed, `killpg(SIGKILL)`, `reaped|unresolved`; `_refuse_start` → `close_generation` | **no `cleanup()`**: the worker's send succeeded, so it waits for `release`/`fd_forward` acknowledgement and is killed under the burned nonce; the table dies with the namespace; the forwarded dup (if sent) is closed at revoke step (2); no executor was ever attached; `_INPUTS` records `receipt_ready` and nothing ever acts on it |
| **C — cancel before any send** (arm unacked, `pin` send failed, request send failed, stop before the request) | cycle: burn dup, close worker socket, `revoke`; controller §4.6; worker: its `recvmsg` returns EOF (no request) → it exits 0 without installing, `state {send: not_attempted}` | nothing was installed; no `cleanup()` (nothing to clean; `cleanup()` would be a no-op by H2-1's rule) |
| **X — executor crash** (exit without `released`) | link EOF → supervisor `stop_context` (`context_replaced`) → S from step 2 | the executor is reaped (crash = exit) before the flush; the run's CP state ends through the existing reaper (`HOST_AUTHORITY_CYCLE.md` "A stopped executor's heartbeats stop") |
| **W — worker crash after receipt** | `state`/EOF on the worker link; if the forwarded dup never arrived → `link_failed` → S without an executor; if it did → S | the table stays; nothing deletes it; helpers in the dead worker's group are killed by the group kill at release |
| **Q — cycle quarantine** (`child_uncertain`, `bootstrap_unresolved`, `flush_failed`, `operation_interrupted`, …) | executor stop as S step 1 (best effort, bounded), registry non-admitting, worker group kill, `exit_required` → the supervisor exits (H6 restarts it ≥ 10 s later) | the namespace is abandoned, never deleted-from; residual admission is bounded by `R_bound` and the prepared timeout; the executor is dead |
| **P — supervisor crash/restart** | all children die with the control group (H6 `KillMode=control-group`, INFERRED I-1); the new supervisor starts a new generation; the old namespace dies with its last holder | the registry's `host_boot_epoch`/`config_generation` rules make the new supervisor's first write supersede the old record; no path revives an old namespace (I2 no naming) |

### 4.8 Lifecycle and ownership table (per resource, per phase)

| Resource | created by | start | install / receipt | prepare / activate / request | close (context end) | reap | cleanup |
|---|---|---|---|---|---|---|---|
| domain owner fd | cycle (`LeaseDomain.create`) | private to the cycle | — | used by H1 children via `setns` | closed by `close_generation` | — | — |
| cycle's duplicate | cycle (`_open_bootstrap`) | owned by `_Handoff` | closed after its one `sendmsg`, or burned at cancel | — | — | — | — |
| worker's received dup | kernel → worker (`SCM_RIGHTS`) | — | `fstat` = identity; `install` dups per helper; `fd_forward` sends one dup | — | — | — | closed at worker exit (after `cleanup()` on F only) |
| forwarded dup | worker → supervisor | — | received in the controller thread | at attach: veth/`ip` steps, executor helper `pass_fds`; closed right after the helper's `Popen` returns; closed at revoke step (2) | — | — | — |
| H2 table | worker (`install`) | — | exact readback → receipt | H1 writes elements | flush by `close_generation` (also after `executor_unresolved`) | — | deleted only on F; otherwise dies with the namespace |
| H2-A channel sockets | supervisor (`socketpair` ×2) | adopted by `BootstrapChannel`; worker end passed to the worker; controller end served by the controller thread | — | — | closed by `commit`/`cancel` | — | — |
| worker link | supervisor | passed at worker spawn | `pin`, `fd_forward`, `state` | — | `release` | worker reaped | both ends closed |
| executor link | supervisor | passed at executor launch | — | `bound`/`claim_request`/`claimed`/`authorized` | `released`/`stop` | executor reaped | both ends closed |
| worker process | supervisor (`Popen`, own process group) | before `register_bootstrap`; receives `pin` on `arm` | runs `install`, sends receipt once | idle, holds its dup | — | `killpg(SIGKILL)` at revoke; `waitpid` + group scan after `release` | `unresolved` if the worker is not reaped or any group member survives the grace |
| executor process | supervisor via execed helper | after `ready` | — | claims, waits for `authorized`, executes | `stop`/SIGTERM/SIGKILL | `waitpid` within grace | `executor_unresolved` → `exit_required` |
| registry slot record | supervisor | `pending` → `active` at attach | — | run record `admitted` at `claimed` | `stopping` before the flush | — | `retained`/empty between generations |
| slot veth | supervisor (netlink by fd) | — | — | created at attach, after `ready`; carries control and pinned target traffic | — | — | dies with the namespace (I-4) |
| CP authority socket | cycle (`connect_cp` per request) | — | — | one connection per tick | — | — | — |

### 4.9 Mandatory obligations (H2 design §4.8, carried verbatim) and where each lives

1. Send exactly `Outcome.receipt` once, on the worker socket, only when `state == "receipt_ready"`;
   never construct receipt bytes any other way. → `worker.py`: the only send of receipt bytes is
   `sock.sendmsg([outcome.receipt])` guarded by `outcome.state == "receipt_ready"`; no other code path
   references `RECEIPT_SCHEMA` or `_receipt_document` (static test).
2. A send that fails (peer closed because the cycle cancelled) is final: no retry, no re-send, no
   second `install()`; call `cleanup()` once (best effort) and exit. → `worker.py` ending F (§4.7),
   entered only on the worker's own `sendmsg` `OSError`; a receipt the cycle read or queued and then
   revoked is ending R′ and runs no `cleanup()` (B-2).
3. Call `cleanup()` after a successful generation only in the order H3's lifecycle contract fixes
   against `LeaseDomain.close_generation` (H1 flush + owner-fd close; the table survives until the
   namespace dies). → the contracted order is S (§4.7): no `cleanup()` after success, ever; the flush
   precedes every holder release; the executor is reaped before the flush.
4. Run the worker as a dedicated process, hand it the borrowed fd, and supervise it under the cycle's
   deadline/revoke; the installer itself inherits no descriptor into its helpers (`close_fds=True`).
   → §4.1, §4.6; the worker's helpers keep H2-1's `close_fds=True`/`pass_fds`.
5. Treat `unresolved_helpers()` non-zero as a reason to report `unresolved` to the controller, never
   "reaped". → the worker's `state` message carries `unresolved = unresolved_helpers()["unreaped"]`;
   a non-zero value makes the controller answer `worker: unresolved` on revoke and makes the supervisor
   treat the generation as `worker_unresolved` (no new generation, `exit_required`).

## 5. Threat model and failure matrix

| # | Threat / fault | Boundary that holds | Owner |
|---|---|---|---|
| T1 | Compromised executor tries to reach the CP backend, management, sibling slots, private ranges or any non-pinned address | generation chain `policy drop` + control accept to the slot gateway only + target accept to pinned IPv4 under a live key (H2, H2-3); host `inet heel_exec` INPUT/FORWARD restriction (H6); ingress forwards only `/v1…` with registry-bound identity (H0) | H2-3 / H6 / H0 |
| T2 | Executor asserts a false claim (`claimed` with ids it does not hold) | CP `tuple_mismatch`/`context_mismatch` ends the context before any key; registry run record is a narrowing filter, PoP is the authority | H1A-2 / H3 refuses on mismatch |
| T3 | Executor asserts a false origin (`bound`/`claim_request`) | the generation is pinned to the reported origin only after the supervisor's own preflight; a claim whose grant environment differs from the pin is `origin_mismatch`; the CP's `egress_hostname` must equal the context | H3 |
| T4 | Late worker/helper writes after cancellation | H2-1 single-use input, no negative receipt; H2-A burned nonce and closed worker socket; worker killed under the nonce; the controller never re-enables | H2-A / H2-1 / H3 |
| T5 | Deleting the table with a live executor | invariant T; no `cleanup()` after success; executor reaped before flush | H3 (tests §6.1 3, L5) |
| T6 | Descriptor leak into the executor or nft | `close_fds=True` everywhere; the executor helper closes `ns_fd` before the privilege drop; `/dev/fd` assertions in tests | H3 |
| T7 | Secret or raw body in supervisor logs/status/registry | links carry ids/digests only (grammar-checked); executor stdio is `/dev/null`; registry fields are the closed H0 schema; no credential path exists in H3 (anonymous-only) | H3 (static tests), C5 for the vault |
| T8 | Privilege escalation from the executor | unprivileged uid, no supplementary groups, `no_new_privs` inherited from the unit, no capability, read-only prefix, `-I -S -B` | H3 helper + H6 unit |
| T9 | Supervisor becomes an SSRF proxy | the supervisor opens no socket on the executor's behalf and forwards nothing; its only outbound connections are the CP Unix socket (`connect_cp`) and the preflight DNS query | H3 (static: no TCP connect in `supervisor.py`) |
| T10 | Revocation latency | registry non-admitting shape (empty `runs`/`contexts`, `stopping`) refuses every run/context route at the next request and `claim` by phase; `resync`/`context_list`/retained pairing routes reach a CP with no active run; executor SIGTERM→SIGKILL ≤ 2 s + grace; `close_generation` flush cuts targets; the cycle's own ends (`stop_requested`, `kill_switch_active`, …) drive S within one tick | H3 (test §6.1 4, L6 ≤ 5 s) |
| T11 | Malformed/hostile link or channel input | exact matching, fixed refusal tokens, generation ends; nothing raised or logged | H3 |
| T12 | Supervisor budget exhaustion / restart loop | `generation_budget` quarantine; ≥ 10 s spacing; H6 restart delay; ledger capacity 65 536 | cycle / H6 |
| T13 | DNS change or rebinding during a run | the unchanged client re-resolves before every attempt through the constrained channel and refuses `dns_changed`/`unsafe_dns` (P4 behaviour kept); the kernel set is fixed at install, so a new address is unreachable even if a stale answer named it; a target whose old address stopped serving is `connect_error`/`timeout` → `target_unavailable`; an address reassigned to a stranger cannot present a certificate for the origin name (TLS `check_hostname`/`CERT_REQUIRED`, `http_transport.py:237-245`) | H2 / H3 (L1 adversarial case) |
| T14 | Namespace revival by name or PID | fd-only everywhere (I2); no `/run/netns`, no `ip netns`, no `nsenter`, no `/proc/<pid>` lookup | H1 / H3 |
| T15 | The executor uses the resolver channel as a DNS oracle or a side channel | the supervisor resolves only `pinned_hostname`; any other name is refused locally without a message; ≤ 64 resolutions per generation; one outstanding | H3 |

## 6. Tests, proofs and clean-room acceptance

### 6.1 Offline suite `tests/test_host_h3.py` (H3-1; macOS and Linux CI, unprivileged)

Harness: the real `HostCycle` through the existing `tests/test_host_cycle.py` seams (`CycleSeams`:
recorded installer domain over a regular-file namespace stand-in, offset clock, scripted exchange —
the pattern of `Harness` at `tests/test_host_cycle.py:239-280`, imported, not copied), the **real**
`deploy/host/supervisor.py` driving it, the **real** `worker.py` as a `python -I -S -B` subprocess in
its own process group, the real H2-A wire and real `SCM_RIGHTS`, and the real `h2_policy` state
machine run unprivileged through H2-1's own labelled seams (fake owned `nft`, the test helper that
skips only `setns`, `_PLATFORM_OK = True`) applied by a test-owned launcher; the H2-1 tracked-file
guard gains `tests/test_host_h3.py` as the second admitted assigner (one hunk, §8.2). The executor is
the real `deploy/host/executor.py` entry run with a **test-owned** `RunnerDaemon` stand-in only
where the runner protocol would need a control plane (labelled `CONTRACT FAKE`), plus one case with
the real `RunnerDaemon` against the scripted transport the runner tests already use
(`tests/test_runner_daemon.py` pattern) with `secret_backend` passed through the constructor seam, to
prove the managed seam composition. No namespace, no privilege, no network.

Mandatory (H2 design §4.8, names fixed):
1. `test_worker_sends_receipt_once_only_from_receipt_ready` — scripted fake-nft outcomes
   `receipt_ready`, `readback_mismatch`→`cleaned`, `timeout`→`quarantined`, `identity_mismatch`: exactly
   one datagram is ever sent and only in the first case; its bytes equal `GenerationBootstrap.receipt()`
   canonical; the cycle reaches `ready` only in that case; AST: one `sendmsg` site, guarded by the state.
2. `test_worker_failed_send_is_final_cleanup_once_no_reinstall` — the **F** scenario (B-2): the fake
   `nft` sleeps through the install step while the test advances the cycle's offset clock past
   `BOOTSTRAP_DEADLINE_MS`, so `_receive` times out and `cancel()` closes the worker socket **before**
   the worker's `sendmsg`; the worker's send raises (I-9), the fake-nft call log shows exactly one
   `delete table` and no second check/install, `state {send: failed}` is sent, the worker exits 0,
   the controller's `revoked` carries `reaped`, `_INPUTS` records `cleaned`, no `ready` event.
3. `test_worker_cleanup_order_against_close_generation_is_the_contracted_one` — recorded order of
   events on the success path is exactly S of §4.7: executor reaped < registry non-admitting <
   `close_generation` < `release` < worker reaped; the fake-nft log contains **no** `delete table`; the
   same with an unresolved executor stand-in (SIGSTOP) still shows the flush (A-4); on ending F the log
   contains exactly one `delete table`, before the worker exits and never while an executor record
   exists.
4. `test_worker_is_supervised_under_the_cycle_deadline_and_revoke` — a worker that never answers:
   the cycle times out at 5000 ms (offset clock), the controller thread answers `revoked` within
   `REVOKE_DEADLINE_MS` after a `killpg`, the worker is reaped; a worker that cannot be reaped (SIGSTOP
   stand-in) yields `unresolved` and the cycle quarantines `bootstrap_unresolved` with no `ready`; a
   surviving fake helper in the worker's group also yields `unresolved` (A-3).
5. `test_worker_reports_unresolved_when_unresolved_helpers_is_nonzero` — the fake nft hangs through
   the reap grace: `unresolved_helpers()["unreaped"] == 1` in the worker; the `state` message carries
   it; the revoke ack says `worker: unresolved`; the supervisor records `worker_unresolved` and refuses a
   new generation (`exit_required`).

Additional named tests:
- `test_receipt_read_then_revoked_runs_no_cleanup_and_kills_the_worker_under_the_nonce` (R′, B-2):
  the `tests/test_host_cycle.py:2234` pattern (stop recorded after the receipt, before the decision):
  the worker's send succeeded, the fake-nft log has **no** `delete table`, no `ready`, the forwarded
  dup is closed before the ack, the worker group is killed and `reaped`, `_INPUTS` stays
  `receipt_ready`.
- `test_pin_is_sent_by_the_controller_on_arm_before_armed_and_the_worker_refuses_a_mismatched_request`
  (B-6): the worker receives `pin` before the request; a request whose fence differs is refused with no
  install; the main thread never holds the supervisor lock inside `start()` (instrumented lock owner
  assertion during the hand-off).
- `test_trusted_constructor_maps_only_validated_fields_and_refuses_origin_or_runner_mismatch` (real
  `ValidatedExecutionBundle` fixtures from the runner tests; every `CycleContext` field traces to the
  table in §4.3; a grant with another origin, or runner fields differing from the slot configuration,
  is refused before `install_context`).
- `test_preflight_uses_the_unchanged_validator_and_refuses_private_or_oversized_answers` (resolver
  seam in the supervisor; `unsafe_dns` → `start_refused:preflight`, no worker spawned).
- `test_link_resolver_resolves_only_the_pinned_name_through_the_supervisor_and_keeps_dns_changed_reachable`
  (B-3): the real `TargetHTTPSClient` with `resolver=LinkResolver` against the runner tests' loopback
  TLS target and `sockets` seam; the supervisor's `BoundedResolver` is the test seam returning a
  mutable answer: reorder → success, drop/add/replace member → `dns_changed`, private member →
  `unsafe_dns`, other hostname → `unsafe_dns` with no datagram, 65th request → `budget`, no reply →
  `timeout`; `resolver_calls == attempts + 1`.
- `test_claim_request_re_resolves_and_defers_on_a_stale_pin` (§4.5 item 4).
- `test_executor_helper_sets_namespace_then_drops_privileges_closes_the_namespace_fd_and_execs_fixed_argv`
  (real helper source with a labelled test helper that skips `setns`/`setresuid` only; `/dev/fd`
  listing shows exactly stdio + the link fd; pinned hash of the production helper; exit codes 124-127).
- `test_executor_link_and_worker_link_match_exactly_and_refuse_descriptors_and_oversize`.
- `test_registry_writer_renders_the_closed_schema_atomically_with_increasing_generation_and_runner_from_slot_config`
  (validated with `validate_registry` from `tests/support/host_ingress_harness.py:241`; the `runner`
  record comes from the slot configuration fixture, never from a link message; attach without the
  configuration is `runner_record_missing`).
- `test_revoke_writes_the_non_admitting_shape_before_the_ack_and_a_failed_write_sends_no_ack` (B-1):
  the rendered record passes `validate_registry`; a port of `runnerPrecheck`'s outcomes on that record
  (claim → `phase`, run/context routes → `identity`, `resync`/`context_list` admitted) is asserted by
  evaluating the real `policy.js` under the QuickJS build only in H3-3; offline, the test asserts the
  shape (`stopping`, three empty lists, new generation) and that an injected write failure leaves the
  cycle to time out (`bootstrap_unresolved`) with no `revoked` datagram.
- `test_executor_crash_ends_the_context_and_reaps_before_the_flush`.
- `test_supervisor_exits_after_the_generation_budget_and_never_forks` (AST: no `os.fork`, no
  `preexec_fn`, `close_fds=True` on every `Popen`, `start_new_session=True` on the worker `Popen`, no
  TCP `connect` in `supervisor.py`).
- `test_logs_status_and_links_carry_fixed_tokens_only` (byte scan of every emitted line and datagram
  against the H2-A/H3 grammars; no path, pid, nonce, digest of a secret, or raw bytes).
- `test_doc_names_every_state_token_order_and_obligation` (this document + `docs/saas/H3_COMPOSITION.md`).
- **H3-1b hunk, gated on H2-3's accepted interface (B-4):**
  `test_binding_generation_defers_claims_and_pins_the_reported_origin_for_the_next_generation`
  (control-only `pin`, `control_only=True` passed to `build_input` only then).
- `test_h2_3_control_accept_is_rendered_and_read_back_exactly` lives in `tests/test_host_h2_policy.py`
  (H2-3, §8.1), not here.

### 6.2 Clean-room component acceptance (what a reviewer may claim from H3-1 green)

That the supervisor/worker composition satisfies the five obligations and invariant T against the real
cycle wire, the real H2-1 state machine and real processes, with no kernel namespace. Nothing about nft,
`setns`, veth, the ingress, pairing, a customer or deployment.

### 6.3 Isolated Linux proof `h3-lifecycle-v1` (H3-2; seventh `workflow_dispatch` job)

Launcher `scripts/host_h3_lifecycle_proof.py` modelled on `scripts/host_h2_policy_proof.py` (fixed
profile, literal ref `refs/heads/codex/self-serve-host-h3-lifecycle-proof`, `STAGE_FILES` = H2-2's
plus `deploy/host/supervisor.py`, `worker.py`, `executor.py`, `tests/linux/test_host_h3_lifecycle.py`,
the launcher and `docs/saas/H3_COMPOSITION.md`; the same eight-wheel closure; `HEEL_TREE_FILES` =
`git ls-files heel` at the candidate; `sudo -n` child; five allow-listed artifacts; sanitizer; zero
skips). Inside the outer namespace: the **real** supervisor process (uid 0), the real `HostCycle` with
the real `ControlPlaneClient` against the real `HostAuthorityListener` + `HostSnapshotDecider` on a
real SQLite control-plane state seeded through the real CP services (the H1A3-2 pattern,
`tests/linux/test_host_authority_proof.py` S-cases, uid 10001 listener in a child PID namespace), real
`LeaseDomain`, real H2-1/H2-3 install with real nft, the real worker, the real executor **launch path**
(helper, uid drop, link, input file) running the real `TargetHTTPSClient` against H2-2's `TLSPeer` in
the peer namespace through the resolver channel (`LinkResolver` in the probe, the supervisor's constrained resolver answering). The executor binary in this proof is a **proof probe**
(`tests/linux/h3_probe.py`, staged): it speaks the real executor link codec (`deploy/host/executor_link.py`)
and drives the real client, but it is **not** the runner daemon and there is no runner-protocol control
plane here — stated in every record and in the doc. Cases:

- **L0** provenance: staged hashes, pinned profile, fresh namespace ruleset empty, real H1 self-test,
  no seam assignment anywhere in the staged H3/H2 modules.
- **L1** success: arm → `pin` → install (control + targets) → receipt → `ready` → veth by fd →
  registry `active` with the `runner` record from the fixture's root-owned slot configuration →
  executor attached → `bound`/`claim_request` (re-resolution equal to the install tuple) /`claimed` →
  context installed → real CP `active` reply → `activated` → `authorized` → the real client reaches
  the pinned IPv4 target over the live key through the resolver channel (`resolver_calls` counted at
  the supervisor), is denied before activation and after `close`; control probe to the slot gateway
  :443 admitted without a key; gateway :8443, gateway UDP 443, gateway from the wrong source, gateway
  over IPv6, sibling address denied (H2-3 oracle). **Adversarial DNS (B-3):** after install the
  fixture's upstream answer set changes: drop/add/replace member → the client refuses `dns_changed`
  before any socket; a peer on the pinned address presenting a certificate for another name → TLS
  refusal; the next generation's preflight picks up the new set (recorded as the new install tuple).
- **L2** binding generation: control-only table (no target accept), `claim_request` → `defer`,
  executor exits, origin pinned for the next generation; ≥ 10 s spacing observed from the cycle's
  budget.
- **L3** failed send (F) and receipt-then-revoke (R′), real nft, real worker, no fake installer or
  nft: the one labelled seam is the cycle's public `CycleSeams.clock` (**FAULT-INJECTION**, the
  precedent of H1A3-2's `_cycle_fixture` seam, `tests/linux/test_host_authority_proof.py:598,2238`,
  and of H2-2 P6(c)). F: the clock reads past `BOOTSTRAP_DEADLINE_MS` at the first receive poll, so
  `_receive` returns `timeout` and `cancel()` closes the worker socket microseconds after the request
  was sent, while the worker still needs three real nft children (milliseconds); the worker's later
  `sendmsg` raises → exactly one `delete table`, ruleset empty, `state {send: failed}`, worker reaped,
  `revoked`/`absent`/`reaped`, no `ready`, no executor process ever existed. The record carries the
  cycle's socket-close instant and the worker's send-attempt instant (from `state`); the case FAILS if
  the margin is below 10 ms or if `send` is not `failed` (it proves the fail-closed state machine on a
  real kernel, not kernel timing). R′: a real `stop()` from the fixture after the receipt was read and
  before the lock-held decision (`tests/test_host_cycle.py:2234` pattern, observed through
  `bootstrap_status()`): no `delete table`, table present until the namespace dies, worker group
  killed, `reaped`, `_INPUTS` stays `receipt_ready` (read through the worker's `state`).
- **L4** revoke with forwarded dup: the controller's dup is closed before the ack (`/proc/self/fd`
  count by identity); `unresolved` when the worker is SIGSTOPped or a helper of its group survives:
  quarantine, `exit_required`, no new generation; a registry write failure injected at revoke: no
  `revoked` datagram, `bootstrap_unresolved`.

- **L5** teardown order S with a live executor and an established connection: the table is present
  until the executor is reaped; the flush precedes `release`; after the last holder closes, the
  namespace identity is gone from every `/proc/*/ns/net` and the host-side veth is gone (I-4).
- **L6** revocation latency: `inactive stop_requested` from the real CP → executor reaped and target
  denied within 5 s wall (recorded, single-run fact).
- **L7** residue: no fixture, domain, namespace descriptor, veth, socket, thread, helper, worker,
  executor or outer-namespace change remains; `unresolved_children()` all zero; `unresolved_helpers()`
  zero; outer fingerprints unchanged.

Gates: statics + H3-1 green locally → small DCO commit → fresh Fable source review → Astra-only
dispatch → independent runtime review. A missing capability, an unsupported profile, any skip or any
readback other than the exact H2-3 shape is FAIL/HOLD, never a fallback.

### 6.4 Managed end-to-end proof `h3-managed-v1` (H3-3; dependent)

The real `deploy/host/executor.py` running the real `RunnerDaemon.serve` inside the generation
namespace, pairing and claiming through the real nginx/njs ingress and the real CP (the H0 harness's G3
ceremony, `tests/support/host_ingress_harness.py`, with H3's registry writer replacing
`SEAM-REGISTRY`), a synthetic local HTTPS target, real evidence in `RunnerStore`, real result
projection. Depends on C4 (service-driven pairing of a managed executor), on the H6 facts in §10 and
on the H0 launcher's build budget. It is the H1A3-A-class combined gate the cycle doc names
(`HOST_AUTHORITY_CYCLE.md` "Limits"); not part of H3-1/H3-2 acceptance.

## 7. Minimal API, persistence and package changes

| Area | Change | Size |
|---|---|---|
| `deploy/host/h2_policy.py` (H2-3) | control accept rule; `control_only` keyword and the empty-tuple shape; `install` entry refusal and `_readback` empty-set precondition under `control_only`; readback oracle (`_READBACK_PARTS` gains `control_rule`); doc | ~60 lines |
| `deploy/host/supervisor.py`, `worker.py`, `executor.py`, `executor_link.py` (new) | the contract above; load `authority.py`, `cycle.py`, `h2_policy.py` and the codec by path like `cycle.py:44-61` (one module object per file per process) | new |
| `heel/runner/daemon.py` | `managed_link` constructor seam; claim gate in `_ServeSession.run`; precheck chain and `claimed`/`released` emission in `_ServeExecution.execute`; `target_network`/`secret_backend` seams unchanged and used by the managed entry | ≤ 40 lines; regenerates the three download artifacts |
| CP (`heel/saas/*`) | none | — |
| Persistence | none in the CP; root-owned per-slot configuration (`/etc/heel/slots/<slot>.json`: listener, peer, hop addresses, uid/gid, volume, prefix pin, **runner record written by C4's pairing ceremony**, later the CP-bound environment origin) and the registry file are inputs the supervisor reads; the supervisor persists nothing else | — |
| Packaging | nothing ships in the open-core wheel from `deploy/host/`; the executor prefix is the existing wheel + `runner` extra | — |
| Workflow | one appended job (H3-2) and the oracle hunks in the four pinning tests (§8.3) | — |

## 8. Bounded, dependency-ordered backlog (one fresh Opus per task, ≤ 3 remediation cycles)

Common gate rules: red tests first; focused module → affected modules → one full suite if the slot
allows; no edit outside the allowed list; `heel/runner/**` edits regenerate the three download artifacts
(`docs/saas/LOCAL_RUNNER_EXECUTION_BRIDGE.md` lineage; `heel-runner-downloads-coupling`); one small DCO
commit (`git commit -s`, identity `Ancilis Codex Agent <agents@ancilis.ai>`, trailer
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`); no push by the author; Astra publishes;
fresh Fable source review; Linux execution only by Astra's manual dispatch of the fixed job; independent
runtime review. Baselines to re-measure, not assume: `tests/test_host_cycle.py` 62 tests (184 passed /
2 skipped per `H2A_BOOTSTRAP_CONTRACT.md`), `tests/test_host_h2_policy.py` 33, `tests/test_host_h2_policy_proof.py`
10, `tests/test_host_authority.py` 60 (counts of `def test_` at this tree; CI: Python 2856/272/749 on
3.11/3.12/3.14 and 2857/271/749 on 3.13, Node 76, Pyodide 5, parity 41, release 18+5).

### 8.1 H2-3 — control accept and control-only shape (Opus → fresh Fable → Astra dispatch → runtime review)

Depends on: H2 accepted at `43a3b76`; **the CodeQL alerts 98/99 on `scripts/host_h2_policy_proof.py:608,610`
dispositioned** (independent review in progress; no implementation grant before that). Allowed files
(exhaustive): `deploy/host/h2_policy.py` — the four code sites: (1) `H2PolicyInput` gains a
keyword-only `control_only: bool = False`; `observed_public_addresses == ()` is accepted **iff**
`control_only` is `True` (biconditional, A-1: `control_only=True` with a non-empty tuple is
`observed_public_addresses_invalid`; an IPv6-only tuple stays `unsupported_ipv6_only`), then
`ipv4_egress_targets == ()`; (2) `render_table` (`h2_policy.py:179-202`) emits, immediately before
the target accept, `ip saddr <slot_hop_src> ip daddr <slot_hop_dst> tcp dport 443 accept`, and omits
the target accept iff `control_only` (its `unsupported_ipv6_only` raise at 182-183 becomes
"empty targets and not control_only"); (3) `install()` entry (521-522) refuses an empty IPv4 set
only when not `control_only`; (4) `_readback` (261-264) accepts an empty target set only under
`control_only`, and `_READBACK_PARTS` gains `control_rule` between `lookup_rule` and `admit_rule`.
Readback invariants (A-1): rule order `reset`, `lookup`, `control`, `admit` (the last absent iff
`control_only`); the control rule's `expr` is exactly `[match ==/in ip saddr <slot_hop_src>,
match == ip daddr <slot_hop_dst>, match == tcp dport 443, accept]` with no `meta`, no set reference,
`slot_hop_dst` byte-equal to the typed-gateway literal of the key; item count 8 with targets, 7
without. `tests/test_host_h2_policy.py` (named:
`test_control_accept_is_rendered_before_the_target_accept_with_fixed_src_dst_port_and_no_mark`,
`test_control_only_is_a_biconditional_with_the_empty_tuple_and_renders_no_target_accept`,
`test_readback_requires_the_control_rule_exactly_and_refuses_another_address_port_source_or_meta`,
`test_install_and_readback_accept_an_empty_target_set_only_under_control_only`,
`test_public_surface_is_exactly_six_names` unchanged). `tests/linux/test_host_h2_policy.py` (A-2:
P1/P2 gain probes **to the gateway** — today's `wrong_port`/`udp` probes target the TLS peer,
`tests/linux/test_host_h2_policy.py:1054-1063` — `SLOT_SRC → gateway:443` admitted without a key,
`wrong_source → gateway:443` denied, gateway UDP 443 denied, gateway IPv6 denied, gateway :8443
denied; P5 gains the control-only shape: whole ruleset one table of 7 items, no target rule, control
admitted, targets denied), `scripts/host_h2_policy_proof.py` (only if a case name changes; otherwise
unchanged), `docs/saas/H2_POLICY_INSTALLATION.md`, `docs/saas/H2_POLICY_PROOF.md`. Gates: focused +
affected green (`tests/test_host_cycle.py` counts unchanged); fresh Fable source review; Astra
dispatches the **existing** `host-h2-policy-proof` job on the literal branch; independent runtime
review (18 + new records, zero skips, exact readback). Outcome: H2 primitive accepted with the
control accept; **H2 stays component evidence**.

### 8.2 H3-1 — supervisor, worker, executor entry, links, offline suite (Opus → fresh Fable)

Depends on: Astra's grant and this spec's round-2 review; the same CodeQL prerequisite as H2-3.
**Coding may overlap H2-3; the integration/test gate waits for H2-3's accepted interface (B-4):**
the worker passes `control_only=` to `build_input` only when the `pin` says so, so every non-binding
generation runs against the accepted H2-1 API, and the one test that needs the H2-3 API
(`test_binding_generation_defers_claims_and_pins_the_reported_origin_for_the_next_generation`) and the
`control_only` pin field are an **H3-1b hunk** committed only after H2-3's source review passes. H3-1
is independent of DO access, C3, C4 and H6; its real-daemon case passes a test `secret_backend` (A-8).
Allowed files (exhaustive):
- new `deploy/host/supervisor.py` (cycle owner, controller thread, registry writer, link writer by raw
  rtnetlink, trusted constructor, preflight, constrained resolver, executor helper constant with
  pinned hash, lock discipline, budget/exit),
- new `deploy/host/worker.py` (receive `pin` then request + fd, `build_input`, `install`, one send,
  `fd_forward`, `state`, ending F only on its own `sendmsg` error, `release`),
- new `deploy/host/executor.py` (managed entry; `LinkResolver`; `RunnerDaemon(..., target_network,
  managed_link, secret_backend)`; `bind`/`run` phases),
- new `deploy/host/executor_link.py` (both link codecs, exact matchers, `SCM_RIGHTS` helpers; imported
  by path by the three modules above and by the proof probe),
- `heel/runner/daemon.py` (§4.5 item 4 only) and the three regenerated download artifacts,
- new `tests/test_host_h3.py` (§6.1),
- `tests/test_host_h2_policy.py` (one hunk: the tracked-file seam guard admits `tests/test_host_h3.py`),
- `tests/test_runner_daemon.py` (one case: the managed seams compose with the real daemon against the
  scripted transport; `defer` leaves the loop offline; `claimed`/`released` emitted; no CLI path passes
  them),
- new `docs/saas/H3_COMPOSITION.md` (status "source candidate, component evidence only"; §4 tables,
  §4.7 endings, §4.9 obligations, non-goals, gates).
No other file: not `authority.py`, `cycle.py`, `h2_policy.py` (H2-3 owns it), `profile.py`, the
ingress files, CP modules, workflows, scripts or settings. Gates: focused `tests/test_host_h3.py` green
on the pinned macOS Python and Linux; affected `tests/test_host_cycle.py`, `tests/test_host_h2_policy.py`,
`tests/test_runner_daemon.py` with unchanged counts plus the additions; full suite once if the slot
allows; artifacts regenerated; DCO commit; fresh Fable review verifies the exhaustive list, public-API-only
use of the cycle/domain/installer (no private attribute of `cycle`/`authority`/`h2_policy` other than
the H2-1 seams in the test launcher), no invented fields, no fork/preexec, the five named tests present
and real, the F/R′ split, the `pin`-on-`arm` ordering and the lock discipline. Outcome: READY for
H3-2 once H3-1b is in; **H3 stays HOLD**.

**Task 1 for the implementer, concretely:** write `tests/test_host_h3.py::test_worker_sends_receipt_once_only_from_receipt_ready`
red: construct a `Harness`-style cycle with `register_bootstrap` on a channel whose worker end is
passed to `python -I -S -B deploy/host/worker.py <fd> <link_fd>` (own process group) with the H2-1
seams applied by the test launcher and a fake `nft` that answers check/install/readback with the
exact P1 shape; the controller thread sends `pin` on `arm`; assert `cycle.start() == "ready"`,
exactly one datagram on the worker socket, bytes equal to `GenerationBootstrap.receipt()` canonical,
`/dev/fd` holders of the stand-in identity in the test process equal to 1 after `fd_forward` is
received and closed; then the three negative scripts. Then write `worker.py` until green; then the F
scenario (test 2) with the sleeping fake `nft` and the advanced offset clock; then the R′ test.

### 8.3 H3-2 — isolated Linux lifecycle proof, launcher, seventh job (Opus → fresh Fable → Astra dispatch → runtime review)

Depends on: H2-3 accepted at runtime; H3-1 reviewed. Allowed files (exhaustive): new
`tests/linux/test_host_h3_lifecycle.py` (§6.3 cases, fixture pieces imported from
`tests/linux/test_host_h2_policy.py` and the real-CP pieces from `tests/linux/test_host_authority_proof.py`
by module import, never copied), new `tests/linux/h3_probe.py`, new `scripts/host_h3_lifecycle_proof.py`,
`.github/workflows/codeql.yml` (append exactly one `host-h3-lifecycle-proof` job after
`host-h2-policy-proof`, same three pinned actions, `contents: read`, no inputs/secrets/cache/services,
literal ref, five artifacts, three-day retention; the 216 existing lines byte-identical), new
`tests/test_host_h3_lifecycle_proof.py` (static oracle: launcher, stage list, seven-job composition,
required cases, sanitizer, literals), minimal oracle hunks in `tests/linux/test_host_h2_policy.py:129,222`,
`tests/linux/test_host_lease_key_shape.py:100,193`, `tests/linux/test_host_authority_proof.py:110,205`
and the composition assertion in `tests/test_host_h2_policy_proof.py:239` and `tests/test_host_authority.py`
(the mutation matrix around 1792-1815, per the H2 design §3 C precedent), new `docs/saas/H3_LIFECYCLE_PROOF.md`.
Unchanged by rule: every launcher, `deploy/host/*`, `heel/**`, the six existing job blocks. Gates:
statics green, DCO commit, fresh Fable source review, Astra-only dispatch, independent runtime review
(every case ran, zero skips, pinned profile, exact tokens, zero residue, hashes equal the commit).
Outcome: bounded H3 lifecycle acceptance recommendation; **not** managed admission.

### 8.4 H3-3 — managed executor end to end (after C4; owner split with C4/H6)

Depends on: C4 service-driven pairing, H6 executor uid/prefix/volume facts, H0 launcher build budget.
Allowed files to be fixed by its own assignment after C4 lands (expected: a launcher composing
`scripts/host_ingress_proof.py` builders by import, `tests/linux/test_host_h3_managed.py`, one job, one
doc, the oracle hunks). Not scheduled by this design.

## 9. Exclusions and remaining owners

### 9.1 Not H3 (named owner)

| Item | Owner |
|---|---|
| Host provisioning: slot static config (listener, peer, hop addresses, uid/gid, volume, prefix pin), executor uid/gid, read-only executor prefix and pin, per-slot volume, `/etc/hosts` for the control name in the executor's view (one slot per host, §2.4), systemd unit (`NoNewPrivileges`, `KillMode=control-group`, restart delay), host `inet heel_exec` INPUT/FORWARD/NAT policy, the slot listener's certificate for the control name (with H0), provider/SKU/kernel qualification, the `Enablement` member | **H6** |
| Service-driven pairing of the managed executor; **writing the root-owned slot configuration's runner record (and later the CP-bound environment origin) from that ceremony (B-5)**; the managed identity backend for a headless executor uid (A-8); anonymous-only managed mode end to end; `deploy/Dockerfile.executor` or its process-sandbox replacement | **C4** |
| Credential intake, `envelope` vault, `login_exchange`, identities | **C5** (human-approved bundle; no implementation here) |
| Discovery engine | **C3** (provider-refused STOP; named only as a dependency of customer acceptance) |
| Result projection, dashboard, evidence viewer, regressions | **C6** |
| Deployment, staging, cost, DO account access | **C8** / Astra / human |
| Final launch gate, customer acceptance layers | **C9** / fresh Fable |

### 9.2 The twelve safety properties: which component owns the proof after H3

| # | Property (customer spec §6.1) | Named tests after H3 |
|---|---|---|
| 1 | no requests outside the verified origin | existing `test_i1_host_confinement_refuses_off_allowlist_redirect_and_rebinding`, `test_dns_is_full_set_pinned_and_rechecked_before_authorized_retry` (unchanged); H2-3 P1/P2 gateway and target cases; H3-1 `test_link_resolver_resolves_only_the_pinned_name_through_the_supervisor_and_keeps_dns_changed_reachable`; H3-2 L1 (incl. the adversarial DNS case) |
| 2 | GET/HEAD + one `login_exchange` POST | owner's existing suite, unchanged by H3: `test_i2_post_inventory_is_rejected_at_compile`, `test_i2_only_inventoried_get_and_head_reach_the_wire`; C2/C3/C5 proposed tests as listed there |
| 3 | signed scope + one-shot attempt | owner's existing suite, unchanged by H3: `test_i3_no_request_without_verified_signed_scope`, `test_i4_no_request_without_one_shot_reserved_attempt`; H3-1 `test_trusted_constructor_maps_only_validated_fields_and_refuses_origin_or_runner_mismatch` |
| 4 | no credential outside the executor vault | C5's proposed tests; H3-1 `test_logs_status_and_links_carry_fixed_tokens_only` for H3's own sinks |
| 5 | raw evidence bounded to the executor | owner's existing suite, unchanged by H3: `test_completed_response_is_written_only_to_required_local_evidence_sink`, `test_operational_cloud_storage_cannot_be_repurposed_for_blocked_or_observed_assessment`; H3: executor stdio to `/dev/null` (helper test) |
| 6 | verifiable containment | owner's existing suite, unchanged by H3: `test_i6_every_request_is_logged_before_it_is_sent`, `test_i8_containment_chains_verify_and_detect_tamper` |
| 7 | workspace/project isolation | owner's existing suite: `test_cross_tenant_objects_unreachable`, `test_tenant_isolation`; H3-2 L1/L7 (namespace per generation, one slot = one workspace executor) |
| 8 | pairing/verification non-replayable | owner's existing suite, unchanged by H3: `test_exchange_is_one_time_and_access_is_workspace_bound`, `test_http_v3_pairing_activation_replays_one_sealed_executable_cursor`; C4's proposed managed-pairing test |
| 9 | quotas idempotent | owner's existing suite, unchanged by H3: `test_duplicate_idempotent_run_charged_once`, `test_concurrent_reservations_never_exceed_quota` |
| 10 | prompt revocation | owner's existing suite: `test_canary_stop.py`, `test_revoked_runner_zero_request_claim_is_stopped_and_refunded_after_deadline`; H3-1 test 4 and `test_revoke_writes_the_non_admitting_shape_before_the_ack_and_a_failed_write_sends_no_ack`; H3-2 L6 (≤ 5 s) |
| 11 | sessions/CSRF/rate limits/audit | owner's existing suite, unchanged by H3: `test_lockout_after_failures`, `test_verify_requires_browser_session_same_origin_and_live_sync_role` |
| 12 | offline/lost authorization/malformed input fail closed visibly | owner's existing suite: `test_restart_coordinator_rehydrates_active_binding_but_requires_fresh_heartbeat`, `test_malformed_and_oversized_bodies`; H3-1 `test_executor_link_and_worker_link_match_exactly_and_refuse_descriptors_and_oversize`, `test_executor_crash_ends_the_context_and_reaps_before_the_flush` |

### 9.3 Explicit exclusions of this design

No DO or provider action; no deployment; no customer traffic; no C3 retry or reframing; no change to
the H2-A wire, the H1 domain, the cycle, the CP codec or the ingress; no second `Enablement` member; no
multi-slot supervisor; no credential path; no model-API use.

## 10. INFERRED register (each with the exact confirming action)

| # | Statement | Confirming action |
|---|---|---|
| I-1 | A systemd unit with `NoNewPrivileges=yes`, `KillMode=control-group` and `RestartSec≥10` gives every descendant `no_new_privs` and kills executor/worker with the supervisor | H6 unit file + H3-3 case reading `/proc/<pid>/status` `NoNewPrivs: 1` for the executor; a supervisor kill test in H3-3 |
| I-2 | A per-slot unprivileged uid/gid and a root-provisioned volume exist on the host | H6 provisioning; H3-1 tests use the current uid with the labelled helper, H3-2 uses a fixture uid (as H1A3-2 uses 10001) |
| I-3 | Between generations the registry slot keeps `phase: stopping` with empty lists and a `namespace_id` naming the last generation; the grammar does not bind `namespace_id` to a live namespace | `policy.js:838,886-905` (read this session: `namespace_id` is a label only); pinned by H3-1's registry test through `validate_registry`; `runnerPrecheck` outcomes on the real `policy.js` only in H3-3 |
| I-4 | Destroying the generation namespace removes both veth ends (host side included) | H3-2 L5/L7: host-side link absent after the last holder closes |
| I-5 | The executor's `getaddrinfo` of the control name resolves through `/etc/hosts` (files) without any DNS packet inside the namespace | H3-3: the control connect succeeds with the files entry present and no `timeout`/`unsafe_dns`; one slot per host until a per-slot mapping exists (§2.4) |
| I-6 | `_require_os_credentials` passes with zero credential bindings | **CONFIRMED by round 1** (`daemon.py:360-383`); no longer inferred |
| I-7 | The controller thread can answer `arm`/`revoke` while `start()` holds no lock | CONFIRMED at `cycle.py:989-1004` (hand-off and cancel outside `_locked`); the supervisor's own lock discipline (§4.2) is pinned by the H3-1 `pin`-on-`arm` test |
| I-8 | `nft` with the fixed control accept before the typed-key target accept keeps the latter's semantics unchanged | H2-3 P1/P2 readback and packet records |
| I-9 | A connected `AF_UNIX` `SOCK_DGRAM` `sendmsg` after the peer closed raises (`ECONNREFUSED` on Linux) rather than queuing; on macOS it raises some `OSError` | H3-1 test 2 on both CI platforms; H3-2 L3; the worker treats any `OSError` as F |
| I-10 | The slot runner listener serves a certificate valid for the control name to a `check_hostname` client | H3-3 with the real ingress; read the H0 nginx server block when H3-3 is planned |
| I-11 | No wildcard `:443` listener other than the slot listeners exists on the host; public HTTPS enters through cloudflared only | H6 qualification; H3-3 G9-style probe from the slot |
| I-12 | `killpg` on the worker's session reaches every H2-1 helper (they inherit the group because H2-1 passes `start_new_session=False`) and a `/proc` group scan within the grace is a sufficient "no survivor" check | H3-1 test 4 (fake helper survivor case) on Linux CI; H3-2 L4 |

## 11. Next action

Astra: (1) launch the fresh independent spec review round 2 of this revision; (2) on acceptance, and
only after the CodeQL alerts 98/99 on `scripts/host_h2_policy_proof.py` are dispositioned, grant
**H2-3** (§8.1) and **H3-1** (§8.2) to fresh Opus sessions (coding may overlap; H3-1's integration gate
and its H3-1b hunk wait for H2-3's accepted interface); (3) after both pass source review and H2-3
passes its runtime review, grant **H3-2** (§8.3); (4) record the C4 dependency (slot runner record,
managed identity backend) and the H6 facts (I-1, I-2, I-10, I-11) before scheduling **H3-3**.
No implementation, dispatch, namespace, provider or customer action was taken by this session; nothing
here is customer admission, deployment or launch evidence. C3 stays STOP.
