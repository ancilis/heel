# Heel self-serve runner bridge — functional design, onboarding order and bounded backlog (T2bD)

Date: 2026-10-18. Branch `feat/self-serve-product`, design base `d9455b45c710b9953cbb5c4956897031ff5255d6`.
Author: Claude Fable 5.1, fresh interactive design session (T2bD). **Design only: no product code,
test, configuration or build artifact changed.** This document refines
`2026-10-18-self-serve-product-launch.md` (the launch spec); where the two differ, the launch spec
was updated in the same commit series so they agree. It satisfies the T2b-design row of launch spec
§11.1 (ownership table) and the T1R instruction that the T2b review confirm or re-split T3/T4.

Every load-bearing claim is **CONFIRMED** (`file:line` at the design base, a test id, or a session
artifact) or **INFERRED** (with the action that confirms it). All new routes, schemas, fields, CLI
commands and module functions are marked **(proposed)**; none exists yet. Evidence for this session:
`.git/self-serve-launch/sessions/T2bD-artifacts/` and `sessions/T2bD-closing.md`.

Goal restated (Kevin, R4; launch spec §11.1): a plan the user approved in the browser actually
reaches the user's verified staging SaaS through the released local runner, observations flow into
redacted cloud findings and replay, with no simulation, canned finding, demo adapter, hidden seed or
fixture recognition. The standalone CLI executor is a foundation, not proof of product functionality.

---

## 0. Verdict summary

| Decision | Outcome |
|---|---|
| 1 `serve` lifecycle | Designed over the existing `RunnerService`/`RunnerCoordinator`/`RunnerControlClient`/`RunnerRuntimeState` with no new framework (§2). One new precondition found: the runner has no cloud grant-signing public key today (§2.2), so a bounded trust-bootstrap task precedes the loop |
| 2 credential-before-binding | Resolved by ordering, not by a bypass: binding first, credentials second, both local; labels reported by the runner over the PoP channel (§3) |
| 3 Approve → target request path | Traced segment by segment with owner, schema and persistence (§4). The first target execution proof is T4a; cloud result projection and dashboard finding are T4b-c, T4b-r and T4b-u |
| 4 gates and seams | T2b proves control-plane behaviour only; target-traffic stop ≤5 s is proved in T4a against a real HTTPS test application through one labelled dial seam, excluded from T8 (§5) |
| 5 R-B quota vs pending | Closed states: owner-visible 402 `runner_quota_exceeded` at invitation, and the same closed code at activation; daemon stops polling (§6) |
| 6 R-C duplicate invitation | Reissue: a new owner invitation invalidates the workspace's open one, closed 201; no 500 (§7) |
| 7 R-A first-lock ENOENT | Separate task T2d after T2b-2, before T3a-s; shipped module, artifacts regenerated (§8) |
| 8 backlog | Re-split into T2b-1, T2b-2, T2c, T2d, T3a-s, T3a-e, T3b, T4a, T4b-c, T4b-r, T4b-u, T5, T6, T7, T8; every task names its source files exhaustively (≤10 source files each; the three regenerated download artifacts are counted separately) with an executable gate (§9); immediate next Opus task is T2b-1 (§9.3) |
| 9 tests and acceptance | §10 of the launch spec updated; clean-room steps reordered; interim vertical-slice gate defined and separated from final deployed acceptance (§10) |

**Design verdict: PASS** (coherent dependencies, no speculative rewrite, no secret or raw evidence in
the cloud, every real-execution segment owned with a meaningful acceptance). This is not an
implementation or launch PASS. Astra's review of the first draft
(`sessions/T2bD-astra-review.md`: lifetime locking, legacy key bootstrap, immutable plan binding,
task sizes, verification order, unsupported execution, over-budget selection) is resolved in
§2.2, §2.3, §2.4, §4.1, §9 and §11; the resolutions are marked **(Astra n)**.

---

## 1. Reachability today (what exists, who constructs it)

| Component | Exists | Constructed by product code today | Evidence |
|---|---|---|---|
| `RunnerService.serve/run_once` (idle claim poll ≥2 s, 0.25 s run heartbeat, 5 s stop controller, maintenance worker) | yes | **tests only** | CONFIRMED `heel/runner/service.py:167-432`; `grep -rl 'RunnerService('` → `tests/test_runner_coordinator.py`, `tests/test_runner_stop.py` only |
| `RunnerCoordinator` (claim decode, context list/claim/rollover, gate, heartbeat/progress/result/stop-ack, findings upload, recovery in constructor) | yes | **tests only** | CONFIRMED `coordinator.py:64-846`; zero constructors under `heel/` |
| `RunnerExecutionAdapter` (binds a lease to `LocalCanaryExecutor` + one target transport) | yes | tests only | CONFIRMED `coordinator.py:846-897` |
| `LocalCanaryExecutor` (frozen actions, per-attempt gate/budget, evidence sink, redaction, containment, terminal projections) | yes | CLI standalone path only (`plan_differential._execute`) | CONFIRMED `execution.py:343-1096`, `plan_differential.py:1468-1472` |
| `TargetHTTPSClient` production constructor `_build_client(origin)` (resolver, sockets, verified TLS, public-address preflight) | yes | CLI standalone path only | CONFIRMED `plan_differential.py:846-850`, `http_transport.py:98-175,637-720` |
| `RunnerControlClient` over `HTTPSControlTransport` | yes | `RunnerDaemon._live_check` (status) only | CONFIRMED `daemon.py:523-536` |
| `RunnerDaemon.pair/status/unpair` | yes | CLI | CONFIRMED `daemon.py:293-591`, `cli.py:237-270` |
| `heel runner serve` | **no** | — | CONFIRMED `cli.py:1118-1192` subcommands: pair, status, unpair, import-openapi, credential, map, prepare, run |
| Cloud route inventory, plan request, plan-differential result projection, regression replay, runner-revoke UI | **no** | — | CONFIRMED `http_api.py:908-1060` matcher; `apps/heel-cloud/app/dashboard/page.tsx:279,409` (binding revoke only) |
| Cloud grant-signing public key on the runner | **no** | — | CONFIRMED §2.2 |

Consequence (unchanged from R4R §5): no browser action can start a live execution today.

---

## 2. Decision 1 — `heel runner serve` lifecycle

### 2.1 Composition (all existing classes; wiring is the only new code)

```
heel runner serve [--once]                                   (proposed CLI, cli.py)
  RunnerDaemon.serve(shutdown_event)                          (proposed, daemon.py)
    record = _load_record()  state must be "active"           daemon.py:198-233 (CONFIRMED)
    identity, signer = _active_identity()  (OS secret store)  daemon.py:455-481 (CONFIRMED)
    authority = record grant-authority key  (§2.2, proposed)
    runtime  = RunnerRuntimeState(runtime_path, identity, signer)   daemon.py:510
    control  = RunnerControlClient(origin, ws, runner, signer, clock, HTTPSControlTransport(origin),
               nonce_source, runtime, trusted_disclosure_keys=authority)  control_client.py:235-292
    store    = RunnerStore(root)        (unbound on first serve; coordinator pins authority)
    coordinator = RunnerCoordinator(control, store, identity, signer, trusted_grant_keys=authority)
               constructor replays pending calls and recovers runs   coordinator.py:67-135
    executor = T2b-2: _ExecutionBridgeAbsent (raises, see 2.4) ; T4a: RunnerExecutionAdapter(...)
    service  = RunnerService(coordinator, executor, heartbeat_interval=0.25, idle_poll_interval=2.0)
    service.serve(cycle_stop_event)
```

The coordinator's `ensure_runner_context` performs binding discovery and installation
(`contexts/list` → `contexts/{id}/claim` → `store.install_cloud_context_binding`, CONFIRMED
`coordinator.py:464-568`); with zero bindings it returns `False` and the service idles at the 2 s
poll (CONFIRMED `service.py:208-215, 410-416`). This is the only way the store becomes
context-bound in the product (namespace = sha256(workspace, project, environment_id), CONFIRMED
`store.py:425-432`), which is what §3 relies on.

### 2.2 Precondition found: the runner has no cloud public key (owner: T2b-1)

`RunnerCoordinator` requires a non-empty `trusted_grant_keys` mapping and the control client's
`trusted_disclosure_keys` must equal it (CONFIRMED `coordinator.py:79-105`); `store` verifies every
context binding with `verify_envelope(trusted_cloud_keys, …)` (CONFIRMED `store.py:6736-6742`);
`validate_execution_bundle` verifies grants with the same keys. Tests supply the server's
`SigningAuthority` directly (CONFIRMED `tests/test_runner_coordinator.py:256-282`). The v3
activation response is a closed set with no key material (CONFIRMED `runner_auth.py:1684-1688`,
`store.py:1162-1166`), the daemon record has no key field (CONFIRMED `daemon.py:60-63`), and no
route publishes the key (`_match`, `http_api.py:908-1060`; `/v1/plans` returns the catalog only,
`:1557-1568`). So a paired runner cannot verify anything the cloud signs.

Design (proposed, T2b-1): deliver the key inside the human-approved pairing ceremony, not by a
separate anonymous fetch (an anonymous fetch would be trust-on-first-use against TLS alone and
would offer a silent re-trust path on key change):

- Activation response becomes `heel.runner-pairing-activated.v4` = the v3 fields plus
  `grant_authority: {key_id, public_key_b64}` where `public_key_b64` is the 32-byte Ed25519 public
  key of `ControlPlane.grant_authority` (`server.py:118,202-217`) and `key_id ==
  ed25519_key_id(public_key)`; built in `RunnerAuthStore.activate_executable`
  (`runner_auth.py:1776-1830`), validated by `_validated_v3_activation_response` (renamed
  accordingly) on replay, and by `RunnerStore._activation_response` (`store.py:1162-1195`).
  `control_protocol` stays `heel.runner-control.v2`. Provenance of v3 peers: see the version
  transition bullet below.
- Daemon record gains `grant_authority_key_id` and `grant_authority_public_key_b64`
  (`_RECORD_FIELDS`, `daemon.py:60-63`); `pair` writes them from the accepted response; `status`
  and `serve` recompute the key id and fail closed `cloud_authority_missing` if absent or mismatched
  (next steps: `heel runner unpair`, then pair with a fresh invitation).
- Key rotation on the control plane therefore requires re-pairing runners; this is a documented
  launch limitation (single grant key, `HEEL_GRANT_SIGNING_KEY_ID`), not a product promise. The
  existing `grant_trusted_keys` set on the server (`server.py:119,220-225`) is unaffected.
- **Version transition (Astra 2).** No universal claim about deployed v3 peers is made. Audited
  provenance only: the v3 activation protocol exists in this branch's source and in the committed
  1.2.0 download artifacts under `apps/heel-cloud/public/downloads` and raw GitHub (CONFIRMED
  launch spec §2 row 5), GitHub Release v1.2.0 has zero assets (CONFIRMED T1D), and this audit
  observed no deployed control plane or distributed runner through the access it had (launch
  spec §15); whether anyone installed the committed artifact is unknown. The peer matrix below is
  therefore stated and tested, not assumed:
  - **Daemon record.** `_validate_record` requires the exact closed field set
    (CONFIRMED `daemon.py:212-233`), so adding fields needs an explicit transition: records are
    accepted with either the v1 set or the v1 set plus the two key fields (schema id stays
    `heel.runner-daemon-pairing.v1`; presence of both key fields is the only discriminator, a
    record with exactly one of them is `local_state_invalid`). An `active` record without the key
    fields stays loadable: `status` reports `state: cloud_authority_missing` with
    `next_steps: ["heel runner unpair", "heel runner pair --origin <origin> --invite <new token>"]`,
    `unpair` works unchanged, `pair` keeps refusing `already_paired`, and `serve` exits closed with
    `cloud_authority_missing` before any network call. `_load_record` never rejects a legacy record.
  - **Server.** `activate_executable` emits `heel.runner-pairing-activated.v4` for new activations.
    A stored activation receipt is replayed exactly as stored (CONFIRMED the receipt holds the
    encrypted exact response, `runner_auth.py:1727-1744`), so the replay validator accepts both the
    v3 and the v4 field sets and never rewrites a receipt. An old runner against a new server
    receives v4 and fails closed `response_rejected` (strict set check, CONFIRMED `store.py:1162-1178`);
    a new runner against an old server receives v3 and fails closed the same way. Neither
    combination is a supported deployment; both are tested so the failure is closed, not a traceback.
  - **Persistence through the existing chain (Astra final).** The validated authority reaches the
    daemon record without new store surfaces: `RunnerStore._activation_response`
    (`store.py:1158-1195`) is the only place that validates and shapes the accepted response; it
    gains the `grant_authority` field check (32-byte Ed25519 key, `key_id == ed25519_key_id(key)`)
    and includes the field in the dict it returns. `accept_pairing_activation` writes that dict
    into the signed journal unchanged (`:1306-1316`); `finish_pairing_activation` and
    `recover_pairing_activation` read the journal and use only `initial_claim_nonce`,
    `runner_id`, `workspace_id` and the digest of the whole response (`:2665-2681`,
    `:2822-2832`); they do not re-check the inner field set, so they carry the new field with no
    edit of their own, and the journal's own closed field set lists journal keys, not inner
    response keys (`:1281`, `:2649`). `RunnerDaemon.pair` already holds the exact response that
    `accept_pairing_activation` validated (`daemon.py:362-367`) and copies `grant_authority`
    into the record after acceptance. Hence
    the `store.py` allowlist for T2b-1 is exactly `_activation_response`; no other store helper
    needs to change, and T2b-1 MUST NOT widen it.
  - **Exact literal inventory for the T2b-1 allowlist (CONFIRMED `grep` at the design base):**
    `heel.runner-pairing-activated.v3` / `activate.v3` / `_validated_v3_activation_response` /
    `_PENDING_V3_FIELDS` occur in `heel/runner/daemon.py` (3), `heel/runner/store.py` (8),
    `heel/saas/http_api.py` (2), `heel/saas/runner_auth.py` (7), `tests/test_runner_control_http.py`
    (6) and `tests/test_runner_public_client.py` (6). T2b-1's allowed files therefore include
    `tests/test_runner_public_client.py`; nothing under `apps/` or `release/` references the literal.

### 2.3 Loop, offline/backoff/resume, signals, revocation, deadlines (proposed, T2b-2)

- **Single instance (Astra 1).** `.daemon.lock` is a *short* record transaction lock: shared in
  `_load_record`, exclusive in `_reserve_record`/`_write_record`/`_remove_record`, each released
  before returning (CONFIRMED `daemon.py:198-284`), and `_flock` is a blocking `LOCK_EX`/`LOCK_SH`
  (CONFIRMED `store.py:708-727`). Holding it for the lifetime of `serve` would block `status`
  (shared) or `pair`/`unpair` (exclusive) indefinitely, so it is not used for instance control.
  Instead `serve` takes a **separate non-blocking instance lock** `.serve.lock` in the same daemon
  directory: opened through `_daemon_fd` with `_LOCK_FLAGS` (`O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC`,
  CONFIRMED `store.py:72-75`) and the same `_secure_regular`/`fchmod 0600` checks, then
  `fcntl.flock(fd, LOCK_EX | LOCK_NB)`; `EWOULDBLOCK` → closed `already_serving`. The kernel
  releases it on process death, so **no PID file is authority** and no stale lock survives a
  crash; the state file's `pid` is informational only. `unpair` tries the same non-blocking
  acquisition and refuses `serve_running` while a serve holds it (then releases); `status` never
  takes it (it reads `serve-state.json`); `credential add` uses only the store's
  `.metadata.lock` transactions (`store.py:5313-5325`) and is unaffected. Record transactions
  inside `serve` stay short. Named tests (T2b-2): `test_second_serve_exits_already_serving_without_touching_the_record`,
  `test_status_and_credential_add_succeed_while_serve_holds_the_instance_lock`,
  `test_unpair_refuses_while_serve_runs_and_succeeds_after_sigterm`,
  `test_serve_instance_lock_is_released_on_sigkill_without_a_stale_pid_check`.
- **Cycle.** One cycle = build control/coordinator/service (above) and call `service.serve(cycle_stop)`.
  `RunnerService.serve` returns only when its event is set and raises on any `run_once` failure
  (CONFIRMED `service.py:361-432`); the daemon classifies the exception:
  - `ControlTransportError` with code `connection_failed` or `timeout` → state `offline`; wait with
    exponential backoff 2 s, 4 s, … capped at 60 s (±25 % jitter, interruptible by the shutdown
    event); then start a new cycle. The new coordinator constructor is the documented restart path
    (replays staged calls, rehydrates the active binding, requires a fresh heartbeat: CONFIRMED
    `test_restart_coordinator_rehydrates_active_binding_but_requires_fresh_heartbeat`,
    `tests/test_runner_coordinator.py:757`). An in-flight run that lost the control plane was already
    cancelled by the heartbeat worker (`cancellation.control_error = "cloud_disconnected"`,
    `service.py:309-313`) and its terminal result is replayed on resume.
  - transport `last_status == 401` with `invalid_runner_auth` → state `revoked`, exit code 3,
    no further control call (mirrors `_live_check`, `daemon.py:537-544`).
  - `403 runner_protocol_upgrade_required` → state `failed`, reason `protocol_upgrade_required`, exit 2.
  - `RunnerStoreError`, `RunnerRuntimeStateError`, `ValueError` (response decoding, chain or local
    authority) → state `failed` with closed reason `local_state_invalid` or `response_rejected`,
    exit 2. No automatic retry on protocol errors: a busy loop against a misbehaving peer is not
    fail-closed.
- **Signals.** `SIGINT`/`SIGTERM` set the shutdown event, set the cycle event and call
  `service.request_local_stop()` → `local_emergency_stop` cancels any in-flight target socket at
  once and the bounded stop-ack follows within 5 s (CONFIRMED `service.py:200-206, 83-105,
  106-158`). Exit 0 with state `stopped`.
- **Revocation and deadlines during a run** are already closed in `RunnerService.heartbeats`
  (gate inactive, `runner_state != active`, proof expired/revoked, kill switch → stop controller
  with deadline `cycle + 5.0`, CONFIRMED `service.py:265-335`) and in the coordinator
  (`execution_gate` refuses a stale gate after 0.5 s and a non-advancing server time, CONFIRMED
  `coordinator.py:633-671`). The daemon adds nothing here.
- **Binding expiry/rollover** is handled by `ensure_runner_context` (24 h `CONTEXT_TTL_MS`,
  rollover journal, CONFIRMED `runner_contexts.py:30`, `coordinator.py:464-568`). The credential
  records live in the context namespace keyed by environment, not by binding id, so a renewed
  binding for the same environment keeps them (CONFIRMED namespace derivation `store.py:425-432`;
  rollover keeps the namespace when the context tuple is unchanged or is a proof-generation
  rollover, `store.py:6346-6420`). INFERRED that `credential add` succeeds against a cloud-installed
  binding without extra keys; confirming test in T2b-2 (§9).
- **Visible state.** `serve` maintains `$HEEL_HOME/runner-daemon/serve-state.json` (proposed,
  schema `heel.runner-serve-state.v1`: `state` ∈ {starting, online, offline, revoked, stopped,
  failed}, `since_ms`, `updated_at_ms`, `last_error_code|null`, `binding_id|null`,
  `access` (the `self_serve_access` object, labels only), `pid`), written with the existing
  secure-file helpers and read by `heel runner status --offline`. Server-side liveness for the
  dashboard's `runner.offline` uses `last_heartbeat_at_ms` on the identity record, updated by
  authenticated runner calls (CONFIRMED written at `runner_auth.py:2961`; INFERRED that this is
  inside `authenticate_and_consume` for every PoP call — confirm by test in T3a-s before exposing
  `last_seen_ms`).
- **Control-plane POSTs vs target GET/HEAD.** Every control call is a PoP-signed `POST` to the
  pinned Heel origin over `HTTPSControlTransport` (`contexts/list`, `claim`, `heartbeat`,
  `progress`, `result`, `stop-ack`, `result-projection`, and the two proposed routes of §3.3 and
  §4 rows 3 and 12). None of them is target traffic. Target traffic is only `GET`/`HEAD` from
  `TargetHTTPSClient` to the verified origin under a frozen manifest action
  (CONFIRMED `execution.py:639-770`, compiler `GET`/`HEAD` only `compiler.py:374-408`).

### 2.4 What T2b-2 does not do

No execution bridge (Astra 6). The service executor in T2b-2 is `_ExecutionUnavailable`
(proposed): its `execute` raises the closed `RunnerServeError("execution_unavailable")`, a
`RunnerPairingError` subclass added to the documented loop exceptions of §2.3; the daemon catches
it, writes `serve-state.json` `state: failed, last_error_code: execution_unavailable`, sends no
request, and exits 2 through the existing fixed CLI line (`_SAFE_RUNNER_PAIRING_FAILURE`,
`cli.py:43`), never a traceback. It does not acknowledge, heartbeat as running, or terminalize
the lease; the coordinator's claim leaves the run `claimed` on the server and the existing reaper
terminalizes and refunds it after its deadlines
(`test_canary_quota.py::test_revoked_runner_zero_request_claim_is_stopped_and_refunded_after_deadline`).
This path is reachable only if a human submits a legacy catalog projection through the human route
(`http_api.py:2303-2318`) and approves it; runner-submitted projections do not exist before T3b.
The same closed code is kept after T4a: `RunnerExecutionAdapter` composition executes **only a
lease whose approval projection is the v2 plan-differential projection of §4.1** (schema
`heel.approval-manifest-projection.v2`, `plan.plan_kind == "plan_differential"`, matching the
locally saved pair); a v1 catalog projection lease or any other kind yields
`execution_unavailable` with zero target traffic (test
`test_serve_refuses_a_catalog_projection_lease_with_execution_unavailable`, T4a). T2b tests
therefore claim control-plane behaviour only, never live execution. No projection, grant,
inventory or plan is fabricated or mocked for a T2b test; T2b is not journey readiness
(launch spec §11.1 ownership table).

---

## 3. Decision 2 — onboarding order, credentials, labels, rotation, legacy

### 3.1 The cycle and its resolution

`heel runner credential add` needs a bound context (`RunnerStore._transaction` opens the selected
namespace, CONFIRMED `store.py:5313-5325`; unbound home → "could not be stored safely", CONFIRMED
T2aR concern A). The only product path that binds the store is the coordinator installing a
cloud context binding (§2.1). Therefore the order is:

```
pair  →  serve (idle)  →  browser "Authorize paired runner" = existing POST …/runner-context-bindings
      →  serve claims and installs the binding (store bound to ws/prj/env, origin = verified origin)
      →  heel runner credential add --role lower_plan  --plan-label <name> --profile … --backend keychain|secret-service
         heel runner credential add --role higher_plan --plan-label <name> …
      →  serve reports {role, plan_label} ×2 to the cloud on its next poll (§3.3)  →  access.ready
      →  browser Import OpenAPI → inventory  →  Prepare plan  →  runner compiles → approval request
      →  browser Approve  →  runner claims grant  →  execution (§4)
```

No local authority bypass (the store still requires the cloud-signed binding), no credential or
handle leaves the machine, and the existing binding preconditions stay (environment verified and
unexpired, runner and key active, one active binding per runner, CONFIRMED
`runner_contexts.py:600-700`). The binding is created **once per runner and environment**; it is
not re-created per plan (correction to launch spec §7.2 step 2; see §11).

### 3.2 Credential record rules (existing, unchanged)

`plan_label` optional, 1–32 printable ASCII, no edge whitespace, distinct between the two roles,
one record per semantic role, label never inferred (CONFIRMED `store.py:800-845, 7049-7067`,
`daemon.py:121-144`, `test_self_serve_access_requires_both_plan_labels_and_never_infers_them`).
`credential add` validates the secret shape against the bound origin
(`validate_credential_secret(profile, secret, origin)`, CONFIRMED `execution.py:420-423`,
`compiler.py:436-444`).

### 3.3 Label report and liveness (proposed, T3a-s server + T3b runner)

The runner reports labels in the body of the plan-request claim poll (§4 row 3): `credential_roles:
[{role, plan_label}]` (labels only; handles, profiles, backends and secrets are never sent). The
server stores `plan_labels_json` and `last_reported_at_ms` on the binding row (migration 30) and
`GET …/runner-context-bindings` surfaces `plan_labels` and `last_seen_ms` per binding so the Access
card renders `access.ready` and the Runner card `runner.offline`. The poll is the same call whether
or not a plan request exists, so the report costs no extra route.

### 3.4 Updating labels, removal, rotation, expiry (proposed, T3b)

- `heel runner credential set-plan-label --role <lower_plan|higher_plan> --plan-label <label>` →
  `RunnerStore.set_credential_plan_label(role, label)` (proposed; exclusive transaction,
  `_assert_plan_label_distinct`, handle and secret untouched). Prints role and label, never the handle.
- `heel runner credential remove --role <role>` → removes the record and deletes the vault item
  (existing `_set_credential_state(handle, None)` and `vault.delete`, `store.py:7117-7131`,
  `create_os_credential` rollback shape `:7138-7202`).
- Rotation = remove + add (new random handle). A pending approval whose local manifest names the
  old handle fails at `_resolve_credentials` with `credential_unavailable` (CONFIRMED
  `execution.py:391-430`), the run terminalizes `failed`, the dashboard shows the closed reason;
  the user prepares a new plan.
- Expired or revoked target credentials produce 401/403 for one or both plans; `evaluate_plan_pair`
  yields `held` or `inconclusive`, never a finding (CONFIRMED predicates
  `plan_differential.py:298-425`, launch spec §14).
- Label report/opaque handle boundary: cloud sees `{role, plan_label}` and the approval projection
  (no `credential_bindings`, CONFIRMED `validate_approval_projection` field set
  `canary_contracts.py:402-404`); the manifest with handles stays local (`save_approved_pair`).

### 3.5 Legacy standalone compatibility

`heel runner run --scope … --base-url …` binds or expects a *static* context named by the origin
(`_setup_store`, CONFIRMED `plan_differential.py:502-528`). A `HEEL_HOME` whose active context is a
cloud binding answers `mismatch` and the CLI returns the forced dry run with nothing sent
(`_prepare`, `:690-706`). Rule: the standalone CLI and the self-serve runner use **separate
`HEEL_HOME` directories**; no code change, documented in T6. Records written before T2a (no
`plan_label`) remain valid for the CLI (CONFIRMED `_credential_record` accepts both sets).

---

## 4. Decision 3 — browser Approve → cloud grant → local claim → target request → evidence → cloud finding

### 4.1 Immutable plan binding (Astra 3)

Everything the human approves and everything that executes must be bound into the signed,
immutable approval projection, never read later from mutable binding or inventory rows. The v1
projection cannot carry it (closed field set, CONFIRMED `canary_contracts.py:402-404`), so the
contract is extended rather than aliased:

- **`heel.approval-manifest-projection.v2` (proposed, T3a-s/T3b)** = the v1 fields plus one
  closed object `plan` = `{plan_kind: "plan_differential"|"regression", plan_request_id,
  plan_request_nonce, inventory_digest, selection_digest, selected_count, plan_labels: [{role,
  plan_label}] (two entries, roles fixed), max_ops, not_executed_count, not_executed_digest}`.
  It is inside `projection_digest`, signed by the runner key, and is what `grant.approval.
  projection_digest` binds (grant schema unchanged). `plan_sha256` in the UI and in `heel runner
  status` is this `projection_digest`. v1 stays valid only for catalog projections; a v2 object on
  a catalog projection or a v1 projection on a binding with an open plan request is rejected
  (`plan_binding_required`). None of the new keys is in `_FORBIDDEN_APPROVAL_KEYS` (CONFIRMED
  `canary_contracts.py:42-48`); `validate_approval_projection` is the single validator used by
  server, runner store, coordinator, executor and the browser client (CONFIRMED callers:
  `canary_runs.py`, `canary_disclosure.py`, `http_api.py`, `compiler.py`, `control_client.py`,
  `execution.py`, `runtime.py`, `store.py`; `lib/canary-api.ts:552` checks the schema id).
- **Snapshots.** A plan request row is immutable after creation: `plan_request_id`, a random
  `plan_request_nonce`, the `inventory_digest` of the inventory row at creation, the user's
  selected routes (§4 row 2) and their `selection_digest`, `max_ops`, `expires_at_ms` (24 h),
  `status` (open → projected → approved | expired | cancelled). The runner receives exactly that
  snapshot in the plan-request claim and echoes it in `plan`.
- **Server checks at submit** (`submit_projection_from_runner_in_transaction`, extended): the
  binding is the one the request names; the plan request is `open`, unexpired, belongs to this
  binding, and `plan.{plan_request_id, plan_request_nonce, inventory_digest, selection_digest,
  max_ops}` equal the row; every projection action (method, template) is in the selected set,
  and the selected set is in the inventory snapshot; `plan_labels` are the runner's own signed
  report (the human reads them from the projection, not from the binding row). Success marks the
  request `projected` with the `approval_id`; one projection per plan request
  (`UNIQUE(plan_request_id)` on the link); the existing `projection_id`/`projection_digest`
  uniqueness per project (CONFIRMED `canary_runs.py:482-500`) means the same projection cannot be
  replayed under a second plan request (`projection_conflict`), and a second projection for the
  same request is `plan_request_consumed`.
- **Later changes.** A new inventory upload or a label change after `projected` does not alter
  the pending approval; the approval list shows `inventory_changed: true` when the live inventory
  digest differs from the snapshot, and the human still approves the exact digest. Approval,
  claim and execution use only the projection (CONFIRMED `coordinator.claim` byte comparison
  `coordinator.py:417-421`; `validate_execution_bundle`). Regression replay reuses the same
  mechanism with `plan_kind: regression` and a one-pair selection.
- **Tests (named, T3a-s unless noted):** `test_v2_projection_binds_plan_request_nonce_inventory_selection_and_labels`,
  `test_projection_with_stale_inventory_or_selection_digest_is_rejected`,
  `test_same_projection_cannot_be_replayed_under_a_second_plan_request`,
  `test_v1_projection_on_a_binding_with_an_open_plan_request_is_rejected_and_v2_catalog_is_rejected`
  (schema/downgrade), `test_cloud_grant_plan_sha256_mismatch_sends_nothing` (T3b: the runner
  refuses a grant whose projection digest differs from its local v2 pair).

Legend: ✔ existing and CONFIRMED; ⊕ proposed (owner in brackets). Schema names in backticks.

| # | Segment | Mechanism | Owner | Schema / persistence |
|---|---|---|---|---|
| 1 | Inventory import | browser parses OpenAPI locally, uploads `heel.route-inventory.v1` (method + template only, ≤200, GET/HEAD, reject-never-truncate) ⊕ | T3a-s (server), T3a-e (Worker, UI client), T6 (page) | table `route_inventories` (migration 30): `environment_id`, `inventory_digest`, `route_count`, `routes_json`, `updated_at_ms` |
| 2 | Prepare plan | `POST …/runner-context-bindings/{rcb}/plan-requests` body `heel.plan-request.v1 {schema_version, plan_kind:"plan_differential", max_ops ≤ 20, routes: [{method, route_template}] (1–10 entries, each present in the current inventory; the user's selection, Astra 7)}` ⊕; owner/admin recent-auth same-origin (`_recent_owner_admin_context` ✔ `http_api.py:2278-2301`); the server snapshots the inventory digest and computes `selection_digest` | T3a-s (route), T6 (selection UI: default = first ten inventory rows, each row a checkbox) | table `canary_plan_requests` (§4.1 snapshot fields) |
| 3 | Runner learns the plan + inventory | `POST …/runners/{id}/contexts/{rcb}/plan-requests/claim` body `heel.runner-plan-request-claim.v1 {schema_version, binding_id, binding_digest, credential_roles}` (≤2 KiB, PoP `runner_claim` capability on the claim chain, exactly like `contexts/list`, ✔ `control_client.py:1236-1330`, `http_api.py:1357-1452`) → 204 none, or 200 `heel.runner-plan-request.v1 {plan_request_id, plan_request_nonce, plan_kind, max_ops, inventory_digest, selection_digest, routes[] (the selected routes only), expires_at_ms}` (≤64 KiB) ⊕ | T3a-s (route), T3a-e (Worker allowlist regex, harness mirror), T3b (control client method, daemon poll) | request `routes` stored locally by `store.replace_routes(routes, source_digest=inventory_digest)` ✔ `store.py:6906` with `operation_id = sha256(method+template)[:16]`, `placeholders` from `normalize_route_template` |
| 4 | Local compile | `plan_differential_pairs(routes, mapping)` ✔ `compiler.py:80-159` → pairs; unmapped placeholders → `not_executed: unbound_placeholder` ✔; `compile_plan_differential_pair(method, template, bindings)` ✔ `:374-408` for the slice (one pair); `compile_plan_differential_plan(pairs)` ⊕ T4b-r for ≤10 pairs (one `plan_entitlement_read` scenario, 2N actions, N ≤ 10 because `actions ≤ 20`, `maximum_requests ≤ 20`, findings observations ≤ 20 are contract caps, CONFIRMED `canary_contracts.py:307-316, 409, 645-660`) | T3b (one pair), T4b-r (plan) | local `save_approved_pair(manifest, projection)` ✔ `store.py:7297`; manifest holds handles, projection does not |
| 5 | Submit approval request | `submit_cloud_context_approval(projection)` ✔ `coordinator.py:570-577` → `contexts/{rcb}/approval-projections` ✔; server links projection to binding ✔ `canary_runs.py:456-514`; ⊕ server performs the §4.1 snapshot checks (`inventory_mismatch`, `plan_binding_required`, `plan_request_consumed`) and marks the plan request `projected` | T3a-s (server check), T3b (runner emits v2) | existing `canary_approval_projections` + `canary_runner_context_projection_links` (+ `plan_request_id`); `plan_sha256` **is** the v2 `projection_digest`, which now binds the `plan` object (§4.1) |
| 6 | Human review and Approve | `GET …/canary-approval-requests` ✔ (`routes`, `hostname`, budget; `canary_runs.py:1848-1911`) ⊕ enriched with the projection's own `plan` object (`plan_kind`, `inventory_digest`, `selection_digest`, `plan_labels`, `not_executed_count`, `max_ops`) and `inventory_changed` (live digest ≠ snapshot); `POST …/canary-runs/{run}/approve` with `projection_digest` + `hostname_retype` + reason, one-transaction quota reservation and signed grant ✔ `canary_runs.py:636-879` (`Meter.CANARY_RUNS`, unchanged) | T3a-s (enrichment), T6 (dialog copy) | grant `heel.execution-grant.v1` ✔ binds `approval.projection_digest`, `manifest_digest`, `egress.hostname`, runner key, nonce, ≤10 min expiry ✔ `canary_contracts.py:536-544` |
| 7 | Runner claims the grant | `coordinator.claim()` ✔ `coordinator.py:410-443`: `claim` POST, compares the cloud projection byte-for-byte with the local approved pair, `validate_execution_bundle`, installs gate and four chains | T2b-2 wiring, ✔ logic | local `reserve_run(grant)` consumes the grant exactly once ✔ `store.py:7452` |
| 8 | Target request | `RunnerExecutionAdapter.execute` ✔ → `LocalCanaryExecutor.execute(bundle, transport, gate_source=coordinator.execution_gate)` ✔; transport = `plan_differential._build_client(binding.origin)` ✔ built per run at claim time (DNS preflight pinned, public addresses only, verified TLS 1.2+, no redirects, 256 KiB cap) wrapped by ⊕ `_PerRunTargetTransport` (daemon glue; one client per lease, host must equal the binding origin host). Each attempt rechecks the live gate and budget before the socket opens ✔ `execution.py:651-713` | T4a | containment chain per action ✔ (`ContainmentLog(store, signer, run_id, grant_id, manifest_digest)`), raw response evidence `ev1_…` under the context run directory ✔ `store_response_evidence` |
| 9 | Live status, stop, revoke | heartbeat 0.25 s → gate; cloud Stop, runner revoke, environment revoke, kill switch → stop within 5 s with stop-ack ✔ (§2.3) | ✔ | `canary_runs` rows, events ✔ |
| 10 | Local result | `ExecutionResult` ✔ (operational projection, v1 findings projection, local view, disclosure preview) → `coordinator.result()` ✔ terminal anchor + detach; ⊕ plan-differential verdicts from local evidence: `_load_observations` by action ordinal ✔ `plan_differential.py:1293-1316` + `evaluate_plan_pair` ✔ `:398-425` → ⊕ local `plan-differential-report.json` in the run directory (pair verdicts, predicates, evidence refs, redaction counts) and `heel runner status` shows the last run summary | T4a | local only |
| 11 | Redacted projection to the cloud | ⊕ `heel.plan-differential-result.v1` (launch spec §7.3; per-pair rows with verdict/predicate/reason/evidence_state, status codes, body shapes, key-path counts, byte counts, `ev1_` refs; `requests_sent`, `retries_used`, `redaction_count`, `plan_sha256`=`projection_digest`, `containment_head_digest`, runner signature; forbidden keys inherit `_FORBIDDEN_FINDINGS_KEYS`); uploaded on the existing `result-projection` route under the existing disclosure permit (`validate_disclosure_permit.projection.schema_version` enum extended; `pair_count`/`finding_count` ≤ 10) | T4b-c (contract, upload, table), T4b-r (runner projector and upload) | table `plan_differential_results` (migration 31) keyed by `run_id`; retention `FINDINGS_RETENTION_MS` ✔ |
| 12 | Permit without manual copying | today the browser says "Return to the local runner to upload this exact summary" (CONFIRMED `dashboard/page.tsx:374`): a manual transfer, forbidden by §11.1 item 3. ⊕ runner polls `POST …/runners/{id}/runs/{run}/disclosure-permits/claim` (PoP, result chain; 204 / 200 permit / 200 `{state:"local_only"}`) for runs in `terminal, local_result_ready` until uploaded or local-only | T4b-c (route), T4b-r (poll) | existing `canary_disclosure` permit rows ✔ `canary_disclosure.py:531,872` |
| 13 | Dashboard finding | `GET …/canary-runs/{run}/plan-differential-result` ⊕ renders `findings.visible` rows; v1 catalog findings route stays for catalog runs | T4b-c (API), T4b-u (dashboard rows and client), T6 (copy) | — |
| 14 | Regression save/replay | launch spec §7.4 ✔ design; replay = plan request of kind `regression` limited to one pair, verdict rules of `heel/regressions.py` ✔ | T5 | tables `regressions` (migration 30) |

**Source of a real response-derived finding.** The verdict for a pair is computed only from the
two stored response bodies and status codes the runner received (`_load_observations` reads
`ev1_*` evidence written by the executor's evidence sink from the live socket, CONFIRMED
`execution.py:716-731`, `plan_differential.py:1293-1316`). Nothing in the projection path, the
dashboard or a fixture can inject a verdict: the projection is signed by the runner key and the
server re-verifies signature and digests (`canary_disclosure.get`, CONFIRMED `:1042-1072`).

**Evidence correlation without leakage (§11.1 item 5).** Every target request carries the
executor's attempt permit bound to `action_ordinal`, `attempt`, `grant_id`, `run_id`; the
containment chain names them before the socket opens (`action_started`, CONFIRMED
`execution.py:699-705`). The target's own access log records method, path and time. Correlation
key for the T8 reviewer: `(run_id, action_ordinal, attempt)` ↔ target log line ↔ `ev1_` reference
in the projection row ↔ containment entry. Credentials appear in none of these: request headers
are redacted before evidence write (CONFIRMED `test_i5_credential_plaintext_absent_from_heel_home_and_output`), the projection has no header or body values (forbidden keys), and the
target log is the operator's.

---

## 5. Decision 4 — gate consistency, real HTTPS test targets, labelled seams

1. **T2b proves control-plane behaviour only.** Its three gate tests (§9) prove: real binding
   claim over the TLS edge harness; outage → `offline` state → resume with a fresh heartbeat; owner
   revoke → `serve` exits `runner_revoked` within one idle poll (≤5 s) and makes no further call.
   They do **not** prove target-traffic stop; a no-op executor cannot prove it and is not used
   as evidence.
2. **T4a proves target-traffic stop ≤5 s** with `test_cloud_run_revoke_stops_target_traffic_within_five_seconds`
   and `test_cloud_run_browser_stop_cancels_in_flight_target_socket_within_five_seconds`: the
   real HTTPS test application's access log shows no request later than revoke/stop + 5 s, and the
   stop-ack reaches the server before the deadline (`STOP_DEADLINE_MS`, CONFIRMED `canary_runs.py:40`).
3. **Real HTTPS test target.** `tests/support/synthetic_tls_target.py` (proposed, T4a): the existing
   `SyntheticTarget` business logic (CONFIRMED `tests/plan_differential_support.py:130-196`:
   deterministic plan-gated JSON from its own handlers) served by a `ThreadingHTTPServer` with
   TLS 1.2+ from `EphemeralCA` (CONFIRMED `tests/support/edge_tls_harness.py:117-178`) and an
   access log `(ts, method, path, status)` for receipts. It obeys production rules: the runner's
   client is the production `TargetHTTPSClient` with the production `TLSTransport` verifying the
   chain and hostname, `GET`/`HEAD` only, redirects refused, host pinned, signed grant and reserved
   attempt per request.
4. **The one runner-side seam, labelled SEAM-TARGET-DIAL.** `TargetHTTPSClient` refuses non-global
   addresses by design (CONFIRMED `http_transport.py:157-175`, `test_r21_production_client_construction_is_unseamed`),
   and a loopback target cannot change that. T4a tests therefore replace the one module attribute
   `plan_differential._build_client` (the precedent accepted since T1, CONFIRMED
   `docs/PLAN_DIFFERENTIAL_RUNNER.md:227-243`) with a factory that returns the production client
   over a resolver answering one fixed public address and a socket connector that dials the
   loopback TLS port, **keeping the production `TLSTransport`** (the existing `PassThroughTLS`
   is not used). The ephemeral CA is trusted through `SSL_CERT_FILE` in the test process only
   (documented operator trust boundary, CONFIRMED `test_r23_ca_trust_follows_openssl_default_locations`).
   Every T4a/T5 test and review names this seam; T8 uses none (deployed staging target with a
   public address and a real certificate).
5. Other labelled seams, unchanged: the TLS edge harness with its ephemeral CA bundle argument
   (SEAM-EDGE-CA) and an injected `OSSecretBackend` (SEAM-SECRET-BACKEND). Nothing else; no
   mocked runner transport, scripted responder or canned finding is integration evidence.

---

## 6. Decision 5 — R-B: active-runner quota rejection is indistinguishable from "pending"

Today `activate`/`activate_executable` raise `RunnerAuthError("runner quota exceeded")`
(CONFIRMED `runner_auth.py:1644-1645, 1764-1766`), the handler maps every `RunnerAuthError` to
`400 invalid_runner_pairing` (CONFIRMED `http_api.py:1128-1151`), and the daemon treats 400 as
"not yet approved" and polls to challenge expiry (CONFIRMED `daemon.py:432-453`).

Design (proposed, T2c), preserving quotas and auth contracts (free `active_runners = 1`, no pricing change):

- **Owner-visible, before the ceremony.** `_runner_pairing_invite` refuses to create an invitation
  when the workspace's active runner count already equals `Meter.ACTIVE_RUNNERS` (`runner_active_limit`
  logic, CONFIRMED `http_api.py:352-363`): `402 {"error":"runner quota exceeded","code":"runner_quota_exceeded","meter":"active_runners"}`
  (the existing quota status, CONFIRMED `:2218-2220`). The dashboard shows "Revoke the existing
  runner first" with the existing revoke action. No pairing row is written.
- **Closed at activation (race-safe).** `RunnerQuotaExceeded(RunnerAuthError)` raised by both
  activation paths; the activate handler maps it to `402 {"schema_version":"heel.runner-error.v1","code":"runner_quota_exceeded"}`
  (same shape as the existing 410 `runner_activation_receipt_expired`, CONFIRMED `:1144-1149`).
  The pairing row stays `approved` until its 10-minute expiry; nothing is activated.
- **Daemon.** `_await_activation` maps `402 runner_quota_exceeded` → `RunnerPairingError("runner_quota_exceeded")`
  immediately (no further poll), leaving the record `exchanged` so `status` reports
  `pairing_incomplete` with next steps `heel runner unpair` and a fresh invitation after the owner
  revokes a runner. Only the holder of the approved pairing key can observe this code; it reveals
  that the workspace reached its runner quota, which the owner already knows.
- Tests: `tests/test_runner_control_http.py::test_http_runner_invite_and_activation_refuse_with_closed_quota_code_at_the_limit`,
  `tests/test_runner_daemon.py::test_pair_reports_runner_quota_exceeded_without_polling_to_expiry`
  (asserts one activation POST, zero sleeps to expiry), Worker passthrough of 402 asserted in
  `runner-edge-route.test.ts` if the Worker filters statuses (INFERRED not; confirm by reading
  `controlPlaneRoute` before writing the test).

## 7. Decision 6 — R-C: second open invitation returns 500

Cause CONFIRMED (R4R §7): `invite` inserts an `invited` row with `runner_id=""` and the table has
`UNIQUE(workspace_id, runner_id)` (`runner_auth.py:98-104, 1530-1551`); the handler catches only
`ValueError`/`RunnerAuthError` (`http_api.py:1066-1074`).

Options weighed: **reuse** is impossible (the raw token is never stored, only its hash); **409
`invitation_open` with `expires_at`** makes the owner wait up to 10 min or consume a token they may
have lost; **reissue** gives the owner an immediate new token and invalidates the old one, which is
the safer outcome for a bearer secret that may have been exposed. Chosen: **reissue**.

Design (proposed, T2c): inside `invite`'s existing `BEGIN IMMEDIATE`, delete the workspace's rows
with `status='invited' AND runner_id=''` before the insert, then insert as today; audit record
`runner_invitation_reissued` with the owner actor. Rows already exchanged (`pending`, `approved`,
`activated`; `runner_id` set) are untouched, so a runner mid-ceremony is unaffected. Concurrency:
two owner clicks serialize on the write transaction; the last token wins; the first exchange with a
superseded token gets the existing `400 invalid_runner_pairing` (invitation_rejected on the daemon,
CONFIRMED `daemon.py:412-414`), fail closed, nothing persisted. No widening: the deletion is scoped
by `workspace_id`; the route keeps `_recent_owner_admin` (same-origin `Origin` + `X-Heel-Internal-Origin`,
recent session ≤15 min, owner/admin role, cookie principal only, CONFIRMED `http_api.py:2278-2301`),
so a cross-site page or an API key cannot reissue. The invitation is still single-use, 10-minute,
workspace-bound (existing tests `test_runner_pair_cli_refuses_reused_invitation_and_wrong_origin`,
`test_invite_token_wrong_workspace_rejected`).
Tests: `tests/test_runner_control_http.py::test_http_second_open_invitation_reissues_and_invalidates_the_first`
(first token → 400 at exchange; second pairs; one `invited` row at any time; cross-workspace owner
cannot clear it), plus the existing CSRF/origin assertions re-run on the invite route.

## 8. Decision 7 — R-A: raw `FileNotFoundError` on the first lock of concurrent first-time pairs

Scope exactly R23R's: `heel/runner/store.py::_flock` (`os.open(filename, O_CREAT, dir_fd=…)`,
CONFIRMED `store.py:708-727`) retries once on `FileNotFoundError` (the macOS `openat` race while the
directory is being created) or pre-creates with `O_EXCL` ignoring `EEXIST`; every loser of a
first-time pair storm must raise a closed `RunnerPairingError` code. Test
`tests/test_runner_daemon.py::test_first_time_pair_storm_losers_raise_closed_codes` (8 threads, fresh
home). Placement: **T2d, after T2b-2 and before T3a-s** — independent of the serve loop, but the
serve tests start concurrent processes on one home, so the fix should land before the T3 runner
tasks build on that behaviour. `store.py` is a shipped module, so T2d regenerates the three download
artifacts. Not folded into any daemon task.

---

## 9. Decision 8 — re-split backlog in dependency order

Rules for every task: one fresh Opus session; allowed files exhaustive (≤10 source files per
task; the three regenerated download artifacts are mechanical scope and are listed and counted
separately); tests written before or with the implementation; DCO-signed small commits with the
exact model trailer; then a fresh Fable review (FAIL blocks the next task; ≤3 remediation cycles
per property). **Verification order (Astra 5), fixed:** (1) focused tests red then green while the
source is being finished; (2) **after the implementation source is final**, regenerate the three
download artifacts with the unchanged deterministic builder from the pinned release venv, run
`scripts/build_open_core_release.py --check` (EXIT 0) and record the artifact digests and the
source fingerprint; (3) affected suites (which include the release checks and would predictably
fail on stale artifacts); (4) the full Python suite against the §1.2 baseline, plus the JS suites
when `apps/heel-cloud` changes; (5) commit, with the diff hash recorded before the commit as R4
did. Any later source change repeats from (2). **Mechanical scope rule:** any task that changes a
shipped public Python module (`release/open-core-v1.json` `python_modules`) regenerates exactly
`apps/heel-cloud/public/downloads/{heel_sim-1.2.0-py3-none-any.whl, heel_sim-1.2.0.tar.gz, manifest}`;
a new public module also adds its path to `release/open-core-v1.json` and the two pinned lists in
`tests/test_open_core_release.py` (`:184,186,964`). Internal version stays `1.2.0` until T7.
Target applications in tests obey §5.

### 9.1 Tasks

| # | Task | Allowed files (exhaustive) | Gate tests (must be green before review) |
|---|---|---|---|
| **T2b-1** | Grant-authority bootstrap at activation (§2.2): v4 activation response with `grant_authority`, replay validator accepting v3 and v4 receipts, runner-side validation, daemon record transition, `status` check | Source (7): `heel/saas/runner_auth.py`, `heel/runner/store.py` (`_activation_response` only), `heel/runner/daemon.py`, `tests/test_runner_control_http.py`, `tests/test_runner_public_client.py`, `tests/test_runner_daemon.py`, `docs/PLAN_DIFFERENTIAL_RUNNER.md`. Mechanical: the three download artifacts | `test_runner_daemon.py::test_real_pairing_over_tls_edge_harness_activates_persists_heartbeats_and_revokes` extended to assert the record's key id equals the harness control plane's `grant_authority.key_id` and the public key verifies a binding signed by it; `test_runner_control_http.py::test_v4_activation_response_carries_the_grant_authority_and_replays_byte_identically`; `test_runner_daemon.py::test_status_reports_cloud_authority_missing_for_a_legacy_record_and_unpair_still_works`; `test_runner_control_http.py::test_old_and_new_activation_peers_fail_closed_with_response_rejected`; red-team: a tampered or extra `grant_authority` field is rejected on both sides |
| **T2b-2** | `heel runner serve` loop (§2.1, §2.3, §2.4): composition, non-blocking instance lock, cycle/backoff/resume, signals, state file, `status --offline` reading it, `_ExecutionUnavailable` | Source (6): `heel/cli.py`, `heel/runner/daemon.py`, `heel/runner/coordinator.py` (adapter glue only, if any), `tests/test_runner_daemon.py`, `tests/support/edge_tls_harness.py` (upstream pause/resume helper only), `docs/PLAN_DIFFERENTIAL_RUNNER.md`. Mechanical: the three download artifacts | `test_runner_serve_claims_a_context_binding_and_reports_access_over_tls` (owner creates the binding over the harness; serve installs it; `credential add` ×2 then succeeds against the cloud-installed context and `status --offline` shows `access.ready`; this also confirms the §2.3 INFERRED item); `test_runner_serve_offline_shows_offline_state_and_resumes` (upstream paused → `offline` with backoff → resumed → `online`, fresh heartbeat required); `test_runner_serve_stops_within_deadline_on_revoke` (owner POST revoke → `revoked` exit within 5 s, zero later control calls); the four locking tests of §2.3, `test_serve_handles_sigterm_with_local_stop_and_exits_stopped`, `test_serve_exits_execution_unavailable_closed_without_traffic_or_traceback`; red-team: replayed server time, regressed control generation (existing coordinator tests re-run), disconnect mid-claim |
| **T2c** | Pairing hygiene: R-B (§6) and R-C (§7) | Source (7): `heel/saas/runner_auth.py`, `heel/saas/http_api.py` (invite + activate handlers only), `heel/runner/daemon.py` (`_await_activation` mapping only), `apps/heel-cloud/lib/canary-api.ts` (error code → message only), `tests/test_runner_control_http.py`, `tests/test_runner_daemon.py`, `apps/heel-cloud/tests/canary-api.test.ts`. Mechanical: the three download artifacts | the four tests named in §6 and §7; existing invite/origin/CSRF tests green |
| **T2d** | R-A first-lock ENOENT (§8) | Source (2): `heel/runner/store.py` (`_flock` only), `tests/test_runner_daemon.py`. Mechanical: the three download artifacts | `test_first_time_pair_storm_losers_raise_closed_codes`; `test_runner_vault.py`, `test_runner_stop.py` unchanged and green |
| **T3a-s** | Server side of inventory, plan requests (with user selection), v2 projection contract and §4.1 snapshot checks, label/liveness report, approval-request enrichment (§4 rows 1–3, 5–6; §3.3; §4.1). Loopback HTTP tests only; no edge | Source (8): `heel/saas/http_api.py`, `heel/saas/runner_contexts.py`, `heel/saas/canary_runs.py`, `heel/saas/migrate.py` (migration 30, additive), `heel/canary_contracts.py`, `tests/test_canary_http.py`, `tests/test_canary_migrations.py`, `tests/test_canary_contracts.py`. Mechanical: the three download artifacts (`canary_contracts.py` is shipped) | `test_inventory_put_rejects_non_get_head`, `test_inventory_put_rejects_more_than_200_routes_without_truncation`, `test_cloud_inventory_mismatch_rejects_plan`, `test_inventory_and_regressions_are_project_scoped` (inventory part), `test_plan_request_claim_returns_the_users_exact_selection_and_records_labels_only`, `test_new_routes_require_same_origin_and_recent_auth` (inventory + plan request), the four §4.1 binding tests; red-team: malicious OpenAPI (oversized, duplicate templates, unicode, traversal), forged labels with handle-like values rejected, cross-project inventory, selection outside the inventory |
| **T3a-e** | Edge and browser client for T3a-s: Worker allowlist regexes and body caps (inventory 64 KiB, plan request 2 KiB, plan-request claim 2 KiB), harness mirror, `CanaryApi` methods and v2 projection acceptance (`lib/canary-api.ts:552`) | Source (6): `apps/heel-cloud/worker/index.ts`, `apps/heel-cloud/lib/canary-api.ts`, `tests/support/edge_tls_harness.py` (route mirror), `apps/heel-cloud/tests/runner-edge-route.test.ts`, `apps/heel-cloud/tests/privacy-boundary.test.mjs`, `apps/heel-cloud/tests/canary-api.test.ts`. Mechanical: none | `runner-edge-route.test.ts` and `privacy-boundary.test.mjs` cover every new route (method, cap, same-origin rule); `canary-api.test.ts` accepts v2 and rejects an unknown schema; harness mirror parity test; `npm run test:unit`, `test:node`, typecheck, lint, build green |
| **T3b** | Runner plan cycle: plan-request claim (control client method), local inventory install, one-pair compile emitting the v2 projection with the `plan` object, submit; `credential set-plan-label` / `remove`; `status` shows `plan_sha256` (= v2 `projection_digest`) and `not_executed` (§4 rows 3–5, §3.4, §4.1) | Source (10): `heel/runner/control_client.py`, `heel/runner/daemon.py`, `heel/runner/compiler.py` (`plan` object only), `heel/runner/store.py` (`set_credential_plan_label` only), `heel/cli.py`, `tests/test_runner_control_http.py`, `tests/test_runner_daemon.py`, `tests/test_runner_cli.py`, `tests/test_runner_compiler.py`, `docs/PLAN_DIFFERENTIAL_RUNNER.md`. Mechanical: the three download artifacts | `test_cloud_grant_plan_sha256_mismatch_sends_nothing` (claim with a projection digest that differs from the local pair → nothing sent); `test_runner_serve_compiles_only_from_the_cloud_delivered_inventory_and_submits_one_pair`; `test_an_arbitrary_second_inventory_shape_binds_without_a_code_change` (two different inventories, no special case); `test_credential_set_plan_label_updates_the_label_and_never_prints_the_handle`; red-team: scope tamper (inventory route not in list), label inference attempts |
| **T4a** | **First target execution proof** (§4 rows 7–10, §5): `RunnerExecutionAdapter` wiring, `_PerRunTargetTransport` over `_build_client`, vault selection (`macos_keychain`/`linux_secret_service`), local plan-differential report, real HTTPS synthetic target support module | Source (6): `heel/runner/daemon.py`, `heel/runner/plan_differential.py` (expose `load_pair_observations`/`evaluate_plan_pair` for the report; no executor change), new `tests/support/synthetic_tls_target.py`, new `tests/test_runner_serve_execution.py`, `tests/test_runner_plan_differential_safety.py` (seam-label assertions only), `docs/PLAN_DIFFERENTIAL_RUNNER.md`. Mechanical: the three download artifacts | `test_cloud_approved_pair_executes_against_a_real_https_target_with_receipts` (approve over the harness → claim → two real GETs → target access log lines correlated to `(run_id, action_ordinal, attempt)` and the containment chain → local report shows `observed/body_superset` derived from the stored `ev1_` bodies); `test_cloud_plan_run_refuses_origin_outside_grant`; `test_cloud_run_containment_entries_carry_workspace_project_runner_grant`; `test_cloud_run_revoke_stops_target_traffic_within_five_seconds`; `test_cloud_run_browser_stop_cancels_in_flight_target_socket_within_five_seconds`; `test_cloud_run_never_sends_credentials_to_heel_home_or_control_plane` (byte scan of the harness forwarded bodies and `HEEL_HOME`); `test_serve_refuses_a_catalog_projection_lease_with_execution_unavailable`; red-team: egress tricks (redirect route in the target), attempt replay (second claim of the same grant → nothing sent), oversized response, D1 denial-envelope closure through the cloud path |
| **T4b-c** | Cloud contract and server for the result projection (§4 rows 11–13): `heel.plan-differential-result.v1`, permit schema enum (`pair_count`/`finding_count` ≤10), `result-projection` upload branch, permit-claim route, `GET …/plan-differential-result`, table `plan_differential_results` (migration 31), Worker allowlist + harness mirror | Source (10): `heel/canary_contracts.py`, `heel/saas/canary_disclosure.py`, `heel/saas/http_api.py`, `heel/saas/migrate.py`, `apps/heel-cloud/worker/index.ts`, `tests/support/edge_tls_harness.py`, `tests/test_canary_privacy.py`, `tests/test_canary_disclosure.py`, `tests/test_canary_http.py`, `apps/heel-cloud/tests/runner-edge-route.test.ts`. Mechanical: the three download artifacts (`canary_contracts.py` is shipped) | `test_plan_differential_result_projection_is_bounded_and_bodyless`, `test_result_projection_rejects_header_and_body_values`, `test_permit_claim_route_returns_204_permit_or_local_only_and_consumes_once`, `test_result_projection_upload_requires_terminal_result_and_matching_permit`; red-team: forged projection/reference, duplicate upload, projection for another run, permit for another run |
| **T4b-r** | Runner side: `compile_plan_differential_plan` (≤10 pairs, one scenario, 2N actions), the plan-differential projector (verdicts from local evidence → signed result projection), permit-claim poll, upload through `coordinator.upload_findings`-style verification with the new schema | Source (7): `heel/runner/compiler.py`, `heel/runner/control_client.py`, `heel/runner/daemon.py`, `heel/runner/plan_differential.py` (projector only), `tests/test_runner_serve_execution.py`, `tests/test_runner_compiler.py`, `tests/test_runner_control_http.py`. Mechanical: the three download artifacts. Depends on T4b-c | `test_result_projection_verdict_is_derived_from_captured_response_digests` (the uploaded row's `evidence_refs` resolve to local evidence whose body digest produced the verdict; a projection with a verdict not supported by its refs is rejected locally), `test_permit_claim_poll_uploads_once_and_local_only_stops_polling`, `test_ten_pair_plan_executes_twenty_requests_and_rows_match_the_access_log` (real HTTPS target, §5) |
| **T4b-u** | Dashboard: `CanaryApi` methods for the result projection, `findings.visible` rows, `plan.review` showing the v2 `plan` object and `inventory_changed`, route selection control for "Prepare plan" (default first ten, checkboxes) | Source (8): `apps/heel-cloud/lib/canary-api.ts`, `apps/heel-cloud/components/canary/ApprovalDialog.tsx`, `apps/heel-cloud/components/canary/RehearsalStep.tsx`, new `apps/heel-cloud/components/canary/PlanFindings.tsx`, `apps/heel-cloud/app/dashboard/page.tsx`, `apps/heel-cloud/tests/canary-api.test.ts`, `apps/heel-cloud/tests/canary-activation.test.tsx`, `apps/heel-cloud/tests/product-contract.test.tsx`. Mechanical: none. Depends on T4b-c | component tests render every verdict/predicate/evidence_state combination from a fixture that is the exact server schema; no finding text is derived client-side; `test:unit`, `test:node`, typecheck, lint, build green |
| **T5** | Regressions from product + quotas + runner-revoke UI (launch spec §7.4, §7.6) | as launch spec §12 T5, plus `apps/heel-cloud/app/dashboard/page.tsx` (runner Revoke control) | `test_regression_replay_reserves_once_under_retry`, `test_regression_replay_reaches_the_real_target_before_and_after_its_patch` (`fail/still_reachable` → `pass/blocked` with receipts), `test_metrics_and_structured_logs_never_contain_handles_or_secrets`, `test_runner_revoke_button_calls_the_post_revoke_route` |
| **T6** | Product surface and truthful copy (launch spec §12 T6; adds `runner.authorized`, `access.*`, `plan.*`, `findings.visible` states; separate-`HEEL_HOME` note; no live-execution claim before T8) | as launch spec §12 T6 | as launch spec §12 T6 |
| **T7** | Release 1.3.0 and deployment (unchanged) | as launch spec §12 T7 | as launch spec §12 T7 |
| **T8** | Clean-room acceptance (launch spec §11 as reordered in §10 below, and §11.1) | none | verbatim YES with evidence or FAIL |

Dependency order: T2b-1 → T2b-2 → T2c → T2d → T3a-s → T3a-e → T3b → T4a → T4b-c → T4b-r → T4b-u → T5 → T6 → T7 → T8.
T2c and T2d may run in parallel with each other, and T3a-e with T3b, on separate commits;
nothing else overlaps. Each task is one session; "may be two sessions" wording is removed.

### 9.2 Interim real vertical-slice gate (after T4a, before any UI polish)

A fresh Fable session reproduces, over the TLS edge harness and the real HTTPS synthetic target
(SEAM-EDGE-CA, SEAM-SECRET-BACKEND, SEAM-TARGET-DIAL labelled), with the released-shape CLI from
the regenerated wheel: pair → serve → authorize binding → two credentials with labels →
inventory upload → plan request with a one-route selection → one-pair approval → Approve → two real target requests with
access-log receipts → local `observed/body_superset` report → revoke mid-run on a second plan →
traffic stops ≤5 s. PASS here is **not** launch acceptance: no deployed Worker, no public
address, no cloud finding row yet (T4b-c/T4b-r), no regression (T5).

### 9.3 Immediate next Opus assignment: T2b-1

Fresh Opus, root this worktree at `d9455b4` or later docs commit, allowed files exactly as the
T2b-1 row. Steps: (1) write every gate test of the T2b-1 row red: the extended real-pairing gate,
`test_v4_activation_response_carries_the_grant_authority_and_replays_byte_identically`,
`test_status_reports_cloud_authority_missing_for_a_legacy_record_and_unpair_still_works`,
`test_old_and_new_activation_peers_fail_closed_with_response_rejected`, and the tampered/extra
field red-team cases on both sides; (2) add `grant_authority` to the v4 activation response in
`RunnerAuthStore.activate_executable` and make the replay validator accept stored v3 and v4
receipts byte for byte; (3) validate and carry it in `RunnerStore._activation_response` only
(§2.2 persistence bullet) and copy it into the daemon record in `RunnerDaemon.pair`, with the
record transition of §2.2; (4) `status` and `serve` fail closed `cloud_authority_missing`
without it while `unpair` still works; (5) focused (`tests/test_runner_daemon.py tests/test_runner_control_http.py
tests/test_runner_public_client.py tests/test_runner_identity.py tests/test_runner_vault.py
tests/test_runner_cli.py`) green with the source final; (6) regenerate the three artifacts from
the pinned release venv, `--check` EXIT 0, record digests and source fingerprint; (7) affected
(`tests/test_canary_http.py tests/test_runner_coordinator.py tests/test_open_core_release.py
tests/test_runner_plan_differential_release.py`) → full Python suite; any source change after
(6) repeats from (6); (8) small DCO commits with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`,
diff hash recorded before committing; (9) closing report with counts and exit codes. No `serve`
command in this task.

---

## 10. Decision 9 — test mapping, clean-room steps, 15-minute goal

- Launch spec §10 rows updated in the same commit series (task names as re-split in §9.1): row 3 proposed test owner T3b; row 10
  keeps `test_runner_serve_stops_within_deadline_on_revoke` (T2b-2, control-plane only) and adds
  `test_cloud_run_revoke_stops_target_traffic_within_five_seconds` (T4a) as the target-traffic
  proof; row 12 keeps `test_runner_serve_offline_shows_offline_state_and_resumes` (T2b-2); rows 1,
  2, 4, 5, 6 point at T3a-s/T3a-e/T4a/T4b-c/T4b-r as in §9.1.
- Launch spec §11 clean-room steps reordered: step 5 (pair) → **step 6a** browser "Authorize paired
  runner" + `heel runner serve` on the machine → **step 6b** the two `credential add` commands with
  `--plan-label` → step 7 import → step 8 Prepare plan (`projection_digest` shown on both sides) →
  step 9 Approve → …; step 11 reads the local plan-differential report (`heel runner status` last
  run summary and the `ev1_` files under the context run directory). Final acceptance remains
  deployed staging, public address, real certificate, no seam.
- **First useful finding ≤15 min** stays the measured final goal (T8 step 15). Latency budget added
  by this design: idle poll 2 s (binding claim, plan request and permit polls share the cadence),
  DNS preflight ≤5 s, approval → first request ≤ 2 s poll + preflight. Nothing here is
  human-paced except the browser steps already counted.

---

## 11. Corrections to the launch spec made in this commit series

1. §7.2 step 2: "Prepare plan" is **not** a new context binding; the binding is created once per
   runner and environment, and a plan request is a separate record (§4 row 2). Reason: one active
   binding per runner (`runner_contexts.py:639-644`), credentials namespaced by environment.
2. §7.2 bounds: launch executes **≤10 pairs / ≤20 requests per approved run** (contract caps
   `actions ≤20`, `maximum_requests ≤20`, findings observations ≤20). The user **selects** which
   inventory routes a plan covers (1–10, an immutable input of the plan request, §4.1; Astra 7),
   so a larger inventory is covered by several plans over different selections, not by repeating
   the first ten. Routes in the selection whose placeholders have no local mapping are
   `not_executed: unbound_placeholder`. The earlier "≤50 pairs, ≤100 requests" would require
   raising four contract caps and is deferred, not required for launch; the safety caps are not
   raised as a workaround.
3. §7.2: `plan_sha256` is the v2 approval `projection_digest`, which binds the immutable `plan`
   object (`plan_kind`, `plan_request_id`, `plan_request_nonce`, `inventory_digest`,
   `selection_digest`, `plan_labels`, `max_ops`, `not_executed_count`, `not_executed_digest`);
   nothing the human approves is read later from a mutable row (§4.1; Astra 3).
4. §7.1: the runner receives the inventory in the plan-request claim response, not in the context
   claim response (closed schema `heel.runner-context-claim-result.v1`, `control_client.py:1292-1300`).
5. §7.5: labels travel in the plan-request claim request body, not in the context claim request.
6. §6: new state `runner.authorized` between `runner.active` and `access.*`; `access.*` requires a
   claimed binding.
7. §12: backlog replaced by §9.1; §13 owners updated; T2b split; T3/T4 re-split.
8. §11: steps 6a/6b as in §10.

## 12. Open items (INFERRED, each with its confirming action and owner)

| Item | Confirming action | Owner |
|---|---|---|
| `credential add` succeeds against a cloud-installed binding without trusted keys | T2b-2 gate test (first row) | T2b-2 |
| `last_heartbeat_at_ms` is updated on every authenticated runner call | read `authenticate_and_consume` around `runner_auth.py:2961`; test before exposing `last_seen_ms` | T3a-s |
| Worker passes 402 from the activation route unchanged | read `controlPlaneRoute` in `apps/heel-cloud/worker/index.ts` | T2c |
| `security -i` / Keychain vault round trip for `credential add` under `serve` concurrency | T2b-2 real-Keychain acceptance record (pair → serve → credential add ×2 → status) | T2b-2 Opus, repeated by Fable |
| Ten pairs in one manifest validate end to end (`actions ≤20`, observations ≤20) | T4b-r compiler test | T4b-r |
| `fcntl.flock(LOCK_EX combined with LOCK_NB)` on the `.serve.lock` descriptor opened with `_LOCK_FLAGS` behaves identically on macOS and Linux (kernel release on death) | the four locking tests of §2.3, run on macOS locally and on Linux in CI | T2b-2 |
