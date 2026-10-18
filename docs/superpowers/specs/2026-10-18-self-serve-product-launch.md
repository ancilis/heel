# Heel self-serve product launch — T1 reality audit, baseline and launch specification

Date: 2026-10-18. Branch `feat/self-serve-product`, forked from exact
`6a2923ba4f01f3e3393dcb8b7bd8a94af82b3dcb` (PR #41 head, base `main` @ `844fc1f`).
Author: Claude Fable 5.1, fresh interactive session (T1). Role: audit, baseline, product and
security design, acceptance design. **This document contains no product code and makes no
launch claim.** It is the contract for the bounded Opus implementation tasks and the Fable
reviews that follow (§12), and for the final clean-room acceptance (§11).

Every load-bearing claim is tagged **CONFIRMED** (with the command, test, URL, artifact or
`file:line` that proves it) or **INFERRED** (with the action that would confirm it). Artifacts
live outside the tree in `.git/self-serve-launch/sessions/T1-artifacts/` of the original
checkout; names below refer to that directory.

Normative words: **MUST**, **MUST NOT**, **MAY**.

---

## 1. Baseline (captured before any tracked change)

Nothing tracked changed during the audit (`git status --short` empty before and after every
step; recorded at the end of every baseline log). PR #41 is OPEN, `MERGEABLE`, all 11 checks
`SUCCESS` (CONFIRMED `gh pr view 41 --json statusCheckRollup`, 2026-10-18). Its head equals this
branch's base, so hosted CI on Linux is green for exactly the audited tree.

### 1.1 Commands discovered from repository configuration

| Source | Command | Artifact |
|---|---|---|
| `.github/workflows/ci.yml` `test` (py3.11–3.14) | venv; pip `cryptography==45.0.7 pytest==9.0.2`; `dnspython==2.8.0` by hash; `python -m pytest -q tests`; `python run_demo.py`; `python scripts/saas_smoke.py`; `heel.saas.site.build` | `python-baseline-v2-py313.log`, `python-baseline-py313.log`, `python-baseline-py311.log` |
| `ci.yml` `package` | `pip --require-hashes -r release/requirements-release.txt`; `scripts/build_open_core_release.py --check`; `HEEL_REQUIRE_STANDARD_BUILD=1 unittest tests.test_open_core_release`; install committed wheel, MCP lifecycle | `python-package-release-check.log` |
| `ci.yml` `ui` (Node 22) | `web/`: `npm ci && npm run build` | `js-baseline.log` |
| `ci.yml` `browser-alpha` (Node 26) | `apps/heel-cloud`: `npm ci --ignore-scripts`; `build_browser_engine.py --check`; `build_browser_sample.py --check`; `node --test tests/browser-engine.test.mjs`; `npm run test:unit`; `typecheck`; `lint`; `npm run build` (fixture env); `npm run test:node` | `js-baseline.log`, `js-test-node-python313.log`, `python-package-release-check.log` |
| `Makefile` | `make test` = `unittest discover`; `PY ?= python3` | (see 1.3) |

### 1.2 Results (CONFIRMED by the named logs; exit codes captured unpiped in the v2 run)

| Suite | Interpreter / tool | Result |
|---|---|---|
| `pytest -q tests` | Python 3.13.5, venv under `$HOME/.cache` | **1 failed, 1752 passed, 2 skipped, 36 warnings, 653 subtests passed** in 306 s; pytest exit 1 (`python-baseline-v2-py313.log`, full output `python-baseline-v2-py313-pytest-full.log`) |
| same | Python 3.13.5, venv under `/private/tmp` | 145 failed, 1608 passed, 2 skipped (`python-baseline-py313.log`) |
| same | Python 3.11.13, venv under `/private/tmp` | 145 failed, 1608 passed, 2 skipped (`python-baseline-py311.log`) |
| `run_demo.py` | 3.13 | exit 0, auth gate PASS |
| `scripts/saas_smoke.py` | 3.13 | `SMOKE PASS`, exit 0 (signup → synthetic run → target verify → scope guard → checkout 503 → kill switch 503 → metrics) |
| site build | 3.13 | exit 0 |
| release `--check` + `test_open_core_release` | 3.13 | exit 0; `Ran 18 tests … OK`; browser engine and sample `--check` exit 0; committed wheel installs with `heel.saas` absent and answers `initialize`/`tools/list` with 23 tools |
| `apps/heel-cloud` | Node v25.9.0, npm 11.12.1 | `npm ci` 0; browser-engine 5/5; vitest **202 passed (18 files)**; typecheck 0; lint 0; build 0; `test:node` **69 pass / 1 fail** with system `python3`, **70/70** with Python 3.13 first on PATH |
| `web` | Node v25.9.0 | `npm ci` 0; `next build` 0 |

Node note: CI pins Node 26 for the browser job and 22 for `web`; the local Node is 25.9.0, which
satisfies `engines >=24.13.1` (`apps/heel-cloud/package.json`). INFERRED that results are
identical on 26; confirmed only by the green PR #41 checks.

### 1.3 Existing failures, each diagnosed to an environment cause (no product change made)

1. **145 runner runtime/stop failures under a `/tmp` venv.** `RunnerRuntimeCorrupt("runtime
   state helper is unavailable")` from `heel/runner/runtime.py:853-891` (`_start_inode_guard`),
   which refuses a `sys.executable` whose ancestor directory is world-writable; `/private/tmp`
   is `drwxrwxrwt`. Re-running with the venv under `$HOME/.cache` removes all 145
   (`python-baseline-py313-failure-diagnosis.log`, `python-baseline-v2-py313.log`). CI uses
   `$RUNNER_TEMP`, which is not world-writable. CONFIRMED.
2. **`test_demo_bench_is_fast_synthetic_benchmark`.** `make demo-bench` runs `python3` from
   PATH (`Makefile` `PY ?= python3`); macOS system Python 3.9.6 lacks `datetime.UTC` used at
   `scripts/demo_workflows.py:167`. With a 3.13 `python3` first on PATH the test and the whole
   module pass (8/8) (`python-baseline-v2-py313-residual-failure.log`). CONFIRMED.
3. **`apps/heel-cloud/tests/mcp-quickstart.test.mjs:16`** installs the committed wheel with the
   displayed `python3 -m venv` command; system Python 3.9.6 is rejected by
   `requires-python >=3.11`. With Python 3.13 first on PATH, 70/70 pass
   (`js-test-node-python313.log`). CONFIRMED.
4. The first baseline wrapper printed `EXIT=0` after the pytest line because the status was read
   after a `| tail` pipeline. The v2 script captures the unpiped status (`pytest EXIT=1`). The
   original log is preserved unmodified.

Net: **no product-attributable failure exists in the baseline.** The 2 skipped tests are not
identified by `-q`; INFERRED harmless, confirmable with `pytest -rs`.

### 1.4 Environment facts that bound later work

- Docker daemon not running locally (CONFIRMED `docker info` connection refused); the compose
  bundle was not executed here. Provider/account facts are in `sessions/T1D-closing.md` and
  `sessions/astra-sites-access.md`; they are evidence, not instructions, and are not repeated.
- Ancilis Brain `orient` returned no Heel-specific canonical memory (3 of 48 confirmed, none on
  Heel); `search_evidence` found only the Astra brief and the agent-first design. Nothing in this
  spec rests on canonical memory.

---

## 2. Proven current journey, step by step (what works, what is manual, what is missing)

Evidence: loopback control plane started from `python -m heel.saas.server` with generated
throwaway secrets (`control-plane-loopback-api-walk.log`), the cloud UI served by `vinext dev` in
`local_review` mode (`/`, `/dashboard`, `/agent`, `/runner`, `/device` all 200; proxy `/api/
control-plane/v1/me` 503 fail-closed), the committed public wheel installed into a clean venv
(`journey-synthetic-plan-differential.log`, `wheel-cli-surface.log`).

| # | DoD step | Today | Evidence | Verdict |
|---|---|---|---|---|
| 1 | Visit public HTTPS | Worker app builds and renders; no public deployment of the full mode exists; the only live URL is owner-gated (401 anonymous) | T1D §A; `js-baseline.log` build | **missing (deploy)** |
| 2 | Sign up / login via production auth | `POST /v1/signup` 201 with `__Host` session translation at the edge; login lockout, signup throttles, `X-Heel-Client-Key` required when edge-trusted | `http_api.py:1800-1835`, walk log | **works (API + UI)** |
| 3 | Create/select workspace/project | signup creates org+workspace (free, catalog 2026-08-24); `POST …/projects` 201; dashboard auto-selects first project | walk log; `dashboard/page.tsx:60-80` | **works** |
| 4 | Register/verify staging target | `POST …/environments` issues https-file or dns-txt challenge with exact ownership attestation; `check`/`revoke` routes; UI "Verify staging now" | `http_api.py:2730-2760`, `verification.py:224-311`, walk log (env_… pending) | **works** (real check needs a reachable public host) |
| 5 | Install public runner via one release command | wheel is committed under `apps/heel-cloud/public/downloads` and on raw GitHub; GitHub Release v1.2.0 has zero assets; no PyPI | `python-package-release-check.log`; T1D §B | **manual** (no one-liner yet) |
| 6 | Pair runner via browser/device | Server: invite → exchange → approve (phrase+fingerprint) → activate (v3 executable), rotate, revoke, resync all implemented and tested over HTTP; UI RunnerStep copy exists. **No runner-side command performs the exchange** (`heel runner --help`: `import-openapi, credential, map, prepare, run`); control client, coordinator and service exist only as library code driven by tests | `http_api.py:1066-1130`, `runner_auth.py:1530-2545`, `worker/index.ts:146-158`, `wheel-cli-surface.log`, dashboard copy "No customer-target pairing command is available in this release" (`dashboard/page.tsx:386`) | **missing (runner CLI)** |
| 7 | Store two local credentials with explicit free/pro labels | `heel runner credential add --role lower_plan|higher_plan --label … --backend ephemeral-env|ephemeral-fd|keychain|secret-service`; handle printed, label and secret never | journey log (two handles) | **works locally**; label is free text, not an explicit plan label shown in product |
| 8 | Import OpenAPI | CLI `heel runner import-openapi` keeps GET/HEAD only (12 routes from fixture); browser review parses OpenAPI locally but does not produce a runner inventory | journey log; `review-v1.ts` | **works CLI; missing from product** |
| 9 | Review dry-run | `heel runner run … --dry-run` prints plan, `plan_sha256`, `requests_sent: 0`; cloud approval projection flow shows scenario/route plan for mapped routes only (≤4) | journey log; `test_canary_http.py:292-420` | **works CLI; product shows mapped-route plan only** |
| 10 | Start plan-differential scan from product | Cloud approve → grant → runner claim → heartbeat/progress/result exists for the 4-scenario catalog (`plan_entitlement_read` included), but the full-inventory plan-differential runner is CLI-only (`R10` test) | `test_runner_plan_differential_safety.py:1026`; `canary_runs.py` | **missing (bridge)** |
| 11 | Live status / recovery | dashboard polls `/canary-runs/{id}` and `/events`; stop with generation; runner resync, pending-call replay, crash recovery tests | `test_canary_http.py:292-420`, `test_runner_coordinator.py` | **works for cloud-coordinated runs** |
| 12 | Undeclared observed/verified finding | synthetic journey from the public wheel: `GET /api/export` `finding/body_superset/observed`, exit 1, 18 requests, `held`/`inconclusive` rows as documented; marker path yields `verified` | journey log (`pdrun-53859157…`) | **works CLI** |
| 13 | Inspect redacted evidence | `heel findings --run` shows `[REDACTED:secret]` request refs and `ev1_…` response refs; raw bodies only under `$HEEL_HOME/plan-runs/<attempt>/`; zero credential bytes in `HEEL_HOME` (`grep` scan = 0 hits) | journey log | **works locally; not surfaced in product** |
| 14 | Save / replay regression | `heel regress add` then `regress run`: `fail/still_reachable` on vulnerable target, `pass/blocked` after hardening | journey log | **works CLI; not in product** |
| 15 | Revoke runner / target | `DELETE /v1/workspaces/{ws}/runners/{id}`, environment `revoke`, context-binding `revoke`; UI buttons | `http_api.py:965-1024`; `dashboard/page.tsx:279,409` | **works** |

Time to first finding today: the synthetic CLI journey took 4 minutes wall clock from `pip
install` to `observed` (05:20:39 → 05:24:37 in the journey log), with no account. The product
path cannot be timed because steps 6, 8–10 do not exist.

---

## 3. Reuse / gap matrix

| Capability | Existing foundation (reuse as-is) | Extend | New |
|---|---|---|---|
| Public edge | `apps/heel-cloud/worker/index.ts` exact allowlist, CSP, `__Host` cookie translation, edge auth | add the new routes of §7 to the allowlist | fixed-origin binding mode (§8.2) if no VPC service |
| Accounts, sessions, device auth | `heel/saas/auth.py`, `device_auth.py`, `cloud_auth.py` (`heel cloud login`) | — | — |
| Workspace/project/tenancy | `tenancy.py`, `projects.py`, `ledger.py`, `entitlement.py`, `catalog.py` (launch quotas `active_runners=1`, `canary_runs=10`) | regression records per project | — |
| Target verification | `verification.py` (`VerifiedEnvironmentService`, attestation, https-file/dns-txt), `network_guard.py` | — | — |
| Runner pairing / auth | `runner_auth.py` (PoP Ed25519, nonces, rotation, revoke, resync), `runner_contexts.py`, migrations 9–29 | — | **runner CLI `heel runner pair/serve/status/unpair`** |
| Run coordination | `canary_runs.py` (approval projection, grant, claim, chains, stop, reaper), `canary_store.py`, `canary_disclosure.py` | approval projection v2 carrying plan-differential plan; result projection for ≤100 route pairs | — |
| Runner execution | `heel/runner/{execution,compiler,adapters,catalog,http_transport,containment,redaction,store,vault}.py`, `plan_differential.py` | execute `run_plan_differential` under a cloud `ExecutionGate` | — |
| Route inventory | `heel runner import-openapi`, `openapi_routes.py` | — | cloud-stored minimized inventory (method + template only) submitted from the browser |
| Findings / evidence | `heel findings`, `heel log`, `companion.py` loopback viewer, `canary_contracts.validate_canary_findings` | dashboard finding list from the new projection | — |
| Regressions | `heel/regressions.py`, `heel regress add/run` | cloud regression record + replay run kind | — |
| Packaging | `scripts/build_open_core_release.py`, `release/open-core-v1.json`, deterministic wheel, `publish.yml` verify job | version 1.3.0, attach assets to the GitHub Release | — |
| Deployment | `deploy/compose.yaml`, `Dockerfile.control-plane`, `heel.saas.server` invariants, `scripts/saas_backup.py`, runbooks, kill switches (`ops.py`) | staging and production env files, Worker binding mode | — |
| Docs | `docs/PLAN_DIFFERENTIAL_RUNNER.md`, `docs/saas/*`, `docs/CAPABILITIES.md` | truthful state updates | runner pairing guide, legal/support pages |

The two planes that both exist today and MUST be reconciled, not duplicated: the legacy
"job plane" (`POST /v1/workspaces/{ws}/runs`, `/targets`, `jobs.py`, still reachable and
exercised by `saas_smoke.py`) and the verified-canary plane (`environments`, `canary-runs`,
`runners`). The launch journey uses only the canary plane; the legacy routes stay internal and
MUST NOT be added to the public Worker allowlist (they are absent today, CONFIRMED
`worker/index.ts:160-178`).

---

## 4. Final data flow (browser → API → runner → staging → evidence)

```
Browser (session cookie)           Public Worker (allowlist)        Private control plane (SQLite, 1 process)
  signup/login/me  ───────────────▶ /api/control-plane/v1/* ─────▶ auth, tenancy, projects
  environment start/check/revoke ─▶ (exact routes only)   ─────▶ VerifiedEnvironmentService (pinned HTTPS/DNS proof)
  route inventory (method+template)▶ NEW                  ─────▶ inventory row (digest), ≤200 routes, no raw OpenAPI
  pairing invite / approve ───────▶                       ─────▶ RunnerAuthStore (invite→exchange→approve→activate)
  context binding create/revoke ──▶                       ─────▶ RunnerContextBindingService (signed, 24 h)
  approval request list / approve ▶                       ─────▶ CanaryRunService: grant (signed, reserves quota)
  run status / events / stop ─────▶                       ─────▶ operational receipts only
  findings (bounded projection) ──▶                       ─────▶ result projection rows (no bodies)
  regression save / replay ───────▶ NEW                   ─────▶ regression record → new approval request

Customer machine: `heel runner serve` (outbound only, Ed25519 PoP, one-time nonces)
  claim ◀── grant + inventory digest ── control plane
  compile plan (routes ∩ inventory, GET/HEAD, two credentials from local vault by opaque handle)
  submit approval projection (plan_sha256, labels, route count)  ──▶ browser approves exact digest + hostname retype
  execute run_plan_differential under ExecutionGate: TargetHTTPSClient → https://<verified origin>:443 only
      raw request/response evidence → $HEEL_HOME (private), credentials replaced by [REDACTED:secret]
  heartbeat/progress (counts, phase) ──▶ control plane ──▶ browser live status
  result projection (per-route verdict, predicate, evidence refs, key-path counts) ──▶ control plane
  disclosure permit (human) ──▶ findings projection visible in dashboard; bodies never leave the machine
```

Invariants carried by this flow: the Worker never proxies to any origin but the configured
control plane (SSRF: no caller-controlled URL exists in `controlPlaneRoute`,
`worker/index.ts:466`); the control plane never sends target traffic (`canary_runs.py` docstring;
`EgressPolicy` default-deny for the legacy plane); only the runner holds credentials (opaque 32-hex
handles, `vault.py`); the cloud receives bounded, schema-validated projections
(`canary_contracts.py:645`, 256 KiB cap, ≤4 scenario results today, raised to ≤100 route
pairs in the new projection of §7.3).

---

## 5. Threat model and trust boundaries

Assets, boundaries and the eleven implemented controls in `docs/saas/THREAT_MODEL.md` remain
valid (CONFIRMED by the walk and tests cited in §10). Additions for the self-serve launch:

| Boundary | Trusted side | Untrusted input | Control (existing / required) |
|---|---|---|---|
| Browser ↔ Worker | Worker code, CSP nonce | everything from the browser | allowlist, `__Host` cookie only, body caps per route family (`worker/index.ts:120-145`), origin check for state changes (`http_api.py:1623,2281`) |
| Worker ↔ control plane | shared edge secret, fixed service binding | none (no caller URL) | `X-Heel-Edge-Auth` required for every route (`/v1/plans` without it → 401, walk log), `X-Heel-Client-Key` derived at the edge |
| Human ↔ runner pairing | browser session with recent auth | invitation token, phrase, fingerprint | one-time invitation, phrase+fingerprint compare in browser, activation signature, v3 executable protocol, rotation single-open ceremony, revoke with reason (`runner_auth.py`) |
| Runner ↔ control plane | runner Ed25519 key in OS keychain/secret-service | all responses | PoP headers, per-capability nonce chains, sequence, 30 s skew, exact response decoding (`control_client.py`), fail-closed on any mismatch |
| Runner ↔ staging | signed scope + cloud grant | all responses | host pinning, no redirects, TLS 1.2, full DNS set pinned and rechecked, 256 KiB JSON only, budget, attempt reservation (`http_transport.py`, `plan_differential.py`) |
| Runner local store | operator's user account | nothing | inode guard, private dirs, redaction before write, HMAC containment chain |
| Cloud evidence | server | runner projections | closed schemas, size caps, forbidden keys (`_FORBIDDEN_FINDINGS_KEYS`), signature over digest, no bodies |

Residual risks that stay documented, not fixed by this launch: `SSL_CERT_FILE` in the operator's
environment chooses the CA set (`docs/PLAN_DIFFERENTIAL_RUNNER.md` Trust boundary); D3/D6/D7/D8
of `docs/REDTEAM_PLAN_DIFFERENTIAL.md` (in-trust-boundary attempt reuse, accounting labels, chain
limits, hand-written `--routes` envelope); password-based signup without email verification
(trial farming bounded by per-client and global signup caps and quotas, not identity proof).

---

## 6. Exact journey and UI states

Pages: `/` (anonymous review), `/agent` (download + MCP), `/device` (device-code approval),
`/dashboard` (activation flow), `/runner` (reference viewer). The dashboard's existing
step cards (`components/canary/{EnvironmentStep,RunnerStep,CanaryAccessStep,RehearsalStep,
RunProgress,ApprovalDialog,DisclosureDialog}.tsx`) are the UI skeleton; each state below MUST
map to one card state and one API condition.

| Step | State id | Visible condition | Next action | Fail-closed state |
|---|---|---|---|---|
| Sign in | `sign_in` | `/v1/me` 401 `auth_required` | signup/login form | lockout message after repeated failures |
| Project | `select_project` | no projects | "Create a project first" | — |
| Target | `environment.pending` | challenge issued (token shown once with `http_url` or `dns_record`) | "Check exact proof" | `environment.failed` with reason code; `expired` after 24 h |
| Target | `environment.verified` | `status: verified`, `verification_record_digest` present | enables Runner step | `revoked` hides runner step |
| Runner | `runner.invite` | owner clicks "Pair a runner": invitation token displayed once (10 min TTL) with the exact command `heel runner pair --origin <origin> --invite <token>` | — | token expiry |
| Runner | `runner.pending_approval` | pairing visible via `GET …/runner-pairings/{id}` with phrase + fingerprint | human compares the six words and fingerprint printed by the runner, clicks Approve | mismatch → Deny, pairing abort |
| Runner | `runner.active` | activation completed; runner heartbeat recent | enables Access step | `runner.offline` ("Restart it on the paired machine") |
| Access | `access.incomplete` | binding lists `plan_labels: []` or one role | instructions: `heel runner credential add --role lower_plan --plan-label free …` and `--role higher_plan --plan-label pro …` | — |
| Access | `access.ready` | runner reported both role handles with plan labels (labels only, never secrets) | enables Inventory | — |
| Inventory | `inventory.empty` | no inventory row for this environment | "Import OpenAPI": browser parses locally, extracts GET/HEAD `method + route_template` only, shows the count, user confirms upload of that minimized list (raw spec stays in browser) | invalid/oversized spec rejected locally |
| Inventory | `inventory.stored` | row with `inventory_digest`, `route_count` | enables Plan | — |
| Plan | `plan.requested` | browser posts "prepare plan"; runner claims context, compiles, submits approval projection | — | `plan.rejected` with closed reason (e.g. `inventory_mismatch`, `credential_missing`) |
| Plan | `plan.review` | approval request shows `plan_sha256`, pairs (method, template, both labels), `not_executed` list, request budget, `requests_sent: 0` | Approve dialog: retype hostname, reason, exact digest | expiry 24 h |
| Run | `run.approved` → `run.claimed` → `run.running` | `progress` counters (`requests_completed`, `remaining_requests`, `retries_used`, `redaction_count`) | Stop (generation-bound) | `run.stopped`, `run.expired`, `run.runner_revoked` |
| Result | `run.completed_local` | `local_result_ready: true`, projection pending disclosure | "Share minimized findings" or "Keep local only" | — |
| Findings | `findings.visible` | per-route rows: verdict, predicate, evidence state, `key_path_count` per plan, `ev1_` refs; link "open raw evidence on the runner machine" (`heel findings --run`, companion URL) | "Save as regression" | — |
| Regression | `regression.saved` | record with finding id, route, predicate, labels | "Replay" → new plan request of kind `regression` | `regression.result: pass/fail/inconclusive` |
| Revoke | — | runner row Revoke; environment Revoke; binding Revoke | — | active run stopped with `runner_revoked` / `target_revoked` |

Copy MUST state on the dashboard, verbatim or equivalent: raw OpenAPI, credentials and response
bodies never leave the customer machine; the cloud sees method and route templates, labels, counts
and digests.

---

## 7. API and persistence changes (exhaustive for this launch)

All new routes are under `/v1/workspaces/{ws}/projects/{prj}/…`, require a browser session with
the owner/admin role (`_recent_owner_admin` for state changes), carry closed schemas validated in
`heel/canary_contracts.py`, and MUST be added to both the Python matcher (`http_api.py:908`) and
the Worker allowlist with a body cap.

### 7.1 Route inventory (new, migration 30 `route_inventories`)

- `PUT …/environments/{env}/route-inventory` body `heel.route-inventory.v1`:
  `{schema_version, routes:[{method:"GET"|"HEAD", route_template}], source_digest}`; ≤200 routes,
  template ≤512 bytes, normalized as `openapi_routes.py` does. Server stores
  `inventory_digest = canonical_digest(routes)`; replaces any previous row (one per environment).
- `GET …/environments/{env}/route-inventory` returns the same plus `inventory_digest`,
  `route_count`, `updated_at_ms`.
- Runner receives `inventory_digest` and `routes` inside the context claim response
  (`runner_contexts.claim_in_transaction`) and MUST compile only from that list.

### 7.2 Approval projection v2 (extend `validate_approval_projection`)

Add `plan_kind: "plan_differential" | "regression"`, `plan_sha256`, `inventory_digest`,
`plan_labels: [{role, label}]` (labels ≤32 chars, two entries, roles fixed), `pairs_planned`,
`not_executed_count`, `max_ops`. Existing v1 projections remain accepted for the catalog run kind.
Grants (`heel.canary-execution-grant.v1`) gain the same `plan_kind` and `plan_sha256`; the runner
MUST refuse a grant whose `plan_sha256` differs from its compiled plan.

### 7.3 Result projection (new schema `heel.plan-differential-result.v1`)

Bounded: ≤100 pair rows `{method, route_template, verdict, predicate, reason,
evidence_state|null, finding_id|null, lower:{status_code, body_shape, key_path_count,
response_bytes}, higher:{…}, evidence_refs:[ev1_…]}`, plus `requests_sent`, `retries_used`,
`redaction_count`, `plan_sha256`, `containment_head_digest`, signature. Forbidden keys inherit
`_FORBIDDEN_FINDINGS_KEYS`; no key names from target bodies, no header values. Stored in a new
table `plan_differential_results` (migration 30) keyed by `run_id`; retention 30 days like
audit rows.

### 7.4 Regressions (new, migration 30 `regressions`)

- `POST …/regressions` from a finding row → `{regression_id, finding_id, route, predicate,
  plan_labels, environment_id}`; ≤50 per project (free tier).
- `POST …/regressions/{id}/replay` creates an approval request of `plan_kind: regression`
  limited to that one pair; result row carries `result: pass|fail|inconclusive` using the
  existing `heel/regressions.py` rules (lower denied by status with higher success = pass; 2xx
  denial envelope = inconclusive).

### 7.5 Credential label report

Runner context claim request gains `credential_roles: [{role, plan_label}]` (no handles, no
secrets); `GET …/runner-context-bindings` surfaces them so the Access card can render
`access.ready`.

### 7.6 Quotas

Reuse `Meter.CANARY_RUNS` (free: 10 per period) for every plan-differential or regression run
reservation at approval time (existing `approval_reserves_and_issues_exact_signed_grant_in_one_
transaction`). No new meter, no pricing change. `Meter.ACTIVE_RUNNERS` stays 1 on free.

### 7.7 Worker

Allowlist additions: inventory `GET/PUT` (cap 64 KiB), regressions `GET/POST` and replay
`POST` (cap 16 KiB). No other change. The runner routes are already allowlisted
(`worker/index.ts:146-158`).

---

## 8. Packaging and deployment design

### 8.1 Runner release (one documented command)

- Bump to `1.3.0` in `pyproject.toml`, `release/open-core-v1.json`, `apps/heel-cloud` download
  names and tests (`test_release_version.py`, `test_open_core_release.py`); regenerate the three
  deterministic artifacts with the existing builder; keep `heel.saas` out of the wheel.
- A release workflow step uploads `heel_sim-1.3.0-py3-none-any.whl`, `.tar.gz` and the manifest as
  GitHub Release assets (today v1.2.0 has none, CONFIRMED T1D §B item 6). PyPI remains optional
  and is not a gate.
- Documented command (the `/agent` page and `docs/PLAN_DIFFERENTIAL_RUNNER.md` MUST show the same
  string, tested by `mcp-quickstart.test.mjs` style contract test):
  `python3 -m pip install 'heel-sim[runner] @ https://github.com/ancilis/heel/releases/download/v1.3.0/heel_sim-1.3.0-py3-none-any.whl'`
  followed by `heel runner pair --origin https://<heel origin> --invite <token>` and
  `heel runner serve`. The manifest SHA-256 is printed next to the command.

### 8.2 Hosting topology

The implemented production topology is Worker + VPC service binding + Tunnel + one non-root
control-plane container (`deploy/compose.yaml`, `docs/saas/OPERATIONS.md`). It requires a
Cloudflare account with VPC services and a Linux host. If the Worker is hosted where VPC
bindings do not exist (the existing Sites app is Worker hosting with only `PUBLIC_ORIGIN`
configured, CONFIRMED `sessions/astra-sites-access.md`), the Worker MUST gain one additional,
equally fixed binding mode: `HEEL_DEPLOYMENT_MODE=fixed_origin` with
`HEEL_CONTROL_PLANE_ORIGIN=https://<private host>` compiled into `vars` at build time, never
read from a request, reached over TLS with the existing `X-Heel-Edge-Auth` secret. The control
plane keeps `HEEL_PRIVATE_NETWORK_ACK=private-vpc-only` semantics by requiring the edge secret on
every route (already true) and binding only behind a TLS terminator that admits the Worker's
egress. This preserves "hosted infrastructure is never an unrestricted proxy": the origin is one
build-time constant and the route allowlist is unchanged. Choice between the two modes is a
hosting-access decision (§15), not a product decision.

### 8.3 Reproducible release, secrets, migrations, rollback, runbooks, kill switch

- Control-plane image `heel-control-plane:1.3.0` built from `deploy/Dockerfile.control-plane`;
  digest recorded in the deployment record as `DEPLOYMENT_2026-09-05.md` does.
- Secrets: the eight names in `deploy/.env.production.example` plus Worker
  `CONTROL_PLANE_EDGE_SECRET`; generated in the provider secret manager; never in logs
  (`server.py:120-245` validates formats, CONFIRMED).
- Migrations apply at start (`migrate.py`, currently 29, launch adds 30); rollback = redeploy the
  previous image against the restore-verified backup (`scripts/saas_backup.py verify`);
  migration 30 is additive only so the previous image can read the database.
- Runbooks: `docs/saas/RUNBOOKS.md` sections apply; add "revoke all runners of a workspace" and
  "trip global kill switch" (`ops.py` `trip`) with the exact command.
- Kill switch: `ops.trip(workspace|global)` returns 503 for new runs and advances
  `kill_switch_generation` so live heartbeats stop (`test_canary_stop.py:432`).

### 8.4 Staging first

A staging deployment with its own origin, database and secrets MUST exist before the
clean-room acceptance; the acceptance (§11) runs against it with a synthetic SaaS staging target
that the team controls.

---

## 9. Existing free-tier behavior (reused, no pricing invented)

CONFIRMED by `GET /v1/workspaces/{ws}/entitlements` on the loopback server (walk log) and
`heel/saas/catalog.py:88-96,143-144`: plan `free`, no card, quotas `runs 25`, `verified_runs 5`,
`verified_targets 1`, `concurrency 1`, `retention_days 7`, `seats 1`, `integrations 0`,
`synced_reviews 3`, `active_runners 1`, `canary_runs 10`; features api/mcp/exports/
scheduled_regressions/rbac/audit_export `unavailable`, sso/scim/data_region/private_runners
`contact_sales`. `HEEL_BILLING_MODE=free_launch` installs `DisabledBilling`; checkout returns 503
(`saas_smoke.py`). Pro and Team are "coming soon". The launch uses exactly these numbers; the
free/pro words in the product are the customer's plan labels for their own staging identities,
not Heel plans.

---

## 10. Twelve safety properties → named automated tests and clean-room acceptance

Existing tests are CONFIRMED present at the cited lines and passing in the v2 baseline. "New"
tests are names the implementer MUST create; the Fable review reads them first.

| # | Property | Existing named tests | New named tests | Clean-room acceptance check |
|---|---|---|---|---|
| 1 | No requests outside signed hosts (redirects, IPv4/IPv6/encoded hosts, Host manipulation, DNS rebinding) | `test_runner_plan_differential_safety.py::test_i1_host_confinement_refuses_off_allowlist_redirect_and_rebinding`, `::test_i1_host_header_is_always_the_normalized_host`; `test_runner_http_transport.py::test_dns_is_full_set_pinned_and_rechecked_before_authorized_retry`, `::test_dns_drift_mixed_answer_and_peer_mismatch_fail_closed`; `test_verified_environments.py` (30 tests) | `test_cloud_plan_run_refuses_origin_outside_grant` | staging target logs show only the verified origin; a redirect route in the synthetic target yields `transport:response_rejected` |
| 2 | Only GET/HEAD in imported inventory execute | `::test_i2_post_inventory_is_rejected_at_compile`, `::test_i2_only_inventoried_get_and_head_reach_the_wire`, `::test_i2_every_transport_action_is_the_compiled_pair` | `test_cloud_inventory_mismatch_rejects_plan`, `test_inventory_put_rejects_non_get_head` | inventory with a POST route is rejected at upload; a route absent from inventory never appears in target logs |
| 3 | Each request verifies signed scope and reserves one-shot attempt | `::test_i3_no_request_without_verified_signed_scope`, `::test_i4_no_request_without_one_shot_reserved_attempt`; `test_canary_grants.py::test_claim_consumes_oldest_exact_nonce_and_provisions_four_chains_atomically`; `test_runner_stop.py::test_execution_bundle_is_exactly_bound_signed_fresh_and_reserved_once` | `test_cloud_grant_plan_sha256_mismatch_sends_nothing` | replaying an approved run id yields no second traffic |
| 4 | No credentials in cloud/browser/findings/logs/traces/metrics/crashes/containment/CI/support exports | `::test_i5_credential_plaintext_absent_from_heel_home_and_output`; `test_runner_redaction.py` (6); `test_canary_privacy.py::test_findings_upload_recursively_rejects_raw_credential_fixture_and_local_path_l…`; `test_runner_plan_differential_cli.py::test_r18_credential_add_prints_handle_never_label_or_secret` | `test_result_projection_rejects_header_and_body_values`, `test_metrics_and_structured_logs_never_contain_handles_or_secrets` | byte scan of control-plane DB, Worker logs, browser network capture and `HEEL_HOME` for both canary secrets = 0 hits |
| 5 | Raw evidence local; bounded redacted cloud projections | `test_runner_http_transport.py::test_completed_response_is_written_only_to_required_local_evidence_sink`; `test_canary_privacy.py::test_operational_cloud_storage_cannot_be_repurposed_for_blocked_or_observed_asse…`; `test_runner_coordinator.py::test_findings_upload_is_closed_bounded_and_continues_the_terminal_result_chain` | `test_plan_differential_result_projection_is_bounded_and_bodyless` | cloud DB rows contain refs and counts only; `ev1_` bodies open only on the runner machine |
| 6 | Verifiable containment chain with caller/workspace/project/runner/scope/route/attempt attribution | `::test_i6_every_request_is_logged_before_it_is_sent`, `::test_i7_every_containment_entry_carries_cli_caller`, `::test_i8_containment_chains_verify_and_detect_tamper` | `test_cloud_run_containment_entries_carry_workspace_project_runner_grant` | `heel log --run` verifies and names workspace, project, runner, grant, route, attempt |
| 7 | Workspace/project isolation (IDs, roles, API keys, sessions, queues, findings sync) | `test_saas_adversarial.py::test_cross_tenant_objects_unreachable`, `::test_client_supplied_role_ignored`, `::test_invite_token_wrong_workspace_rejected`; `test_saas_http_api.py::test_tenant_isolation`, `::test_api_keys_scoped_and_never_privileged`; `test_canary_http.py::test_context_dashboard_hides_runner_bound_in_another_project_until_revoke` | `test_inventory_and_regressions_are_project_scoped` | second account cannot read the first account's environment, inventory, run or findings (404/403 only) |
| 8 | Verification/pairing non-replayable, cannot widen or cross workspaces | `test_saas_device_auth.py::test_exchange_is_one_time_and_access_is_workspace_bound`, `::test_refresh_rotates_both_tokens_and_reuse_revokes_family`; `test_runner_control_http.py::test_http_pairing_exchange_returns_runner_only_challenge_for_activation`, `::test_http_v3_pairing_activation_replays_one_sealed_executable_cursor`; `test_canary_grants.py::test_rotation_start_has_one_immutable_old_key_bound_ceremony` | `test_runner_pair_cli_refuses_reused_invitation_and_wrong_origin` | reused invitation token → rejected; runner paired to workspace A cannot claim in workspace B |
| 9 | Quotas/billing idempotent under races/retries | `test_saas_adversarial.py::test_duplicate_idempotent_run_charged_once`, `::test_concurrent_reservations_never_exceed_quota`; `test_canary_quota.py` (8); `test_canary_grants.py::test_approval_is_exactly_idempotent_and_cross_run_key_reuse_conflicts` | `test_regression_replay_reserves_once_under_retry` | double-click Approve consumes one `canary_runs` unit; usage endpoint matches |
| 10 | Prompt revocation of scopes/runners/credentials/active jobs | `test_canary_stop.py` (21), `test_canary_quota.py::test_revoked_runner_zero_request_claim_is_stopped_and_refunded_after_deadline`; `test_runner_stop.py` | `test_runner_serve_stops_within_deadline_on_revoke` | revoke runner during a run → heartbeat gate inactive, target logs stop within 5 s, UI shows `runner_revoked` |
| 11 | Production sessions, CSRF/origin, rate limiting/audit for signup/login/device/state changes | `test_saas_http_api.py::test_lockout_after_failures`, `::test_session_lifecycle`; `test_saas_device_auth.py::test_start_rate_limit_caps_one_client_and_repeated_challenge`, `::test_verify_requires_browser_session_same_origin_and_live_sync_role`; `test_launch_journey.py`; `apps/heel-cloud/tests/privacy-boundary.test.mjs`, `runner-edge-route.test.ts` | `test_new_routes_require_same_origin_and_recent_auth` | cross-origin POST to inventory/regressions rejected; signup throttle observed with a 4th signup from one client |
| 12 | Offline/lost authorization/malformed input fail closed with visible state | `test_runner_coordinator.py::test_restart_rehydrates_active_binding_but_requires_fresh_heartbeat`, `::test_live_gate_rejects_replayed_server_time_and_regressed_control_generation`; `test_saas_adversarial.py::test_malformed_and_oversized_bodies`; `test_runner_plan_differential_cli.py::test_r16_rejections_use_the_existing_fixed_line_and_reflect_nothing` | `test_runner_serve_offline_shows_offline_state_and_resumes` | kill the runner mid-run: dashboard shows `runner.offline`; restart: run resumes or terminalizes with reason; malformed OpenAPI upload shows a reason, no server error |

---

## 11. Clean-room acceptance script (final, executed by a fresh Fable session)

Preconditions: staging deployment of the full mode (§8.4); a fresh machine or user account with
no repository checkout; a synthetic staging SaaS the team controls, with one route that returns
the pro-only export to a free identity and is **not declared** plan-gated in its OpenAPI. Capture
URLs, commands, screenshots, artifact digests, finding ids and timestamps at every step.

```
# 0. clock start
# 1. browser: open https://<staging origin>/ ; sign up (new email) ; confirm /dashboard shows select_project
# 2. browser: create project ; register https://<synthetic staging host> ; place /.well-known/heel-verify.txt ; "Check exact proof" → verified
# 3. browser: "Pair a runner" → copy the one-line install + pair commands shown
# 4. machine: python3 -m pip install 'heel-sim[runner] @ https://github.com/ancilis/heel/releases/download/v1.3.0/heel_sim-1.3.0-py3-none-any.whl'
#             sha256sum of the wheel equals the manifest shown on /agent
# 5. machine: heel runner pair --origin https://<staging origin> --invite <token>   → prints six words + fingerprint
#    browser: compare, Approve → runner prints "active"
# 6. machine: heel runner credential add --role lower_plan --plan-label free --profile bearer --backend keychain   (secret via prompt/fd, never argv)
#             heel runner credential add --role higher_plan --plan-label pro --profile bearer --backend keychain
#             heel runner serve   (leave running)
# 7. browser: Import OpenAPI (the synthetic SaaS spec) → shows N GET/HEAD routes → Upload minimized inventory
# 8. browser: Prepare plan → plan.review shows plan_sha256, pairs, requests_sent 0 ; machine: heel runner status shows the same plan_sha256
# 9. browser: Approve (retype host) → run.running ; watch progress counters ; optional Stop/resume test
# 10. browser: findings.visible lists GET /exports/… verdict finding, predicate body_superset (or marker_leak → verified), evidence_state observed/verified
# 11. machine: heel findings --run <id> shows [REDACTED:secret] refs ; open the ev1_ evidence file ; grep both secrets across $HEEL_HOME, browser HAR, control-plane DB dump → 0 hits
# 12. browser: Save as regression → Replay → result fail/still_reachable
# 13. patch the synthetic SaaS to enforce the plan gate ; browser: Replay → result pass/blocked
# 14. browser: Revoke runner → machine runner exits with runner_revoked ; Revoke environment → runner step locked
# 15. clock stop ; record minutes from step 1 to step 10 (target ≤ 15)
```

The final reviewer answers verbatim: "Can a new user with no repository access sign up for Heel
and obtain an evidence-backed, undeclared product-abuse finding against a staging SaaS?" Only an
unqualified YES with the captured evidence passes. Mocked boundaries, loopback seams or the
synthetic harness are not journey proof.

---

## 12. Dependency-ordered bounded backlog (allowed files and a gate each)

Each task is one fresh Opus session, focused → affected → full suites, signed small commits,
then a fresh Fable adversarial review (FAIL blocks the next task; ≤3 remediation cycles per
property before escalation). Allowed files are exhaustive; anything else is out of bounds.

| # | Task | Allowed files | Gate (must be green before review) |
|---|---|---|---|
| T2 | Runner pairing and daemon CLI: `heel runner pair`, `serve`, `status`, `unpair`; glue over `RunnerControlClient`, `RunnerCoordinator`, `RunnerService`, `SystemSecureSigner`; keychain/secret-service key storage; offline/resync behaviour; credential `--plan-label` | `heel/cli.py`, new `heel/runner/daemon.py`, `heel/runner/__init__.py`, `tests/test_runner_daemon.py` (new), `docs/PLAN_DIFFERENTIAL_RUNNER.md` | pairing + heartbeat against a real loopback `heel.saas.server` over HTTP in a test; `test_runner_pair_cli_refuses_reused_invitation_and_wrong_origin`; `test_runner_serve_stops_within_deadline_on_revoke`; red-team: device-code theft, invitation replay, rotation races, disconnect/revocation |
| T3 | Cloud route inventory + plan projection v2 + grant binding (§7.1, §7.2, §7.5) | `heel/saas/http_api.py`, `heel/saas/runner_contexts.py`, `heel/saas/canary_runs.py`, `heel/saas/migrate.py` (migration 30), `heel/canary_contracts.py`, `heel/runner/compiler.py`, `heel/runner/daemon.py`, `apps/heel-cloud/worker/index.ts`, `apps/heel-cloud/lib/canary-api.ts`, tests `test_canary_http.py`, `test_canary_grants.py`, `test_canary_migrations.py`, `runner-edge-route.test.ts`, `canary-api.test.ts` | `test_cloud_inventory_mismatch_rejects_plan`, `test_inventory_put_rejects_non_get_head`, `test_cloud_grant_plan_sha256_mismatch_sends_nothing`, `test_inventory_and_regressions_are_project_scoped`; red-team: scope tamper/allowlist, malicious OpenAPI (oversized, duplicate templates, unicode), forged projection |
| T4 | Cloud-approved plan-differential execution + result projection + dashboard findings (§7.3) | `heel/runner/execution.py`, `heel/runner/plan_differential.py`, `heel/runner/daemon.py`, `heel/saas/canary_runs.py`, `heel/saas/http_api.py`, `heel/canary_contracts.py`, `apps/heel-cloud/components/canary/*`, `apps/heel-cloud/app/dashboard/page.tsx`, `apps/heel-cloud/lib/canary-api.ts`, tests `test_runner_plan_differential_safety.py`, `test_canary_privacy.py`, `test_canary_http.py`, component tests | `test_cloud_plan_run_refuses_origin_outside_grant`, `test_plan_differential_result_projection_is_bounded_and_bodyless`, `test_result_projection_rejects_header_and_body_values`, `test_cloud_run_containment_entries_carry_workspace_project_runner_grant`; red-team: egress tricks, attempt replay/concurrency, leakage paths, oversized responses, error false positives (D1 closure must hold through the cloud path) |
| T5 | Regressions from product + quotas + revoke end-to-end (§7.4, §7.6) | `heel/saas/http_api.py`, `heel/saas/canary_runs.py`, `heel/saas/migrate.py`, `heel/regressions.py`, `heel/runner/daemon.py`, `apps/heel-cloud/**` (regression UI), tests | `test_regression_replay_reserves_once_under_retry`, `test_new_routes_require_same_origin_and_recent_auth`, `test_runner_serve_offline_shows_offline_state_and_resumes`, `test_metrics_and_structured_logs_never_contain_handles_or_secrets`; red-team: quota/billing races, regression with expired/missing credentials, session fixation, invitation replay on the new routes |
| T6 | Product surface: OpenAPI import step, pairing/access instructions, device page, status/recovery states (§6), legal/support/security pages (drafts for Kevin's approval), truthful docs (`CAPABILITIES.md`, `BUILD_STATE.md`, `README.md`, `/agent` copy) | `apps/heel-cloud/app/**`, `apps/heel-cloud/components/**`, `apps/heel-cloud/tests/**`, `docs/**`, `README.md` | vitest + `test:node` + `rendered-html.test.mjs` green; copy contract tests for every state id in §6 |
| T7 | Release and deployment: version 1.3.0, deterministic artifacts, GitHub Release assets step, `fixed_origin` Worker mode if required (§8.2), staging env, runbook additions, acceptance tooling | `pyproject.toml`, `release/**`, `scripts/build_open_core_release.py`, `apps/heel-cloud/public/downloads/*` (regenerated only), `apps/heel-cloud/build/deployment-config.ts`, `apps/heel-cloud/scripts/prepare-runtime.mjs`, `.github/workflows/*.yml`, `deploy/**`, `docs/saas/**`, release tests | `build_open_core_release.py --check`; `test_open_core_release`; `test_runner_plan_differential_release.py`; `deployment-config.test.ts`; `actionlint`; staging deploy green with `/v1/readyz` 200 privately and anonymous review working publicly |
| T8 | Final clean-room acceptance (§11) by a fresh Fable session | none (evidence only) | verbatim YES with evidence, or FAIL with the failing step |

Required red-team coverage across T2–T5 (each item named in at least one review): session
fixation, device code theft, invitation replay, rotation races, scope tamper/allowlist, egress
tricks, attempt replay/concurrency, leakage paths, malicious OpenAPI/oversized responses, forged
projection/reference, error false positives, quota/billing races, disconnect/revocation,
regression with expired/missing credentials.

Prerequisite: PR #41 lands and this branch is rebased onto `main` before the final product PR.
No commit of this launch goes to PR #41's branch.

---

## 13. Fifteen DoD steps — owner and acceptance check

| # | Step | Implementation owner | Acceptance check (Fable) |
|---|---|---|---|
| 1 | Visit public HTTPS | T7 | anonymous GET `/` 200 on the production origin; `/api/control-plane/v1/me` 401 not 503 |
| 2 | Sign up / login | existing; T6 copy | §11 step 1; lockout and throttle observed |
| 3 | Workspace/project | existing | §11 step 2 |
| 4 | Register/verify staging target | existing | §11 step 2 with a real https-file proof |
| 5 | Install runner, one command | T7 | §11 step 4; wheel digest equals manifest |
| 6 | Pair via browser/device | T2 | §11 step 5; reused token rejected |
| 7 | Two local credentials with plan labels | T2 | §11 step 6; labels visible in UI, handles never, secrets nowhere |
| 8 | Import OpenAPI | T3, T6 | §11 step 7; raw spec absent from network capture |
| 9 | Review dry-run | T3 | §11 step 8; `plan_sha256` equal on both sides, `requests_sent 0` |
| 10 | Start scan from product | T4 | §11 step 9; first target request only after Approve |
| 11 | Live status / recovery | T4, T5 | §11 step 9 and the §10 #12 offline check |
| 12 | Undeclared observed/verified finding | T4 | §11 step 10 |
| 13 | Inspect redacted evidence | T4 | §11 step 11 |
| 14 | Save / replay regression | T5 | §11 steps 12–13 |
| 15 | Revoke runner / target | existing; T5 wiring | §11 step 14 |

---

## 14. Exclusions and accurate launch claims

Deferred (not built, not claimed): writes or any non-GET/HEAD method; lifecycle automation; trial
farming; tenant differential; limit probing; HAR import; browser credential capture; MCP execution
of runner scans (`R10` stays: CLI/daemon only); unrestricted fuzzing; paid plans and checkout;
Windows machine runner (POSIX only, as today); multi-node control plane; email verification.

Accurate claims after T8 PASS: "A SaaS operator can sign up, verify a staging origin, pair a
local runner, and receive evidence-backed observed (and, with a marker, verified) findings that a
lower plan receives a higher plan's read responses on routes not declared as gated. Credentials
and raw responses never leave the operator's machine; Heel Cloud stores route templates, labels,
counts, digests and verdicts." Static OpenAPI review remains a separate, static capability with
its own truthful state (`docs/CAPABILITIES.md`). Error envelopes are inconclusive; status-only
matches are insufficient; plan labels are never inferred from responses.

---

## 15. Missing access or secrets (concrete; values never printed) and independent work

CONFIRMED gaps on this machine (details in `sessions/T1D-closing.md`, read as evidence):
no Cloudflare login (`wrangler whoami` "Not logged in"); no Docker daemon; GitHub Release
v1.2.0 has no assets; no Actions secrets; Sites management access exists for the Worker only.
Railway access exists (personal workspace, two unrelated projects) but hosting the control plane
there is new spend.

Concrete escalations for Kevin, each needed only when its task starts:

1. **Hosting decision for the private control plane** (T7): either Cloudflare account access
   (Worker + VPC service + Tunnel, the implemented topology) plus a Linux host, or approval of
   new spend on Railway (or equivalent) with the `fixed_origin` Worker mode of §8.2. Secrets are
   generated inside the chosen provider; none are needed from Kevin.
2. **Legal acceptance** (T6/T7): approve the drafted Terms, Privacy, acceptable-use and
   support/security contact pages before the audience becomes public.
3. Nothing else blocks T2–T6; they proceed now on local loopback evidence.

---

## 16. Evidence index

`T1-artifacts/`: `python-baseline-py313.log`, `python-baseline-py311.log`,
`python-baseline-v2-py313.log`, `python-baseline-v2-py313-pytest-full.log`,
`python-baseline-v2-py313-{demo,smoke}.log`, `python-baseline-py313-failure-diagnosis.log`,
`python-baseline-v2-py313-residual-failure.log`, `python-package-release-check.log`,
`js-baseline.log`, `js-test-node-python313.log`, `journey-synthetic-plan-differential.log`,
`wheel-cli-surface.log`, `control-plane-loopback-api-walk.log`. Session transcript:
`sessions/T1-fable-terminal.log`. Related: `sessions/T1D-closing.md`,
`sessions/astra-sites-access.md`, `RUN-LOG.md`.
