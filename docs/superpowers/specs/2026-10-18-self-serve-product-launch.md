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

Revision T1R (2026-10-18, fresh Fable adversarial specification review): corrections to §1–§3,
§6–§8, §10, §12, §13 and §15. The list of defects found, with evidence, is in
`2026-10-18-self-serve-product-design-review.md` (same directory). T1R artifacts live in
`.git/self-serve-launch/sessions/T1R-artifacts/`. No product code changed in either revision.

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
| `pytest -q tests` | Python 3.13.5, venv under `$HOME/.cache` | **1 failed, 1752 passed, 2 skipped, 36 warnings, 653 subtests passed** in 306 s; pytest exit 1 (`python-baseline-v2-py313.log`, full output `python-baseline-v2-py313-pytest-full.log`). This is the baseline of record; no later full rerun was performed (T1R), so no "clean full run" is claimed |
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

1. **145 failures under a `/tmp` venv, 144 of them removed by relocating the venv.**
   `RunnerRuntimeCorrupt("runtime state helper is unavailable")` from
   `heel/runner/runtime.py:853-891` (`_start_inode_guard`) refuses a `sys.executable` whose
   ancestor directory is world-writable; `/private/tmp` is `drwxrwxrwt`
   (`python-baseline-py313-failure-diagnosis.log`, one reproduced failure). The `/tmp` run ended
   145 failed / 1608 passed / 2 skipped; the `$HOME/.cache` run ended 1 failed / 1752 passed /
   2 skipped (same 1755 tests), so **144** failures are attributable to the venv location and
   **1** (item 2) persists in both. CONFIRMED by the two summary lines. The `/tmp` log lists only
   39 of the 145 `FAILED` rows (32 `test_runner_runtime.py`, 7 `test_runner_stop.py`) because
   the first wrapper piped pytest through `tail`; that all 144 are inode-guard failures is
   INFERRED (confirming action: rerun the `/tmp` venv with `pytest -q -rf tests` and compare the
   full list; not done, to avoid another full suite). CI uses `$RUNNER_TEMP`, not world-writable.
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

Net: **no product-attributable failure exists in the baseline.** The 2 skipped tests are
CONFIRMED (T1R, focused `pytest -q -rs` on the three modules that contain skip markers, same venv;
`T1R-artifacts/focused-skip-reasons-py313.log`): `tests/test_open_core_release.py:1604`
"clean source rebuild requires locally installed release tooling: setuptools, wheel" and
`tests/test_open_core_release.py:1908` "optional integration requires importable
build.__main__" — both environment tooling, neither product.

### 1.4 Environment facts that bound later work

- Docker daemon not running locally (CONFIRMED `docker info` connection refused); the compose
  bundle was not executed here. Provider/account facts are in `sessions/T1D-closing.md` and
  `sessions/astra-sites-access.md`; they are evidence, not instructions, and are not repeated.
- Ancilis Brain `orient` returned no Heel-specific canonical memory (3 of 48 confirmed, none on
  Heel); `search_evidence` found only the Astra brief and the agent-first design. Nothing in this
  spec rests on canonical memory.
- Evidence provenance (T1R): the cloud UI dev-server run of T1 (`vinext dev`, `local_review`
  mode) left no artifact log; its observations below are INFERRED from the T1 closing report
  (confirming action: rerun with the page responses captured to a log). The loopback API walk
  is direct HTTP to the Python control plane; it is not a browser, not the Worker, not a deployed
  origin. Nothing in §2 is browser end-to-end proof; only §11 produces that.

---

## 2. Proven current journey, step by step (what works, what is manual, what is missing)

Evidence: loopback control plane started from `python -m heel.saas.server` with generated
throwaway secrets (`control-plane-loopback-api-walk.log`), the cloud UI served by `vinext dev` in
`local_review` mode (`/`, `/dashboard`, `/agent`, `/runner`, `/device` all 200; proxy `/api/
control-plane/v1/me` 503 fail-closed), the committed public wheel installed into a clean venv
(`journey-synthetic-plan-differential.log`, `wheel-cli-surface.log`).

| # | DoD step | Today | Evidence | Verdict |
|---|---|---|---|---|
| 1 | Visit public HTTPS | Worker app builds; this audit found no public deployment of the full mode (the one live URL found is owner-gated, 401 anonymous). Absence elsewhere is not proven: no provider credentials beyond Sites/Railway/GitHub were available (T1D §D) | T1D §A, §D; `js-baseline.log` build | **missing (deploy) as far as this audit could see** |
| 2 | Sign up / login via production auth | `POST /v1/signup` 201 over loopback HTTP to the Python control plane; login lockout, signup throttles, `X-Heel-Client-Key` required when edge-trusted. The browser form path through the Worker was **not** exercised (dev server ran in `local_review`, where `/api/control-plane/v1/me` is 503) | `http_api.py:1800-1835`, walk log | **works (loopback API)**; browser/Worker path **untested** |
| 3 | Create/select workspace/project | signup creates org+workspace (free, catalog 2026-08-24); `POST …/projects` 201 over loopback; dashboard auto-select is code-read only | walk log; `dashboard/page.tsx:60-80` | **works (loopback API)**; UI untested |
| 4 | Register/verify staging target | `POST …/environments` issues the https-file or dns-txt challenge (201) with exact ownership attestation; `check`/`revoke` routes exist; UI copy "Verify staging now" exists. **Challenge issuance is not proof verification**: no `check` succeeded in this audit (needs a reachable public host). Verification logic is covered at unit level by `test_verified_environments.py` (67 collected) | `http_api.py:2730-2760`, `verification.py:224-311`, walk log (env_… pending) | **challenge issuance works (loopback API)**; successful verification **untested** |
| 5 | Install public runner via one release command | wheel is committed under `apps/heel-cloud/public/downloads` and on raw GitHub; GitHub Release v1.2.0 has zero assets; no PyPI | `python-package-release-check.log`; T1D §B | **manual** (no one-liner yet) |
| 6 | Pair runner via browser/device | Server: invite → exchange → approve (phrase+fingerprint) → activate (v3 executable), rotate, revoke, resync implemented; the `test_http_*` tests in `test_runner_control_http.py` drive a real loopback `serve(ControlPlane(...))` over **plain HTTP, no TLS, no edge secret** (`public_origin="http://127.0.0.1"`, line 681-700). UI RunnerStep copy exists. **No runner-side command performs the exchange** (`heel runner --help`: `import-openapi, credential, map, prepare, run`); `RunnerControlClient`, `RunnerCoordinator`, `RunnerService` are constructed by tests only (zero constructors under `heel/` or `scripts/`, T1R fact-check log), and the control client has **no HTTPS transport** (`transport` is injected; `control_client.py` imports only `urlsplit`) | `http_api.py:1066-1130`, `runner_auth.py:1530-2545`, `worker/index.ts:146-158`, `wheel-cli-surface.log`, dashboard copy "No customer-target pairing command is available in this release" (`dashboard/page.tsx:386`) | **missing (runner CLI)** |
| 7 | Store two local credentials with explicit free/pro labels | `heel runner credential add --role <lower_plan or higher_plan> --label … --backend <ephemeral-env, ephemeral-fd, keychain or secret-service>`; handle printed, label and secret never | journey log (two handles) | **works locally**; label is free text, not an explicit plan label shown in product |
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

Reading the verdict column: "works (loopback API)" means a direct HTTP call to the Python
control plane succeeded in this audit; it does not mean the Worker, the browser or a deployed
origin were exercised. Those remain the job of §11.

---

## 3. Reuse / gap matrix

| Capability | Existing foundation (reuse as-is) | Extend | New |
|---|---|---|---|
| Public edge | `apps/heel-cloud/worker/index.ts` exact allowlist, CSP, `__Host` cookie translation, edge auth | add the new routes of §7 to the allowlist | fixed-origin binding mode (§8.2) if no VPC service |
| Accounts, sessions, device auth | `heel/saas/auth.py`, `device_auth.py`, `cloud_auth.py` (`heel cloud login`) | — | — |
| Workspace/project/tenancy | `tenancy.py`, `projects.py`, `ledger.py`, `entitlement.py`, `catalog.py` (launch quotas `active_runners=1`, `canary_runs=10`) | regression records per project | — |
| Target verification | `verification.py` (`VerifiedEnvironmentService`, attestation, https-file/dns-txt), `network_guard.py` | — | — |
| Runner pairing / auth | `runner_auth.py` (PoP Ed25519, nonces, rotation, revoke, resync), `runner_contexts.py`, migrations 9–29; runner side: `RunnerStore` pairing journal / identity records / credential records (`store.py`), `SystemSecureSigner` with macOS Keychain or Linux secret-service seed storage (`identity.py:317`), `RunnerRuntimeState` (`runtime.py`) | credential record gains `plan_label` (`store.py` `_credential_record`, `_new_credential`) | **runner CLI `heel runner pair/serve/status/unpair`**; **HTTPS control transport** for `RunnerControlClient` (none exists; see §12 T2a) |
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
| Access | `access.incomplete` | binding lists `plan_labels: []` or one role | instructions: `heel runner credential add --role lower_plan --plan-label <your lower-plan name> …` and `--role higher_plan --plan-label <your higher-plan name> …` (labels are the operator's own words, e.g. `free` / `pro`; roles are fixed) | — |
| Access | `access.ready` | runner reported both role handles with plan labels (labels only, never secrets) | enables Inventory | — |
| Inventory | `inventory.empty` | no inventory row for this environment | "Import OpenAPI": browser parses locally, extracts GET/HEAD `method + route_template` only, shows the count, user confirms upload of that minimized list (raw spec stays in browser) | invalid/oversized spec rejected locally |
| Inventory | `inventory.stored` | row with `inventory_digest`, `route_count` | enables Plan | — |
| Plan | `plan.requested` | "Prepare plan" = the existing `POST …/runner-context-bindings` (no new route) carrying `plan_kind`, `inventory_digest`, `max_ops`; the paired runner lists and claims the binding, compiles locally, submits the v2 approval projection (§7.2 order) | — | `plan.rejected` with closed reason (`inventory_mismatch`, `inventory_too_large`, `credential_missing`, `plan_label_missing`, `binding_expired`) |
| Plan | `plan.review` | approval request shows `plan_sha256`, `pairs_planned` (method, template, `bindings_sha256`), both plan labels, `not_executed_count`, `max_ops`, `requests_sent: 0`; `heel runner status` prints the same `plan_sha256` | Approve dialog: retype hostname, reason, exact digest | expiry 24 h (`APPROVAL_TTL_MS`) |
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
- Bounds are **reject, never truncate**: >200 routes → 413 with closed reason
  `inventory_too_large` and no row written; any method other than GET/HEAD, a duplicate
  `(method, route_template)`, or a template that fails normalization → 400 `inventory_invalid`,
  no row written. The browser shows the count before upload so the user trims the spec locally.
  200 is a cloud-side bound chosen below the runner's own `MAX_PLAN_DIFFERENTIAL_ROUTES = 2000`
  (`compiler.py:77`) and the Worker body cap for this route (64 KiB); it is a technical bound,
  not an entitlement.
- Dynamic path parameters: the cloud stores templates only (`/users/{id}`). Concrete values come
  from the runner's local mapping store (`heel runner map`) and enter the signed approval as
  `bindings_sha256` per pair (`plan_differential.py` `_bindings_sha256`), never as values. A pair
  whose template has parameters without a local mapping is listed in `not_executed` with reason
  `unmapped`; it is never sent.
- `GET …/environments/{env}/route-inventory` returns the same plus `inventory_digest`,
  `route_count`, `updated_at_ms`.
- Runner receives `inventory_digest` and `routes` inside the context claim response
  (`runner_contexts.claim_in_transaction`) and MUST compile only from that list.

### 7.2 Approval projection v2 (extend `validate_approval_projection`)

Add `plan_kind: "plan_differential" | "regression"`, `plan_sha256`, `inventory_digest`,
`plan_labels: [{role, label}]` (labels ≤32 chars, two entries, roles fixed), `pairs_planned`,
`not_executed_count`, `not_executed_digest`, `max_ops`. Existing v1 projections remain accepted
for the catalog run kind. Grants (`heel.canary-execution-grant.v1`) gain the same `plan_kind` and
`plan_sha256`; the runner MUST refuse a grant whose `plan_sha256` differs from its compiled plan.

Bounds (T1R): v1 `actions` is capped at 20 entries and the projection at 64 KiB
(`canary_contracts.py:402-410`); the Worker caps the context-submit body at 69 632 bytes
(`worker/index.ts` `MAX_RUNNER_CONTEXT_SUBMIT_BODY_BYTES`). The runner executes at most
`effective_max_ops // 2` pairs (`plan_differential.py` `allowed = effective // 2`,
`MAX_MAX_OPS = 100`), i.e. **≤50 pairs, ≤100 requests per run**; every further compiled pair is
listed as `not_executed` with reason `over_budget`. Therefore `pairs_planned` is a list of ≤50
`{method, route_template, bindings_sha256}` entries (no values, no handles, no labels per entry),
`not_executed_count` is an integer and `not_executed_digest` is the canonical digest of the local
`not_executed` list (so the human-approved digest binds the whole plan while the body stays
under the caps). The v2 `actions` cap becomes 100 for `plan_kind: plan_differential` only; v1
keeps 20. `heel runner status` prints the full `not_executed` list locally.

Ownership and order (normative). A run exists only if every step below happened in this order,
and each step is attributable:

1. **Human, browser**: `PUT route-inventory` (§7.1) → `inventory_digest`.
2. **Human, browser**: "Prepare plan" = existing `POST …/runner-context-bindings` with
   `plan_kind`, `inventory_digest`, `max_ops` (≤100). The binding is cloud-signed, scoped to
   workspace + project + verified environment, 24 h TTL (`CONTEXT_TTL_MS`). It can create a
   projection but cannot reserve quota, issue a grant, claim a run or authorize traffic
   (`runner_contexts.py` docstring).
3. **Runner, `heel runner serve`**: lists and claims the binding (existing `contexts/list`,
   `contexts/{id}/claim`); the claim response carries `inventory_digest` and the route list.
4. **Runner, local**: compiles `routes ∩ inventory`, GET/HEAD only, deterministic order, both
   credential roles resolved by opaque handle from the local store; the compiled plan carries
   `plan_sha256`. If the local credential records lack a `plan_label` for either role, or the
   local signed scope origin differs from the environment origin, compile fails closed with the
   §6 reason and nothing is submitted.
5. **Runner**: submits the v2 approval projection (existing `contexts/{id}/approval-projections`).
6. **Human, browser**: approves the exact `plan_sha256` with hostname retype; the existing
   one-transaction path reserves quota and issues the signed grant
   (`approval_reserves_and_issues_exact_signed_grant_in_one_transaction`).
7. **Runner**: claims the grant, compares `plan_sha256`, and only then executes under
   `ExecutionGate` with the local signed scope **and** the grant both verified per request.

The signed scope stays immutable: it is bound at pairing/binding time to the verified origin and
is never widened by inventory, plan or grant. The cloud never receives credential handles, header
values, parameter values, raw OpenAPI or response bodies at any step.

### 7.3 Result projection (new schema `heel.plan-differential-result.v1`)

Bounded: ≤100 pair rows `{method, route_template, verdict, predicate, reason,
evidence_state|null, finding_id|null, lower:{status_code, body_shape, key_path_count,
response_bytes}, higher:{…}, evidence_refs:[ev1_…]}`, plus `requests_sent`, `retries_used`,
`redaction_count`, `plan_sha256`, `containment_head_digest`, signature. Forbidden keys inherit
`_FORBIDDEN_FINDINGS_KEYS`; no key names from target bodies, no header values. Stored in a new
table `plan_differential_results` (migration 30) keyed by `run_id`. Row cap: ≤50 executed pair
rows (= the §7.2 execution bound) plus `not_executed_count`; the schema cap stays 100 so a
future `max_ops` change does not need a schema change. Retention follows the existing constants,
not a new policy: result rows expire with `FINDINGS_RETENTION_MS` = 7 days
(`canary_disclosure.py:38`, equal to the free plan's `retention_days=7`, `catalog.py:92`);
operational receipts 7 days (`OPERATIONAL_RETENTION_MS`, `canary_runs.py:37`); audit rows 30 days
(`AUDIT_RETENTION_MS`, `canary_runs.py:38`). The earlier "30 days" for result rows was wrong.

### 7.4 Regressions (new, migration 30 `regressions`)

- `POST …/regressions` from a finding row → `{regression_id, finding_id, route, predicate,
  plan_labels, environment_id}`. Bound: ≤100 stored regressions per project, a **technical
  storage bound** equal to the result-row schema cap, not an entitlement or pricing term (no
  existing decision sets a regression count; the catalog lists `scheduled_regressions` as
  `unavailable` on free, `catalog.py`, so replay is manual only and nothing is scheduled).
  Regression records are configuration, not findings, and are kept until deleted or until the
  project is deleted; the finding they point at expires after 7 days (§7.3) and the record then
  shows `finding_expired` while remaining replayable.
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
transaction`). No new meter, no pricing change, no new retention period. `Meter.ACTIVE_RUNNERS`
stays 1 on free. Free retention stays 7 days for everything findings-like.

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
- Documented command (the `/agent` page, the dashboard `runner.invite` card and
  `docs/PLAN_DIFFERENTIAL_RUNNER.md` MUST show the same string; `mcp-quickstart.test.mjs:26`
  asserts the exact `INSTALL_AGENT` constant today and MUST be updated in the same change):

  ```
  python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else "Heel runner needs Python 3.11 or newer")' \
    && python3 -m venv "$HOME/.heel-runner" \
    && "$HOME/.heel-runner/bin/python" -m pip install \
         'heel-sim[runner] @ https://github.com/ancilis/heel/releases/download/v1.3.0/heel_sim-1.3.0-py3-none-any.whl#sha256=<wheel sha256 from the release manifest>'
  ```

  One chain, fail-fast: a version failure prints the message, exits non-zero and nothing after
  `&&` runs; the `#sha256=` URL fragment makes pip itself refuse a wheel whose bytes do not
  match, so verification is bound to the artifact, not to a later manual check. The literal
  digest is substituted by the T7 release step from the deterministic manifest the builder
  already produces; **no v1.3.0 release exists today** (v1.2.0 has zero assets), so the string
  above is the contract for T7, not a working command. The same three lines, with the real
  digest, MUST appear on `/agent`, on the `runner.invite` card and in
  `docs/PLAN_DIFFERENTIAL_RUNNER.md`, and the contract test MUST install from a local copy of
  the wheel with the same `#sha256=` fragment so the displayed digest is proven against the
  committed bytes. Then `"$HOME/.heel-runner/bin/heel" runner pair --origin https://<heel origin>
  --invite <token>` and `… runner serve`. Coherence requirements (T1R): the wheel's `runner`
  extra is exactly `cryptography==45.0.7` (`pyproject.toml:32`) and `requires-python >=3.11`
  (`:10`); macOS system `python3` is 3.9 (baseline failures 2 and 3), hence the check; the venv
  MUST live under `$HOME`, not `/tmp`, because the runner's inode guard refuses a world-writable
  ancestor (baseline failure 1) and `serve` would fail closed; runner key storage requires macOS
  Keychain or a Linux secret-service (`identity.py:317-340`); on a machine without either,
  `heel runner pair` MUST fail closed with the message "no supported runner OS secret service"
  and MUST NOT fall back to a file. Windows is unsupported (§14).

### 8.2 Hosting topology

The implemented production topology is Worker + VPC service binding + Tunnel + one non-root
control-plane container (`deploy/compose.yaml`, `docs/saas/OPERATIONS.md`). It requires a
Cloudflare account with VPC services and a Linux host. If the Worker is hosted where VPC
bindings do not exist (the existing Sites app is Worker hosting with only `PUBLIC_ORIGIN`
configured, CONFIRMED `sessions/astra-sites-access.md`), the Worker MUST gain one additional,
equally fixed binding mode: `HEEL_DEPLOYMENT_MODE=fixed_origin` with
`HEEL_CONTROL_PLANE_ORIGIN=https://<private host>` compiled into `vars` at build time, never
read from a request, reached over TLS with the existing `X-Heel-Edge-Auth` secret.

`HEEL_PRIVATE_NETWORK_ACK=private-vpc-only` MUST NOT be reused for this mode. Today that value
only acknowledges a non-loopback bind (`server.py:183-186`); it asserts a private network and a
public-ingress host would make that assertion false. The mode therefore requires, as product
changes in T7 (allowed files extended in §12): a distinct acknowledgement
`HEEL_INGRESS_ACK=edge-authenticated-tls-ingress` accepted by `ProductionConfiguration` only
together with `HEEL_CONTROL_PLANE_HOST=127.0.0.1` (the app binds loopback; a host-local TLS
terminator is the only listener on 443), and these enforceable ingress restrictions, each with a
deployment acceptance check that T7 MUST record before T8:

| Restriction | Enforced by | Acceptance (recorded with command and output) |
|---|---|---|
| Only TCP 443 reachable from the Internet | host firewall / provider network policy | external port scan of the origin host shows 443 only |
| Requests lacking the exact `X-Heel-Edge-Auth` value never reach the app | TLS terminator rule (header match before proxying) **and** the existing app check (`http_api.py:787`, defense in depth) | anonymous `GET https://<origin>/v1/me` → 401 from the terminator, and no app request log line for it |
| The edge secret is distributed to exactly three holders and nowhere else | one value generated in the provider secret manager and delivered to the Worker secret store (`CONTROL_PLANE_EDGE_SECRET`), the terminator rule, and the control-plane env (`HEEL_EDGE_AUTH_SECRET_B64`, §8.3); never in the repo, image, build logs or `wrangler.toml` | `wrangler secret list` names it; `git grep` and the image layers do not contain it; the deployment record names the three holders |
| Optional, if the provider supports it: mTLS from the Worker to the origin | Worker mTLS certificate binding + terminator client-cert verification | a request without the client certificate is refused at TLS |

The header proves possession of the shared secret, not that the caller is the Worker and not
that the network is private; anyone holding the value can reach the app, which is why the
distribution row above is a restriction and why rotation (`ops.py`-style runbook entry) is part
of T7. Until a host exists and those checks are recorded, `fixed_origin` is **deferred and
INFERRED**; this spec makes no private-network claim for it. The Worker side still never proxies to a
caller-chosen origin: the origin is one build-time constant and the route allowlist is unchanged.
Choice between the two modes is a hosting-access decision (§15), not a product decision.

### 8.3 Reproducible release, secrets, migrations, rollback, runbooks, kill switch

- Control-plane image `heel-control-plane:1.3.0` built from `deploy/Dockerfile.control-plane`;
  digest recorded in the deployment record as `DEPLOYMENT_2026-09-05.md` does.
- Secrets: `deploy/.env.production.example` lists 12 keys, of which 6 carry secret values
  (`HEEL_DEVICE_TOKEN_PEPPER_B64`, `HEEL_RUNNER_AUTH_PEPPER_B64`, `HEEL_API_KEY_PEPPER`,
  `HEEL_EDGE_AUTH_SECRET_B64`, `HEEL_GRANT_SIGNING_PRIVATE_KEY_B64`,
  `HEEL_CLOUDFLARE_TUNNEL_TOKEN`); plus the Worker secret `CONTROL_PLANE_EDGE_SECRET`, which
  holds the same value as `HEEL_EDGE_AUTH_SECRET_B64` (one secret, two holders in the VPC
  topology; three in `fixed_origin`, §8.2). All are generated in the provider secret manager
  and never logged (`server.py:120-245` validates formats, CONFIRMED). The `fixed_origin` mode
  adds `HEEL_INGRESS_ACK` (non-secret) and drops the tunnel token.
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

Existing tests are CONFIRMED present by `def <name>` in the named file and passing in the v2
baseline (T1R re-checked every id: `T1R-artifacts/t1r-spec-fact-checks.log`; every name below is
complete and runnable as `pytest tests/<file>::<name>`). Whole-file counts are
`pytest --collect-only -q` counts. "Proposed" tests are **not yet implemented**; they are the
exact ids the implementer MUST create in the task named in §12, and the Fable review reads them
first. Where a file name is omitted inside a cell, it is the last file named in that cell.

| # | Property | Existing named tests (CONFIRMED) | Proposed tests (not yet implemented; owning task) | Clean-room acceptance check |
|---|---|---|---|---|
| 1 | No requests outside signed hosts (redirects, IPv4/IPv6/encoded hosts, Host manipulation, DNS rebinding) | `test_runner_plan_differential_safety.py::test_i1_host_confinement_refuses_off_allowlist_redirect_and_rebinding`, `::test_i1_host_header_is_always_the_normalized_host`; `test_runner_http_transport.py::test_dns_is_full_set_pinned_and_rechecked_before_authorized_retry`, `::test_dns_drift_mixed_answer_and_peer_mismatch_fail_closed`; `test_verified_environments.py` (67 collected) | `tests/test_canary_http.py::test_cloud_plan_run_refuses_origin_outside_grant` (T4) | staging target logs show only the verified origin; a redirect route in the synthetic target yields `transport:response_rejected` |
| 2 | Only GET/HEAD in imported inventory execute | `::test_i2_post_inventory_is_rejected_at_compile`, `::test_i2_only_inventoried_get_and_head_reach_the_wire`, `::test_i2_every_transport_action_is_the_compiled_pair` | `tests/test_canary_http.py::test_cloud_inventory_mismatch_rejects_plan`, `::test_inventory_put_rejects_non_get_head`, `::test_inventory_put_rejects_more_than_200_routes_without_truncation` (T3) | inventory with a POST route is rejected at upload; a route absent from inventory never appears in target logs |
| 3 | Each request verifies signed scope and reserves one-shot attempt | `::test_i3_no_request_without_verified_signed_scope`, `::test_i4_no_request_without_one_shot_reserved_attempt`; `test_canary_grants.py::test_claim_consumes_oldest_exact_nonce_and_provisions_four_chains_atomically`; `test_runner_stop.py::test_execution_bundle_is_exactly_bound_signed_fresh_and_reserved_once` | `tests/test_runner_daemon.py::test_cloud_grant_plan_sha256_mismatch_sends_nothing` (T3) | replaying an approved run id yields no second traffic |
| 4 | No credentials in cloud/browser/findings/logs/traces/metrics/crashes/containment/CI/support exports | `test_runner_plan_differential_safety.py::test_i5_credential_plaintext_absent_from_heel_home_and_output`; `test_runner_redaction.py` (12 collected); `test_canary_privacy.py::test_findings_upload_recursively_rejects_raw_credential_fixture_and_local_path_leakage`; `test_runner_plan_differential_cli.py::test_r18_credential_add_prints_handle_never_label_or_secret` | `tests/test_canary_privacy.py::test_result_projection_rejects_header_and_body_values` (T4), `tests/test_saas_ops.py::test_metrics_and_structured_logs_never_contain_handles_or_secrets` (T5) | byte scan of control-plane DB, Worker logs, browser network capture and `HEEL_HOME` for both canary secrets = 0 hits |
| 5 | Raw evidence local; bounded redacted cloud projections | `test_runner_http_transport.py::test_completed_response_is_written_only_to_required_local_evidence_sink`; `test_canary_privacy.py::test_operational_cloud_storage_cannot_be_repurposed_for_blocked_or_observed_assessment`; `test_runner_coordinator.py::test_findings_upload_is_closed_bounded_and_continues_the_terminal_result_chain` | `tests/test_canary_privacy.py::test_plan_differential_result_projection_is_bounded_and_bodyless` (T4) | cloud DB rows contain refs and counts only; `ev1_` bodies open only on the runner machine |
| 6 | Verifiable containment chain with caller/workspace/project/runner/scope/route/attempt attribution | `::test_i6_every_request_is_logged_before_it_is_sent`, `::test_i7_every_containment_entry_carries_cli_caller`, `::test_i8_containment_chains_verify_and_detect_tamper` | `tests/test_runner_daemon.py::test_cloud_run_containment_entries_carry_workspace_project_runner_grant` (T4) | `heel log --run` verifies and names workspace, project, runner, grant, route, attempt |
| 7 | Workspace/project isolation (IDs, roles, API keys, sessions, queues, findings sync) | `test_saas_adversarial.py::test_cross_tenant_objects_unreachable`, `::test_client_supplied_role_ignored`, `::test_invite_token_wrong_workspace_rejected`; `test_saas_http_api.py::test_tenant_isolation`, `::test_api_keys_scoped_and_never_privileged`; `test_canary_http.py::test_context_dashboard_hides_runner_bound_in_another_project_until_revoke` | `tests/test_canary_http.py::test_inventory_and_regressions_are_project_scoped` (T3, extended in T5) | second account cannot read the first account's environment, inventory, run or findings (404/403 only) |
| 8 | Verification/pairing non-replayable, cannot widen or cross workspaces | `test_saas_device_auth.py::test_exchange_is_one_time_and_access_is_workspace_bound`, `::test_refresh_rotates_both_tokens_and_reuse_revokes_family`; `test_runner_control_http.py::test_http_pairing_exchange_returns_runner_only_challenge_for_activation`, `::test_http_v3_pairing_activation_replays_one_sealed_executable_cursor`; `test_canary_grants.py::test_rotation_start_has_one_immutable_old_key_bound_ceremony` (note: the `test_http_*` tests run a real loopback server over plain HTTP without TLS or edge secret) | `tests/test_runner_daemon.py::test_runner_pair_cli_refuses_reused_invitation_and_wrong_origin`, `::test_real_pairing_over_tls_edge_harness_activates_persists_heartbeats_and_revokes` (T2a) | reused invitation token → rejected; runner paired to workspace A cannot claim in workspace B |
| 9 | Quotas/billing idempotent under races/retries | `test_saas_adversarial.py::test_duplicate_idempotent_run_charged_once`, `::test_concurrent_reservations_never_exceed_quota`; `test_canary_quota.py` (7 collected); `test_canary_grants.py::test_approval_is_exactly_idempotent_and_cross_run_key_reuse_conflicts` | `tests/test_canary_quota.py::test_regression_replay_reserves_once_under_retry` (T5) | double-click Approve consumes one `canary_runs` unit; usage endpoint matches |
| 10 | Prompt revocation of scopes/runners/credentials/active jobs | `test_canary_stop.py` (18 collected), `test_canary_quota.py::test_revoked_runner_zero_request_claim_is_stopped_and_refunded_after_deadline`; `test_runner_stop.py` (61 collected) | `tests/test_runner_daemon.py::test_runner_serve_stops_within_deadline_on_revoke` (T2b) | revoke runner during a run → heartbeat gate inactive, target logs stop within 5 s, UI shows `runner_revoked` |
| 11 | Production sessions, CSRF/origin, rate limiting/audit for signup/login/device/state changes | `test_saas_http_api.py::test_lockout_after_failures`, `::test_session_lifecycle`; `test_saas_device_auth.py::test_start_rate_limit_caps_one_client_and_repeated_challenge`, `::test_verify_requires_browser_session_same_origin_and_live_sync_role`; `test_launch_journey.py`; `apps/heel-cloud/tests/privacy-boundary.test.mjs`, `runner-edge-route.test.ts` | `tests/test_canary_http.py::test_new_routes_require_same_origin_and_recent_auth` (T3, extended in T5) | cross-origin POST to inventory/regressions rejected; signup throttle observed with a 4th signup from one client |
| 12 | Offline/lost authorization/malformed input fail closed with visible state | `test_runner_coordinator.py::test_restart_coordinator_rehydrates_active_binding_but_requires_fresh_heartbeat`, `::test_live_gate_rejects_replayed_server_time_and_regressed_control_generation`; `test_saas_adversarial.py::test_malformed_and_oversized_bodies`; `test_runner_plan_differential_cli.py::test_r16_rejections_use_the_existing_fixed_line_and_reflect_nothing` | `tests/test_runner_daemon.py::test_runner_serve_offline_shows_offline_state_and_resumes` (T2b) | kill the runner mid-run: dashboard shows `runner.offline`; restart: run resumes or terminalizes with reason; malformed OpenAPI upload shows a reason, no server error |

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
#    browser: compare, Approve → runner prints "active" ; kill and restart the runner process → heel runner status still active (real OS keychain persistence)
# 6. machine: heel runner credential add --role lower_plan --plan-label free --profile bearer --backend keychain   (secret via prompt/fd, never argv; "free"/"pro" are this operator's chosen labels)
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
| T2a | Runner pairing CLI and transport: `heel runner pair`, `status`, `unpair`; new HTTPS control transport (`transport.post` adapter for `RunnerControlClient`: TLS 1.2+ default trust plus an optional explicit CA bundle argument used only by tests, origin pinned to the `--origin` value, no redirects, 256 KiB response cap, 30 s timeout); runner identity seed in `SystemSecureSigner` (Keychain/secret-service, fail closed otherwise); pairing journal and identity record persisted in the existing `RunnerStore`; credential records gain an optional `plan_label` and `heel runner credential add --plan-label <operator label>`: an operator-chosen label (1–32 printable ASCII characters, no whitespace at the ends, distinct between the two roles, e.g. `free` / `pro`); the roles stay the fixed `lower_plan` / `higher_plan`; labels are never inferred from responses or from the label text. The flag is **optional for the standalone CLI**: `credential add` without it, and records written before T2a, keep working for `heel runner run` and the existing CLI tests; only the self-serve path (binding claim / plan compile, §7.2 step 4) requires both labels and otherwise reports `access.incomplete` / `plan_label_missing` with the exact command to run. No `serve` loop yet | `heel/cli.py`, new `heel/runner/daemon.py`, new `heel/runner/control_transport.py`, `heel/runner/store.py` (credential record `plan_label` only), `heel/runner/identity.py` (label namespace only), `heel/runner/__init__.py`, new `tests/test_runner_daemon.py`, `tests/test_runner_cli.py`, `tests/test_runner_vault.py`, `tests/test_runner_identity.py`, new test-only `tests/support/edge_tls_harness.py`, `docs/PLAN_DIFFERENTIAL_RUNNER.md` | **Real pairing integration gate**: `test_real_pairing_over_tls_edge_harness_activates_persists_heartbeats_and_revokes` drives, over the **test TLS + edge harness** (a loopback TLS listener with an ephemeral self-signed CA that injects `X-Heel-Edge-Auth` and forwards to `serve(ControlPlane(edge_auth_secret=…))`; the product keeps every guard, the only test seam is the CA bundle argument): owner session creates the invitation over HTTP → `heel runner pair` exchanges → browser-session `approve` over HTTP with phrase + fingerprint → runner `activate` → identity seed present in an in-memory `OSSecretBackend` that the **test code** passes through the existing explicit `backend=` constructor parameter (limited proof: it shows the seed flows into the injected backend and survives a process restart that re-injects the same object; it does not prove OS keychain persistence) → runner record active in the store → process restart reloads it → `heel runner status` shows active → owner `DELETE …/runners/{id}` → next runner call fails closed `runner_revoked`. No seeded rows, no hand-edited activation, no fabricated runner credential. Plus `test_runner_pair_cli_refuses_reused_invitation_and_wrong_origin`, `test_r18`-style assertion that `--plan-label` is printed and the secret never is. **Real OS secret-store acceptance (separate, required)**: on a macOS machine with Keychain (or Linux with secret-service) Opus records, with commands and output in the T2a closing, `heel runner pair` → `heel runner status` active → kill and restart the process → `status` still active with the same runner key id → `unpair` removes the seed; this is the only proof of persistence and is repeated by Fable in §11 step 5. **Forbidden**: any new environment variable, flag or config value that selects an insecure or in-memory backend in product code; the existing `PYTEST_CURRENT_TEST` check in `identity.py:_backend` MUST NOT be extended. Constructor injection of a backend is ordinary dependency injection, not by itself a vulnerability; the T2a Fable review treats that check as a defect only if it shows concrete runtime reachability (a CLI or daemon path by which an `InMemorySecretBackend` can be selected at all), and otherwise records it as not reachable. Red-team: device-code theft, invitation replay, rotation races, wrong-origin / downgrade-to-http, CA-bundle argument cannot be set from env or config, in-memory backend unreachable from any CLI path |
| T2b | Runner daemon loop: `heel runner serve` over `RunnerService` + `RunnerCoordinator`; heartbeat cadence; binding list/claim; offline state and resume; stop/revoke handling; runtime persistence in `RunnerRuntimeState` | `heel/cli.py`, `heel/runner/daemon.py`, `heel/runner/coordinator.py` (adapter glue only), `tests/test_runner_daemon.py`, `tests/test_runner_coordinator.py`, `docs/PLAN_DIFFERENTIAL_RUNNER.md` | over the same harness: `serve` heartbeats against the real server, claims a context binding, survives a server outage with `runner.offline` visible, resumes; `test_runner_serve_stops_within_deadline_on_revoke` (target traffic stops ≤5 s after revoke); `test_runner_serve_offline_shows_offline_state_and_resumes`; red-team: disconnect/revocation, replayed server time, regressed control generation |
| T3 | Cloud route inventory + plan projection v2 + grant binding (§7.1, §7.2, §7.5) | `heel/saas/http_api.py`, `heel/saas/runner_contexts.py`, `heel/saas/canary_runs.py`, `heel/saas/migrate.py` (migration 30), `heel/canary_contracts.py`, `heel/runner/compiler.py`, `heel/runner/daemon.py`, `apps/heel-cloud/worker/index.ts`, `apps/heel-cloud/lib/canary-api.ts`, tests `test_canary_http.py`, `test_canary_grants.py`, `test_canary_migrations.py`, `runner-edge-route.test.ts`, `canary-api.test.ts` | `test_cloud_inventory_mismatch_rejects_plan`, `test_inventory_put_rejects_non_get_head`, `test_cloud_grant_plan_sha256_mismatch_sends_nothing`, `test_inventory_and_regressions_are_project_scoped`; red-team: scope tamper/allowlist, malicious OpenAPI (oversized, duplicate templates, unicode), forged projection |
| T4 | Cloud-approved plan-differential execution + result projection + dashboard findings (§7.3) | `heel/runner/execution.py`, `heel/runner/plan_differential.py`, `heel/runner/daemon.py`, `heel/saas/canary_runs.py`, `heel/saas/http_api.py`, `heel/canary_contracts.py`, `apps/heel-cloud/components/canary/*`, `apps/heel-cloud/app/dashboard/page.tsx`, `apps/heel-cloud/lib/canary-api.ts`, tests `test_runner_plan_differential_safety.py`, `test_canary_privacy.py`, `test_canary_http.py`, component tests | `test_cloud_plan_run_refuses_origin_outside_grant`, `test_plan_differential_result_projection_is_bounded_and_bodyless`, `test_result_projection_rejects_header_and_body_values`, `test_cloud_run_containment_entries_carry_workspace_project_runner_grant`; red-team: egress tricks, attempt replay/concurrency, leakage paths, oversized responses, error false positives (D1 closure must hold through the cloud path) |
| T5 | Regressions from product + quotas + revoke end-to-end (§7.4, §7.6) | `heel/saas/http_api.py`, `heel/saas/canary_runs.py`, `heel/saas/migrate.py`, `heel/regressions.py`, `heel/runner/daemon.py`, `apps/heel-cloud/**` (regression UI), tests | `test_regression_replay_reserves_once_under_retry`, `test_new_routes_require_same_origin_and_recent_auth`, `test_runner_serve_offline_shows_offline_state_and_resumes`, `test_metrics_and_structured_logs_never_contain_handles_or_secrets`; red-team: quota/billing races, regression with expired/missing credentials, session fixation, invitation replay on the new routes |
| T6 | Product surface: OpenAPI import step, pairing/access instructions, device page, status/recovery states (§6), legal/support/security pages (drafts for Kevin's approval), truthful docs (`CAPABILITIES.md`, `BUILD_STATE.md`, `README.md`, `/agent` copy) | `apps/heel-cloud/app/**`, `apps/heel-cloud/components/**`, `apps/heel-cloud/tests/**`, `docs/**`, `README.md` | vitest + `test:node` + `rendered-html.test.mjs` green; copy contract tests for every state id in §6 |
| T7 | Release and deployment: version 1.3.0, deterministic artifacts, GitHub Release assets step, `fixed_origin` Worker mode **only if** the §8.2 restrictions can be enforced on the chosen host (otherwise the implemented VPC topology), `HEEL_INGRESS_ACK` in `ProductionConfiguration`, staging env, runbook additions, acceptance tooling | `pyproject.toml`, `release/**`, `scripts/build_open_core_release.py`, `apps/heel-cloud/public/downloads/*` (regenerated only), `apps/heel-cloud/build/deployment-config.ts`, `apps/heel-cloud/scripts/prepare-runtime.mjs`, `apps/heel-cloud/tests/mcp-quickstart.test.mjs`, `apps/heel-cloud/app/agent/page.tsx` (install string only), `heel/saas/server.py` (ingress ack only), `tests/test_saas_server.py`, `.github/workflows/*.yml`, `deploy/**`, `docs/saas/**`, release tests | `build_open_core_release.py --check`; `test_open_core_release`; `test_runner_plan_differential_release.py`; `deployment-config.test.ts`; `actionlint`; staging deploy green with `/v1/readyz` 200 privately and anonymous review working publicly |
| T8 | Final clean-room acceptance (§11) by a fresh Fable session | none (evidence only) | verbatim YES with evidence, or FAIL with the failing step |

T3 and T4 as listed each touch more than ten files; the Fable review of T2b MUST confirm or
re-split them before T3 starts (candidate split: T3a inventory route + Worker allowlist + v2
projection validation; T3b context-claim payload + grant `plan_sha256` + runner compile binding).

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
| 2 | Sign up / login | existing API; browser path untested until T8; T6 copy | §11 step 1 in a real browser through the Worker; lockout and throttle observed |
| 3 | Workspace/project | existing API; browser path untested until T8 | §11 step 2 |
| 4 | Register/verify staging target | existing API (challenge issuance proven; verification not yet) | §11 step 2 with a real https-file proof reaching `status: verified` |
| 5 | Install runner, one command | T7 | §11 step 4; wheel digest equals manifest |
| 6 | Pair via browser/device | T2a (pair), T2b (serve) | §11 step 5; reused token rejected |
| 7 | Two local credentials with plan labels | T2a | §11 step 6; labels visible in UI, handles never, secrets nowhere |
| 8 | Import OpenAPI | T3, T6 | §11 step 7; raw spec absent from network capture |
| 9 | Review dry-run | T3 | §11 step 8; `plan_sha256` equal on both sides, `requests_sent 0` |
| 10 | Start scan from product | T4 | §11 step 9; first target request only after Approve |
| 11 | Live status / recovery | T2b, T4, T5 | §11 step 9 and the §10 #12 offline check |
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
there is new spend. This audit found no deployed Python control plane through the access it had;
that is not proof that none exists under credentials this machine lacks (Cloudflare account state
untested, T1D §D item 14).

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
