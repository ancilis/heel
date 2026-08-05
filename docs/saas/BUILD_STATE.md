# HEEL SaaS — Build State Ledger

Durable, resumable state for the autonomous SaaS build. A fresh Fable session resumes
by reading this file, verifying the claimed state, and continuing from the first
unproven gate.

## Model boundary
- Builder/integrator: **Fable** (`claude-fable-5`). Sole implementer.
- Reviewer: **Codex Sol** (`gpt-5.6-sol`), read-only adversarial gates only. Never edits.

## Base and worktree
- Base SHA: `2b623a85fad329e8659d1cffb21fb1ed368918fc` (`origin/main`, tip merged rebrand + p09–p19 uplift).
- Feature branch: `saas/heel-build`.
- Worktree: `/Users/hellohelloalbus/.config/superpowers/worktrees/heel/saas-heel-build`.
- Rationale: the initial checkout (`codex/rebrand-heel` @ `ef6b1bd`) was a **divergent duplicate rename, 45 commits behind** `origin/main` and missing the entire product-model/adapter uplift (`entitlements.py`, `economics.py`, `importers.py`, `openapi_import.py`, `control_simulator.py`, `bench.py`, `incident.py`, `modes.py`, …). Building on it would have been building on an obsolete branch. `origin/main` is the coherent upstream.

## Preservation decisions
- Untracked owner work in the original checkout (`launch/`, `docs/RESEARCH_LIBRARY_EXPANSION_PROMPT.md`) is **left untouched** in `/Users/hellohelloalbus/heel`. The new worktree is a separate directory; nothing there is moved, reset, or absorbed.
- No `git reset`, force-push, or branch deletion performed.

## Baseline verification (from base SHA)
- `python3 -m unittest discover -s tests -p 'test_*.py'` → **200 tests, OK** (Python 3.14.3, 2026-07-13).
- Pure-stdlib, zero runtime deps (DECISIONS D-001).

## Reusable core (verified present)
- `heel/scope.py` — HMAC-signed, human-only `AuthorizationScope` (the safety spine). No write path over MCP/REST/agent.
- `heel/entitlements.py` — entitlement *graph* over the tested ProductModel (NOT SaaS billing; distinct concern).
- `heel/targets.py` — synthetic targets with planted ground truth.
- `heel/store.py` — SQLite persistence: runs, findings, append-only hash-chained containment log.
- `heel/rest.py`, `heel/mcp_server.py` — loopback-only surfaces (must NOT be exposed as the SaaS API).
- `heel/web_export.py` — static snapshot exporter (must NOT run against tenant/prod data).

## Phase status
| Phase | Description | Status |
|---|---|---|
| 0 | Inventory, reconcile upstream, worktree, baseline | **DONE** |
| 1 | Brand/open-core ADR, ICP, plans/prices, entitlement contract, architecture | in progress |
| 2 | SaaS foundation: schema, tenancy, auth, roles, API keys | **DONE** (auth.py, migrate.py, http_api.py; 15 tests) |
| 3 | Job plane, target verification, signed scopes, safe adapters | **DONE** (verification.py, jobs.py, egress.py + HTTP wiring; 14 tests) |
| 4 | Usage ledger, quotas, billing lifecycle, reconciliation | **DONE** (ledger/billing from Phase 1 + reconcile.py; 5 tests) |
| 5 | App UX, onboarding, live dashboard, integration surfaces | **DONE** (dashboard.py server-rendered app; 6 tests) |
| 6 | Public website, pricing, enterprise, docs, lifecycle email, legal | **DONE** (site.py static generator; 6 tests; legal = counsel-review templates) |
| 7 | Security, privacy, admin, observability, support, runbooks | **DONE** (ops.py kill switches/audit/metrics, healthz/readyz, RUNBOOKS.md; 5 tests) |
| 8 | IaC, CI/CD, staging, backup/restore/rollback | **DONE (local layer)** — smoke + backup/verify scripts, make targets, CI steps; cloud IaC owner-gated |
| 9 | Adversarial/integration/browser/load/recovery/black-box | **DONE (local scope)** — 8 black-box adversarial tests; browser/load vs deployed infra owner-gated |
| 10 | Staging rehearsal, launch docs, owner handoff | **DONE (local scope)** — LAUNCH.md refreshed vs shipped system; staging rehearsal owner-gated |

## Sol review gates
The MCP transport blocker is CLEARED: on the fresh 2026-07-13 session (Codex CLI 0.144.3), the
prior codex MCP server had been restarted and `mcp__codex__codex` (model `gpt-5.6-sol`, sandbox
read-only) responded normally. Gate 1 ran as a true adversarial loop — Sol found real defects each
round; Fable fixed, tested, committed, and re-submitted on the same thread until PASS.

| Gate | Scope | Thread ID | Disposition |
|---|---|---|---|
| 1 | Catalog, brand, architecture, open-core boundary | `019f5d11-c4f2-70e3-ad85-1111ffedf685` | **PASS** (2026-07-13, after 4 fix rounds: e0c1581, ca2e4a6, 2cb4cf8, d8cff3c) |
| 2 | Tenancy, target verification, scope, worker isolation | — | pending |
| 3 | Billing, entitlement, usage ledger, free-tier liability | — | pending |
| 4 | Final diff, threat model, ops, website claims, launch readiness | — | pending |

Gate-1 defects closed (each re-verified by Sol): replay-proof idempotent enqueue; fail-closed
billing webhook (503 without secret); execution-side concurrency/retention/integrations
enforcement; subscription catalog-version pinning; `web/` restored to Apache-2.0 with corrected
ADR-0001 boundary; honest API/CLI pricing language; honest ADR-0002/0003 implementation status;
refunded idempotency keys burned (409); atomic API-key quota; enqueue-race rollback; per-IP +
platform-wide signup throttles on BOTH signup surfaces; automatic global run/verified-run circuit
breaker inside the ledger transaction; cross-workspace hostname verification cap.

## Open risks
- Full hosted deployment (live Postgres, Stripe live mode, deployed Next.js backend, workers, IaC-provisioned cloud) requires owner-only external credentials — tracked in `OWNER_ACTIONS.md`.

## True external blockers
See `docs/saas/OWNER_ACTIONS.md`.

## Exact next action
Gate 1 is **PASS** (thread `019f5d11-c4f2-70e3-ad85-1111ffedf685`). Run Gates 2 → 3 → 4 over
`mcp__codex__codex` the same way (fresh thread per gate, read-only, `gpt-5.6-sol`), fixing any
findings between rounds and recording thread IDs + verdicts above. After Gate 4 passes, the
remaining work is owner-gated only: (a) owner credentials for cloud deploy (OWNER_ACTIONS #1–8);
(b) staging rehearsal + counsel review once (a) lands. Do NOT mark anything launch-ratified until
Sol gates 1–4 pass. Suite state at Gate-1 PASS: 360 tests OK, smoke PASS (d8cff3c).

## Phase 9 evidence (2026-07-13)
- `tests/test_saas_adversarial.py` (8): forged/mutated cookies + bearer keys → 401; client-supplied
  role claims ignored (server-side membership only); cross-tenant job read → 404, cross-tenant key
  revoke → 404/403; invite tokens workspace-bound; webhook duplicate not re-applied and stale
  timestamp → 400; idempotent duplicate enqueues charge exactly once; 60-thread quota race on
  separate connections yields exactly 25 grants / 35 denials; malformed JSON 400, non-object 400,
  oversized body 413, path junk 404.
- Recovery drill covered by Phase 8 backup VERIFY PASS; browser/load tests against deployed cloud
  infra remain owner-gated.

## Phase 8 evidence (2026-07-13)
- `scripts/saas_smoke.py` — boots the real server, drives signup → synthetic run → target verify →
  scope-guarded verified run → checkout → kill switch → metrics; SMOKE PASS locally.
- `scripts/saas_backup.py` — SQLite online-backup + restore verification (integrity_check,
  migrations current, reconcile clean) per the restore-drill runbook; VERIFY PASS on a real copy.
- Makefile: `saas-smoke`, `saas-backup`, `saas-restore-verify`, `saas-site`. CI: smoke + site
  build added to the test matrix. Cloud IaC/staging remain owner-credential-gated
  (OWNER_ACTIONS).

## Phase 7 evidence (2026-07-13)
- `heel/saas/ops.py` — global/per-workspace kill switches denying new run enqueues (503) with
  mandatory reason + append-only `admin_audit`; thread-safe metrics counters with text exposition.
- HTTP: `/v1/healthz`, `/v1/readyz` (DB probe), `/v1/metrics`; `runs_enqueued_total` /
  `quota_exceeded_total` counters wired at the enqueue choke point.
- `docs/saas/RUNBOOKS.md` — kill switch, target abuse, billing support, key rotation, credential
  breach, restore drill, generic incident; all local steps executable today, owner steps marked.
- Tests: `tests/test_saas_ops.py` (5).

## Phase 6 evidence (2026-07-13)
- `heel/saas/site.py` — static site generator (index, pricing, docs, security, terms, privacy).
  Pricing/quotas rendered FROM `catalog.py` so the site cannot disagree with enforcement; every
  marketing claim maps to an enforcing module; legal pages carry a visible "template — requires
  counsel review" banner (owner action). Never touches tenant data.
- Lifecycle email remains a stub by design (invite tokens returned in-band); real ESP is an
  owner-credential adapter, listed in OWNER_ACTIONS.
- Tests: `tests/test_saas_site.py` (6) — catalog/site consistency, safety claims present, no
  secret/tenant material in output.

## Phase 5 evidence (2026-07-13)
- `heel/saas/dashboard.py` — server-rendered `/app` on the same control plane and session auth:
  signup/login/logout forms (throttle-aware), dashboard with plan/state, usage bars, synthetic-run
  button, target add/check with published-record instructions, onboarding checklist. All output
  html-escaped (XSS test); anonymous access redirects to login; API keys cannot use /app.
- Tests: `tests/test_saas_dashboard.py` (6).

## Phase 4 evidence (2026-07-13)
- Quotas/ledger/dunning already landed in Phase 1 (`ledger.py`, `billing.py`; period buckets make
  monthly rollover implicit). New: `heel/saas/reconcile.py` — nightly-runnable invariant report:
  workspace plan-pin vs subscription mismatch, subscriptions for unknown workspaces, stale
  unsettled reservations (auto-refund under `repair=True` only when >24 h old AND no live job),
  unapplied webhook-event count. Repairs are customer-favorable only (refunds, never charges).
- Tests: `tests/test_saas_reconcile.py` (5).

## Phase 3 evidence (2026-07-13)
- `heel/saas/verification.py` — DNS TXT / HTTP-file ownership challenges, injected resolvers,
  24 h challenge TTL, 30-day re-verify window, revocation, per-workspace verified count.
- `heel/saas/egress.py` — default-deny allowlist; only the run's verified target, ports 80/443;
  post-resolution private/loopback/link-local IP refusal (DNS-rebinding block).
- `heel/saas/jobs.py` — reserve-at-enqueue settlement (consume on success, refund on
  failure/lease expiry via reaper), worker leases + heartbeat, immutable RunBudget (60 s wall
  clock, token cap, egress limited to verified target). Verified jobs fail closed: verified
  target + engine-minted scope reference required; no validator configured → disabled.
- HTTP wiring: `/targets`, `/targets/check`, `/jobs/{id}`; verified `/runs` path 403s and
  refunds reservations on any guard failure; verified-target plan limit → 402 + upgrade hint.
- Tests: `tests/test_saas_job_plane.py` (14).

## Phase 2 evidence (2026-07-13)
- `heel/saas/auth.py` — PBKDF2 (600k iters) passwords, hashed opaque sessions with TTL+idle
  expiry, per-email lockout throttle.
- `heel/saas/migrate.py` — ordered versioned migrations + `schema_migrations` tracking,
  sqlite/postgres dialect translate, parametrized `copy_table` export.
- `heel/saas/http_api.py` — loopback-default JSON control plane; every workspace route through
  `tenancy.require`; API keys workspace-bound, never owner/admin, never `create_scope`
  (human-only preserved); verified runs 501 until Phase 3; signed webhook + plan re-pin;
  quota 402 with upgrade hint.
- Tests: `tests/test_saas_http_api.py` (15).

## Fresh verification (2026-07-13, HEAD)
`python3 -m unittest discover -s tests -p 'test_*.py'` → **331 tests, OK** · `make saas-smoke` → SMOKE PASS · backup/verify drill → VERIFY PASS (Python 3.14.3).
