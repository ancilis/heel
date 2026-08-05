# Heel Findings-Only Continuity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans and complete each task with RED/GREEN tests plus independent review.

**Goal:** Let a customer run Heel locally in the browser or on their machine, explicitly sync only a privacy-minimized findings projection, and see the same hosted review continuity from the App and Agent without uploading the OpenAPI document or local review context.

**Architecture:** The public core projects a validated `heel.review.v1` envelope into a closed, canonical `heel.findings-sync.v1` request. Per-project HMAC pseudonyms preserve continuity inside one project while preventing cross-project correlation. The commercial Python control plane accepts the request transactionally behind a same-origin web proxy, meters only new substantive projections, and returns a stable receipt. A human web action or interactive CLI ceremony is the only approval authority; MCP may prepare and read sync state but cannot approve it.

**Launch decisions:**

- `surface_ref` and `source.result_ref` are client-asserted, project-pseudonymous provenance. `source.result_ref` is a project-keyed HMAC of the local review `result_hash`; the raw result hash never crosses the local boundary or enables cross-project correlation. Heel validates their format and internal canonical consistency but makes no server-attestation claim.
- Browser traffic reaches the Python control plane through a same-origin BFF/proxy with request-body logging disabled. Customer review storage does not move into the Cloudflare worker.
- Web sessions may approve through an explicit dialog. Machine sync requires device authentication plus an interactive CLI approval. API keys and MCP can prepare/read but cannot approve.
- Each project receives one immutable 32-byte namespace key for launch. A compromised namespace requires an explicit destructive namespace reset or new project; silent rotation is forbidden because it would break finding identity continuity.
- OWNER, ADMIN, and MEMBER may sync. OWNER, ADMIN, MEMBER, and VIEWER may read. BILLING cannot read review data.
- Both App and Agent continuity are required before this phase is accepted.

**Privacy ceiling:** The sync object never contains raw OpenAPI, routes, paths, descriptions, examples, product/model/source/baseline identifiers, raw surface IDs, reasons, free-form controls, questions, answers, regressions, arbitrary metadata, prompts, secrets, credentials, or customer data. `findings_only` is a maximum disclosure policy, never an automatic trigger.

---

## Task 1: Freeze the projection and receipt contracts

**Files:**

- Create: `heel/findings_sync.py`
- Create: `tests/test_findings_sync.py`
- Create: `tests/fixtures/findings_sync/request-one-finding.json`
- Create: `tests/fixtures/findings_sync/request-pass.json`
- Create: `tests/fixtures/findings_sync/receipt-created.json`
- Modify: `release/open-core-v1.json`
- Modify: `scripts/build_browser_engine.py`
- Modify: `tests/test_browser_engine_build.py`
- Modify: `tests/test_open_core_release.py`

- [ ] Add failing tests for exact request/receipt keys, recursive duplicate-key rejection, non-finite values, bool-as-int rejection, size/count limits, closed risk/control catalog, severity/reachability invariants, canonical ordering, stable IDs, projection hashes, and never-cross fields.
- [ ] Validate a complete canonical `heel.review.v1` envelope before projection. Reject altered review/result hashes, bad summaries, unsupported versions/modes, and malformed privacy/safety claims locally before any network path exists.
- [ ] Implement `project_findings_sync(review, project_ref, namespace_key)` with the exact `heel.findings-sync.v1` contract, tagged HMAC surface references, tagged finding IDs, deterministic ordering, and a projection hash that excludes execution mode and result hash.
- [ ] Implement strict receipt parsing for `heel.findings-sync-receipt.v1`.
- [ ] Commit Python golden fixtures for the approved one-finding and pass cases.
- [ ] Add the module to both public build allowlists and rebuild/check the browser and open-core artifacts.
- [ ] Gate: equivalent browser/machine findings have the same projection hash and IDs but preserve distinct project-pseudonymous source result references; a different project key changes all pseudonyms.

## Task 2: Add independent browser validation and projection preview

**Files:**

- Create: `apps/heel-cloud/lib/findings-sync-v1.ts`
- Create: `apps/heel-cloud/lib/findings-sync-client.ts`
- Create: `apps/heel-cloud/tests/findings-sync-v1.test.ts`
- Modify: `apps/heel-cloud/workers/heel-review.worker.ts`
- Modify: `apps/heel-cloud/tests/browser-privacy.test.ts`

- [ ] Write failing cross-language fixture tests and network-spy tests.
- [ ] Add an exact-key TypeScript validator that independently verifies Python-produced canonical requests, IDs, hashes, bounds, and receipts. Python remains the only projector.
- [ ] Add a pure worker `project_findings` message. Its result may contain only the allowed projection envelope; the raw source never enters an HTTP client.
- [ ] Add a client orchestrator that separates local review, local projection preview, explicit approval, transport, and receipt validation.
- [ ] Gate: Python and TypeScript accept/reject the same fixtures byte-for-byte, and preparing or previewing performs zero sync requests.

## Task 3: Add tenant projects, atomic persistence, and quotas

**Files:**

- Modify: `heel/saas/migrate.py`
- Create: `heel/saas/projects.py`
- Create: `heel/saas/findings_sync.py`
- Modify: `heel/saas/catalog.py`
- Modify: `heel/saas/tenancy.py`
- Modify: `heel/saas/ledger.py`
- Modify: `tests/test_saas_core.py`
- Modify: `tests/test_saas_control_plane.py`
- Modify: `tests/test_saas_adversarial.py`

- [ ] Append migrations for projects, projections, findings, source observations/receipts, immutable approval digests, and append-only audit events. Every row carries `workspace_id`.
- [ ] Provision one immutable per-project namespace key and return it only to authorized project clients. Never log or accept it in sync payloads.
- [ ] Add `SYNCED_REVIEWS` quotas: Hosted Free 3/month, Pro 25/month, Team 100/month. Add `sync_findings` and `view_synced_reviews` capabilities with the approved role matrix.
- [ ] Refactor ledger reservation so projection, findings, provenance, quota, receipt, and audit commit or roll back in one database transaction. Check the operational kill switch before admission.
- [ ] Enforce uniqueness for project-pseudonymous source result references, projection hashes, finding IDs, and idempotency digests inside `(workspace, project)`.
- [ ] Gate: exact retry returns the byte-equivalent receipt and charges once; same source/different projection returns 409; same projection/different source reuses the synced review and finding rows, creates one provenance event, and consumes no second projection quota.

## Task 4: Expose the authenticated same-origin API

**Files:**

- Modify: `heel/saas/http_api.py`
- Modify: `apps/heel-cloud/worker/index.ts`
- Modify: `tests/test_saas_http_api.py`
- Modify: `apps/heel-cloud/tests/production-artifact.test.mjs`

- [ ] Add workspace-scoped project create/list, findings-sync accept, and synced-review list/detail routes.
- [ ] Add a sync-specific strict JSON reader with duplicate-key rejection, identity content encoding only, 256 KiB raw/canonical request bounds, and non-echoing field/index error codes.
- [ ] Bind workspace, project, actor, role, capability, quota, and idempotency at the existing authorization choke point. Body `project_ref` must match the authorized route.
- [ ] Require `Idempotency-Key: fs1-<request_digest>` where the digest covers the complete canonical request.
- [ ] Add a same-origin BFF/proxy route to the Python API. Disable body logging, buffering to analytics, and error-reporting capture for sync traffic.
- [ ] Gate: cross-tenant references, roles, malformed bodies, replay races, and payload-echo attempts fail closed; production artifact tests prove no raw review sink exists in the web worker.

## Task 5: Ship explicit-consent App continuity

**Files:**

- Create: `apps/heel-cloud/lib/findings-sync-queue.ts`
- Create: `apps/heel-cloud/components/review/FindingsSyncDialog.tsx`
- Create: `apps/heel-cloud/components/review/FindingsSyncStatus.tsx`
- Create: `apps/heel-cloud/components/projects/ProjectHistory.tsx`
- Modify: `apps/heel-cloud/components/review/ReviewWorkspace.tsx`
- Modify: `apps/heel-cloud/app/page.tsx`
- Add/modify focused Vitest files beside these modules.

- [ ] Keep anonymous local value and local review storage unchanged.
- [ ] Require authentication and explicit project selection before the sync action appears.
- [ ] Show an allowed-field preview and epistemically precise copy such as “local model flagged” and “not declared”; never claim a proven vulnerability or production reachability.
- [ ] A human click approves the exact `(workspace, project_ref, request_digest)` for at most ten minutes. Never accept `approved:true` or equivalent client JSON.
- [ ] Persist only immutable approved request bytes, digest, retry state, and receipt in a separate IndexedDB queue. Any substantive change requires new approval.
- [ ] Gate: local review -> sign in -> create/select project -> explicit findings-only confirmation -> receipt -> hosted history survives logout/login, while network/queue/database/log assertions contain no never-cross data.

## Task 6: Ship device-authenticated CLI and MCP continuity

**Files:**

- Create: `heel/cloud_auth.py`
- Create: `heel/cloud_client.py`
- Create: `heel/sync_queue.py`
- Modify: `heel/cli.py`
- Modify: `heel/mcp_server.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_mcp_server.py`
- Add focused cloud-client/auth/queue tests.

- [ ] Add device login/status/logout with secure OS-backed token storage where available and permission-restricted local fallback.
- [ ] Add CLI sync prepare, interactive approve, status, and receipt/history commands. Approval is bound to the exact request digest and project and expires after ten minutes; immutable offline retries may refresh transport authorization only for the persisted human-approved digest.
- [ ] Add MCP prepare, preview, status, receipt, and history tools. MCP cannot mint or transmit human approval and cannot widen the disclosure policy.
- [ ] Keep API keys unable to approve sync requests.
- [ ] Gate: a licensed machine review can be prepared through MCP, approved only through the interactive CLI, accepted once by the server, and read back through both MCP and the App.

## Task 7: Prove the App+Agent continuity stopping condition

- [ ] Run Python unit, adversarial, migration, tenant, replay/race, quota rollback, retention/deletion, CLI, MCP, open-core artifact, and browser-engine artifact suites.
- [ ] Run web unit, privacy/network-spy, typecheck, lint, production build, and production-artifact suites.
- [ ] Run a clean end-to-end scenario in which browser and machine reviews of equivalent substantive input retain distinct project-pseudonymous source result references but converge on the same server `synced_review_id`, projection hash, and finding IDs.
- [ ] Inspect HTTP bodies, offline queues, database rows, audit events, application logs, and analytics to prove only the approved projection/provenance fields crossed the boundary.
- [ ] Independently review tenant isolation, consent authority, claims language, and raw-data absence.
- [ ] Stop this phase only when the same authorized project/history is visible from the App and Agent and all boundaries fail closed. Billing-provider integration, general marketing, and public launch deployment remain separate launch tasks.
