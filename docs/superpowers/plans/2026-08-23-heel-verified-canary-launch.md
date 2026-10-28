# Heel Verified Canary Launch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the approved customer-local Heel Runner flow so a stranger can verify an isolated
staging origin, approve and execute a bounded read-only canary rehearsal from the web app or local
MCP, inspect findings locally, and separately authorize a findings projection for cloud history.

**Architecture:** New canary contracts, storage, runner identity, verification, and lifecycle live
beside the legacy static-review path; they do not overload `JobPlane`, local HMAC scopes, device
tokens, or `heel.findings-sync.v1`. The customer-local runner owns OpenAPI, canary credentials,
concrete fixture IDs, target traffic, raw evidence, and assessment outcomes. Heel Cloud owns exact
approval projections, asymmetric one-shot grants, operational coordination, quotas, audit, and
separately permitted `CanaryFindingsProjection.v1` records.

**Tech Stack:** Python 3.11–3.13, SQLite WAL/FULL, `cryptography` Ed25519 runner extra, stdlib HTTPS
and MCP JSON-RPC, TypeScript/React/Vitest, Cloudflare Worker/VPC binding, Docker Compose.

**Execution model:** `gpt-5.6-sol` is the accountable architect and integration watch: it scopes
each packet, freezes contracts, reviews results, arbitrates deviations, and owns final integration.
The configured OpenRouter `stealth/ox-alpha` capsule is the primary bounded implementation worker
for RED/GREEN TDD, fixtures, schemas, repetitive tests, packaging, and tightly specified patches;
it never receives secrets, customer data, private strategy, unrelated files, or Git history, and
its output is reviewed and applied by Sol rather than written directly into this worktree. Grok 4.6
may take larger capsule-safe multi-file packets, Opus 5 may take independent high-risk build or
review packets, and Fable provides fresh reasoning/reproduction review when available. A fresh Sol
pass checks spec compliance and a separate Sol pass checks code quality before the next task starts.

**Controlling design:**
`docs/superpowers/specs/2026-08-05-heel-verified-canary-rehearsal-design.md`.

---

## File structure

- `heel/canary_contracts.py`: duplicate-free canonical JSON and closed canary schemas.
- `heel/crypto.py`: Ed25519 key parsing, signing, verification, key IDs, and rotation-safe key sets.
- `heel/saas/canary_store.py`: tenant-bound persistence for runner, grant, run, event, receipt, and
  disclosure records.
- `heel/saas/network_guard.py`: exact-origin normalization and public-address-pinned HTTPS proof.
- `heel/saas/verification.py`: `VerifiedEnvironment.v1` challenge, attestation, expiry, revocation.
- `heel/saas/runner_auth.py`: runner pairing and proof-of-possession request authentication.
- `heel/saas/canary_runs.py`: execution approval, grant, claim, heartbeat, events, stop, result.
- `heel/saas/canary_disclosure.py`: one-use disclosure permit and canary findings persistence.
- `heel/saas/canary_reaper.py`: short background expiry/reconciliation cycle.
- `heel/runner/identity.py`: local runner key and pairing state.
- `heel/runner/control_client.py`: fixed-route runner control transport.
- `heel/runner/vault.py`: macOS Keychain/Linux Secret Service/headless ephemeral secret adapters.
- `heel/runner/openapi_routes.py`: local read-only route inventory.
- `heel/runner/catalog.py`: four fixed read-only scenario definitions.
- `heel/runner/compiler.py`: local manifest and signed approval-projection compiler.
- `heel/runner/http_transport.py`: exact-host, TLS-verified, cancellable target transport.
- `heel/runner/adapters.py`: four deterministic differential-read adapters.
- `heel/runner/execution.py`: budgets, action loop, assessment, operational receipts.
- `heel/runner/redaction.py`: closed credential/token redaction.
- `heel/runner/containment.py`: signed, closed-event local containment chain.
- `heel/runner/companion.py`: strict-loopback local result UI/API.
- `heel/runner/service.py`: runner supervisor, polling, heartbeat, stop, and CLI lifecycle.
- `apps/heel-cloud/lib/canary-api.ts`: exact browser control-plane client and validators.
- `apps/heel-cloud/components/canary/`: activation, approval, progress, stop, and disclosure UI.

Hot integration files (`heel/saas/http_api.py`, `heel/saas/migrate.py`, `heel/mcp_server.py`, and
`apps/heel-cloud/worker/index.ts`) remain sequentially owned by one implementation task at a time.

---

### Task 1: Freeze canonical canary contracts

**Files:**
- Create: `heel/canary_contracts.py`
- Create: `tests/test_canary_contracts.py`
- Create: `tests/fixtures/canary/contracts/approval-projection.v1.json`
- Create: `tests/fixtures/canary/contracts/operational-run.v1.json`
- Create: `tests/fixtures/canary/contracts/canary-findings.v1.json`
- Modify: `release/open-core-v1.json`
- Modify: `tests/test_open_core_release.py`

- [ ] **Step 1: Write the failing canonicalization and privacy tests**

Create tests that import this public API:

```python
from heel.canary_contracts import (
    APPROVAL_PROJECTION_SCHEMA,
    CANARY_FINDINGS_SCHEMA,
    OPERATIONAL_RUN_SCHEMA,
    ContractError,
    canonical_bytes,
    canonical_digest,
    parse_json,
    validate_approval_projection,
    validate_canary_findings,
    validate_operational_run,
)

def test_canonical_json_normalizes_unicode_and_mapping_order():
    left = {"label": "e\u0301", "count": 1}
    right = {"count": 1, "label": "\u00e9"}
    assert canonical_bytes(left) == canonical_bytes(right)
    assert canonical_digest(left) == canonical_digest(right)

def test_parser_rejects_duplicate_keys_and_non_integer_numbers():
    for raw in (b'{"a":1,"a":2}', b'{"a":1.5}', b'{"a":NaN}', b'{"a":true}'):
        try:
            parse_json(raw, max_bytes=128)
        except ContractError:
            pass
        else:
            raise AssertionError(raw)

def test_operational_projection_rejects_assessment_content():
    value = operational_fixture()
    value["assessment"] = "observed"
    with pytest.raises(ContractError, match="unknown field"):
        validate_operational_run(value)

def test_approval_projection_rejects_credentials_and_concrete_ids():
    value = approval_fixture()
    for field in ("credential_handle", "fixture_id", "headers", "payload", "script"):
        with pytest.raises(ContractError):
            validate_approval_projection({**value, field: "secret"})
```

Also assert exact keys, closed enums, NFC strings, integer bounds, 64 KiB approval limit, 256 KiB
local manifest limit, 256 KiB findings limit, normalized HTTPS origin, `GET|HEAD` methods, exact
port 443, one concurrency, 20 requests, five seconds/action, 60 seconds/run, and stable fixture
digests.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `python3 -m pytest tests/test_canary_contracts.py -q`

Expected: collection fails with `ModuleNotFoundError: No module named 'heel.canary_contracts'`.

- [ ] **Step 3: Implement the canonical core and closed validators**

The module must expose these exact contracts:

```python
APPROVAL_PROJECTION_SCHEMA = "heel.approval-manifest-projection.v1"
OPERATIONAL_RUN_SCHEMA = "heel.operational-run-projection.v1"
CANARY_FINDINGS_SCHEMA = "heel.canary-findings-projection.v1"
DISCLOSURE_PERMIT_SCHEMA = "heel.disclosure-permit.v1"

class ContractError(ValueError):
    pass

def parse_json(raw: bytes, *, max_bytes: int) -> object: ...
def canonical_bytes(value: object) -> bytes: ...
def canonical_digest(value: object) -> str: ...
def validate_test_manifest(value: object) -> dict: ...
def validate_approval_projection(value: object) -> dict: ...
def validate_runner_identity(value: object) -> dict: ...
def validate_execution_grant(value: object) -> dict: ...
def validate_operational_run(value: object) -> dict: ...
def validate_canary_findings(value: object) -> dict: ...
def validate_disclosure_permit(value: object) -> dict: ...
```

Implement duplicate rejection with `object_pairs_hook`, reject `parse_float` and
`parse_constant`, recursively reject booleans where integers are required, normalize every string
to NFC before canonical encoding, sort object keys, use UTF-8 without ASCII escaping, and append no
trailing newline. Every validator compares `set(value)` to its exact allowed key set and returns a
new normalized dictionary rather than mutating the caller.

- [ ] **Step 4: Commit exact golden fixtures and verify GREEN**

Generate the three fixtures from validator-accepted dictionaries in the test, write canonical JSON
plus one newline, and assert the literal SHA-256 digests in the test. Run:

`python3 -m pytest tests/test_canary_contracts.py -q`

Expected: all focused contract tests pass.

- [ ] **Step 5: Preserve the open-core boundary**

Add `heel/canary_contracts.py` to the Apache open-core manifest so runner and cloud validate the
same bytes without importing commercial modules. Extend `tests/test_open_core_release.py` to assert
the file is present and no `heel/saas/` path enters the artifact.

- [ ] **Step 6: Run regression gates and commit**

Run:

```bash
python3 -m pytest tests/test_canary_contracts.py tests/test_open_core_release.py -q
python3 -m unittest tests.test_findings_sync tests.test_review_contract -v
git add heel/canary_contracts.py tests/test_canary_contracts.py \
  tests/fixtures/canary/contracts release/open-core-v1.json tests/test_open_core_release.py
git commit -m "feat: freeze verified canary contracts"
```

Expected: all commands pass and the commit contains only Task 1 files.

---

### Task 2: Add canary persistence, Ed25519 authority, quotas, and production gates

**Files:**
- Create: `heel/crypto.py`
- Create: `heel/saas/canary_store.py`
- Create: `tests/test_crypto.py`
- Create: `tests/test_canary_migrations.py`
- Modify: `heel/saas/migrate.py`
- Modify: `heel/saas/catalog.py`
- Modify: `heel/saas/ledger.py`
- Modify: `heel/saas/server.py`
- Modify: `pyproject.toml`
- Modify: `deploy/Dockerfile.control-plane`
- Test: `tests/test_saas_core.py`
- Test: `tests/test_saas_server.py`

- [ ] **Step 1: Write failing migration, crypto, quota, and fail-closed tests**

Assert migration 6 creates tenant-bound environment, runner, key, nonce, projection, grant, run,
event, operational receipt, disclosure permit, canary findings, and canary audit tables. Assert
Ed25519 signs canonical bytes and rejects wrong key IDs/messages. Assert the new catalog pins
`active_runners=1` and `canary_runs=10` only for the new catalog version. Assert a consumed canary
reservation can receive one compensating `platform_fault_refund`, while legacy meters retain their
current no-refund-after-consumption behavior. Assert production construction refuses missing grant
signing private key, key ID, and trusted public key set before binding.

- [ ] **Step 2: Run focused tests and verify RED**

Run:

```bash
python3 -m pytest tests/test_crypto.py tests/test_canary_migrations.py \
  tests/test_saas_core.py tests/test_saas_server.py -q
```

Expected: failures identify missing migration 6, crypto module, meters, and production variables.

- [ ] **Step 3: Implement crypto and append-only migration 6**

Add a `runner` optional dependency on `cryptography` while keeping the browser/static core importable
without it. `heel.crypto` imports `cryptography` lazily and exposes:

```python
def ed25519_key_id(public_key_bytes: bytes) -> str: ...
def load_private_key_base64(value: str): ...
def load_public_key_set(value: str) -> dict[str, object]: ...
def sign_envelope(private_key, key_id: str, payload: bytes) -> dict[str, str]: ...
def verify_envelope(keys: dict[str, object], signed: dict[str, str], payload: bytes) -> None: ...
```

Append migration 6; do not edit migrations 1–5. Every durable record contains `workspace_id`, and
project-owned records also contain `project_ref`. Add uniqueness for runner public keys, consumed
nonces, `(run_id, sequence)`, one operational projection/run, and one findings projection digest.

- [ ] **Step 4: Implement new catalog meters and compensating refund**

Add `Meter.ACTIVE_RUNNERS` and `Meter.CANARY_RUNS`, bump `CATALOG_VERSION`, preserve prior catalog
snapshots, and expose an exactly-once `refund_consumed_in_transaction(reservation_id, reason)` that
accepts only `platform_fault|runner_fault` on `CANARY_RUNS` and records a linked negative adjustment.

- [ ] **Step 5: Wire fail-closed production configuration**

Require `HEEL_GRANT_SIGNING_PRIVATE_KEY_B64`, `HEEL_GRANT_SIGNING_KEY_ID`, and
`HEEL_GRANT_TRUSTED_PUBLIC_KEYS` in production. Parse them before acquiring the database lock, run
migration 6 before listener creation, and inject a `CanaryStore` plus signing authority into
`ControlPlane`.

- [ ] **Step 6: Verify and commit**

Run the focused tests plus `python3 -m unittest tests.test_saas_reconcile -v`; then commit as
`feat: add canary cloud foundations`.

---

### Task 3: Implement `VerifiedEnvironment.v1`

**Files:**
- Create: `heel/saas/network_guard.py`
- Create: `tests/test_verified_environments.py`
- Modify: `heel/saas/verification.py`
- Modify: `heel/saas/http_api.py`
- Modify: `heel/saas/server.py`
- Test: `tests/test_saas_job_plane.py`
- Test: `tests/test_saas_adversarial.py`

- [ ] **Step 1: Write failing exact-origin and hostile-network tests**

Cover canonical `https://host` origins; reject credentials, IP literals, ports, paths, queries,
fragments, Unicode ambiguity, private/special answers, rebinding, redirects, proxy environment,
oversized challenge bodies, cross-tenant IDs, expired proof, revoked proof, and executable
`production` classification. Assert the UI/API string is exactly
`ownership verified; environment classification supplied by you`.

- [ ] **Step 2: Verify RED**

Run: `python3 -m pytest tests/test_verified_environments.py -q`

Expected: missing `VerifiedEnvironment`/`PinnedHttpsVerifier` failures.

- [ ] **Step 3: Implement guarded DNS/HTTPS proof**

`network_guard.py` must expose exact-origin normalization, public-address classification, and a
redirect-disabled/proxy-disabled port-443 verifier that pins the resolved address while preserving
TLS hostname verification and caps the body and deadline. `verification.py` must persist project,
environment class, attestation text/version, proof/normalization version, structured failure code,
expiry, and revocation.

- [ ] **Step 4: Expose closed target routes and production-wire resolvers**

Add list/start/check/revoke routes with recent owner/admin checks for attestation/revocation. Return
closed response dictionaries and no challenge token after verification. Inject the real safe DNS
resolver and pinned HTTPS verifier in `build_server()`.

- [ ] **Step 5: Verify and commit**

Run focused, job-plane, adversarial, and server tests; commit as
`feat: verify exact staging environments`.

---

### Task 4: Add runner identity, pairing, and proof-of-possession control transport

**Files:**
- Create: `heel/saas/runner_auth.py`
- Create: `heel/runner/__init__.py`
- Create: `heel/runner/identity.py`
- Create: `heel/runner/control_client.py`
- Create: `tests/test_runner_identity.py`
- Create: `tests/test_runner_control_http.py`
- Modify: `heel/saas/http_api.py`
- Modify: `heel/saas/tenancy.py`
- Modify: `heel/saas/server.py`

- [ ] **Step 1: Write failing pairing, PoP, replay, and capability tests**

Assert a runner public-key fingerprint and phrase are shown before approval; existing device bearer
tokens cannot call runner routes; runner credentials expose exactly `runner_claim`,
`runner_heartbeat`, `runner_progress`, and `runner_result`; signed method/path/body/timestamp/nonce
tuples reject replay, stale clocks, changed bodies, changed paths, wrong runners, revoked keys, and
cross-workspace IDs.

- [ ] **Step 2: Verify RED**

Run: `python3 -m pytest tests/test_runner_identity.py tests/test_runner_control_http.py -q`.

- [ ] **Step 3: Implement runner pairing and identity storage**

Reuse only the browser ceremony shape from `DeviceAuthStore`. Create separate runner challenges,
identities, Ed25519 keys, proof nonces, capabilities, rotation, and revocation. Human approval
requires a recent owner/admin session plus exact phrase and full fingerprint match.

- [ ] **Step 4: Implement fixed-route immediate control requests**

`control_client.py` must have named methods rather than a public generic request method. Idle claim
polls use immediate responses; heartbeat/event/result/stop-ack requests carry monotonic sequences
and chained server nonces. Human requests and runner requests use separate short SQLite
connections/transactions so target I/O or PBKDF2 never blocks heartbeat.

- [ ] **Step 5: Verify and commit**

Run runner tests, existing device-auth tests, HTTP API tests, and server tests; commit as
`feat: pair authenticated Heel runners`.

---

### Task 5: Build the local compiler and secure credential vault

**Files:**
- Create: `heel/runner/store.py`
- Create: `heel/runner/vault.py`
- Create: `heel/runner/openapi_routes.py`
- Create: `heel/runner/catalog.py`
- Create: `heel/runner/compiler.py`
- Create: `tests/test_runner_vault.py`
- Create: `tests/test_runner_compiler.py`
- Create: `tests/test_runner_cli.py`
- Create: `tests/fixtures/canary/staging-openapi.json`
- Modify: `heel/cli.py`

- [ ] **Step 1: Write failing local-only compiler and vault tests**

Assert only `GET|HEAD` operations enter route inventory; concrete OpenAPI text and fixture IDs never
enter approval projection; random credential IDs remain local; Cloud/MCP see semantic roles only;
Keychain/Secret Service adapters never fall back to plaintext; headless FD/env secrets are not
persisted; unsupported secure storage blocks live execution but not static review.

- [ ] **Step 2: Verify RED**

Run the three runner tests and confirm missing-module failures.

- [ ] **Step 3: Implement local route state, vaults, and four scenario definitions**

Define fixed IDs for anonymous/authenticated read, object-ownership read, role-bound read, and
plan-entitlement read. Auth profiles are exactly anonymous, bearer, cookie jar, and `X-API-Key`.
The local store uses descriptor-anchored owner-only files but never stores secret values.

- [ ] **Step 4: Implement deterministic compilation and CLI slices**

Compile the full `TestManifest.v1` locally and upload only the signed
`ApprovalManifestProjection.v1`. Add `heel runner import-openapi`, `credential add`, `map`, and
`prepare`; every command emits bounded non-secret JSON or human text.

- [ ] **Step 5: Verify and commit**

Run compiler/vault/CLI tests plus existing OpenAPI and local-agent suites; commit as
`feat: compile local canary rehearsals`.

---

### Task 6: Build the read-only executor, containment, stop, and local companion

**Files:**
- Create: `heel/runner/adapters.py`
- Create: `heel/runner/http_transport.py`
- Create: `heel/runner/execution.py`
- Create: `heel/runner/redaction.py`
- Create: `heel/runner/containment.py`
- Create: `heel/runner/companion.py`
- Create: `heel/runner/service.py`
- Create: `tests/test_runner_adapters.py`
- Create: `tests/test_runner_http_transport.py`
- Create: `tests/test_runner_stop.py`
- Create: `tests/test_runner_redaction.py`
- Create: `tests/test_runner_companion.py`

- [ ] **Step 1: Write failing deterministic adapter and transport tests**

Use scripted local TLS transports and resolvers. Assert exact host/443, DNS before every connection,
peer pinning, TLS hostname verification, redirect rejection, no subdomains, five-second action
deadline, 20-request/60-second ceilings, one read-only retry, response cap, and one concurrency.

- [ ] **Step 2: Write failing containment, redaction, stop, and loopback tests**

Assert closed event codes and chained signatures; redact configured secrets and common token forms;
Cloud payloads contain no raw traffic; local/Cloud stop closes in-flight transport, starts no later
action, and acknowledges within five seconds. The companion accepts loopback, expected Host, and a
runner-local one-use fragment/bootstrap only; reject DNS rebinding, CORS, non-loopback, credential,
and raw-traffic endpoints.

- [ ] **Step 3: Verify RED**

Run all five focused tests and confirm failures are caused by missing runner executor modules.

- [ ] **Step 4: Implement minimal read-only execution**

Each adapter declares scenario/version, role/route requirements, request constructor, evaluator,
redactor, and `read_only` side-effect class. The executor emits local assessment
`blocked|observed|inconclusive` separately from Cloud disposition
`completed|incomplete|failed|stopped`.

- [ ] **Step 5: Implement supervisor and companion**

The supervisor polls at most every two seconds, heartbeats at least every second while active,
handles cancellation in a separate thread/event, and never performs target I/O under a Cloud DB
transaction. The companion binds `127.0.0.1`, sets `Cache-Control: no-store`, and exposes only
sanitized local result and disclosure-preview endpoints.

- [ ] **Step 6: Verify and commit**

Run focused tests, full local-agent/MCP static tests, and privacy scans; commit as
`feat: execute bounded local canary reads`.

---

### Task 7: Coordinate grants, lifecycle, quotas, stop, receipts, and disclosure

**Files:**
- Create: `heel/saas/canary_runs.py`
- Create: `heel/saas/canary_disclosure.py`
- Create: `heel/saas/canary_reaper.py`
- Create: `tests/test_canary_grants.py`
- Create: `tests/test_canary_lifecycle.py`
- Create: `tests/test_canary_stop.py`
- Create: `tests/test_canary_disclosure.py`
- Create: `tests/test_canary_quota.py`
- Create: `tests/test_canary_privacy.py`
- Modify: `heel/saas/http_api.py`
- Modify: `heel/saas/server.py`
- Modify: `heel/saas/reconcile.py`

- [ ] **Step 1: Write failing grant/lifecycle/race tests**

Assert recent owner/admin hostname retype and reason; approval projection signature; one
transaction for approval, quota reservation, job, nonce, and grant; runner-pinned claim;
single-use nonce; ordered idempotent events; legal lifecycle transitions; kill generation;
heartbeat/stop; race-safe quota settlement/refund.

- [ ] **Step 2: Write failing privacy/disclosure tests**

Assert `OperationalRunProjection.v1` never stores assessment; local digest preview precedes a
recent-human `DisclosurePermit.v1`; permit binds runner/run/schema/digest/bytes/workspace and expires
in ten minutes; upload bytes must match the digest; legacy findings approvals cannot authorize
canary disclosure.

- [ ] **Step 3: Verify RED**

Run all six canary service tests and confirm missing services/transitions.

- [ ] **Step 4: Implement transactional coordination**

Implement explicit transition tables, quota rules from the spec, runner-pinned claim, monotonic
events, one-second heartbeat state, stop generation, non-assessment operational projection, and
24-hour/seven-day/30-day retention. Start/stop a short reaper thread with the production server.

- [ ] **Step 5: Implement separate disclosure authority**

Validate `CanaryFindingsProjection.v1` independently, mint one-use permits only through a recent
human session, persist only the permitted exact projection, and return a closed receipt.

- [ ] **Step 6: Verify and commit**

Run focused canary services, adversarial, reconcile, server, and findings-sync regression suites;
commit as `feat: coordinate authorized canary runs`.

---

### Task 8: Ship the exact edge and immediate-value web workflow

**Files:**
- Create: `apps/heel-cloud/lib/canary-api.ts`
- Create: `apps/heel-cloud/app/dashboard/page.tsx`
- Create: `apps/heel-cloud/app/runner/page.tsx`
- Create: `apps/heel-cloud/components/canary/ActivationCard.tsx`
- Create: `apps/heel-cloud/components/canary/EnvironmentStep.tsx`
- Create: `apps/heel-cloud/components/canary/RunnerStep.tsx`
- Create: `apps/heel-cloud/components/canary/CanaryAccessStep.tsx`
- Create: `apps/heel-cloud/components/canary/RehearsalStep.tsx`
- Create: `apps/heel-cloud/components/canary/ApprovalDialog.tsx`
- Create: `apps/heel-cloud/components/canary/RunProgress.tsx`
- Create: `apps/heel-cloud/components/canary/DisclosureDialog.tsx`
- Create: `apps/heel-cloud/tests/canary-api.test.ts`
- Create: `apps/heel-cloud/tests/canary-activation.test.tsx`
- Modify: `apps/heel-cloud/worker/index.ts`
- Modify: `apps/heel-cloud/tests/privacy-boundary.test.mjs`
- Modify: `apps/heel-cloud/tests/production-artifact.test.mjs`

- [ ] **Step 1: Write failing API, edge, privacy, and activation tests**

Assert four activation steps, precise recovery states, immutable approval summary, hostname retype,
reason, progress/budget, stop, loopback result handoff, and separate disclosure. Assert exact human
and runner route regexes; cookie/bearer/signature headers never cross authority classes; forwarding,
connection-nominated, and internal-origin headers are stripped both ways; target traffic payloads
and generic run/job prefixes remain 404.

- [ ] **Step 2: Verify RED**

Run focused Vitest and production-artifact tests; confirm missing UI/API routes and the known
bidirectional header-stripping defect.

- [ ] **Step 3: Implement exact TypeScript client and edge allowlists**

Independently validate every closed response. Reconstruct headers from empty sets per route class,
apply per-route body limits, and forward no ambient authorization. Do not expose a generic
`request(path)` method from `canary-api.ts`.

- [ ] **Step 4: Implement the customer workflow**

Keep anonymous static review in the first viewport. Signed-in dashboard leads with Verify staging,
Pair runner, Add canary access, Run first rehearsal. The approval and disclosure dialogs remain
visually and semantically distinct; Cloud shows operational status only before disclosure.

- [ ] **Step 5: Verify and commit**

Run unit, node privacy, production artifact, typecheck, lint, and production build; commit as
`feat: ship canary activation dashboard`.

---

### Task 9: Add canary MCP, signed packaging, and the binary launch gate

**Files:**
- Create: `tests/test_mcp_canary.py`
- Create: `tests/test_canary_launch_journey.py`
- Create: `scripts/canary_staging_smoke.py`
- Modify: `heel/mcp_server.py`
- Modify: `heel/cli.py`
- Modify: `pyproject.toml`
- Modify: `MANIFEST.in`
- Modify: `release/open-core-v1.json`
- Modify: `scripts/build_open_core_release.py`
- Modify: `scripts/release_smoke.py`
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/publish.yml`
- Modify: `apps/heel-cloud/app/agent/page.tsx`
- Modify: `apps/heel-cloud/tests/mcp-quickstart.test.mjs`
- Modify: `docs/MCP_QUICKSTART.md`
- Modify: `docs/saas/OWNER_ACTIONS.md`

- [ ] **Step 1: Write failing MCP authority/conformance tests**

Expose a separately named canary family:

```text
heel_connection_status
heel_list_environments
heel_list_canary_scenarios
heel_prepare_rehearsal
heel_execute_grant
heel_canary_run_status
heel_get_canary_findings
heel_get_containment_summary
heel_compare_canary_regression
```

Assert MCP cannot verify targets, pair runners, create credentials, approve/mint/widen grants,
change disclosure, schedule work, or send arbitrary URL/header/payload/script input.

- [ ] **Step 2: Verify RED**

Run `python3 -m pytest tests/test_mcp_canary.py -q` and confirm missing tool failures.

- [ ] **Step 3: Implement local stdio tools and CLI launch commands**

Tools call runner-local services; `heel_execute_grant` accepts only an already signed, runner-bound
grant ID. Preserve all legacy static-review tool schemas. Add `heel runner start`, status, stop, and
open-result CLI commands.

- [ ] **Step 4: Package and sign the runner**

Include `heel/runner/` in wheel/sdist/open-core artifacts, keep Pyodide imports runner-free, publish
SHA-256 entries signed by the release Ed25519 key, verify before pairing, and document
`pipx install 'heel-sim[runner]==<version>'`. CI covers Python 3.11–3.13, macOS Apple silicon, Ubuntu
22.04/24.04, raw stdio, Codex CLI preset, and the manual Claude Desktop certification checklist.

- [ ] **Step 5: Run credential-free launch verification**

Run the full 739+ Python regression suite, all new canary tests, browser engine checks, all Node
unit/node/privacy tests, typecheck, lint, production build, Wrangler dry run, Compose parse,
backup/restore, open-core scan, release smoke, and local fake-target journey. Fix warnings, including
the current expected-disconnect `BrokenPipeError`, so completion output is clean.

- [ ] **Step 6: Run the owner-assisted deployed binary gate**

With owner-provided Cloudflare/provider secrets and a public isolated staging app, execute both:

```text
App: signup -> attest/verify -> pair -> map canaries -> approve -> run -> stop -> local result
     -> disclosure permit -> synchronized dashboard finding
Agent: Claude Desktop and Codex CLI -> prepare -> browser approve -> runner execute -> local result
       -> separate disclosure -> same dashboard result
```

Capture only digests, dispositions, timing, and redaction counts. Do not capture credentials, raw
responses, concrete fixture IDs, or OpenAPI content.

- [ ] **Step 7: Independent final review and release commit**

Require Sol spec compliance and final integration, plus independent code quality/security,
tenant/privacy, product-claim, and operations reviews with no Critical or Important findings. Use
Fable for a fresh highest-risk reproduction/reasoning pass when available; use Opus 5 for an
independent high-risk implementation or review packet where it materially reduces launch risk.
Commit remaining docs/artifacts as `feat: make verified canary rehearsal launch ready`.

---

## Plan self-review record

- **Spec coverage:** Sections 1–15 map to Tasks 1–9; anonymous/static value remains a regression
  gate, while deployed app and agent canary flows are Task 9's binary gate.
- **Privacy split:** Task manifest, approval projection, operational projection, local assessment,
  and canary findings projection are separate artifacts with separate authority.
- **Type consistency:** Contract names and enums match the controlling spec; legacy device,
  findings-sync, job, and static MCP contracts remain unchanged.
- **External blockers:** Provider accounts, production keys, public staging, PyPI authority, Claude
  Desktop certification, legal approval, and public go-live remain owner actions. Tasks 1–9 Step 5
  are executable without those credentials; Task 9 Step 6 is the only owner-assisted gate.
