# Heel Anonymous Browser Alpha Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a deployable Heel experience that shows a useful finding immediately and lets an anonymous visitor paste or drop an OpenAPI JSON document, review it entirely in their browser with the canonical Python engine, inspect the findings, and export the result without an account or upload; a private deployment is an acceptance preview, while the public-alpha claim requires explicit public-access approval and a public deployment.

**Architecture:** Preserve `web/` as the Apache-2.0 static control-room demo and create the commercial customer surface under `apps/heel-cloud/` from the Sites vinext starter. Package only the browser-safe Heel review dependency closure into a deterministic pure-Python wheel, self-host that wheel and a pinned Pyodide runtime, and execute it in a dedicated module Web Worker. The UI communicates with the worker through JSON strings, validates the strict `heel.review.v1` envelope again in TypeScript, and stores only completed result envelopes locally; raw OpenAPI input never enters a server route, cache, URL, analytics event, log, or durable browser storage.

**Tech Stack:** Python 3.11+ standard library, deterministic wheel packaging, Pyodide `314.0.3`, TypeScript 5, React 19, Next-compatible vinext, Vite, Tailwind 4, native Web Workers and IndexedDB, Node test runner/Vitest where needed, Cloudflare-compatible Sites hosting.

**Approved source:** `docs/superpowers/specs/2026-08-04-heel-agent-first-saas-launch-design.md`

---

## File structure and boundaries

- Create `heel/product_model.py`, `heel/openapi_model.py`, and `heel/static_review.py`: pure kernels extracted from the current mixed native/I/O modules, with compatibility re-exports left in place.
- Create `heel/browser_review.py`: strict JSON-text-in/JSON-text-out adapter over `review_openapi(..., execution_mode="browser_local")`; no I/O.
- Create `heel/review_answers.py`: bounded declarative operation-control answers that enrich an in-memory specification before a rerun.
- Create `scripts/build_browser_engine.py`: build a deterministic, allowlisted browser wheel and SHA-256 manifest; never include `heel.saas`, local storage, MCP, REST, credentials, or runner code.
- Create `tests/test_browser_review.py` and `tests/test_browser_engine_build.py`: native parity, safety, and artifact-boundary tests.
- Create `apps/heel-cloud/`: new commercial customer site initialized from the Sites vinext starter. Keep the nested application out of the Apache `web/` surface and apply the existing commercial license header policy to original source files.
- Create `apps/heel-cloud/app/`: metadata, layout, the immediate-value page, error boundary, and accessibility structure.
- Create `apps/heel-cloud/data/sample-openapi.json` and `sample-review.v1.json`: committed, generated, drift-checked first-viewport evidence.
- Create `apps/heel-cloud/components/review/`: input, finding, questions, privacy receipt, and export UI.
- Create `apps/heel-cloud/lib/review-v1.ts`: strict untrusted-data validator for the Python envelope.
- Create `apps/heel-cloud/lib/browser-review-client.ts`: worker lifecycle, timeouts, cancellation, and redacted errors.
- Create `apps/heel-cloud/lib/local-reviews.ts`: IndexedDB result-envelope storage only; raw documents are never persisted.
- Create `apps/heel-cloud/workers/heel-review.worker.ts`: pinned Pyodide boot and one-review-at-a-time execution boundary.
- Modify `apps/heel-cloud/worker/index.ts`: attach the production CSP and browser security headers to every app response.
- Create `apps/heel-cloud/scripts/prepare-runtime.mjs`: copy the allowlisted pinned Pyodide runtime and generated Heel wheel into `public/heel-runtime/`, with a verified manifest.
- Create `apps/heel-cloud/tests/`: schema, worker/engine, privacy, local-history, rendered-product, and production-build tests.
- Retain `heel/saas/dashboard.py`, `heel/saas/site.py`, and `web/` unchanged except for links added deliberately in a later migration. They remain tested compatibility/demo surfaces during this milestone.

### Product direction (already delegated by the owner)

Use a high-trust technical editorial direction: warm off-white working canvas, charcoal typography, restrained amber Heel accent, red only for blockers, green only for verified local/privacy state. Avoid generic dark-dashboard chrome. The first viewport contains a completed, realistic finding on one side and two decisive actions—**Run the sample** and **Analyze mine**—on the other. The page should feel like a launch review in progress, not a marketing site with a hidden app.

---

### Task 1: Scaffold the isolated customer application

**Files:**
- Create: `apps/heel-cloud/**` from the Sites vinext starter
- Modify: `apps/heel-cloud/package.json`
- Modify: `apps/heel-cloud/.gitignore`
- Modify: `apps/heel-cloud/.openai/hosting.json`
- Create: `apps/heel-cloud/README.md`
- Test: `apps/heel-cloud/tests/rendered-html.test.mjs`

- [ ] **Step 1: Verify the parent worktree and target are safe**

Run:

```bash
git status --short
test ! -e apps/heel-cloud
```

Expected: the worktree has no unexplained changes and the target does not exist.

- [ ] **Step 2: Initialize with the required Sites starter**

Run the bundled initializer with the exact new application directory as its target:

```bash
/Users/hellohelloalbus/.codex/plugins/cache/openai-bundled/sites/0.1.30/scripts/init-site.sh "$PWD/apps/heel-cloud"
```

Expected: dependencies install and the starter builds in `apps/heel-cloud`. The initializer creates a nested `.git`; remove only `apps/heel-cloud/.git` immediately so the application remains part of the Heel worktree. Never touch the parent `.git` or any broader directory.

- [ ] **Step 3: Freeze the application identity and dependency set**

In `apps/heel-cloud/package.json`:

- rename the package to `@heel/cloud`;
- keep the starter's pinned vinext/React/Vite/Cloudflare packages;
- add exact `pyodide: 314.0.3`;
- add exact Vitest and DOM-test dependencies needed by later tasks;
- add `test:unit: "vitest run"`, `test:node: "node --test tests/*.test.mjs"`, and `test: "npm run test:unit && npm run test:node"` scripts;
- keep `build`, `start`, and `lint` compatible with the starter;
- make `test` run unit/privacy/engine tests before the production build.

Do not add Clerk, Stripe, analytics, error reporting, uploads, D1, or R2 in this anonymous milestone. Keep `.openai/hosting.json` with `d1: null` and `r2: null`.

- [ ] **Step 4: Replace starter identity without building product UI yet**

Remove the starter preview marker/components and loading-skeleton dependency. Also remove the unused starter `db/`, `drizzle/`, `drizzle.config.ts`, `app/chatgpt-auth.ts`, Drizzle dependencies/scripts, D1 interfaces/bindings, and migrations; verify the build contains no database migration bundle. Add Heel metadata, a minimal accessible loading shell, the proprietary-file headers required by `ADR-0001`, and a concise app README that states the browser-local boundary. Do not copy the Apache control room wholesale.

- [ ] **Step 5: Verify the clean starter**

Run:

```bash
cd apps/heel-cloud
npm ci --ignore-scripts --no-audit --no-fund
npm run lint
npm run build
```

Expected: lint and the vinext deployment build pass; no database or object-storage binding is requested.

- [ ] **Step 6: Commit**

```bash
git add apps/heel-cloud
git commit -m "build: scaffold Heel cloud app"
```

---

### Task 2: Separate the pure review kernel and create the strict browser adapter

**Files:**
- Create: `heel/product_model.py`
- Create: `heel/openapi_model.py`
- Create: `heel/static_review.py`
- Create: `heel/review_answers.py`
- Create: `heel/browser_review.py`
- Create: `tests/test_browser_review.py`
- Create: `tests/test_review_answers.py`
- Modify: `heel/importers.py`
- Modify: `heel/launch_review.py`
- Modify: `heel/openapi_import.py`
- Modify: `heel/review_service.py`

- [ ] **Step 1: Write failing adapter tests**

Cover:

```python
from heel.browser_review import MAX_BROWSER_INPUT_BYTES, review_openapi_json

payload = review_openapi_json(json.dumps(valid_spec))
envelope = json.loads(payload)
self.assertEqual(envelope["schema_version"], "heel.review.v1")
self.assertEqual(envelope["execution_mode"], "browser_local")
self.assertEqual(envelope["privacy"], {
    "execution": "browser_local",
    "network_calls": False,
    "uploaded": False,
    "sync_intent": "none",
})
```

Also prove:

- canonical JSON is returned with no stdout/stderr side effects;
- native `review_openapi(..., execution_mode="browser_local")` and adapter output are exactly equal;
- duplicate keys, non-object roots, lone surrogates/invalid Unicode text, excessive bytes, excessive nesting/nodes, remote `$ref`, malformed OpenAPI, and secret-bearing examples fail closed with stable public error codes; malformed original UTF-8 bytes are tested later at the browser's fatal `TextDecoder` boundary because they cannot be represented by the Python `str` API;
- exception text never contains the submitted source, secret values, or Python traceback;
- declarative operation answers such as `tenant_filter: enforced`, `entitlement_check: enforced`, and `rate_limit: enforced` enrich a deep copy, remove the corresponding operation question/risk after rerun, and never weaken an existing declaration;
- `not_enforced` and `unknown` never add or remove a control: `not_enforced` preserves the finding/question and yields a typed UI receipt of `confirmed_gap`; `unknown` preserves them and yields `unanswered`; neither changes the strict engine envelope or its hashes;
- presentation semantics deterministically label every missing declaration as an assumption ("not declared in this OpenAPI; not proof the control is absent") and calculate only a UI-local confidence label: `preliminary` while any question is unanswered/unknown, `confirmed_gaps` when any answer is not enforced, and `improved` only when enforced answers reduce the question count and no confirmed gap exists;
- unknown question/surface/field/value, contradictory duplicates, excessive answer count/size, and product-level answers that cannot be applied safely fail closed;
- `socket`, `urllib`, subprocess execution, filesystem reads/writes, local project storage, MCP, REST, and SaaS imports are absent from the browser dependency closure, not merely uncalled.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
python3 -m unittest tests.test_browser_review tests.test_review_answers -v
```

Expected: import failure because `heel.browser_review` does not exist.

- [ ] **Step 3: Extract a genuinely pure dependency closure**

Move, without semantic changes:

- ProductModel constants/validation into `heel/product_model.py`;
- pure OpenAPI-object normalization/mapping into `heel/openapi_model.py`;
- static ProductModel comparison and review dataclasses into `heel/static_review.py`.

Keep file loading/writing in `heel/openapi_import.py`, Git/subprocess helpers in `heel/launch_review.py`, and other native operator conveniences in `heel/importers.py`. Preserve public imports through compatibility re-exports so existing CLI, MCP, SaaS, and tests do not break. Make `heel/review_service.py` import only the pure modules. Add an import-graph test that fails if the pure closure imports `os`, `pathlib`, `subprocess`, `socket`, `urllib`, storage, MCP, REST, runner, or SaaS code.

- [ ] **Step 4: Implement minimal declarative answer enrichment**

`heel/review_answers.py` accepts a bounded JSON array keyed by the existing operation `surface` and explicit fields. It may add only known static declarations to a deep copy of the spec when the value is `enforced`: tenant scope, server-side entitlement, and server-side rate limit. `not_enforced` and `unknown` are validated but perform no model mutation, so the corresponding finding/question remains. The module cannot delete declarations, answer product-level/broad-OAuth questions ambiguously, create paths, change targets, introduce `$ref`, or authorize live behavior. The adapter reruns the same canonical review against the enriched in-memory copy and returns only a normal `heel.review.v1` envelope; unanswered/unsupported questions remain visible. There is no answer receipt in the Python or worker transport.

- [ ] **Step 5: Implement the minimal adapter**

Expose:

```python
MAX_BROWSER_INPUT_BYTES = 2 * 1024 * 1024

class BrowserReviewError(ValueError):
    def __init__(self, code: str, public_message: str): ...

def review_openapi_json(source: str, answers_json: str = "[]") -> str:
    """Return canonical heel.review.v1 JSON without I/O or active execution."""
```

Parse source and answers with duplicate-key detection, enforce the existing structural limits before expensive traversal, require a JSON object, apply only validated answer enrichment, call only `review_openapi(spec, execution_mode="browser_local")`, validate the returned envelope, and serialize with `stable_json`. Map internal exceptions to a small documented public error vocabulary. Never accept URLs or file paths.

- [ ] **Step 6: Run native parity and safety tests**

```bash
python3 -m unittest tests.test_browser_review tests.test_review_answers tests.test_review_service tests.test_review_contract tests.test_openapi_import tests.test_launch_review -v
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add heel/product_model.py heel/openapi_model.py heel/static_review.py heel/review_answers.py heel/browser_review.py heel/importers.py heel/launch_review.py heel/openapi_import.py heel/review_service.py tests/test_browser_review.py tests/test_review_answers.py
git commit -m "feat: expose the Heel browser review kernel"
```

---

### Task 3: Build an allowlisted, integrity-pinned browser engine

**Files:**
- Create: `scripts/build_browser_engine.py`
- Create: `tests/test_browser_engine_build.py`
- Create generated: `apps/heel-cloud/browser-engine/heel_browser-1.1.0-py3-none-any.whl`
- Create generated: `apps/heel-cloud/browser-engine/manifest.json`
- Modify: `apps/heel-cloud/.gitignore`
- Create: `apps/heel-cloud/scripts/prepare-runtime.mjs`
- Test: `apps/heel-cloud/tests/browser-engine.test.mjs`

- [ ] **Step 1: Write failing artifact-boundary tests**

Require a reproducible wheel containing only:

```text
heel/__init__.py
heel/browser_review.py
heel/contracts.py
heel/entitlements.py
heel/openapi_model.py
heel/product_model.py
heel/review_contract.py
heel/review_answers.py
heel/review_rules.py
heel/review_service.py
heel/static_review.py
heel_browser-1.1.0.dist-info/{METADATA,WHEEL,RECORD}
heel_browser-1.1.0.dist-info/licenses/{LICENSE,NOTICE}
```

`contracts.py` and `entitlements.py` remain in the allowlist only because the pure ProductModel validator uses their `Affordance`, `Category`, `SyntheticTarget`, and `EntitlementGraph` types. The import-graph test must prove that actual dependency before packaging; if the extraction eliminates it, remove both rather than carrying unused code.

The test must reject unexpected modules, path traversal, duplicate archive names, non-deterministic timestamps/order, missing hashes, missing Apache-2.0 `LICENSE`/`NOTICE`, `heel/saas`, MCP/REST/runner/storage/native-I/O code, `.pyc`, secrets, and any former namespace. Build twice and assert byte-for-byte equality. A separate license-boundary test requires the established proprietary SPDX header on every original TypeScript/JavaScript/CSS source under `apps/heel-cloud`, while explicitly excluding generated, vendored, lock, manifest, image, and test-fixture assets.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
python3 -m unittest tests.test_browser_engine_build -v
```

Expected: failure because the builder and artifact do not exist.

- [ ] **Step 3: Implement deterministic wheel and manifest generation**

Use Python standard-library `zipfile`, `hashlib`, `base64`, `csv`, and `tempfile`; do not invoke a networked build backend. Pin archive timestamps, permissions, ordering, wheel metadata, and the explicit module allowlist. Write `manifest.json` with schema version, engine version, wheel name, byte length, and SHA-256. The script accepts an explicit output directory and never deletes outside it.

- [ ] **Step 4: Prepare self-hosted runtime assets**

`apps/heel-cloud/scripts/prepare-runtime.mjs` must:

1. validate the committed engine manifest and wheel digest;
2. copy only the Pyodide loader, WebAssembly/runtime files, and Python stdlib files needed for no-dependency Python execution from pinned `node_modules/pyodide`;
3. copy the wheel and manifest to `public/heel-runtime/`;
4. refuse symlinks, unexpected paths, digest mismatch, or an unpinned package version;
5. leave generated runtime files ignored by Git while keeping the small reviewed wheel and manifest tracked under `browser-engine/`.

Now add `predev` and `prebuild` hooks for `node scripts/prepare-runtime.mjs`; Task 1 intentionally left them absent so its clean starter build did not depend on a future task.

- [ ] **Step 5: Execute the real browser wheel under Pyodide in Node**

The Node test loads the local pinned runtime, installs/unpacks the local wheel without PyPI/CDN access, invokes `heel.browser_review.review_openapi_json` on the shared sample fixture, and compares the returned envelope to native Python output after the deliberate `execution_mode`/privacy-mode change. It must assert at least one finding and one recommended control.

Run:

```bash
python3 scripts/build_browser_engine.py --output apps/heel-cloud/browser-engine
python3 -m unittest tests.test_browser_engine_build -v
cd apps/heel-cloud
node --test tests/browser-engine.test.mjs
```

Expected: deterministic artifact tests and real Pyodide execution pass with network disabled.

- [ ] **Step 6: Commit**

```bash
git add scripts/build_browser_engine.py tests/test_browser_engine_build.py apps/heel-cloud/browser-engine apps/heel-cloud/scripts/prepare-runtime.mjs apps/heel-cloud/tests/browser-engine.test.mjs apps/heel-cloud/.gitignore apps/heel-cloud/package.json apps/heel-cloud/package-lock.json
git commit -m "build: package Heel for private browser execution"
```

---

### Task 4: Implement the worker boundary, strict client contract, and local result history

**Files:**
- Create: `apps/heel-cloud/workers/heel-review.worker.ts`
- Modify: `apps/heel-cloud/worker/index.ts`
- Create: `apps/heel-cloud/lib/browser-review-client.ts`
- Create: `apps/heel-cloud/lib/review-v1.ts`
- Create: `apps/heel-cloud/lib/local-reviews.ts`
- Create: `apps/heel-cloud/lib/review-presentation.ts`
- Create: `apps/heel-cloud/types/pyodide.d.ts`
- Test: `apps/heel-cloud/tests/review-v1.test.ts`
- Test: `apps/heel-cloud/tests/browser-review-client.test.ts`
- Test: `apps/heel-cloud/tests/local-reviews.test.ts`
- Test: `apps/heel-cloud/tests/privacy-boundary.test.mjs`

- [ ] **Step 1: Write failing strict-contract tests**

Create a typed `ReviewEnvelopeV1` plus `parseReviewEnvelopeV1(value: unknown)`. Test exact top-level/nested fields, schema and engine version, safe integers, finite numbers, lowercase SHA-256 hashes, result-hash integrity, summary counts, deterministic sort constraints, the static safety receipt, and exact browser-local privacy values. Unknown fields and malformed/untrusted worker output must fail closed. Also define and test `deriveAnswerReceipt(before, after, submittedAnswers)`: every answer must match a real pre-review question; `enforced` requires that question to disappear after rerun, while `not_enforced`/`unknown` require it to remain. It returns the exact UI-only applied/confirmed-gap/unanswered items and confidence label or fails closed on inconsistency.

- [ ] **Step 2: Write failing lifecycle and privacy tests**

Cover ready/review/result/error protocol messages with request IDs, one active request, stale-message rejection, explicit cancel by worker termination, timeout restart, crash recovery, 2 MiB preflight, bounded answer payloads, redacted public errors, and structured-clone-safe strings only. The privacy source test must fail if raw source is written to `localStorage`, `sessionStorage`, IndexedDB, Cache API, URL state, console, analytics, server actions, or `fetch`/XHR/WebSocket payloads.

- [ ] **Step 3: Run the new tests to verify they fail**

```bash
cd apps/heel-cloud
npm run test:unit
npm run test:node
```

Expected: failures because the strict contract, client, presentation projection, worker protocol, and local store do not exist.

- [ ] **Step 4: Implement the strict TypeScript validator and presentation projection**

Keep both dependency-free. Treat every worker response, submitted answer array, derived receipt, and IndexedDB value as untrusted. Do not duplicate review rules; TypeScript validates and presents the Python engine's envelope only. `review-presentation.ts` is the single authoritative receipt path: the main-thread client retains the validated pre-rerun envelope and submitted answers, validates the returned post-rerun envelope, then calls `deriveAnswerReceipt(before, after, answers)`. The worker transports only the envelope JSON. `review-presentation.ts` owns the exact assumption and UI-confidence vocabulary defined in Task 2 tests; these labels are never inserted into or represented as fields of `heel.review.v1`.

- [ ] **Step 5: Implement the dedicated module worker**

Boot sequence:

1. load only same-origin pinned runtime assets;
2. verify the Heel wheel against the manifest digest before unpack/install;
3. import `heel.browser_review` and report `ready`;
4. disable or guard `fetch`, XHR, WebSocket, EventSource, and dynamic package loading before accepting customer input;
5. accept a JSON string, call the adapter, return only a JSON result string or `{code, message}`;
6. never log source or traceback.

The worker does not silently fall back to a cloud/API route.

- [ ] **Step 6: Implement the main-thread client**

Start engine boot before the user submits. Enforce size before `postMessage`, expose progress states (`loading_engine`, `ready`, `reviewing`, `complete`, `failed`), terminate/recreate on cancel or timeout, validate every result, and retain the caller's textarea value plus declarative answers after a failure. A rerun retains the validated pre-rerun envelope on the main thread, posts the same in-memory source with the bounded answer array, validates the returned envelope, and derives the answer receipt locally from before/after/answers. It never persists or uploads either input.

- [ ] **Step 7: Persist results only**

Use one versioned IndexedDB database and object store keyed by `review_id`. Store a wrapper with validated `ReviewEnvelopeV1`, local `saved_at`, and `sync_state: "local_only"`. Never store the source document. Provide list/get/delete/clear functions, bounded item/count cleanup, and fail without preventing an in-memory review when browser storage is unavailable.

- [ ] **Step 8: Attach production browser security headers**

Wrap every response in `apps/heel-cloud/worker/index.ts` with a tested header policy, including a CSP that permits only same-origin scripts, assets, module workers, and the pinned WebAssembly execution requirement; `connect-src 'self'`; `worker-src 'self'`; no framing; strict referrer policy; MIME sniffing protection; and a conservative permissions policy. Preserve required vinext image handling. Tests must parse the actual worker source/build output and prove the Pyodide/worker URLs are allowed while third-party/CDN/API destinations are not.

- [ ] **Step 9: Run tests and commit**

```bash
cd apps/heel-cloud
npm run test:unit
npm run test:node
npm run lint
```

Expected: strict contract, lifecycle, storage, and privacy tests pass.

```bash
git add apps/heel-cloud/workers apps/heel-cloud/worker/index.ts apps/heel-cloud/lib apps/heel-cloud/types apps/heel-cloud/tests apps/heel-cloud/package.json apps/heel-cloud/package-lock.json
git commit -m "feat: run Heel reviews inside the browser"
```

---

### Task 5: Build the immediate-value customer interface

**Files:**
- Modify: `apps/heel-cloud/app/layout.tsx`
- Modify: `apps/heel-cloud/app/page.tsx`
- Modify: `apps/heel-cloud/app/globals.css`
- Create: `apps/heel-cloud/components/review/OpenApiInput.tsx`
- Create: `apps/heel-cloud/components/review/FindingView.tsx`
- Create: `apps/heel-cloud/components/review/QuestionList.tsx`
- Create: `apps/heel-cloud/components/review/PrivacyReceipt.tsx`
- Create: `apps/heel-cloud/components/review/ReviewWorkspace.tsx`
- Create: `apps/heel-cloud/lib/sample-openapi.ts`
- Create: `apps/heel-cloud/lib/review-export.ts`
- Create: `apps/heel-cloud/data/sample-openapi.json`
- Create: `apps/heel-cloud/data/sample-review.v1.json`
- Create: `scripts/build_browser_sample.py`
- Create: `tests/test_browser_sample.py`
- Create: `apps/heel-cloud/public/og.png` after the interface direction is stable
- Test: `apps/heel-cloud/tests/product-contract.test.tsx`
- Test: `apps/heel-cloud/tests/rendered-html.test.mjs`

- [ ] **Step 1: Write failing product-contract tests**

Require:

- a meaningful example blocker, its reachability reason, recommended control, and regression suggestion in the first rendered product view;
- visible **Run the sample** and **Analyze mine** actions before signup/install/payment;
- paste, keyboard-accessible file selection, and drag/drop for `.json`/OpenAPI JSON;
- file/source size shown before execution and oversize rejection before worker messaging;
- the first completed result opens the highest-severity reachable finding, followed by controls, regressions, and optional questions;
- operation-level tenant, entitlement, and rate-limit questions provide explicit enforced/not-enforced/unknown answers, and **Rerun with answers** visibly updates the review through the Python engine without persisting the source;
- local JSON and Markdown downloads without an API call;
- a precise privacy receipt: browser-local, source not uploaded, zero analyzer network calls, results saved only on this device, no sync intent;
- no login wall, fake cloud-save control, fake testimonial, invented customer count, or unsupported accuracy claim;
- responsive keyboard/focus behavior, reduced-motion support, semantic status announcements, error focus, sufficient contrast, and touch targets;
- no raw OpenAPI persistence or telemetry.

- [ ] **Step 2: Run the new product and sample tests to verify they fail**

```bash
python3 -m unittest tests.test_browser_sample -v
cd apps/heel-cloud
npm run test:unit
npm run test:node
```

Expected: failures because the generated sample artifacts and product interface do not exist.

- [ ] **Step 3: Implement the stable sample and executable provenance**

Bundle `apps/heel-cloud/data/sample-openapi.json`, a conventional SaaS sample covering trials, exports, tenant boundaries, entitlements, OAuth, and an agent-adjacent operation. Keep it small, sanitized, deterministic, and aligned with the native golden fixture. `scripts/build_browser_sample.py` runs the native adapter in `browser_local` mode and writes canonical `sample-review.v1.json`; `--check` rebuilds in memory and fails on drift. The Pyodide engine test must return that exact artifact. Render the committed result artifact in the server-rendered first viewport so useful evidence is visible before the worker downloads or boots.

- [ ] **Step 4: Implement the result-first page**

Build one cohesive route:

```text
Heel mark + "Runs here, not on our server" status
Launch headline + concrete one-sentence promise
Completed example finding | Run sample / Analyze mine workspace
Active result: gate, top finding, reachability, control, regression
Optional questions that improve confidence
Local privacy receipt + export + local-history controls
Agent/MCP availability link
Plain product boundaries and early-access pricing link/preview
```

Do not reproduce the old sidebar control room. Use realistic result content and progressive disclosure rather than a generic feature grid.

- [ ] **Step 5: Implement input, progress, recovery, and export interactions**

Keep source and guided answers in component memory. Decode dropped/selected file bytes with `new TextDecoder("utf-8", { fatal: true })`; reject malformed byte sequences before parsing, while Python continues to reject lone Unicode surrogates. Initialize the engine in the background, show honest loading/review states, allow retry/cancel, preserve the source on worker failure, and never upload as fallback. For safely supported operation questions, collect declarative `enforced`, `not_enforced`, or `unknown` answers and rerun the same Python engine; show the changed finding/question counts and the exact assumption/confidence/confirmed-gap receipt, and retain unsupported product-level questions for later modeling instead of pretending to answer them. Export validated envelopes with deterministic filenames and escaped Markdown.

- [ ] **Step 6: Generate one product-specific social card**

Once headline, palette, and interface motif are stable, use the required image generation path exactly once for a complete 1200×630 Heel card. Inspect all text. If unusable, retry once; otherwise wire `public/og.png` into absolute host-derived Open Graph/X metadata. If it cannot be validated, omit `og:image` rather than shipping a generic image.

- [ ] **Step 7: Run product and build tests**

```bash
cd apps/heel-cloud
npm test
npm run lint
npm run build
```

Expected: tests, lint, and the Cloudflare-compatible vinext deployment build pass. The output contains the self-hosted runtime and no source maps or raw test fixtures with secrets.

- [ ] **Step 8: Commit**

```bash
git add apps/heel-cloud/app apps/heel-cloud/components apps/heel-cloud/data apps/heel-cloud/lib apps/heel-cloud/public/og.png apps/heel-cloud/tests scripts/build_browser_sample.py tests/test_browser_sample.py
git commit -m "feat: deliver anonymous browser launch reviews"
```

---

### Task 6: Prove parity, privacy, deployability, and publish the alpha

**Files:**
- Create: `tests/test_browser_native_parity.py`
- Create: `apps/heel-cloud/tests/production-artifact.test.mjs`
- Create: `apps/heel-cloud/tests/browser-acceptance.md`
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`
- Modify: `docs/saas/OWNER_ACTIONS.md` only for genuinely external-account actions

- [ ] **Step 1: Add cross-runtime golden parity**

For the same OpenAPI fixture, compare native Python and the actual Pyodide wheel. Require identical schema/engine/product/source/model/baseline hashes, gate, summary, findings, controls, regressions, questions, and safety. Require the deliberate differences to be exactly `execution_mode`, its matching privacy execution string, and the derived `review_id`/`result_hash`; independently validate each envelope's hash and ID. Fail if any rule output drifts or if the two mode-specific identities do not differ.

- [ ] **Step 2: Add production-artifact privacy assertions**

Inspect the built output and require:

- same-origin pinned runtime and exact verified Heel wheel are present;
- no CDN URL, PyPI request, API review endpoint, analytics/error-reporting SDK, source map, `.env`, secret, former brand namespace, `heel.saas`, MCP, REST, runner, or raw customer/sample secret is shipped;
- security headers/CSP restrict scripts, workers, connections, framing, and referrers consistently with the app's runtime needs;
- the worker cannot access cloud persistence bindings.

- [ ] **Step 3: Put the browser gate in CI**

Extend CI to build the deterministic wheel, run Python browser tests, run the real Pyodide Node test, run application tests/lint/build, and inspect the production artifact. Cache dependencies without caching customer input. Keep Python 3.11–3.13 core coverage intact.

- [ ] **Step 4: Run the full repository launch gate**

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/build_browser_engine.py --output apps/heel-cloud/browser-engine --check
cd apps/heel-cloud
npm ci --ignore-scripts --no-audit --no-fund
npm test
npm run lint
npm run build
```

Expected: all suites and builds pass from a clean checkout. Record actual counts and timings; do not substitute previous results.

- [ ] **Step 5: Run independent gates**

Dispatch, sequentially:

1. Fable product/spec review against the approved design's immediate-value and privacy contract;
2. code-quality/security review of the Python/browser boundary, Web Worker, artifact builder, storage, and headers;
3. claim review of every customer-facing sentence.

Fix every Critical/Important issue and repeat the affected gate.

- [ ] **Step 6: Run the supported-browser acceptance and performance gate**

The Sites workflow forbids interactive browser QA unless the owner has explicitly approved browser testing. If that approval is not already explicit at execution time, request it once here; do not install or invoke standalone Playwright/Chromium as a workaround. After approval, read and use the in-app Browser control skill against the exact healthy local URL, and record the acceptance run in `apps/heel-cloud/tests/browser-acceptance.md`.

Exercise sample review, paste, drop, invalid JSON, oversize rejection, guided answer + rerun, cancel/retry, worker crash recovery, local history, JSON download, Markdown download, keyboard flow, and a narrow mobile viewport. Inspect requests during the review and prove no raw source or answer payload leaves the worker boundary. On a supported browser and warm app connection, require a meaningful example at initial render, sample completion within 30 seconds including first engine boot, and a useful finding from the maximum supported valid fixture within two minutes. Fix failures and repeat. Without this gate, the output is a private technical preview and must not be called a launch-ready browser alpha.

- [ ] **Step 7: Create the Sites project and persist hosting identity**

Read and follow the complete `sites-hosting` skill. Call `create_site` once, persist only the returned `project_id` plus the existing null D1/R2 bindings in `apps/heel-cloud/.openai/hosting.json`, and retain the returned short-lived source credential without placing it in a URL, file, environment example, Git configuration, log, or response.

- [ ] **Step 8: Rebuild and commit the exact deployable source**

Because hosting metadata changed, rerun the production build and artifact test. Then commit every reviewed browser-alpha source file, generated browser wheel/manifest, CI/doc change, browser-acceptance record, and `apps/heel-cloud/.openai/hosting.json`. Require `git status --short` to be clean after the commit.

```bash
git add heel apps/heel-cloud scripts/build_browser_engine.py tests .github/workflows/ci.yml README.md docs/saas/OWNER_ACTIONS.md docs/superpowers/plans/2026-08-04-heel-anonymous-browser-alpha.md
git commit -m "release: verify Heel browser alpha"
```

- [ ] **Step 9: Push, package, and publish through Sites**

Push the exact branch-head commit with the returned per-command HTTP authorization header and use that SHA as `commit_sha`. Package only `apps/heel-cloud` with the Sites `package-site.sh` helper and save exactly one version. Deploy privately for acceptance by default. To claim the public anonymous browser alpha, obtain explicit approval naming public access and deploy that exact validated version publicly; a private URL is labeled only as a private acceptance preview. Poll directly to success/failure and open the exact returned URL through the hosting handoff. Neither access level claims the later authenticated/cloud/billing phases are complete.

- [ ] **Step 10: Record the deployed milestone without changing source**

Record the deployed URL and version in the task handoff/control plane, not by mutating the already validated source after deployment. If a durable repository document must change, treat it as a new follow-up commit and do not imply that it was the deployed commit.

Expected milestone: a visitor can open the published site, see a real finding immediately, run the sample, paste/drop a valid OpenAPI JSON document, receive and export a strict browser-local review, recover from failures without upload, and continue using local CLI/MCP when the site or cloud is unavailable.

---

## Explicitly deferred to the next independently testable plan

- Clerk authentication, organizations, sessions, invitations, and password recovery.
- D1/Postgres durable cloud project state and server-side tenant authorization.
- Findings-only/sanitized-model synchronization and consent receipts.
- Local-runner device authorization and outbound cloud pairing.
- Remote MCP authentication and continuity.
- Stripe Checkout/Portal/webhooks, quotas, paid entitlements, and email.
- Managed isolated cloud execution, production operations, legal launch approval, and public billing activation.

The anonymous alpha must not stub these behind clickable controls or make launch claims about them. It creates a complete pre-account value path and the browser half of the local-first product; later plans add cloud custody only behind explicit consent and authentication.
