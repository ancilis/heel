# Heel customer-ready self-serve launch — re-scope, reality audit and design (T3S)

Date: 2026-10-19. Branch `feat/self-serve-product`, design base
`1250918a15902821cb899fd4af1b21a3249194df` (clean). Author: Claude Fable 5.1, fresh interactive
design session (T3S). **Design and specification only: no product, test, build, package,
configuration or artifact code changed.** Astra orchestrates under Kevin's persistent
authorization; Opus implements; a fresh Fable reviews. Nothing here is implementation or launch
acceptance.

**Authority.** This document is the current launch authority. It implements the approved human
correction recorded in `.git/self-serve-launch/CUSTOMER-READY-REQUIREMENT-2026-10-19.md` (Kevin:
"ready for a customer to sign up and use against their SaaS, give it location or url, creds and
let it go"). Where it conflicts with `2026-10-18-self-serve-product-launch.md` (the launch spec)
or `2026-10-18-self-serve-runner-bridge.md` (the bridge spec), this document wins; both older
documents carry a T3S banner naming exactly which of their assumptions are superseded (§2.3).
Everything in them that is not named there stays in force. Historical session logs and specs are
evidence, never authority over the latest human requirement.

Tags: **CONFIRMED** (command, test, URL, artifact or `file:line` at the design base) or
**INFERRED** (with the confirming action). Evidence for this session:
`.git/self-serve-launch/sessions/T3S-artifacts/`, `sessions/T3S-design.md`,
`sessions/T3S-closing.md`. All new routes, schemas, modules, tables and tests are marked
**(proposed)**; none exists.

Normative words: **MUST**, **MUST NOT**, **MAY**.

> **T3SR revision (2026-10-19, fresh independent Fable design review, commit after `f6a79ee`).**
> Astra's review `sessions/ASTRA-T3S-design-review.md` found six contradictions in the `f6a79ee`
> draft; `sessions/T3SR-review.md` verifies each one against evidence. The **draft claims
> superseded by this revision** are: (1) the credential path (draft §2.1 R5 / §2.4 / §4.4 / §5.3
> could not all hold; one path is now specified in §2.4 and §5.3, and the Worker and control
> plane are named as in-memory plaintext transit processors); (2) the raw-body caps (draft
> §2.4 256 KiB vs §3.2 2 MiB; now one table in §2.4 with transient discovery bodies); (3) the
> `form_login` profile (cookie-session HTML form; the real Zonal client is a JSON login that
> returns a bearer token, `sessions/T3SR-artifacts/zonal-public-static-observation.md`; now
> `login_exchange`, §3.6); (4) route templating by id-shape only (now a conservative
> classifier with canary tests, §3.3); (5) "nothing is scanned" during discovery and the
> circular allowlist restatement (now bounded discovery traffic and a provenance rule, §3.4–§3.5,
> with the finite contract in `2026-10-19-self-serve-discovery-contract.md`); (6) ownership
> proof read as provenance and one identity read as a plan pair (§6.4). Safety property 2 is
> **amended, not unchanged**: exactly one `login_exchange` POST per identity per discovery authorization or scan run under a
> distinct recorded authorization (§3.6). The historical T3S report (`sessions/T3S-closing.md`,
> `T3S-design.md`) stays as history; its "DESIGN PASS" was the author's verdict and is not Astra
> acceptance. This revision's verdict is in `sessions/T3SR-closing.md`.

---

## 0. Verdict summary

| # | Question | Answer |
|---|---|---|
| 1 | Can a customer today sign up, give a URL and credentials, and get findings? | **No.** No browser action starts any target traffic; the only real executor is the standalone CLI (`heel runner run`) plus a `serve` loop that executes nothing (§1). |
| 2 | What does the latest requirement change? | Three previously mandatory things become optional or forbidden as defaults: a customer OpenAPI document, a customer-installed runner, and engineer setup. Discovery becomes a product function. Final acceptance moves from a synthetic-only target to a real, authorized, unprepared SaaS plus a synthetic known-positive (§2, §6). |
| 3 | Which original invariants cannot be kept unchanged? | **One customer decision bundle (§2.4), three explicit amendments:** (a) credentials and scan evidence are held by a Heel-operated executor, not customer-local; (b) the credential enters through the browser and transits the Worker and control plane in memory; (c) GET/HEAD gains one `login_exchange` POST per identity per authorization or run. None of the three is "preserved"; each is named as an amendment in §6.1 rows 2 and 4. Preserved unchanged: signed immutable scopes, one-shot attempts, containment, isolation, revocation, redacted control-plane data, no credential in the control-plane database, logs, traces, metrics or model APIs. **Deliberately amended** (T3SR): the browser form is the credential entry point (the old "no credential in a browser payload" wording no longer holds for that one request), the Worker and control plane are in-memory transit processors of that one request (§2.4), and GET/HEAD gains exactly one `login_exchange` POST per identity per discovery authorization or scan run (§3.6). |
| 4 | Recommended default | **Managed execution plane** ("Heel-managed scanner"): the existing runner code (`LocalCanaryExecutor`, `TargetHTTPSClient`, containment, redaction, `RunnerStore`) run by Heel in an isolated per-workspace executor that pairs with the control plane through the existing runner protocol. The customer-local runner stays as an **optional private connector**, not the default onboarding (§2.2, §5). |
| 5 | What can be built before Kevin decides? | Everything that does not store a customer credential or raw body on Heel infrastructure: TLS repair, discovery engine, inventory-with-provenance and plan-request server work, managed executor in anonymous-only mode, findings projection, UI shell, ownership/authorization UX (§7.2). |
| 6 | Design verdict | **DESIGN PASS** for this specification as a reviewable, dependency-ordered plan with one explicit human decision. **Not** an implemented PASS, **not** a customer-ready PASS (§6.5). |

---

## 1. Proven current journey and barriers (reality audit at `1250918`)

### 1.1 Method

Graph-first per repository instruction: `get_architecture` (11 606 nodes, 31 996 edges, status
`ready`) and `search_graph` on the indexed project
`Users-hellohelloalbus-.codex-worktrees-heel-self-serve-product-heel`. Recorded limits:
regex alternation and `(?i)` patterns returned 0 results for symbols that exist (`RunnerService`
found with the plain name), and Python control-plane routes are not modelled as `Route` nodes
(the 20 `Route` nodes are TypeScript worker/header strings), so the `_match` matcher and literal
strings were read with `grep`/`sed` (fallback permitted for literals). Probe transcript:
`T3S-artifacts/t3s-reality-probes.log`. No test suite was rerun; the baseline of record stays
the R2 full validation (Python 1984 pass / 2 skip / 653 subtests; JS 204 unit / 70 Node / 5
engine / 41 browser / 3 parity; CONFIRMED `RUN-LOG.md` "T2b2R2 COMPLETE") and the T1 baseline
(1752/1/2, environment-attributed failure) is preserved as history, not erased.

### 1.2 What exists, what each customer step hits today

| # | Customer step (latest requirement) | Today | Evidence | Verdict |
|---|---|---|---|---|
| 1 | Sign up in a browser | Control-plane signup/login/session/lockout exist; browser → Worker path untested; no public deployment found | launch spec §2 rows 1–3; `T3S-deployment-facts.md` (no linked Railway project, v1.2.0 release has zero assets) | works (loopback API); **deploy missing** |
| 2 | Give the SaaS URL | `POST …/environments` issues an https-file or dns-txt ownership challenge with attestation | `heel/saas/verification.py:297-303` (`proof_method in {"https-file","dns-txt"}`), `:229` classes `staging/sandbox/production` | works (challenge); **proof requires the customer to place a file or DNS record** (§4.3) |
| 3 | Give credentials in the product | **No product credential entry exists.** Credentials exist only as runner-local records written by `heel runner credential add` with profiles `bearer`, `x_api_key`, `cookie_jar` (`anonymous` implicit) | `heel/runner/catalog.py:23-30`, `heel/runner/execution.py:332-337`, `store.py:815` | **missing**; no form-login profile (§3.6) |
| 4 | Authorize testing | Ownership attestation at challenge + human Approve of an exact projection digest with hostname retype | `verification.py:299`, `canary_runs.py` approve path (launch spec §7.2 step 6) | exists for the approval; **no discovery authorization** (§3.4) |
| 5 | Heel discovers routes | **Nothing.** Graph: no crawl symbol; `discover` symbols are the abuse-hypothesis model calls (`heel/model.py` `AnthropicModel.discover`, `heel/agents.py:heuristic_discover`), not HTTP route discovery. The only inventory source is an OpenAPI document (`heel/runner/openapi_routes.py:RouteInventory`, GET/HEAD only `:69`; browser parse in `review-v1.ts`) | `search_graph` results in probes log | **missing** (§3) |
| 6 | Heel scans | Real HTTPS executor exists and is CLI-only: `plan_differential._build_client` (`plan_differential.py:846`), `LocalCanaryExecutor`, 256 KiB JSON cap, public-address preflight (`http_transport.py:159` `not address.is_global` → refused), GET/HEAD compile (`compiler.py:123,384`), budgets `maximum_requests: 20` (`compiler.py:26`). `heel runner serve` exists (`cli.py:1186`, `daemon.py:688`) but its executor is `_ExecutionUnavailable` (`daemon.py:332-336,1307`); `RunnerExecutionAdapter` has graph in-degree 0 (no product constructor) | probes log | **bridge missing**; the control plane never sends target traffic (`canary_runs.py:3`) and there is no hosted worker (the legacy `JobPlane` has no executor in the tree) |
| 7 | Real HTTPS to a customer host | Both production TLS constructors use `ssl.PROTOCOL_TLSv1_2` (`http_transport.py:235`, `network_guard.py:248`); `AttributeError` on OpenSSL 4 builds; `network_guard.TLSTransport` loads zero CAs so the HTTPS ownership verifier fails closed on every real host | `sessions/T2bTLSD-design.md` F1–F3 (CONFIRMED probes), accepted design `ASTRA-T2bTLS-design-decisions.md` | **blocker for any real target, hosted or local** (§7.1 C1) |
| 8 | Findings with evidence | Local verdicts from stored responses (`evaluate_plan_pair`, `plan_differential.py:398`), `heel findings` CLI; no cloud result projection, no dashboard finding rows | launch spec §2 rows 12–13 | works CLI; **product missing** |
| 9 | Delete credentials / revoke | Runner revoke route, environment revoke, binding revoke exist; `unpair` refuses after binding (`context_bound`, open gap); no credential-delete UI | `sessions/T2b2-closing.md` verdict; `docs/PLAN_DIFFERENTIAL_RUNNER.md:500-502` | partial |

**Barriers to the required journey, in order of cost to the customer today:** (a) no deployment;
(b) must install Python ≥3.11 runner and keep it running (contradicts the requirement);
(c) must produce an OpenAPI document (contradicts); (d) must place an ownership proof file or DNS
record (allowed but must be surfaced as a customer action); (e) must type credentials in a CLI
(contradicts); (f) real HTTPS fails on OpenSSL 4 builds and the ownership verifier fails on all
builds (defect); (g) nothing turns an approved plan into target traffic from the product.

### 1.3 Authenticated target observation (evidence, not product proof)

Astra signed in to the proposed validation target through the customer-filled browser form
(`sessions/T3S-zonal-browser-evidence.md`): `/dashboard`, organization "Ancilis Demo Tenant",
role "ORG ADMIN", navigation Dashboard/Brief/Discovery/Agents/My Work/Certifications/Evidence/
Integrations/Agent Graph/Runtime Coverage, export buttons Posture PDF / OSCAL JSON / Evidence
CSV / Evidence NDJSON. CONFIRMED as browser UI evidence only. It proves: a form login with
organization slug + email + password (no form-login profile exists, row 3); one identity only
(no second identity, §4.5); export links that an authenticated HTML crawl would surface
(§3.2). It does **not** prove synthetic data, target provenance, authorization scope, or that the
application was not prepared for Heel. "ORG ADMIN" is an application string, never a plan label.

### 1.4 Reuse / gap matrix (modules named exactly)

| Capability | Reuse as-is (CONFIRMED present) | Extend | New (proposed) |
|---|---|---|---|
| Public edge, sessions, tenancy, quotas | `apps/heel-cloud/worker/index.ts` (fixed origin, allowlist), `heel/saas/{auth,tenancy,projects,entitlement,catalog,ledger}.py` | allowlist rows for §5.1 routes | — |
| Target ownership/authorization | `heel/saas/verification.py` (`VerifiedEnvironmentService`, attestation), `network_guard.py` (`PinnedHTTPSVerifier`, `BoundedDNSResolver`) | TLS repair (C1); authorization record fields (§4.3) | — |
| Credentials | `heel/runner/store.py` credential records (opaque handle, `plan_label`), `vault.py` backends, `redaction.py` | new vault backend for the managed plane (§5.3, gated by §2.4); `login_exchange` profile (§3.6) | browser credential intake routes (§5.1) |
| Execution | `heel/runner/{execution,compiler,http_transport,containment,coordinator,service,daemon,runtime,control_client,control_transport}.py`, `plan_differential.py` (`_build_client`, `evaluate_plan_pair`, `_load_observations`) | `RunnerExecutionAdapter` wiring in `daemon.serve` (bridge spec T4a, host-agnostic); discovery transport profile (§3.3) | `heel/runner/discovery.py` (§3); managed executor deployment unit (§5.2) |
| Inventory | `heel/runner/openapi_routes.py` (`RouteInventory`, `normalize_route_template`) | inventory rows carry provenance (§3.5) | discovery candidate store |
| Plan/approval/grant | `heel/saas/{canary_runs,runner_contexts,canary_disclosure}.py`, `heel/canary_contracts.py` (caps: actions ≤20, 64 KiB projection, 256 KiB findings, ≤20 observations `:314,403,591,646,669`) | v2 projection with `plan` object (bridge spec §4.1, unchanged); new `plan_kind: discovery` (§3.4) | plan-request routes (bridge spec T3a-s, unchanged) |
| Findings | `heel/regressions.py`, `heel findings`, `canary_contracts.validate_canary_findings` | result projection `heel.plan-differential-result.v1` (launch spec §7.3, unchanged) | dashboard rows, hosted evidence viewer (§4.6) |
| Packaging/deploy | `scripts/build_open_core_release.py`, `deploy/compose.yaml`, `Dockerfile.control-plane`, `ops.py` kill switch | managed-executor image + env (§5.2) | — |

Mock integrations are not journey evidence anywhere in this document (launch spec §11.1 items
2–4 remain binding).

---

## 2. Original vs latest requirements, conflicts, and the one decision

### 2.1 Matrix

| # | Original requirement (launch spec / CUSTOMER-EXECUTION-REQUIREMENT) | Latest requirement (CUSTOMER-READY-REQUIREMENT-2026-10-19) | Conflict? | Resolution in this spec |
|---|---|---|---|---|
| R1 | Customer imports an OpenAPI document | Customer MUST NOT need to provide OpenAPI | **Yes** | OpenAPI becomes optional input; discovery is the default inventory source (§3). Superseded. |
| R2 | Customer installs the released runner and keeps `heel runner serve` running | No manual runner installation as a prerequisite | **Yes** | Managed execution plane is the default; local runner is an optional private connector (§2.2, §5.4). Superseded as default. |
| R3 | Credentials entered by CLI on the customer machine, stored in OS keychain/secret-service | Customer gives credentials in the product and "lets it go" | **Yes** | Browser credential entry into the managed plane's vault (§4.4, §5.3). **Requires Kevin's decision (§2.4).** |
| R4 | Raw evidence stays on the customer machine; cloud receives bounded redacted projections | Customer receives understandable, evidence-backed findings without a machine | **Yes** | Raw evidence held by the managed plane under bounded retention; control plane still receives projections only (§5.3). **Part of §2.4.** |
| R5 | No credential in browser, cloud DB, logs, traces, metrics, model prompts | the customer types credentials into the product | **Yes (browser and edge)** | **Amended, not unchanged** (T3SR). The browser form holds the plaintext until submit; the Worker and the control plane process it **in memory, for one request, never persisting it** (named plaintext transit processors, §2.4 and §5.3); the managed executor's vault is the only persistent holder. Still absolute: no credential in the control-plane database, Worker/control-plane/executor logs, traces, metrics, crash reports, support exports, CI or model APIs (§6.1 row 4). A compromised Heel web application or edge can steal the input; the spec never claims otherwise. |
| R6 | Signed immutable scopes, one-shot attempts, grants bound to projection digest | unchanged | No | Preserved byte-for-byte; discovery runs use the same grant mechanism in rounds (§3.4). |
| R7 | GET/HEAD only, from an imported inventory | discovery must not hide writes | No, but needs a rule | Inventory = union of imported and discovered routes with provenance; execution still only from the approved inventory snapshot; a discovered route never widens host or method (§3.5). Exactly one narrow, separately authorized `login_exchange` POST per identity per discovery authorization or scan run (§3.6); safety property 2 is amended to say so (§6.1 row 2). |
| R8 | Isolated workspaces/projects, containment, revocation, safe quotas/auth | unchanged | No | Preserved; managed plane adds per-workspace isolation and egress restriction (§5.2). |
| R9 | Final acceptance on a synthetic staging SaaS through the public path | Synthetic is intermediate; a real authorized unprepared SaaS must validate the actual flow | **Yes (scope)** | Two acceptance layers (§6.3–§6.4). Synthetic-only PASS is superseded as final. |
| R10 | Two identities with operator plan labels (`lower_plan`/`higher_plan`) | Customer may have one identity | Partial | Identity slots: anonymous (implicit), identity A (required), identity B (optional). Plan differential needs B; with A only, anonymous-exposure comparison is the honest capability (§4.5). |
| R11 | Verified-environment ownership proof before any traffic | "give it location or url" | Partial | Ownership proof kept (it is the authorization control); surfaced as an explicit customer action with both methods and a visible gap when neither is possible (§4.3). |
| R12 | Twelve safety properties with named tests; clean-room acceptance | unchanged | No | Re-mapped to the managed plane (§6). |

### 2.2 Deployment/access options compared

| Option | Customer action | Credential custody | Raw evidence custody | Works for private/VPN SaaS | Keeps every original invariant | Verdict |
|---|---|---|---|---|---|---|
| A. Local runner only (current plan) | install Python ≥3.11, run `serve`, CLI credentials | customer | customer | yes | yes | Fails R2/R3 of the latest requirement. Kept as the optional private connector. |
| B. Browser-executed scanning | none | browser tab | browser | no | partially | Rejected: cross-origin responses are unreadable without the target's CORS consent; a browser extension is an installation; no durable evidence. |
| C. Managed execution plane (Heel-operated, isolated per workspace, existing runner code) | sign up, URL, credentials, approve | **Heel (new)** | **Heel (new)** | no (public addresses only, by design) | all except R3/R4 custody | **Recommended default.** |
| D. C by default + A as optional private connector | as C; A for private targets or customers who refuse custody | per choice | per choice | via A | as C | **Recommended shape** (C is the default onboarding; A is advanced). |

### 2.3 What is superseded in the two older specs (exact list)

Launch spec: §6 Access/Inventory rows (CLI credential commands and "Import OpenAPI" as the only
inventory path), §7.1 "browser parses OpenAPI" as the sole inventory source, §8.1 install
command as a **prerequisite** (it remains the private-connector install), §11 steps 4–7
(install/pair/CLI credentials/import) as the **default** clean-room path, §11.1 item 1 "sent by
the customer-local runner installed from the public download path" as the only released path,
§14 claim text. Bridge spec: §3.1 onboarding order as the **default** (it remains the
private-connector order), §9.1 task ownership where this document's §7 reassigns. Everything
else in both documents stays in force, in particular the v2 projection (§4.1), the serve loop
(§2), the result projection (§4 rows 11–13), the seams rule (§5), the quota/invitation fixes
(§6–§8), and the verification order (§9).

### 2.4 Proposal for Kevin: hosted custody of customer credentials and target responses (T3SR corrected)

This is the only change to a hard original invariant. It is prepared for review, not assumed.
Synthetic test-data permission for the Zonal environment does **not** approve custody of any
future customer's credentials; this proposal asks for that decision explicitly. No
implementation that stores a customer credential, or holds any real customer target response
on Heel infrastructure, may start before Kevin records a decision. Until then the hosted
executor may send traffic **only to Heel-owned synthetic fixtures** (C4 anonymous-only mode,
§7.2); it does not touch the Zonal target or any customer origin.

**The one secret path (Option 1, recommended): plaintext in transit through Heel's edge and
control plane in memory, persisted only in the executor's vault.**

| Item | Exact proposal |
|---|---|
| Data held | (a) per verified environment up to two identity credentials, profile `bearer`, `x_api_key`, `cookie_jar` or `login_exchange` (fields such as `org_slug`, `email`, `password`), each ≤4 KiB; (b) scan responses: ≤256 KiB each, ≤20 per run (`canary_contracts.py` caps), headers redacted before write (`redaction.py`), **retained**; (c) discovery responses: ≤2 MiB each (HTML/JS/JSON/XML/text), ≤20 per round, ≤100 per authorization, ≤32 MiB per authorization, **transient**: parsed in executor memory, reduced to `{method, route_template, provenance, status_code}` candidates, and discarded before the round result is reported; never written to disk, never retained, never projected. Transient processing is still processing of target data on Heel's plane and is stated as such. |
| Plaintext recipients, in order | 1. the customer's browser (form field until submit; the Heel web application's JS runs there, so a compromised Heel application or supply chain can read it); 2. the Cloudflare Worker edge (`apps/heel-cloud/worker/index.ts`) as a TLS-terminating proxy, request body in memory only; 3. the control plane intake handler, in memory for the lifetime of one HTTP request (≤10 s), which validates shape and hands the secret to the executor's long-poll claim (§5.3); 4. the managed executor for that workspace, which encrypts it into its vault. **No** database row, queue, cache, log, trace, metric, crash dump, support export, CI artifact or model API ever receives it; the intake handler runs with logging of request bodies disabled and the response carries only `{identity_id, state}`. |
| Persistent holder | only the managed executor's per-workspace vault (`vault.py` backend `envelope`, §5.3). The control plane stores `{identity_id, role_slot, plan_label, profile, created_at_ms, intake_state}` and never the secret. |
| Lifetime | Credential: until the customer deletes it, revokes the environment, deletes the project/workspace, or the environment verification expires, whichever first; deletion is acknowledged by the executor (`deleted_at_ms`) or shown as `delete_pending`. Scan responses: `FINDINGS_RETENTION_MS` (7 days, `canary_disclosure.py:38`), purged; deleted immediately on "Delete evidence" or environment revoke. Discovery responses: end of round. No new retention policy is invented. |
| Isolation | Per-workspace executor identity (its own Ed25519 runner key, paired through the existing protocol, §5.2); per-workspace vault data key wrapped by a provider KMS key where the host offers one, otherwise by `HEEL_EXECUTOR_MASTER_KEY_B64` held only in the executor's environment; vault AEAD associated data binds `{workspace_id, project_id, environment_id, identity_id, intake_request_id, runner_key_generation}` (§5.3); evidence directory per workspace and run with the existing inode guard. **A per-workspace process is not an OS security boundary by itself.** The selected managed architecture therefore **requires** an enforceable host boundary as a C4/C8 gate: container per workspace with read-only root FS and no shell, host-level egress policy allowing 443 to the verified origin's pinned addresses plus the control plane origin only (`test_executor_egress_policy_refuses_unlisted_host_private_address_and_port`), pinned DNS via the existing `BoundedDNSResolver`. If the chosen provider cannot enforce that boundary, C8 records an **unresolved deployment gap** and selects a capable host or stops; the product never ships a "application-level isolation only" disclosure as a substitute, and customer-ready PASS is not reachable without the gate. No hosting cost is committed by this proposal. |
| Trust assumptions, stated plainly | Heel becomes a **credential custodian** and a **processor of target response bodies**. A compromise of the Heel web application, the Worker, the control plane process memory, the executor host or the vault key exposes customer SaaS credentials and up to 7 days of scan response bodies for the affected workspaces. Response bodies may contain the customer's own end-user data; Heel's redactor removes known credential shapes (`redaction.py` header/assignment/bearer/JWT/API-token patterns) and **nothing else** — arbitrary sensitive scalars in a body are retained as evidence and shown in the viewer. Insider access must be governed (break-glass logging). Terms/Privacy must say all of this (legal acceptance, launch spec §15). Customers with stricter custody rules keep the private connector. This is not and MUST NOT be described as "customer-local". |
| UX consequence | Zero installation. URL → ownership proof → credentials in the browser → "Authorize discovery" → "Approve scan". "Delete credentials" and "Delete evidence" are one click with an executor acknowledgement. The credentials card says: "Held encrypted by Heel's managed scanner for this workspace until you delete them. Heel's web edge and control plane handle the value in memory while you submit it and never store it." |
| Option 2 (hardening, not required for this decision) | Browser-side sealing to the executor's public key so the Worker and control plane see only ciphertext. Honest assessment: the control plane serves both the JavaScript and the key, so sealing protects only against **passive** control-plane leakage (logs, memory dumps, database), not against an active control-plane compromise; it needs a WebCrypto-supported key type (ECDH P-256; X25519 is not available in every browser), an executor-signed key certificate, AEAD binding of `{workspace, project, environment, identity_id, request_id, expiry}`, a one-use ciphertext mailbox with TTL and replay protection, and audited rotation. It is **not** derived from the Ed25519 identity key by any conversion. Recorded as a possible C5b after C5, if Kevin wants the extra assurance; not assumed. |
| Alternative (ii) if raw-body custody is declined | Hosted credentials, no scan-body retention: verdicts computed in executor memory; only digests, key-path sets and redacted excerpts ≤512 bytes stored. Findings lose body-level inspectability; honest but weaker evidence. |
| Alternative (i) if credential custody is declined | Private connector only: the latest requirement is not met and this is reported as the product gap. |
| Recommendation | Accept Option 1 with alternative (ii) as the fallback for raw bodies. The decision Kevin records is one of: **1** (Option 1, retain bodies 7 days), **1-ii** (Option 1, no body retention), **i** (decline). |

Routine, reversible design choices below are made here under the Astra/Fable authorization
and need no Kevin decision.

---

## 3. Automatic discovery without a customer OpenAPI document

### 3.1 Principles

Discovery is **read-only reconnaissance under an explicit, bounded authorization**, executed by
the same executor path as scans (frozen manifest, signed grant, one-shot attempts, containment,
GET/HEAD, pinned host, public addresses only, no redirects followed). It is deterministic
(regex and HTML/JSON parsing); **no model API receives target bodies, headers or credentials**.
If model assistance is ever added for ranking, its input is limited to `{method,
route_template, provenance_kind, status_code}` and this sentence becomes a tested boundary.

### 3.2 Sources, in order (all same-origin, GET/HEAD)

| Phase | Identity | Seed / extraction | Provenance kind | Budget |
|---|---|---|---|---|
| 0 passive | none (0 requests) | customer-supplied URL; optional OpenAPI URL or file (kept as a source, not required) | `customer_url`, `imported_openapi` | — |
| 1 anonymous | anonymous | fixed seed list (exactly 12, constant `DISCOVERY_SEED_PATHS`, digest bound into round 1): `/openapi.json`, `/openapi.yaml`, `/swagger.json`, `/swagger/v1/swagger.json`, `/v3/api-docs`, `/api-docs`, `/api/openapi.json`, `/api/swagger.json`, `/.well-known/openapi`, `/robots.txt`, `/sitemap.xml`, `/` | `well_known_spec`, `robots`, `sitemap`, `html_link`, `script_src` | 12 requests (round 1) |
| 2 anonymous | anonymous | same-origin `<a href>`, `<link>`, `<form action>` (GET only), `<script src>` from phase-1 HTML; fetch ≤8 scripts; extract quoted path literals (`"/api/..."`, template literals, `fetch(`/`axios.` first-argument strings) | `js_literal`, `html_link` | ≤20 requests |
| 3 authenticated | identity A (then B if present) | app shell after login; same extraction as phase 2; follow same-origin navigation links depth ≤2 | `html_link_auth`, `js_literal_auth`, `redirect_location` | ≤20 requests per identity (one round each) |
| 4 spec parse | none | any discovered OpenAPI document parsed by the existing `RouteInventory` rules (GET/HEAD only) | `discovered_openapi` | 0 requests |

Budgets (T3SR, deterministic, two distinct clocks):

- **Authorization TTL = 15 min** (`expires_at_ms`): the window in which rounds may still be
  issued; it covers claim latency and the customer's idle time, not execution.
- **Global active execution budget = 120 s** across all rounds of one authorization
  (`max_total_execution_ms`), server-measured as Σ(round terminal time − round issue time) in
  `discovery_rounds`; the next round is refused when fewer than 10 s remain, and each round's
  grant wall budget is `min(60 000 ms, remaining)` (the existing per-run cap is 60 s,
  CONFIRMED `canary_contracts.py:591` `remaining_wall_ms > 60000` fails). This keeps the
  customer's **first useful finding ≤15 min** target (§4.2) viable: discovery ≤2 min of
  execution, not 15 min. If C3/C4 measurement shows 2 min is not achievable, the acceptance
  record states the measured number; nothing inflates the target silently.
- **Requests**: 5 rounds × ≤20 actions = ≤100 issued actions. The phase table above
  (12 + 20 + 20 + 20 = 72 planned, one spare round) is a per-round planning maximum; the global
  cap is on **actions the server has issued**, counted at issue time, not on runner-reported
  completions. An authorization that would exceed 100 issued actions is refused at issue.
- **Bytes**: per body ≤2 MiB (transport profile cap). Server-enforced by construction:
  ≤ issued actions × 2 MiB (≤200 MiB worst case). Executor-enforced tighter stop: ≤8 MiB per
  round and ≤32 MiB per authorization, reported in the operational receipt and shown; the
  server records runner-reported bytes as informational, never as the enforcement.
- **In flight**: one round at a time (the previous round must be terminal, §3.4); abandoned
  rounds are made terminal by the existing reaper at grant expiry (≤10 min) so the budget cannot
  hang.

Discovery bodies are **transient** (parsed in memory, discarded at round end, §2.4). When a
budget stops discovery early, the UI shows `discovery.partial` with the exact counters
(`rounds_used/5`, `actions_issued/100`, `execution_ms_used/120000`, `bytes_received`), never a
silent truncation.
Pages and scripts are fetched through a **discovery transport profile** (proposed,
`http_transport.py`): same `TargetHTTPSClient` guards (resolver pinning, public-address
preflight, TLS 1.2+, no redirects, host pinned) with accepted content types `text/html`,
`application/json`, `text/javascript`/`application/javascript`, `text/plain`,
`application/xml`/`text/xml` and the 2 MiB cap. Scan actions keep the existing 256 KiB JSON-only
profile; the profile is named in the frozen manifest action (`transport_profile: discovery|scan`)
and cannot be chosen by a response.

### 3.3 Candidate rules (safe method and path selection)

- Only `GET` and `HEAD` become candidates. A literal that evidently names another method (e.g.
  `method: "POST"` adjacent to the path) is recorded as `excluded: method_not_allowed` so the
  customer sees it; it is never executed.
- Must be same origin as the verified environment after normalization; anything else is
  `excluded: off_origin` (a discovered route is not authority to widen host scope).
- Deny-pattern list (case-insensitive path segments and query keys): `logout`, `signout`,
  `sign-out`, `delete`, `remove`, `destroy`, `reset`, `revoke`, `disable`, `unsubscribe`,
  `confirm`, `verify`, `accept`, `cancel`, `rotate`, `regenerate`, `impersonate`, `export-all`,
  `action=`, `token=`, `key=`, `code=` → `excluded: side_effect_risk`. GET with side effects
  exists in the wild; this list is a heuristic and the exclusion reason is shown.
- Static assets (`.js`, `.css`, `.map`, `.png`, `.svg`, `.woff*`, `.ico`) are discovery inputs,
  never scan candidates (`excluded: static_asset`).
- Query strings are stripped from templates; `page`, `cursor`, `offset`, `limit` keys are noted as
  `paginated: true` and never enumerated.
- **Templating is a conservative classifier, not an id-shape match** (T3SR; replacing only
  integers/UUIDs/ULIDs/hex is not secret-free: paths carry e-mails, account names, tokens and
  query-derived ids). A path segment is kept **verbatim in the template only if** all hold: it is
  1–32 characters of `[a-z0-9_-]` (after case-fold it equals the original), it contains no `@`
  or `.`, it does not match any `redaction.py` secret pattern (bearer/JWT/API-token/assignment),
  its Shannon entropy is <3.5 bits per character when ≥16 characters long, and it occurs as a
  constant in at least two independent sources (two distinct pages/scripts, or a static source
  literal plus a link). Every other segment becomes a positional placeholder `{p1}`, `{p2}`, …
  through `normalize_route_template`; its observed bytes live only in the executor's **local
  mapping** (today's `heel runner map` store) and enter the signed projection only as
  `bindings_sha256`. Query strings are never templated or projected. **Hash is not redaction**:
  a digest of a secret-bearing path is still never projected (bindings are hashed only after the
  classifier has replaced the segment). Raw bytes from any page, script or response never cross
  to the control plane; the boundary is "template of allowlisted vocabulary segments only".
  Named canary tests (C3): `test_route_templates_never_contain_email_token_jwt_hex_or_source_fragment_canaries` — a fixture whose links contain an e-mail, an `sk_live_…` token, a JWT, a 32-hex id, a `javascript:` URL and a 200-byte JS source fragment; assert none appears in any projection byte, inventory row or log.
- Response-body scalars are a separate policy: discovery bodies are never retained or projected
  (§2.4); scan bodies are retained on the executor with the known-credential redactor only, and
  the consent copy says that arbitrary sensitive customer data in a body is **not** redacted.
- Redirects are never followed by the transport. A same-origin `Location` on a 3xx becomes a
  candidate with provenance `redirect_location`; a cross-origin one is `excluded: off_origin`.
- DNS: the existing full-set pinning and recheck per request; a target whose addresses are not
  all global is refused by the preflight (`http_transport.py:159`) → environment state
  `target_not_public` (§4.2) → the private connector is the only path.
- Login walls: a phase-1/2 page that redirects to `/login` is recorded; phase 3 repeats it
  authenticated.
- Nothing in discovery captures browser credentials, fuzzes, writes, cycles lifecycle, or
  compares tenants. Those remain excluded (§8).

### 3.4 Authorization and execution model (bounded discovery traffic under one finite authorization)

Discovery **is target traffic**: up to 100 authorized GET/HEAD requests reach the customer's
origin before any scan. The UI never says "nothing is scanned"; it says **"Discovery traffic:
N of 100 requests sent to `<origin>`"**, and the later plan card's `scan_requests_sent: 0` counts
scan requests only.

The customer clicks **"Authorize discovery"** once (owner/admin, recent-auth, same-origin). The
server writes an immutable **discovery authorization** (`heel.discovery-authorization.v1`, exact
fields in `2026-10-19-self-serve-discovery-contract.md` §2): environment, actor, the fixed
bound `{max_rounds: 5, max_actions_per_round: 20, max_requests: 100, max_total_execution_ms:
120 000, max_wall_ms_per_round: 60 000, max_body_bytes: 2 MiB, expires_at_ms: created + 15 min}`
(§3.2 explains the two clocks), `identities_authorized`
(labels), `login_exchange_authorized`, the seed-list digest, and `authorization_digest`. It
reserves **one** `Meter.CANARY_RUNS` unit (idempotent on the client `Idempotency-Key`,
`ca1-…` pattern as today) for all rounds; the unit is refunded only if round 1 never issues.

Rounds reuse the existing grant path with no new trust path:

1. The executor compiles round `r` as a frozen manifest (`plan_kind: discovery`, ≤20 actions,
   `transport_profile: discovery`) and submits the signed v2 projection whose `plan` object
   carries `{authorization_id, authorization_digest, round: r, frontier_digest,
   cumulative_requests_before, sources}`. Round 1's frontier is exactly the 12 seeds; the server
   checks the digest. At every round end the executor uploads a signed **candidate report**
   (templates and source ordinals only, no values; `heel.discovery-round-report.v1`, contract
   spec §2.6) and derives the next frontier **only from its own recorded reports**, naming the
   recording round and ordinal in `sources`. The server grants a later-round action only if that
   recorded relationship holds (contract spec §4 step 9a), and a report's source ordinal must
   name an action its round actually issued (contract spec §2.6). Bodies never reach the server, so the
   server proves the recorded relationship, not page content: a compromised executor could
   record a fabricated same-origin GET/HEAD candidate but could not widen host, method, round
   count, action count or execution time (trust boundary, contract spec §2.6).
2. **Server auto-issue is bounded, not open-ended**: it issues a grant only if the authorization
   is `open` and unexpired, its authorizer still holds owner/admin membership (otherwise it closes
   `revoked`; an already-issued round keeps its bounded expiry, live gate and revoke, contract spec
   §4 step 2a), `r == rounds_issued + 1`, the previous round's run is terminal,
   `cumulative_requests_before == actions_issued_so_far`, `actions_issued_so_far + actions ≤
   100`, `execution_ms_used + 10 000 ≤ 120 000`, every action is GET/HEAD (plus the one
   `login_exchange` for the authorization when authorized and not yet performed) on the verified
   origin, and the kill switch generation matches. Otherwise it refuses with a
   closed reason (`authorization_exhausted`, `round_out_of_order`, `bound_exceeded`, …) and the
   authorization moves to `done` or `failed`. The human authorized the bound once; **every
   round's scope is immutable and inside that bound; no target content can widen it** (a page
   can only add same-origin GET/HEAD candidates to a later frontier that is itself capped).
3. Each round is a normal grant (`maximum_requests ≤ 20`, one-shot attempts, containment entries,
   live gate, revoke within 5 s). Stop at 5 rounds, 100 issued actions, 120 s of execution, the
   15-min TTL, revoke, or an empty frontier, whichever first.

Discovery output is a **candidate inventory**. Scanning (plan differential) needs the separate
"Approve scan" with hostname retype (§4.2).

### 3.5 Inventory provenance and the GET/HEAD allowlist rule (reconciled, non-circular)

The original invariant "only GET/HEAD in the imported inventory execute" becomes two rules with
distinct provenance:

- **Discovery traffic rule**: a discovery action may execute only if it is GET/HEAD on the
  verified origin **and** its target is either a fixed seed (round 1, digest-bound) or a
  candidate **recorded in a signed report of an earlier round of the same authorization**
  (`source.round < r`, `source.source_ordinal` names the action that produced it; the server
  checks the recorded relationship before granting, contract spec §4 step 9a), under a grant
  issued inside that authorization's bound (§3.4). "Where did this request come from" is always
  answerable from server records; whether the page really contained it is the executor's
  attestation (trust boundary, contract spec §2.6).
- **Scan traffic rule**: a scan action may execute only if it is GET/HEAD and its `(method,
  route_template)` is in the approved inventory snapshot bound into the signed projection
  (bridge spec §4.1, unchanged); an inventory row carries `provenance: [{kind, round,
  source_ordinal, status_code}]`, `first_seen_ms`, `state: candidate|selected|excluded`,
  `excluded_reason` and **no concrete URL, query or body**. The only non-GET/HEAD action that
  can ever compile is the single `login_exchange` of §3.6, which is not an inventory row.

The existing reject-never-truncate bound (≤200 routes) stays for import; a discovery that finds
more keeps the first 200 by phase order and reports `truncated_count` as a visible number.
Imported OpenAPI routes keep `kind: imported_openapi`. Enforcement points are unchanged: the
compiler's GET/HEAD check (`compiler.py:123`), the server's selection ⊆ snapshot check, and
the new server round check (§3.4).

### 3.6 Authentication types: supported, narrow POST, visible gaps

| Type | Support | Rule |
|---|---|---|
| Bearer token, `X-API-Key`, cookie jar pasted by the customer | supported today (`catalog.py:23`) | unchanged |
| **Credential exchange login (JSON or form POST → bearer token or session cookie)** — the Zonal shape is `POST /v1/auth/login`, JSON body `{org_slug, email, password}`, response `access_token` used as `Authorization: Bearer` (CONFIRMED in the public static client, INFERRED for the server; `T3SR-artifacts/zonal-public-static-observation.md`) | **new profile `login_exchange` (proposed, replaces the draft `form_login`)** | Declaration `{endpoint_path, encoding: json|form, field_map: {org_slug?, username|email, password}, result: {kind: bearer_json_pointer|set_cookie, pointer?: "/access_token"}, csrf: none|header_from_prelogin_get(name)}`. Heel **proposes** the declaration from static sources found in discovery (a literal `POST` call adjacent to a path containing `login|signin|session|token` and adjacent field literals), shows it in plain words ("Heel found a sign-in request to `/v1/auth/login` with fields org_slug, email, password and a token in `access_token`"), and the **customer only confirms it and types the field values** (slug, e-mail, password). The customer MUST NOT be asked to edit the endpoint, encoding, JSON pointer, header names or CSRF handling: any flow that needs such an edit is recorded as `auth_unsupported: login_shape_unknown` and **fails the no-engineer acceptance** for that target; it is a missing-automation gap, never a customer task. The deterministic extractor MUST derive the declaration from minified public SPA assets (fetch/axios call with a string literal path adjacent to `login|signin|session|token`, `method:"POST"`, a JSON body built from an object literal whose keys include a password-like field, and a response property read like `access_token`/`token` or a `Set-Cookie` result), tested by `tests/test_runner_discovery.py::test_login_declaration_is_derived_from_minified_spa_assets_json_body_to_bearer` on a generic fixture modelled on the observed shape (CONFIRMED static shape, `T3SR-artifacts/zonal-public-static-observation.md`) and by the no-host-special-case gate (§6.4 step 10: no Zonal hostname, asset name or string appears in the product). If Heel finds no candidate, the card offers "paste an API token or cookie from the app" as a **fallback path, not as default success proof**. Execution: **one `login_exchange` per identity per discovery authorization and one per scan run** — the returned token/cookie is held in executor memory and reused across that authorization's rounds, so a five-round discovery performs one login, not five; rate limit 3/hour/identity applies to exchanges (one discovery plus one scan fits); request body never written to evidence or logs (the login request is **not** a scan action and produces **no raw-body evidence**; only `{status_code, result_state}` is recorded); the optional pre-login `GET` for a CSRF token counts against the round budget. This is a **distinct recorded authorization** (`login_exchange_authorized: true` in the authorization record, "Authorize Heel to sign in as this identity" checkbox), not a general write capability; the manifest action type is `login_exchange` and the compiler refuses every other non-GET/HEAD method. Safety property 2 reads: "GET/HEAD only, plus at most one `login_exchange` per identity per discovery authorization or scan run, to the confirmed path" (§6.1 row 2). Username/password never enter raw-body evidence, projections or inventory rows. |
| SSO / OAuth redirect flows | **unsupported** | state `auth_unsupported: sso` with the advice to supply an API token or cookie if the SaaS offers one |
| MFA / TOTP / email codes, CAPTCHA, device-bound sessions | **unsupported** | same, `auth_unsupported: mfa|captcha|device_bound`; never bypassed. The Zonal client has an `mfa_required` branch (`/v1/auth/mfa/*`): if MFA is enabled on the test identity, Layer 2 reports this gap and does not PASS the authenticated flow. |

---

## 4. Customer UI and state flow (simple path)

### 4.1 Pages

Existing `/dashboard` step cards remain the skeleton (`components/canary/*`). The default path
hides the runner install card; it appears only under "Advanced: private connector".

### 4.2 States

| Step | State id | Visible condition | Customer action | Fail-closed / gap state |
|---|---|---|---|---|
| Sign in | `sign_in` | `/v1/me` 401 | signup/login | lockout |
| Target | `target.entered` | URL normalized to origin | "Prove you own it" | `target_invalid`, `target_not_public` (private address: "use the private connector") |
| Target | `environment.pending` | challenge shown with both methods: file at `/.well-known/heel-verify.txt` **or** DNS TXT; attestation checkbox text names authorization | "Check proof" | `environment.failed` reason; `ownership_unproven` stays visible as a customer-action gap |
| Target | `environment.verified` | verified record | enables Credentials | `revoked` |
| Credentials | `credentials.none` | no identity for this environment | "Add identity A": profile picker (bearer / API key / cookie / sign-in form), label field ("name this plan or role, e.g. free"), secret field; "Add identity B" optional | `credentials.unavailable` while §2.4 undecided: card shows "Credential entry is not yet available; use the private connector" |
| Credentials | `credentials.stored` | labels only, handles never, "held by Heel's managed scanner until you delete them" | "Delete" per identity; "Delete all" | `auth_unsupported: …` for sign-in forms needing SSO/MFA/CAPTCHA |
| Discovery | `discovery.authorize` | bound text (§3.4): "Heel will send up to 100 GET/HEAD requests to `<origin>` over up to five rounds, about two minutes of traffic, signed-out and as the identities you entered; this is target traffic" | "Authorize discovery" | — |
| Discovery | `discovery.running` → `discovery.done` | "Discovery traffic: N of 100 requests sent", `rounds_used/5`, `bytes_received`, candidates found, excluded counts by reason | — | `discovery.partial` (budget hit, TLS error, login failed) with reason and the same counters |
| Inventory | `inventory.candidates` | table: method, template, provenance kinds, state; default selection = first 10 `candidate` rows by phase order; "Import OpenAPI instead/also" link | select ≤10, "Approve scan" | `inventory.empty` ("No GET/HEAD routes were found; add an OpenAPI document or use the private connector") |
| Plan | `plan.review` | `plan_sha256`, selected pairs, identity labels, pairs `anonymous vs A` and/or `A vs B`, `scan_requests_sent: 0` (discovery traffic already sent is shown beside it, never hidden) | Approve with hostname retype | `plan.rejected` closed reason |
| Run | `run.running` | counters | Stop | `run.stopped`, `run.runner_revoked` |
| Findings | `findings.visible` | per route: verdict (`finding` / `held` / `inconclusive`), predicate, evidence state, what it means in one sentence, "View evidence" (hosted redacted viewer, §4.6) | "Save as regression" | `findings.none` ("No findings. N routes compared; M inconclusive because …") |
| Delete | — | "Delete credentials", "Delete evidence", "Revoke target" | — | run stopped with `target_revoked` |

**First useful finding ≤15 min** budget on the default path: signup 1 min; ownership proof is
customer-paced (file/DNS; typically 2–5 min); credentials 1 min; discovery ≤2 min; approve 1
min; scan ≤1 min; projection ≤10 s. The measured number is recorded in acceptance (§6.4 step
14), never assumed.

### 4.3 Ownership verification and explicit authorization

Kept: ownership proof by https-file or dns-txt with the attestation acknowledgement
(`verification.py:299`), environment class, the hostname retype on Approve. Added (proposed):
the authorization record `{environment_id, actor, discovery_bound, identities_authorized:
[labels], login_exchange_authorized: bool, recorded_at_ms}` shown in the UI and bound into the
discovery plan. Honest gap: a customer who cannot place a file or a DNS record cannot proceed;
the card says so. Supplied credentials prove account access, **not** ownership; they never
substitute for the proof. For the Zonal target, Ancilis must place the proof; this is a
customer action, recorded as such.

### 4.4 Credential entry, deletion, revocation (default path; Option 1 of §2.4)

Browser form → `POST …/environments/{env}/identities` (proposed, §5.1) over the Worker (TLS
terminated at the edge; body ≤8 KiB; passed through in memory) → the control plane intake
handler validates shape only (profile, label 1–32 printable ASCII, size, `login_exchange`
declaration fields) and holds the secret **in process memory for this one request** while it
hands it to the workspace executor's long-poll claim (§5.3). The handler returns `{identity_id,
intake_state: stored | not_delivered}` only. The control plane stores `{identity_id, role_slot,
plan_label, profile, created_at_ms, intake_state, deleted_at_ms}` and **never the secret**; the
Worker and the control plane are named **plaintext transit processors** (§2.4), and request-body
logging is disabled on this route by construction (`test_identity_intake_route_never_logs_or_persists_the_body`).
If no executor claims within 10 s the response is `not_delivered` and the customer re-enters;
nothing is queued. Deletion: `DELETE …/identities/{id}` → the executor deletes the vault item
and acknowledges (`deleted_at_ms`); until then the UI shows `delete_pending`. Environment
revoke deletes all identities and evidence for that environment. Rotation = delete + add.
Labels are the customer's words; the product never infers them from responses or role strings
(existing rule, `store.py:7049-7067`).

### 4.5 Identities without engineer setup

Slots: `anonymous` (implicit, no credential), `identity_a` (required for any authenticated
scan), `identity_b` (optional). Pairs compiled: `(anonymous, identity_a)` → "signed-out vs
signed-in" comparison using the existing `body_superset`/`marker_leak`/`status_parity` predicates
with `lower = anonymous`; `(identity_a, identity_b)` → the existing plan differential. Copy
states: "With one identity Heel can only compare signed-out and signed-in access. Add a second
identity on a different plan or role to look for plan-gating gaps." Empty bodies, errors,
denial envelopes and status-only matches remain `held`/`inconclusive` and can never become an
`observed` finding (`plan_differential.py:252-260,381-395`).

### 4.6 Evidence viewer (hosted, redacted)

`GET …/canary-runs/{run}/evidence/{ev1_ref}` (proposed) served by the control plane **by
proxying a bounded request to the workspace's executor** (never stored in the control-plane DB):
redacted headers, body ≤256 KiB, `[REDACTED:secret]` markers as today, owner/admin recent-auth
same-origin only, audit row per view. Under §2.4 alternative (ii) this viewer shows key paths
and ≤512-byte excerpts instead.

---

## 5. API, persistence, packaging, deployment, operations

### 5.1 Routes (proposed; all under `/v1/workspaces/{ws}/projects/{prj}/…`, owner/admin, recent-auth same-origin for state changes, Worker allowlist + body cap each)

| Route | Body / cap | Notes |
|---|---|---|
| `POST …/environments/{env}/identities` | `heel.environment-identity.v1` ≤8 KiB | §4.4; secret forwarded, never stored; gated by §2.4 |
| `DELETE …/environments/{env}/identities/{id}` | none | acknowledged deletion |
| `POST …/environments/{env}/discovery-authorizations` | `heel.discovery-authorization.v1` ≤2 KiB | §3.4; reserves one `CANARY_RUNS` unit |
| `GET …/environments/{env}/route-inventory` | — | now includes provenance and states (§3.5) |
| `PUT …/environments/{env}/route-inventory` | ≤64 KiB | optional OpenAPI import (unchanged from launch spec §7.1) |
| plan requests, claim, approval, result projection, permit, regressions | unchanged | bridge spec §4, launch spec §7.2–§7.4 |
| `GET …/canary-runs/{run}/evidence/{ref}` | — | §4.6 |
| executor control routes | unchanged runner protocol | the managed executor is a runner (§5.2) |

Tables (additive migrations, numbering continues from 30/31 of the launch spec):
`environment_identities` (metadata only), `discovery_authorizations`, `discovery_rounds`,
`route_inventories` provenance columns, `evidence_views` audit.

### 5.2 Managed execution plane (deployment unit)

- One **managed executor** process per workspace, started on first environment verification,
  running the existing daemon code path (`RunnerDaemon.serve` with `RunnerExecutionAdapter`,
  bridge spec T4a) with `HEEL_HOME` on a private per-workspace volume; same inode guard and
  secure-file helpers.
- **Pairing** uses the existing invite → exchange → approve → activate protocol, driven by the
  control plane's own service actor; the phrase/fingerprint human comparison is replaced by the
  service verifying the fingerprint it generated. This is acceptable because the executor is
  Heel's infrastructure, not an untrusted customer machine; the human comparison remains for the
  private connector. `Meter.ACTIVE_RUNNERS` (free = 1) counts the managed executor; a customer
  who adds a private connector on free must retire the managed one (stated in the UI).
- **Egress (C4/C8 gate, not optional)**: the executor host policy allows 443 to the verified
  origin's pinned addresses and to the control plane only (`EgressPolicy` semantics from
  `heel/saas/egress.py` applied at the host; the application-level preflight remains). The
  mechanism MUST be enforceable outside the executor process (container network policy or
  provider firewall) and proven by `test_executor_egress_policy_refuses_unlisted_host_private_address_and_port`
  against the real deployment unit; a provider that cannot enforce it is recorded as an
  unresolved deployment gap in C8 and blocks customer-ready PASS (§2.4 Isolation). No cost is
  committed now. **The default hosted service is never an
  unrestricted SSRF proxy**: every request is from a frozen, signed, approved manifest to one
  verified origin; private, loopback, link-local and literal-IP targets are refused at the
  preflight (`http_transport.py:159`) and by the environment verifier.
- **Image**: `heel-executor:<version>` from a new `deploy/Dockerfile.executor` (proposed) built
  from the open-core wheel plus the `runner` extra; non-root, read-only root FS, one writable
  volume; no shell. Hosting: the same provider as the control plane. Railway project metadata is
  reachable read-only (`T3S-deployment-facts.md`); new hosted resources are a cost decision for
  Kevin when C8 starts (no price invented).
- **Operations**: kill switch (`ops.trip`) stops all executors' new rounds (existing generation
  gate); runbook entries "delete all identities of a workspace", "rotate executor vault key",
  "break-glass evidence access" (audited); backups exclude vaults and raw evidence.

### 5.3 Secret path and vault backend (Option 1 of §2.4)

Control plane → executor delivery (proposed): the executor's existing PoP channel gains a
`credential-intake/claim` long-poll (same signing, nonce and capability shape as the permit
claim, bridge spec §4 row 12; ≤10 s hold). The intake handler of §4.4 completes the pending
long-poll of the **same workspace's** executor with the plaintext over the mutually
authenticated control channel, waits for the executor's **signed intake receipt**, then returns
to the browser. The receipt is `heel.credential-intake-receipt.v1 {identity_id,
intake_request_id, runner_key_id, runner_key_generation, stored_at_ms}` signed with the
executor's Ed25519 key through the existing `sign_envelope` (`heel/crypto.py:85`); it carries
**no value derived from the secret** — no hash, tag, length or checksum of the credential may
appear in any receipt, metadata row, browser response or log (a deterministic digest of a
password is an offline guessing oracle; the old Keychain integrity tag was acceptable only
inside the same vault ACL, T2bCQ1 qualification, and is not reused across the control channel).
Delivery is idempotent on `intake_request_id` (a server nonce bound into the long-poll
response): a retried hand-off with the same id returns the same receipt, a different secret
under the same id is refused. The secret exists on the control plane only in that handler's
memory for ≤10 s and in no table, queue, cache or ciphertext mailbox; a control-plane restart
loses it and the customer re-enters (`intake_state: not_delivered`). Environment revoke,
identity delete and workspace delete are also delivered as **tombstones on the executor's next
claim poll**, so the executor deletes the vault item even if the original acknowledgement was
lost; `deleted_at_ms` is set only from the executor's signed delete receipt.
There is **no X25519 or other key derived from the Ed25519 identity key**; Option 2 sealing, if
ever adopted, uses a separate, executor-generated, executor-signed key (§2.4). Vault backend
(proposed, `vault.py`): `envelope` — per-workspace data key wrapped by a KMS key where
available, else by `HEEL_EXECUTOR_MASTER_KEY_B64` (executor environment only, validated at start
like the other peppers, `server.py:120-245` pattern), AEAD `ChaCha20-Poly1305` from the already
pinned `cryptography==45.0.7` with associated data `{workspace_id, project_id, environment_id,
identity_id, intake_request_id, runner_key_generation, profile}`, so an item cannot be replayed
into another project, identity or key generation. The exact C5 proof (named tests for receipt
non-derivation, idempotent delivery, tombstone deletion, AAD binding) is owned by the C5
contract; this proposal promises no secret-derived tag anywhere. Secrets never appear in argv, child-process env, logs or metrics (existing redaction
and `test_i5` byte scans extended, §6.1 row 4).

### 5.4 Optional private connector (advanced path)

The customer-local runner stays exactly as specified in the launch and bridge specs
(install one-liner, pair, `serve`, CLI credentials, OS keychain, local raw evidence). The UI
presents it under "Advanced: private connector" with the honest reasons to choose it: private
or VPN-only targets, or a custody policy that forbids Heel-held credentials. It is not the
default onboarding and no copy may imply it is required.

### 5.5 Retained and strengthened controls

Roles (`_recent_owner_admin`), CSRF/origin checks, `__Host` cookie, lockout and signup
throttles, device auth, edge secret, kill switch, migrations-before-bind, backups: unchanged.
Strengthened: forbidden-key sets gain `password`, `secret`, `token`, `cookie`, `authorization`
for every new schema; the evidence viewer is audited; identity deletion is acknowledged by the
executor, not assumed.

---

## 6. Safety properties, tests, acceptance

### 6.1 Twelve properties → named tests (existing CONFIRMED, proposed with owner)

| # | Property | Existing (CONFIRMED, launch spec §10) | Proposed (owner in §7) |
|---|---|---|---|
| 1 | No requests outside the verified origin | `test_i1_host_confinement_refuses_off_allowlist_redirect_and_rebinding`, `test_dns_is_full_set_pinned_and_rechecked_before_authorized_retry` | `tests/test_runner_discovery.py::test_discovery_never_fetches_off_origin_or_follows_redirects` (C3); `tests/test_executor_serve_execution.py::test_managed_run_refuses_origin_outside_grant` (C4) |
| 2 | Only GET/HEAD from the approved inventory snapshot execute, **plus at most one `login_exchange` POST per identity per discovery authorization or scan run to the customer-confirmed path (amended, §3.6)**; discovery actions only from the digest-bound seeds or the same authorization's earlier rounds (§3.5) | `test_i2_post_inventory_is_rejected_at_compile`, `test_i2_only_inventoried_get_and_head_reach_the_wire` | `test_runner_discovery.py::test_discovered_candidates_are_get_head_same_origin_and_deny_listed_paths_are_excluded` (C3); `tests/test_canary_http.py::test_inventory_rows_carry_provenance_and_selection_outside_snapshot_is_rejected` (C2); `tests/test_runner_compiler.py::test_login_exchange_action_targets_only_the_confirmed_path_and_no_other_non_get_head_compiles` (C5); `tests/test_canary_http.py::test_discovery_round_actions_must_be_recorded_candidates_of_an_earlier_round_of_the_same_authorization` (C2); `tests/test_runner_discovery.py::test_route_templates_never_contain_email_token_jwt_hex_or_source_fragment_canaries` (C3) |
| 3 | Signed scope + one-shot attempt per request | `test_i3_no_request_without_verified_signed_scope`, `test_i4_no_request_without_one_shot_reserved_attempt` | `test_runner_discovery.py::test_each_discovery_round_is_a_frozen_manifest_under_its_own_grant_and_stops_at_the_authorized_bound` (C3/C4) |
| 4 | No credential at rest or in any sink other than the executor vault: never in the control-plane DB, Worker/control-plane/executor logs, traces, metrics, crash reports, support exports, CI or model APIs. **Explicit exception (amended, §2.4 Option 1):** the browser form, the Worker and the control-plane intake handler hold the plaintext in memory for the one intake request; no receipt or metadata carries a secret-derived value (§5.3) | `test_i5_credential_plaintext_absent_from_heel_home_and_output`, `test_findings_upload_recursively_rejects_raw_credential_fixture_and_local_path_leakage` | `tests/test_canary_privacy.py::test_identity_intake_route_never_logs_or_persists_the_body_and_stores_metadata_only` (C5); `tests/test_canary_privacy.py::test_login_exchange_request_body_and_returned_token_never_reach_evidence_projection_or_logs` (C5); `tests/test_canary_privacy.py::test_intake_receipt_and_identity_metadata_carry_no_secret_derived_value` (C5); `tests/test_executor_serve_execution.py::test_managed_run_never_writes_credentials_to_control_plane_db_logs_or_metrics` (C5); `test_runner_discovery.py::test_discovery_sends_nothing_to_a_model_api` (C3, asserts no model client import in the module) |
| 5 | Raw evidence bounded to the executor; control plane holds projections only | `test_completed_response_is_written_only_to_required_local_evidence_sink`, `test_operational_cloud_storage_cannot_be_repurposed_for_blocked_or_observed_assessment` | `test_canary_privacy.py::test_plan_differential_result_projection_is_bounded_and_bodyless` (C6, from launch spec); `tests/test_canary_http.py::test_evidence_view_is_proxied_bounded_audited_and_never_persisted` (C6) |
| 6 | Verifiable containment with workspace/project/runner/grant/route/attempt | `test_i6_every_request_is_logged_before_it_is_sent`, `test_i8_containment_chains_verify_and_detect_tamper` | `test_executor_serve_execution.py::test_managed_run_containment_entries_carry_workspace_project_executor_grant` (C4) |
| 7 | Workspace/project isolation | `test_cross_tenant_objects_unreachable`, `test_tenant_isolation`, `test_context_dashboard_hides_runner_bound_in_another_project_until_revoke` | `test_canary_http.py::test_identities_inventory_discovery_and_evidence_are_project_scoped` (C2/C5); `test_executor_serve_execution.py::test_one_executor_per_workspace_cannot_claim_another_workspaces_grant` (C4) |
| 8 | Pairing/verification non-replayable | `test_exchange_is_one_time_and_access_is_workspace_bound`, `test_http_v3_pairing_activation_replays_one_sealed_executable_cursor` | `test_executor_serve_execution.py::test_managed_executor_pairing_is_service_driven_single_use_and_fingerprint_verified` (C4) |
| 9 | Quotas idempotent | `test_duplicate_idempotent_run_charged_once`, `test_concurrent_reservations_never_exceed_quota` | `tests/test_canary_quota.py::test_discovery_authorization_reserves_one_unit_for_all_rounds_under_retry` (C2) |
| 10 | Prompt revocation | `test_canary_stop.py` (18), `test_revoked_runner_zero_request_claim_is_stopped_and_refunded_after_deadline` | `test_executor_serve_execution.py::test_environment_revoke_deletes_identities_and_evidence_and_stops_target_traffic_within_five_seconds` (C5/C6) |
| 11 | Sessions, CSRF/origin, rate limits, audit | `test_lockout_after_failures`, `test_verify_requires_browser_session_same_origin_and_live_sync_role` | `test_canary_http.py::test_identity_discovery_and_evidence_routes_require_same_origin_recent_auth_and_are_audited` (C2/C5) |
| 12 | Offline/lost authorization/malformed input fail closed visibly | `test_restart_coordinator_rehydrates_active_binding_but_requires_fresh_heartbeat`, `test_malformed_and_oversized_bodies` | `test_runner_discovery.py::test_discovery_partial_on_tls_error_login_failure_or_budget_is_visible_and_never_a_finding` (C3); `tests/test_runner_http_transport.py::test_both_transports_construct_without_the_legacy_constant_and_negotiate_tls12_and_tls13` (C1) |

Tests of the private-connector path (bridge spec §9.1) remain as specified for that path.

### 6.2 What an acceptance run may and may not use

Unchanged from launch spec §11.1 items 2–4: no mocked transports, canned findings, seeded rows,
fixture-only adapters, hidden flags, admin seeding, or manual copying. Test seams
(SEAM-EDGE-CA, SEAM-SECRET-BACKEND, SEAM-TARGET-DIAL) are labelled and are never acceptance
evidence. Both acceptance layers traverse browser → Worker → control plane → managed executor →
HTTPS target → projection → dashboard.

### 6.3 Layer 1 — synthetic known positive and patch transition (detection proof)

A team-run real HTTPS application (public address, real certificate) with one export route that
returns a higher plan's data to the lower identity and is not declared gated; onboarded through
the **default path only** (no runner install): sign up → URL → proof → two identities →
Authorize discovery → candidates include the export route with provenance `html_link_auth` or
`js_literal_auth` → Approve scan → `finding/body_superset/observed` → patch the application →
Replay → `pass/blocked`. Target-side access-log receipts correlated to `(run_id, action_ordinal,
attempt)` and containment entries. PASS here proves detection and the mechanism, **not**
customer readiness.

### 6.4 Layer 2 — real authorized SaaS not prepared for Heel (onboarding proof)

Target: the one Kevin supplies (currently `https://zonal-acceptance-production-d349.up.railway.app`,
recorded as proposed). **Ownership proof establishes authorization, not provenance** (T3SR): a
file or DNS record shows control of the origin; it cannot show that the application was not
prepared for Heel or that its data is synthetic. Those two facts come from Kevin's recorded
statement in the goal thread plus the product's authorization record, and the acceptance report
quotes both. With one identity on the target, Layer 2 can prove onboarding, discovery,
`login_exchange`, authenticated scanning and the honest **signed-out vs signed-in** comparison;
it cannot prove plan-differential detection, which stays with Layer 1's two identities. If the
Zonal flow is unsupported at any step (MFA enabled, login shape not confirmed, no proof
possible) the report says **gap**, not PASS. Steps, each timestamped:

```
1  browser: sign up on the deployed origin (new account)
2  browser: enter the URL; place the proof (file or DNS) on the target; Check → verified
3  browser: add identity A with the customer's label (login_exchange profile; confirm the declaration Heel proposed: POST /v1/auth/login, json, org_slug/email/password, token at /access_token); identity B if the customer has one
4  browser: Authorize discovery → rounds complete or partial with reasons; candidate table shows provenance
5  browser: select ≤10 candidates → Approve scan (hostname retype) → run completes
6  browser: findings.visible or findings.none with per-route reasons; open one evidence view
7  target: access log shows only GET/HEAD (plus exactly one login_exchange POST per identity for the discovery authorization and one per scan run) from the executor, each correlated to an attempt; discovery requests ≤100 and scan requests ≤20 counted separately
8  browser: Delete credentials → executor acknowledgement; Delete evidence; Revoke target
9  byte scan: control-plane DB dump, Worker logs, executor logs and metrics contain neither secret
10 code review: no target-host, fixture or demo conditional in the product diff; a second target with a different host/inventory/credentials traverses the same code
11 honesty check: if the target has no plan-gating gap, the result is findings.none or held/inconclusive rows with reasons; no finding is fabricated
12 record: synthetic-data statement, ownership and "not prepared for Heel" provenance come from the customer's recorded statement and the product record, not from the ownership proof and not from the hostname words "acceptance" or "production"; one identity → signed-out vs signed-in only, stated as such
13 unsupported items (SSO/MFA/CAPTCHA, private address, no proof possible) are shown as gaps, not hidden
14 clock: minutes from step 1 to step 6 (target ≤15, customer-paced step 2 recorded separately)
```

### 6.5 Final PASS definition and the two questions

**Design PASS** (this document): the plan is coherent, bounded and reviewable, with exactly one
human decision outstanding (§2.4). **Implemented PASS**: every §7 task reviewed green by a fresh
Fable. **Customer-ready PASS**: Layer 1 and Layer 2 both PASS on the deployed default path, the
§2.4 decision is recorded and implemented as decided, legal pages are accepted, and the
remaining gaps (§8) are shown in the product.

The original verbatim question stays and is answered honestly on its own terms: *"Can a new
user with no repository access sign up for Heel and obtain an evidence-backed, undeclared
product-abuse finding against a staging SaaS?"* — answered by Layer 1 (YES only with evidence).
The stricter customer-readiness question is answered by Layer 2: *"Can a customer sign up, give
their SaaS URL and credentials, authorize testing, and receive understandable evidence-backed
findings (or an honest no-findings result) without OpenAPI, installation or an engineer?"* A
YES to the first with a NO to the second is reported exactly that way.

---

## 7. Bounded, dependency-ordered backlog

Rules unchanged from bridge spec §9 (one fresh Opus per task, exhaustive allowed files ≤10
source files plus the three regenerated download artifacts when a shipped module changes,
red-first tests, verification order, DCO + exact model trailer, fresh Fable review, ≤3
remediation cycles). Every task below emphasises the real usable customer journey; no task
inherits peripheral runner fixes as a prerequisite unless named.

### 7.1 Tasks

| # | Task | Depends on | Allowed files (exhaustive) | Gate (green before review) | Owner |
|---|---|---|---|---|---|
| **C1** | TLS repair, accepted design (`T2bTLSD-design.md` §6): both constructors `PROTOCOL_TLS_CLIENT`, min 1.2, no max, `CERT_REQUIRED`, `check_hostname`, `load_default_certs()`; verifier loopback gate; docs amendment | none | `heel/runner/http_transport.py` (constructor), `heel/saas/network_guard.py` (constructor), `tests/test_runner_http_transport.py`, `tests/test_runner_plan_differential_safety.py`, `tests/plan_differential_support.py`, `tests/test_verified_environments.py`, `docs/PLAN_DIFFERENTIAL_RUNNER.md`, `docs/superpowers/specs/2026-10-02-plan-differential-runner.md` (dated amendment). Mechanical: three download artifacts | the T2bTLSD §4.4 gates on 3.11/3.12/3.13/3.14-OpenSSL4 with controlled test CA; full-suite under the shared lock; CodeQL dispatched by Astra at the candidate ref and inspected (no dismissals) | Opus → fresh Fable |
| **C2** | Server: exactly the finite contract in `2026-10-19-self-serve-discovery-contract.md` (schemas, states, authz, idempotency, round budgets, named tests); inventory with provenance and states, discovery authorizations/rounds tables, plan requests with user selection, v2 projection + `plan_kind: discovery`, bounded auto-issue, one-unit quota, same-origin/recent-auth. **Starts only after Astra accepts that contract spec**; no identity/credential route in C2 | C1 not required | `heel/saas/http_api.py`, `heel/saas/runner_contexts.py`, `heel/saas/canary_runs.py`, `heel/saas/migrate.py`, `heel/canary_contracts.py`, `tests/test_canary_http.py`, `tests/test_canary_migrations.py`, `tests/test_canary_contracts.py`, `tests/test_canary_quota.py`. Mechanical: artifacts (`canary_contracts.py` shipped) | §6.1 rows 2, 7, 9, 11 (C2 ids) + bridge spec §4.1 four binding tests + `test_discovery_round_projection_is_auto_approved_only_within_the_recorded_bound_and_refused_after_it` | Opus → Fable |
| **C3** | Discovery engine (host-agnostic module): seed list, HTML/JS/sitemap/robots extraction, candidate rules and deny list, templating with local mapping, round frontier compiler (≤20 actions), discovery transport profile, partial-result reasons; fixture pages for unit tests + one real loopback HTTPS target via SEAM-TARGET-DIAL | C1 | new `heel/runner/discovery.py`, `heel/runner/http_transport.py` (profile only), `heel/runner/compiler.py` (`compile_discovery_round`), `heel/runner/openapi_routes.py` (provenance field), new `tests/test_runner_discovery.py`, new `tests/support/discovery_fixture_target.py`, `tests/test_runner_compiler.py`, `docs/PLAN_DIFFERENTIAL_RUNNER.md`. Mechanical: artifacts | §6.1 rows 1, 2, 3, 4, 12 (C3 ids); `test_discovery_finds_export_routes_from_authenticated_html_and_js_on_a_real_https_fixture`; red-team: JS literal injection of other hosts, `javascript:`/`data:` links, 10 000-link page, deeply nested redirects, login loop | Opus → Fable |
| **C4** | Managed executor, **anonymous-only mode** (no credential, no raw-body persistence beyond the run unless §2.4 is decided): `RunnerExecutionAdapter` wiring in `serve` (bridge spec T4a, host-agnostic), service-driven pairing, discovery rounds end to end against a real HTTPS fixture over the TLS edge harness, `deploy/Dockerfile.executor`, executor egress policy | C2, C3 | `heel/runner/daemon.py`, `heel/runner/plan_differential.py` (expose observation loaders), `heel/saas/http_api.py` (service pairing actor only), `heel/saas/runner_auth.py` (service actor), new `deploy/Dockerfile.executor`, new `tests/test_executor_serve_execution.py`, `tests/support/edge_tls_harness.py`, `tests/support/synthetic_tls_target.py` (new, bridge spec §5.3), `docs/saas/OPERATIONS.md`. Mechanical: artifacts | §6.1 rows 1, 6, 7, 8 (C4 ids); `test_managed_discovery_then_anonymous_scan_reaches_a_real_https_target_with_receipts`; target-traffic stop ≤5 s on revoke; bridge spec T4a red-team list | Opus → Fable |
| **C5** | Credential intake and identities (**gated by the §2.4 decision**): identity routes, in-memory intake → executor long-poll claim (Option 1), `envelope` vault backend, `login_exchange` profile with the customer-confirmed declaration, delete/revoke acknowledgement, identity slots and pair compile | C4, Kevin §2.4 | `heel/saas/http_api.py`, `heel/saas/migrate.py`, `heel/runner/vault.py`, `heel/runner/catalog.py`, `heel/runner/execution.py` (`form_login` resolve), `heel/runner/compiler.py` (`login_post` action), `heel/runner/control_client.py` (intake claim), `tests/test_canary_privacy.py`, `tests/test_executor_serve_execution.py`, `tests/test_runner_compiler.py`. Mechanical: artifacts | §6.1 rows 2, 4, 7, 10, 11 (C5 ids); `test_managed_scan_with_two_identities_yields_observed_finding_from_a_real_https_target`; red-team: secret in log/metrics/crash, second non-GET/HEAD compiled, login to a different path or encoding than confirmed, replayed intake claim, intake body in any log sink | Opus → Fable |
| **C6** | Result projection, dashboard findings, hosted evidence view, regression save/replay (launch spec §7.3–§7.4, bridge spec T4b-c/r/u + T5, consolidated to the default path) | C4 (C5 for identity pairs) | as bridge spec rows T4b-c, T4b-r, T4b-u, T5 (split into C6a server/runner and C6b UI if >10 files), plus `heel/saas/canary_disclosure.py` evidence proxy | §6.1 rows 5, 10 (C6 ids) + bridge spec T4b/T5 gates | Opus → Fable |
| **C7** | Product surface and copy for the default path (§4.2 states, gaps shown, private connector under Advanced, legal drafts) | C2 (shell), C5/C6 (full) | as launch spec T6 | copy contract tests for every §4.2 state id; no live-execution claim before Layer 2 PASS | Opus → Fable |
| **C8** | Release and deployment: control plane + executor images, staging origin, `fixed_origin`/VPC decision (launch spec §8.2 unchanged), hosting cost approval (Kevin), install one-liner kept for the private connector only | C4–C7 | as launch spec T7 + `deploy/Dockerfile.executor` | staging green; anonymous `/` 200; executor pairs with staging | Opus → Fable |
| **C9** | Acceptance Layer 1 then Layer 2 (§6.3–§6.4) | C8 | none | PASS/FAIL with evidence; verbatim answers to both questions | fresh Fable |

C2 implementation deltas (migration 30, quota/grant-reference semantics, the signed 2 MiB
discovery grant profile, and the resulting C3/C4/C7 ownership) are recorded in
`2026-10-19-self-serve-discovery-contract.md` §9; C3's allowed files additionally include
`heel/canary_contracts.py` and `tests/test_canary_contracts.py` for the manifest v2 discovery profile.

Parallelism: C1 ∥ C2; C3 after C1; C4 after C2+C3; C5 after C4 and the decision; C6 after C4;
C7 shell after C2. Private-connector tasks from the bridge spec (T2c, T2d, T3b, local T4a
proof) move to a **connector track** after C9 unless a managed-plane task needs one of them
(none identified).

### 7.2 Independent work that continues while Kevin decides §2.4

C1, C2 (after the contract spec is accepted), C3, C4 (anonymous-only, **against Heel-owned
synthetic fixtures only**), C7 shell, C8 preparation. None of them stores a customer credential,
and none sends hosted-plane traffic to a customer origin or holds a real customer response,
transiently or otherwise, before the §2.4 decision.

### 7.3 Disposition of held drafts and known issues

| Item | Decision | Scope/impact if deferred |
|---|---|---|
| TLS repair (T2bTLS draft) | **C1, first.** Needed by every real HTTPS target and by the ownership verifier | none deferred |
| CodeQL 7-alert baseline (T2bCQ1, `ASTRA-CodeQL-R1/decision.md`) | classification kept as narrow false positives with the alert-43 hash-confidentiality qualification; **not** a security pass; alerts stay open; the inventory-not-secret assumption is tested in C2 (`INVENTORY-SECRET-BOUNDARY-NOTE.md`: provenance/inventory rows contain templates only, synthetic credential canaries in the C2/C3 tests) | — |
| R2R item A lingering resync attempt (T2b2R3 draft, LOW) | **kept, re-sequenced**: after C4, before C8, because the managed executor runs the same client and key rotation must not be blocked; not a prerequisite for C1–C4 | LOW: rotation readiness only; no target-traffic or secret effect |
| F6 force-stop on repeated signals | **connector track** (interactive local runner usability); the managed executor is a service with graceful drain | usability only; not a containment failure (`ASTRA-T2b2F6-design-decisions.md`) |
| T2b-3 retirement core (bound context/credential/seed retirement) | **split**: the managed plane needs environment-revoke deletion (C5) and executor retirement on workspace delete (C8); the local `unpair`-after-binding gap stays on the connector track and is documented as an open gap | documented gap; no safety blocker lost |
| R-B quota 500/402, R-C duplicate invitation (T2c), R-A lock ENOENT (T2d) | connector track; the service-driven pairing in C4 reuses the invite path, so C4's review must confirm it does not hit R-C (one open invitation per workspace at a time) | — |
| T4a recovery handoff (`T4a-recovery-handoff.md`) | binding on C4 (claimed-run restart, consumed-claim reconciliation, credential-missing fail-closed) | — |

### 7.4 Immediate next independent Opus assignment: C1 (TLS) first; C2 may start in parallel

**Status (Astra sequencing decision, 2026-10-19, recorded during T3S):** C1 is launched as a
fresh Opus task in an isolated worktree from `1250918` with exactly the C1 row's scope (two TLS
constructors, the named tests, `docs/PLAN_DIFFERENTIAL_RUNNER.md`, the dated amendment to the
2026-10-02 executor spec, the three release artifacts) and **no edits** to the launch, bridge or
this spec; no credential-boundary change is implemented by it. Opus roots the C1 worktree at
`1250918` (not at the T3S docs commit) and does not need this document to do its work.

Fresh Opus, allowed files exactly the C1
row. Steps: (1) red-first: capability case (`delattr(ssl, "PROTOCOL_TLSv1_2")` then construct
both transports) and the `PinnedHTTPSVerifier` loopback gate with a controlled CA via
`SSL_CERT_FILE`; (2) both constructors to the accepted shape; (3) `TLSLoopbackServer` gains
explicit bounds; assert TLS 1.2-only → 1.2, 1.3-only → 1.3, 1.0/1.1-only → `SSLError`, wrong
host/CA/pin rejections unchanged; (4) docs amendments dated, R23 trust-boundary sentences kept
verbatim; (5) focused → regenerate artifacts → affected → full suite on 3.11 and 3.14/OpenSSL 4
under `full-suite.lock`, true exits recorded; installed-wheel gate with source excluded from
`sys.path`; (6) DCO commits with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`;
(7) closing with counts; Astra dispatches CodeQL at the candidate ref. In parallel, a second
fresh Opus may start **C2** on the server files (disjoint allowed files). C3 starts when C1 is
reviewed.

---

## 8. Exclusions, launch claims, missing access, provenance, secrets

**Excluded (not built, not claimed):** writes other than the one confirmed `login_exchange` per
identity per run; fuzzing; lifecycle automation; tenant differential; limit probing; browser
credential capture; HAR import; SSO/MFA/CAPTCHA handling; private/VPN targets on the default
path; paid plans; Windows runner; scanning of targets the customer has not proven ownership
of; any model-API use with target data.

**Claims permitted after Customer-ready PASS:** "A SaaS operator can sign up, verify a staging
origin, enter their test identities, authorize discovery, approve a read-only scan, and receive
evidence-backed findings that a lower plan (or a signed-out visitor) receives a higher plan's
read responses on routes not declared as gated. Heel's managed scanner holds the entered
credentials and the captured responses for the retention period, and deletes them on request;
Heel Cloud stores route templates, labels, counts, digests and verdicts." Until then, no copy
may say Heel scans a user's SaaS. If §2.4 is declined, the claim is restricted to the private
connector and the gap is stated.

**Missing real-world access and provenance (not invented):** no deployed control plane or
executor exists; hosting is a cost decision; GitHub Release v1.2.0 has no assets; the Zonal
target's ownership proof, authorization scope, synthetic-data status and "not prepared for Heel"
status are to be established by the product's own records and Kevin's statement, not by
hostname words; only one identity has been observed there; the browser login Astra performed is
not Heel integration. No credentials were seen, copied, stored or requested by this session.

**Secrets:** none appear in this document, the session artifacts, the closing, any command,
test name or log. Any future model-assisted step (§3.1) MUST state its exact input boundary and
MUST NOT receive credentials, headers or bodies.
