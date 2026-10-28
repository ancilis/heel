# Heel Agent-First SaaS Launch Design

**Date:** 2026-08-04  
**Status:** Approved design direction; implementation not yet started  
**Canonical brand:** Heel  
**Launch class:** Public paid beta, usable by customers  

## 1. Outcome

Heel launches as a privacy-first, agent-first SaaS abuse-review product for three increasingly
specialized product shapes:

1. Conventional web SaaS: trials, plans, seats, entitlements, exports, tenant boundaries,
   authentication, admin/support workflows, billing, OAuth, and integrations.
2. AI-enabled SaaS: the conventional surface plus inference-cost abuse, model quotas,
   prompt-driven data exposure, and AI-feature misuse.
3. AI-native and agentic products: the preceding surfaces plus tools, MCP connectors,
   cross-tenant retrieval, memory, autonomous actions, and confused-deputy risks.

The launch promise is:

> Connect Heel to your AI, or open the Heel app. Heel rehearses how customers could abuse your
> SaaS before it ships, while sensitive analysis stays under your control.

Heel accepts an optional OpenAPI document as a machine-readable description of any web API. It is
not an OpenAI-specific product. OpenAPI accelerates route discovery; a guided product-rules model
adds the pricing, entitlement, workflow, support, integration, and agent details an API document
cannot express.

### 1.1 Immediate-value contract

Heel must demonstrate value before it asks for account creation, installation, payment, team setup,
or a long questionnaire.

- The public landing page renders a real interactive example finding, its reachability rationale,
  its recommended control, and its regression suggestion in the first viewport.
- **Run the sample** starts a preloaded conventional-SaaS review with one action and no account.
- **Analyze mine** accepts a pasted or dropped OpenAPI JSON document and runs locally before login.
- Heel infers what it can, labels assumptions and confidence, and produces an initial review before
  asking optional questions that improve accuracy.
- The first result view leads with the most important reachable finding, not setup completion,
  engine telemetry, or an empty dashboard.
- Account creation appears when the user chooses to save, synchronize, compare later, collaborate,
  export through Heel Cloud, connect an agent, or upgrade.

The launch performance targets are a meaningful example finding visible immediately, a completed
sample review within 30 seconds, and a first useful finding from a valid customer OpenAPI document
within two minutes on a supported browser. Missing business rules reduce confidence and create
clearly labeled questions; they do not trap the user in onboarding.

## 2. Launch customer and job

The first user is a platform, application-security, or senior backend engineer at a 5–100-person
B2B SaaS company. The buyer is a technical founder, CTO, Head of Engineering, or Head of Security.
The purchase trigger is a new trial, pricing model, export, OAuth integration, admin workflow,
marketplace, AI feature, or agent/tool surface.

Their job is:

> Before this release reaches customers, show which legitimate product flows can be gamed, why
> they are reachable, and which control and regression test the team should add.

Consultancies and enterprises are expansion segments. Launch copy does not attempt to serve all
three segments equally.

## 3. One product, two complete interfaces

Heel has two first-class entry points over the same engine, project model, entitlements, and result
schema.

### 3.1 Heel Agent

Heel MCP is the canonical programmatic and agent interface. A user connects it to an MCP-capable AI
client or agent framework and can complete the review conversationally.

The launch MCP tool family covers:

- authentication, license, runner, and synchronization status;
- project creation and selection;
- OpenAPI import and product-model validation;
- guided collection of missing SaaS, AI-enabled, and AI-native product rules;
- launch review execution and status;
- findings, reachability rationale, recommended controls, and regression suggestions;
- comparison with a saved baseline;
- Markdown and JSON report export;
- explicit synchronization of approved result data.

Local stdio MCP is the default for desktop AI clients and private environments. Heel Cloud exposes
the same versioned tool contract as a remote MCP endpoint for cloud-only AI surfaces. Sensitive
remote-MCP jobs are dispatched to a paired private runner over an outbound connection. When no
runner is connected, remote MCP can operate only on data already approved for Heel Cloud or on an
explicitly sanitized hosted job.

### 3.2 Heel App

The web application is a complete conventional SaaS experience for customers who want to log in
and have the product work without configuring an agent.

- An anonymous visitor sees a completed interactive finding immediately and can run a preloaded
  local demonstration with one action.
- A signed-in user can drag in or paste an OpenAPI document, use the guided product questionnaire,
  run a review, inspect findings, compare versions, and export a report.
- An anonymous user can also drag in or paste a valid OpenAPI document and receive a local initial
  review. Signing in is offered only when the user wants persistence or cloud features.
- The default browser path executes the Heel engine locally in an isolated Web Worker through a
  browser-compatible Python/WebAssembly runtime.
- Signing in is required to save or synchronize results, join a team, manage billing, or pair a
  runner; it is not required for the local demonstration.
- For work beyond browser limits, the app pairs with the same local Heel runner used by MCP.

The web application also provides the control plane for account administration, team roles,
runner pairing, synchronization policy, human approvals, billing, audit history, and visual reports.

### 3.3 Cross-interface continuity

A project created in the app is selectable through MCP. A review started through MCP appears in the
dashboard when its policy permits synchronization. Both interfaces display the same review IDs,
engine version, model hash, findings, controls, baseline, and report.

## 4. Privacy and execution model

Analysis is local-first. Isolation is an explicit fallback, not an excuse to take custody of raw
customer architecture.

### 4.1 Execution modes

| Mode | Where analysis runs | Intended input | Network access | Default synchronization |
|---|---|---|---|---|
| Browser local | Isolated browser Web Worker | OpenAPI + guided model | None for the analyzer | Findings only after consent |
| Machine local | Heel CLI/MCP private runner | Local files, CI artifacts, larger models | Deny by default | Findings only |
| Cloud isolated | Ephemeral tenant-isolated worker | Explicitly sanitized model | None for launch reviews | Sanitized model + findings |
| Future live target | Customer-controlled private runner | Authorized staging/canary target | Exact signed-scope allowlist | Findings and audit summary only |

The launch product enables the first three modes for static/model-based review. Live or staging
target execution remains disabled until the complete runner, scope, egress, result, and audit path
is implemented and independently ratified.

### 4.2 Per-project data policy

Each project has one clearly displayed policy:

1. **Local only:** no project input or result is sent to Heel Cloud.
2. **Findings only:** normalized findings, controls, report metadata, hashes, and engine version
   synchronize. This is the default.
3. **Sanitized model and findings:** the user approves a sanitized structured model for team history
   and cloud execution.
4. **Managed isolated execution:** sanitized input is uploaded for an ephemeral cloud job and raw
   job input is deleted automatically after the configured short retention window.

Heel never requests source repositories, production credentials, customer records, payment data,
OAuth secrets, raw support transcripts, or production logs for a launch review. UI and MCP import
flows warn against these inputs and reject common secret patterns before synchronization.

### 4.3 Failure behavior

- If Heel Cloud is unavailable, local MCP, CLI, and browser reviews continue. Approved sync events
  queue locally and retry idempotently.
- If the browser worker fails, the input remains on the device and the user can retry or switch to
  the local runner; Heel does not silently upload it.
- If a remote MCP client requests a sensitive operation without a paired runner, Heel returns a
  precise runner-required response instead of falling back to cloud execution.
- If a paid entitlement cannot be refreshed, a signed cached entitlement permits paid cloud
  features for a 72-hour grace period. Community local CLI/MCP functionality never stops working.
- Invalid or oversized models fail before quota consumption. Failed reviews refund reserved cloud
  quota automatically.

## 5. Safety boundary for agents

Agents are untrusted callers. MCP may execute safe local/model reviews and read approved results,
but it cannot create, widen, relax, or mutate an authorization scope.

Human-only actions occur in the signed-in web control plane or a local interactive CLI ceremony:

- approve or change a project synchronization policy;
- pair or revoke a runner;
- authorize future staging/live targets;
- mint or widen a signed target scope;
- change billing, team ownership, or destructive retention settings.

Future target execution requires proof of control, a human-created immutable signed scope, exact
target binding, expiry, canary-only limits, and an outbound-only customer runner. No prompt inside an
AI conversation can satisfy that ceremony.

## 6. Product architecture

### 6.1 Repository and licensing boundaries

The existing 23-commit SaaS branch is the implementation base. The Arceo rename is reversed as one
atomic migration while preserving all later hosted work.

The target repository structure is:

```text
heel/                         Apache-2.0 core engine, CLI, local MCP, browser-compatible review code
heel/runner/                  local/private execution and outbound cloud pairing
heel/saas/                    proprietary control-plane domain services and adapters
apps/heel-cloud/              proprietary Next.js marketing site and customer application
web/                          Apache-2.0 local engine control-room demo
tests/                        core, SaaS, privacy, tenancy, MCP, billing, and integration tests
deploy/                       container and Render Blueprint definitions
```

Community users retain unlimited local core CLI and base MCP capability under Apache-2.0. The paid
product licenses Heel Cloud: remote MCP, team synchronization, project history, visual reports,
runner coordination, CI/release gates, cloud retention, and support. A cloud outage or subscription
change never revokes the open-source local engine.

### 6.2 Cloud services

The launch deployment uses one provider surface through a Render Blueprint:

- **Heel Cloud web:** Next.js marketing, dashboard, browser workflow, and authenticated BFF.
- **Heel Cloud API:** Python control plane built around the existing tenancy, entitlement, ledger,
  billing-state, audit, and kill-switch primitives.
- **Heel Cloud worker:** Python worker for sanitized, no-network model reviews and exports.
- **Render Postgres:** durable multi-tenant state, job queue, audit events, billing state, and result
  envelopes, with managed backups and point-in-time recovery on the selected paid plan.

The Postgres job queue uses transactional claiming rather than adding Redis at launch. Reports are
stored as normalized JSON and rendered to Markdown on demand; PDF is not a launch requirement.

Clerk provides hosted identity, email verification, password recovery, session management, and
organization-aware login. Heel remains authoritative for workspace roles and permissions. Stripe
provides Checkout, subscriptions, signed webhooks, and Customer Portal. Resend handles invitations,
review-complete notices, and product email not owned by the identity provider.

### 6.3 Local execution clients

- The browser worker loads a pinned, integrity-checked browser build of the Heel core and runs in a
  dedicated worker with no analyzer network API.
- The private runner stores tokens in the operating-system credential store, uses outbound-only
  HTTPS to Heel Cloud, and has a stable device identity that can be revoked.
- `heel auth login` uses a device-authorization flow to bind a local MCP/runner installation to a
  Heel Cloud account without copying browser session cookies.
- Local result envelopes include project ID, review ID, engine version, model hash, result hash,
  execution mode, timestamps, and the selected synchronization class.

### 6.4 Core data model

The launch data model contains:

- users and external identity references;
- organizations, workspaces, memberships, roles, and invitations;
- projects and synchronization policies;
- product-model versions and content hashes;
- reviews, execution mode, engine version, status, quota reservation, and timestamps;
- findings, controls, regression suggestions, and baselines;
- paired runners, device keys, last-seen state, and revocations;
- subscriptions, catalog version, Stripe references, and webhook events;
- append-only usage ledger and administrative audit events.

Every durable record carries a workspace ID. Tenant authorization is enforced through one
server-side policy boundary and backed by Postgres row-level security where the database role model
supports it. Browser or agent claims are never entitlement authority.

## 7. Customer journeys

### 7.1 App-first activation

1. Land directly on a completed interactive example finding.
2. Choose **Run the sample** or **Analyze mine** with no account wall.
3. For **Analyze mine**, paste/drop OpenAPI and acknowledge the secret/PII warning.
4. Heel runs locally, infers the initial model, and shows the highest-severity reachable finding,
   control, regression suggestion, assumptions, and confidence within two minutes.
5. The user may answer focused follow-up questions to refine the already-visible result; unanswered
   questions remain explicit uncertainty, not a blocked workflow.
6. When the user chooses save, sync, team sharing, cloud export, comparison, or upgrade, create and
   verify the account without discarding the local review.
7. Create the cloud project, confirm the default **Findings only** policy, synchronize the approved
   result, and establish it as the baseline.

### 7.2 Agent-first activation

1. Sign up and choose **Connect your AI**.
2. Install Heel and run `heel auth login`.
3. Select an AI-surface preset or copy the standard MCP configuration.
4. Ask the AI to review a SaaS release.
5. Heel MCP imports the model locally, asks only for missing product rules, runs the review, and
   explains findings.
6. The user explicitly tells Heel to save or synchronize the result.
7. The same review becomes visible in the Heel Cloud dashboard and team history.

The pre-account value event is a visitor completing the sample or a local review and opening a
finding/control. The account activation event is that local value event followed by saving,
synchronizing, comparing, exporting, or connecting an agent within ten minutes of signup.

## 8. Packaging and pricing

Prices are USD. Annual self-serve pricing is ten times monthly pricing.

| Tier | Price | Launch entitlement |
|---|---:|---|
| Community | $0 | Unlimited local CLI and base MCP; local-only projects and reports |
| Hosted Free | $0, no card | 1 cloud project, 3 synchronized reviews/month, 1 seat, 7-day cloud history |
| Pro | $49/month or $490/year | 5 projects, 25 synchronized reviews/month, 3 seats, 90-day history, remote MCP, exports, email support |
| Team | $199/month or $1,990/year | 25 projects, 100 synchronized reviews/month, 10 seats, one-year history, API/CI, RBAC, audit export, priority support |
| Enterprise | Custom annual | Contracted features that are actually configured; no unimplemented checkbox claims |

Local Community execution is not artificially metered because the open core has no marginal cloud
cost. Quotas cover stored/synchronized reviews and hosted execution. Self-serve quotas hard-stop
with an upgrade path; Heel does not charge surprise overages at launch.

## 9. Public site and claims

The site leads with two primary actions:

- **Open Heel:** start on a real finding, then run the sample or analyze a specification locally.
- **Connect your AI:** configure Heel MCP and a private runner.

The site includes product, pricing, security, privacy, documentation, acceptable-use, support,
status, login, signup, and enterprise-contact routes. Every product claim maps to a running feature
and automated or operational verification. Launch copy does not claim live-target probing, hosted
MCP execution without a runner, scheduled regressions, SSO/SCIM, private regions, SOC 2, or an SLA.

Operative Terms, Privacy Policy, AUP, refund/cancellation language, DPA, subprocessors list, and the
open-core/commercial boundary require owner and counsel approval before public payment acceptance.

## 10. Observability and operations

- Structured logs include request ID, workspace ID, review ID, execution mode, and outcome, never
  raw customer model content.
- Health and readiness probes distinguish process health, database readiness, migration state, and
  worker availability.
- Metrics cover signup, activation, review latency/failure, sync outcome, queue age, quota denial,
  Stripe webhook lag/failure, runner connectivity, tenant anomalies, and deletion jobs.
- Production secrets live in provider secret storage. No secret or live price ID is committed.
- Postgres backups and point-in-time recovery are enabled. A restore drill and application rollback
  are tested against staging before launch.
- Global and workspace kill switches deny new hosted spend or synchronization while preserving
  local review access.

## 11. Verification strategy

Implementation follows test-driven development. The launch gate requires:

1. Existing core and SaaS unit suites remain green without unclosed socket/database warnings.
2. A case-insensitive repository scan finds no `arceo` reference except an explicitly documented
   historical migration note.
3. Native Python and browser-worker review fixtures produce semantically identical result envelopes.
4. Local and remote MCP pass the same tool-schema and behavior conformance suite.
5. Privacy tests prove local-only inputs never reach the cloud and each synchronization class sends
   only its allowed fields.
6. Cross-tenant and IDOR tests cover every project, model, review, finding, runner, billing, and
   report route.
7. Browser end-to-end tests cover anonymous demo, signup, email verification, first review, finding,
   synchronization, history, quota, upgrade, portal, cancellation, deletion, and logout.
8. Agent end-to-end tests cover device login, MCP configuration, local review, explanation, explicit
   sync, cloud history, token refresh, revocation, and offline grace.
9. Stripe test-mode tests cover monthly/annual checkout, signed webhook replay/order handling,
   upgrade, scheduled downgrade, payment failure, portal, cancellation, refund, and chargeback.
10. Postgres integration tests cover migrations, transactional quotas, job claiming, RLS, backups,
    restore, and rollback.
11. Container and deployed staging smoke tests prove a completed review and persisted findings;
    `queued` and `stub.local` are launch failures.

## 12. Explicitly deferred

The following are not part of the paid-beta launch:

- live or staging target probing;
- remotely hosted sensitive execution without a paired private runner;
- agent-created or agent-widened authorization scopes;
- scheduled live regressions;
- SSO/SCIM, private regions, on-prem control plane, and private worker fleets;
- source-code ingestion;
- LLM-generated detection claims;
- PDF export; Markdown and JSON are sufficient at launch.

These capabilities may be added only when their complete customer journey, safety boundary,
operational ownership, and independent review are real.

## 13. Implementation order

1. Atomically restore the Heel package, protocol identifiers, environment names, documentation,
   tests, and generated assets while preserving the 23 hosted commits.
2. Repair packaging and create real app, worker, migration, and runner entry points.
3. Freeze the versioned review/result/sync schema shared by native Python, browser, MCP, and cloud.
4. Build the browser worker and private runner, then prove local/cloud privacy contracts.
5. Move the control plane to managed Postgres and connect real job execution to persisted results.
6. Build the new Heel Cloud Next.js application and both activation journeys.
7. Integrate identity, email, Stripe Checkout/webhooks/portal, and server-authoritative entitlements.
8. Add Render deployment, secrets, migrations, backups, staging, monitoring, rollback, and deployed
   smoke tests.
9. Replace all placeholder legal/trust content with owner-approved operative content.
10. Run independent security, product-claim, browser, MCP, and operations gates; fix every blocker
    before accepting public payment.

## 14. Binary launch gate

Heel is launch-ready only when a stranger can complete both supported paths:

- App: open site, run locally, create account, review a real sanitized model, receive findings,
  synchronize according to policy, return to history, pay, manage billing, and delete the account.
- Agent: authenticate a licensed installation, connect an MCP AI surface, run the same local review,
  explain findings, explicitly synchronize them, and see the identical review in Heel Cloud.

The deployment must also pass tenant isolation, privacy, Stripe, backup/restore, rollback, monitoring,
support, and legal gates. Passing unit tests or queueing a job alone is not launch readiness.
