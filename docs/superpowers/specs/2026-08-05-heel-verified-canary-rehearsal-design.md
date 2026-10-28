# Heel Verified Canary Rehearsal Launch Design

**Date:** 2026-08-05  
**Status:** Architecture approved; detailed contract awaiting owner review  
**Canonical brand:** Heel  
**Launch requirement:** A customer can run a bounded abuse rehearsal against a verified staging
environment from Heel Cloud or an MCP-capable AI surface.

## 1. Relationship to the existing launch design

This document amends
`2026-08-04-heel-agent-first-saas-launch-design.md`. The earlier document remains controlling for
anonymous local OpenAPI review, findings synchronization, identity, tenancy, packaging, operations,
and the open-core boundary.

This document specifically supersedes sections 3.1 (remote MCP at launch), 4.1 (future live
target), 6.2 (provider topology), 8 (paid launch packaging), 9 (claims excluding live rehearsal),
the live-target portions of sections 11–13, and the payment portions of section 14 in the earlier
design. The current free Early Access topology—Cloudflare Worker, private Tunnel/VPC binding, one
Python control-plane process, and one durable SQLite database—remains controlling.

A verified, paired, customer-local canary rehearsal is now a binary launch requirement. It does not
authorize a Heel-hosted live-testing service or broad production testing.

## 2. Product outcome

After signup, a customer can connect one verified staging SaaS environment, pair a Heel Runner,
connect Claude Desktop, OpenAI Codex CLI, or another local stdio MCP-capable agent, and execute a
useful bounded test pack. The same capability is available from the Heel web application for
customers who do not want to use an AI client. Other stdio MCP clients may be protocol-compatible,
but launch certification names only clients exercised by end-to-end tests.

The launch promise is:

> Verify your staging app, approve an exact canary rehearsal, and let Heel show which product
> boundaries can be crossed before customers find them. Credentials and raw traffic remain on
> your machine.

Heel is an abuse-rehearsal product, not an autonomous penetration-testing agent. An AI may explain
the system, propose safe scenario IDs, and summarize findings. It cannot construct arbitrary HTTP
traffic, access credentials, prove target ownership, grant itself authority, or widen an approved
run.

## 3. Core launch experience

Activation has two honest lanes. **Analyze a specification now** preserves the existing anonymous,
browser-local OpenAPI review and its measured first-result target; it requires no account or
runner. **Rehearse deployed staging** begins the verified flow below and advertises the 20-minute
target only when the customer has a reachable staging origin, an OpenAPI document or route map, and
prepared canary identities. The useful static result stays visible while live setup proceeds and is
never represented as observed target traffic.

### 3.1 App-first journey

1. The customer signs up or signs in and creates a project.
2. **Test my staging app** asks for one canonical HTTPS origin and labels it `staging` or `sandbox`.
3. Heel gives the customer a DNS TXT challenge and an HTTPS-file alternative. The dashboard checks
   proof, reports precise failures, and records verification expiry.
4. **Pair runner** gives the customer a copyable one-command install/start path. Runner approval
   happens in the signed-in browser. The dashboard confirms runner version, capabilities, and last
   heartbeat without receiving target credentials.
5. The runner imports an OpenAPI document locally or guides the customer through a minimal route
   map. Heel immediately recommends eligible canary scenarios and explains any missing setup.
6. The customer creates local credential handles for two isolated canary identities where a test
   needs differential authorization. Secrets remain in the operating-system credential store.
7. The customer selects a safe test pack. The browser shows an immutable preview containing the
   exact origin, routes, methods, canary roles, request ceiling, duration, and the mandatory
   operational-receipt schema.
8. A recently authenticated owner or admin retypes the hostname, supplies a reason, and approves
   one short-lived execution grant.
9. The paired runner claims the grant over its outbound connection, validates it, executes the
   deterministic adapters, and posts bounded ordered progress events.
10. Heel Cloud shows operational status, and **Open local result** opens the runner companion UI
    with scenario outcomes, the most important finding, evidence summary, recommended control, and
    regression action.
11. If the user wants dashboard history, they preview the exact local finding projection and
    complete the separate digest-bound disclosure ceremony. Raw requests and responses remain
    local in either case.

The target activation goal is a first completed canary rehearsal within 20 minutes of signup for a
customer with a reachable staging origin, an OpenAPI document, and prepared canary accounts.

### 3.2 Agent-first journey

1. The customer pairs the runner and verifies the environment through the same human-controlled
   web flow.
2. The customer copies a tested local stdio MCP configuration for Claude Desktop or OpenAI Codex
   CLI. The runner and MCP server are the same locally authenticated Heel installation.
3. The customer asks the AI to assess a release or a named product boundary.
4. MCP reads sanitized target metadata and eligible scenario IDs, then prepares a deterministic
   rehearsal manifest. It returns the plan and a browser approval link.
5. No catalog test packet is sent until the human completes the exact approval ceremony.
6. After approval, MCP may submit the grant for execution or the customer may click **Run now** in
   Heel Cloud. Both paths execute the identical signed manifest on the paired runner.
7. MCP can read local progress and findings. It can read cloud history only for findings the user
   separately synchronized. It cannot read raw credentials or raw response bodies.

Route matching and manifest compilation happen inside the runner process. The OpenAPI document is
not uploaded by implication. Remote MCP is deferred until its OAuth, tenant selection, capability,
runner-relay, retention, rate-limit, and result-disclosure contracts receive a separate design.

### 3.3 Local-review fallback

Anonymous browser-local and authenticated model/static review remain usable without a runner. If a
runner, cloud service, proof record, or credential handle is unavailable, Heel offers model review
and reports the exact live-execution prerequisite that is missing. It never silently substitutes a
hosted live probe.

## 4. Chosen architecture

### 4.1 Customer-local paired runner

The launch executor is a customer-local Heel Runner. Target traffic originates from the customer's
machine or private CI environment, while coordination and approved findings history live in Heel
Cloud.

The runner:

- creates a non-exportable or locally protected runner keypair during pairing;
- stores target credentials behind opaque local handles in the operating-system credential store;
- maintains an outbound-only authenticated control connection to Heel Cloud;
- verifies every execution-grant signature and immutable field locally;
- compiles approved safe action IDs through fixed, versioned adapters;
- applies target, DNS, redirect, egress, request, concurrency, response-size, and time budgets;
- records a tamper-evident containment log and raw evidence locally;
- emits mandatory bounded coordination receipts plus an approved finding projection, if any, to
  Heel Cloud; and
- responds to revocation and emergency stop before the next action and within five seconds.

The runner is the only launch component allowed to possess canary credentials or send live target
test traffic. The tightly constrained Cloud verifier may send only the DNS query or single HTTPS
challenge GET described in section 5.1; it cannot call product routes. The browser, Heel Cloud, MCP
server, and model provider receive no credential handle or credential value.

`RunnerIdentity.v1` is distinct from the existing sync-only machine credential. It records the
workspace, public key and displayed fingerprint, runner and adapter versions, capability list,
pairing actor/time, last heartbeat, and rotation/revocation state. Approval requires a browser user
to match a runner-generated phrase and fingerprint. Every runner request includes proof of
possession over the method, path, body digest, timestamp, and server nonce. Runner identity and
control-plane grant signatures use Ed25519 with explicit key IDs and overlapping verification-only
rotation windows. Replays and cross-runner claims fail closed.

Runner credentials have separate, least-privilege capabilities: `runner_claim`, `runner_heartbeat`,
`runner_progress`, and `runner_result`. They do not inherit `sync_findings`, human approval,
billing, target management, or workspace administration. Key rotation and replacement require a
fresh human ceremony; revocation invalidates unused runner-bound grants.

### 4.2 Runner-control transport

The launch transport uses immediate, bounded HTTPS requests rather than WebSockets or long polling.
An idle runner polls for work at most every two seconds. While executing, a supervisor sends a
heartbeat at least once per second and receives current stop, revocation, proof-freshness, and
kill-switch state. Claims, heartbeats, ordered progress events, result receipts, and stop
acknowledgments are independently idempotent and carry monotonic sequence numbers.

Every control-plane request and SQLite transaction is brief; no runner request holds the global
request lock while waiting for work or target I/O. The dashboard polls the ordered event feed rather
than depending on a server-held stream. The supervisor must be able to cancel in-flight target I/O;
tests must prove that an emergency stop produces no later target action and a stop acknowledgment
within five seconds.

### 4.3 Heel Cloud control plane

Heel Cloud owns accounts, workspaces, projects, target-verification records, runner identities,
approval projections, human approvals, single-use execution grants, job state, quotas, audit
events, mandatory coordination receipts, and approved result projections.

The control plane does not store target credentials, arbitrary request templates, raw request or
response bodies, target session tokens, or unapproved local evidence. It coordinates a run but is
not its network executor.

The existing target verifier, human-only scope ceremony, job leases, kill switches, pairing flow,
and findings-only synchronization are reused as concepts and extended where their current contracts
are insufficient. The existing synthetic/model `run_abuse` engine remains the static-review engine;
it is not relabeled as live execution.

### 4.4 Provider-neutral MCP

The versioned MCP surface exposes:

- `heel_connection_status`
- `heel_list_environments`
- `heel_list_scenarios`
- `heel_prepare_rehearsal`
- `heel_execute_grant`
- `heel_run_status`
- `heel_get_findings`
- `heel_get_containment_summary`
- `heel_compare_regression`

Names may be normalized during protocol versioning, but their authority classes are fixed.

MCP must not expose target proof completion, runner approval, credential creation or reading, grant
minting, scope widening, synchronization approval, recurring scheduling, billing administration,
or emergency-stop disabling. An AI is always an untrusted caller even when the user has configured
the client to auto-approve MCP tools.

### 4.5 Why launch does not use the alternatives

- A Heel-hosted live runner would require Heel to hold credentials, isolate hostile responses,
  operate hardened multi-tenant egress workers, and assume a materially larger security and
  operational boundary. It is deferred to an independently designed managed tier.
- A browser-only live runner cannot reliably reach arbitrary staging origins because of browser
  cross-origin controls and cannot offer an adequate credential boundary. The browser remains a
  complete static-review and control-plane interface.
- A model-only connected review remains valuable, but it cannot truthfully satisfy the promise to
  test the deployed staging application.

## 5. Authorization and execution contract

### 5.1 Target verification

An executable target is `VerifiedEnvironment.v1`: one exact normalized public HTTPS origin with
workspace, project, declared environment class, proof method/version, verified time, expiry,
revocation state, normalization version, and structured failure code. Launch grants do not contain
wildcards.

The owner explicitly attests that the origin is isolated staging/sandbox infrastructure containing
only test or canary data. Heel labels the result honestly: **ownership verified; environment
classification supplied by you**. A new attestation is required after target replacement or proof
expiry.

Verification supports DNS TXT or one HTTPS challenge GET. The HTTPS verifier resolves only public
addresses, pins the selected peer address for the connection, rejects private and special-use
addresses before and after resolution, ignores environment proxy settings, disables redirects,
permits only port 443, and enforces a small response and time limit. This narrowly scoped ownership
request is the only target connection Heel Cloud sends at launch.

Verification is necessary but not sufficient to execute. The runner rechecks proof freshness and
resolves the hostname immediately before a run and before every new connection. Literal IPs,
private or special-use addresses, internal names, metadata endpoints, non-HTTPS origins, DNS
rebinding, unapproved ports, redirects, and newly discovered hosts fail closed.

Production origins may be recorded for product identity, but launch execution is enabled only for
targets explicitly labeled `staging` or `sandbox`. Production canary execution requires a later
owner-controlled feature gate and a separate safety ratification.

### 5.2 Runner pairing

Pairing reuses only the browser-mediated ceremony from existing device authorization. It creates the
separate `RunnerIdentity.v1` and proof-of-possession credentials from section 4.1; existing
sync-only bearer tokens cannot claim runner work. The browser displays the runner-generated
verification phrase and public-key fingerprint before approval. A runner has no ambient authority
to create grants.

Revocation blocks new work immediately and invalidates unused runner-bound grants. Loss of the
local key requires a new pairing ceremony. Tokens are short-lived and rotated without exposing the
runner private key.

### 5.3 Safe test manifest and approval projection

An AI or user selects only cataloged scenario IDs. The runner-local deterministic compiler is
authoritative: it turns those choices, the locally imported OpenAPI route map, and explicit user
mappings into `TestManifest.v1`. The full manifest never leaves the runner.

`TestManifest.v1` includes:

- workspace, project, target record, exact origin, and environment class;
- runner identity and minimum compatible runner/adapter versions;
- ordered scenario IDs and `ScenarioAdapter.v1` versions;
- exact HTTP methods, normalized route templates, locally bound canary fixture IDs, and allowed
  status/body-shape assertions;
- random 128-bit local credential-handle IDs and semantic roles;
- fixed auth profiles limited at launch to anonymous, bearer, cookie jar, and `X-API-Key`;
- maximum requests, concurrency, per-action and wall time, response bytes, and exact egress
  host/port;
- redirect prohibition, retry policy, and local evidence retention; and
- a canonical digest used by approval, grant, execution, containment, and results.

`ScenarioAdapter.v1` is deterministic code with a versioned scenario ID, accepted route/auth roles,
request-construction function, response evaluator, redaction contract, and declared side-effect
class. Launch adapters are read-only. They do not accept code, arbitrary request templates, or model
output at execution time.

The runner derives `ApprovalManifestProjection.v1` for Heel Cloud and the browser ceremony. Its
closed schema contains exact origin, normalized route templates and methods, scenario/adapter IDs,
semantic canary roles without credential-handle IDs, assertion classes, side-effect class, all
budgets, target/runner IDs, and the full-manifest digest. It excludes OpenAPI content, concrete
fixture IDs, request values, headers, credentials, and local labels.

Both schemas use a versioned canonical JSON encoding: duplicate keys are rejected, strings are
UTF-8/NFC, object keys are sorted, numeric fields are bounded integers, and non-finite/floating
values are forbidden. The local manifest is capped at 256 KiB and the approval projection at
64 KiB. The runner signs the projection and compilation attestation; the browser approves its
digest. The projection is deleted 24 hours after a terminal/expired grant, leaving only its digest,
scenario IDs, budgets, actor, target record, and audit disposition.

Neither schema can contain arbitrary scripts, shell commands, model-generated URLs, free-form
headers, raw credentials, unrestricted payloads, or model-selected retry behavior.

### 5.4 Human approval and execution grant

`ExecutionGrant.v1` is a new tenant-bound authority object rather than an overload of the existing
local HMAC scope file. A recently authenticated owner or admin approves one immutable
`ApprovalManifestProjection.v1` after reviewing it and retyping the exact hostname.

The signed grant binds:

- the local-manifest and approval-projection digests and exact target-verification record;
- workspace, project, actor, reason, consent timestamp, and audit event;
- the paired runner public key;
- immutable budgets no larger than system and workspace ceilings;
- one nonce, one job, a roughly ten-minute expiry, and single-use state;
- current kill-switch generation; and
- the maximum permitted operational-receipt schema, which contains no findings.

Heel Cloud signs grants asymmetrically. Only the control plane holds the signing key; runners pin
the trusted verification key set. Claiming consumes the nonce transactionally. Retries resume the
same idempotent job or require a fresh grant; they never replay target-changing actions.

### 5.5 Execution and disclosure state

Lifecycle phase, Cloud-visible execution disposition, and local assessment outcome are separate
fields. The execution lifecycle is:

```text
prepared -> awaiting_execution_approval -> approved -> claimed -> running -> finalizing -> terminal
prepared / awaiting_execution_approval -> cancelled
awaiting_execution_approval / approved -> expired
claimed / running -> stop_requested -> finalizing -> terminal
```

A terminal execution has one Cloud-visible disposition: `completed`, `incomplete`, `failed`, or
`stopped`. It contains no security assessment. The local result has one assessment outcome:
`blocked`, `observed`, or `inconclusive`; individual scenarios use the same vocabulary. `blocked`
means the tested abuse boundary held, not complete security coverage. Assessment outcomes enter
Heel Cloud only through the post-run disclosure permit. Lifecycle actors, legal transitions, quota
reservation/settlement, disconnect behavior, and stop reasons are closed enums.

Findings disclosure has its own lifecycle:

```text
local_result_ready -> awaiting_disclosure_approval -> permitted -> synchronized
local_result_ready / awaiting_disclosure_approval -> local_only
awaiting_disclosure_approval / permitted -> expired
```

Cancellation, runner revocation, target-proof expiry, credential unavailability, version mismatch,
budget exhaustion, DNS change, containment rejection, or cloud disconnection cannot produce a
`blocked` or `observed` assessment; any available local assessment is `inconclusive`.

## 6. Launch safe-test catalog

The initial catalog is deliberately small and useful. Each scenario is deterministic, bounded,
canary-only, and produces an observed differential rather than an exploitability claim.

1. **Anonymous-versus-authenticated read:** compare approved `GET`/`HEAD` routes without and with a
   canary session.
2. **Object-ownership read:** bind a customer-prepared, uniquely namespaced canary-A fixture locally
   and verify that canary B cannot read its exact mapped `GET` route. Concrete IDs never leave the
   runner.
3. **Role-bound read:** compare a mapped `GET` operation using low-privilege and privileged canary
   roles.
4. **Plan or entitlement read:** compare one mapped `GET` feature using canaries assigned to two
   test plans.

All launch test traffic is read-only. Future mutation adapters remain disabled. A later mutation
design must require the run to create a unique namespaced fixture through fixed code, bind every
subsequent ID to that fixture, reserve cleanup budget inaccessible to test actions, prohibit
arbitrary or pre-existing IDs, and verify cleanup before it can enter the catalog.

Launch excludes brute force, credential attacks, scraping, resource exhaustion, destructive admin
operations, real exports, payments, external email or messaging, real webhooks, SSRF exploitation,
prompt injection against third parties, unrestricted fuzzing, and prohibited content. Unsupported
requests become a non-executing advisory finding or handoff.

Default ceilings are one concurrent request, at most 20 total requests, a cancellable five-second
per-action deadline, 60 seconds wall time, bounded response bodies, no redirects, exact port 443,
and at most one read-only retry. A catalog scenario may impose a lower limit but neither a user nor
an AI may raise it above the signed grant.

## 7. Credentials, evidence, and synchronization

Canary credentials are created outside Heel or through customer-owned staging fixtures. The runner
stores them locally under random 128-bit IDs and optional human-readable local labels. MCP and Cloud
see only semantic roles such as `lower_privilege` and `higher_privilege`; neither receives the
credential ID, local label, or value.

Interactive installations use macOS Keychain, Windows Credential Manager, or Linux Secret Service.
Headless CI accepts credentials through a documented ephemeral environment/file-descriptor adapter
that never persists them. Heel does not silently fall back to a plaintext credential file; an
unavailable secure store blocks live execution while static review remains usable.

The runner redacts configured secrets and common token forms before any log or result serialization.
Raw requests, raw response bodies, full headers, cookies, tokens, and locally imported OpenAPI
documents stay local by default.

Execution necessarily sends `OperationalRunProjection.v1` to Heel Cloud. It contains the job and
grant identifiers, lifecycle phase and non-assessment disposition, timestamps, aggregate
request/budget counters, runner/adapter versions, stop/error category, containment-event codes, and
redaction counts. It contains no `blocked`/`observed`/`inconclusive` assessment, route parameters,
response content, credentials, concrete object IDs, finding text, or customer payloads and is
disclosed on the approval screen. The detailed projection expires after seven days; minimal IDs,
digests, actor, quota settlement, and execution disposition remain in the 30-day audit record.

After execution, the runner creates the new closed `CanaryFindingsProjection.v1` containing only:

- run, grant, target, manifest, adapter, and engine identifiers/digests;
- scenario status and timestamps;
- normalized route identity without concrete object IDs or query values;
- status-code and bounded structural observations;
- finding title, reachability rationale, confidence, recommended control, and regression suggestion;
- containment decisions and redaction counters; and
- local-evidence references that are meaningless outside the paired runner.

Execution consent is not findings-disclosure consent. The runner shows the exact projection and its
digest in its loopback companion UI or local MCP result. If the user chooses synchronization, the
runner opens a signed Heel Cloud confirmation link containing only the digest and bounded counts. A
recently authenticated human confirms that they reviewed the local projection; Cloud issues a
single-use, ten-minute `DisclosurePermit.v1` bound to the runner, run, schema version, digest, byte
limit, and workspace. Only then may the runner upload the exact projection. Launch has no standing
or agent-controlled disclosure policy.

A declined or expired permit produces local runner/MCP results plus the mandatory operational
projection, not an empty or misleading successful dashboard finding. Synced findings use the
existing seven-day Early Access history retention; local evidence follows the runner's local
retention setting.

## 8. Safety and failure behavior

- Every target action rechecks the active run, grant, kill-switch generation, remaining budgets,
  exact host, and containment policy.
- A local emergency stop cancels in-flight transport immediately. A Cloud stop sets
  `stop_requested`; the one-second supervisor heartbeat receives it, cancels the cancellable target
  client, sends no later target action, and acknowledges the stop within five seconds.
- Graceful cancellation or runner/cloud disconnection starts no new target action. Because the
  launch catalog is read-only, it has no target cleanup permission and cannot invent a repair step.
- Target responses are untrusted data. They are size-bounded, parsed by hardened deterministic
  adapters, and never interpreted as instructions.
- Model/provider failure falls back to deterministic catalog guidance or blocks preparation. It
  never relaxes the execution contract.
- Every prepared, approved, rejected, expired, claimed, attempted, contained, stop-requested,
  finalized, local-result, disclosure-permitted, and synchronized transition receives an
  actor-attributed audit or containment event.
- Findings use `observed`, `blocked`, or `inconclusive` language. Heel does not claim complete
  coverage, precision, or proven exploitability without ground truth.
- Static/local review remains available when live execution fails closed.

## 9. Web experience requirements

The authenticated dashboard must make the next valuable action obvious and never land a new user
on an empty administrative shell. Its primary project card shows a four-step activation path:

1. **Verify staging**
2. **Pair runner**
3. **Add canary access**
4. **Run first rehearsal**

Each step has one primary action, an inline success check, a concise explanation of what stays
local, and a precise recovery path. Completed steps collapse without disappearing from settings.

The run screen leads with recommended safe scenarios, not a generic request builder. The approval
screen is visually distinct from planning and results. Progress names the current scenario and
remaining budget. On completion, **Open local result** opens the runner's loopback companion UI. If
the user then approves disclosure, the synchronized dashboard leads with the highest-value observed
boundary and a concrete control; engine telemetry and containment details are available without
dominating the page. If disclosure is declined, the page retains operational status, explains how
to reopen the local result, and enumerates the minimal coordination receipt Heel Cloud retained.

The product includes tested copyable MCP presets and a connection diagnostic that proves the AI
surface can reach Heel without granting live authority.

## 10. Packaging and launch entitlement

The runner and local stdio MCP ship from the same signed Heel distribution and use one browser
pairing flow. The browser dashboard and local MCP use the same versioned manifest, grant, and result
contracts while retaining their distinct authority classes.

Free Early Access uses the current in-repository PBKDF2 password authentication and server-side
`__Host-heel_session` browser sessions; it does not use or claim Clerk, SSO, or SCIM. Human execution
and disclosure approvals require a recently reauthenticated owner/admin session. Vendor identity
is reconsidered before paid or multi-replica launch, not silently introduced into this release.

The first public release uses the existing free Early Access account entitlement while payments
remain disabled. It includes one workspace, one verified staging target, one paired runner, one
seat, and ten canary runs per UTC calendar month. The server-authoritative catalog meters are
`verified_staging_targets=1`, `active_runners=1`, and `canary_runs_per_month=10`; Community static
local review remains unmetered.

One canary-run unit is reserved when the human approval creates a grant. It is released when the
grant expires or is revoked unclaimed, the runner rejects it before target traffic, containment
blocks the first request, or a closed `platform_fault`/`runner_fault` prevents useful execution. It
settles transactionally on the first catalog target request for customer cancellation, target/auth
failure, `blocked`, `observed`, and target-caused `inconclusive` results. A later classified Heel
platform/runner fault refunds the settled unit exactly once. Idempotency keys prevent duplicate
reservation, settlement, or refund; the usage ledger records every transition without storing
finding content.

The supported runner matrix is macOS 13+ on Apple silicon and Ubuntu 22.04/24.04 x86_64 with Python
3.11–3.13. Clean-machine gates exercise both. The release publishes the `heel-sim` universal wheel
and source archive to PyPI plus the same-origin download page, a SHA-256 manifest signed by the Heel
Ed25519 release key, and copyable `pipx install heel-sim==<version>` / `heel runner start` commands.
The runner verifies the release manifest before pairing and the dashboard rejects revoked or
incompatible runner/adapter versions. Windows browser-local review remains supported, but a Windows
live runner is deferred until its credential-store and cancellation contracts pass the same gates.

Paid tiers may later meter synchronized history, seats, targets, runners, CI gates, and managed
execution. Launch does not accept payment for an unimplemented capability.

## 11. Deployment shape

The launch deployment remains one Cloudflare Worker, one private Tunnel/VPC binding, one non-root
Python control-plane process, and one durable SQLite database using the existing WAL/FULL,
backup/restore, and single-owner invariants. It does not add a public live-execution worker. Durable
storage contains target proof, runner identity, approval projections, grants, jobs, audit events,
operational projections, disclosure permits, and approved finding projections. An in-process
coordination loop expires grants, reaps runner leases, settles quotas, and processes approved
synchronization; it sends no test traffic and performs no network I/O while holding a database
transaction.

The public edge exposes only exact versioned target, runner, approval projection, execution
approval, claim/heartbeat/progress, run-status, stop, disclosure-permit, and result-projection
routes. Session-only human routes cannot be called with runner credentials. Runner routes have the
separate capabilities from section 4.1 and closed request/response schemas. Billing, metrics,
internal jobs, arbitrary proxy paths, target request/response payloads, and raw evidence remain
unreachable from the public edge.

Deployment is launchable only when production fails closed for missing grant-signing keys, target
verifiers, runner-key validation, storage migrations, kill-switch state, and result-projection
validators.

## 12. Verification and acceptance criteria

Implementation follows test-driven development. Launch requires proof that:

1. A new customer completes signup, staging verification, runner pairing, canary mapping, human
   approval, execution, results, and optional sync through the deployed application.
2. Claude Desktop and OpenAI Codex CLI each pass an end-to-end local stdio MCP test that prepares the
   same rehearsal, opens human approval, executes only the approved grant, and reads the local
   result; cloud history appears only after the disclosure permit and upload.
3. Apart from the constrained ownership challenge, zero target traffic occurs before valid proof,
   runner binding, recent human approval, and transactional single-use grant consumption.
4. Every runner target request matches the signed manifest, exact host, adapter, and remaining
   budget.
5. Attempts to inject a URL, header, payload, credential, redirect, subdomain, private address,
   script, shell command, retry, scenario, or limit outside the manifest are rejected and audited.
6. DNS rebinding, proof expiry, grant replay, cross-tenant IDs, revoked runners, stale adapters,
   cloud loss, stop requests, and kill-switch changes fail closed.
7. Canary credential IDs/labels/values, concrete fixture IDs, and raw responses never appear in
   model context, MCP payloads, cloud storage, logs, synchronized findings, analytics, or cloud
   browser responses.
8. Emergency stop prevents the next action within five seconds and revokes unused grants.
9. Every terminal run has valid local-manifest, approval-projection, and grant digests, a containment
   chain, redaction report, quota settlement, operational receipt, and local-result receipt.
10. Manual regression replay uses a new one-shot grant and reports `blocked`, `observed`, or
    `inconclusive` against the same versioned scenario.
11. Anonymous local OpenAPI review and local MCP review continue to pass their existing privacy and
    product contracts.
12. Production packaging, migrations, edge allowlists, dependency injection, runner installation,
    rollback, backup/restore, monitoring, and deployed smoke tests pass from clean environments.
13. The public edge never accepts target request/response payloads; every control API body is
    schema-validated and size-bounded, and forwarding, connection-nominated, and internal-origin
    headers are stripped in both directions.

## 13. Implementation dependency order

1. Freeze canonical local-manifest, approval-projection, operational-projection,
   `CanaryFindingsProjection.v1`, grant, disclosure-permit, runner-identity, lifecycle, and
   containment contracts with privacy and adversarial tests.
2. Add SQLite migrations, asymmetric signing-key configuration, nonce/replay storage, short-lived
   projection retention, and fail-closed production construction.
3. Implement `RunnerIdentity.v1`, proof-of-possession authentication, least-privilege runner
   capabilities, pairing, rotation, revocation, and the immediate short-poll transport.
4. Harden and production-wire `VerifiedEnvironment.v1` DNS/HTTPS proof with public-address pinning,
   exact normalization, staging attestation, expiry, and revocation.
5. Build the local runner compiler, loopback companion UI, credential vault adapter, four read-only
   `ScenarioAdapter.v1` implementations, cancellable HTTP client, exact egress enforcement,
   redaction, and containment log through test-driven slices.
6. Extend job coordination with immutable digests, transactional grant consumption, runner-pinned
   claims, monotonic progress, heartbeat/stop behavior, quotas, kill-switch generations, lifecycle
   outcomes, operational receipts, and disclosure permits.
7. Expose only the new exact edge routes and repair bidirectional forwarding/internal-header
   stripping before making any canary route public.
8. Build the web activation checklist, target proof, runner pairing, scenario mapping, immutable
   approval, progress/stop, local-result handoff, disclosure confirmation, and synchronized result
   experience.
9. Version the local MCP canary tools separately from legacy model review, then prove the same
   grant/result behavior through Claude Desktop and OpenAI Codex CLI presets.
10. Package the runner from a clean machine and pass the full deployed staging, privacy, tenant,
    rollback, backup/restore, monitoring, product-claim, and stranger-activation gates.

## 14. Explicitly deferred

- broad production testing or any target not explicitly verified and staging-classified;
- a Heel-hosted live runner or Heel custody of target credentials;
- browser-only direct target execution;
- Windows live-runner execution;
- remote/Streamable HTTP MCP and cloud-only AI surfaces;
- agent-created or agent-widened grants, scopes, credentials, targets, or synchronization policy;
- scheduled or unattended live regressions;
- arbitrary HTTP request builders, user-authored live scripts, unrestricted fuzzing, load testing,
  brute force, credential attacks, mutation scenarios, destructive tests, or third-party targets;
- source-repository ingestion and autonomous patch deployment; and
- claims of complete security coverage, penetration-test equivalence, or guaranteed prevention.

## 15. Binary launch gate

Heel is not launch-ready until a stranger can complete both of these against a deployed staging
system:

- **App:** sign up, attest and verify the staging origin, pair a runner, configure local canary
  roles, approve and execute a catalog rehearsal, inspect a useful local result, stop a run, and
  complete the separate disclosure ceremony to synchronize findings.
- **Agent:** connect both the Claude Desktop and OpenAI Codex CLI launch presets, prepare the same
  catalog rehearsal, cross the human execution-approval ceremony, execute it on the paired runner,
  read the local result in the conversation, and see it in the dashboard only after the separate
  disclosure permit and upload.

Neither a queued job, a synthetic-only result, a mocked HTTP adapter, a locally passing unit suite,
nor persuasive launch copy satisfies this gate. The deployed journey must send constrained traffic
from the customer runner to the verified staging target and produce an auditable bounded result.
