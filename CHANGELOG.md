# Changelog

All notable changes to Heel are documented here. Format loosely follows Keep a Changelog.

## [Unreleased]

- Upgrade the control-plane cryptography pin to 50.0.1 and synchronize the hosted-proof wheel lock. The hosted control plane is not deployed; the runner side of this upgrade shipped in 1.3.0rc2 (below). Historical RC1 artifacts and publisher remain unchanged.

- Answer a v3 runner pairing activation that loses its short SQLite busy wait (numeric `SQLITE_BUSY`/`SQLITE_LOCKED`, no open transaction, independent runner connection) with `503 runner_control_busy` (`retry_after_ms: 1000`, `Retry-After: 1`); `heel runner pair` resends the identical sealed activation after that bounded hint and never past the challenge deadline. Every other route and error stays a generic 500, whose log line gains only a typed `sqlite_primary_code` (H1A3-1F3DF).
- Add the control-plane host-authority snapshot decision and private listener wiring (H1A-2), default off: migration 31 adds a permanent anti-replay generation ledger (no row ever leaves it; 65 536 rows, fail-closed), `HEEL_MANAGED_HOST=1` refuses a missing or unsafe listener configuration before any lock or bind, and a listener thread that outlives its bounded stop keeps database ownership until the process exits. See `docs/saas/HOST_AUTHORITY_SNAPSHOT.md`.
- Move owner runner revocation to `POST /v1/workspaces/{ws}/runners/{id}/revoke` (same `heel.runner-revoke.v1` body and recent owner/admin same-origin checks) at the control plane and the edge Worker; the old `DELETE …/runners/{id}` could never succeed and is no longer routed.
- Add a signed-scope, customer-local synthetic export entitlement reference through CLI and MCP, plus app instructions and local report viewing.
- Require protected content and an entitled positive control for boundary results; status-only reads are inconclusive.
- Preserve unknown metadata as questions, separate evidence state from severity/disposition, deduplicate operation representations and require applicable commercial rules for relevant library hypotheses.
- Label personas/economics as assumptions and lifecycle models as unexecuted; publish current capability gaps.


Final integration pass for the adapter-driven SaaS abuse rehearsal platform.

### Integrated
- continuous abuse rehearsal positioning for pre-launch launch review, existing-product rehearsal,
  incident follow-up, and CI regressions.
- ProductModel adapter contract for sanitized imports, staging/catalog models, and local demo data.
- entitlement graph mapping product metadata into ordinary Heel affordances.
- launch review for static ProductModel diffs before customer traffic arrives.
- regressions that turn findings into reusable abuse-control checks without repro playbooks.
- economic severity as report-layer business-impact metadata.
- personas for motivation-profiled opportunistic customer abuse.
- scenario packs that keep agent/MCP as one premium pack within broad SaaS abuse rehearsal.
- control simulator for offline proposed-fix ranking.
- HeelBench public benchmark scaffolding and report rendering.
- incident-to-scenario workflow for sanitized incidents and near misses.
- dashboard war room over the same MCP-first capability.
- shadow-API/UI backing endpoint abuse detection for scripted lookup paths that bypass paid bulk API access.

## [1.3.0rc4]: unpublished candidate

Runner preview candidate for the H2 result handoff. It is not a GitHub release, not on PyPI and not
publicly deployed. Customer copy is unchanged: the paired-runner surfaces keep the published
v1.3.0rc3 install and the other surfaces keep the published, hash-pinned 1.3.0rc2 install, until
this candidate's own release passes an anonymous public verification. The same-origin `/downloads/`
files are labeled as this not-yet-published candidate.

- Version identity 1.3.0rc4 (npm 1.3.0-rc.4) across the package, release contract, review engine,
  MCP server info, `server.json` and browser engine; 1.3.0rc3 stays an accepted saved-review and
  findings-sync engine version. Wheel, source archive, manifest, browser wheel/manifest, browser
  sample and review golden are regenerated with the unchanged builders and open-core
  classification; no new public module. The published 1.3.0rc3 bytes and version sources are kept
  byte for byte as the historical fixture `tests/fixtures/runner_preview_rc3/`.
- Result handoff (runner): the rehearsal itself is unchanged, the read-only `GET`/`HEAD` plan of an
  approved scope run by the local runner, with credentials in the local vault and raw evidence on
  the customer's machine. After a terminal run, `heel runner serve` sends a metadata-only
  disclosure poll (digest, byte count and counts of the store-verified local findings projection;
  no findings bytes) on the run's sealed result chain: every step for ten minutes, then once per
  60 s, never at or after retention. Only a human-issued permit leads to the existing
  `upload_findings`, which re-verifies binding, window and authority before the redacted findings
  leave and records `consumed` with the real receipt. Keep-local and synchronized stop polling for
  the life of the process; a restart sends one idempotent poll. A staged poll answered with a
  non-200 or unreadable response is re-sent byte-identically on its next due step, and an upload
  answered 502/503/504 is re-sent no sooner than 60 s later; any other refusal stops for the
  process and startup stays fail-closed. Runtime schema v6 adds the `poll-disclosure` pending
  operation (v5 rows copied verbatim). Retention prune now finishes for `available` and `consumed`
  runs from their exact local terminal root.
- Result handoff (Heel Cloud source, not deployed): a metadata-only disclosure-poll route on the
  runner proof family (2 KiB cap) and a view-scoped disclosure read; the dashboard keeps the shown
  run across reload (re-authorized by the tenant-scoped run read, nothing in browser storage) and
  sharing or keeping local is an explicit click, after which only server values of the redacted
  finding are shown. Copy now says Heel Cloud only checks the ownership proof and that approved
  read-only `GET`/`HEAD` rehearsals run from the local runner.
- Make the Linux `secret-service` vault and runner signing key work in a real session: `secret-tool` now receives one validated `DBUS_SESSION_BUS_ADDRESS` (a single local `unix:path=` socket owned by the user, optional 32-hex `guid`, re-serialised; remote, list, abstract, `tmpdir`/`runtime`, `unixexec`, `autolaunch` and escaped addresses are refused before launch) besides `PATH` and `LC_ALL`; no other variable is forwarded and macOS Keychain behaviour is unchanged. Missing is reported only after a search for the item's own attributes exits 0 with no output, so an unreachable service or a locked keyring is unavailable rather than missing and a locked existing credential or signing key is never overwritten.
- Findings semantics are unchanged from 1.3.0rc3: an ordinary plan-differential key-path finding
  is medium confidence and its values are not compared, error envelopes are `inconclusive`, the
  canary-marker path stays separate, and the derived `evidence_states` list is unsigned and computed
  only from the signed results. This is not a comprehensive abuse or authorization assessment.
- Known CI limitations, causes UNKNOWN and not fixed: the Python 3.13 paired plan-differential run
  that returned `inconclusive` (see 1.3.0rc3), and a bridge resolver-count assertion that saw 2 of
  5 resolver calls once on Python 3.11. Both tests keep their exact expectations with allowlisted
  failure diagnostics; a recurrence is read from its diagnostic, not rerun to green.

## [1.3.0rc3]: 2026-11-11

Runner preview prerelease, published as a GitHub prerelease at
<https://github.com/ancilis/heel/releases/tag/v1.3.0rc3> from source commit
`17a1ea70ee03a78232d04c00d589b78d6f55f0f6`. It is not a stable release and it is not published to
PyPI. The paired-runner surfaces install it from that release; the other customer copy keeps the
published, hash-pinned 1.3.0rc2 install. Known limitation: one paired plan-differential CI run on
Python 3.13 returned `inconclusive` where `blocked` was expected; its root cause is UNKNOWN and not
fixed, and the test keeps its exact expectation with an allowlisted failure diagnostic.

- Version identity 1.3.0rc3 (npm 1.3.0-rc.3) across the package, release contract, review engine,
  MCP server info, `server.json` and browser engine; 1.3.0rc2 stays an accepted saved-review and
  findings-sync engine version.
- Wheel, source archive, manifest, browser wheel/manifest, browser sample and review golden
  regenerated with the unchanged builders. Before the runner integration below, only version
  strings, the two supported-engine-version sets and `RECORD` differed from the published 1.3.0rc2
  wheel.
- Runner integration (five independently reviewed local-runner changes): `runner prepare --live`
  now queues the immutable plan and the running `serve` submits it to the existing Cloud approval
  queue; `runner findings --run` reads only verified, signed, redacted local results and prints no
  raw evidence; `runner regress add|list|record` and `runner prepare --live --regression` save an
  observed finding as a local definition and replay that one scenario as a fresh plan that needs
  a new browser approval and one-shot grant. Replay reuses the existing read-only (`GET`/`HEAD`)
  canary scenarios, works only in a Cloud-bound context whose verified canary approval queue is
  reachable, and records `pass` only for `blocked` with a completed run (`observed` is `fail`,
  anything else `inconclusive`). In the paired (browser-approved) run, a completed
  `plan_entitlement_read` pair without a canary marker binding is now also evaluated by the existing
  plan-differential comparator on the two stored, redacted bodies bound to that scenario's own
  action ordinals: a lower-plan key-path superset is `observed` (medium confidence, values not
  compared), a lower-plan denial is `blocked`, and missing, expired or malformed evidence stays
  `inconclusive`; no new request is sent. `runner findings` also prints a derived, unsigned
  top-level `evidence_states` list (`observed`, `verified` for the canary-marker path, `held`,
  `inconclusive`) computed only from the signed results; the signed objects are unchanged. New
  public module `heel/runner/regressions.py`; changed `heel/cli.py` and
  `heel/runner/{coordinator,daemon,execution,plan_differential,service,store}.py`. No new Cloud API,
  detector, network-guard, dependency or pricing change. Proven only with local test fixtures;
  no deployed pairing, browser approval or public replay journey is claimed. Guide:
  `docs/RUNNER_REGRESSION_REPLAY.md`.
- The published 1.3.0rc2 bytes and version sources are kept byte for byte as the historical fixture
  `tests/fixtures/runner_preview_rc2/`, against which the fixed rc2 publisher is tested.

## [1.3.0rc2]: 2026-11-10

Corrected runner preview prerelease, published as a GitHub prerelease at
<https://github.com/ancilis/heel/releases/tag/v1.3.0rc2> from source commit
`c082d238d7439730ef7fcfa98676167540b90172`. It is not a stable release, its GitHub release record is
not immutable, and it is not published to PyPI. Publishing this runner package does not deploy Heel
Cloud, the control plane or any hosted service; the hosted and control-plane work listed under
Unreleased remains unreleased.

### Fixed
- A response that is a recognized error or denial envelope is inconclusive for either plan at
  every HTTP status, even when it also carries the protected marker. 1.3.0rc1 has two synthetic
  reference errata, neither of which is a pass: the HTTP 200 `error_envelope` case and the HTTP 403
  `hardened` case each report `invariant_held` with `regression_passed=true`. This candidate
  reports each as `inconclusive` with `regression_passed=false`; the vulnerable result is
  unchanged. The shared content predicate and the plan-differential evaluator read one denial
  vocabulary.
- Plan-differential status parity alone and undecided lower responses no longer store a finding
  or add to local finding counts. Their pairs, redacted observations, raw attempt evidence and
  containment entries are kept.
- `heel regress add` refuses an `inconclusive` plan-differential execution record stored by an
  earlier version, identified by its runtime provenance; such records remain readable. A saved
  regression whose replayed pair is status parity alone reports `inconclusive`, not
  `still_reachable`.
- The local `/runner` report viewer no longer presents a 1.3.0rc1 held `error_envelope` (HTTP 200)
  or `hardened` (HTTP 403) report as a passed regression; it names each as an inconclusive error
  envelope, not a pass. It presents a pass only for a held `public` or `redacted` report with
  `regression_passed=true`, verified evidence and a completed reference-only run without network
  calls. It checks the report's shape and does not authenticate the file.

### Changed
- Python package, release contract, MCP `serverInfo`, `server.json`, browser engine and newly
  generated reviews identify `1.3.0rc2`; the npm package uses `1.3.0-rc.2`. Saved `1.3.0rc1`
  reviews and findings-sync sources remain readable alongside `1.1.0`, `1.1.1` and `1.2.0`.
- Regenerated `heel_sim-1.3.0rc2` and `heel_browser-1.3.0rc2` artifacts through the existing
  deterministic builders. The published 1.3.0rc1 release and its assets are unchanged.
- The `runner` extra pins `cryptography==50.0.1`, which publishes macOS wheels for Apple silicon
  only. Intel macOS is unsupported by this preview; a source build of that dependency needs an
  additional (Rust) toolchain and is untested. The documented one-command install targets Apple
  silicon macOS or Linux x86_64/aarch64 with Python 3.11 or newer.

## [1.3.0rc1]: 2026-10-23

Runner preview prerelease, published as a GitHub prerelease at
<https://github.com/ancilis/heel/releases/tag/v1.3.0rc1>. It carries the changes listed under
Unreleased at its candidate commit. It is not a stable release and is not published to PyPI.

### Changed
- Python package, release contract, MCP `serverInfo`, `server.json`, browser engine and newly
  generated reviews identify `1.3.0rc1` (PEP 440). The Heel Cloud npm package uses the equivalent
  SemVer spelling `1.3.0-rc.1`.
- Regenerated `heel_sim-1.3.0rc1` wheel, source archive and manifest, and the
  `heel_browser-1.3.0rc1` wheel and manifest, through the existing deterministic builders.
- Saved `1.1.0`, `1.1.1` and `1.2.0` reviews and findings-sync sources remain readable; the
  `heel.review.v1` and `heel.findings-sync.v1` schemas and all wire protocols are unchanged.
- The `runner` extra still pins `cryptography==45.0.7`. A source-free test installs the candidate
  wheel with that extra and runs the synthetic vulnerable and hardened reference cases. This is
  packaging evidence only, not runner pairing, serving, HTTP or hosted-findings evidence.

## [1.2.0]: 2026-08-04

Privacy-minimized findings continuity contracts for Heel Cloud. Raw OpenAPI source and guided
answers remain local; the public core can derive and validate only the canonical, project-scoped
finding projection that later consent and transport layers are permitted to handle.

### Added
- Project-scoped, content-addressed findings projections with stable request digests and exact
  receipt validation.
- Closed finding/control vocabulary, project-pseudonymous source and surface references, and
  browser/Agent artifact coverage for the projection module.

### Compatibility
- Genuine 1.1.0 and 1.1.1 `heel.review.v1` history remains readable and content-addressed under the
  unchanged schema; current release artifacts and newly generated reviews identify version 1.2.0.

## [1.1.1]: 2026-08-04

Launch-ready Heel Cloud and local-agent distribution with deterministic, digest-pinned browser and
open-core artifacts. New reviews are written as engine 1.1.1 while genuine persisted 1.1.0 review
history remains readable and content-addressed under the unchanged `heel.review.v1` schema.

### Security
- Hardened release verification against noncanonical ZIP, gzip/DEFLATE, and USTAR metadata channels,
  sensitive member paths, archive traversal, and expansion/resource-bound violations.

## [1.1.0]: 2026-06-07

Apache-2.0 relicense + DCO, and a major scenario-library depth expansion.

### Added: research scenario library (the recall lever)
- **45 source-anchored business-logic abuse scenarios** across all 10 categories
  (`heel/scenarios_lib/research_owasp.json`, declarative JSON) + a semantic-vocabulary expansion,
  integrated from an external research deliverable anchored to OWASP API/OAT/WSTG/LLM-Top-10, the MCP
  2025-06-18 schema, and Stripe/Kong/Microsoft/Auth0 config docs. Library 67 -> **119 scenarios**.
- A `prop_exists` criterion operator; over-broad absence-checks paired with `guard_absent` for precision.
- **Measured (frozen held-out test set, authored blind to the library): localization recall 0.38 ->
  0.50 at precision 0.97 -> 0.98.** See `docs/RESEARCH_LIBRARY.md`, `EVAL.md` §wave 6, `DECISIONS.md` D-032.

## [1.0.0]: 2026-06-05

First production-ready release: an agent-native abuse-simulation tool whose canonical surface is an
MCP server, proven by an honest detection metric on independently-authored targets.

### Core capability
- **MCP server** (`heel-mcp`, stdio JSON-RPC) exposing 8 consumption/execution tools, **no
  scope-mutation tool exists, by construction**. Thin **REST API** (`heel-rest`) and **CLI** (`heel`)
  over the same capability.
- **Out-of-band, HMAC-signed, immutable authorization scopes** (confused-deputy model). Every
  caller-side escalation is rejected and written to an HMAC-hash-chained, tamper-evident containment
  log. (`TestAuthGate`, `TestScopeImmutability`.)
- **Two agent classes**: adversarial (declarative, model-driven) and opportunistic-human
  (motivation-profiled). **Affordance chaining** for multi-step abuse.
- **Declarative scenario library** across all 10 abuse categories, addable without code (incl. JSON);
  **semantic signal matching** for vocabulary generalization. **Swappable LLM control loop**
  (`HEEL_MODEL=anthropic`, via stdlib `urllib`) with a deterministic offline default.
- **Control search**, optional off-by-default data-classification annotation, lane-discipline handoffs.

### Honest evaluation (the spine)
- Planted-vector **self-consistency** backtest on two synthetic targets (labeled as a wiring metric).
- **Blind-target** evaluation (independent encodings) with measured encoding-overlap + Wilson CI.
- **Held-out** evaluation against targets authored by an **independent LLM swarm, blind to the probe
  vocabulary**, with a **dev/test split** (test set frozen + content-hashed):
  - localization recall **0.38** (cluster-CI [0.29, 0.49]), attribution recall **0.31**, precision
    **0.97** on 199 independently-authored weaknesses.
  - Two gaps disclosed, not hidden: dev→test (overfitting) and localization→attribution (mis-categorization).
- Four adversarial red-team passes (safety spine, blind-eval honesty, held-out methodology, and a
  production launch-readiness security review, verdict SHIP, no blockers); all findings fixed,
  including REST anti-DNS-rebinding + anti-CSRF and data-dir 0700 enforcement. See `docs/REDTEAM_*.md`.

### Tooling & ops
- **Control-room UI** (`web/`, Next.js), abuse board, backtest, blind/held-out eval, live swarm,
  auth gate, scope panel, containment log, MCP/integration, scenario library.
- `pip install heel-sim` (pure-stdlib, **zero runtime deps**); console scripts `heel` / `heel-mcp` /
  `heel-rest`; `heel doctor` self-check; `heel eval` honest headline.
- GitHub Actions CI (Python 3.11–3.13 + wheel smoke test + UI build). 53 tests.

### Safety (§10, non-negotiable)
Synthetic-first · contained canary-only PoCs · never generates prohibited content · no real-PII ·
plausibility-weighted · severity-honest · immutable self-audit · lane discipline. See `SECURITY.md`.
