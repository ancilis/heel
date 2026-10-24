# Changelog

All notable changes to Heel are documented here. Format loosely follows Keep a Changelog.

## [Unreleased]

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

## [1.3.0rc2]: unpublished candidate

Corrected runner preview release candidate. It carries the changes listed under Unreleased at its
candidate commit and is not yet published as a GitHub release or to PyPI.

### Fixed
- A 2xx response that is a recognized error or denial envelope is inconclusive for either plan,
  even when it also carries the protected marker. The synthetic reference `error_envelope` case
  now reports `inconclusive` with `regression_passed=false`, correcting the 1.3.0rc1 erratum;
  the vulnerable and hardened results are unchanged. The shared content predicate and the
  plan-differential evaluator read one denial vocabulary.
- Plan-differential status parity alone and undecided lower responses no longer store a finding
  or add to local finding counts. Their pairs, redacted observations, raw attempt evidence and
  containment entries are kept.
- `heel regress add` refuses an `inconclusive` plan-differential execution record stored by an
  earlier version, identified by its runtime provenance; such records remain readable. A saved
  regression whose replayed pair is status parity alone reports `inconclusive`, not
  `still_reachable`.
- The local `/runner` report viewer no longer presents a 1.3.0rc1 `error_envelope` report, or
  any held report without `regression_passed=true`, as a passed regression.

### Changed
- Python package, release contract, MCP `serverInfo`, `server.json`, browser engine and newly
  generated reviews identify `1.3.0rc2`; the npm package uses `1.3.0-rc.2`. Saved `1.3.0rc1`
  reviews and findings-sync sources remain readable alongside `1.1.0`, `1.1.1` and `1.2.0`.
- Regenerated `heel_sim-1.3.0rc2` and `heel_browser-1.3.0rc2` artifacts through the existing
  deterministic builders. The published 1.3.0rc1 release and its assets are unchanged.

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
