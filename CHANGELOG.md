# Changelog

All notable changes to Heel are documented here. Format loosely follows Keep a Changelog.

## [Unreleased]

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
