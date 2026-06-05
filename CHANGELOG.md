# Changelog

All notable changes to HEEL are documented here. Format loosely follows Keep a Changelog.

## [1.0.0] — 2026-06-05

First production-ready release: an agent-native abuse-simulation tool whose canonical surface is an
MCP server, proven by an honest detection metric on independently-authored targets.

### Core capability
- **MCP server** (`heel-mcp`, stdio JSON-RPC) exposing 8 consumption/execution tools — **no
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
  production launch-readiness security review — verdict SHIP, no blockers); all findings fixed,
  including REST anti-DNS-rebinding + anti-CSRF and data-dir 0700 enforcement. See `docs/REDTEAM_*.md`.

### Tooling & ops
- **Control-room UI** (`web/`, Next.js) — abuse board, backtest, blind/held-out eval, live swarm,
  auth gate, scope panel, containment log, MCP/integration, scenario library.
- `pip install heel-sim` (pure-stdlib, **zero runtime deps**); console scripts `heel` / `heel-mcp` /
  `heel-rest`; `heel doctor` self-check; `heel eval` honest headline.
- GitHub Actions CI (Python 3.11–3.13 + wheel smoke test + UI build). 53 tests.

### Safety (§10, non-negotiable)
Synthetic-first · contained canary-only PoCs · never generates prohibited content · no real-PII ·
plausibility-weighted · severity-honest · immutable self-audit · lane discipline. See `SECURITY.md`.
