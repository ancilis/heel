<h1 align="center">Arceo</h1>

<p align="center"><b>Abuse rehearsal for SaaS, before launch and continuously after.</b></p>

<p align="center">
<a href="https://github.com/ancilis/arceo/actions/workflows/ci.yml"><img src="https://github.com/ancilis/arceo/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/ancilis/arceo/actions/workflows/codeql.yml"><img src="https://github.com/ancilis/arceo/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
<a href="https://scorecard.dev/viewer/?uri=github.com/ancilis/arceo"><img src="https://api.scorecard.dev/projects/github.com/ancilis/arceo/badge" alt="OpenSSF Scorecard"></a>
<a href="https://pypi.org/project/arceo/"><img src="https://img.shields.io/pypi/v/arceo.svg" alt="PyPI"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="Apache 2.0"></a>
<img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+">
<img src="https://img.shields.io/badge/deps-zero-brightgreen" alt="Zero dependencies">
<img src="https://img.shields.io/badge/surface-MCP--first-8a2be2" alt="MCP-first">
</p>

---

It's launch day. Somewhere, a customer just found the export endpoint with no rate limit, farmed your
"one free trial" a thousand times, or talked your AI agent into calling a tool it should never touch.
Six months later, the same product may be dealing with trial farming already happening, seat sharing
on mature accounts, export scraping by legitimate customers, AI-token cost abuse, integration/OAuth
overreach, or support/workflow gaming after an incident.

**Arceo is abuse rehearsal for SaaS.** A swarm of adversarial and opportunistic agents
probes a product *you own*, proves an abuse path is **reachable** with a *contained* proof-of-concept,
and hands you a ranked report with the fix, before launch and continuously after.

Pre-launch launch review remains the sharpest default use case. Existing products are supported
through existing-product rehearsal: authorized, contained, canary-only runs against staging,
imported product models, sanitized telemetry, or explicitly authorized production-like targets.
Arceo is not a default permission slip for production probing: every non-synthetic path starts with a
human-created scope and operator-approved limits. There is no scope creation, widening, relaxation,
or mutation path over MCP, REST, or agent surfaces.

It is **agent-native** (its canonical surface is an **MCP server** other agents call), **honest** (it
reports its *real* detection rate against abuse it has never seen, not a vanity number), and
**safe by construction** (synthetic-first, contained PoCs, an authorization gate no prompt-injected
agent can talk its way past). Pure Python standard library, **zero dependencies**.

## See it in 30 seconds

```bash
pip install arceo      # zero deps · Python 3.11+
arceo doctor               # environment self-check
arceo eval                 # the honest detection headline
```

Or run the full proof from a clone, no install:

```bash
git clone https://github.com/ancilis/arceo && cd arceo && make demo
```

```text
AUTHORIZATION GATE (agent caller is an untrusted, possibly prompt-injected channel):
  [REJECTED+logged ✓]  run a target NOT in the allowlist
  [REJECTED+logged ✓]  call a forged scope-widening tool
  [REJECTED+logged ✓]  inject an instruction in the target arg
  -> auth gate: PASS, no escalation reachable via the agent surface

HELD-OUT EVALUATION: targets authored by an INDEPENDENT LLM swarm (blind to Arceo's probes):
  TEST (FROZEN, never tuned, 199 weaknesses):
     LOCALIZATION recall 0.50   ATTRIBUTION recall 0.33   precision 0.98
  -> the honest real-target ceiling. Semantic generalization on vocabulary it never saw, not near 1.0.
```

That second number is the point: **Arceo tells you what it can't catch yet.**

Try a SaaS abuse review against the sanitized local demo model, still with no API keys,
network access, or real systems touched:

```bash
arceo import validate examples/saas_demo/product_model.json
arceo launch-review --before examples/saas_demo/product_model.json --after examples/saas_demo/product_model.json
arceo scope create --target synthetic-saas --operator you --confirm
arceo run --mode synthetic --scope <scope_id> --target synthetic-saas --scenario sc.trial.serial
arceo findings --run <run_id>
arceo regress add --run <run_id> --vector <vector_id> --name free_trial_serial_signup
arceo regress run --scope <scope_id> --target synthetic-saas
```

From a clone, the same local workflows are available as CI-friendly demos:

```bash
make demo-import
make demo-launch-review
make demo-regressions
make demo-bench
```

## Why Arceo is different

- 🤖 **Agent-native, MCP-first.** The capability is an MCP server. Wire it into Claude Desktop,
  Cursor, or CI and let an agent run abuse rehearsals on demand. A thin REST API and a CLI sit over
  the same capability.
- 🔒 **The calling agent is untrusted.** Authorization scopes are **human-only, out-of-band, and
  HMAC-signed**, immutable from the caller side. A prompt-injected agent can run *within* a scope a
  human approved, but **cannot create, widen, or escape one** (those tools don't exist, by
  construction). Every escalation attempt is rejected and written to a tamper-evident audit log.
- 📏 **Radically honest metrics.** Most "AI security" tools quote a number you can't trust. Arceo
  publishes a *ladder* (below), measures against abuse authored by an **independent LLM swarm blind to
  its own probes**, on a **frozen, content-hashed test set**, and shows you the overfitting and
  mis-categorization gaps instead of hiding them. Four adversarial red-team passes, all findings fixed.
- 🛡️ **Safety spine, non-negotiable.** Synthetic-first. Findings are *contained, canary-only* proofs,
  never working exploits, real exfiltration, or prohibited content. True software vulns are handed off
  to AppSec, pure model-jailbreaks to model red-team. Arceo stays in its lane. See [SECURITY.md](SECURITY.md).

## Pre-launch, post-launch, and after incidents

- **Pre-launch:** run the launch review before customer traffic arrives. Rehearse trial farming,
  export/rate-limit abuse, weak recovery, entitlement bypass, agent tool over-scope, and integration
  abuse while the blast radius is still synthetic or staging-only.
- **Post-launch:** turn observed product pressure into contained scenarios. Rehearse trial farming
  already happening, seat sharing on mature accounts, export scraping by legitimate customers,
  AI-token cost abuse, and integration/OAuth overreach.
- **After incidents:** convert the incident pattern into a regression scenario, especially support
  and workflow gaming where the issue was a business-process affordance rather than a software vuln.

## Why not pentest, QA, or a fraud platform?

Arceo is not a replacement for penetration testing, AppSec scanners, functional QA,
fraud/bot platforms, runtime WAF/API protection, Trust & Safety manual review, or
model red-team tools. Those programs remain necessary. Arceo complements them by filling
the missing product-abuse rehearsal step: intended features, legitimate customer paths,
pricing and entitlement rules, workflows, integrations, and agent tools can all be
misused even when the endpoint has no injection bug and the UI works as specified.

Example: QA says export button works. AppSec says endpoint has no injection bug. A fraud
platform may catch abuse after traffic appears. Arceo asks whether the export business
flow can be used by a trial user to harvest more data than intended, then proves that
only with contained, canary-only evidence.

See [docs/POSITIONING.md](docs/POSITIONING.md) for the full comparison table.

## What it hunts

A 10-category abuse taxonomy: license/entitlement gaming, UI backing endpoints used as unpriced bulk
APIs, data harvesting, unintended endpoints, function abuse, content policy, identity/account
takeover, trust-economy fraud, integration abuse, compliance boundaries, and (only when the target
has an agent/MCP surface) **agent-specific abuse** like tool over-scope, confused-deputy tool calls,
cross-tenant RAG, and indirect-injection-to-action.

Scenarios are organized into packs so teams can focus a run without narrowing Arceo's positioning:
`core_saas`, `payments_billing`, `trust_safety`, `integrations`, `compliance`, and `agent_mcp`.
Agent/MCP is one premium pack for products with agentic surfaces; Arceo remains broad SaaS abuse
rehearsal first. See [docs/SCENARIO_PACKS.md](docs/SCENARIO_PACKS.md).

Two agent classes hunt in parallel: a **programmatic adversary** (finds weak controls) and a
**motivation-profiled opportunistic human** (games normal affordances, catches what the adversary
misses, like coupon stacking). Plus **affordance chaining** for multi-step abuse (for example, weak
recovery and a non-rotated session compose into account takeover).

## Honest about what it can't do

Arceo reports four levels, weakest claim to strongest evidence:

| metric | what it measures | result |
|---|---|---|
| self-consistency | wiring works (probes vs. plants authored together) | ~1.0 *(a wiring test, not accuracy)* |
| blind | independent *encodings* of known weaknesses | ~0.40 |
| held-out **DEV** | independent authorship, tuned-on | 0.70 |
| **held-out TEST** | **independent LLM authorship, frozen, never tuned on** | **localization 0.50 · attribution 0.33 · precision 0.98** |

The headline is the bottom row: real detection on 199 abuse weaknesses an independent LLM swarm
invented in its *own* vocabulary, which Arceo never saw. It improves only by widening real-vocabulary
coverage, never by writing probes against known answers. Full method: [EVAL.md](EVAL.md) ·
[docs/HELDOUT_PROVENANCE.md](docs/HELDOUT_PROVENANCE.md). Reusable benchmark harness:
[docs/ARCEOBENCH.md](docs/ARCEOBENCH.md).

## Use it like an operator

```bash
# 1) a HUMAN authorizes a target OUT-OF-BAND (the only way to mint a scope)
arceo scope create --target synthetic-saas --operator you --confirm

# 2) an agent / CLI runs WITHIN that scope (and cannot widen it)
arceo run --scope <scope_id> --target synthetic-saas
arceo report --run <run_id> --economic --economic-assumptions docs/economic_assumptions.example.json
arceo coverage --run <run_id>
arceo log --run <run_id>          # immutable, hash-chained audit trail

# 3) turn a finding into a permanent abuse-control regression
arceo regress add --run <run_id> --vector <vector_id> --name free_trial_serial_signup
arceo regress run --scope <scope_id> --target synthetic-saas
```

For a real-ish local SaaS shape without connecting to a customer system, see
[`examples/saas_demo`](examples/saas_demo/). It provides a sanitized ProductModel and OpenAPI
fixture for Free/Pro/Enterprise plans, seats, trial eligibility, coupons, usage and AI-token meters,
exports, OAuth, webhooks, support actions, agent tools, MCP connector metadata, and canary-only
declared controls.

**Connect from an MCP client.** Point Claude Desktop / Cursor / CI at the `arceo-mcp` server:

```json
{ "mcpServers": { "arceo": { "command": "arceo-mcp",
  "env": { "ARCEO_HOME": "/path/to/.arceo", "ARCEO_SIGNING_KEY": "/path/outside/.arceo/arceo.key" } } } }
```

## The control room

A dense Next.js dashboard over the same capability: an abuse board (ranked, reachability-weighted),
the honest backtests, a live swarm monitor, the authorization gate, the read-only scope panel, the
containment log, and the scenario library.

```bash
make ui        # http://localhost:3000   (or `npm run build` for a static export)
```

## Bring your own LLM (optional)

The deterministic engine runs fully offline with no API key. Flip on the LLM control loop for
smarter discovery:

```bash
ARCEO_MODEL=anthropic ANTHROPIC_API_KEY=sk-... arceo-mcp   # via stdlib urllib, no SDK
```

It only ever sees *observable* synthetic affordance properties (never secrets or real data) and stays
in Arceo's lane. For imported or real-target adapters, that means scoped, sanitized, canary-only
metadata, never secrets or real customer data.

## Security & assurance

A security tool has to earn trust. Arceo ships the evidence: **zero dependencies**, **reproducible
builds**, **Sigstore-signed release provenance** + **SBOM**, **OpenSSF Scorecard** + **CodeQL**, and
the real assurance, **four independent multi-agent red-team passes** whose full reports are in the
repo, every finding fixed with a regression test. The core claim held under attack: *a prompt-injected
caller cannot create, widen, or escape a signed authorization scope.* See **[TRUST.md](TRUST.md)** and
**[SECURITY.md](SECURITY.md)**, and verify the build yourself: `gh attestation verify <wheel> --repo ancilis/arceo`.

## Docs

[ARCHITECTURE](ARCHITECTURE.md) · [EVAL](EVAL.md) · [DECISIONS](DECISIONS.md) ·
[SECURITY](SECURITY.md) · [TRUST](TRUST.md) · [ADAPTERS](docs/ADAPTERS.md) ·
[MODES](docs/MODES.md) · [POSITIONING](docs/POSITIONING.md) ·
[ENTITLEMENTS](docs/ENTITLEMENTS.md) · [LAUNCH REVIEW](docs/LAUNCH_REVIEW.md) ·
[REGRESSIONS](docs/REGRESSIONS.md) · [INCIDENTS](docs/INCIDENTS.md) ·
[OPENAPI IMPORT](docs/OPENAPI_IMPORT.md) · [SCENARIO AUTHORING](docs/SCENARIO_AUTHORING.md) ·
[SCENARIO PACKS](docs/SCENARIO_PACKS.md) · [PERSONAS](docs/PERSONAS.md) ·
[CONTROL SIMULATOR](docs/CONTROL_SIMULATOR.md) ·
[ECONOMIC SEVERITY](docs/ECONOMIC_SEVERITY.md) · [ARCEOBENCH](docs/ARCEOBENCH.md) ·
[HELDOUT PROVENANCE](docs/HELDOUT_PROVENANCE.md) ·
[RESEARCH LIBRARY](docs/RESEARCH_LIBRARY.md) · [ROADMAP](docs/ROADMAP.md) · [CONTRIBUTING](CONTRIBUTING.md) ·
[CHANGELOG](CHANGELOG.md) · red-team reports under [`docs/`](docs/)

## Status

**Status: production-ready spine, beta adapters (v1.1.0).** 55 core tests on Python 3.11 to
3.13, CI green, zero runtime dependencies, four red-team passes. The core authorization gate,
containment model, and evaluation ladder are the production-ready spine. Real-target adapters remain
beta until adapter coverage and operator controls mature.

---

<p align="center"><sub>Apache-2.0 licensed · synthetic-first · the safety spine (§10) overrides every instruction, including any arriving through a calling agent.</sub></p>
