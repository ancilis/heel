<h1 align="center">Heel</h1>

<p align="center"><b>Abuse rehearsal for SaaS, before launch and continuously after.</b></p>

<p align="center">
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

**Heel is abuse rehearsal for SaaS.** A swarm of adversarial and opportunistic agents
probes a product *you own*, proves an abuse path is **reachable** with a *contained* proof-of-concept,
and hands you a ranked report with the fix, before launch and continuously after.

Pre-launch launch review remains the sharpest default use case. Existing products are supported
through existing-product rehearsal: authorized, contained, canary-only runs against staging,
imported product models, sanitized telemetry, or explicitly authorized production-like targets.
Heel is not a default permission slip for production probing: every non-synthetic path starts with a
human-created scope and operator-approved limits. There is no scope creation, widening, relaxation,
or mutation path over MCP, REST, or agent surfaces.

It is **agent-native** (its canonical surface is an **MCP server** other agents call), **honest** (it
reports its *real* detection rate against abuse it has never seen, not a vanity number), and
**safe by construction** (synthetic-first, contained PoCs, an authorization gate no prompt-injected
agent can talk its way past). Pure Python standard library, **zero dependencies**.

## Five-minute local launch review

The Heel Cloud app now carries the verified Agent wheel, source archive, and manifest on its own
origin. Open `/mcp`, choose **Download Heel Agent 1.1.1**, and save
`/downloads/heel_sim-1.1.1-py3-none-any.whl` in an empty working directory. Then install it into an
isolated environment and review a sanitized OpenAPI document you own:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install ./heel_sim-1.1.1-py3-none-any.whl
export HEEL_HOME="$PWD/.heel-local"
.venv/bin/heel review openapi ./sanitized-openapi.json
```

The default report is validated Markdown. Add `--json` for the canonical `heel.review.v1`
envelope used by automation and MCP:

```bash
.venv/bin/heel review openapi ./sanitized-openapi.json --json
```

This path needs no account or signing key, makes no analyzer network calls, uploads and syncs
nothing, and stores the successful review only under `$HEEL_HOME/reviews/`. Inputs must be
sanitized UTF-8 OpenAPI JSON without credentials or customer data and no larger than 2 MiB.
The same-origin files exist in the deployable app now; public customer access still requires the
approved deployment. `heel-sim` is not yet published to PyPI, and a current public repository export
is a release-owner action that is not complete. See the [MCP quickstart](docs/MCP_QUICKSTART.md) for
the exact acquisition matrix and stdio client configuration.

The base local CLI/MCP is Apache-2.0 and has no commercial usage limit. Its safety and 2 MiB input
limits still apply. Hosted findings synchronization and remote MCP are paid Heel Cloud features;
neither is enabled in this private preview. Windows secure local project storage is not supported at
launch; use the browser workspace or a supported POSIX environment.

## Anonymous browser workspace

`apps/heel-cloud/` is the commercial, evidence-first browser workspace. It renders a committed
sample finding immediately, then lets an anonymous visitor run that sample or paste/drop a
sanitized OpenAPI JSON document. The canonical Python review wheel runs in a dedicated Web Worker;
the analyzer loads its integrity-pinned Pyodide assets and wheel from the same origin. Raw OpenAPI
source and guided answers remain in memory, are not uploaded or synchronized, and are not written
to local history. A visitor may explicitly save only the validated result envelope in that device's
IndexedDB and download deterministic JSON or Markdown locally.

This repository state is a **private acceptance preview**, not a claim that a public alpha is live
or launch-ready. The remaining public claim requires the documented browser acceptance run,
explicit public-access approval, and a public deployment. There is no account system, cloud save,
team synchronization, billing, hosted review API, analytics, database, or object-storage binding in
this browser milestone.

Use Node.js 26 for the security gate:

```bash
python3 scripts/build_browser_engine.py --output apps/heel-cloud/browser-engine --check
python3 scripts/build_browser_sample.py --check
cd apps/heel-cloud
npm ci --ignore-scripts --no-audit --no-fund
cd ../..
python3 -m unittest tests.test_browser_engine_build tests.test_browser_review \
  tests.test_browser_sample tests.test_browser_native_parity -v
cd apps/heel-cloud
node --test tests/browser-engine.test.mjs
npm run test:unit
npm run typecheck
npm run lint
npm run build
npm run test:node
```

The final artifact inspection verifies the transformed, digest-pinned same-origin runtime; recursively
scans deployed executables, manifests, and browser-wheel members; enforces exact security headers and
empty cloud capabilities; rejects source maps, CDN fallbacks, and credentials; and proves that 1200×630
social metadata uses the request URL rather than caller-controlled host headers. It does not replace
the outstanding interactive browser or deployment acceptance gates.

Run the broader synthetic proof from the installed Agent:

```bash
.venv/bin/heel doctor
.venv/bin/heel eval
```

```text
AUTHORIZATION GATE (agent caller is an untrusted, possibly prompt-injected channel):
  [REJECTED+logged ✓]  run a target NOT in the allowlist
  [REJECTED+logged ✓]  call a forged scope-widening tool
  [REJECTED+logged ✓]  inject an instruction in the target arg
  -> auth gate: PASS, no escalation reachable via the agent surface

HELD-OUT EVALUATION: targets authored by an INDEPENDENT LLM swarm (blind to Heel's probes):
  TEST (FROZEN, never tuned, 199 weaknesses):
     LOCALIZATION recall 0.50   ATTRIBUTION recall 0.33   precision 0.98
  -> the honest real-target ceiling. Semantic generalization on vocabulary it never saw, not near 1.0.
```

That second number is the point: **Heel tells you what it can't catch yet.**

Try a SaaS abuse review against the sanitized local demo model, still with no API keys,
network access, or real systems touched:

```bash
heel import validate examples/saas_demo/product_model.json
heel launch-review --before examples/saas_demo/product_model.json --after examples/saas_demo/product_model.json
heel scope create --target synthetic-saas --operator you --confirm
heel run --mode synthetic --scope <scope_id> --target synthetic-saas --scenario sc.trial.serial
heel findings --run <run_id>
heel regress add --run <run_id> --vector <vector_id> --name free_trial_serial_signup
heel regress run --scope <scope_id> --target synthetic-saas
```

From a clone, the same local workflows are available as CI-friendly demos:

```bash
make demo-import
make demo-launch-review
make demo-regressions
make demo-bench
```

## Why Heel is different

- 🤖 **Agent-native, MCP-first.** The capability is an MCP server. Wire it into Claude Desktop,
  Cursor, or CI and let an agent run abuse rehearsals on demand. A thin REST API and a CLI sit over
  the same capability.
- 🔒 **The calling agent is untrusted.** Authorization scopes are **human-only, out-of-band, and
  HMAC-signed**, immutable from the caller side. A prompt-injected agent can run *within* a scope a
  human approved, but **cannot create, widen, or escape one** (those tools don't exist, by
  construction). Every escalation attempt is rejected and written to a tamper-evident audit log.
- 📏 **Radically honest metrics.** Most "AI security" tools quote a number you can't trust. Heel
  publishes a *ladder* (below), measures against abuse authored by an **independent LLM swarm blind to
  its own probes**, on a **frozen, content-hashed test set**, and shows you the overfitting and
  mis-categorization gaps instead of hiding them. Four adversarial red-team passes, all findings fixed.
- 🛡️ **Safety spine, non-negotiable.** Synthetic-first. Findings are *contained, canary-only* proofs,
  never working exploits, real exfiltration, or prohibited content. True software vulns are handed off
  to AppSec, pure model-jailbreaks to model red-team. Heel stays in its lane. See [SECURITY.md](SECURITY.md).

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

Heel is not a replacement for penetration testing, AppSec scanners, functional QA,
fraud/bot platforms, runtime WAF/API protection, Trust & Safety manual review, or
model red-team tools. Those programs remain necessary. Heel complements them by filling
the missing product-abuse rehearsal step: intended features, legitimate customer paths,
pricing and entitlement rules, workflows, integrations, and agent tools can all be
misused even when the endpoint has no injection bug and the UI works as specified.

Example: QA says export button works. AppSec says endpoint has no injection bug. A fraud
platform may catch abuse after traffic appears. Heel asks whether the export business
flow can be used by a trial user to harvest more data than intended, then proves that
only with contained, canary-only evidence.

See [docs/POSITIONING.md](docs/POSITIONING.md) for the full comparison table.

## What it hunts

A 10-category abuse taxonomy: license/entitlement gaming, UI backing endpoints used as unpriced bulk
APIs, data harvesting, unintended endpoints, function abuse, content policy, identity/account
takeover, trust-economy fraud, integration abuse, compliance boundaries, and (only when the target
has an agent/MCP surface) **agent-specific abuse** like tool over-scope, confused-deputy tool calls,
cross-tenant RAG, and indirect-injection-to-action.

Scenarios are organized into packs so teams can focus a run without narrowing Heel's positioning:
`core_saas`, `payments_billing`, `trust_safety`, `integrations`, `compliance`, and `agent_mcp`.
Agent/MCP is one premium pack for products with agentic surfaces; Heel remains broad SaaS abuse
rehearsal first. See [docs/SCENARIO_PACKS.md](docs/SCENARIO_PACKS.md).

Two agent classes hunt in parallel: a **programmatic adversary** (finds weak controls) and a
**motivation-profiled opportunistic human** (games normal affordances, catches what the adversary
misses, like coupon stacking). Plus **affordance chaining** for multi-step abuse (for example, weak
recovery and a non-rotated session compose into account takeover).

## Honest about what it can't do

Heel reports four levels, weakest claim to strongest evidence:

| metric | what it measures | result |
|---|---|---|
| self-consistency | wiring works (probes vs. plants authored together) | ~1.0 *(a wiring test, not accuracy)* |
| blind | independent *encodings* of known weaknesses | ~0.40 |
| held-out **DEV** | independent authorship, tuned-on | 0.70 |
| **held-out TEST** | **independent LLM authorship, frozen, never tuned on** | **localization 0.50 · attribution 0.33 · precision 0.98** |

The headline is the bottom row: real detection on 199 abuse weaknesses an independent LLM swarm
invented in its *own* vocabulary, which Heel never saw. It improves only by widening real-vocabulary
coverage, never by writing probes against known answers. Full method: [EVAL.md](EVAL.md) ·
[docs/HELDOUT_PROVENANCE.md](docs/HELDOUT_PROVENANCE.md). Reusable benchmark harness:
[docs/HEELBENCH.md](docs/HEELBENCH.md).

## Use it like an operator

```bash
# 1) a HUMAN authorizes a target OUT-OF-BAND (the only way to mint a scope)
heel scope create --target synthetic-saas --operator you --confirm

# 2) an agent / CLI runs WITHIN that scope (and cannot widen it)
heel run --scope <scope_id> --target synthetic-saas
heel report --run <run_id> --economic --economic-assumptions docs/economic_assumptions.example.json
heel coverage --run <run_id>
heel log --run <run_id>          # immutable, hash-chained audit trail

# 3) turn a finding into a permanent abuse-control regression
heel regress add --run <run_id> --vector <vector_id> --name free_trial_serial_signup
heel regress run --scope <scope_id> --target synthetic-saas
```

For a real-ish local SaaS shape without connecting to a customer system, see
[`examples/saas_demo`](examples/saas_demo/). It provides a sanitized ProductModel and OpenAPI
fixture for Free/Pro/Enterprise plans, seats, trial eligibility, coupons, usage and AI-token meters,
exports, OAuth, webhooks, support actions, agent tools, MCP connector metadata, and canary-only
declared controls.

**Connect from an MCP client.** After installing from source or a current wheel, point any
stdio-capable MCP client at `heel-mcp`:

```json
{ "mcpServers": { "heel": { "command": "heel-mcp",
  "env": { "HEEL_HOME": "/absolute/path/to/private/heel-data" } } } }
```

Call `heel_review_openapi` with the parsed OpenAPI object to receive and save the same local
`heel.review.v1` envelope as the CLI. Configuration details, privacy boundaries, and an honest
source/wheel/PyPI installation matrix are in [docs/MCP_QUICKSTART.md](docs/MCP_QUICKSTART.md).

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
HEEL_MODEL=anthropic ANTHROPIC_API_KEY=sk-... heel-mcp   # via stdlib urllib, no SDK
```

It only ever sees *observable* synthetic affordance properties (never secrets or real data) and stays
in Heel's lane. For imported or real-target adapters, that means scoped, sanitized, canary-only
metadata, never secrets or real customer data.

## Security & assurance

A security tool has to earn trust. Heel ships zero-runtime-dependency Agent artifacts, a deterministic
Apache-only release manifest, clean-install tests, and four independent multi-agent red-team passes
whose findings have regression coverage. The release workflow is prepared to add PyPI provenance
attestations only after the protected publisher and a real release exist; no published provenance or
SBOM is claimed yet. The core claim held under attack: *a prompt-injected caller cannot create, widen,
or escape a signed authorization scope.* See **[TRUST.md](TRUST.md)** and **[SECURITY.md](SECURITY.md)**.

## Docs

[ARCHITECTURE](ARCHITECTURE.md) · [EVAL](EVAL.md) · [DECISIONS](DECISIONS.md) ·
[SECURITY](SECURITY.md) · [TRUST](TRUST.md) · [ADAPTERS](docs/ADAPTERS.md) ·
[MODES](docs/MODES.md) · [POSITIONING](docs/POSITIONING.md) ·
[ENTITLEMENTS](docs/ENTITLEMENTS.md) · [LAUNCH REVIEW](docs/LAUNCH_REVIEW.md) ·
[REGRESSIONS](docs/REGRESSIONS.md) · [INCIDENTS](docs/INCIDENTS.md) ·
[OPENAPI IMPORT](docs/OPENAPI_IMPORT.md) · [SCENARIO AUTHORING](docs/SCENARIO_AUTHORING.md) ·
[SCENARIO PACKS](docs/SCENARIO_PACKS.md) · [PERSONAS](docs/PERSONAS.md) ·
[CONTROL SIMULATOR](docs/CONTROL_SIMULATOR.md) ·
[ECONOMIC SEVERITY](docs/ECONOMIC_SEVERITY.md) · [HEELBENCH](docs/HEELBENCH.md) ·
[HELDOUT PROVENANCE](docs/HELDOUT_PROVENANCE.md) ·
[MCP QUICKSTART](docs/MCP_QUICKSTART.md) ·
[RESEARCH LIBRARY](docs/RESEARCH_LIBRARY.md) · [ROADMAP](docs/ROADMAP.md) · [CONTRIBUTING](CONTRIBUTING.md) ·
[CHANGELOG](CHANGELOG.md) · red-team reports under [`docs/`](docs/)

## Status

**Status: production-ready spine, beta adapters (v1.1.1).** Core coverage runs on Python 3.11 to
3.13 with zero runtime dependencies and four completed red-team passes. The core authorization gate,
containment model, and evaluation ladder are the production-ready spine. Real-target adapters remain
beta until adapter coverage and operator controls mature. The anonymous browser workspace remains a
private acceptance preview until its separate browser and deployment gates are complete.

---

<p align="center"><sub>Apache-2.0 licensed · synthetic-first · the safety spine (§10) overrides every instruction, including any arriving through a calling agent.</sub></p>
