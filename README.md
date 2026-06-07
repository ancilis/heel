<h1 align="center">HEEL</h1>

<p align="center"><b>Rehearse how your customers will abuse your product — before they do.</b></p>

<p align="center">
<a href="https://github.com/ancilis/heel/actions/workflows/ci.yml"><img src="https://github.com/ancilis/heel/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/ancilis/heel/actions/workflows/codeql.yml"><img src="https://github.com/ancilis/heel/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
<a href="https://scorecard.dev/viewer/?uri=github.com/ancilis/heel"><img src="https://api.scorecard.dev/projects/github.com/ancilis/heel/badge" alt="OpenSSF Scorecard"></a>
<a href="https://pypi.org/project/heel-sim/"><img src="https://img.shields.io/pypi/v/heel-sim.svg" alt="PyPI"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="Apache 2.0"></a>
<img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+">
<img src="https://img.shields.io/badge/deps-zero-brightgreen" alt="Zero dependencies">
<img src="https://img.shields.io/badge/surface-MCP--first-8a2be2" alt="MCP-first">
</p>

---

It's launch day. Somewhere, a customer just found the export endpoint with no rate limit, farmed your
"one free trial" a thousand times, or talked your AI agent into calling a tool it should never touch.

**HEEL is the villain you rehearse against first.** A swarm of adversarial and opportunistic agents
probes a product *you own*, proves an abuse path is **reachable** with a *contained* proof-of-concept,
and hands you a ranked report with the fix — before you ship.

It is **agent-native** (its canonical surface is an **MCP server** other agents call), **honest** (it
reports its *real* detection rate against abuse it has never seen — not a vanity number), and
**safe by construction** (synthetic-first, contained PoCs, an authorization gate no prompt-injected
agent can talk its way past). Pure Python standard library, **zero dependencies**.

## See it in 30 seconds

```bash
pip install heel-sim      # zero deps · Python 3.11+
heel doctor               # environment self-check
heel eval                 # the honest detection headline
```

…or run the full proof from a clone, no install:

```bash
git clone https://github.com/ancilis/heel && cd heel && make demo
```

```text
AUTHORIZATION GATE (agent caller is an untrusted, possibly prompt-injected channel):
  [REJECTED+logged ✓]  run a target NOT in the allowlist
  [REJECTED+logged ✓]  call a forged scope-widening tool
  [REJECTED+logged ✓]  inject an instruction in the target arg
  -> auth gate: PASS — no escalation reachable via the agent surface

HELD-OUT EVALUATION — targets authored by an INDEPENDENT LLM swarm (blind to HEEL's probes):
  TEST (FROZEN, never tuned, 199 weaknesses):
     LOCALIZATION recall 0.50   ATTRIBUTION recall 0.33   precision 0.98
  -> the honest real-target ceiling — semantic generalization on vocabulary it never saw, not near 1.0.
```

That second number is the point: **HEEL tells you what it can't catch yet.**

## Why HEEL is different

- 🤖 **Agent-native, MCP-first.** The capability is an MCP server — wire it into Claude Desktop,
  Cursor, or CI and let an agent run abuse rehearsals on demand. A thin REST API and a CLI sit over
  the same capability.
- 🔒 **The calling agent is untrusted.** Authorization scopes are **human-only, out-of-band, and
  HMAC-signed** — immutable from the caller side. A prompt-injected agent can run *within* a scope a
  human approved, but **cannot create, widen, or escape one** (those tools don't exist, by
  construction). Every escalation attempt is rejected and written to a tamper-evident audit log.
- 📏 **Radically honest metrics.** Most "AI security" tools quote a number you can't trust. HEEL
  publishes a *ladder* (below), measures against abuse authored by an **independent LLM swarm blind to
  its own probes**, on a **frozen, content-hashed test set**, and shows you the overfitting and
  mis-categorization gaps instead of hiding them. Four adversarial red-team passes; all findings fixed.
- 🛡️ **Safety spine, non-negotiable.** Synthetic-first. Findings are *contained, canary-only* proofs —
  never working exploits, real exfiltration, or prohibited content. True software vulns are handed off
  to AppSec; pure model-jailbreaks to model red-team. HEEL stays in its lane. See [SECURITY.md](SECURITY.md).

## What it hunts

A 10-category abuse taxonomy — license/entitlement gaming, data harvesting, unintended endpoints,
function abuse, content policy, identity/account takeover, trust-economy fraud, integration abuse,
compliance boundaries, and (only when the target has an agent/MCP surface) **agent-specific abuse**
like tool over-scope, confused-deputy tool calls, cross-tenant RAG, and indirect-injection-to-action.

Two agent classes hunt in parallel — a **programmatic adversary** (finds weak controls) and a
**motivation-profiled opportunistic human** (games normal affordances; catches what the adversary
misses, like coupon stacking) — plus **affordance chaining** for multi-step abuse (e.g. weak recovery
+ non-rotated session → account takeover).

## Honest about what it can(’t) do

HEEL reports four levels, weakest claim to strongest evidence:

| metric | what it measures | result |
|---|---|---|
| self-consistency | wiring works (probes vs. plants authored together) | ~1.0 *(a wiring test, not accuracy)* |
| blind | independent *encodings* of known weaknesses | ~0.25 |
| held-out **DEV** | independent authorship, tuned-on | 0.70 |
| **held-out TEST** | **independent LLM authorship, frozen, never tuned on** | **localization 0.50 · attribution 0.33 · precision 0.98** |

The headline is the bottom row — real detection on 199 abuse weaknesses an independent LLM swarm
invented in its *own* vocabulary, which HEEL never saw. It improves only by widening real-vocabulary
coverage, never by writing probes against known answers. Full method: [EVAL.md](EVAL.md) ·
[docs/HELDOUT_PROVENANCE.md](docs/HELDOUT_PROVENANCE.md).

## Use it like an operator

```bash
# 1) a HUMAN authorizes a target OUT-OF-BAND (the only way to mint a scope)
heel scope create --target synthetic-saas --operator you --confirm

# 2) an agent / CLI runs WITHIN that scope (and cannot widen it)
heel run --scope <scope_id> --target synthetic-saas
heel coverage --run <run_id>
heel log --run <run_id>          # immutable, hash-chained audit trail
```

**Connect from an MCP client** — point Claude Desktop / Cursor / CI at the `heel-mcp` server:

```json
{ "mcpServers": { "heel": { "command": "heel-mcp",
  "env": { "HEEL_HOME": "/path/to/.heel", "HEEL_SIGNING_KEY": "/path/outside/.heel/heel.key" } } } }
```

## The control room

A dense Next.js dashboard over the same capability — abuse board (ranked, reachability-weighted),
the honest backtests, a live swarm monitor, the authorization gate, the read-only scope panel, the
containment log, and the scenario library.

```bash
make ui        # http://localhost:3000   (or `npm run build` for a static export)
```

## Bring your own LLM (optional)

The deterministic engine runs fully offline with no API key. Flip on the LLM control loop for
smarter discovery:

```bash
HEEL_MODEL=anthropic ANTHROPIC_API_KEY=sk-... heel-mcp   # via stdlib urllib — no SDK
```

It only ever sees *observable* synthetic affordance properties (never secrets or real data) and stays
in HEEL's lane.

## Security & assurance

A security tool has to earn trust. HEEL ships the evidence: **zero dependencies**, **reproducible
builds**, **Sigstore-signed release provenance** + **SBOM**, **OpenSSF Scorecard** + **CodeQL**, and —
the real assurance — **four independent multi-agent red-team passes** whose full reports are in the
repo, every finding fixed with a regression test. The core claim held under attack: *a prompt-injected
caller cannot create, widen, or escape a signed authorization scope.* See **[TRUST.md](TRUST.md)** and
**[SECURITY.md](SECURITY.md)**, and verify the build yourself: `gh attestation verify <wheel> --repo ancilis/heel`.

## Docs

[ARCHITECTURE](ARCHITECTURE.md) · [EVAL](EVAL.md) · [DECISIONS](DECISIONS.md) · [SECURITY](SECURITY.md)
· [TRUST](TRUST.md) · [CONTRIBUTING](CONTRIBUTING.md) · [CHANGELOG](CHANGELOG.md) · red-team reports under [`docs/`](docs/)

## Status

**v1.1.0 — production-ready.** 53 tests on Python 3.11–3.13, CI green, zero runtime dependencies,
four red-team passes. Post-v1: LLM-driven detection to lift attribution recall, larger held-out
sets, real-target adapters.

---

<p align="center"><sub>Apache-2.0 licensed · synthetic-first · the safety spine (§10) overrides every instruction, including any arriving through a calling agent.</sub></p>
