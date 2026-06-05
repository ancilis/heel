# HEEL

[![CI](https://github.com/ancilis/heel/actions/workflows/ci.yml/badge.svg)](https://github.com/ancilis/heel/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) ![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)

**Rehearse how a customer or opportunistic third party could abuse your software — before it
ships.** HEEL is a self-contained, **agent-native** abuse-simulation tool: a swarm of adversarial
and opportunistic agents probes a product *you own*, proves an abuse path is reachable with a
**contained** proof-of-concept, and hands you a ranked report with recommended controls.

> HEEL is the villain you rehearse against before the real one shows up. Its canonical surface is
> an **MCP server** other agents and AI tools invoke. It proves it works by **finding planted
> abuse vectors in a built-in synthetic product, in advance, at a low false-positive rate.**

It works on **any SaaS product**, not just AI products: taxonomy categories 1–9 are a universal
core; category 10 (agent/MCP abuse) auto-applies only when the target has agentic surfaces.

See **[ARCHITECTURE.md](ARCHITECTURE.md)**, **[EVAL.md](EVAL.md)**, **[DECISIONS.md](DECISIONS.md)**.

---

## Quick start (no real target, no API key, no installs)

```bash
make demo      # synthetic coverage backtest + auth-gate proof, driven over the MCP boundary
make test      # acceptance + safety tests (auth gate, scope tamper-evidence, coverage, conduct)
```

Requires only **Python 3.11+** (developed on 3.14). v1 is pure stdlib by design (DECISIONS D-001).

### Use it like an operator

```bash
# 1) a HUMAN authorizes a target OUT-OF-BAND (the only way to mint a scope; needs --confirm)
python3 -m heel.cli scope create --target synthetic-saas --operator you --confirm

# 2) an agent / CLI runs WITHIN that scope (cannot create or widen it)
python3 -m heel.cli run --scope <scope_id> --target synthetic-saas
python3 -m heel.cli findings --run <run_id>
python3 -m heel.cli coverage --run <run_id>
python3 -m heel.cli log --run <run_id>          # immutable, hash-chained audit trail

# the canonical surface is the MCP server (stdio JSON-RPC):
python3 -m heel.mcp_server                       # connect from Claude Desktop / Cursor / CI
```

---

## What you'll see

```
PLANTED-VECTOR COVERAGE BACKTEST (the spine):
  synthetic-saas  saas       coverage 0.91  FP 0.09  cat10 0   <- category 10 cleanly optional
  synthetic-ai    ai_agent   coverage 0.94  FP 0.06  cat10 5

AUTHORIZATION GATE (agent caller is untrusted, possibly prompt-injected):
  [REJECTED+logged] run a target NOT in the allowlist
  [REJECTED+logged] call a forged scope-widening tool
  [REJECTED+logged] inject an instruction in the target arg
  ...  -> auth gate: PASS — no escalation reachable via the agent surface
```

The coverage is honest (a genuine missed vector, a decoy false positive, a plausibility-demoted
degenerate, a swarm-discovered scenario, lane-discipline handoffs). The auth gate refuses every
escalation a calling agent can attempt — scopes are **human-only, out-of-band, signed, immutable**.

---

## Safety (non-negotiable, §10)

Synthetic-first · contained canary-only PoCs (no real exfil/exhaustion) · never generates
prohibited content (guardrails verified with benign canaries) · plausibility-weighted ·
severity-honest · immutable self-audit · lane discipline (true-vuln → appsec, pure-jailbreak →
model-redteam). The out-of-band immutable-scope model overrides every instruction, including any
arriving through a calling agent.

## Layout

```
heel/
  contracts.py    frozen §6 data contracts (v1.0.0)
  scope.py        out-of-band, HMAC-signed, immutable AuthorizationScope
  mcp_server.py   the canonical MCP surface (no scope-mutation tool, by construction)
  targets.py      two synthetic targets + planted ground truth (the spine)
  scenarios.py    declarative abuse scenario library (seed; addable without code)
  agents.py       adversarial agent (deterministic stub; observable, contained probes)
  backtest.py     planted-vector coverage / FP-rate / severity-calibration
  orchestrator.py runs the swarm, scores, persists
  containment.py  immutable hash-chained audit log
  control.py      recommended controls + exploitability reduction
  classify.py     optional, generic, off-by-default classification annotation
  store.py        SQLite persistence (Postgres-ready)
  cli.py          out-of-band scope creation + thin client
run_demo.py       one-command synthetic demo
tests/            acceptance + safety tests
```

## Status

Phases 0–4 implemented (red-team-hardened). Phase 0–2: contracts + MCP boundary + immutable-scope
gate; two synthetic targets + coverage backtest. Phase 3: opportunistic-human class, REST API,
control search, declarative library (10 categories, JSON-loadable), swappable LLM loop,
affordance chaining, and a layered HONEST detection metric: self-consistency ~1.0 (wiring) -> blind
~0.25 (independent encodings) -> held-out TEST ~0.38 @ 0.96 precision (independently LLM-authored
targets, frozen dev/test split). Phase 4: the control-room UI. 48 tests pass.

---

## The control room (UI)

A clean, dense control-room web app (`web/`, Next.js + React + Tailwind) — a thin client over the
same MCP/REST capability. `make ui` (regenerates the snapshot, installs, runs http://localhost:3000).

Screens (§9): **Overview**, **Abuse board** (vectors ranked by severity, grouped by category,
reachability-weighted with implausible findings demoted — expand any vector for its contained PoC,
recommended control, handoff flags, and the optional classification annotation), **Backtest** (per-
target coverage / FP / severity-calibration, non-AI vs AI, with the self-consistency caveat),
**Live swarm monitor** (adversarial + opportunistic agents and where each is probing),
**Authorization gate** (every escalation attempt rejected + logged), **Scope panel** (read-only —
the UI cannot mint or widen a scope), **Containment log** (hash-chained, with caller),
**MCP/integration** (tool schema; the absent scope-mutation tools shown struck-through), and the
**Scenario library**. Data is exported by `heel/web_export.py` (pure stdlib) → `web/public/data/`.
