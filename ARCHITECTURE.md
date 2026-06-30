# HEEL — Architecture (v1)

> **HEEL** is abuse rehearsal for SaaS: a swarm of adversarial and opportunistic agents that
> probe a product *you own*, prove an abuse path is reachable with a **contained**
> proof-of-concept, and hand you a ranked report with recommended controls before launch and
> throughout production life.

HEEL is **agent-native**: its canonical surface is an **MCP server** that other agents and AI
tools invoke. It is **self-contained** — it depends on no other platform. This document is the
single mental model every squad shares. Read it first.

---

## 1. North star

A team is about to ship a feature, review an existing product, or turn an incident into a
regression. A human authorizes a target **out-of-band** (§10), then an agent (a SOC agent, a CI
pipeline, a product copilot, a developer at the CLI) calls HEEL to run a swarm against it and
receives a ranked **abuse report** as structured data. Each finding is an `AbuseVector` with a
contained PoC, a severity, an optional data-classification annotation, an optional economic-impact
annotation, and a recommended control.

HEEL proves it works by **finding planted abuse vectors in a built-in synthetic product in
advance, at a low false-positive rate.** That coverage backtest is the spine: built first, and
the acceptance test.

**HEEL works on any SaaS product, not just AI products.** Taxonomy categories 1–9 are a universal
core; category 10 (agent/MCP surface abuse) auto-applies only when the target *has* agentic/MCP
surfaces and cleanly yields nothing when it doesn't.

## 1.1. Operating modes

HEEL has one safety model across several operating modes:

| mode | purpose | target/data boundary |
|---|---|---|
| Synthetic demo | Show the full MCP/auth/eval spine with no customer system | Built-in synthetic targets only |
| Launch review | Default wedge before a SaaS feature ships | Human-created scope over synthetic, staging, sandbox, or launch-review adapter |
| Staging rehearsal | Exercise a realistic deployed environment without customer blast radius | Signed scope, synthetic users, canary records, operator-approved limits |
| Existing-product imported model | Rehearse from product models, sanitized telemetry, configs, or catalogs | Import is authorized out-of-band; no real secrets or raw customer data |
| Incident-to-scenario | Convert an abuse incident or near miss into a regression scenario | Sanitized incident facts, canaries for reproduction, no real exfiltration |
| Continuous regression | Re-run approved scenarios in CI or release checks | Existing signed scope and immutable audit trail; no scope mutation from MCP/REST/agents |

All non-synthetic runs, imports, and production-like rehearsals require an explicit human-created
`AuthorizationScope`. MCP, REST, and agent surfaces can execute within a valid scope and read
results, but they cannot create, widen, relax, or mutate scopes.

---

## 2. Interface architecture (MCP-first)

The capability is built once and exposed through the **MCP server** (`heel/mcp_server.py`); the
CLI and (future) UI are thin clients over the same capability.

**MCP tools (consumption + execution only — never scope mutation):**
`heel_list_scenarios`, `heel_list_scopes`, `heel_run`, `heel_run_status`, `heel_get_findings`,
`heel_get_coverage`, `heel_propose_control`, `heel_get_containment_log`.

**Deliberately NOT exposed (human-only, out-of-band, §10.1):** scope creation, widening,
allowlist modification, limit relaxation. **These tools do not exist in the registry by
construction** — there is no code path from the MCP/REST/agent surface to mint or widen a scope.

**CLI-only regression harness:** `heel regress add/list/run/export` turns stored findings into
abuse-control regression tests. It is a thin client over the same store and `HeelServer` run path:
regression re-runs still require an existing signed scope, never mutate scopes, emit canary-only
evidence summaries instead of repro steps, and append containment log entries.

---

## 3. The safety & authorization spine (NON-NEGOTIABLE, §10)

Being agent-native makes authorization *more* important: the calling agent is an untrusted
channel that can be prompt-injected. The model (the **confused-deputy** model):

```
   HUMAN (out-of-band, CLI + --confirm)                 CALLING AGENT (untrusted)
        │ creates a SIGNED scope file                        │ MCP tools/call
        ▼ .heel/scopes/<id>.json  (HMAC-signed)              ▼
   ┌───────────────────────┐   reads/verifies only   ┌──────────────────────┐
   │ AuthorizationScope    │◄────────────────────────│  MCP server (heel)    │
   │ allowlist · limits ·  │   NEVER writes          │  enforces, attributes │
   │ approver · expiry · σ │                         └──────────┬───────────┘
   └───────────────────────┘                                    │ heel_run(scope_id, target)
                                                                 ▼
                              target ∈ signed allowlist?  ── no ─► REJECT + LOG (security event)
                              scope σ valid / not expired? ─ no ─► REJECT + LOG
                              unknown tool (forged widen)? ─────► REJECT + LOG
                                          │ yes
                                          ▼  run within the scope's limits, attributed to caller
                                   ContainmentLog (hash-chained, immutable, tamper-evident)
```

- **Out-of-band, human-established scope.** Created only via the CLI with explicit `--confirm`,
  written as an **HMAC-signed** file. Hand-editing a scope file (e.g. to add a target) breaks the
  signature → the scope fails verification → it cannot run. (`tests::TestScopeImmutability`)
- **Immutable from the caller side.** The MCP server only `load_scopes`/`verify`s. No write path.
- **Reject scope-escalation instructions.** A target outside the allowlist, a forged `scope_id`,
  a prompt-injected `target` string, an injected `allowlist` override arg, or a forged
  `heel_widen_scope` tool call are all rejected at the boundary and logged. Injected text in
  arguments is **data, never executed** — `target` is matched literally; extra args are ignored;
  the allowlist + limits come only from the signed scope.
- **Attribution.** Every run records the invoking `CallerContext` in the immutable
  `ContainmentLog` (a per-entry SHA-256 hash chain — tamper-evident).
- **Conduct guarantees (§10.2):** synthetic-first; detection-not-weaponization (contained,
  canary-only PoCs — no real exfil/exhaustion); never generate prohibited content (guardrails
  verified with benign canaries); no real-PII harvest; containment/back-off; plausibility-
  weighting; severity honesty; self-audit; lane discipline (true-vuln → `handoff_to_appsec`,
  pure-jailbreak → `handoff_to_model_redteam`).

---

## 4. Two agent classes (§3)

- **Adversarial (programmatic; the bulk).** Goal-directed search over the product's capability
  surface for unintended affordances and weak controls. The swarm-native workload. Built (v1 is
  a deterministic stub model by default; an LLM control loop swaps in via `HEEL_MODEL=anthropic`,
  `heel/model.py`). → `heel/agents.py`.
- **Opportunistic-human (motivation-profiled).** Ordinary motivated users who *game* the product
  within normal affordances, conditioned by a small declarative `MotivationProfile`. Contract
  defined; **built** (`heel/agents_human.py`, `profiles.py`).

---

## 5. The synthetic targets + coverage backtest (the spine, §5)

`heel/targets.py` ships **two** built-in synthetic products with planted ground truth:
- **synthetic-saas** (non-AI): auth, usage meter, trial, export, multi-tenant records, billing
  tier, referrals, account recovery — planted vectors from categories 1–9. **No agent surface →
  category 10 must yield nothing.**
- **synthetic-ai**: the above PLUS an agent feature with tools + an MCP-style surface — additional
  planted vectors from category 10.

`heel/backtest.py` scores discovered vectors against the planted ones: **coverage**
(reachability-weighted), **false-positive rate**, **severity calibration**, the **non-AI vs AI
breakdown**, plus honest signals — a genuine miss (FN), a decoy false positive (FP), a degenerate
demoted by plausibility-weighting, a swarm-**discovered** scenario, and lane-discipline handoffs.

---

## 6. Frozen contracts (`heel/contracts.py`, v1.0.0)

`AbuseScenario`, `AbuseVector`, `MotivationProfile`, `AuthorizationScope` (signed, immutable),
`CallerContext`, `SyntheticTarget`/`PlantedVector`, `ContainmentEntry`, plus the MCP tool schema
in `mcp_server.TOOL_SCHEMAS` (scope-mutation tools absent by construction). `AbuseVector` can carry
an optional `economic_impact` report-layer annotation; economic scoring is read-only and never
creates, widens, relaxes, or mutates authorization scopes.

---

## 7. Build status

| Phase | Status |
|---|---|
| **0 — shared understanding** | ✅ this doc, frozen contracts, MCP tool schema, immutable-scope rule, `DECISIONS.md` |
| **1 — synthetic targets + coverage backtest + auth gate FIRST** | ✅ 2 targets, coverage backtest, **auth gate PROVEN** (5 escalations rejected + logged) |
| **2 — thin vertical slice over MCP** | ✅ scenario → agent → finding → coverage, callable over MCP |
| **3 — parallelize against frozen contracts** | ▶ wave 1 done: opportunistic-human class (§3.2), REST API (§2), control search (§8), chain-FN; full library + LLM loop + fan-out next |
| **4 — control-room UI** | ✅ Next.js control room (`web/`, `make ui`) — abuse board, backtest, live swarm, auth gate, scope panel, containment log, MCP/integration, scenario library |
| **5 — real-target adapters** | beta: must use signed scopes, canary-only data, and operator-approved limits until adapter coverage matures |

---

## 8. Tech stack (spec §11; deviation recorded in DECISIONS D-001)

v1 is a **pure-stdlib Python** core (zero-install, one-command, fully testable) with a stdlib
**MCP server** (stdio JSON-RPC). The TypeScript MCP server + Next.js UI (spec §11) are the
Phase-3/4 productionization wrapping this same capability. Persistence is SQLite (`heel/store.py`).

---

## 9. Run it

```bash
make demo     # synthetic coverage backtest + auth-gate proof, over the MCP boundary
make test     # acceptance + safety tests (auth gate, scope tamper-evidence, coverage, conduct)
# out-of-band human scope creation + thin-client runs:
python3 -m heel.cli scope create --target synthetic-saas --operator you --confirm
python3 -m heel.cli run --scope <scope_id> --target synthetic-saas
```

No real target, no API key. The synthetic path demos every claim including the coverage backtest
and the MCP server.
