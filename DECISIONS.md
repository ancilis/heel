# HEEL — Decision log

Every non-obvious decision and assumption (spec §14). Append-only.

---

### D-001 — v1 is a pure-stdlib Python core with a stdlib MCP server (deviation from §11 TS, recorded)
**Why:** the §13 DoD's hardest constraint is *one-command bring-up; the synthetic demo runs
end-to-end with no real target and no API key*. A single-language pure-stdlib core (the host has
no third-party libs and scipy/torch wheels for Python 3.14 aren't guaranteed) runs from a clean
checkout with zero `pip install` and is fully testable. The MCP protocol is language-agnostic, so
the MCP server is implemented in stdlib Python (stdio JSON-RPC) — a legitimate, common choice. The
TypeScript MCP server + Next.js UI (§11) are the Phase-3/4 productionization that wrap this same
capability behind the *same* tool schema. **Impact:** `heel/` is pure stdlib; `sqlite3`/`hmac`/
`hashlib` (all stdlib) back persistence/signing/audit.

### D-002 — AuthorizationScope is an out-of-band, HMAC-signed, immutable file
**Why:** §10.1 requires that a calling agent can run within a scope but can never create or widen
one, even via prompt injection. Modelling the scope as a **signed file** the CLI writes (with
`--confirm`) and the server only reads makes the boundary structural: there is no write path from
the MCP/REST/agent surface, and **hand-editing the file breaks the HMAC signature** so a widened
scope fails verification. Tamper-evidence + human-only creation in one mechanism.
(`tests::TestScopeImmutability`).

### D-003 — Immutable containment log is a per-entry hash chain
**Why:** §10.2.8 (self-audit) + tamper-evidence. Each `ContainmentEntry.entry_hash =
sha256(prev_hash + canonical(entry))`, so any edit to the audit trail is detectable
(`verify_chain`). Append-only via SQLite. Rejected escalation attempts are logged as security
events attributed to the caller.

### D-004 — The coverage backtest is engineered to be HONEST, not circular
**Why:** a seed library that maps 1:1 onto planted vectors would score a meaningless ~100%. The
synthetic targets therefore include: a planted vector **no seed scenario can catch and discovery
can't infer** (`promo_stacking` → a genuine FN, so coverage < 1.0), a **decoy** that looks abusable
but is hardened (`export_billing` → a real FP), a **degenerate** present-but-unreachable affordance
(`legacy_import` → found and demoted by plausibility-weighting, not counted), a planted vector with
**no seed scenario that the swarm must DISCOVER** (`webhook_endpoint`), and **lane-discipline
handoffs** (SSRF → appsec, jailbreak surface → model-redteam). Severity priors deliberately differ
from planted ground truth so **severity calibration < 1.0** (≈0.66–0.78). The honest signals — the
FN, the FP, the demotion, the discovery, the calibration — matter more than the headline coverage.

### D-005 — v1 agents are a deterministic stub model
**Why:** §11 mandates a stub model path so the synthetic demo runs with no API key. The adversarial
agent's probes read only OBSERVABLE signals (control presence as revealed by probing; enumerated
properties) — never the planted ground truth — and emit contained, canary-only PoCs. The
Anthropic/LLM control loop and the opportunistic-human class are Phase 3 behind the same contracts.

### D-006 — Classification enrichment is optional, generic, off by default
**Why:** §8 — annotative only, no governance coupling. `heel/classify.py` is a swappable
`Classifier` interface with a default field-name/shape heuristic; `enrich(..., enabled=False)` is a
no-op unless explicitly turned on. HEEL is fully functional with it off; it enforces nothing at
runtime and binds to no external framework.

### D-007 — `git init` + commit the scaffold locally; do not push
**Why:** the DoD speaks in repo terms ("clean checkout", "one command"). A brand-new repo we are
creating, so committing the baseline locally is the natural starting point. No remote/push without
an explicit request.

### D-008 — Content/jailbreak surfaces are verified, never exercised
**Why:** §10.2.3 is absolute. The content-guardrail probe sends a **benign canary** to check that a
guardrail is PRESENT and reports absence at max severity — it never generates, completes, or
describes any prohibited artifact under any framing. Pure model-jailbreak surfaces are **handed off**
(`handoff_to_model_redteam`), never weaponized — HEEL's lane is the product/business *consequence*,
not the technique (§4.10 boundary).

---

## Red-team-driven hardening (v1 safety-spine review)

A 4-agent adversarial workflow confirmed the #1 claim (a prompt-injected MCP caller cannot escape
a signed scope) but found gaps between claim and implementation. Fixes:

### D-009 — Signing-key threat model made honest; key can live outside the data dir
**Why:** the red-team showed the HMAC key co-located in `.heel/` reduces tamper-evidence to "can
you write `.heel/`" rather than "possess a secret". `HEEL_SIGNING_KEY` now points the key outside
the data dir (keychain/HSM in prod). The in-`.heel/` default is documented as demo-only. Fixed the
"stable per repo" docstring (the key is random per home, not repo-stable).

### D-010 — Reachability is a continuous depth-based estimate, not two magic keys
**Why:** the auditor showed the old estimator keyed off two declared strings (gameable; cov_w
cosmetic). It now discounts by observed prerequisite depth (chained steps, auth/verification/payment
gates), so a degenerate hidden behind depth is demoted even without self-declaring, and
reachability-weighted coverage is load-bearing.

### D-011 — Rate/resource limits are ENFORCED server-side (not just signed)
**Why:** `contracts.py` claimed "enforced server-side regardless of caller request" but nothing
read the field — a max_requests=1 scope ran 20×. The server now enforces `max_requests` via a
persisted per-scope run counter before each run; over-limit runs are rejected and logged.
(max_concurrency/backoff are Phase 3.)

### D-012 — Containment log is HMAC-signed + completeness-checked
**Why:** bare sha256 chaining let an actor rewrite + re-chain the whole log undetected. Each entry
is now HMAC-signed with the signing key (re-chaining needs the secret); `verify_chain` checks global
seq-contiguity (defeats middle deletion) and `run_is_logged` requires a `run_start` for any run
(defeats whole-run deletion). **Residual:** tail-truncation needs an external head anchor (Phase 3).

### D-013 — No severity inflation
**Why:** a hard 0.9/1.0 override on a missing content guardrail overrode the scenario's modeled
impact. Severity now always comes from the scenario `severity_model` with a surfaced uncertainty
band (no inflation, §10.2.7).

### D-014 — The backtest is a SELF-CONSISTENCY / wiring metric, not detection accuracy
**Why:** the seed probes were authored against the planted weaknesses, so coverage/calibration are
self-consistency checks. This is now stated in the data (`metric_kind`, `caveat`) and every doc;
the 0.9 numbers are NOT cited as real-target accuracy. Trustworthy real-target evaluation requires
blind targets + held-out scenarios (independently-authored plants vs probes) — the next step.

---

## Phase 3 — wave 1

### D-015 — Both agent classes merge by affordance; opportunistic ADDS, never overrides
**Why:** the adversarial class produces calibrated severities; the opportunistic-human class would
over-rate shared affordances. So the opportunistic class only ADDS affordances it uniquely games
(seat sharing, region arbitrage, coupon stacking) — preserving adversarial calibration while
closing the adversarial coupon-stacking blind spot. A multi-affordance `ato_chain` vector is
missed by both (single-affordance) classes, keeping an honest FN (coverage < 1.0). Affordance-
chaining discovery is later Phase-3 work.

### D-016 — REST is a thin client over the SAME HeelServer (one auth gate)
**Why:** §2 — build the capability once. `heel/rest.py` routes HTTP to `HeelServer.call_tool`, so
the §10 enforcement is identical and cannot diverge. No scope-creation route exists (POST /scopes
→ 405 + security log). `check_same_thread=False` lets the threaded server share the store.

### D-017 — Control proposal is a ranked search, not a single string
**Why:** §7/§8 — `heel_propose_control` returns the agent's recommendation plus a per-category
control bank, ranked by estimated exploitability reduction. A Phase-4 version re-simulates each
candidate against the affordance to measure the reduction empirically rather than estimate it.

### D-018 — The scenario library is fully declarative (addable without code, incl. JSON)
**Why:** §4 "scenarios are specs addable without code". Per-strategy probe functions are replaced by
ONE generic `evaluate_criterion` over a small declarative language (guard_absent / prop±equals/in/
exists / prop_contains / prop_neq / all_of / any_of / not). Controls + handoff move INTO the scenario
spec. `heel/scenarios_lib/*.json` is merged at load. Breadth is now 34 scenarios across all 10
categories; scenarios that match no synthetic affordance correctly don't fire (no FP inflation).

### D-019 — LLM control loop is a swappable Model with an offline deterministic default
**Why:** §11 "an LLM control loop ... a stub model path so the synthetic demo runs with no API key".
`heel/model.py`: `StubModel` (deterministic, heuristic discovery, default) and `AnthropicModel`
(`HEEL_MODEL=anthropic`, Messages API via stdlib urllib, no SDK). The model only sees observable
properties and only proposes declarative scenario specs — HEEL builds the contained PoC; the model
stays in lane and falls back to the heuristic on error/no-key. Keeps the pure-stdlib core.

### D-020 — UI is a thin client over a pure-stdlib JSON snapshot
**Why:** §9 control room. `heel/web_export.py` runs the full synthetic flow over the MCP capability
(deterministic) and writes `web/public/data/snapshot.json`; the Next.js app reads it. Same pattern
as the rest of HEEL: the capability is built once (MCP-first) and every surface is a thin client.
The UI honors the epistemics (reachability-weighting visible, implausible demoted not hidden;
predicted/contained PoCs; optional classification shown when on; the scope panel is read-only and
cannot mint/widen a scope). `node_modules` gitignored; the snapshot is committed so the UI renders
on a clean checkout.
