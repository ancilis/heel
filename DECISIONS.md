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

### D-021 — Blind-target evaluation is the honest detection metric; coverage is self-consistency
**Why:** the red-team showed the synthetic coverage is circular. `heel/blind.py` plants weaknesses
using a broad ENCODING vocabulary authored independently of the seed probes (synonyms the library
doesn't key off, verified not to leak via discovery either); `heel/blind_eval.py` aggregates real
recall/precision/FP + 95% CI across many targets. Real recall ~0.25 (vs 0.93 self-consistency) is
the honest real-target estimate; it rises only by growing the library's encoding breadth — it cannot
be gamed by writing probes against known plants.

### D-022 — Affordance-chaining is a real capability; compound findings aren't false positives
**Why:** chaining (`heel/chaining.py`) finds multi-step abuse (ATO = weak recovery + non-rotated
session) the single-affordance classes miss, closing the synthetic ato_chain FN. The backtest
EXCLUDES `chain:`-prefixed compound findings from the FP count (a chain over two genuinely-vulnerable
affordances is a legitimate escalation, not a false alarm on a hardened affordance). The honest
sub-1.0 signal now lives in the blind eval, not the synthetic coverage.

### D-023 — Fan-out is a bounded thread pool (honest about the GIL)
**Why:** §7 thousand-agent fan-out. `blind_eval` runs targets via `concurrent.futures` threads — the
INTERNAL eval path (no scope/real target, so no auth gate needed; it never touches a real system).
With the stub model the GIL bounds CPU speedup, so we call it a bounded fan-out, not literal 1000×;
with real LLM agents (`HEEL_MODEL=anthropic`) threads overlap network-bound work. Determinism is
preserved (each target seeded; no shared mutable RNG across threads).

### D-024 — The blind eval is a transparent LOWER BOUND vs measured encoding-overlap, not a dialed number
**Why:** the second red-team showed recall ≈ the matchable-encoding fraction (author-chosen), precision
rested on one over-broad probe, and the CI was mis-modelled. Fixes: report recall against the
empirically-MEASURED encoding-overlap (the independent variable) and label it a stated lower bound;
Wilson CI on the pooled proportion; per-probe FP attribution + boundary decoys; sound chaining FP
accounting (a chain over a decoy is a real FP, not a laundered "compound"); a synonym-leak regression
test; honest fan-out wording (GIL-bound thread pool). The honest claim: HEEL detects what its library
anticipates (~the measured overlap); a defensible external accuracy claim needs independently-authored
or held-out scenarios — stated, not hidden.

### D-025 — Held-out, independently-authored targets are the strongest detection metric
**Why:** the blind eval's encoding-overlap was still author-chosen. `heel/heldout/targets.json` is
authored by an independent LLM swarm blind to HEEL's probes (workflow `heel-heldout-authoring`;
provenance in docs/HELDOUT_PROVENANCE.md), removing author control over the vocabulary.
`heel/heldout_eval.py` reports recall exact-match (~0.26) vs with semantic generalization (~0.57,
Wilson CI), at ~0.95 precision, with per-category breakdown. Frozen for deterministic offline runs.

### D-026 — Semantic signal matching is the honest generalization axis (not exact property names)
**Why:** exact property==value/kind criteria don't generalize to vocabularies HEEL didn't author.
`heel/semantic.py` matches weakness FAMILIES by topic keywords in the property KEY + permissive value
indicators (and absence of a hardened indicator), via `{"semantic": signal}` criteria on kind "*"
scenarios (agent-category ones gated to has_agent_surface to preserve cat-10 optionality). On the
held-out set this roughly doubles recall at high precision. Topic+permissive (not topic alone) keeps
precision: a tightened tenant topic avoids miscategorizing an MCP `context_isolation` finding.

### D-027 — Held-out uses a dev/test split; the frozen TEST recall is the headline
**Why:** tuning the semantic catalog to raise recall would overfit if measured on the same targets.
The semantic catalog is tuned on DEV (heel/heldout/targets.json, 8 products); a larger TEST set
(heel/heldout/test_targets.json, 14 products / 199 weaknesses) was authored by a fresh independent
LLM swarm and frozen WITHOUT the tuner inspecting its properties. Reported: DEV semantic 0.73 vs
TEST semantic 0.38 (Wilson CI [0.31,0.45]) at 0.96 precision — the dev→test gap is the overfitting
gap, shown rather than hidden. recall improves only by widening real-vocabulary coverage.

### D-028 — Boolean polarity is property-dependent → no bare "true" in the permissive vocabulary
**Why:** broadening semantic permissive values with "true"/"enabled" wrecked precision
(audit_logged:true is GOOD, acts_on_content:true is BAD). Removed them; precision recovered to 0.96
on both dev and the unseen test set. Where true==weakness, the signal matches the explicit bad word
(e.g. "passthrough", "no_check") instead.
