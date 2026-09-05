# Heel — Evaluation

September 4 business-rule correction: current synthetic vocabulary run reports localization recall **0.417**, attribution recall **0.251**, precision **0.976** on 199 authored weaknesses. Rule applicability requirements reduce metadata-only matches. These are model-matching metrics, not live detection accuracy or proof of customer effectiveness. Scenario entries include alternate encodings, not that many independent executable mechanisms. The historical 120 scenarios / localization recall 0.50 / attribution recall 0.33 / precision 0.98 discussion below predates these changes. The export reference has separate behavioral acceptance described in [CAPABILITIES.md](docs/CAPABILITIES.md).

Honest results from the integrated Heel platform. Reproduce with `make demo`, `make demo-bench`, or
`python3 -m unittest discover -s tests`. Everything is computed locally and deterministically.
The evaluation story applies to the same product described in README, ARCHITECTURE, SECURITY, TRUST,
and DECISIONS: pre-launch launch review plus existing-product abuse rehearsal, with signed scopes,
canary-only findings, beta adapters, and no scope creation, widening, relaxation, or mutation path
over MCP, REST, or agent surfaces.

---

> **Framing.** Heel reports a ladder, not a vanity number. Synthetic self-consistency proves the
> wiring and safety spine. Blind targets give a lower bound against independently encoded weaknesses.
> The headline is the frozen held-out TEST split: independently authored targets, blind to Heel's
> probes, with localization, attribution, precision, and cluster CIs reported separately.

## 1. Current headline metrics

The current public benchmark (`heel bench report`) summarizes the integrated library:

| metric | value | meaning |
|---|---:|---|
| self-consistency coverage | 1.00 | synthetic wiring check, not real-target accuracy |
| blind lower-bound recall | 0.404 | repository-authored blind encodings; lower bound, not an external claim |
| held-out DEV localization recall | 0.763 | tuned-on split, useful for development |
| held-out DEV attribution recall | 0.485 | right affordance and category on DEV |
| held-out TEST localization recall | **0.497** | frozen, independently authored TEST split |
| held-out TEST attribution recall | **0.332** | stricter TEST headline: right affordance and category |
| held-out TEST precision | **0.98** | precision on unseen vocabulary |
| scenario library | **120 scenarios** | declarative scenarios across all 10 abuse categories |

Rounded for README: localization recall 0.50, attribution recall 0.33, precision 0.98. The
localization→attribution gap is disclosed because flagging the right affordance is weaker evidence
than also assigning the right abuse category.

## 2. What each metric is allowed to mean

- **Self-consistency** runs synthetic targets over the MCP boundary under an enforced signed scope.
  It proves contracts, containment, planted-vector scoring, category-10 optionality, and auth-gate
  behavior. It is a wiring test, not real-target detection accuracy.
- **Blind lower bound** uses procedurally generated targets with independently encoded weaknesses.
  It measures the library's encoding overlap and surfaces false-positive attribution.
- **Held-out DEV** is allowed to influence semantic/library work.
- **Held-out TEST** is frozen and content-hashed. It is the unbiased number for independently
  authored target vocabulary.
- **Imported ProductModel / existing-product modes** are model rehearsals over sanitized metadata
  unless an operator explicitly authorizes canary-only staging or production-like adapters. Imported
  targets have no planted ground truth, so Heel labels their outputs as rehearsals instead of
  coverage or accuracy.

## 3. Safety and authorization invariants

The agent caller is treated as an untrusted, possibly prompt-injected confused deputy. Every
escalation attempt over the MCP surface is **rejected and logged**:

| attempt (via MCP) | result |
|---|---|
| run a `target` NOT in the scope allowlist | **REJECTED + logged** |
| call a forged `heel_widen_scope` tool | **REJECTED + logged** (tool absent by construction) |
| inject an instruction in the `target` arg | **REJECTED + logged** (target matched literally) |
| run with a forged `scope_id` | **REJECTED + logged** |
| pass an injected `allowlist` / `_relax_limits` arg | **REJECTED + logged** (extra args ignored) |
| **hand-edit a signed scope file to add a target** | **REJECTED** (HMAC signature breaks) |
| run an expired scope | **REJECTED** |

→ **Auth gate: PASS** — no escalation is reachable via the agent surface. Runs are attributed to
the caller; the **containment log hash-chain verifies** and is **tamper-evident** (mutating any
entry fails `verify_chain`). There is **no scope-creation/widening tool** in the registry; scopes
are human-only, out-of-band, signed (DECISIONS D-002). The same no-scope-mutation rule applies to
MCP, REST, CLI-triggered agent workflows, imported ProductModels, regressions, incidents, launch
review, and control simulation.

## 4. Recommended controls, handoffs, optional enrichment

- Every `AbuseVector` carries a **recommended control** + estimated exploitability reduction
  (`heel_propose_control`).
- **Lane discipline:** the SSRF url-fetch vector is found AND flagged `handoff_to_appsec`; the pure
  model-jailbreak surface is **handed off** (`handoff_to_model_redteam`), never weaponized or
  counted as a product-abuse finding.
- **Optional classification annotation** (off by default, generic, annotative-only):

  ```
  enrichment OFF: agent_retrieval → classification_impact = None        (cleanly absent)
  enrichment ON : agent_retrieval → classification_impact = {data_classes: [personal_data]}
                                     obligation_impact = {obligations: [access_control,
                                       breach_notification_if_exfiltrated, cross_tenant_isolation,
                                       data_subject_rights]}
  ```

## 5. Safety guards exercised

| guarantee | how it's exercised |
|---|---|
| synthetic-first | every core capability is exercised against planted synthetic targets; real-target adapters are beta and require signed scopes, canaries, and operator-approved limits |
| detection, not weaponization | every finding's PoC is `sample: canary_only`, `contained: true` — no real exfil/exhaustion |
| never generate prohibited content | the content guardrail is verified PRESENT with a **benign canary**; no artifact is ever generated |
| no real-PII harvest | synthetic canary records only |
| plausibility-weighting | the degenerate `legacy_import` is flagged `plausible: false` and demoted, not ranked |
| severity honesty | likelihood × impact with explicit uncertainty; calibration reported (≈0.66–0.78) |
| self-audit | immutable hash-chained `ContainmentLog`, verified each run, attributed to the caller |
| lane discipline | true-vuln → `handoff_to_appsec`; pure-jailbreak → `handoff_to_model_redteam` |

## 6. Honest limits

- Heel is strongest as abuse rehearsal, not an exploit generator, pentest replacement, fraud
  platform, or permission slip for production probing.
- Real-target adapter coverage remains beta. Existing-product runs must stay scoped, canary-only,
  rate-limited, and operator-approved.
- Held-out TEST recall is not near 1.0. The honest improvement path is broader source-anchored
  scenario and semantic vocabulary coverage, measured against frozen or newly held-out targets.
- Economic severity and control simulation are report-layer estimates until a human implements a
  control and verifies it through launch review or regression.

---

## 8. Red-team findings (v1 safety-spine review) — `docs/`-level summary

A 4-agent adversarial workflow attacked the auth gate, prompt-injection surface, §10.2 conduct
guarantees, and backtest honesty. **The #1 claim held**: a prompt-injected MCP/REST caller cannot
create, widen, add a target to, relax the limits of, or run outside a signed scope — every
escalation path fails closed. It found real gaps between *claim* and *implementation*, now fixed:

| red-team finding | severity | fix (verified by test) |
|---|---|---|
| rate/resource limits stored+signed but **never enforced** (ran 20× under a max_requests=1 scope) | HIGH | server-side per-scope request counter enforces `max_requests`; over-limit runs rejected+logged (`test_rate_limit_enforced`) |
| containment log chained with **bare sha256** → re-chainable without a secret | HIGH | each entry **HMAC-signed** with the signing key; key-less re-chaining fails (`test_containment_rechain_without_key_fails`); + seq-contiguity + `run_is_logged` completeness (`test_whole_run_deletion_detected`) |
| backtest is **circular** — coverage/calibration are self-consistency checks, not accuracy | HIGH | re-framed everywhere as a **self-consistency / wiring** metric with an explicit caveat in the data and the docs (`test_backtest_labeled_self_consistency`); added hardened decoys; reachability made depth-based |
| **severity inflation** — hard 0.9/1.0 override for a missing content guardrail | MEDIUM | removed; severity comes from the scenario model with surfaced uncertainty (`test_no_severity_inflation`) |
| signing key **co-located** with the scopes it protects | MEDIUM | `HEEL_SIGNING_KEY` env points the key outside the data dir; threat model documented honestly (DECISIONS D-009); fixed the os.urandom/"stable" docstring mismatch |
| **accountability** — forgeable `clientInfo.name`, no-handshake anonymity, dropped args | MEDIUM | caller marked `mcp:`/`unauthenticated:no-handshake` and documented as self-asserted (auth gate never depends on it); ignored args are logged |
| reachability-weighting recognized **two magic keys** (gameable) | MEDIUM | continuous **depth-based** estimator (prerequisite steps / auth gates discount reachability) |
| FP rate rested on **one firing decoy** | MEDIUM | added hardened decoys sharing property names with vulnerable affordances (safe values) — the precise probes correctly don't fire (earned low FP) |

**Residual (honest):** tail-truncation of the most-recent log entries needs an **external head
anchor** (Phase 3); the backtest's real-target accuracy is still unmeasured (blind-target eval is
the next step); limits enforce `max_requests` (concurrency/backoff are Phase 3). See DECISIONS
D-009…D-014.

---

## 9. Phase 3 — wave 1 (capability breadth against the frozen contracts)

Built against the frozen §6 contracts; the §10 auth gate is unchanged and shared by every surface.

**Opportunistic-human agent class (§3.2, DoD #3).** Persona-modeled gaming of *normal*
affordances, conditioned by a declarative customer-incentive library in `heel/profiles.py`.
The built-ins cover coupon stacking, seat sharing, agency resale, data brokerage, trial farming,
integration overreach, support pressure, marketplace reputation gaming, usage-meter optimization,
AI cost amplification, and agent-wrapper building. Personas gate on motivation tags, sophistication,
patience, risk tolerance, and observable affordance criteria:

| gamed affordance | category | pursued by |
|---|---|---|
| `region_pricing` (region arbitrage) | license_entitlement | `agency_reseller` (requires higher sophistication) |
| `seats` (seat sharing / concurrency) | license_entitlement | `seat_sharer`, with agency-reseller evidence when resale motivation also matches |
| `promo_stacking` (coupon stacking) | license_entitlement | `coupon_stacker` |
| `export_records` + `record_get` | data_harvesting | `data_broker` (export first, enumeration second) |
| `agent_infer_loop` | agent_mcp_surface | `ai_cost_amplifier` |

Both classes run by default. If an adversarial finding already owns an affordance, it stays primary
and persona evidence is attached without changing severity/category/control. Persona-only findings
are ranked by a stable severity/reachability rule. This is why reports can explain not just what is
weak, but which motivated customer archetype would game it. (`TestOpportunisticClass`,
`TestPersonaFindings`; operator guide: `docs/PERSONAS.md`.)

**REST API (§2).** A thin REST surface (`heel/rest.py`, `make rest`) over the **same** `HeelServer`
capability — so the auth gate is identical. There is **no scope-creation route** (`POST /scopes` →
405 + security log); an out-of-allowlist `POST /runs` is rejected `403` exactly as over MCP.
(`TestRestSharesAuthGate`.)

**Control search (§8).** `heel_propose_control` now returns a **ranked set of candidate controls**
by estimated exploitability reduction (the agent's recommendation + a per-category control bank),
sorted. (`TestControlSearch`.)

The suite passed for this wave. Still deferred to later Phase-3/4 waves: full library breadth (many scenarios
per category), the LLM agent control loop, true thousand-agent fan-out, affordance-chaining
discovery, and the UI.

### Phase 3 — wave 2: library depth + LLM loop

**Declarative library (§4, DoD #2).** Scenarios are now pure SPECS interpreted by a single generic
criterion evaluator (`agents.evaluate_criterion`) — so they are **addable without code**, including
from `heel/scenarios_lib/*.json`. The library is **34 scenarios across all 10 categories** (32
declarative in-code + 2 from JSON), with breadth that exceeds the synthetic targets (many scenarios
match no planted affordance — they're there for real targets, and correctly don't fire → no FP
inflation). The honest signals are unchanged (coverage 0.93/0.95, FN `ato_chain`, FP `export_billing`,
discovery `webhook_endpoint`, handoffs). (`TestLibraryAndModel`.)

**LLM control loop (§3, §11).** The adversarial agent's discovery is driven by a swappable `Model`
(`heel/model.py`). The default `StubModel` is deterministic and offline (the demo uses it, no key);
`AnthropicModel` swaps in behind `HEEL_MODEL=anthropic` (+ `ANTHROPIC_API_KEY`), calling the Messages
API via stdlib `urllib` (no SDK). The model only sees OBSERVABLE properties and only PROPOSES
declarative scenario specs (Heel builds the contained PoC), stays in Heel's lane (no weaponization /
prohibited content / jailbreak technique), and falls back to the heuristic on any error or missing
key. (`test_model_stub_is_default_and_anthropic_falls_back_without_key`.)

The suite passed for this wave.

### Phase 3 — wave 3: blind-target evaluation (the honest detection metric) + chaining + fan-out

The red-team's deepest finding was that the synthetic coverage is a **self-consistency** metric, not
detection accuracy. This wave fixes it with a genuinely independent measurement.

**Blind-target evaluation (`heel/blind.py`, `heel/blind_eval.py`).** Procedurally-generated targets
whose planted weaknesses use ENCODINGS authored independently of the seed probes — only some match a
scenario; the rest are synonym vocabularies the library doesn't key off; decoys share property names
with safe values. The library is run against many such targets concurrently (the §7 **fan-out**, a
thread pool) and a real recall/precision DISTRIBUTION is aggregated:

| metric | value |
|---|---|
| **real recall** | **0.25** (95% CI [0.19, 0.31]) — vs the 0.93+ self-consistency coverage |
| real precision | 0.78 |
| false-positive rate | 0.19 |
| found / planted | 72 / 287 (215 missed — unanticipated encodings) |
| category-10 clean on blind non-AI targets | **23/23** (verified, not structural) |

This is the **honest real-target estimate**: Heel catches what its library anticipates, which on
blind targets is ~a quarter of plants. **Recall rises as the library's encoding breadth grows** —
that is the honest improvement axis, and the metric can't be gamed by writing probes against known
plants. (`TestBlindEvaluation`.)

**Affordance-chaining (`heel/chaining.py`).** Multi-step abuse the single-affordance classes miss —
e.g. ATO = weak recovery + non-rotated session. This closes the synthetic `ato_chain` FN with a real
capability; the honest sub-1.0 signal now lives in the blind eval. Compound chain findings over
genuinely-vulnerable affordances are reported separately, not counted as false positives.
(`TestChaining`.)

The suite passed for this wave.

### Phase 3 — wave 3b: the blind eval, red-team-hardened

A second red-team attacked the blind eval itself and found it was *partly* a re-parameterized knob.
Fixes (DECISIONS D-024):
- **Recall is reported against the MEASURED encoding-overlap** (the independent variable that bounds
  it) and labelled a **stated lower bound** — not emergent detection skill. Measured overlap 0.33;
  real recall 0.25 ≈ overlap minus reachability/category slack. It rises only as the library covers
  more of the encoding vocabulary — uncheatable by writing probes against known plants. A defensible
  external claim still needs independently-authored / held-out scenarios (stated honestly).
- **Wilson score interval** on the pooled found/planted proportion (the right binomial model),
  replacing population-stdev normal-z on a mean-of-ratios.
- **Per-probe false-positive attribution**: all 44 FPs come from one over-broad probe
  (`sc.export.overbroad`) — surfaced, so precision (0.62) isn't silently carried by a single rule.
  Added boundary decoys exercising that failure mode.
- **Chaining FP soundness**: the blanket `chain:`-prefix FP exclusion was unsound (it could launder
  a false positive over a hardened decoy). Now a chain is a legitimate compound ONLY if all its legs
  are genuinely vulnerable; a chain touching a decoy is counted as a real false positive
  (`test_chain_over_decoy_counts_as_false_positive`). Compound severity is tied to reachability.
- **Regression guard**: a test asserts no synonym encoding leaks into detection via any seed
  criterion (with the kind gate) or the discovery heuristic. Fan-out asserts synthetic-only targets
  and is described honestly (GIL-bound thread pool, not literal 1000×).

The suite passed for this wave.

### Phase 3 — wave 4: held-out evaluation (independent authorship) + semantic generalization

The final integrity step: even the blind eval's encodings were written by Heel's author, so the
encoding-overlap (hence recall) was ultimately a designer choice (red-team finding). This wave
removes that last lever.

**Held-out targets, independently authored.** A multi-agent workflow spawned 8 LLM agents that each
authored a synthetic product with planted abuse weaknesses — given only the abuse taxonomy + an
output schema, and **blind to Heel's scenario/semantic vocabulary** (provenance:
`docs/HELDOUT_PROVENANCE.md`). They invented their own property names
(`tenant_scope_check: disabled`, `private_ip_range_block: absent`, `export_audit_event: not_emitted`,
…). Frozen in `heel/heldout/targets.json`: 8 products, 97 planted weaknesses, all 10 categories.

**Semantic generalization (`heel/semantic.py`).** Exact property==value criteria don't generalize to
an unseen vocabulary. A scenario can instead declare a SEMANTIC signal — a weakness family recognized
by topic keywords in the property key + permissive indicators in the value (topic+permissive keeps
precision). This is the honest improvement axis: widen real-vocabulary coverage, don't write probes
against known plants.

**The honest real-target ceiling** (`heel/heldout_eval.py`, `make demo`):

| | recall | precision |
|---|---|---|
| exact-match only | **0.26** (25/97) — barely generalizes | — |
| **with semantic** | **0.57** (Wilson CI [0.47, 0.66]) | **0.95** |

`recall_by_category` surfaces where Heel is strong (data-harvesting 10/15, function-abuse 10/13) vs
weak (unintended-endpoints 7/15, license-entitlement 7/14). Neither number is near 1.0 — this is the
honest detection ceiling on independently-authored abuse, and the UI's "Held-out (real)" screen shows
the exact→semantic jump. The suite passed for this wave.

**The three honesty levels, in one place:** self-consistency coverage ~1.0 (wiring) → blind lower
bound ~0.25 (independent encodings, author-controlled overlap) → held-out semantic ~0.57 at 0.95
precision (independent authorship, no author control). Each strips a layer of circularity.

### Phase 3 — wave 5: dev/test discipline + broadened semantic coverage

To improve recall honestly (not by overfitting), the held-out evaluation now uses a proper
**dev/test split**. The semantic catalog (`heel/semantic.py`, expanded from 12 to ~34 signal
families) was tuned on the **DEV** set (the original 8 products). A **larger TEST set — 14 products,
199 weaknesses, authored by a fresh independent LLM swarm and frozen WITHOUT inspection** — gives the
unbiased number.

| split | exact recall | semantic recall | precision |
|---|---|---|---|
| DEV (tuned on, 97 weaknesses) | 0.26 | **0.73** | 0.96 |
| **TEST (frozen, 199 weaknesses)** | 0.085 | **0.38** (Wilson CI [0.31, 0.45]) | **0.96** |

The **dev→test gap (0.73 → 0.38) is the overfitting gap, shown honestly** — the unbiased
generalization is 0.38, and **precision holds at 0.96 on entirely unseen vocabulary** (the semantic
matcher's topic+permissive gating doesn't over-fire). Semantic generalization still beats exact
matching ~4.4× on unseen targets (0.085 → 0.38). TEST `recall_by_category` exposes the real weak
spots (agent/MCP 4/18, content-policy 1/11, unintended-endpoints 9/27) — the honest backlog. A key
precision lesson: bare boolean `true`/`enabled` were removed from the permissive vocabulary because
polarity is property-dependent (`audit_logged:true` is good, `acts_on_content:true` is bad).

The suite passed for this wave. The four honesty levels now coexist: self-consistency ~1.0 → blind ~0.25 →
held-out DEV ~0.73 (tuned) → **held-out TEST ~0.38 (unbiased) @ 0.96 precision**.

### Phase 3 — wave 5b: held-out methodology red-team fixes

A 3-agent red-team audited the dev/test held-out metric (verdict: HONEST, with real fixes). All applied:

- **CRITICAL — localization vs attribution.** The score credited a true positive on affordance match
  alone, so ~29% of TEST localizations carried the WRONG category. Both are now reported:
  **localization recall 0.38**, the stricter **attribution recall 0.27** (right affordance AND
  category). `heel/backtest.py` adds `attribution_coverage`; the gap is shown, not hidden.
- **HIGH — clustered CI.** The iid Wilson treated 199 weaknesses nested in 14 targets as independent
  (~30–45% too narrow). Replaced with a **target-level cluster bootstrap**: localization CI [0.29,
  0.49], attribution [0.20, 0.35], precision [0.94, 1.0].
- **HIGH — substring collisions.** `orm`⊂`format`, `ttl`⊂`throttle`, `allowed`⊂`disallowed` etc. fixed
  by **word-boundary token matching** (`heel/semantic.py`); ambiguous `never`/`fixed`/bare `true`
  removed. TEST precision rose to **0.97**.
- **MEDIUM — researcher degrees of freedom.** `test_targets.json` is **content-hashed** (reported in
  the eval); the reachability≥0.25 gate is disclosed as a no-op (0/199 filtered); per-category recall
  is labelled descriptive-only (denominators too small for strong/weak claims).

The honest TEST picture: **localization 0.38 (CI [0.29,0.49]) · attribution 0.27 (CI [0.20,0.35]) ·
precision 0.97** on 199 independently-authored weaknesses, sha `3dba2486…`. Specificity-ranked
dedup (D-031) then lifted attribution to **0.31** (mis-categorization 29%→18%) — developed on dev,
measured once on the frozen test. The suite passed for this wave.

### Phase 3 — wave 6: external research library integration (the recall lever)

Integrated a source-anchored external research deliverable — **45 business-logic abuse scenarios
across all 10 categories** (declarative JSON, `scenarios_lib/research_owasp.json`) plus a semantic
vocabulary expansion harvested from primary sources (OWASP API/OAT/WSTG/LLM Top-10, the MCP
2025-06-18 schema, and Stripe/Kong/Microsoft/Auth0 config docs). The research was authored from those
sources **independently of, and with no access to, the held-out test set**, so measuring its lift
there is a fair, unbiased test.

| | before | after |
|---|---|---|
| library size | 67 | **119** scenarios, 10 categories |
| held-out **TEST** localization recall | 0.38 | **0.50** (cluster-CI [0.42, 0.59]) |
| held-out **TEST** attribution recall | 0.31 | **0.33** |
| held-out **TEST** precision | 0.97 | **0.98** |
| blind real recall (encoding-overlap) | 0.25 | 0.43 |

A genuine **+12pp localization recall lift on the frozen, independently-authored test set, at
unchanged-to-better precision** — the honest recall lever the dev/test discipline was built to
measure. Integration preserved the precision discipline: boolean-true-is-bad fields stayed as exact
scenarios (not semantic topics); over-broad `{"not":{"prop_exists":X}}` absence-checks were paired
with `guard_absent` (fixing a real precision liability on hardened affordances while keeping recall);
a `prop_exists` operator was added to the criterion evaluator. Provenance + sources:
[docs/RESEARCH_LIBRARY.md](docs/RESEARCH_LIBRARY.md). The suite passed for this wave.
