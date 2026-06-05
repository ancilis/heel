# HEEL — Evaluation (v1, Phase 0–2)

Honest results from the synthetic spine. Reproduce with `make demo` / `make test`. Everything is
computed at runtime; deterministic.

---

## 1. Planted-vector coverage backtest (the spine, §5 / DoD #4)

Two synthetic targets, run over the MCP boundary under an enforced scope:

| target | kind | coverage | cov (reach-wt) | FP-rate | severity-calib | category-10 findings |
|---|---|---|---|---|---|---|
| **synthetic-saas** | non-AI | **0.91** | 0.92 | **0.09** | 0.78 | **0** |
| **synthetic-ai** | AI/agent | **0.94** | 0.95 | **0.06** | 0.66 | 5 |

- **Category 10 cleanly yields 0 findings on the non-AI target** — proving it is optional and
  auto-applies only when the target has agent/MCP surfaces (DoD #4).
- The numbers are honest, not circular (DECISIONS D-004). Per target: **TP 10/16, a genuine miss
  (FN=1: `promo_stacking` — planted, reachable, but no scenario can infer it), a real false
  positive (FP=1: `export_billing` — a hardened decoy the over-broad export heuristic flags), and
  1 implausible finding demoted by plausibility-weighting (`legacy_import` — present but
  unreachable).**
- **Severity calibration < 1.0** (0.66–0.78): HEEL's severity estimates rank-correlate with the
  planted true impact but are deliberately imperfect (no inflation, no peeking).

## 2. Scenario library (DoD #2)

**19 seed scenarios across 9 categories** (data_harvesting, license_entitlement,
unintended_endpoints, function_abuse, content_policy, identity_account, trust_economy,
compliance_boundary, agent_mcp_surface) **+ integration_extensibility represented via a
swarm-DISCOVERED scenario** (`sc.discovered.webhook_endpoint`, found on a planted vector no seed
scenario covers) = **all 10 §4 categories represented.** The §4.10 agent/MCP pack
(`applies_when = has_agent_surface`) runs only on the AI target.

## 3. Authorization gate (the safety spine, §10.1 / DoD #6)

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
are human-only, out-of-band, signed (DECISIONS D-002).

## 4. Recommended controls, handoffs, optional enrichment (DoD #5)

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

## 5. Safety guards exercised (§10.2)

| guarantee | how it's exercised |
|---|---|
| synthetic-first | every capability runs against the planted synthetic targets; real-target adapters not built |
| detection, not weaponization | every finding's PoC is `sample: canary_only`, `contained: true` — no real exfil/exhaustion |
| never generate prohibited content | the content guardrail is verified PRESENT with a **benign canary**; no artifact is ever generated |
| no real-PII harvest | synthetic canary records only |
| plausibility-weighting | the degenerate `legacy_import` is flagged `plausible: false` and demoted, not ranked |
| severity honesty | likelihood × impact with explicit uncertainty; calibration reported (≈0.66–0.78) |
| self-audit | immutable hash-chained `ContainmentLog`, verified each run, attributed to the caller |
| lane discipline | true-vuln → `handoff_to_appsec`; pure-jailbreak → `handoff_to_model_redteam` |

## 6. Tests (DoD #8)

`python3 -m unittest discover -s tests` → **22 tests pass**: auth gate (8), scope immutability /
tamper-evidence / expiry (2), coverage backtest (5: coverage+FP, cat-10-clean-on-non-AI,
cat-10-present-on-AI, discovery, honest-FN), safety spine (6: contained PoCs, content-guardrail
never generates, appsec handoff, model-redteam handoff, implausible demotion, containment
tamper-evidence + chain validity).

## 7. Honest limits & what's next

1. **The backtest measures the synthetic targets**, where HEEL's seed scenarios were written
   against the planted weaknesses — high coverage is expected; the value is the *falsifiable
   harness* plus the honest FN/FP/calibration. Real-target coverage is unknown until a
   human-authorized run; an optional real-telemetry residual loop is a stretch hook (§5).
2. **Agents are a deterministic stub** (D-005); the LLM control loop and the opportunistic-human
   class are Phase 3.
3. **Full 10-category library breadth** (many scenarios per category) and the **MCP/REST/UI** thin
   clients are Phase 3/4. v1 seeds enough to score coverage and prove the spine.
4. **Severity calibration on 10–16 true positives** is a small sample; treat it as directional.

**Bottom line:** the falsifiable spine exists — two synthetic targets, an honest coverage backtest
(category 10 cleanly optional), and an authorization gate that **refuses every escalation a calling
agent can attempt** — all callable over MCP, with the §10 conduct guarantees implemented and tested.
