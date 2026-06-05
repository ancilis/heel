# HEEL — Red-team findings: blind-eval / chaining / fan-out

3-agent review of the honesty-metric work. The blind eval was found to be structurally less
circular than the self-consistency backtest (synonyms genuinely don't leak), but recall was a
re-parameterized knob, precision rested on one probe, and the chaining FP exclusion was unsound.
All fixed — see EVAL §wave3b / DECISIONS D-024, D-022.

## measurement-skeptic / red-team auditor of the HEEL blind-eval detection metric

**Verdict:** PARTIALLY RIGGED — independent ENCODINGS but a DIALED recall. The metric removes the seed/plant co-authorship circularity (synonyms are real blind spots, no synonym leaks into detection), so it is a strictly better number than the 0.93 self-consistency coverage. But recall ≈ 0.25 is a re-parameterized hand-tune, not a discovered property: it equals the matchable-encoding fraction (1/3, minus reachability/category-mix), which the author controls by choosing how many encodings per weakness match a seed. Precision is dominated by one decoy and one over-broad probe. Not yet a defensible third-party detection metric; it is an honest-DISTRIBUTION shaped backtest, and should be labeled a stated LOWER BOUND with held-out/independently-authored scenarios before any external claim.

### [HIGH] Recall is mechanically the matchable-encoding fraction, not an emergent detection property (the core 'still rigged' issue)

**Evidence:** blind.py:27-69 defines each weakness with exactly 3 encodings where only the FIRST matches a seed scenario; blind.py:92 picks one uniformly at random (rng.choice(encodings)). I traced detectability per encoding: every weakness is DETECT on enc#0 and BLIND on enc#1/#2 (the synonyms). Running the real pipeline (run_adversarial+run_chaining+score_target) over 40 targets: TP=72, FN=215, and the count of planted vectors that happen to carry a library-matchable encoding = 72/287 = 0.251 — identical to recall=0.251 with ZERO slack (no reachability or category loss eats into it). blind_eval.blind_eval(40) returns real_recall_mean=0.248, CI [0.19,0.306]. So recall is fixed by the design choice '1 of 3 encodings matches', i.e. ~1/3. Whoever sets matchable-encodings-per-weakness sets recall. blind_eval.py:70-72 even concedes 'Recall rises as the library's encoding breadth grows' — i.e. the number is a tuning knob.

**Recommendation:** Stop presenting 0.25 as a measured detection rate. Either (a) randomize the matchable fraction per weakness and REPORT it as the independent variable, plotting recall vs. encoding-overlap so the dependence is explicit, or (b) have a SEPARATE author (or a held-out scenario set never shown to the plant generator) write the encodings, so the matchable fraction is genuinely unknown to the library author. Until then, label the number 'recall at 1-of-3 designer-chosen encoding overlap', not 'real recall ~0.25'.

### [HIGH] Precision 0.78 is an artifact of ONE decoy tripping ONE over-broad probe; 5 of 6 decoys are inert

**Evidence:** blind.py:72-79 defines 6 DECOYS. I fired all seed scenarios against each: only export/{route:/api/billing/export} fires (sc.export.overbroad, the substring 'export' probe at scenarios.py:46-47). The other 5 (record tenant_check:enforced, meter reset_window:server, admin_action audit_logged:True, flag gated_by:server, agent_tool granted_scope==intended_scope) NEVER fire — they are FP bait that exercises no failure mode. Across 40 targets every false positive (22/22) is the same billing-export decoy. So precision 0.785 / fp_rate 0.187 measures exactly one probe's one over-broad substring rule, not a precision distribution. The 'decoys share property names with safe values' design (blind.py:13) mostly tests that probes correctly require the UNSAFE value — which they do — so those decoys can never produce a FP and add nothing to precision.

**Recommendation:** Add decoys that genuinely sit on the boundary of each probe's failure mode (e.g. an export with a legitimate entitlement guard but a tempting route; an agent_tool with granted_scope='all' but intended_scope='all' to test prop_neq; a near-miss meter). Report per-probe FP attribution so precision can't be carried by a single rule. As-is, precision is a 1-probe artifact, not a metric.

### [MEDIUM] CI is computed with population stdev and a normal z on a mean-of-ratios — understated and mis-modeled

**Evidence:** blind_eval.py:46 uses statistics.pstdev(xs)/math.sqrt(len(xs)) — population stdev, not sample stdev. For the sample sizes here that narrows the SEM (and thus the CI half-width) by a factor sqrt((n-1)/n); I measured ~5% narrower on a representative vector. Two further issues: (i) blind_eval.py:47 uses 1.96 (normal z) rather than a t-quantile, slightly too narrow at n=40 and more so for precision where only targets with tp+fp>0 contribute (n<40); (ii) each per-target recall is a ratio with a different denominator (reachable_planted varies 5-9), but the CI treats the 40 ratios as i.i.d. scalars — a mean-of-ratios CI that ignores the denominators and the binomial structure. The aggregate total_found/total_planted (72/287) would warrant a proper proportion CI (Wilson), which is the more defensible statistic here.

**Recommendation:** Use statistics.stdev (sample) or, better, report a Wilson score interval on the pooled 72/287 proportion. Use a t-quantile (or bootstrap over targets) given n=40. Report precision CI only with its actual contributing n. These are small numeric corrections but the current CI is both understated and the wrong model for a proportion.

### [LOW] ssrf weakness: detecting encoding routes to appsec handoff but is still counted as a finding — minor accounting ambiguity

**Evidence:** blind.py:65-68 ssrf enc#0 is agent_tool/{allowlist:missing, handoff:appsec}; scenarios.py:63-65 sc.func.ssrf has handoff='appsec'. In agents.run_adversarial:111-115 only handoff=='model_redteam' is diverted to a non-finding; 'appsec' handoffs DO become AbuseVectors and count as TP. That is internally consistent, but it means a 'true-vuln, hand to appsec' item is scored as a product-abuse detection in the recall numerator. backtest.py:13 says handoffs are 'reported but not scored as product-abuse findings', which conflicts with appsec vectors counting as TP.

**Recommendation:** Decide whether appsec-handoff vectors count toward product-abuse recall; if not, exclude them from TP to match the backtest docstring. Either way the effect is tiny (ssrf is 1 of 10 weaknesses, agent-only), but it is an inconsistency a third party would flag.

### [INFO] Synonym encodings do NOT leak into detection — this part is genuinely clean

**Evidence:** I checked all 20 synonym encodings (enc#1/#2 of all 10 weaknesses) against (a) every seed success_criterion via agents.evaluate_criterion and (b) the heuristic substring keys agents.py:133-134 (protection/check/filter/isolation/guard/logged/allowlist/limit + missing values). Zero synonyms match any seed criterion and zero contain a hint substring with a missing value. The heuristic only fires on enc#0 props that ALSO match a seed (tenant_check, audit_logged, tenant_filter, allowlist) — so the heuristic is redundant with the seed match, not an independent leak. Examples of true blind spots: record/{tenant_scope:shared}, record/{isolation:off} (note: 'isolation' value 'off' is not in _MISSING_VALUES, so even this near-miss does not leak), meter/{reset:user_settable}, flag/{enforcement:clientside}, agent_tool/{rag_scope:global}, agent_tool/{egress:open}.

**Recommendation:** No change needed for the encoding-independence claim itself; it holds. Document this leak-check as a regression test (assert no synonym matches any seed or heuristic) so future scenario additions cannot silently turn a 'blind spot' into a covered one and inflate recall.

### [INFO] What would make this defensible: held-out authorship + stated lower bound + breadth-curve

**Evidence:** The pipeline is sound mechanically (blind_eval.py:28-41 runs the real library: run_adversarial over all_seed_scenarios + run_chaining + score_target; category-10 cleanly 0 on 23/23 non-AI targets, confirmed). The gap is independence, not wiring. Three concrete fixes: (1) AUTHORSHIP SPLIT — generate encodings from a source the scenario author does not control (a held-out scenarios_lib loaded via scenarios.py:123 load_json_scenarios, authored by a different party, with the plant generator forbidden from seeing it), so the matchable fraction is unknown a priori. (2) STATED LOWER BOUND — frame the result as 'library detects >= X% of planted weaknesses under encoding distribution D', with D published, since recall is monotone in encoding breadth (blind_eval.py:70-72). (3) BREADTH CURVE — sweep matchable-encodings-per-weakness from 1/3 to 3/3 and plot recall, turning the hidden knob into a reported axis. Also add boundary decoys (per finding #3) and fix the CI (per finding #4).

**Recommendation:** Ship the metric only with: independently-authored held-out encodings, a Wilson CI on pooled 72/287, a published encoding distribution, and the recall-vs-breadth curve. Then 0.25 becomes a defensible lower bound rather than a re-parameterized hand-tune.

## Red-team reviewer (HEEL chaining + backtest soundness)

**Verdict:** Chaining is a real capability and honesty is preserved in the blind eval, BUT the backtest's blanket "chain:"-prefix FP exclusion (backtest.py:64-66) is unsound and exploitable: a chain over hardened decoys is laundered into a zero-FP "compound discovery," and this blind spot propagates into the headline blind-eval precision. Fix required before the FP/precision numbers can be trusted.

### [HIGH] Blanket 'chain:'-prefix FP exclusion launders false positives over hardened decoys
*Location:* `/Users/hellohelloalbus/heel/heel/backtest.py:62-66`

**Evidence:** fp is computed as `[f for f in plausible if f.affordance_id not in planted_affordances and not f.affordance_id.startswith("chain:")]` — the chain: prefix is excluded UNCONDITIONALLY, with no verification that the chain's legs are planted/vulnerable. I built a target of two pure decoys (Affordance(... decoy=True) record with tenant_check=missing + ungated export decoy); run_chaining emitted a plausible high-severity 'chain:dec_record+dec_export' finding, and score_target reported false_positives=0, false_positive_affordances=[], compound_chain_findings=1, fp_rate=0.0. A genuine false alarm was scored as a legitimate compound discovery. The comment at backtest.py:62-63 asserts a chain is 'over genuinely-vulnerable affordances' but the code never checks that.

**Recommendation:** Do not exclude chains by prefix. Instead, count a chain as a TP only if its constituent legs are all planted-vulnerable (members ⊆ planted_affordances / not decoys); count it as an FP if any leg is a decoy/hardened affordance. Concretely, decompose affordance_id after 'chain:' (or carry the matched leg ids on the AbuseVector) and validate each leg against planted_affordances and aff.decoy before deciding TP vs FP. The chaining code already has the leg ids at chaining.py:43 — propagate them so the scorer can audit them.

### [HIGH] Compound-FP blindness propagates into the headline blind-eval precision
*Location:* `/Users/hellohelloalbus/heel/heel/blind_eval.py:36-39`

**Evidence:** _eval_one sets `tp, fp = sc["true_positives"], sc["false_positives"]` and `precision = tp/(tp+fp)`. Since sc['false_positives'] comes from score_target's chain-excluding fp set (backtest.py:65-66), any false-positive chain is invisible to both fp_rate and the reported real_precision_mean (~0.78). The precision CI therefore cannot detect compound false alarms by construction. On the current 40-seed blind corpus only 1 chain fires and not over a non-planted leg, so the defect is latent there — but it is structural, and I reproduced it directly with a decoy pair.

**Recommendation:** After fixing backtest FP accounting (finding 1), the blind-eval precision will automatically include compound FPs. Additionally add a blind-eval assertion/metric counting plausible chain findings whose legs are not all planted, so compound precision is explicitly tracked rather than silently zero.

### [MEDIUM] Compound severity is static and decoupled from reachability — label stays 'high' when implausible
*Location:* `/Users/hellohelloalbus/heel/heel/chaining.py:46-53`

**Evidence:** like, imp = pat['severity'] reads the hardcoded (0.7,0.8) tuple from the pattern definition (chaining.py:17,22) and emits Severity(like, imp, 0.25) regardless of the matched legs' true_severity. reachability_score is correctly discounted (reach=min(...)*0.8, chaining.py:44) and plausible=reach>=0.25 (chaining.py:52), but the Severity object is independent: I observed a degenerate chain at reach=0.054 plausible=False still reporting severity.label='high' (Severity.label, contracts.py:103-105, keys only on likelihood*impact). A consumer sorting/triaging by severity.label could surface an unreachable compound vector as high.

**Recommendation:** Derive compound severity from the matched legs (e.g., max/aggregate of leg true/assigned severities) rather than a static tuple, and reflect implausibility in the surfaced severity (demote label when plausible is False, or expose an effective_severity = severity*reachability), consistent with the contracts.py:16-17 promise that 'degenerate findings are flagged, never ranked.'

### [LOW] exfil_chain double-counts already-found single-affordance vulns and inflates the precision denominator
*Location:* `/Users/hellohelloalbus/heel/heel/chaining.py:22-26`

**Evidence:** On synthetic-saas the exfil_chain fires as 'chain:record_get+export_records', but record_get (cross_tenant_idor) and export_records (export_no_entitlement_check) are ALREADY reported as TPs by the single-affordance probes (sc.record.tenant, sc.export.entitlement). The chain adds a redundant plausible finding (n_plausible went to 13) that is exempt from the FP numerator (backtest.py:65-66) but still counts in the plausible denominator used elsewhere — net effect: it can only dilute fp_rate and pad the compound_chain_findings count without representing new ground truth.

**Recommendation:** Either suppress a compound finding whose legs are each already independently reported (only emit when the chain crosses a NON-vulnerable/guarded leg, as ato_chain legitimately does via session_mgmt at targets.py:78-79), or mark such redundant compounds so they are not counted as distinct discoveries.

### [INFO] ato_chain mapping (maps_to) sidesteps the chain: prefix, so the legitimate compound is itself unaudited as a chain
*Location:* `/Users/hellohelloalbus/heel/heel/chaining.py:43`

**Evidence:** aid = pat['maps_to'] or ('chain:' + ...) — because ato_chain sets maps_to='ato_chain' (chaining.py:21), its finding gets affordance_id='ato_chain' (no 'chain:' prefix), matching the planted vector and scoring as a normal TP (confirmed: coverage no longer lists ato_chain in missed). This is the intended/legitimate path, but note the consequence: the chain: prefix is the ONLY signal the backtest uses to identify compounds, and the one genuinely-good compound bypasses it while spurious compounds (finding 1) carry it. The prefix is thus a poor discriminator for the FP decision.

**Recommendation:** Identify compound findings by a structural flag on AbuseVector (e.g., reproduction['strategy']=='affordance_chain', already set at chaining.py:50) plus validated leg membership, rather than by string-prefixing the affordance_id, which is both spoofable and inconsistently applied.

## Security and concurrency reviewer (HEEL blind_eval fan-out)

**Verdict:** blind_eval is deterministic and race-free (verified: identical across runs and across 1/8/16 workers; per-seed local RNG, read-only module globals, no shared Store/connection). It intentionally runs WITHOUT scope/Store/containment because targets are purely synthetic and in-memory — acceptable for an internal detection-accuracy eval, but the unscoped/unlogged path is structurally reusable and should be guarded against non-synthetic targets. The 'thousand-agent fan-out' label is dishonest: it is 40 targets, 8 GIL-bound threads, deterministic stub, no real parallelism — and the real-LLM concerns in (3) are currently moot because the fan-out hardcodes StubModel and never consults HEEL_MODEL.

### [MEDIUM] 'Thousand-agent fan-out' is overstated: 40 targets, GIL-bound threads, deterministic stub
*Location:* `/Users/hellohelloalbus/heel/heel/blind_eval.py`

**Evidence:** blind_eval.py:7 labels it 'the §7 thousand-agent FAN-OUT'; blind_eval.py:50 defines def blind_eval(n: int = 40, workers: int = 8); blind_eval.py:51 ThreadPoolExecutor(max_workers=workers); _eval_one runs a StubModel (blind_eval.py:30) doing pure-Python dict comparisons with no I/O. orchestrator.py:6 itself says 'the true thousand-agent fan-out are Phase 3.' Under the CPython GIL, CPU-bound stub work across threads serializes, so there is no real parallelism and nowhere near a thousand agents.

**Recommendation:** Rename/reword to an honest description, e.g. '40 synthetic targets scored concurrently via a thread pool (GIL-bound, deterministic stub)'. Reserve 'fan-out'/'thousand-agent' for the network-bound real-LLM path, and only once it is actually wired and measured.

### [MEDIUM] Fan-out runs agent with no scope, no Store, and a _noop containment log (no audit trail)
*Location:* `/Users/hellohelloalbus/heel/heel/blind_eval.py`

**Evidence:** _noop at blind_eval.py:24 is passed as the log to run_adversarial (blind_eval.py:30) and run_chaining (blind_eval.py:32), discarding every probe/finding/handoff/chain event. The scoped path mcp_server.heel_run (scope.verify, target_in_scope, max_requests at mcp_server.py:94-112) + orchestrator.run_abuse (ContainmentLog at orchestrator.py:33) is entirely bypassed. run_adversarial/run_chaining accept any object with .affordances, so nothing structurally prevents this unscoped, unlogged path from being pointed at a non-synthetic target.

**Recommendation:** Acceptable for the internal eval because every target is an in-memory SyntheticTarget from generate_blind_target (no network, no real system). Harden by asserting isinstance(t, SyntheticTarget) (or a synthetic-only flag) at the top of _eval_one, and add a one-line docstring note that this path is deliberately unscoped/unlogged and synthetic-only, so a future caller cannot repurpose it against a real target.

### [LOW] Real-LLM fan-out concerns are latent: HEEL_MODEL=anthropic is bypassed and the LLM path is unaudited
*Location:* `/Users/hellohelloalbus/heel/heel/blind_eval.py`

**Evidence:** _eval_one hardcodes model=StubModel() (blind_eval.py:30), so get_model()/AnthropicModel (model.py:110-113) never runs in the fan-out and HEEL_MODEL is ignored here. If swapped to get_model(): no backoff/rate-limit (scope limits are bypassed per the unscoped path); urllib.request.urlopen(timeout=30) (model.py:76) blocks one worker thread per call; 429/errors silently fall back to the heuristic (model.py:62-64), inflating apparent recall; the response is parsed by text.find('{')/rfind('}') with no schema validation (model.py:79); lane discipline is prompt-only (model.py:23-31) with no post-hoc enforcement; and because the log is _noop, model_error/model_fallback/discovered_scenario_llm events are discarded so the parallel LLM calls cannot be audited.

**Recommendation:** Either keep the fan-out stub-only and say so explicitly, or, when enabling the real model, (a) thread the scope's rate/concurrency limits and a real backoff through the pool, (b) cap workers and add per-call retry/jitter for 429s, (c) validate the model's returned scenarios against a schema before materializing, and (d) replace _noop with a real (even in-memory) logger so the LLM control loop is auditable.

### [INFO] Determinism and race-freedom confirmed (no actionable defect)
*Location:* `/Users/hellohelloalbus/heel/heel/blind.py`

**Evidence:** Only RNG is the per-target local random.Random(f"blind:{seed}") at blind.py:83 (never the global random module). Module globals touched by the fan-out are read-only constants (scenarios.py:33,157; agents.py:133-134; model.py:23). No Store/sqlite connection is opened in the fan-out (store.py Store uses check_same_thread=False but is never instantiated here). ex.map preserves input order, so aggregation/CI is order-stable. Empirically verified: blind_eval(40,8) gave byte-identical results on repeat runs (recall 0.248, CI [0.19,0.306], precision 0.785), and results were invariant across workers=1/8/16 (total_found=72, total_missed=215, total_planted=287).

**Recommendation:** No change required. Optionally add a regression test asserting blind_eval(n, workers=1) == blind_eval(n, workers=8) to lock in determinism and worker-count invariance against future edits (e.g., if a shared Store/log is ever introduced).
