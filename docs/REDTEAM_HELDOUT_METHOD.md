# HEEL — Red-team findings: dev/test held-out methodology (wave 5b)

3-agent audit of the dev/test split + broadened semantic matcher. Verdict: HONEST with real fixes.
All applied — see EVAL §wave5b / DECISIONS D-029,D-030.

## auditor of HEEL held-out dev/test split honesty

**Verdict:** HONEST with one caveat. The 0.377 @ 0.962 TEST result is a legitimate, reproducible, unbiased generalization number; precision is earned against real tempting decoys; the catalog is not fitted to the glimpsed bazaarloop product; and DEV is framed as context, not used to inflate the headline. The single caveat: the 'authored blind to the probe vocabulary' provenance claim overstates independence at the matching layer — 73% of the topic tokens that actually fire on TEST also appear in DEV keys, so the firing vocabulary is more DEV-correlated than the prose implies (though 70% of catches still land on TEST-novel keys).

### [MEDIUM] TEST set is materially independent at the key level but the catalog's FIRING vocabulary overlaps DEV by 73%
*Location:* `/Users/hellohelloalbus/heel/heel/semantic.py:132 and /Users/hellohelloalbus/heel/heel/heldout_eval.py:5`

**Evidence:** Exact full-property-key overlap DEV∩TEST is 121/866 = 14.0% of TEST keys. But semantic.semantic_match() matches via substring topic tokens, not full keys (heel/semantic.py:132-140). Of the catalog topic tokens that actually appear in TEST property keys (93), 68 (73%) also appear in DEV keys — i.e. most of the firing vocabulary was validated against the tuned-on split. Counter-evidence that keeps it honest: of the 71 TEST affordances the catalog catches, 50 (70%) are caught via a property key that is NOVEL to TEST (never literally present in DEV), so real synonym generalization is occurring. Only 25 firing topics are TEST-novel (e.g. webhook, oauth, otp, recover, wallet, jwt, undocumented).

**Recommendation:** Soften the provenance prose in heldout_eval.py:5-8 and the docstring claim 'genuinely held out' to acknowledge token-level overlap: e.g. 'TEST property KEYS are 86% novel, but ~73% of the topic tokens that fire were also observed in DEV.' Report the 73% topic-overlap figure alongside the 0.38 recall so the 'unbiased' claim is fully auditable rather than asserted.

### [INFO] Catalog is NOT fitted to the glimpsed bazaarloop product (the two bazaarloop-only tokens are dead)
*Location:* `/Users/hellohelloalbus/heel/heel/semantic.py:48`

**Evidence:** Exactly two catalog topic tokens fire only on bazaarloop and nowhere in DEV or the other 13 TEST products: 'sequential_id' (semantic.py:48, enumeration) and 'signature_check' (semantic.py:92, webhook_replay). Both are DEAD: across all of DEV+TEST neither ever produces an actual topic+permissive firing, because bazaarloop's values are hardened — sequential_ids='...listing_id is monotonic...' and inbound_signature_check='...HMAC not actually validated...' both return _value_permissive=False. No catalog signal/topic looks suspiciously bespoke to bazaarloop's properties.

**Recommendation:** No action required for honesty. Optionally prune the two dead tokens (sequential_id, signature_check) since they catch nothing, or add a positive bazaarloop-blindness assertion to the provenance doc to preempt the concern.

### [INFO] Precision 0.962 on TEST is earned: 33/42 decoys are tempting and 3 genuinely trip the catalog
*Location:* `/Users/hellohelloalbus/heel/heel/backtest.py:65`

**Evidence:** TEST has 42 decoys (3 per product, 17% of 241 affordances). Of these, 33 are 'tempting' — their property KEY carries a catalog topic token, so they sit in a probe's blast radius and only the hardened VALUE saves them (18 are explicitly value-hardened, e.g. veloxis 'graphql-introspection-hardened', vaultdrop 'decoy-cross-tenant-acl-strict'). The decoys are not inert: 3 actually trip a probe and become the 3 false positives that pull precision below 1.0 — bazaarloop/admin-rbac-decoy (network_gate value), vaultdrop/decoy-cross-tenant-acl-strict (id_format='...random UUIDv4, non-sequential' matching the enumeration permissive heuristic), payrollpilot/aff-export-redaction-guardrail (mask_format value). So precision 0.962 = 75 TP / (75 TP + 3 FP) reflects a real adversarial test. Only 9 decoys are inert (no topic token) and contribute nothing.

**Recommendation:** Precision claim stands. Minor: the 9 inert decoys (e.g. veloxis wallet-topup-idempotency-hardened, toolhub decoy-fetch-egress-allowlist) inflate the raw decoy count without testing the catalog; consider reporting 'tempting decoys: 33' rather than 'decoys: 42' so the precision denominator's adversarial strength is explicit.

### [INFO] DEV (0.73) is framed as context/ceiling, not used to inflate the headline TEST number (0.38)
*Location:* `/Users/hellohelloalbus/heel/heel/heldout_eval.py:104`

**Evidence:** heldout_eval.py:104-108 builds the headline leading with 'held-out TEST recall (unbiased ...): exact 0.085 -> semantic 0.377 (Wilson CI ...) at precision 0.962' and only then appends 'DEV recall 0.732' as the tuning reference. discipline string (line 94-95) states 'the TEST number is the unbiased one.' The UI (web/src/components/screens.tsx:180-196) renders the TEST donut as the primary visual ('semantic (test)' 0.38), labels DEV 'DEV recall (tuned) ... the tuning ceiling', and shows 'overfitting gap ... dev − test, honestly shown'. The DEV-valued top-level back-compat aliases (heldout_eval.py:98-99) exist only for legacy callers; the UI reads h.dev/h.test explicitly and never substitutes DEV for the headline.

**Recommendation:** No change needed; this is a model of honest framing. Only residual risk: any OLD caller reading top-level with_semantic.recall (=0.732 DEV, heldout_eval.py:99) would mistake it for the headline. Audit external consumers of the top-level keys, or add a deprecation note that top-level == DEV.

## adversarial reviewer — semantic matcher precision/recall honesty

**Verdict:** The 0.38 @ 0.96 recall/precision is defensible as a count of "right affordances flagged / not-flagged-on-decoys," but it is NOT an honest measure of correct detection: ~36% of the credited true positives carry the wrong category and severity. Precision and the dev->test overfitting gap are presented without disclosing that attribution (category/severity) is never scored. Recommend either (a) re-score recall/precision with a category-match requirement and report the attribution-aware number alongside, or (b) explicitly caveat that the metric is affordance-localization only, not categorization. The 'orm'/'ttl'/'rag'/'plan' short-substring topics must be word-boundary-anchored.

### [CRITICAL] Q4 (headline): 36% of TEST true positives report the WRONG category and severity, yet count as correct — metric scores affordance_id only, never attribution
*Location:* `/Users/hellohelloalbus/heel/heel/backtest.py:60-61,114; /Users/hellohelloalbus/heel/heel/agents.py:121-123`

**Evidence:** score_target computes tp = [pv for pv in reachable if pv.affordance_id in found_aff] (backtest.py:60) — it matches on affordance_id and NEVER compares pv.category to the finding's category, nor true_severity to reported severity. I re-ran the TEST split: of 75 true-positive affordances, 48 were credited with the correct category and 27 (36%) with a WRONG category+severity. Examples: lumengrade/cross-tenant-cert-lookup planted=data_harvesting reported=compliance_boundary(critical 0.72); helmsman/aff-confused-deputy-cloud-api planted=agent_mcp_surface reported=unintended_endpoints(high 0.48); fennec/aff-statement-bulk-export-enum planted=data_harvesting reported=unintended_endpoints(high 0.48). When multiple signals fire, agents.py:122 keeps the highest-severity vector (v.severity.score > cur.severity.score), so the loudest accidental match wins the label. The 0.962 precision and the 0.73->0.38 'overfitting gap' are therefore both attribution-blind: a finding can be 'right count, wrong reason/label' and still inflate both numbers.

**Recommendation:** Add a category-aware (and ideally severity-aware) scoring mode: a TP requires affordance_id AND category match. Report both the localization recall (current 0.38) and the attribution-correct recall (which would drop ~36% on these TPs, to roughly 0.24). At minimum, prominently caveat in heldout_eval.py/EVAL.md that recall/precision measure affordance localization, not correct categorization or severity.

### [HIGH] Q2: short topic substring 'orm' (mass_assignment, unintended_endpoints) collides with 'format'/'normalization'/'storm' — same class as the 'isolation' bug, fires on real enumeration keys
*Location:* `/Users/hellohelloalbus/heel/heel/semantic.py:62 (topic 'orm'); matched in agents.py:138 via substring`

**Evidence:** semantic_match does `any(t in str(k).lower() for t in topics)` (semantic.py:138). Topic 'orm' is 3 chars and a substring of many benign keys. On test_targets.json it fires inside: id_format (x5), household_id_format (x2), trip_id_format, file_id_format, query_id_format, otp_format, token_format, mask_format, export_formats, normalization, retry_storm, format. These are enumeration / data-harvesting / recovery properties, but they get attributed to mass_assignment (category unintended_endpoints). Confirmed real mis-attributions: lumengrade/cross-tenant-cert-lookup ('id_format' true=data_harvesting -> mass_assignment); vaultdrop/fileid-enumeration-scrape ('file_id_format'); fennec/aff-statement-bulk-export-enum ('household_id_format'); bazaarloop/webhook-replay-no-signature ('retry_storm', true=integration_extensibility).

**Recommendation:** Word-boundary anchor short topics, e.g. match on token boundaries (split key on '_'/non-alnum and require whole-token or known-prefix match) instead of raw substring. Audit and fix all topics <=4 chars: 'orm','ttl','rag','sms','csv','jwt','otp','mfa','2fa','url_','plan','gate','seat','tier','bulk','dump','vote'.

### [HIGH] Q2: 'ttl'->'throttle', 'rag'->'storage', 'plan'->'..._plan', 'seat'->'..._per_seat', 'balance'->'load_balancer' collisions cause more cross-category mis-attribution
*Location:* `/Users/hellohelloalbus/heel/heel/semantic.py:103 (ttl), 110 (rag), 53-54 (plan/gate/tier), 55-56 (seat), 87 (balance)`

**Evidence:** On real TEST keys: 'throttle' (recovery, identity_account) fires retention via 'ttl' substring (veloxis/recovery-otp-no-throttle-ato -> reported compliance_boundary); 'token_storage' fires retrieval_tenant (agent_mcp_surface) via 'rag' inside 'sto-rag-e' (talentloop and fennec oauth-token affordances -> reported agent_mcp_surface instead of integration_extensibility); 'guard_between_data_and_plan' fires tier_gate (unintended_endpoints) via 'plan' (helmsman indirect-injection and token-meter affordances); 'max_active_schedules_per_seat' fires seat_sharing (license_entitlement) on a function_abuse denial-of-wallet affordance (quanta/scheduled-query-denial-of-wallet); 'load_balancer' triggers payout_fraud via 'balance'. Total: across 91 semantic fires on non-decoy TEST affordances, 34 fire with a signal whose category != the affordance's true category.

**Recommendation:** Same word-boundary fix; specifically 'ttl' should require a token like 'ttl'/'time_to_live' not a substring of 'throttle', and 'rag' should not match inside 'storage'/'fragment'. Consider dropping ultra-ambiguous tokens entirely in favor of longer ones ('retrieval','vector','knowledge_base' already cover the RAG case).

### [MEDIUM] Q1: hardened-token escape hatch suppresses genuinely-weak values (false negatives) when any hardened-ish word co-occurs anywhere in the value
*Location:* `/Users/hellohelloalbus/heel/heel/semantic.py:127-129`

**Evidence:** _value_permissive returns False if ANY hardened substring appears anywhere in the value, before checking permissive (semantic.py:127). So a value like 'unlimited_audited', 'global_admin_reviewed', 'wildcard_blocked', 'external_verified' all test as NON-permissive even though the leading token is clearly weak — because 'audited'/'reviewed'/'blocked'/'verified' appear. 'no_dns_rebinding_or_private_ip_block' would be suppressed by 'block'. This silently drops real weaknesses whenever the authoring vocabulary mentions a control word in the same string, and is a plausible contributor to the low recall in categories like unintended_endpoints (9/27) and content_policy (1/11).

**Recommendation:** Don't let a single hardened substring veto the whole value. Score permissive vs hardened token COUNTS/positions (e.g. require the hardened token to be the dominant/leading clause) or evaluate per-clause after splitting on separators. At minimum, document this as a known recall sink in EVAL.md.

### [MEDIUM] Q1: permissive substrings fire on benign/negated tokens — 'allowed'⊂'disallowed', 'never'⊂'never_expires', 'fixed'⊂'fixed_by_review', 'off'⊂'officer'/'offset', 'open'⊂'reopened'/'openid', 'cross'⊂'across'/'crossover'
*Location:* `/Users/hellohelloalbus/heel/heel/semantic.py:24-32,123-129`

**Evidence:** _value_permissive does `any(perm in sv for perm in _PERMISSIVE)`. Tested directly: 'disallowed'->permissive True (contains 'allowed'); 'never_expires'->True (a SAFE token-rotation value, contains 'never'); 'fixed_by_review'->True via 'fixed'; 'officer'/'offset'/'officebound'->True via 'off'; 'openid'/'open_id'/'reopened'->True via 'open'; 'across'/'crossover'/'crossing'->True via 'cross'; 'clientele'/'clientless'->True via 'client'; 'shared_nothing'->True via 'shared'; 'publication'->True via 'public'. Any of these inside a value on a topic-matching key will manufacture a match. (These didn't blow up precision on the frozen TEST set only because the independent authors happened not to use such benign vocab on permissive-suppressed keys — i.e. the 0.96 is partly luck of the held-out vocabulary, not robustness.)

**Recommendation:** Anchor permissive/hardened tokens to word boundaries and handle negation ('disallowed','never_expires','no_...' polarity). 'never' as a bare permissive token is especially dangerous since 'never expires'(bad) and 'never shared'/'never logged'(good) flip polarity. Add a small negation guard.

### [MEDIUM] Q2: same property key matches multiple signals in different categories (password_reset, plugin_review, informed_consent) — dictionary-iteration order plus highest-severity-wins decides the label
*Location:* `/Users/hellohelloalbus/heel/heel/semantic.py:51,62,78,85,105,116; resolved in agents.py:121-123`

**Evidence:** Probed the topic tables: 'password_reset' matches both meter_reset (license_entitlement, via 'reset') and recovery_weak (identity_account); 'plugin_review' matches review_manipulation (trust_economy) and tool_poisoning (agent_mcp_surface); 'informed_consent'/'export_format' match mass_assignment (via 'orm') and consent/bulk_export. Which one is REPORTED is decided by agents.py:122 keeping the highest severity_model score, not by which is correct — e.g. recovery (0.6/0.7) vs meter_reset (0.6/0.6) means a password-reset weakness would be reported as recovery here by score, but the tie/ordering is fragile and undocumented.

**Recommendation:** Make signal selection deterministic and attribution-aware rather than severity-greedy: prefer the signal whose category matches the affordance's declared category when available, or report all firing signals and let scoring credit a category match. Document the tie-break.

### [LOW] Q3: dropping bare 'true'/'enabled' DOES structurally blind the matcher to true==bad families (mass-assignment, indirect-injection), but the measured recall loss on this frozen TEST set is small (~2 affordances) and is unquantified/unacknowledged in code
*Location:* `/Users/hellohelloalbus/heel/heel/semantic.py:21-23,123-129`

**Evidence:** The design comment (semantic.py:21-23) justifies excluding 'true'/'enabled' for precision and says true==weakness must be encoded as an explicit bad word. I scanned TEST for topic-keyed properties whose value is bare True/'enabled'/'yes' that consequently did NOT fire: only 2 (streamharbor/watch-history-idor cross_tenant=True; quanta/nl2sql-exec-tool explain_plan_returned=True). The reason the loss is small is that the independent authors encoded mass-assignment/indirect-injection via descriptive strings (e.g. bazaarloop/payout-mass-assignment accepted_undocumented_fields=[...]; helmsman/aff-indirect-injection content_treated_as='instructions_not_data', guard_between_data_and_plan='none'), so true-polarity giveaways were rare. BUT this is data-dependent luck: the correct signal indirect_injection FAILS to fire on helmsman/aff-indirect-injection because its topic 'untrusted_content' matches key untrusted_content_source whose value is a list (not permissive); the affordance is only credited as a TP via spurious tier_gate/ssrf/api_key_leak fires — confirming Q4 in a single case.

**Recommendation:** State the true==bad recall-loss explicitly in semantic.py / EVAL.md, and add per-property polarity handling (a curated set of keys where bare True IS the weakness, e.g. acts_on_content, cross_tenant, mass_assign-style) so these families are detected by their correct signal rather than by accident. Also make _value_permissive treat a non-empty list value as evidence (e.g. untrusted_content_source listing real sources).

### [INFO] Precision is computed against decoys only; the 3 TEST false positives are all explicit decoy affordances — so 0.96 measures decoy-avoidance, not attribution correctness
*Location:* `/Users/hellohelloalbus/heel/heel/backtest.py:65-80,96; /Users/hellohelloalbus/heel/heel/heldout_eval.py:78-80`

**Evidence:** fp_rate/precision count a plausible finding as FP only if its affordance is non-planted (a hardened decoy): backtest.py:74-79. The 3 TEST FPs are bazaarloop/admin-rbac-decoy, vaultdrop/decoy-cross-tenant-acl-strict, payrollpilot/aff-export-redaction-guardrail — all decoys. Nothing in the precision computation penalizes a finding that lands on a real weakness but with the wrong category/severity. So a model that flagged every real affordance with a randomly-chosen-but-plausible category would still score ~0.96 precision here.

**Recommendation:** Report an attribution-aware precision (finding category must match the affordance's planted category) next to the decoy-avoidance precision, so the headline number reflects correctness of the label, not just localization.

## measurement statistician + skeptic auditing HEEL's held-out detection metric

**Verdict:** The 0.38 point estimate is honest and the dev->test overfitting gap is disclosed well, but the reported uncertainty is materially understated. The correct headline is "TEST semantic recall 0.38, target-clustered 95% CI approx [0.28,0.48] (n=14 products, 199 weaknesses), precision 0.96 [0.89,0.99]" — replace the iid Wilson with a target-level bootstrap/cluster CI, demote all per-category figures to descriptive-only, and lock the authoring seed + reachability threshold + product count under a pre-registered protocol to close the remaining degrees of freedom.

### [HIGH] Wilson CI treats 199 clustered weaknesses as iid; it is ~45% too narrow
*Location:* `/Users/hellohelloalbus/heel/heel/heldout_eval.py:79 and /Users/hellohelloalbus/heel/heel/blind_eval.py:52-59`

**Evidence:** _run pools tp/plant across targets and calls _wilson(tp, plant) with plant=199, modeling one binomial of 199 independent trials. But the 199 weaknesses are nested in 14 targets with strong between-target heterogeneity: per-target semantic recall ranges 1/13=0.077 (veloxis) to 12/16=0.75 (helmsman); unweighted per-target mean 0.378, between-target stdev 0.182. I estimated the intra-cluster correlation (one-way ANOVA estimator, target = cluster) at ICC~=0.087, giving design effect ~=2.15 and effective sample size n_eff~=92 (not 199). Recomputing: naive Wilson = [0.312,0.446] (half-width 0.067); design-effect Wilson on n_eff = [0.288,0.483]; target-bootstrap (20k resamples of whole targets) = [0.285,0.477] (half-width 0.096); cluster t-interval on per-target rates df=13 = [0.269,0.486]. All three correct methods agree the true 95% CI is ~[0.28,0.48], about 45% wider than the reported [0.31,0.45].

**Recommendation:** Replace the pooled iid Wilson at heldout_eval.py:79 with a target-level (cluster) bootstrap CI — resample the 14 targets with replacement, recompute pooled recall per resample, take the 2.5/97.5 percentiles — or a design-effect-corrected Wilson using n_eff = n/deff. Report it as a cluster/target-bootstrap CI and state n_clusters=14 explicitly next to n_weaknesses=199. The headline string at heldout_eval.py:104-108 should carry the wider interval.

### [MEDIUM] reachability>=0.25 filter is inert here but is an unlocked, author-tunable gate on an LLM-authored field
*Location:* `/Users/hellohelloalbus/heel/heel/heldout_eval.py:52 (reachable=reach>=0.25) and :74-77 / backtest.py:55,123 (reachable_planted)`

**Evidence:** PlantedVector.reachable is set from reach>=0.25 where reach=float(a.get('reachability',0.7)) comes straight from the LLM-authored target file. I checked the actual data: in TEST, 0 of 199 non-decoy weaknesses fall below 0.25 (distribution: 7 in [0.25,0.5), 123 in [0.5,0.75), 69 >=0.75; min observed ~0.45); in DEV, 0 of 97 are filtered. So the threshold does NOT bias the current 0.38 / 0.73 numbers — that is good and should be stated. However it is a live denominator gate: because the recall denominator is reachable_planted, a future authoring run that assigns lower reachability to hard-to-detect weaknesses would shrink the denominator and inflate recall, with no detection improvement. The threshold (0.25) is a free parameter chosen by the author, not validated, and the eval does not assert the filter is a no-op.

**Recommendation:** Either (a) drop the reachability filter for the headline and report recall over ALL planted weaknesses (since it is currently a no-op this does not change 0.38), or (b) keep it but add an assertion/printout of how many weaknesses it removes per split (should be 0) and lock the 0.25 threshold + the reachability field in the pre-registered protocol so it cannot be retuned. Report recall both filtered and unfiltered to show the filter is not load-bearing.

### [MEDIUM] Per-category recall denominators are far too small to support strong/weak category claims
*Location:* `/Users/hellohelloalbus/heel/heel/heldout_eval.py:80 (recall_by_category) and docs/HELDOUT_PROVENANCE.md:44-45`

**Evidence:** TEST per-category counts and their Wilson CIs: content_policy 1/11=0.09 CI[0.02,0.38]; trust_economy 3/9=0.33 CI[0.12,0.65] (width 0.53); agent_mcp_surface 4/18 CI[0.09,0.45]; every one of the 10 categories has a CI width between 0.33 and 0.53. The provenance doc claims the breakdown 'shows exactly where HEEL is weak vs strong' but with these denominators no two categories are statistically distinguishable — e.g. content_policy's [0.02,0.38] overlaps license_entitlement's [0.31,0.66]. The DEV breakdown is worse (content_policy 0/1, trust_economy 2/2) — single-digit denominators that cannot support any rate claim.

**Recommendation:** Present recall_by_category as descriptive counts only (k/n), explicitly labelled 'not powered for per-category inference,' and remove any 'strong/weak category' language from docs/HELDOUT_PROVENANCE.md:44-45. If category-level claims are wanted, they require a much larger TEST set (order 50+ weaknesses per category) and category-level CIs printed alongside.

### [MEDIUM] Residual researcher degrees of freedom: re-runnable authoring, choice of n and threshold, one glimpsed product
*Location:* `/Users/hellohelloalbus/heel/docs/HELDOUT_PROVENANCE.md:49,57-67 and /Users/hellohelloalbus/heel/heel/heldout_eval.py:101 (os.path.exists gate)`

**Evidence:** The set is described as frozen, but provenance:49 says 'regenerating it requires re-running the authoring workflow' — i.e. the author can re-run the LLM swarm and, absent a committed seed/hash, select a favorable TEST set without ever editing semantic.py (the metric moves without improving detection). Other live levers: n=14 products is author-chosen (heldout_eval._eval_split just reads whatever file is present); the reachability threshold 0.25 is hard-coded and unvalidated; and provenance:66-67 admits one TEST product (bazaarloop-marketplace) was glimpsed in a tool-result notification — that product's per-target recall is 5/14=0.357, near the pooled mean, so it is not currently distorting the number, but it breaches the blind-freeze invariant in principle. The TEST file is also not content-hash-pinned in the repo, so 'frozen' is a social claim, not an enforced one.

**Recommendation:** Pre-register and commit, before any TEST run: the authoring RNG seed/workflow version, the exact product count, the reachability threshold, and a SHA-256 of test_targets.json; report the number ONCE against that frozen hash. Quarantine bazaarloop-marketplace into a separate 'leaked' bucket and report TEST recall both with and without it (here: with=0.377, without=70/185=0.378 — confirm and disclose). Add an assertion that the committed test file hash matches the pre-registered hash so a silent re-authoring cannot pass unnoticed.

### [LOW] Precision 0.96 is also a tiny-denominator, clustered figure and should carry a CI
*Location:* `/Users/hellohelloalbus/heel/heel/heldout_eval.py:79 (precision = tp/(tp+fp))`

**Evidence:** TEST precision is 75/78 = 0.962 — it rests on just 3 false positives, with no interval reported. Wilson CI on 75/78 is [0.89,0.99]. Like recall, the FPs are clustered by target/probe (blind_eval.py:88 already tracks false_positives_by_probe; heldout_eval does not), so even this interval is mildly optimistic. The headline presents 0.96 as if it were a stable point.

**Recommendation:** Report precision with its Wilson CI [0.89,0.99] and, as in blind_eval, attribute the 3 FPs to specific probes/targets so the reader can see the precision claim hangs on 3 events. State n_fp=3 explicitly.

### [INFO] Positive controls: point estimate, exact-vs-semantic gap, and dev-vs-test gap are honestly reported
*Location:* `/Users/hellohelloalbus/heel/heel/heldout_eval.py:90-109`

**Evidence:** I reproduced all headline numbers exactly: exact-match TEST 17/199=0.085, semantic TEST 75/199=0.377, DEV 71/97=0.732. The code does not key the semantic catalog off the TEST file, the dev->test drop (0.73->0.38) is surfaced as the overfitting gap in the headline string (:106-108), and the one glimpsed product is disclosed. The structural honesty is good; the issues above are about quantifying uncertainty, not about a faked point estimate.

**Recommendation:** Keep the exact-vs-semantic and dev-vs-test reporting. Layer the cluster-CI, descriptive-only categories, precision CI, and a pre-registered freeze on top — these strengthen rather than contradict the existing honest framing.
