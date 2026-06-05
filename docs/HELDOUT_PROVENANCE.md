# HEEL — held-out evaluation set: provenance

`heel/heldout/targets.json` is the strongest honesty test in HEEL: it measures real detection
accuracy on targets whose abuse weaknesses were authored **independently of, and blind to, HEEL's
detection probes**. This document records exactly how they were produced, so the independence claim
is auditable.

## How they were authored

A multi-agent workflow (`heel-heldout-authoring`) spawned **8 parallel LLM agents**, each acting as
an adversarial product-security architect. Each agent was given **only**:

- a one-line product brief (e.g. "a B2B analytics SaaS", "an AI coding assistant with a code-exec
  tool + retrieval"),
- the 10-category abuse **taxonomy** (category names + example abuses), and
- an output **schema** (product → affordances with `kind`, `category`, `properties`, `weakness`,
  `severity`, `reachability`, `is_decoy`).

They were **NOT** given HEEL's scenario library, its `success_criterion` vocabulary, the
`heel/semantic.py` signal catalog, or any property names HEEL keys off. They were explicitly
instructed to **invent the natural property names and values for their product** and told the set
was "a held-out test for a detector you cannot see."

The result: property vocabularies HEEL's authors never chose — `seat_counter_basis`,
`shared_login_detection: none`, `tenant_scope_check: disabled`, `api_revalidates_entitlement: false`,
`private_ip_range_block: absent`, `export_audit_event: not_emitted`, `writable_fields_whitelist:
absent`, `delete_semantics: soft_delete_flag_only`, … — across all 10 categories, with hardened
decoys mixed in.

## Why this is the right test

The earlier **blind eval** (`heel/blind.py`) removed the seed/plant co-authorship circularity, but
its encodings were still written by HEEL's author — so the encoding-overlap (and hence recall) was
ultimately a designer choice (red-team finding, `docs/REDTEAM_BLIND_FINDINGS.md`). This held-out set
removes that last lever: a **different author** (the LLM swarm) wrote the encodings, with no sight of
the probes. HEEL's recall here is real detection accuracy with no author control over the vocabulary.

## The honest result (`heel/heldout_eval.py`, `make demo`)

- **Exact-match recall ≈ 0.26** — exact property/kind matching barely generalizes to an
  independently-authored vocabulary.
- **With semantic generalization ≈ 0.57** (Wilson CI ≈ [0.48, 0.68]) at **precision ≈ 0.95** — the
  `heel/semantic.py` synonym families recover roughly twice as much, on vocabulary HEEL never saw.
- **Neither is near 1.0.** `recall_by_category` is reported as descriptive per-category counts (k/n)
  only — the denominators (≈1–29 per category) are far too small for per-category strong/weak claims.

This is the honest real-target ceiling. It improves only by widening the library's semantic coverage
of real abuse vocabularies — not by writing probes against known plants. The set is **frozen** so the
eval is deterministic and offline; regenerating it requires re-running the authoring workflow.

## Update — dev/test split (wave 5)

To improve recall without overfitting, the held-out eval now uses two splits:

- **DEV** (`heel/heldout/targets.json`, 8 products / 97 weaknesses) — the semantic catalog
  (`heel/semantic.py`) was tuned on these.
- **TEST** (`heel/heldout/test_targets.json`, 14 products / 199 weaknesses) — authored by a SECOND
  independent LLM swarm (workflow `heel-heldout-testset`, 14 diverse product briefs), **frozen and
  not inspected by the tuner** (the freeze script prints counts only, never properties). The TEST
  recall is the unbiased number.

Result: DEV semantic recall 0.73 vs **TEST semantic recall 0.38** (Wilson CI [0.31, 0.45]) at **0.96
precision**; exact-match TEST 0.085. The dev→test gap is the overfitting gap, reported openly. The
honest generalization on vocabulary HEEL never saw is ~0.38, and it rises only by widening the
semantic catalog's coverage of real abuse vocabularies — never by writing probes against known
plants. (One TEST product was glimpsed by the tuner in a tool-result notification; the catalog was
not tuned against it — a fresh red-team audits for any such leakage.)

## Update — methodology red-team fixes (wave 5b)

A 3-agent red-team audited the dev/test methodology (verdict: HONEST, with fixes). Applied:

- **Localization vs attribution recall.** The score credited a TP on affordance match alone, so
  ~29% of TEST localizations carried the wrong category. Now both are reported: TEST **localization
  ~0.38** and the stricter **attribution ~0.27** (right affordance AND category). The
  localization→attribution gap is shown, not hidden.
- **Cluster bootstrap CIs.** The iid Wilson interval treated 199 clustered weaknesses as independent
  (~30–45% too narrow). Replaced with a target-level bootstrap (resample the targets): localization
  CI ≈ [0.29, 0.49], attribution ≈ [0.20, 0.35], precision ≈ [0.94, 1.0].
- **Word-boundary matching.** Topic/permissive tokens are now anchored at token boundaries, killing
  substring collisions (`orm`⊂`format`, `ttl`⊂`throttle`, `allowed`⊂`disallowed`); TEST precision
  rose to ~0.97. Ambiguous `never`/`fixed` and bare `true`/`enabled` removed.
- **Pre-registration.** `test_targets.json` is content-hashed (`sha256` in the eval output) so the
  number is reported against a frozen set; the reachability≥0.25 gate is disclosed as a no-op (it
  removes 0/199). The catalog was confirmed NOT fitted to the one glimpsed product (its two unique
  tokens never fire). Auditor's residual caveat (honest): ~73% of the topic tokens that fire on TEST
  also appear in DEV keys, though ~70% of catches still land on TEST-novel property keys.
