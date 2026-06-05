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
- **Neither is near 1.0**, and `recall_by_category` shows exactly where HEEL is weak (e.g.
  unintended-endpoints, license-entitlement) vs strong (data-harvesting, function-abuse).

This is the honest real-target ceiling. It improves only by widening the library's semantic coverage
of real abuse vocabularies — not by writing probes against known plants. The set is **frozen** so the
eval is deterministic and offline; regenerating it requires re-running the authoring workflow.
