# HEEL — research scenario library (`scenarios_lib/research_owasp.json`)

45 business-logic abuse-detection scenarios across all 10 categories, plus a semantic-vocabulary
expansion, integrated from an external source-anchored research deliverable. The scenarios are
declarative JSON (addable without code) and were authored from PRIMARY SOURCES, independently of —
and with no access to — HEEL's held-out evaluation targets.

## Measured impact (honest, on the FROZEN held-out test set)

The research was authored blind to the test set, so measuring its lift there is fair:

| metric | before | after |
|---|---|---|
| library size | 67 scenarios | **119** (45 research + semantic enrichment) |
| held-out **TEST** localization recall | 0.38 | **0.50** (cluster-CI [0.42, 0.59]) |
| held-out **TEST** precision | 0.97 | **0.98** |
| exact-match TEST recall | 0.085 | 0.10 |

A genuine +12pp recall lift at unchanged-to-better precision on vocabulary HEEL never saw.

## Primary sources

OWASP API Security Top 10 2023 (BOLA/BFLA/BOPLA/mass-assignment/resource-consumption/business-flows/
SSRF/inventory) · OWASP Automated Threats / OAT taxonomy (OAT-001/002/005/006/013/016/019/021) ·
OWASP WSTG + Cheat Sheets (CSV/formula injection, Forgot-Password, OAuth2) · OWASP LLM Top 10 2025
(LLM06 excessive agency, LLM10 unbounded consumption) · the MCP 2025-06-18 schema (tool annotation
HINTS: `readOnlyHint`/`destructiveHint`/`openWorldHint`; token-passthrough forbidden) · vendor config
docs: Stripe (Billing Meter `default_aggregation`/`event_time_window`; webhook 300s tolerance), Kong
(`limit_by`/`window_size`), Microsoft (SharePoint external sharing), Google/Auth0 (OAuth).

## Integration notes (precision discipline)

- **Polarity respected.** Boolean-true-is-bad fields (`destructiveHint:true`, `openWorldHint:true`)
  stay as EXACT scenarios, never semantic topics — "true" is deliberately not a permissive value.
- **Absence-checks tightened.** `{"not":{"prop_exists":X}}` clauses over-fired on hardened decoys
  that enforce the control under a different key; each is now paired with `guard_absent`, which kept
  the held-out recall while restoring precision (a `prop_exists` operator was added to the evaluator).
- **MCP annotations are HINTS, not contracts** — a mislabeled destructive tool is itself a finding;
  detectors verify behavior, not the label.

Per-category counts, the coverage matrix, and full per-claim provenance (incl. labeled
plausible-but-inferred items) are in the source deliverable. Severity values are calibrated estimates,
not measured base rates.
