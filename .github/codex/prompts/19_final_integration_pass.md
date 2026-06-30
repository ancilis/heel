# Prompt 19 — Final integration and consistency pass

Task: Final integration pass after all previous PRs.

Run the full test suite and inspect the docs for consistency.

Checks:

- README, ARCHITECTURE, SECURITY, TRUST, EVAL, DECISIONS agree on:
  - pre-launch + existing-product positioning
  - safety constraints
  - adapter maturity
  - no scope mutation over MCP/REST/agent surfaces
  - canary-only findings
  - honest eval metrics
- pyproject description matches README.
- CLI help includes:
  - import
  - init --from-openapi
  - launch-review
  - regress
  - controls simulate
  - bench
  - incident
  - scenario validate
- All new docs link from README Docs section.
- All new examples are safe and contain no secrets.
- No Python runtime dependency was added.
- Existing tests still pass.
- New tests cover major new behavior.
- UI builds if web changes were made.

Add or update CHANGELOG.md:
Add an “Unreleased” section with:

- continuous abuse rehearsal positioning
- ProductModel adapter contract
- entitlement graph
- launch review
- regressions
- economic severity
- personas
- scenario packs
- control simulator
- HEELBench
- incident-to-scenario
- dashboard war room

Acceptance criteria:

- The repo reads like one coherent product, not a pile of features.
