# Prompt 18 — Add CI/demo commands for the new workflows

Task: Update Makefile, README commands, and tests so the new workflows are easy to try.

Add Makefile targets:

- make demo
- make demo-import
- make demo-launch-review
- make demo-regressions
- make demo-bench
- make test
- make ui

Ensure:

- make demo remains fast and deterministic.
- New demos do not require API keys.
- New demos do not require network access.
- New demos do not touch real systems.
- Output clearly labels synthetic/imported/staging modes.

Update README “See it in 30 seconds”:

- Keep current simple path.
- Add “Try a SaaS abuse review” path:
  - heel import validate examples/saas_demo/product_model.json
  - heel launch-review ...
  - heel regress ...

Tests:

- Makefile targets that can be tested in CI are exercised.
- CLI help includes new commands.
- README command snippets are checked if the repo already has doc tests; otherwise add lightweight tests.

Acceptance criteria:

- The new feature set is discoverable and demoable.
