# Prompt 10 — Build public benchmark scaffolding: HEELBench

Task: Create HEELBench, a public benchmark harness for SaaS abuse rehearsal.

Do not fabricate inflated results. Reuse existing held-out methodology and make the benchmark honest.

Create:

- docs/HEELBENCH.md
- heel/bench.py
- CLI:
  - heel bench run
  - heel bench report --format markdown|json
- tests

Benchmark metrics:

- self-consistency coverage
- blind lower-bound recall
- held-out DEV localization recall
- held-out DEV attribution recall
- held-out TEST localization recall
- held-out TEST attribution recall
- precision
- severity calibration
- control recommendation coverage
- no-weaponization compliance
- canary-only compliance
- category coverage

Use existing heldout_eval/blind_eval/backtest functions where possible.

Output should clearly label:

- what is synthetic wiring
- what is blind but author-controlled
- what is independent held-out
- what was tuned on DEV
- what is frozen TEST
- attribution vs localization

Add benchmark metadata:

- test set content hash
- number of targets
- number of planted weaknesses
- categories
- scenario library size
- date generated
- code version

Tests:

- bench report includes attribution and localization separately
- bench report includes content hash for frozen test
- bench report includes precision
- bench report does not call self-consistency “accuracy”
- no-weaponization compliance is computed from finding reproduction fields

Docs:

- Explain why this benchmark exists.
- Invite external scenario packs / target packs without exposing unsafe details.
- Make clear that the benchmark measures safe detection/rehearsal, not exploitation.

Acceptance criteria:

- Heel’s evaluation story becomes a reusable benchmark asset.
