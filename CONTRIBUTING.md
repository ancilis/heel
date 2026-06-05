# Contributing to HEEL

Thanks for helping rehearse abuse before it ships. HEEL is small, pure-stdlib, and test-first.

## Setup

```bash
pip install -e .
make test     # acceptance + safety tests (pure stdlib, no extra deps)
make demo     # auth-gate proof + honest backtests
heel doctor   # environment self-check
```

The core is **pure Python standard library** (DECISIONS D-001) — please keep runtime dependencies at
zero. The UI (`web/`) is a separate Next.js app and a thin client over the same snapshot.

## The safety spine is non-negotiable (§10)

Any contribution **must** preserve these. PRs that weaken them will not be merged:

- **Synthetic-first / detection-not-weaponization.** Probes read only *observable* signals and emit
  *contained, canary-only* proofs. Never add code that produces working exploits, real exfiltration,
  resource exhaustion, or detection-evasion for malicious use.
- **Never generate prohibited or illegal content**, under any framing. Guardrail presence is verified
  with benign canaries only.
- **Scopes stay human-only and out-of-band.** Do not add any MCP/REST/agent path that creates,
  widens, or relaxes a scope. The authorization gate (`tests/test_heel.py::TestAuthGate`) must stay green.
- **Lane discipline.** True software vulns → `handoff_to_appsec`; pure jailbreaks → model red-team.
- **Metric honesty.** Don't inflate coverage, hide false positives, or tune against the frozen
  held-out **test** set (`heel/heldout/test_targets.json`). Tune on **dev**, measure on test once.

## Adding scenarios (no code required)

Drop a JSON file in `heel/scenarios_lib/` — it's merged at load time. Each scenario is a declarative
spec (surface pattern + `success_criterion` + severity + control). See `heel/scenarios.py` and the
generic `evaluate_criterion`. For vocabulary that generalizes, prefer a `{"semantic": "<signal>"}`
criterion and extend `heel/semantic.py`'s catalog (topic keywords + permissive/hardened values).

## Tests

Add/extend tests in `tests/test_heel.py` (stdlib `unittest`). All tests must pass on Python 3.11–3.13
(CI runs the matrix + a wheel install smoke test + the UI build). Run `make test` before opening a PR.

## Commit style

Match the surrounding code's density and idiom. Explain *why* in the message. By contributing you
agree your work is licensed under the repository's MIT license.
