# Master instruction for every Codex task

You are working in the `ancilis/heel` repository.

Goal: evolve Heel from a synthetic-first abuse-simulation engine into a safe, adapter-driven abuse rehearsal platform for SaaS products, usable before launch and for existing products.

Non-negotiable safety constraints:

- Never add functionality that attacks third-party systems.
- Never generate working exploit payloads.
- Never perform real data exfiltration, real credential abuse, real payment abuse, real spam, or resource exhaustion.
- All real-target or imported-target flows must require an explicit human-created AuthorizationScope.
- The MCP/REST/agent surfaces must never be able to create, widen, relax, or mutate scopes.
- Findings must remain contained/canary-only.
- Keep lane discipline: true software vulnerabilities are handed off to AppSec; pure jailbreaks are handed off to model red-team.
- Preserve the existing zero-runtime-dependency Python core unless a task explicitly touches the Next.js UI.
- Add or update tests for every behavior change.
- Update docs when public behavior or positioning changes.

Before editing, inspect:

- README.md
- ARCHITECTURE.md
- SECURITY.md
- TRUST.md
- EVAL.md
- DECISIONS.md
- heel/contracts.py
- heel/mcp_server.py
- heel/orchestrator.py
- heel/scenarios.py
- heel/agents.py
- heel/targets.py
- heel/backtest.py
- tests/test_heel.py

Important existing constraints:

- Heel is MCP-first.
- Scope creation is human-only and out-of-band.
- The MCP server exposes execution/read tools only and deliberately has no scope mutation tool.
- v1 uses a pure Python stdlib core and zero runtime dependencies.
- The current scenario system is declarative and supports JSON scenario packs under `heel/scenarios_lib/*.json`.
- The evaluation story must remain honest: distinguish synthetic self-consistency, blind lower bound, held-out localization, held-out attribution, precision, and calibration.

Deliver a clean PR-sized change with tests and docs.
