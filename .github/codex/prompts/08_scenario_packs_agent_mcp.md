# Prompt 8 — Make agent/MCP abuse a premium scenario pack, not the whole product

Task: Reorganize agent/MCP abuse scenarios as a named optional pack while keeping them enabled for agentic targets.

Why:
Heel should be understood as SaaS abuse rehearsal generally. Agent/MCP abuse is an important surface, not the whole product.

Changes:

- Add scenario pack metadata:
  - core_saas
  - agent_mcp
  - payments_billing
  - trust_safety
  - integrations
  - compliance
- Update scenario definitions to include pack name.
- Update list_scenarios filtering to support pack filter.
- Update CLI:
  - heel scenarios --pack agent_mcp
  - heel run --packs core_saas,agent_mcp
- Keep current behavior by default:
  - all relevant packs run
  - agent/MCP scenarios only apply when target has agent surface
- Add docs/SCENARIO_PACKS.md

Tests:

- agent_mcp pack contains existing agent/MCP scenarios
- agent_mcp scenarios do not fire on non-agent targets
- filtering by pack works
- default behavior remains backward-compatible
- README positions agent/MCP as one surface among many

Docs:

- Explain:
  “Heel covers SaaS abuse broadly. Agent/MCP is a premium pack for products with agentic surfaces.”
- Add examples:
  - over-scoped tools
  - confused deputy
  - cross-tenant retrieval
  - indirect-injection-to-action
  - cost amplification
  - tool poisoning

Acceptance criteria:

- The repo no longer risks being read as only an AI security tool.
