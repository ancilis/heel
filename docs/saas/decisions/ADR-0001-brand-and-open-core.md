# ADR-0001 — Brand name and open-core boundary

Status: Accepted · Date: 2026-07-13 · Decider: Fable (autonomous, delegated)

## Context
The product was renamed Heel → ARCEO. Evidence verified: `origin/main` tip commit is
"Merge … rebrand-arceo"; `pyproject.toml` `name = "arceo"`, `[project.scripts]` = `arceo`,
`arceo-mcp`, `arceo-rest`; README title "Arceo"; package dir `arceo/`; homepage
`github.com/ancilis/arceo`. The remote is still `github.com/ancilis/heel.git` (repo not yet
renamed on GitHub — an owner action). The core is Apache-2.0 with a DCO and NOTICE.

## Decision
1. **Canonical product/package/CLI name: `arceo`.** No further rename. The `heel_sim`/`arceo_sim`
   egg-info dirs are stale build artifacts (ignored), not authoritative.
2. **Repo rename to `ancilis/arceo` is an OWNER action** (GitHub-side). Code keeps working via the
   existing remote until then; badge/URL references already point to `arceo`.
3. **Open-core boundary:**
   - **Open core (Apache-2.0, stays in this repo, `arceo/` package):** the engine — scope safety
     spine, synthetic targets, agents, scenarios, entitlement graph, importers, evaluation honesty,
     containment log, CLI, MCP server, loopback REST. This is the reusable, auditable value.
   - **Commercial hosted layer (proprietary, isolated under `arceo/saas/` + `web/`):** multi-tenant
     control plane, billing, metering, quotas, hosted auth, managed workers, admin. This code is a
     **separate licensing unit** and MUST carry its own proprietary header, NOT the Apache grant.
4. **Do not relicense the Apache core.** Adding proprietary hosted code to an Apache repo is
   permitted (Apache-2.0 does not virally relicense combined/aggregate works), but the boundary must
   be explicit per-file. A dedicated `LICENSE-COMMERCIAL.md` documents the hosted-layer terms; the
   root `LICENSE` (Apache-2.0) and `NOTICE` are preserved unchanged. This is a documentation of
   intent, **not legal advice** — flagged for owner counsel review in OWNER_ACTIONS.

## Alternatives rejected
- Keep dual "Heel" aliases in user-facing copy: rejected — the rebrand is committed; aliases add
  confusion. Retain only compatibility shims where a hard break would harm existing installs.
- Full proprietary relicense: rejected — destroys the open-source trust that is the top-of-funnel.
- AGPL the core: rejected — deters the developer/security ICP and complicates hosted use.

## Consequences / reversibility
Reversible via a follow-up ADR. Migration cost of the open-core split is low because hosted code is
greenfield under `arceo/saas/`. Per-file license headers make the boundary machine-checkable.
