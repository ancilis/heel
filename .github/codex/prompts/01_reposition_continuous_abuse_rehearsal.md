# Prompt 1 — Reposition from “pre-launch only” to “continuous abuse rehearsal”

Task: Reposition Heel from “pre-launch only” to “continuous abuse rehearsal for SaaS,” while preserving the pre-launch wedge.

Update README.md, ARCHITECTURE.md, SECURITY.md, TRUST.md, and pyproject.toml wording.

Desired positioning:

- Heel is abuse rehearsal for SaaS.
- It helps teams rehearse customer, integration, bot, and agent abuse before launch and throughout production life.
- Pre-launch launch review remains the sharpest default use case.
- Existing products are supported through authorized, contained, canary-only runs against staging, imported product models, sanitized telemetry, or explicitly authorized production-like targets.
- Do not imply Heel safely runs arbitrary active probes against production without operator approval.
- Make “production-ready” precise: production-ready safety/auth/eval spine; beta real-target adapter coverage until adapters mature.

Specific edits:

1. README.md:
   - Replace the single “before you ship” framing with “before launch and continuously after.”
   - Add a short section: “Pre-launch, post-launch, and after incidents.”
   - Add a “What Heel is not” section or expand existing wording:
     - not a pentest replacement
     - not functional QA
     - not runtime fraud decisioning
     - not a bot mitigation service
     - not a jailbreak tool
   - Add a concise comparison table:
     - pentest/AppSec scanner
     - QA/functional testing
     - fraud/bot platform
     - model red-team
     - Heel
   - Keep the strong launch-day examples, but add examples for existing products:
     - trial farming already happening
     - seat sharing on mature accounts
     - export scraping by legitimate customers
     - AI-token cost abuse
     - integration/OAuth overreach
     - support/workflow gaming after an incident

2. ARCHITECTURE.md:
   - Add operating modes:
     - synthetic demo
     - launch review
     - staging rehearsal
     - existing-product imported model
     - incident-to-scenario
     - continuous regression
   - Emphasize that all non-synthetic runs require explicit human scope authorization.

3. SECURITY.md:
   - Update real-target language.
   - Replace “real-target adapters are out of v1 scope” with:
     - “real-target adapters are beta and must run through signed scopes, canary-only data, and operator-approved limits.”
   - Add “Existing product mode” safety constraints:
     - prefer staging/sandbox
     - use synthetic users/canaries
     - read-only discovery when possible
     - no real exfiltration
     - no resource exhaustion
     - no automated high-volume probing

4. pyproject.toml:
   - Keep Development Status :: 4 - Beta unless the repo truly supports mature real-target adapters.
   - Update description to mention continuous SaaS abuse rehearsal, not only pre-launch.

5. DECISIONS.md:
   - Add a new decision:
     “D-033 — Heel supports pre-launch and existing-product abuse rehearsal.”
   - Explain why pre-launch is the wedge but existing products widen adoption.
   - Explain the safety consequences.

Tests:

- Add a docs consistency test that checks README/SECURITY do not claim unrestricted production probing.
- Add a metadata test that pyproject description contains “abuse rehearsal” and does not overclaim “pentest replacement.”

Acceptance criteria:

- The repo no longer reads as only pre-launch.
- Safety boundaries are clearer, not weaker.
- The “Production-ready vs Beta” mismatch is resolved.
