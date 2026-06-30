# Prompt 12 — Dashboard war room

Task: Redesign the Next.js dashboard from “report viewer” into an abuse war room.

Inspect `web/` and current snapshot generation before editing.

Dashboard goals:
Answer four questions:

1. What can customers game?
2. How much can it cost us?
3. Which control stops the most abuse with the least friction?
4. Is this now covered by a regression?

Add or update UI sections:

- Abuse Board:
  - ranked by reachability + severity + optional economic impact
  - filter by category, persona, pack, product area
- Launch Review:
  - changed surfaces
  - pass/warn/block gate
  - suggested regressions
- Existing Product Review:
  - imported model summary
  - entitlement graph risks
  - live/staging/synthetic mode indicator
- Control Simulator:
  - candidate controls
  - estimated abuse reduction
  - friction cost
  - recommended bundle
- Regression Coverage:
  - findings with regression
  - findings without regression
  - last run status
- Incident Library:
  - sanitized incidents
  - generated scenarios
  - generated regressions
- Safety & Authorization:
  - signed scope status
  - read-only scope panel
  - containment log
  - canary-only status
  - no scope mutation path

Update:

- heel/web_export.py to include new snapshot fields using deterministic sample data.
- web/public/data/snapshot.json
- UI components in web/

Constraints:

- Do not add runtime dependencies to Python core.
- UI dependencies are acceptable only if already part of the web app pattern; avoid unnecessary packages.
- Keep snapshot deterministic.

Tests:

- existing Python tests still pass
- UI build passes
- snapshot includes sections for economics, regressions, launch review, controls, incidents
- dashboard visibly labels synthetic/imported/staging mode
- dashboard does not imply unsafe production probing

Acceptance criteria:

- The dashboard feels like an operator control room for abuse rehearsal, not a generic scanner report.
