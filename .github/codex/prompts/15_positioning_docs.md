# Prompt 15 — Add “why not pentest / QA / fraud platform?” README section

Task: Add a clear differentiation section to README.md and docs/POSITIONING.md.

Create `docs/POSITIONING.md`.

Explain Heel compared to:

- penetration testing / AppSec scanners
- functional QA
- fraud/bot platforms
- runtime WAF/API protection
- Trust & Safety manual review
- model red-team tools

Core message:
Heel is not a replacement for any of these.
Heel fills the missing product-abuse rehearsal step:

- abuse of intended features
- legitimate customer misuse
- business-logic gaming
- pricing/entitlement/workflow exploitation
- integration abuse
- agent/tool overreach
- safe contained proof before or after launch

Add table columns:

- Tool category
- Primary question
- When it runs
- Typical signal
- What it misses
- How Heel complements it

Add examples:

- QA says export button works.
- AppSec says endpoint has no injection bug.
- Fraud platform may catch abuse after traffic appears.
- Heel asks whether the export business flow can be used by a trial user to harvest more data than intended.

Acceptance criteria:

- A skeptical reader understands why Heel is a distinct category.
- The docs do not attack adjacent tools; they position Heel as complementary.
