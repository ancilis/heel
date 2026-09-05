# Business-abuse wedge implementation — September 4, 2026

The delivered workflow is **synthetic export-read entitlement validation**, available through the installed CLI and MCP, with app onboarding and local report viewing. It connects an explicit product rule and hypothesis to human authorization, two bounded reads, protected-content evidence, a server-side fix and the same passing regression. It does not establish broad SaaS readiness or arbitrary customer-target onboarding.

## Baseline and decisions

Knowledge-graph discovery was followed by source inspection in this worktree. `AGENTS.md` was absent on disk; the supplied instructions were followed. The two existing review documents were preserved and their relevant claims reproduced:

- `heel runner pair --cloud …` was not implemented (exit 2); cloud/MCP pairing was incomplete. Unsupported instructions were removed. The supported reference path now has installed CLI and real MCP stdio acceptance.
- A positive-role HTTP 200 paired with a lower-role HTTP 200 error envelope was classified as an observed failure. Status-only observations now return inconclusive.
- One export operation without metadata produced four findings across endpoint/export representations. Missing fields now produce questions; explicit negative declarations remain hypotheses. Duplicate representations are grouped by operation and invariant.
- Broad library predicates could match legitimate capabilities. Relevant mechanisms now require applicable product-rule context; weak signals remain investigation prompts. Permitted coupon stacking and bulk access are counterexamples, not vulnerabilities.

Baseline: **1,464 Python tests passed, 2 skipped, 653 subtests passed**, with two existing TLS deprecation warnings. The original `.venv` had no pytest. Secure tests used a private, non-symlinked temporary directory and a copied virtual environment.

Export entitlement was the smallest complete slice because the existing runner already supported isolated plan roles and bounded read pairs. Trial eligibility and usage accounting require lifecycle/ledger behavior; this change models those sequences without pretending to execute them.

## What changed

`business_rules.py` describes motivation, actor/capability, intended rule/source, preconditions, invariant, observations, safe boundary, remedy, regression and coverage gaps. ProductModel accepts declared rules and ordered lifecycle actions. Unknown, customer-declared, inferred, observed and verified states are separate from severity and execution disposition. Input declarations and modeled sequences cannot certify behavior.

Static review, guided answers, JSON/Markdown exports and browser presentation preserve uncertainty. Customer answers establish declarations. Persona traits and economic impact are explicitly assumptions. Alternate library encodings share mechanism labels; OpenAPI is one input. AI/agent abuse remains optional.

The reference product performs a real session/account lookup and export-license check before serialization. The vulnerable case omits that check; the hardened case enforces it. Heel observes serialized content rather than reading a “control present” property. An entitled positive control and exact protected marker are mandatory. Public/redacted responses, HTTP-200 denials and missing positive controls have distinct outcomes.

The existing signed compiler/executor, grants, stop handling, budgets, replay protections and private evidence store carry the reference execution. The public reference entrypoints accept no URL, customer credentials or transport override. Calls invoke the synthetic handler in process: no socket, DNS, TLS, production target, payment, extraction or resource exhaustion. Production HTTPS restrictions were retained.

Reports retain predicate observations and local evidence references. Raw evidence stays local. Disclosure remains separate. The app displays a bounded imported summary without uploading it; it does **not** authenticate an imported report. Reference signing keys are ephemeral and the local authority is not cloud-trusted.

## Verification record

Validation logs are retained in [business-abuse-validation](business-abuse-validation/).

| Check | Result |
| --- | --- |
| Full Python suite, `HEEL_REQUIRE_STANDARD_BUILD=1`, private TMPDIR | 1,491 passed; 653 subtests passed; no skips; two existing TLS deprecation warnings |
| Final report-count correction plus regression/packaging checks | 43 passed; 26 subtests passed |
| Frontend unit tests | 197 passed |
| TypeScript and ESLint | Passed |
| Production build and Node artifact/security tests | Build completed; 70 passed in isolated app copy with real dependency directories |
| Browser wheel, browser sample, open-core archive freshness | Passed |
| Installed wheel `[runner]`, isolated Python imports | CLI prepare/scope/vulnerable/hardened/HTTP-200 denial/inconclusive passed; replay and missing scope rejected |
| Actual MCP stdio lifecycle | initialize, initialized, tools/list, prepare and authorized execute passed |
| SaaS smoke | Passed: signup, synthetic run, target proof, scope gate, disabled payments, kill switch and metrics |
| Synthetic held-out TEST, 199 authored weaknesses | Localization 0.417; attribution 0.251; precision 0.976. Vocabulary matching only, not live accuracy |
| Whitespace/diff checks | Passed |

The first worktree frontend build failed because the existing `node_modules` symlink correctly triggered runtime containment. Its Node run had 64 passes and six environment/stale-artifact failures. An isolated copy with real dependency directories passed all 70 after rebuilding. Its copied npm launcher needed direct invocation of `node node_modules/vinext/dist/cli.js build`; the safeguard was not changed. These checks used Node 25.9.0, not the documented Node 26 gate. A clean npm dependency installation, interactive browser acceptance and production deployment were not performed.

An intermediate full Python run had one outdated documentation assertion requiring the removed “production-ready” phrase. It was replaced with an assertion that the README limits readiness to the supported reference. Other baseline expectation changes reflect the reproduced false positives and new evidence requirements, not relaxed authorization checks.

## Demo and limits

Follow [the runnable demo](../EXPORT_DEMO.md). Expected sequence: vulnerable → `verified_violation`; hardened → `invariant_held` and `regression_passed=true`; HTTP-200 denial → held with a successful positive control; missing positive control → inconclusive. Public/redacted variants and cancellation are also covered. `scripts/reference_acceptance.py` repeats the installed CLI and MCP journey from an empty private workspace.

The passing invariant covers one export read and one synthetic row. It does not establish cumulative scraping limits, usage accounting, trial eligibility, plan-change sequences, alternate access paths, customer-specific rule correctness or real-team usability. Arbitrary prose product rules are captured, not automatically compiled into executable invariants. The legacy model scorer still keeps its strongest hypothesis per operation; it is not an exhaustive count of distinct mechanisms. Historical reports remain readable and may retain older semantics. Cloud pairing and general customer-target validation are incomplete.

Next: validate export fixture setup and rule capture with a team's authorized sandbox. The next new mechanism justified by the product priorities is trial eligibility across one account lifecycle transition, backed by an explicit eligibility subject and bounded synthetic ledger. Do not expand all three families into execution systems together.

No deployment, external publication, subagents or model changes were performed.
