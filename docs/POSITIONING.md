# Positioning

Arceo is not a replacement for penetration testing, AppSec scanners, functional QA,
fraud/bot platforms, runtime WAF/API protection, Trust & Safety manual review, or
model red-team tools. Those programs answer important questions that Arceo should not
try to own.

Arceo fills the missing product-abuse rehearsal step. It asks whether intended
features, legitimate customer paths, pricing and entitlement rules, workflows,
integrations, and agent tools can be misused before or after launch. The output is a
safe contained proof, ranked severity, and a recommended control.

## The Missing Step

Adjacent tools usually ask whether the system is built correctly, protected at
runtime, or reviewed after suspicious activity appears. Arceo asks a different
question: can a normal product capability be used in a way the business did not
intend?

This includes:

- abuse of intended features.
- legitimate customer misuse.
- business-logic gaming.
- pricing/entitlement/workflow exploitation.
- integration abuse.
- agent/tool overreach.
- safe contained proof before or after launch.

## Comparison

| Tool category | Primary question | When it runs | Typical signal | What it misses | How Arceo complements it |
|---|---|---|---|---|---|
| penetration testing / AppSec scanners | Is there an exploitable implementation flaw or known vulnerability? | Periodic assessments, pre-release checks, CI, and security reviews | Vulnerability findings, CVEs, injection paths, unsafe implementation behavior | Legitimate customer actions that exploit pricing, entitlement, workflow, export, or integration rules without a software bug | Rehearses product-abuse paths and hands true software vulns to AppSec instead of competing with it |
| functional QA | Does the expected workflow work as specified? | During feature development, release testing, and regression cycles | Passing user stories, UI flows, API contract checks, and acceptance tests | Whether a working feature can be overused, chained, or used by the wrong customer segment | Uses canary scenarios to ask how valid features can be gamed after QA proves they function |
| fraud/bot platforms | Should live traffic, accounts, or transactions be allowed, challenged, or blocked? | Runtime, after traffic and behavior signals exist | Risk scores, velocity rules, device signals, bot scores, chargeback or abuse telemetry | Abuse paths before traffic appears, new launch flows without history, and product controls that should exist upstream | Rehearses likely abuse before runtime signals accumulate and turns incidents into canary regressions |
| runtime WAF/API protection | Should this request be blocked or rate-limited at the edge? | Runtime, inline with requests | Signature matches, API anomaly signals, request rate, protocol violations | Business-logic misuse made of valid requests and normal product operations | Identifies where product-level entitlements, limits, approval gates, and audit controls should be added |
| Trust & Safety manual review | Is this content, account, seller, buyer, or user action policy-violating? | Queue-based review after reports, model flags, or policy triggers | Case decisions, policy labels, enforcement history, reviewer notes | Pre-launch product mechanics that create review volume or enable policy abuse at scale | Rehearses workflow and incentive abuse so product controls reduce manual-review burden |
| model red-team tools | Can the model be jailbroken, steered into unsafe content, or made to violate model policy? | Model evaluation, safety testing, and prompt/application review | Jailbreak transcripts, policy eval scores, unsafe generations | Downstream business consequences of agent tools, permissions, retrieval, billing, and workflow actions | Hands pure jailbreaks to model red-team and rehearses agent/tool overreach in product context |

## Export Example

QA says export button works. AppSec says endpoint has no injection bug. Fraud platform may catch abuse after traffic appears.

Arceo asks whether the export business flow can be used by a trial user to harvest more data than intended. The rehearsal stays canary-only: it checks entitlement,
row-cap, rate-limit, tenant-scope, approval, and audit-log controls without real
exfiltration or third-party targeting.

That is why Arceo complements adjacent tools. It does not replace them; it turns
product-abuse questions into safe rehearsal scenarios before the only signal is a
customer, attacker, or opportunistic user discovering the path first.
