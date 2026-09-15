# Current capabilities — September 15, 2026

Heel discovers hypotheses about customers extracting excess product value, evading commercial rules, or imposing costs. Customers include free/paying users, tenant administrators, agencies, integrations and coordinated accounts. OpenAPI is one source of product structure; product rules and lifecycle context require additional declarations. AI/agent abuse is an optional surface.

| Workflow | Current support | Evidence and limits |
| --- | --- | --- |
| OpenAPI / ProductModel review | CLI, browser worker, MCP | Static hypotheses and unanswered questions; absent metadata is unknown |
| Explicit product rules | ProductModel optional business_rules | Statement, source, evidence state; customer answers are declarations; arbitrary prose rules are not compiled into tests |
| Trial / promotion eligibility | Local stateful campaigns plus static library | Bounded identity/eligibility and benefit-ledger checks with explicit fixtures; no real payments |
| Usage / expensive features | Local stateful campaigns | Compare aggregate counters across explicitly mapped operations; no load or resource-exhaustion testing |
| Export read entitlement | Reference plus configurable local HTTP campaigns, CLI/MCP and browser plan/report workspace | Explicit positive control and protected-content assertions over bounded responses |
| Export bulk access / automation limits | Static investigation | A read entitlement result does not verify scraping, throughput or usage accounting |
| Plan downgrade / alternate-path lifecycle | Explicit local HTTP campaigns and ordered models | Campaigns execute approved transitions; model-only sequences remain unexecuted |
| Tenant / role / integration / agent boundaries | Configurable local HTTP campaigns; original four runner primitives retained | Requires application-specific actors, fixtures and assertions; missing observations remain inconclusive |
| Cloud pairing | Incomplete public journey | Local campaigns connect owned sandboxes independently; no `heel runner pair` command is advertised |
| Cloud account / findings continuity | Implemented separately | Does not constitute a completed live validation journey; production acceptance remains separate |
| Economic/persona analysis | Assumptions | No measured customer motives, incident rates or dollar impact |
| Synthetic vocabulary evaluation | Repository and supplied wheel | Measures model matching, not live detection accuracy; revised predicates change old scores |

Evidence states are independent of severity and execution disposition: unknown (unanswered), customer_declared (intended rule/control), inferred (hypothesis), observed (raw local response), verified (the exact invariant was established). Static review cannot encode verified behavior. Historical review records remain readable with their original schema; they may contain older, weaker claims.

A metadata gate named `pass` means only no matching static warning. It is not complete coverage, release approval, or evidence of launch safety. The reference's `invariant_held` means the protected marker was absent on that one lower-plan read with a successful positive control.

## Reference acceptance boundary

The reference product implements a session-to-account lookup and checks `export_license` before serializing protected content in its hardened configuration. The vulnerable configuration omits that check. Error/public/redacted cases change actual output, not control-presence properties for Heel to inspect. Reference calls invoke this handler in process: no HTTP socket, DNS, TLS, or customer deployment is exercised. The real HTTPS runner restrictions remain unchanged; there is no `allow-localhost`, arbitrary URL or injected transport option in the public reference entrypoints.

The reference signs an ephemeral local sandbox grant, uses the existing compiler, executor, private evidence store and one-shot reservation defenses, and discards reference signing keys at process exit. It does not mint a cloud-trusted target verification record. Replays of a supplied attempt ID are rejected. Raw synthetic evidence stays local; standalone report viewing does not authenticate an imported report's signature. Cloud disclosure remains a separate authorized workflow and is not part of this reference demo.

The separate [campaign workflow](CAMPAIGNS.md) now executes declared rules across 12 families, including bounded lifecycle and ledger checks. Operators map their own application routes and response fields. Its actual-HTTP fixture is an acceptance tool, not evidence that every customer workflow is covered. The original reference boundary above remains unchanged.

## Campaign coverage and limits

`heel campaign discover` suggests families from sanitized OpenAPI vocabulary. `template` creates editable examples; `prepare` validates their exact actions and reports configured/unconfigured families. Human `authorize` binds the entire plan digest and request allowance. CLI/MCP execution observes HTTP responses and state transitions; reports distinguish violation, held, inconclusive and not applicable. `compare` verifies local report signatures and compares only the same campaign digest.

Browser `/campaigns` authoring/report inspection is local-only. Target execution uses the installed runner, bearer or fixed API-key canary actors, exact paths and bounded JSON. Canonical public HTTPS and explicit literal loopback are supported. Cookie auth, query strings, arbitrary headers, encoded routes, browser automation, automatic inference of business intent and production probing are not part of this contract. Scenario coverage is configured and observed, never inferred from the 120-entry static library count.
