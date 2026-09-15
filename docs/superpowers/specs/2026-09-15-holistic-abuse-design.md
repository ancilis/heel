# Holistic abuse campaigns

Build direction: extend Heel into a personal, useful abuse-testing product. Customer discovery, design partners and commercial launch gates are not prerequisites.

## Architecture

Keep the static review and signed read runner; add a local campaign engine for explicit business-rule tests against owned sandbox applications. A campaign declares origin, canary actors, exact bounded operations, rule assertions, positive controls, cleanup and applicability. Human authorization binds the canonical campaign digest and total request budget. CLI/MCP can execute approved campaigns but cannot authorize or widen them.

Campaign families cover tenant/role/plan access, trials, promotions, cumulative usage, quotas, entitlement transitions, idempotency, workflow order, integrations and agent actions. JSON response assertions and comparisons across steps provide a general rule mechanism. A scenario label alone does not imply tested coverage. Missing evidence, failed prerequisites and unsupported cases remain explicit.

Network execution uses HTTPS with public-address validation and pinned connections. An explicitly authorized loopback sandbox mode supports local development without changing existing cloud runner safeguards. Credentials are environment references, never embedded plan values or report data. Requests are sequential, rate/time/body bounded, never automatically retried, and stopped on throttling. Only explicitly approved mutations can run. Cleanup runs within the same budget and scope. One-shot attempt reservation, signed local report integrity and scope-budget accounting prevent silent replay.

The browser gets a campaign builder and local report explorer. It prepares files and commands, shows coverage and evidence outcomes, and does not proxy target traffic or ask users to paste credentials. CLI exports reports and compares repeat runs for regressions. A runnable local HTTP SaaS fixture independently enforces commercial rules so acceptance crosses a real socket and varies product behavior.

## Review fixes

Normalize negative answers into declared control gaps; separate plan intent from enforcement; scope bulk exceptions; include deleted controls in diff review; provide sufficient bounded guided-answer capacity with visible limits.

## Acceptance

Each new rule family has vulnerable and defended HTTP fixtures. Tests cover unrelated public behavior, auth failure, missing/malformed evidence, mutation approval, redirects, private egress rejection, changed plan digest, scope expiry, replay, budget consumption, cancellation and cleanup. CLI/MCP and browser entrypoints are tested. Full existing suites, artifact freshness and release installation are verified before completion. No public deployment is part of this change.
