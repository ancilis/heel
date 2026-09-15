# Holistic abuse implementation — September 15, 2026

Branch: `codex/holistic-abuse`, based on `ancilis/heel` main at `844fc1f40717b0012a80573ba7848befa273d22b`.

## Delivered behavior

Heel now supports operator-configured business-abuse campaigns against owned HTTP sandboxes, rather than restricting the executable public workflow to the built-in export handler. This work follows the owner's direction to build a useful personal product without design-partner or product-market-fit gates.

- Strict campaign manifests declare actors, intended rules, exact actions, positive prerequisites, cross-step assertions, cleanup and resource budgets.
- Twelve configurable families cover tenant, role and entitlement boundaries; trials and promotions; usage accounting and quotas; entitlement transitions; idempotency and workflow order; integration and delegated-agent permissions.
- OpenAPI discovery suggests families and lists missing bindings. It does not infer or certify business intent.
- Local CLI and MCP execute real HTTP requests under a human-created scope bound to the entire canonical campaign digest. The local workflow requires no cloud pairing.
- Evidence reports retain outcomes, status/size/timing and response hashes, not credentials or raw response bodies. Local signatures authenticate stored reports and same-campaign comparisons identify fixes, regressions and inconclusive results.
- The browser `/campaigns` workspace builds editable plans and inspects local reports with outcome filters and explicit untested coverage. Browser report viewing does not authenticate local signatures.
- The independent, disposable HTTP demo implements both vulnerable and defended product controls. Installed CLI/MCP acceptance exercised all 12 configured rules and cleanup across an actual socket.

See [the operator guide](../CAMPAIGNS.md) for the complete workflow and application mapping instructions.

## Review defects corrected

1. Negative guided answers now become declared control gaps consumed by static analysis, while remaining hypotheses.
2. Permitted bulk access no longer hides a separately declared paid entitlement requirement.
3. Required-plan metadata no longer stands in for an enforcement declaration.
4. Removed controls appear in release diffs as qualified investigations.
5. Guided answers support 512 selections and a consistent 256 KiB boundary, with the UI exposing the selection limit.

Additional campaign checks cover digest changes, one-shot attempts, total scope budget, distinct actor credentials, authorization expiry during rate waits, absolute response deadlines, cancellation, redirects, unsafe origins, missing prerequisites, inline credentials and fixture expansion limits.

## Validation

| Gate | Final result |
| --- | --- |
| Full Python suite, mandatory standard-build integration enabled | **1,524 passed; 653 subtests passed; no skips** |
| Frontend unit suite | **206 passed** |
| TypeScript and ESLint | Passed |
| Node 26 browser/runtime/privacy/artifact suite | **70 passed** |
| Production builds | CI/full configuration and actual private local-review configuration built successfully |
| Deterministic browser wheel, sample and Agent artifacts | Freshness checks passed |
| Final installed-wheel CLI and real MCP stdio acceptance | 12 vulnerable violations; 12 hardened held rules; 12 fixed comparisons; 12 MCP held rules; zero leftover fixtures |
| Runtime dependency check | Campaign imports and templates worked with site-packages disabled |
| Deployed acceptance | `/campaigns`, `/agent`, manifest and wheel returned HTTP 200; deployed manifest/wheel exactly matched local candidate bytes |

Two existing TLS deprecation warnings remain. Two oversized-body tests intermittently raced server rejection against client upload on macOS. Their oversized cases now assert rejection from the declared content length without transmitting the already-rejected body; the at-limit upload and rejection assertions remain intact. No server limit was relaxed.

An artifact test's existing bounded Python compressor timed out once while checks competed for local resources. The complete 70-test suite passed serially with the same timeout and security assertions. That suite expects the CI fixture origin and was run against the corresponding build. The actual private-origin build was packaged and verified separately.

No interactive browser walkthrough was performed. No external customer application, production target, real payment or load-exhaustion path was exercised.

## Private deployment

- URL: https://heel-agent-first-private.hellostella.chatgpt.site/campaigns
- Audience: owner-only; one allowed account, no groups, no external visitors.
- Sites version: **7**.
- Sites source commit: `84eab7178fea5500ff57ff8230f5e81500765406`.
- Version ID: `appgprj_6a7367fb10d081919d924022266edf67~appgver_2969ed7732808191b593e5d47bef2841`.
- Deployment ID: `appgdep_6aa9d3c1d90481918799fe203cf7595f`.
- Successful publication: `2026-09-15T23:25:26.653303+00:00`.
- Archive SHA-256: `2b0ccdb160d42c2c4ebdf4c4558f9e3a3aeabcf5d84d50cfcced751ca0936e15`.

The existing audience, runtime environment and local-review deployment mode were preserved. This publishes the browser workspace and downloads, not the Python cloud control plane. Earlier versions remain available for rollback.

## Practical boundaries

Rules, routes, actors, fixtures and observation fields must be configured for the application. The implementation is a bounded API campaign engine, not an assertion that every possible form of product abuse is covered. Cookie authentication, query strings, encoded routes, browser automation, concurrent race/load testing and automatic business-rule inference are outside this campaign contract. Existing cloud pairing remains separate and incomplete.

The unpublished Agent preview retains version 1.2.0. Existing installations must use the documented `--force-reinstall` command or a fresh environment to obtain the new commands.

Validation logs and the installed acceptance summary are retained locally in `/Users/hellohelloalbus/heel-launch/reviews/2026-09-15/`. The original review drafts in the main worktree were preserved.
