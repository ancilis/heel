# Owner-private deployment — September 5, 2026

Deployed successfully to **https://heel-agent-first-private.hellostella.chatgpt.site**.
Access remains owner-only: one explicitly allowed owner, no groups or external visitors.
This is a private Sites publication, not a public SaaS launch or deployment of the
Python control plane.

## Release identity

- GitHub implementation commit on `main`: `0f0feff362a6cbfc9f10a31ef133eb1a856cd1c8`.
- Sites application-source commit: `b39b079a83cf831025ba0779e4922a1d16840a70`.
- Site project: `appgprj_6a7367fb10d081919d924022266edf67`.
- Saved version: 4, `appgprj_6a7367fb10d081919d924022266edf67~appgver_83111a110d348191be03b528990ca45e`.
- Deployment: `appgdep_6a9b9e9b02e48191b28b7a59f4d50b59`, succeeded at `2026-09-05T04:46:32Z`.
- Archive SHA-256: `729ba0a3750333d062e9164e25d11eb1421a2b2d87a39cbb226a0a24ef22dce6`.
- Runtime environment revision: 1; only the nonsecret `PUBLIC_ORIGIN` was added.

The Sites source checkout is rooted at the application, rather than the unrelated
parent repository layout previously stored there. GitHub retains the complete Heel
repository. Neither repository was force-pushed.

## Deployment behavior

The new explicit `HEEL_DEPLOYMENT_MODE=local_review` emits no `CONTROL_PLANE` binding.
It rejects a supplied private VPC service ID. The default `full` mode still requires
its original private-service and canonical-origin configuration. No dummy VPC ID was
deployed. Account/sync APIs remain unavailable without a configured private backend.

The site offers local review, the installed Agent download and export-reference
onboarding/report viewing. CLI/MCP execute the synthetic reference customer-locally;
the website does not execute customer-target probes. Cloud pairing and cumulative
usage/trial execution remain unsupported. The publication does not change these claims.

## Validation

- Fresh full Python suite: 1,491 passed, 653 subtests passed, no skips; two existing
  TLS deprecation warnings.
- Frontend: 202 unit tests passed; typecheck and lint passed.
- Node 26.8.1: all 70 browser/runtime/artifact/security checks passed.
- Full-mode test build and actual owner-private local-review build both completed.
- Browser wheel and open-core archive freshness checks passed.
- SaaS smoke passed, including scope rejection, disabled payments and kill switch.
- Authenticated deployed GETs of `/`, `/runner`, `/agent`, and the downloadable
  manifest returned HTTP 200 and expected content.
- The deployed manifest equals the committed manifest. The downloaded wheel's SHA-256
  equals the wheel committed on `main`.

Node 26 uses a different compression implementation from the Python release builder.
The artifact verifier now uses the builder's Python compressor for exact canonical-byte
comparison, with bounded subprocess output and timeout. This retains the rejection of
noncanonical streams and avoids enormous assertion diffs. No transport safeguard changed.

The first hosted Scorecard run failed before analysis because the old GCR action image
was unavailable. Its workflow was updated to the official v2.4.4 action at the immutable
commit `2d1146689b8cda280b9bc96326124645441f03bc`, whose image is hosted on GHCR.
Hosted CI/CodeQL/Scorecard outcomes are available on the corresponding `main` commit;
local test completion does not substitute for those hosted outcomes.

## Rollback and remaining work

The prior Sites versions remain available for rollback. Keep owner-private access
and select a previous saved version if the new application causes a regression.
No private database, credentials or deployment topology was changed.

Next product work remains sandbox-based export fixture/rule capture, then one bounded
trial-eligibility lifecycle with an explicit eligibility subject. Public access,
production cloud control-plane setup and arbitrary customer-target validation require
additional implementation and operational evidence.
