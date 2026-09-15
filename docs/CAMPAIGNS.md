# Business-abuse campaigns

Campaigns connect a product rule to actual HTTP observations, a saved local report and a repeatable regression. They work through the CLI and MCP. The browser `/campaigns` page prepares editable plans and inspects reports without making target requests.

## Run the complete local demo

Use the current supplied wheel or this checkout. The campaign engine uses the Python standard library. Secure storage requires POSIX.

The unpublished preview retains version 1.2.0. To update an existing installation, use `python -m pip install --force-reinstall --no-deps ./heel_sim-1.2.0-py3-none-any.whl`; otherwise pip may retain the older preview with the same version. A fresh isolated environment also works.

Terminal 1 starts a real, deliberately vulnerable, in-memory SaaS fixture on loopback:

```sh
heel campaign demo --port 8765
```

Terminal 2 creates a campaign covering all 12 rule families:

```sh
export HEEL_HOME="$PWD/.heel"
export HEEL_CANARY_OWNER=heel-canary-owner
export HEEL_CANARY_OUTSIDER=heel-canary-outsider
heel campaign template > heel-campaign.json
heel campaign prepare heel-campaign.json
heel campaign authorize heel-campaign.json --operator "me" --runs 10 --confirm
heel campaign run heel-campaign.json --scope SCOPE_ID
```

Replace `SCOPE_ID` with the authorization result. A run ID is generated automatically. Save it as the before run. The vulnerable fixture produces violations; exit code 1 is intentional.

Stop the demo with Ctrl+C and restart the same address with its actual controls enabled:

```sh
heel campaign demo --port 8765 --hardened
```

Repeat the same campaign and compare the reported run IDs:

```sh
heel campaign run heel-campaign.json --scope SCOPE_ID
heel campaign compare BEFORE_RUN_ID AFTER_RUN_ID
heel campaign report AFTER_RUN_ID --format markdown
```

The hardened fixture holds all configured rules. Each scenario has a positive fixture check and removes its synthetic state. The demo controls are in `heel/campaign_demo.py`; campaign execution crosses a real HTTP socket and observes application state rather than reading a control-presence flag.

## Test your own application

1. Inventory the sanitized API: `heel campaign discover sanitized-openapi.json`. Suggested families are vocabulary-based hypotheses, not executed tests. The output lists the bindings still required.
2. Generate one focused plan: `heel campaign template --family entitlement --origin https://staging.your-domain.com --environment staging > heel-campaign.json`.
3. Edit the plan or use the browser campaign editor. Replace demo paths with your exact routes, map isolated canary credentials to actors, and select response fields that demonstrate your intended rule. Remove demo setup/cleanup steps when your fixtures are pre-created; retain cleanup for state your test changes. No Heel source changes are required.
4. Run `prepare`, inspect every operation, and authorize that exact plan. Set the named `HEEL_CANARY_*` variables only in the local runner environment.
5. Execute, fix the application, execute again, and compare authentic reports from the same campaign. Changing the plan creates a new digest and requires new authorization. It is not an equivalent regression comparison.

For example, a read entitlement campaign can read `/api/exports/heel-canary-report` as an entitled actor and then as a lower-plan actor. The positive prerequisite can compare `/records/0/id` with `heel-canary-row`; the negative assertion can require that field to be absent. Use your real response semantics. An error, missing fixture or wrong response shape must not be mistaken for a working control.

Do not copy the fixture credentials above into a real deployment. They are public identifiers for the disposable demo, not production credentials.

## What the templates exercise

| Family | Executed rule |
| --- | --- |
| Tenant isolation | Other-tenant actor cannot obtain protected canary data |
| Role boundary | Lower-privilege actor cannot obtain administrator data |
| Entitlement | Lower-plan actor cannot obtain paid export value |
| Trial eligibility | Identity change does not reset a stable subject's trial allowance |
| Promotion limits | Different promotions cannot exceed the same subject's benefit allowance |
| Usage accounting | UI and API consumption both increment the authoritative meter |
| Quota | Two bounded attempts cannot consume more than the fixture allowance |
| Lifecycle | Downgrade removes access on subsequent reads |
| Idempotency | Repeating one request key grants a benefit once |
| Workflow order | Fulfillment cannot precede approval |
| Integration scope | A limited integration cannot read owner-only data |
| Agent actions | A delegated agent cannot obtain owner-only capability results |

Read families share the same differential mechanism; category labels are not independent detection algorithms. Trial, promotion, metering, quota, lifecycle, repetition and ordering tests operate on state transitions. You can author additional scenarios in these families with the same execution and evidence model.

## Plan contract

`heel.campaign.v1` contains a name, exact origin, environment, actors, explicit mutation permission, resource limits and scenarios. `campaign prepare` validates the whole plan without network access and returns its digest-bound target.

- Actors use `anonymous`, `bearer` or fixed `X-API-Key` authentication. Authenticated actors reference a `HEEL_CANARY_*` environment variable. Inline credentials are rejected.
- Steps specify a unique ID, actor, method, exact relative path and accepted status codes. Optional JSON objects are limited to 8 KiB. The only variable substitution is `{run}`, a generated 32-character fixture identifier.
- Mutations (`POST`, `PUT`, `PATCH`, `DELETE`) require `allow_mutations=true` in the authorized plan and a `heel-canary-` fixture in the path or body. Mutation and cleanup operations are part of the same signed digest and request budget.
- Each scenario declares an intended rule, positive prerequisites, assertions and cleanup. A failed or missing prerequisite makes the scenario inconclusive and stops its remaining primary actions. Explicit `not_applicable_reason` skips a scenario visibly.
- Assertion operands refer to a prior step and a JSON pointer. Supported comparisons are equality, inequality, numeric ordering, contains/not-contains, exists/absent and bounded numeric deltas against a baseline observation. There is no executable expression language.
- Root plans are limited to 40 scenarios, 20 primary steps per scenario and 200 total requests. Responses are capped at 64 KiB; absolute request and campaign deadlines prevent slow responses from holding execution open. No concurrency or automatic retries are used.

Origin modes are canonical public HTTPS for `sandbox`/`staging`, or explicit literal `http://127.0.0.1:PORT` for local development. Loopback mode does not enable arbitrary private-network egress or change the existing cloud runner. Remote DNS must remain public and stable, connections use pinned addresses with TLS hostname verification, and redirects are rejected. Query strings, encoded paths, cookie authentication, arbitrary request headers and browser interaction are currently outside this campaign contract.

## Evidence and coverage

Outcomes are `violation`, `held`, `inconclusive` and `not_applicable`. A report records scenario rules, assertion outcomes, response status/size/timing and SHA-256 digests. Raw response bodies and credentials are not written to reports. Response content is used in memory to evaluate the declared assertions.

Each family shows configured, held and violated counts. Families with no scenarios are untested. A held result applies to those exact observations, not all actors, states or endpoints in a product. The old synthetic vocabulary benchmark is a separate metric and is not live detection accuracy.

Reports are saved under `$HEEL_HOME/campaigns/RUN_ID.json`, authenticated with the local signing key, and verified by `campaign report` and `campaign compare`. The browser validates report structure but cannot authenticate that local signature; imported results are labeled reported outcomes. Local HMAC integrity assumes the signing key remains under the operator's control. Use the existing external signing-key configuration when separating operators from data-directory writers.

The private ledger reserves the full per-run request budget before any request. Attempts remain consumed after cancellation or a crash. `--runs` authorizes a finite number of repetitions, and `--ttl` controls scope expiry. Concurrent campaigns in one Heel home are rejected. Stop with Ctrl+C; cleanup is attempted only while authorization, duration, request budget and cancellation permit it. Failed cleanup is visible and cannot silently produce a held result.

CLI exit codes: 0 for held applicable rules; 1 for observed rule violations; 2 for inconclusive/rejected/no-applicable-test runs. Comparison exits 1 for regressions and 2 for unresolved inconclusive results. These commands can be used directly as CI release checks.

## MCP

The local server exposes:

- `heel_discover_campaigns` with sanitized `openapi`.
- `heel_prepare_campaign` with an inline `campaign`.
- `heel_execute_campaign` with the same `campaign`, existing `scope_id` and fresh 32-hex `attempt`.
- `heel_get_campaign_report` with `run_id`.

No campaign authorization or scope-mutation tool exists. Authority is created out of band through the human CLI. Campaigns do not require cloud pairing or the hosted Python control plane. They do not add production-target authorization or change billing/deployment availability.
