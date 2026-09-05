# Heel

Heel is a privacy-first local SaaS launch-review engine for browser, CLI, and MCP
workflows. It analyzes a sanitized OpenAPI document on the operator's machine and
returns ranked investigation hypotheses, unanswered product-rule questions, and regression ideas. The core has no
runtime dependencies and does not require an account or network connection.

## Install the supplied release artifact

Create an isolated environment, then install the wheel supplied with this release:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ./heel_sim-1.2.0-py3-none-any.whl
heel --version
```

Use only release artifacts obtained from your authorized distributor. No public
package registry or source repository is designated by this release metadata.

## Start a local review

The [MCP and CLI quickstart](MCP_QUICKSTART.md) creates a tiny sanitized OpenAPI
example and reviews it locally. Browser-based agent hosts can start `heel-mcp` as a
stdio server and invoke the same local analyzer.

`heel-mcp` itself does not upload the OpenAPI document, and Heel's local analyzer
makes no network calls. The AI client or model provider may receive or upload the
document before invoking Heel. Heel cannot enforce that upstream boundary. Review
the AI client's and model provider's data-handling settings before providing a
sensitive specification.

Heel is a launch-review aid, not a penetration-testing replacement. Review its
[security boundaries](SECURITY.md) before using customer-derived specifications or
exposing a local service.


## Synthetic export entitlement validation

The supplied wheel supports `heel reference prepare` and `heel reference run`. Install the runner extra with `python -m pip install './heel_sim-1.2.0-py3-none-any.whl[runner]'`. Then run `heel scope create --target reference:export --operator "your name" --confirm` outside MCP. Use its returned scope ID:

```sh
heel reference run --scope SCOPE_ID --case vulnerable --attempt 11111111111111111111111111111111
heel reference run --scope SCOPE_ID --case hardened --attempt 22222222222222222222222222222222
```

Each 32-hex attempt ID is consumed once. The first result is a verified synthetic protected-content violation; the second checks the fix with the same invariant. `error_envelope`, `redacted`, `public`, and `inconclusive` exercise other outcomes. `--stop` checks cancellation. Reports remain under `.heel/reference/ATTEMPT/report.json`.

MCP exposes `heel_prepare_reference` and `heel_execute_reference` (`scope_id`, `case`, `attempt`); it cannot create the required scope. The app's `/runner` page gives these instructions and reads local reports without uploading. The reference executes an actual in-process product handler through the signed local runner, not an HTTP socket. No external URL or credentials can be supplied. Cloud pairing is incomplete and `heel runner pair` is not supported.

Only one synthetic export read entitlement is validated. No trial lifecycle, usage accounting, cumulative scraping limits, real billing or production behavior is established. Static findings and library matches are hypotheses; absent metadata is unknown. No findings is not launch safety. Historical vocabulary benchmarks do not measure live accuracy.
