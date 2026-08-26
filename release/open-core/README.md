# Heel

Heel is a privacy-first local SaaS launch-review engine for browser, CLI, and MCP
workflows. It analyzes a sanitized OpenAPI document on the operator's machine and
returns ranked abuse paths, missing controls, and regression ideas. The core has no
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
