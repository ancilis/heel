# Heel MCP and CLI quickstart

This quickstart uses a synthetic, sanitized API description. Run it after activating
the environment where the supplied Heel release artifact is installed.

## Create a local OpenAPI example

```sh
python - <<'PY'
import json
from pathlib import Path

specification = {
    "openapi": "3.1.0",
    "info": {"title": "Synthetic Projects API", "version": "1.0.0"},
    "paths": {
        "/projects/{project_id}": {
            "get": {
                "operationId": "getProject",
                "parameters": [
                    {
                        "name": "project_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {"200": {"description": "Synthetic project"}},
            }
        }
    },
}
Path("sample-openapi.json").write_text(
    json.dumps(specification, indent=2) + "\n",
    encoding="utf-8",
)
PY
```

## Review it from the CLI

```sh
heel review openapi sample-openapi.json
heel review openapi sample-openapi.json --json
```

The review runs locally and saves its result under `HEEL_HOME` (by default,
`.heel`). Set `HEEL_HOME` to a private directory if the review contains sensitive
product structure.

## Verify the MCP handshake

MCP clients should start `heel-mcp` over stdio, initialize the session, send the
initialized notification, and only then list or call tools. This command performs
that exact lifecycle and prints the JSON-RPC responses:

```sh
python - <<'PY' | heel-mcp
import json

messages = [
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "heel-quickstart", "version": "1.0"},
        },
    },
    {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    },
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
]
for message in messages:
    print(json.dumps(message, separators=(",", ":")), flush=True)
PY
```

After the handshake, call `heel_review_openapi` with a parsed OpenAPI object. Keep
the stdio stream machine-only: diagnostic text belongs on stderr, not stdout.

See [security boundaries](SECURITY.md) before using non-synthetic input.


## Synthetic export entitlement validation

The supplied wheel supports `heel reference prepare` and `heel reference run`. Install the runner extra with `python -m pip install './heel_sim-1.2.0-py3-none-any.whl[runner]'`. Then run `heel scope create --target reference:export --operator "your name" --confirm` outside MCP. Use its returned scope ID:

```sh
heel reference run --scope SCOPE_ID --case vulnerable --attempt 11111111111111111111111111111111
heel reference run --scope SCOPE_ID --case hardened --attempt 22222222222222222222222222222222
```

Each 32-hex attempt ID is consumed once. The first result is a verified synthetic protected-content violation; the second checks the fix with the same invariant. `error_envelope`, `redacted`, `public`, and `inconclusive` exercise other outcomes. `--stop` checks cancellation. Reports remain under `.heel/reference/ATTEMPT/report.json`.

MCP exposes `heel_prepare_reference` and `heel_execute_reference` (`scope_id`, `case`, `attempt`); it cannot create the required scope. The app's `/runner` page gives these instructions and reads local reports without uploading. The reference executes an actual in-process product handler through the signed local runner, not an HTTP socket. No external URL or credentials can be supplied. Cloud pairing is incomplete and `heel runner pair` is not supported.

Only one synthetic export read entitlement is validated. No trial lifecycle, usage accounting, cumulative scraping limits, real billing or production behavior is established. Static findings and library matches are hypotheses; absent metadata is unknown. No findings is not launch safety. Historical vocabulary benchmarks do not measure live accuracy.
