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
