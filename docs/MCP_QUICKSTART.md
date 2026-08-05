# Heel local-agent and MCP quickstart

Heel's Local Agent Alpha reviews an OpenAPI JSON document on your machine and returns a
validated `heel.review.v1` result. It requires no Heel Cloud account and makes no network calls.
It uploads nothing and has no sync path. Successful reviews are saved only below the private
`HEEL_HOME` directory you choose.

Your OpenAPI input must not contain credentials or customer data. Use a sanitized product
definition even though the analyzer stays local. The input must be a regular, non-symlink
UTF-8 JSON file no larger than 2 MiB.

## Install honestly

`heel-sim` is not yet published to PyPI. Choose the command that matches what you have:

From the current source checkout:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install .
```

From a wheel you have already built or downloaded from a project release:

```bash
python3 -m pip install ./dist/heel_sim-1.1.0-py3-none-any.whl
```

Only after `heel-sim` is published to PyPI will this be the normal registry install:

```bash
python3 -m pip install heel-sim
```

Python 3.11 or newer is required. The hardened local review store currently requires a
POSIX filesystem with descriptor-relative operations and no-follow support.

## Review from the CLI

Set `HEEL_HOME` to a private absolute path whose parent directories are not symbolic links,
then review a sanitized OpenAPI JSON file:

```bash
export HEEL_HOME="$PWD/.heel-local"
.venv/bin/heel review openapi tests/fixtures/openapi/saas_api.json
```

The default output is validated Markdown. For a canonical machine-readable envelope:

```bash
.venv/bin/heel review openapi tests/fixtures/openapi/saas_api.json --json
```

Both formats come from the same pure review service and validated exporters used by MCP.
On success, the canonical JSON result is stored at
`$HEEL_HOME/reviews/<review_id>.json`. The command does not create an authorization scope,
signing key, database, account, or network connection.

## Connect an MCP client

After `heel-mcp` is available on the client application's `PATH`, use the standard stdio
server configuration shape:

```json
{
  "mcpServers": {
    "heel": {
      "command": "heel-mcp",
      "env": {
        "HEEL_HOME": "/absolute/path/to/private/heel-data"
      }
    }
  }
}
```

If the desktop client does not inherit your virtual environment's `PATH`, replace
`heel-mcp` with the absolute path to `.venv/bin/heel-mcp`. Restart the MCP client after
changing its configuration.

The local review tool is `heel_review_openapi`. Its arguments contain the parsed OpenAPI
object, not a filename:

```json
{
  "name": "heel_review_openapi",
  "arguments": {
    "openapi": {
      "openapi": "3.1.0",
      "info": {"title": "Example SaaS", "version": "1.0.0"},
      "paths": {}
    }
  }
}
```

The MCP tool and `heel review openapi ... --json` return the same deterministic
`heel.review.v1` envelope for the same document. MCP also persists that result below the
configured `HEEL_HOME`. The MCP server exposes review-consumption tools but no scope creation,
widening, or relaxation tool.

## Verify the install

From a source checkout, the release smoke builds from a clean tracked-file snapshot, inspects
the wheel, installs it into a temporary virtual environment, and exercises both installed
entry points:

```bash
make release-smoke
```

A passing run ends with:

```text
release smoke: PASS (clean wheel, installed CLI, installed MCP)
```
