# Heel local-agent and MCP quickstart

Heel's Local Agent Alpha reviews an OpenAPI JSON document on your machine and returns a
validated `heel.review.v1` result. It requires no Heel Cloud account and makes no network calls.
It uploads nothing and has no sync path. Successful reviews are saved only below the private
`HEEL_HOME` directory you choose.

Your OpenAPI input must not contain credentials or customer data. Use a sanitized product
definition even though the analyzer stays local. The input must be a regular, non-symlink
UTF-8 JSON file no larger than 2 MiB.

## Install the current Agent

The primary acquisition path is Heel Cloud's `/agent` page. Choose **Download Heel Agent 1.1.1**;
the same-origin wheel is `/downloads/heel_sim-1.1.1-py3-none-any.whl`. In the directory where you
saved it, run:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install ./heel_sim-1.1.1-py3-none-any.whl
```

The wheel, `heel_sim-1.1.1.tar.gz`, and `heel-open-core-manifest.json` are already part of the
deployable Heel Cloud build. Public customer access still depends on the approved deployment.
`heel-sim` is not yet published to PyPI, and the current public repository export is a release-owner
action that is not complete. Maintainers may install from this private source checkout, but customer
instructions must not rely on it. Only after an actual PyPI release will this registry command work:

```bash
python3 -m pip install heel-sim
```

Python 3.11 or newer is required. The hardened local review store requires a POSIX filesystem with
descriptor-relative operations and no-follow support. Windows secure local project storage is not
supported at launch; Windows customers can use the isolated browser workspace or a supported POSIX
environment.

The base local CLI/MCP is Apache-2.0 and has no commercial usage limit; technical input and safety
limits still apply. Hosted findings synchronization and remote MCP are paid Heel Cloud features and
are not part of the local Apache package.

## Review from the CLI

Set `HEEL_HOME` to a private absolute path whose parent directories are not symbolic links,
then review a sanitized OpenAPI JSON file:

```bash
export HEEL_HOME="$PWD/.heel-local"
.venv/bin/heel review openapi ./sanitized-openapi.json
```

The default output is validated Markdown. For a canonical machine-readable envelope:

```bash
.venv/bin/heel review openapi ./sanitized-openapi.json --json
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

On macOS, use the resolved absolute path (for example `/private/var/...`, not the `/var` symlink)
when placing `HEEL_HOME` outside the current directory.

## Verify the release as a maintainer

From this private source checkout, the canonical gate checks the committed same-origin bytes,
rebuilds through the standard packaging frontend, clean-installs both distributions, and completes
the initialized MCP lifecycle. Run it with Python 3.13, matching the release workflow:

```bash
env PIP_CONFIG_FILE=/dev/null PYTHONNOUSERSITE=1 \
  python3.13 -m pip --isolated install \
  --require-hashes --only-binary=:all: \
  -r release/requirements-release.txt
python3.13 scripts/build_open_core_release.py \
  --output apps/heel-cloud/public/downloads --check
HEEL_REQUIRE_STANDARD_BUILD=1 \
  python3.13 -m unittest tests.test_open_core_release -v
```
