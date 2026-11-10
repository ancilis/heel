# Heel local-agent and MCP quickstart

Heel's Local Agent Alpha reviews an OpenAPI JSON document on your machine and returns a
validated `heel.review.v1` result. It requires no Heel Cloud account and makes no network calls.
It uploads nothing and has no sync path. Successful reviews are saved only below the private
`HEEL_HOME` directory you choose.

Your OpenAPI input must not contain credentials or customer data. Use a sanitized product
definition even though the analyzer stays local. The input must be a regular, non-symlink
UTF-8 JSON file no larger than 2 MiB.

## Install the current Agent

The current public Agent is the 1.3.0rc2 runner preview, published as a public GitHub prerelease at
<https://github.com/ancilis/heel/releases/tag/v1.3.0rc2>. It is a preview, not a stable release.
Its GitHub release record is not immutable. It is not a deployed Heel Cloud URL and does not indicate
customer acceptance. No source checkout, manual download, or Heel Cloud deployment is needed to
install it. You need a POSIX shell and Python 3.11 or newer as `python3` with its standard `venv`
module, on Apple silicon macOS or Linux x86_64/aarch64. Intel macOS is unsupported by this preview:
its pinned `cryptography` dependency ships no Intel macOS wheel, and a source build needs an
additional (Rust) toolchain and is untested. In an empty private directory, this one copy-paste
command creates a virtual environment in `./heel-rc2`, installs the hash-pinned public wheel with its
`runner` extra, and prints `heel 1.3.0rc2`:

```bash
python3 -m venv heel-rc2 && ./heel-rc2/bin/python -m pip --isolated install 'heel-sim[runner] @ https://github.com/ancilis/heel/releases/download/v1.3.0rc2/heel_sim-1.3.0rc2-py3-none-any.whl#sha256=f8698204e1d38aa80b8ca31dedd743c3d42e28d02c5153bddb4f02b44ecdf01c' && ./heel-rc2/bin/heel --version
```

The CLI is then `./heel-rc2/bin/heel` and the stdio MCP server is `./heel-rc2/bin/heel-mcp`. pip
installs the public wheel only if it matches that SHA-256. `--isolated` makes pip ignore environment
variables and user configuration. The `runner` extra, which the optional synthetic
[export reference](EXPORT_DEMO.md) needs, downloads the pinned `cryptography` dependency from the
Python package index under pip's normal verification; this command does not hash-pin it. The local
review and MCP tools below do not need it. An independent anonymous run of this exact command passed
on Apple silicon macOS with Python 3.13.5; other platforms and Python versions have not been
clean-room tested.

1.3.0rc2 corrects two errata of the earlier 1.3.0rc1 prerelease, which remains published and
unchanged at <https://github.com/ancilis/heel/releases/tag/v1.3.0rc1>: its synthetic reference
reports the HTTP 200 `error_envelope` case and the HTTP 403 `hardened` case, both error responses, as
passed regressions; read those rc1 results as inconclusive. 1.3.0rc2 reports both cases as
inconclusive with regression_passed=false (see the [export reference](EXPORT_DEMO.md)).

A Heel Cloud build from this repository also bundles Agent files on its own origin:
`heel_sim-1.3.0rc3-py3-none-any.whl`, `heel_sim-1.3.0rc3.tar.gz`, and
`heel-open-core-manifest.json`. They are that build's artifacts, not a separate verified public
release: in this repository they are the 1.3.0rc3 candidate, which is not yet published as a public
release, and public customer access to them still depends on the approved deployment. The public
command above is the recommended install. If you did download the wheel from a deployment's `/agent`
page (`/downloads/heel_sim-1.3.0rc3-py3-none-any.whl`), run this in the directory where you saved it
and use `.venv` in place of `heel-rc2` below:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install ./heel_sim-1.3.0rc3-py3-none-any.whl
```

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

Set `HEEL_HOME` to a private absolute physical path in which no component is a symbolic link,
then review a sanitized OpenAPI JSON file. `pwd -P` prints the physical working directory:

```bash
export HEEL_HOME="$(pwd -P)/.heel-local"
./heel-rc2/bin/heel review openapi ./sanitized-openapi.json
```

The default output is validated Markdown. For a canonical machine-readable envelope:

```bash
./heel-rc2/bin/heel review openapi ./sanitized-openapi.json --json
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
`heel-mcp` with the absolute path to `heel-rc2/bin/heel-mcp`. Restart the MCP client after
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

On macOS, `/tmp` and `/var` are symbolic links to `/private/tmp` and `/private/var`, and `$TMPDIR`
is below `/var`. Use the resolved physical path from the first command, for example
`$(pwd -P)/.heel-local` or `/private/var/...`. A command that does not open private storage, such as
`heel scope create`, can succeed with a `HEEL_HOME` that passes through them, and that success does
not show the path is safe: opening the private runner and reference storage refuses it. Heel refuses
symbolic links in private storage on purpose; do not disable or work around that check. For a generic
`Reference rehearsal rejected` message from the optional export reference, follow the
[troubleshooting steps](EXPORT_DEMO.md#if-the-reference-run-is-rejected). That message does not
always mean a storage-path problem.

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
