# Heel Cloud

The commercial Heel customer application. This anonymous milestone ships an
evidence-first browser workspace: a real committed finding is visible on first
render, and a visitor can run the sanitized sample or paste/drop an OpenAPI JSON
document without an account. The canonical Python engine runs in a dedicated Web
Worker from an integrity-pinned, same-origin Pyodide runtime and Heel wheel.

Raw OpenAPI source and guided answers remain in component/worker memory. They
are never uploaded, synchronized, placed in a URL, or written to durable browser
storage. A visitor may explicitly save only a validated result envelope in that
device's IndexedDB and export validated JSON or Markdown locally. The analyzer
makes zero network calls after its same-origin runtime assets are loaded.

This is a private acceptance preview. It is not a claim that the public browser
alpha is deployed or launch-ready: interactive browser acceptance, explicit
public-access approval, and public deployment remain separate gates. This
milestone has no authentication, cloud save, hosted review API, server customer
persistence, database, object storage, billing, analytics, or error-reporting
SDK.

The deployable app already includes the exact verified Agent files advertised on `/agent`:

- `/downloads/heel_sim-1.1.1-py3-none-any.whl`
- `/downloads/heel_sim-1.1.1.tar.gz`
- `/downloads/heel-open-core-manifest.json`

The build validates their exact set, sizes, digests, and Apache-only archive members without
regenerating them. CI clean-installs the committed wheel and completes a real initialized MCP review.
Public customer deployment, PyPI publication, and the current public repository export are separate
release-owner actions and are not complete.

The base local CLI/MCP is Apache-2.0 and has no commercial usage limit. Hosted findings
synchronization and remote MCP are paid Heel Cloud features; they are not enabled in this anonymous
milestone. Windows secure local project storage is not supported at launch; the browser workspace
remains available without that store.

## Node versions

- Production and hosting: Node.js `>=24.13.1`
- Security verification: Node.js 25+; Node.js 26 is recommended

The production floor covers the synchronous module hooks used by runtime
preparation. The browser security test additionally requires the network-aware
Node permission model. Use a supported Node 26 release for CI security checks;
the application itself does not require the short-lived Node 25 line in
production.

## Local checks

```bash
npm ci --ignore-scripts --no-audit --no-fund
cd ../..
env PIP_CONFIG_FILE=/dev/null PYTHONNOUSERSITE=1 \
  python3.13 -m pip --isolated install \
  --require-hashes --only-binary=:all: \
  -r release/requirements-release.txt
python3.13 scripts/build_open_core_release.py \
  --output apps/heel-cloud/public/downloads --check
HEEL_REQUIRE_STANDARD_BUILD=1 \
  python3.13 -m unittest tests.test_open_core_release -v
python3 scripts/build_browser_engine.py --output apps/heel-cloud/browser-engine --check
python3 scripts/build_browser_sample.py --check
python3 -m unittest tests.test_browser_engine_build tests.test_browser_review \
  tests.test_browser_sample tests.test_browser_native_parity -v
cd apps/heel-cloud
node --test tests/browser-engine.test.mjs
npm run test:unit
npm run typecheck
npm run lint
npm run build
npm run test:node
```

The release-tool install and release gate require Python 3.13 to match CI. The browser-only Python
checks remain supported on the project-wide Python 3.11+ range.

The production-artifact test runs after the build and verifies the transformed,
digest-pinned same-origin runtime; recursively scans deployed executables,
manifests, browser-wheel members, and the Agent wheel/source archive; enforces exact response CSP/security
headers and empty cloud capabilities; rejects source maps, CDN fallbacks, and
credentials; and proves that 1200×630 social metadata uses the request URL rather
than caller-controlled host headers. These automated checks do not replace the
outstanding keyboard, narrow-viewport, request-inspection, timing, and deployment
acceptance run.
