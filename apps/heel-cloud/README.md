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
node --test tests/privacy-boundary.test.mjs tests/rendered-html.test.mjs \
  tests/production-artifact.test.mjs
```

The production-artifact test runs after the build and verifies the exact runtime
and wheel digests, same-origin bootstrap, response CSP/security headers, empty
cloud-persistence bindings, absence of source maps and credential files, and the
host-derived 1200×630 social metadata. These automated checks do not replace the
outstanding keyboard, narrow-viewport, request-inspection, timing, and deployment
acceptance run.
