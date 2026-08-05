# Heel Cloud

The commercial Heel customer application. This anonymous milestone runs the
review engine browser-locally: OpenAPI documents stay on the device and are
never uploaded to Heel Cloud. It has no authentication, server persistence,
database, object storage, or analytics.

This scaffold intentionally contains only an accessible loading shell. Task 5
adds the product interface without copying the Apache-2.0 `web/` control-room
demo.

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
npm test
npm run typecheck
npm run lint
npm run build
```
