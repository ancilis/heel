# Heel Cloud

The commercial Heel customer application. This anonymous milestone runs the
review engine browser-locally: OpenAPI documents stay on the device and are
never uploaded to Heel Cloud. It has no authentication, server persistence,
database, object storage, or analytics.

This scaffold intentionally contains only an accessible loading shell. Task 5
adds the product interface without copying the Apache-2.0 `web/` control-room
demo.

## Prerequisites

- Node.js `>=22.13.0`

## Local checks

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm test
npm run lint
npm run build
```
