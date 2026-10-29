# JavaScript dependency security — October 28, 2026

This note records the bounded dependency follow-up for `web/` and
`apps/heel-cloud/` on base `3ec28067`. It describes verified lock and build
behavior. It is not a launch-security sign-off, and it does not describe a
public deployment. Independent security review and exact-tree CI are still
required.

## What changed

| Project | Package | Before | After | Why this version |
|---|---|---|---|---|
| web | `next`, `eslint-config-next` | 16.2.7 | 16.4.2 | Next fixed the last of its listed advisories in 16.4.1. 16.4.2 is the bug-fix patch already locked in `apps/heel-cloud`. |
| web (via Next) | `sharp` / `postcss` / `nanoid` | 0.34.5 / 8.4.31, 8.5.15 / 3.3.12 | 0.35.5 / 8.5.23 / 3.3.20 | Brought in by Next 16.4.2's own dependency ranges. |
| cloud | `vite` | 8.2.2 | 8.2.4 | Maintainer patch for the Vite and launch-editor advisories on the 8.2 line. |
| cloud | `vitest` | 4.1.11 | 4.1.12 | Maintainer patch for the `@vitest/mocker` advisories. |
| both | Browserslist, baseline-browser-mapping, source-map-js, Zod, brace-expansion, fast-uri, fflate, js-yaml | vulnerable releases | patched releases | Relocked inside the ranges their parents already declare (`npm update <name> --package-lock-only`). No overrides were added. |

No framework major version, application source, Vite/Next/ESLint config,
static-export setting, VPC binding or origin/auth/CSRF control changed.

## Audit state after the change

Both web audits report 0: the full graph and `--omit=dev`. Before the
change npm counted 8 vulnerable packages in the full graph (1 moderate, 6
high, 1 critical) and 6 in the production graph, covering 34 advisories.

The cloud `--omit=dev` audit still reports 0, as it did before. The cloud
full-graph count drops from 17 vulnerable packages (6 moderate, 11 high) to
8 (3 moderate, 5 high). Those 8 packages cover 21 of the 44 baseline
advisories, all in development and build tooling:

| Advisory | Locked path | Fixed release | Why it was not taken here |
|---|---|---|---|
| Satori [GHSA-wx4j-mvgx-mqwp](https://github.com/advisories/GHSA-wx4j-mvgx-mqwp) | vinext 1.0.0-beta.8 → @vercel/og 0.8.6 → satori 0.16.0 | vinext ≥ 1.0.0-beta.13 (@vercel/og 1.0.3, satori 0.33.5) | That vinext build imports `cloudflare:workers` into the Worker entry and moves the generated prerender secret outside its classified manifests. 11 of 76 `test:node` production-artifact tests fail. |
| Sharp [GHSA-rgj7-g3m4-5g8c](https://github.com/lovell/sharp/security/advisories/GHSA-rgj7-g3m4-5g8c), [GHSA-wq5f-xc86-pv6w](https://github.com/lovell/sharp/security/advisories/GHSA-wq5f-xc86-pv6w) | @cloudflare/vite-plugin 1.53.1 / wrangler 4.125.0 → miniflare → sharp 0.35.2 | plugin ≥ 1.63.1 (sharp 0.35.5) | The emitted Worker `compatibility_date` is not pinned in `vite.config.ts`, so it follows the plugin's built-in default. 1.63.2 moves it from 2026-08-20 to 2026-10-06. |
| 18 undici advisories ([GHSA-4w7w-5xrc-9h26](https://github.com/nodejs/undici/security/advisories/GHSA-4w7w-5xrc-9h26) and 17 others) | miniflare and jsdom → undici 7.29.0 | plugin 1.66.0 (miniflare with undici 7.30.1) | Same `compatibility_date` change. Plugin 1.64.0 and later also emit Worker source maps and an `upload_source_maps` setting by default, which fails 2 production-artifact tests. |

Reachability, verified against the build on this base:

- The emitted Worker and static client output contain no Satori, @vercel/og,
  resvg, fflate, Sharp, undici, Miniflare, workerd or Vite dev-client code.
  `vinext-externals.json` is empty.
- `vinext build` runs no prerender step and does not start Miniflare.
  Miniflare runs only for local `vinext dev` and `wrangler dev` simulation.
  jsdom runs only as the Vitest environment.
- The Worker's `/_vinext/image` route sends images to the Cloudflare Images
  binding (`env.IMAGES`), not to Sharp. This route existed before this
  change.

These advisories stay open until the change below is reviewed. No waiver
is recorded.

## Bounded follow-up for the remaining advisories

This was tested in a scratch export, not committed: plugin 1.66.0 and
wrangler 4.154.0, plus two lines in `apps/heel-cloud/vite.config.ts`:

```ts
    compatibility_date: "2026-08-20",   // in localBindingConfig
    build: { sourcemap: false },        // in the returned Vite config
```

With those lines, `test:node` passes 76/76, unit tests pass 378 (1
skipped), typecheck passes, and the emitted `wrangler.json` matches the
baseline except for one new empty `k2` binding list. The cloud full audit
then reports only the Satori entry. The vinext upgrade needs its own review
of the `cloudflare:workers` import and of the prerender-secret
classification. It must not be taken just to clear the audit.

## Verification commands

Run with the CI Node majors (Node 22 for web, Node 26 for cloud). This
change was verified with Node 22.23.4 / npm 10.9.9 and Node 26.13.0 / npm
11.20.0.

```sh
# web (Node 22)
npm ci && npm run lint && npm run build
npm audit --package-lock-only            # full graph, not only --omit=dev

# apps/heel-cloud (Node 26)
npm ci --ignore-scripts --no-audit --no-fund
npm audit --package-lock-only            # full dev/build graph
npm audit --omit=dev --audit-level=high --package-lock-only --ignore-scripts
npm run test:unit && npm run typecheck && npm run lint
HEEL_CONTROL_PLANE_VPC_SERVICE_ID=00000000-0000-4000-8000-000000000001 \
  HEEL_PUBLIC_ORIGIN=https://heel.example npm run build
npm run test:node
```

A zero `--omit=dev` audit does not clear the cloud build chain. vinext and
the Cloudflare tooling are dev-declared but produce the Worker. Wrangler
ships a prebundled CLI, and code inlined there has no lock entry for npm
audit to check.

## Deployment notes

- Serve only the static `web/out` export for the control-room UI. Do not
  expose `next dev` or `next start`.
- Do not expose `vinext dev`, `vite dev` or `wrangler dev` on a public
  interface. Do not feed untrusted images, fonts or archives into local
  build or simulation tooling.
- Before any Cloudflare plugin or Wrangler upgrade, pin `compatibility_date`
  and check the emitted `dist/server/wrangler.json` and the absence of
  `.map` files. `test:node` enforces both checks.
- The cloud build is not byte-reproducible: `BUILD_ID` and chunk names
  change on every build, even from the same lock. Compare emitted output by
  configuration and dependency markers, not by file hash.
