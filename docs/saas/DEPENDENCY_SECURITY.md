# JavaScript dependency security — October 29, 2026

This note records the bounded dependency follow-up for `web/` and
`apps/heel-cloud/`. The first step (base `3ec28067`, head `09ae2bc5`)
patched web Next, cloud Vite and Vitest. The second step upgrades the
Cloudflare plugin and Wrangler with the Worker runtime policy pinned. It
describes verified lock and build behavior. It is not a launch-security
sign-off, and it does not describe a public deployment. Independent
security review, exact-tree Linux CI and CodeQL/GHAS are still required.

## What changed

| Project | Package | Before | After | Why this version |
|---|---|---|---|---|
| web | `next`, `eslint-config-next` | 16.2.7 | 16.4.2 | Next fixed the last of its listed advisories in 16.4.1. 16.4.2 is the bug-fix patch already locked in `apps/heel-cloud`. |
| web (via Next) | `sharp` / `postcss` / `nanoid` | 0.34.5 / 8.4.31, 8.5.15 / 3.3.12 | 0.35.5 / 8.5.23 / 3.3.20 | Brought in by Next 16.4.2's own dependency ranges. |
| cloud | `vite` | 8.2.2 | 8.2.4 | Maintainer patch for the Vite and launch-editor advisories on the 8.2 line. |
| cloud | `vitest` | 4.1.11 | 4.1.12 | Maintainer patch for the `@vitest/mocker` advisories. |
| both | Browserslist, baseline-browser-mapping, source-map-js, Zod, brace-expansion, fast-uri, fflate, js-yaml | vulnerable releases | patched releases | Relocked inside the ranges their parents already declare (`npm update <name> --package-lock-only`). No overrides were added. |
| cloud | `@cloudflare/vite-plugin` / `wrangler` | 1.53.1 / 4.125.0 | 1.66.0 / 4.154.0 | First releases that carry both fixes. Miniflare 5.20261023.1-beta pins Sharp 0.35.5 and undici 7.30.1. |

The plugin upgrade resolves through an ordinary
`npm install --save-exact --package-lock-only` with no new override. The
existing `ws` override is unchanged. The upgrade touches 92 lock records:
64 changed, 28 removed and none added. The lock now holds one Miniflare, one
Sharp 0.35.5 and one undici 7.30.1. Next's nested Sharp 0.35.5 copy is
deduplicated into the top-level copy. jsdom's `^7.25.0` resolves to the
same undici 7.30.1.

`apps/heel-cloud/vite.config.ts` now pins two values the plugin would
otherwise choose:

```ts
    compatibility_date: "2026-08-20",   // in localBindingConfig
    build: { sourcemap: false },        // in the returned Vite config
```

Without them, plugin 1.66.0 moves the emitted Worker date to its built-in
2026-10-23 default. It also emits 52 `.map` files and
`upload_source_maps: true`. Plugin 1.64.0 and later take the Worker map
setting from the environment `build.sourcemap`, then the top-level
`build.sourcemap`, then `upload_source_maps`, and otherwise `true`. With
both pins, the emitted `wrangler.json` equals the earlier build except
for one new empty `k2` list. `production-artifact.test.mjs` now asserts
the following:

- The exact date and the `["nodejs_compat"]` flags.
- Disabled observability.
- The fixed `CONTROL_PLANE` VPC service and the `../client` assets root.
- No `.map` file anywhere in `dist`.
- No `sourceMappingURL` directive in any `dist` file that decodes as
  UTF-8, whatever its suffix.
- No Source Map v3 document in any `dist` file that decodes as UTF-8,
  whatever its name or suffix. A regular map is a JSON object with a
  `sources` list and either `mappings` or `sourcesContent`. An index map
  has `sections` at offsets that embed such a map or name one by `url`.
  A leading `)]}'` line is ignored.
- Every unapproved binding list stays empty. `k2` is accepted only as `[]`.

The map check does not inspect binary or compressed files (gzip, zip,
wheel, wasm), other encodings such as base64, or a map nested under
another JSON key. The current build output contains no map document.

No application source, Worker code, Next/ESLint config, static-export
setting, VPC binding or origin/auth/CSRF control changed.

## Audit state after the change

npm reports *vulnerable package groups*, and a group can be a parent that
only inherits a child's advisory. The counts below separate groups from
unique advisory IDs, which are taken from the direct `via` records.

| Lock | Graph | Groups / IDs before | Groups / IDs after |
|---|---|---|---|
| web | full | 8 / 34 | 0 / 0 |
| web | `--omit=dev` | 6 / 31 | 0 / 0 |
| cloud | full, at `3ec28067` | 17 / 44 | — |
| cloud | full, at `09ae2bc5` | 8 / 21 | 3 / 1 |
| cloud | `--omit=dev` | 0 / 0 | 0 / 0 |

These counts come from lock-only audits on October 29, 2026. Another day's
advisory database can report different results.

The plugin upgrade clears all 20 Sharp and undici IDs:

- Sharp [GHSA-rgj7-g3m4-5g8c](https://github.com/lovell/sharp/security/advisories/GHSA-rgj7-g3m4-5g8c)
  and [GHSA-wq5f-xc86-pv6w](https://github.com/lovell/sharp/security/advisories/GHSA-wq5f-xc86-pv6w).
- 18 undici IDs: six high, nine moderate and three low.

One cloud dev/build advisory remains open. **The full dependency audit is
not clean.**

| Advisory | npm groups | Locked path | Fixed release | Status |
|---|---|---|---|---|
| Satori [GHSA-wx4j-mvgx-mqwp](https://github.com/vercel/satori/security/advisories/GHSA-wx4j-mvgx-mqwp) (moderate) | `vinext`, `@vercel/og`, `satori` | vinext 1.0.0-beta.8 → @vercel/og 0.8.6 → satori 0.16.0 | satori 0.33.5, reached through a later vinext | Open. See the vinext gate below. No waiver is recorded. |

Reachability evidence for the candidate build:

- The compiler's module graph for the Worker (rsc), SSR and browser
  builds is recorded in a scratch build with an observe-only plugin.
  - Contains only application modules, Vite/vinext/Cloudflare virtual
    modules, `node:` built-ins and these packages: vinext,
    @vitejs/plugin-rsc, react, react-dom, react-server-dom-webpack and
    scheduler.
  - Does **not** contain Satori, @vercel/og, resvg, fflate, Sharp/@img,
    undici, Miniflare, workerd, Wrangler, launch-editor, jsdom or esbuild
    modules.
  - The plugin's generated Worker entry is byte-identical to the one from
    plugin 1.53.1.
  - A missing package name in the output is not, on its own, treated as
    proof that its code is absent.
- `vinext-externals.json` is empty.
- No emitted Worker or SSR module imports a non-built-in package. The
  only other non-relative imports are Pyodide's Node-only branches in the
  vendored `client/heel-runtime` files.
- `vinext build` runs no prerender step and does not start Miniflare.
  Miniflare runs only for local `vinext dev` and `wrangler dev`
  simulation. jsdom runs only as the Vitest environment.
- The cloud app is not a static export. Its existing `/_vinext/image`
  route sends images to the Cloudflare Images binding (`env.IMAGES`), not
  to Sharp. Application and Worker source are unchanged, so no route is
  added.

Installed development tooling still runs during local development, tests
and builds. Its native image code differs between macOS and Linux. These
macOS results do not cover Linux, which needs the exact-tree CI run.

## Remaining vinext gate (not taken here)

Satori's fix arrives with vinext 1.0.0-beta.13 and later. That upgrade
needs its own reviewed evidence before any tracked change.

**Correction.** The earlier note said beta.13 "moves the generated
prerender secret outside its classified manifests". The failing assertion
does not show that. Beta.13 emitted the canonical
`server/vinext-server.json` but no longer the duplicate
`server/ssr/vinext-server.json`. The assertion therefore found one
expected manifest missing, not a secret in a new public path.

Two separate beta.13 changes still require review:

- **Prerender capability.** beta.13 compiles the generated prerender
  secret into Worker server code and uses it as a request capability.
  It controls prerender path discovery and cacheability probes. This
  changes Worker authority. It needs exact secret-value scanning of every
  output and runtime probes of the capability check before any
  manifest-list change.
- **Workers tracing.** beta.13 adds a side-effect `cloudflare:workers`
  tracing import to the Worker entry. It records span attributes and
  exceptions when the platform exposes tracing. Real Workers behavior at
  this compatibility date, with observability disabled, must be proven.
  A no-op test shim is not that proof.

beta.13's @vercel/og 1.0.3 → Satori 0.33.5 path pins fflate 0.7.3. That
reintroduces the fflate advisory that the relock above fixed with 0.7.5.
Taking beta.13 to clear Satori therefore leaves a new full-audit finding
unless a supported fix exists.

## Evidence corrections

The original evidence from the first step stays unedited. These
corrections apply to it:

- Its prose counted eight high undici advisories. The audit records show
  six high, nine moderate and three low.
- Its lock-change counts (55 web, 23 cloud) measure changed versions and
  paths only. Counting every added, removed or changed lock record,
  including metadata and root records, gives 74 web and 24 cloud.
- Its "17 → 8" and "8 / 6" figures count npm package groups, not
  advisories (see the table above).

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
- Keep `compatibility_date` and `build.sourcemap` pinned in
  `vite.config.ts` for every Cloudflare plugin or Wrangler upgrade. Check
  the emitted `dist/server/wrangler.json` and the absence of `.map` files.
  `test:node` enforces both.
- The cloud build is not byte-reproducible: `BUILD_ID` and chunk names
  change on every build, even from the same lock. Compare emitted output by
  configuration and compiled module provenance, not by file hash.
- Deployment upload roots, deployed route behavior and Linux native
  tooling remain unverified. Verify them separately.
