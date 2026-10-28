// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const appRoot = new URL("../", import.meta.url);
const commercialHeader = "SPDX-License-Identifier: LicenseRef-Heel-Commercial";
const sourceExtensions = new Set([".css", ".js", ".jsx", ".mjs", ".ts", ".tsx"]);
const ignoredRootDirectories = new Set([
  ".next",
  ".vinext",
  ".wrangler",
  "coverage",
  "dist",
  "node_modules",
  "out",
  "outputs",
  "work",
]);
const ignoredRootPaths = new Set(["next-env.d.ts", "public/heel-runtime"]);

async function assertMissing(relativePath) {
  await assert.rejects(access(new URL(relativePath, appRoot)));
}

async function sourceFiles(directoryUrl, rootUrl = directoryUrl) {
  const relativeDirectory = relative(fileURLToPath(rootUrl), fileURLToPath(directoryUrl)).replaceAll("\\", "/");
  if (ignoredRootPaths.has(relativeDirectory)) {
    return [];
  }

  const entries = await readdir(directoryUrl, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    if (directoryUrl.href === rootUrl.href && ignoredRootDirectories.has(entry.name)) {
      continue;
    }

    const entryUrl = new URL(`${entry.name}${entry.isDirectory() ? "/" : ""}`, directoryUrl);
    const relativeEntry = relative(fileURLToPath(rootUrl), fileURLToPath(entryUrl)).replaceAll("\\", "/");
    if (ignoredRootPaths.has(relativeEntry)) continue;
    if (entry.isDirectory()) {
      files.push(...(await sourceFiles(entryUrl, rootUrl)));
    } else if (sourceExtensions.has(extname(entry.name))) {
      files.push(entryUrl);
    }
  }

  return files;
}

test("keeps the anonymous app free of server-side customer capabilities", async () => {
  const [packageJson, hosting, vite, worker, buildPlugin] = await Promise.all([
    readFile(new URL("package.json", appRoot), "utf8").then(JSON.parse),
    readFile(new URL(".openai/hosting.json", appRoot), "utf8").then(JSON.parse),
    readFile(new URL("vite.config.ts", appRoot), "utf8"),
    readFile(new URL("worker/index.ts", appRoot), "utf8"),
    readFile(new URL("build/sites-vite-plugin.ts", appRoot), "utf8"),
  ]);

  assert.equal(packageJson.name, "@heel/cloud");
  assert.equal(packageJson.dependencies.pyodide, "314.0.3");
  assert.equal(packageJson.dependencies["react-loading-skeleton"], undefined);
  assert.equal(packageJson.dependencies["drizzle-orm"], undefined);
  assert.equal(packageJson.devDependencies["drizzle-kit"], undefined);
  assert.equal(packageJson.scripts.predev, "node scripts/prepare-runtime.mjs");
  assert.equal(packageJson.scripts.prebuild, "node scripts/prepare-runtime.mjs");
  assert.deepEqual(Object.keys(hosting).sort(), ["d1", "project_id", "r2"]);
  assert.match(hosting.project_id, /^appgprj_[0-9a-f]{32}$/);
  assert.equal(hosting.d1, null);
  assert.equal(hosting.r2, null);

  for (const path of [
    "app/_sites-preview/",
    "app/chatgpt-auth.ts",
    "db/",
    "drizzle/",
    "drizzle.config.ts",
    "examples/d1/",
    "public/favicon.svg",
    "public/file.svg",
    "public/globe.svg",
    "public/window.svg",
  ]) {
    await assertMissing(path);
  }

  const cloudSource = `${vite}\n${worker}\n${buildPlugin}`;
  assert.doesNotMatch(
    cloudSource,
    /D1Database|d1_databases|r2_buckets|drizzle|database_id|database_name/i,
  );
});

test("uses Heel identity, trusted request-origin metadata, and commercial source", async () => {
  const [page, layout, worker, readme, socialCard] = await Promise.all([
    readFile(new URL("app/page.tsx", appRoot), "utf8"),
    readFile(new URL("app/layout.tsx", appRoot), "utf8"),
    readFile(new URL("worker/index.ts", appRoot), "utf8"),
    readFile(new URL("README.md", appRoot), "utf8"),
    readFile(new URL("public/og.png", appRoot)),
  ]);

  const identitySource = `${page}\n${layout}`;
  assert.doesNotMatch(
    identitySource,
    /codex-preview|SkeletonPreview|Starter Project|Your site is taking shape/i,
  );
  assert.match(layout, /const title = "Heel/);
  assert.match(layout, /generateMetadata/);
  assert.match(layout, /x-heel-internal-origin/);
  assert.match(layout, /\$\{origin\}\/og\.png/);
  assert.doesNotMatch(layout, /values\.get\(["'](?:host|x-forwarded-host|x-forwarded-proto)["']\)/);
  assert.match(worker, /new URL\(request\.url\)\.origin/);
  assert.match(worker, /requestHeaders\.set\([\s\S]*x-heel-internal-origin/);
  assert.equal(socialCard.readUInt32BE(16), 1200);
  assert.equal(socialCard.readUInt32BE(20), 630);
  assert.match(readme, /never uploaded/i);
  assert.match(readme, /evidence-first browser workspace/i);
  assert.match(readme, /Agent files advertised on `\/agent`/);
  assert.doesNotMatch(readme, /Agent files served from `\/agent`/);

  const files = await sourceFiles(appRoot);
  for (const file of files) {
    const source = await readFile(file, "utf8");
    assert.ok(source.includes(commercialHeader), `${join(file.pathname)} lacks the commercial SPDX header`);
  }
});

test("ships server-renderable evidence, local interaction semantics, and accessible responsive styles", async () => {
  const [page, agentPage, workspace, input, privacy, sample, css] = await Promise.all([
    readFile(new URL("app/page.tsx", appRoot), "utf8"),
    readFile(new URL("app/agent/page.tsx", appRoot), "utf8").catch(() => ""),
    readFile(new URL("components/review/ReviewWorkspace.tsx", appRoot), "utf8"),
    readFile(new URL("components/review/OpenApiInput.tsx", appRoot), "utf8"),
    readFile(new URL("components/review/PrivacyReceipt.tsx", appRoot), "utf8"),
    readFile(new URL("data/sample-review.v1.json", appRoot), "utf8"),
    readFile(new URL("app/globals.css", appRoot), "utf8"),
  ]);

  const productSource = `${page}\n${workspace}\n${input}\n${privacy}`;
  assert.doesNotMatch(page, /Preparing Heel|loading-shell/);
  assert.match(productSource, /Run the sample/);
  assert.match(productSource, /Analyze mine/);
  assert.match(productSource, /Your product description stays in this browser/);
  assert.match(workspace, /aria-live="polite"/);
  assert.match(workspace, /role="alert"/);
  assert.match(workspace, /tabIndex=\{-1\}/);
  assert.match(input, /TextDecoder\("utf-8", \{ fatal: true \}\)/);
  assert.match(input, /onDrop=/);
  assert.match(input, /aria-live="polite"/);
  assert.match(workspace, /Save result on this device/);
  assert.match(workspace, /Clear local history/);
  assert.match(workspace, /useMemo\(\(\) => reviewToJson\(result\), \[result\]\)/);
  assert.match(sample, /agent_surface_overscope/);
  assert.match(page, /href="\/agent"/);
  assert.doesNotMatch(page, /href="\/mcp"/);
  await assertMissing("app/mcp/");
  assert.match(agentPage, /heel-sim/);
  assert.match(agentPage, /\.venv\/bin\/python -m pip install \./);
  assert.match(agentPage, /\/absolute\/path\/to\/download-folder\/\.venv\/bin\/heel-mcp/);
  assert.match(agentPage, /mcpServers/);
  assert.match(agentPage, /HEEL_HOME/);
  assert.match(agentPage, /HEEL_CLOUD_ORIGIN/);
  assert.match(agentPage, /heel_sync_prepare/);
  assert.match(agentPage, /heel cloud sync approve/);
  assert.match(agentPage, /MCP cannot log in, approve, send, retry, refresh, or revoke/i);
  assert.match(agentPage, /PyPI publication is not yet available/i);
  assert.match(agentPage, /credentials or customer data/i);
  assert.match(agentPage, /AI client is separate/i);
  assert.doesNotMatch(agentPage, /python3 -m pip install heel-sim/);

  assert.doesNotMatch(productSource, /sign.?up.{0,30}(review|analy)/i);
  assert.doesNotMatch(productSource, /testimonial|customers trust|accuracy rate|cloud save/i);
  assert.match(css, /:focus-visible/);
  assert.match(css, /min-height:\s*44px/);
  assert.match(css, /prefers-reduced-motion:\s*reduce/);
  assert.match(css, /@media\s*\(max-width:\s*720px\)/);
});

test("documents a non-emitting TypeScript validation command", async () => {
  const [packageJson, readme] = await Promise.all([
    readFile(new URL("package.json", appRoot), "utf8").then(JSON.parse),
    readFile(new URL("README.md", appRoot), "utf8"),
  ]);

  assert.equal(packageJson.scripts.typecheck, "tsc --noEmit --incremental false");
  assert.match(readme, /npm run typecheck/);
});

test("lints tracked build source and ignores compiler state", async () => {
  const { ESLint } = await import("eslint");
  const eslint = new ESLint({ cwd: fileURLToPath(appRoot) });
  const [eslintConfig, gitignore] = await Promise.all([
    readFile(new URL("eslint.config.mjs", appRoot), "utf8"),
    readFile(new URL(".gitignore", appRoot), "utf8"),
  ]);

  assert.doesNotMatch(eslintConfig, /["']build\/\*\*["']/);
  assert.equal(await eslint.isPathIgnored("build/sites-vite-plugin.ts"), false);
  assert.match(gitignore, /^\*\.tsbuildinfo$/m);
  assert.match(gitignore, /^\/public\/heel-runtime\/$/m);
});

test("commercial source discovery skips generated roots but checks nested namesakes", async () => {
  const fixtureRoot = await mkdtemp(join(tmpdir(), "heel-source-boundary-"));

  try {
    await writeFile(join(fixtureRoot, "tracked.ts"), commercialHeader, "utf8");
    const generatedDirectories = [...ignoredRootDirectories];
    const nestedSources = [
      ...generatedDirectories.map((directory) => `app/${directory}/source.ts`),
      "app/public/heel-runtime/source.mjs",
    ];

    for (const directory of generatedDirectories) {
      await mkdir(join(fixtureRoot, directory), { recursive: true });
      await writeFile(join(fixtureRoot, directory, "generated.ts"), "generated", "utf8");
      await mkdir(join(fixtureRoot, "app", directory), { recursive: true });
      await writeFile(join(fixtureRoot, "app", directory, "source.ts"), "unlicensed", "utf8");
    }

    await mkdir(join(fixtureRoot, "public", "heel-runtime"), { recursive: true });
    await writeFile(join(fixtureRoot, "public", "heel-runtime", "generated.mjs"), "generated", "utf8");
    await mkdir(join(fixtureRoot, "app", "public", "heel-runtime"), { recursive: true });
    await writeFile(join(fixtureRoot, "app", "public", "heel-runtime", "source.mjs"), "unlicensed", "utf8");

    const files = await sourceFiles(pathToFileURL(`${fixtureRoot}/`));
    const relativeFiles = files
      .map((file) => relative(fixtureRoot, fileURLToPath(file)).replaceAll("\\", "/"))
      .sort();
    assert.deepEqual(relativeFiles, [...nestedSources, "tracked.ts"].sort());

    const unlicensedFiles = [];
    for (const file of files) {
      if (!(await readFile(file, "utf8")).includes(commercialHeader)) {
        unlicensedFiles.push(relative(fixtureRoot, fileURLToPath(file)).replaceAll("\\", "/"));
      }
    }
    assert.deepEqual(unlicensedFiles.sort(), nestedSources.sort());
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});
