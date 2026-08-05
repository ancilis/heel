// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
import { access, readFile, readdir } from "node:fs/promises";
import { extname, join } from "node:path";
import test from "node:test";

const appRoot = new URL("../", import.meta.url);
const commercialHeader = "SPDX-License-Identifier: LicenseRef-Heel-Commercial";
const sourceExtensions = new Set([".css", ".js", ".jsx", ".mjs", ".ts", ".tsx"]);

async function assertMissing(relativePath) {
  await assert.rejects(access(new URL(relativePath, appRoot)));
}

async function sourceFiles(directoryUrl) {
  const entries = await readdir(directoryUrl, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    if ([".next", ".vinext", ".wrangler", "dist", "node_modules"].includes(entry.name)) {
      continue;
    }

    const entryUrl = new URL(`${entry.name}${entry.isDirectory() ? "/" : ""}`, directoryUrl);
    if (entry.isDirectory()) {
      files.push(...(await sourceFiles(entryUrl)));
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
  assert.equal(packageJson.scripts.predev, undefined);
  assert.equal(packageJson.scripts.prebuild, undefined);
  assert.deepEqual(hosting, { d1: null, r2: null });

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

test("uses Heel identity and marks original source as commercial", async () => {
  const [page, layout, readme] = await Promise.all([
    readFile(new URL("app/page.tsx", appRoot), "utf8"),
    readFile(new URL("app/layout.tsx", appRoot), "utf8"),
    readFile(new URL("README.md", appRoot), "utf8"),
  ]);

  const identitySource = `${page}\n${layout}`;
  assert.doesNotMatch(
    identitySource,
    /codex-preview|SkeletonPreview|Starter Project|Your site is taking shape/i,
  );
  assert.match(layout, /title:\s*"Heel/);
  assert.match(readme, /browser-local/i);
  assert.match(readme, /never uploaded/i);
  assert.match(readme, /Task 5/);

  const files = await sourceFiles(appRoot);
  for (const file of files) {
    const source = await readFile(file, "utf8");
    assert.ok(source.includes(commercialHeader), `${join(file.pathname)} lacks the commercial SPDX header`);
  }
});
