// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const appRoot = new URL("../", import.meta.url);
const commercialHeader = "SPDX-License-Identifier: LicenseRef-Heel-Commercial";
const sourceExtensions = new Set([".css", ".js", ".jsx", ".mjs", ".ts", ".tsx"]);
const ignoredSourceDirectories = new Set([
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

async function assertMissing(relativePath) {
  await assert.rejects(access(new URL(relativePath, appRoot)));
}

async function sourceFiles(directoryUrl) {
  const entries = await readdir(directoryUrl, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    if (ignoredSourceDirectories.has(entry.name)) {
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
});

test("commercial source discovery skips every generated output tree", async () => {
  const fixtureRoot = await mkdtemp(join(tmpdir(), "heel-source-boundary-"));

  try {
    await writeFile(join(fixtureRoot, "tracked.ts"), commercialHeader, "utf8");
    for (const directory of [
      ".next",
      ".vinext",
      ".wrangler",
      "coverage",
      "dist",
      "node_modules",
      "out",
      "outputs",
      "work",
    ]) {
      await mkdir(join(fixtureRoot, directory), { recursive: true });
      await writeFile(join(fixtureRoot, directory, "generated.ts"), "generated", "utf8");
    }

    const files = await sourceFiles(pathToFileURL(`${fixtureRoot}/`));
    assert.deepEqual(files.map((file) => file.pathname.split("/").at(-1)), ["tracked.ts"]);
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});
