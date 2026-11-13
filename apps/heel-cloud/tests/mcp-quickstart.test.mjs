// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
import { access, constants, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";


const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));
const pageUrl = new URL("../app/agent/page.tsx", import.meta.url);
const shellQuote = (value) => `'${value.replaceAll("'", `'"'"'`)}'`;
// Every environment a displayed command creates, and every executable a displayed command runs.
const createdEnvironments = (source) => [...source.matchAll(/python3 -m venv (\S+)/g)].map((match) => match[1]);
const executableReferences = (source) =>
  [...source.matchAll(/([\w.-]+)\/bin\/(heel-mcp|heel|python)\b/g)].map(([, environment, executable]) => ({
    environment,
    executable,
  }));


test("both install variants and every later step use one environment", async () => {
  const source = await readFile(pageUrl, "utf8");
  const created = createdEnvironments(source);
  assert.equal(created.length, 2, "the public and bundled installs each create an environment");
  assert.deepEqual(new Set(created), new Set(["heel-rc5"]));
  const references = executableReferences(source);
  assert.ok(references.length >= 7, JSON.stringify(references));
  for (const reference of references) assert.equal(reference.environment, "heel-rc5", JSON.stringify(reference));
  assert.doesNotMatch(source, /\.venv\b/);
});


test("the displayed install and verification perform a real handshake against the release wheel", async () => {
  const source = await readFile(pageUrl, "utf8");
  const installMatch = source.match(/const INSTALL_AGENT = `([\s\S]*?)`;/);
  const verifyMatch = source.match(/const VERIFY_SERVER = `([\s\S]*?)`;/);
  assert.ok(installMatch, "MCP page must expose the exact Agent install command");
  assert.ok(verifyMatch, "MCP page must expose the exact verification command");
  const displayedInstall = installMatch[1].replaceAll("\\\\", "\\");
  const displayedVerify = verifyMatch[1].replaceAll("\\\\", "\\");
  assert.equal(
    displayedInstall,
    "python3 -m venv heel-rc5\n./heel-rc5/bin/python -m pip install ./heel_sim-1.3.0rc5-py3-none-any.whl",
  );
  assert.match(displayedVerify, /\| \.\/heel-rc5\/bin\/heel-mcp$/);
  const wheel = join(repoRoot, "apps/heel-cloud/public/downloads/heel_sim-1.3.0rc5-py3-none-any.whl");
  const workingDirectory = await mkdtemp(join(await realpath(repoRoot), ".heel-mcp-quickstart-"));
  const currentInstall = displayedInstall.replace(
    "./heel_sim-1.3.0rc5-py3-none-any.whl",
    shellQuote(wheel),
  );

  try {
    const environment = {
      ...process.env,
      HEEL_HOME: join(workingDirectory, "heel-home"),
      PIP_CONFIG_FILE: "/dev/null",
      PIP_DISABLE_PIP_VERSION_CHECK: "1",
      PIP_NO_INDEX: "1",
      PIP_NO_CACHE_DIR: "1",
      PYTHONNOUSERSITE: "1",
    };
    delete environment.PYTHONPATH;
    const install = spawnSync("/bin/sh", ["-c", currentInstall], {
      cwd: workingDirectory,
      encoding: "utf8",
      env: environment,
    });
    assert.equal(install.status, 0, install.stderr || install.stdout);
    // Every executable the page later runs or configures exists in the environment just installed.
    for (const { environment, executable } of executableReferences(source)) {
      await access(join(workingDirectory, environment, "bin", executable), constants.X_OK);
    }
    const verification = spawnSync("/bin/sh", ["-c", displayedVerify], {
      cwd: workingDirectory,
      encoding: "utf8",
      env: environment,
    });
    assert.equal(verification.status, 0, verification.stderr || verification.stdout);
    const responses = verification.stdout.trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(responses.length, 2, verification.stdout);
    assert.equal(responses[0]?.result?.serverInfo?.name, "heel");
    assert.ok(
      responses[1]?.result?.tools?.some((tool) => tool.name === "heel_review_openapi"),
      verification.stdout,
    );
  } finally {
    await rm(workingDirectory, { recursive: true, force: true });
  }
});
