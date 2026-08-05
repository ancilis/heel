// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
import { mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";


const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));
const pageUrl = new URL("../app/mcp/page.tsx", import.meta.url);


test("the displayed MCP verification performs a real handshake against current Heel", async () => {
  const source = await readFile(pageUrl, "utf8");
  const match = source.match(/const VERIFY_SERVER = `([\s\S]*?)`;/);
  assert.ok(match, "MCP page must expose the exact verification command");
  const displayedCommand = match[1].replaceAll("\\\\", "\\");
  const executable = "/absolute/path/to/heel/.venv/bin/heel-mcp";
  assert.match(displayedCommand, new RegExp(executable.replaceAll("/", "\\/")));
  const currentCommand = displayedCommand.replace(executable, "python3 -m heel.mcp_server");
  const heelHome = await mkdtemp(join(await realpath(repoRoot), ".heel-mcp-quickstart-"));

  try {
    const result = spawnSync("/bin/sh", ["-c", currentCommand], {
      cwd: repoRoot,
      encoding: "utf8",
      env: { ...process.env, HEEL_HOME: heelHome },
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const responses = result.stdout.trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(responses.length, 2, result.stdout);
    assert.equal(responses[0]?.result?.serverInfo?.name, "heel");
    assert.ok(
      responses[1]?.result?.tools?.some((tool) => tool.name === "heel_review_openapi"),
      result.stdout,
    );
  } finally {
    await rm(heelHome, { recursive: true, force: true });
  }
});
