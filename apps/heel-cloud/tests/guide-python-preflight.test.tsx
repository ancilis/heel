// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { cleanup, render } from "@testing-library/react";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import Guide from "../app/guide/page";
import { RUNNER_RC6_INSTALL } from "../components/canary/RunnerPairingCard";


afterEach(cleanup);

function commands(): string[] {
  render(<Guide />);
  return Array.from(document.querySelectorAll("pre"), (block) => block.textContent ?? "");
}

/** A stub interpreter: `--version` prints its version; `-c` exits as the preflight's own check would for it. */
function stub(dir: string, name: string, version: string, hasVenv = true, sub = "bin"): void {
  const [major, minor] = version.split(".").map(Number);
  const ok = hasVenv && (major > 3 || (major === 3 && minor >= 11));
  writeFileSync(join(dir, sub, name), `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "Python ${version}"; exit 0; fi\nexit ${ok ? 0 : 1}\n`);
  chmodSync(join(dir, sub, name), 0o755);
}

function runPreflight(script: string, setup: (dir: string) => void, heelPython?: (dir: string) => string): string {
  const dir = mkdtempSync(join(tmpdir(), "heel-preflight-"));
  try {
    mkdirSync(join(dir, "bin"));
    setup(dir);
    // Only the stubs and the shell's own utilities are reachable; nothing is downloaded or installed.
    const prefix = heelPython ? `HEEL_PYTHON=${heelPython(dir)}\n` : "";
    return execFileSync("/bin/sh", ["-c", prefix + script], { env: { PATH: `${dir}/bin:/bin` } as unknown as NodeJS.ProcessEnv, encoding: "utf8" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("guide install: interpreter preflight before the venv", () => {
  test("the preflight comes before the unchanged rc6 install command", () => {
    const blocks = commands();
    const install = blocks.indexOf(RUNNER_RC6_INSTALL);
    const preflight = blocks.findIndex((block) => block.includes("sys.version_info < (3, 11)"));
    expect(install).toBeGreaterThan(-1);
    expect(preflight).toBeGreaterThan(-1);
    expect(preflight).toBeLessThan(install);
    expect(blocks[preflight]).not.toMatch(/curl|wget|brew install|\bpip\b|venv heel/);
    expect(document.body.textContent).toMatch(/On some Macs the default python3 is 3\.9, which is\s+too old/);
    expect(document.body.textContent).toMatch(/no compatible\s+interpreter was found on your PATH or at HEEL_PYTHON/);
    expect(document.body.textContent).toMatch(/Heel never downloads Python for you\./);
  });

  test("it selects an installed compatible interpreter, prefers python3, and names the absent prerequisite", () => {
    const script = commands().find((block) => block.includes("sys.version_info < (3, 11)")) as string;
    // Default macOS: python3 is 3.9, a Homebrew python3.13 is installed.
    expect(runPreflight(script, (dir) => { stub(dir, "python3", "3.9.6"); stub(dir, "python3.13", "3.13.1"); }))
      .toMatch(/^use: python3\.13 \(Python 3\.13\.1, .*python3\.13\)\nPython 3\.9\.6\n$/);
    // A compatible python3 is used as shown.
    expect(runPreflight(script, (dir) => { stub(dir, "python3", "3.12.4"); stub(dir, "python3.13", "3.13.1"); }))
      .toMatch(/^use: python3 \(Python 3\.12\.4, /);
    // A new enough interpreter without venv/ensurepip is skipped.
    expect(runPreflight(script, (dir) => { stub(dir, "python3", "3.9.6"); stub(dir, "python3.12", "3.12.1", false); }))
      .toBe("Python 3.9.6\n");
    // No compatible interpreter at all: no use: line, only the old version.
    expect(runPreflight(script, (dir) => stub(dir, "python3", "3.9.6"))).toBe("Python 3.9.6\n");
    // A compatible interpreter at a custom absolute path, off PATH, is selected only through the same check.
    const custom = (dir: string) => { stub(dir, "python3", "3.9.6"); mkdirSync(join(dir, "opt")); stub(dir, "py", "3.13.2", true, "opt"); };
    expect(runPreflight(script, custom, (dir) => join(dir, "opt", "py"))).toMatch(/^use: \/.*\/opt\/py \(Python 3\.13\.2, \/.*\/opt\/py\)\nPython 3\.9\.6\n$/);
    const old = (dir: string) => { stub(dir, "python3", "3.9.6"); mkdirSync(join(dir, "opt")); stub(dir, "py", "3.10.9", true, "opt"); };
    expect(runPreflight(script, old, (dir) => join(dir, "opt", "py"))).toBe("Python 3.9.6\n");
  });
});
