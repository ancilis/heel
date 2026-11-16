// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { cleanup, render } from "@testing-library/react";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import McpQuickstart from "../app/agent/page";
import Guide from "../app/guide/page";
import Runner from "../app/runner/page";
import { RUNNER_RC7_INSTALL, RUNNER_RC7_VENV_INSTALL_TAIL } from "../components/canary/RunnerPairingCard";


afterEach(cleanup);

const WHEEL_SPEC = "heel-sim[runner] @ https://github.com/ancilis/heel/releases/download/v1.3.0rc7/"
  + "heel_sim-1.3.0rc7-py3-none-any.whl#sha256=da4ac495e67e3b4a90801dd22901a513427f2b6d28afc97939effcbb9d9dcf21";

/**
 * A stub interpreter. `--version` prints its version; `-c` (the installer's check) succeeds only for >= 3.11 with venv;
 * `-m venv DIR` is recorded and creates DIR/bin/python (records its pip arguments) and DIR/bin/heel (prints a version).
 */
function stub(path: string, version: string, hasVenv = true): void {
  const [major, minor] = version.split(".").map(Number);
  const ok = hasVenv && (major > 3 || (major === 3 && minor >= 11));
  writeFileSync(path, `#!/bin/sh
if [ "$1" = "--version" ]; then echo "Python ${version}"; exit 0; fi
if [ "$1" = "-c" ]; then exit ${ok ? 0 : 1}; fi
echo "venv $0 $*" >> "$LOG"
if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then
  mkdir -p "$3/bin"
  printf '#!/bin/sh\\nfor a in "$@"; do echo "pip-arg $a" >> "$LOG"; done\\n' > "$3/bin/python"
  printf '#!/bin/sh\\necho heel 1.3.0rc7\\n' > "$3/bin/heel"
  chmod +x "$3/bin/python" "$3/bin/heel"
fi
`);
  chmodSync(path, 0o755);
}

interface Outcome { status: number | null; stdout: string; stderr: string; log: string; created: boolean }

/** Runs the exact public install command in a fresh empty directory with only stub interpreters reachable. */
function install(setup: (bin: string, other: string) => void, heelPython?: (other: string) => string): Outcome {
  const dir = mkdtempSync(join(tmpdir(), "heel-install-"));
  try {
    const bin = join(dir, "bin"); const other = join(dir, "opt"); const work = join(dir, "work");
    for (const path of [bin, other, work]) mkdirSync(path);
    setup(bin, other);
    const log = join(dir, "log");
    const prefix = heelPython ? `HEEL_PYTHON=${heelPython(other)}\n` : "";
    const run = spawnSync("/bin/sh", ["-c", prefix + RUNNER_RC7_INSTALL],
      { cwd: work, env: { PATH: `${bin}:/bin:/usr/bin`, LOG: log } as unknown as NodeJS.ProcessEnv, encoding: "utf8" });
    const strip = (text: string) => text.replaceAll(dir, "<dir>");
    return { status: run.status, stdout: strip(run.stdout), stderr: run.stderr,
      log: existsSync(log) ? strip(readFileSync(log, "utf8")) : "", created: existsSync(join(work, "heel-rc7")) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("the one public rc7 installer selects a compatible Python or fails before any venv", () => {
  test("it keeps the exact runbook wheel pin and flags after the selected interpreter", () => {
    expect(RUNNER_RC7_VENV_INSTALL_TAIL).toBe(`-m venv heel-rc7 && ./heel-rc7/bin/python -m pip --isolated install '${WHEEL_SPEC}' && ./heel-rc7/bin/heel --version`);
    expect(RUNNER_RC7_INSTALL.split(RUNNER_RC7_VENV_INSTALL_TAIL)).toHaveLength(2);
    expect(RUNNER_RC7_INSTALL).toContain(`"$HEEL_PY" ${RUNNER_RC7_VENV_INSTALL_TAIL}; fi`);
    expect(RUNNER_RC7_INSTALL).not.toMatch(/python3 -m venv|(^|; )exit\b|curl|wget|brew install/);
    expect(RUNNER_RC7_INSTALL).not.toContain("\n");  // one copy/paste line, safe in an inline code element
  });

  test("default python3 3.9 with python3.13 installed: python3.13 builds the venv and pip gets the exact wheel", () => {
    const out = install((bin) => { stub(join(bin, "python3"), "3.9.6"); stub(join(bin, "python3.13"), "3.13.1"); });
    expect(out.status).toBe(0);
    expect(out.stdout).toBe("Using <dir>/bin/python3.13: Python 3.13.1\nheel 1.3.0rc7\n");
    expect(out.log.split("\n")[0]).toBe("venv <dir>/bin/python3.13 -m venv heel-rc7");
    expect(out.log).toContain(`pip-arg ${WHEEL_SPEC}\n`);
    expect(out.log).toContain("pip-arg --isolated\n");
  });

  test("a compatible python3 is used first; one without venv/ensurepip is skipped", () => {
    expect(install((bin) => { stub(join(bin, "python3"), "3.12.4"); stub(join(bin, "python3.13"), "3.13.1"); }).log)
      .toMatch(/^venv <dir>\/bin\/python3 -m venv heel-rc7\n/);
    expect(install((bin) => { stub(join(bin, "python3"), "3.12.4", false); stub(join(bin, "python3.11"), "3.11.9"); }).log)
      .toMatch(/^venv <dir>\/bin\/python3\.11 -m venv heel-rc7\n/);
  });

  test("HEEL_PYTHON selects an installed absolute path off PATH only after the same check", () => {
    const good = install((bin, other) => { stub(join(bin, "python3"), "3.9.6"); stub(join(other, "py"), "3.13.2"); }, (other) => join(other, "py"));
    expect(good.status).toBe(0);
    expect(good.log.split("\n")[0]).toBe("venv <dir>/opt/py -m venv heel-rc7");
    const old = install((bin, other) => { stub(join(bin, "python3"), "3.9.6"); stub(join(other, "py"), "3.10.9"); }, (other) => join(other, "py"));
    expect(old.status).not.toBe(0);
    expect(old.created).toBe(false);
  });

  test("no compatible interpreter: a clear message, a failing status, and nothing created", () => {
    const out = install((bin) => { stub(join(bin, "python3"), "3.9.6"); stub(join(bin, "python3.12"), "3.12.1", false); });
    expect(out.status).toBe(1);
    expect(out.stderr).toMatch(/^Heel needs Python 3\.11 or newer with venv and ensurepip; none was found on PATH or at HEEL_PYTHON\. Nothing was installed\./);
    expect(out.stdout).toBe("");
    expect(out.log).toBe("");
    expect(out.created).toBe(false);
  });
});

describe("every public rc7 install surface shows that one guarded command", () => {
  for (const [name, Page] of [["/guide", Guide], ["/runner", Runner], ["/agent", McpQuickstart]] as const) {
    test(`${name} renders the shared installer and no unguarded default-python3 install`, () => {
      render(<Page />);
      const text = (document.body.textContent ?? "").replace(/\s+/g, " ");
      const blocks = Array.from(document.querySelectorAll("pre"), (block) => block.textContent ?? "");
      expect(blocks.some((block) => block.split("\n")[0] === RUNNER_RC7_INSTALL)).toBe(true);
      expect(document.body.textContent).not.toContain(`python3 ${RUNNER_RC7_VENV_INSTALL_TAIL}`);
      expect(text).toMatch(/on some Macs the default python3 is 3\.9/i);
      expect(text).toMatch(/HEEL_PYTHON=\/path\/to\/python3/);
    });
  }

  test("the guide has no separate advisory preflight and keeps the no-download promise", () => {
    render(<Guide />);
    const text = (document.body.textContent ?? "").replace(/\s+/g, " ");
    expect(text).not.toMatch(/use: python3/);
    expect(text).toMatch(/Heel never downloads Python for you\./);
    expect(text).toMatch(/stops before creating anything/);
  });
});
