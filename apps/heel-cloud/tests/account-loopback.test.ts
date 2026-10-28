// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/**
 * Account contract against the real Python control plane over loopback HTTP.
 *
 * SEAM: `ControlPlane()` (in-memory SQLite) served by `heel.saas.http_api.serve` on 127.0.0.1;
 * the client transport maps `/api/control-plane/v1/…` to that listener and carries the private
 * `heel_session` cookie like a browser would. There is no Worker, no TLS, no edge auth and no
 * `__Host-` cookie translation here, so this is API-contract evidence only — not proof of the
 * public HTTPS signup path. Opt in with HEEL_LOOPBACK_PYTHON=<python ≥3.11 with Heel's deps>.
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { resolve } from "node:path";
import { createInterface } from "node:readline";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { resolveAccount } from "../lib/account-context";
import { HeelCloudApi, type HeelCloudTransport } from "../lib/heel-cloud-api";


const PYTHON = process.env.HEEL_LOOPBACK_PYTHON ?? "";
const REPO_ROOT = resolve(process.cwd(), "../..");
const LAUNCHER = `
import json, sys, threading
sys.path.insert(0, sys.argv[1])
from heel.saas.http_api import ControlPlane, serve
from heel.saas.tenancy import Role
cp = ControlPlane()
server = serve(cp)
print(server.server_address[1], flush=True)
threading.Thread(target=server.serve_forever, daemon=True).start()
for line in sys.stdin:
    # SEAM-FIXTURE: free workspaces have one seat, so a second member cannot be invited through
    # the product; the test inserts that membership directly to exercise server role checks.
    workspace_id, user_id, role = json.loads(line)
    with cp.request_lock:
        cp.store.add_member(workspace_id, user_id, Role(role))
    print("ok", flush=True)
server.shutdown()
server.server_close()
`;
const SECRET = "Loopback-Pa55word-c7a";

let child: ChildProcessWithoutNullStreams | null = null;
let lines: AsyncIterator<string> | null = null;
let port = 0;


async function fixtureAddMember(workspaceRef: string, userId: string, role: string): Promise<void> {
  child!.stdin.write(`${JSON.stringify([workspaceRef, userId, role])}\n`);
  expect((await lines!.next()).value).toBe("ok");
}


class Browser {
  cookie: string | null = null;
  readonly setCookies: string[] = [];

  readonly transport: HeelCloudTransport = async (path, init) => {
    expect(path.startsWith("/api/control-plane/v1/")).toBe(true);
    const headers = new Headers(init.headers);
    if (this.cookie !== null) headers.set("Cookie", `heel_session=${this.cookie}`);
    const response = await fetch(`http://127.0.0.1:${port}${path.slice("/api/control-plane".length)}`, {
      body: init.body, headers, method: init.method, redirect: "error", signal: init.signal,
    });
    for (const value of response.headers.getSetCookie()) {
      this.setCookies.push(value);
      const match = /^heel_session=([^;]*)/.exec(value);
      if (match) this.cookie = /Max-Age=0/i.test(value) || match[1] === "" ? null : match[1];
    }
    return response;
  };

  readonly api = new HeelCloudApi({ transport: this.transport });
}


async function raw(browser: Browser, method: string, path: string, body?: unknown): Promise<Response> {
  return browser.transport(`/api/control-plane${path}`, {
    method, body: body === undefined ? undefined : JSON.stringify(body),
    headers: { "Content-Type": "application/json", Accept: "application/json" },
  });
}


describe.skipIf(PYTHON === "")("account API contract over loopback HTTP (real ControlPlane)", () => {
  beforeAll(async () => {
    child = spawn(PYTHON, ["-I", "-c", LAUNCHER, REPO_ROOT], { stdio: ["pipe", "pipe", "pipe"] });
    lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
    const first = await Promise.race([
      lines.next(),
      new Promise<never>((_, fail) => child!.once("exit", (code) => fail(new Error(`control plane exited ${code}`)))),
    ]);
    port = Number(first.value);
    expect(Number.isInteger(port) && port > 0).toBe(true);
  }, 30_000);

  afterAll(async () => {
    const owned = child;
    child = null;
    if (owned === null || owned.exitCode !== null) return;
    const exited = new Promise((done) => owned.once("exit", done));
    owned.stdin.end();
    const timer = setTimeout(() => owned.kill("SIGKILL"), 5_000);
    await exited;
    clearTimeout(timer);
  });

  test("signup → project → reload → logout → login, with server-bound identity and roles", async () => {
    const owner = new Browser();
    await expect(resolveAccount(owner.api, {})).resolves.toEqual({ phase: "sign_in" });

    await expect(owner.api.signup("owner@example.test", "short")).rejects.toMatchObject({ code: "invalid_signup", status: 400 });
    const created = await owner.api.signup("owner@example.test", SECRET);
    expect(created.workspaceRef).toMatch(/^ws_[0-9a-f]{16}$/);
    expect(owner.setCookies.at(-1)).toMatch(/^heel_session=[^;]+; HttpOnly; SameSite=Lax; Path=\/$/);
    const firstToken = owner.cookie;

    const duplicate = new Browser();
    await expect(duplicate.api.signup("owner@example.test", SECRET)).rejects.toMatchObject({ code: "account_exists", status: 409 });
    expect(duplicate.cookie).toBeNull();

    const empty = await resolveAccount(owner.api, {});
    expect(empty).toMatchObject({ phase: "select_project", account: { userId: created.userId, workspace: { workspaceRef: created.workspaceRef, role: "owner" } } });

    const alpha = await owner.api.createProject(created.workspaceRef, "Alpha");
    const beta = await owner.api.createProject(created.workspaceRef, "Beta");
    expect(alpha.projectRef).toMatch(/^prj_[0-9a-f]{32}$/);
    const reloaded = await resolveAccount(owner.api, { workspaceRef: created.workspaceRef, projectRef: beta.projectRef });
    expect(reloaded.phase === "ready" && reloaded.project.name).toBe("Beta");

    // The free plan has one seat: the real invite route refuses a second member.
    const invite = await raw(owner, "POST", `/v1/workspaces/${created.workspaceRef}/invites`, { email: "viewer@example.test", role: "viewer" });
    expect(invite.status).toBe(402);
    const viewer = new Browser();
    const viewerAccount = await viewer.api.signup("viewer@example.test", `${SECRET}-viewer`);
    await fixtureAddMember(created.workspaceRef, viewerAccount.userId, "viewer");
    const viewing = await resolveAccount(viewer.api, { workspaceRef: created.workspaceRef, projectRef: alpha.projectRef });
    expect(viewing).toMatchObject({ phase: "ready", account: { workspace: { workspaceRef: created.workspaceRef, role: "viewer" } } });
    expect(viewing.phase === "ready" && viewing.project.name).toBe("Alpha");
    await expect(viewer.api.createProject(created.workspaceRef, "Not allowed")).rejects.toMatchObject({ code: "forbidden", status: 403 });

    // The viewer's own default workspace is honored; another account's refs never are.
    const ownOnly = await resolveAccount(viewer.api, { workspaceRef: "ws_ffffffffffffffff", projectRef: beta.projectRef });
    expect(ownOnly).toMatchObject({ phase: "select_project", account: { workspace: { workspaceRef: viewerAccount.workspaceRef, role: "owner" } } });

    await owner.api.logout();
    expect(owner.cookie).toBeNull();
    await expect(resolveAccount(owner.api, {})).resolves.toEqual({ phase: "sign_in" });
    owner.cookie = firstToken;
    await expect(owner.api.me()).rejects.toMatchObject({ code: "auth_required", status: 401 });
    owner.cookie = null;

    await expect(owner.api.login("owner@example.test", "wrong-password-123")).rejects.toMatchObject({ code: "invalid_login", status: 403 });
    await owner.api.login("owner@example.test", SECRET);
    const back = await resolveAccount(owner.api, { workspaceRef: created.workspaceRef, projectRef: alpha.projectRef });
    expect(back.phase === "ready" && back.projects.map((item) => item.name).sort()).toEqual(["Alpha", "Beta"]);
  }, 60_000);
});
