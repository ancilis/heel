// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/**
 * Runner pairing invitation contract against the real Python control plane over loopback HTTP.
 *
 * SEAM: `ControlPlane(...)` (in-memory SQLite, runner auth enabled) served by
 * `heel.saas.http_api.serve` on 127.0.0.1. The transport maps `/api/control-plane/v1/…` to that
 * listener, carries the private `heel_session` cookie, and adds exactly the two same-origin headers
 * the Worker sets on a browser ceremony (`Origin` = public origin, `X-Heel-Internal-Origin`). The
 * Worker passes the response body through unchanged, so the bytes parsed here are the bytes the
 * server produced. There is no TLS, edge auth or `__Host-` translation: API-contract evidence only.
 * Opt in with HEEL_LOOPBACK_PYTHON=<python ≥3.11 with Heel's deps>.
 *
 * Privacy: the invitation token is a live one-time credential shape; assertions only check it
 * against the runner's grammar and never print or snapshot its value.
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { resolve } from "node:path";
import { createInterface } from "node:readline";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { CanaryApi, type CanaryTransport } from "../lib/canary-api";
import { HeelCloudApi, type HeelCloudTransport } from "../lib/heel-cloud-api";


const PYTHON = process.env.HEEL_LOOPBACK_PYTHON ?? "";
const REPO_ROOT = resolve(process.cwd(), "../..");
const PUBLIC_ORIGIN = "https://heel.test";
const LAUNCHER = `
import sys, threading
sys.path.insert(0, sys.argv[1])
from heel.saas.http_api import ControlPlane, serve
# Synthetic, test-only peppers; never a deployment value.
cp = ControlPlane(device_token_pepper=b"d" * 32, runner_auth_pepper=b"r" * 32,
                  enable_device_auth=True, public_origin=sys.argv[2])
server = serve(cp)
print(server.server_address[1], flush=True)
threading.Thread(target=server.serve_forever, daemon=True).start()
sys.stdin.read()
server.shutdown()
server.server_close()
`;
// The runner CLI's accepted invitation grammar (heel/runner/daemon.py `_INVITATION`).
const RUNNER_INVITATION = /^[A-Za-z0-9+/]{43}=$/;

let child: ChildProcessWithoutNullStreams | null = null;
let port = 0;


class Browser {
  cookie: string | null = null;

  async #send(path: string, init: RequestInit): Promise<Response> {
    expect(path.startsWith("/api/control-plane/v1/")).toBe(true);
    const headers = new Headers(init.headers);
    if (this.cookie !== null) headers.set("Cookie", `heel_session=${this.cookie}`);
    headers.set("Origin", PUBLIC_ORIGIN);
    headers.set("X-Heel-Internal-Origin", "same-origin");
    const response = await fetch(`http://127.0.0.1:${port}${path.slice("/api/control-plane".length)}`, {
      body: init.body, headers, method: init.method, redirect: "error", signal: init.signal,
    });
    for (const value of response.headers.getSetCookie()) {
      const match = /^heel_session=([^;]*)/.exec(value);
      if (match) this.cookie = /Max-Age=0/i.test(value) || match[1] === "" ? null : match[1];
    }
    return response;
  }

  readonly accountTransport: HeelCloudTransport = (path, init) => this.#send(path, init);
  readonly canaryTransport: CanaryTransport = (path, init) => this.#send(path, init);
  readonly account = new HeelCloudApi({ transport: this.accountTransport });
  readonly canary = new CanaryApi({ transport: this.canaryTransport });
}


describe.skipIf(PYTHON === "")("runner pairing invitation contract over loopback HTTP (real ControlPlane)", () => {
  beforeAll(async () => {
    child = spawn(PYTHON, ["-I", "-c", LAUNCHER, REPO_ROOT, PUBLIC_ORIGIN], { stdio: ["pipe", "pipe", "pipe"] });
    const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
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

  test("the server's actual 201 invitation is accepted and yields a runner-valid one-time token", async () => {
    // One invitation per workspace: at f3db25d2 a second live invitation in the same workspace is a
    // separate server-side failure (reported, not exercised here), so the raw observation and the
    // product-client call each use their own fresh synthetic account.
    const observer = new Browser();
    const observedAccount = await observer.account.signup("pairing-observer@example.test", "Loopback-Observer-Pa55word");

    // Observe the actual server response shape: status, media type, field names and types only.
    const observed = await observer.canaryTransport(`/api/control-plane/v1/workspaces/${observedAccount.workspaceRef}/runner-pairings`, {
      body: '{"schema_version":"heel.runner-pairing-invite.v1"}', method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
    });
    expect(observed.status).toBe(201);
    expect(observed.headers.get("Content-Type")).toBe("application/json");
    const body = await observed.json() as Record<string, unknown>;
    expect(Object.fromEntries(Object.entries(body).map(([key, value]) => [key, typeof value])))
      .toEqual({ schema_version: "string", invitation_token: "string", expires_at: "number" });
    expect(body.schema_version).toBe("heel.runner-pairing-invitation.v1");
    expect(RUNNER_INVITATION.test(body.invitation_token as string)).toBe(true);

    // The product client must accept the same server-produced response shape, unchanged.
    const owner = new Browser();
    const created = await owner.account.signup("pairing-owner@example.test", "Loopback-Pairing-Pa55word");
    const before = Date.now() / 1000;
    const invitation = await owner.canary.createRunnerPairingInvitation(created.workspaceRef);
    expect(RUNNER_INVITATION.test(invitation.invitationToken)).toBe(true);
    expect(invitation.invitationToken === body.invitation_token).toBe(false);  // never reused across invitations
    expect(invitation.expiresAt).toBeGreaterThan(before + 9 * 60);
    expect(invitation.expiresAt).toBeLessThanOrEqual(Date.now() / 1000 + 10 * 60 + 1);
    expect(Object.isFrozen(invitation)).toBe(true);

    // Workspace attribution: another account's workspace is still refused by the server.
    const outsider = new Browser();
    await outsider.account.signup("pairing-outsider@example.test", "Loopback-Outsider-Pa55word");
    await expect(outsider.canary.createRunnerPairingInvitation(created.workspaceRef)).rejects.toMatchObject({ status: 403 });
  }, 60_000);
});
