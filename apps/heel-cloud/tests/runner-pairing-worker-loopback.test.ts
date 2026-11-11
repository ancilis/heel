// @vitest-environment node
// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/**
 * The complete runner pairing exchange through the product Worker into the real Python control plane.
 *
 * SEAM (loopback API-contract evidence only; not public acceptance):
 *   browser  — the product clients (`HeelCloudApi`, `CanaryApi`) with a transport that sends what a
 *              browser sends for a same-origin `fetch`: `Sec-Fetch-Site: same-origin` on every
 *              request, `Origin` only on non-GET/HEAD requests (Fetch §4.1 "append a request
 *              Origin header"), the `__Host-heel_session` cookie, and the edge-added
 *              `CF-Connecting-IP`. Each request is dispatched by the product `worker.fetch`.
 *   runner   — the released runner code (`heel.runner`: pairing material, `RunnerDaemon._exchange`,
 *              the transport's request framing and response decoder, the store's sealed v3
 *              activation and its v4 acceptance) posting bare `/v1/...` to a loopback listener that
 *              hands each request to the same `worker.fetch`.
 *   worker   — `env.CONTROL_PLANE.fetch` forwards the Worker's upstream request unchanged (method,
 *              path, allowlisted headers, body) to `heel.saas.http_api.serve` on 127.0.0.1, which
 *              requires the edge secret.
 * Not covered: TLS, the Cloudflare VPC/Tunnel hop, the deployed Worker and the live browser.
 * Opt in with HEEL_LOOPBACK_PYTHON=<python ≥3.11 with Heel's deps>.
 *
 * Privacy: the invitation token travels only through stdin to the runner process; assertions use
 * statuses, field names/types and equality, never printing token, cookie or challenge values.
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { resolve } from "node:path";
import { createInterface } from "node:readline";
import { afterAll, beforeAll, describe, expect, test, vi } from "vitest";

vi.mock("vinext/server/image-optimization", () => ({
  handleImageOptimization: vi.fn(), DEFAULT_DEVICE_SIZES: [], DEFAULT_IMAGE_SIZES: [],
}));
vi.mock("vinext/server/app-router-entry", () => ({ default: { fetch: vi.fn() } }));

import { CanaryApi, CanaryApiError, type CanaryTransport } from "../lib/canary-api";
import { HeelCloudApi, type HeelCloudTransport } from "../lib/heel-cloud-api";
import worker from "../worker/index";

const PYTHON = process.env.HEEL_LOOPBACK_PYTHON ?? "";
const REPO_ROOT = resolve(process.cwd(), "../..");
const PUBLIC_ORIGIN = "https://heel.test";
// Synthetic, test-only edge secret; never a deployment value.
const EDGE_SECRET = "e".repeat(43);
const CONTEXT = { waitUntil() {}, passThroughOnException() {} };

const CONTROL_PLANE = `
import sys, threading
sys.path.insert(0, sys.argv[1])
from heel.crypto import SigningAuthority
from heel.saas.http_api import ControlPlane, serve
# Synthetic, test-only peppers and authority; never deployment values.
cp = ControlPlane(device_token_pepper=b"d" * 32, runner_auth_pepper=b"r" * 32, enable_device_auth=True,
                  public_origin=sys.argv[2], edge_auth_secret=sys.argv[3],
                  grant_authority=SigningAuthority.generate())
server = serve(cp)
print(server.server_address[1], flush=True)
threading.Thread(target=server.serve_forever, daemon=True).start()
sys.stdin.read()
server.shutdown()
server.server_close()
`;

const RUNNER = `
import http.client, json, os, sys, tempfile, time
sys.path.insert(0, sys.argv[1])
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from heel import __version__
from heel.canary_contracts import canonical_bytes
from heel.crypto import ed25519_key_id
from heel.runner.control_transport import HTTPSControlTransport, _validate_headers, _validate_path
from heel.runner.daemon import RunnerDaemon, _adapter_versions
from heel.runner.identity import SecureSigner, create_runner_pairing_material
from heel.runner.store import RunnerStore

EDGE_PORT = int(sys.argv[2])

class Signer(SecureSigner):
    def __init__(self):
        self._key = Ed25519PrivateKey.generate()
        self.public_key = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = ed25519_key_id(self.public_key)
    def sign(self, payload):
        return self._key.sign(payload)

class EdgeTransport(HTTPSControlTransport):
    # The released transport's request framing and strict response decoder; plain loopback socket.
    def _exchange(self, path, *, headers, body, limit):
        path = _validate_path(path)
        request_headers = _validate_headers(headers)
        deadline = time.monotonic() + self._timeout
        connection = http.client.HTTPConnection("127.0.0.1", EDGE_PORT, timeout=self._timeout)
        try:
            connection.putrequest("POST", path, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", self._host)
            connection.putheader("Accept", "application/json")
            connection.putheader("Content-Length", str(len(body)))
            for name, value in request_headers.items():
                connection.putheader(name, value)
            connection.endheaders(body)
            return self._decode(connection.getresponse(), connection, deadline, limit)
        finally:
            connection.close()

def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)

transport = EdgeTransport(sys.argv[3])
signer = Signer()
material = create_runner_pairing_material("Loopback runner", __version__, _adapter_versions(), signer)
store = RunnerStore(os.path.realpath(tempfile.mkdtemp(prefix="heel-pairing-runner-")))
pending = activation = None
for line in sys.stdin:
    command = json.loads(line)
    if command["op"] == "exchange":
        body = canonical_bytes(material.executable_exchange_request(command["token"]))
        pending = RunnerDaemon._exchange(transport, body, material.fingerprint)
        emit({"schema_version": pending["schema_version"], "pairing_id": pending["pairing_id"],
              "runner_id": pending["runner_id"], "pairing_phrase": " ".join(material.pairing_phrase),
              "fingerprint": material.fingerprint})
    elif command["op"] == "activate":
        if activation is None:
            activation = material.prepare_executable_activation(pending, store=store, now_ms=int(time.time() * 1000))
        status, _, payload = transport.post(
            "/v1/runner-pairings/" + pending["pairing_id"] + "/activate",
            headers={"Content-Type": "application/json"}, body=canonical_bytes(dict(activation.request)),
        )
        result = {"status": status, "code": payload.get("code") if isinstance(payload, dict) else None}
        if status == 200:
            identity = store.accept_pairing_activation(activation, payload, now_ms=int(time.time() * 1000))
            result.update(schema_version=payload["schema_version"], workspace_id=identity.workspace_id,
                          runner_id=identity.runner_id, key_id_matches=identity.key_id == signer.key_id)
        emit(result)
`;

interface Upstream { method: string; path: string; headerNames: string[]; bodyBytes: number }

let controlPlane: ChildProcessWithoutNullStreams | null = null;
let controlPlanePort = 0;
let edge: Server | null = null;
let edgePort = 0;
const upstream: Upstream[] = [];

function workerEnv() {
  return {
    CONTROL_PLANE: {
      // The private binding: the Worker's exact upstream request, re-addressed to the loopback CP.
      async fetch(request: Request): Promise<Response> {
        const url = new URL(request.url);
        expect(url.origin).toBe(PUBLIC_ORIGIN);
        const body = request.method === "GET" ? null : new Uint8Array(await request.arrayBuffer());
        upstream.push({ method: request.method, path: url.pathname, headerNames: [...request.headers.keys()].sort(), bodyBytes: body?.byteLength ?? 0 });
        const headers = new Headers(request.headers);
        headers.delete("content-length");
        return fetch(`http://127.0.0.1:${controlPlanePort}${url.pathname}`, {
          body, headers, method: request.method, redirect: "manual",
        });
      },
    },
    CONTROL_PLANE_EDGE_SECRET: EDGE_SECRET,
    PUBLIC_ORIGIN,
  } as never;
}

async function viaWorker(path: string, init: { method: string; headers: Headers; body?: string }): Promise<Response> {
  const request = new Request(`${PUBLIC_ORIGIN}${path}`, { body: init.body, headers: init.headers, method: init.method });
  return worker.fetch(request, workerEnv(), CONTEXT);
}

/** A browser tab on the public origin: same-origin fetch headers, `__Host-` session cookie. */
class Browser {
  cookie: string | null = null;
  constructor(readonly fetchSite = "same-origin", readonly origin: string | null = PUBLIC_ORIGIN) {}

  async send(path: string, init: RequestInit): Promise<Response> {
    const method = init.method ?? "GET";
    const headers = new Headers(init.headers);
    headers.set("Sec-Fetch-Site", this.fetchSite);
    // A same-origin GET/HEAD carries no Origin; every other method carries the page origin.
    if (method !== "GET" && method !== "HEAD" && this.origin !== null) headers.set("Origin", this.origin);
    if (this.cookie !== null) headers.set("Cookie", `__Host-heel_session=${this.cookie}`);
    if (typeof init.body === "string") headers.set("Content-Length", String(new TextEncoder().encode(init.body).byteLength));
    headers.set("CF-Connecting-IP", "127.0.0.1");  // added by the Cloudflare edge, not the page
    const response = await viaWorker(path, { body: init.body as string | undefined, headers, method });
    for (const value of response.headers.getSetCookie()) {
      const match = /^__Host-heel_session=([^;]*)/.exec(value);
      if (match) this.cookie = /Max-Age=0/i.test(value) || match[1] === "" ? null : match[1];
    }
    return response;
  }

  readonly accountTransport: HeelCloudTransport = (path, init) => this.send(path, init);
  readonly canaryTransport: CanaryTransport = (path, init) => this.send(path, init);
  readonly account = new HeelCloudApi({ transport: this.accountTransport });
  readonly canary = new CanaryApi({ transport: this.canaryTransport });
}

/** The released runner process; one JSON command per line, one JSON result per line. */
class Runner {
  readonly #child: ChildProcessWithoutNullStreams;
  readonly #lines: AsyncIterator<string>;
  constructor() {
    this.#child = spawn(PYTHON, ["-I", "-c", RUNNER, REPO_ROOT, String(edgePort), PUBLIC_ORIGIN], { stdio: ["pipe", "pipe", "pipe"] });
    this.#lines = createInterface({ input: this.#child.stdout })[Symbol.asyncIterator]();
  }
  async command(value: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.#child.stdin.write(`${JSON.stringify(value)}\n`);
    const next = await this.#lines.next();
    if (next.done) throw new Error("runner process exited");
    return JSON.parse(next.value) as Record<string, unknown>;
  }
  async close(): Promise<void> {
    if (this.#child.exitCode !== null) return;
    const exited = new Promise((done) => this.#child.once("exit", done));
    this.#child.stdin.end();
    await exited;
  }
}

function shape(value: Record<string, unknown>): Record<string, string> {
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, typeof item]));
}

describe.skipIf(PYTHON === "")("runner pairing through the product Worker into the real ControlPlane (loopback)", () => {
  beforeAll(async () => {
    class LengthStream extends TransformStream<Uint8Array, Uint8Array> {
      constructor(length: number) { void length; super(); }
    }
    (globalThis as typeof globalThis & { FixedLengthStream: typeof LengthStream }).FixedLengthStream = LengthStream;

    controlPlane = spawn(PYTHON, ["-I", "-c", CONTROL_PLANE, REPO_ROOT, PUBLIC_ORIGIN, EDGE_SECRET], { stdio: ["pipe", "pipe", "pipe"] });
    const lines = createInterface({ input: controlPlane.stdout })[Symbol.asyncIterator]();
    const first = await Promise.race([
      lines.next(),
      new Promise<never>((_, fail) => controlPlane!.once("exit", (code) => fail(new Error(`control plane exited ${code}`)))),
    ]);
    controlPlanePort = Number(first.value);
    expect(Number.isInteger(controlPlanePort) && controlPlanePort > 0).toBe(true);

    // The runner's dashboard-origin socket: each request is handed, unchanged, to worker.fetch.
    edge = createServer((incoming, outgoing) => {
      const chunks: Buffer[] = [];
      incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
      incoming.on("end", async () => {
        const headers = new Headers();
        for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
          headers.append(incoming.rawHeaders[index], incoming.rawHeaders[index + 1]);
        }
        const body = Buffer.concat(chunks);
        const response = await viaWorker(incoming.url ?? "/", {
          body: incoming.method === "GET" ? undefined : body.toString("utf8"), headers, method: incoming.method ?? "GET",
        });
        const payload = Buffer.from(await response.arrayBuffer());
        outgoing.writeHead(response.status, Object.fromEntries([...response.headers.entries()].filter(([name]) => name !== "content-length")));
        outgoing.end(payload);
      });
    });
    await new Promise<void>((done) => edge!.listen(0, "127.0.0.1", done));
    edgePort = (edge.address() as AddressInfo).port;
  }, 30_000);

  afterAll(async () => {
    await new Promise((done) => edge?.close(done));
    const owned = controlPlane;
    controlPlane = null;
    if (owned === null || owned.exitCode !== null) return;
    const exited = new Promise((done) => owned.once("exit", done));
    owned.stdin.end();
    const timer = setTimeout(() => owned.kill("SIGKILL"), 5_000);
    await exited;
    clearTimeout(timer);
  });

  test("invite → released-format claim → browser inspect → approve → activate", async () => {
    const owner = new Browser();
    const account = await owner.account.signup("pairing-worker-owner@example.test", "Loopback-Worker-Pa55word");
    const workspace = account.workspaceRef;

    // 1. Invite (browser POST through the Worker).
    const invitation = await owner.canary.createRunnerPairingInvitation(workspace);
    expect(/^[A-Za-z0-9+/]{43}=$/.test(invitation.invitationToken)).toBe(true);

    // 2. Claim: the released runner's v3 exchange on the bare /v1 spelling, through the Worker.
    const runner = new Runner();
    try {
      const pending = await runner.command({ op: "exchange", token: invitation.invitationToken });
      expect(shape(pending)).toEqual({ schema_version: "string", pairing_id: "string", runner_id: "string", pairing_phrase: "string", fingerprint: "string" });
      expect(pending.schema_version).toBe("heel.runner-pairing-pending.v3");
      const pairingRef = pending.pairing_id as string;
      expect(pairingRef).toMatch(/^pending_[0-9a-f]{32}$/);

      // The runner polls activation before any approval: refused, retryable.
      expect(await runner.command({ op: "activate" })).toEqual({ status: 400, code: "invalid_runner_pairing" });

      // 3. Inspect: a same-origin browser GET (no Origin header) through the Worker.
      upstream.length = 0;
      const raw = await owner.send(`/api/control-plane/v1/workspaces/${workspace}/runner-pairings/${pairingRef}`, {
        method: "GET", headers: { Accept: "application/json" },
      });
      const rawBody = await raw.json() as Record<string, unknown>;
      expect({
        status: raw.status, contentType: raw.headers.get("Content-Type"), error: rawBody.error ?? null,
        reachedControlPlane: upstream.length,
      }).toEqual({ status: 200, contentType: "application/json", error: null, reachedControlPlane: 1 });
      upstream.length = 0;
      const view = await owner.canary.inspectRunnerPairing(workspace, pairingRef);
      expect(view).toEqual({
        pairingId: pairingRef, runnerId: pending.runner_id, pairingPhrase: pending.pairing_phrase,
        fingerprint: pending.fingerprint, status: "pending", expiresAt: expect.any(Number),
      });
      // The read stays a bodiless GET carrying only the edge-derived ceremony headers.
      expect(upstream).toEqual([{
        method: "GET", path: `/v1/workspaces/${workspace}/runner-pairings/${pairingRef}`,
        headerNames: ["cookie", "origin", "x-heel-edge-auth", "x-heel-internal-origin"], bodyBytes: 0,
      }]);

      // Owner/admin isolation is still the control plane's: another account's session is refused.
      const outsider = new Browser();
      await outsider.account.signup("pairing-worker-outsider@example.test", "Loopback-Outsider-Pa55word");
      await expect(outsider.canary.inspectRunnerPairing(workspace, pairingRef)).rejects.toMatchObject({ status: 403 });

      // A cross-site or unlabelled read, or a foreign Origin, never reaches the private binding.
      for (const browser of [new Browser("cross-site"), new Browser("same-site"), new Browser("none")]) {
        browser.cookie = owner.cookie;
        upstream.length = 0;
        await expect(browser.canary.inspectRunnerPairing(workspace, pairingRef)).rejects.toBeInstanceOf(CanaryApiError);
        expect(upstream).toEqual([]);
      }
      upstream.length = 0;
      const foreign = await viaWorker(`/api/control-plane/v1/workspaces/${workspace}/runner-pairings/${pairingRef}`, {
        method: "GET",
        headers: new Headers({ Cookie: `__Host-heel_session=${owner.cookie}`, "Sec-Fetch-Site": "same-origin", Origin: "https://evil.test" }),
      });
      expect(foreign.status).toBe(400);
      expect(upstream).toEqual([]);

      // 4. Approve: recent owner POST with the phrase and fingerprint the browser showed.
      await owner.canary.approveRunnerPairing(workspace, pairingRef, view.pairingPhrase, view.fingerprint);

      // 5. Activate: the runner resends its one sealed request and accepts the v4 response.
      const activated = await runner.command({ op: "activate" });
      expect(activated).toEqual({
        status: 200, code: null, schema_version: "heel.runner-pairing-activated.v4",
        workspace_id: workspace, runner_id: pending.runner_id, key_id_matches: true,
      });

      // The pairing is consumed: the browser can no longer inspect or approve it.
      await expect(owner.canary.inspectRunnerPairing(workspace, pairingRef)).rejects.toMatchObject({ status: 404 });
    } finally {
      await runner.close();
    }
  }, 120_000);
});
