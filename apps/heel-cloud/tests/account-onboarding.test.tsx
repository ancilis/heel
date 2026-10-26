// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/**
 * Dashboard account onboarding flows.
 *
 * SEAM: `fetch` is replaced by an in-memory fake of the control-plane account routes and the
 * App Router is stubbed. This proves the UI state machine and its use of the real client, not
 * production signup; `account-loopback.test.ts` exercises the real Python control plane.
 */

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import Dashboard from "../app/dashboard/page";
import { CanaryApi, CanaryApiError } from "../lib/canary-api";


const nav = vi.hoisted(() => ({ search: "", replace: vi.fn() }));
vi.mock("next/navigation", () => ({
  usePathname: () => "/dashboard",
  useRouter: () => nav,
  useSearchParams: () => new URLSearchParams(nav.search),
}));

const SECRET = "Canary-Pa55word-7f3e91";
const EMAIL = "founder@example.test";

type Role = "owner" | "admin" | "member" | "viewer" | "billing";
type Wire = Record<string, unknown>;
interface Account { userId: string; email: string; password: string; memberships: { workspace_id: string; role: Role }[] }


function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
}


function hex(value: number, length: number): string {
  return value.toString(16).padStart(length, "0");
}


/** A `VerifiedEnvironment.v1` list entry as the control plane stores it; only verified entries are executable. */
function environmentWire(environmentId: string, origin: string, proofMethod: string, verified: boolean, generation = 1): Wire {
  return {
    schema_version: "VerifiedEnvironment.v1", environment_id: environmentId, origin, environment_class: "staging",
    status: verified ? "verified" : "pending", attestation: "ownership verified; environment classification supplied by you",
    attestation_version: "v1", attestation_acknowledgement: "accepted", proof_method: proofMethod,
    proof_version: proofMethod === "https-file" ? "https-file.v1" : "dns-txt.v1", normalization_version: "exact-origin.v1",
    challenge_generation: generation, challenge_expires_at: 4_000_000_000_000, last_failure_code: null,
    verified_at: verified ? 1 : null, proof_expires_at: verified ? 4_000_000_000_000 : null,
    verification_record_digest: verified ? "a".repeat(64) : null, revoked_at: null, is_executable: verified,
  };
}


/** In-memory stand-in for the account routes; one "cookie" models the HttpOnly session. */
class FakeControlPlane {
  readonly accounts = new Map<string, Account>();
  readonly projects = new Map<string, Wire[]>();
  readonly calls: { method: string; path: string; body: string }[] = [];
  session: Account | null = null;
  next = 1;
  offline = false;
  /** Models the real control plane without its canary signing authority: canary reads 503. */
  canaryOutage = false;
  /** Paths whose response waits for `release(path)`. */
  readonly held = new Map<string, { wait: Promise<void>; release: () => void }>();
  overrides = new Map<string, () => Response>();
  /** Target-proof environments per `workspace/project`, persisted across page loads like the server's. */
  readonly environments = new Map<string, Wire[]>();
  /** Whether the customer has published the proof; until then a check answers `verified: false`. */
  proofPublished = false;
  /** Server-side pending challenge per environment, like the real row's `challenge_token`; never in the list. */
  readonly challenges = new Map<string, { token: string; generation: number; expired: boolean }>();
  /** Models the control plane's 15-minute owner/admin ceremony; a real login makes the session recent again. */
  recentAuth = true;

  account(email: string, password: string, memberships: { role: Role; projects?: string[] }[]): Account {
    const account: Account = { userId: `usr_${hex(this.next++, 16)}`, email, password, memberships: [] };
    for (const membership of memberships) {
      const workspaceRef = `ws_${hex(this.next++, 16)}`;
      account.memberships.push({ workspace_id: workspaceRef, role: membership.role });
      this.projects.set(workspaceRef, []);
      for (const name of membership.projects ?? []) this.addProject(workspaceRef, name, account.userId);
    }
    this.accounts.set(email, account);
    return account;
  }

  addProject(workspaceRef: string, name: string, userId: string): Wire {
    const project = { workspace_id: workspaceRef, project_ref: `prj_${hex(this.next++, 32)}`, name, created_by: `membership:${userId}`, created_at: this.next };
    this.projects.get(workspaceRef)?.push(project);
    return project;
  }

  /** A pending record left by an earlier page load; its challenge exists only server-side. */
  seedPending(workspaceRef: string, projectRef: string, origin: string, proofMethod = "dns-txt"): string {
    const environmentId = `env_${hex(this.next++, 32)}`;
    const key = `${workspaceRef}/${projectRef}`;
    this.environments.set(key, [...(this.environments.get(key) ?? []), environmentWire(environmentId, origin, proofMethod, false)]);
    this.challenges.set(environmentId, { token: `synthetic-proof-token-${this.next++}`, generation: 1, expired: false });
    return environmentId;
  }

  hold(path: string): () => void {
    let release = () => {};
    const wait = new Promise<void>((resolve) => { release = resolve; });
    this.held.set(path, { wait, release });
    return () => { this.held.delete(path); release(); };
  }

  readonly fetch = async (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
    const path = String(input);
    const method = init.method ?? "GET";
    const body = typeof init.body === "string" ? init.body : "";
    this.calls.push({ method, path, body });
    if (this.offline) throw new TypeError("network down");
    const held = this.held.get(path);
    if (held) await held.wait;
    const override = this.overrides.get(`${method} ${path}`);
    if (override) return override();
    const route = path.replace(/^\/api\/control-plane/, "");
    const data = body ? JSON.parse(body) as Wire : {};
    if (method === "POST" && route === "/v1/signup") {
      const email = String(data.email ?? "").trim();
      const password = String(data.password ?? "");
      if (!email.includes("@")) return json({ error: "valid email required" }, 400);
      if (password.length < 10) return json({ error: "password must be at least 10 characters" }, 400);
      if (this.accounts.has(email)) return json({ error: "account already exists" }, 409);
      this.session = this.account(email, password, [{ role: "owner" }]);
      return json({ user_id: this.session.userId, workspace_id: this.session.memberships[0].workspace_id }, 201);
    }
    if (method === "POST" && route === "/v1/login") {
      const account = this.accounts.get(String(data.email ?? "").trim());
      if (account === undefined || account.password !== data.password) return json({ error: "invalid email or password" }, 403);
      this.session = account;
      this.recentAuth = true;
      return json({ user_id: account.userId });
    }
    if (method === "POST" && route === "/v1/logout") {
      this.session = null;
      return json({ ok: true });
    }
    if (this.session === null) return json({ error: "authentication required" }, 401);
    if (method === "GET" && route === "/v1/me") {
      return json({ user_id: this.session.userId, workspaces: this.session.memberships });
    }
    const projects = route.match(/^\/v1\/workspaces\/(ws_[0-9a-f]{16})\/projects$/);
    if (projects) {
      const membership = this.session.memberships.find((item) => item.workspace_id === projects[1]);
      if (membership === undefined) return json({ error: "not a member" }, 403);
      if (method === "GET") {
        if (membership.role === "billing") return json({ error: "insufficient role" }, 403);
        return json({ projects: this.projects.get(projects[1]) ?? [] });
      }
      if (!["owner", "admin", "member"].includes(membership.role)) return json({ error: "insufficient role" }, 403);
      return json(this.addProject(projects[1], String(data.name).trim(), this.session.userId), 201);
    }
    if (this.canaryOutage && /\/projects\/prj_[0-9a-f]{32}\/runner-context-bindings$/.test(route)) {
      return json({ code: "canary_authority_unavailable" }, 503);
    }
    const target = route.match(/^\/v1\/workspaces\/(ws_[0-9a-f]{16})\/projects\/(prj_[0-9a-f]{32})\/environments(?:\/(env_[0-9a-f]{32})\/(check|challenge|challenge\/rotate))?$/);
    if (target) {
      if (!this.session.memberships.some((item) => item.workspace_id === target[1])) return json({ error: "not a member" }, 403);
      const key = `${target[1]}/${target[2]}`;
      const stored = this.environments.get(key) ?? [];
      if (method === "GET" && target[3] === undefined) {
        return json({ schema_version: "heel.verified-environment-list.v1", environments: stored });
      }
      if (method !== "POST") return json({ error: "not found" }, 404);
      if (!this.recentAuth) return json({ error: "a recent owner or admin browser session is required", code: "recent_auth_required" }, 403);
      const instructions = (origin: string, token: string) => ({
        http_url: `${origin}/.well-known/heel-verify.txt`, dns_record: `_heel.${origin.slice("https://".length)} TXT heel-verify=${token}`,
      });
      if (target[3] === undefined) {
        // Like the real service, a start for an origin this project already has replaces that record's challenge.
        const origin = String(data.origin);
        const existing = stored.find((item) => item.origin === origin);
        const environmentId = (existing?.environment_id as string | undefined) ?? `env_${hex(this.next++, 32)}`;
        const generation = (this.challenges.get(environmentId)?.generation ?? 0) + 1;
        const record = environmentWire(environmentId, origin, String(data.proof_method), false, generation);
        this.environments.set(key, existing ? stored.map((item) => item === existing ? record : item) : [...stored, record]);
        const token = `synthetic-proof-token-${this.next++}`;
        this.challenges.set(environmentId, { token, generation, expired: false });
        return json({
          schema_version: "heel.verified-environment-challenge.v1", environment_id: environmentId, origin,
          environment_class: data.environment_class, proof_method: data.proof_method, token, ...instructions(origin, token),
          challenge_generation: generation, expires_at: 4_000_000_000_000, attestation: data.attestation_text,
        }, 201);
      }
      const index = stored.findIndex((item) => item.environment_id === target[3]);
      if (index < 0) return json({ error: "environment not found", code: "environment_not_found" }, 404);
      const record = stored[index];
      const current = this.challenges.get(target[3]);
      if (target[4] !== "check") {
        const rotate = target[4] === "challenge/rotate";
        const schema = `heel.verified-environment-challenge-${rotate ? "rotate" : "recover"}.v1`;
        if (Object.keys(data).join() !== "schema_version" || data.schema_version !== schema) return json({ error: "invalid", code: "invalid_environment_challenge" }, 400);
        if (record.status !== "pending") return json({ error: "proof is not pending", code: "environment_challenge_closed" }, 409);
        if (!rotate && (current === undefined || current.expired)) return json({ error: "pending proof expired", code: "environment_challenge_expired" }, 409);
        if (rotate && current !== undefined && !current.expired) return json({ error: "pending proof is still current", code: "environment_challenge_live" }, 409);
        let challenge = current as { token: string; generation: number; expired: boolean };
        if (rotate) {
          challenge = { token: `synthetic-proof-token-${this.next++}`, generation: (current?.generation ?? 0) + 1, expired: false };
          this.challenges.set(target[3], challenge);
          this.environments.set(key, stored.map((item, position) => position === index
            ? environmentWire(target[3], String(record.origin), String(record.proof_method), false, challenge.generation) : item));
        }
        return json({
          schema_version: "heel.verified-environment-challenge-recovery.v1", environment_id: target[3], origin: record.origin,
          environment_class: record.environment_class, proof_method: record.proof_method, token: challenge.token,
          ...instructions(String(record.origin), challenge.token), challenge_generation: challenge.generation,
          expires_at: 4_000_000_000_000, attestation: record.attestation, attestation_version: "v1", attestation_acknowledgement: "accepted",
        }, rotate ? 201 : 200);
      }
      const verified = this.proofPublished && current !== undefined && !current.expired;
      if (verified) {
        const verifiedRecord = environmentWire(target[3], String(record.origin), String(record.proof_method), true, current.generation);
        this.environments.set(key, stored.map((item, position) => position === index ? verifiedRecord : item));
        this.challenges.delete(target[3]);
      }
      return json({ schema_version: "heel.verified-environment-check-result.v1", verified });
    }
    if (method === "GET" && /\/projects\/prj_[0-9a-f]{32}\/runner-context-bindings$/.test(route)) {
      return json({ schema_version: "heel.runner-context-binding-dashboard.v1", server_time_ms: 1, runners: [], bindings: [] });
    }
    return json({ error: "not modeled" }, 503);
  };
}


/** Records every write; Node 25's own `localStorage` global has no backing store under jsdom. */
function recordingStorage(): Storage {
  const items = new Map<string, string>();
  return {
    get length() { return items.size; },
    clear: () => items.clear(),
    getItem: (key: string) => items.get(key) ?? null,
    key: (index: number) => [...items.keys()][index] ?? null,
    removeItem: (key: string) => { items.delete(key); },
    setItem: (key: string, value: string) => { items.set(key, String(value)); },
  };
}

let server: FakeControlPlane;
const consoleOutput: string[] = [];

beforeEach(() => {
  server = new FakeControlPlane();
  nav.search = "";
  nav.replace.mockReset();
  nav.replace.mockImplementation((href: string) => { nav.search = href.split("?")[1] ?? ""; });
  vi.stubGlobal("fetch", server.fetch);
  vi.stubGlobal("localStorage", recordingStorage());
  vi.stubGlobal("sessionStorage", recordingStorage());
  consoleOutput.length = 0;
  for (const level of ["log", "info", "warn", "error", "debug"] as const) {
    vi.spyOn(console, level).mockImplementation((...args: unknown[]) => { consoleOutput.push(args.map(String).join(" ")); });
  }
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});


function fill(label: RegExp, value: string): void {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}


function expectNoSecretLeak(): void {
  expect(document.body.innerHTML).not.toContain(SECRET);
  for (const input of Array.from(document.querySelectorAll("input"))) expect(input.value).not.toContain(SECRET);
  expect(nav.replace.mock.calls.flat().join(" ")).not.toContain(SECRET);
  expect(nav.search).not.toContain(SECRET);
  expect(globalThis.localStorage.length).toBe(0);
  expect(globalThis.sessionStorage.length).toBe(0);
  expect(consoleOutput.join("\n")).not.toContain(SECRET);
  for (const call of server.calls) {
    expect(call.path).not.toContain(SECRET);
    if (!/\/v1\/(signup|login)$/.test(call.path)) expect(call.body).not.toContain(SECRET);
  }
}


async function signUp(): Promise<void> {
  render(<Dashboard />);
  await screen.findByRole("heading", { name: "Create your Heel account" });
  fill(/^Email/, EMAIL);
  fill(/^Password/, SECRET);
  fireEvent.click(screen.getByRole("button", { name: "Create free account" }));
}


describe("dashboard account onboarding", () => {
  test("a new visitor signs up, creates a first project and lands in that project", async () => {
    await signUp();
    await screen.findByText("Create a project first.");
    const bar = screen.getByRole("region", { name: "Workspace and project" });
    expect(within(bar).getByRole("combobox", { name: /workspace/i })).toBeTruthy();
    // The workspace bar renders before the URL-sync effect writes the address, so wait for it.
    await waitFor(() => expect(nav.search).toMatch(/^workspace=ws_[0-9a-f]{16}$/));

    fireEvent.change(within(bar).getByLabelText(/new project/i), { target: { value: "  Billing staging  " } });
    fireEvent.click(within(bar).getByRole("button", { name: "Create project" }));

    await screen.findByText("Project created. Add a target next.");
    const created = server.calls.find((call) => call.method === "POST" && call.path.endsWith("/projects"));
    expect(JSON.parse(created?.body ?? "{}")).toEqual({ name: "Billing staging" });
    const project = screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement;
    expect(project.selectedOptions[0].textContent).toBe("Billing staging");
    // The address is written by the URL-sync effect after the commit that shows the notice, so wait for it.
    await waitFor(() => expect(nav.search).toMatch(/^workspace=ws_[0-9a-f]{16}&project=prj_[0-9a-f]{32}$/));
    expect(screen.queryByText(/Create your Heel account/)).toBeNull();
    expectNoSecretLeak();
  });

  test("a duplicate email is explained, switches to sign-in and never keeps the password", async () => {
    server.account(EMAIL, "an-older-password", [{ role: "owner" }]);
    await signUp();
    expect((await screen.findByRole("alert")).textContent).toBe("An account with that email already exists. Sign in instead.");
    expect(screen.getByRole("heading", { name: "Sign in to Heel" })).toBeTruthy();
    expect((screen.getByLabelText(/^Password/) as HTMLInputElement).value).toBe("");
    expect(server.session).toBeNull();
    expectNoSecretLeak();
  });

  test("invalid input and a wrong password show closed messages without echoing values", async () => {
    server.account(EMAIL, "the-right-password", [{ role: "owner", projects: ["Main"] }]);
    render(<Dashboard />);
    await screen.findByRole("heading", { name: "Create your Heel account" });
    fireEvent.click(screen.getByRole("button", { name: /already have an account/i }));
    fill(/^Email/, EMAIL);
    fill(/^Password/, SECRET);
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("That email and password did not match an account.");
    expect(alert.textContent).not.toContain(EMAIL);
    expectNoSecretLeak();

    fill(/^Password/, "the-right-password");
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await screen.findByRole("combobox", { name: /project/i });
    expect(screen.queryByRole("alert")).toBeNull();
  });

  test("a reload restores the server-confirmed workspace and project from the address", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "viewer", projects: ["Viewer project"] }, { role: "owner", projects: ["Alpha", "Beta"] }]);
    server.session = account;
    const ownerWs = account.memberships[1].workspace_id;
    const beta = server.projects.get(ownerWs)?.[1].project_ref as string;
    nav.search = `workspace=${ownerWs}&project=${beta}`;

    render(<Dashboard />);
    const project = await screen.findByRole("combobox", { name: /project/i }) as HTMLSelectElement;
    expect(project.value).toBe(beta);
    expect((screen.getByRole("combobox", { name: /workspace/i }) as HTMLSelectElement).value).toBe(ownerWs);
    expect(nav.replace).not.toHaveBeenCalled();
  });

  test("an address naming someone else's workspace is replaced by this account's own context", async () => {
    const other = server.account("other@example.test", "other-password", [{ role: "owner", projects: ["Theirs"] }]);
    const mine = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Mine"] }]);
    server.session = mine;
    nav.search = `workspace=${other.memberships[0].workspace_id}&project=${server.projects.get(other.memberships[0].workspace_id)?.[0].project_ref as string}`;

    render(<Dashboard />);
    const project = await screen.findByRole("combobox", { name: /project/i }) as HTMLSelectElement;
    expect(project.selectedOptions[0].textContent).toBe("Mine");
    expect(document.body.textContent).not.toContain("Theirs");
    expect(server.calls.some((call) => call.path.includes(other.memberships[0].workspace_id))).toBe(false);
    // The URL-sync effect replaces the address after the commit that shows this account's project, so wait for it.
    await waitFor(() => expect(nav.search).toContain(mine.memberships[0].workspace_id));
  });

  test("switching workspace re-reads the server identity and role before showing projects", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Owned"] }, { role: "viewer", projects: ["Watched"] }]);
    server.session = account;
    render(<Dashboard />);
    await screen.findByRole("combobox", { name: /project/i });
    const meCalls = server.calls.filter((call) => call.path.endsWith("/v1/me")).length;

    fireEvent.change(screen.getByRole("combobox", { name: /workspace/i }), { target: { value: account.memberships[1].workspace_id } });
    await screen.findByText(/Your viewer role can view this workspace but cannot create projects/);
    expect(server.calls.filter((call) => call.path.endsWith("/v1/me")).length).toBe(meCalls + 1);
    expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).selectedOptions[0].textContent).toBe("Watched");
    expect(screen.queryByLabelText(/new project/i)).toBeNull();
  });

  test("the server, not the hidden button, decides: a refused create shows the role message", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "member", projects: ["Shared"] }]);
    server.session = account;
    server.overrides.set(`POST /api/control-plane/v1/workspaces/${account.memberships[0].workspace_id}/projects`,
      () => json({ error: "insufficient role" }, 403));
    render(<Dashboard />);
    fireEvent.change(await screen.findByLabelText(/new project/i), { target: { value: "Another" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Your role in this workspace does not allow that action.");
    expect(server.projects.get(account.memberships[0].workspace_id)).toHaveLength(1);
  });

  test("a billing-only workspace is shown as unavailable to the role, with a way to switch", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "billing" }, { role: "viewer" }]);
    server.session = account;
    nav.search = `workspace=${account.memberships[0].workspace_id}`;
    render(<Dashboard />);
    await screen.findByText("This workspace is not available to your role.");
    expect(screen.getByText(/Your billing role cannot open projects in this workspace/)).toBeTruthy();
    fireEvent.change(screen.getByRole("combobox", { name: /workspace/i }), { target: { value: account.memberships[1].workspace_id } });
    await screen.findByText("No projects exist yet. A workspace owner, admin or member must create one.");
  });

  test("sign out clears the private context and the address, and a late create cannot repopulate it", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Secret roadmap"] }]);
    server.session = account;
    render(<Dashboard />);
    await screen.findByRole("combobox", { name: /project/i });
    const projectsPath = `/api/control-plane/v1/workspaces/${account.memberships[0].workspace_id}/projects`;
    const release = server.hold(projectsPath);

    fireEvent.change(screen.getByLabelText(/new project/i), { target: { value: "Late arrival" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    await waitFor(() => expect(server.calls.some((call) => call.method === "POST" && call.path === projectsPath)).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await screen.findByText("You signed out. Sign in again to continue.");
    const callsAfterSignOut = server.calls.length;

    await act(async () => { release(); await Promise.resolve(); });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(document.body.textContent).not.toMatch(/Secret roadmap|Late arrival/);
    expect(screen.getByRole("heading", { name: "Create your Heel account" })).toBeTruthy();
    expect(server.calls.length).toBe(callsAfterSignOut);
    expect(nav.search).toBe("");
    expectNoSecretLeak();
  });

  test("a second account signing in after sign-out sees only its own context", async () => {
    server.account("first@example.test", "first-password", [{ role: "owner", projects: ["First private"] }]);
    const second = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Second project"] }]);
    server.session = server.accounts.get("first@example.test") ?? null;
    render(<Dashboard />);
    await screen.findByRole("combobox", { name: /project/i });
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await screen.findByRole("heading", { name: "Create your Heel account" });
    fireEvent.click(screen.getByRole("button", { name: /already have an account/i }));
    fill(/^Email/, EMAIL);
    fill(/^Password/, SECRET);
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    const project = await screen.findByRole("combobox", { name: /project/i }) as HTMLSelectElement;
    expect(project.selectedOptions[0].textContent).toBe("Second project");
    expect(document.body.textContent).not.toContain("First private");
    expectNoSecretLeak();
    // The URL-sync effect writes the second account's address after the commit that shows its project, so wait for it.
    await waitFor(() => expect(nav.search).toContain(second.memberships[0].workspace_id));
    expectNoSecretLeak();
  });

  test("an expired session during an action returns to sign-in and drops the private context", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Expiring"] }]);
    server.session = account;
    render(<Dashboard />);
    await screen.findByRole("combobox", { name: /project/i });
    server.session = null;
    fireEvent.change(screen.getByLabelText(/new project/i), { target: { value: "After expiry" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    await screen.findByText(/Your session ended\. Sign in again to continue/);
    expect(document.body.textContent).not.toContain("Expiring");
    expect(screen.getByRole("heading", { name: "Create your Heel account" })).toBeTruthy();
    // The URL-sync effect clears the address after the commit that shows sign-in, so wait for it.
    await waitFor(() => expect(nav.search).toBe(""));
  });

  test("an unavailable service is a retryable error, not a signed-out state", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Back online"] }]);
    server.session = account;
    server.offline = true;
    render(<Dashboard />);
    await screen.findByText("Heel Cloud could not load your workspace.");
    expect(screen.queryByRole("heading", { name: "Create your Heel account" })).toBeNull();
    server.offline = false;
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    const project = await screen.findByRole("combobox", { name: /project/i }) as HTMLSelectElement;
    expect(project.selectedOptions[0].textContent).toBe("Back online");
  });

  test("a sign-out the server cannot confirm keeps the user signed in and says so", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Still here"] }]);
    server.session = account;
    server.overrides.set("POST /api/control-plane/v1/logout", () => json({ error: "down" }, 503));
    render(<Dashboard />);
    await screen.findByRole("combobox", { name: /project/i });
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await screen.findByText("Heel Cloud could not confirm sign-out, so you are still signed in. Try again.");
    expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).selectedOptions[0].textContent).toBe("Still here");
  });
});


/** Waits out pending microtasks and the fake's async hops without asserting anything. */
async function settle(): Promise<void> {
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 30)); });
}


async function signInFromSignedOut(email: string, password: string): Promise<void> {
  await screen.findByRole("heading", { name: "Create your Heel account" });
  fireEvent.click(screen.getByRole("button", { name: /already have an account/i }));
  fill(/^Email/, email);
  fill(/^Password/, password);
  fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
}


/** Same-document navigation: the App Router re-renders the page with new search params. */
function navigate(view: ReturnType<typeof render>, search: string): void {
  nav.search = search;
  view.rerender(<Dashboard />);
}


function expectCanaryLocked(): void {
  expect(screen.queryByRole("heading", { name: "Add target" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Create ownership proof" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Authorize paired runner" })).toBeNull();
  expect(screen.queryByText("Ready for customer setup")).toBeNull();
}


describe("C7AR1 R1: a canary service outage keeps the signed-in account usable", () => {
  test("a first project created during the outage is kept, with account controls and a truthful blocked next step", async () => {
    server.canaryOutage = true;
    await signUp();
    await screen.findByText("Create a project first.");
    fill(/new project/i, "Billing staging");
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));

    await screen.findByText("Canary setup could not be loaded.");
    await screen.findByText(/Project created\. Canary setup is unavailable right now/);
    expect(screen.queryByText(/Add a target next/)).toBeNull();
    const project = screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement;
    expect(project.selectedOptions[0].textContent).toBe("Billing staging");
    expect(nav.search).toMatch(/^workspace=ws_[0-9a-f]{16}&project=prj_[0-9a-f]{32}$/);
    expect(nav.search).toContain(project.value);
    expect(screen.getByRole("button", { name: "Sign out" })).toBeTruthy();
    expect(screen.queryByText("Heel Cloud could not load your workspace.")).toBeNull();
    expectCanaryLocked();
    expectNoSecretLeak();

    server.canaryOutage = false;
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    await screen.findByRole("heading", { name: "Add target" });
    expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).value).toBe(project.value);

    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await screen.findByText("You signed out. Sign in again to continue.");
    expect(document.body.textContent).not.toContain("Billing staging");
    // The URL-sync effect clears the address after the commit that shows the sign-out notice, so wait for it.
    await waitFor(() => expect(nav.search).toBe(""));
  });

  test("a ready account that loses the canary service keeps project switching and sign-out, then recovers", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Alpha", "Beta"] }]);
    server.session = account;
    const ws = account.memberships[0].workspace_id;
    const [alpha, beta] = (server.projects.get(ws) ?? []).map((item) => item.project_ref as string);
    render(<Dashboard />);
    await screen.findByRole("heading", { name: "Add target" });

    server.canaryOutage = true;
    fireEvent.change(screen.getByRole("combobox", { name: /project/i }), { target: { value: beta } });
    await screen.findByText("Canary setup could not be loaded.");
    expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).value).toBe(beta);
    // The outage notice can render before the URL-sync effect writes Beta's address, so wait for it.
    await waitFor(() => expect(nav.search).toBe(`workspace=${ws}&project=${beta}`));
    expectCanaryLocked();

    fireEvent.change(screen.getByRole("combobox", { name: /project/i }), { target: { value: alpha } });
    await waitFor(() => expect(nav.search).toBe(`workspace=${ws}&project=${alpha}`));
    expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).value).toBe(alpha);
    expectCanaryLocked();

    server.canaryOutage = false;
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    await screen.findByRole("heading", { name: "Add target" });
    expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).value).toBe(alpha);

    server.canaryOutage = true;
    fireEvent.change(screen.getByRole("combobox", { name: /project/i }), { target: { value: beta } });
    await screen.findByText("Canary setup could not be loaded.");
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await screen.findByText("You signed out. Sign in again to continue.");
    expect(server.session).toBeNull();
    // The URL-sync effect clears the address after the commit that shows the sign-out notice, so wait for it.
    await waitFor(() => expect(nav.search).toBe(""));
  });

  test("a canary 401 is still session loss, not an outage", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Expiring"] }]);
    server.session = account;
    const ws = account.memberships[0].workspace_id;
    const prj = server.projects.get(ws)?.[0].project_ref as string;
    server.overrides.set(`GET /api/control-plane/v1/workspaces/${ws}/projects/${prj}/runner-context-bindings`,
      () => json({ error: "authentication required" }, 401));
    render(<Dashboard />);
    await screen.findByText(/Your session ended\. Sign in again to continue/);
    expect(screen.queryByRole("combobox", { name: /project/i })).toBeNull();
    expect(nav.search).toBe("");
  });

  test("an account service failure stays distinct from a canary outage and still offers sign-out", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Main"] }]);
    server.session = account;
    server.overrides.set("GET /api/control-plane/v1/me", () => json({ error: "down" }, 503));
    render(<Dashboard />);
    await screen.findByText("Heel Cloud could not load your workspace.");
    expect(screen.queryByText("Canary setup could not be loaded.")).toBeNull();
    expect(screen.queryByRole("combobox", { name: /project/i })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await screen.findByText("You signed out. Sign in again to continue.");
    expect(server.session).toBeNull();
  });
});


describe("C7AR1 R2: responses from a previous session never change the current one", () => {
  async function holdCreateThenSwitchAccount(response: () => Response): Promise<{ release: () => void; second: Account }> {
    const first = server.account("first@example.test", "first-password", [{ role: "owner", projects: ["First"] }]);
    const second = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Second"] }]);
    server.session = first;
    render(<Dashboard />);
    await screen.findByRole("combobox", { name: /project/i });
    const path = `/api/control-plane/v1/workspaces/${first.memberships[0].workspace_id}/projects`;
    const release = server.hold(path);
    server.overrides.set(`POST ${path}`, response);
    fill(/new project/i, "Old request");
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    await waitFor(() => expect(server.calls.some((call) => call.method === "POST" && call.path === path)).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await signInFromSignedOut(EMAIL, SECRET);
    await screen.findByRole("combobox", { name: /project/i });
    expect(server.session).toBe(second);
    return { release, second };
  }

  test("a delayed 401 from the previous account cannot sign out the new account's view", async () => {
    const { release, second } = await holdCreateThenSwitchAccount(() => json({ error: "authentication required" }, 401));
    await act(async () => { release(); });
    await settle();
    expect(server.session).toBe(second);
    expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).selectedOptions[0].textContent).toBe("Second");
    expect(screen.queryByText(/Your session ended/)).toBeNull();
    expect(nav.search).toContain(second.memberships[0].workspace_id);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  test("a delayed refusal or late success from the previous account shows nothing in the new account", async () => {
    const { release, second } = await holdCreateThenSwitchAccount(() => json({ error: "insufficient role" }, 403));
    await act(async () => { release(); });
    await settle();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByText(/Project created/)).toBeNull();
    expect(nav.search).toContain(second.memberships[0].workspace_id);
  });

  test("a create whose follow-up load is overtaken by navigation does not announce or select it", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Alpha", "Beta"] }]);
    server.session = account;
    const ws = account.memberships[0].workspace_id;
    const beta = server.projects.get(ws)?.[1].project_ref as string;
    const view = render(<Dashboard />);
    await screen.findByRole("combobox", { name: /project/i });
    const meCalls = () => server.calls.filter((call) => call.path.endsWith("/v1/me")).length;
    const release = server.hold("/api/control-plane/v1/me");
    fill(/new project/i, "Announced late");
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    await waitFor(() => expect(meCalls()).toBe(2));
    navigate(view, `workspace=${ws}&project=${beta}`);
    await waitFor(() => expect(meCalls()).toBe(3));
    await act(async () => { release(); });
    await settle();
    expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).value).toBe(beta);
    expect(screen.queryByText(/Project created/)).toBeNull();
    expect(nav.search).toBe(`workspace=${ws}&project=${beta}`);
  });

  test("an expiry in the current session still ends the view", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Current"] }]);
    server.session = account;
    render(<Dashboard />);
    await screen.findByRole("combobox", { name: /project/i });
    const path = `/api/control-plane/v1/workspaces/${account.memberships[0].workspace_id}/projects`;
    const release = server.hold(path);
    server.overrides.set(`POST ${path}`, () => json({ error: "authentication required" }, 401));
    fill(/new project/i, "Expiring request");
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    await waitFor(() => expect(server.calls.some((call) => call.method === "POST" && call.path === path)).toBe(true));
    await act(async () => { release(); });
    await screen.findByText(/Your session ended\. Sign in again to continue/);
    expect(document.body.textContent).not.toContain("Current");
    expect(nav.search).toBe("");
  });
});


describe("C7AR1 R3: same-document navigation is revalidated and applied", () => {
  function twoProjects(): { ws: string; alpha: string; beta: string } {
    const account = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Alpha", "Beta"] }]);
    server.session = account;
    const ws = account.memberships[0].workspace_id;
    const [alpha, beta] = (server.projects.get(ws) ?? []).map((item) => item.project_ref as string);
    return { ws, alpha, beta };
  }

  test("Back and Forward between two valid projects apply each entry instead of restoring the old one", async () => {
    const { ws, alpha, beta } = twoProjects();
    nav.search = `workspace=${ws}&project=${alpha}`;
    const view = render(<Dashboard />);
    const select = await screen.findByRole("combobox", { name: /project/i }) as HTMLSelectElement;
    expect(select.value).toBe(alpha);
    const meCalls = () => server.calls.filter((call) => call.path.endsWith("/v1/me")).length;
    const before = meCalls();

    navigate(view, `workspace=${ws}&project=${beta}`);
    await waitFor(() => expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).value).toBe(beta));
    await settle();
    expect(meCalls()).toBe(before + 1);
    expect(nav.search).toBe(`workspace=${ws}&project=${beta}`);

    navigate(view, `workspace=${ws}&project=${alpha}`);
    await waitFor(() => expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).value).toBe(alpha));
    await settle();
    expect(nav.search).toBe(`workspace=${ws}&project=${alpha}`);
    expect(nav.replace).not.toHaveBeenCalled();
  });

  test("a same-document hint for a foreign or deleted project is checked against live data and corrected", async () => {
    const { ws, alpha } = twoProjects();
    const other = server.account("other@example.test", "other-password", [{ role: "owner", projects: ["Theirs"] }]);
    const otherWs = other.memberships[0].workspace_id;
    const theirs = server.projects.get(otherWs)?.[0].project_ref as string;
    nav.search = `workspace=${ws}&project=${alpha}`;
    const view = render(<Dashboard />);
    await screen.findByRole("combobox", { name: /project/i });

    navigate(view, `workspace=${otherWs}&project=${theirs}`);
    await waitFor(() => expect(nav.replace).toHaveBeenCalled());
    await settle();
    expect(nav.search).toBe(`workspace=${ws}&project=${alpha}`);
    expect(document.body.textContent).not.toContain("Theirs");
    expect(server.calls.some((call) => call.path.includes(otherWs))).toBe(false);

    navigate(view, `workspace=${ws}&project=prj_${"f".repeat(32)}`);
    await settle();
    expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).value).toBe(alpha);
    expect(nav.search).toBe(`workspace=${ws}&project=${alpha}`);
  });

  test("overlapping navigations settle on the latest entry, not the slowest response", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Alpha"] }, { role: "owner", projects: ["Gamma"] }]);
    server.session = account;
    const [ws1, ws2] = account.memberships.map((item) => item.workspace_id);
    const alpha = server.projects.get(ws1)?.[0].project_ref as string;
    const gamma = server.projects.get(ws2)?.[0].project_ref as string;
    nav.search = `workspace=${ws2}&project=${gamma}`;
    const view = render(<Dashboard />);
    await screen.findByRole("combobox", { name: /project/i });

    const release = server.hold(`/api/control-plane/v1/workspaces/${ws1}/projects`);
    navigate(view, `workspace=${ws1}&project=${alpha}`);
    await waitFor(() => expect(server.calls.some((call) => call.path.endsWith(`${ws1}/projects`))).toBe(true));
    navigate(view, `workspace=${ws2}&project=${gamma}`);
    await waitFor(() => expect((screen.queryByRole("combobox", { name: /project/i }) as HTMLSelectElement | null)?.value).toBe(gamma));
    await act(async () => { release(); });
    await settle();
    expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).value).toBe(gamma);
    expect(nav.search).toBe(`workspace=${ws2}&project=${gamma}`);
  });

  test("navigating to an entry with refs while signed out reveals nothing and clears them", async () => {
    const { ws, beta } = twoProjects();
    server.session = null;
    const view = render(<Dashboard />);
    await screen.findByRole("heading", { name: "Create your Heel account" });
    navigate(view, `workspace=${ws}&project=${beta}`);
    await waitFor(() => expect(nav.search).toBe(""));
    await settle();
    expect(screen.getByRole("heading", { name: "Create your Heel account" })).toBeTruthy();
    expect(server.calls.some((call) => call.path.includes(ws))).toBe(false);
  });

  test("a user's own selection is still written to the address and not undone by the sync", async () => {
    const { ws, alpha, beta } = twoProjects();
    nav.search = `workspace=${ws}&project=${alpha}`;
    const view = render(<Dashboard />);
    await screen.findByRole("combobox", { name: /project/i });
    fireEvent.change(screen.getByRole("combobox", { name: /project/i }), { target: { value: beta } });
    await waitFor(() => expect(nav.search).toBe(`workspace=${ws}&project=${beta}`));
    view.rerender(<Dashboard />);
    await settle();
    expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).value).toBe(beta);
    expect(nav.search).toBe(`workspace=${ws}&project=${beta}`);
  });
});


// SEAM (C7AR2): besides the fake transport above, `CanaryApi` methods are replaced only to hold or settle a
// component's async action at a chosen moment. No proof, binding, approval, run or target request is real; the
// terminal run below is component metadata so the existing local-summary input renders.
function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (error: unknown) => void } {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

function projectSelect(): HTMLSelectElement {
  return screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement;
}

function signOutButton(): HTMLButtonElement {
  return screen.getByRole("button", { name: "Sign out" }) as HTMLButtonElement;
}

function alphaBeta(): { ws: string; alpha: string; beta: string } {
  const account = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Alpha", "Beta"] }]);
  server.session = account;
  const ws = account.memberships[0].workspace_id;
  const [alpha, beta] = (server.projects.get(ws) ?? []).map((item) => item.project_ref as string);
  nav.search = `workspace=${ws}&project=${alpha}`;
  return { ws, alpha, beta };
}

function challenge(token: string): Record<string, unknown> {
  return { environment_id: `env_${"1".repeat(32)}`, http_url: "https://synthetic.example.test/proof", token };
}

async function requestProof(): Promise<void> {
  fill(/target url/i, "https://synthetic.example.test");
  fireEvent.click(screen.getByRole("button", { name: "Create ownership proof" }));
}

const BLOCKED_NOTICE = /Project created\. Canary setup is unavailable right now/;
const RUN_ID = `crun_${"1".repeat(32)}`;
const SUMMARY = JSON.stringify({
  schema_version: "heel.canary-findings-projection.v1", projection_digest: "a".repeat(64),
  scenario_results: [{ assessment_outcome: "observed", finding: null }],
});

/** Shows a terminal local-result run only where `owns(projectRef)` holds, so the summary input renders there. */
function terminalRunWhere(owns: (projectRef: string) => boolean): void {
  vi.spyOn(CanaryApi.prototype, "listPendingApprovalRequests").mockImplementation(async (_workspaceRef, projectRef) =>
    ({ hasMore: false, request: owns(projectRef) ? { runId: RUN_ID, approvalId: "old-approval" } : null }) as never);
  vi.spyOn(CanaryApi.prototype, "getRun").mockResolvedValue({
    run: { runId: RUN_ID, approvalId: "old-approval", status: "terminal" },
    progress: { available: true, localResultReady: true, scenariosCompleted: 0, scenariosTotal: 0, requestsStarted: 0, remainingRequests: 0, remainingWallMs: 0 },
  } as never);
}

/** Chooses a local summary whose read settles only when the returned promise is settled. */
async function chooseHeldSummary(): Promise<ReturnType<typeof deferred<string>>> {
  await screen.findByText("Load local summary to review separate sharing →");
  const read = deferred<string>();
  fireEvent.change(document.querySelector("input[type=file]") as HTMLInputElement, { target: { files: [{ size: 25, text: () => read.promise }] } });
  return read;
}

function expectNoLocalSummaryState(): void {
  expect(screen.queryByRole("dialog", { name: "Share result summary?" })).toBeNull();
  expect(screen.queryByText("Share result summary?")).toBeNull();
  expect(screen.queryByText("That file is not a closed signed canary summary.")).toBeNull();
}


describe("C7AR2 N3: a successful Retry replaces the outage notice with the current state", () => {
  async function createDuringOutage(): Promise<string> {
    server.canaryOutage = true;
    await signUp();
    await screen.findByText("Create a project first.");
    fill(/new project/i, "Recovered");
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    await screen.findByText(BLOCKED_NOTICE);
    return projectSelect().value;
  }

  test("after recovery the blocked notice is replaced and the ready form, selection, address and status agree", async () => {
    const created = await createDuringOutage();
    server.canaryOutage = false;
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    await screen.findByRole("heading", { name: "Add target" });

    expect(screen.queryByText(BLOCKED_NOTICE)).toBeNull();
    expect(screen.queryByText(/target verification is blocked/)).toBeNull();
    expect(screen.getByText("Project created. Add a target next.")).toBeTruthy();
    expect(screen.getByText("Ready for customer setup")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Try again" })).toBeNull();
    expect(projectSelect().value).toBe(created);
    expect(projectSelect().selectedOptions[0].textContent).toBe("Recovered");
    expect(nav.search).toBe(`workspace=${server.session?.memberships[0].workspace_id}&project=${created}`);
    expect(signOutButton().disabled).toBe(false);
    expectNoSecretLeak();
  });

  test("a Retry while the outage continues keeps the truthful blocked notice and Try again", async () => {
    const created = await createDuringOutage();
    const reads = () => server.calls.filter((call) => call.path.endsWith("/runner-context-bindings")).length;
    const before = reads();
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(reads()).toBe(before + 1));
    await screen.findByText("Canary setup could not be loaded.");
    await settle();
    expect(screen.getByText(BLOCKED_NOTICE)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
    expect(projectSelect().value).toBe(created);
    expect(signOutButton().disabled).toBe(false);
    expectCanaryLocked();
  });

  test("a Retry that finds the session ended drops the project notice with the private context", async () => {
    await createDuringOutage();
    server.session = null;
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    // A re-resolution that finds no session shows the existing sign-in state (resolveAccount's sign_in).
    await screen.findByRole("heading", { name: "Create your Heel account" });
    await settle();
    expect(screen.queryByText(/Project created/)).toBeNull();
    expect(document.body.textContent).not.toContain("Recovered");
    expect(nav.search).toBe("");
  });
});


describe("C7AR2 N2: busy state belongs to the operation and context that started it", () => {
  test("navigating to another valid project releases an obsolete action's busy state", async () => {
    const { ws, beta } = alphaBeta();
    const held = deferred<Record<string, unknown>>();
    vi.spyOn(CanaryApi.prototype, "startEnvironmentProof").mockReturnValue(held.promise as never);
    const view = render(<Dashboard />);
    await screen.findByRole("heading", { name: "Add target" });
    await requestProof();
    expect(signOutButton().disabled).toBe(true);

    navigate(view, `workspace=${ws}&project=${beta}`);
    await waitFor(() => expect(projectSelect().value).toBe(beta));
    expect(signOutButton().disabled).toBe(false);
    expect(projectSelect().disabled).toBe(false);
    expect((screen.getByLabelText(/new project/i) as HTMLInputElement).disabled).toBe(false);
    fill(/target url/i, "https://synthetic.example.test");
    expect((screen.getByRole("button", { name: "Create ownership proof" }) as HTMLButtonElement).disabled).toBe(false);

    await act(async () => { held.resolve(challenge("challenge-alpha")); });
    await settle();
    expect(projectSelect().value).toBe(beta);
    expect(document.body.textContent).not.toContain("challenge-alpha");
    expect(signOutButton().disabled).toBe(false);
  });

  test("an obsolete action's finally cannot clear the newer project's in-flight action", async () => {
    const { ws, beta } = alphaBeta();
    const first = deferred<Record<string, unknown>>();
    const second = deferred<Record<string, unknown>>();
    const start = vi.spyOn(CanaryApi.prototype, "startEnvironmentProof")
      .mockReturnValueOnce(first.promise as never).mockReturnValueOnce(second.promise as never);
    const view = render(<Dashboard />);
    await screen.findByRole("heading", { name: "Add target" });
    await requestProof();
    navigate(view, `workspace=${ws}&project=${beta}`);
    await waitFor(() => expect(projectSelect().value).toBe(beta));
    await requestProof();
    expect(start).toHaveBeenCalledTimes(2);
    expect(start.mock.calls[1][1]).toBe(beta);
    expect(signOutButton().disabled).toBe(true);

    await act(async () => { first.resolve(challenge("challenge-alpha")); });
    await settle();
    expect(signOutButton().disabled, "Beta's own pending action must keep its controls disabled").toBe(true);
    expect((screen.getByRole("button", { name: "Create ownership proof" }) as HTMLButtonElement).disabled).toBe(true);
    expect(document.body.textContent).not.toContain("challenge-alpha");

    await act(async () => { second.resolve(challenge("challenge-beta")); });
    await screen.findByText(/challenge-beta/);
    expect(signOutButton().disabled).toBe(false);
  });

  test("an obsolete action that fails after navigation neither clears the newer action nor annotates it", async () => {
    const { ws, beta } = alphaBeta();
    const first = deferred<Record<string, unknown>>();
    const second = deferred<Record<string, unknown>>();
    vi.spyOn(CanaryApi.prototype, "startEnvironmentProof")
      .mockReturnValueOnce(first.promise as never).mockReturnValueOnce(second.promise as never);
    const view = render(<Dashboard />);
    await screen.findByRole("heading", { name: "Add target" });
    await requestProof();
    navigate(view, `workspace=${ws}&project=${beta}`);
    await waitFor(() => expect(projectSelect().value).toBe(beta));
    await requestProof();

    await act(async () => { first.reject(new CanaryApiError("unavailable", 503)); });
    await settle();
    expect(signOutButton().disabled).toBe(true);
    expect(screen.queryByText(/temporarily unavailable/i)).toBeNull();
    await act(async () => { second.resolve(challenge("challenge-beta")); });
    await screen.findByText(/challenge-beta/);
    expect(signOutButton().disabled).toBe(false);
  });

  test("the current action still blocks a second submit in its own context", async () => {
    alphaBeta();
    const held = deferred<Record<string, unknown>>();
    const start = vi.spyOn(CanaryApi.prototype, "startEnvironmentProof").mockReturnValue(held.promise as never);
    render(<Dashboard />);
    await screen.findByRole("heading", { name: "Add target" });
    await requestProof();
    const button = screen.getByRole("button", { name: "Create ownership proof" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.click(button);
    expect(start).toHaveBeenCalledTimes(1);
    expect(signOutButton().disabled).toBe(true);
    await act(async () => { held.resolve(challenge("challenge-alpha")); });
    await screen.findByText(/challenge-alpha/);
    expect(signOutButton().disabled).toBe(false);
  });

  test("a verified check whose refresh settles after navigation cannot erase the newer project's challenge", async () => {
    const { ws, alpha, beta } = alphaBeta();
    vi.spyOn(CanaryApi.prototype, "startEnvironmentProof")
      .mockResolvedValueOnce(challenge("challenge-alpha") as never).mockResolvedValueOnce(challenge("challenge-beta") as never);
    vi.spyOn(CanaryApi.prototype, "checkEnvironmentProof").mockResolvedValue(true);
    const real = CanaryApi.prototype.listEnvironments;
    const refresh = deferred<never[]>();
    let holdAlpha = false;
    vi.spyOn(CanaryApi.prototype, "listEnvironments").mockImplementation(function (this: CanaryApi, workspaceRef: string, projectRef: string) {
      return holdAlpha && projectRef === alpha ? refresh.promise : real.call(this, workspaceRef, projectRef);
    });
    const view = render(<Dashboard />);
    await screen.findByRole("heading", { name: "Add target" });
    await requestProof();
    await screen.findByText(/challenge-alpha/);
    holdAlpha = true;
    fireEvent.click(screen.getByRole("button", { name: "Check ownership proof" }));
    await screen.findByText("Target ownership verified. No product route was contacted.");

    navigate(view, `workspace=${ws}&project=${beta}`);
    await waitFor(() => expect(projectSelect().value).toBe(beta));
    await requestProof();
    await screen.findByText(/challenge-beta/);
    await act(async () => { refresh.resolve([]); });
    await settle();
    expect(screen.getByText(/challenge-beta/)).toBeTruthy();
    expect(screen.queryByText("Target ownership verified. No product route was contacted.")).toBeNull();
  });
});


describe("C7AR2 N1: a local summary read belongs to the account and project that chose it", () => {
  async function chooseThenSwitchAccount(): Promise<{ read: ReturnType<typeof deferred<string>>; second: Account }> {
    const first = server.account("first@example.test", "first-password", [{ role: "owner", projects: ["First"] }]);
    const second = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Second"] }]);
    server.session = first;
    terminalRunWhere(() => server.session === first);
    render(<Dashboard />);
    const read = await chooseHeldSummary();
    fireEvent.click(signOutButton());
    await signInFromSignedOut(EMAIL, SECRET);
    await screen.findByRole("combobox", { name: /project/i });
    expect(server.session).toBe(second);
    return { read, second };
  }

  test("a previous account's summary that reads successfully opens nothing for the new account", async () => {
    const { read, second } = await chooseThenSwitchAccount();
    await act(async () => { read.resolve(SUMMARY); });
    await settle();
    expectNoLocalSummaryState();
    expect(projectSelect().selectedOptions[0].textContent).toBe("Second");
    expect(nav.search).toContain(second.memberships[0].workspace_id);
    expect(signOutButton().disabled).toBe(false);
    expectNoSecretLeak();
  });

  test("a previous account's summary that fails to parse shows no error to the new account", async () => {
    const { read } = await chooseThenSwitchAccount();
    await act(async () => { read.resolve("not-json"); });
    await settle();
    expectNoLocalSummaryState();
    expect(projectSelect().selectedOptions[0].textContent).toBe("Second");
  });

  test("a project switch in the same account drops the previous project's successful read", async () => {
    const { ws, alpha, beta } = alphaBeta();
    terminalRunWhere((projectRef) => projectRef === alpha);
    const view = render(<Dashboard />);
    const read = await chooseHeldSummary();
    navigate(view, `workspace=${ws}&project=${beta}`);
    await waitFor(() => expect(projectSelect().value).toBe(beta));
    await act(async () => { read.resolve(SUMMARY); });
    await settle();
    expectNoLocalSummaryState();
    expect(projectSelect().value).toBe(beta);
  });

  test("a project switch in the same account drops the previous project's failed read", async () => {
    const { ws, alpha, beta } = alphaBeta();
    terminalRunWhere((projectRef) => projectRef === alpha);
    const view = render(<Dashboard />);
    const read = await chooseHeldSummary();
    navigate(view, `workspace=${ws}&project=${beta}`);
    await waitFor(() => expect(projectSelect().value).toBe(beta));
    await act(async () => { read.reject(new DOMException("read failed", "NotReadableError")); });
    await settle();
    expectNoLocalSummaryState();
    expect(projectSelect().value).toBe(beta);
  });

  test("in the current context an invalid summary is refused and a valid one opens the sharing review", async () => {
    const { alpha } = alphaBeta();
    terminalRunWhere((projectRef) => projectRef === alpha);
    render(<Dashboard />);
    const invalid = await chooseHeldSummary();
    await act(async () => { invalid.resolve("not-json"); });
    await screen.findByText("That file is not a closed signed canary summary.");
    expect(screen.queryByRole("dialog", { name: "Share result summary?" })).toBeNull();

    const valid = await chooseHeldSummary();
    await act(async () => { valid.resolve(SUMMARY); });
    const dialog = await screen.findByRole("dialog", { name: "Share result summary?" });
    expect(within(dialog).getByText("Crossed").nextSibling?.textContent).toBe("1");
    expect(within(dialog).getByText("25 B")).toBeTruthy();
    expect(projectSelect().value).toBe(alpha);
  });
});


// SEAM (C7AR3): executable-environment, paired-runner and binding metadata are component fixtures returned by
// `CanaryApi` spies so the binding controls render. A mutation applies its change to the fixture when it settles
// successfully (as a server would, even when the UI later ignores it), and a held binding read settles on demand.
// No proof, runner, binding or target request is real.
const ALPHA_ORIGIN = "https://alpha-private-staging.example.test";
const ALPHA_RUNNER = "Alpha-private-runner";
const AUTHORIZED = "Canary access was authorized for this exact paired runner and verified environment.";
const REVOKED = "Canary access was revoked. Issued grants and active work were not changed.";
const CANARY_UNAVAILABLE = "Heel Cloud is temporarily unavailable. Your local result is unchanged.";

type BindingWorld = {
  reads: { mock: { calls: unknown[][] } };
  mutations: ReturnType<typeof vi.spyOn>;
  /** The next mutation call waits for this; its rejection is the mutation's failure. */
  holdMutation: () => ReturnType<typeof deferred<void>>;
  /** The next binding read for `projectRef` waits for this; its rejection is the read's failure. */
  holdRead: (projectRef: string) => ReturnType<typeof deferred<void>>;
};

/** Every project in `origins` gets one executable environment, one paired runner and one active binding. */
function bindingWorld(action: "create" | "revoke", origins: Record<string, { origin: string; runner: string }>): BindingWorld {
  const state = new Map<string, { runners: Record<string, unknown>[]; bindings: Record<string, unknown>[] }>();
  const environments = new Map<string, Record<string, unknown>>();
  Object.entries(origins).forEach(([projectRef, { origin, runner }], index) => {
    const n = String(index + 1);
    environments.set(projectRef, { environmentId: `env_${n.repeat(32)}`, origin, isExecutable: true, verificationRecordDigest: "a".repeat(64) });
    state.set(projectRef, {
      runners: [{ runnerId: `runner-${n}`, runnerKeyId: `key-${n}`, displayName: runner, fingerprint: n.repeat(64) }],
      bindings: [{ bindingId: `rcb_${n.repeat(32)}`, origin, runnerId: `runner-${n}`, status: "active" }],
    });
  });
  const mutationHolds: ReturnType<typeof deferred<void>>[] = [];
  const readHolds = new Map<string, ReturnType<typeof deferred<void>>>();
  vi.spyOn(CanaryApi.prototype, "listEnvironments").mockImplementation(async (_workspaceRef, projectRef) =>
    (environments.has(projectRef) ? [environments.get(projectRef)] : []) as never);
  const reads = vi.spyOn(CanaryApi.prototype, "listRunnerContextBindings").mockImplementation(async (_workspaceRef, projectRef) => {
    const held = readHolds.get(projectRef);
    if (held) { readHolds.delete(projectRef); await held.promise; }
    const current = state.get(projectRef) ?? { runners: [], bindings: [] };
    return { runners: [...current.runners], bindings: current.bindings.map((item) => ({ ...item })) } as never;
  });
  const mutations = action === "create"
    ? vi.spyOn(CanaryApi.prototype, "createRunnerContextBinding").mockImplementation(async (_workspaceRef, projectRef, input) => {
      const held = mutationHolds.shift();
      if (held) await held.promise;
      const current = state.get(projectRef);
      current?.bindings.push({ bindingId: `rcb_${"c".repeat(32)}`, origin: environments.get(projectRef)?.origin, runnerId: input.runnerId, status: "active" });
      return current?.bindings.at(-1) as never;
    })
    : vi.spyOn(CanaryApi.prototype, "revokeRunnerContextBinding").mockImplementation(async (_workspaceRef, projectRef, bindingId) => {
      const held = mutationHolds.shift();
      if (held) await held.promise;
      for (const item of state.get(projectRef)?.bindings ?? []) if (item.bindingId === bindingId) item.status = "revoked";
    });
  return {
    reads, mutations,
    holdMutation: () => { const held = deferred<void>(); mutationHolds.push(held); return held; },
    holdRead: (projectRef) => { const held = deferred<void>(); readHolds.set(projectRef, held); return held; },
  };
}

function alphaBetaBindings(action: "create" | "revoke"): { ws: string; alpha: string; beta: string; world: BindingWorld } {
  const { ws, alpha, beta } = alphaBeta();
  const world = bindingWorld(action, { [alpha]: { origin: ALPHA_ORIGIN, runner: ALPHA_RUNNER }, [beta]: { origin: "https://beta-staging.example.test", runner: "Beta runner" } });
  return { ws, alpha, beta, world };
}

/** Waits until the binding section shows exactly `items` (the dashboard's step card repeats the section heading). */
async function bindingsShown(items: string[]): Promise<void> {
  await screen.findByRole("button", { name: "Authorize paired runner" });
  await waitFor(() => expect(bindingItems()).toEqual(items));
}

function bindingItems(): string[] {
  return Array.from(document.querySelectorAll(".context-binding-list li span"), (item) => item.textContent ?? "");
}

function authorizeButton(): HTMLButtonElement {
  return screen.getByRole("button", { name: "Authorize paired runner" }) as HTMLButtonElement;
}

/** Chooses the shown project's own environment and runner (no submit). */
function chooseBindingTarget(): void {
  const environment = screen.getByLabelText("Verified environment") as HTMLSelectElement;
  fireEvent.change(environment, { target: { value: environment.options[1].value } });
  const runner = screen.getByLabelText("Paired runner") as HTMLSelectElement;
  fireEvent.change(runner, { target: { value: runner.options[1].value } });
}

/** Starts the binding action in the shown project through its enabled control. */
function startBindingAction(action: "create" | "revoke"): void {
  if (action === "create") {
    chooseBindingTarget();
    fireEvent.click(authorizeButton());
  } else fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
}

function readsFor(world: BindingWorld, projectRef: string, from: number): number {
  return world.reads.mock.calls.slice(from).filter((call) => call[1] === projectRef).length;
}

/** Beta is shown exactly as Beta loaded it: selection, address, its own binding and runner, no Alpha metadata or feedback. */
function expectBetaIntact(ws: string, beta: string): void {
  expect(projectSelect().value).toBe(beta);
  expect(nav.search).toBe(`workspace=${ws}&project=${beta}`);
  expect(bindingItems()).toEqual(["https://beta-staging.example.test · runner-2 · active"]);
  expect(document.body.textContent).not.toContain(ALPHA_ORIGIN);
  expect(document.body.textContent).not.toContain(ALPHA_RUNNER);
  expect(screen.queryByText(AUTHORIZED)).toBeNull();
  expect(screen.queryByText(REVOKED)).toBeNull();
  expect(screen.queryByText(CANARY_UNAVAILABLE)).toBeNull();
  expect(screen.queryByText(/Your session ended/)).toBeNull();
}

type Settlement = "success" | "failure" | "401";
function settleHeld(held: ReturnType<typeof deferred<void>>, outcome: Settlement): void {
  if (outcome === "success") held.resolve();
  else held.reject(new CanaryApiError("unavailable", outcome === "401" ? 401 : 503));
}


describe("C7AR3: a binding action's follow-up refresh belongs to the context that started the action", () => {
  for (const action of ["create", "revoke"] as const) {
    test(`${action}: a mutation that succeeds after navigation starts no old-context refresh and keeps Beta's selection, runner and address`, async () => {
      const { ws, alpha, beta, world } = alphaBetaBindings(action);
      const mutation = world.holdMutation();
      const view = render(<Dashboard />);
      await bindingsShown([`${ALPHA_ORIGIN} · runner-1 · active`]);
      startBindingAction(action);
      expect(world.mutations).toHaveBeenCalledTimes(1);
      expect(signOutButton().disabled).toBe(true);

      navigate(view, `workspace=${ws}&project=${beta}`);
      await waitFor(() => expect(projectSelect().value).toBe(beta));
      await bindingsShown(["https://beta-staging.example.test · runner-2 · active"]);
      chooseBindingTarget();
      expect(signOutButton().disabled).toBe(false);
      const before = world.reads.mock.calls.length;

      await act(async () => { mutation.resolve(); });
      await settle();
      expect(readsFor(world, alpha, before), "an obsolete mutation must not start a refresh for its old context").toBe(0);
      expectBetaIntact(ws, beta);
      expect((screen.getByLabelText("Paired runner") as HTMLSelectElement).value).toBe("runner-2");
      expect(signOutButton().disabled).toBe(false);
      expectNoSecretLeak();
    });

    for (const outcome of ["success", "failure", "401"] as const) {
      test(`${action}: a refresh in flight across navigation that settles with ${outcome} changes nothing in Beta`, async () => {
        const { ws, alpha, beta, world } = alphaBetaBindings(action);
        const view = render(<Dashboard />);
        await bindingsShown([`${ALPHA_ORIGIN} · runner-1 · active`]);
        const refresh = world.holdRead(alpha);
        const before = world.reads.mock.calls.length;
        startBindingAction(action);
        await waitFor(() => expect(readsFor(world, alpha, before)).toBe(1));

        navigate(view, `workspace=${ws}&project=${beta}`);
        await waitFor(() => expect(projectSelect().value).toBe(beta));
        await bindingsShown(["https://beta-staging.example.test · runner-2 · active"]);
        chooseBindingTarget();
        expect(signOutButton().disabled).toBe(false);

        await act(async () => { settleHeld(refresh, outcome); });
        await settle();
        expect(readsFor(world, alpha, before)).toBe(1);
        expectBetaIntact(ws, beta);
        expect((screen.getByLabelText("Paired runner") as HTMLSelectElement).value).toBe("runner-2");
        expect(signOutButton().disabled).toBe(false);
        expect(server.session).not.toBeNull();
      });
    }

    for (const outcome of ["success", "failure"] as const) {
      test(`${action}: an obsolete mutation's ${outcome} cannot release or overwrite Beta's own in-flight ${action}`, async () => {
        const { ws, alpha, beta, world } = alphaBetaBindings(action);
        const old = world.holdMutation();
        const view = render(<Dashboard />);
        await bindingsShown([`${ALPHA_ORIGIN} · runner-1 · active`]);
        startBindingAction(action);
        navigate(view, `workspace=${ws}&project=${beta}`);
        await waitFor(() => expect(projectSelect().value).toBe(beta));
        await bindingsShown(["https://beta-staging.example.test · runner-2 · active"]);
        const current = world.holdMutation();
        startBindingAction(action);
        expect(world.mutations).toHaveBeenCalledTimes(2);
        expect(world.mutations.mock.calls[1][1]).toBe(beta);
        expect(signOutButton().disabled).toBe(true);
        const before = world.reads.mock.calls.length;

        await act(async () => { settleHeld(old, outcome); });
        await settle();
        expect(readsFor(world, alpha, before)).toBe(0);
        expect(projectSelect().value).toBe(beta);
        expect(nav.search).toBe(`workspace=${ws}&project=${beta}`);
        expect(signOutButton().disabled, "Beta's own pending action must keep its controls disabled").toBe(true);
        expect(document.body.textContent).not.toContain(ALPHA_ORIGIN);
        expect(screen.queryByText(action === "create" ? AUTHORIZED : REVOKED)).toBeNull();
        expect(screen.queryByText(CANARY_UNAVAILABLE)).toBeNull();

        await act(async () => { current.resolve(); });
        await screen.findByText(action === "create" ? AUTHORIZED : REVOKED);
        expect(readsFor(world, beta, before)).toBe(1);
        expect(bindingItems()).toEqual(action === "create"
          ? ["https://beta-staging.example.test · runner-2 · active", "https://beta-staging.example.test · runner-2 · active"]
          : ["https://beta-staging.example.test · runner-2 · revoked"]);
        expect(projectSelect().value).toBe(beta);
        expect(signOutButton().disabled).toBe(false);
      });
    }

    for (const held of ["mutation", "refresh"] as const) {
      test(`${action}: after sign-out and another account's sign-in, the old account's held ${held} restores nothing`, async () => {
        const first = server.account("first@example.test", "first-password", [{ role: "owner", projects: ["First-private-alpha", "First-private-beta"] }]);
        const second = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Second"] }]);
        server.session = first;
        const firstWs = first.memberships[0].workspace_id;
        const [alpha, beta] = (server.projects.get(firstWs) ?? []).map((item) => item.project_ref as string);
        const secondWs = second.memberships[0].workspace_id;
        const secondProject = server.projects.get(secondWs)?.[0].project_ref as string;
        nav.search = `workspace=${firstWs}&project=${alpha}`;
        const world = bindingWorld(action, {
          [alpha]: { origin: ALPHA_ORIGIN, runner: ALPHA_RUNNER },
          [beta]: { origin: "https://first-beta.example.test", runner: "First beta runner" },
          [secondProject]: { origin: "https://second-staging.example.test", runner: "Second runner" },
        });
        const mutation = held === "mutation" ? world.holdMutation() : null;
        const view = render(<Dashboard />);
        await bindingsShown([`${ALPHA_ORIGIN} · runner-1 · active`]);
        const refresh = held === "refresh" ? world.holdRead(alpha) : null;
        startBindingAction(action);
        if (refresh) await waitFor(() => expect(world.reads.mock.calls.at(-1)?.[1]).toBe(alpha));

        // Sign-out is disabled while the action runs; navigation releases it, as a real user would reach it.
        navigate(view, `workspace=${firstWs}&project=${beta}`);
        await waitFor(() => expect(projectSelect().value).toBe(beta));
        fireEvent.click(signOutButton());
        await signInFromSignedOut(EMAIL, SECRET);
        await waitFor(() => expect(projectSelect().value).toBe(secondProject));
        expect(server.session).toBe(second);
        const before = world.reads.mock.calls.length;

        await act(async () => { (mutation ?? refresh)?.resolve(); });
        await settle();
        expect(readsFor(world, alpha, before)).toBe(0);
        expect(projectSelect().value).toBe(secondProject);
        expect(Array.from(projectSelect().options, (option) => option.textContent)).not.toContain("First-private-alpha");
        expect(nav.search).toBe(`workspace=${secondWs}&project=${secondProject}`);
        expect(bindingItems()).toEqual(["https://second-staging.example.test · runner-3 · active"]);
        expect(document.body.textContent).not.toContain("First-private");
        expect(document.body.textContent).not.toContain(ALPHA_ORIGIN);
        expect(screen.queryByText(action === "create" ? AUTHORIZED : REVOKED)).toBeNull();
        expect(signOutButton().disabled).toBe(false);
        expectNoSecretLeak();
      });
    }
  }

  test("a current create refreshes its own bindings, says so, and blocks a second submit until then", async () => {
    const { alpha, world } = alphaBetaBindings("create");
    const mutation = world.holdMutation();
    render(<Dashboard />);
    await bindingsShown([`${ALPHA_ORIGIN} · runner-1 · active`]);
    const before = world.reads.mock.calls.length;
    startBindingAction("create");
    expect(authorizeButton().disabled).toBe(true);
    fireEvent.click(authorizeButton());
    expect(world.mutations).toHaveBeenCalledTimes(1);
    expect(signOutButton().disabled).toBe(true);

    await act(async () => { mutation.resolve(); });
    await screen.findByText(AUTHORIZED);
    expect(readsFor(world, alpha, before)).toBe(1);
    expect(bindingItems()).toEqual([`${ALPHA_ORIGIN} · runner-1 · active`, `${ALPHA_ORIGIN} · runner-1 · active`]);
    expect(projectSelect().value).toBe(alpha);
    expect(signOutButton().disabled).toBe(false);
  });

  test("a current revoke refreshes its own binding to revoked and says so", async () => {
    const { alpha, world } = alphaBetaBindings("revoke");
    render(<Dashboard />);
    await bindingsShown([`${ALPHA_ORIGIN} · runner-1 · active`]);
    const before = world.reads.mock.calls.length;
    startBindingAction("revoke");
    await screen.findByText(REVOKED);
    expect(readsFor(world, alpha, before)).toBe(1);
    expect(bindingItems()).toEqual([`${ALPHA_ORIGIN} · runner-1 · revoked`]);
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
    expect(signOutButton().disabled).toBe(false);
  });

  for (const action of ["create", "revoke"] as const) {
    test(`${action}: a current refresh failure is shown instead of success feedback`, async () => {
      const { alpha, world } = alphaBetaBindings(action);
      render(<Dashboard />);
      await bindingsShown([`${ALPHA_ORIGIN} · runner-1 · active`]);
      const refresh = world.holdRead(alpha);
      startBindingAction(action);
      await act(async () => { refresh.reject(new CanaryApiError("unavailable", 503)); });
      await screen.findByText(CANARY_UNAVAILABLE);
      expect(screen.queryByText(action === "create" ? AUTHORIZED : REVOKED)).toBeNull();
      expect(projectSelect().value).toBe(alpha);
      expect(signOutButton().disabled).toBe(false);
    });

    for (const step of ["mutation", "refresh"] as const) {
      test(`${action}: a current ${step} 401 ends the session and clears the private context`, async () => {
        const { alpha, world } = alphaBetaBindings(action);
        render(<Dashboard />);
        await bindingsShown([`${ALPHA_ORIGIN} · runner-1 · active`]);
        const held = step === "mutation" ? world.holdMutation() : world.holdRead(alpha);
        startBindingAction(action);
        await act(async () => { held.reject(new CanaryApiError("unavailable", 401)); });
        await screen.findByText(/Your session ended/);
        expect(document.body.textContent).not.toContain(ALPHA_ORIGIN);
        expect(document.body.textContent).not.toContain(ALPHA_RUNNER);
        expect(screen.queryByRole("combobox", { name: /project/i })).toBeNull();
        expect(screen.queryByText(action === "create" ? AUTHORIZED : REVOKED)).toBeNull();
        expect(nav.search).toBe("");
      });
    }
  }
});


describe("C7AR3: the proof check's environment refresh keeps the same owner boundary", () => {
  function proofWorld(alpha: string): { check: ReturnType<typeof deferred<boolean>>; environmentReads: () => string[] } {
    vi.spyOn(CanaryApi.prototype, "startEnvironmentProof").mockResolvedValue(challenge("challenge-alpha") as never);
    const check = deferred<boolean>();
    vi.spyOn(CanaryApi.prototype, "checkEnvironmentProof").mockImplementation((_workspaceRef, projectRef) =>
      projectRef === alpha ? check.promise : Promise.resolve(false));
    const real = CanaryApi.prototype.listEnvironments;
    const spy = vi.spyOn(CanaryApi.prototype, "listEnvironments").mockImplementation(function (this: CanaryApi, workspaceRef: string, projectRef: string) {
      return real.call(this, workspaceRef, projectRef);
    });
    return { check, environmentReads: () => spy.mock.calls.map((call) => call[1]) };
  }

  for (const outcome of ["verified", "401"] as const) {
    test(`a check that settles (${outcome}) after navigation starts no environment refresh for the old project`, async () => {
      const { ws, alpha, beta } = alphaBeta();
      const { check, environmentReads } = proofWorld(alpha);
      const view = render(<Dashboard />);
      await screen.findByRole("heading", { name: "Add target" });
      await requestProof();
      await screen.findByText(/challenge-alpha/);
      fireEvent.click(screen.getByRole("button", { name: "Check ownership proof" }));

      navigate(view, `workspace=${ws}&project=${beta}`);
      await waitFor(() => expect(projectSelect().value).toBe(beta));
      await screen.findByRole("heading", { name: "Add target" });
      const before = environmentReads().length;
      if (outcome === "verified") await act(async () => { check.resolve(true); });
      else await act(async () => { check.reject(new CanaryApiError("unavailable", 401)); });
      await settle();
      expect(environmentReads().slice(before)).not.toContain(alpha);
      expect(projectSelect().value).toBe(beta);
      expect(nav.search).toBe(`workspace=${ws}&project=${beta}`);
      expect(screen.queryByText("Target ownership verified. No product route was contacted.")).toBeNull();
      expect(screen.queryByText(/Your session ended/)).toBeNull();
      expect(document.body.textContent).not.toContain("challenge-alpha");
      expect(signOutButton().disabled).toBe(false);
    });
  }

  test("a current verified check refreshes environments, says so and clears the challenge", async () => {
    const { alpha } = alphaBeta();
    const { check, environmentReads } = proofWorld(alpha);
    render(<Dashboard />);
    await screen.findByRole("heading", { name: "Add target" });
    await requestProof();
    await screen.findByText(/challenge-alpha/);
    const before = environmentReads().length;
    fireEvent.click(screen.getByRole("button", { name: "Check ownership proof" }));
    await act(async () => { check.resolve(true); });
    await screen.findByText("Target ownership verified. No product route was contacted.");
    await waitFor(() => expect(environmentReads().slice(before)).toEqual([alpha]));
    await waitFor(() => expect(screen.queryByText(/challenge-alpha/)).toBeNull());
    expect(signOutButton().disabled).toBe(false);
  });

  test("a current non-matching check keeps the challenge and says the proof did not match", async () => {
    const { alpha } = alphaBeta();
    const { check } = proofWorld(alpha);
    render(<Dashboard />);
    await screen.findByRole("heading", { name: "Add target" });
    await requestProof();
    await screen.findByText(/challenge-alpha/);
    fireEvent.click(screen.getByRole("button", { name: "Check ownership proof" }));
    await act(async () => { check.resolve(false); });
    await screen.findByText("Proof did not match yet. No product route was contacted.");
    expect(screen.getByText(/challenge-alpha/)).toBeTruthy();
    expect(signOutButton().disabled).toBe(false);
  });

  test("a current check 401 ends the session", async () => {
    const { alpha } = alphaBeta();
    const { check } = proofWorld(alpha);
    render(<Dashboard />);
    await screen.findByRole("heading", { name: "Add target" });
    await requestProof();
    await screen.findByText(/challenge-alpha/);
    fireEvent.click(screen.getByRole("button", { name: "Check ownership proof" }));
    await act(async () => { check.reject(new CanaryApiError("unavailable", 401)); });
    await screen.findByText(/Your session ended/);
    expect(document.body.textContent).not.toContain("challenge-alpha");
    expect(nav.search).toBe("");
  });
});


// SEAM (CUSTOMER-TRACK-UX): the in-memory fake above stands in for the control plane's existing environment-proof
// routes (start, check and list). This is local synthetic evidence of the UI flow and its requests, not a deployed
// journey: no target is contacted and no proof is published anywhere.
describe("CUSTOMER-TRACK-UX: a new customer registers one target through the existing ownership-proof contract", () => {
  const TARGET = "https://staging.customer.example.test";
  const BOUNDARY = "Target verified. Managed scanning, credentials, discovery, and scan approval are not available in this build.";
  const FORBIDDEN = /credential|identit|secret|discover|scan|crawl|pairing|install|openapi|route-inventory|plan|finding/i;

  function selection(): { ws: string; prj: string } {
    const query = new URLSearchParams(nav.search);
    return { ws: query.get("workspace") ?? "", prj: query.get("project") ?? "" };
  }

  function expectNoRunnerDefault(): void {
    expect(screen.queryByRole("region", { name: /launch activation/i })).toBeNull();
    expect(screen.queryByRole("link", { name: /open pairing guide/i })).toBeNull();
    expect(screen.queryByRole("button", { name: "Authorize paired runner" })).toBeNull();
    expect(document.body.textContent).not.toMatch(/next action: pair runner|pair the local runner/i);
  }

  test("sign up, create a project, prove ownership after one honest retry and see the persisted verified target", async () => {
    await signUp();
    await screen.findByText("Create a project first.");
    fill(/new project/i, "Customer staging");
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    await screen.findByText("Project created. Add a target next.");
    await screen.findByRole("heading", { name: "Add target" });
    await waitFor(() => expect(nav.search).toMatch(/^workspace=ws_[0-9a-f]{16}&project=prj_[0-9a-f]{32}$/));
    const { ws, prj } = selection();
    // The refs the card acts on are the server-confirmed membership and the project the server created.
    expect(ws).toBe(server.session?.memberships[0].workspace_id);
    expect(prj).toBe(server.projects.get(ws)?.[0].project_ref);
    expect(document.body.textContent).toMatch(/publicly reachable/);
    expect(document.body.textContent).toMatch(/Ownership proof is required/);
    expectNoRunnerDefault();

    fill(/target url/i, TARGET);
    fireEvent.change(screen.getByLabelText("Ownership proof method"), { target: { value: "dns-txt" } });
    fireEvent.click(screen.getByRole("button", { name: "Create ownership proof" }));
    await screen.findByText(/^Target verification pending\./);
    const instruction = screen.getByText(/^Publish this exact record: _heel\.staging\.customer\.example\.test TXT heel-verify=synthetic-proof-token-[0-9]+$/).textContent ?? "";
    const token = instruction.split("=").at(-1) ?? "";
    expect(screen.queryByLabelText(/target url/i)).toBeNull();
    expect(screen.queryByRole("button", { name: "Create ownership proof" })).toBeNull();

    // Not yet published: the challenge stays and the honest retry message is shown.
    fireEvent.click(screen.getByRole("button", { name: "Check ownership proof" }));
    await screen.findByText("Proof did not match yet. No product route was contacted.");
    expect(screen.getByText(instruction)).toBeTruthy();
    expect(screen.getByText(/^Target verification pending\./)).toBeTruthy();
    expect(screen.queryByText(BOUNDARY)).toBeNull();

    server.proofPublished = true;
    fireEvent.click(screen.getByRole("button", { name: "Check ownership proof" }));
    await screen.findByText("Target ownership verified. No product route was contacted.");
    const card = screen.getByRole("region", { name: "Your target" });
    expect(within(card).getByRole("status").textContent).toBe(BOUNDARY);
    expect(within(card).getByText(TARGET)).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Add target" })).toBeNull();
    expect(screen.queryByText(instruction)).toBeNull();
    expectNoRunnerDefault();

    // The only state changes are the account, the project and the existing proof start/check, all in this context.
    const base = `/api/control-plane/v1/workspaces/${ws}/projects/${prj}`;
    const environmentId = (server.environments.get(`${ws}/${prj}`) ?? [])[0]?.environment_id as string;
    expect(environmentId).toMatch(/^env_[0-9a-f]{32}$/);
    expect(server.calls.filter((call) => call.method !== "GET").map((call) => `${call.method} ${call.path}`)).toEqual([
      "POST /api/control-plane/v1/signup",
      `POST /api/control-plane/v1/workspaces/${ws}/projects`,
      `POST ${base}/environments`,
      `POST ${base}/environments/${environmentId}/check`,
      `POST ${base}/environments/${environmentId}/check`,
    ]);
    const start = server.calls.find((call) => call.method === "POST" && call.path === `${base}/environments`);
    expect(JSON.parse(start?.body ?? "{}")).toEqual({
      schema_version: "heel.verified-environment-start.v1", origin: TARGET, environment_class: "staging", proof_method: "dns-txt",
      attestation_text: "ownership verified; environment classification supplied by you", attestation_version: "v1",
      attestation_acknowledgement: "accepted",
    });
    for (const call of server.calls.filter((item) => item.path.endsWith("/check"))) {
      expect(JSON.parse(call.body)).toEqual({ schema_version: "heel.verified-environment-check.v1" });
    }
    // Reads are the account context plus the dashboard's existing operational reads for this project only.
    const reads = new Set(server.calls.filter((call) => call.method === "GET").map((call) => call.path));
    const allowedReads = new Set([
      "/api/control-plane/v1/me", `/api/control-plane/v1/workspaces/${ws}/projects`,
      `${base}/environments`, `${base}/runner-context-bindings`, `${base}/canary-approval-requests`,
    ]);
    expect([...reads].filter((path) => !allowedReads.has(path))).toEqual([]);
    expect(server.calls.every((call) => call.path.startsWith("/api/control-plane/v1/"))).toBe(true);
    expect(server.calls.filter((call) => FORBIDDEN.test(call.path.slice("/api/control-plane/v1/".length)))).toEqual([]);

    // The target and the proof token are shown on screen only: never in the address, storage or logs.
    for (const value of [TARGET, token]) {
      expect(nav.replace.mock.calls.flat().join(" ")).not.toContain(value);
      expect(nav.search).not.toContain(value);
      expect(consoleOutput.join("\n")).not.toContain(value);
    }
    expectNoSecretLeak();

    // Verified is the server's persisted state: a fresh page load in the same session shows it again.
    cleanup();
    render(<Dashboard />);
    const reloaded = await screen.findByRole("region", { name: "Your target" });
    expect(within(reloaded).getByRole("status").textContent).toBe(BOUNDARY);
    expect(within(reloaded).getByText(TARGET)).toBeTruthy();
    expectNoRunnerDefault();
  });

  test("a proof start that settles after the session ended elsewhere restores nothing, even after signing in again", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Customer staging"] }]);
    server.session = account;
    const ws = account.memberships[0].workspace_id;
    const prj = server.projects.get(ws)?.[0].project_ref as string;
    nav.search = `workspace=${ws}&project=${prj}`;
    const view = render(<Dashboard />);
    await screen.findByRole("heading", { name: "Add target" });
    const release = server.hold(`/api/control-plane/v1/workspaces/${ws}/projects/${prj}/environments`);
    fill(/target url/i, TARGET);
    fireEvent.click(screen.getByRole("button", { name: "Create ownership proof" }));
    // Sign-out is disabled while the start is in flight, so the session ends in another tab and the user navigates.
    server.session = null;
    navigate(view, "");
    await screen.findByRole("heading", { name: "Create your Heel account" });
    const signedOutStatus = screen.getAllByRole("status").map((item) => item.textContent);
    release();
    await settle();
    // The old session's late 401 is not this view's session loss: the signed-out status is unchanged.
    expect(screen.getAllByRole("status").map((item) => item.textContent)).toEqual(signedOutStatus);
    expect(screen.queryByText(/Target verification pending/)).toBeNull();
    expect(document.body.textContent).not.toMatch(/synthetic-proof-token/);
    expect(document.body.textContent).not.toContain(TARGET);
    expect(nav.search).toBe("");

    await signInFromSignedOut(EMAIL, SECRET);
    await screen.findByRole("heading", { name: "Add target" });
    expect((screen.getByLabelText(/target url/i) as HTMLInputElement).value).toBe("");
    expect(screen.queryByRole("button", { name: "Check ownership proof" })).toBeNull();
    expect(document.body.textContent).not.toMatch(/synthetic-proof-token/);
    expectNoSecretLeak();
  });

  test("an account that already operates a private connector keeps its advanced tools beside the verified status", async () => {
    alphaBetaBindings("create");
    render(<Dashboard />);
    await bindingsShown([`${ALPHA_ORIGIN} · runner-1 · active`]);
    expect(within(screen.getByRole("region", { name: "Your target" })).getByRole("status").textContent).toBe(BOUNDARY);
    const activation = screen.getByRole("region", { name: /launch activation/i });
    expect(within(activation).getAllByRole("listitem").map((step) => step.querySelector("h2")?.textContent))
      .toEqual(["Verify staging", "Pair runner", "Add canary access", "Run first rehearsal"]);
    expect(screen.getByRole("button", { name: "Authorize paired runner" })).toBeTruthy();
    expect(screen.getByRole("complementary", { name: "Safety boundaries" }).textContent)
      .toMatch(/The paired runner owns target traffic\..*GET \+ HEAD.*Staging :443 only/);
  });
});


// SEAM (CUSTOMER-TRACK-UX-F1): the same in-memory control plane; `/v1/me` is held to observe the loading state.
describe("CUSTOMER-TRACK-UX-F1: no visitor is sent into runner onboarding before a private connector exists", () => {
  const INTRO = "Add one publicly reachable staging or sandbox HTTPS target and prove you own it. Managed scanning is not available in this build.";

  function expectNoRunnerFunnel(): void {
    expect(screen.queryByRole("region", { name: /launch activation/i })).toBeNull();
    expect(screen.queryByRole("heading", { name: /^(Verify staging|Pair runner|Add canary access|Run first rehearsal)$/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /verify staging now|open pairing guide/i })).toBeNull();
    expect(screen.queryByRole("button", { name: "Authorize paired runner" })).toBeNull();
    expect(document.body.textContent).not.toMatch(/next action: (verify staging|pair runner)|runner pairing starts after|first useful run/i);
  }

  function expectTruthfulDefaultCopy(): void {
    const intro = screen.getByRole("heading", { level: 1 }).closest("section");
    expect(intro?.textContent).toContain(INTRO);
    expect(intro?.textContent).not.toMatch(/runner onboarding|canary rehearsal/i);
    const rail = screen.getByRole("complementary", { name: "Safety boundaries" });
    expect(rail.textContent).toMatch(/No scan traffic is sent in this build\./);
    expect(rail.textContent).toMatch(/Ownership check.*One proof file or DNS record/);
    expect(rail.textContent).toMatch(/Operational status only/);
    expect(rail.textContent).not.toMatch(/runner owns target traffic|GET \+ HEAD|:443/i);
  }

  test("while the session is still loading, no runner step or prerequisite is shown", async () => {
    const release = server.hold("/api/control-plane/v1/me");
    render(<Dashboard />);
    await screen.findByText("Checking your session.");
    expectNoRunnerFunnel();
    expectTruthfulDefaultCopy();
    release();
    await screen.findByRole("heading", { name: "Create your Heel account" });
  });

  test("a signed-out visitor sees account access and the target-first copy, never a runner funnel", async () => {
    render(<Dashboard />);
    await screen.findByRole("heading", { name: "Create your Heel account" });
    expectNoRunnerFunnel();
    expectTruthfulDefaultCopy();
  });

  test("an unavailable service is retryable without advertising runner onboarding", async () => {
    server.offline = true;
    render(<Dashboard />);
    await screen.findByRole("button", { name: "Try again" });
    expectNoRunnerFunnel();
    expectTruthfulDefaultCopy();
  });

  test("a new account without a project, without a workspace, with a refused role or during a canary outage sees no runner funnel", async () => {
    const cases: { name: string; arrange: () => void; shown: () => Promise<unknown> }[] = [
      { name: "no project", arrange: () => { server.session = server.account(EMAIL, SECRET, [{ role: "owner" }]); },
        shown: () => screen.findByText("Create a project first.") },
      { name: "no workspace", arrange: () => { server.session = server.account("lone@example.test", SECRET, []); },
        shown: () => screen.findByText(/not a member of any workspace/) },
      { name: "refused role", arrange: () => { server.session = server.account("billing@example.test", SECRET, [{ role: "billing" }]); },
        shown: () => screen.findByText(/role cannot open projects/) },
      { name: "canary outage", arrange: () => {
        server.session = server.account("outage@example.test", SECRET, [{ role: "owner", projects: ["Customer staging"] }]);
        server.canaryOutage = true;
      }, shown: () => screen.findByText(/stay locked until it loads/) },
    ];
    for (const item of cases) {
      cleanup();
      server.canaryOutage = false;
      item.arrange();
      render(<Dashboard />);
      await item.shown();
      expectNoRunnerFunnel();
      expectTruthfulDefaultCopy();
    }
  });

  test("a new account's ready project offers Add target with the same truthful copy and no runner funnel", async () => {
    server.session = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Customer staging"] }]);
    render(<Dashboard />);
    await screen.findByRole("heading", { name: "Add target" });
    expectNoRunnerFunnel();
    expectTruthfulDefaultCopy();
  });
});


// SEAM (CUSTOMER-TRACK-UX-F1): the in-memory control plane keeps each pending challenge server-side, like the real
// row, and models the recovery/rotation routes, the 15-minute ceremony and same-origin upsert. Local synthetic
// evidence of the UI state machine only; `tests/test_verified_environments.py` proves the real routes over HTTP.
describe("CUSTOMER-TRACK-UX-F1: a pending ownership proof survives a reload and is resumed explicitly", () => {
  const TARGET = "https://staging.customer.example.test";
  const OTHER = "https://sandbox.customer.example.test";
  const BOUNDARY = "Target verified. Managed scanning, credentials, discovery, and scan approval are not available in this build.";
  const EXPIRED = "This pending proof expired. Issue a replacement proof for the same target.";
  const RECENT_AUTH = "For your security, showing or replacing a pending proof needs a sign-in from the last 15 minutes. The proof is kept on the server: sign out, sign in again, then resume it.";

  function ownerWith(projects: string[] = ["Customer staging"], second?: string[]): { ws: string; prj: string; ws2: string; prj2: string } {
    const memberships = [{ role: "owner" as const, projects }, ...(second ? [{ role: "owner" as const, projects: second }] : [])];
    const account = server.account(EMAIL, SECRET, memberships);
    server.session = account;
    const ws = account.memberships[0].workspace_id;
    const ws2 = account.memberships[1]?.workspace_id ?? "";
    const prj = server.projects.get(ws)?.[0].project_ref as string;
    nav.search = `workspace=${ws}&project=${prj}`;
    return { ws, prj, ws2, prj2: (server.projects.get(ws2)?.[0]?.project_ref as string | undefined) ?? "" };
  }

  function base(ws: string, prj: string): string {
    return `/api/control-plane/v1/workspaces/${ws}/projects/${prj}`;
  }

  function postsSince(mark: number): string[] {
    return server.calls.slice(mark).filter((call) => call.method === "POST").map((call) => call.path.replace(/^.*\/environments/, "/environments"));
  }

  function tokenOf(environmentId: string): string {
    return server.challenges.get(environmentId)?.token ?? "";
  }

  function expectProofOnlyOnScreen(token: string): void {
    expect(globalThis.localStorage.length).toBe(0);
    expect(globalThis.sessionStorage.length).toBe(0);
    expect(nav.search).not.toContain(token);
    expect(nav.replace.mock.calls.flat().join(" ")).not.toContain(token);
    expect(consoleOutput.join("\n")).not.toContain(token);
  }

  async function pendingGroup(): Promise<HTMLElement> {
    return screen.findByRole("group", { name: "Pending ownership proof" });
  }

  test("a reload after starting a proof shows the pending target and resumes the same proof through the existing check", async () => {
    const { ws, prj } = ownerWith();
    render(<Dashboard />);
    await screen.findByRole("heading", { name: "Add target" });
    fill(/target url/i, TARGET);
    fireEvent.change(screen.getByLabelText("Ownership proof method"), { target: { value: "dns-txt" } });
    fireEvent.click(screen.getByRole("button", { name: "Create ownership proof" }));
    await screen.findByText(/^Target verification pending\./);
    const environmentId = server.environments.get(`${ws}/${prj}`)?.[0].environment_id as string;
    const token = tokenOf(environmentId);
    const instruction = `Publish this exact record: _heel.staging.customer.example.test TXT heel-verify=${token}`;
    expect(screen.getByText(instruction)).toBeTruthy();

    const mark = server.calls.length;
    cleanup();
    render(<Dashboard />);
    const pending = await pendingGroup();
    expect(within(pending).getByText(TARGET)).toBeTruthy();
    expect(screen.queryByText(instruction)).toBeNull();
    expect(screen.queryByRole("button", { name: "Check ownership proof" })).toBeNull();
    expect(document.body.textContent).not.toContain(token);
    // Loading the page recovers nothing, registers nothing and checks nothing on its own.
    await settle();
    expect(postsSince(mark)).toEqual([]);

    fireEvent.click(within(pending).getByRole("button", { name: "Resume ownership proof" }));
    await screen.findByText(instruction);
    expect(postsSince(mark)).toEqual([`/environments/${environmentId}/challenge`]);
    expect(server.environments.get(`${ws}/${prj}`)).toHaveLength(1);
    expect(server.challenges.get(environmentId)).toEqual({ token, generation: 1, expired: false });

    fireEvent.click(screen.getByRole("button", { name: "Check ownership proof" }));
    await screen.findByText("Proof did not match yet. No product route was contacted.");
    expect(screen.getByText(instruction)).toBeTruthy();
    server.proofPublished = true;
    fireEvent.click(screen.getByRole("button", { name: "Check ownership proof" }));
    const card = await screen.findByRole("region", { name: "Your target" });
    expect(within(card).getByRole("status").textContent).toBe(BOUNDARY);
    expect(postsSince(mark)).toEqual([
      `/environments/${environmentId}/challenge`, `/environments/${environmentId}/check`, `/environments/${environmentId}/check`,
    ]);
    expect(server.calls.slice(mark).every((call) => call.path.startsWith(`${base(ws, prj)}/`) || call.path.endsWith("/v1/me") || call.path.endsWith("/projects"))).toBe(true);
    expectProofOnlyOnScreen(token);
    expectNoSecretLeak();
  });

  test("an expired pending proof is replaced in the same record only when the user asks", async () => {
    const { ws, prj } = ownerWith();
    const environmentId = server.seedPending(ws, prj, TARGET, "https-file");
    const oldToken = tokenOf(environmentId);
    server.challenges.get(environmentId)!.expired = true;
    const mark = server.calls.length;
    render(<Dashboard />);
    fireEvent.click(within(await pendingGroup()).getByRole("button", { name: "Resume ownership proof" }));
    await screen.findByText(EXPIRED);
    const pending = screen.getByRole("group", { name: "Pending ownership proof" });
    expect(within(pending).queryByRole("button", { name: "Resume ownership proof" })).toBeNull();
    expect(document.body.textContent).not.toContain(oldToken);
    expect(postsSince(mark)).toEqual([`/environments/${environmentId}/challenge`]);
    expect(server.challenges.get(environmentId)?.generation).toBe(1);

    fireEvent.click(within(pending).getByRole("button", { name: "Issue replacement proof" }));
    const newToken = await waitFor(() => {
      const current = tokenOf(environmentId);
      expect(current).not.toBe(oldToken);
      return current;
    });
    await screen.findByText(`Place the one-time token at ${TARGET}/.well-known/heel-verify.txt: ${newToken}`);
    expect(postsSince(mark)).toEqual([`/environments/${environmentId}/challenge`, `/environments/${environmentId}/challenge/rotate`]);
    expect(server.environments.get(`${ws}/${prj}`)).toHaveLength(1);
    expect(server.environments.get(`${ws}/${prj}`)?.[0].environment_id).toBe(environmentId);
    expect(server.challenges.get(environmentId)?.generation).toBe(2);
    expect(document.body.textContent).not.toContain(oldToken);

    server.proofPublished = true;
    fireEvent.click(screen.getByRole("button", { name: "Check ownership proof" }));
    await screen.findByRole("region", { name: "Your target" });
    expectProofOnlyOnScreen(newToken);
  });

  test("with several pending targets the user chooses which one to resume; none is picked silently", async () => {
    const { ws, prj } = ownerWith();
    const first = server.seedPending(ws, prj, TARGET);
    const second = server.seedPending(ws, prj, OTHER);
    const mark = server.calls.length;
    render(<Dashboard />);
    const pending = await pendingGroup();
    const select = within(pending).getByRole("combobox", { name: "Pending target" }) as HTMLSelectElement;
    expect(select.value).toBe("");
    expect((within(pending).getByRole("button", { name: "Resume ownership proof" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(pending).getByRole("button", { name: "Resume ownership proof" }));
    await settle();
    expect(postsSince(mark)).toEqual([]);

    fireEvent.change(select, { target: { value: second } });
    fireEvent.click(within(pending).getByRole("button", { name: "Resume ownership proof" }));
    await screen.findByText(`Publish this exact record: _heel.sandbox.customer.example.test TXT heel-verify=${tokenOf(second)}`);
    expect(postsSince(mark)).toEqual([`/environments/${second}/challenge`]);
    expect(document.body.textContent).not.toContain(tokenOf(first));
  });

  test("a malformed or foreign recovery response shows no proof and re-reads the listed state", async () => {
    const { ws, prj } = ownerWith();
    const environmentId = server.seedPending(ws, prj, TARGET);
    const token = tokenOf(environmentId);
    const valid = {
      schema_version: "heel.verified-environment-challenge-recovery.v1", environment_id: environmentId, origin: TARGET,
      environment_class: "staging", proof_method: "dns-txt", token, http_url: `${TARGET}/.well-known/heel-verify.txt`,
      dns_record: `_heel.staging.customer.example.test TXT heel-verify=${token}`, challenge_generation: 1, expires_at: 4_000_000_000_000,
      attestation: "ownership verified; environment classification supplied by you", attestation_version: "v1", attestation_acknowledgement: "accepted",
    };
    for (const body of [
      { ...valid, environment_id: `env_${"f".repeat(32)}` },
      { ...valid, origin: OTHER },
      { ...valid, challenge_generation: 7 },
      { ...valid, raw_proof_body: "x" },
    ]) {
      cleanup();
      server.overrides.set(`POST ${base(ws, prj)}/environments/${environmentId}/challenge`, () => json(body));
      render(<Dashboard />);
      const resume = within(await pendingGroup()).getByRole("button", { name: "Resume ownership proof" });
      const listReads = () => server.calls.filter((call) => call.method === "GET" && call.path === `${base(ws, prj)}/environments`).length;
      const before = listReads();
      fireEvent.click(resume);
      await screen.findByText("Heel Cloud returned an invalid canary response.");
      expect(screen.queryByRole("button", { name: "Check ownership proof" })).toBeNull();
      expect(document.body.textContent).not.toContain(token);
      await waitFor(() => expect(listReads()).toBe(before + 1));
    }
  });

  for (const action of ["resume", "replace"] as const) {
    for (const transition of ["project switch", "workspace switch", "session ended elsewhere"] as const) {
      test(`a ${action} that settles after a ${transition} shows nothing in the new context`, async () => {
        const { ws, prj, ws2, prj2 } = ownerWith(["Alpha", "Beta"], ["Gamma"]);
        const beta = server.projects.get(ws)?.[1].project_ref as string;
        const environmentId = server.seedPending(ws, prj, TARGET);
        if (action === "replace") server.challenges.get(environmentId)!.expired = true;
        const view = render(<Dashboard />);
        const pending = await pendingGroup();
        if (action === "replace") {
          fireEvent.click(within(pending).getByRole("button", { name: "Resume ownership proof" }));
          await screen.findByText(EXPIRED);
        }
        const path = `${base(ws, prj)}/environments/${environmentId}/challenge${action === "replace" ? "/rotate" : ""}`;
        const release = server.hold(path);
        fireEvent.click(within(screen.getByRole("group", { name: "Pending ownership proof" }))
          .getByRole("button", { name: action === "resume" ? "Resume ownership proof" : "Issue replacement proof" }));
        await waitFor(() => expect(server.calls.some((call) => call.path === path)).toBe(true));
        if (transition === "project switch") {
          navigate(view, `workspace=${ws}&project=${beta}`);
          await waitFor(() => expect(projectSelect().value).toBe(beta));
          await screen.findByRole("heading", { name: "Add target" });
        } else if (transition === "workspace switch") {
          navigate(view, `workspace=${ws2}&project=${prj2}`);
          await waitFor(() => expect(projectSelect().value).toBe(prj2));
          await screen.findByRole("heading", { name: "Add target" });
        } else {
          server.session = null;
          navigate(view, "");
          await screen.findByRole("heading", { name: "Create your Heel account" });
        }
        const statuses = screen.queryAllByRole("status").map((item) => item.textContent);
        release();
        await settle();
        expect(screen.queryAllByRole("status").map((item) => item.textContent)).toEqual(statuses);
        expect(screen.queryByRole("button", { name: "Check ownership proof" })).toBeNull();
        expect(screen.queryByRole("group", { name: "Pending ownership proof" })).toBeNull();
        expect(document.body.textContent).not.toMatch(/synthetic-proof-token|heel-verify/);
        expect(document.body.textContent).not.toContain(TARGET);
        expectProofOnlyOnScreen(tokenOf(environmentId));
      });
    }
  }

  test("a recovery 401 in the current session ends it without showing the proof", async () => {
    const { ws, prj } = ownerWith();
    const environmentId = server.seedPending(ws, prj, TARGET);
    server.overrides.set(`POST ${base(ws, prj)}/environments/${environmentId}/challenge`, () => json({ error: "authentication required" }, 401));
    render(<Dashboard />);
    fireEvent.click(within(await pendingGroup()).getByRole("button", { name: "Resume ownership proof" }));
    await screen.findByText(/Your session ended/);
    expect(document.body.textContent).not.toContain(tokenOf(environmentId));
    expect(nav.search).toBe("");
  });

  for (const afterLogin of ["live", "expired"] as const) {
    test(`after the fresh-sign-in window lapses, a real sign-in shows the kept proof again (${afterLogin})`, async () => {
      const { ws, prj } = ownerWith();
      const environmentId = server.seedPending(ws, prj, TARGET);
      const token = tokenOf(environmentId);
      server.recentAuth = false;
      render(<Dashboard />);
      fireEvent.click(within(await pendingGroup()).getByRole("button", { name: "Resume ownership proof" }));
      await screen.findByText(RECENT_AUTH);
      expect(screen.queryByRole("button", { name: "Check ownership proof" })).toBeNull();
      expect(screen.queryByRole("button", { name: "Issue replacement proof" })).toBeNull();
      expect(document.body.textContent).not.toContain(token);
      // Nothing was cleared or rotated server-side, and the session age was not refreshed silently.
      expect(server.challenges.get(environmentId)).toEqual({ token, generation: 1, expired: false });
      expect(server.recentAuth).toBe(false);

      fireEvent.click(signOutButton());
      await signInFromSignedOut(EMAIL, SECRET);
      if (afterLogin === "expired") server.challenges.get(environmentId)!.expired = true;
      const mark = server.calls.length;
      fireEvent.click(within(await pendingGroup()).getByRole("button", { name: "Resume ownership proof" }));
      if (afterLogin === "live") {
        await screen.findByText(`Publish this exact record: _heel.staging.customer.example.test TXT heel-verify=${token}`);
        expect(postsSince(mark)).toEqual([`/environments/${environmentId}/challenge`]);
      } else {
        await screen.findByText(EXPIRED);
        fireEvent.click(screen.getByRole("button", { name: "Issue replacement proof" }));
        await screen.findByText(/heel-verify=synthetic-proof-token-/);
        expect(postsSince(mark)).toEqual([`/environments/${environmentId}/challenge`, `/environments/${environmentId}/challenge/rotate`]);
        expect(server.challenges.get(environmentId)?.generation).toBe(2);
      }
      expect(server.environments.get(`${ws}/${prj}`)).toHaveLength(1);
      expectProofOnlyOnScreen(token);
      expectNoSecretLeak();
    });
  }
});
