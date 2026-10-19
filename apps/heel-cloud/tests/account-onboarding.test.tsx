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
    if (method === "GET" && /\/projects\/prj_[0-9a-f]{32}\/environments$/.test(route)) {
      return json({ schema_version: "heel.verified-environment-list.v1", environments: [] });
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
    expect(nav.search).toMatch(/^workspace=ws_[0-9a-f]{16}$/);

    fireEvent.change(within(bar).getByLabelText(/new project/i), { target: { value: "  Billing staging  " } });
    fireEvent.click(within(bar).getByRole("button", { name: "Create project" }));

    await screen.findByText("Project created. Verify a staging origin next.");
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
    expect(nav.search).toContain(mine.memberships[0].workspace_id);
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
    expect(nav.search).toContain(second.memberships[0].workspace_id);
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
    expect(nav.search).toBe("");
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
  expect(screen.queryByRole("heading", { name: "Verify staging now" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Create proof challenge" })).toBeNull();
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
    expect(screen.queryByText(/Verify a staging origin next/)).toBeNull();
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
    await screen.findByRole("heading", { name: "Verify staging now" });
    expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).value).toBe(project.value);

    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await screen.findByText("You signed out. Sign in again to continue.");
    expect(nav.search).toBe("");
    expect(document.body.textContent).not.toContain("Billing staging");
  });

  test("a ready account that loses the canary service keeps project switching and sign-out, then recovers", async () => {
    const account = server.account(EMAIL, SECRET, [{ role: "owner", projects: ["Alpha", "Beta"] }]);
    server.session = account;
    const ws = account.memberships[0].workspace_id;
    const [alpha, beta] = (server.projects.get(ws) ?? []).map((item) => item.project_ref as string);
    render(<Dashboard />);
    await screen.findByRole("heading", { name: "Verify staging now" });

    server.canaryOutage = true;
    fireEvent.change(screen.getByRole("combobox", { name: /project/i }), { target: { value: beta } });
    await screen.findByText("Canary setup could not be loaded.");
    expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).value).toBe(beta);
    expect(nav.search).toBe(`workspace=${ws}&project=${beta}`);
    expectCanaryLocked();

    fireEvent.change(screen.getByRole("combobox", { name: /project/i }), { target: { value: alpha } });
    await waitFor(() => expect(nav.search).toBe(`workspace=${ws}&project=${alpha}`));
    expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).value).toBe(alpha);
    expectCanaryLocked();

    server.canaryOutage = false;
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    await screen.findByRole("heading", { name: "Verify staging now" });
    expect((screen.getByRole("combobox", { name: /project/i }) as HTMLSelectElement).value).toBe(alpha);

    server.canaryOutage = true;
    fireEvent.change(screen.getByRole("combobox", { name: /project/i }), { target: { value: beta } });
    await screen.findByText("Canary setup could not be loaded.");
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await screen.findByText("You signed out. Sign in again to continue.");
    expect(server.session).toBeNull();
    expect(nav.search).toBe("");
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
  fill(/staging origin/i, "https://synthetic.example.test");
  fireEvent.click(screen.getByRole("button", { name: "Create proof challenge" }));
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
    await screen.findByRole("heading", { name: "Verify staging now" });

    expect(screen.queryByText(BLOCKED_NOTICE)).toBeNull();
    expect(screen.queryByText(/staging verification is blocked/)).toBeNull();
    expect(screen.getByText("Project created. Verify a staging origin next.")).toBeTruthy();
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
    await screen.findByRole("heading", { name: "Verify staging now" });
    await requestProof();
    expect(signOutButton().disabled).toBe(true);

    navigate(view, `workspace=${ws}&project=${beta}`);
    await waitFor(() => expect(projectSelect().value).toBe(beta));
    expect(signOutButton().disabled).toBe(false);
    expect(projectSelect().disabled).toBe(false);
    expect((screen.getByLabelText(/new project/i) as HTMLInputElement).disabled).toBe(false);
    fill(/staging origin/i, "https://synthetic.example.test");
    expect((screen.getByRole("button", { name: "Create proof challenge" }) as HTMLButtonElement).disabled).toBe(false);

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
    await screen.findByRole("heading", { name: "Verify staging now" });
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
    expect((screen.getByRole("button", { name: "Create proof challenge" }) as HTMLButtonElement).disabled).toBe(true);
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
    await screen.findByRole("heading", { name: "Verify staging now" });
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
    await screen.findByRole("heading", { name: "Verify staging now" });
    await requestProof();
    const button = screen.getByRole("button", { name: "Create proof challenge" }) as HTMLButtonElement;
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
    await screen.findByRole("heading", { name: "Verify staging now" });
    await requestProof();
    await screen.findByText(/challenge-alpha/);
    holdAlpha = true;
    fireEvent.click(screen.getByRole("button", { name: "Check exact proof" }));
    await screen.findByText("Staging ownership verified. Pair the local runner next.");

    navigate(view, `workspace=${ws}&project=${beta}`);
    await waitFor(() => expect(projectSelect().value).toBe(beta));
    await requestProof();
    await screen.findByText(/challenge-beta/);
    await act(async () => { refresh.resolve([]); });
    await settle();
    expect(screen.getByText(/challenge-beta/)).toBeTruthy();
    expect(screen.queryByText("Staging ownership verified. Pair the local runner next.")).toBeNull();
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
      await screen.findByRole("heading", { name: "Verify staging now" });
      await requestProof();
      await screen.findByText(/challenge-alpha/);
      fireEvent.click(screen.getByRole("button", { name: "Check exact proof" }));

      navigate(view, `workspace=${ws}&project=${beta}`);
      await waitFor(() => expect(projectSelect().value).toBe(beta));
      await screen.findByRole("heading", { name: "Verify staging now" });
      const before = environmentReads().length;
      if (outcome === "verified") await act(async () => { check.resolve(true); });
      else await act(async () => { check.reject(new CanaryApiError("unavailable", 401)); });
      await settle();
      expect(environmentReads().slice(before)).not.toContain(alpha);
      expect(projectSelect().value).toBe(beta);
      expect(nav.search).toBe(`workspace=${ws}&project=${beta}`);
      expect(screen.queryByText("Staging ownership verified. Pair the local runner next.")).toBeNull();
      expect(screen.queryByText(/Your session ended/)).toBeNull();
      expect(document.body.textContent).not.toContain("challenge-alpha");
      expect(signOutButton().disabled).toBe(false);
    });
  }

  test("a current verified check refreshes environments, says so and clears the challenge", async () => {
    const { alpha } = alphaBeta();
    const { check, environmentReads } = proofWorld(alpha);
    render(<Dashboard />);
    await screen.findByRole("heading", { name: "Verify staging now" });
    await requestProof();
    await screen.findByText(/challenge-alpha/);
    const before = environmentReads().length;
    fireEvent.click(screen.getByRole("button", { name: "Check exact proof" }));
    await act(async () => { check.resolve(true); });
    await screen.findByText("Staging ownership verified. Pair the local runner next.");
    await waitFor(() => expect(environmentReads().slice(before)).toEqual([alpha]));
    await waitFor(() => expect(screen.queryByText(/challenge-alpha/)).toBeNull());
    expect(signOutButton().disabled).toBe(false);
  });

  test("a current non-matching check keeps the challenge and says the proof did not match", async () => {
    const { alpha } = alphaBeta();
    const { check } = proofWorld(alpha);
    render(<Dashboard />);
    await screen.findByRole("heading", { name: "Verify staging now" });
    await requestProof();
    await screen.findByText(/challenge-alpha/);
    fireEvent.click(screen.getByRole("button", { name: "Check exact proof" }));
    await act(async () => { check.resolve(false); });
    await screen.findByText("Proof did not match yet. No product route was contacted.");
    expect(screen.getByText(/challenge-alpha/)).toBeTruthy();
    expect(signOutButton().disabled).toBe(false);
  });

  test("a current check 401 ends the session", async () => {
    const { alpha } = alphaBeta();
    const { check } = proofWorld(alpha);
    render(<Dashboard />);
    await screen.findByRole("heading", { name: "Verify staging now" });
    await requestProof();
    await screen.findByText(/challenge-alpha/);
    fireEvent.click(screen.getByRole("button", { name: "Check exact proof" }));
    await act(async () => { check.reject(new CanaryApiError("unavailable", 401)); });
    await screen.findByText(/Your session ended/);
    expect(document.body.textContent).not.toContain("challenge-alpha");
    expect(nav.search).toBe("");
  });
});
