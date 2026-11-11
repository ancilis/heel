// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/**
 * CUSTOMER-TERMINAL-RESULT-VIEW: once a run leaves `awaiting_execution_approval` the control plane no longer lists it as
 * a pending request, so the dashboard must keep reading that run's own status until it settles.
 *
 * CUSTOMER-RESULT-HANDOFF-B: the shown run survives reload through one opaque `run` address ref that the run read
 * re-authorizes, and the redacted finding reaches the page only through the disclosure status read, an explicit Share
 * or Keep local, and the strict findings read. No file is chosen and nothing is stored in the browser.
 *
 * SEAM: the account and canary clients are replaced by prototype spies returning parsed client values. The pending
 * list is modelled as the server returns it: only runs awaiting approval appear there. The disclosure status is one
 * in-memory server value that the two decision spies change as the control plane would; the findings value is
 * produced by the real strict `getFindings` parser from a fixture in the server schema. No target, runner or
 * control-plane request is real; the counters below are synthetic and match the shape of a 2-request, 1-scenario run.
 */

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import Dashboard from "../app/dashboard/page";
import {
  CanaryApi, CanaryApiError, type CanaryDisclosureState, type CanaryFindingsProjection, type CanaryRunDashboard,
} from "../lib/canary-api";
import { HeelCloudApi } from "../lib/heel-cloud-api";


const WS = `ws_${"a".repeat(16)}`;
const PRJ = `prj_${"b".repeat(32)}`;
const PRJ2 = `prj_${"9".repeat(32)}`;
const RUN = `crun_${"c".repeat(32)}`;
const OTHER_RUN = `crun_${"8".repeat(32)}`;
const APPROVAL = `projection_${"d".repeat(24)}`;
const ENV = `env_${"e".repeat(32)}`;
const ORIGIN = "https://synthetic-staging.example.test";

const nav = vi.hoisted(() => ({ search: "" }));
vi.mock("next/navigation", () => ({
  usePathname: () => "/dashboard",
  useRouter: () => ({ replace: (href: string) => { nav.search = href.split("?")[1] ?? ""; } }),
  useSearchParams: () => new URLSearchParams(nav.search),
}));


function dashboard(status: string, disposition: string | null, progress: Partial<CanaryRunDashboard["progress"]>): CanaryRunDashboard {
  return {
    approvalControlGeneration: 1,
    run: {
      runId: RUN, approvalId: APPROVAL, grantId: status === "awaiting_execution_approval" ? null : "cgr_synthetic",
      status, executionDisposition: disposition, errorCategory: "none", stopReason: "none", sourceEventSequence: 0,
      quotaState: "reserved", killSwitchGeneration: 1, stopGeneration: 0, stopDeadlineMs: null,
      stopAcknowledgedAtMs: null, stopAckLate: false,
    },
    progress: {
      available: true, currentScenarioId: null, scenariosCompleted: 0, scenariosTotal: 1, requestsStarted: 0,
      requestsCompleted: 0, remainingRequests: 20, remainingWallMs: 60_000, retriesUsed: 0, redactionCount: 0,
      localResultReady: false, ...progress,
    },
  };
}

// The read model exactly as `_canary_dashboard_progress` derives it before and after the runner's signed receipt.
const APPROVED = dashboard("approved", null, {});
const TERMINAL = dashboard("terminal", "completed", {
  scenariosCompleted: 1, requestsStarted: 2, requestsCompleted: 2, remainingRequests: 18, remainingWallMs: 58_000,
  redactionCount: 2, localResultReady: true,
});

const METADATA = { projectionDigest: "a".repeat(64), projectionBytes: 1840, scenarioCount: 1, findingCount: 1 };
const FINDING_TITLE = "Lower-plan read covered every key path of the higher-plan response";
const EVIDENCE_REF = `ev1_${"4".repeat(64)}`;

function disclosureState(status: CanaryDisclosureState["status"]): CanaryDisclosureState {
  return { requestId: `cdr_${"1".repeat(32)}`, runId: RUN, status, projection: METADATA };
}

/** The synchronized projection in the exact server schema, as `GET …/findings` returns it. */
function findingsWire(): Record<string, unknown> {
  return {
    schema_version: "heel.canary-findings-projection.v1", projection_id: "cfp_synthetic", run_id: RUN,
    grant_id: "cgr_synthetic", workspace_id: WS, project_id: PRJ, environment_id: ENV,
    manifest_digest: "1".repeat(64), approval_projection_digest: "2".repeat(64), grant_digest: "3".repeat(64),
    engine_version: "heel-1.3.0", adapter_versions: ["plan-differential.v1"], started_at_ms: 1, finished_at_ms: 2,
    assessment_outcome: "observed",
    scenario_results: [{
      ordinal: 0, scenario_id: "plan-differential-export", adapter_version: "plan-differential.v1",
      assessment_outcome: "observed", route: { method: "GET", route_template: "/api/export" },
      observations: [
        { semantic_role: "higher_plan", status_code: 200, body_shape: "json_object", truncation_state: "complete" },
        { semantic_role: "lower_plan", status_code: 200, body_shape: "json_object", truncation_state: "complete" },
      ],
      finding: {
        title: FINDING_TITLE, reachability_rationale: "The free-plan identity read the export route.", confidence: "medium",
        recommended_control: "Enforce the plan entitlement on the export route.", regression_suggestion: "Replay the free-plan export read.",
      },
      containment_codes: ["action_completed", "redacted"], redaction_count: 2, local_evidence_refs: [EVIDENCE_REF],
    }],
    containment_codes: ["action_completed", "redacted"], redaction_count: 2, projection_digest: METADATA.projectionDigest,
    signing_key_id: "runner_key_synthetic", signature_b64: `${"A".repeat(86)}==`,
  };
}

// Captured before any spy replaces it, so the fixture always passes through the real strict parser.
const realGetFindings = CanaryApi.prototype.getFindings;

async function strictFindings(): Promise<Readonly<CanaryFindingsProjection>> {
  const body = JSON.stringify(findingsWire());
  const api = new CanaryApi({ transport: async () => new Response(body, { status: 200, headers: { "Content-Type": "application/json" } }) });
  return realGetFindings.call(api, WS, PRJ, RUN);
}

let runReads: CanaryRunDashboard[];
let getRun: ReturnType<typeof vi.spyOn>;
// The control plane's disclosure row for RUN; an Error is what the read throws (404 until the runner registers).
let serverDisclosure: CanaryDisclosureState | Error;
let getDisclosure: ReturnType<typeof vi.spyOn>;
let getFindings: ReturnType<typeof vi.spyOn>;
let createPermit: ReturnType<typeof vi.spyOn>;
let keepLocal: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  nav.search = `workspace=${WS}&project=${PRJ}`;
  vi.spyOn(HeelCloudApi.prototype, "me").mockResolvedValue({ userId: "usr_synthetic", workspaces: [{ workspaceRef: WS, role: "owner" }] });
  vi.spyOn(HeelCloudApi.prototype, "listProjects").mockResolvedValue([
    { workspaceRef: WS, projectRef: PRJ, name: "Synthetic staging", createdBy: "membership:usr_synthetic", createdAt: 1 },
    { workspaceRef: WS, projectRef: PRJ2, name: "Second project", createdBy: "membership:usr_synthetic", createdAt: 2 },
  ]);
  vi.spyOn(CanaryApi.prototype, "listEnvironments").mockResolvedValue([{
    schemaVersion: "VerifiedEnvironment.v1", environmentId: ENV, origin: ORIGIN, environmentClass: "staging",
    status: "verified", proofMethod: "https-file", challengeGeneration: 1, challengeExpiresAt: null,
    proofExpiresAt: 4_000_000_000_000, lastFailureCode: null, verificationRecordDigest: "f".repeat(64), isExecutable: true,
  }] as never);
  vi.spyOn(CanaryApi.prototype, "listRunnerContextBindings").mockResolvedValue({
    runners: [],
    bindings: [{
      bindingId: `rcb_${"1".repeat(32)}`, bindingDigest: "2".repeat(64), environmentId: ENV, origin: ORIGIN,
      environmentClass: "staging", verificationRecordDigest: "f".repeat(64), runnerId: "runr_synthetic",
      runnerKeyId: "k_synthetic", status: "active", issuedAtMs: 1, expiresAtMs: 4_000_000_000_000, firstClaimedAtMs: null,
    }],
  });
  // The server lists a run only while it awaits approval; this one was approved before the page saw it settle.
  let listed = true;
  vi.spyOn(CanaryApi.prototype, "listPendingApprovalRequests").mockImplementation(async () => {
    if (!listed) return { request: null, hasMore: false };
    listed = false;
    return { request: { runId: RUN, approvalId: APPROVAL } as never, hasMore: false };
  });
  runReads = [APPROVED, TERMINAL];
  getRun = vi.spyOn(CanaryApi.prototype, "getRun").mockImplementation(async (_ws, _prj, runRef) => {
    expect(runRef).toBe(RUN);
    const next = runReads.length > 1 ? runReads.shift() : runReads[0];
    if (next instanceof Error) throw next;
    return next as CanaryRunDashboard;
  });
  serverDisclosure = new CanaryApiError("canary_run_not_found", 404);
  getDisclosure = vi.spyOn(CanaryApi.prototype, "getDisclosure").mockImplementation(async (ws, prj, runRef) => {
    expect([ws, prj, runRef]).toEqual([WS, PRJ, RUN]);
    if (serverDisclosure instanceof Error) throw serverDisclosure;
    return serverDisclosure;
  });
  getFindings = vi.spyOn(CanaryApi.prototype, "getFindings").mockImplementation(async (ws, prj, runRef) => {
    expect([ws, prj, runRef]).toEqual([WS, PRJ, RUN]);
    if (serverDisclosure instanceof Error || serverDisclosure.status !== "synchronized") throw new CanaryApiError("canary_run_not_found", 404);
    return strictFindings();
  });
  createPermit = vi.spyOn(CanaryApi.prototype, "createDisclosurePermit").mockImplementation(async () => {
    serverDisclosure = disclosureState("permitted");
    return {} as never;
  });
  keepLocal = vi.spyOn(CanaryApi.prototype, "markDisclosureLocalOnly").mockImplementation(async () => {
    serverDisclosure = disclosureState("local_only");
    return {} as never;
  });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});


function metric(label: string): string {
  const term = screen.getAllByText(label).find((item) => item.tagName === "DT");
  return term?.nextElementSibling?.textContent ?? "";
}


describe("CUSTOMER-TERMINAL-RESULT-VIEW: an approved run is followed to its terminal status", () => {
  test("the run that left the pending list is re-read until the control plane reports it terminal", async () => {
    render(<Dashboard />);
    await screen.findByText("Rehearsal running");
    expect(metric("Budget")).toBe("0 / 20 requests");

    await screen.findByText("Rehearsal complete", undefined, { timeout: 4_000 });
    expect(metric("Scenarios")).toBe("1 / 1");
    expect(metric("Budget")).toBe("2 / 20 requests");
    expect(await screen.findByText(/Waiting for the paired runner to report the local result\./)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Stop rehearsal" })).toBeNull();
    // The followed run is now the address's third opaque ref, so a reload restores it.
    expect(new URLSearchParams(nav.search).get("run")).toBe(RUN);
  });

  test("polling stops once the run is terminal", async () => {
    render(<Dashboard />);
    await screen.findByText("Rehearsal complete", undefined, { timeout: 4_000 });
    const reads = getRun.mock.calls.length;
    await new Promise((resolve) => setTimeout(resolve, 2_500));
    expect(getRun.mock.calls.length).toBe(reads);
  }, 10_000);

  test("the completed activation shows all four steps done and no pairing or approval action", async () => {
    render(<Dashboard />);
    await screen.findByText("Rehearsal complete", undefined, { timeout: 4_000 });
    expect(screen.getByLabelText("4 of 4 setup steps complete")).toBeTruthy();
    expect(screen.getByText("Complete")).toBeTruthy();
    expect(screen.queryByText(/Next action: pair runner/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Review exact plan" })).toBeNull();
  });

  test("no link is offered to a fixed loopback port the runner never binds", async () => {
    render(<Dashboard />);
    await screen.findByText("Rehearsal complete", undefined, { timeout: 4_000 });
    expect(document.querySelector('a[href^="http://127.0.0.1"]')).toBeNull();
    expect(screen.queryByRole("link", { name: "Open local result" })).toBeNull();
  });

  test("a run the control plane no longer returns is dropped instead of shown with invented metrics", async () => {
    runReads = [APPROVED, new CanaryApiError("canary_run_not_found", 404) as never];
    render(<Dashboard />);
    await screen.findByText("Rehearsal running");
    await waitFor(() => expect(screen.queryByText("Rehearsal running")).toBeNull(), { timeout: 4_000 });
    expect(screen.queryByText("Rehearsal complete")).toBeNull();
    expect(screen.queryByRole("region", { name: "Result sharing" })).toBeNull();
    expect(new URLSearchParams(nav.search).get("run")).toBeNull();
  });
});


const RUN_ADDRESS = `workspace=${WS}&project=${PRJ}&run=${RUN}`;

/** A reload: nothing is pending, the address carries the run ref, and the page starts from scratch. */
function reload(search = RUN_ADDRESS): ReturnType<typeof render> {
  vi.spyOn(CanaryApi.prototype, "listPendingApprovalRequests").mockResolvedValue({ request: null, hasMore: false });
  runReads = [TERMINAL];
  nav.search = search;
  return render(<Dashboard />);
}

function runParam(): string | null {
  return new URLSearchParams(nav.search).get("run");
}

function sharingRegion(): HTMLElement {
  return screen.getByRole("region", { name: "Result sharing" });
}

async function settle(ms = 300): Promise<void> {
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, ms)); });
}

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}


describe("CUSTOMER-RESULT-HANDOFF-B G1: the shown run survives reload through one re-authorized opaque ref", () => {
  test("a reload with the run ref restores the terminal view from the run read alone", async () => {
    reload();
    await screen.findByText("Rehearsal complete");
    expect(metric("Scenarios")).toBe("1 / 1");
    expect(metric("Budget")).toBe("2 / 20 requests");
    expect(getRun).toHaveBeenCalledWith(WS, PRJ, RUN, expect.any(AbortSignal));
    expect(screen.getByLabelText("4 of 4 setup steps complete")).toBeTruthy();
    expect(runParam()).toBe(RUN);
  });

  test("a foreign or purged run ref (404) is dropped from the address and shows nothing", async () => {
    reload();
    runReads = [new CanaryApiError("canary_run_not_found", 404) as never];
    await waitFor(() => expect(runParam()).toBeNull());
    await settle();
    expect(nav.search).toBe(`workspace=${WS}&project=${PRJ}`);
    expect(screen.queryByText("Rehearsal complete")).toBeNull();
    expect(screen.queryByText("Rehearsal running")).toBeNull();
    expect(screen.queryByText("That rehearsal is unavailable in this project.")).toBeNull();
  });

  test("a run ref refused by role (403) is dropped without a notice or a retry loop", async () => {
    reload();
    runReads = [new CanaryApiError("unavailable", 403) as never];
    await waitFor(() => expect(runParam()).toBeNull());
    const reads = getRun.mock.calls.length;
    await settle(2_300);
    expect(getRun.mock.calls.length).toBe(reads);
    expect(screen.queryByText("Rehearsal complete")).toBeNull();
  });

  test("a run ref is never read for a project the server did not confirm", async () => {
    reload(`workspace=${WS}&project=prj_${"7".repeat(32)}&run=${RUN}`);
    await screen.findByRole("combobox", { name: /project/i });
    await settle();
    expect(getRun).not.toHaveBeenCalled();
    expect(runParam()).toBeNull();
    expect(nav.search).toBe(`workspace=${WS}&project=${PRJ}`);
  });

  test("a run ref naming a run still awaiting approval is left to the pending list, not shown as running", async () => {
    reload();
    runReads = [dashboard("awaiting_execution_approval", null, {})];
    await waitFor(() => expect(runParam()).toBeNull());
    await settle();
    expect(screen.queryByText("Rehearsal running")).toBeNull();
    expect(screen.queryByText("Rehearsal complete")).toBeNull();
  });

  test("a pending approval for another run wins over the run ref", async () => {
    nav.search = RUN_ADDRESS;
    vi.spyOn(CanaryApi.prototype, "listPendingApprovalRequests").mockResolvedValue({
      request: { runId: OTHER_RUN, approvalId: APPROVAL, scenarios: [], routes: [], origin: ORIGIN, hostname: "synthetic-staging.example.test", projectionDigest: "5".repeat(64), requestBudget: 2, durationSeconds: 60, egress: "synthetic-staging.example.test:443" } as never,
      hasMore: false,
    });
    getRun.mockImplementation(async (_ws: string, _prj: string, runRef: string) => {
      const awaiting = dashboard("awaiting_execution_approval", null, {});
      return runRef === OTHER_RUN ? { ...awaiting, run: { ...awaiting.run, runId: OTHER_RUN } } : TERMINAL;
    });
    render(<Dashboard />);
    await screen.findByRole("button", { name: "Review exact plan" });
    await settle();
    expect(screen.queryByText("Rehearsal complete")).toBeNull();
    expect(runParam()).toBeNull();
    expect(getDisclosure).not.toHaveBeenCalled();
  });

  test("a session lost on the run read signs out and clears every ref", async () => {
    reload();
    runReads = [new CanaryApiError("unavailable", 401) as never];
    await screen.findByText(/Your session ended\./);
    await waitFor(() => expect(nav.search).toBe(""));
    expect(screen.queryByText("Rehearsal complete")).toBeNull();
  });

  test("a project switch drops the shown run and its ref", async () => {
    reload();
    await screen.findByText("Rehearsal complete");
    fireEvent.change(screen.getByRole("combobox", { name: /project/i }), { target: { value: PRJ2 } });
    await waitFor(() => expect(nav.search).toBe(`workspace=${WS}&project=${PRJ2}`));
    await settle();
    expect(screen.queryByText("Rehearsal complete")).toBeNull();
    expect(screen.queryByRole("region", { name: "Result sharing" })).toBeNull();
  });

  test("an outage on the run read keeps the ref, says so, and shows the run once the read succeeds", async () => {
    reload();
    runReads = [new CanaryApiError("unavailable", 0) as never, TERMINAL];
    await screen.findByText(/could not read that rehearsal right now, so nothing is shown for it/);
    expect(runParam()).toBe(RUN);
    expect(screen.queryByText("Rehearsal complete")).toBeNull();
    await screen.findByText("Rehearsal complete", undefined, { timeout: 4_000 });
  });

  test("a late run read for a previous project is not adopted after a switch", async () => {
    const held = deferred<CanaryRunDashboard>();
    reload();
    getRun.mockImplementation(() => held.promise);
    await screen.findByRole("combobox", { name: /project/i });
    fireEvent.change(screen.getByRole("combobox", { name: /project/i }), { target: { value: PRJ2 } });
    await waitFor(() => expect(nav.search).toBe(`workspace=${WS}&project=${PRJ2}`));
    await act(async () => { held.resolve(TERMINAL); });
    await settle();
    expect(screen.queryByText("Rehearsal complete")).toBeNull();
    expect(runParam()).toBeNull();
  });
});


describe("CUSTOMER-RESULT-HANDOFF-B G2/G3: the redacted finding is shown only after an explicit share", () => {
  test("waiting runner, then server metadata, then explicit Share, permit, synchronized finding card", async () => {
    reload();
    await screen.findByText("Rehearsal complete");
    await within(sharingRegion()).findByText(/Waiting for the paired runner to report the local result\./);
    expect(within(sharingRegion()).getByText(/while it is offline the result stays there and nothing is shared/)).toBeTruthy();

    serverDisclosure = disclosureState("awaiting_disclosure_approval");
    const review = await screen.findByRole("button", { name: "Review sharing" }, { timeout: 4_000 });
    expect(sharingRegion().textContent).toMatch(/1 scenario, 1 finding\. Nothing has been shared\./);
    expect(createPermit).not.toHaveBeenCalled();
    fireEvent.click(review);
    const dialog = screen.getByRole("dialog", { name: "Share result summary?" });
    expect(within(dialog).getByText("1 scenarios")).toBeTruthy();
    expect(within(dialog).getByText("Findings").nextSibling?.textContent).toBe("1");
    expect(within(dialog).getByText("1.8 KB")).toBeTruthy();

    fireEvent.click(within(dialog).getByRole("button", { name: "Share this summary" }));
    await waitFor(() => expect(createPermit).toHaveBeenCalledTimes(1));
    expect(createPermit).toHaveBeenCalledWith(WS, PRJ, RUN, METADATA);
    await within(sharingRegion()).findByText(/Share approved\. The paired runner uploads this exact summary/);
    expect(screen.queryByRole("dialog", { name: "Share result summary?" })).toBeNull();
    expect(getFindings).not.toHaveBeenCalled();

    serverDisclosure = disclosureState("synchronized");
    const card = await screen.findByRole("region", { name: "Rehearsal result" }, { timeout: 4_000 });
    expect(within(card).getByRole("heading", { name: FINDING_TITLE })).toBeTruthy();
    expect(within(card).getByText("GET /api/export")).toBeTruthy();
    expect(within(card).getByText("medium")).toBeTruthy();
    expect(within(card).getByText("Enforce the plan entitlement on the export route.")).toBeTruthy();
    expect(within(card).getByText("The free-plan identity read the export route.")).toBeTruthy();
    expect(within(card).getByText("Replay the free-plan export read.")).toBeTruthy();
    expect(within(card).getByText(EVIDENCE_REF)).toBeTruthy();
    expect(within(card).getByText(METADATA.projectionDigest)).toBeTruthy();
    expect(within(card).getByRole("list", { name: "Recorded responses" }).textContent).toMatch(/higher_plan: 200 · json_object.*lower_plan: 200 · json_object/);
    expect(card.textContent).not.toMatch(/evidence:\s*200|status-only evidence|error envelope is evidence/i);
    expect(sharingRegion().textContent).toMatch(/Redacted summary shared with this workspace\./);

    // Settled: neither read repeats.
    const reads = getDisclosure.mock.calls.length + getFindings.mock.calls.length;
    await settle(2_300);
    expect(getDisclosure.mock.calls.length + getFindings.mock.calls.length).toBe(reads);

    // Reload the tab: the run and the card come back from the same server reads.
    cleanup();
    reload();
    await screen.findByRole("region", { name: "Rehearsal result" });
    expect(screen.getByText("Rehearsal complete")).toBeTruthy();
    expect(createPermit).toHaveBeenCalledTimes(1);
  }, 20_000);

  test("Keep local records the decision with the server metadata and never reads findings", async () => {
    serverDisclosure = disclosureState("local_result_ready");
    reload();
    fireEvent.click(await screen.findByRole("button", { name: "Review sharing" }));
    fireEvent.click(within(screen.getByRole("dialog", { name: "Share result summary?" })).getByRole("button", { name: "Keep result local" }));
    await within(sharingRegion()).findByText("Result kept local. No summary bytes were uploaded.");
    expect(keepLocal).toHaveBeenCalledWith(WS, PRJ, RUN, METADATA);
    expect(createPermit).not.toHaveBeenCalled();
    await settle(2_300);
    expect(getFindings).not.toHaveBeenCalled();
    expect(screen.queryByRole("region", { name: "Rehearsal result" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Review sharing" })).toBeNull();
  }, 10_000);

  test("no decision is made without a click, and the review dialog does not open by itself", async () => {
    serverDisclosure = disclosureState("awaiting_disclosure_approval");
    reload();
    await screen.findByRole("button", { name: "Review sharing" });
    await settle(2_300);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(createPermit).not.toHaveBeenCalled();
    expect(keepLocal).not.toHaveBeenCalled();
    expect(getFindings).not.toHaveBeenCalled();
  }, 10_000);

  test("an unreadable status or findings response is reported as unavailable, never as a result", async () => {
    serverDisclosure = new CanaryApiError("invalid_response", 502);
    reload();
    await within(await screen.findByRole("region", { name: "Result sharing" })).findByText(/returned no readable sharing status for this result, so none is shown/);
    expect(screen.queryByRole("button", { name: "Review sharing" })).toBeNull();

    serverDisclosure = disclosureState("synchronized");
    getFindings.mockRejectedValue(new CanaryApiError("invalid_response", 502));
    await within(sharingRegion()).findByText(/shared, but Heel Cloud could not return it right now, so none is shown/, undefined, { timeout: 4_000 });
    expect(screen.queryByRole("region", { name: "Rehearsal result" })).toBeNull();
    expect(document.body.textContent).not.toMatch(new RegExp(FINDING_TITLE));
  }, 10_000);

  test("a late disclosure read for a previous project is not adopted after a switch", async () => {
    const held = deferred<CanaryDisclosureState>();
    getDisclosure.mockImplementation(() => held.promise);
    reload();
    await screen.findByText("Rehearsal complete");
    await waitFor(() => expect(getDisclosure).toHaveBeenCalled());
    fireEvent.change(screen.getByRole("combobox", { name: /project/i }), { target: { value: PRJ2 } });
    await waitFor(() => expect(nav.search).toBe(`workspace=${WS}&project=${PRJ2}`));
    await act(async () => { held.resolve(disclosureState("awaiting_disclosure_approval")); });
    await settle();
    expect(screen.queryByRole("button", { name: "Review sharing" })).toBeNull();
    expect(screen.queryByRole("region", { name: "Result sharing" })).toBeNull();
  });

  test("a sign-out drops the shown run, its ref and its sharing state", async () => {
    vi.spyOn(HeelCloudApi.prototype, "logout").mockResolvedValue(undefined);
    serverDisclosure = disclosureState("awaiting_disclosure_approval");
    reload();
    await screen.findByRole("button", { name: "Review sharing" });
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await screen.findByText(/You signed out\./);
    await waitFor(() => expect(nav.search).toBe(""));
    expect(screen.queryByRole("region", { name: "Result sharing" })).toBeNull();
    expect(screen.queryByText("Rehearsal complete")).toBeNull();
  });

  test("recent-auth recovery keeps only the opaque refs and re-authorizes the run before showing it", async () => {
    const logout = vi.spyOn(HeelCloudApi.prototype, "logout").mockResolvedValue(undefined);
    const login = vi.spyOn(HeelCloudApi.prototype, "login").mockResolvedValue(undefined as never);
    serverDisclosure = disclosureState("awaiting_disclosure_approval");
    createPermit.mockRejectedValue(new CanaryApiError("recent_auth_required", 403));
    reload();
    fireEvent.click(await screen.findByRole("button", { name: "Review sharing" }));
    fireEvent.click(within(screen.getByRole("dialog", { name: "Share result summary?" })).getByRole("button", { name: "Share this summary" }));
    await screen.findByText(/sharing a result summary or keeping it local needs an owner or admin sign-in from the last 15 minutes/);
    expect(screen.queryByRole("dialog")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Sign in again" }));
    await screen.findByText(/Sign in again to return to this rehearsal result\. Nothing was shared/);
    expect(logout).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(nav.search).toBe(""));
    const runReadsBefore = getRun.mock.calls.length;

    fireEvent.click(screen.getByRole("button", { name: /already have an account/i }));
    fireEvent.change(screen.getByLabelText(/^Email/), { target: { value: "owner@example.test" } });
    fireEvent.change(screen.getByLabelText(/^Password/), { target: { value: "synthetic-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await screen.findByText("Rehearsal complete");
    expect(login).toHaveBeenCalledTimes(1);
    expect(getRun.mock.calls.length).toBeGreaterThan(runReadsBefore);
    expect(runParam()).toBe(RUN);
    // Nothing was approved on the user's behalf: the same choice is offered again.
    await screen.findByRole("button", { name: "Review sharing" });
    expect(screen.queryByRole("dialog")).toBeNull();
  }, 10_000);
});


describe("CUSTOMER-RESULT-HANDOFF-B: no manual file hop and no browser storage", () => {
  test("no file input, extraction step or loopback link remains, and nothing is written to storage", async () => {
    // A recording store per area (the runtime's own global has no backing store under jsdom); any write is a failure.
    const writes: string[] = [];
    const recording = (): Storage => {
      const items = new Map<string, string>();
      return {
        get length() { return items.size; }, clear: () => items.clear(), getItem: (key: string) => items.get(key) ?? null,
        key: (index: number) => [...items.keys()][index] ?? null, removeItem: (key: string) => { items.delete(key); },
        setItem: (key: string, value: string) => { writes.push(key); items.set(key, String(value)); },
      };
    };
    vi.stubGlobal("localStorage", recording());
    vi.stubGlobal("sessionStorage", recording());
    serverDisclosure = disclosureState("synchronized");
    reload();
    await screen.findByRole("region", { name: "Rehearsal result" });
    expect(document.querySelector("input[type=file]")).toBeNull();
    expect(document.body.textContent).not.toMatch(/Load local summary|choose the signed local summary|findings_projection|heel\.local-result-view/i);
    expect(document.querySelector('a[href^="http://127.0.0.1"], a[href^="http://localhost"]')).toBeNull();
    expect(writes).toEqual([]);
    expect(globalThis.localStorage.length).toBe(0);
    expect(globalThis.sessionStorage.length).toBe(0);
  });
});
