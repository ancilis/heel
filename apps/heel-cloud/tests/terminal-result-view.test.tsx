// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/**
 * CUSTOMER-TERMINAL-RESULT-VIEW: once a run leaves `awaiting_execution_approval` the control plane no longer lists it as
 * a pending request, so the dashboard must keep reading that run's own status until it settles.
 *
 * SEAM: the account and canary clients are replaced by prototype spies returning parsed client values. The pending
 * list is modelled as the server returns it: only runs awaiting approval appear there. No target, runner or
 * control-plane request is real; the counters below are synthetic and match the shape of a 2-request, 1-scenario run.
 */

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import Dashboard from "../app/dashboard/page";
import { CanaryApi, CanaryApiError, type CanaryRunDashboard } from "../lib/canary-api";
import { HeelCloudApi } from "../lib/heel-cloud-api";


const WS = `ws_${"a".repeat(16)}`;
const PRJ = `prj_${"b".repeat(32)}`;
const RUN = `crun_${"c".repeat(32)}`;
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

let runReads: CanaryRunDashboard[];
let getRun: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  nav.search = `workspace=${WS}&project=${PRJ}`;
  vi.spyOn(HeelCloudApi.prototype, "me").mockResolvedValue({ userId: "usr_synthetic", workspaces: [{ workspaceRef: WS, role: "owner" }] });
  vi.spyOn(HeelCloudApi.prototype, "listProjects").mockResolvedValue([
    { workspaceRef: WS, projectRef: PRJ, name: "Synthetic staging", createdBy: "membership:usr_synthetic", createdAt: 1 },
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
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
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
    expect(screen.getByText("Load local summary to review separate sharing →")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Stop rehearsal" })).toBeNull();
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
    expect(screen.queryByText("Load local summary to review separate sharing →")).toBeNull();
  });
});
