// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";

import Dashboard from "../app/dashboard/page";
import Runner from "../app/runner/page";
import { ActivationCard, type ActivationSnapshot } from "../components/canary/ActivationCard";
import { ApprovalDialog } from "../components/canary/ApprovalDialog";
import { DisclosureDialog } from "../components/canary/DisclosureDialog";
import { FindingsCard } from "../components/canary/FindingsCard";
import { RunProgress } from "../components/canary/RunProgress";
import type { CanaryFindingsProjection } from "../lib/canary-api";


// SEAM: the dashboard reads its selection from the App Router; these render tests have no router.
const router = vi.hoisted(() => ({ replace: vi.fn() }));
vi.mock("next/navigation", () => ({
  usePathname: () => "/dashboard",
  useRouter: () => router,
  useSearchParams: () => new URLSearchParams(),
}));

afterEach(cleanup);

// The dashboard's initial (session-checking) state, i.e. a private connector is not yet known.
const LOCKED: ActivationSnapshot = { environment: "unverified", runner: "locked", canaryAccess: "locked", rehearsal: "locked" };


describe("canary activation dashboard", () => {
  test("keeps approval projections on the paired runner and exposes no browser upload path", () => {
    const source = readFileSync(resolve(process.cwd(), "app/dashboard/page.tsx"), "utf8");
    expect(source).toContain("Authorize paired runner");
    expect(source).toContain("This runner is fixed to its first claimed environment. To move it, stop and re-pair a fresh runner, then authorize access here.");
    expect(source).toContain("revokeContextBinding");
    expect(source).toContain("never accepts projection file uploads");
    expect(source).not.toContain("loadProjection(");
    expect(source).not.toContain("Choose approval projection");
  });
  test("uses the project-scoped server runner list as the add-access selector", () => {
    const source = readFileSync(resolve(process.cwd(), "app/dashboard/page.tsx"), "utf8");
    const selector = source.slice(source.indexOf("Paired runner<select"), source.indexOf("</select></label>", source.indexOf("Paired runner<select")));
    expect(selector).toContain("context.contextBindings.runners.map");
    expect(selector).not.toContain("context.contextBindings.bindings.map");
  });
  test("clears an occupied runner selection after refresh or a project switch", () => {
    const source = readFileSync(resolve(process.cwd(), "app/dashboard/page.tsx"), "utf8");
    expect(source).toContain("const selectedRunnerAvailable");
    expect(source).toContain("setSelectedRunner((current) => contextBindings.runners.some");
    expect(source).toContain("setSelectedRunner(\"\"); setSelectedBindingEnvironment(\"\");");
    expect(source).toContain("!selectedRunnerAvailable");
    expect(source).toContain("value={selectedRunnerAvailable ? selectedRunner : \"\"}");
  });
  test("keys approval-dialog state to the discovered request and clears it on identity loss", () => {
    const source = readFileSync(resolve(process.cwd(), "app/dashboard/page.tsx"), "utf8");
    expect(source).toContain("type ApprovalDialogState = { requestKey: string; open: boolean } | null");
    expect(source).toContain("function approvalRequestKey");
    expect(source).toContain("const clearApprovalIdentity");
    expect(source).toContain("setApprovalDialog({ requestKey: approvalKey, open: true })");
    expect(source).toContain("<ApprovalDialog key={approvalKey}");
    expect(source).not.toContain("const [approvalOpen");
  });
  test("keeps approval review available only while the server still reports awaiting approval", () => {
    const source = readFileSync(resolve(process.cwd(), "app/dashboard/page.tsx"), "utf8");
    expect(source).toContain("const [pendingApproval, setPendingApproval]");
    expect(source).toContain("const [observedRun, setObservedRun]");
    expect(source).toContain('next.run.status !== "awaiting_execution_approval"');
    expect(source).toContain("error.status === 401 || error.status === 403");
    expect(source).toContain("const hasPlan = pendingApproval !== null && pendingApproval.run.run.status === \"awaiting_execution_approval\"");
  });
  test("does not lead a visitor without a private connector into the runner activation funnel", () => {
    render(<Dashboard />);

    expect(screen.queryByRole("region", { name: /launch activation/i })).toBeNull();
    expect(document.body.textContent).not.toMatch(/next action: verify staging|pair runner/i);
  });

  test("keeps the private-connector activation card's four ordered steps and one unambiguous next action", () => {
    render(<ActivationCard completedSteps={0} snapshot={LOCKED} />);

    const activation = screen.getByRole("region", { name: /launch activation/i });
    const steps = within(activation).getAllByRole("listitem");
    expect(steps).toHaveLength(4);
    expect(steps.map((step) => step.querySelector("h2")?.textContent)).toEqual([
      "Verify staging",
      "Pair runner",
      "Add canary access",
      "Run first rehearsal",
    ]);
    expect(within(activation).getByText(/next action: verify staging/i)).toBeTruthy();
    expect(within(activation).getByRole("link", { name: /verify staging now/i })).toBeTruthy();
    expect(within(activation).getByText(/first useful run/i)).toBeTruthy();
    expect(screen.queryByRole("navigation", { name: /preview activation states/i })).toBeNull();
    expect(document.body.textContent).not.toMatch(/Northstar workspace|Sample state only/i);
  });

  test("keeps pre-disclosure cloud status operational and free of local-sensitive content", () => {
    render(<Dashboard />);

    const content = document.body.textContent?.toLowerCase() ?? "";
    expect(content).toMatch(/operational status only/i);
    // The one boundary statement that credentials and raw evidence stay on the runner machine names them; nothing else may.
    const boundary = "and credentials and raw evidence stay there.";
    expect(content.split(boundary).length - 1).toBe(1);
    expect(content.replace(boundary, "")).not.toMatch(/raw evidence|credential|fixture id|openapi|authorization header|access token/i);
    expect(screen.queryByText(/finding|vulnerab/i)).toBeNull();
  });

  test("offers precise recovery for interrupted setup and a usable local runner route", () => {
    render(<ActivationCard completedSteps={0} snapshot={LOCKED} />);
    expect(screen.getByText(/proof has not been checked yet/i)).toBeTruthy();
    expect(screen.getByText(/runner pairing starts after verification/i)).toBeTruthy();
    expect(screen.getByText(/add two isolated test identities on the runner machine/i)).toBeTruthy();

    cleanup();
    render(<Runner />);
    expect(screen.getByRole("heading", { name: /validate an export entitlement/i })).toBeTruthy();
    expect(screen.getByText(/not general execution against arbitrary customer targets/i)).toBeTruthy();
    expect(screen.getAllByRole("link", { name: /paired runner guide/i }).every((link) => link.getAttribute("href") === "/guide")).toBe(true);
    expect(screen.queryByText(/copper · field · seven|8C1F · 4E29 · A773/i)).toBeNull();
    expect(screen.getByRole("link", { name: /dashboard/i }).getAttribute("href"))
      .toBe("/dashboard");
  });
});


describe("canary approval and disclosure boundaries", () => {
  test("requires exact hostname and a reason while the approval summary stays immutable", () => {
    const approve = vi.fn();
    render(<ApprovalDialog
      open
      origin="https://staging.example.test"
      routes={["GET /account", "HEAD /plans/current"]}
      scenarios={["Anonymous read", "Plan boundary"]}
      requestBudget={12}
      durationSeconds={45}
      egress="staging.example.test:443"
      onApprove={approve}
      onClose={vi.fn()}
    />);

    const dialog = screen.getByRole("dialog", { name: /approve one rehearsal/i });
    expect(within(dialog).getByText(/immutable execution summary/i)).toBeTruthy();
    expect(within(dialog).getByDisplayValue("https://staging.example.test"))
      .toHaveProperty("readOnly", true);
    expect(within(dialog).getByDisplayValue("12 requests"))
      .toHaveProperty("readOnly", true);
    expect(within(dialog).getByDisplayValue("staging.example.test:443"))
      .toHaveProperty("readOnly", true);
    const confirm = within(dialog).getByLabelText(/retype exact hostname/i);
    const reason = within(dialog).getByLabelText(/reason for this rehearsal/i);
    const button = within(dialog).getByRole("button", { name: /approve and run/i });
    expect(button).toHaveProperty("disabled", true);

    fireEvent.change(confirm, { target: { value: "staging.example.test" } });
    fireEvent.change(reason, { target: { value: "Release boundary check" } });
    expect(button).toHaveProperty("disabled", false);
    fireEvent.click(button);
    expect(approve).toHaveBeenCalledWith("Release boundary check");
  });

  test("makes disclosure a separate metadata-only choice with a local-only exit", () => {
    const localOnly = vi.fn();
    const permit = vi.fn();
    render(<DisclosureDialog
      open
      completedScenarios={4}
      outcomeCounts={{ blocked: 2, observed: 1, inconclusive: 1 }}
      byteCount={1840}
      onKeepLocal={localOnly}
      onPermit={permit}
      onClose={vi.fn()}
    />);

    const dialog = screen.getByRole("dialog", { name: /share result summary/i });
    expect(dialog.classList.contains("disclosure-dialog")).toBe(true);
    expect(within(dialog).getByText(/separate disclosure/i)).toBeTruthy();
    expect(within(dialog).getByText(/metadata only/i)).toBeTruthy();
    expect(within(dialog).getByText("4 scenarios")).toBeTruthy();
    expect(within(dialog).getByText("1.8 KB")).toBeTruthy();
    expect(dialog.textContent?.toLowerCase()).not.toMatch(/raw evidence|credential|fixture id|openapi/i);

    fireEvent.click(within(dialog).getByRole("button", { name: /keep result local/i }));
    expect(localOnly).toHaveBeenCalledOnce();
    expect(permit).not.toHaveBeenCalled();
  });
});


describe("active rehearsal controls", () => {
  test("shows bounded progress, stop, retry recovery, and loopback local-result handoff", () => {
    const stop = vi.fn();
    const retry = vi.fn();
    const { rerender } = render(<RunProgress
      phase="running"
      completedScenarios={2}
      totalScenarios={4}
      requestsUsed={7}
      requestBudget={12}
      secondsRemaining={31}
      onStop={stop}
    />);

    const progress = screen.getByRole("region", { name: /rehearsal progress/i });
    expect(within(progress).getByRole("progressbar").getAttribute("aria-valuenow")).toBe("2");
    expect(within(progress).getByText("7 / 12 requests")).toBeTruthy();
    fireEvent.click(within(progress).getByRole("button", { name: /stop rehearsal/i }));
    expect(stop).toHaveBeenCalledOnce();

    rerender(<RunProgress
      phase="error"
      completedScenarios={2}
      totalScenarios={4}
      requestsUsed={7}
      requestBudget={12}
      secondsRemaining={0}
      recovery="Runner lost contact. Confirm it is online, then retry status."
      onRetry={retry}
    />);
    fireEvent.click(screen.getByRole("button", { name: /retry status/i }));
    expect(retry).toHaveBeenCalledOnce();

    rerender(<RunProgress
      phase="complete"
      completedScenarios={4}
      totalScenarios={4}
      requestsUsed={11}
      requestBudget={12}
      secondsRemaining={0}
      localResultUrl="http://127.0.0.1:7331/runs/run-preview"
    />);
    const local = screen.getByRole("link", { name: /open local result/i });
    expect(local.getAttribute("href")).toBe("http://127.0.0.1:7331/runs/run-preview");
    expect(local.getAttribute("rel")).toContain("noreferrer");
  });

  test("ships responsive, reduced-motion, and scroll-boundary foundations", () => {
    const css = readFileSync(resolve(process.cwd(), "app/globals.css"), "utf8");
    expect(css).toMatch(/overscroll-behavior:\s*none/);
    expect(css).toMatch(/scrollbar-width:\s*thin/);
    expect(css).toMatch(/@media\s*\(prefers-reduced-motion:\s*reduce\)/);
    expect(css).toMatch(/@media\s*\(max-width:\s*760px\)/);
    expect(css).not.toMatch(/scroll-behavior:\s*smooth/);
  });
});


// CUSTOMER-ONBOARDING-STATE: the observed journey had an active paired runner and an exact target authorization, yet
// the card read "1/4 ready · Next action: pair runner · Ready to pair" and pointed at a runner companion that is not wired.
describe("CUSTOMER-ONBOARDING-STATE: activation progress follows the actual paired runner and authorization", () => {
  const CLI = "./heel-rc5/bin/heel";

  function stepState(activation: HTMLElement, title: string): string {
    const step = within(activation).getAllByRole("listitem").find((item) => item.querySelector("h2")?.textContent === title);
    return step?.querySelector(".step-state")?.textContent ?? "";
  }

  function expectNoDeadGuidance(): void {
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/companion/i);
    expect(text).not.toMatch(/20 minutes/i);
    expect(text).not.toMatch(/rc2/i);
    expect(screen.queryByRole("link", { name: /open pairing guide|add access locally/i })).toBeNull();
    expect(Array.from(document.querySelectorAll("a"), (link) => link.getAttribute("href"))).not.toContain("/runner#canary-access");
  }

  test("a paired runner authorized for the exact environment is never sent back to pairing", () => {
    render(<ActivationCard completedSteps={2} environmentOrigin="https://staging.example.test"
      snapshot={{ environment: "verified", runner: "paired", canaryAccess: "authorized", rehearsal: "locked" }} />);
    const activation = screen.getByRole("region", { name: /launch activation/i });
    expect(within(activation).getByText("2/4 ready")).toBeTruthy();
    expect(stepState(activation, "Pair runner")).toBe("Paired");
    expect(stepState(activation, "Add canary access")).toBe("Finish on runner");
    const next = within(activation).getByRole("status").textContent ?? "";
    expect(next).toMatch(/next action: finish local setup on the runner machine/i);
    expect(next).not.toMatch(/pair runner/i);
    expect(activation.textContent).not.toMatch(/ready to pair/i);
    // The cloud cannot observe liveness or local credentials; it says what it knows and what the plan will confirm.
    expect(activation.textContent).toMatch(/cannot see whether it is running right now/i);
    expect(activation.textContent).not.toMatch(/pair (it )?again|re-pair/i);
    expect(activation.textContent).toMatch(/Heel Cloud never receives them and cannot confirm them here/);
    expect(activation.textContent).toMatch(/If the runner submits a valid signed plan, it appears here for review; nothing runs unless you approve it\./);
    for (const command of [`${CLI} runner serve`, `${CLI} runner credential add --role lower_plan`, `${CLI} runner credential add --role higher_plan`,
      `${CLI} runner import-openapi`, `${CLI} runner status`]) expect(activation.textContent).toContain(command);
    expect(within(activation).getByText(/first useful run · 15-minute target/i)).toBeTruthy();
    expectNoDeadGuidance();
  });

  test("a paired runner without an authorization is asked to authorize, not to pair", () => {
    render(<ActivationCard completedSteps={2} environmentOrigin="https://staging.example.test"
      snapshot={{ environment: "verified", runner: "paired", canaryAccess: "unauthorized", rehearsal: "locked" }} />);
    const activation = screen.getByRole("region", { name: /launch activation/i });
    expect(stepState(activation, "Pair runner")).toBe("Paired");
    expect(stepState(activation, "Add canary access")).toBe("Authorize below");
    expect(within(activation).getByRole("status").textContent).toMatch(/next action: authorize the paired runner below/i);
    expect(activation.textContent).toMatch(/does not add or reveal any credential/i);
    expectNoDeadGuidance();
  });

  test("an unpaired runner keeps the pairing next action without a dead guide link", () => {
    render(<ActivationCard completedSteps={1} environmentOrigin="https://staging.example.test"
      snapshot={{ environment: "verified", runner: "unpaired", canaryAccess: "locked", rehearsal: "locked" }} />);
    const activation = screen.getByRole("region", { name: /launch activation/i });
    expect(stepState(activation, "Pair runner")).toBe("Ready to pair");
    expect(within(activation).getByRole("status").textContent).toMatch(/next action: pair runner/i);
    expect(activation.textContent).toMatch(/create a one-time invitation on this page/i);
    expectNoDeadGuidance();
  });

  test("legacy local-access states name the documented CLI instead of a companion", () => {
    for (const canaryAccess of ["missing", "partial", "error"] as const) {
      cleanup();
      render(<ActivationCard completedSteps={2}
        snapshot={{ environment: "verified", runner: "paired", canaryAccess, rehearsal: "locked" }} />);
      expect(document.body.textContent, canaryAccess).toMatch(/runner (credential add|status)/);
      expectNoDeadGuidance();
    }
  });
});


describe("CUSTOMER-RESULT-HANDOFF-B: result sharing and the shared finding render only server values", () => {
  test("the sharing review opens from the server's metadata counts alone and makes no choice by itself", () => {
    const permit = vi.fn();
    const local = vi.fn();
    render(<DisclosureDialog open completedScenarios={1} findingCount={1} byteCount={1840} onKeepLocal={local} onPermit={permit} onClose={vi.fn()} />);
    const dialog = screen.getByRole("dialog", { name: /share result summary/i });
    expect(within(dialog).getByText("1 scenarios")).toBeTruthy();
    expect(within(dialog).getByText("Findings").nextSibling?.textContent).toBe("1");
    // No per-outcome counts are invented when the server metadata does not carry them.
    expect(within(dialog).queryByText("Held")).toBeNull();
    expect(within(dialog).queryByText("Crossed")).toBeNull();
    expect(dialog.textContent).toMatch(/opaque ids/);
    expect(dialog.textContent?.toLowerCase()).not.toMatch(/raw evidence|credential|fixture id|openapi/);
    expect(permit).not.toHaveBeenCalled();
    expect(local).not.toHaveBeenCalled();
  });

  test("a busy sharing review cannot submit a second decision", () => {
    const permit = vi.fn();
    render(<DisclosureDialog busy open completedScenarios={1} findingCount={0} byteCount={10} onKeepLocal={vi.fn()} onPermit={permit} onClose={vi.fn()} />);
    const share = screen.getByRole("button", { name: /share this summary/i });
    expect(share).toHaveProperty("disabled", true);
    fireEvent.click(share);
    expect(permit).not.toHaveBeenCalled();
  });

  test("a scenario without a server finding shows none, and observations are never presented as evidence", () => {
    const findings = {
      schema_version: "heel.canary-findings-projection.v1", projection_id: "cfp_x", run_id: `crun_${"c".repeat(32)}`,
      grant_id: "cgr_x", workspace_id: `ws_${"a".repeat(16)}`, project_id: `prj_${"b".repeat(32)}`, environment_id: `env_${"e".repeat(32)}`,
      manifest_digest: "1".repeat(64), approval_projection_digest: "2".repeat(64), grant_digest: "3".repeat(64),
      engine_version: "heel-1.3.0", adapter_versions: ["a.v1"], started_at_ms: 1, finished_at_ms: 2, assessment_outcome: "blocked",
      scenario_results: [{
        ordinal: 0, scenario_id: "anonymous-read", adapter_version: "a.v1", assessment_outcome: "blocked",
        route: { method: "HEAD", route_template: "/account" },
        observations: [{ semantic_role: "anonymous", status_code: 401, body_shape: "json_object", truncation_state: "complete" }],
        finding: null, containment_codes: ["action_completed"], redaction_count: 0, local_evidence_refs: [],
      }],
      containment_codes: ["action_completed"], redaction_count: 0, projection_digest: "d".repeat(64),
      signing_key_id: "k", signature_b64: `${"A".repeat(86)}==`,
    } as CanaryFindingsProjection;
    render(<FindingsCard findings={findings} />);
    const card = screen.getByRole("region", { name: "Rehearsal result" });
    expect(within(card).getByText("No finding was reported for this scenario.")).toBeTruthy();
    expect(within(card).queryByRole("article")).toBeNull();
    expect(within(card).getByText("HEAD /account")).toBeTruthy();
    expect(within(card).getByRole("list", { name: "Recorded responses" }).textContent).toBe("anonymous: 401 · json_object");
    expect(within(card).getByText(/status and body shape only, no content/)).toBeTruthy();
    expect(within(card).queryByRole("list", { name: "Local evidence references" })).toBeNull();
    expect(card.textContent).not.toMatch(/vulnerab|severity|critical|exploit/i);
  });

  test("a completed rehearsal points to the result and the sharing choice, not to a manual runner hop", () => {
    render(<ActivationCard completedSteps={4} snapshot={{ environment: "verified", runner: "paired", canaryAccess: "ready", rehearsal: "complete" }} />);
    const next = screen.getByText(/next action: review the result below and choose whether to share its redacted summary/i);
    expect(next.closest("[role=status]")?.textContent).not.toMatch(/runner machine|load local summary|upload/i);
  });
});
