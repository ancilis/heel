// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";

import { ApprovalDialog } from "../components/canary/ApprovalDialog";
import { BOUND_OBJECTIVE_CAVEAT, FindingsCard } from "../components/canary/FindingsCard";
import { ScenarioBindingStep } from "../components/canary/ScenarioBindingStep";
import type {
  CanaryFindingsProjection,
  FrozenScenarioBinding,
  ScenarioLibraryEntry,
  ScenarioPlanAction,
} from "../lib/canary-api";


afterEach(cleanup);

const DIGEST = "a".repeat(64);
const ACTIONS: ScenarioPlanAction[] = [
  { catalogScenarioId: "anonymous_authenticated_read", method: "GET", routeTemplate: "/api/canary" },
  { catalogScenarioId: "plan_entitlement_read", method: "HEAD", routeTemplate: "/billing/features" },
];

function entry(id: string, overrides: Partial<ScenarioLibraryEntry> = {}): ScenarioLibraryEntry {
  return {
    id, source: "library", revision: null, definitionDigest: DIGEST, definition: { id }, objective: `Objective ${id}`,
    category: "unintended_endpoints", kind: "endpoint", pack: "core_saas", recommendedControl: "control",
    mechanismId: id, applicability: "unknown", applicabilityRule: "always", evidenceState: "inferred",
    executionSupport: "static_only", catalogScenarioId: null, bindingVersion: null, coverageStatement: null,
    prerequisites: [], ...overrides,
  };
}

function bound(id: string, catalog: string, overrides: Partial<ScenarioLibraryEntry> = {}): ScenarioLibraryEntry {
  return entry(id, { executionSupport: "runner_supported", catalogScenarioId: catalog, bindingVersion: 1,
    coverageStatement: `Executed check: ${catalog} (GET/HEAD, roles a and b).`, prerequisites: ["methods: GET"], ...overrides });
}

const ENTRIES = [
  bound("sc.endpoint.hidden", "anonymous_authenticated_read"),
  bound("sc.flag.tiergate", "plan_entitlement_read"),
  bound("sc.internal.custom_read", "anonymous_authenticated_read", { source: "custom", revision: 3, definitionDigest: "c".repeat(64), evidenceState: "customer_declared" }),
  entry("sc.sem.static_only"),
];

function frozenRow(overrides: Partial<FrozenScenarioBinding> = {}): FrozenScenarioBinding {
  return {
    catalogScenarioId: "anonymous_authenticated_read", method: "HEAD", routeTemplate: "/account",
    libraryScenarioId: "sc.endpoint.hidden", source: "library", definitionDigest: DIGEST, revision: null,
    libraryDigest: "f".repeat(64), bindingVersion: 1, approvalId: "ap_canary", projectionDigest: "2".repeat(64),
    manifestDigest: "1".repeat(64), boundAtMs: 1,
    display: { objective: "Objective", mechanismId: "route-access", pack: "core_saas", coverageStatement: "Executed check: x" },
    ...overrides,
  };
}

const FINDINGS = {
  schema_version: "heel.canary-findings-projection.v1", projection_id: "cfp_x", run_id: `crun_${"c".repeat(32)}`,
  grant_id: "cgr_x", workspace_id: `ws_${"a".repeat(16)}`, project_id: `prj_${"b".repeat(32)}`, environment_id: `env_${"e".repeat(32)}`,
  manifest_digest: "1".repeat(64), approval_projection_digest: "2".repeat(64), grant_digest: "3".repeat(64),
  engine_version: "heel-1.3.0", adapter_versions: ["a.v1"], started_at_ms: 1, finished_at_ms: 2, assessment_outcome: "blocked",
  scenario_results: [{
    ordinal: 0, scenario_id: "anonymous_authenticated_read", adapter_version: "a.v1", assessment_outcome: "blocked",
    route: { method: "HEAD", route_template: "/account" },
    observations: [], finding: null, containment_codes: ["action_completed"], redaction_count: 0, local_evidence_refs: [],
  }],
  containment_codes: ["action_completed"], redaction_count: 0, projection_digest: "d".repeat(64),
  signing_key_id: "k", signature_b64: `${"A".repeat(86)}==`,
} as CanaryFindingsProjection;


describe("scenario binding step", () => {
  test("offers only entries bound to each action's check and posts the exact plan tuples", () => {
    const onFreeze = vi.fn();
    render(<ScenarioBindingStep accepting actions={ACTIONS} busy={false} entries={ENTRIES} frozen={[]} onFreeze={onFreeze} />);
    const anonymous = screen.getByRole("list", { name: "Entries for anonymous_authenticated_read GET /api/canary" });
    const plan = screen.getByRole("list", { name: "Entries for plan_entitlement_read HEAD /billing/features" });
    expect(within(anonymous).getAllByRole("checkbox")).toHaveLength(2);
    expect(anonymous.textContent).toContain("sc.endpoint.hidden");
    expect(anonymous.textContent).toContain("sc.internal.custom_read (custom revision 3)");
    expect(anonymous.textContent).not.toContain("sc.flag.tiergate");
    expect(within(plan).getAllByRole("checkbox")).toHaveLength(1);
    expect(plan.textContent).toContain("sc.flag.tiergate");
    expect(screen.queryByText(/sc\.sem\.static_only/)).toBeNull();
    const freeze = screen.getByRole("button", { name: "Freeze bindings" }) as HTMLButtonElement;
    expect(freeze.disabled).toBe(true);
    fireEvent.click(within(anonymous).getAllByRole("checkbox")[1]);
    fireEvent.click(within(plan).getByRole("checkbox"));
    expect(freeze.disabled).toBe(false);
    fireEvent.click(freeze);
    expect(onFreeze).toHaveBeenCalledWith([
      { catalogScenarioId: "anonymous_authenticated_read", method: "GET", routeTemplate: "/api/canary",
        libraryScenarioId: "sc.internal.custom_read", source: "custom", definitionDigest: "c".repeat(64) },
      { catalogScenarioId: "plan_entitlement_read", method: "HEAD", routeTemplate: "/billing/features",
        libraryScenarioId: "sc.flag.tiergate", source: "library", definitionDigest: DIGEST },
    ]);
  });

  test("shows frozen rows read-only and offers nothing once bindings can no longer change", () => {
    const onFreeze = vi.fn();
    const { rerender } = render(<ScenarioBindingStep accepting actions={ACTIONS} busy={false} entries={ENTRIES}
      frozen={[frozenRow({ method: "GET", routeTemplate: "/api/canary" })]} onFreeze={onFreeze} />);
    expect(screen.getByRole("list", { name: "Frozen bindings" }).textContent).toContain("sc.endpoint.hidden");
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.queryByRole("button", { name: "Freeze bindings" })).toBeNull();
    rerender(<ScenarioBindingStep accepting={false} actions={[]} busy={false} entries={ENTRIES} frozen={[]} onFreeze={onFreeze} />);
    expect(screen.getByText("Bindings can no longer be frozen for this run.")).toBeTruthy();
    expect(onFreeze).not.toHaveBeenCalled();
  });

  test("approval stays enabled without bindings and never depends on the binding step", () => {
    const onApprove = vi.fn();
    render(<ApprovalDialog durationSeconds={60} egress="canary.acme.dev:443" onApprove={onApprove} onClose={() => undefined}
      open origin="https://canary.acme.dev" requestBudget={2} routes={["GET /api/canary"]} scenarios={["anonymous_authenticated_read"]}
      scenarioBinding={{ accepting: true, actions: ACTIONS, busy: false, entries: ENTRIES, frozen: [], onFreeze: vi.fn() }} />);
    expect(screen.getByText("What this run stands for (optional)")).toBeTruthy();
    fireEvent.change(screen.getByLabelText(/Retype exact hostname/), { target: { value: "canary.acme.dev" } });
    fireEvent.change(screen.getByLabelText(/Reason for this rehearsal/), { target: { value: "bounded check" } });
    const approve = screen.getByRole("button", { name: "Approve and run" }) as HTMLButtonElement;
    expect(approve.disabled).toBe(false);
    fireEvent.click(approve);
    expect(onApprove).toHaveBeenCalledWith("bounded check");
  });
});


describe("findings card frozen-binding label", () => {
  test("states what the run stands for only when the tuple and both signed-plan digests match", () => {
    render(<FindingsCard findings={FINDINGS} frozenBindings={[frozenRow(), frozenRow({ libraryScenarioId: "sc.internal.x", source: "custom", revision: 2 })]} />);
    const card = screen.getByRole("region", { name: "Rehearsal result" });
    expect(card.textContent).toContain("Executed check: anonymous_authenticated_read HEAD /account");
    expect(within(card).getByText("Stands for: sc.endpoint.hidden, sc.internal.x (revision 2)")).toBeTruthy();
    expect(within(card).getByText(BOUND_OBJECTIVE_CAVEAT)).toBeTruthy();
    expect(card.textContent).not.toContain("No bound library entry for this run");
  });

  test.each([
    ["a different approval projection digest", { projectionDigest: "9".repeat(64) }],
    ["a different manifest digest", { manifestDigest: "9".repeat(64) }],
    ["a different method", { method: "GET" as const }],
    ["a different route", { routeTemplate: "/other" }],
    ["a different check", { catalogScenarioId: "plan_entitlement_read" }],
  ])("renders no bound entry for %s", (_label, overrides) => {
    render(<FindingsCard findings={FINDINGS} frozenBindings={[frozenRow(overrides)]} />);
    const card = screen.getByRole("region", { name: "Rehearsal result" });
    expect(within(card).getByText("No bound library entry for this run")).toBeTruthy();
    expect(card.textContent).not.toContain("Stands for");
    expect(card.textContent).not.toContain(BOUND_OBJECTIVE_CAVEAT);
  });

  test("without frozen bindings the card says the run stands for no library entry", () => {
    render(<FindingsCard findings={FINDINGS} />);
    expect(screen.getByText("No bound library entry for this run")).toBeTruthy();
  });
});
