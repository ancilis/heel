// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";

import { ApprovalDialog } from "../components/canary/ApprovalDialog";
import { ConfiguredTestsPanel, type ConfiguredTestsApi } from "../components/canary/ConfiguredTestsPanel";
import { FindingsCard, INCONCLUSIVE_NOTE } from "../components/canary/FindingsCard";
import { ScenarioLibraryCard, routeProblem, type ScenarioLibraryApi } from "../components/library/ScenarioLibraryCard";
import {
  configuredConditionReview,
  type CanaryConfiguredFindingsProjection,
  type ConfiguredApprovalView,
  type ConfiguredPlanRequestView,
  type LiveReadAssertion,
  type ScenarioLibrary,
  type ScenarioLibraryEntry,
} from "../lib/canary-api";

afterEach(cleanup);

const WS = "ws_0123456789abcdef";
const PRJ = "prj_" + "1".repeat(32);
const ASSERTION: LiveReadAssertion = {
  schema_version: "heel.live-read-assertion.v1",
  success_witness: { path: ["meta", "state"], expected_fixture: "export_ok" },
  condition: { kind: "json_scalar_equals_fixture", path: ["export", "rows", 0, "ssn_hint"], expected_fixture: "secret_hint" },
};
const COVERAGE = {
  anonymous_authenticated_read: "Configured live read: anonymous.",
  plan_entitlement_read: "Configured live read: plans.",
};

function entry(id: string, overrides: Partial<ScenarioLibraryEntry> = {}): ScenarioLibraryEntry {
  return {
    id, source: "library", revision: null, definitionDigest: "a".repeat(64),
    definition: { id, kind: "plan", objective: `Objective ${id}`, category: "license_entitlement", recommended_control: "c",
      success_criterion: { prop: "gated_by", equals: "client" }, investigation_signals: { prop: "x", in: ["y"] },
      severity_model: { likelihood: 0.5, impact: 0.5 }, containment_limits: { sample: "canary_only" }, source: "builtin" },
    objective: `Objective ${id}`, category: "license_entitlement", kind: "plan", pack: "core_saas", recommendedControl: "c",
    mechanismId: id, applicability: "unknown", applicabilityRule: "always", evidenceState: "inferred",
    executionSupport: "static_only", catalogScenarioId: null, bindingVersion: null, coverageStatement: null,
    prerequisites: [], liveTest: null, liveSupport: "template_only", ...overrides,
  };
}

const CUSTOM = entry("sc.internal.export-hint", {
  source: "custom", revision: 1, evidenceState: "customer_declared", liveSupport: "configured_live_read",
  definition: { id: "sc.internal.export-hint", objective: "Free plan must not read the hint", kind: "plan", category: "license_entitlement",
    recommended_control: "c", containment_limits: { no_live_targets: true } },
  objective: "Free plan must not read the hint",
  liveTest: { scenarioId: "plan_entitlement_read", method: "GET", routeTemplate: "/billing/features", assertion: ASSERTION,
    assertionDigest: "sha256:" + "b".repeat(64), localInputRefs: ["export_ok", "secret_hint"], roles: ["lower_plan", "higher_plan"],
    coverageStatement: "Configured live read: plans.", setupSteps: [] },
});
const STATIC = entry("sc.internal.static-only", { source: "custom", revision: 3, evidenceState: "customer_declared", liveSupport: "static_only" });
const LIBRARY: ScenarioLibrary = {
  libraryDigest: "f".repeat(64), engineVersion: "1", bindingVersion: 1, customCoverageStatements: COVERAGE,
  liveTestCoverageStatements: COVERAGE, scenarios: [entry("sc.flag.tiergate"), entry("sc.endpoint.hidden"), CUSTOM, STATIC],
};

describe("guided private live test authoring", () => {
  test("route pre-checks are explicit and parameterized routes get their own unsupported reason", () => {
    expect(routeProblem("/billing/features")).toBeNull();
    expect(routeProblem("/items/{item_id}")).toMatch(/Parameterized routes are not supported/);
    expect(routeProblem("billing")).toMatch(/must begin with \//);
    expect(routeProblem("/a?b=1")).toMatch(/no query/);
  });

  test("a copy of the library template never carries investigation_signals and is analysis-only static", async () => {
    const created: unknown[] = [];
    const api: ScenarioLibraryApi = {
      listScenarioLibrary: vi.fn(async () => LIBRARY),
      createCustomScenario: vi.fn(async (_ws, input) => { created.push(input); return { ...CUSTOM, warnings: [] }; }),
    };
    render(<ScenarioLibraryCard api={api} canManage createAssessor={vi.fn()} workspaceRef={WS} />);
    fireEvent.click(screen.getByRole("button", { name: "Open scenario library" }));
    const form = await screen.findByRole("group", { name: "Create a private live test" });
    fireEvent.click(within(form).getByRole("button", { name: "Save private test" }));
    expect(api.createCustomScenario).not.toHaveBeenCalled();
    expect(within(form).getByLabelText(/^Imported route/).getAttribute("aria-invalid")).toBe("true");
    fireEvent.change(within(form).getByLabelText(/^Test name/), { target: { value: "copy-check" } });
    fireEvent.change(within(form).getByLabelText(/^What this test protects/), { target: { value: "Free plan must not read it" } });
    fireEvent.change(within(form).getByLabelText(/^Imported route/), { target: { value: "/billing/features" } });
    const success = within(form).getByRole("group", { name: "Successful response check" });
    fireEvent.change(within(success).getByLabelText("Segment 1 object key"), { target: { value: "meta" } });
    fireEvent.change(within(success).getByLabelText("Expected value reference"), { target: { value: "export_ok" } });
    const condition = within(form).getByRole("group", { name: "Condition to test" });
    fireEvent.change(within(condition).getByLabelText("Segment 1 object key"), { target: { value: "audit_log" } });
    fireEvent.click(within(form).getByRole("button", { name: "Save private test" }));
    await waitFor(() => expect(api.createCustomScenario).toHaveBeenCalledTimes(1));
    const input = created[0] as { definition: Record<string, unknown>; liveTest: { routeTemplate: string; assertion: LiveReadAssertion } };
    expect(input.definition.id).toBe("sc.internal.copy-check");
    expect("investigation_signals" in input.definition).toBe(false);
    expect("source" in input.definition).toBe(false);
    expect((input.definition.containment_limits as Record<string, unknown>).no_live_targets).toBe(true);
    expect(input.liveTest.routeTemplate).toBe("/billing/features");
    expect(input.liveTest.assertion.condition).toEqual({ kind: "json_field_present", path: ["audit_log"] });
    expect(await screen.findByText("./heel-rc6/bin/heel runner input add --name export_ok --type text --backend keychain")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Value type for export_ok"), { target: { value: "number" } });
    fireEvent.change(screen.getByLabelText("Runner machine secret store"), { target: { value: "secret-service" } });
    expect(screen.getByText("./heel-rc6/bin/heel runner input add --name export_ok --type number --backend secret-service")).toBeTruthy();
    expect(screen.queryByLabelText(/expected value$/i)).toBeNull();
  });

  test("editing a configured revision supersedes it and says the old revision stays unchanged", async () => {
    const api: ScenarioLibraryApi = { listScenarioLibrary: vi.fn(async () => LIBRARY), createCustomScenario: vi.fn() };
    render(<ScenarioLibraryCard api={api} canManage createAssessor={vi.fn()} workspaceRef={WS} />);
    fireEvent.click(screen.getByRole("button", { name: "Open scenario library" }));
    fireEvent.click(await screen.findByRole("button", { name: /Edit sc\.internal\.export-hint/ }));
    expect(screen.getByText(/Saving creates revision 2; revision 1 and every run that used it stay unchanged/)).toBeTruthy();
    expect((screen.getByLabelText(/^Imported route/) as HTMLInputElement).value).toBe("/billing/features");
  });

  test("a configured custom revision names its live execution mode; static rows keep the static label", async () => {
    const api: ScenarioLibraryApi = { listScenarioLibrary: vi.fn(async () => LIBRARY), createCustomScenario: vi.fn() };
    render(<ScenarioLibraryCard api={api} canManage createAssessor={vi.fn()} workspaceRef={WS} />);
    fireEvent.click(screen.getByRole("button", { name: "Open scenario library" }));
    const configured = await screen.findByTestId("scenario-row-sc.internal.export-hint");
    expect(configured.textContent).toContain("ExecutionConfigured live test on your paired runner: Lower plan vs higher plan read");
    expect(configured.textContent).not.toContain("Static analysis only");
    expect(screen.getByTestId("scenario-row-sc.internal.static-only").textContent).toContain("ExecutionStatic analysis only");
    expect(screen.getByTestId("scenario-row-sc.flag.tiergate").textContent).toContain("ExecutionStatic analysis only");
  });
});

function view(overrides: Partial<ConfiguredPlanRequestView> = {}): ConfiguredPlanRequestView {
  return {
    planRequestId: "cpr_" + "c".repeat(32), bindingId: "rcb_" + "d".repeat(32), planKind: "configured_live_read", status: "open",
    instances: [{ testInstanceId: "lti_" + "e".repeat(32), scenarioId: "plan_entitlement_read",
      source: { sourceScenarioId: "sc.internal.export-hint", sourceRevision: 1 }, method: "GET", routeTemplate: "/billing/features",
      assertion: ASSERTION, assertionDigest: "sha256:" + "b".repeat(64), localInputRefs: ["export_ok", "secret_hint"] }],
    planLabels: [{ role: "higher_plan", plan_label: "Pro" }, { role: "lower_plan", plan_label: "Free" }],
    sourceRunId: null, createdAtMs: 1, expiresAtMs: 2, runnerSeenAtMs: null, readiness: null, approvalId: null, runId: null,
    projectionDigest: null, ...overrides,
  };
}

function panelApi(requests: ConfiguredPlanRequestView[]): ConfiguredTestsApi & { created: unknown[] } {
  const created: unknown[] = [];
  return {
    created,
    listScenarioLibrary: vi.fn(async () => LIBRARY),
    listConfiguredPlanRequests: vi.fn(async () => requests),
    createConfiguredPlanRequest: vi.fn(async (_w, _p, _b, input) => { created.push(input); return view(); }),
    cancelConfiguredPlanRequest: vi.fn(async () => view({ status: "cancelled" })),
  };
}

describe("configured tests panel", () => {
  test("static-only revisions cannot be selected; plan labels are operator-supplied and required", async () => {
    const api = panelApi([]);
    render(<ConfiguredTestsPanel api={api} bindingId={"rcb_" + "d".repeat(32)} canManage projectRef={PRJ} workspaceRef={WS} />);
    const staticBox = await screen.findByLabelText(/sc\.internal\.static-only revision 3/);
    expect((staticBox as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByText(/Static only: this revision has no configured live test/)).toBeTruthy();
    fireEvent.click(screen.getByLabelText(/sc\.internal\.export-hint revision 1/));
    const request = screen.getByRole("button", { name: "Request a dry run from the paired runner" }) as HTMLButtonElement;
    expect(request.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Lower plan name"), { target: { value: "Free" } });
    fireEvent.change(screen.getByLabelText("Higher plan name"), { target: { value: "Pro" } });
    expect(request.disabled).toBe(false);
    fireEvent.click(request);
    await waitFor(() => expect(api.created).toHaveLength(1));
    expect(api.created[0]).toEqual({ planKind: "configured_live_read",
      tests: [{ sourceScenarioId: "sc.internal.export-hint", sourceRevision: 1 }],
      planLabels: [{ role: "higher_plan", plan_label: "Pro" }, { role: "lower_plan", plan_label: "Free" }] });
  });

  test("readiness shows only the selected test's requirements with the next local command; old runners are explained", async () => {
    const waiting = panelApi([view()]);
    const { unmount } = render(<ConfiguredTestsPanel api={waiting} bindingId={"rcb_" + "d".repeat(32)} canManage projectRef={PRJ} workspaceRef={WS} />);
    expect(await screen.findByText(/A runner older than this release cannot run configured tests/)).toBeTruthy();
    unmount();
    const ready = panelApi([view({ runnerSeenAtMs: 5, readiness: { reportedAtMs: 5, instances: [{ testInstanceId: "lti_" + "e".repeat(32), requirements: [
      { kind: "local_input", subject: "export_ok", state: "ready" },
      { kind: "local_input", subject: "secret_hint", state: "missing" },
      { kind: "role_credential", subject: "lower_plan", state: "ready" },
      { kind: "route", subject: null, state: "ready" },
    ] }] } })]);
    render(<ConfiguredTestsPanel api={ready} bindingId={"rcb_" + "d".repeat(32)} canManage projectRef={PRJ} workspaceRef={WS} />);
    const list = await screen.findByRole("list", { name: /Runner readiness for sc\.internal\.export-hint/ });
    expect(within(list).getAllByRole("listitem")).toHaveLength(4);
    expect(within(list).getByText("./heel-rc6/bin/heel runner input add --name secret_hint --type text --backend keychain")).toBeTruthy();
    fireEvent.change(within(list).getByLabelText("Value type for secret_hint"), { target: { value: "boolean" } });
    fireEvent.change(screen.getByLabelText("Runner machine secret store"), { target: { value: "secret-service" } });
    expect(within(list).getByText("./heel-rc6/bin/heel runner input add --name secret_hint --type boolean --backend secret-service")).toBeTruthy();
    expect(within(list).getByText(/equality is strict, so text "42" never equals the number 42/)).toBeTruthy();
    expect(within(list).queryByText(/--name export_ok/)).toBeNull();
  });

  test("an approved request links back to its run so a reload can always reach status, sharing and result", async () => {
    const api = panelApi([view({ status: "approved", runId: "crun_" + "9".repeat(32), approvalId: "projection_x", projectionDigest: "f".repeat(64) })]);
    render(<ConfiguredTestsPanel api={api} bindingId={"rcb_" + "d".repeat(32)} canManage projectRef={PRJ} workspaceRef={WS} />);
    const link = await screen.findByRole("link", { name: /Open run crun_9+: status, sharing and result/ });
    expect(link.getAttribute("href")).toBe(`/dashboard?workspace=${WS}&project=${PRJ}&run=crun_${"9".repeat(32)}`);
  });
});

const CONFIGURED: ConfiguredApprovalView = {
  planRequestId: "cpr_" + "c".repeat(32), planKind: "configured_live_read", reviewSchema: "heel.configured-condition-review.v1",
  planLabels: [{ role: "higher_plan", plan_label: "Pro" }, { role: "lower_plan", plan_label: "Free" }],
  instances: [{ ...view().instances[0], roles: ["lower_plan", "higher_plan"], requestCount: 2 }],
};

describe("configured approval review", () => {
  test("approval needs an explicit review of the displayed conditions, and the review restates them exactly", () => {
    const onApprove = vi.fn();
    render(<ApprovalDialog configured={CONFIGURED} durationSeconds={30} egress="staging.example.com:443" onApprove={onApprove}
      onClose={vi.fn()} open origin="https://staging.example.com" requestBudget={20} routes={["GET /billing/features"]} scenarios={["plan_entitlement_read"]} />);
    expect(screen.getByText(/"export" › "rows" › \[0\] › "ssn_hint" equals your local value “secret_hint”/)).toBeTruthy();
    expect(screen.getByText(/lower plan \(“Free”, operator-supplied\) → higher plan \(“Pro”, operator-supplied\)/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText(/Retype exact hostname/), { target: { value: "staging.example.com" } });
    fireEvent.change(screen.getByLabelText(/Reason for this rehearsal/), { target: { value: "reviewed run" } });
    const approve = screen.getByRole("button", { name: "Approve and run" }) as HTMLButtonElement;
    expect(approve.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/I reviewed every route, role pair and condition above/));
    expect(approve.disabled).toBe(false);
    const review = configuredConditionReview(CONFIGURED, 20);
    expect(review).toEqual({
      schema_version: "heel.configured-condition-review.v1", plan_labels: CONFIGURED.planLabels, maximum_requests: 20,
      instances: [{ test_instance_id: "lti_" + "e".repeat(32), source: { source_scenario_id: "sc.internal.export-hint", source_revision: 1 },
        scenario_id: "plan_entitlement_read", method: "GET", route_template: "/billing/features", roles: ["lower_plan", "higher_plan"],
        request_count: 2, assertion: ASSERTION, local_input_refs: ["export_ok", "secret_hint"] }],
    });
  });
});

function result(outcome: "observed" | "blocked" | "inconclusive", reason: string) {
  return {
    ordinal: 0, test_instance_id: "lti_" + "e".repeat(32), scenario_id: "plan_entitlement_read", adapter_version: "1",
    source: { source_scenario_id: "sc.internal.export-hint", source_revision: 1 }, assertion_digest: "sha256:" + "b".repeat(64),
    condition_kind: "json_scalar_equals_fixture" as const, route: { method: "GET" as const, route_template: "/billing/features" },
    assessment_outcome: outcome, reason, positive_control: reason.startsWith("restricted_") ? "established" as const : "not_established" as const,
    restricted_condition: outcome === "observed" ? "true" as const : outcome === "blocked" ? "false" as const : "not_observed" as const,
    observations: [], finding: outcome === "observed" ? { title: "Configured live condition held for the restricted role", reachability_rationale: "r",
      confidence: "medium" as const, recommended_control: "Enforce it", regression_suggestion: "Replay" } : null,
    containment_codes: ["action_rejected"], redaction_count: 0, local_evidence_refs: ["ev1_" + "0".repeat(64)],
  };
}

function findings(results: ReturnType<typeof result>[]): CanaryConfiguredFindingsProjection {
  return {
    schema_version: "heel.canary-findings-projection.v2", projection_id: "p", run_id: "crun_" + "9".repeat(32), grant_id: "g",
    workspace_id: WS, project_id: PRJ, environment_id: "env_" + "1".repeat(32), manifest_digest: "1".repeat(64),
    approval_projection_digest: "2".repeat(64), grant_digest: "3".repeat(64), engine_version: "2", adapter_versions: ["1"],
    started_at_ms: 1, finished_at_ms: 2, assessment_outcome: results[0].assessment_outcome, test_results: results,
    containment_codes: [], redaction_count: 0, projection_digest: "4".repeat(64), signing_key_id: "k", signature_b64: "s",
  };
}

describe("configured results", () => {
  test("inconclusive says it is neither pass nor failure, explains the reason and containment, and offers no replay", () => {
    const onReplay = vi.fn();
    render(<FindingsCard findings={findings([result("inconclusive", "positive_control_condition_false")])} onReplay={onReplay} />);
    expect(screen.getByText(INCONCLUSIVE_NOTE)).toBeTruthy();
    expect(screen.getByText(/could not establish a baseline/)).toBeTruthy();
    expect(screen.getByText(/refused at least one request before sending it/)).toBeTruthy();
    expect(screen.getByText(/does not test the whole scenario objective/)).toBeTruthy();
    expect(screen.getByText(/heel runner findings --run crun_9+/)).toBeTruthy();
    expect(screen.getByText(/verified, signed redacted summary and these evidence references; it does not print response bodies/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /replay/ })).toBeNull();
  });

  test("an observed instance can be replayed by its exact frozen instance id", () => {
    const onReplay = vi.fn();
    render(<FindingsCard findings={findings([result("observed", "restricted_condition_true")])} onReplay={onReplay} />);
    fireEvent.click(screen.getByRole("button", { name: "Save and replay this exact test" }));
    expect(onReplay).toHaveBeenCalledWith("lti_" + "e".repeat(32));
  });
});

describe("configured results show the frozen condition of exactly that run", () => {
  const PLAN_EQUALS: LiveReadAssertion = { ...ASSERTION, condition: { kind: "json_scalar_equals_fixture", path: ["export", "plan"], expected_fixture: "pro_plan" } };
  const second = { ...result("blocked", "restricted_condition_false"), ordinal: 1, test_instance_id: "lti_" + "f".repeat(32),
    source: { source_scenario_id: "sc.internal.export-plan", source_revision: 1 }, assertion_digest: "sha256:" + "c".repeat(64) };
  const frozenPlan = view({
    status: "approved", runId: "crun_" + "9".repeat(32), approvalId: "p", projectionDigest: "2".repeat(64),
    instances: [view().instances[0], { ...view().instances[0], testInstanceId: "lti_" + "f".repeat(32),
      source: { sourceScenarioId: "sc.internal.export-plan", sourceRevision: 1 }, assertion: PLAN_EQUALS,
      assertionDigest: "sha256:" + "c".repeat(64), localInputRefs: ["export_ok", "pro_plan"] }],
  });

  test("two conditions on one route stay distinguishable, with reference names only", () => {
    render(<FindingsCard findings={findings([result("observed", "restricted_condition_true"), second])} frozenPlan={frozenPlan} />);
    const items = screen.getAllByRole("listitem").filter((item) => item.querySelector("h3"));
    expect(within(items[0]).getByText(/"export" › "rows" › \[0\] › "ssn_hint" equals your local value “secret_hint”/)).toBeTruthy();
    expect(within(items[1]).getByText(/"export" › "plan" equals your local value “pro_plan”/)).toBeTruthy();
    expect(within(items[1]).getByText("export_ok, pro_plan")).toBeTruthy();
  });

  test("a different run, signed plan or assertion digest is shown as unavailable, never substituted", () => {
    const edited = view({ ...frozenPlan, instances: [{ ...frozenPlan.instances[0], assertionDigest: "sha256:" + "d".repeat(64),
      assertion: PLAN_EQUALS }] });
    render(<FindingsCard findings={findings([result("observed", "restricted_condition_true")])} frozenPlan={edited} />);
    expect(screen.getByText(/The exact frozen condition for this result is unavailable/)).toBeTruthy();
    expect(screen.queryByText(/"export" › "plan"/)).toBeNull();
    cleanup();
    render(<FindingsCard findings={findings([result("observed", "restricted_condition_true")])} frozenPlan="unavailable" />);
    expect(screen.getByText(/The current library is not substituted/)).toBeTruthy();
    cleanup();
    render(<FindingsCard findings={findings([result("observed", "restricted_condition_true")])}
      frozenPlan={view({ ...frozenPlan, projectionDigest: "9".repeat(64) })} />);
    expect(screen.getByText(/The exact frozen condition for this result is unavailable/)).toBeTruthy();
  });
});

describe("setup and replay advice", () => {
  test("every generated command is one runnable shell command with concrete arguments", async () => {
    const { spawnSync } = await import("node:child_process");
    const { IMPORT_COMMAND, credentialCommand, inputCommand, readinessAdvice } = await import("../lib/live-test-text");
    const commands = [IMPORT_COMMAND];
    for (const backend of ["keychain", "secret-service"] as const) {
      for (const type of ["text", "number", "boolean", "null"] as const) commands.push(inputCommand("secret_hint", type, backend));
      commands.push(credentialCommand("lower_plan", "Free tier", backend), credentialCommand("authenticated", null, backend));
    }
    for (const command of commands) {
      expect(command.startsWith("./heel-rc6/bin/heel runner ")).toBe(true);
      expect(command).not.toMatch(/[<>|]/);
      expect(spawnSync("bash", ["-n", "-c", command]).status).toBe(0);
    }
    expect(credentialCommand("lower_plan", "Free tier", "keychain")).toBe(
      './heel-rc6/bin/heel runner credential add --role lower_plan --label "lower plan" --plan-label "Free tier" --profile bearer --backend keychain');
    const credential = readinessAdvice({ kind: "role_credential", subject: "higher_plan", state: "missing" }, "GET /x", "configured_live_read",
      { backend: "secret-service", typeFor: () => "text", planLabelFor: () => "Pro" });
    expect(credential?.commands).toEqual(["./heel-rc6/bin/heel runner credential add --role higher_plan --label \"higher plan\" --plan-label Pro --profile bearer --backend secret-service"]);
    expect(() => inputCommand("bad name;rm", "text", "keychain")).toThrow();
  });

  test("a replay never advises re-adding a value under the same name; a fresh request still does", async () => {
    const { readinessAdvice } = await import("../lib/live-test-text");
    for (const state of ["revoked", "missing"] as const) {
      const replay = readinessAdvice({ kind: "local_input", subject: "secret_hint", state }, "GET /x", "configured_regression");
      expect(replay?.commands).toEqual([]);
      expect(replay?.text).toMatch(/cannot repair this replay\. Cancel this request, then request a new dry run/);
    }
    const fresh = readinessAdvice({ kind: "local_input", subject: "secret_hint", state: "revoked" }, "GET /x", "configured_live_read");
    expect(fresh?.commands[0]).toContain("runner input add --name secret_hint");
  });

  test("the replay panel shows the replay-specific advice for a revoked original value", async () => {
    const api = panelApi([view({ planKind: "configured_regression", sourceRunId: "crun_" + "9".repeat(32), runnerSeenAtMs: 5,
      readiness: { reportedAtMs: 5, instances: [{ testInstanceId: "lti_" + "e".repeat(32), requirements: [
        { kind: "frozen_run", subject: null, state: "ready" }, { kind: "local_input", subject: "secret_hint", state: "revoked" },
      ] }] } })]);
    render(<ConfiguredTestsPanel api={api} bindingId={"rcb_" + "d".repeat(32)} canManage projectRef={PRJ} workspaceRef={WS} />);
    const list = await screen.findByRole("list", { name: /Runner readiness/ });
    expect(within(list).getByText(/cannot repair this replay/)).toBeTruthy();
    expect(within(list).queryByText(/runner input add/)).toBeNull();
  });
});
