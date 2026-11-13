// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";

import { OUTCOME_WORDS, ScenarioLibraryCard, type ScenarioAssessor, type ScenarioLibraryApi } from "../components/library/ScenarioLibraryCard";
import { CanaryApiError, type ScenarioLibrary, type ScenarioLibraryEntry } from "../lib/canary-api";
import { SCENARIO_ASSESSMENT_NOTES, type ScenarioAssessmentEnvelopeV1 } from "../lib/browser-review-client";


afterEach(cleanup);

const WORKSPACE = "ws_0123456789abcdef";
const DIGEST = "a".repeat(64);
const COVERAGE = {
  anonymous_authenticated_read: "Executed check: anonymous_authenticated_read (GET/HEAD, roles anonymous and authenticated). The custom objective and its criterion are not executed; they are analysis-only.",
  plan_entitlement_read: "Executed check: plan_entitlement_read (GET/HEAD, roles lower_plan and higher_plan). The custom objective and its criterion are not executed; they are analysis-only.",
};

function row(id: string, overrides: Partial<ScenarioLibraryEntry> = {}): ScenarioLibraryEntry {
  return {
    id, source: "library", revision: null, definitionDigest: DIGEST,
    definition: { id, kind: "endpoint", objective: `Objective ${id}`, success_criterion: { prop: "method", equals: "GET" } },
    objective: `Objective ${id}`, category: "unintended_endpoints", kind: "endpoint", pack: "core_saas",
    recommendedControl: "control", mechanismId: id, applicability: "unknown", applicabilityRule: "always",
    evidenceState: "inferred", executionSupport: "static_only", catalogScenarioId: null, bindingVersion: null,
    coverageStatement: null, prerequisites: [], ...overrides,
  };
}

const LIBRARY: ScenarioLibrary = {
  libraryDigest: "f".repeat(64), engineVersion: "1.3.0rc4", bindingVersion: 1, customCoverageStatements: COVERAGE,
  scenarios: [
    row("sc.endpoint.hidden", { executionSupport: "runner_supported", catalogScenarioId: "anonymous_authenticated_read",
      bindingVersion: 1, coverageStatement: "Executed check: anonymous_authenticated_read (GET/HEAD, roles anonymous and authenticated). The library objective beyond this check remains inferred; it is not executed.",
      prerequisites: ["methods: GET, HEAD", "heel runner map --scenario <catalog id>"] }),
    row("sc.sem.missing_rate_limit"),
    row("sc.internal.admin_read", { source: "custom", revision: 2, evidenceState: "customer_declared" }),
  ],
};

function api(overrides: Partial<ScenarioLibraryApi> = {}): ScenarioLibraryApi & { listScenarioLibrary: ReturnType<typeof vi.fn>; createCustomScenario: ReturnType<typeof vi.fn> } {
  return {
    listScenarioLibrary: vi.fn(async () => LIBRARY),
    createCustomScenario: vi.fn(async () => ({ ...LIBRARY.scenarios[2], warnings: [] })),
    ...overrides,
  } as never;
}

function envelope(ids: string[]): ScenarioAssessmentEnvelopeV1 {
  return {
    schema_version: "heel.scenario-assessment.v1", engine_version: "1.3.0rc4", source_hash: "1".repeat(64),
    model_hash: "2".repeat(64), answers_hash: "3".repeat(64), library_digest: LIBRARY.libraryDigest, selection_hash: "4".repeat(64),
    custom: [], model_coverage: { product_model_fields: "evaluated", entitlement_graph_edges: "not_evaluated", agent_surface: "unknown" },
    results: ids.map((id, index) => ({
      scenario_id: id, source: "library", revision: null, definition_digest: DIGEST, mechanism_id: id,
      outcome: index === 0 ? "inferred_finding" : "no_matching_surface",
      applicability: index === 0 ? "matched_surface" : "unknown", evidence_state: index === 0 ? "customer_declared" : "unknown",
      rule_source: "unknown", surface: index === 0 ? { method: "GET", route: "/admin/users" } : null,
      match_count: index === 0 ? 1 : 0, matches: [], recommended_control: "control",
      note: SCENARIO_ASSESSMENT_NOTES[index === 0 ? "inferred_finding" : "no_matching_surface"],
    })),
    privacy: { execution: "browser_local", network_calls: false, uploaded: false },
  };
}

const RUN_OUTCOME_WORDS = /\b(Held|Crossed|Unclear|blocked|observed|inconclusive)\b/;


describe("scenario library card", () => {
  test("lists every row as applicability unknown with capability and setup labels and no outcome words", async () => {
    const createAssessor = vi.fn();
    const quiet = api();
    render(<ScenarioLibraryCard api={quiet} canManage createAssessor={createAssessor} workspaceRef="ws_fedcba9876543210" />);
    expect(quiet.listScenarioLibrary).not.toHaveBeenCalled();  // nothing is requested before the customer opens it
    cleanup();
    render(<ScenarioLibraryCard api={api()} canManage createAssessor={createAssessor} workspaceRef={WORKSPACE} />);
    expect(screen.queryByRole("list", { name: "Scenarios" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Open scenario library" }));
    const list = await screen.findByRole("list", { name: "Scenarios" });
    const rows = within(list).getAllByRole("listitem").filter((item) => item.dataset.testid?.startsWith("scenario-row-"));
    expect(rows).toHaveLength(3);
    for (const item of rows) {
      expect(item.textContent).toContain("Applicabilityunknown");
      expect(item.textContent).not.toMatch(RUN_OUTCOME_WORDS);
      for (const word of Object.values(OUTCOME_WORDS)) expect(item.textContent).not.toContain(word);
    }
    const hidden = screen.getByTestId("scenario-row-sc.endpoint.hidden");
    expect(hidden.textContent).toContain("Runner-supported check: anonymous_authenticated_read");
    expect(hidden.textContent).toContain("The library objective beyond this check remains inferred");
    expect(within(hidden).getByRole("list", { name: "Prerequisites for sc.endpoint.hidden" }).textContent).toContain("heel runner map");
    expect(screen.getByTestId("scenario-row-sc.sem.missing_rate_limit").textContent).toContain("Static analysis only");
    expect(screen.getByTestId("scenario-row-sc.internal.admin_read").textContent).toContain("Custom revision 2");
    expect(createAssessor).not.toHaveBeenCalled();
  });

  test("custom intake shows the fixed coverage sentence and requires the explicit checkbox", async () => {
    const client = api();
    render(<ScenarioLibraryCard api={client} canManage createAssessor={vi.fn()} workspaceRef={WORKSPACE} />);
    fireEvent.click(screen.getByRole("button", { name: "Open scenario library" }));
    await screen.findByRole("list", { name: "Scenarios" });
    const definition = { id: "sc.internal.admin_read", kind: "endpoint", objective: "Admin stays private" };
    fireEvent.change(screen.getByLabelText(/Scenario definition/), { target: { value: JSON.stringify(definition) } });
    expect(screen.getByText(/Suggested from kind: anonymous_authenticated_read\. You choose; kind never binds a check\./)).toBeTruthy();
    expect(screen.getByText(/Saving creates revision 3; revision 2 stays unchanged\./)).toBeTruthy();
    const save = screen.getByRole("button", { name: "Save custom revision" }) as HTMLButtonElement;
    expect(save.disabled).toBe(false);  // analysis-only save needs no acknowledgement
    fireEvent.change(screen.getByLabelText("Runner check binding"), { target: { value: "anonymous_authenticated_read" } });
    const ack = screen.getByLabelText(COVERAGE.anonymous_authenticated_read) as HTMLInputElement;
    expect(save.disabled).toBe(true);
    fireEvent.click(ack);
    expect(save.disabled).toBe(false);
    fireEvent.click(save);
    await waitFor(() => expect(client.createCustomScenario).toHaveBeenCalledTimes(1));
    expect(client.createCustomScenario).toHaveBeenCalledWith(WORKSPACE, {
      definition, supersedesRevision: 2,
      executionBinding: { catalogScenarioId: "anonymous_authenticated_read", coverageAck: COVERAGE.anonymous_authenticated_read },
    });
  });

  test("shows validator messages for an invalid custom scenario", async () => {
    const client = api({ createCustomScenario: vi.fn(async () => { throw new CanaryApiError("invalid_scenario", 400, ["containment_limits: include a bounded sample cap"]); }) });
    render(<ScenarioLibraryCard api={client} canManage createAssessor={vi.fn()} workspaceRef={WORKSPACE} />);
    fireEvent.click(screen.getByRole("button", { name: "Open scenario library" }));
    await screen.findByRole("list", { name: "Scenarios" });
    fireEvent.change(screen.getByLabelText(/Scenario definition/), { target: { value: "{\"id\":\"sc.internal.bad\"}" } });
    fireEvent.click(screen.getByRole("button", { name: "Save custom revision" }));
    expect((await screen.findByRole("alert")).textContent).toContain("containment_limits: include a bounded sample cap");
  });

  test("assesses only the selected scenarios in this browser and renders outcomes from the envelope only", async () => {
    const client = api();
    const assessScenarios = vi.fn(async (_source: string, _answers: unknown, selection: { scenarios: readonly { scenario_id: string }[] }) =>
      envelope(selection.scenarios.map((item) => item.scenario_id)));
    const assessor: ScenarioAssessor = { assessScenarios };
    const createAssessor = vi.fn(() => assessor);
    render(<ScenarioLibraryCard api={client} canManage={false} createAssessor={createAssessor} workspaceRef={WORKSPACE}
      retainedInput={{ source: "{\"openapi\":\"3.1.0\"}", answers: [{ surface: "listitems", field: "tenant_filter", value: "unknown" }] }} />);
    fireEvent.click(screen.getByRole("button", { name: "Open scenario library" }));
    await screen.findByRole("list", { name: "Scenarios" });
    expect(screen.queryByLabelText(/Scenario definition/)).toBeNull();  // viewers cannot author
    const assess = screen.getByRole("button", { name: "Assess statically in this browser" }) as HTMLButtonElement;
    expect(assess.disabled).toBe(true);
    fireEvent.click(within(screen.getByTestId("scenario-row-sc.internal.admin_read")).getByRole("checkbox"));
    fireEvent.click(within(screen.getByTestId("scenario-row-sc.sem.missing_rate_limit")).getByRole("checkbox"));
    fireEvent.click(assess);
    const results = await screen.findByRole("list", { name: "Static assessment results" });
    expect(createAssessor).toHaveBeenCalledTimes(1);
    const [source, answers, selection] = assessScenarios.mock.calls[0];
    expect(source).toBe("{\"openapi\":\"3.1.0\"}");
    expect(answers).toEqual([{ surface: "listitems", field: "tenant_filter", value: "unknown" }]);
    expect(selection).toEqual({
      library_digest: LIBRARY.libraryDigest,
      scenarios: [
        { scenario_id: "sc.sem.missing_rate_limit", source: "library", revision: null, definition_digest: DIGEST, definition: LIBRARY.scenarios[1].definition },
        { scenario_id: "sc.internal.admin_read", source: "custom", revision: 2, definition_digest: DIGEST, definition: LIBRARY.scenarios[2].definition },
      ],
    });
    expect(results.textContent).toContain("sc.sem.missing_rate_limit: Inferred finding · evidence customer_declared");
    expect(results.textContent).toContain("no matching surface in the supplied model; not evidence of absence");
    expect(results.textContent).not.toContain("sc.endpoint.hidden");
    // Library rows themselves still carry no outcome after an assessment.
    expect(screen.getByTestId("scenario-row-sc.sem.missing_rate_limit").textContent).not.toContain("Inferred finding");
    expect(client.listScenarioLibrary).toHaveBeenCalledTimes(1);
    expect(client.createCustomScenario).not.toHaveBeenCalled();
  });
});
