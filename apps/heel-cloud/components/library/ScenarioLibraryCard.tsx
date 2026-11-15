// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useEffect, useRef, useState } from "react";

import type {
  CustomScenarioInput,
  LiveReadAssertion,
  ScenarioBindableCatalogId,
  ScenarioLibrary,
  ScenarioLibraryEntry,
} from "../../lib/canary-api";
import { CanaryApiError } from "../../lib/canary-api";
import { COMPARISON_LABELS, conditionText, successCheckText } from "../../lib/live-test-text";
import {
  LiveAssertionFields,
  emptyLiveAssertionDraft,
  hydrateLiveAssertion,
  validateLiveAssertionDraft,
  type LiveAssertionDraft,
  type LiveAssertionValidation,
} from "../onboarding/LiveAssertionFields";
import type {
  RetainedBrowserInput,
  ScenarioAssessmentEnvelopeV1,
  ScenarioAssessmentOutcome,
  ScenarioAssessmentSelection,
} from "../../lib/browser-review-client";
import type { ReviewAnswer } from "../../lib/review-presentation";


export interface ScenarioLibraryApi {
  listScenarioLibrary(workspaceRef: string, signal?: AbortSignal): Promise<Readonly<ScenarioLibrary>>;
  createCustomScenario(workspaceRef: string, input: CustomScenarioInput): Promise<Readonly<ScenarioLibraryEntry & { warnings: readonly string[] }>>;
}

export interface ScenarioAssessor {
  assessScenarios(
    source: string,
    answers: readonly ReviewAnswer[],
    selection: ScenarioAssessmentSelection,
  ): Promise<ScenarioAssessmentEnvelopeV1>;
}

export interface ScenarioLibraryCardProps {
  workspaceRef: string;
  api: ScenarioLibraryApi;
  canManage: boolean;
  /** Created only when the customer starts a browser-local assessment. */
  createAssessor: () => ScenarioAssessor;
  /** The ReviewWorkspace's retained local input, when one exists in this browser. */
  retainedInput?: RetainedBrowserInput | null;
  /** Called after a revision is saved, so other cards re-read server state. */
  onSaved?: () => void;
}

// The static fields a private copy may carry (server CUSTOM_EVALUATION_FIELDS); the library template supplies them.
const CUSTOM_FIELDS = new Set([
  "id", "category", "objective", "kind", "success_criterion", "severity_model", "recommended_control",
  "containment_limits", "applies_when", "pack", "probe_strategy", "investigation_signals", "exploitability_reduction",
]);
const TEMPLATE_FOR: Readonly<Record<ScenarioBindableCatalogId, string>> = Object.freeze({
  plan_entitlement_read: "sc.flag.tiergate",
  anonymous_authenticated_read: "sc.endpoint.hidden",
});
const SLUG = /^[a-z0-9][a-z0-9-]{1,60}$/;

/** A browser-side pre-check; the server's route validation stays authoritative. */
export function routeProblem(route: string): string | null {
  if (route === "") return "Enter the exact imported path, for example /billing/features.";
  if (!route.startsWith("/")) return "The path must begin with /.";
  if (route.includes("{") || route.includes("}")) {
    return "Parameterized routes are not supported for configured tests yet. Choose a literal imported route.";
  }
  if (route.includes("?") || route.includes("#") || route.includes("//") || /\s/.test(route)) {
    return "Enter only the path: no query, fragment, spaces or empty segments.";
  }
  if (new TextEncoder().encode(route).byteLength > 512) return "The path is too long.";
  return null;
}

type GuidedForm = {
  editId: string | null;
  slug: string;
  objective: string;
  comparison: ScenarioBindableCatalogId;
  method: "GET" | "HEAD";
  route: string;
  draft: LiveAssertionDraft;
  validation: LiveAssertionValidation;
  attempted: boolean;
};

function newGuidedForm(): GuidedForm {
  const draft = emptyLiveAssertionDraft();
  return {
    editId: null, slug: "", objective: "", comparison: "plan_entitlement_read", method: "GET", route: "",
    draft, validation: validateLiveAssertionDraft(draft), attempted: false,
  };
}

function guidedFromRow(row: ScenarioLibraryEntry): GuidedForm {
  const live = row.liveTest;
  const draft = (live ? hydrateLiveAssertion(live.assertion) : null) ?? emptyLiveAssertionDraft();
  return {
    editId: row.id, slug: row.id.replace(/^sc\.(?:internal|community)\./, ""), objective: row.objective,
    comparison: live?.scenarioId ?? "plan_entitlement_read", method: live?.method ?? "GET",
    route: live?.routeTemplate ?? "", draft, validation: validateLiveAssertionDraft(draft), attempted: false,
  };
}

export const OUTCOME_WORDS: Readonly<Record<ScenarioAssessmentOutcome, string>> = Object.freeze({
  inferred_finding: "Inferred finding",
  handoff: "Handed off to model red-team",
  investigation_prompt: "Investigation prompt",
  criterion_unknown: "Unknown",
  criterion_not_met: "Criterion not met (static)",
  no_matching_surface: "No matching surface",
});

const KIND_SUGGESTIONS: Readonly<Record<string, ScenarioBindableCatalogId>> = Object.freeze({
  endpoint: "anonymous_authenticated_read",
  admin_action: "anonymous_authenticated_read",
  flag: "plan_entitlement_read",
  plan: "plan_entitlement_read",
  meter: "plan_entitlement_read",
});
const BINDABLE: readonly ScenarioBindableCatalogId[] = ["anonymous_authenticated_read", "plan_entitlement_read"];
const MAX_SELECTED = 160;


function errorText(error: unknown): string {
  if (error instanceof CanaryApiError) {
    return error.details.length > 0 ? `${error.message} ${error.details.join("; ")}` : error.message;
  }
  if (error instanceof Error && "publicMessage" in error) return String((error as { publicMessage: unknown }).publicMessage);
  return "The scenario library is temporarily unavailable.";
}


/**
 * The workspace scenario library. Every row's applicability is unknown; a row never shows a run or assessment
 * outcome. Static assessment runs only in this browser over the customer's own OpenAPI document, with only the
 * scenarios the customer selected, and its result is never uploaded.
 */
export function ScenarioLibraryCard({ workspaceRef, api, canManage, createAssessor, retainedInput = null, onSaved }: ScenarioLibraryCardProps) {
  const [guided, setGuided] = useState<GuidedForm>(newGuidedForm);
  const [savedNote, setSavedNote] = useState<{ id: string; revision: number; refs: readonly string[] } | null>(null);
  const [library, setLibrary] = useState<Readonly<ScenarioLibrary> | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [draft, setDraft] = useState("");
  const [bindCatalog, setBindCatalog] = useState<ScenarioBindableCatalogId | "">("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [localSource, setLocalSource] = useState("");
  const [assessment, setAssessment] = useState<ScenarioAssessmentEnvelopeV1 | null>(null);
  const assessor = useRef<ScenarioAssessor | null>(null);
  const [reloadTick, setReloadTick] = useState(0);
  // Nothing is requested until the customer opens the library.
  const [opened, setOpened] = useState(false);

  useEffect(() => {
    if (!opened) return;
    const controller = new AbortController();
    api.listScenarioLibrary(workspaceRef, controller.signal)
      .then((next) => { if (!controller.signal.aborted) setLibrary(next); })
      .catch((error: unknown) => { if (!controller.signal.aborted) setNotice(errorText(error)); });
    return () => controller.abort();
  }, [api, workspaceRef, reloadTick, opened]);

  useEffect(() => () => {
    const current = assessor.current as (ScenarioAssessor & { dispose?: () => void }) | null;
    current?.dispose?.();
    assessor.current = null;
  }, []);

  let parsedDraft: Record<string, unknown> | null = null;
  try {
    const value: unknown = draft.trim() === "" ? null : JSON.parse(draft);
    parsedDraft = value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    parsedDraft = null;
  }
  const suggestion = parsedDraft !== null && typeof parsedDraft.kind === "string" ? KIND_SUGGESTIONS[parsedDraft.kind] : undefined;
  const coverage = bindCatalog === "" || library === null ? null : library.customCoverageStatements[bindCatalog];
  const existing = parsedDraft !== null && library !== null
    ? library.scenarios.find((row) => row.source === "custom" && row.id === parsedDraft?.id) ?? null
    : null;
  const canSave = canManage && !busy && parsedDraft !== null && (bindCatalog === "" || acknowledged);

  const saveCustom = async () => {
    if (parsedDraft === null || library === null) return;
    setBusy(true);
    setNotice(null);
    try {
      await api.createCustomScenario(workspaceRef, {
        definition: parsedDraft,
        supersedesRevision: existing?.revision ?? null,
        executionBinding: bindCatalog === "" || coverage === null ? null : { catalogScenarioId: bindCatalog, coverageAck: coverage },
      });
      setDraft("");
      setBindCatalog("");
      setAcknowledged(false);
      setAssessment(null);
      setReloadTick((value) => value + 1);
    } catch (error) {
      setNotice(errorText(error));
    } finally {
      setBusy(false);
    }
  };

  const editing = guided.editId === null || library === null ? null
    : library.scenarios.find((row) => row.source === "custom" && row.id === guided.editId) ?? null;
  const guidedId = guided.editId ?? `sc.internal.${guided.slug}`;
  const slugError = guided.editId !== null || SLUG.test(guided.slug) ? null
    : "Use 2-61 lowercase letters, digits or hyphens, starting with a letter or digit.";
  const objectiveError = guided.objective.trim() === "" ? "Describe what this test protects." : null;
  const routeError = routeProblem(guided.route);
  const guidedReady = canManage && !busy && library !== null && slugError === null && objectiveError === null
    && routeError === null && guided.validation.ok;
  const showGuidedErrors = guided.attempted;

  const saveGuided = async () => {
    setGuided((form) => ({ ...form, attempted: true }));
    if (!guidedReady || library === null || !guided.validation.ok) return;
    const template = library.scenarios.find((row) => row.id === TEMPLATE_FOR[guided.comparison]);
    const base: Record<string, unknown> = editing !== null
      ? { ...editing.definition }
      : Object.fromEntries(Object.entries(template?.definition ?? {}).filter(([key]) => CUSTOM_FIELDS.has(key)));
    if (editing === null && template === undefined) { setNotice("The library template is unavailable. Reload the library."); return; }
    const limits = (base.containment_limits ?? {}) as Record<string, unknown>;
    const definition = {
      ...base, id: guidedId, objective: guided.objective.trim(),
      containment_limits: { ...limits, no_live_targets: true },
    };
    setBusy(true);
    setNotice(null);
    try {
      const saved = await api.createCustomScenario(workspaceRef, {
        definition,
        supersedesRevision: editing?.revision ?? null,
        executionBinding: null,
        liveTest: {
          scenarioId: guided.comparison, method: guided.method, routeTemplate: guided.route,
          assertion: guided.validation.assertion as LiveReadAssertion,
        },
      });
      setSavedNote({ id: saved.id, revision: saved.revision ?? 1, refs: saved.liveTest?.localInputRefs ?? [] });
      setGuided(newGuidedForm());
      setReloadTick((value) => value + 1);
      onSaved?.();
    } catch (error) {
      setNotice(errorText(error));
    } finally {
      setBusy(false);
    }
  };

  const source = retainedInput?.source ?? localSource;
  const answers = retainedInput?.answers ?? [];
  const chosen = library === null ? [] : library.scenarios.filter((row) => selected.has(row.id));
  const canAssess = !busy && library !== null && source.trim() !== "" && chosen.length > 0 && chosen.length <= MAX_SELECTED;

  const assess = async () => {
    if (library === null) return;
    setBusy(true);
    setNotice(null);
    try {
      assessor.current ??= createAssessor();
      const result = await assessor.current.assessScenarios(source, answers, {
        library_digest: library.libraryDigest,
        scenarios: chosen.map((row) => ({
          scenario_id: row.id, source: row.source, revision: row.revision,
          definition_digest: row.definitionDigest, definition: row.definition,
        })),
      });
      setAssessment(result);
    } catch (error) {
      setAssessment(null);
      setNotice(errorText(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section aria-labelledby="scenario-library-title" className="runner-recovery scenario-library-card">
      <p className="canary-kicker">Scenario library</p>
      <h2 id="scenario-library-title">Library and custom scenarios</h2>
      <p>
        Applicability is unknown for every scenario until your product model says otherwise. Runner-supported entries
        name the one differential read check that can execute; everything else is analysis-only. Custom scenarios stay
        private to this workspace.
      </p>
      {!opened ? (
        <button className="button button-secondary" onClick={() => setOpened(true)} type="button">Open scenario library</button>
      ) : null}
      {notice ? <p role="alert">{notice}</p> : null}
      {!opened ? null : library === null ? <p>Loading the scenario library…</p> : <>
        <p>Library digest <code>{library.libraryDigest}</code> · engine {library.engineVersion}</p>
        <ul aria-label="Scenarios" className="scenario-library-list">
          {library.scenarios.map((row) => (
            <li key={row.id} data-testid={`scenario-row-${row.id}`}>
              <label>
                <input
                  checked={selected.has(row.id)}
                  disabled={busy}
                  onChange={(event) => setSelected((current) => {
                    const next = new Set(current);
                    if (event.target.checked) next.add(row.id);
                    else next.delete(row.id);
                    return next;
                  })}
                  type="checkbox"
                />
                <code>{row.id}</code>
              </label>
              <span>{row.source === "custom" ? `Custom revision ${row.revision}` : `Library · ${row.pack}`}</span>
              <p>{row.objective}</p>
              <dl>
                <div><dt>Applicability</dt><dd>{row.applicability}</dd></div>
                <div><dt>Evidence</dt><dd>{row.evidenceState === "customer_declared" ? "customer declared definition" : "inferred"}</dd></div>
                <div><dt>Execution</dt><dd>{row.executionSupport === "runner_supported"
                  ? `Runner-supported check: ${row.catalogScenarioId}`
                  : "Static analysis only"}</dd></div>
              </dl>
              {row.source === "custom" ? (row.liveTest !== null ? <>
                <p>Configured live test: {COMPARISON_LABELS[row.liveTest.scenarioId]} · <code>{row.liveTest.method} {row.liveTest.routeTemplate}</code></p>
                <p>Success check: {successCheckText(row.liveTest.assertion)}. Condition: {conditionText(row.liveTest.assertion)}.</p>
                <p>{row.liveTest.coverageStatement}</p>
              </> : <p>Static only: no configured live test on this revision.</p>) : null}
              {row.source === "custom" && canManage ? (
                <button className="text-button" disabled={busy} onClick={() => { setSavedNote(null); setGuided(guidedFromRow(row)); }} type="button">
                  Edit {row.id} (saves revision {(row.revision ?? 0) + 1})
                </button>
              ) : null}
              {row.coverageStatement ? <p>{row.coverageStatement}</p> : null}
              {row.prerequisites.length > 0 ? (
                <ul aria-label={`Prerequisites for ${row.id}`}>
                  {row.prerequisites.map((item) => <li key={item}><code>{item}</code></li>)}
                </ul>
              ) : null}
            </li>
          ))}
        </ul>

        <fieldset className="scenario-assessment">
          <legend>Assess statically in this browser</legend>
          <p>
            Uses only the selected scenarios against your own OpenAPI document. The document, answers and result stay
            in this browser; nothing is executed against your product and nothing is uploaded.
          </p>
          {retainedInput === null ? (
            <label>
              OpenAPI JSON (kept in this browser)
              <textarea onChange={(event) => setLocalSource(event.target.value)} rows={4} value={localSource} />
            </label>
          ) : <p>Using the OpenAPI document already reviewed in this browser.</p>}
          <button className="button button-secondary" disabled={!canAssess} onClick={() => void assess()} type="button">
            Assess statically in this browser
          </button>
          {assessment ? (
            <ol aria-label="Static assessment results">
              {assessment.results.map((result) => (
                <li key={result.scenario_id}>
                  <code>{result.scenario_id}</code>: {OUTCOME_WORDS[result.outcome]} · evidence {result.evidence_state}
                  {result.surface !== null && "method" in result.surface ? <> · <code>{result.surface.method} {result.surface.route}</code></> : null}
                  <p>{result.note}</p>
                </li>
              ))}
            </ol>
          ) : null}
        </fieldset>

        {canManage ? (
          <fieldset className="custom-scenario-intake guided-live-test" aria-describedby="guided-live-test-note">
            <legend>{editing ? `Edit private test ${editing.id}` : "Create a private live test"}</legend>
            <p id="guided-live-test-note">
              No JSON needed. A configured test reads one literal imported route once per role and checks one JSON field.
              Expected values are named here and entered only on your runner; they never reach the browser or Heel Cloud.
              {editing ? ` Saving creates revision ${(editing.revision ?? 0) + 1}; revision ${editing.revision} and every run that used it stay unchanged.` : ""}
            </p>
            {editing === null ? (
              <label>
                Test name
                <span id="guided-slug-hint">Saved as <code>sc.internal.{guided.slug || "your-name"}</code>.</span>
                <input aria-describedby={showGuidedErrors && slugError ? "guided-slug-hint guided-slug-error" : "guided-slug-hint"}
                  aria-invalid={showGuidedErrors && slugError !== null} disabled={busy} value={guided.slug}
                  onChange={(event) => setGuided((form) => ({ ...form, slug: event.target.value }))} />
                {showGuidedErrors && slugError ? <span className="error-message" id="guided-slug-error">{slugError}</span> : null}
              </label>
            ) : null}
            <label>
              What this test protects
              <textarea aria-describedby={showGuidedErrors && objectiveError ? "guided-objective-error" : undefined}
                aria-invalid={showGuidedErrors && objectiveError !== null} disabled={busy} rows={2} value={guided.objective}
                onChange={(event) => setGuided((form) => ({ ...form, objective: event.target.value }))} />
              {showGuidedErrors && objectiveError ? <span className="error-message" id="guided-objective-error">{objectiveError}</span> : null}
            </label>
            <label>
              Comparison
              <select disabled={busy} value={guided.comparison}
                onChange={(event) => setGuided((form) => ({ ...form, comparison: event.target.value as ScenarioBindableCatalogId }))}>
                {BINDABLE.map((id) => <option key={id} value={id}>{COMPARISON_LABELS[id]}</option>)}
              </select>
            </label>
            <div className="approval-fields">
              <label>
                Method
                <select disabled={busy} value={guided.method}
                  onChange={(event) => setGuided((form) => ({ ...form, method: event.target.value as "GET" | "HEAD" }))}>
                  <option value="GET">GET</option>
                  <option value="HEAD">HEAD (status only: always inconclusive for a field condition)</option>
                </select>
              </label>
              <label>
                Imported route
                <span id="guided-route-hint">The exact literal path from the OpenAPI document imported on your runner.</span>
                <input aria-describedby={guided.route !== "" && routeError ? "guided-route-hint guided-route-error" : "guided-route-hint"}
                  aria-invalid={(guided.route !== "" || showGuidedErrors) && routeError !== null} disabled={busy} value={guided.route}
                  onChange={(event) => setGuided((form) => ({ ...form, route: event.target.value }))} />
                {(guided.route !== "" || showGuidedErrors) && routeError ? <span className="error-message" id="guided-route-error">{routeError}</span> : null}
              </label>
            </div>
            <LiveAssertionFields draft={guided.draft} disabled={busy} showErrors={showGuidedErrors}
              onChange={(draft, validation) => setGuided((form) => ({ ...form, draft, validation }))} />
            <p>{library?.liveTestCoverageStatements[guided.comparison]}</p>
            <div className="run-actions">
              <button className="button button-primary" disabled={!canManage || busy} onClick={() => void saveGuided()} type="button">
                {editing ? "Save new revision" : "Save private test"}
              </button>
              {editing ? <button className="button button-secondary" disabled={busy} onClick={() => setGuided(newGuidedForm())} type="button">Cancel edit</button> : null}
            </div>
            {savedNote ? (
              <div role="status">
                <p>Saved <code>{savedNote.id}</code> revision {savedNote.revision}. Before requesting a dry run, enter each named value on the runner (hidden prompt):</p>
                <ul aria-label="Local values to enter on the runner">
                  {savedNote.refs.map((ref) => <li key={ref}><code>heel runner input add --name {ref} --type text --backend keychain</code></li>)}
                </ul>
              </div>
            ) : null}
          </fieldset>
        ) : null}

        {canManage ? (
          <details className="custom-scenario-intake">
          <summary>Advanced: paste a static scenario definition (JSON)</summary>
          <fieldset className="custom-scenario-intake">
            <legend>Save a private custom scenario</legend>
            <label>
              Scenario definition (JSON, validated by Heel; analysis-only unless bound below)
              <textarea onChange={(event) => setDraft(event.target.value)} rows={6} value={draft} />
            </label>
            {existing ? <p>Saving creates revision {(existing.revision ?? 0) + 1}; revision {existing.revision} stays unchanged.</p> : null}
            <label>
              Runner check binding
              <select onChange={(event) => { setBindCatalog(event.target.value as ScenarioBindableCatalogId | ""); setAcknowledged(false); }} value={bindCatalog}>
                <option value="">None (analysis-only)</option>
                {BINDABLE.map((id) => <option key={id} value={id}>{id}</option>)}
              </select>
            </label>
            {suggestion ? <p>Suggested from kind: {suggestion}. You choose; kind never binds a check.</p> : null}
            {coverage ? (
              <label>
                <input checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} type="checkbox" />
                {coverage}
              </label>
            ) : null}
            <button className="button button-primary" disabled={!canSave} onClick={() => void saveCustom()} type="button">
              Save custom revision
            </button>
          </fieldset>
          </details>
        ) : null}
      </>}
    </section>
  );
}
