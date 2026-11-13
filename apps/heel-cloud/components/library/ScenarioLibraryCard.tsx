// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useEffect, useRef, useState } from "react";

import type {
  CustomScenarioInput,
  ScenarioBindableCatalogId,
  ScenarioLibrary,
  ScenarioLibraryEntry,
} from "../../lib/canary-api";
import { CanaryApiError } from "../../lib/canary-api";
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
export function ScenarioLibraryCard({ workspaceRef, api, canManage, createAssessor, retainedInput = null }: ScenarioLibraryCardProps) {
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
        ) : null}
      </>}
    </section>
  );
}
