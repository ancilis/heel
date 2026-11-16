// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useCallback, useEffect, useState } from "react";

import type {
  ConfiguredPlanRequestInput,
  ConfiguredPlanRequestView,
  PlanLabel,
  ScenarioLibrary,
  ScenarioLibraryEntry,
} from "../../lib/canary-api";
import { CanaryApiError } from "../../lib/canary-api";
import { selectionQuery } from "../../lib/account-context";
import { BackendChoice, ValueTypeChoice } from "./LocalValueChoices";
import type { LocalBackend, LocalValueType } from "../../lib/live-test-text";
import {
  COMPARISON_LABELS,
  STATE_WORDS,
  conditionText,
  readinessAdvice,
  requirementLabel,
  roleText,
  successCheckText,
} from "../../lib/live-test-text";

export interface ConfiguredTestsApi {
  listScenarioLibrary(workspaceRef: string, signal?: AbortSignal): Promise<Readonly<ScenarioLibrary>>;
  listConfiguredPlanRequests(workspaceRef: string, projectRef: string, signal?: AbortSignal): Promise<readonly ConfiguredPlanRequestView[]>;
  createConfiguredPlanRequest(workspaceRef: string, projectRef: string, bindingId: string, input: ConfiguredPlanRequestInput): Promise<ConfiguredPlanRequestView>;
  cancelConfiguredPlanRequest(workspaceRef: string, projectRef: string, planRequestId: string): Promise<ConfiguredPlanRequestView>;
}

export interface ConfiguredTestsPanelProps {
  api: ConfiguredTestsApi;
  workspaceRef: string;
  projectRef: string;
  /** The active paired-runner authorization for the verified target, if any. */
  bindingId: string | null;
  canManage: boolean;
  /** Bumped by the page after a library save or a replay request so the panel re-reads server state. */
  refreshTick?: number;
  /** Opens the approval dialog for a projected (signed dry-run) request. */
  onReviewApproval?: () => void;
  pollMs?: number;
}

const MAX_SELECTED = 4;
const LABEL = /^[A-Za-z0-9][A-Za-z0-9 .-]{0,31}$/;

function errorText(error: unknown): string {
  if (error instanceof CanaryApiError) return error.message;
  return "Heel Cloud is temporarily unavailable. Nothing was requested.";
}

function statusText(request: ConfiguredPlanRequestView): string {
  if (request.status === "open") {
    if (request.runnerSeenAtMs === null) {
      return "Waiting for your paired runner to pick this up. Keep heel runner serve running on the runner machine. "
        + "A runner older than this release cannot run configured tests and never picks this up; update it if this stays.";
    }
    const missing = request.readiness?.instances.some((entry) => entry.requirements.some((item) => item.state !== "ready"));
    return missing
      ? "Your runner checked the selected tests and needs the local setup below. Nothing has been sent to the target."
      : "Your runner has everything it needs and is preparing the signed dry run. Nothing has been sent to the target.";
  }
  if (request.status === "projected") return "The signed dry run is ready. Review every condition and approve it to run once.";
  if (request.status === "approved") return `Approved once as run ${request.runId}. The result appears after the runner finishes and you choose to share the redacted summary.`;
  if (request.status === "cancelled") return "Cancelled. Nothing was sent to the target.";
  return "Expired before it produced a plan. Nothing was sent to the target. Request it again.";
}

/**
 * Selects workspace-private configured tests, freezes them into one request for the paired runner, and shows only the
 * runner's bounded readiness for exactly those tests. Everything shown is re-read from the server, so a reload at any
 * step returns to the same request, readiness and frozen configuration.
 */
export function ConfiguredTestsPanel({
  api, workspaceRef, projectRef, bindingId, canManage, refreshTick = 0, onReviewApproval, pollMs = 4000,
}: ConfiguredTestsPanelProps) {
  const [library, setLibrary] = useState<Readonly<ScenarioLibrary> | null>(null);
  const [requests, setRequests] = useState<readonly ConfiguredPlanRequestView[] | null>(null);
  const [selected, setSelected] = useState<readonly string[]>([]);
  const [lowerLabel, setLowerLabel] = useState("");
  const [higherLabel, setHigherLabel] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [tick, setTick] = useState(0);
  const [backend, setBackend] = useState<LocalBackend>("keychain");
  const [valueTypes, setValueTypes] = useState<Readonly<Record<string, LocalValueType>>>({});

  const reload = useCallback(() => setTick((value) => value + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    Promise.all([api.listScenarioLibrary(workspaceRef, controller.signal), api.listConfiguredPlanRequests(workspaceRef, projectRef, controller.signal)])
      .then(([nextLibrary, nextRequests]) => {
        if (controller.signal.aborted) return;
        setLibrary(nextLibrary);
        setRequests(nextRequests);
      })
      .catch((error: unknown) => { if (!controller.signal.aborted) setNotice(errorText(error)); });
    return () => controller.abort();
  }, [api, workspaceRef, projectRef, refreshTick, tick]);

  const current = requests?.[0] ?? null;
  const live = current !== null && (current.status === "open" || current.status === "projected");
  useEffect(() => {
    if (!live) return;
    const timer = setInterval(reload, pollMs);
    return () => clearInterval(timer);
  }, [live, pollMs, reload]);

  const configured: readonly ScenarioLibraryEntry[] = library?.scenarios.filter((row) => row.source === "custom") ?? [];
  const chosen = configured.filter((row) => selected.includes(row.id) && row.liveTest !== null);
  const needsLabels = chosen.some((row) => row.liveTest?.scenarioId === "plan_entitlement_read");
  const labelsValid = !needsLabels || (LABEL.test(lowerLabel) && LABEL.test(higherLabel) && lowerLabel !== higherLabel);
  const blocked = current !== null && current.status === "open";
  const canRequest = canManage && !busy && bindingId !== null && chosen.length > 0 && chosen.length <= MAX_SELECTED && labelsValid && !blocked;

  const request = async () => {
    if (bindingId === null) return;
    setBusy(true); setNotice(null);
    try {
      const labels: PlanLabel[] = needsLabels
        ? [{ role: "higher_plan", plan_label: higherLabel }, { role: "lower_plan", plan_label: lowerLabel }] : [];
      await api.createConfiguredPlanRequest(workspaceRef, projectRef, bindingId, {
        planKind: "configured_live_read",
        tests: chosen.map((row) => ({ sourceScenarioId: row.id, sourceRevision: row.revision as number })),
        planLabels: labels,
      });
      setSelected([]);
      reload();
    } catch (error) { setNotice(errorText(error)); } finally { setBusy(false); }
  };

  const cancel = async (planRequestId: string) => {
    setBusy(true); setNotice(null);
    try { await api.cancelConfiguredPlanRequest(workspaceRef, projectRef, planRequestId); reload(); }
    catch (error) { setNotice(errorText(error)); } finally { setBusy(false); }
  };

  return (
    <section aria-labelledby="configured-tests-title" className="runner-recovery configured-tests-panel">
      <p className="canary-kicker">Configured live tests</p>
      <h2 id="configured-tests-title">Run your private tests on the paired runner</h2>
      <p>
        Choose up to four private tests. Your paired runner checks only what those tests need, then signs a dry run for you to
        review. Nothing reaches the target until you approve it, and expected values never leave the runner.
      </p>
      {notice ? <p role="alert">{notice}</p> : null}
      {bindingId === null ? <p>Authorize a paired runner for your verified target first; configured tests run only through it.</p> : null}
      {library === null || requests === null ? <p>Loading your private tests…</p> : <>
        {configured.length === 0 ? <p>No private tests yet. Create one in the scenario library on this page (Open scenario library, then Create a private live test).</p> : (
          <fieldset disabled={!canManage || busy || blocked}>
            <legend>Tests for the next dry run</legend>
            <ul aria-label="Private tests" className="scenario-library-list">
              {configured.map((row) => {
                const test = row.liveTest;
                const id = `configured-select-${row.id}`;
                return (
                  <li key={row.id}>
                    <label htmlFor={id}>
                      <input id={id} type="checkbox" disabled={test === null}
                        aria-describedby={`${id}-detail`}
                        checked={selected.includes(row.id)}
                        onChange={(event) => setSelected((items) => event.target.checked
                          ? [...items, row.id].slice(0, MAX_SELECTED) : items.filter((item) => item !== row.id))} />
                      <code>{row.id}</code> revision {row.revision}
                    </label>
                    <p id={`${id}-detail`}>{test === null
                      ? "Static only: this revision has no configured live test, so it cannot run."
                      : `${COMPARISON_LABELS[test.scenarioId]} · ${test.method} ${test.routeTemplate} · condition: ${conditionText(test.assertion)}`}</p>
                  </li>
                );
              })}
            </ul>
            {needsLabels ? (
              <div className="approval-fields">
                <p id="plan-label-note">Name the two plans as you know them. These labels are yours, frozen in the review, and never read from the target.</p>
                <label>Lower plan name<input aria-describedby="plan-label-note" aria-invalid={lowerLabel !== "" && !LABEL.test(lowerLabel)} onChange={(event) => setLowerLabel(event.target.value)} value={lowerLabel} /></label>
                <label>Higher plan name<input aria-describedby="plan-label-note" aria-invalid={higherLabel !== "" && !LABEL.test(higherLabel)} onChange={(event) => setHigherLabel(event.target.value)} value={higherLabel} /></label>
              </div>
            ) : null}
            <button className="button button-primary" disabled={!canRequest} onClick={() => void request()} type="button">
              Request a dry run from the paired runner
            </button>
            {blocked ? <p>A request is already waiting for this runner; cancel it to change the selection.</p> : null}
          </fieldset>
        )}

        {current !== null ? (
          <article aria-labelledby="configured-request-title" className="configured-request">
            <h3 id="configured-request-title">{current.planKind === "configured_regression" ? "Latest replay request" : "Latest dry-run request"}</h3>
            <p role="status">{statusText(current)}</p>
            {current.status === "open" && current.readiness?.instances.some((entry) => entry.requirements.some((item) => item.state !== "ready")) ? (
              <BackendChoice onChange={setBackend} value={backend} />
            ) : null}
            <ol aria-label="Frozen tests in this request">
              {current.instances.map((instance, index) => {
                const readiness = current.readiness?.instances[index];
                return (
                  <li key={instance.testInstanceId}>
                    <p><code>{instance.source.sourceScenarioId}</code> revision {instance.source.sourceRevision} · {COMPARISON_LABELS[instance.scenarioId]} · <code>{instance.method} {instance.routeTemplate}</code></p>
                    <p>Roles: {(instance.scenarioId === "plan_entitlement_read" ? ["lower_plan", "higher_plan"] : ["anonymous", "authenticated"]).map((role) => roleText(role, current.planLabels)).join(" → ")}</p>
                    <p>Success check: {successCheckText(instance.assertion)}</p>
                    <p>Condition: {conditionText(instance.assertion)}</p>
                    {readiness && current.status === "open" ? (
                      <ul aria-label={`Runner readiness for ${instance.source.sourceScenarioId}`}>
                        {readiness.requirements.map((item) => {
                          const advice = readinessAdvice(item, `${instance.method} ${instance.routeTemplate}`, current.planKind, {
                            backend, typeFor: (ref) => valueTypes[ref] ?? "text",
                            planLabelFor: (role) => current.planLabels.find((label) => label.role === role)?.plan_label ?? null,
                          });
                          const chooseType = item.kind === "local_input" && advice !== null && advice.commands.length > 0 && item.subject !== null;
                          return (
                            <li key={`${item.kind}:${item.subject ?? ""}`}>
                              {requirementLabel(item)}: <strong>{STATE_WORDS[item.state]}</strong>
                              {chooseType ? <ValueTypeChoice reference={item.subject as string} value={valueTypes[item.subject as string] ?? "text"}
                                onChange={(value) => setValueTypes((types) => ({ ...types, [item.subject as string]: value }))} /> : null}
                              {advice ? <>
                                <br /><span>{advice.text}</span>
                                {advice.commands.map((command) => <span key={command}><br /><code>{command}</code></span>)}
                                {advice.note ? <><br /><small>{advice.note}</small></> : null}
                              </> : null}
                            </li>
                          );
                        })}
                      </ul>
                    ) : null}
                  </li>
                );
              })}
            </ol>
            {current.status === "open" && canManage ? (
              <button className="button button-secondary" disabled={busy} onClick={() => void cancel(current.planRequestId)} type="button">Cancel this request</button>
            ) : null}
            {current.runId !== null && current.status === "approved" ? (
              <p>
                <a href={`/dashboard${selectionQuery({ workspaceRef, projectRef, runRef: current.runId })}`}>
                  Open run {current.runId}: status, sharing and result
                </a>
              </p>
            ) : null}
            {current.status === "projected" && onReviewApproval ? (
              <button className="button button-primary" onClick={onReviewApproval} type="button">Review and approve the dry run</button>
            ) : null}
          </article>
        ) : null}
      </>}
    </section>
  );
}
