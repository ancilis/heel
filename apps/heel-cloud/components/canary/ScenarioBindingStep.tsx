// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useState } from "react";

import type {
  FrozenScenarioBinding,
  ScenarioBindingItem,
  ScenarioLibraryEntry,
  ScenarioPlanAction,
} from "../../lib/canary-api";


export interface ScenarioBindingStepProps {
  /** Literal action tuples of the signed plan awaiting approval, as the bindings view returned them. */
  actions: readonly ScenarioPlanAction[];
  /** The workspace library listing; only runner-supported entries bound to an action's check are offered. */
  entries: readonly ScenarioLibraryEntry[];
  frozen: readonly FrozenScenarioBinding[];
  accepting: boolean;
  busy: boolean;
  onFreeze: (items: ScenarioBindingItem[]) => void;
}


function actionKey(action: ScenarioPlanAction): string {
  return `${action.catalogScenarioId}\u0000${action.method}\u0000${action.routeTemplate}`;
}


/**
 * Optional, separate from approval: freezes which library or custom revisions this exact run stands for.
 * Nothing here changes the signed plan or the approval; a run approved without bindings stands for no entry.
 */
export function ScenarioBindingStep({ actions, entries, frozen, accepting, busy, onFreeze }: ScenarioBindingStepProps) {
  // One library entry can be frozen against one action of the plan.
  const [selected, setSelected] = useState<Readonly<Record<string, string>>>({});
  const items: ScenarioBindingItem[] = [];
  for (const action of actions) {
    for (const entry of entries) {
      if (selected[entry.id] !== actionKey(action)) continue;
      items.push({
        catalogScenarioId: action.catalogScenarioId, method: action.method, routeTemplate: action.routeTemplate,
        libraryScenarioId: entry.id, source: entry.source, definitionDigest: entry.definitionDigest,
      });
    }
  }
  const canFreeze = accepting && frozen.length === 0 && !busy && items.length > 0 && items.length <= 8;

  return (
    <fieldset aria-labelledby="scenario-binding-title" className="immutable-summary scenario-binding-step">
      <legend id="scenario-binding-title">What this run stands for (optional)</legend>
      <p>
        Bind library or custom scenarios to the exact checks in this signed plan before approving. Bindings are frozen
        once and never follow later library or custom edits. Approval does not require bindings; without them this run
        stands for no library entry.
      </p>
      {frozen.length > 0 ? (
        <ul aria-label="Frozen bindings">
          {frozen.map((row) => (
            <li key={row.libraryScenarioId}>
              <code>{row.libraryScenarioId}</code>{row.revision === null ? "" : ` (revision ${row.revision})`} → Executed
              check: {row.catalogScenarioId} {row.method} <code>{row.routeTemplate}</code>
            </li>
          ))}
        </ul>
      ) : null}
      {frozen.length === 0 && accepting ? (
        <ol aria-label="Plan checks">
          {actions.map((action) => {
            const key = actionKey(action);
            const offered = entries.filter((entry) => entry.executionSupport === "runner_supported"
              && entry.catalogScenarioId === action.catalogScenarioId);
            return (
              <li key={key}>
                <p>Executed check: {action.catalogScenarioId} {action.method} <code>{action.routeTemplate}</code></p>
                {offered.length === 0 ? <p>No library entry is bound to this check.</p> : (
                  <ul aria-label={`Entries for ${action.catalogScenarioId} ${action.method} ${action.routeTemplate}`}>
                    {offered.map((entry) => (
                      <li key={entry.id}>
                        <label>
                          <input
                            checked={selected[entry.id] === key}
                            disabled={busy}
                            onChange={(event) => setSelected((current) => {
                              const next = { ...current };
                              if (event.target.checked) next[entry.id] = key;
                              else delete next[entry.id];
                              return next;
                            })}
                            type="checkbox"
                          />
                          <code>{entry.id}</code>{entry.revision === null ? "" : ` (custom revision ${entry.revision})`}
                        </label>
                        <span>{entry.coverageStatement}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            );
          })}
        </ol>
      ) : null}
      {frozen.length === 0 && !accepting ? <p>Bindings can no longer be frozen for this run.</p> : null}
      {frozen.length === 0 && accepting ? (
        <button className="button button-secondary" disabled={!canFreeze} onClick={() => onFreeze(items)} type="button">
          Freeze bindings
        </button>
      ) : null}
    </fieldset>
  );
}
