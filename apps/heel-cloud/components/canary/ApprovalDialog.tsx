// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useState } from "react";

import type { ConfiguredApprovalView } from "../../lib/canary-api";
import { COMPARISON_LABELS, conditionText, roleText, successCheckText } from "../../lib/live-test-text";
import { ScenarioBindingStep, type ScenarioBindingStepProps } from "./ScenarioBindingStep";


export interface ApprovalDialogProps {
  open: boolean;
  origin: string;
  routes: readonly string[];
  scenarios: readonly string[];
  requestBudget: number;
  durationSeconds: number;
  egress: string;
  onApprove: (reason: string) => void;
  onClose: () => void;
  /** Optional selection-provenance step; approval never depends on it. */
  scenarioBinding?: ScenarioBindingStepProps;
  /** A configured plan's frozen conditions; approving then requires an explicit review of each. */
  configured?: ConfiguredApprovalView | null;
}


export function ApprovalDialog({
  open,
  origin,
  routes,
  scenarios,
  requestBudget,
  durationSeconds,
  egress,
  onApprove,
  onClose,
  scenarioBinding,
  configured = null,
}: ApprovalDialogProps) {
  const [hostname, setHostname] = useState("");
  const [reason, setReason] = useState("");
  const [reviewed, setReviewed] = useState(false);
  if (!open) return null;

  const exactHostname = new URL(origin).hostname;
  const canApprove = hostname === exactHostname && reason.trim().length >= 4 && (configured === null || reviewed);
  const plannedReads = configured === null ? null : configured.instances.reduce((sum, item) => sum + item.requestCount, 0);

  return (
    <div className="canary-dialog-backdrop" role="presentation">
      <section
        aria-labelledby="approval-title"
        aria-describedby="approval-boundary"
        aria-modal="true"
        className="canary-dialog approval-dialog"
        role="dialog"
      >
        <div className="dialog-kicker-row">
          <p className="canary-kicker">Execution approval</p>
          <button aria-label="Close approval" className="dialog-close" onClick={onClose} type="button">×</button>
        </div>
        <h2 id="approval-title">Approve one rehearsal</h2>
        <p id="approval-boundary" className="dialog-lede">
          Review the fixed execution boundaries below. Approval applies once and cannot widen while it runs.
        </p>

        <fieldset className="immutable-summary">
          <legend>Immutable execution summary</legend>
          <div className="immutable-grid">
            <label>Exact origin<input aria-readonly="true" readOnly value={origin} /></label>
            <label>Request ceiling<input aria-readonly="true" readOnly value={`${requestBudget} requests`} /></label>
            <label>Time ceiling<input aria-readonly="true" readOnly value={`${durationSeconds} seconds`} /></label>
            <label>Only allowed egress<input aria-readonly="true" readOnly value={egress} /></label>
          </div>
          <div className="immutable-columns">
            <div><span>Routes</span><ul>{routes.map((route) => <li key={route}><code>{route}</code></li>)}</ul></div>
            <div><span>Scenarios</span><ul>{scenarios.map((scenario) => <li key={scenario}>{scenario}</li>)}</ul></div>
          </div>
        </fieldset>

        {configured !== null ? (
          <fieldset className="immutable-summary configured-review" aria-describedby="configured-review-note">
            <legend>{configured.planKind === "configured_regression" ? "Saved regression to replay" : "Configured live tests in this signed plan"}</legend>
            <p id="configured-review-note">
              {plannedReads} planned reads ({requestBudget}-request signed ceiling). Each test reads one route once per role and
              reports only whether its condition held for the restricted role after the control read succeeded. Expected values
              stay on your runner; only their names appear here.
            </p>
            <ol aria-label="Configured tests to approve">
              {configured.instances.map((item) => (
                <li key={item.testInstanceId}>
                  <h3><code>{item.source.sourceScenarioId}</code> revision {item.source.sourceRevision}</h3>
                  <dl>
                    <div><dt>Comparison</dt><dd>{COMPARISON_LABELS[item.scenarioId]}</dd></div>
                    <div><dt>Route</dt><dd><code>{item.method} {item.routeTemplate}</code></dd></div>
                    <div><dt>Roles (restricted, then control)</dt><dd>{item.roles.map((role) => roleText(role, configured.planLabels)).join(" → ")}</dd></div>
                    <div><dt>Requests</dt><dd>{item.requestCount}</dd></div>
                    <div><dt>Successful response check</dt><dd>{successCheckText(item.assertion)}</dd></div>
                    <div><dt>Condition tested</dt><dd>{conditionText(item.assertion)}</dd></div>
                    <div><dt>Local values (names only)</dt><dd>{item.localInputRefs.join(", ")}</dd></div>
                  </dl>
                </li>
              ))}
            </ol>
            <label className="configured-review-ack">
              <input checked={reviewed} onChange={(event) => setReviewed(event.target.checked)} type="checkbox" />
              I reviewed every route, role pair and condition above; approve exactly these.
            </label>
          </fieldset>
        ) : null}

        {scenarioBinding ? <ScenarioBindingStep {...scenarioBinding} /> : null}

        <div className="approval-fields">
          <label>
            Retype exact hostname
            <span>Confirm <code>{exactHostname}</code></span>
            <input autoComplete="off" onChange={(event) => setHostname(event.target.value)} value={hostname} />
          </label>
          <label>
            Reason for this rehearsal
            <span>Recorded with this one-time approval.</span>
            <textarea onChange={(event) => setReason(event.target.value)} rows={3} value={reason} />
          </label>
        </div>

        <div className="dialog-actions">
          <button className="button button-primary" disabled={!canApprove}
            onClick={() => onApprove(reason.trim())} type="button">Approve and run</button>
          <button className="button button-secondary" onClick={onClose} type="button">Cancel</button>
        </div>
      </section>
    </div>
  );
}
