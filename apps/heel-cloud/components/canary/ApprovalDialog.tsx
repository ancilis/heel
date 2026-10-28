// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useState } from "react";


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
}: ApprovalDialogProps) {
  const [hostname, setHostname] = useState("");
  const [reason, setReason] = useState("");
  if (!open) return null;

  const exactHostname = new URL(origin).hostname;
  const canApprove = hostname === exactHostname && reason.trim().length >= 4;

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
