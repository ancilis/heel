// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type { FindingsSyncReceiptV1 } from "../../lib/findings-sync-v1";


export type FindingsSyncUiState =
  | "local_only"
  | "preparing"
  | "awaiting_consent"
  | "syncing"
  | "synced"
  | "retry_pending";


const STATUS_COPY: Readonly<Record<FindingsSyncUiState, string>> = Object.freeze({
  local_only: "Local only — nothing has been sent to Heel Cloud.",
  preparing: "Preparing a findings-only preview in this browser.",
  awaiting_consent: "Preview ready — no findings have been sent.",
  syncing: "Sending only the approved findings projection.",
  synced: "Findings continuity is available in this project.",
  retry_pending: "Approved findings are saved locally for a safe retry.",
});


export function FindingsSyncStatus({
  state,
  receipt = null,
}: {
  state: FindingsSyncUiState;
  receipt?: FindingsSyncReceiptV1 | null;
}) {
  return (
    <div className={`sync-status sync-status-${state}`} role="status" aria-live="polite">
      <span className="sync-status-dot" aria-hidden="true" />
      <span>{STATUS_COPY[state]}</span>
      {state === "synced" && receipt !== null ? (
        <small>
          {receipt.disposition === "created" ? "New hosted review" : "Matched existing hosted review"}
          {" · "}{receipt.metered ? "counted once" : "not counted again"}
        </small>
      ) : null}
    </div>
  );
}
