// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";


export interface DisclosureDialogProps {
  open: boolean;
  completedScenarios: number;
  outcomeCounts: {
    blocked: number;
    observed: number;
    inconclusive: number;
  };
  byteCount: number;
  onKeepLocal: () => void;
  onPermit: () => void;
  onClose: () => void;
}


function readableBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}


export function DisclosureDialog({
  open,
  completedScenarios,
  outcomeCounts,
  byteCount,
  onKeepLocal,
  onPermit,
  onClose,
}: DisclosureDialogProps) {
  if (!open) return null;

  return (
    <div className="canary-dialog-backdrop disclosure-backdrop" role="presentation">
      <section
        aria-labelledby="disclosure-title"
        aria-describedby="disclosure-boundary"
        aria-modal="true"
        className="canary-dialog disclosure-dialog"
        role="dialog"
      >
        <div className="dialog-kicker-row">
          <p className="canary-kicker">Separate disclosure</p>
          <button aria-label="Close disclosure" className="dialog-close" onClick={onClose} type="button">×</button>
        </div>
        <h2 id="disclosure-title">Share result summary?</h2>
        <p id="disclosure-boundary" className="dialog-lede">
          The rehearsal is already complete. This optional, one-use choice shares only the summary listed below with your Heel history.
        </p>

        <dl className="disclosure-receipt">
          <div><dt>Coverage</dt><dd>{completedScenarios} scenarios</dd></div>
          <div><dt>Held</dt><dd>{outcomeCounts.blocked}</dd></div>
          <div><dt>Crossed</dt><dd>{outcomeCounts.observed}</dd></div>
          <div><dt>Unclear</dt><dd>{outcomeCounts.inconclusive}</dd></div>
          <div><dt>Summary size</dt><dd>{readableBytes(byteCount)}</dd></div>
        </dl>

        <div className="disclosure-boundary-note">
          <strong>Metadata only</strong>
          <p>Scenario outcomes and recommended controls are included. Request content and local identifiers stay on this machine.</p>
        </div>

        <div className="dialog-actions">
          <button className="button disclosure-permit" onClick={onPermit} type="button">Share this summary</button>
          <button className="button disclosure-local" onClick={onKeepLocal} type="button">Keep result local</button>
        </div>
      </section>
    </div>
  );
}
