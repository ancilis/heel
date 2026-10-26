// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import Link from "next/link";


export type OwnershipProofMethod = "https-file" | "dns-txt";

/** The dashboard's client-side shape gate; the control plane still decides what is acceptable. */
const TARGET_ORIGIN_SHAPE = /^https:\/\/[a-z0-9.-]+$/;

const PROOF_METHOD_LABELS: Readonly<Record<OwnershipProofMethod, string>> = Object.freeze({ "https-file": "HTTPS file", "dns-txt": "DNS TXT" });

/** A server-listed pending record; it carries no proof material, only what identifies the target. */
export interface PendingTarget {
  environmentId: string;
  origin: string;
  proofMethod: OwnershipProofMethod;
}

export const TARGET_UNAVAILABLE_BOUNDARY = "Target verified. Managed scanning, credentials, discovery, and scan approval are not available in this build.";

export interface TargetRegistrationCardProps {
  /** Origin of the project's persisted, server-verified environment, or null when none exists yet. */
  verifiedOrigin: string | null;
  origin: string;
  proofMethod: OwnershipProofMethod;
  /** The proof instruction returned by the last successful start, or null before one exists. */
  instruction: string | null;
  busy: boolean;
  onOriginChange: (origin: string) => void;
  onProofMethodChange: (method: OwnershipProofMethod) => void;
  onCreateProof: () => void;
  onCheckProof: () => void;
  /** Pending records from the server list, shown again after a reload. */
  pendingTargets: readonly PendingTarget[];
  /** The record the user chose, or the only pending record; never another target chosen silently. */
  selectedPendingId: string | null;
  /** The record whose proof the server reported expired or missing; it can only be replaced. */
  replacementPendingId: string | null;
  onSelectPendingTarget: (environmentId: string) => void;
  onResumeProof: () => void;
  onReplaceProof: () => void;
}


/** Registers one public HTTPS target through the existing ownership-proof contract; it never contacts the target. */
export function TargetRegistrationCard({
  verifiedOrigin, origin, proofMethod, instruction, busy,
  onOriginChange, onProofMethodChange, onCreateProof, onCheckProof,
  pendingTargets, selectedPendingId, replacementPendingId, onSelectPendingTarget, onResumeProof, onReplaceProof,
}: TargetRegistrationCardProps) {
  const selectedPending = pendingTargets.find((item) => item.environmentId === selectedPendingId);
  if (verifiedOrigin !== null) {
    return (
      <section className="runner-recovery" id="verify-origin" aria-labelledby="target-title"><p className="canary-kicker">Registered target</p><h2 id="target-title">Your target</h2>
        <p><code>{verifiedOrigin}</code></p>
        <p role="status">{TARGET_UNAVAILABLE_BOUNDARY}</p>
        <p>Optional: if you already operate a paired private connector, its access controls appear on this page. <Link href="/runner">About private connectors</Link></p>
      </section>
    );
  }
  return (
    <section className="runner-recovery" id="verify-origin" aria-labelledby="target-title"><p className="canary-kicker">Exact public HTTPS origin</p><h2 id="target-title">Add target</h2>
      {instruction !== null ? <>
        <p role="status">Target verification pending. Publish this proof, then check it.</p>
        <p><code>{instruction}</code></p>
        <button className="button button-primary" disabled={busy} onClick={onCheckProof} type="button">Check ownership proof</button>
      </> : <>
        {pendingTargets.length > 0 ? <div role="group" aria-label="Pending ownership proof">
          <p role="status">Ownership proof pending for a registered target. The proof is kept on the server; resume it to see the instruction again.</p>
          {pendingTargets.length === 1
            ? <p><code>{pendingTargets[0].origin}</code> · {PROOF_METHOD_LABELS[pendingTargets[0].proofMethod]}</p>
            : <label>Pending target<select disabled={busy} onChange={(event) => onSelectPendingTarget(event.target.value)} value={selectedPending?.environmentId ?? ""}><option value="">Choose a pending target</option>{pendingTargets.map((item) => <option key={item.environmentId} value={item.environmentId}>{item.origin} · {PROOF_METHOD_LABELS[item.proofMethod]}</option>)}</select></label>}
          {selectedPending !== undefined && selectedPending.environmentId === replacementPendingId ? <>
            <p>This proof can no longer be checked. A replacement keeps this target and makes the old proof invalid.</p>
            <button className="button button-primary" disabled={busy} onClick={onReplaceProof} type="button">Issue replacement proof</button>
          </> : <button className="button button-primary" disabled={busy || selectedPending === undefined} onClick={onResumeProof} type="button">Resume ownership proof</button>}
          <p>Or register a different target:</p>
        </div> : null}
        <p>The target must be one staging or sandbox HTTPS origin that is publicly reachable. Ownership proof is required before anything else; Heel does not contact the target from this browser.</p>
        <label>Target URL<input autoComplete="url" onChange={(event) => onOriginChange(event.target.value)} placeholder="https://staging.yourcompany.com" value={origin} /></label>
        <label>Ownership proof method<select onChange={(event) => onProofMethodChange(event.target.value as OwnershipProofMethod)} value={proofMethod}><option value="https-file">HTTPS file</option><option value="dns-txt">DNS TXT</option></select></label>
        <button className="button button-primary" disabled={busy || !TARGET_ORIGIN_SHAPE.test(origin.trim())} onClick={onCreateProof} type="button">Create ownership proof</button>
      </>}
    </section>
  );
}
