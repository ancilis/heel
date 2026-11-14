// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import Link from "next/link";


export type OwnershipProofMethod = "https-file" | "dns-txt";

/** The canonical shape the browser client sends; the control plane still decides what is acceptable. */
const TARGET_ORIGIN_SHAPE = /^https:\/\/[a-z0-9.-]{1,253}$/;

export type TargetOriginCheck =
  | { readonly ok: true; readonly origin: string }
  | { readonly ok: false; readonly message: string | null };

/**
 * The dashboard's client-side origin gate. It makes only three safe, meaning-preserving changes to pasted input:
 * outer whitespace is trimmed, one root `/` is dropped and the host name is lowercased. Anything else that is not
 * exactly `https://host` (another scheme, credentials, a port, a path, a query or a fragment) is refused with what to
 * fix, never silently discarded. It sends nothing; the control plane remains the authority.
 */
export function checkTargetOrigin(input: string): TargetOriginCheck {
  const value = input.trim();
  if (value === "") return { ok: false, message: null };
  if (!value.startsWith("https://")) {
    return { ok: false, message: /^http:\/\//i.test(value)
      ? "Use https://. Heel registers only HTTPS targets."
      : "Start with lowercase https:// followed by the host name, for example https://staging.yourcompany.com." };
  }
  const rest = value.slice("https://".length);
  const authorityEnd = rest.search(/[/?#]/);
  const authority = authorityEnd === -1 ? rest : rest.slice(0, authorityEnd);
  const suffix = authorityEnd === -1 ? "" : rest.slice(authorityEnd);
  if (authority.includes("@")) return { ok: false, message: "Remove the user name or password before @. Credentials are never entered here." };
  if (authority.includes(":")) return { ok: false, message: "Remove the port. Only the default HTTPS port is supported." };
  if (suffix !== "" && suffix !== "/") {
    const part = /^\/[^?#]/.test(suffix) ? "path" : suffix.includes("?") && (!suffix.includes("#") || suffix.indexOf("?") < suffix.indexOf("#")) ? "query (?…)" : "fragment (#…)";
    return { ok: false, message: `Remove the ${part}. Enter only the origin, for example https://staging.yourcompany.com.` };
  }
  if (authority === "") return { ok: false, message: "Add the host name after https://." };
  const origin = `https://${authority.toLowerCase()}`;
  if (!TARGET_ORIGIN_SHAPE.test(origin)) return { ok: false, message: "Use only letters, digits, dots and hyphens in the host name." };
  return { ok: true, origin };
}

const PROOF_METHOD_LABELS: Readonly<Record<OwnershipProofMethod, string>> = Object.freeze({ "https-file": "HTTPS file", "dns-txt": "DNS TXT" });

/** A server-listed pending record; it carries no proof material, only what identifies the target. */
export interface PendingTarget {
  environmentId: string;
  origin: string;
  proofMethod: OwnershipProofMethod;
}

export const TARGET_UNAVAILABLE_BOUNDARY = "Target verified. Heel Cloud contacts it only to check your ownership proof. Rehearsals run only from a runner on your own machine, using the read-only GET and HEAD requests of a plan you approve; credentials and raw evidence stay on that machine.";
/** The same boundary for an account that operates a paired private runner, which keeps its credentials locally. */
export const TARGET_CONNECTOR_BOUNDARY = "Target verified. Heel Cloud contacts it only to check your ownership proof; your paired runner sends only the read-only GET and HEAD requests of a plan you approve. Target authorization is separate from test credentials: credentials are stored only on your paired runner's machine and are never entered in this browser. A rehearsal appears here only after that runner submits a valid signed plan, and runs only if you approve it.";

export interface TargetRegistrationCardProps {
  /** True when the account already operates a paired private runner or authorization for this project. */
  privateConnector?: boolean;
  /** Origin of the project's persisted, server-verified environment, or null when none exists yet. */
  verifiedOrigin: string | null;
  origin: string;
  proofMethod: OwnershipProofMethod;
  /** The proof instruction returned by the last successful start, or null before one exists. */
  instruction: string | null;
  busy: boolean;
  onOriginChange: (origin: string) => void;
  onProofMethodChange: (method: OwnershipProofMethod) => void;
  /** Receives the exact canonical origin the button validated, so the submission never depends on later state. */
  onCreateProof: (origin: string) => void;
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
  verifiedOrigin, origin, proofMethod, instruction, busy, privateConnector = false,
  onOriginChange, onProofMethodChange, onCreateProof, onCheckProof,
  pendingTargets, selectedPendingId, replacementPendingId, onSelectPendingTarget, onResumeProof, onReplaceProof,
}: TargetRegistrationCardProps) {
  const selectedPending = pendingTargets.find((item) => item.environmentId === selectedPendingId);
  const originCheck = checkTargetOrigin(origin);
  const originError = !originCheck.ok && originCheck.message !== null ? originCheck.message : null;
  const originNormalized = originCheck.ok && originCheck.origin !== origin ? originCheck.origin : null;
  if (verifiedOrigin !== null) {
    return (
      <section className="runner-recovery" id="verify-origin" aria-labelledby="target-title"><p className="canary-kicker">Registered target</p><h2 id="target-title">Your target</h2>
        <p><code>{verifiedOrigin}</code></p>
        <p role="status">{privateConnector ? TARGET_CONNECTOR_BOUNDARY : TARGET_UNAVAILABLE_BOUNDARY}</p>
        {privateConnector ? null : <p>Optional: if you already operate a paired private connector, its access controls appear on this page. <Link href="/guide">Paired runner guide</Link></p>}
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
        <label>Target URL<input aria-describedby={originError !== null ? "target-origin-error" : originNormalized !== null ? "target-origin-canonical" : undefined}
          aria-invalid={originError !== null ? true : undefined} autoComplete="url" onChange={(event) => onOriginChange(event.target.value)}
          placeholder="https://staging.yourcompany.com" value={origin} /></label>
        {originError !== null ? <p id="target-origin-error">{originError}</p> : null}
        {originNormalized !== null ? <p id="target-origin-canonical">Heel will register <code>{originNormalized}</code>.</p> : null}
        <label>Ownership proof method<select onChange={(event) => onProofMethodChange(event.target.value as OwnershipProofMethod)} value={proofMethod}><option value="https-file">HTTPS file</option><option value="dns-txt">DNS TXT</option></select></label>
        <button className="button button-primary" disabled={busy || !originCheck.ok} onClick={() => { if (originCheck.ok) onCreateProof(originCheck.origin); }} type="button">Create ownership proof</button>
      </>}
    </section>
  );
}
