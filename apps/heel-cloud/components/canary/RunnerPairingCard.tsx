// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { useState } from "react";

import { canonicalPublicOrigin } from "../../build/deployment-config";
import type { RunnerPairingView } from "../../lib/canary-api";


/** The verified public 1.3.0rc2 runner install line; it must stay byte-identical to the one on `/agent`. */
export const RUNNER_RC2_INSTALL = "python3 -m venv heel-rc2 && ./heel-rc2/bin/python -m pip --isolated install 'heel-sim[runner] @ https://github.com/ancilis/heel/releases/download/v1.3.0rc2/heel_sim-1.3.0rc2-py3-none-any.whl#sha256=f8698204e1d38aa80b8ca31dedd743c3d42e28d02c5153bddb4f02b44ecdf01c' && ./heel-rc2/bin/heel --version";
export const RUNNER_RC2_RELEASE_URL = "https://github.com/ancilis/heel/releases/tag/v1.3.0rc2";
const PAIRING_ID_SHAPE = /^pending_[0-9a-f]{32}$/;
export const PAIRING_UNCONFIGURED = "Runner pairing is unavailable: this dashboard's public address is not configured, so no pair command can be shown. No invitation was created; contact your Heel operator.";

/**
 * The runner's `--origin`: the deployment's one canonical public origin, inlined at build time from the validated
 * HEEL_PUBLIC_ORIGIN (next.config.ts) and checked again here. Anything else yields no command.
 */
function runnerOrigin(): string | null {
  return canonicalPublicOrigin(process.env.HEEL_PUBLIC_ORIGIN);
}

/** The words the person typed from their terminal, compared case- and spacing-insensitively to the server's phrase. */
export function pairingPhraseMatches(typed: string, phrase: string): boolean {
  const normalized = typed.trim().toLowerCase().split(/\s+/).join(" ");
  return normalized.length > 0 && normalized === phrase;
}

function clock(seconds: number): string {
  return new Date(seconds * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export interface RunnerPairingCardProps {
  /** The one-time invitation, held only in page memory and shown only until a pairing request is opened. */
  invitation: { token: string; expiresAt: number } | null;
  /** The server's current view of the pairing request the person opened. */
  pairing: RunnerPairingView | null;
  /** True once the server accepted the approval of the opened pairing. */
  approved: boolean;
  nowSeconds: number;
  busy: boolean;
  onCreateInvitation: () => void;
  onInspect: (pairingId: string) => void;
  onApprove: (typedPhrase: string) => void;
  onRefreshRunners: () => void;
}


/**
 * Pairs one local runner: a one-time invitation, the runner's own `heel runner pair`, then a human comparison of the
 * six words and fingerprint the runner printed before an explicit approval. Target credentials stay on the runner
 * machine; this card never asks for them.
 */
export function RunnerPairingCard({
  invitation, pairing, approved, nowSeconds, busy, onCreateInvitation, onInspect, onApprove, onRefreshRunners,
}: RunnerPairingCardProps) {
  const [pairingId, setPairingId] = useState("");
  const invitationExpired = invitation !== null && nowSeconds >= invitation.expiresAt;
  const candidateId = pairingId.trim();
  const origin = runnerOrigin();

  return (
    <section className="runner-recovery" aria-labelledby="pair-runner-title"><p className="canary-kicker">Local runner</p><h2 id="pair-runner-title">Pair a runner</h2>
      <p>The runner runs on your machine and sends the only target traffic. Target credentials stay on that machine; this browser never asks for them.</p>
      <p>1. Install the public preview runner (<a href={RUNNER_RC2_RELEASE_URL}>Heel 1.3.0rc2 release</a>):</p>
      <p><code>{RUNNER_RC2_INSTALL}</code></p>
      <p>2. Create a one-time invitation. It expires after 10 minutes and is shown only here, once.</p>
      {origin === null ? <p role="status">{PAIRING_UNCONFIGURED}</p> : invitation !== null && !invitationExpired ? <div role="group" aria-label="Runner pairing invitation">
        <p>Run this on the runner machine before {clock(invitation.expiresAt)}. It prints a pairing id, six words and a fingerprint:</p>
        <p><code>{`./heel-rc2/bin/heel runner pair --origin ${origin} --invite ${invitation.token}`}</code></p>
      </div> : <>
        {invitationExpired ? <p role="status">This invitation expired unused or unopened. Create a new one.</p> : null}
        <button className="button button-primary" disabled={busy} onClick={onCreateInvitation} type="button">Create pairing invitation</button>
      </>}
      <p>3. Open the pairing request the runner printed.</p>
      <label>Pairing id from your terminal<input autoComplete="off" disabled={busy} onChange={(event) => setPairingId(event.target.value)} placeholder="pending_…" spellCheck={false} value={pairingId} /></label>
      <button className="button" disabled={busy || !PAIRING_ID_SHAPE.test(candidateId)} onClick={() => onInspect(candidateId)} type="button">Open pairing request</button>
      {pairing !== null ? <PairingComparison key={pairing.pairingId} approved={approved} busy={busy} expired={nowSeconds >= pairing.expiresAt}
        onApprove={onApprove} onRefreshRunners={onRefreshRunners} pairing={pairing} /> : null}
    </section>
  );
}


/** One opened pairing request; keyed by its id so typed words and the fingerprint confirmation never carry over. */
function PairingComparison({ pairing, approved, expired, busy, onApprove, onRefreshRunners }: {
  pairing: RunnerPairingView; approved: boolean; expired: boolean; busy: boolean;
  onApprove: (typedPhrase: string) => void; onRefreshRunners: () => void;
}) {
  const [typedPhrase, setTypedPhrase] = useState("");
  const [fingerprintConfirmed, setFingerprintConfirmed] = useState(false);
  const phraseMatches = pairingPhraseMatches(typedPhrase, pairing.pairingPhrase);
  return (
    <div role="group" aria-label="Pending runner pairing">
      {approved ? <>
        <p role="status">Runner approved. Leave <code>heel runner pair</code> running until it reports the runner active, then check <code>heel runner status</code>.</p>
        <button className="button" disabled={busy} onClick={onRefreshRunners} type="button">Refresh paired runners</button>
      </> : expired ? <p role="status">This pairing request expired. Create a new invitation and run the pair command again.</p> : <>
        <p>4. Compare with your terminal. Approve only if both match exactly.</p>
        <p>Six words: <strong>{pairing.pairingPhrase}</strong></p>
        <p>Fingerprint: <code>{pairing.fingerprint}</code></p>
        <label>Type the six words shown in your terminal<input autoComplete="off" disabled={busy} onChange={(event) => setTypedPhrase(event.target.value)} spellCheck={false} value={typedPhrase} /></label>
        {typedPhrase.trim() !== "" && !phraseMatches ? <p role="alert">These words do not match this pairing request. Do not approve it; nothing was sent.</p> : null}
        <label><input checked={fingerprintConfirmed} disabled={busy} onChange={(event) => setFingerprintConfirmed(event.target.checked)} type="checkbox" /> The fingerprint in my terminal is exactly the one above</label>
        <button className="button button-primary" disabled={busy || !phraseMatches || !fingerprintConfirmed} onClick={() => onApprove(typedPhrase)} type="button">Approve this runner</button>
      </>}
    </div>
  );
}
