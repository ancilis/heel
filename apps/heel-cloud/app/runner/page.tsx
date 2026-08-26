// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { CanaryApi, CanaryApiError } from "../../lib/canary-api";
import { HeelCloudApi, HeelCloudApiError } from "../../lib/heel-cloud-api";


type Connection =
  | { phase: "checking" }
  | { phase: "sign_in"; message: string }
  | { phase: "ready"; workspaceRef: string };

type PairingView = { pairingId: string; phrase: string; fingerprint: string };

const cloudApi = new HeelCloudApi();
const canaryApi = new CanaryApi();
const PAIR_COMMAND = "heel runner pair --cloud <origin>";


export default function Runner() {
  const [connection, setConnection] = useState<Connection>({ phase: "checking" });
  const [invitation, setInvitation] = useState<string | null>(null);
  const [pairingId, setPairingId] = useState("");
  const [pairing, setPairing] = useState<PairingView | null>(null);
  const [phraseConfirmed, setPhraseConfirmed] = useState(false);
  const [fingerprintConfirmed, setFingerprintConfirmed] = useState(false);
  const [working, setWorking] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void cloudApi.me().then((session) => {
      if (cancelled) return;
      const workspace = session.workspaces.find((item) => item.role === "owner" || item.role === "admin");
      if (workspace === undefined) {
        setConnection({ phase: "sign_in", message: "Connect an owner or admin workspace to create a runner invitation." });
      } else {
        setConnection({ phase: "ready", workspaceRef: workspace.workspaceRef });
      }
    }).catch((error: unknown) => {
      if (cancelled) return;
      setConnection({
        phase: "sign_in",
        message: error instanceof HeelCloudApiError ? error.message : "Heel Cloud is temporarily unavailable.",
      });
    });
    return () => { cancelled = true; };
  }, []);

  const pairCommand = invitation === null ? null : PAIR_COMMAND;

  async function createInvitation(): Promise<void> {
    if (connection.phase !== "ready") return;
    setWorking(true);
    setNotice(null);
    try {
      const created = await canaryApi.createRunnerPairingInvitation(connection.workspaceRef);
      setInvitation(created.invitationToken);
      setNotice("One-time invitation ready. Run the command on the machine that can reach staging.");
    } catch (error) {
      setNotice(error instanceof CanaryApiError ? error.message : "Could not create the runner invitation.");
    } finally {
      setWorking(false);
    }
  }

  async function inspectPairing(): Promise<void> {
    if (connection.phase !== "ready") return;
    setWorking(true);
    setNotice(null);
    try {
      const value = await canaryApi.inspectRunnerPairing(connection.workspaceRef, pairingId.trim());
      setPairing({
        pairingId: value.pairing_id as string,
        phrase: value.pairing_phrase as string,
        fingerprint: value.fingerprint as string,
      });
      setPhraseConfirmed(false);
      setFingerprintConfirmed(false);
    } catch (error) {
      setPairing(null);
      setNotice(error instanceof CanaryApiError ? error.message : "Could not load that pairing request.");
    } finally {
      setWorking(false);
    }
  }

  async function approvePairing(): Promise<void> {
    if (connection.phase !== "ready" || pairing === null || !phraseConfirmed || !fingerprintConfirmed) return;
    setWorking(true);
    setNotice(null);
    try {
      await canaryApi.approveRunnerPairing(connection.workspaceRef, pairing.pairingId, pairing.phrase, pairing.fingerprint);
      setNotice("Runner approved. Return to its terminal to complete the signed activation challenge.");
      setPairing(null);
    } catch (error) {
      setNotice(error instanceof CanaryApiError ? error.message : "Could not approve the runner.");
    } finally {
      setWorking(false);
    }
  }

  return (
    <main className="runner-page">
      <header className="dashboard-nav">
        <Link className="brand" href="/" aria-label="Heel home"><span className="brand-mark" aria-hidden="true">H</span><span>Heel</span></Link>
        <Link className="text-link" href="/dashboard">Return to activation</Link>
      </header>

      <section className="runner-hero" aria-labelledby="runner-title">
        <div><p className="canary-kicker">Outbound-only · customer local</p><h1 id="runner-title">Pair your runner.</h1>
          <p>Run one command on the machine that can reach staging. Compare what it shows with this browser before you approve anything.</p></div>
        <div className="runner-waiting" role="status"><i aria-hidden="true" /><span>
          {connection.phase === "checking" ? "Checking your signed-in workspace" : connection.phase === "ready" ? "Workspace connected" : "Connect your signed-in workspace"}
        </span></div>
      </section>

      {connection.phase !== "ready" ? <section className="runner-recovery" aria-live="polite">
        <p className="canary-kicker">Connection required</p><h2>Connect your signed-in workspace.</h2>
        <p>{connection.phase === "checking" ? "Heel is checking this browser session. Nothing has been approved." : connection.message}</p>
        <Link className="button button-primary" href="/">Open sign in</Link>
      </section> : <>
        <section className="runner-command" aria-labelledby="runner-command-title">
          <div className="runner-command-number" aria-hidden="true">01</div><div>
            <p className="canary-kicker">On the runner machine</p><h2 id="runner-command-title">Start pairing</h2>
            {pairCommand === null ? <button className="button button-primary" disabled={working} onClick={() => void createInvitation()} type="button">Create one-time pairing command</button> : <>
              <div className="command-copy"><code>{pairCommand}</code></div>
              <p>Replace <code>&lt;origin&gt;</code> with the Heel address shown in this browser, then select and copy the command.</p>
              <p>When the runner prompts with a silent <code>read --silent</code> input, paste this one-use invitation. It is never placed in shell history, process arguments, or a URL.</p>
              <div className="command-copy"><code aria-label="One-use invitation code">{invitation}</code></div>
              <p>Select and copy the invitation separately.</p>
              <p>Paste it only when the runner prompts. The terminal will then return a pairing ID, short phrase, and key fingerprint.</p>
            </>}
          </div>
        </section>

        <section className="runner-compare" aria-labelledby="runner-compare-title">
          <div className="runner-command-number" aria-hidden="true">02</div><div>
            <p className="canary-kicker">In this browser</p><h2 id="runner-compare-title">Compare before approval</h2>
            <label>Pairing ID from the runner terminal<input autoComplete="off" onChange={(event) => setPairingId(event.target.value)} placeholder="pending_…" value={pairingId} /></label>
            <button className="button button-secondary" disabled={working || !/^pending_[0-9a-f]{32}$/.test(pairingId.trim())} onClick={() => void inspectPairing()} type="button">Load signed pairing request</button>
            {pairing ? <>
              <dl className="pairing-preview"><div><dt>Phrase</dt><dd>{pairing.phrase}</dd></div><div><dt>Fingerprint</dt><dd><code>{pairing.fingerprint}</code></dd></div><div><dt>Capability</dt><dd>Canary runner</dd></div></dl>
              <label><input checked={phraseConfirmed} onChange={(event) => setPhraseConfirmed(event.target.checked)} type="checkbox" /> Phrase matches the runner terminal exactly</label>
              <label><input checked={fingerprintConfirmed} onChange={(event) => setFingerprintConfirmed(event.target.checked)} type="checkbox" /> Fingerprint matches the runner terminal exactly</label>
              <div className="runner-approval-actions"><button className="button button-primary" disabled={working || !phraseConfirmed || !fingerprintConfirmed} onClick={() => void approvePairing()} type="button">Approve matching runner</button><button className="button button-secondary" onClick={() => setPairing(null)} type="button">Deny request</button></div>
            </> : <p className="runner-preview-boundary">Approval stays unavailable until you load and compare a signed pairing request.</p>}
          </div>
        </section>
      </>}

      {notice ? <p className="runner-recovery" role="status">{notice}</p> : null}
      <section className="runner-local-access" id="canary-access" aria-labelledby="runner-access-title">
        <p className="canary-kicker">After pairing · stays on this machine</p><h2 id="runner-access-title">Add isolated test access.</h2>
        <p>Create two staging-only identities, assign each a semantic role in the companion, and confirm the eligible read-only scenarios. Heel Cloud receives only role names and plan ceilings.</p>
        <div className="local-access-flow" aria-label="Local access setup sequence"><span>1 · Open companion</span><i aria-hidden="true">→</i><span>2 · Add roles</span><i aria-hidden="true">→</i><span>3 · Prepare plan</span></div>
      </section>
      <aside className="runner-recovery" aria-labelledby="runner-recovery-title"><p className="canary-kicker">Nothing appeared?</p><h2 id="runner-recovery-title">Recover without losing setup.</h2><p>Confirm the cloud origin, check outbound HTTPS, then create a new one-time invitation. An expired or denied request grants nothing.</p></aside>
    </main>
  );
}
