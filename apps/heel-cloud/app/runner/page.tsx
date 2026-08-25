// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useState } from "react";
import Link from "next/link";


const pairCommand = "heel runner pair --cloud https://YOUR_HEEL_DOMAIN";


export default function Runner() {
  const [copied, setCopied] = useState(false);

  async function copyCommand(): Promise<void> {
    if (navigator.clipboard === undefined) return;
    await navigator.clipboard.writeText(pairCommand);
    setCopied(true);
  }

  return (
    <main className="runner-page">
      <header className="dashboard-nav">
        <Link className="brand" href="/" aria-label="Heel home">
          <span className="brand-mark" aria-hidden="true">H</span><span>Heel</span>
        </Link>
        <Link className="text-link" href="/dashboard">Return to activation</Link>
      </header>

      <section className="runner-hero" aria-labelledby="runner-title">
        <div>
          <p className="canary-kicker">Outbound-only · customer local</p>
          <h1 id="runner-title">Pair your runner.</h1>
          <p>Run one command on the machine that can reach staging. Compare what it shows with this browser before you approve anything.</p>
        </div>
        <div className="runner-waiting" role="status"><i aria-hidden="true" /><span>Waiting for this browser to approve</span></div>
      </section>

      <section className="runner-command" aria-labelledby="runner-command-title">
        <div className="runner-command-number" aria-hidden="true">01</div>
        <div>
          <p className="canary-kicker">On the runner machine</p>
          <h2 id="runner-command-title">Start pairing</h2>
          <div className="command-copy"><code>{pairCommand}</code><button onClick={() => void copyCommand()} type="button">{copied ? "Copied" : "Copy command"}</button></div>
          <p>The terminal will show a short phrase and key fingerprint. Leave it open.</p>
        </div>
      </section>

      <section className="runner-compare" aria-labelledby="runner-compare-title">
        <div className="runner-command-number" aria-hidden="true">02</div>
        <div>
          <p className="canary-kicker">In this browser</p>
          <h2 id="runner-compare-title">Compare before approval</h2>
          <dl className="pairing-preview">
            <div><dt>Phrase</dt><dd>copper · field · seven</dd></div>
            <div><dt>Fingerprint</dt><dd><code>8C1F · 4E29 · A773</code></dd></div>
            <div><dt>Capability</dt><dd>Canary runner</dd></div>
          </dl>
          <div className="runner-approval-actions">
            <button className="button button-primary" disabled type="button">Approve matching runner</button>
            <button className="button button-secondary" type="button">Deny request</button>
          </div>
          <p className="runner-preview-boundary">Launch preview: approval stays disabled until a signed pairing request arrives.</p>
        </div>
      </section>

      <section className="runner-local-access" id="canary-access" aria-labelledby="runner-access-title">
        <p className="canary-kicker">After pairing · stays on this machine</p>
        <h2 id="runner-access-title">Add isolated test access.</h2>
        <p>Create two staging-only identities, assign each a semantic role in the companion, and confirm the eligible read-only scenarios. Heel Cloud receives only role names and plan ceilings.</p>
        <div className="local-access-flow" aria-label="Local access setup sequence">
          <span>1 · Open companion</span><i aria-hidden="true">→</i><span>2 · Add roles</span><i aria-hidden="true">→</i><span>3 · Prepare plan</span>
        </div>
      </section>

      <aside className="runner-recovery" aria-labelledby="runner-recovery-title">
        <p className="canary-kicker">Nothing appeared?</p>
        <h2 id="runner-recovery-title">Recover without losing setup.</h2>
        <p>Confirm the cloud origin, check outbound HTTPS, then start a new pairing request. An expired or denied request grants nothing.</p>
        <button className="button button-secondary" type="button">Check connection</button>
      </aside>
    </main>
  );
}
