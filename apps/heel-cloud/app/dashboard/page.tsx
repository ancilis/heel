// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useState } from "react";
import Link from "next/link";

import { ActivationCard, type ActivationSnapshot } from "../../components/canary/ActivationCard";
import { ApprovalDialog } from "../../components/canary/ApprovalDialog";
import { DisclosureDialog } from "../../components/canary/DisclosureDialog";
import { RunProgress, type RunPhase } from "../../components/canary/RunProgress";


type Preview = "setup" | "ready" | "running" | "complete" | "error" | "stopped";

const previewSnapshots: Record<Preview, ActivationSnapshot> = {
  setup: { environment: "unverified", runner: "locked", canaryAccess: "locked", rehearsal: "locked" },
  ready: { environment: "verified", runner: "online", canaryAccess: "ready", rehearsal: "ready" },
  running: { environment: "verified", runner: "online", canaryAccess: "ready", rehearsal: "running" },
  complete: { environment: "verified", runner: "online", canaryAccess: "ready", rehearsal: "complete" },
  error: { environment: "verified", runner: "online", canaryAccess: "ready", rehearsal: "error" },
  stopped: { environment: "verified", runner: "online", canaryAccess: "ready", rehearsal: "error" },
};

const completedSteps: Record<Preview, number> = {
  setup: 0,
  ready: 3,
  running: 4,
  complete: 4,
  error: 3,
  stopped: 4,
};


export default function Dashboard() {
  const [preview, setPreview] = useState<Preview>("setup");
  const [approvalOpen, setApprovalOpen] = useState(false);
  const [disclosureOpen, setDisclosureOpen] = useState(false);

  let runPhase: RunPhase | null = null;
  if (preview === "running") runPhase = "running";
  if (preview === "complete") runPhase = "complete";
  if (preview === "error") runPhase = "error";
  if (preview === "stopped") runPhase = "stopped";

  return (
    <main className="canary-dashboard">
      <header className="dashboard-nav">
        <Link className="brand" href="/" aria-label="Heel home">
          <span className="brand-mark" aria-hidden="true">H</span>
          <span>Heel</span>
        </Link>
        <div className="dashboard-context">
          <span className="dashboard-workspace">Northstar workspace</span>
          <span className="dashboard-presence"><i aria-hidden="true" /> Runner local</span>
        </div>
      </header>

      <section className="dashboard-intro" aria-labelledby="dashboard-title">
        <div>
          <p className="canary-kicker">Verified canary rehearsal</p>
          <h1 id="dashboard-title">Cross the boundary <em>before</em> your customers do.</h1>
          <p>Verify one staging environment, pair one local runner, and complete a bounded read-only rehearsal.</p>
        </div>
        <aside className="preview-notice" aria-label="Launch preview status">
          <span className="preview-pulse" aria-hidden="true" />
          <div><strong>Launch preview</strong><p>Sample state only · no request has been sent</p></div>
        </aside>
      </section>

      <nav aria-label="Preview activation states" className="preview-switcher">
        <span>Preview state</span>
        <button aria-pressed={preview === "setup"} onClick={() => setPreview("setup")} type="button">Setup</button>
        <button aria-pressed={preview === "ready"} onClick={() => setPreview("ready")} type="button">Ready</button>
        <button aria-pressed={preview === "running"} onClick={() => setPreview("running")} type="button">Active run</button>
        <button aria-pressed={preview === "complete"} onClick={() => setPreview("complete")} type="button">Complete</button>
        <button aria-pressed={preview === "error"} onClick={() => setPreview("error")} type="button">Recovery</button>
      </nav>

      <div className="dashboard-grid">
        <ActivationCard
          completedSteps={completedSteps[preview]}
          onReviewApproval={() => setApprovalOpen(true)}
          snapshot={previewSnapshots[preview]}
        />

        <aside className="dashboard-rail" aria-label="Rehearsal safety boundaries">
          <section className="boundary-ledger">
            <p className="canary-kicker">Always enforced</p>
            <h2>The runner owns target traffic.</h2>
            <dl>
              <div><dt>Origin</dt><dd>One verified host</dd></div>
              <div><dt>Methods</dt><dd>GET + HEAD</dd></div>
              <div><dt>Egress</dt><dd>Staging :443 only</dd></div>
              <div><dt>Cloud view</dt><dd>Operational status only</dd></div>
            </dl>
          </section>

          {runPhase ? <RunProgress
            completedScenarios={preview === "complete" ? 4 : 2}
            localResultUrl={preview === "complete" ? "http://127.0.0.1:7331/runs/run-preview" : undefined}
            onRetry={preview === "error" ? () => setPreview("running") : undefined}
            onStop={preview === "running" ? () => setPreview("stopped") : undefined}
            phase={runPhase}
            recovery={preview === "error" ? "Runner lost contact. Confirm it is online, then retry status." : undefined}
            requestBudget={12}
            requestsUsed={preview === "complete" ? 11 : 7}
            secondsRemaining={preview === "running" ? 31 : 0}
            totalScenarios={4}
          /> : null}

          {preview === "complete" ? <button className="disclosure-entry" onClick={() => setDisclosureOpen(true)} type="button">
            <span>Optional history</span><strong>Review separate summary sharing →</strong>
          </button> : null}
        </aside>
      </div>

      <ApprovalDialog
        durationSeconds={45}
        egress="staging.example.test:443"
        onApprove={() => { setApprovalOpen(false); setPreview("running"); }}
        onClose={() => setApprovalOpen(false)}
        open={approvalOpen}
        origin="https://staging.example.test"
        requestBudget={12}
        routes={["GET /account", "GET /objects/{object}", "HEAD /plans/current"]}
        scenarios={["Anonymous read", "Object ownership read", "Plan boundary read"]}
      />

      <DisclosureDialog
        byteCount={1840}
        completedScenarios={4}
        onClose={() => setDisclosureOpen(false)}
        onKeepLocal={() => setDisclosureOpen(false)}
        onPermit={() => setDisclosureOpen(false)}
        open={disclosureOpen}
        outcomeCounts={{ blocked: 2, observed: 1, inconclusive: 1 }}
      />
    </main>
  );
}
