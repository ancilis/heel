// SPDX-License-Identifier: LicenseRef-Heel-Commercial

export type RunnerState = "locked" | "unpaired" | "pairing" | "online" | "offline" | "error";

export interface RunnerStepProps {
  state: RunnerState;
  version?: string;
  lastSeen?: string;
  recovery?: string;
}


const stateLabel: Record<RunnerState, string> = {
  locked: "After verification",
  unpaired: "Ready to pair",
  pairing: "Awaiting approval",
  online: "Online",
  offline: "Offline",
  error: "Needs attention",
};


export function RunnerStep({ state, version, lastSeen, recovery }: RunnerStepProps) {
  return (
    <li className={`activation-step activation-step-${state}`}>
      <article aria-labelledby="runner-step-title">
        <div className="step-index" aria-hidden="true">02</div>
        <div className="step-body">
          <div className="step-heading">
            <div><p className="canary-kicker">Local execution</p><h2 id="runner-step-title">Pair runner</h2></div>
            <span className="step-state">{stateLabel[state]}</span>
          </div>
          {state === "locked" ? <p className="step-recovery">Runner pairing starts after verification so it can bind to the exact staging environment.</p> : null}
          {state === "unpaired" ? <p className="step-recovery">Start the local runner, compare its phrase and fingerprint here, then approve it in this browser.</p> : null}
          {state === "pairing" ? <p className="step-recovery" role="status">Waiting for browser approval. Pairing alone cannot start a rehearsal.</p> : null}
          {state === "online" ? <p className="step-success">Runner {version ?? "compatible"} is online{lastSeen ? ` · seen ${lastSeen}` : ""}.</p> : null}
          {state === "offline" ? <p className="step-recovery" role="alert">Runner is offline. Restart it on the paired machine; this page will keep the setup intact.</p> : null}
          {state === "error" ? <p className="step-recovery" role="alert">{recovery ?? "Pairing could not finish. Confirm the displayed phrase, then start a fresh request."}</p> : null}
          <div className="step-actions">
            {state === "unpaired" || state === "error" ? <a className="button button-primary" href="/runner">Open pairing guide</a> : null}
            {state === "offline" ? <button className="button button-secondary" type="button">Check runner again</button> : null}
          </div>
        </div>
      </article>
    </li>
  );
}
