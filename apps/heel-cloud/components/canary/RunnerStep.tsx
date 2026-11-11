// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { RUNNER_RC3_CLI } from "./RunnerPairingCard";

/** `paired`: the workspace holds an active runner key; Heel Cloud cannot see whether that runner is running now. */
export type RunnerState = "locked" | "unpaired" | "pairing" | "paired" | "online" | "offline" | "error";

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
  paired: "Paired",
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
          {state === "unpaired" ? <p className="step-recovery">A workspace owner or admin can create a one-time invitation on this page, run <code>{`${RUNNER_RC3_CLI} runner pair`}</code> on the runner machine, compare its six words and fingerprint here, then approve it in this browser.</p> : null}
          {state === "pairing" ? <p className="step-recovery" role="status">Waiting for browser approval. Pairing alone cannot start a rehearsal.</p> : null}
          {state === "paired" ? <p className="step-success">Runner paired with an active key. This page cannot see whether it is running right now: keep <code>{`${RUNNER_RC3_CLI} runner serve`}</code> running on that machine and check it with <code>{`${RUNNER_RC3_CLI} runner status`}</code>.</p> : null}
          {state === "online" ? <p className="step-success">Runner {version ?? "compatible"} is online{lastSeen ? ` · seen ${lastSeen}` : ""}.</p> : null}
          {state === "offline" ? <p className="step-recovery" role="alert">Runner is offline. Restart <code>{`${RUNNER_RC3_CLI} runner serve`}</code> on the paired machine; the pairing and setup stay intact.</p> : null}
          {state === "error" ? <p className="step-recovery" role="alert">{recovery ?? "Pairing could not finish. Confirm the displayed phrase, then start a fresh request."}</p> : null}
          <div className="step-actions">
            {state === "offline" ? <button className="button button-secondary" type="button">Check runner again</button> : null}
          </div>
        </div>
      </article>
    </li>
  );
}
