// SPDX-License-Identifier: LicenseRef-Heel-Commercial

export type EnvironmentState = "unverified" | "checking" | "verified" | "expired" | "error";

export interface EnvironmentStepProps {
  state: EnvironmentState;
  origin?: string;
  recovery?: string;
}


const stateLabel: Record<EnvironmentState, string> = {
  unverified: "Next",
  checking: "Checking",
  verified: "Ready",
  expired: "Renew proof",
  error: "Needs attention",
};


export function EnvironmentStep({ state, origin, recovery }: EnvironmentStepProps) {
  return (
    <li className={`activation-step activation-step-${state}`} id="environment-setup">
      <article aria-labelledby="environment-step-title">
        <div className="step-index" aria-hidden="true">01</div>
        <div className="step-body">
          <div className="step-heading">
            <div><p className="canary-kicker">Ownership boundary</p><h2 id="environment-step-title">Verify staging</h2></div>
            <span className="step-state">{stateLabel[state]}</span>
          </div>
          {state === "unverified" ? <p className="step-recovery">Proof has not been checked yet. Add one exact HTTPS staging origin, then choose DNS or HTTPS-file proof.</p> : null}
          {state === "checking" ? <p className="step-recovery" role="status">Checking the selected proof. No product routes are contacted.</p> : null}
          {state === "verified" ? <p className="step-success"><code>{origin}</code> is verified and eligible for rehearsal setup.</p> : null}
          {state === "expired" ? <p className="step-recovery" role="alert">Verification expired. Refresh the same proof before approving another rehearsal.</p> : null}
          {state === "error" ? <p className="step-recovery" role="alert">{recovery ?? "Heel could not confirm proof. Check the exact record value and retry."}</p> : null}
          <div className="step-actions">
            {state !== "verified" && state !== "checking" ? <a className="button button-primary" href="#verify-origin">Verify staging now</a> : null}
            {state === "error" || state === "expired" ? <button className="text-button" type="button">Retry proof check</button> : null}
          </div>
        </div>
      </article>
    </li>
  );
}
