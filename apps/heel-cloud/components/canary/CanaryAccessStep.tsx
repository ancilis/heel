// SPDX-License-Identifier: LicenseRef-Heel-Commercial

export type CanaryAccessState = "locked" | "missing" | "partial" | "ready" | "error";

export interface CanaryAccessStepProps {
  state: CanaryAccessState;
  roles?: readonly string[];
  recovery?: string;
}


const stateLabel: Record<CanaryAccessState, string> = {
  locked: "After pairing",
  missing: "Add locally",
  partial: "One role missing",
  ready: "Ready",
  error: "Needs attention",
};


export function CanaryAccessStep({ state, roles = [], recovery }: CanaryAccessStepProps) {
  return (
    <li className={`activation-step activation-step-${state}`}>
      <article aria-labelledby="canary-access-step-title">
        <div className="step-index" aria-hidden="true">03</div>
        <div className="step-body">
          <div className="step-heading">
            <div><p className="canary-kicker">Isolated test access</p><h2 id="canary-access-step-title">Add canary access</h2></div>
            <span className="step-state">{stateLabel[state]}</span>
          </div>
          {state === "locked" ? <p className="step-recovery">Add two isolated test identities on this machine after the runner is paired. Heel Cloud sees role names only.</p> : null}
          {state === "missing" ? <p className="step-recovery">Create two staging-only identities, then save each as a local role in the runner companion.</p> : null}
          {state === "partial" ? <p className="step-recovery" role="alert">One required role is still missing. Add the second isolated identity before preparing the plan.</p> : null}
          {state === "ready" ? <p className="step-success">{roles.length > 0
            ? `${roles.length} local roles are mapped and eligible for the selected scenarios.`
            : "The signed runner plan confirms its required local role mappings."}</p> : null}
          {state === "error" ? <p className="step-recovery" role="alert">{recovery ?? "Local access check failed. Reopen the companion and repair the named role."}</p> : null}
          <div className="step-actions">
            {state === "missing" || state === "partial" || state === "error" ? <a className="button button-primary" href="/runner#canary-access">Add access locally</a> : null}
          </div>
        </div>
      </article>
    </li>
  );
}
