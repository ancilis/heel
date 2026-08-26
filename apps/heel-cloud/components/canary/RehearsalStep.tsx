// SPDX-License-Identifier: LicenseRef-Heel-Commercial

export type RehearsalState = "locked" | "ready" | "awaiting_approval" | "running" | "complete" | "error";

export interface RehearsalStepProps {
  state: RehearsalState;
  scenarioCount?: number;
  recovery?: string;
  onReviewApproval?: () => void;
}


const stateLabel: Record<RehearsalState, string> = {
  locked: "Finish setup",
  ready: "Ready to review",
  awaiting_approval: "Approval required",
  running: "In progress",
  complete: "Complete",
  error: "Needs attention",
};


export function RehearsalStep({ state, scenarioCount = 0, recovery, onReviewApproval }: RehearsalStepProps) {
  return (
    <li className={`activation-step activation-step-${state}`}>
      <article aria-labelledby="rehearsal-step-title">
        <div className="step-index" aria-hidden="true">04</div>
        <div className="step-body">
          <div className="step-heading">
            <div><p className="canary-kicker">Bounded execution</p><h2 id="rehearsal-step-title">Run first rehearsal</h2></div>
            <span className="step-state">{stateLabel[state]}</span>
          </div>
          {state === "locked" ? <p className="step-recovery">Complete the first three steps to prepare a read-only plan with fixed routes, time, request, and egress ceilings.</p> : null}
          {state === "ready" || state === "awaiting_approval" ? <p className="step-recovery">{scenarioCount} safe scenarios are ready. Review the immutable plan before anything runs.</p> : null}
          {state === "running" ? <p className="step-success" role="status">The paired runner is executing the approved plan. You can stop it at any time.</p> : null}
          {state === "complete" ? <p className="step-success">Operational receipt complete. Open the detailed result on the runner machine.</p> : null}
          {state === "error" ? <p className="step-recovery" role="alert">{recovery ?? "The rehearsal did not start. No additional action was sent; review setup and retry."}</p> : null}
          <div className="step-actions">
            {(state === "ready" || state === "awaiting_approval") && onReviewApproval ? <button className="button button-primary"
              onClick={onReviewApproval} type="button">Review exact plan</button> : null}
          </div>
        </div>
      </article>
    </li>
  );
}
