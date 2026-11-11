// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { RUNNER_RC2_CLI } from "./RunnerPairingCard";

/**
 * `unauthorized`: a runner is paired but holds no active authorization for this verified environment.
 * `authorized`: it does; its local credentials are not observable here, so this step is not complete until a plan.
 */
export type CanaryAccessState = "locked" | "unauthorized" | "authorized" | "missing" | "partial" | "ready" | "error";

export interface CanaryAccessStepProps {
  state: CanaryAccessState;
  roles?: readonly string[];
  recovery?: string;
}


const stateLabel: Record<CanaryAccessState, string> = {
  locked: "After pairing",
  unauthorized: "Authorize below",
  authorized: "Finish on runner",
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
          {state === "locked" ? <p className="step-recovery">Add two isolated test identities on the runner machine after the runner is paired. Heel Cloud sees role names only.</p> : null}
          {state === "unauthorized" ? <p className="step-recovery">Authorize the paired runner for this verified environment below. Authorization lets that runner claim this target; it does not add or reveal any credential.</p> : null}
          {state === "authorized" ? <div className="step-recovery">
            <p>The paired runner is authorized for this verified environment. Test credentials are added only on the runner machine; Heel Cloud never receives them and cannot confirm them here.</p>
            <ol>
              <li>Keep <code>{`${RUNNER_RC2_CLI} runner serve`}</code> running so the runner claims this authorization.</li>
              <li>Add one staging-only credential per plan: <code>{`${RUNNER_RC2_CLI} runner credential add --role lower_plan --plan-label free --profile bearer --label "free canary" --backend keychain`}</code>, then <code>{`${RUNNER_RC2_CLI} runner credential add --role higher_plan --plan-label pro --profile bearer --label "pro canary" --backend keychain`}</code> (on Linux, <code>--backend secret-service</code>).</li>
              <li>Import your read routes: <code>{`${RUNNER_RC2_CLI} runner import-openapi ./openapi.json`}</code>.</li>
              <li>Check <code>{`${RUNNER_RC2_CLI} runner status`}</code> on that machine; it reports <code>access.ready</code> when local access is complete.</li>
            </ol>
            <p>If the runner submits a valid signed plan, it appears here for review; nothing runs unless you approve it.</p>
          </div> : null}
          {state === "missing" ? <p className="step-recovery">Add two staging-only identities on the runner machine with <code>{`${RUNNER_RC2_CLI} runner credential add`}</code>, one per plan role.</p> : null}
          {state === "partial" ? <p className="step-recovery" role="alert">One required role is still missing. Add the second isolated identity with <code>{`${RUNNER_RC2_CLI} runner credential add`}</code> before preparing the plan.</p> : null}
          {state === "ready" ? <p className="step-success">{roles.length > 0
            ? `${roles.length} local roles are mapped and eligible for the selected scenarios.`
            : "The signed runner plan confirms its required local role mappings."}</p> : null}
          {state === "error" ? <p className="step-recovery" role="alert">{recovery ?? `Local access check failed. Run ${RUNNER_RC2_CLI} runner status on the runner machine and repair the named role.`}</p> : null}
        </div>
      </article>
    </li>
  );
}
