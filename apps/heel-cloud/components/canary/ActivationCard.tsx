// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { CanaryAccessStep, type CanaryAccessState } from "./CanaryAccessStep";
import { EnvironmentStep, type EnvironmentState } from "./EnvironmentStep";
import { RehearsalStep, type RehearsalState } from "./RehearsalStep";
import { RunnerStep, type RunnerState } from "./RunnerStep";


export interface ActivationSnapshot {
  environment: EnvironmentState;
  runner: RunnerState;
  canaryAccess: CanaryAccessState;
  rehearsal: RehearsalState;
}

export interface ActivationCardProps {
  snapshot: ActivationSnapshot;
  completedSteps: number;
  environmentOrigin?: string;
  scenarioCount?: number;
  onReviewApproval?: () => void;
}


export function ActivationCard({ snapshot, completedSteps, environmentOrigin, scenarioCount = 0, onReviewApproval }: ActivationCardProps) {
  // A paired runner is never sent back to pairing: the cloud holds its active key even when it cannot see it running.
  const runnerPaired = snapshot.runner === "paired" || snapshot.runner === "online" || snapshot.runner === "offline";
  const firstIncomplete = snapshot.environment !== "verified"
    ? "verify staging"
    : !runnerPaired
      ? "pair runner"
      : snapshot.canaryAccess === "unauthorized"
        ? "authorize the paired runner below"
        : snapshot.canaryAccess !== "ready"
          ? "finish local setup on the runner machine"
          : snapshot.rehearsal === "complete"
            ? "review the result below and choose whether to share its redacted summary"
            : snapshot.rehearsal === "running"
              ? "follow the approved rehearsal or stop it"
              : "review the exact rehearsal";

  return (
    <section aria-label="Launch activation" className="activation-card">
      <header className="activation-card-header">
        <div>
          <p className="canary-kicker">First useful run · 15-minute target</p>
          <h2>Your staging rehearsal, end to end.</h2>
        </div>
        <div className="activation-meter" aria-label={`${completedSteps} of 4 setup steps complete`}>
          <span>{completedSteps}/4 ready</span>
          <div aria-hidden="true"><i style={{ width: `${completedSteps * 25}%` }} /></div>
        </div>
      </header>

      <div className="next-action" role="status">
        <span aria-hidden="true">↳</span>
        <p><strong>Next action: {firstIncomplete}.</strong> The rest stays locked until its prerequisite is confirmed.</p>
      </div>

      <ol className="activation-steps">
        <EnvironmentStep origin={environmentOrigin} state={snapshot.environment} />
        <RunnerStep state={snapshot.runner} />
        <CanaryAccessStep state={snapshot.canaryAccess} />
        <RehearsalStep onReviewApproval={onReviewApproval} scenarioCount={scenarioCount} state={snapshot.rehearsal} />
      </ol>
    </section>
  );
}
