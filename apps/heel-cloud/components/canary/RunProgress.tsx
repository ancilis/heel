// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";


/** `incomplete`: terminal, but the runner-signed disposition is not `completed` (for example `cloud_disconnected`). */
export type RunPhase = "running" | "stopping" | "complete" | "incomplete" | "stopped" | "error";

export interface RunProgressProps {
  phase: RunPhase;
  completedScenarios: number;
  totalScenarios: number;
  requestsUsed: number;
  requestBudget: number;
  secondsRemaining: number;
  recovery?: string;
  localResultUrl?: string;
  onStop?: () => void;
  onRetry?: () => void;
}


function safeLoopbackUrl(value: string | undefined): string | null {
  if (value === undefined) return null;
  try {
    const parsed = new URL(value);
    const loopback = parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost" || parsed.hostname === "[::1]";
    return parsed.protocol === "http:" && loopback ? parsed.href : null;
  } catch {
    return null;
  }
}


/** Only a terminal run the runner signed as `completed` is complete; every other disposition is shown as incomplete. */
export function terminalRunPhase(disposition: string | null): RunPhase {
  return disposition === "completed" ? "complete" : disposition === "stopped" ? "stopped" : "incomplete";
}


const ERROR_CATEGORY_TEXT: Readonly<Record<string, string>> = Object.freeze({
  cloud_disconnected: "the runner could not keep confirming this run with Heel Cloud while it ran",
  target_unavailable: "the target did not answer as required",
  credential_unavailable: "a local credential or value was unavailable on the runner",
  budget_exhausted: "the run reached its request or time ceiling",
  containment_rejected: "the runner's containment refused an action",
  version_mismatch: "the runner and Heel Cloud versions did not match",
  proof_expired: "the target's ownership proof expired",
  dns_changed: "the target's DNS answer changed during the run",
  runner_fault: "the runner reported an internal fault",
  platform_fault: "Heel Cloud reported an internal fault",
});

/** Causes where the runner itself stopped talking to Heel Cloud; only these are addressed by restarting serve once. */
const RESTART_CAUSES: ReadonlySet<string> = new Set(["cloud_disconnected", "runner_fault"]);

/**
 * Explains a terminal run that did not complete, from the run's signed operational status alone (disposition and
 * error category). It never states outcomes or findings: those stay on the runner unless the customer shares them.
 * A missing disposition is reported as unknown, never as something the runner signed.
 */
export function incompleteRunExplanation(disposition: string | null, errorCategory: string, cli: string): string {
  const reason = ERROR_CATEGORY_TEXT[errorCategory];
  const cause = errorCategory !== "none" ? ` (${errorCategory}${reason ? `: ${reason}` : ""})` : "";
  const status = disposition === null
    ? `Heel Cloud has no runner-signed disposition for this ended rehearsal${cause}`
    : `The runner signed this rehearsal as ${disposition}${cause}`;
  const next = RESTART_CAUSES.has(errorCategory)
    ? `On the runner machine, run ${cli} runner status. If ${cli} runner serve has stopped, start it once more with the same HEEL_HOME; `
      + "if it stops again, do not loop: keep this run and report it (see Feedback in the guide). Then request a fresh dry run."
    : `On the runner machine, run ${cli} runner status and follow the guide's recovery for what it reports before you request `
      + "a fresh dry run; restarting serve alone does not fix every cause.";
  return `${status}. It did not finish cleanly, so it is not a completed rehearsal; do not rely on its test outcomes either way. ${next}`;
}


const phaseLabel: Record<RunPhase, string> = {
  running: "Rehearsal running",
  stopping: "Stop requested",
  complete: "Rehearsal complete",
  incomplete: "Rehearsal incomplete",
  stopped: "Rehearsal stopped",
  error: "Status needs attention",
};


export function RunProgress({
  phase,
  completedScenarios,
  totalScenarios,
  requestsUsed,
  requestBudget,
  secondsRemaining,
  recovery,
  localResultUrl,
  onStop,
  onRetry,
}: RunProgressProps) {
  const progress = totalScenarios === 0 ? 0 : Math.round((completedScenarios / totalScenarios) * 100);
  const localUrl = safeLoopbackUrl(localResultUrl);

  return (
    <section aria-label="Rehearsal progress" className={`run-progress run-progress-${phase}`}>
      <div className="run-progress-heading">
        <div>
          <p className="canary-kicker">Operational status only</p>
          <h3>{phaseLabel[phase]}</h3>
        </div>
        <span className="run-phase-pill">{phase}</span>
      </div>

      <div
        aria-label={`${completedScenarios} of ${totalScenarios} scenarios complete`}
        aria-valuemax={totalScenarios}
        aria-valuemin={0}
        aria-valuenow={completedScenarios}
        className="run-progress-track"
        role="progressbar"
      >
        <span style={{ width: `${progress}%` }} />
      </div>

      <dl className="run-metrics">
        <div><dt>Scenarios</dt><dd>{completedScenarios} / {totalScenarios}</dd></div>
        <div><dt>Budget</dt><dd>{requestsUsed} / {requestBudget} requests</dd></div>
        <div><dt>Time remaining</dt><dd>{secondsRemaining}s</dd></div>
      </dl>

      {recovery ? <p className="run-recovery" role="alert">{recovery}</p> : null}
      <div className="run-actions">
        {phase === "running" && onStop ? <button className="button stop-button" onClick={onStop}
          type="button">Stop rehearsal</button> : null}
        {phase === "error" && onRetry ? <button className="button button-secondary" onClick={onRetry}
          type="button">Retry status</button> : null}
        {phase === "complete" && localUrl ? <a className="button button-primary" href={localUrl}
          rel="noreferrer" target="_blank">Open local result</a> : null}
      </div>
    </section>
  );
}
