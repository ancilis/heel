// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";


export type RunPhase = "running" | "stopping" | "complete" | "stopped" | "error";

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


const phaseLabel: Record<RunPhase, string> = {
  running: "Rehearsal running",
  stopping: "Stop requested",
  complete: "Rehearsal complete",
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
