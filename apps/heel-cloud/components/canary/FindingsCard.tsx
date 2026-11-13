// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type {
  CanaryAssessmentOutcome,
  CanaryFindingsProjection,
  CanaryScenarioResult,
  FrozenScenarioBinding,
} from "../../lib/canary-api";


export interface FindingsCardProps {
  /** The synchronized projection exactly as the strict `getFindings` parser returned it. */
  findings: Readonly<CanaryFindingsProjection>;
  /** Bindings frozen before approval for this run; joined only on the exact tuple and both plan digests. */
  frozenBindings?: readonly FrozenScenarioBinding[];
}

export const BOUND_OBJECTIVE_CAVEAT = "The library objective beyond this check remains inferred; it was not tested.";

/** A frozen row stands for a result only when its action tuple and both signed-plan digests are identical. */
export function boundEntriesFor(
  findings: Readonly<CanaryFindingsProjection>,
  item: Readonly<CanaryScenarioResult>,
  frozen: readonly FrozenScenarioBinding[],
): FrozenScenarioBinding[] {
  return frozen.filter((row) => row.catalogScenarioId === item.scenario_id
    && row.method === item.route.method
    && row.routeTemplate === item.route.route_template
    && row.projectionDigest === findings.approval_projection_digest
    && row.manifestDigest === findings.manifest_digest);
}


const OUTCOME_LABELS: Readonly<Record<CanaryAssessmentOutcome, string>> = Object.freeze({
  blocked: "Held",
  observed: "Crossed",
  inconclusive: "Unclear",
});


/**
 * Renders only what the runner signed and the control plane returned. Nothing is derived, ranked or summarized here:
 * a scenario without a server finding shows none, observations are the status code and body shape the runner
 * recorded (never content), and evidence appears only as opaque references that resolve on the runner machine.
 */
export function FindingsCard({ findings, frozenBindings = [] }: FindingsCardProps) {
  return (
    <section aria-labelledby="findings-title" className="runner-recovery findings-card">
      <p className="canary-kicker">Shared redacted summary</p>
      <h2 id="findings-title">Rehearsal result</h2>
      <dl>
        <div><dt>Outcome</dt><dd>{OUTCOME_LABELS[findings.assessment_outcome]} ({findings.assessment_outcome})</dd></div>
        <div><dt>Redactions</dt><dd>{findings.redaction_count}</dd></div>
        <div><dt>Summary digest</dt><dd><code>{findings.projection_digest}</code></dd></div>
      </dl>
      <ol aria-label="Scenario results">
        {findings.scenario_results.map((item) => (
          <li key={item.scenario_id}>
            <h3>{item.route.method} {item.route.route_template}</h3>
            <p>Executed check: {item.scenario_id} {item.route.method} {item.route.route_template}</p>
            {(() => {
              const bound = boundEntriesFor(findings, item, frozenBindings);
              return bound.length === 0
                ? <p>No bound library entry for this run</p>
                : <>
                  <p>Stands for: {bound.map((row) => row.revision === null
                    ? row.libraryScenarioId
                    : `${row.libraryScenarioId} (revision ${row.revision})`).join(", ")}</p>
                  <p>{BOUND_OBJECTIVE_CAVEAT}</p>
                </>;
            })()}
            <dl>
              <div><dt>Scenario</dt><dd>{item.scenario_id}</dd></div>
              <div><dt>Scenario outcome</dt><dd>{OUTCOME_LABELS[item.assessment_outcome]} ({item.assessment_outcome})</dd></div>
            </dl>
            {item.finding === null
              ? <p>No finding was reported for this scenario.</p>
              : <article aria-label={`Finding: ${item.finding.title}`}>
                <h4>{item.finding.title}</h4>
                <dl>
                  <div><dt>Confidence</dt><dd>{item.finding.confidence}</dd></div>
                  <div><dt>Recommended control</dt><dd>{item.finding.recommended_control}</dd></div>
                  <div><dt>Why it is reachable</dt><dd>{item.finding.reachability_rationale}</dd></div>
                  <div><dt>Regression to keep</dt><dd>{item.finding.regression_suggestion}</dd></div>
                </dl>
              </article>}
            {item.observations.length > 0 ? <>
              <p>Recorded responses (status and body shape only, no content):</p>
              <ul aria-label="Recorded responses">
                {item.observations.map((observation) => (
                  <li key={observation.semantic_role}>
                    {observation.semantic_role}: {observation.status_code} · {observation.body_shape}
                    {observation.truncation_state === "truncated" ? " · truncated" : ""}
                  </li>
                ))}
              </ul>
            </> : null}
            {item.local_evidence_refs.length > 0 ? <>
              <p>Local evidence references (the evidence itself stays on the runner machine):</p>
              <ul aria-label="Local evidence references">
                {item.local_evidence_refs.map((ref) => <li key={ref}><code>{ref}</code></li>)}
              </ul>
            </> : null}
          </li>
        ))}
      </ol>
    </section>
  );
}
