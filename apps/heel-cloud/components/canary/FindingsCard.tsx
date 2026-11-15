// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type {
  AnyCanaryFindingsProjection,
  CanaryAssessmentOutcome,
  CanaryConfiguredFindingsProjection,
  CanaryConfiguredResult,
  CanaryFindingsProjection,
  CanaryScenarioResult,
  FrozenScenarioBinding,
} from "../../lib/canary-api";
import { CONTAINMENT_ADVICE, reasonText } from "../../lib/live-test-text";


export interface FindingsCardProps {
  /** The synchronized projection exactly as the strict `getFindings` parser returned it. */
  findings: Readonly<AnyCanaryFindingsProjection>;
  /** Bindings frozen before approval for this run; joined only on the exact tuple and both plan digests. */
  frozenBindings?: readonly FrozenScenarioBinding[];
  /** Configured runs only: request a fresh, separately approved replay of one observed instance. */
  onReplay?: (testInstanceId: string) => void;
  replayBusy?: boolean;
}

export const INCONCLUSIVE_NOTE = "Inconclusive establishes neither a pass nor a failure: no verdict was reached for this check.";

function ContainmentNotes({ codes }: { codes: readonly string[] }) {
  const relevant = codes.filter((code) => !["admitted", "action_started", "action_completed"].includes(code));
  if (relevant.length === 0) return null;
  return <ul aria-label="Containment notes">{relevant.map((code) => <li key={code}><code>{code}</code>: {CONTAINMENT_ADVICE[code] ?? "Recorded by the runner."}</li>)}</ul>;
}

function EvidenceRefs({ refs, runId }: { refs: readonly string[]; runId: string }) {
  if (refs.length === 0) return null;
  return <>
    <p>Local evidence references. The raw responses stay on the runner machine; inspect them there with <code>heel runner findings --run {runId}</code>.</p>
    <ul aria-label="Local evidence references">{refs.map((ref) => <li key={ref}><code>{ref}</code></li>)}</ul>
  </>;
}

function ConfiguredResultItem({ item, runId, onReplay, replayBusy }: {
  item: Readonly<CanaryConfiguredResult>; runId: string; onReplay?: (id: string) => void; replayBusy: boolean;
}) {
  return (
    <li>
      <h3><code>{item.source.source_scenario_id}</code> revision {item.source.source_revision}</h3>
      <dl>
        <div><dt>Route</dt><dd><code>{item.route.method} {item.route.route_template}</code></dd></div>
        <div><dt>Condition kind</dt><dd>{item.condition_kind === "json_field_present" ? "Field is present" : "Value equals your local value"}</dd></div>
        <div><dt>Outcome</dt><dd>{OUTCOME_LABELS[item.assessment_outcome]} ({item.assessment_outcome})</dd></div>
        <div><dt>Reason</dt><dd><code>{item.reason}</code>: {reasonText(item.reason)}</dd></div>
        <div><dt>Control read</dt><dd>{item.positive_control === "established" ? "succeeded" : "did not establish a baseline"}</dd></div>
        <div><dt>Condition for the restricted role</dt><dd>{item.restricted_condition === "not_observed" ? "not observed" : item.restricted_condition}</dd></div>
      </dl>
      {item.assessment_outcome === "inconclusive" ? <p>{INCONCLUSIVE_NOTE}</p> : null}
      <p>This result covers only the configured field condition on this route; it does not test the whole scenario objective.</p>
      {item.finding !== null ? <article aria-label={`Finding: ${item.finding.title}`}>
        <h4>{item.finding.title}</h4>
        <dl>
          <div><dt>Recommended control</dt><dd>{item.finding.recommended_control}</dd></div>
          <div><dt>Regression to keep</dt><dd>{item.finding.regression_suggestion}</dd></div>
        </dl>
      </article> : null}
      {item.observations.length > 0 ? <ul aria-label="Recorded responses">
        {item.observations.map((observation) => <li key={observation.action_ordinal}>
          {observation.semantic_role}: {observation.status_code} · {observation.body_shape}
          {observation.truncation_state === "truncated" ? " · truncated" : ""}
        </li>)}
      </ul> : null}
      <ContainmentNotes codes={item.containment_codes} />
      <EvidenceRefs refs={item.local_evidence_refs} runId={runId} />
      {item.assessment_outcome === "observed" && onReplay ? <p>
        <button className="button button-secondary" disabled={replayBusy} onClick={() => onReplay(item.test_instance_id)} type="button">
          Save and replay this exact test
        </button>{" "}
        Replays the frozen condition and the same local values on your runner after you fix the target. It needs a new dry run and approval.
      </p> : null}
    </li>
  );
}

function ConfiguredFindings({ findings, onReplay, replayBusy }: {
  findings: Readonly<CanaryConfiguredFindingsProjection>; onReplay?: (id: string) => void; replayBusy: boolean;
}) {
  return (
    <section aria-labelledby="findings-title" className="runner-recovery findings-card">
      <p className="canary-kicker">Shared redacted summary</p>
      <h2 id="findings-title">Configured test result</h2>
      <dl>
        <div><dt>Overall</dt><dd>{OUTCOME_LABELS[findings.assessment_outcome]} ({findings.assessment_outcome})</dd></div>
        <div><dt>Redactions</dt><dd>{findings.redaction_count}</dd></div>
        <div><dt>Summary digest</dt><dd><code>{findings.projection_digest}</code></dd></div>
      </dl>
      <ol aria-label="Configured test results">
        {findings.test_results.map((item) => <ConfiguredResultItem key={item.test_instance_id} item={item}
          onReplay={onReplay} replayBusy={replayBusy} runId={findings.run_id} />)}
      </ol>
    </section>
  );
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
export function FindingsCard({ findings: any, frozenBindings = [], onReplay, replayBusy = false }: FindingsCardProps) {
  if (any.schema_version === "heel.canary-findings-projection.v2") {
    return <ConfiguredFindings findings={any} onReplay={onReplay} replayBusy={replayBusy} />;
  }
  const findings: Readonly<CanaryFindingsProjection> = any;
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
              ? <p>No finding was reported for this scenario.{item.assessment_outcome === "inconclusive" ? ` ${INCONCLUSIVE_NOTE}` : ""}</p>
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
            <ContainmentNotes codes={item.containment_codes} />
            <EvidenceRefs refs={item.local_evidence_refs} runId={findings.run_id} />
          </li>
        ))}
      </ol>
    </section>
  );
}
