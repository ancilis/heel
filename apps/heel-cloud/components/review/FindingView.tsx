// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type { ReviewFindingV1, ReviewRegressionV1 } from "../../lib/review-v1";


interface FindingViewProps {
  finding: ReviewFindingV1;
  regression: ReviewRegressionV1 | null;
}


export function FindingView({ finding, regression }: FindingViewProps) {
  return (
    <article className="finding-card" aria-labelledby={`finding-${finding.surface_id}`}>
      <div className="finding-meta">
        <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
        <span>{finding.reachable ? "Reachable in the model" : "Reachability unknown"}</span>
        <code>{finding.surface_id}</code>
      </div>
      <h3 id={`finding-${finding.surface_id}`}>{finding.risk.replaceAll("_", " ")}</h3>
      <dl className="evidence-list">
        <div>
          <dt>Why this capability needs investigation</dt>
          <dd>{finding.reason}</dd>
        </div>
        <div>
          <dt>Recommended control</dt>
          <dd>{finding.control}</dd>
        </div>
        {regression ? (
          <div>
            <dt>Suggested check to retain</dt>
            <dd>
              <code>{regression.name}</code>
              <span>{regression.scenario_hint}</span>
            </dd>
          </div>
        ) : null}
      </dl>
    </article>
  );
}
