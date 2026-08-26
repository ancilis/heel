// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type { HeelCloudReviewSummary } from "../../lib/heel-cloud-api";


function createdLabel(seconds: number): string {
  try {
    return new Intl.DateTimeFormat("en", {
      dateStyle: "medium",
      timeStyle: "short",
      timeZone: "UTC",
    }).format(new Date(seconds * 1_000));
  } catch {
    return "Recorded in Heel Cloud";
  }
}


export function ProjectHistory({
  projectName,
  reviews,
  loading = false,
  onRefresh,
}: {
  projectName: string;
  reviews: HeelCloudReviewSummary[];
  loading?: boolean;
  onRefresh(): void;
}) {
  return (
    <section className="cloud-history" aria-labelledby="cloud-history-title">
      <div className="history-heading">
        <div>
          <p className="eyebrow">Hosted findings continuity</p>
          <h3 id="cloud-history-title">{projectName}</h3>
        </div>
        <button className="text-button" type="button" onClick={onRefresh} disabled={loading}>
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </div>
      <p className="history-source-note">
        These are privacy-minimized model findings, not proof of a production vulnerability or reachability.
      </p>
      {reviews.length === 0 ? <p>No findings-only reviews synced to this project yet.</p> : (
        <ul className="cloud-history-list">
          {reviews.map((review) => (
            <li key={review.syncedReviewId}>
              <div>
                <span className={`gate gate-${review.gateStatus}`}>{review.gateStatus}</span>
                <strong>{review.findingsCount} locally flagged finding{review.findingsCount === 1 ? "" : "s"}</strong>
              </div>
              <span>
                {review.blockersCount} blocker{review.blockersCount === 1 ? "" : "s"} · {createdLabel(review.createdAt)} UTC
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
