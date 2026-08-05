// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { ReviewWorkspace } from "../components/review/ReviewWorkspace";
import { SAMPLE_REVIEW } from "../lib/sample-openapi";


export default function Home() {
  return (
    <main id="top">
      <header className="site-header">
        <a className="brand" href="#top" aria-label="Heel home">
          <span className="brand-mark" aria-hidden="true">H</span>
          <span>Heel</span>
        </a>
        <span className="local-status">
          <span aria-hidden="true" />
          Source analysis runs here, not on our server
        </span>
      </header>

      <ReviewWorkspace initialReview={SAMPLE_REVIEW} />

      <section className="mcp-section" id="mcp" aria-labelledby="mcp-title">
        <p className="eyebrow">Agent-first when you want it</p>
        <h2 id="mcp-title">The same review from your local AI surface.</h2>
        <p>
          The first-party Apache-2.0 <code>heel-sim</code> download includes the
          {" "}<code>heel-mcp</code> executable for an agent-controlled local stdio workflow.
          No account or package registry is required. <a href="/agent">
            Open local MCP setup
          </a>.
        </p>
      </section>

      <section className="availability" id="availability" aria-labelledby="availability-title">
        <p className="eyebrow">Start local · add continuity when useful</p>
        <h2 id="availability-title">Useful before signup. Predictable after.</h2>
        <div className="price-grid">
          <article>
            <strong>Free</strong>
            <span>$0 · no card</span>
            <p>Browser, CLI, base MCP, and 3 findings-only cloud reviews each month.</p>
          </article>
          <article>
            <strong>Pro</strong>
            <span>$49/month</span>
            <p>25 synced reviews, 3 seats, exports, and email support.</p>
          </article>
          <article>
            <strong>Team</strong>
            <span>$199/month</span>
            <p>100 synced reviews, 10 seats, role controls, and priority support.</p>
          </article>
        </div>
      </section>
    </main>
  );
}
