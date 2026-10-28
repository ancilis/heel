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
          Your product description stays in this browser
        </span>
      </header>

      <ReviewWorkspace initialReview={SAMPLE_REVIEW} />

      <section className="mcp-section" id="mcp" aria-labelledby="mcp-title">
        <p className="eyebrow">From product rules to repeatable checks</p>
        <h2 id="mcp-title">Investigate locally. Validate with a bounded rehearsal.</h2>
        <p>
          Use the Apache-2.0 <code>heel-sim</code> download and local
          {" "}<code>heel-mcp</code> workflow to investigate product rules and retain checks.
          No account or package registry is required. <a href="/agent">
            Open local MCP setup
          </a>.
        </p>
      </section>

      <section className="availability" id="availability" aria-labelledby="availability-title">
        <p className="eyebrow">Three ways normal capabilities become abuse</p>
        <h2 id="availability-title">What can a user gain—or make you pay for?</h2>
        <div className="price-grid">
          <article>
            <strong>Trials &amp; promotions</strong>
            <span>Eligibility and repeat value</span>
            <p>Could account changes or coordinated users claim benefits beyond the intended rule? Investigate eligibility assumptions.</p>
          </article>
          <article>
            <strong>Usage &amp; costs</strong>
            <span>Consumption and commercial limits</span>
            <p>Could normal features consume unmetered value or shift unexpected costs onto the product? Investigate accounting assumptions.</p>
          </article>
          <article>
            <strong>Exports &amp; automation</strong>
            <span>Access to paid product value</span>
            <p>Could users obtain export value their plan does not include? Validate one synthetic read entitlement and repeat after the fix.</p>
          </article>
        </div>
        <p className="quickstart-note">
          Browser review generates hypotheses. The local export reference validates one read boundary; trial eligibility and cumulative usage remain investigation areas.
        </p>
      </section>
    </main>
  );
}
