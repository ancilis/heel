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
          Runs here, not on our server
        </span>
      </header>

      <ReviewWorkspace initialReview={SAMPLE_REVIEW} />

      <section className="mcp-section" id="mcp" aria-labelledby="mcp-title">
        <p className="eyebrow">Agent-first when you want it</p>
        <h2 id="mcp-title">The same review from your local AI surface.</h2>
        <p>
          Heel&apos;s current MCP server runs over local stdio. Use the browser now,
          or install <code>heel-mcp</code> for an agent-controlled workflow on your machine.
        </p>
      </section>

      <section className="availability" id="availability" aria-labelledby="availability-title">
        <p className="eyebrow">Clear boundary, clear price</p>
        <h2 id="availability-title">Local browser, CLI, and base MCP stay free.</h2>
        <p>Heel Cloud paid beta starts at $49/month. Collaboration capabilities are coming later.</p>
      </section>
    </main>
  );
}
