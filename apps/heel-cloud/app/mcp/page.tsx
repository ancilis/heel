// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type { Metadata } from "next";
import Link from "next/link";


const INSTALL_FROM_SOURCE = `cd /absolute/path/to/heel
python3 -m venv .venv
.venv/bin/python -m pip install .`;

const MCP_CONFIGURATION = `{
  "mcpServers": {
    "heel": {
      "command": "/absolute/path/to/heel/.venv/bin/heel-mcp",
      "env": {
        "HEEL_HOME": "/absolute/path/to/private/heel-data"
      }
    }
  }
}`;

const VERIFY_SERVER = `printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\\n' \\
  | /absolute/path/to/heel/.venv/bin/heel-mcp`;


export const metadata: Metadata = {
  title: "Local MCP setup — Heel",
  description: "Connect Heel's local stdio MCP server to an AI client from a licensed source checkout.",
};


export default function McpQuickstart() {
  return (
    <main className="quickstart-main">
      <header className="site-header">
        <Link className="brand" href="/" aria-label="Heel browser review">
          <span className="brand-mark" aria-hidden="true">H</span>
          <span>Heel</span>
        </Link>
        <span className="local-status">
          <span aria-hidden="true" />
          Local stdio · no Heel account
        </span>
      </header>

      <article className="mcp-quickstart">
        <header className="quickstart-hero">
          <div>
            <p className="eyebrow">MCP quickstart · source checkout</p>
            <h1>Run Heel from your AI client.</h1>
            <p>
              Install the <code>heel-sim</code> distribution from licensed source,
              then point any stdio-capable MCP client at the <code>heel-mcp</code> executable.
            </p>
          </div>
          <Link className="button button-secondary" href="/">Back to browser review</Link>
        </header>

        <aside className="quickstart-privacy" aria-label="Local privacy boundary">
          <strong>Know the boundary.</strong>
          <p>
            Heel&apos;s MCP review process runs on your machine, makes no analyzer network calls,
            and does not upload your OpenAPI to Heel. Your AI client is separate and may have
            its own data handling. Use a sanitized API description without credentials or customer data.
          </p>
        </aside>

        <section className="quickstart-steps" aria-label="Local MCP setup steps">
          <article className="quickstart-card">
            <p className="step-number">01 · Install</p>
            <h2>Install from your source checkout</h2>
            <p>
              <code>heel-sim</code> is not published to PyPI. Run these commands only inside
              the licensed source checkout supplied to you.
            </p>
            <pre><code>{INSTALL_FROM_SOURCE}</code></pre>
          </article>

          <article className="quickstart-card">
            <p className="step-number">02 · Configure</p>
            <h2>Add the local stdio server</h2>
            <p>
              Replace both absolute paths. <code>HEEL_HOME</code> must be a private local directory;
              reviewed results are saved below it only after a successful MCP review.
            </p>
            <pre><code>{MCP_CONFIGURATION}</code></pre>
          </article>

          <article className="quickstart-card">
            <p className="step-number">03 · Verify</p>
            <h2>Check the executable before connecting</h2>
            <p>
              This sends a standard JSON-RPC tool-list request over local stdin and prints the
              response to stdout. It does not start a hosted service.
            </p>
            <pre><code>{VERIFY_SERVER}</code></pre>
          </article>

          <article className="quickstart-card">
            <p className="step-number">04 · Review</p>
            <h2>Use the local review tool</h2>
            <p>
              Restart your AI client, choose <code>heel_review_openapi</code>, and provide a sanitized
              OpenAPI object. The tool returns a deterministic <code>heel.review.v1</code> envelope with
              findings, controls, questions, and suggested regressions.
            </p>
            <p className="quickstart-note">
              If your client does not use the <code>mcpServers</code> shape, enter the same absolute
              executable path and <code>HEEL_HOME</code> value in its local stdio MCP settings.
            </p>
          </article>
        </section>
      </article>
    </main>
  );
}
