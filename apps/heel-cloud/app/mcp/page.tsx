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

const VERIFY_SERVER = `printf '%s\\n' \\
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"heel-quickstart-check","version":"1.0"}}}' \\
  '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \\
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \\
  | /absolute/path/to/heel/.venv/bin/heel-mcp`;


export const metadata: Metadata = {
  title: "Local MCP setup — Heel",
  description: "Connect Heel's local stdio MCP server to an AI client from an official release source package.",
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
            <p className="eyebrow">MCP quickstart · release source package</p>
            <h1>Run Heel from your AI client.</h1>
            <p>
              Install the <code>heel-sim</code> distribution from the official release source package,
              then point any stdio-capable MCP client at the <code>heel-mcp</code> executable.
            </p>
          </div>
          <Link className="button button-secondary" href="/">Back to browser review</Link>
        </header>

        <aside className="quickstart-privacy" aria-label="Local privacy boundary">
          <strong>Know the boundary.</strong>
          <p>
            Heel&apos;s MCP review process runs on your machine, makes no analyzer network calls,
            and does not upload your OpenAPI to Heel. Your AI client is separate from Heel. The AI
            client or model provider may receive or upload the OpenAPI before invoking local Heel.
            Heel cannot enforce that client-provider boundary. Check the client&apos;s data handling and
            use a sanitized API description without credentials or customer data.
          </p>
        </aside>

        <section className="quickstart-steps" aria-label="Local MCP setup steps">
          <article className="quickstart-card">
            <p className="step-number">01 · Install</p>
            <h2>Install from the release source</h2>
            <p>
              Heel&apos;s base MCP core is Apache-2.0 licensed and free to run locally. The current
              MCP release source package is not yet available as a public download. Do not use the
              public main branch as a substitute; run these commands only after obtaining and extracting
              the official release package.
            </p>
            <p>
              <code>heel-sim</code> is not published to PyPI. Python 3.11 or newer is required.
              Secure project storage requires a POSIX filesystem with descriptor-relative operations
              and no-follow support. Windows is not currently supported for MCP local project storage.
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
              This performs the required initialize, initialized-notification, and tool-list sequence
              over local stdin, then prints the two JSON-RPC responses. It does not start a hosted service.
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
            <p className="quickstart-note">
              All exposed MCP tools remain constrained. Static review tools stay local. Target execution
              requires a pre-existing, human-created signed scope. Heel MCP exposes no tool to create,
              widen, or relax a scope. Scope creation is an out-of-band CLI action; do not grant
              agent-controlled shells access to that CLI, HEEL_HOME, or the signing key.
            </p>
          </article>
        </section>
      </article>
    </main>
  );
}
