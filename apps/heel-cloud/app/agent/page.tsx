// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type { Metadata } from "next";
import Link from "next/link";
import releaseManifest from "../../public/downloads/heel-open-core-manifest.json";


const WHEEL_SHA256 = releaseManifest.artifacts.find(
  ({ name }) => name === "heel_sim-1.2.0-py3-none-any.whl",
)?.sha256;

if (WHEEL_SHA256 === undefined) {
  throw new Error("verified Heel Agent wheel is missing from the release manifest");
}

const INSTALL_AGENT = `python3 -m venv .venv
.venv/bin/python -m pip install ./heel_sim-1.2.0-py3-none-any.whl`;

const MCP_CONFIGURATION = `{
  "mcpServers": {
    "heel": {
      "command": "/absolute/path/to/download-folder/.venv/bin/heel-mcp",
      "env": {
        "HEEL_HOME": "/absolute/path/to/private/heel-data",
        "HEEL_CLOUD_ORIGIN": "https://YOUR_HEEL_DOMAIN"
      }
    }
  }
}`;

const VERIFY_SERVER = `printf '%s\\n' \\
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"heel-quickstart-check","version":"1.0"}}}' \\
  '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \\
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \\
  | .venv/bin/heel-mcp`;


export const metadata: Metadata = {
  title: "Local MCP setup — Heel",
  description: "Download Heel Agent and connect its local stdio MCP server to an AI client.",
};


export default function AgentQuickstart() {
  return (
    <main className="quickstart-main">
      <header className="site-header">
        <Link className="brand" href="/" aria-label="Heel browser review">
          <span className="brand-mark" aria-hidden="true">H</span>
          <span>Heel</span>
        </Link>
        <span className="local-status">
          <span aria-hidden="true" />
          Local first · optional cloud continuity
        </span>
      </header>

      <article className="mcp-quickstart">
        <header className="quickstart-hero">
          <div>
            <p className="eyebrow">Heel Agent 1.2.0 · local MCP quickstart</p>
            <h1>Run Heel from your AI client.</h1>
            <p>
              Download the verified <code>heel-sim</code> wheel, then point any stdio-capable
              MCP client at the installed <code>heel-mcp</code> executable.
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
            <h2>Download and install Heel Agent</h2>
            <p>
              Heel&apos;s base MCP core is Apache-2.0 licensed and free to run locally. Download the
              exact first-party wheel below; the source archive is provided alongside it for inspection.
            </p>
            <div className="hero-actions" aria-label="Heel Agent downloads">
              <a
                className="button button-primary"
                download
                href="/downloads/heel_sim-1.2.0-py3-none-any.whl"
              >
                Download Heel Agent 1.2.0
              </a>
              <a
                className="button button-secondary"
                download
                href="/downloads/heel_sim-1.2.0.tar.gz"
              >
                Download source archive
              </a>
              <a href="/downloads/heel-open-core-manifest.json">View artifact manifest</a>
            </div>
            <p className="quickstart-note">
              Wheel SHA-256: <code>{WHEEL_SHA256}</code>
            </p>
            <p>
              PyPI publication is not yet available. Python 3.11 or newer is required.
              Secure project storage requires a POSIX filesystem with descriptor-relative operations
              and no-follow support. Windows is not currently supported for MCP local project storage.
            </p>
            <pre><code>{INSTALL_AGENT}</code></pre>
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

          <article className="quickstart-card">
            <p className="step-number">05 · Optional continuity</p>
            <h2>Keep minimized findings across devices</h2>
            <p>
              The local review works without an account or network connection. If you want a hosted
              dashboard and findings history, authorize this machine in your browser, choose a project,
              and let the agent prepare an immutable findings-only request.
            </p>
            <pre><code>{`.venv/bin/heel cloud --origin https://YOUR_HEEL_DOMAIN login
.venv/bin/heel cloud --origin https://YOUR_HEEL_DOMAIN projects`}</code></pre>
            <p>
              Your AI client can call <code>heel_sync_prepare</code>, then show you the preview and local
              status. Raw OpenAPI and review context stay on this machine; only the exact minimized
              findings envelope shown at approval is eligible to leave it.
            </p>
            <p>
              To send, leave the AI surface and run the interactive command below in your own terminal.
              Replace the references and digest with the values from the prepared record.
            </p>
            <pre><code>{`.venv/bin/heel cloud sync approve \\
  --workspace WORKSPACE_REF \\
  --project PROJECT_REF \\
  --digest REQUEST_DIGEST`}</code></pre>
            <p className="quickstart-note">
              MCP cannot log in, approve, send, retry, refresh, or revoke. Those authority-bearing
              actions remain human-only CLI or browser steps, and approval covers one exact digest for
              a short window.
            </p>
          </article>
        </section>
      </article>
    </main>
  );
}
