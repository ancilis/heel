// SPDX-License-Identifier: LicenseRef-Heel-Commercial
"use client";

import { useState } from "react";
import Link from "next/link";

export default function Runner() {
  const [summary, setSummary] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function inspect(file: File | undefined) {
    setError(null);
    setSummary(null);
    if (!file) return;
    try {
      if (file.size > 128 * 1024) throw new Error();
      const report: unknown = JSON.parse(await file.text());
      if (typeof report !== "object" || report === null) throw new Error();
      const r = report as Record<string, unknown>;
      if (r.target !== "reference:export" || r.mechanism_id !== "export-read-entitlement" ||
          r.uploaded !== false || !["verified_violation", "invariant_held", "inconclusive"].includes(String(r.result))) throw new Error();
      setSummary(r.result === "verified_violation"
        ? "The local report records protected synthetic export content reaching the lower-plan account. Apply the server-side export entitlement check, then repeat with the hardened product."
        : r.result === "invariant_held"
          ? "The local report records a successful entitled positive control and no protected marker in the lower-plan response. This read regression passed."
          : "The local report could not establish the invariant. Check the positive control and response format; this is not a pass.");
    } catch {
      setError("Choose a local Heel reference report JSON file under 128 KiB.");
    }
  }
  return <main className="runner-page">
    <header className="dashboard-nav"><Link className="brand" href="/">Heel</Link><Link href="/dashboard">Dashboard</Link></header>
    <section className="runner-hero">
      <div><p className="canary-kicker">Customer-local · synthetic reference</p><h1>Validate an export entitlement.</h1>
      <p>Test whether a user can extract paid value through a normal export capability. Validate one protected synthetic row, apply the entitlement fix, and retain the regression.</p></div>
    </section>
    <section className="runner-command">
      <div><h2>1. Review the rule and authorize the reference product</h2>
      <p>Download the supplied wheel from /agent and install the local runner extra, inspect the bounded plan, then create a signed scope. These commands contact no product target.</p>
      <pre><code>{`python -m pip install './heel_sim-1.2.0-py3-none-any.whl[runner]'
heel reference prepare
heel scope create --target reference:export --operator "your name" --confirm`}</code></pre>
      <p>Copy the returned scope ID into the next commands.</p>
      <h2>2. Validate, fix, and repeat</h2>
      <pre><code>{`heel reference run --scope SCOPE_ID --case vulnerable --attempt 11111111111111111111111111111111
heel reference run --scope SCOPE_ID --case hardened --attempt 22222222222222222222222222222222`}</code></pre>
      <p>Each attempt is consumed once. Use a new 32-character hexadecimal attempt ID for a fresh run. Reports and raw synthetic evidence stay under your local .heel/reference directory.</p>
      <p>The hardened reference checks the account’s current export license before serializing protected fields. HTTP status alone never establishes the result.</p>
      <h2>3. Inspect the local report</h2>
      <label>Reference report JSON <input type="file" accept=".json,application/json" onChange={(event) => void inspect(event.target.files?.[0])} /></label>
      {summary && <p role="status">{summary}</p>}{error && <p role="alert">{error}</p>}
      <p>This viewer reads the file only in this browser. Imported reports are untrusted summaries; the viewer does not authenticate their signatures. No file is uploaded.</p>
      <h2>Use the same workflow through MCP</h2>
      <p>Call heel_prepare_reference, then heel_execute_reference with scope_id, case, and a fresh attempt. The scope must first be created by a human in the CLI. MCP cannot authorize itself.</p>
      </div>
    </section>
    <aside className="runner-recovery"><h2>What this establishes</h2>
      <p>Only the two synthetic reads are validated. Trial eligibility, cumulative usage, scraping limits, plan-change sequences, and other access paths remain untested. No findings does not establish launch safety.</p>
      <p>Cloud runner pairing and arbitrary customer-target execution are incomplete public workflows. The supported validation path here is the local reference product; the browser does not execute target requests.</p>
    </aside>
  </main>;
}
