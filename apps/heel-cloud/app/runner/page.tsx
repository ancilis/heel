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
      // A pass is only the shape the reference producer writes for a held case: a known
      // held case, verified evidence, a completed reference-only run, regression_passed
      // true. This checks shape only; it does not authenticate the file. 1.3.0rc1 wrongly
      // reported the HTTP-200 error_envelope case as invariant_held.
      const provenance = typeof r.provenance === "object" && r.provenance !== null ? r.provenance as Record<string, unknown> : null;
      const held = r.result === "invariant_held" && r.regression_passed === true &&
        typeof r.case === "string" && ["hardened", "public", "redacted"].includes(r.case) &&
        r.evidence_state === "verified" && r.execution_disposition === "completed" &&
        r.execution_support === "reference_only" && provenance !== null &&
        provenance.kind === "reference_product_execution" && provenance.network_calls === false;
      setSummary(r.result === "verified_violation"
        ? "The local report records protected synthetic export content reaching the lower-plan account. Apply the server-side export entitlement check, then repeat with the hardened product."
        : held
          ? "The local report records a successful entitled positive control and no protected marker in the lower-plan response. This read regression passed."
          : r.result === "invariant_held" && r.case === "error_envelope"
            ? "This report's held result is not valid evidence: an HTTP 200 error envelope is inconclusive, as Heel 1.3.0rc1 wrongly reported it. Treat it as inconclusive; this is not a pass."
            : r.result === "invariant_held"
              ? "This report's held result does not match a supported completed reference pass: a known held case, verified evidence, a completed reference-only run and regression_passed true. This is not a pass; rerun the case with a fresh attempt."
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
      <div className="runner-command-number" aria-hidden="true">01</div>
      <div><h2>1. Review the rule and authorize the reference product</h2>
      <p>This optional local preview is not a step in the default Heel journey. Heel 1.3.0rc1 is a public preview prerelease at <a href="https://github.com/ancilis/heel/releases/tag/v1.3.0rc1">github.com/ancilis/heel/releases/tag/v1.3.0rc1</a>. It is not a stable release, PyPI publication is not yet available, and it does not indicate live-target support or launch readiness. No source checkout or manual wheel download is needed; pip fetches the pinned wheel directly from the public release.</p>
      <p>In an empty private directory with Python 3.11 or newer, install the hash-pinned public wheel with the local runner extra, inspect the bounded plan, then create a signed scope. pip refuses the wheel unless its SHA-256 matches, and --isolated ignores pip environment variables and user configuration. Installing the extra fetches the pinned cryptography package from your Python package index; these commands contact no product target.</p>
      <pre><code>{`python3 -m venv .venv
.venv/bin/python -m pip --isolated install \\
  'heel-sim[runner] @ https://github.com/ancilis/heel/releases/download/v1.3.0rc1/heel_sim-1.3.0rc1-py3-none-any.whl#sha256=176a17b0d4d7f4ea44420d8099239f32dbb17eeead981e5aa360f0a5bbccb94a'
export HEEL_HOME="$(pwd -P)/.heel"
.venv/bin/heel reference prepare
.venv/bin/heel scope create --target reference:export --operator "your name" --confirm`}</code></pre>
      <p>HEEL_HOME must be a physical path in which no component is a symbolic link; pwd -P prints one. On macOS, /tmp and /var are symbolic links, so a $PWD below them is refused. Heel refuses symbolic links in private storage on purpose.</p>
      <p>Copy the returned scope ID into the next commands.</p>
      <h2>2. Validate, fix, and repeat</h2>
      <pre><code>{`.venv/bin/heel reference run --scope SCOPE_ID --case vulnerable --attempt 11111111111111111111111111111111
.venv/bin/heel reference run --scope SCOPE_ID --case hardened --attempt 22222222222222222222222222222222`}</code></pre>
      <p>Expected results: verified_violation for the vulnerable case, then invariant_held with regression_passed=true for the hardened case. Each report records execution_support reference_only, network_calls false, and uploaded false.</p>
      <p>Known 1.3.0rc1 erratum: it reports the error_envelope case, an HTTP 200 error response, as invariant_held with regression_passed=true. That result is inconclusive, not a pass. The corrected 1.3.0rc2 candidate reports it as inconclusive with regression_passed=false; 1.3.0rc2 is not yet published.</p>
      <p>Each attempt is consumed once. Use a new 32-character lowercase hexadecimal attempt ID for a fresh run. Reports and raw synthetic evidence stay under your local .heel/reference directory.</p>
      <h3>If the run is rejected</h3>
      <p>Every refusal prints the same message, “Reference rehearsal rejected. Check the signed synthetic scope, unique attempt and private local storage.”, and exits with status 2. Not every rejection is a storage-path problem, so check each of these: HEEL_HOME is a physical private path with no symbolic link in any component; SCOPE_ID came from heel scope create --target reference:export with the same HEEL_HOME and has not expired, or create a fresh scope; the attempt has never been used in this HEEL_HOME, and a new attempt ID is always safe. Do not disable the storage checks or edit the store database or scope files. If you ask for help, share only the command, exit status, and message, never raw exceptions, signing keys, scope files, or credentials.</p>
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
