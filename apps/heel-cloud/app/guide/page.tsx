// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type { Metadata } from "next";
import Link from "next/link";
import { RUNNER_RC5_CLI, RUNNER_RC5_INSTALL, RUNNER_RC5_RELEASE_URL } from "../../components/canary/RunnerPairingCard";

const CLI = RUNNER_RC5_CLI;

const LINUX_VAULT = `sudo apt-get install dbus gnome-keyring libsecret-tools    # Debian/Ubuntu package names
dbus-run-session -- bash                                   # headless only: private session bus
read -rs pw && printf '%s' "$pw" \\
    | gnome-keyring-daemon --unlock --components=secrets >/dev/null; unset pw`;

const PAIR = `export HEEL_HOME="$(pwd -P)/.heel"
${CLI} runner pair --origin https://YOUR_HEEL_DASHBOARD_ORIGIN --invite INVITATION`;

const SERVE = `${CLI} runner serve      # keep this running; use a second terminal with the same HEEL_HOME
${CLI} runner status     # in the second terminal`;

const CREDENTIALS = `${CLI} runner credential add --role lower_plan --plan-label free --profile bearer --label "free canary" --backend keychain
${CLI} runner credential add --role higher_plan --plan-label pro --profile bearer --label "pro canary" --backend keychain
${CLI} runner credential add --role authenticated --profile bearer --label "signed-in canary" --backend keychain`;

const IMPORT_AND_MAP = `${CLI} runner import-openapi ./openapi.json
printf '{"id":"heel-canary-export-0001"}' > export-fixture.json
${CLI} runner map --scenario plan_entitlement_read --method GET \\
    --route '/exports/{id}' --fixture-fd 3 3<export-fixture.json
printf '{"id":"heel-canary-record-0001"}' > record-fixture.json
${CLI} runner map --scenario anonymous_authenticated_read --method GET \\
    --route '/records/{id}' --fixture-fd 3 3<record-fixture.json`;

const MARKER = `{"id": "heel-canary-export-0001", "protected_canary": "heel-canary-export-0001", ...}`;

const PREPARE = `${CLI} runner prepare           # local readiness check; sends nothing
${CLI} runner prepare --live    # queue the signed plan; serve submits it for browser review`;

const FINDINGS = `${CLI} runner status --offline     # shows the run_id once serve submitted the plan
${CLI} runner findings --run RUN_ID`;

const REGRESS = `${CLI} runner regress add --run RUN_ID --scenario plan_entitlement_read --name "export plan entitlement read"
# fix the target, then:
${CLI} runner prepare --live --regression REGRESSION_ID
# approve the new plan in the browser; after the run completes:
${CLI} runner regress record --regression REGRESSION_ID --run NEW_RUN_ID
${CLI} runner regress list`;

const CUSTOM = `{
  "id": "sc.internal.exports.entitlement_gate",
  "category": "data_harvesting",
  "objective": "Bulk export is available without a server-side entitlement check",
  "kind": "export",
  "success_criterion": {"guard_absent": true},
  "severity_model": {"likelihood": 0.55, "impact": 0.7},
  "recommended_control": "enforce server-side entitlement checks and canary export row caps",
  "containment_limits": {"canary_only": true, "no_live_targets": true, "max_examples": 2},
  "applies_when": "always"
}`;

const FEEDBACK = `Setup step: (for example "7. Add canary credentials")
Heel version: (output of ${CLI} --version)
OS and Python: (for example Ubuntu 24.04, Python 3.12)
Command or button: (the command without secrets, or the button label)
Exit status and fixed message or error code: (for example rc 2, "Heel runner serve stopped: response_rejected.")
Approximate time (UTC):
Expected:
Observed:`;

export const metadata: Metadata = {
  title: "Paired runner guide — Heel",
  description: "Set up Heel's paired runner against your own verified staging target, step by step, with its recorded evidence and limits.",
};

export default function Guide() {
  return (
    <main className="quickstart-main">
      <header className="site-header">
        <Link className="brand" href="/" aria-label="Heel home">
          <span className="brand-mark" aria-hidden="true">H</span>
          <span>Heel</span>
        </Link>
        <span className="local-status">
          <span aria-hidden="true" />
          Public preview · paired runner
        </span>
      </header>

      <article className="mcp-quickstart">
        <header className="quickstart-hero">
          <div>
            <p className="eyebrow">Heel 1.3.0rc5 public preview · paired runner guide</p>
            <h1>Rehearse two read checks against your own staging target.</h1>
            <p>
              Heel Cloud checks that you own one staging HTTPS origin. A runner on your machine holds
              the test credentials and sends the only target traffic, and it sends nothing until you
              approve an exact signed plan in this browser.
            </p>
          </div>
          <Link className="button button-secondary" href="/dashboard">Open the dashboard</Link>
        </header>

        <aside className="quickstart-privacy" aria-label="What this preview covers">
          <strong>What this covers.</strong>
          <p>
            The paired runner runs two fixed read checks over <code>GET</code> routes from your own
            OpenAPI document. <code>anonymous_authenticated_read</code> checks whether an anonymous
            request gets a record that only a signed-in canary should see.{" "}
            <code>plan_entitlement_read</code> checks whether a lower-plan canary gets a record that
            only a higher-plan canary should see. Each check is marker-backed: the record must carry a
            marker you place in your staging data (step 8). The target is one public HTTPS origin on
            port 443, methods are <code>GET</code> and <code>HEAD</code> only, and redirects are not
            followed. Nothing else about your product is tested. The scenario library lists breadth,
            not executed coverage.
          </p>
          <p>
            Sign-up is public but rate-limited: if it answers that there were too many recent sign-ups,
            try again later. Version 1.3.0rc5 is a
            public preview prerelease, not a stable release, and it is not published to PyPI. Only the
            <code> bearer</code> credential profile has been exercised end to end. The{" "}
            <code>x_api_key</code> and <code>cookie_jar</code> profiles are implemented, but no
            recorded acceptance covers them.
          </p>
        </aside>

        <section className="quickstart-steps" aria-label="Paired runner setup steps">
          <article className="quickstart-card">
            <p className="step-number">01 · Account</p>
            <h2>Sign in and create a project</h2>
            <p>
              Create an account or sign in on the <Link href="/dashboard">dashboard</Link>. Your default
              workspace opens;
              name a project for the staging target. Owners and admins pair runners, approve plans,
              share results and revoke access. Each of these actions requires that you signed in within
              the last 15 minutes. If you did not, it is refused and nothing changes; sign out, sign in
              again and repeat the action.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">02 · Ownership</p>
            <h2>Prove you own the exact staging origin</h2>
            <p>
              Under Add target, enter one publicly reachable staging or sandbox origin, such as{" "}
              <code>https://staging.yourcompany.com</code>. Choose HTTPS file or DNS TXT, then Create
              ownership proof. For HTTPS file, serve exactly the value shown at{" "}
              <code>/.well-known/heel-verify.txt</code> on that origin. For DNS TXT, publish the TXT
              record shown. Then choose Check ownership proof. Heel Cloud contacts the target only to
              read this proof. A pending proof is kept on the server, so after you sign in again you can
              resume it. The recorded journey used HTTPS-file proof. DNS proof is implemented but was
              not part of that journey.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">03 · Install</p>
            <h2>Install the runner from the public release</h2>
            <p>
              You need Python 3.11 or newer as <code>python3</code> with its <code>venv</code> module, on
              Apple silicon macOS or Linux x86_64/aarch64. Intel macOS is unsupported by this preview.
              In an empty private directory, the command below installs the public{" "}
              <a href={RUNNER_RC5_RELEASE_URL}>1.3.0rc5 release</a> wheel and prints{" "}
              <code>heel 1.3.0rc5</code>. pip refuses the wheel unless its SHA-256 matches. The pinned{" "}
              <code>cryptography</code> dependency comes from your package index and is not hash-pinned
              by this command. No source checkout is needed.
            </p>
            <pre><code>{RUNNER_RC5_INSTALL}</code></pre>
            <p>
              The runner keeps its signing key and credentials only in the operating system vault: macOS
              Keychain or the Linux Secret Service. Without one, pairing fails; there is no file
              fallback. A desktop Linux session normally has an unlocked keyring already. On a headless
              Linux host, install and unlock one first. Type the keyring password at the hidden prompt.
            </p>
            <pre><code>{LINUX_VAULT}</code></pre>
          </article>

          <article className="quickstart-card">
            <p className="step-number">04 · Pair</p>
            <h2>Pair the runner and compare its words</h2>
            <p>
              On the dashboard, choose Create pairing invitation. The invitation is shown only once and
              expires after 10 minutes. The dashboard then shows a <code>runner pair</code> command;
              run it on the runner machine. Set <code>HEEL_HOME</code> to a physical path with no
              symbolic link in any component, and use the same <code>HEEL_HOME</code> for every later
              command. The invitation appears in that command&apos;s process arguments on your machine,
              so pair on a machine you control.
            </p>
            <pre><code>{PAIR}</code></pre>
            <p>
              The runner prints a pairing ID, six words and a key fingerprint. Enter the pairing ID on
              the dashboard, open the request, and check that the words and fingerprint match the
              terminal exactly. Approve only if they match. Leave <code>runner pair</code> running
              until the runner reports{" "}
              <code>&quot;state&quot;: &quot;active&quot;</code>. Pairing alone authorizes no target
              traffic.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">05 · Serve</p>
            <h2>Keep the runner online</h2>
            <pre><code>{SERVE}</code></pre>
            <p>
              <code>serve</code> polls Heel Cloud over the paired, signed channel and is the only
              process that sends target requests. If it reports <code>offline</code>, it retries by
              itself. If it stops with <code>response_rejected</code>, start it once more on the same{" "}
              <code>HEEL_HOME</code>. If it stops again, do not loop: report it (see Feedback below).
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">06 · Authorize</p>
            <h2>Authorize the runner for the verified target</h2>
            <p>
              Under Add canary access on the dashboard, select the verified environment and the paired
              runner, then choose Authorize paired runner. The runner is fixed to the first environment
              it claims. To move it to another one, pair a fresh runner. Authorization adds and reveals
              no credential.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">07 · Credentials</p>
            <h2>Add staging-only canary credentials on the runner machine</h2>
            <p>
              Use isolated staging test accounts, never real customer accounts. Each command prompts{" "}
              <code>Canary credential:</code> with hidden input. Heel stores the credential in the OS
              vault and never prints it; Heel Cloud never receives it. The plan labels{" "}
              <code>free</code> and <code>pro</code> are your own words for your plans, and Heel never
              infers them. <code>plan_entitlement_read</code> needs a lower-plan and a higher-plan
              account. <code>anonymous_authenticated_read</code> needs one signed-in account. On Linux,
              use <code>--backend secret-service</code>.
            </p>
            <pre><code>{CREDENTIALS}</code></pre>
            <p>
              <code>{CLI} runner status</code> reports <code>access.ready</code> when local access is
              complete. If it reports <code>access.incomplete</code>, it names the missing role and the
              command to run.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">08 · Routes and canary data</p>
            <h2>Import your OpenAPI and map each check to a canary record</h2>
            <p>
              <code>import-openapi</code> reads your local OpenAPI JSON and keeps only <code>GET</code>{" "}
              and <code>HEAD</code> routes. The OpenAPI document is not uploaded. Map each check to one
              imported route, written exactly as in your document. Supply the path values through{" "}
              <code>--fixture-fd</code>, because Heel never invents an ID. A parameterized route
              mapped without <code>--fixture-fd</code> is refused with{" "}
              <code>Heel runner mapping could not be saved safely.</code>
            </p>
            <pre><code>{IMPORT_AND_MAP}</code></pre>
            <p>
              The marker is a staging-data requirement, not something Heel reads from OpenAPI. In your
              staging product, create each canary record with an ID that starts with{" "}
              <code>heel-canary-</code>. Return it as a JSON object whose <code>protected_canary</code>{" "}
              field equals that ID, and only to identities that are entitled to it:
            </p>
            <pre><code>{MARKER}</code></pre>
            <p>
              The higher-plan or signed-in request is the positive control, and it must succeed with
              the marker. If the lower-plan or anonymous request also receives the marker, Heel reports
              an <code>observed</code> finding. If it is refused with 401, 402, 403 or 404 and an empty
              body, the check is held (<code>blocked</code>). A JSON error or denial envelope is{" "}
              <code>inconclusive</code> at every status: it is neither a finding nor a pass.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">09 · Plan</p>
            <h2>Prepare locally, then submit the plan for review</h2>
            <pre><code>{PREPARE}</code></pre>
            <p>
              <code>prepare</code> without <code>--live</code> checks credentials, mappings and routes
              locally. <code>prepare --live</code> compiles one signed plan with fixed routes, roles and
              budgets, and <code>serve</code> submits its metadata for review. Neither command executes
              anything. No target request is sent until you approve the plan in the browser.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">10 · Approve</p>
            <h2>Read the exact plan, optionally freeze bindings, and approve</h2>
            <p>
              The approval dialog shows the exact origin, the request and time ceilings, the only
              allowed egress (<code>host:443</code>), each route once per role, and the scenarios. In
              the recorded journey these were 4 GET requests for the two checks, with a ceiling of 20
              requests and 60 seconds.
            </p>
            <p>
              Optional: under What this run stands for, bind library entries or custom revisions to the
              exact checks in this plan. Bindings are frozen once and never follow later library or
              custom edits. Approval does not require them. Without bindings, the run stands for no
              library entry. To approve, retype the exact hostname, give a reason, and choose Approve
              and run. Approval applies once.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">11 · Result</p>
            <h2>View status, read the result, choose whether to share</h2>
            <p>
              The dashboard shows signed progress while the run is active. When it finishes, read the
              verified local result on the runner machine:
            </p>
            <pre><code>{FINDINGS}</code></pre>
            <p>
              <code>heel runner status --offline</code> can still show the last submission as awaiting
              approval after its run has completed, so use <code>findings</code> or the dashboard to
              read the result. The dashboard then asks you to choose Share this summary or Keep result
              local. Only an explicit share uploads the runner-signed redacted summary: outcomes, route
              methods and paths, status and body shape, finding text and recommended controls. Request
              and response bodies, credentials and raw evidence stay on the runner machine.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">12 · Regression</p>
            <h2>Save an observed finding and replay it after the fix</h2>
            <pre><code>{REGRESS}</code></pre>
            <p>
              Each replay is a fresh plan that you approve again in the browser. A blocked, completed
              replay records <code>pass</code>, and an observed one records <code>fail</code>. Anything
              else, including an error envelope, records <code>inconclusive</code>.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">13 · Stop and revoke</p>
            <h2>Stop a run, revoke the target context, revoke the runner</h2>
            <p>
              <strong>Stop</strong> on the run progress asks the runner to stop the current run. In
              the recorded journey, a short run completed before Stop was accepted. Stopping a run while
              it is in flight has not been demonstrated.
            </p>
            <p>
              <strong>Revoke</strong> on the authorized context stops future authorization for that
              target only. Grants already issued and work already active are not changed.
            </p>
            <p>
              <strong>Revoke runner</strong> makes Heel Cloud stop accepting that runner&apos;s keys
              and request a stop of its active rehearsals. <code>serve</code> then exits with{" "}
              <code>runner_authentication_rejected</code>. Run <code>{CLI} runner unpair</code> on that
              machine to remove its local identity.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">Optional · Custom scenarios</p>
            <h2>Describe your own rule as a custom scenario</h2>
            <p>
              In the scenario library on the dashboard, you can save a workspace-private custom scenario
              in the public authoring schema. Use the <code>sc.internal.</code> or{" "}
              <code>sc.community.</code> namespace. For example:
            </p>
            <pre><code>{CUSTOM}</code></pre>
            <p>
              The <code>success_criterion</code> is a declaration for analysis and is never executed.
              Each save is validated and creates a new immutable revision; earlier revisions are never
              edited. A run whose binding was frozen to revision 1 keeps naming revision 1 after you
              save revision 2. Static assessment runs only in this browser against your OpenAPI
              document and uploads nothing. A criterion whose property is absent from that document
              stays <code>unknown</code>. That is not evidence either way.
            </p>
          </article>
        </section>

        <section className="quickstart-steps" aria-label="Standalone command and known limits">
          <article className="quickstart-card">
            <p className="step-number">Separate tool</p>
            <h2>The standalone body-differential command</h2>
            <p>
              <code>heel runner run</code> is a separate, CLI-only command with no Heel Cloud pairing
              or browser approval. It uses a signed local scope, compares the response bodies of two
              plan accounts over imported read routes, and records <code>observed</code> when the lower
              plan&apos;s body contains every key path of the higher plan&apos;s. You do not need it for
              the paired workflow above. Its steps are in the public repository&apos;s{" "}
              <a href="https://github.com/ancilis/heel/blob/main/docs/PLAN_DIFFERENTIAL_RUNNER.md">runner documentation</a>.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">Evidence</p>
            <h2>What has been recorded, and its limits</h2>
            <p>
              On November 13, 2026, one fresh preview account ran this workflow from a clean Linux
              machine with the public release and the browser. The target was a controlled synthetic
              staging app that Heel operates on the public network. This is not a customer target or
              customer acceptance. The workflow produced two observed findings, an authorization one
              and an entitlement one. It also produced a redacted shared summary, two saved regressions
              whose replays passed after the target was patched, a custom revision kept frozen on its
              run after an edit and reload, and an inconclusive result for error envelopes. Requests
              into another workspace were refused with 403 and into another project with 404. A run
              kept local uploaded no summary bytes. The context and the runner were then revoked.
            </p>
            <p>
              Time to the first finding was about 29.4 minutes, including install. That misses the
              15-minute goal, and the time includes a control-plane outage that recovered with its data
              intact. An automatic-restart recovery for that outage has since been merged and deployed;
              in a controlled fault test it restarted with data preserved and was ready in about 12
              seconds.
              Separately, <code>serve</code> once stopped with <code>response_rejected</code> before a
              run started: nothing was sent, and that run&apos;s quota was refunded. One restart of{" "}
              <code>serve</code> recovered, and a fresh plan then ran. The cause is unknown. This is a
              preview, and no launch-readiness claim is made.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">Feedback</p>
            <h2>Report a problem</h2>
            <p>
              Open an issue at{" "}
              <a href="https://github.com/ancilis/heel/issues/new">github.com/ancilis/heel/issues/new</a>{" "}
              and include:
            </p>
            <pre><code>{FEEDBACK}</code></pre>
            <p className="quickstart-note">
              GitHub issues are public. Never include credentials, invitations, raw response bodies,
              private OpenAPI documents, or unredacted logs. The fixed message, exit status and version
              are enough to start.
            </p>
          </article>
        </section>

        <p className="quickstart-note">
          An optional, local-only <Link href="/runner">synthetic export reference</Link> runs without
          any network target. It is not part of this workflow.
        </p>
      </article>
    </main>
  );
}
