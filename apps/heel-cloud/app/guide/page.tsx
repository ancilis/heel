// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type { Metadata } from "next";
import Link from "next/link";
import { RUNNER_RC7_CLI, RUNNER_RC7_INSTALL, RUNNER_RC7_RELEASE_URL } from "../../components/canary/RunnerPairingCard";

/** The installed executable path; every runner command on this page starts with it, never a bare `heel`. */
const CLI = RUNNER_RC7_CLI;
/** The release named next to the shared install constants above; it changes with them. */
const RELEASE = "1.3.0rc7";

const LINUX_VAULT = `sudo apt-get install dbus gnome-keyring libsecret-tools    # Debian/Ubuntu package names
dbus-run-session -- bash                                   # headless only: private session bus
IFS= read -rs pw && printf '%s' "$pw" \\
    | gnome-keyring-daemon --unlock --components=secrets >/dev/null; unset pw
(umask 077 && rm -f .heel-bus && printf '%s\\n' "$DBUS_SESSION_BUS_ADDRESS" > .heel-bus)   # headless only`;

const PAIR = `export HEEL_HOME="$(pwd -P)/.heel"
${CLI} runner pair --origin https://YOUR_HEEL_DASHBOARD_ORIGIN --invite INVITATION`;

const SERVE = `${CLI} runner serve      # keep this running in the first terminal`;

const SECOND_TERMINAL = `cd SAME_PRIVATE_DIRECTORY
export HEEL_HOME="$(pwd -P)/.heel"
IFS= read -r DBUS_SESSION_BUS_ADDRESS < .heel-bus && export DBUS_SESSION_BUS_ADDRESS   # headless Linux only
${CLI} runner status`;

const IMPORT = `${CLI} runner import-openapi ./openapi.json`;

const CREDENTIALS = `# Lower plan vs higher plan tests: one staging account per plan
${CLI} runner credential add --role lower_plan --profile bearer --label "lower plan staging" --backend keychain
${CLI} runner credential add --role higher_plan --profile bearer --label "higher plan staging" --backend keychain
# Anonymous vs signed-in tests: one signed-in staging account (the anonymous read sends no credential)
${CLI} runner credential add --role authenticated --profile bearer --label "signed-in staging" --backend keychain`;

const INPUTS = `${CLI} runner input add --name expected_account --type text --backend keychain
${CLI} runner input list      # names, handles and states only; never values`;

const FINDINGS = `${CLI} runner findings --run RUN_ID`;

const LEGACY_MAP = `# Legacy only: fixed-marker checks. Configured tests do not use map, prepare or regress.
printf '{"id":"heel-canary-export-0001"}' > export-fixture.json
${CLI} runner map --scenario plan_entitlement_read --method GET \\
    --route '/exports/{id}' --fixture-fd 3 3<export-fixture.json
${CLI} runner prepare --live
${CLI} runner regress add --run RUN_ID --scenario plan_entitlement_read --name "export plan entitlement read"`;

const LEGACY_MARKER = `{"id": "heel-canary-export-0001", "protected_canary": "heel-canary-export-0001"}`;

const FEEDBACK = `Setup step: (for example "10. Enter expected values on the runner")
Heel version: (output of ${CLI} --version)
OS and Python: (for example Ubuntu 24.04, Python 3.12)
Command or button: (the command without secrets, or the button label)
Exit status and fixed message or error code: (for example rc 2, "Heel runner serve stopped: response_rejected.")
Approximate time (UTC):
Expected:
Observed:`;

export const metadata: Metadata = {
  title: "Paired runner guide — Heel",
  description: "Configure and run your own private read tests against your own verified staging target through Heel's paired runner, with their recorded evidence and limits.",
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
            <p className="eyebrow">Heel {RELEASE} public preview · paired runner guide</p>
            <h1>Configure a private read test and run it against your own staging target.</h1>
            <p>
              Heel Cloud checks that you own one staging HTTPS origin. You describe a test in the
              browser; a runner on your machine holds the credentials and expected values and sends the
              only target traffic. Nothing is sent until you approve the exact signed dry run in this
              browser.
            </p>
          </div>
          <Link className="button button-secondary" href="/dashboard">Open the dashboard</Link>
        </header>

        <aside className="quickstart-privacy" aria-label="What this preview covers">
          <strong>What this covers.</strong>
          <p>
            A configured test reads one literal <code>GET</code> route from your own imported OpenAPI
            document, once for a restricted role and once for a control role, and checks one JSON field
            in each response. Two comparisons exist: anonymous vs signed-in, and lower plan vs higher
            plan. The target is one public HTTPS origin on port 443, methods are <code>GET</code> and{" "}
            <code>HEAD</code> only, and redirects are not followed. A field condition on{" "}
            <code>HEAD</code> is always inconclusive, because <code>HEAD</code> returns no body. There
            are no writes, multi-step workflows, trials or cumulative usage tests. A result covers only
            the configured field condition on that one route, not your product. The scenario library
            lists breadth, not executed coverage.
          </p>
          <p>
            Sign-up is public but rate-limited: if it answers that there were too many recent sign-ups,
            try again later. Version {RELEASE} is a public preview prerelease, not a stable release,
            and it is not published to PyPI. Only the <code>bearer</code> credential profile has been
            exercised end to end. The <code>x_api_key</code> and <code>cookie_jar</code> profiles are
            implemented, but no recorded acceptance covers them.
          </p>
        </aside>

        <section className="quickstart-steps" aria-label="Configured test steps">
          <article className="quickstart-card">
            <p className="step-number">01 · Account</p>
            <h2>Sign in and create a project</h2>
            <p>
              Create an account or sign in on the <Link href="/dashboard">dashboard</Link>. Your default
              workspace opens; name a project for the staging target. Owners and admins pair runners,
              approve plans, share results and revoke access. Each of these actions requires that you
              signed in within the last 15 minutes. If you did not, it is refused and nothing changes;
              sign out, sign in again and repeat the action.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">02 · Ownership</p>
            <h2>Prove you own the exact staging origin</h2>
            <p>
              Test only a staging or sandbox origin that you own or are authorized to test. Under Add
              target, enter one publicly reachable HTTPS origin, such as{" "}
              <code>https://staging.yourcompany.com</code>. Choose HTTPS file or DNS TXT, then Create
              ownership proof. For HTTPS file, serve exactly the value shown at{" "}
              <code>/.well-known/heel-verify.txt</code> on that origin; for DNS TXT, publish the TXT
              record shown. Then choose Check ownership proof. Heel Cloud contacts the target only to
              read this proof. A pending proof is kept on the server, so after you sign in again you can
              resume it. Recorded journeys used HTTPS-file proof; DNS proof is implemented but not
              recorded.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">03 · Install</p>
            <h2>Install the released runner</h2>
            <p>
              You need an installed Python 3.11 or newer with its <code>venv</code> module, on Apple
              silicon macOS or Linux x86_64/aarch64. Intel macOS is unsupported by this preview.
              In an empty private directory, the command below installs the public{" "}
              <a href={RUNNER_RC7_RELEASE_URL}>{RELEASE} release</a> wheel and prints its version. pip
              refuses the wheel unless its SHA-256 matches. The pinned <code>cryptography</code>{" "}
              dependency comes from your package index and is not hash-pinned by this command. No source
              checkout is needed. Every command below starts with the installed path{" "}
              <code>{CLI}</code>, not a bare <code>heel</code>. Where the dashboard shows a command
              starting with <code>heel</code>, run it with that same path.
            </p>
            <p>
              On some Macs the default <code>python3</code> is 3.9, which is too old. The command
              therefore first picks the first Python 3.11 or newer with <code>venv</code> and{" "}
              <code>ensurepip</code> on your PATH, and prints which one it uses. To use one installed at
              another absolute path, first run <code>HEEL_PYTHON=/path/to/python3</code> in the same
              shell. If none is found, it says so and stops before creating anything; install Python 3.11
              or newer (for example from python.org, Homebrew, or your Linux package manager) and run it
              again. Heel never downloads Python for you. If an earlier attempt already created{" "}
              <code>./heel-rc7</code> with an older Python, start again in a new empty private directory.
            </p>
            <pre><code>{RUNNER_RC7_INSTALL}</code></pre>
            <p>
              The runner keeps its signing key, credentials and expected values only in the operating
              system vault. On macOS that is the Keychain: use <code>--backend keychain</code>. On Linux
              it is the Secret Service: use <code>--backend secret-service</code> wherever this page
              shows <code>--backend keychain</code>. Without a vault, pairing fails; there is no file
              fallback. A desktop Linux session normally has an unlocked keyring already. On a headless
              Linux host, install and unlock one first, in the empty private directory. Type the keyring
              password at the hidden prompt; it goes to the daemon on standard input only. The last line
              saves only the session bus address, which is local connection metadata and not a secret,
              to <code>.heel-bus</code> with mode 0600, so that a second terminal can reach the same
              unlocked keyring. Keep this shell open: exiting it ends the bus and the keyring session.
            </p>
            <pre><code>{LINUX_VAULT}</code></pre>
          </article>

          <article className="quickstart-card">
            <p className="step-number">04 · Pair</p>
            <h2>Pair the runner and compare its words</h2>
            <p>
              On the dashboard, choose Create pairing invitation. The invitation is shown only once and
              expires after 10 minutes. Run the <code>runner pair</code> command the dashboard shows on
              the runner machine. Set <code>HEEL_HOME</code> to a physical path with no symbolic link in
              any component, and use the same <code>HEEL_HOME</code> for every later command. The
              invitation appears in that command&apos;s process arguments on your machine, so pair on a
              machine you control.
            </p>
            <pre><code>{PAIR}</code></pre>
            <p>
              The runner prints a pairing ID, six words and a key fingerprint. Enter the pairing ID on
              the dashboard, open the request, and approve only if the words and fingerprint match the
              terminal exactly. Leave <code>runner pair</code> running until it reports{" "}
              <code>&quot;state&quot;: &quot;active&quot;</code>. Pairing alone authorizes no target
              traffic.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">05 · Serve</p>
            <h2>Keep the runner online</h2>
            <pre><code>{SERVE}</code></pre>
            <p>
              Run every later runner command in a second terminal, as the same user, in the same private
              directory and with the same <code>HEEL_HOME</code>. On a headless Linux host, load the bus
              address saved in step 03; on macOS or a desktop Linux session, skip that line.
            </p>
            <pre><code>{SECOND_TERMINAL}</code></pre>
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
              it claims; to move it to another one, pair a fresh runner. Authorization adds and reveals
              no credential. Before you add credentials or values, wait until{" "}
              <code>{CLI} runner status</code> shows a <code>binding_id</code> under <code>serve</code>.
              A credential add before then is refused with{" "}
              <code>Heel runner credential could not be stored safely.</code> and stores nothing; run it
              again once the <code>binding_id</code> appears.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">07 · Routes</p>
            <h2>Import your ordinary OpenAPI document on the runner</h2>
            <pre><code>{IMPORT}</code></pre>
            <p>
              <code>import-openapi</code> reads your local OpenAPI JSON and keeps only <code>GET</code>{" "}
              and <code>HEAD</code> routes. The document is not uploaded, and it needs no Heel-specific
              annotation. A configured test needs a literal route, such as{" "}
              <code>/api/profile</code>: a route with a path parameter, such as{" "}
              <code>/records/{"{id}"}</code>, is reported as unsupported.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">08 · Credentials</p>
            <h2>Add staging-only credentials for the roles your tests need</h2>
            <p>
              Use isolated staging test accounts, never real customer accounts. Each command prompts{" "}
              <code>Canary credential:</code> with hidden input. Heel stores the credential in the OS
              vault and never prints it; Heel Cloud never receives it. Add only the roles your tests
              compare.
            </p>
            <pre><code>{CREDENTIALS}</code></pre>
          </article>

          <article className="quickstart-card">
            <p className="step-number">09 · Create</p>
            <h2>Create a private test in the browser</h2>
            <p>
              On the dashboard, choose Open scenario library, then fill in Create a private live test.
              No JSON is needed.
            </p>
            <ul>
              <li><strong>Test name</strong>: saved as <code>sc.internal.your-name</code>, private to your workspace.</li>
              <li><strong>Comparison</strong>: Anonymous vs signed-in read, or Lower plan vs higher plan read.</li>
              <li><strong>Method</strong> and <strong>Imported route</strong>: <code>GET</code> and the exact literal path from step 07.</li>
              <li>
                <strong>Successful response check</strong>: a field path and the <em>name</em> of a local
                expected value, for example <code>expected_account</code>. The control read must
                return 200 with this field equal to that value.
              </li>
              <li>
                <strong>Condition to test</strong>: a field path, with Field is present, or Scalar equals
                local input (another value name).
              </li>
            </ul>
            <p>
              The form checks each field before Save private test and names what to correct. Enter
              value names only: never type an expected value, credential or response in the browser.
              Edit saves a new revision; the earlier revision, and every run that used it, stay
              unchanged.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">10 · Values</p>
            <h2>Enter expected values on the runner</h2>
            <p>
              After a save, the dashboard lists each value name the test uses. For each one, run{" "}
              <code>runner input add</code> on the runner machine and type the value at the hidden{" "}
              <code>Expected value</code> prompt. The value goes to the OS vault and is never printed,
              uploaded or shown in the browser.
            </p>
            <pre><code>{INPUTS}</code></pre>
            <p>
              <code>--type</code> states the kind of value: <code>text</code> (typed as is, no
              quotes), <code>number</code>, <code>boolean</code> (<code>true</code> or{" "}
              <code>false</code>) or <code>null</code> (no prompt). Adding a value under an existing
              name makes the new one current for future dry runs; earlier approved runs keep the exact
              value they froze.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">11 · Dry run</p>
            <h2>Request a dry run from the paired runner</h2>
            <p>
              Under Configured live tests, select up to four private tests. For a plan comparison, name
              the lower and higher plan as you know them; these labels are yours, frozen in the review,
              and never read from the target. Choose Request a dry run from the paired runner.
            </p>
            <p>
              The runner checks only what the selected tests need: the imported route, each
              credential and each named value. The dashboard shows each item as ready, missing, revoked
              or unsupported, with the local command for anything missing. Nothing is sent to the target
              at this stage. When everything is ready, the runner signs the dry run.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">12 · Approve</p>
            <h2>Review the exact dry run, then approve it once</h2>
            <p>
              Choose Review and approve the dry run. The review shows the exact origin, the request and
              time ceilings, and, for each test, its revision, comparison, route, roles (restricted, then
              control), request count, successful response check, condition and the value names. Each
              test reads its route once per role. Confirm that you reviewed every route, role pair and
              condition, retype the exact hostname, give a reason, and approve. Approval applies once,
              to exactly this signed plan.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">13 · Result</p>
            <h2>Read the outcome and choose whether to share</h2>
            <p>
              When the run finishes, the dashboard asks you to choose Share this summary or Keep result
              local. Only an explicit share uploads the runner-signed redacted summary: outcomes,
              reasons, route methods and paths, status and body shape. Response bodies, credentials and
              expected values stay on the runner machine. Each test has one outcome:
            </p>
            <ul>
              <li>
                <strong>observed</strong>: the control read succeeded and the condition held for the
                restricted role.
              </li>
              <li>
                <strong>blocked</strong>: the control read succeeded, and the restricted role either got
                a successful response in which the condition did not hold, or an empty 401, 402, 403 or
                404.
              </li>
              <li>
                <strong>inconclusive</strong>: no verdict, for example a failed control read, a JSON
                error envelope, a <code>HEAD</code> read or a missing value. It is neither a pass nor a
                failure.
              </li>
            </ul>
            <p>
              On the runner machine, <code>findings</code> prints the same runner-signed, redacted
              local summary of a finished run. It does not show raw response bodies.
            </p>
            <pre><code>{FINDINGS}</code></pre>
          </article>

          <article className="quickstart-card">
            <p className="step-number">14 · Replay</p>
            <h2>Replay the exact test after a fix</h2>
            <p>
              After you patch the target, choose Save and replay this exact test on an observed result.
              The replay reuses the frozen test and the exact local values the original run used, on the
              runner that ran it. It is a fresh dry run that you review and approve again.
            </p>
            <p>
              If one of those frozen values is missing or revoked, the replay cannot run, and adding a
              new value under the same name does not repair it. Cancel the replay request, then create a
              new test with new values and approve its own dry run.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">15 · Stop and revoke</p>
            <h2>Stop a run, revoke the target context, revoke the runner</h2>
            <p>
              <strong>Stop</strong> on the run progress asks the runner to stop the current run. In
              the recorded journey, a short run completed before Stop was accepted. Stopping a run while
              it is in flight has not been demonstrated.
            </p>
            <p>
              If an approved dry run never started because the runner was interrupted, restart{" "}
              <code>serve</code> and keep its credentials and local files: if <code>serve</code> is
              still running, press Ctrl+C once in its terminal and wait for it to exit, then run the step
              05 command again with the same <code>HEEL_HOME</code>. Stop on the dashboard does not stop{" "}
              <code>serve</code>. The runner then runs that dry run. If Heel Cloud had already stopped it,
              that start only records the stop and the dashboard shows <strong>Stop requested</strong>;
              restart <code>serve</code> the same way once more and the runner retires the run without
              contacting the target. If the run still shows <strong>Rehearsal running</strong> with no
              progress, choose <strong>Stop rehearsal</strong>, then restart <code>serve</code> the same
              way: Heel Cloud confirms the run never started and the runner retires it. The stopped run is
              not resumed. Request and approve a new dry run (steps 11 and 12). If{" "}
              <strong>Stop rehearsal</strong> is not shown, wait until the approval has expired (at most
              10 minutes after you approved it), then restart <code>serve</code> the same way. Until Heel
              Cloud has ended the run, <code>serve</code> reports <code>offline</code> with{" "}
              <code>inactive_claim_waiting_for_cloud</code> and retries by itself; it then retires the
              run. A run that already started is never resumed this way, and a
              revoked runner or context stays revoked. If <code>serve</code> stops again, report it (see
              Feedback below).
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
        </section>

        <section className="quickstart-steps" aria-label="Examples, legacy setup and known limits">
          <article className="quickstart-card">
            <p className="step-number">Examples</p>
            <h2>Three tests on a synthetic staging fixture</h2>
            <p>
              These examples use Heel&apos;s controlled synthetic staging fixture, whose ordinary
              responses carry <code>&quot;account_id&quot;: &quot;acct_canary&quot;</code>. Each uses
              the success check <code>account_id</code> equals the local value{" "}
              <code>expected_account</code>, entered as text <code>acct_canary</code>.
            </p>
            <p>
              The fixture is a small Cloudflare Worker, distributed separately from the runner package:
              its four files are the <code>heel-staging-fixture-</code> assets of the{" "}
              <a href={RUNNER_RC7_RELEASE_URL}>{RELEASE} release</a>, with a manifest of their digests.
              Its README explains how to download, check and deploy them with no repository checkout.
              Deploying and changing its mode needs your own authorized Cloudflare account; Heel does
              not provide one.
            </p>
            <ul>
              <li>
                <strong>Authentication</strong>: Anonymous vs signed-in read,{" "}
                <code>GET /api/private-record</code>, condition <code>record_id</code> is present.
              </li>
              <li>
                <strong>Field-level redaction</strong>: Lower plan vs higher plan read,{" "}
                <code>GET /api/profile</code>, condition <code>profile</code> ›{" "}
                <code>billing_contact</code> is present.
              </li>
              <li>
                <strong>Whole-feature entitlement</strong>: Lower plan vs higher plan read,{" "}
                <code>GET /api/export</code>, condition <code>rows</code> is present.
              </li>
            </ul>
            <p>
              These are the two comparisons applied to three access rules, not three detectors, and not
              complete coverage of any rule. They are a static description: reading them proves nothing
              about your connection or your target. Only a run through your own paired runner against
              your own verified target is evidence about it.
            </p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">Legacy</p>
            <h2>The earlier fixed-marker checks</h2>
            <p>
              Before configured tests, the paired runner ran two fixed checks, mapped with{" "}
              <code>runner map</code>, compiled with <code>runner prepare --live</code> and saved with{" "}
              <code>runner regress</code>. They decide a read only when your staging data returns a{" "}
              <code>protected_canary</code> marker. The configured flow above does not use these
              commands, and a legacy <code>--scenario</code> regression does not replay a configured
              test.
            </p>
            <pre><code>{LEGACY_MAP}</code></pre>
            <pre><code>{LEGACY_MARKER}</code></pre>
            <p>
              Also legacy: the scenario library&apos;s Advanced paste of a static scenario definition in
              JSON. Its <code>success_criterion</code> is analysis only and is never executed; static
              assessment runs only in this browser and uploads nothing.
            </p>
          </article>

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
              The recorded attempts below used the legacy fixed-marker checks, not configured tests. No
              public end-to-end run of the configured flow is recorded on this page yet.
            </p>
            <p>
              Two attempts are recorded on November 13, 2026. Each used a separate fresh preview
              account, a clean Linux container, the public release and the browser. In both, the target
              was a controlled synthetic staging app that Heel operates on the public network. Neither
              is a customer target or customer acceptance, and neither promises how long your own
              setup will take.
            </p>
            <p>
              The first attempt exercised two checks. It produced two observed findings, an
              authorization one and an entitlement one. It also produced a redacted shared summary, two
              saved regressions whose replays passed after the target was patched, a custom revision
              kept frozen on its run after an edit and reload, and an inconclusive result for error
              envelopes. Requests into another workspace were refused with 403 and into another project
              with 404. A run kept local uploaded no summary bytes. The context and the runner were then
              revoked. Its time to the first finding was about 29.4 minutes, including install and a
              control-plane outage that recovered with its data intact. Separately, <code>serve</code>{" "}
              once stopped with <code>response_rejected</code> before a run started: nothing was sent,
              that run&apos;s quota was refunded, and one restart recovered. The cause is unknown.
            </p>
            <p>
              The second attempt, on the corrected hosted service, exercised one check,{" "}
              <code>plan_entitlement_read</code>. The browser showed the observed entitlement finding 6
              minutes 54 seconds (414.1 s) after the start, install included. After the target was
              patched, the replay was held (<code>blocked</code>). The runner was then revoked, and{" "}
              <code>serve</code> exited with code 3, <code>runner_authentication_rejected</code>.
            </p>
            <p>This is a preview, and no launch-readiness claim is made.</p>
          </article>

          <article className="quickstart-card">
            <p className="step-number">Feedback</p>
            <h2>Report a problem</h2>
            <p>
              Open an issue at{" "}
              <a href="https://github.com/ancilis/heel/issues/new">github.com/ancilis/heel/issues/new</a>{" "}
              (a GitHub account is required) and include:
            </p>
            <pre><code>{FEEDBACK}</code></pre>
            <p className="quickstart-note">
              GitHub issues are public. Never include credentials, invitations, expected values, raw
              response bodies, private OpenAPI documents, or unredacted logs. The fixed message, exit
              status and version are enough to start.
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
