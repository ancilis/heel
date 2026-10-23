# Runner preview release procedure (release owner)

This is the administrative procedure for publishing the committed `1.3.0rc1` candidate
as the GitHub **prerelease** `v1.3.0rc1`, titled `Heel runner preview 1.3.0rc1`, with
`scripts/publish_runner_preview_release.py`.

Status: **not yet performed.** No tag, draft or release exists for this candidate. No
public URL or release-asset digest has been verified yet. Only the release owner runs
the steps below, after an independent review of the tool and green source CI. The tool's
author does not run them.

What this release proves is limited. Publication alone proves nothing about the bytes.
Verified distribution means the trusted expected manifest and artifact digests were
checked before anything was installed or executed; that is what a passing
`verify-public` adds. Even then it is evidence about packaging and the synthetic
reference only, not launch acceptance. It does not establish any of these:

- runner pairing
- `heel runner serve`
- HTTPS target traffic
- hosted findings
- launch readiness

Final Fable clean-room launch acceptance is still required after the public bytes exist.
So is a separately authorized real pair -> serve -> HTTPS journey.

## Fixed identity

| Item | Value |
| --- | --- |
| Repository | `ancilis/heel` (the only one the tool accepts) |
| Tag / release | `v1.3.0rc1`, `prerelease: true`, never `latest` |
| Assets | `heel_sim-1.3.0rc1-py3-none-any.whl`, `heel_sim-1.3.0rc1.tar.gz`, `heel-open-core-manifest.json` |
| Source of bytes | the committed files in `apps/heel-cloud/public/downloads/` at the expected commit |
| PyPI | not used; `publish.yml` keeps its stable-only condition `draft == false && prerelease == false` |

The tool talks only to `api.github.com` and `uploads.github.com`, and only on this
repository's release paths. Asset bytes come from GitHub's release-asset CDN hosts, which
must be HTTPS and are always contacted without credentials. There is no option to point
it at another API host, repository or tag.

The only authenticated writes it can send are `POST .../releases` (create the draft),
`PATCH .../releases/{id}` (publish it) and `POST` to the upload path (missing assets).
It has no Git-ref write path, no `DELETE` and no `PUT`.

## What the tool can and cannot guarantee

- **Tag.** The tool issues no Git-ref create, move or push request. Whenever it checks
  the tag, it requires `v1.3.0rc1` to exist and resolve to `SHA`. But GitHub's create
  and update release endpoints document that `target_commitish` "determines where the
  Git tag is created from", is "unused if the Git tag already exists", and defaults to
  the default branch. So if another privileged actor deletes the tag between two of the
  tool's requests, a release `POST` or `PATCH` can recreate the tag. Both requests send
  `target_commitish = SHA` explicitly, so any such implicit creation is bound to `SHA`
  rather than the default branch. That constrains the effect; it does not make it
  impossible. The tool re-reads the tag after staging and after publishing.
- **Bytes.** Reads and writes are separate REST requests. GitHub documents no
  conditional (`If-Match`/ETag) or compare-and-publish primitive for releases, and the
  tool sends none. The tool hashes all three draft assets before its one `PATCH`, and
  re-lists and hashes them again after it. That detects a writer that changed them in
  between; it cannot prevent one. Keeping other writers out of the window is the
  operational precondition below, not a technical lock.
- **Immutable releases.** GitHub's immutable-releases setting locks a release's tag
  and assets only *after* publication. It does not protect the draft window or the
  `PATCH`. The last recorded owner read showed it disabled for this repository. Enabling
  it is a separate hardening decision for the owner; this procedure does not change it
  or assume it.

## Preconditions

1. The candidate commit has been independently reviewed and source CI is green. Record
   the full 40-hex SHA as `SHA`.
2. A clean checkout of exactly `SHA`, run with Python 3.11 or newer. `git status` must
   show nothing, including untracked files.
3. `gh auth status` shows the release owner logged in to `github.com` with permission to
   create and edit releases (see "Credential permissions" below). The tool reads the
   credential with `gh auth token`, keeps it in memory only, and never puts it in argv,
   logs, notes or evidence.
4. The release owner creates and pushes the tag `v1.3.0rc1` at `SHA` themselves. The
   tool sends no tag or Git-ref write; see "What the tool can and cannot guarantee" for
   the implicit-creation case. A lightweight tag or an annotated tag is fine. Annotated
   tags are peeled at most four levels deep. Cycles, and tags that point at a tree or
   blob, are rejected.
5. The package index must be reachable for the `[runner]` extra (`cryptography==45.0.7`).
6. The release window below is recorded and coordinated.

### Credential permissions

From GitHub's REST documentation (Releases, and "Permissions required for fine-grained
personal access tokens"):

- Creating and editing a release requires push access. For a fine-grained token, the
  create (`POST /repos/{owner}/{repo}/releases`) and update
  (`PATCH /repos/{owner}/{repo}/releases/{release_id}`) endpoints are listed under the
  **Contents** repository permission (write).
- If the resolved target commit "adds or modifies any file under .github/workflows/
  relative to the repository's default branch, the authenticating token must be
  authorized to modify workflows". Otherwise the endpoint returns `404 Not Found` (some
  paths return `403 Resource not accessible by integration`). OAuth and classic personal
  access tokens need the `workflow` scope; fine-grained and GitHub App installation
  tokens also need the **Workflows** repository permission (write). The Actions
  `GITHUB_TOKEN` cannot be authorized for this.
- Check `git diff --stat origin/main "$SHA" -- .github/workflows` after a fresh fetch.
  If it is not empty, the owner's credential needs the workflow permission. (At the
  time of writing, the candidate branch changes `ci.yml`, `codeql.yml` and
  `publish.yml` relative to the last locally fetched `origin/main`.)

Missing access is an operator dependency. A `404`/`403` from the tool is reported, not
worked around: the tool never refreshes a login, adds scopes or retries with another
credential, and neither should the owner mid-window without recording it.

### Release window and other writers

GitHub offers no lock that stops another authorized writer from changing the tag,
release or assets while this procedure runs. Exclusive writing is therefore an explicit
operational trust assumption. Before `stage-draft`, the designated release owner
records, in the release evidence:

1. the source `SHA`, the tag `v1.3.0rc1` and (once it exists) the release id;
2. the release window: it starts before `stage-draft` and ends only after a successful
   `verify-public`, or after the owner records a published-but-unverified (`5`) or
   unknown (`4`) outcome and escalates it;
3. the release, tag and asset writers known to the owner (other administrators and
   maintainers with release access, and any automation that creates, edits or uploads
   to releases or tags), and the scope inspected to identify them (for example the
   repository's collaborator and team access settings and `.github/workflows`);
4. for each known writer, a written acknowledgement that they will stay inactive for
   the window. If none were identified, record that fact and the inspection scope. Do
   not invent acknowledgements, and do not claim every possible credential was
   enumerated;
5. the GitHub tag, release, asset and activity evidence the owner can see immediately
   before `stage-draft` and immediately after `verify-public`. Keep what is available.
   Snapshots show state at two moments; they do not prove that nothing happened in
   between, and an organization audit API that is unavailable is not a guarantee.

An identified writer that has not acknowledged the window blocks the procedure. This
coordination is what "the bytes cannot change during publication" rests on; the tool's
post-`PATCH` hashing and `verify-public` only detect a breach after the fact.

Compute the external manifest digest from the commit:

```sh
git show "$SHA:apps/heel-cloud/public/downloads/heel-open-core-manifest.json" | shasum -a 256
```

## Local checks before any remote call

`stage-draft` and `publish-and-verify` check all of the following before they read the
credential or contact GitHub. Any failure exits `3`, and nothing has been written.

- The checkout root is the tool's own checkout. `HEAD` equals `--expected-sha`. The
  worktree is clean, including untracked files.
- These committed sources all say `1.3.0rc1`: `pyproject.toml`,
  `release/open-core-v1.json`, `heel/__init__.py` (`__version__`) and
  `scripts/build_open_core_release.py` (`RELEASE_VERSION`). So does the wheel's
  `METADATA`.
- The commit's `apps/heel-cloud/public/downloads/` tree holds exactly the three assets,
  each a regular `100644` blob.
- The working directory's path components are plain directories, not symlinks. The
  directory lists exactly the three names. Each file is a regular file (opened with
  `O_NOFOLLOW`) whose bytes equal the committed blob.
- The manifest is byte-for-byte the builder's canonical manifest for that wheel and
  source archive: schema `heel.open-core-artifacts.v1`, version `1.3.0rc1`, names,
  sizes and SHA-256.
- Existing release checks, run as subprocesses with GitHub tokens removed from the
  environment:
  1. `python -I scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads --check`
     must exit 0 and print `open-core release artifacts are current`.
  2. `HEEL_REQUIRE_RUNNER_EXTRA_INSTALL=1 python -m unittest -v tests.test_public_runner_preview_release`
     must exit 0, run at least 5 tests and end with a bare `OK`. Any skip fails.

## 1. Stage the draft

```sh
python scripts/publish_runner_preview_release.py stage-draft \
  --repository ancilis/heel --tag v1.3.0rc1 --expected-sha "$SHA"
```

1. The tool checks the remote tag resolves to `SHA`.
2. It lists every release, following pagination, and finds the one with tag `v1.3.0rc1`.
   It refuses if there is more than one.
3. If none exists, it reads the tag again and creates one draft prerelease:
   `target_commitish = SHA`, the fixed title, notes generated from the verified
   manifest, and `make_latest = "false"`. If the tag was deleted after that read,
   GitHub recreates it at `SHA` (not the default branch) as a side effect of this
   request.
4. An existing release is reused only if all of these match: draft, prerelease, target,
   title, notes and upload location.
5. It lists every asset, following pagination. Each existing asset must have a canonical
   name, a unique id, a `state` of `uploaded`, this repository's asset URL, and the
   expected size and digest. It is then downloaded, and its bytes must equal the
   candidate.
6. Only missing assets are uploaded. Each one is re-listed and downloaded again to
   verify it.
7. It re-reads the tag; it must still resolve to `SHA`.

The tool refuses rather than repairs. It refuses unknown or duplicate assets,
conflicting bytes with the same name, a non-draft or non-prerelease release, and any
other target, title, notes or host. It never deletes, replaces or overwrites anything.

If a create or upload response is lost, the tool re-reads state. If the object is there,
it is verified and the run continues. If not, the tool exits `4` ("outcome unknown")
without retrying. Run `stage-draft` again later; it starts by re-reading.

Inspect the draft in the GitHub UI. It is still not public, and draft assets are not
evidence of anonymous availability.

## 2. Publish and verify

```sh
python scripts/publish_runner_preview_release.py publish-and-verify \
  --repository ancilis/heel --tag v1.3.0rc1 --expected-sha "$SHA"
```

1. The tool repeats the local checks and the tag check.
2. It requires the matching draft to hold exactly the three verified assets.
3. Immediately before publishing, it reads `HEAD`, the clean state and the remote tag
   again.
4. It sends one `PATCH` with `draft: false, prerelease: true, make_latest: "false",
   target_commitish: SHA`. The explicit target means that, if the tag was deleted after
   step 3, GitHub's implicit recreation is bound to `SHA` instead of falling back to the
   default branch. The stored draft target is not relied on for this.
5. It re-reads the release whether or not the response arrived. Publication counts as
   established only when that re-read is a well-formed record of the same release id,
   URL, tag and title with `draft: false`:
   - the re-read fails, or returns a malformed or different release: exit `4`
     (outcome unknown); nothing is retried, and publication is not claimed
   - still a draft: exit `4`; nothing is retried
   - published: it says whether the publish was acknowledged, then continues
6. After publication is established, before any success, it checks the acknowledged
   response names the same release and `SHA`; checks the re-read's target, prerelease
   flag and notes; re-reads the tag; re-lists the assets; and downloads and hashes all
   three. Any failure or read error here exits `5`.
7. It never converts a stable release. If the release is already a published matching
   prerelease, the tool sends no publish request and says so, but still re-lists and
   hashes its assets; a mismatch exits `5`.
8. It runs `verify-public` in a new process with these properties:
   - `python -I`
   - working directory: a new temporary directory outside the checkout
   - `HOME` set to a new empty directory
   - no GitHub token, git configuration, netrc or pip configuration

Exit `5` means the release **is published** but a later verification failed: the
post-publication check, the anonymous verification, or the verification process itself.
It is never a success. Do not delete, recreate, replace or re-upload anything; the tool
prints the read-only `verify-public` recovery command (step 3). If the bytes really
changed, `verify-public` fails before installing or running anything, and the owner
escalates with the recorded window evidence.

Exit `4` after a `PATCH` means the tool could not establish the outcome. Do not repeat
the `PATCH` blindly. Re-run `publish-and-verify` later; it re-reads first and sends no
second publish request if the release is already published.

## 3. Read-only public verification and recovery

```sh
python -I scripts/publish_runner_preview_release.py verify-public \
  --repository ancilis/heel --tag v1.3.0rc1 --expected-sha "$SHA" \
  --expected-manifest-sha256 "$MANIFEST_SHA256"
```

`verify-public` never reads a credential and only sends `GET` requests. It may run from
any directory, ideally a fresh machine or shell.

1. It checks the anonymous tag.
2. It reads the public release by tag. The release must be published, a prerelease, at
   `SHA`, with the fixed title.
3. It requires exactly the three assets at
   `https://github.com/ancilis/heel/releases/download/v1.3.0rc1/<name>`.
4. It downloads each asset into a new directory outside the checkout. Downloads are
   bounded by the listed size, and only HTTPS CDN redirects are followed.
5. It requires the manifest SHA-256 to equal `--expected-manifest-sha256`, the
   canonical manifest to match the wheel and source archive, and the release notes to
   equal the notes generated from those bytes.
6. It creates a Python venv in that directory, using a credential-scrubbed environment.
7. It installs `./heel_sim-1.3.0rc1-py3-none-any.whl[runner]` with `pip --isolated`
   and runs `pip check`.
8. It checks that `heel-sim 1.3.0rc1` and `cryptography 45.0.7` are installed, that
   `heel` imports from the venv rather than a checkout, and that `heel.saas` is absent.
9. It runs `heel scope create --target reference:export`, then
   `heel reference run --case vulnerable` (`verified_violation`) and `--case hardened`
   (`invariant_held`). Both must report `reference_only`, no network calls and no upload.

It prints one JSON evidence record. That record lists the asset sizes and digests, the
installed versions and the two outcomes, plus an explicit `not_proven` list (pairing,
serve, HTTPS target traffic, hosted findings, launch readiness). Step logs stay in the
printed `work_directory`. A failure exits non-zero and prints no success record.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | the mode completed and its evidence was printed |
| `1` | verification failed (`verify-public`, or a proof step) |
| `2` | usage, including running with no mode |
| `3` | refused: a precondition failed and this run sent no mutation |
| `4` | outcome unknown: a mutation was sent and could not be confirmed by re-reading; nothing was retried |
| `5` | published, but post-publication or anonymous verification failed; never a success; recover read-only with `verify-public` |

## After publication

Record the following in the release evidence:

- the `verify-public` JSON
- the release id
- the GitHub URL
- the manifest digest from the notes

- the release-window record and the before/after GitHub evidence

Customer copy may cite the public URL and digests only after a successful anonymous
`verify-public`. Any customer-facing install command must itself keep a trusted digest
check before installation; no verified public URL exists yet. Final Fable clean-room
launch acceptance repeats anonymous acquisition independently. Remaining trust
assumptions and limits:

- No other writer acts during the release window. This is coordination, not a lock.
  An undisclosed or compromised credential could still act; post-publication hashing
  and `verify-public` would detect changed bytes, but only after exposure.
- A deleted tag can be recreated by a release request, bound to `SHA`.
- The loopback tests model GitHub from its documentation; real wire behaviour is
  confirmed only by the owner run.
- The tool never asserts anything about the PyPI route beyond the unchanged stable-only
  workflow condition.
