# Runner preview 1.3.0rc6 release procedure (release owner)

This is the administrative procedure for publishing the committed `1.3.0rc6` candidate
as the GitHub **prerelease** `v1.3.0rc6`, titled `Heel runner preview 1.3.0rc6`, together with the
standalone synthetic staging fixture, with
`scripts/publish_runner_preview_release_rc6.py`.

Status: **final pins in place (`PIN_STATUS = "FINAL"`); not yet performed.** The pins
below are the rc6 artifacts built once at source `db34fafe4ac892e4c2361bd0cd96c78b5278b9d2`
(tree `19902b10f3cfd6b4d3f82643e709f09b91e0910e`). That source is the E3 SOURCE/UX-accepted candidate
`72a1e049598af8aec3d8b4698ceaf743eaebb7b1` (descendant of `origin/main` `b7e00b3b`) plus the rc5
publisher test's move to the historical rc5 fixture, the version-bound tests, the rc6 re-version
with the single artifact build, the H2 runtime-lock refresh and the staging-fixture publication
inputs. The later commits that add this tool, its test and this runbook, and the Worker's legacy rc5
download alias, change none of the pinned bytes. No `v1.3.0rc6` tag, draft or release exists. Only
the release owner runs the steps below, after an independent review of this tool and green
exact-tree CI, and only under a separate publication decision. The tool's author does not run them.
The tool refuses every mode (exit `3`, before any credential read, gate or request) if `PIN_STATUS`
is anything but `FINAL`.

The rc6 tool is a separate, version-scoped copy of the reviewed and published rc5 tool
(`scripts/publish_runner_preview_release_rc5.py`). It differs from rc5 only in these hunks:

| Hunk | Change |
| --- | --- |
| E1 | module docstring names `1.3.0rc6` |
| E2 | `VERSION = "1.3.0rc6"` (tag, title, wheel and source archive names derive from it) |
| E3 | the pinned digests and sizes (`EXPECTED_SHA256`, `EXPECTED_SIZES`) for all eight assets and their comment |
| E4 | unchanged: `PIN_STATUS = "FINAL"` and the check at the start of `main` that refuses every mode unless it is `FINAL` are carried over byte for byte |
| E5 | the rc6 runner-change text in the release notes, replacing rc5's |
| E6 | user agent `heel-runner-preview-publisher-rc6` and program name |
| E7 | the tag-peeling docstring names `refs/tags/v1.3.0rc6` |
| F1 | module docstring: eight assets, and the staging fixture's purpose |
| F2 | `RUNNER_ASSET_NAMES` and the exact fixture constants: `FIXTURE_DIR`, `FIXTURE_FILES` (four asset to file names), `FIXTURE_REPOSITORY_ONLY` (`target.test.mjs`), `FIXTURE_MANIFEST` and its committed path and schema; `ASSET_NAMES` is the three runner artifacts, the four fixture files and the fixture manifest |
| F3 | `verify_artifact_set` also requires the canonical fixture manifest for the four fixture files' bytes (`verify_fixture_set`) |
| F4 | the release notes' fixture section: separate distribution, the operator's own Cloudflare account, `SOURCE_REVISION` (the expected source commit) and the five fixture rows from the pinned constants |
| F5 | the local candidate reads the runner artifacts from the downloads directory only, and the fixture from `tests/fixtures/customer_staging/` (exactly the four files plus `target.test.mjs`, regular committed blobs, no symlinked path) and `release/heel-staging-fixture-manifest.json` |
| F6 | refusal messages say eight candidate assets (and three runner artifacts for the downloads tree) |

The transport, GitHub client, tag peeling, draft, collision, outcome-unknown,
reconciliation, exact-digest binding, four-case installed proof and anonymous-verification
logic is reused unchanged; `tests/test_runner_preview_publisher_rc6.py` enforces that
diff bound with every changed line written out literally, exact changed-line counts, and the
carried E4 lines in both tools.
The rc1 to rc5 tools, their tests, runbooks and historical fixtures
(`tests/fixtures/runner_preview_rc1/` through `tests/fixtures/runner_preview_rc5/`) are
unchanged and byte-pinned by that test, except that the rc5 test now reads the published rc5
bytes from its historical fixture. The published `v1.3.0rc1` to `v1.3.0rc5`
releases, tags and their bytes are not touched by anything here.

What this release proves is limited. Publishing rc6 is component delivery, not a completed
customer journey and not customer acceptance. Verified distribution means the trusted
expected manifest and artifact digests were checked before anything was installed or
executed; that is what a passing `verify-public` adds. Even then it is evidence about
packaging and the synthetic reference only. The rc6 runner change (configured live read tests:
`heel runner serve` claims owner-approved, signed configured test plans from a Heel Cloud that
serves the configured-test sync route, and runs each instance as bounded `GET`/`HEAD` reads of one
literal imported route for a restricted and a control role, deciding one JSON field condition after
a success check, with local expected values in the operating system vault) is proven only with
local test fixtures and a local browser journey. Against a Heel Cloud without that route `serve`
refuses the response, so the Worker must be deployed before or with this runner. Only the `bearer`
credential profile has been exercised end to end. Findings semantics of the existing checks are
those of rc5: an ordinary plan-differential key-path observation is medium confidence
(`evidence_state` `observed`) and values are not compared, error envelopes are `inconclusive`,
and `verified` is reserved for a high-confidence finding where both isolated canary roles
received the exact approved marker. The known CI limitations recorded for rc5 (causes UNKNOWN,
not fixed) are carried unchanged. The staging fixture assets are a test fixture for a separately
deployed synthetic target: publishing them deploys nothing and grants access to nothing. It does
not establish any of these:

- runner pairing
- `heel runner serve`
- HTTPS target traffic
- hosted findings, or a deployed result handoff
- a plan-differential finding on a normal deployed target or through the public browser journey
- launch readiness

## Fixed identity

| Item | Value |
| --- | --- |
| Repository | `ancilis/heel` (the only one the tool accepts) |
| Tag / release | `v1.3.0rc6`, `prerelease: true`, `make_latest: "false"`, never `latest` |
| Wheel | `heel_sim-1.3.0rc6-py3-none-any.whl`, 2991367 bytes, SHA-256 `bf1bf975fd970bc79c2fdf711d5113f852fa72549fbc0117f47e12e205e5403e` |
| Source archive | `heel_sim-1.3.0rc6.tar.gz`, 635213 bytes, SHA-256 `2abee106f96b6c32cc77eb7e774f87b97ba7d9d465b8efccdb0f333a973e519b` |
| Manifest | `heel-open-core-manifest.json`, 347 bytes, SHA-256 `ce710dc0081c8e9a84d7662804367abfd22211847ac06f986b2573ad81d04aa8` |
| Fixture README | `heel-staging-fixture-README.md`, 30273 bytes, SHA-256 `7848ccc9c6aec7326e54e8d90aa299caceb494d69f62aba4671d83a377ffa004` |
| Fixture OpenAPI | `heel-staging-fixture-openapi.json`, 2282 bytes, SHA-256 `520288872cee2480168063427ce616e7ee15aa9931c8d0ec40029899f7c13f19` |
| Fixture Worker | `heel-staging-fixture-worker.mjs`, 13120 bytes, SHA-256 `b0d8c1f426986ab613c1f4ca46302607c249cf4a7bcb47c415ac747b552d3bf3` |
| Fixture config | `heel-staging-fixture-wrangler.jsonc`, 765 bytes, SHA-256 `9c33fbf3092722dbfde0f09d6ff68557a07e6cb7379c9e2d72509faaf46b988a` |
| Fixture manifest | `heel-staging-fixture-manifest.json`, 786 bytes, SHA-256 `ac52bd5d0520f279cb136c9523ff6102148002b6e6ee7755e86aafe6347bf434` |
| Source of fixture bytes | `tests/fixtures/customer_staging/{README.md,openapi.json,worker.mjs,wrangler.jsonc}` and `release/heel-staging-fixture-manifest.json` at the expected commit; `target.test.mjs` stays repository-only |
| Source of bytes | the committed files in `apps/heel-cloud/public/downloads/` at the expected commit (blobs `89ffd94bf8571e9ea5f981ad77ced3ebbf69ed35`, `f32cd5a3958dfd4d0291d70dd290f045baa179a6`, `6f759c743a22af99a18248096cba9075c564c33e` at `db34fafe4ac892e4c2361bd0cd96c78b5278b9d2`) |
| Runner extra | `cryptography==50.0.1`; Python 3.11 or newer |
| PyPI | not used; `publish.yml` keeps its stable-only condition `draft == false && prerelease == false` |

The digests and sizes are constants in the tool (`EXPECTED_SHA256`, `EXPECTED_SIZES`).
As for rc2, the tool refuses any local candidate (exit `3`, before reading a credential)
and fails any anonymously acquired public bytes (exit `1`, before installing anything)
whose SHA-256 or length differs from these exact values, even if the bytes and manifest
are internally consistent. The published rc5 bytes (`6fcaaa43`: wheel
`a7c7293be3e30f1c3fb6fd968ab16c2845ebaae34d4fe3bcb2ddfd54855aa226`, source archive `3cd3cbc9aa84381f58703c13cc0f446fa8fc8fe57d395283cdc422ff3ded579e`, manifest `8d822c5eea3bebf8b4b5b139121165b4be218e1914743b8561ec22414f5eef51`) are therefore refused;
`FinalizationTests` also requires every rc6 runner digest to differ from those rc5 digests.
The fixture assets have no earlier release; their pins are bound to the committed files and to
the canonical fixture manifest.

The tool talks only to `api.github.com` and `uploads.github.com`, and only on this
repository's release paths. Asset bytes come from GitHub's release-asset CDN hosts, which
must be HTTPS and are always contacted without credentials. There is no option to point
it at another API host, repository or tag.

The only authenticated writes it can send are `POST .../releases` (create the draft),
`PATCH .../releases/{id}` (publish it) and `POST` to the upload path (missing assets).
It has no Git-ref write path, no `DELETE` and no `PUT`, and no primitive that converts a
prerelease into a stable release.

## What the tool can and cannot guarantee

These are the rc2 guarantees and limits, unchanged:

- **Tag.** The tool issues no Git-ref create, move or push request. Whenever it checks
  the tag, it requires `v1.3.0rc6` to exist and resolve to `SHA`. GitHub's create and
  update release endpoints create a missing tag from `target_commitish`, so if another
  privileged actor deletes the tag between two of the tool's requests, a release `POST`
  or `PATCH` can recreate the tag. Both requests send `target_commitish = SHA`
  explicitly, so any such implicit creation is bound to `SHA` rather than the default
  branch. That constrains the effect; it does not make it impossible. The tool re-reads
  the tag after staging and after publishing.
- **Bytes.** Reads and writes are separate REST requests with no compare-and-publish
  primitive. The tool hashes all eight draft assets before its one `PATCH` and re-lists
  and hashes them again after it. That detects a writer that changed them in between;
  it cannot prevent one. Keeping other writers out of the window is an operational
  precondition, not a technical lock.
- **Immutable releases.** GitHub's immutable-releases setting locks a release's tag and
  assets only after publication. This procedure does not change it or assume it; the
  release owner records its state at the window.

## Event side effects

| Event | Effect |
| --- | --- |
| Push of `refs/tags/v1.3.0rc6` (owner, outside the tool) | No workflow is expected to run: re-read every default-branch workflow's `on:` block at `SHA` before the window and record that none has `push: tags`. |
| Draft creation and asset uploads | No workflow runs (`publish.yml` listens only to `published`). Draft and draft assets are invisible anonymously. |
| Publication as a prerelease | One `publish.yml` run is created and its `verify-release` job is skipped by `if: github.event.release.draft == false && github.event.release.prerelease == false`; `publish` depends on it, so nothing goes to PyPI and no attestation is made. Repository watchers get GitHub's release notification. `make_latest: "false"` keeps `releases/latest` unchanged. The prerelease appears on the public releases page immediately. |
| Staging Worker deploy (separate task) | Serves the committed rc6 bytes at `/downloads/*` on the deployed origin; record whichever exposure happens first, as for rc2. |

### Hazard: converting the rc6 prerelease to a stable release

Do **not** un-check "Set as a pre-release" on `v1.3.0rc6` in the GitHub UI, and do not
edit the release to `prerelease: false` by any other means. `release/open-core-v1.json`
names `1.3.0rc6`, which equals the tag, so `publish.yml` would run for real against the
`pypi` environment, as described for rc2 in `docs/RUNNER_PREVIEW_RELEASE_RC2.md`. The
tool itself cannot cause this: `check_release` requires `prerelease is True`, both writes
send `prerelease: true`, and the source test asserts there is no stable-conversion
primitive.

## Platform support

Unchanged from rc2: the `[runner]` extra pins `cryptography==50.0.1`, which publishes
macOS wheels for Apple silicon only. Intel macOS is **not supported by this preview** and
is untested. Release-owner preflight must run on Apple silicon or Linux x86_64/aarch64
with Python 3.11 or newer, because the enforced runner-extra gate and `verify-public`
install the wheel's `[runner]` extra.

## Preconditions

0. This finalized tool (final pins, `PIN_STATUS = "FINAL"`) has had its own independent
   review. Until then stop here.
1. The candidate commit `SHA` (the merge on `main` that contains the eight final rc6
   assets' sources and this tool) has been independently reviewed and exact-tree CI is green. Its
   three downloads and five fixture assets must be byte-identical to the pins in "Fixed identity"; the tool
   refuses otherwise.
2. A clean checkout of exactly `SHA`, run with Python 3.11 or newer on a supported host.
   `git status` must show nothing, including untracked files.
3. `gh auth status` shows the release owner logged in to `github.com` with permission to
   create and edit releases. The tool reads the credential with `gh auth token`, keeps it
   in memory only, and never puts it in argv, logs, notes or evidence. No broader
   permission is needed or requested.
4. The release owner creates and pushes the tag `v1.3.0rc6` at `SHA` themselves. The
   tool sends no tag or Git-ref write.
5. The package index must be reachable for the `[runner]` extra (`cryptography==50.0.1`).
6. The release window is recorded and coordinated exactly as in
   `docs/RUNNER_PREVIEW_RELEASE.md` "Release window and other writers", with `v1.3.0rc6`
   as the tag. An identified writer that has not acknowledged the window blocks the
   procedure.

Compute the external manifest digest from the commit; it must equal the pinned manifest
digest in "Fixed identity":

```sh
git show "$SHA:apps/heel-cloud/public/downloads/heel-open-core-manifest.json" | shasum -a 256
```

## Local checks before any remote call

`stage-draft` and `publish-and-verify` check all of the following before they read the
credential or contact GitHub. Any failure exits `3`, and nothing has been written.

- `PIN_STATUS` is `FINAL`.
- The checkout root is the tool's own checkout. `HEAD` equals `--expected-sha`. The
  worktree is clean, including untracked files.
- `pyproject.toml`, `release/open-core-v1.json`, `heel/__init__.py` (`__version__`) and
  `scripts/build_open_core_release.py` (`RELEASE_VERSION`) all say `1.3.0rc6`, and so
  does the wheel's `METADATA`.
- The commit's downloads tree holds exactly the three runner assets as regular `100644` blobs;
  the working files are regular, non-symlinked and equal to those blobs.
- The commit's `tests/fixtures/customer_staging/` holds exactly `README.md`, `openapi.json`,
  `worker.mjs`, `wrangler.jsonc` and the repository-only `target.test.mjs`, and
  `release/heel-staging-fixture-manifest.json` is one regular blob; the working files are
  regular, reached through no symlink and equal to those blobs.
- The manifest is the builder's canonical manifest for that wheel and source archive, and the
  fixture manifest is the canonical manifest for the four fixture files.
- **Each artifact's SHA-256 and length equal the pinned values in "Fixed identity".**
- The builder `--check` and the enforced runner-extra tests
  (`HEEL_REQUIRE_RUNNER_EXTRA_INSTALL=1 python -m unittest -v tests.test_public_runner_preview_release`,
  at least 5 tests, bare `OK`, no skips) pass, run with GitHub tokens removed.

## 1. Stage the draft

```sh
python scripts/publish_runner_preview_release_rc6.py stage-draft \
  --repository ancilis/heel --tag v1.3.0rc6 --expected-sha "$SHA"
```

The rc2 behaviour with the rc6 identity: verify the remote tag; find the single release on
`v1.3.0rc6` (more than one refuses); otherwise create one draft prerelease with
`target_commitish = SHA`, the fixed title, notes generated from the verified manifest and
`make_latest = "false"`; reuse an existing release only if draft, prerelease, target,
title, notes and upload location all match; verify every existing asset's name, id,
state, URL, size, digest and downloaded bytes; upload only missing assets and re-verify
each; re-read the tag.

The tool refuses rather than repairs: unknown or duplicate assets, same-name assets with
different bytes, a non-draft or non-prerelease release, and any other target, title,
notes or host. It never deletes, replaces or overwrites anything. If a create or upload
response is lost, the tool re-reads state: present objects are verified and the run
continues; otherwise it exits `4` (outcome unknown) without retrying. Run `stage-draft`
again later; it starts by re-reading.

## 2. Publish and verify

```sh
python scripts/publish_runner_preview_release_rc6.py publish-and-verify \
  --repository ancilis/heel --tag v1.3.0rc6 --expected-sha "$SHA"
```

The rc2 behaviour with the rc6 identity: repeat the local checks and the tag check;
require the matching draft with exactly the eight verified assets; re-read `HEAD`, clean
state and tag; send one `PATCH {draft: false, prerelease: true, make_latest: "false",
target_commitish: SHA}`; re-read the release; check the acknowledgement and the re-read;
re-read the tag; re-list and re-hash all assets; then run `verify-public` in a new
`python -I` process outside the checkout with no GitHub credential, git, netrc or pip
configuration.

Exit `5` means the release **is published** but a later verification failed. It is never
a success. Do not delete, recreate, replace or re-upload anything; the tool prints the
read-only `verify-public` recovery command. Exit `4` after a `PATCH` means the outcome
could not be established; do not repeat the `PATCH` blindly. Re-run `publish-and-verify`
later; it re-reads first and sends no second publish request if the release is already
published.

## 3. Read-only public verification and recovery

```sh
python -I scripts/publish_runner_preview_release_rc6.py verify-public \
  --repository ancilis/heel --tag v1.3.0rc6 --expected-sha "$SHA" \
  --expected-manifest-sha256 "<pinned manifest SHA-256 from Fixed identity>"
```

`verify-public` never reads a credential and only sends `GET` requests. Its steps are the
rc2 steps with the rc6 identity: anonymous tag and release checks; exactly the eight
assets at `https://github.com/ancilis/heel/releases/download/v1.3.0rc6/<name>`, each
downloaded within its listed size into a new directory outside the checkout; the
expected manifest digest, the canonical manifest, **each asset's pinned SHA-256 and
length** and the generated release notes, all before anything is installed; a venv in a
credential-scrubbed environment with `./heel_sim-1.3.0rc6-py3-none-any.whl[runner]` and
`pip check`; `heel-sim 1.3.0rc6` and `cryptography 50.0.1` installed, `heel` imported from
the venv and `heel.saas` absent; then the same four synthetic reference cases as rc2:

| Case | Attempt | Result | `regression_passed` | `evidence_state` |
| --- | --- | --- | --- | --- |
| `vulnerable` | `5` x 32 | `verified_violation` | `false` | (not asserted) |
| `public` | `6` x 32 | `invariant_held` | `true` | (not asserted) |
| `hardened` (HTTP 403) | `7` x 32 | `inconclusive` | `false` | `unknown` |
| `error_envelope` (HTTP 200) | `8` x 32 | `inconclusive` | `false` | `unknown` |

It prints one JSON evidence record with asset sizes and digests, installed versions, the
four outcomes and an explicit `not_proven` list. A failure exits non-zero and prints no
success record.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | the mode completed and its evidence was printed |
| `1` | verification failed (`verify-public`, or a proof step) |
| `2` | usage, including running with no mode |
| `3` | refused: a precondition failed (including pins not final) and this run sent no mutation |
| `4` | outcome unknown: a mutation was sent and could not be confirmed by re-reading; nothing was retried |
| `5` | published, but post-publication or anonymous verification failed; never a success; recover read-only with `verify-public` |

## Customer install command (deployable only after a passing anonymous verify-public)

The customer surfaces in this candidate already name this command; the pin is provisional until
an anonymous `verify-public` for `v1.3.0rc6` has passed and its evidence is recorded. Do not deploy
the Worker that serves that copy before then. Prerequisites: Python 3.11
or newer available as `python3`, with its standard `venv` module; Apple silicon macOS or
Linux x86_64/aarch64. One copy-paste command creates an isolated venv in `./heel-rc6`,
installs the hash-pinned wheel with its `[runner]` extra, and prints the installed version;
the CLI is then `./heel-rc6/bin/heel`:

```sh
python3 -m venv heel-rc6 && ./heel-rc6/bin/python -m pip --isolated install 'heel-sim[runner] @ https://github.com/ancilis/heel/releases/download/v1.3.0rc6/heel_sim-1.3.0rc6-py3-none-any.whl#sha256=bf1bf975fd970bc79c2fdf711d5113f852fa72549fbc0117f47e12e205e5403e' && ./heel-rc6/bin/heel --version
```

pip refuses to install the wheel unless its SHA-256 equals the pinned digest. The
`cryptography==50.0.1` dependency comes from the package index under pip's normal
verification; it is not hash-pinned by this command.

## Staging fixture download (no checkout)

The fixture README gives the same anonymous procedure: download the four
`heel-staging-fixture-*` files from `https://github.com/ancilis/heel/releases/download/v1.3.0rc6/`
into one directory under their original names, download the fixture manifest, compare every
SHA-256 with it and with the release notes, and take `SOURCE_REVISION` from the release notes. No
git, checkout, private configuration or helper is needed; deploying it needs the operator's own
authorized Cloudflare account and the prerequisites the README declares.

## Legacy rc5 bytes and links

Moving the current assets to rc6 updates current indexes; it does not delete or relabel any
immutable versioned asset.

| What | rc5 identity | After this candidate |
| --- | --- | --- |
| GitHub release `v1.3.0rc5` (id 444618116, tag object `9a05e067`, target `6fcaaa43`) | wheel 2869122 bytes `a7c7293b…a226`, source archive 610466 bytes `3cd3cbc9…579e`, manifest 347 bytes `8d822c5e…ef51` | untouched: nothing here sends a request for it; the rc6 tool reads its tag paths only for `v1.3.0rc6` and writes only to the one release it found and checked by that tag; the published rc5 install command keeps working |
| Repository copy of those bytes | `tests/fixtures/runner_preview_rc5/` (same blobs `0437447e`, `f1d5556e`, `c5beaa79`) | byte-pinned by `tests/test_runner_preview_publisher_rc5.py` and by `PROTECTED_BLOBS` in the rc6 test |
| Site path `/downloads/heel_sim-1.3.0rc5-py3-none-any.whl` and `/downloads/heel_sim-1.3.0rc5.tar.gz` (served by the deployed rc5 Worker and named by rc5 copy) | the same bytes as the release assets | the Worker answers exactly these two paths (`GET`/`HEAD`, no query) with `308` to the corresponding `v1.3.0rc5` release asset; same file name, same bytes; a client must follow redirects (`curl -L`) |
| Site path `/downloads/heel-open-core-manifest.json` | an unversioned current index | now the rc6 manifest; the rc5 manifest stays immutable as the `v1.3.0rc5` release asset and in the fixture |
| `/heel-runtime/heel_browser-1.3.0rc5-py3-none-any.whl` | an internal browser-engine runtime file, loaded through the page's engine manifest, never a customer link and never a release asset | replaced by the rc6 engine; a page opened before the Worker deploy reloads to the rc6 engine; saved reviews carry `engine_version` 1.3.0rc5, which stays accepted. The rc5 bytes stay in Git history (blob of `apps/heel-cloud/browser-engine/heel_browser-1.3.0rc5-py3-none-any.whl` at `6fcaaa43`) and in the deployed rc5 Worker version kept for rollback |

The current `/downloads/` guards stay exact: `scripts/prepare-runtime.mjs`, the production
artifact test, the release-version and plan-differential release tests and this tool's local gate
each still require exactly the three current runner files. The legacy alias is a fixed two-entry
map in `worker/index.ts`, covered by `tests/legacy-downloads.test.ts`; it serves no rc5 file from
the site and allows no other name.

## Candidate binding and finalization

`tests/test_runner_preview_publisher_rc6.py` reads this checkout's
`apps/heel-cloud/public/downloads/*`, the four staging fixture files, the fixture manifest and the
four version sources and requires them to equal the pinned rc6 blob ids, digests and sizes; it
fails at import on purpose if any of them changes. E3 carries the rc6 digests and sizes for all
eight assets, E4 keeps `PIN_STATUS = "FINAL"`, the test pins `PINNED_COMMIT` (`db34fafe4ac892e4c2361bd0cd96c78b5278b9d2`) and the rc6
blobs, and `INTERIM_SHA256` keeps the published rc5 runner digests so the rc6 ones must differ from
them. The E5 release-note text describes the accepted scope and matches the rc6 CHANGELOG entry at
that source.

A later candidate (for example rc7) that replaces the downloads must move the rc6 bytes and fixture
assets into a historical fixture (the rc1 to rc5 precedent) or retire this tool; it must not
silently re-pin.

## After publication

Record the `verify-public` JSON, the release id, the GitHub URL, the manifest digest from
the notes, the release-window record and the before/after GitHub evidence, and whether
the Worker exposure happened first. Remaining trust assumptions and limits are those of
the rc1 to rc5 runbooks.
