# Runner preview 1.3.0rc3 release procedure (release owner)

This is the administrative procedure for publishing the committed `1.3.0rc3` candidate
as the GitHub **prerelease** `v1.3.0rc3`, titled `Heel runner preview 1.3.0rc3`, with
`scripts/publish_runner_preview_release_rc3.py`.

Status: **final pins in place (`PIN_STATUS = "FINAL"`); not yet performed.** The pins
below are the final reviewed rc3 artifacts at source `4b68c2f96d3c0c85c9c0a0a6453f72b4f56c8ca4`
(tree `8989f05fb4691b7f53a362a8712c21404e58e239`). That source carries the five earlier
runner commits, the paired plan-differential bridge (`755e921`, patch-identical to the
reviewed `8696619`), the evidence-state display (`1766782`, patch-identical to the reviewed
`6b3cf3f`) and the single artifact refresh `1c53324`. No `v1.3.0rc3` tag, draft or release
exists. Only the release owner runs the steps below, after an independent review of this
finalized tool and green exact-tree CI, and only under a separate publication decision.
The tool's author does not run them. The tool refuses every mode (exit `3`, before any
credential read, gate or request) if `PIN_STATUS` is anything but `FINAL`.

The rc3 tool is a separate, version-scoped copy of the reviewed and published rc2 tool
(`scripts/publish_runner_preview_release_rc2.py`). It differs from rc2 only in the
enumerated E1-E7 hunks:

| Hunk | Change |
| --- | --- |
| E1 | module docstring names `1.3.0rc3` |
| E2 | `VERSION = "1.3.0rc3"` (tag, title, wheel and source archive names derive from it) |
| E3 | the pinned digests and sizes (`EXPECTED_SHA256`, `EXPECTED_SIZES`) and their comment |
| E4 | `PIN_STATUS` and the one check at the start of `main` that refuses every mode unless it is `FINAL` |
| E5 | the rc3 runner-change text in the release notes, replacing rc2's rc1-errata sentence |
| E6 | user agent `heel-runner-preview-publisher-rc3` and program name |
| E7 | the tag-peeling docstring names `refs/tags/v1.3.0rc3` |

The transport, GitHub client, tag peeling, draft, collision, outcome-unknown,
reconciliation, exact-digest binding, four-case installed proof and anonymous-verification
logic is reused unchanged; `tests/test_runner_preview_publisher_rc3.py` enforces that
diff bound with exact changed-line counts. The rc1 and rc2 tools, their tests, runbooks
and historical fixtures (`tests/fixtures/runner_preview_rc1/`,
`tests/fixtures/runner_preview_rc2/`) are unchanged and byte-pinned by that test. The
published `v1.3.0rc2` release and its bytes are not touched by anything here.

What this release proves is limited. Publishing rc3 is component delivery, not a completed
customer journey and not customer acceptance. Verified distribution means the trusted
expected manifest and artifact digests were checked before anything was installed or
executed; that is what a passing `verify-public` adds. Even then it is evidence about
packaging and the synthetic reference only. The rc3 runner changes (plan submission
through `serve`, signed local findings, saved regression replay) are proven only with
local test fixtures. So is the markerless plan-differential result: when an approved
`plan_entitlement_read` pair binds no canary marker, the runner compares the two stored,
redacted responses by key path only, and a lower-plan response that covers every key path
of the higher-plan response, with the higher-plan control succeeding, is a medium-confidence key-path observation (`evidence_state`
`observed`). Values are not compared and plan gating is not declared, so it is not the
verified canary behaviour: `verified` is reserved for a high-confidence finding where both
isolated canary roles received the exact approved marker. The `evidence_states` list that
`runner findings --run` prints is unsigned and derived from the signed results. It does not
establish any of these:

- runner pairing
- `heel runner serve`
- HTTPS target traffic
- hosted findings
- a plan-differential finding on a normal deployed target or through the public browser journey
- launch readiness

## Fixed identity

| Item | Value |
| --- | --- |
| Repository | `ancilis/heel` (the only one the tool accepts) |
| Tag / release | `v1.3.0rc3`, `prerelease: true`, `make_latest: "false"`, never `latest` |
| Wheel | `heel_sim-1.3.0rc3-py3-none-any.whl`, 2769936 bytes, SHA-256 `0b75aef7c22a18b78fdafcdffce995a90b1ba3da5b09db166f24e89c49419bca` |
| Source archive | `heel_sim-1.3.0rc3.tar.gz`, 591640 bytes, SHA-256 `fd5c5e2cf54849ec81368dd641f4ba9e1a71b4cf790ee7ce2ce341c30fb996f3` |
| Manifest | `heel-open-core-manifest.json`, 347 bytes, SHA-256 `7eb56ad211d53d87f6a0e093252966d26e65f4404c76f3302966cb22f435e8a0` |
| Source of bytes | the committed files in `apps/heel-cloud/public/downloads/` at the expected commit (blobs `7fcbeb6621c30fbf7239e4f3b9e682e27b03011d`, `a1ece2a02488c38024d29e3d949052987dde9004`, `260aebd9ca49e17b1bff58611b3066cf8ea24738` at `4b68c2f96d3c0c85c9c0a0a6453f72b4f56c8ca4`) |
| Runner extra | `cryptography==50.0.1`; Python 3.11 or newer |
| PyPI | not used; `publish.yml` keeps its stable-only condition `draft == false && prerelease == false` |

The digests and sizes are constants in the tool (`EXPECTED_SHA256`, `EXPECTED_SIZES`).
As for rc2, the tool refuses any local candidate (exit `3`, before reading a credential)
and fails any anonymously acquired public bytes (exit `1`, before installing anything)
whose SHA-256 or length differs from these exact values, even if the bytes and manifest
are internally consistent. The interim rc3 candidate bytes (`cbbc531c`: wheel
`6ce976ac2d703c735d933b2a4d77406a1181b54b2eac4c13199da2c79dc79c5c`, source archive `d55397d880e6396ace238cb48a0dacfe969ad7b564803e2921980406b3175b7c`, manifest `988fc2bda719e15bf03cfacb9477a1c7c568b420afacb88d2a91aa9285eafef3`) are therefore refused;
`FinalizationTests` also requires every final digest to differ from those interim digests.

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
  the tag, it requires `v1.3.0rc3` to exist and resolve to `SHA`. GitHub's create and
  update release endpoints create a missing tag from `target_commitish`, so if another
  privileged actor deletes the tag between two of the tool's requests, a release `POST`
  or `PATCH` can recreate the tag. Both requests send `target_commitish = SHA`
  explicitly, so any such implicit creation is bound to `SHA` rather than the default
  branch. That constrains the effect; it does not make it impossible. The tool re-reads
  the tag after staging and after publishing.
- **Bytes.** Reads and writes are separate REST requests with no compare-and-publish
  primitive. The tool hashes all three draft assets before its one `PATCH` and re-lists
  and hashes them again after it. That detects a writer that changed them in between;
  it cannot prevent one. Keeping other writers out of the window is an operational
  precondition, not a technical lock.
- **Immutable releases.** GitHub's immutable-releases setting locks a release's tag and
  assets only after publication. This procedure does not change it or assume it; the
  release owner records its state at the window.

## Event side effects

| Event | Effect |
| --- | --- |
| Push of `refs/tags/v1.3.0rc3` (owner, outside the tool) | No workflow is expected to run: re-read every default-branch workflow's `on:` block at `SHA` before the window and record that none has `push: tags`. |
| Draft creation and asset uploads | No workflow runs (`publish.yml` listens only to `published`). Draft and draft assets are invisible anonymously. |
| Publication as a prerelease | One `publish.yml` run is created and its `verify-release` job is skipped by `if: github.event.release.draft == false && github.event.release.prerelease == false`; `publish` depends on it, so nothing goes to PyPI and no attestation is made. Repository watchers get GitHub's release notification. `make_latest: "false"` keeps `releases/latest` unchanged. The prerelease appears on the public releases page immediately. |
| Staging Worker deploy (separate task) | Serves the committed rc3 bytes at `/downloads/*` on the deployed origin; record whichever exposure happens first, as for rc2. |

### Hazard: converting the rc3 prerelease to a stable release

Do **not** un-check "Set as a pre-release" on `v1.3.0rc3` in the GitHub UI, and do not
edit the release to `prerelease: false` by any other means. `release/open-core-v1.json`
names `1.3.0rc3`, which equals the tag, so `publish.yml` would run for real against the
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
1. The candidate commit `SHA` (the merge on `main` that contains the three final rc3
   files and this tool) has been independently reviewed and exact-tree CI is green. Its
   three downloads must be byte-identical to the pins in "Fixed identity"; the tool
   refuses otherwise.
2. A clean checkout of exactly `SHA`, run with Python 3.11 or newer on a supported host.
   `git status` must show nothing, including untracked files.
3. `gh auth status` shows the release owner logged in to `github.com` with permission to
   create and edit releases. The tool reads the credential with `gh auth token`, keeps it
   in memory only, and never puts it in argv, logs, notes or evidence. No broader
   permission is needed or requested.
4. The release owner creates and pushes the tag `v1.3.0rc3` at `SHA` themselves. The
   tool sends no tag or Git-ref write.
5. The package index must be reachable for the `[runner]` extra (`cryptography==50.0.1`).
6. The release window is recorded and coordinated exactly as in
   `docs/RUNNER_PREVIEW_RELEASE.md` "Release window and other writers", with `v1.3.0rc3`
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
  `scripts/build_open_core_release.py` (`RELEASE_VERSION`) all say `1.3.0rc3`, and so
  does the wheel's `METADATA`.
- The commit's downloads tree holds exactly the three assets as regular `100644` blobs;
  the working files are regular, non-symlinked and equal to those blobs.
- The manifest is the builder's canonical manifest for that wheel and source archive.
- **Each artifact's SHA-256 and length equal the pinned values in "Fixed identity".**
- The builder `--check` and the enforced runner-extra tests
  (`HEEL_REQUIRE_RUNNER_EXTRA_INSTALL=1 python -m unittest -v tests.test_public_runner_preview_release`,
  at least 5 tests, bare `OK`, no skips) pass, run with GitHub tokens removed.

## 1. Stage the draft

```sh
python scripts/publish_runner_preview_release_rc3.py stage-draft \
  --repository ancilis/heel --tag v1.3.0rc3 --expected-sha "$SHA"
```

The rc2 behaviour with the rc3 identity: verify the remote tag; find the single release on
`v1.3.0rc3` (more than one refuses); otherwise create one draft prerelease with
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
python scripts/publish_runner_preview_release_rc3.py publish-and-verify \
  --repository ancilis/heel --tag v1.3.0rc3 --expected-sha "$SHA"
```

The rc2 behaviour with the rc3 identity: repeat the local checks and the tag check;
require the matching draft with exactly the three verified assets; re-read `HEAD`, clean
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
python -I scripts/publish_runner_preview_release_rc3.py verify-public \
  --repository ancilis/heel --tag v1.3.0rc3 --expected-sha "$SHA" \
  --expected-manifest-sha256 "<pinned manifest SHA-256 from Fixed identity>"
```

`verify-public` never reads a credential and only sends `GET` requests. Its steps are the
rc2 steps with the rc3 identity: anonymous tag and release checks; exactly the three
assets at `https://github.com/ancilis/heel/releases/download/v1.3.0rc3/<name>`, each
downloaded within its listed size into a new directory outside the checkout; the
expected manifest digest, the canonical manifest, **each asset's pinned SHA-256 and
length** and the generated release notes, all before anything is installed; a venv in a
credential-scrubbed environment with `./heel_sim-1.3.0rc3-py3-none-any.whl[runner]` and
`pip check`; `heel-sim 1.3.0rc3` and `cryptography 50.0.1` installed, `heel` imported from
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

## Customer install command (publishable only after a passing anonymous verify-public)

Do not put this in customer copy until an anonymous
`verify-public` for `v1.3.0rc3` has passed and its evidence is recorded. Customer copy
keeps the published rc2 command until then. Prerequisites: Python 3.11 or newer available
as `python3`, with its standard `venv` module; Apple silicon macOS or Linux
x86_64/aarch64. One copy-paste command creates an isolated venv in `./heel-rc3`, installs
the hash-pinned wheel with its `[runner]` extra, and prints the installed version; the
CLI is then `./heel-rc3/bin/heel`:

```sh
python3 -m venv heel-rc3 && ./heel-rc3/bin/python -m pip --isolated install 'heel-sim[runner] @ https://github.com/ancilis/heel/releases/download/v1.3.0rc3/heel_sim-1.3.0rc3-py3-none-any.whl#sha256=0b75aef7c22a18b78fdafcdffce995a90b1ba3da5b09db166f24e89c49419bca' && ./heel-rc3/bin/heel --version
```

pip refuses to install the wheel unless its SHA-256 equals the pinned digest. The
`cryptography==50.0.1` dependency comes from the package index under pip's normal
verification; it is not hash-pinned by this command.

## Candidate binding and finalization

`tests/test_runner_preview_publisher_rc3.py` reads this checkout's
`apps/heel-cloud/public/downloads/*` and the four version sources and requires them to
equal the pinned rc3 blob ids, digests and sizes; it fails at import on purpose if any
of them changes. Finalization is done: E3 carries the final digests and sizes, E4 sets
`PIN_STATUS = "FINAL"`, the test pins `PINNED_COMMIT` (`4b68c2f96d3c0c85c9c0a0a6453f72b4f56c8ca4`) and the final blobs,
and `INTERIM_SHA256` keeps the interim digests so the final ones must differ from them.
The E5 release-note text describes the accepted scope and matches the rc3 CHANGELOG entry
at that source.

A later candidate (for example rc4) that replaces the downloads must move the rc3 bytes
into a historical fixture (the rc1 and rc2 precedent) or retire this tool; it must not
silently re-pin.

## After publication

Record the `verify-public` JSON, the release id, the GitHub URL, the manifest digest from
the notes, the release-window record and the before/after GitHub evidence, and whether
the Worker exposure happened first. Remaining trust assumptions and limits are those of
the rc1 and rc2 runbooks.
