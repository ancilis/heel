# Runner preview 1.3.0rc2 release procedure (release owner)

This is the administrative procedure for publishing the committed `1.3.0rc2` candidate
as the GitHub **prerelease** `v1.3.0rc2`, titled `Heel runner preview 1.3.0rc2`, with
`scripts/publish_runner_preview_release_rc2.py`.

Status: **not yet performed.** No `v1.3.0rc2` tag, draft or release exists. No public
URL or release-asset digest has been verified. Only the release owner runs the steps
below, after an independent review of the tool and green source CI, and only under a
separate publication decision. The tool's author does not run them.

The rc2 tool is a separate, version-scoped copy of the reviewed rc1 tool
(`scripts/publish_runner_preview_release.py`). It differs from rc1 only in the enumerated
D1-D10 hunks: identity (`1.3.0rc2`, user agent, program name, tag docstring), the
`cryptography==50.0.1` runner pin, the exact accepted digests and sizes, the rc2 release
notes and the rc2 four-case installed proof. The transport, GitHub client, tag peeling,
draft, collision, outcome-unknown, reconciliation and anonymous-verification logic is
reused unchanged; `tests/test_runner_preview_publisher_rc2.py` enforces that diff bound.
The rc1 tool, its tests, its fixture and `docs/RUNNER_PREVIEW_RELEASE.md` are unchanged.

What this release proves is limited. Publishing rc2 is component delivery toward
customer step 5, not a completed customer journey and not customer acceptance. Verified
distribution means the trusted expected manifest and artifact digests were checked
before anything was installed or executed; that is what a passing `verify-public` adds.
Even then it is evidence about packaging and the synthetic reference only. It does not
establish any of these:

- runner pairing
- `heel runner serve`
- HTTPS target traffic
- hosted findings
- launch readiness

Both the original customer-local journey and the approved hosted Option 1 remain open;
this procedure bypasses neither the C3 provider stop nor any held runtime guard.

## Fixed identity

| Item | Value |
| --- | --- |
| Repository | `ancilis/heel` (the only one the tool accepts) |
| Tag / release | `v1.3.0rc2`, `prerelease: true`, `make_latest: "false"`, never `latest` |
| Wheel | `heel_sim-1.3.0rc2-py3-none-any.whl`, 2707051 bytes, SHA-256 `f8698204e1d38aa80b8ca31dedd743c3d42e28d02c5153bddb4f02b44ecdf01c` |
| Source archive | `heel_sim-1.3.0rc2.tar.gz`, 577946 bytes, SHA-256 `5903ce81b81e6243547881b82288376d3a45ba6b4ef41e88ca108b84994604b6` |
| Manifest | `heel-open-core-manifest.json`, 347 bytes, SHA-256 `eb3e5536fe22d040fbd3805fea60ec67b1933ff8c8d6f7c91d443cc46aefbff8` |
| Source of bytes | the committed files in `apps/heel-cloud/public/downloads/` at the expected commit (blobs `d1a281ed544a728be199b75afc7194f8a4637665`, `d4c6ab4ef94df1941125c856ae3dcbead0f1a3e4`, `5ecb6b0ab1bf0e036127e23a6af69a06c0b47adf` at main `1d1ec2d8986a1baca650ef0153d9ad0829c3886b`) |
| Runner extra | `cryptography==50.0.1`; Python 3.11 or newer |
| PyPI | not used; `publish.yml` keeps its stable-only condition `draft == false && prerelease == false` |

The digests and sizes are constants in the tool (`EXPECTED_SHA256`, `EXPECTED_SIZES`).
Unlike rc1, which only required the manifest to be consistent with the artifacts, the
rc2 tool refuses any local candidate (exit `3`, before reading a credential) and fails
any anonymously acquired public bytes (exit `1`, before installing anything) whose
SHA-256 or length differs from these exact values, even if the bytes and manifest are
internally consistent.

The tool talks only to `api.github.com` and `uploads.github.com`, and only on this
repository's release paths. Asset bytes come from GitHub's release-asset CDN hosts, which
must be HTTPS and are always contacted without credentials. There is no option to point
it at another API host, repository or tag.

The only authenticated writes it can send are `POST .../releases` (create the draft),
`PATCH .../releases/{id}` (publish it) and `POST` to the upload path (missing assets).
It has no Git-ref write path, no `DELETE` and no `PUT`, and no primitive that converts a
prerelease into a stable release.

## What the tool can and cannot guarantee

- **Tag.** The tool issues no Git-ref create, move or push request. Whenever it checks
  the tag, it requires `v1.3.0rc2` to exist and resolve to `SHA`. GitHub's create and
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
  assets only after publication. The last recorded owner read showed it disabled; this
  procedure does not change it or assume it.

## Event side effects

| Event | Effect |
| --- | --- |
| Push of `refs/tags/v1.3.0rc2` (owner, outside the tool) | No workflow runs. `ci.yml`, `codeql.yml` and `scorecard.yml` trigger on pushes to `main`; `claude-review.yml` on pull requests and dispatch; `publish.yml` on `release: published`. No workflow has `push: tags`. |
| Draft creation and asset uploads | No workflow runs (`publish.yml` listens only to `published`). Draft and draft assets are invisible anonymously. |
| Publication as a prerelease | One `publish.yml` run is created and its `verify-release` job is skipped by `if: github.event.release.draft == false && github.event.release.prerelease == false`; `publish` depends on it, so nothing goes to PyPI and no attestation is made. Repository watchers get GitHub's release notification. `make_latest: "false"` keeps `releases/latest` at `v1.2.0`. The prerelease appears on the public releases page immediately. |
| Staging Worker deploy (separate task) | Serves the same accepted rc2 bytes at `/downloads/*` on the deployed origin. See "Exposure through the Worker" below. |

### Hazard: converting the rc2 prerelease to a stable release

Do **not** un-check "Set as a pre-release" on `v1.3.0rc2` in the GitHub UI, and do not
edit the release to `prerelease: false` by any other means. If that happened,
`publish.yml` would run for real: `release/open-core-v1.json` names `1.3.0rc2`, which
equals the tag, the checkout would be the tagged commit, and the `publish` job targets
the `pypi` environment, which was observed to exist with **no protection rules**.
Whether PyPI would accept the upload depends on a Trusted Publisher that is not known to
exist (`heel-sim` is not on PyPI); the hazard stands regardless. The rc1 release never
had this exposure because its tag no longer matches the contract version.

The tool itself cannot cause this: `check_release` requires `prerelease is True`, both
writes send `prerelease: true`, and the source test asserts there is no stable-conversion
primitive. The prohibition above covers human or other-automation edits during and
after the release window.

## Platform support

The `[runner]` extra pins `cryptography==50.0.1`. That release publishes macOS wheels for
Apple silicon (`macosx_11_0_arm64`) only, plus manylinux/musllinux and Windows wheels; it
publishes no macOS x86_64 or universal2 wheel (`45.0.7` did). On Intel macOS pip would
fall back to building `cryptography` from source, which needs an additional (Rust)
toolchain. That path is **not supported by this preview** and is untested; it is not
claimed to be impossible. The release notes say so. Release-owner preflight must run on
Apple silicon or Linux x86_64/aarch64 with Python 3.11 or newer, because the enforced
runner-extra gate and `verify-public` install the wheel's `[runner]` extra.

## Preconditions

1. The candidate commit `SHA` (the merge on `main` that contains the three rc2 files)
   has been independently reviewed and source CI is green.
2. A clean checkout of exactly `SHA`, run with Python 3.11 or newer on a supported host
   (see "Platform support"). `git status` must show nothing, including untracked files.
3. `gh auth status` shows the release owner logged in to `github.com` with permission to
   create and edit releases (Contents write; `workflow` permission additionally if `SHA`
   changes `.github/workflows/` relative to the default branch). The tool reads the
   credential with `gh auth token`, keeps it in memory only, and never puts it in argv,
   logs, notes or evidence.
4. The release owner creates and pushes the tag `v1.3.0rc2` at `SHA` themselves (the rc1
   precedent is an annotated tag). The tool sends no tag or Git-ref write.
5. The package index must be reachable for the `[runner]` extra (`cryptography==50.0.1`).
6. The release window is recorded and coordinated exactly as in
   `docs/RUNNER_PREVIEW_RELEASE.md` "Release window and other writers", with `v1.3.0rc2`
   as the tag. An identified writer that has not acknowledged the window blocks the
   procedure.

Compute the external manifest digest from the commit; it must equal
`eb3e5536fe22d040fbd3805fea60ec67b1933ff8c8d6f7c91d443cc46aefbff8`:

```sh
git show "$SHA:apps/heel-cloud/public/downloads/heel-open-core-manifest.json" | shasum -a 256
```

## Local checks before any remote call

`stage-draft` and `publish-and-verify` check all of the following before they read the
credential or contact GitHub. Any failure exits `3`, and nothing has been written.

- The checkout root is the tool's own checkout. `HEAD` equals `--expected-sha`. The
  worktree is clean, including untracked files.
- `pyproject.toml`, `release/open-core-v1.json`, `heel/__init__.py` (`__version__`) and
  `scripts/build_open_core_release.py` (`RELEASE_VERSION`) all say `1.3.0rc2`, and so
  does the wheel's `METADATA`.
- The commit's downloads tree holds exactly the three assets as regular `100644` blobs;
  the working files are regular, non-symlinked and equal to those blobs.
- The manifest is the builder's canonical manifest for that wheel and source archive.
- **Each artifact's SHA-256 and length equal the accepted values in "Fixed identity".**
- The builder `--check` and the enforced runner-extra tests
  (`HEEL_REQUIRE_RUNNER_EXTRA_INSTALL=1 python -m unittest -v tests.test_public_runner_preview_release`,
  at least 5 tests, bare `OK`, no skips) pass, run with GitHub tokens removed.

## 1. Stage the draft

```sh
python scripts/publish_runner_preview_release_rc2.py stage-draft \
  --repository ancilis/heel --tag v1.3.0rc2 --expected-sha "$SHA"
```

The behaviour is the rc1 behaviour with the rc2 identity: verify the remote tag; find
the single release on `v1.3.0rc2` (more than one refuses); otherwise create one draft
prerelease with `target_commitish = SHA`, the fixed title, notes generated from the
verified manifest and `make_latest = "false"`; reuse an existing release only if draft,
prerelease, target, title, notes and upload location all match; verify every existing
asset's name, id, state, URL, size, digest and downloaded bytes; upload only missing
assets and re-verify each; re-read the tag.

The tool refuses rather than repairs: unknown or duplicate assets, same-name assets with
different bytes, a non-draft or non-prerelease release, and any other target, title,
notes or host. It never deletes, replaces or overwrites anything. If a create or upload
response is lost, the tool re-reads state: present objects are verified and the run
continues; otherwise it exits `4` (outcome unknown) without retrying. Run `stage-draft`
again later; it starts by re-reading.

## 2. Publish and verify

```sh
python scripts/publish_runner_preview_release_rc2.py publish-and-verify \
  --repository ancilis/heel --tag v1.3.0rc2 --expected-sha "$SHA"
```

Again the rc1 behaviour with the rc2 identity: repeat the local checks and the tag check;
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
python -I scripts/publish_runner_preview_release_rc2.py verify-public \
  --repository ancilis/heel --tag v1.3.0rc2 --expected-sha "$SHA" \
  --expected-manifest-sha256 eb3e5536fe22d040fbd3805fea60ec67b1933ff8c8d6f7c91d443cc46aefbff8
```

`verify-public` never reads a credential and only sends `GET` requests:

1. It checks the anonymous tag and reads the public release by tag (published,
   prerelease, at `SHA`, fixed title).
2. It requires exactly the three assets at
   `https://github.com/ancilis/heel/releases/download/v1.3.0rc2/<name>` and downloads
   each, bounded by its listed size, into a new directory outside the checkout.
3. It requires the manifest SHA-256 to equal `--expected-manifest-sha256`, the canonical
   manifest to match the wheel and source archive, **each asset's SHA-256 and length to
   equal the accepted values**, and the release notes to equal the notes generated from
   those bytes. Any mismatch fails before anything is installed or executed.
4. It creates a venv in a credential-scrubbed environment, installs
   `./heel_sim-1.3.0rc2-py3-none-any.whl[runner]` with `pip --isolated`, and runs
   `pip check`.
5. It checks that `heel-sim 1.3.0rc2` and `cryptography 50.0.1` are installed, that
   `heel` imports from the venv rather than a checkout, and that `heel.saas` is absent.
6. It runs `heel scope create --target reference:export`, then the four synthetic
   reference cases. Each must report `reference_only`, no network calls and no upload:

   | Case | Attempt | Result | `regression_passed` | `evidence_state` |
   | --- | --- | --- | --- | --- |
   | `vulnerable` | `5` x 32 | `verified_violation` | `false` | (not asserted) |
   | `public` | `6` x 32 | `invariant_held` | `true` | (not asserted) |
   | `hardened` (HTTP 403) | `7` x 32 | `inconclusive` | `false` | `unknown` |
   | `error_envelope` (HTTP 200) | `8` x 32 | `inconclusive` | `false` | `unknown` |

   The last two rows are the corrected 1.3.0rc1 errata: rc1 reported `hardened` as
   `invariant_held`.

It prints one JSON evidence record with asset sizes and digests, installed versions, the
four outcomes and an explicit `not_proven` list. A failure exits non-zero and prints no
success record.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | the mode completed and its evidence was printed |
| `1` | verification failed (`verify-public`, or a proof step) |
| `2` | usage, including running with no mode |
| `3` | refused: a precondition failed and this run sent no mutation |
| `4` | outcome unknown: a mutation was sent and could not be confirmed by re-reading; nothing was retried |
| `5` | published, but post-publication or anonymous verification failed; never a success; recover read-only with `verify-public` |

## Customer install command (publishable only after a passing anonymous verify-public)

Do not put this in customer copy until an anonymous `verify-public` for `v1.3.0rc2` has
passed and its evidence is recorded. Prerequisites: Python 3.11 or newer available as
`python3` (check `python3 --version`), with its standard `venv` module; Apple silicon
macOS or Linux x86_64/aarch64 (Intel macOS is unsupported by this preview, see "Platform
support"). One copy-paste command creates an isolated venv in `./heel-rc2`, installs the
hash-pinned wheel with its `[runner]` extra, and prints the installed version; the CLI
is then `./heel-rc2/bin/heel`:

```sh
python3 -m venv heel-rc2 && ./heel-rc2/bin/python -m pip --isolated install 'heel-sim[runner] @ https://github.com/ancilis/heel/releases/download/v1.3.0rc2/heel_sim-1.3.0rc2-py3-none-any.whl#sha256=f8698204e1d38aa80b8ca31dedd743c3d42e28d02c5153bddb4f02b44ecdf01c' && ./heel-rc2/bin/heel --version
```

pip refuses to install the wheel unless its SHA-256 equals the pinned digest. The
`cryptography==50.0.1` dependency comes from the package index under pip's normal
verification; it is not hash-pinned by this command.

## Exposure through the Worker

The staging Worker serves `apps/heel-cloud/public/` as static assets, so deploying it
makes the same accepted rc2 bytes publicly reachable at `/downloads/*` on that origin.
Whichever happens first, that deploy or this GitHub publication, is the moment rc2
became public, and the operator records it with these digests. A `workers.dev` URL can
be an explicitly designated launch origin, and a direct hash-pinned install from the
site origin is technically possible; GitHub is the selected durable, versioned
distribution path because a release binds the bytes to a tag and source commit and keeps
them, while the current site pipeline replaces `/downloads/*` on each deploy and has no
historical-asset retention commitment. Customer copy on the site still says rc2 is not
yet published and installs rc1; correcting it is a separate bounded copy packet after a
passing `verify-public`, not part of this procedure.

## Candidate binding and the future rc3 trade-off

`tests/test_runner_preview_publisher_rc2.py` reads this checkout's
`apps/heel-cloud/public/downloads/*` and the four version sources and requires them to
equal the pinned rc2 blob ids, digests and sizes. That avoids committing a second 3.3 MB
copy of the artifacts now. The cost: when a later candidate (for example rc3) replaces
the downloads or edits a pinned version source, the rc2 test module fails at import on
purpose. That later packet must either move the rc2 bytes into a historical fixture (the
rc1 precedent, `tests/fixtures/runner_preview_rc1/`) or retire this tool; it must not
silently re-pin.

## rc1 runbook status line

`docs/RUNNER_PREVIEW_RELEASE.md` still says "Status: **not yet performed.**" for rc1.
That line is historical text: the `v1.3.0rc1` prerelease (release id 421915025) was
published on 2026-10-23. The rc1 runbook is deliberately not edited by the rc2 change.

## After publication

Record the `verify-public` JSON, the release id, the GitHub URL, the manifest digest from
the notes, the release-window record and the before/after GitHub evidence, and whether
the Worker exposure happened first. Remaining trust assumptions and limits are those of
the rc1 runbook: no other writer acts during the window (coordination, not a lock); a
deleted tag can be recreated by a release request, bound to `SHA`; the loopback tests
model GitHub from its documentation, and real wire behaviour is confirmed only by the
owner run.
