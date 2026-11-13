# Runner preview 1.3.0rc5 release procedure (release owner)

This is the administrative procedure for publishing the committed `1.3.0rc5` candidate
as the GitHub **prerelease** `v1.3.0rc5`, titled `Heel runner preview 1.3.0rc5`, with
`scripts/publish_runner_preview_release_rc5.py`.

Status: **final pins in place (`PIN_STATUS = "FINAL"`); not yet performed.** The pins
below are the rc5 artifacts built once at source `79a1273b9653f5602b7db59b359aa49827c2026d`
(tree `417e8584ea096744e13f30580702038775e0adb6`). That source is `origin/main` `872cff90` plus the accepted
result-chain recovery commits (`acb72dd`, `28397f6`, `98df889`), the scenario-library commits
(`365929d`, `5160d9f`, `0f266bc`, `8d515bf`, `a4a28f3`) and its display-bound remedy (`0da135c`),
and the accepted install-copy commits (`72ea83e`, `9056d2d`, `192b462`), each cherry-picked with an
identical patch-id, then the rc4 publisher test's move to the historical rc4 fixture, the
version-bound tests, the rc5 re-version with the single artifact build, and the H2 bookkeeping
refresh. No `v1.3.0rc5` tag, draft or release exists. Only the release owner runs the steps
below, after an independent review of this tool and green exact-tree CI, and only under a
separate publication decision. The tool's author does not run them. The tool refuses every mode
(exit `3`, before any credential read, gate or request) if `PIN_STATUS` is anything but `FINAL`.

The rc5 tool is a separate, version-scoped copy of the reviewed and published rc4 tool
(`scripts/publish_runner_preview_release_rc4.py`). It differs from rc4 only in these hunks:

| Hunk | Change |
| --- | --- |
| E1 | module docstring names `1.3.0rc5` |
| E2 | `VERSION = "1.3.0rc5"` (tag, title, wheel and source archive names derive from it) |
| E3 | the pinned digests and sizes (`EXPECTED_SHA256`, `EXPECTED_SIZES`) and their comment |
| E4 | unchanged: `PIN_STATUS = "FINAL"` and the check at the start of `main` that refuses every mode unless it is `FINAL` are carried over byte for byte |
| E5 | the rc5 runner-change text in the release notes, replacing rc4's |
| E6 | user agent `heel-runner-preview-publisher-rc5` and program name |
| E7 | the tag-peeling docstring names `refs/tags/v1.3.0rc5` |

The transport, GitHub client, tag peeling, draft, collision, outcome-unknown,
reconciliation, exact-digest binding, four-case installed proof and anonymous-verification
logic is reused unchanged; `tests/test_runner_preview_publisher_rc5.py` enforces that
diff bound with exact changed-line counts and requires the carried E4 lines in both tools.
The rc1, rc2, rc3 and rc4 tools, their tests, runbooks and historical fixtures
(`tests/fixtures/runner_preview_rc1/` through `tests/fixtures/runner_preview_rc4/`) are
unchanged and byte-pinned by that test, except that the rc4 test now reads the published rc4
bytes from its historical fixture. The published `v1.3.0rc2`, `v1.3.0rc3` and `v1.3.0rc4`
releases and their bytes are not touched by anything here.

What this release proves is limited. Publishing rc5 is component delivery, not a completed
customer journey and not customer acceptance. Verified distribution means the trusted
expected manifest and artifact digests were checked before anything was installed or
executed; that is what a passing `verify-public` adds. Even then it is evidence about
packaging and the synthetic reference only. The rc5 runner changes (recovery of a staged
disclosure poll or findings upload refused with `invalid_runner_auth` through the existing
result-chain resync, retired only on the server's cursor proof; metadata-only recovery of a
staged upload whose human permit expired, so `serve` comes online; a consumed upload without a
receipt stays parked and fails closed) are proven only with local test fixtures. The wheel also
carries `heel/browser_assess.py`, the browser-local static scenario assessment: a static result
compares declared scenario definitions with a locally reviewed OpenAPI document and the
customer's answers, keeps unknown inputs unknown and is not live evidence. The rehearsal itself is
unchanged: the approved read-only `GET`/`HEAD` plan runs from the local runner, credentials stay
in the local vault and raw evidence stays on the customer's machine. Findings semantics are those
of rc4: an ordinary plan-differential key-path observation is medium confidence
(`evidence_state` `observed`) and values are not compared, error envelopes are `inconclusive`,
and `verified` is reserved for a high-confidence finding where both isolated canary roles
received the exact approved marker. The `evidence_states` list that `runner findings --run`
prints is unsigned and derived from the signed results. The known CI limitations recorded for
rc4 (causes UNKNOWN, not fixed) are carried unchanged; a recurrence is read from its
diagnostic, not rerun to green. It does not establish any of these:

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
| Tag / release | `v1.3.0rc5`, `prerelease: true`, `make_latest: "false"`, never `latest` |
| Wheel | `heel_sim-1.3.0rc5-py3-none-any.whl`, 2869122 bytes, SHA-256 `a7c7293be3e30f1c3fb6fd968ab16c2845ebaae34d4fe3bcb2ddfd54855aa226` |
| Source archive | `heel_sim-1.3.0rc5.tar.gz`, 610466 bytes, SHA-256 `3cd3cbc9aa84381f58703c13cc0f446fa8fc8fe57d395283cdc422ff3ded579e` |
| Manifest | `heel-open-core-manifest.json`, 347 bytes, SHA-256 `8d822c5eea3bebf8b4b5b139121165b4be218e1914743b8561ec22414f5eef51` |
| Source of bytes | the committed files in `apps/heel-cloud/public/downloads/` at the expected commit (blobs `0437447ed987bf1cba64638205bd75cbd450d913`, `f1d5556e264cf9797467d17718b8f6fe6154cf5f`, `c5beaa79d365154a46cd1bf42cded274ddfd1e69` at `79a1273b9653f5602b7db59b359aa49827c2026d`) |
| Runner extra | `cryptography==50.0.1`; Python 3.11 or newer |
| PyPI | not used; `publish.yml` keeps its stable-only condition `draft == false && prerelease == false` |

The digests and sizes are constants in the tool (`EXPECTED_SHA256`, `EXPECTED_SIZES`).
As for rc2, the tool refuses any local candidate (exit `3`, before reading a credential)
and fails any anonymously acquired public bytes (exit `1`, before installing anything)
whose SHA-256 or length differs from these exact values, even if the bytes and manifest
are internally consistent. The published rc4 bytes (`68b8d50e`: wheel
`27cc929b32d07c6fa3466dd6e8cb3079cb90b513d93bf65dc64cae05393ba2af`, source archive `ae4f0e0a0b3e93bb93adb525150bdb9180c8fe9e5017c8d23323984e76e02dbd`, manifest `d87a9602419a020dfa26315de9797f027d9a90f237b0b0573259de468721551f`) are therefore refused;
`FinalizationTests` also requires every rc5 digest to differ from those rc4 digests.

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
  the tag, it requires `v1.3.0rc5` to exist and resolve to `SHA`. GitHub's create and
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
| Push of `refs/tags/v1.3.0rc5` (owner, outside the tool) | No workflow is expected to run: re-read every default-branch workflow's `on:` block at `SHA` before the window and record that none has `push: tags`. |
| Draft creation and asset uploads | No workflow runs (`publish.yml` listens only to `published`). Draft and draft assets are invisible anonymously. |
| Publication as a prerelease | One `publish.yml` run is created and its `verify-release` job is skipped by `if: github.event.release.draft == false && github.event.release.prerelease == false`; `publish` depends on it, so nothing goes to PyPI and no attestation is made. Repository watchers get GitHub's release notification. `make_latest: "false"` keeps `releases/latest` unchanged. The prerelease appears on the public releases page immediately. |
| Staging Worker deploy (separate task) | Serves the committed rc5 bytes at `/downloads/*` on the deployed origin; record whichever exposure happens first, as for rc2. |

### Hazard: converting the rc5 prerelease to a stable release

Do **not** un-check "Set as a pre-release" on `v1.3.0rc5` in the GitHub UI, and do not
edit the release to `prerelease: false` by any other means. `release/open-core-v1.json`
names `1.3.0rc5`, which equals the tag, so `publish.yml` would run for real against the
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
1. The candidate commit `SHA` (the merge on `main` that contains the three final rc5
   files and this tool) has been independently reviewed and exact-tree CI is green. Its
   three downloads must be byte-identical to the pins in "Fixed identity"; the tool
   refuses otherwise.
2. A clean checkout of exactly `SHA`, run with Python 3.11 or newer on a supported host.
   `git status` must show nothing, including untracked files.
3. `gh auth status` shows the release owner logged in to `github.com` with permission to
   create and edit releases. The tool reads the credential with `gh auth token`, keeps it
   in memory only, and never puts it in argv, logs, notes or evidence. No broader
   permission is needed or requested.
4. The release owner creates and pushes the tag `v1.3.0rc5` at `SHA` themselves. The
   tool sends no tag or Git-ref write.
5. The package index must be reachable for the `[runner]` extra (`cryptography==50.0.1`).
6. The release window is recorded and coordinated exactly as in
   `docs/RUNNER_PREVIEW_RELEASE.md` "Release window and other writers", with `v1.3.0rc5`
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
  `scripts/build_open_core_release.py` (`RELEASE_VERSION`) all say `1.3.0rc5`, and so
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
python scripts/publish_runner_preview_release_rc5.py stage-draft \
  --repository ancilis/heel --tag v1.3.0rc5 --expected-sha "$SHA"
```

The rc2 behaviour with the rc5 identity: verify the remote tag; find the single release on
`v1.3.0rc5` (more than one refuses); otherwise create one draft prerelease with
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
python scripts/publish_runner_preview_release_rc5.py publish-and-verify \
  --repository ancilis/heel --tag v1.3.0rc5 --expected-sha "$SHA"
```

The rc2 behaviour with the rc5 identity: repeat the local checks and the tag check;
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
python -I scripts/publish_runner_preview_release_rc5.py verify-public \
  --repository ancilis/heel --tag v1.3.0rc5 --expected-sha "$SHA" \
  --expected-manifest-sha256 "<pinned manifest SHA-256 from Fixed identity>"
```

`verify-public` never reads a credential and only sends `GET` requests. Its steps are the
rc2 steps with the rc5 identity: anonymous tag and release checks; exactly the three
assets at `https://github.com/ancilis/heel/releases/download/v1.3.0rc5/<name>`, each
downloaded within its listed size into a new directory outside the checkout; the
expected manifest digest, the canonical manifest, **each asset's pinned SHA-256 and
length** and the generated release notes, all before anything is installed; a venv in a
credential-scrubbed environment with `./heel_sim-1.3.0rc5-py3-none-any.whl[runner]` and
`pip check`; `heel-sim 1.3.0rc5` and `cryptography 50.0.1` installed, `heel` imported from
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
`verify-public` for `v1.3.0rc5` has passed and its evidence is recorded. Until then every
customer install surface keeps the published rc4 command; a later, bounded copy change moves them. Prerequisites: Python 3.11
or newer available as `python3`, with its standard `venv` module; Apple silicon macOS or
Linux x86_64/aarch64. One copy-paste command creates an isolated venv in `./heel-rc5`,
installs the hash-pinned wheel with its `[runner]` extra, and prints the installed version;
the CLI is then `./heel-rc5/bin/heel`:

```sh
python3 -m venv heel-rc5 && ./heel-rc5/bin/python -m pip --isolated install 'heel-sim[runner] @ https://github.com/ancilis/heel/releases/download/v1.3.0rc5/heel_sim-1.3.0rc5-py3-none-any.whl#sha256=a7c7293be3e30f1c3fb6fd968ab16c2845ebaae34d4fe3bcb2ddfd54855aa226' && ./heel-rc5/bin/heel --version
```

pip refuses to install the wheel unless its SHA-256 equals the pinned digest. The
`cryptography==50.0.1` dependency comes from the package index under pip's normal
verification; it is not hash-pinned by this command.

## Candidate binding and finalization

`tests/test_runner_preview_publisher_rc5.py` reads this checkout's
`apps/heel-cloud/public/downloads/*` and the four version sources and requires them to
equal the pinned rc5 blob ids, digests and sizes; it fails at import on purpose if any
of them changes. E3 carries the rc5 digests and sizes, E4 keeps `PIN_STATUS = "FINAL"`,
the test pins `PINNED_COMMIT` (`79a1273b9653f5602b7db59b359aa49827c2026d`) and the rc5 blobs, and `INTERIM_SHA256` keeps
the published rc4 digests so the rc5 ones must differ from them. The E5 release-note text
describes the accepted scope and matches the rc5 CHANGELOG entry at that source.

A later candidate (for example rc6) that replaces the downloads must move the rc5 bytes
into a historical fixture (the rc1, rc2, rc3 and rc4 precedent) or retire this tool; it must not
silently re-pin.

## After publication

Record the `verify-public` JSON, the release id, the GitHub URL, the manifest digest from
the notes, the release-window record and the before/after GitHub evidence, and whether
the Worker exposure happened first. Remaining trust assumptions and limits are those of
the rc1, rc2, rc3 and rc4 runbooks.
