# Runner preview release procedure (release owner)

This is the administrative procedure for publishing the committed `1.3.0rc1` candidate
as the GitHub **prerelease** `v1.3.0rc1`, titled `Heel runner preview 1.3.0rc1`, with
`scripts/publish_runner_preview_release.py`.

Status: **not yet performed.** No tag, draft or release exists for this candidate. No
public URL or release-asset digest has been verified yet. Only the release owner runs
the steps below, after an independent review of the tool and green source CI. The tool's
author does not run them.

What this release proves is limited. Publishing it, and passing `verify-public`, is
evidence about packaging and the synthetic reference only. It does not establish any of
these:

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

## Preconditions

1. The candidate commit has been independently reviewed and source CI is green. Record
   the full 40-hex SHA as `SHA`.
2. A clean checkout of exactly `SHA`, run with Python 3.11 or newer. `git status` must
   show nothing, including untracked files.
3. `gh auth status` shows the release owner logged in to `github.com` with permission to
   create releases. The tool reads the credential with `gh auth token`, keeps it in
   memory only, and never puts it in argv, logs, notes or evidence.
4. The release owner creates and pushes the tag `v1.3.0rc1` at `SHA` themselves. The
   tool never creates, moves, forces or pushes a tag. A lightweight tag or an annotated
   tag is fine. Annotated tags are peeled at most four levels deep. Cycles, and tags
   that point at a tree or blob, are rejected.
5. The package index must be reachable for the `[runner]` extra (`cryptography==45.0.7`).

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
   manifest, and `make_latest = "false"`.
4. An existing release is reused only if all of these match: draft, prerelease, target,
   title, notes and upload location.
5. It lists every asset, following pagination. Each existing asset must have a canonical
   name, a unique id, a `state` of `uploaded`, this repository's asset URL, and the
   expected size and digest. It is then downloaded, and its bytes must equal the
   candidate.
6. Only missing assets are uploaded. Each one is re-listed and downloaded again to
   verify it.

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
4. It sends one `PATCH` with `draft: false, prerelease: true, make_latest: "false"`.
5. It re-reads the release whether or not the response arrived, and reports what it
   finds:
   - published: it says whether the publish was acknowledged
   - still a draft: it exits `4`, and nothing is retried
6. It never converts a stable release. If the release is already a published matching
   prerelease, the tool sends no publish request and says so.
7. It runs `verify-public` in a new process with these properties:
   - `python -I`
   - working directory: a new temporary directory outside the checkout
   - `HOME` set to a new empty directory
   - no GitHub token, git configuration, netrc or pip configuration

Exit `5` means the release **is published** but anonymous verification failed. Do not
delete, recreate or re-upload anything. Recover read-only with step 3.

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
| `5` | published, but anonymous verification failed; recover with `verify-public` |

## After publication

Record the following in the release evidence:

- the `verify-public` JSON
- the release id
- the GitHub URL
- the manifest digest from the notes

Customer copy may cite the public URL and digests only after a successful anonymous
`verify-public`. Final Fable clean-room launch acceptance repeats anonymous acquisition
independently. Remaining residual risks:

- GitHub could create the tag at `target_commitish` if someone deletes it between the
  tool's last tag read and its request. The tool reads the tag immediately before both
  the create and the publish, and `target_commitish` is always the exact `SHA`.
- The tool never asserts anything about the PyPI route beyond the unchanged stable-only
  workflow condition.
