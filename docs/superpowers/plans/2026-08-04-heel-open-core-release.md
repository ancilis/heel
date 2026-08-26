# Heel Open-Core Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce deterministic, Apache-only `heel-sim` wheel and source artifacts that customers can install from Heel itself without publishing proprietary SaaS code or relying on the stale public repository.

**Architecture:** The private monorepo remains the source of truth, but one explicit allowlist defines the public release closure. A deterministic standard-library builder emits a wheel, source archive, and signed-by-digest manifest; independent artifact tests inspect their members and install the wheel in a clean environment. Heel Cloud ships the already-verified artifacts as same-origin downloads and the MCP page links to them without claiming PyPI or the stale public branch is current.

**Tech Stack:** Python 3.11+ standard library (`ast`, `csv`, `hashlib`, `tarfile`, `zipfile`), `unittest`, Node 26 artifact tests, Next.js/vinext, GitHub Actions.

---

## File structure

- `release/open-core-v1.json` — canonical allowlist of public build files, modules, package data, documentation, licenses, console scripts, and release version.
- `release/open-core/README.md` — release-specific product/install guide with no monorepo-only commands.
- `release/open-core/MCP_QUICKSTART.md` — self-contained local MCP setup and valid protocol handshake.
- `release/open-core/SECURITY.md` — exact local trust boundary and disclosure instructions.
- `scripts/build_open_core_release.py` — deterministic allowlist consumer; builds wheel, source tarball, and canonical manifest; supports `--check`.
- `tests/test_open_core_release.py` — mutation, archive-content, metadata, clean-install, and real MCP-handshake proof.
- `pyproject.toml` — normal Python builds discover only the top-level `heel` package, never `heel.saas`.
- `MANIFEST.in` — source builds include only explicitly public docs/data and prune proprietary trees.
- `apps/heel-cloud/public/downloads/` — committed generated release artifacts served same-origin.
- `apps/heel-cloud/app/mcp/page.tsx` — truthful first-party download and install instructions.
- `apps/heel-cloud/tests/mcp-quickstart.test.mjs` — executes the displayed installation and MCP verification path.
- `apps/heel-cloud/tests/production-artifact.test.mjs` — classifies and inspects the downloadable wheel/source archive rather than treating them as opaque binaries.
- `.github/workflows/ci.yml` and `.github/workflows/publish.yml` — generate/check the same artifacts and reject commercial leakage before upload.

### Task 1: Freeze the public release allowlist

**Files:**
- Create: `release/open-core-v1.json`
- Create: `release/open-core/README.md`
- Create: `release/open-core/MCP_QUICKSTART.md`
- Create: `release/open-core/SECURITY.md`
- Create: `tests/test_open_core_release.py`
- Modify: `pyproject.toml`
- Modify: `MANIFEST.in`

- [ ] **Step 1: Write the failing packaging-boundary test**

Add a test that reads the release contract and asserts exact top-level fields, unique normalized paths, and absence of every proprietary prefix:

```python
FORBIDDEN_PREFIXES = (
    "apps/", "deploy/", "docs/saas/", "docs/superpowers/", "heel/saas/", "web/",
)

def test_release_contract_is_an_exact_public_allowlist(self):
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    self.assertEqual(set(contract), {
        "build_files", "console_scripts", "documents", "licenses", "package_data",
        "python_modules", "schema_version", "version",
    })
    self.assertEqual(contract["schema_version"], "heel.open-core-release.v1")
    paths = contract["build_files"] + contract["python_modules"] + contract["package_data"] + contract["documents"] + contract["licenses"]
    self.assertEqual(len(paths), len(set(paths)))
    for path in paths:
        self.assertEqual(PurePosixPath(path).as_posix(), path)
        self.assertFalse(path.startswith(FORBIDDEN_PREFIXES), path)
        self.assertNotIn("..", PurePosixPath(path).parts)
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```bash
python3 -m unittest tests.test_open_core_release.OpenCoreReleaseTests.test_release_contract_is_an_exact_public_allowlist -v
```

Expected: `FAIL` because `release/open-core-v1.json` does not exist.

- [ ] **Step 3: Add the exact release contract**

Create `release/open-core-v1.json` with canonical JSON and these values:

```json
{
  "build_files": [
    "MANIFEST.in",
    "pyproject.toml",
    "release/open-core-v1.json"
  ],
  "console_scripts": {
    "heel": "heel.cli:main",
    "heel-mcp": "heel.mcp_server:main",
    "heel-rest": "heel.rest:serve"
  },
  "documents": [
    "release/open-core/MCP_QUICKSTART.md",
    "release/open-core/README.md",
    "release/open-core/SECURITY.md"
  ],
  "licenses": ["DCO", "LICENSE", "NOTICE"],
  "package_data": [
    "heel/heldout/targets.json",
    "heel/scenarios_lib/community.json"
  ],
  "python_modules": [
    "heel/__init__.py",
    "heel/agents.py",
    "heel/agents_human.py",
    "heel/backtest.py",
    "heel/bench.py",
    "heel/blind.py",
    "heel/blind_eval.py",
    "heel/browser_review.py",
    "heel/chaining.py",
    "heel/classify.py",
    "heel/cli.py",
    "heel/containment.py",
    "heel/contracts.py",
    "heel/control.py",
    "heel/control_simulator.py",
    "heel/economics.py",
    "heel/entitlements.py",
    "heel/heldout_eval.py",
    "heel/importers.py",
    "heel/incident.py",
    "heel/launch_review.py",
    "heel/local_projects.py",
    "heel/mcp_server.py",
    "heel/model.py",
    "heel/modes.py",
    "heel/openapi_import.py",
    "heel/openapi_model.py",
    "heel/orchestrator.py",
    "heel/product_model.py",
    "heel/profiles.py",
    "heel/regressions.py",
    "heel/rest.py",
    "heel/review_answers.py",
    "heel/review_contract.py",
    "heel/review_export.py",
    "heel/review_rules.py",
    "heel/review_service.py",
    "heel/scenario_validate.py",
    "heel/scenarios.py",
    "heel/scope.py",
    "heel/semantic.py",
    "heel/static_review.py",
    "heel/store.py",
    "heel/targets.py",
    "heel/web_export.py"
  ],
  "schema_version": "heel.open-core-release.v1",
  "version": "1.1.0"
}
```

The file must end with one newline and keys must remain sorted.

- [ ] **Step 4: Make standard package discovery fail closed**

Replace the wildcard package finder in `pyproject.toml` with:

```toml
[tool.setuptools]
include-package-data = false
license-files = ["LICENSE", "NOTICE"]
packages = ["heel"]

[tool.setuptools.package-data]
heel = ["heldout/targets.json", "scenarios_lib/community.json"]
```

Set the project readme to `release/open-core/README.md`. The release-specific README and MCP
quickstart must be self-contained: no local link may leave the release allowlist, and no fenced
command may require `apps/`, `web/`, `tests/`, `docs/saas`, `heel/saas`, the stale public GitHub
branch, or an unavailable PyPI package. Their five-minute path creates a tiny sanitized OpenAPI JSON
file inline, installs from the local wheel/source archive, and uses the real three-message MCP
handshake.

Remove the stale `[project.urls]` table until the public repository or production Heel site is
current. Do not put `ancilis/heel` in release metadata while that repository still serves the old
Arceo source.

Replace `MANIFEST.in` with explicit public includes and a final defensive prune:

```text
include DCO LICENSE NOTICE
include heel/*.py
include heel/heldout/targets.json
include heel/scenarios_lib/community.json
include release/open-core-v1.json
include release/open-core/MCP_QUICKSTART.md release/open-core/README.md release/open-core/SECURITY.md
exclude LICENSE-COMMERCIAL.md
exclude README.md
exclude heel/heldout/test_targets.json
exclude heel/scenarios_lib/research_owasp.json
prune apps
prune deploy
prune tests
prune web
prune heel/saas
prune docs/saas
prune docs/superpowers
global-exclude __pycache__/*
global-exclude *.pyc
```

- [ ] **Step 5: Run the boundary test and commit**

Run:

```bash
python3 -m unittest tests.test_open_core_release.OpenCoreReleaseTests.test_release_contract_is_an_exact_public_allowlist -v
```

Expected: `PASS`.

Also run the standard-build integration in mandatory mode so a missing PyPA build frontend fails
instead of skipping:

```bash
HEEL_REQUIRE_STANDARD_BUILD=1 python3 -m unittest tests.test_open_core_release -v
```

Commit:

```bash
git add release/open-core-v1.json release/open-core tests/test_open_core_release.py pyproject.toml MANIFEST.in
git commit -m "test: freeze Apache open-core release boundary"
```

### Task 2: Build deterministic wheel and source artifacts

**Files:**
- Create: `scripts/build_open_core_release.py`
- Modify: `tests/test_open_core_release.py`

- [ ] **Step 1: Add RED artifact-shape and determinism tests**

The test must run the builder twice into separate real temporary directories and assert byte-identical artifacts, canonical manifest bytes, fixed archive timestamps, exact member allowlists, no symlinks, no duplicate members, and no `LicenseRef-Heel-Commercial`, `heel/saas`, `docs/saas`, secret patterns, `.env`, key, or certificate files.

Use these exact artifact names:

```python
WHEEL = "heel_sim-1.1.0-py3-none-any.whl"
SDIST = "heel_sim-1.1.0.tar.gz"
MANIFEST = "heel-open-core-manifest.json"
```

Expected wheel metadata:

```text
Metadata-Version: 2.4
Name: heel-sim
Version: 1.1.0
Requires-Python: >=3.11
License-Expression: Apache-2.0
License-File: LICENSE
License-File: NOTICE
```

Expected console entry points:

```text
[console_scripts]
heel = heel.cli:main
heel-mcp = heel.mcp_server:main
heel-rest = heel.rest:serve
```

- [ ] **Step 2: Run the artifact test and verify RED**

Run:

```bash
python3 -m unittest tests.test_open_core_release.OpenCoreReleaseTests.test_build_is_deterministic_and_exact -v
```

Expected: `FAIL` because `scripts/build_open_core_release.py` is missing.

- [ ] **Step 3: Implement the deterministic builder**

Follow the reviewed mechanics already used by `scripts/build_browser_engine.py`:

```python
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
FIXED_TAR_MTIME = 0
DIST_INFO = "heel_sim-1.1.0.dist-info"
RECORD_PATH = f"{DIST_INFO}/RECORD"
```

Required builder behavior:

1. Load `release/open-core-v1.json` with duplicate-key rejection and exact-field validation.
2. Resolve every input beneath the repository root without following symlinks; require regular files.
3. Compare the contract's `heel/*.py` entries with the actual top-level `heel/*.py` set and fail on an unclassified new module.
4. Parse every public Python module with `ast`; reject any import whose resolved local package starts with `heel.saas` or `.saas`.
5. Build a `ZIP_STORED` wheel with fixed modes/timestamps, licenses under `heel_sim-1.1.0.dist-info/licenses/`, exact metadata, entry points, and a sorted PEP 376 `RECORD`.
6. Build a gzip-compressed tar source tree rooted at `heel_sim-1.1.0/`, containing every allowlisted
   `build_files`, source, data, document, and license entry, with uid/gid 0, empty owner/group names,
   mode `0644`, mtime 0, and gzip header mtime 0.
7. Emit canonical `heel.open-core-artifacts.v1` JSON containing version plus name/size/SHA-256 for both archives.
8. Write with descriptor-safe atomic replacement and reject symlinked output roots/components.
9. `--check` compares exact committed bytes without rewriting them.

Descriptor-safe means component-wise `dir_fd`/`openat` operations with `O_NOFOLLOW`, `fstat`
regular-file checks, same-directory exclusive temporary files, file and directory `fsync`, and
`dir_fd`-anchored replacement. Stage the wheel, source archive, and candidate manifest, then publish
the manifest last. A path-only precheck followed by `mkstemp`/`os.replace` is not sufficient.

Archive parsing tests must enforce hard limits for archive bytes, member count, per-member bytes,
and total uncompressed bytes before allocation. The wheel must be unencrypted `ZIP_STORED` without
ZIP64, comments, or extra fields; tests read every member, validate its local header/CRC, fixed
mode/time, exact order, and `RECORD`-last URL-safe SHA-256 rows. The source archive uses USTAR regular
files only and rejects links, devices, sparse/GNU/PAX records, unsafe names, and non-canonical
mode/uid/gid/mtime/order; gzip mtime, filename, XFL, and OS header bytes are pinned.

The CLI must be:

```text
python3 scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads
python3 scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads --check
```

- [ ] **Step 4: Add clean-install and real MCP tests**

In `tests/test_open_core_release.py`, create a clean virtual environment, install with no index/dependencies, and execute:

```python
subprocess.run([venv_python, "-m", "pip", "install", "--no-index", "--no-deps", wheel], check=True)
subprocess.run([
    venv_python, "-c",
    "import importlib.util; import heel; "
    "assert importlib.util.find_spec('heel.saas') is None; "
    "assert heel.__version__ == '1.1.0'",
], check=True)
```

Then send newline-delimited `initialize`, `notifications/initialized`, and `tools/list` messages to the installed `heel-mcp`; assert the initialize response names `heel` and the tool list contains `heel_review_openapi`.

Create a second clean environment and install `heel_sim-1.1.0.tar.gz` offline with
`--no-index --no-deps --no-build-isolation`. Rebuild a wheel from that source archive and compare
its semantic package parity with the allowlist-built wheel: exact source/data/license/entry-point
members and bytes, required METADATA/WHEEL fields, and independently valid `RECORD` hash/size/self
rows. Setuptools-generated generator strings and metadata serialization need not be byte-identical.
Run clean-install checks from a directory outside the repository with `PYTHONPATH` removed,
`PYTHONNOUSERSITE=1`, pip `--isolated --no-cache-dir`, and scrubbed pip environment/config. Provision
the already-installed `setuptools>=68` backend explicitly for `--no-build-isolation`; never fetch it.
The source archive is not accepted if it is merely a snapshot that cannot install and reproduce the
same public package members.

- [ ] **Step 5: Run release tests and commit**

Run:

```bash
python3 -m unittest tests.test_open_core_release -v
```

Expected: all tests `PASS`.

Commit:

```bash
git add scripts/build_open_core_release.py tests/test_open_core_release.py
git commit -m "feat: build deterministic Heel open-core releases"
```

### Task 3: Ship the verified first-party download

**Files:**
- Create: `apps/heel-cloud/public/downloads/heel_sim-1.1.0-py3-none-any.whl`
- Create: `apps/heel-cloud/public/downloads/heel_sim-1.1.0.tar.gz`
- Create: `apps/heel-cloud/public/downloads/heel-open-core-manifest.json`
- Modify: `apps/heel-cloud/app/mcp/page.tsx`
- Modify: `apps/heel-cloud/tests/product-contract.test.tsx`
- Modify: `apps/heel-cloud/tests/mcp-quickstart.test.mjs`

- [ ] **Step 1: Generate and verify release bytes**

Run:

```bash
python3 scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads
python3 scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads --check
```

Expected: the second command prints `open-core release artifacts are current` and exits 0.

- [ ] **Step 2: Write RED download and install-copy tests**

Assert `/mcp` contains a real link to `/downloads/heel_sim-1.1.0-py3-none-any.whl`, a source link to `/downloads/heel_sim-1.1.0.tar.gz`, the manifest SHA-256, and this install sequence:

```text
python3 -m venv .venv
.venv/bin/python -m pip install ./heel_sim-1.1.0-py3-none-any.whl
```

Remove all `not yet available`, `licensed source checkout`, stale GitHub-main, and PyPI-install copy. Keep the truthful statement that PyPI publication is not yet available.

- [ ] **Step 3: Implement the first-party acquisition UI**

The install card must lead with a normal anchor whose label is `Download Heel Agent 1.1.0`, point to the wheel, and carry the `download` attribute. Put the source archive and exact SHA-256 from the generated manifest alongside it. Retain Python/POSIX/Windows requirements, the AI-client privacy boundary, and human-only scope warning.

- [ ] **Step 4: Execute the displayed flow**

Update `mcp-quickstart.test.mjs` to extract the literal install and verify snippets from `page.tsx`, replace only the displayed relative wheel path with the absolute committed wheel path, run the install in a repository-local real temporary directory, then execute the displayed handshake using the installed `heel-mcp`. Assert `heel_review_openapi` appears.

- [ ] **Step 5: Run app tests and commit**

Run:

```bash
cd apps/heel-cloud
npm run test:unit
npm run test:node
npm run typecheck
npm run lint
npm run build
```

Expected: all commands exit 0; build contains `/mcp` and all three download files.

Commit:

```bash
git add apps/heel-cloud/public/downloads apps/heel-cloud/app/mcp/page.tsx apps/heel-cloud/tests/product-contract.test.tsx apps/heel-cloud/tests/mcp-quickstart.test.mjs
git commit -m "feat: ship first-party Heel Agent download"
```

### Task 4: Inspect release artifacts inside the production deployment

**Files:**
- Modify: `apps/heel-cloud/tests/production-artifact.test.mjs`
- Modify: `apps/heel-cloud/scripts/prepare-runtime.mjs`

- [ ] **Step 1: Write RED deployment-classification tests**

Require the built deployment to contain exactly the three expected files under `client/downloads/`. Validate their sizes/digests against `heel-open-core-manifest.json`; parse the wheel ZIP and source `tar.gz` members; apply the same commercial-prefix, credential, symlink, duplicate-member, path-traversal, source-map, and unexpected-extension checks used by the standalone Python release test.

- [ ] **Step 2: Make preparation validate, never generate, release bytes**

Extend `prepare-runtime.mjs` to read the canonical release manifest and three files from `public/downloads`, reject symlinks and unexpected download-directory entries, and validate exact digest/size. Do not modify or regenerate the release bytes during npm build.

- [ ] **Step 3: Run production gates**

Run:

```bash
cd apps/heel-cloud
npm run build
node --test tests/production-artifact.test.mjs tests/mcp-quickstart.test.mjs
```

Expected: all tests `PASS`, and mutations adding `heel/saas/auth.py` or `docs/saas/PRODUCT.md` to either release archive fail the member scanner.

- [ ] **Step 4: Commit**

```bash
git add apps/heel-cloud/scripts/prepare-runtime.mjs apps/heel-cloud/tests/production-artifact.test.mjs
git commit -m "test: prove deployed Agent release boundary"
```

### Task 5: Make CI and publishing fail closed

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/publish.yml`
- Modify: `README.md`
- Modify: `docs/MCP_QUICKSTART.md`
- Modify: `apps/heel-cloud/README.md`

- [ ] **Step 1: Add release checks to CI**

Before any generic build step, run:

```yaml
- name: Check deterministic Apache-only release artifacts
  run: |
    python scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads --check
    python -m unittest tests.test_open_core_release -v
```

The package job must install the committed deterministic wheel and execute the real three-message MCP handshake. Remove the invalid pre-initialize `tools/list` smoke.

- [ ] **Step 2: Gate PyPI publication on the same bytes**

The publish workflow must:

1. run the builder into an empty `dist/` directory;
2. run `tests.test_open_core_release` against those bytes;
3. run `twine check` on only the wheel and source tarball;
4. attest and upload only `heel_sim-1.1.0-py3-none-any.whl` and `heel_sim-1.1.0.tar.gz`;
5. never publish an artifact produced by unrestricted setuptools discovery.

Do not claim publication until the trusted publisher and release actually exist.

- [ ] **Step 3: Reconcile public install documentation**

Document the current order truthfully:

1. same-origin Heel Cloud download works now;
2. PyPI and the public repository remain release-owner actions;
3. base local CLI/MCP stays Apache-2.0 and unlimited;
4. hosted synchronization/remote MCP remains a paid cloud feature;
5. Windows local secure project storage is not supported at launch.

- [ ] **Step 4: Run the full release gate**

Run:

```bash
python3 scripts/build_open_core_release.py --output apps/heel-cloud/public/downloads --check
python3 -m unittest tests.test_open_core_release -v
python3 -m unittest discover -s tests -p 'test_*.py' -v
cd apps/heel-cloud
npm run test:unit
npm run typecheck
npm run lint
npm run build
npm run test:node
```

Expected: every command exits 0; no release archive contains proprietary material; the installed `heel-mcp` returns `heel_review_openapi` after a valid handshake.

- [ ] **Step 5: Independent review and commit**

Request independent Fable spec review and a separate quality/security review. Fix every Critical/Important finding and rerun the exact gate above.

Commit:

```bash
git add .github/workflows/ci.yml .github/workflows/publish.yml README.md docs/MCP_QUICKSTART.md apps/heel-cloud/README.md
git commit -m "ci: gate Apache-only Heel Agent releases"
```

## Completion proof

This plan is complete only when all of the following are true:

- A customer can download the exact current Heel Agent wheel from `/mcp`, install it, and complete a real MCP handshake without a source checkout or PyPI.
- Wheel and sdist are byte-reproducible, hash-pinned, and independently member-inspected.
- The source archive contains its exact public build contract and installs offline into the same
  normalized wheel member set.
- `heel.saas`, hosted application code, private docs, commercial markers, and credentials are absent.
- `find_spec("heel.saas")` is `None` in the clean installed environment.
- CI and PyPI publishing use the same allowlist and artifact tests.
- The private monorepo is not represented as safe to push wholesale to the public repository.
