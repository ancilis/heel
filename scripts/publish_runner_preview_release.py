#!/usr/bin/env python3
"""Stage, publish and anonymously verify the Heel runner preview 1.3.0rc1 GitHub prerelease.

This is a release-owner tool for the already committed candidate artifacts.  Importing it or
asking for help does nothing.  Each mode must be selected explicitly:

``stage-draft``
    Verify the local candidate, require the existing remote tag at the expected commit, then
    create or resume only a *draft prerelease* and upload only missing canonical assets.
``publish-and-verify``
    Require that draft with exactly the three verified assets, publish it as a prerelease,
    then run ``verify-public`` in a new credential-free process.
``verify-public``
    Read-only and anonymous.  Verify the already published prerelease, download its assets
    without GitHub credentials, and install the wheel's ``[runner]`` extra in a new venv to
    run the two synthetic reference outcomes.

The tool never creates, moves or pushes a tag, and never deletes, replaces or overwrites a
release or asset.  The installed proof is packaging and synthetic-reference evidence only: it
does not establish pairing, serving, HTTPS target traffic, hosted findings or launch
readiness.  See docs/RUNNER_PREVIEW_RELEASE.md.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import tomllib
from urllib.parse import urlencode, urlsplit
import zipfile


ROOT = Path(os.path.abspath(__file__)).parents[1]
REPOSITORY = "ancilis/heel"
VERSION = "1.3.0rc1"
TAG = f"v{VERSION}"
TITLE = f"Heel runner preview {VERSION}"
DOWNLOADS = "apps/heel-cloud/public/downloads"
WHEEL = f"heel_sim-{VERSION}-py3-none-any.whl"
SDIST = f"heel_sim-{VERSION}.tar.gz"
MANIFEST = "heel-open-core-manifest.json"
ASSET_NAMES = (WHEEL, SDIST, MANIFEST)
MANIFEST_SCHEMA = "heel.open-core-artifacts.v1"
RUNNER_REQUIREMENT = "cryptography==45.0.7"
# Version sources that must all name the candidate; read from the committed source tree.
VERSION_SOURCES = (
    "pyproject.toml",
    "release/open-core-v1.json",
    "heel/__init__.py",
    "scripts/build_open_core_release.py",
)

API_HOST = "api.github.com"
UPLOAD_HOST = "uploads.github.com"
WEB_HOST = "github.com"
# Hosts GitHub uses for release-asset bytes.  They only ever receive anonymous requests.
CDN_HOSTS = frozenset(
    {
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com",
    }
)
API_VERSION = "2022-11-28"
USER_AGENT = "heel-runner-preview-publisher"
TIMEOUT_SECONDS = 60
PER_PAGE = 100
MAX_PAGES = 20
MAX_TAG_DEPTH = 4
MAX_REDIRECTS = 3
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_ASSET_BYTES = 32 * 1024 * 1024
RUNNER_TEST_MODULE = "tests.test_public_runner_preview_release"
MIN_RUNNER_TESTS = 5

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_REFUSED = 3
EXIT_UNKNOWN = 4
EXIT_PUBLISHED_UNVERIFIED = 5

_SHA = re.compile(r"\A[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"\A[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"\A[A-Za-z0-9_]{20,255}\Z")
_ID = r"[1-9][0-9]{0,15}"
_REPO_PATH = f"/repos/{REPOSITORY}"
_API_PATHS = tuple(
    re.compile(pattern)
    for pattern in (
        rf"\A{_REPO_PATH}/git/ref/tags/{re.escape(TAG)}\Z",
        rf"\A{_REPO_PATH}/git/tags/[0-9a-f]{{40}}\Z",
        rf"\A{_REPO_PATH}/releases\Z",
        rf"\A{_REPO_PATH}/releases/{_ID}\Z",
        rf"\A{_REPO_PATH}/releases/{_ID}/assets\Z",
        rf"\A{_REPO_PATH}/releases/assets/{_ID}\Z",
        rf"\A{_REPO_PATH}/releases/tags/{re.escape(TAG)}\Z",
    )
)
_UPLOAD_PATH = re.compile(rf"\A{_REPO_PATH}/releases/{_ID}/assets\Z")
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
# Words the closing evidence must never use as an outcome: this proof establishes none of them.
NOT_PROVEN = ("pairing", "heel runner serve", "HTTPS target traffic", "hosted findings", "launch readiness")


class ReleaseError(Exception):
    """A closed, credential-free failure message with its exit status."""

    exit_code = EXIT_FAILED


class Refused(ReleaseError):
    """A precondition failed; this step sent no mutation."""

    exit_code = EXIT_REFUSED


class OutcomeUnknown(ReleaseError):
    """A mutation was sent and its outcome could not be established by re-reading."""

    exit_code = EXIT_UNKNOWN


class VerificationFailed(ReleaseError):
    exit_code = EXIT_FAILED


class PublishedUnverified(ReleaseError):
    exit_code = EXIT_PUBLISHED_UNVERIFIED


class TransportError(Exception):
    """The connection failed or ended before a complete response was read."""


class Reporter:
    """Closed key=value progress lines on stderr; every line is scrubbed of known secrets."""

    def __init__(self, stream=None):
        self.stream = stream if stream is not None else sys.stderr
        self._secrets: list[str] = []

    def secret(self, value: str) -> None:
        if value:
            self._secrets.append(value)

    def redact(self, text: str) -> str:
        for value in self._secrets:
            text = text.replace(value, "[redacted]")
        return text

    def event(self, name: str, /, **facts: object) -> None:
        parts = [f"heel-preview-release: {name}"]
        parts.extend(f"{key}={value}" for key, value in facts.items())
        print(self.redact(" ".join(parts)), file=self.stream, flush=True)


class Response:
    def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes):
        self.status = status
        self.headers = [(key.lower(), value) for key, value in headers]
        self.body = body

    def header(self, name: str) -> str | None:
        values = [value for key, value in self.headers if key == name]
        if len(values) > 1:
            raise VerificationFailed(f"response repeats the {name} header")
        return values[0] if values else None


class HttpsTransport:
    """Certificate-verified HTTPS to one named host per request; never follows redirects."""

    def send(self, host, method, target, headers, body, limit):
        connection = http.client.HTTPSConnection(
            host, 443, timeout=TIMEOUT_SECONDS, context=ssl.create_default_context(),
        )
        return _exchange(connection, method, target, headers, body, limit)


def _exchange(connection, method, target, headers, body, limit) -> Response:
    try:
        connection.request(method, target, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read(limit + 1)
        if len(payload) > limit:
            raise VerificationFailed("response exceeds its size limit")
        return Response(response.status, response.getheaders(), payload)
    except (OSError, http.client.HTTPException) as error:
        raise TransportError(type(error).__name__) from None
    finally:
        connection.close()


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationFailed("response JSON repeats a key")
        result[key] = value
    return result


def _json(payload: bytes):
    try:
        return json.loads(payload, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise VerificationFailed("response is not valid JSON") from None


def _is_positive_int(value) -> bool:
    return type(value) is int and value > 0


def _follow_cdn(transport, location: str | None, limit: int) -> bytes:
    """Anonymously follow GitHub's asset redirect; only HTTPS release-asset CDN hosts qualify."""
    for _ in range(MAX_REDIRECTS):
        if location is None:
            raise VerificationFailed("asset redirect has no location")
        parts = urlsplit(location)
        if (
            parts.scheme != "https"
            or parts.hostname not in CDN_HOSTS
            or parts.username is not None
            or parts.password is not None
            or parts.port not in (None, 443)
            or parts.fragment
        ):
            raise VerificationFailed("asset redirect location is not an allowed HTTPS asset host")
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        response = transport.send(
            parts.hostname, "GET", target,
            {"Accept": "application/octet-stream", "User-Agent": USER_AGENT}, None, limit,
        )
        if response.status == 200:
            return response.body
        if response.status not in _REDIRECTS:
            raise VerificationFailed(f"asset host returned HTTP {response.status}")
        location = response.header("location")
    raise VerificationFailed("asset redirect chain is too long")


class GitHubClient:
    """Authenticated calls restricted to the repository's release paths on the API/upload hosts."""

    def __init__(self, transport, token: str, reporter: Reporter):
        if not _TOKEN.fullmatch(token or ""):
            raise Refused("the GitHub credential from gh has an unexpected form")
        self.transport = transport
        self._token = token
        self.reporter = reporter
        reporter.secret(token)

    def _send(self, host, method, path, *, query=None, body=None, content_type=None,
              accept="application/vnd.github+json", limit=MAX_JSON_BYTES) -> Response:
        allowed = _UPLOAD_PATH.fullmatch(path) if host == UPLOAD_HOST else (
            host == API_HOST and any(pattern.fullmatch(path) for pattern in _API_PATHS)
        )
        if not allowed:
            raise VerificationFailed("refusing an authenticated request outside the release paths")
        headers = {
            "Accept": accept,
            "Authorization": f"Bearer {self._token}",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": API_VERSION,
        }
        if body is not None:
            headers["Content-Type"] = content_type or "application/json"
        target = path + (f"?{urlencode(query)}" if query else "")
        return self.transport.send(host, method, target, headers, body, limit)

    def get_json(self, path, query=None):
        response = self._send(API_HOST, "GET", path, query=query)
        return response.status, (_json(response.body) if response.status == 200 else None), response

    def post_json(self, path, document):
        return self._send(API_HOST, "POST", path, body=_dumps(document))

    def patch_json(self, path, document):
        return self._send(API_HOST, "PATCH", path, body=_dumps(document))

    def upload(self, release_id: int, name: str, payload: bytes) -> Response:
        return self._send(
            UPLOAD_HOST, "POST", f"{_REPO_PATH}/releases/{release_id}/assets",
            query={"name": name}, body=payload, content_type="application/octet-stream",
        )

    def download_asset(self, asset_id: int, size: int) -> bytes:
        # Authorization goes only to the exact API asset path; the redirect target is anonymous.
        response = self._send(
            API_HOST, "GET", f"{_REPO_PATH}/releases/assets/{asset_id}",
            accept="application/octet-stream", limit=size,
        )
        if response.status == 200:
            return response.body
        if response.status not in _REDIRECTS:
            raise VerificationFailed(f"asset download returned HTTP {response.status}")
        return _follow_cdn(self.transport, response.header("location"), size)


class AnonymousClient:
    """Read-only GitHub access that has no credential and only issues GET requests."""

    def __init__(self, transport):
        self.transport = transport

    def get_json(self, path, query=None):
        if not any(pattern.fullmatch(path) for pattern in _API_PATHS):
            raise VerificationFailed("refusing a request outside the release paths")
        target = path + (f"?{urlencode(query)}" if query else "")
        response = self.transport.send(
            API_HOST, "GET", target,
            {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT,
             "X-GitHub-Api-Version": API_VERSION},
            None, MAX_JSON_BYTES,
        )
        return response.status, (_json(response.body) if response.status == 200 else None), response

    def download_public(self, name: str, size: int) -> bytes:
        response = self.transport.send(
            WEB_HOST, "GET", f"/{REPOSITORY}/releases/download/{TAG}/{name}",
            {"Accept": "application/octet-stream", "User-Agent": USER_AGENT}, None, size,
        )
        if response.status == 200:
            return response.body
        if response.status not in _REDIRECTS:
            raise VerificationFailed(f"public download of {name} returned HTTP {response.status}")
        return _follow_cdn(self.transport, response.header("location"), size)


def _dumps(document) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _canonical(value) -> bytes:
    """The builder's manifest encoding (scripts/build_open_core_release.py)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def verify_artifact_set(artifacts: dict[str, bytes]) -> dict:
    """Require the exact builder manifest for these wheel and source archive bytes."""
    if set(artifacts) != set(ASSET_NAMES):
        raise VerificationFailed("artifact set is not exactly the wheel, source archive and manifest")
    try:
        manifest = _json(artifacts[MANIFEST])
    except VerificationFailed:
        raise VerificationFailed("manifest is not valid JSON") from None
    expected = {
        "artifacts": sorted(
            (
                {"name": name, "sha256": hashlib.sha256(artifacts[name]).hexdigest(),
                 "size": len(artifacts[name])}
                for name in (WHEEL, SDIST)
            ),
            key=lambda record: record["name"],
        ),
        "schema_version": MANIFEST_SCHEMA,
        "version": VERSION,
    }
    if not isinstance(manifest, dict) or manifest.get("version") != VERSION:
        raise VerificationFailed("manifest does not name the candidate version")
    if artifacts[MANIFEST] != _canonical(expected):
        raise VerificationFailed("manifest is not the canonical manifest for these artifact bytes")
    return expected


def render_release_notes(source_sha: str, manifest_bytes: bytes) -> str:
    """Release body from verified source and artifact metadata only; it claims no verification."""
    manifest = _json(manifest_bytes)
    rows = [f"| `{record['name']}` | {record['size']} | `{record['sha256']}` |"
            for record in manifest["artifacts"]]
    rows.append(
        f"| `{MANIFEST}` | {len(manifest_bytes)} | `{hashlib.sha256(manifest_bytes).hexdigest()}` |"
    )
    return "\n".join(
        [
            f"{TITLE} is a GitHub prerelease of the Heel open-core package with its optional "
            "`[runner]` extra. It is not a stable release and is not published to PyPI.",
            "",
            f"Source commit: `{source_sha}` (tag `{TAG}`).",
            "",
            "| Asset | Bytes | SHA-256 |",
            "| --- | --- | --- |",
            *rows,
            "",
            "The manifest records the wheel and source archive digests. It cannot contain its own "
            "digest, so the manifest digest appears only in these release notes.",
            "",
            "Check the digests before installing, then install with "
            f"`python -m pip install './{WHEEL}[runner]'` on Python 3.11 or newer.",
            "",
            "Limitations: this preview is packaging and synthetic-reference evidence only. It does "
            "not establish runner pairing, `heel runner serve`, HTTPS target traffic, hosted "
            "findings or launch readiness. Cloud pairing remains an incomplete public journey.",
            "",
        ]
    )


# --------------------------------------------------------------------------- local gates


def _git(root: Path, *arguments: str, binary: bool = False):
    result = subprocess.run(
        ["git", "-C", str(root), *arguments], capture_output=True, timeout=120,
        env=_child_environment(), stdin=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise Refused(f"git {arguments[0]} failed")
    return result.stdout if binary else result.stdout.decode("utf-8", "replace")


def _child_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("GH_", "GITHUB_", "PYTHONPATH", "PYTHONHOME"))
    }
    environment.update(extra or {})
    return environment


def _read_regular(path: Path, limit: int) -> bytes:
    status = os.lstat(path)
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise Refused(f"{path.name} is not a regular local file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise Refused(f"{path.name} is not a regular local file")
        chunks, total = [], 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > limit:
                raise Refused(f"{path.name} exceeds the artifact size limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _committed_versions(root: Path, sha: str) -> dict[str, str]:
    def blob(path: str) -> bytes:
        return _git(root, "cat-file", "blob", f"{sha}:{path}", binary=True)

    def assigned(source: bytes, name: str) -> str | None:
        for node in ast.parse(source).body:
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name
                    and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
                return node.value.value
        return None

    try:
        return {
            "pyproject.toml": tomllib.loads(blob("pyproject.toml").decode("utf-8"))["project"]["version"],
            "release/open-core-v1.json": json.loads(blob("release/open-core-v1.json"))["version"],
            "heel/__init__.py": assigned(blob("heel/__init__.py"), "__version__"),
            "scripts/build_open_core_release.py": assigned(
                blob("scripts/build_open_core_release.py"), "RELEASE_VERSION"),
        }
    except (KeyError, TypeError, ValueError, SyntaxError):
        raise Refused("a committed version source is malformed") from None


def run_local_release_checks(root: Path) -> list[str]:
    """The two existing release checks this tool requires; returns their closed names."""
    python = sys.executable
    builder = subprocess.run(
        [python, "-I", "scripts/build_open_core_release.py", "--output", DOWNLOADS, "--check"],
        cwd=root, capture_output=True, text=True, timeout=600, env=_child_environment(),
        stdin=subprocess.DEVNULL,
    )
    if builder.returncode != 0 or builder.stdout.strip() != "open-core release artifacts are current":
        raise Refused("local gate failed: open-core builder --check")
    runner = subprocess.run(
        [python, "-m", "unittest", "-v", RUNNER_TEST_MODULE],
        cwd=root, capture_output=True, text=True, timeout=1800,
        env=_child_environment({"HEEL_REQUIRE_RUNNER_EXTRA_INSTALL": "1"}),
        stdin=subprocess.DEVNULL,
    )
    lines = [line.strip() for line in runner.stderr.splitlines() if line.strip()]
    ran = [int(match.group(1)) for line in lines if (match := re.fullmatch(r"Ran (\d+) tests? in .+", line))]
    if runner.returncode != 0 or len(ran) != 1 or ran[0] < MIN_RUNNER_TESTS or lines[-1:] != ["OK"]:
        raise Refused("local gate failed: enforced source-free runner-extra install tests")
    return ["open-core builder --check", f"{RUNNER_TEST_MODULE} ({ran[0]} tests, 0 skipped)"]


def verify_local_candidate(root: Path, sha: str, gate_runner, reporter: Reporter) -> dict[str, bytes]:
    """Every check that must hold before any credential is read or remote call is made."""
    top = _git(root, "rev-parse", "--show-toplevel").strip()
    if os.path.realpath(top) != os.path.realpath(root):
        raise Refused("the tool is not running from the root of its own checkout")
    head = _git(root, "rev-parse", "--verify", "HEAD^{commit}").strip()
    if head != sha:
        raise Refused("checkout HEAD is not the expected source commit")
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise Refused("checkout is not clean")
    versions = _committed_versions(root, sha)
    if set(versions.values()) != {VERSION}:
        raise Refused("committed version sources do not all name the candidate version")

    tree = _git(root, "ls-tree", "-z", sha, "--", f"{DOWNLOADS}/").split("\0")
    entries = {}
    for line in filter(None, tree):
        meta, path = line.split("\t", 1)
        entries[path.rsplit("/", 1)[-1]] = meta.split()
    if set(entries) != set(ASSET_NAMES) or any(
        meta[0] != "100644" or meta[1] != "blob" for meta in entries.values()
    ):
        raise Refused("committed downloads are not exactly the three regular candidate artifacts")

    current = root
    for part in DOWNLOADS.split("/"):
        current = current / part
        status = os.lstat(current)
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            raise Refused("downloads path leaves the checkout or is not a plain directory")
    if set(os.listdir(current)) != set(ASSET_NAMES):
        raise Refused("downloads directory is not exactly the wheel, source archive and manifest")
    artifacts = {}
    for name in ASSET_NAMES:
        payload = _read_regular(current / name, MAX_ASSET_BYTES)
        if payload != _git(root, "cat-file", "blob", f"{sha}:{DOWNLOADS}/{name}", binary=True):
            raise Refused(f"{name} differs from the committed blob")
        artifacts[name] = payload
    try:
        verify_artifact_set(artifacts)
    except VerificationFailed as error:
        raise Refused(str(error)) from None
    with zipfile.ZipFile(io.BytesIO(artifacts[WHEEL])) as wheel:
        metadata = wheel.read(f"heel_sim-{VERSION}.dist-info/METADATA").decode("utf-8")
    if f"\nVersion: {VERSION}\n" not in metadata:
        raise Refused("wheel metadata does not name the candidate version")
    checks = gate_runner(root)
    reporter.event(
        "local-candidate-verified", source=sha,
        **{name.replace(".", "_"): hashlib.sha256(payload).hexdigest() for name, payload in artifacts.items()},
        checks=len(checks),
    )
    return artifacts


# --------------------------------------------------------------------------- remote state


def verify_remote_tag(client, sha: str, reporter: Reporter) -> str:
    """Peel refs/tags/v1.3.0rc1 to its commit; lightweight and annotated tags are explicit."""
    status, ref, _ = client.get_json(f"{_REPO_PATH}/git/ref/tags/{TAG}")
    if status == 404:
        raise Refused(f"remote tag {TAG} does not exist; the release owner must create it first")
    if status != 200 or not isinstance(ref, dict) or ref.get("ref") != f"refs/tags/{TAG}":
        raise Refused(f"remote tag {TAG} lookup returned an unexpected reference")
    target = ref.get("object")
    seen: set[str] = set()
    kind = "lightweight"
    for depth in range(MAX_TAG_DEPTH + 1):
        if not isinstance(target, dict) or not isinstance(target.get("sha"), str) or not _SHA.fullmatch(target["sha"]):
            raise Refused("remote tag target is malformed")
        if target.get("type") == "commit":
            if target["sha"] != sha:
                raise Refused(f"remote tag {TAG} does not resolve to the expected source commit")
            reporter.event("remote-tag-verified", tag=TAG, kind=kind, source=sha)
            return kind
        if target.get("type") != "tag":
            raise Refused("remote tag points at an object that is neither a commit nor a tag")
        if depth == MAX_TAG_DEPTH:
            raise Refused("remote tag peeling exceeded its bound")
        if target["sha"] in seen:
            raise Refused("remote tag objects form a cycle")
        seen.add(target["sha"])
        status, tag, _ = client.get_json(f"{_REPO_PATH}/git/tags/{target['sha']}")
        if status != 200 or not isinstance(tag, dict) or tag.get("sha") != target["sha"]:
            raise Refused("remote annotated tag object lookup returned another identity")
        if depth == 0 and tag.get("tag") != TAG:
            raise Refused("remote annotated tag object names a different tag")
        kind = "annotated"
        target = tag.get("object")
    raise Refused("remote tag peeling exceeded its bound")


def _expected_release_url(release_id: int) -> str:
    return f"https://{API_HOST}{_REPO_PATH}/releases/{release_id}"


def check_release(release, *, sha: str, draft: bool, notes: str | None) -> int:
    """Require the release identity this tool creates; return its id."""
    if not isinstance(release, dict) or not _is_positive_int(release.get("id")):
        raise Refused("release record is malformed")
    release_id = release["id"]
    if release.get("url") != _expected_release_url(release_id):
        raise Refused("release record names another repository or release")
    if release.get("tag_name") != TAG or release.get("name") != TITLE:
        raise Refused("release tag or title is not the runner preview identity")
    if release.get("target_commitish") != sha:
        raise Refused("release target is not the expected source commit")
    if release.get("prerelease") is not True:
        raise Refused("release is not a prerelease; this tool never creates or converts a stable release")
    if release.get("draft") is not draft:
        raise Refused("release is not a draft" if draft else "release is still a draft")
    if notes is not None and release.get("body") != notes:
        raise Refused("release notes differ from the verified candidate notes")
    expected_upload = f"https://{UPLOAD_HOST}{_REPO_PATH}/releases/{release_id}/assets{{?name,label}}"
    if "upload_url" in release and release["upload_url"] != expected_upload:
        raise Refused("release upload location is not the expected GitHub upload path")
    return release_id


def _paged(client, path: str) -> list:
    items = []
    for page in range(1, MAX_PAGES + 1):
        status, data, response = client.get_json(path, {"per_page": PER_PAGE, "page": page})
        if status != 200 or not isinstance(data, list):
            raise Refused(f"listing {path.rsplit('/', 1)[-1]} returned HTTP {status}")
        items.extend(data)
        if 'rel="next"' not in (response.header("link") or ""):
            return items
    raise Refused("listing exceeded its page bound")


def find_release(client):
    matches = [item for item in _paged(client, f"{_REPO_PATH}/releases")
               if isinstance(item, dict) and item.get("tag_name") == TAG]
    if len(matches) > 1:
        raise Refused(f"more than one release uses tag {TAG}")
    return matches[0] if matches else None


def list_assets(client, release_id: int, artifacts: dict[str, bytes] | None, *, public: bool = False) -> dict:
    """Validate every listed asset's identity; ``artifacts`` fixes expected sizes and digests."""
    by_name: dict[str, dict] = {}
    seen_ids: set[int] = set()
    for asset in _paged(client, f"{_REPO_PATH}/releases/{release_id}/assets"):
        if not isinstance(asset, dict) or not _is_positive_int(asset.get("id")):
            raise Refused("asset record is malformed")
        name = asset.get("name")
        if name not in ASSET_NAMES:
            raise Refused("release contains an unexpected asset")
        if name in by_name or asset["id"] in seen_ids:
            raise Refused("release contains a duplicate asset identity")
        seen_ids.add(asset["id"])
        if asset.get("url") != f"https://{API_HOST}{_REPO_PATH}/releases/assets/{asset['id']}":
            raise Refused("asset record names another repository or asset")
        if asset.get("state") != "uploaded":
            raise Refused(f"asset {name} is not fully uploaded")
        size = asset.get("size")
        if not _is_positive_int(size) or size > MAX_ASSET_BYTES:
            raise Refused(f"asset {name} has an invalid size")
        if artifacts is not None:
            if size != len(artifacts[name]):
                raise Refused(f"asset {name} conflicts with the candidate bytes (size)")
            digest = asset.get("digest")
            if digest is not None and digest != "sha256:" + hashlib.sha256(artifacts[name]).hexdigest():
                raise Refused(f"asset {name} conflicts with the candidate bytes (digest)")
        if public and asset.get("browser_download_url") != (
            f"https://{WEB_HOST}/{REPOSITORY}/releases/download/{TAG}/{name}"
        ):
            raise Refused(f"asset {name} public location is not the expected release path")
        by_name[name] = asset
    return by_name


def verify_asset_bytes(client, assets: dict, artifacts: dict[str, bytes], reporter: Reporter) -> None:
    for name, asset in assets.items():
        try:
            payload = client.download_asset(asset["id"], asset["size"])
        except VerificationFailed as error:
            raise Refused(f"asset {name} could not be verified: {error}") from None
        if payload != artifacts[name]:
            raise Refused(f"asset {name} conflicts with the candidate bytes; nothing was replaced")
        reporter.event("asset-verified", name=name, size=len(payload),
                       sha256=hashlib.sha256(payload).hexdigest())


def _uncertain(response) -> bool:
    return response is None or response.status >= 500


def _create_draft(client, sha: str, notes: str, reporter: Reporter) -> dict:
    document = {
        "tag_name": TAG, "target_commitish": sha, "name": TITLE, "body": notes,
        "draft": True, "prerelease": True, "generate_release_notes": False, "make_latest": "false",
    }
    try:
        response = client.post_json(f"{_REPO_PATH}/releases", document)
    except TransportError:
        response = None
    if response is not None and response.status == 201:
        reporter.event("draft-created", tag=TAG)
        return _json(response.body)
    if not _uncertain(response):
        raise Refused(f"creating the draft returned HTTP {response.status}")
    # The server may have committed the draft; reconcile by reading, never by repeating.
    release = find_release(client)
    if release is None:
        raise OutcomeUnknown(
            "draft creation outcome is unknown and the release list does not show it; no retry "
            "was sent. Re-run stage-draft later; it starts by re-reading the releases."
        )
    reporter.event("draft-create-reconciled", tag=TAG)
    return release


def _upload(client, release_id: int, name: str, payload: bytes, artifacts, reporter) -> None:
    try:
        response = client.upload(release_id, name, payload)
    except TransportError:
        response = None
    if response is not None and response.status == 201:
        uploaded = _json(response.body)
        if not isinstance(uploaded, dict) or uploaded.get("name") != name or uploaded.get("size") != len(payload):
            raise Refused(f"upload response for {name} names another asset")
    elif not _uncertain(response):
        raise Refused(f"uploading {name} returned HTTP {response.status}")
    assets = list_assets(client, release_id, artifacts)
    if name not in assets:
        raise OutcomeUnknown(
            f"upload of {name} has an unknown outcome and the asset list does not show it; no "
            "retry was sent. Re-run stage-draft later; it re-reads and verifies existing assets."
        )
    verify_asset_bytes(client, {name: assets[name]}, artifacts, reporter)
    reporter.event("asset-uploaded", name=name, reconciled=response is None or response.status != 201)


def stage_draft(client, sha: str, artifacts: dict[str, bytes], reporter: Reporter) -> dict:
    notes = render_release_notes(sha, artifacts[MANIFEST])
    verify_remote_tag(client, sha, reporter)
    release = find_release(client)
    if release is None:
        verify_remote_tag(client, sha, reporter)
        release = _create_draft(client, sha, notes, reporter)
    else:
        reporter.event("draft-found", tag=TAG)
    release_id = check_release(release, sha=sha, draft=True, notes=notes)
    existing = list_assets(client, release_id, artifacts)
    verify_asset_bytes(client, existing, artifacts, reporter)
    for name in ASSET_NAMES:
        if name not in existing:
            _upload(client, release_id, name, artifacts[name], artifacts, reporter)
    final = list_assets(client, release_id, artifacts)
    if set(final) != set(ASSET_NAMES):
        raise Refused("draft does not hold exactly the three candidate assets")
    reporter.event("draft-staged", tag=TAG, assets=len(final), state="draft-prerelease")
    return {"mode": "stage-draft", "state": "draft-prerelease", "tag": TAG, "source": sha,
            "assets": sorted(final), "public": False}


def _reread(client, release_id: int):
    status, release, _ = client.get_json(f"{_REPO_PATH}/releases/{release_id}")
    return release if status == 200 else None


def publish(client, root: Path, sha: str, artifacts: dict[str, bytes], reporter: Reporter) -> dict:
    notes = render_release_notes(sha, artifacts[MANIFEST])
    verify_remote_tag(client, sha, reporter)
    release = find_release(client)
    if release is None:
        raise Refused("no draft prerelease exists; run stage-draft first")
    if isinstance(release, dict) and release.get("draft") is False:
        release_id = check_release(release, sha=sha, draft=False, notes=notes)
        assets = list_assets(client, release_id, artifacts)
        if set(assets) != set(ASSET_NAMES):
            raise Refused("published prerelease does not hold exactly the three candidate assets")
        verify_asset_bytes(client, assets, artifacts, reporter)
        reporter.event("already-published", tag=TAG, publish_request_sent=False)
        return {"published_now": False}
    release_id = check_release(release, sha=sha, draft=True, notes=notes)
    assets = list_assets(client, release_id, artifacts)
    if set(assets) != set(ASSET_NAMES):
        raise Refused("draft does not hold exactly the three candidate assets; run stage-draft")
    verify_asset_bytes(client, assets, artifacts, reporter)
    # Read the source identity again immediately before the one publication request.
    if _git(root, "rev-parse", "--verify", "HEAD^{commit}").strip() != sha or _git(
        root, "status", "--porcelain=v1", "--untracked-files=all"
    ):
        raise Refused("checkout changed before publication")
    verify_remote_tag(client, sha, reporter)
    try:
        response = client.patch_json(
            f"{_REPO_PATH}/releases/{release_id}",
            {"draft": False, "prerelease": True, "make_latest": "false"},
        )
    except TransportError:
        response = None
    if response is not None and response.status not in (200,) and not _uncertain(response):
        raise Refused(f"publishing returned HTTP {response.status}; re-read the release before any retry")
    reread = _reread(client, release_id)
    if reread is None:
        raise OutcomeUnknown("publication request was sent and the release could not be re-read")
    if reread.get("draft") is True:
        if response is not None and response.status == 200:
            raise OutcomeUnknown("publication was acknowledged but the release still reads as a draft")
        raise OutcomeUnknown(
            "publication outcome is unknown and the release still reads as a draft; no retry was "
            "sent. Re-run publish-and-verify later; it re-reads the release first."
        )
    check_release(reread, sha=sha, draft=False, notes=notes)
    final = list_assets(client, release_id, artifacts)
    if set(final) != set(ASSET_NAMES):
        raise Refused("published prerelease does not hold exactly the three candidate assets")
    reporter.event("published", tag=TAG, prerelease=True,
                   acknowledged=response is not None and response.status == 200)
    return {"published_now": True}


# --------------------------------------------------------------------------- public verification


def scrubbed_environment(work: Path) -> dict[str, str]:
    """A new environment with no GitHub, git, pip, netrc or Python user configuration."""
    home = work / "home"
    home.mkdir(mode=0o700, exist_ok=True)
    temporary = work / "tmp"
    temporary.mkdir(mode=0o700, exist_ok=True)
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "LANG": "C.UTF-8",
        "HEEL_HOME": str(work / "heel-home"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "NETRC": os.devnull,
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_CACHE_DIR": "1",
        "PIP_NO_INPUT": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


_IMPORT_PROBE = r'''
import importlib.util, json, sys
from pathlib import Path
venv, checkout = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
for entry in sys.path:
    if entry and Path(entry).resolve().is_relative_to(checkout):
        raise SystemExit("checkout on sys.path")
import heel, heel.runner.identity
origin = Path(heel.__file__).resolve()
print(json.dumps({
    "heel_version": heel.__version__,
    "heel_in_venv": origin.is_relative_to(venv) and not origin.is_relative_to(checkout),
    "saas_absent": importlib.util.find_spec("heel.saas") is None,
}, sort_keys=True))
'''


class ProofFailed(VerificationFailed):
    pass


def run_installed_reference_proof(acquisition: Path, work: Path) -> dict:
    """Install the downloaded wheel's [runner] extra in a new venv and run both reference cases."""
    if sys.version_info < (3, 11):
        raise ProofFailed("Python 3.11 or newer is required for the installed proof")
    environment = scrubbed_environment(work)
    venv = work / "venv"
    logs = work / "logs"
    logs.mkdir(mode=0o700, exist_ok=True)

    def run(step: str, command: list[str], cwd: Path, timeout: int = 300) -> str:
        result = subprocess.run(command, cwd=cwd, env=environment, capture_output=True, text=True,
                                timeout=timeout, stdin=subprocess.DEVNULL)
        (logs / f"{step}.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        if result.returncode != 0:
            raise ProofFailed(f"installed proof step {step} failed (rc={result.returncode}); log in {logs}")
        return result.stdout

    python = str(venv / "bin/python")
    run("venv", [sys.executable, "-I", "-m", "venv", str(venv)], work)
    run("pip-install", [python, "-I", "-m", "pip", "--isolated", "install", f"./{WHEEL}[runner]"],
        acquisition, timeout=900)
    run("pip-check", [python, "-I", "-m", "pip", "check"], work)
    installed = json.loads(run("metadata", [python, "-I", "-c",
        "import importlib.metadata as m, json;"
        "print(json.dumps({d.metadata['Name'].lower(): d.version for d in m.distributions()}))"], work))
    if installed.get("heel-sim") != VERSION or installed.get("cryptography") != RUNNER_REQUIREMENT.split("==")[1]:
        raise ProofFailed("installed distribution versions are not the candidate and its runner pin")
    probe = json.loads(run("import-probe", [python, "-I", "-c", _IMPORT_PROBE, str(venv), str(ROOT)], work))
    if probe != {"heel_version": VERSION, "heel_in_venv": True, "saas_absent": True}:
        raise ProofFailed("installed package identity or heel.saas exclusion check failed")
    heel = str(venv / "bin/heel")
    scope = json.loads(run("scope-create", [heel, "scope", "create", "--target", "reference:export",
                                            "--operator", "runner preview public verification", "--confirm"],
                           work))["created_scope"]
    outcomes = {}
    for case, attempt, expected, passed in (("vulnerable", "5" * 32, "verified_violation", False),
                                            ("hardened", "6" * 32, "invariant_held", True)):
        report = json.loads(run(f"reference-{case}", [heel, "reference", "run", "--scope", scope,
                                                      "--case", case, "--attempt", attempt], work))
        if (report.get("result") != expected or report.get("regression_passed") is not passed
                or report.get("execution_support") != "reference_only"
                or report.get("uploaded") is not False
                or report.get("provenance", {}).get("network_calls") is not False):
            raise ProofFailed(f"synthetic reference case {case} did not produce its expected outcome")
        outcomes[case] = expected
    return {
        "python": sys.version.split()[0],
        "installed": {"heel-sim": installed["heel-sim"], "cryptography": installed["cryptography"]},
        "import_probe": probe,
        "reference_outcomes": outcomes,
        "scope": "packaging and synthetic reference only",
    }


def verify_public(anonymous: AnonymousClient, sha: str, manifest_sha256: str, proof_runner,
                  reporter: Reporter, work_root: Path | None = None) -> dict:
    """Read-only: verify the published prerelease and its anonymously acquired bytes."""
    verify_remote_tag(anonymous, sha, reporter)
    status, release, _ = anonymous.get_json(f"{_REPO_PATH}/releases/tags/{TAG}")
    if status == 404:
        raise VerificationFailed(f"no published release for {TAG} is publicly visible")
    if status != 200:
        raise VerificationFailed(f"public release lookup returned HTTP {status}")
    try:
        release_id = check_release(release, sha=sha, draft=False, notes=None)
        listed = list_assets(anonymous, release_id, None, public=True)
    except Refused as error:
        raise VerificationFailed(str(error)) from None
    if set(listed) != set(ASSET_NAMES):
        raise VerificationFailed("public release does not hold exactly the three candidate assets")
    work = Path(tempfile.mkdtemp(prefix="heel-preview-public-", dir=work_root)).resolve()
    if work.is_relative_to(ROOT.resolve()):
        raise VerificationFailed("public verification directory is inside the checkout")
    acquisition = work / "acquisition"
    acquisition.mkdir(mode=0o700)
    acquired = {}
    for name in ASSET_NAMES:
        payload = anonymous.download_public(name, listed[name]["size"])
        if len(payload) != listed[name]["size"]:
            raise VerificationFailed(f"public asset {name} size differs from its listing")
        acquired[name] = payload
        (acquisition / name).write_bytes(payload)
    if hashlib.sha256(acquired[MANIFEST]).hexdigest() != manifest_sha256:
        raise VerificationFailed("public manifest digest is not the expected manifest digest")
    verify_artifact_set(acquired)
    if release.get("body") != render_release_notes(sha, acquired[MANIFEST]):
        raise VerificationFailed("public release notes differ from the verified candidate notes")
    digests = {name: hashlib.sha256(payload).hexdigest() for name, payload in acquired.items()}
    reporter.event("public-assets-verified", tag=TAG, credentials="none",
                   **{name.replace(".", "_"): digest for name, digest in digests.items()})
    proof = proof_runner(acquisition, work)
    reporter.event("installed-reference-proof", result="passed", support="reference_only")
    return {
        "mode": "verify-public",
        "tag": TAG,
        "source": sha,
        "release_id": release_id,
        "assets": {name: {"size": len(acquired[name]), "sha256": digests[name]} for name in ASSET_NAMES},
        "anonymous_acquisition": True,
        "installed_proof": proof,
        "not_proven": list(NOT_PROVEN),
        "work_directory": str(work),
    }


def spawn_verify_public(sha: str, manifest_sha256: str, reporter: Reporter) -> int:
    """Run verify-public in a new process with no GitHub credential and no checkout cwd."""
    work = Path(tempfile.mkdtemp(prefix="heel-preview-verify-")).resolve()
    command = [sys.executable, "-I", os.path.abspath(__file__), "verify-public",
               "--repository", REPOSITORY, "--tag", TAG, "--expected-sha", sha,
               "--expected-manifest-sha256", manifest_sha256]
    environment = scrubbed_environment(work)
    reporter.event("verify-public-started", credentials="none", cwd=work)
    return subprocess.run(command, cwd=work, env=environment, stdin=subprocess.DEVNULL,
                          timeout=3600).returncode


# --------------------------------------------------------------------------- command line


def gh_token() -> str:
    """Use the release owner's existing gh login; the credential never appears in argv or logs."""
    gh = shutil.which("gh")
    if gh is None:
        raise Refused("the GitHub CLI (gh) is required for the authenticated modes")
    result = subprocess.run([gh, "auth", "token", "--hostname", WEB_HOST], capture_output=True,
                            text=True, timeout=30, stdin=subprocess.DEVNULL)
    if result.returncode != 0:
        raise Refused("gh auth token failed; the release owner must run gh auth login")
    return result.stdout.strip()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="publish_runner_preview_release.py",
        description=f"Release-owner tool for the {TITLE} GitHub prerelease. "
                    "No mode runs unless it is named explicitly.",
    )
    modes = parser.add_subparsers(dest="mode", metavar="MODE")
    for mode, summary in (
        ("stage-draft", "create or resume the draft prerelease and upload missing assets"),
        ("publish-and-verify", "publish the verified draft as a prerelease, then verify-public"),
        ("verify-public", "read-only anonymous verification of the published prerelease"),
    ):
        sub = modes.add_parser(mode, help=summary, description=summary)
        sub.add_argument("--repository", required=True, help=f"must be {REPOSITORY}")
        sub.add_argument("--tag", required=True, help=f"must be {TAG}")
        sub.add_argument("--expected-sha", required=True, help="full 40-hex source commit")
        if mode == "verify-public":
            sub.add_argument("--expected-manifest-sha256", required=True,
                             help=f"SHA-256 of the committed {MANIFEST}")
    return parser


def main(argv=None, *, transport=None, token_provider=None, gate_runner=None, proof_runner=None,
         spawn_verify=None, root: Path | None = None, reporter: Reporter | None = None,
         stdout=None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    stdout = stdout if stdout is not None else sys.stdout
    if arguments.mode is None:
        parser.print_help(sys.stderr)
        return 2
    reporter = reporter or Reporter()
    transport = transport or HttpsTransport()
    root = Path(root or ROOT)
    try:
        if sys.version_info < (3, 11):
            raise Refused("Python 3.11 or newer is required")
        if arguments.repository != REPOSITORY or arguments.tag != TAG:
            raise Refused(f"only {REPOSITORY} tag {TAG} is supported")
        if not _SHA.fullmatch(arguments.expected_sha):
            raise Refused("--expected-sha must be a full lowercase 40-hex commit")
        sha = arguments.expected_sha
        if arguments.mode == "verify-public":
            if not _DIGEST.fullmatch(arguments.expected_manifest_sha256):
                raise Refused("--expected-manifest-sha256 must be 64 lowercase hex characters")
            result = verify_public(AnonymousClient(transport), sha, arguments.expected_manifest_sha256,
                                   proof_runner or run_installed_reference_proof, reporter)
        else:
            artifacts = verify_local_candidate(root, sha, gate_runner or run_local_release_checks, reporter)
            client = GitHubClient(transport, (token_provider or gh_token)(), reporter)
            if arguments.mode == "stage-draft":
                result = stage_draft(client, sha, artifacts, reporter)
            else:
                outcome = publish(client, root, sha, artifacts, reporter)
                manifest_sha256 = hashlib.sha256(artifacts[MANIFEST]).hexdigest()
                code = (spawn_verify or spawn_verify_public)(sha, manifest_sha256, reporter)
                if code != EXIT_OK:
                    raise PublishedUnverified(
                        f"the prerelease is published but anonymous verification failed (rc={code}). "
                        "Do not recreate, delete or re-upload. Recover read-only with: "
                        f"verify-public --repository {REPOSITORY} --tag {TAG} --expected-sha {sha} "
                        f"--expected-manifest-sha256 {manifest_sha256}"
                    )
                result = {"mode": "publish-and-verify", "tag": TAG, "source": sha,
                          "state": "published-prerelease", **outcome,
                          "anonymous_verification": "passed in a credential-free process"}
    except ReleaseError as error:
        reporter.event("failed", status=type(error).__name__, exit=error.exit_code)
        print(reporter.redact(f"error: {error}"), file=reporter.stream, flush=True)
        return error.exit_code
    except (TransportError, subprocess.TimeoutExpired, OSError) as error:
        # verify-public never mutates, so its network failure is simply a failed verification.
        code = EXIT_FAILED if arguments.mode == "verify-public" else EXIT_UNKNOWN
        reporter.event("failed", status=type(error).__name__, exit=code)
        print("error: a network or process step failed; re-run the same mode, which re-reads "
              "state before any change", file=reporter.stream, flush=True)
        return code
    print(reporter.redact(json.dumps(result, sort_keys=True)), file=stdout, flush=True)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
