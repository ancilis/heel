"""Release-owner publisher for the runner preview 1.3.0rc5 prerelease, against a controlled fake GitHub.

Every remote call here goes to a loopback HTTP server that plays the GitHub API, upload, web and
release-asset CDN hosts.  The publisher keeps its logical ``https://`` host checks; only the
test transport maps those logical hosts to the loopback socket.  None of this is evidence of a
real GitHub publication, and no test reads a real credential.

The rc5 tool is a copy of the reviewed, published rc4 tool (scripts/publish_runner_preview_release_rc4.py)
that differs only in the enumerated hunks E1-E3 and E5-E7; E4 (the FINAL pin status and its refusal
of every other status) is carried over byte for byte.  DiffBoundTests enforces that.  Its candidate is
the 1.3.0rc5 bytes this checkout carries, bound below by git blob id, SHA-256 and size; this module
fails at import on purpose if they differ.

The pins below are the rc5 candidate built once at source 79a1273b and the tool's PIN_STATUS is FINAL.
InterimPinTests keeps proving that any other status refuses every mode; FinalizationTests requires the
rc5 digests to differ from the published rc4 digests recorded here, which the tool therefore refuses.
"""
from __future__ import annotations

import hashlib
import http.client
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from types import MappingProxyType
from unittest import mock
from urllib.parse import parse_qs, urlsplit



ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/publish_runner_preview_release_rc5.py"
BASE_SCRIPT = ROOT / "scripts/publish_runner_preview_release_rc4.py"
RUNBOOK = ROOT / "docs/RUNNER_PREVIEW_RELEASE_RC5.md"
DOWNLOADS = "apps/heel-cloud/public/downloads"
# The rc5 candidate at 79a1273b9653f5602b7db59b359aa49827c2026d
# (tree 417e8584ea096744e13f30580702038775e0adb6), written out here independently of the tool.
PINNED_COMMIT = "79a1273b9653f5602b7db59b359aa49827c2026d"
PINNED_BLOBS = {
    f"{DOWNLOADS}/heel_sim-1.3.0rc5-py3-none-any.whl": "0437447ed987bf1cba64638205bd75cbd450d913",
    f"{DOWNLOADS}/heel_sim-1.3.0rc5.tar.gz": "f1d5556e264cf9797467d17718b8f6fe6154cf5f",
    f"{DOWNLOADS}/heel-open-core-manifest.json": "c5beaa79d365154a46cd1bf42cded274ddfd1e69",
    "pyproject.toml": "2c245eba1f21fff4ef30aef7358c663cd11c71ca",
    "release/open-core-v1.json": "1ef6625c41fc54cb4d0aefb44754849bb4cc2009",
    "heel/__init__.py": "a18d39633de609cefccf59b07abdf3ffe0329c51",
    "scripts/build_open_core_release.py": "5fd6df1aa7f2acc9a2f32b3d5b79479fd4841ce8",
}
ACCEPTED_SHA256 = {
    "heel_sim-1.3.0rc5-py3-none-any.whl": "a7c7293be3e30f1c3fb6fd968ab16c2845ebaae34d4fe3bcb2ddfd54855aa226",
    "heel_sim-1.3.0rc5.tar.gz": "3cd3cbc9aa84381f58703c13cc0f446fa8fc8fe57d395283cdc422ff3ded579e",
    "heel-open-core-manifest.json": "8d822c5eea3bebf8b4b5b139121165b4be218e1914743b8561ec22414f5eef51",
}
ACCEPTED_SIZES = {
    "heel_sim-1.3.0rc5-py3-none-any.whl": 2869122,
    "heel_sim-1.3.0rc5.tar.gz": 610466,
    "heel-open-core-manifest.json": 347,
}
# The published v1.3.0rc4 digests (68b8d50e), by asset role.  Fixed forever: the rc5 pins must differ
# from every one, so the tool can never be pointed at the previous release's bytes.
INTERIM_SHA256 = {
    "heel_sim-1.3.0rc5-py3-none-any.whl": "27cc929b32d07c6fa3466dd6e8cb3079cb90b513d93bf65dc64cae05393ba2af",
    "heel_sim-1.3.0rc5.tar.gz": "ae4f0e0a0b3e93bb93adb525150bdb9180c8fe9e5017c8d23323984e76e02dbd",
    "heel-open-core-manifest.json": "d87a9602419a020dfa26315de9797f027d9a90f237b0b0573259de468721551f",
}
INTERIM_STATUS = "AWAITING-FINAL-ARTIFACT-PINS"
# The published rc4, rc3 and rc2 and historical rc1 publishers, tests, runbooks and fixtures; unchanged by rc5.
PROTECTED_BLOBS = {
    "scripts/publish_runner_preview_release.py": "b399c533e93f3aa1347d48e0efa5e3cc80340e0d",
    "scripts/publish_runner_preview_release_rc2.py": "24688c85692f100ef348267523514c2baada612c",
    "scripts/publish_runner_preview_release_rc3.py": "da499590878e0c8cc812db6f7d02ccfcdaf9cbfb",
    "scripts/publish_runner_preview_release_rc4.py": "afb4704557803885ee060efa8fb1475107bb22f8",
    "tests/test_runner_preview_publisher.py": "2ac2f3b022251240921fc0d7768e6622851e2b87",
    "tests/test_runner_preview_publisher_rc2.py": "6a387c3173aa7cd23ad9bde6c6606bdeb1a7baf8",
    "tests/test_runner_preview_publisher_rc3.py": "470ab45db75fa7fdb686e5469510316881fd55f1",
    "tests/test_runner_preview_publisher_rc4.py": "81d3ac34c832dfe879350236b378ff9e75d1fc93",
    "docs/RUNNER_PREVIEW_RELEASE.md": "e2a88cbfa18c99aa2956583e3ad0d3bb32f3598a",
    "docs/RUNNER_PREVIEW_RELEASE_RC2.md": "2cd345251b586b63781c5a7aed8e193d6fa788e4",
    "docs/RUNNER_PREVIEW_RELEASE_RC3.md": "66f7fc7b03d4dba1449c919fe2cb2cd29edef684",
    "docs/RUNNER_PREVIEW_RELEASE_RC4.md": "ed8f2eba25a58c48303ca22773131450fd11865d",
    "tests/fixtures/runner_preview_rc1/artifacts/heel-open-core-manifest.json": "61691e27cadc8608c5f0e3b73e75902ca278b06b",
    "tests/fixtures/runner_preview_rc1/artifacts/heel_sim-1.3.0rc1-py3-none-any.whl": "6be8b96d444a8ef3ceadfd1004d354b9e7c75e24",
    "tests/fixtures/runner_preview_rc1/artifacts/heel_sim-1.3.0rc1.tar.gz": "1d93115c17bed290f469f576900993176f5edcf7",
    "tests/fixtures/runner_preview_rc1/provenance.json": "252af580c68ed0dcd3da64034eba32f071478129",
    "tests/fixtures/runner_preview_rc1/version_sources/__init__.py.txt": "33d834d4701d715bc4bdc987ce389cc85cdf3dee",
    "tests/fixtures/runner_preview_rc1/version_sources/build_open_core_release.py.txt": "d74f7f6bf5b6dbd07aa2f0b5f12fdfe8116bf9d3",
    "tests/fixtures/runner_preview_rc1/version_sources/open-core-v1.json.txt": "a6810fcac95714bf196ba58e9ba08461d4037fa5",
    "tests/fixtures/runner_preview_rc1/version_sources/pyproject.toml.txt": "7ce20c920e70617a7836a37794c27141b5fb4da5",
    "tests/fixtures/runner_preview_rc2/artifacts/heel-open-core-manifest.json": "5ecb6b0ab1bf0e036127e23a6af69a06c0b47adf",
    "tests/fixtures/runner_preview_rc2/artifacts/heel_sim-1.3.0rc2-py3-none-any.whl": "d1a281ed544a728be199b75afc7194f8a4637665",
    "tests/fixtures/runner_preview_rc2/artifacts/heel_sim-1.3.0rc2.tar.gz": "d4c6ab4ef94df1941125c856ae3dcbead0f1a3e4",
    "tests/fixtures/runner_preview_rc2/provenance.json": "0de947db97364095af2708c8070cfddd1ab44523",
    "tests/fixtures/runner_preview_rc2/version_sources/__init__.py.txt": "4ac153ee416e448e4571b1c218fc4b37d160103e",
    "tests/fixtures/runner_preview_rc2/version_sources/build_open_core_release.py.txt": "60eb72918a8b82ede3f62174b33824e3eaf5815f",
    "tests/fixtures/runner_preview_rc2/version_sources/open-core-v1.json.txt": "b7855f999b2d834660aed7e099418e457c6debfb",
    "tests/fixtures/runner_preview_rc2/version_sources/pyproject.toml.txt": "2f787dde0aee1caefd38d2e2a15b1c1c28f82dae",
    "tests/fixtures/runner_preview_rc3/artifacts/heel-open-core-manifest.json": "260aebd9ca49e17b1bff58611b3066cf8ea24738",
    "tests/fixtures/runner_preview_rc3/artifacts/heel_sim-1.3.0rc3-py3-none-any.whl": "7fcbeb6621c30fbf7239e4f3b9e682e27b03011d",
    "tests/fixtures/runner_preview_rc3/artifacts/heel_sim-1.3.0rc3.tar.gz": "a1ece2a02488c38024d29e3d949052987dde9004",
    "tests/fixtures/runner_preview_rc3/provenance.json": "479eb028bbc4621d87ef1cc71b0c80f2e8cfbbbd",
    "tests/fixtures/runner_preview_rc3/version_sources/__init__.py.txt": "b9e9d2c91ef63f198685763c7e2fd51c1c8ea98b",
    "tests/fixtures/runner_preview_rc3/version_sources/build_open_core_release.py.txt": "c18acf6e7ce1286ba6a0a289809f9bd3afbb6194",
    "tests/fixtures/runner_preview_rc3/version_sources/open-core-v1.json.txt": "51de2e9a0e4acb47f2923ac1ab162134f4ea0f16",
    "tests/fixtures/runner_preview_rc3/version_sources/pyproject.toml.txt": "eadaa9da1448bdfbb56d1aeb828dd8ded39ed8e6",
    "tests/fixtures/runner_preview_rc4/artifacts/heel-open-core-manifest.json": "90e53aabb727ff44f48fb5734163f1625d7fc7b1",
    "tests/fixtures/runner_preview_rc4/artifacts/heel_sim-1.3.0rc4-py3-none-any.whl": "715b12f41cbff5395e6d95608da56c9def274c45",
    "tests/fixtures/runner_preview_rc4/artifacts/heel_sim-1.3.0rc4.tar.gz": "77024cfb3973df888074b3c9bde0ff940f521761",
    "tests/fixtures/runner_preview_rc4/provenance.json": "38fd0d045e2dc9585ddaf685544e14473788886c",
    "tests/fixtures/runner_preview_rc4/version_sources/__init__.py.txt": "dc5cb23483f19113d42f030e90f23a060c473369",
    "tests/fixtures/runner_preview_rc4/version_sources/build_open_core_release.py.txt": "13e36cf0baf97b03833582020b70b914cbf3cbe7",
    "tests/fixtures/runner_preview_rc4/version_sources/open-core-v1.json.txt": "41254a0b0275b8503a3897aaa4f51961ff6cfa49",
    "tests/fixtures/runner_preview_rc4/version_sources/pyproject.toml.txt": "2271c9055df7e92016b7a813cbd8b26e94e2f2ec",
}
INSTALL_REQUIRED = os.environ.get("HEEL_REQUIRE_RUNNER_EXTRA_INSTALL") == "1"
# A synthetic credential: it has no real-token prefix and only proves non-reflection.
TOKEN = "heelfaketoken_" + "Q7" * 15
REPO = "/repos/ancilis/heel"
CDN = "objects.githubusercontent.com"


def _load():
    spec = importlib.util.spec_from_file_location("heel_preview_publisher_rc5_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = _load()
_real_git = P._git
NAMES = P.ASSET_NAMES


def final_pins(test: unittest.TestCase) -> None:
    """Let the reused rc2 flows run against the pinned bytes; InterimPinTests covers the refusal."""
    patcher = mock.patch.object(P, "PIN_STATUS", "FINAL")
    patcher.start()
    test.addCleanup(patcher.stop)


class PinnedCandidateError(Exception):
    pass


def _git_blob_id(payload: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(payload) + payload).hexdigest()


def load_pinned_rc5(directory: Path = ROOT) -> tuple[dict[str, bytes], dict[str, bytes]]:
    """The pinned rc5 artifacts by asset name and version sources by path, each pinned by blob id.

    A mismatch is a hard failure, never a skip: it means this checkout no longer carries the pinned
    rc5 candidate (see the module docstring).
    """
    try:
        downloads = directory / DOWNLOADS
        if sorted(os.listdir(downloads)) != sorted(P.ASSET_NAMES):
            raise PinnedCandidateError("downloads are not exactly the pinned rc5 wheel, sdist and manifest")
        loaded = {}
        for source in [f"{DOWNLOADS}/{name}" for name in P.ASSET_NAMES] + list(P.VERSION_SOURCES):
            path = directory / source
            if path.is_symlink() or not path.is_file():
                raise PinnedCandidateError(f"{source} is not a regular file")
            payload = path.read_bytes()
            if _git_blob_id(payload) != PINNED_BLOBS[source]:
                raise PinnedCandidateError(f"{source} is not the pinned rc5 blob")
            loaded[source] = payload
        for name in P.ASSET_NAMES:
            payload = loaded[f"{DOWNLOADS}/{name}"]
            if (hashlib.sha256(payload).hexdigest(), len(payload)) != (ACCEPTED_SHA256[name], ACCEPTED_SIZES[name]):
                raise PinnedCandidateError(f"{name} digest or size is not the pinned rc5 value")
    except (OSError, KeyError) as error:
        raise PinnedCandidateError(f"pinned rc5 candidate unreadable ({type(error).__name__})") from None
    artifacts = {name: loaded[f"{DOWNLOADS}/{name}"] for name in P.ASSET_NAMES}
    return artifacts, {source: loaded[source] for source in P.VERSION_SOURCES}


CANDIDATE, CANDIDATE_SOURCES = load_pinned_rc5()
MANIFEST_SHA = hashlib.sha256(CANDIDATE[P.MANIFEST]).hexdigest()


def canonical_manifest(artifacts: dict[str, bytes], version: str = None) -> bytes:
    document = {
        "artifacts": sorted(({"name": name, "sha256": hashlib.sha256(artifacts[name]).hexdigest(),
                              "size": len(artifacts[name])} for name in (P.WHEEL, P.SDIST)),
                            key=lambda record: record["name"]),
        "schema_version": P.MANIFEST_SCHEMA,
        "version": version or P.VERSION,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def canonical_but_unaccepted() -> dict[str, bytes]:
    """A valid rc5-named wheel (same METADATA, new zip comment) with its own canonical manifest.

    Every rc1-style check accepts it; only the pinned-digest binding refuses it.
    """
    buffer = io.BytesIO(CANDIDATE[P.WHEEL])
    with zipfile.ZipFile(buffer, "a") as archive:
        archive.comment = b"not the pinned 1.3.0rc5 wheel"
    artifacts = {P.WHEEL: buffer.getvalue(), P.SDIST: CANDIDATE[P.SDIST]}
    artifacts[P.MANIFEST] = canonical_manifest(artifacts)
    return {name: artifacts[name] for name in P.ASSET_NAMES}


class FakeGitHub:
    """Release state plus fault knobs, served for api/uploads/github.com and one CDN host."""

    def __init__(self, sha: str):
        self.sha = sha
        self.lock = threading.Lock()
        self.requests: list[dict] = []
        self.page_size = 100
        self.tag_ref = {"ref": f"refs/tags/{P.TAG}", "object": {"type": "commit", "sha": sha}}
        self.tag_objects: dict[str, dict] = {}
        self.ref_reads = 0
        self.move_tag_after_reads: int | None = None
        self.releases: list[dict] = []
        self.assets: dict[int, list[dict]] = {}
        self.next_id = 7000
        self.faults: dict[str, object] = {}
        self.cdn_override: dict[str, bytes] = {}
        # Provider model: a release create/update recreates a missing tag from target_commitish,
        # falling back to the default branch when it is omitted (GitHub Releases REST docs).
        self.default_branch_sha = "d" * 40
        self.implicit_tags: list[str] = []
        # Another privileged writer acting between the tool's requests: "before POST",
        # "before PATCH" and "after PATCH" callbacks, run under the lock.
        self.hooks: dict[str, object] = {}
        self.patched = False

    # -- state helpers -------------------------------------------------------------------------
    def release_record(self, release: dict) -> dict:
        record = {key: value for key, value in release.items() if not key.startswith("_")}
        record["assets"] = [self.asset_record(release, asset) for asset in self.assets[release["id"]]]
        return record

    def asset_record(self, release: dict, asset: dict) -> dict:
        tag = P.TAG if not release["draft"] else "untagged-0123456789abcdef"
        record = {
            "id": asset["id"], "name": asset["name"], "size": len(asset["_bytes"]),
            "state": asset.get("state", "uploaded"),
            "url": f"https://api.github.com{REPO}/releases/assets/{asset['id']}",
            "browser_download_url": f"https://github.com/ancilis/heel/releases/download/{tag}/{asset['name']}",
            "digest": "sha256:" + hashlib.sha256(asset["_bytes"]).hexdigest(),
        }
        record.update(asset.get("_override", {}))
        return record

    def seed_release(self, *, draft=True, prerelease=True, assets=(), sha=None, body=None,
                     tag=None, title=None, payloads=None):
        manifest = (payloads or CANDIDATE)[P.MANIFEST]
        release_id = self.next_id
        self.next_id += 1
        release = {
            "id": release_id, "url": f"https://api.github.com{REPO}/releases/{release_id}",
            "upload_url": f"https://uploads.github.com{REPO}/releases/{release_id}/assets{{?name,label}}",
            "tag_name": tag or P.TAG, "target_commitish": sha or self.sha,
            "name": title or P.TITLE,
            "body": body if body is not None else P.render_release_notes(sha or self.sha, manifest),
            "draft": draft, "prerelease": prerelease,
        }
        self.releases.append(release)
        self.assets[release_id] = []
        for name in assets:
            self.add_asset(release_id, name, (payloads or CANDIDATE)[name])
        return release

    def add_asset(self, release_id: int, name: str, payload: bytes, **extra) -> dict:
        asset = {"id": self.next_id, "name": name, "_bytes": payload, **extra}
        self.next_id += 1
        self.assets[release_id].append(asset)
        return asset

    def candidate(self):
        found = [release for release in self.releases if release["tag_name"] == P.TAG]
        return found[0] if found else None

    def methods(self, method: str, prefix: str = "") -> list[dict]:
        return [r for r in self.requests if r["method"] == method and r["path"].startswith(prefix)]

    def run_hook(self, name: str) -> None:
        hook = self.hooks.get(name)
        if hook:
            hook(self)

    def recreate_missing_tag(self, commitish) -> None:
        if self.tag_ref is not None:
            return
        sha = commitish if isinstance(commitish, str) and re.fullmatch(r"[0-9a-f]{40}", commitish) \
            else self.default_branch_sha
        self.tag_ref = {"ref": f"refs/tags/{P.TAG}", "object": {"type": "commit", "sha": sha}}
        self.implicit_tags.append(sha)

    def replace_asset(self, name: str, payload: bytes, **extra) -> None:
        """Delete-and-re-upload by another writer: same name, new id, new bytes."""
        release = self.candidate()
        self.assets[release["id"]] = [a for a in self.assets[release["id"]] if a["name"] != name]
        self.add_asset(release["id"], name, payload, **extra)


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *arguments):
        pass

    def _send(self, status, payload=b"", headers=()):
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload).encode()
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def _drop(self):
        self.close_connection = True

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PATCH(self):
        self._route("PATCH")

    def do_DELETE(self):
        self._route("DELETE")

    def do_PUT(self):
        self._route("PUT")

    def _route(self, method):
        github: FakeGitHub = self.server.github
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        parts = urlsplit(self.path)
        host = self.headers.get("Host")
        query = {key: values[0] for key, values in parse_qs(parts.query).items()}
        with github.lock:
            github.requests.append({
                "host": host, "method": method, "path": parts.path, "query": query,
                "authorization": self.headers.get("Authorization"), "body": body,
            })
            authorized = self.headers.get("Authorization") == f"Bearer {TOKEN}"
            if github.faults.get("secret_error") and method == "GET" and parts.path == f"{REPO}/releases":
                return self._send(500, {"message": f"boom {TOKEN} {self.headers.get('Authorization')}"},
                                  [("X-Echo", TOKEN)])
            if host == "api.github.com":
                return self._api(method, parts.path, query, body, authorized)
            if host == "uploads.github.com":
                return self._upload(method, parts.path, query, body, authorized)
            if host == "github.com":
                return self._web(method, parts.path)
            if host == CDN:
                return self._cdn(parts.path)
            return self._send(421)

    def _page(self, items, query):
        github = self.server.github
        page = int(query.get("page", "1"))
        size = min(int(query.get("per_page", "30")), github.page_size)
        chunk = items[(page - 1) * size: page * size]
        headers = []
        if page * size < len(items):
            headers.append(("Link", f'<https://api.github.com/repositories/1/x?page={page + 1}>; rel="next"'))
        return self._send(200, chunk, headers)

    def _api(self, method, path, query, body, authorized):
        github = self.server.github
        if path == f"{REPO}/git/ref/tags/{P.TAG}" and method == "GET":
            github.ref_reads += 1
            if github.tag_ref is None:
                return self._send(404, {"message": "Not Found"})
            ref = json.loads(json.dumps(github.tag_ref))
            if github.move_tag_after_reads is not None and github.ref_reads > github.move_tag_after_reads:
                ref["object"] = {"type": "commit", "sha": "e" * 40}
            return self._send(200, ref)
        match = re.fullmatch(rf"{REPO}/git/tags/([0-9a-f]{{40}})", path)
        if match and method == "GET":
            tag = github.tag_objects.get(match.group(1))
            return self._send(200, tag) if tag else self._send(404, {"message": "Not Found"})
        if path == f"{REPO}/releases" and method == "GET":
            visible = [github.release_record(r) for r in github.releases if authorized or not r["draft"]]
            return self._page(visible, query)
        if path == f"{REPO}/releases" and method == "POST":
            if not authorized:
                return self._send(401)
            document = json.loads(body)
            github.run_hook("before POST")
            if github.faults.get("drop_create_nocommit"):
                return self._drop()
            github.recreate_missing_tag(document.get("target_commitish"))
            release = github.seed_release(draft=document["draft"], prerelease=document["prerelease"],
                                          sha=document["target_commitish"], body=document["body"],
                                          title=document["name"], tag=document["tag_name"])
            if github.faults.get("drop_create_commit"):
                return self._drop()
            return self._send(201, github.release_record(release))
        if path == f"{REPO}/releases/tags/{P.TAG}" and method == "GET":
            published = [r for r in github.releases if r["tag_name"] == P.TAG and not r["draft"]]
            return self._send(200, github.release_record(published[0])) if published else self._send(404)
        match = re.fullmatch(rf"{REPO}/releases/(\d+)", path)
        if match:
            release = next((r for r in github.releases if r["id"] == int(match.group(1))), None)
            if release is None or (release["draft"] and not authorized):
                return self._send(404)
            if method == "GET":
                reread = github.faults.get("reread_after_patch") if github.patched else None
                if reread == "500":
                    return self._send(500, {"message": "unavailable"})
                if reread == "drop":
                    return self._drop()
                if reread == "other":
                    return self._send(200, {**github.release_record(release), "id": release["id"] + 1,
                                            "url": f"https://api.github.com{REPO}/releases/{release['id'] + 1}"})
                if reread == "malformed":
                    return self._send(200, {**github.release_record(release), "draft": "false"})
                return self._send(200, github.release_record(release))
            if method == "PATCH":
                if not authorized:
                    return self._send(401)
                document = json.loads(body)
                github.run_hook("before PATCH")
                if github.faults.get("drop_patch_nocommit"):
                    return self._drop()
                github.recreate_missing_tag(document.get("target_commitish"))
                if not github.faults.get("patch_keeps_draft"):
                    release.update(document)
                release.pop("make_latest", None)
                github.patched = True
                github.run_hook("after PATCH")
                if github.faults.get("drop_patch_commit"):
                    return self._drop()
                record = github.release_record(release)
                if github.faults.get("patch_response_other_target"):
                    record["target_commitish"] = "main"
                # The acknowledgement alone conflicts; the stored release a re-read returns does not.
                record.update(github.faults.get("patch_response_override") or {})
                return self._send(200, record)
            return self._send(405)
        match = re.fullmatch(rf"{REPO}/releases/(\d+)/assets", path)
        if match and method == "GET":
            if github.patched and github.faults.get("asset_list_after_patch") == "500":
                return self._send(500, {"message": "unavailable"})
            release = next(r for r in github.releases if r["id"] == int(match.group(1)))
            return self._page([github.asset_record(release, a) for a in github.assets[release["id"]]], query)
        match = re.fullmatch(rf"{REPO}/releases/assets/(\d+)", path)
        if match and method == "GET":
            if not authorized:
                return self._send(404)
            location = github.faults.get("asset_location") or f"https://{CDN}/blob/{match.group(1)}?sig=s"
            return self._send(302, b"", [("Location", location)])
        return self._send(404, {"message": "Not Found"})

    def _upload(self, method, path, query, body, authorized):
        github = self.server.github
        match = re.fullmatch(rf"{REPO}/releases/(\d+)/assets", path)
        if not (match and method == "POST" and authorized):
            return self._send(404)
        release_id = int(match.group(1))
        name = query["name"]
        if any(asset["name"] == name for asset in github.assets[release_id]):
            return self._send(422, {"message": "already_exists"})
        if github.faults.get("drop_upload_nocommit") == name:
            return self._drop()
        asset = github.add_asset(release_id, name, body)
        if github.faults.get("drop_upload_commit") == name:
            return self._drop()
        release = next(r for r in github.releases if r["id"] == release_id)
        return self._send(201, github.asset_record(release, asset))

    def _web(self, method, path):
        github = self.server.github
        match = re.fullmatch(rf"/ancilis/heel/releases/download/{re.escape(P.TAG)}/(.+)", path)
        release = next((r for r in github.releases if r["tag_name"] == P.TAG and not r["draft"]), None)
        if not match or method != "GET" or release is None:
            return self._send(404)
        asset = next((a for a in github.assets[release["id"]] if a["name"] == match.group(1)), None)
        if asset is None:
            return self._send(404)
        location = github.faults.get("public_location") or f"https://{CDN}/blob/{asset['id']}?sig=p"
        return self._send(302, b"", [("Location", location)])

    def _cdn(self, path):
        github = self.server.github
        failure = github.faults.get("cdn_after_patch") if github.patched else None
        if failure == "500":
            return self._send(500)
        if failure == "drop":
            return self._drop()
        match = re.fullmatch(r"/blob/(\d+)", path)
        for assets in github.assets.values():
            for asset in assets:
                if match and asset["id"] == int(match.group(1)):
                    return self._send(200, github.cdn_override.get(asset["name"], asset["_bytes"]))
        return self._send(404)


class LoopbackTransport:
    """Sends real HTTP bytes to the fake server; the logical host travels in the Host header."""

    HOSTS = frozenset({"api.github.com", "uploads.github.com", "github.com", CDN})

    def __init__(self, port: int, github: FakeGitHub):
        self.port = port
        self.github = github
        self.sent: list[tuple[str, str, str, dict]] = []

    def send(self, host, method, target, headers, body, limit):
        self.sent.append((host, method, target, dict(headers)))
        if host not in self.HOSTS:
            raise P.TransportError("unroutable test host")
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        return P._exchange(connection, method, target, {**headers, "Host": host}, body, limit)



def _git(cwd: Path, *arguments: str) -> str:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(cwd),
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    }
    return subprocess.run(["git", *arguments], cwd=cwd, env=environment, check=True,
                          capture_output=True, text=True).stdout


class FixtureCheckout:
    """A temporary git checkout holding only the pinned rc5 version sources and artifacts."""

    def __init__(self, temporary: Path, *, artifacts=None, pyproject_version=None):
        self.root = temporary / "checkout"
        for relative, payload in CANDIDATE_SOURCES.items():
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        if pyproject_version:
            path = self.root / "pyproject.toml"
            path.write_text(path.read_text().replace(f'version = "{P.VERSION}"',
                                                     f'version = "{pyproject_version}"', 1))
        downloads = self.root / P.DOWNLOADS
        downloads.mkdir(parents=True)
        for name, payload in (artifacts or CANDIDATE).items():
            (downloads / name).write_bytes(payload)
        _git(self.root, "init", "-q")
        self.commit()

    def commit(self) -> str:
        _git(self.root, "add", "-A")
        _git(self.root, "commit", "-q", "--no-verify", "-m", "fixture")
        self.sha = _git(self.root, "rev-parse", "HEAD").strip()
        return self.sha


class PinnedLoaderTests(unittest.TestCase):
    """The candidate is the pinned rc5 bytes this checkout carries, loaded offline."""

    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp(prefix="heel-publisher-rc5-pinned-")).resolve()
        self.addCleanup(shutil.rmtree, self.temporary, ignore_errors=True)

    def copy(self, name="pinned") -> Path:
        target = self.temporary / name
        for relative, payload in {**{f"{DOWNLOADS}/{n}": p for n, p in CANDIDATE.items()},
                                  **CANDIDATE_SOURCES}.items():
            path = target / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        return target

    def test_candidate_is_the_pinned_rc5_identity_the_publisher_names(self):
        self.assertEqual(P.VERSION, "1.3.0rc5")
        self.assertEqual(tuple(CANDIDATE), P.ASSET_NAMES)
        self.assertEqual(tuple(CANDIDATE_SOURCES), P.VERSION_SOURCES)
        checkout = FixtureCheckout(self.temporary)
        self.assertEqual(P._committed_versions(checkout.root, checkout.sha),
                         dict.fromkeys(P.VERSION_SOURCES, P.VERSION))
        manifest = P.verify_artifact_set(CANDIDATE)
        self.assertEqual(manifest["version"], P.VERSION)

    def test_loader_needs_no_git_history_network_or_subprocess(self):
        copied = self.copy()

        def refused(*arguments, **keywords):
            raise AssertionError("the pinned candidate loader must not spawn or connect")

        with mock.patch.object(subprocess, "run", refused), \
                mock.patch.object(subprocess, "Popen", refused), \
                mock.patch.object(socket, "socket", refused):
            self.assertEqual(load_pinned_rc5(copied), (CANDIDATE, CANDIDATE_SOURCES))

    def test_loader_rejects_missing_altered_relabelled_or_extra_bytes(self):
        downloads = Path(DOWNLOADS)

        def flip_sdist_byte(directory):
            path = directory / downloads / P.SDIST
            payload = bytearray(path.read_bytes())
            payload[100] ^= 1
            path.write_bytes(bytes(payload))

        def symlink_manifest(directory):
            path = directory / downloads / P.MANIFEST
            outside = self.temporary / "outside.json"
            outside.write_bytes(path.read_bytes())
            path.unlink()
            path.symlink_to(outside)

        def canonical_but_wrong(directory):
            for name, payload in canonical_but_unaccepted().items():
                (directory / downloads / name).write_bytes(payload)

        def relabel_pyproject(directory):
            path = directory / "pyproject.toml"
            path.write_bytes(path.read_bytes().replace(b'version = "1.3.0rc5"', b'version = "1.3.0rc6"', 1))

        mutations = {
            "missing wheel": lambda d: (d / downloads / P.WHEEL).unlink(),
            "altered sdist": flip_sdist_byte,
            "extra download": lambda d: (d / downloads / "notes.txt").write_bytes(b"x"),
            "symlinked manifest": symlink_manifest,
            "canonical but unpinned bytes": canonical_but_wrong,
            "truncated version source": lambda d: (d / "heel/__init__.py").write_bytes(b""),
            "relabelled version source": relabel_pyproject,
            "missing version source": lambda d: (d / "release/open-core-v1.json").unlink(),
        }
        for index, (label, mutate) in enumerate(mutations.items()):
            with self.subTest(label):
                copied = self.copy(f"pinned-{index}")
                mutate(copied)
                with self.assertRaises(PinnedCandidateError):
                    load_pinned_rc5(copied)


class PublisherHarness(unittest.TestCase):
    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp(prefix="heel-publisher-test-")).resolve()
        self.addCleanup(shutil.rmtree, self.temporary, ignore_errors=True)
        self.assertFalse(self.temporary.is_relative_to(ROOT))
        final_pins(self)
        self.checkout = FixtureCheckout(self.temporary)
        self.github = FakeGitHub(self.checkout.sha)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.github = self.github
        self.server.daemon_threads = True
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.transport = LoopbackTransport(self.server.server_address[1], self.github)
        self.token_calls = 0
        self.gate_calls = 0
        self.spawned: list[tuple[str, str]] = []
        self.spawn_result = 0
        self.proof_calls: list[Path] = []

    def token(self):
        self.token_calls += 1
        return TOKEN

    def gate(self, root):
        self.gate_calls += 1
        return ["fixture gate"]

    def proof(self, acquisition, work):
        self.proof_calls.append(acquisition)
        return {"scope": "packaging and synthetic reference only"}

    def spawn(self, sha, manifest_sha256, reporter):
        self.spawned.append((sha, manifest_sha256))
        return self.spawn_result

    def run_tool(self, mode, *, sha=None, extra=(), gate=None, proof=None):
        argv = [mode, "--repository", "ancilis/heel", "--tag", P.TAG,
                "--expected-sha", sha or self.checkout.sha, *extra]
        if mode == "verify-public" and "--expected-manifest-sha256" not in extra:
            argv += ["--expected-manifest-sha256", MANIFEST_SHA]
        err, out = io.StringIO(), io.StringIO()
        code = P.main(argv, transport=self.transport, token_provider=self.token,
                      gate_runner=gate or self.gate, proof_runner=proof or self.proof,
                      spawn_verify=self.spawn, root=self.checkout.root,
                      reporter=P.Reporter(err), stdout=out)
        self.last_err, self.last_out = err.getvalue(), out.getvalue()
        self.assertNotIn(TOKEN, self.last_err + self.last_out)
        return code

    def assert_no_destructive_requests(self):
        self.assertEqual(self.github.methods("DELETE"), [])
        self.assertEqual(self.github.methods("PUT"), [])
        for request in self.github.requests:
            if request["authorization"] is not None:
                self.assertIn(request["host"], ("api.github.com", "uploads.github.com"), request)
        uploads = [r["query"]["name"] for r in self.github.requests if r["host"] == "uploads.github.com"]
        self.assertEqual(len(uploads), len(set(uploads)), "an asset upload was repeated")

    def assert_no_mutation(self):
        self.assertEqual([r for r in self.github.requests if r["method"] != "GET"], [])

    def assert_no_git_ref_request_except_reads(self):
        git = [r for r in self.github.requests if "/git/" in r["path"]]
        self.assertTrue(git)
        self.assertTrue(all(r["method"] == "GET" for r in git), git)

    def requests_after_patch(self) -> list[dict]:
        index = next(i for i, r in enumerate(self.github.requests) if r["method"] == "PATCH")
        return self.github.requests[index + 1:]


class ImportAndCommandLineTests(unittest.TestCase):
    def setUp(self):
        final_pins(self)

    def test_import_help_and_default_invocation_have_no_side_effects(self):
        forbidden = mock.Mock(side_effect=AssertionError("side effect"))
        with mock.patch("subprocess.run", forbidden), mock.patch("subprocess.Popen", forbidden), \
                mock.patch("socket.create_connection", forbidden), \
                mock.patch("http.client.HTTPSConnection", forbidden):
            module = _load()
            with mock.patch("sys.stderr", io.StringIO()) as stderr:
                self.assertEqual(module.main([]), 2)
            self.assertIn("stage-draft", stderr.getvalue())
            with mock.patch("sys.stdout", io.StringIO()) as stdout, self.assertRaises(SystemExit) as exit_:
                module.main(["--help"])
            self.assertEqual(exit_.exception.code, 0)
            self.assertIn("verify-public", stdout.getvalue())
        forbidden.assert_not_called()

    def test_help_runs_as_an_isolated_script(self):
        result = subprocess.run([sys.executable, "-I", str(SCRIPT), "--help"], capture_output=True,
                                text=True, timeout=60, cwd=tempfile.gettempdir())
        self.assertEqual(result.returncode, 0, result.stderr)
        for mode in ("stage-draft", "publish-and-verify", "verify-public"):
            self.assertIn(mode, result.stdout)
        self.assertNotIn("--api", result.stdout)

    def test_cli_has_no_host_override_and_rejects_noncanonical_identity(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for option in re.findall(r'add_argument\("(--[a-z0-9-]+)"', source):
            self.assertIn(option, {"--repository", "--tag", "--expected-sha", "--expected-manifest-sha256"})
        forbidden = mock.Mock(side_effect=AssertionError("network or token use"))
        for argv in (
            ["stage-draft", "--repository", "other/heel", "--tag", P.TAG, "--expected-sha", "a" * 40],
            ["stage-draft", "--repository", "ancilis/heel", "--tag", "v1.3.0", "--expected-sha", "a" * 40],
            ["stage-draft", "--repository", "ancilis/heel", "--tag", P.TAG, "--expected-sha", "HEAD"],
            ["publish-and-verify", "--repository", "ancilis/heel", "--tag", P.TAG, "--expected-sha", "A" * 40],
            ["verify-public", "--repository", "ancilis/heel", "--tag", P.TAG, "--expected-sha", "a" * 40,
             "--expected-manifest-sha256", "zz"],
        ):
            with self.subTest(argv=argv):
                code = P.main(argv, transport=mock.Mock(send=forbidden), token_provider=forbidden,
                              gate_runner=forbidden, reporter=P.Reporter(io.StringIO()))
                self.assertEqual(code, P.EXIT_REFUSED)
        forbidden.assert_not_called()

    def test_source_has_no_delete_replace_or_stable_conversion_primitive(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for needle in ('"DELETE"', '"PUT"', '"prerelease": False', "git push", "--force", '"draft": True, "prerelease": False'):
            self.assertNotIn(needle, source)
        methods = set(re.findall(r'"(GET|POST|PATCH|PUT|DELETE)"', source))
        self.assertEqual(methods, {"GET", "POST", "PATCH"})

    def test_tag_claims_are_precise_and_no_git_ref_write_is_possible(self):
        source = SCRIPT.read_text(encoding="utf-8")
        runbook = RUNBOOK.read_text(encoding="utf-8")
        for text in (source, runbook):
            self.assertNotIn("never creates, moves or pushes a tag", text)
            self.assertNotIn("never creates, moves, forces or pushes a tag", text)
            self.assertNotIn("always the exact `SHA`", text)
        self.assertIn("a release request can recreate it", source)
        self.assertIn("can recreate the tag", runbook)
        sent = []
        transport = mock.Mock(send=lambda *a: sent.append(a) or P.Response(200, [], b"{}"))
        client = P.GitHubClient(transport, TOKEN, P.Reporter(io.StringIO()))
        for method, host, path in (
            ("POST", P.API_HOST, f"{REPO}/git/refs"),
            ("PATCH", P.API_HOST, f"{REPO}/git/refs/tags/{P.TAG}"),
            ("PATCH", P.API_HOST, f"{REPO}/git/ref/tags/{P.TAG}"),
            ("POST", P.API_HOST, f"{REPO}/git/tags"),
            ("POST", P.API_HOST, f"{REPO}/releases/7000"),
            ("PATCH", P.API_HOST, f"{REPO}/releases"),
            ("GET", P.UPLOAD_HOST, f"{REPO}/releases/7000/assets"),
        ):
            with self.subTest(method=method, path=path), self.assertRaises(P.VerificationFailed):
                client._send(host, method, path, body=b"{}")
        self.assertEqual(sent, [])
        client.get_json(f"{REPO}/git/ref/tags/{P.TAG}")
        self.assertEqual(len(sent), 1)

    def test_stable_only_pypi_workflow_condition_is_unchanged(self):
        workflow = (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
        self.assertIn("    types: [published]\n", workflow)
        self.assertIn(
            "    if: github.event.release.draft == false && github.event.release.prerelease == false\n",
            workflow,
        )

    def test_release_notes_hold_only_verified_metadata_and_limitations(self):
        notes = P.render_release_notes("c" * 40, CANDIDATE[P.MANIFEST])
        self.assertTrue(notes.isascii())
        self.assertIn("Heel runner preview 1.3.0rc5", notes)
        self.assertNotIn("Heel runner preview 1.3.0rc4", notes)
        self.assertIn("prerelease", notes)
        install = ("`python -m pip --isolated install 'heel-sim[runner] @ https://github.com/ancilis/heel"
                   "/releases/download/v1.3.0rc5/heel_sim-1.3.0rc5-py3-none-any.whl"
                   f"#sha256={ACCEPTED_SHA256['heel_sim-1.3.0rc5-py3-none-any.whl']}'`")
        self.assertIn(install, notes)
        self.assertIn("`cryptography==50.0.1`", notes)
        self.assertIn("Intel macOS is not supported by this preview's runner dependency", notes)
        self.assertIn("Python 3.11 or newer", notes)
        self.assertIn("Adds local runner changes over 1.3.0rc4: a staged disclosure poll or findings upload "
                      "that Heel Cloud refuses with `invalid_runner_auth` is recovered", notes)
        self.assertIn("retired only on the server's cursor proof, and nothing is re-signed inside recovery", notes)
        self.assertIn("A staged upload whose human permit has expired is recovered metadata-only", notes)
        self.assertIn("an upload consumed without a receipt stays parked and fails closed", notes)
        self.assertIn("These changes are proven only with local test fixtures.", notes)
        # The markerless key-path result stays medium confidence and distinct from the canary-marker state.
        self.assertIn("the paired `plan_entitlement_read` key-path finding is medium confidence and values are "
                      "not compared, error envelopes are `inconclusive`, and the unsigned `evidence_states` "
                      "list keeps that `observed` state separate from the canary-marker state.", notes)
        self.assertNotIn("sends a metadata-only disclosure poll (digest", notes)
        self.assertNotIn("high-confidence key-path", notes)
        self.assertNotIn("`runner prepare --live` queues", notes)
        self.assertNotIn("Corrects two 1.3.0rc1", notes)
        self.assertIn("not published to PyPI", notes)
        self.assertIn("c" * 40, notes)
        for name, payload in CANDIDATE.items():
            self.assertIn(f"| `{name}` | {len(payload)} | `{hashlib.sha256(payload).hexdigest()}` |", notes)
        for claim in ("pairing", "heel runner serve", "HTTPS target traffic", "hosted findings", "launch readiness"):
            self.assertIn(claim, notes)
        self.assertNotIn("verified", notes.lower())
        # The only URL is the pinned public wheel location; nothing else links out.
        self.assertNotIn("http", notes.replace("HTTPS target traffic", "").replace(install, ""))
        self.assertNotIn(TOKEN, notes)
        # The manifest is the artifact; rendering external metadata leaves its bytes unchanged.
        self.assertEqual((ROOT / DOWNLOADS / P.MANIFEST).read_bytes(), CANDIDATE[P.MANIFEST])

    def test_default_credential_source_is_gh_without_token_in_argv(self):
        completed = subprocess.CompletedProcess([], 0, stdout=TOKEN + "\n", stderr="")
        with mock.patch.object(P.shutil, "which", return_value="/opt/gh"), \
                mock.patch.object(P.subprocess, "run", return_value=completed) as run:
            self.assertEqual(P.gh_token(), TOKEN)
        self.assertEqual(run.call_args.args[0], ["/opt/gh", "auth", "token", "--hostname", "github.com"])
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr=f"no login {TOKEN}")
        with mock.patch.object(P.shutil, "which", return_value="/opt/gh"), \
                mock.patch.object(P.subprocess, "run", return_value=failed):
            with self.assertRaises(P.Refused) as raised:
                P.gh_token()
        self.assertNotIn(TOKEN, str(raised.exception))
        with self.assertRaises(P.Refused):
            P.GitHubClient(mock.Mock(), "short token", P.Reporter(io.StringIO()))

    def test_default_local_gate_runs_the_builder_check_and_enforced_runner_tests(self):
        calls = []

        def fake_run(command, **keywords):
            calls.append((command, keywords))
            if "scripts/build_open_core_release.py" in command:
                return subprocess.CompletedProcess(command, 0, "open-core release artifacts are current\n", "")
            return subprocess.CompletedProcess(command, 0, "", self.runner_stderr)

        self.runner_stderr = "test_a ... ok\n\n" + "-" * 70 + "\nRan 5 tests in 9.0s\n\nOK\n"
        with mock.patch.object(P.subprocess, "run", side_effect=fake_run), \
                mock.patch.dict(os.environ, {"GH_TOKEN": TOKEN, "GITHUB_TOKEN": TOKEN}):
            checks = P.run_local_release_checks(ROOT)
        self.assertEqual(checks[1], "tests.test_public_runner_preview_release (5 tests, 0 skipped)")
        builder, runner = calls
        self.assertEqual(builder[0][1:], ["-I", "scripts/build_open_core_release.py", "--output",
                                          "apps/heel-cloud/public/downloads", "--check"])
        self.assertEqual(runner[0][1:], ["-m", "unittest", "-v", "tests.test_public_runner_preview_release"])
        self.assertEqual(runner[1]["env"]["HEEL_REQUIRE_RUNNER_EXTRA_INSTALL"], "1")
        for _, keywords in calls:
            self.assertNotIn("GH_TOKEN", keywords["env"])
            self.assertNotIn("GITHUB_TOKEN", keywords["env"])
        for stderr in ("Ran 5 tests in 1s\n\nOK (skipped=1)\n", "Ran 4 tests in 1s\n\nOK\n",
                       "Ran 5 tests in 1s\n\nFAILED (failures=1)\n", ""):
            with self.subTest(stderr=stderr):
                calls.clear()
                self.runner_stderr = stderr
                with mock.patch.object(P.subprocess, "run", side_effect=fake_run), \
                        self.assertRaises(P.Refused):
                    P.run_local_release_checks(ROOT)
        with mock.patch.object(P.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, "stale\n", "")), \
                self.assertRaises(P.Refused):
            P.run_local_release_checks(ROOT)

    def test_scrubbed_environments_drop_inherited_github_and_python_configuration(self):
        hostile = {"GH_TOKEN": TOKEN, "GITHUB_TOKEN": TOKEN, "PYTHONPATH": str(ROOT),
                   "PIP_INDEX_URL": "https://user:pw@example.invalid/simple", "NETRC": "/x/.netrc",
                   "GIT_ASKPASS": "/x/askpass", "HOME": str(Path.home())}
        with tempfile.TemporaryDirectory() as work, mock.patch.dict(os.environ, hostile):
            environment = P.scrubbed_environment(Path(work))
            child = P._child_environment()
            for value in environment.values():
                self.assertNotIn(TOKEN, value)
            self.assertTrue(Path(environment["HOME"]).is_relative_to(Path(work)))
            self.assertEqual(environment["NETRC"], os.devnull)
            self.assertEqual(environment["PIP_CONFIG_FILE"], os.devnull)
            self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
            for key in ("GH_TOKEN", "GITHUB_TOKEN", "PYTHONPATH", "PIP_INDEX_URL", "GIT_ASKPASS"):
                self.assertNotIn(key, environment)
            for key in ("GH_TOKEN", "GITHUB_TOKEN", "PYTHONPATH"):
                self.assertNotIn(key, child)

    def test_publish_spawns_verify_public_without_credentials_outside_the_checkout(self):
        with mock.patch.object(P.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0)) as run, \
                mock.patch.dict(os.environ, {"GH_TOKEN": TOKEN, "GITHUB_TOKEN": TOKEN}):
            self.assertEqual(P.spawn_verify_public("d" * 40, "e" * 64, P.Reporter(io.StringIO())), 0)
        command, keywords = run.call_args.args[0], run.call_args.kwargs
        self.assertEqual(command[1:4], ["-I", str(SCRIPT), "verify-public"])
        self.assertNotIn(TOKEN, " ".join(command))
        self.assertFalse(Path(keywords["cwd"]).resolve().is_relative_to(ROOT))
        self.assertNotIn(TOKEN, json.dumps(keywords["env"]))
        self.assertFalse({"GH_TOKEN", "GITHUB_TOKEN"} & set(keywords["env"]))
        shutil.rmtree(keywords["cwd"], ignore_errors=True)


class LocalCandidateGateTests(PublisherHarness):
    def assert_refused_before_any_remote_call(self, code):
        self.assertEqual(code, P.EXIT_REFUSED, self.last_err)
        self.assertEqual(self.github.requests, [])
        self.assertEqual(self.transport.sent, [])
        self.assertEqual(self.token_calls, 0)

    def test_wrong_source_commit_is_refused(self):
        self.assert_refused_before_any_remote_call(self.run_tool("stage-draft", sha="0" * 40))
        self.assertIn("HEAD is not the expected source commit", self.last_err)

    def test_dirty_tracked_or_untracked_checkout_is_refused(self):
        (self.checkout.root / "untracked.txt").write_text("x")
        self.assert_refused_before_any_remote_call(self.run_tool("stage-draft"))
        (self.checkout.root / "untracked.txt").unlink()
        with (self.checkout.root / "pyproject.toml").open("a") as handle:
            handle.write("\n")
        self.assert_refused_before_any_remote_call(self.run_tool("publish-and-verify"))
        self.assertIn("not clean", self.last_err)

    def test_malformed_or_noncanonical_manifest_is_refused(self):
        for payload in (b"{not json", json.dumps(json.loads(CANDIDATE[P.MANIFEST]), indent=1).encode()):
            with self.subTest(payload=payload[:10]):
                (self.checkout.root / P.DOWNLOADS / P.MANIFEST).write_bytes(payload)
                sha = self.checkout.commit()
                self.assert_refused_before_any_remote_call(self.run_tool("stage-draft", sha=sha))
                self.assertIn("manifest", self.last_err)

    def test_artifact_bytes_that_disagree_with_the_manifest_are_refused(self):
        wheel = bytearray(CANDIDATE[P.WHEEL])
        wheel[100] ^= 1
        (self.checkout.root / P.DOWNLOADS / P.WHEEL).write_bytes(bytes(wheel))
        sha = self.checkout.commit()
        self.assert_refused_before_any_remote_call(self.run_tool("stage-draft", sha=sha))

    def test_missing_or_extra_artifact_is_refused(self):
        downloads = self.checkout.root / P.DOWNLOADS
        (downloads / P.SDIST).unlink()
        sha = self.checkout.commit()
        self.assert_refused_before_any_remote_call(self.run_tool("stage-draft", sha=sha))
        (downloads / P.SDIST).write_bytes(CANDIDATE[P.SDIST])
        (downloads / "extra.whl").write_bytes(b"x")
        sha = self.checkout.commit()
        self.assert_refused_before_any_remote_call(self.run_tool("stage-draft", sha=sha))

    def test_symlinked_artifact_or_escaping_downloads_path_is_refused(self):
        downloads = self.checkout.root / P.DOWNLOADS
        outside = self.temporary / "outside"
        outside.mkdir()
        shutil.copyfile(downloads / P.SDIST, outside / P.SDIST)
        (downloads / P.SDIST).unlink()
        (downloads / P.SDIST).symlink_to(outside / P.SDIST)
        sha = self.checkout.commit()
        self.assert_refused_before_any_remote_call(self.run_tool("stage-draft", sha=sha))
        self.assertIn("regular", self.last_err)
        # Committed regular files, but the working downloads directory now escapes via a link.
        (downloads / P.SDIST).unlink()
        (downloads / P.SDIST).write_bytes(CANDIDATE[P.SDIST])
        sha = self.checkout.commit()
        for name in NAMES:
            shutil.copyfile(downloads / name, outside / name)
        public = downloads.parent
        shutil.move(str(downloads), str(self.temporary / "moved"))
        public.joinpath("downloads").symlink_to(outside, target_is_directory=True)
        self.assert_refused_before_any_remote_call(self.run_tool("stage-draft", sha=sha))
        # The same escape is refused by the path walk itself, independent of git status.
        with self.assertRaises(P.Refused) as raised, mock.patch.object(P, "_git", side_effect=lambda root, *a, binary=False: {
            "rev-parse": f"{root}\n" if a[1] == "--show-toplevel" else f"{sha}\n", "status": "",
        }.get(a[0]) if a[0] in ("rev-parse", "status") else _real_git(root, *a, binary=binary)):
            P.verify_local_candidate(self.checkout.root, sha, self.gate, P.Reporter(io.StringIO()))
        self.assertIn("downloads path leaves the checkout", str(raised.exception))

    def test_inconsistent_version_source_is_refused(self):
        (self.temporary / "v").mkdir()
        checkout = FixtureCheckout(self.temporary / "v", pyproject_version="1.3.0")
        self.checkout = checkout
        self.assert_refused_before_any_remote_call(self.run_tool("stage-draft", sha=checkout.sha))
        self.assertIn("version", self.last_err)

    def test_accepted_digest_mismatch_is_refused_before_any_credential_read(self):
        wrong = canonical_but_unaccepted()
        # Control: every rc1-style check accepts these bytes; only the pinned-digest binding refuses them.
        self.assertEqual(P.verify_artifact_set(wrong)["version"], P.VERSION)
        (self.temporary / "w").mkdir()
        self.checkout = FixtureCheckout(self.temporary / "w", artifacts=wrong)
        for mode in ("stage-draft", "publish-and-verify"):
            with self.subTest(mode):
                self.assert_refused_before_any_remote_call(self.run_tool(mode))
                self.assertIn(f"{P.WHEEL} is not the accepted 1.3.0rc5 artifact", self.last_err)
                self.assertEqual(self.gate_calls, 0)

    def test_local_release_check_failure_is_refused(self):
        def failing(root):
            raise P.Refused("local gate failed: open-core builder --check")

        self.assert_refused_before_any_remote_call(self.run_tool("stage-draft", gate=failing))
        self.assertIn("builder --check", self.last_err)


class RemoteTagTests(PublisherHarness):
    def annotated(self, sha, *, tag=None, object_type="commit", target=None):
        self.github.tag_objects[sha] = {"sha": sha, "tag": tag or P.TAG,
                                        "object": {"type": object_type, "sha": target or self.checkout.sha}}

    def test_lightweight_and_annotated_tags_resolve_to_the_source(self):
        self.assertEqual(P.verify_remote_tag(P.AnonymousClient(self.transport), self.checkout.sha,
                                             P.Reporter(io.StringIO())), "lightweight")
        self.github.tag_ref["object"] = {"type": "tag", "sha": "1" * 40}
        self.annotated("1" * 40, object_type="tag", target="2" * 40)
        self.annotated("2" * 40, tag="inner")
        self.assertEqual(P.verify_remote_tag(P.AnonymousClient(self.transport), self.checkout.sha,
                                             P.Reporter(io.StringIO())), "annotated")

    def test_missing_cyclic_deep_mistyped_or_mismatched_tags_are_refused_without_writes(self):
        cases = {
            "missing": lambda: setattr(self.github, "tag_ref", None),
            "wrong-ref": lambda: self.github.tag_ref.update(ref="refs/tags/v1.3.0rc10"),
            "wrong-commit": lambda: self.github.tag_ref.update(object={"type": "commit", "sha": "9" * 40}),
            "tree": lambda: self.github.tag_ref.update(object={"type": "tree", "sha": "9" * 40}),
            "cycle": lambda: (self.github.tag_ref.update(object={"type": "tag", "sha": "1" * 40}),
                              self.annotated("1" * 40, object_type="tag", target="2" * 40),
                              self.annotated("2" * 40, object_type="tag", target="1" * 40)),
            "too-deep": lambda: (self.github.tag_ref.update(object={"type": "tag", "sha": "1" * 40}),
                                 [self.annotated(f"{i}" * 40, object_type="tag", target=f"{i + 1}" * 40)
                                  for i in range(1, 7)]),
            "renamed-annotated": lambda: (self.github.tag_ref.update(object={"type": "tag", "sha": "1" * 40}),
                                          self.annotated("1" * 40, tag="v9")),
            "confused-object": lambda: (self.github.tag_ref.update(object={"type": "tag", "sha": "1" * 40}),
                                        self.github.tag_objects.update({"1" * 40: {
                                            "sha": "3" * 40, "tag": P.TAG,
                                            "object": {"type": "commit", "sha": self.checkout.sha}}})),
            "blob-annotated": lambda: (self.github.tag_ref.update(object={"type": "tag", "sha": "1" * 40}),
                                       self.annotated("1" * 40, object_type="blob")),
        }
        for label, arrange in cases.items():
            with self.subTest(label):
                self.github.tag_ref = {"ref": f"refs/tags/{P.TAG}",
                                       "object": {"type": "commit", "sha": self.checkout.sha}}
                self.github.tag_objects.clear()
                self.github.requests.clear()
                arrange()
                self.assertEqual(self.run_tool("stage-draft"), P.EXIT_REFUSED, self.last_err)
                self.assert_no_mutation()
                self.assertEqual(self.github.releases, [])


class StageDraftTests(PublisherHarness):
    def stored(self) -> dict[str, bytes]:
        release = self.github.candidate()
        return {asset["name"]: asset["_bytes"] for asset in self.github.assets[release["id"]]}

    def test_fresh_draft_prerelease_is_created_and_every_asset_uploaded_and_verified(self):
        self.assertEqual(self.run_tool("stage-draft"), P.EXIT_OK, self.last_err)
        release = self.github.candidate()
        self.assertTrue(release["draft"])
        self.assertTrue(release["prerelease"])
        self.assertEqual(release["target_commitish"], self.checkout.sha)
        self.assertEqual(self.stored(), CANDIDATE)
        create = self.github.methods("POST", f"{REPO}/releases")
        self.assertEqual(len([r for r in create if r["host"] == "api.github.com"]), 1)
        document = json.loads(create[0]["body"])
        self.assertEqual((document["draft"], document["prerelease"], document["make_latest"]), (True, True, "false"))
        self.assertEqual(self.github.methods("PATCH"), [])
        self.assert_no_destructive_requests()
        result = json.loads(self.last_out)
        self.assertEqual((result["state"], result["public"]), ("draft-prerelease", False))
        downloads = [r for r in self.github.requests if r["host"] == CDN]
        self.assertTrue(downloads)
        self.assertTrue(all(r["authorization"] is None for r in downloads))
        self.assertEqual(self.gate_calls, 1)

    def test_matching_partial_draft_resumes_with_only_missing_uploads(self):
        self.github.seed_release(assets=[P.WHEEL])
        self.assertEqual(self.run_tool("stage-draft"), P.EXIT_OK, self.last_err)
        uploads = [r["query"]["name"] for r in self.github.requests if r["host"] == "uploads.github.com"]
        self.assertEqual(uploads, [P.SDIST, P.MANIFEST])
        self.assertEqual(self.github.methods("POST", f"{REPO}/releases")[0]["host"], "uploads.github.com")
        self.assertEqual(self.stored(), CANDIDATE)
        self.assert_no_destructive_requests()
        self.github.requests.clear()
        self.assertEqual(self.run_tool("stage-draft"), P.EXIT_OK, self.last_err)
        self.assert_no_mutation()

    def test_pagination_finds_the_draft_and_every_asset(self):
        self.github.page_size = 1
        for index in range(4):
            self.github.seed_release(tag=f"v0.{index}", title="old", draft=False, prerelease=False)
        self.github.seed_release(assets=[P.WHEEL, P.SDIST])
        self.assertEqual(self.run_tool("stage-draft"), P.EXIT_OK, self.last_err)
        pages = [r["query"].get("page") for r in self.github.requests
                 if r["method"] == "GET" and r["path"] == f"{REPO}/releases"]
        self.assertIn("5", pages)
        self.assertEqual([r["query"]["name"] for r in self.github.requests if r["host"] == "uploads.github.com"],
                         [P.MANIFEST])
        self.assertEqual(len(self.github.releases), 5)

    def test_tag_deleted_after_final_read_before_create_is_recreated_only_at_the_expected_sha(self):
        # Another privileged actor deletes the tag after the tool's last tag GET; the provider
        # then creates it from the POST's target_commitish.  The tool binds it, it cannot stop it.
        self.github.hooks["before POST"] = lambda github: setattr(github, "tag_ref", None)
        self.assertEqual(self.run_tool("stage-draft"), P.EXIT_OK, self.last_err)
        create = json.loads(self.github.methods("POST", f"{REPO}/releases")[0]["body"])
        self.assertEqual(create["target_commitish"], self.checkout.sha)
        self.assertEqual(self.github.implicit_tags, [self.checkout.sha])
        self.assertNotIn(self.github.default_branch_sha, self.github.implicit_tags)
        self.assert_no_git_ref_request_except_reads()
        self.assert_no_destructive_requests()
        # The tag is re-read after staging and resolves to the source.
        self.assertGreater(self.github.ref_reads, 2)
        self.assertTrue(self.last_err.rstrip().splitlines()[-1].startswith(
            "heel-preview-release: draft-staged"))

    def test_lost_create_response_after_commit_is_reconciled_without_repeating(self):
        self.github.faults["drop_create_commit"] = True
        self.assertEqual(self.run_tool("stage-draft"), P.EXIT_OK, self.last_err)
        self.assertEqual(len([r for r in self.github.methods("POST") if r["host"] == "api.github.com"]), 1)
        self.assertIn("draft-create-reconciled", self.last_err)
        self.assertEqual(self.stored(), CANDIDATE)

    def test_lost_create_without_visible_draft_reports_unknown_and_does_not_retry(self):
        self.github.faults["drop_create_nocommit"] = True
        self.assertEqual(self.run_tool("stage-draft"), P.EXIT_UNKNOWN, self.last_err)
        self.assertEqual(len(self.github.methods("POST")), 1)
        self.assertIn("no retry", self.last_err)

    def test_lost_upload_response_is_reconciled_and_verified(self):
        self.github.faults["drop_upload_commit"] = P.SDIST
        self.assertEqual(self.run_tool("stage-draft"), P.EXIT_OK, self.last_err)
        self.assertEqual(self.stored(), CANDIDATE)
        self.assertIn(f"asset-uploaded name={P.SDIST} reconciled=True", self.last_err)
        self.assert_no_destructive_requests()

    def test_lost_upload_without_visible_asset_reports_unknown_and_does_not_retry(self):
        self.github.faults["drop_upload_nocommit"] = P.SDIST
        self.assertEqual(self.run_tool("stage-draft"), P.EXIT_UNKNOWN, self.last_err)
        self.assertEqual([r["query"]["name"] for r in self.github.requests if r["host"] == "uploads.github.com"],
                         [P.WHEEL, P.SDIST])
        self.assertNotIn(P.MANIFEST, self.stored())

    def test_conflicting_unknown_duplicate_or_incomplete_assets_are_refused_untouched(self):
        changed = bytearray(CANDIDATE[P.WHEEL])
        changed[-30] ^= 1
        cases = {
            "same-name-bytes": lambda rid: self.github.add_asset(
                rid, P.WHEEL, bytes(changed), _override={"digest": None}),
            "same-name-digest": lambda rid: self.github.add_asset(
                rid, P.WHEEL, CANDIDATE[P.WHEEL], _override={"digest": "sha256:" + "0" * 64}),
            "size": lambda rid: self.github.add_asset(rid, P.SDIST, CANDIDATE[P.SDIST][:-1]),
            "unknown": lambda rid: self.github.add_asset(rid, "notes.txt", b"x"),
            "duplicate": lambda rid: (self.github.add_asset(rid, P.WHEEL, CANDIDATE[P.WHEEL]),
                                      self.github.add_asset(rid, P.WHEEL, CANDIDATE[P.WHEEL])),
            "open-state": lambda rid: self.github.add_asset(rid, P.SDIST, CANDIDATE[P.SDIST], state="starter"),
            "foreign-url": lambda rid: self.github.add_asset(
                rid, P.SDIST, CANDIDATE[P.SDIST],
                _override={"url": "https://api.github.com/repos/other/heel/releases/assets/1"}),
        }
        for label, arrange in cases.items():
            with self.subTest(label):
                self.github.releases.clear()
                self.github.requests.clear()
                release = self.github.seed_release()
                arrange(release["id"])
                before = [dict(asset) for asset in self.github.assets[release["id"]]]
                self.assertEqual(self.run_tool("stage-draft"), P.EXIT_REFUSED, self.last_err)
                self.assert_no_mutation()
                self.assertEqual(self.github.assets[release["id"]], before)

    def test_unexpected_release_state_is_refused_not_repaired(self):
        cases = {
            "published": dict(draft=False),
            "not-prerelease": dict(prerelease=False),
            "stable-published": dict(draft=False, prerelease=False),
            "other-target": dict(sha="f" * 40),
            "other-title": dict(title="Heel 1.3.0rc1"),
            "other-notes": dict(body="edited"),
        }
        for label, keywords in cases.items():
            with self.subTest(label):
                self.github.releases.clear()
                self.github.requests.clear()
                self.github.seed_release(**keywords)
                self.assertEqual(self.run_tool("stage-draft"), P.EXIT_REFUSED, self.last_err)
                self.assert_no_mutation()
        # Only the target differs (same notes): a branch-targeted draft is not reused.
        self.github.releases.clear()
        self.github.seed_release()["target_commitish"] = "main"
        self.github.requests.clear()
        self.assertEqual(self.run_tool("stage-draft"), P.EXIT_REFUSED, self.last_err)
        self.assertIn("release target is not the expected source commit", self.last_err)
        self.assert_no_mutation()
        self.github.releases.clear()
        self.github.seed_release()
        self.github.seed_release()
        self.github.requests.clear()
        self.assertEqual(self.run_tool("stage-draft"), P.EXIT_REFUSED)
        self.assertIn("more than one release", self.last_err)
        self.assert_no_mutation()

    def test_hostile_upload_and_download_locations_never_receive_the_credential(self):
        release = self.github.seed_release(assets=[P.WHEEL])
        release["upload_url"] = "https://evil.example/repos/ancilis/heel/releases/1/assets{?name,label}"
        self.assertEqual(self.run_tool("stage-draft"), P.EXIT_REFUSED, self.last_err)
        self.assert_no_mutation()
        release["upload_url"] = f"https://uploads.github.com{REPO}/releases/{release['id']}/assets{{?name,label}}"
        for location in (
            "https://evil.example/blob/1",
            f"http://{CDN}/blob/1",
            f"https://user@{CDN}/blob/1",
            f"https://{CDN}:8443/blob/1",
            "https://api.github.com/repos/other/heel/releases/assets/1",
            "https://uploads.github.com/repos/ancilis/heel/releases/1/assets",
        ):
            with self.subTest(location):
                self.github.requests.clear()
                self.transport.sent.clear()
                self.github.faults["asset_location"] = location
                self.assertEqual(self.run_tool("stage-draft"), P.EXIT_REFUSED, self.last_err)
                self.assert_no_mutation()
                self.assertIn("allowed HTTPS asset host", self.last_err)
                for host, _, _, headers in self.transport.sent:
                    self.assertNotEqual(host, "evil.example")
                    if "Authorization" in headers:
                        self.assertEqual(host, "api.github.com")
                self.assertEqual(len([s for s in self.transport.sent if s[0] not in ("api.github.com",)]), 0)

    def test_secret_bearing_error_responses_are_not_reflected(self):
        self.github.faults["secret_error"] = True
        self.assertEqual(self.run_tool("stage-draft"), P.EXIT_REFUSED)
        self.assertIn("HTTP 500", self.last_err)
        self.assertNotIn("boom", self.last_err)
        self.assert_no_mutation()


class PublishTests(PublisherHarness):
    def staged(self):
        return self.github.seed_release(assets=list(NAMES))

    def test_matching_draft_is_published_as_a_prerelease_then_verified_anonymously(self):
        release = self.staged()
        self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_OK, self.last_err)
        patches = self.github.methods("PATCH")
        self.assertEqual(len(patches), 1)
        self.assertEqual(json.loads(patches[0]["body"]),
                         {"draft": False, "prerelease": True, "make_latest": "false",
                          "target_commitish": self.checkout.sha})
        self.assertEqual((release["draft"], release["prerelease"]), (False, True))
        self.assertEqual(self.spawned, [(self.checkout.sha, MANIFEST_SHA)])
        result = json.loads(self.last_out)
        self.assertEqual(result["state"], "published-prerelease")
        self.assertEqual(result["post_publication_bytes"], "re-listed and hashed")
        # After the PATCH: the tag, the asset list and every asset's bytes are read again.
        after = self.requests_after_patch()
        self.assertEqual(len([r for r in after if r["host"] == CDN]), 3)
        self.assertTrue(any(r["path"] == f"{REPO}/git/ref/tags/{P.TAG}" for r in after))
        self.assertTrue(all(r["method"] == "GET" for r in after))
        self.assertEqual([r for r in self.github.requests if r["method"] == "POST"], [])
        self.assert_no_destructive_requests()

    def test_publication_requires_exactly_the_three_matching_assets(self):
        for assets, extra in (([P.WHEEL, P.SDIST], None), (list(NAMES), "notes.txt")):
            with self.subTest(assets=assets, extra=extra):
                self.github.releases.clear()
                self.github.requests.clear()
                release = self.github.seed_release(assets=assets)
                if extra:
                    self.github.add_asset(release["id"], extra, b"x")
                self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_REFUSED, self.last_err)
                self.assert_no_mutation()
                self.assertTrue(release["draft"])
                self.assertEqual(self.spawned, [])

    def test_missing_draft_or_stable_release_is_never_created_or_converted(self):
        self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_REFUSED)
        self.assertIn("run stage-draft", self.last_err)
        self.github.seed_release(assets=list(NAMES), draft=False, prerelease=False)
        self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_REFUSED)
        self.assertIn("never creates or converts a stable release", self.last_err)
        self.assert_no_mutation()
        self.github.releases.clear()
        self.github.seed_release(assets=list(NAMES), prerelease=False)
        self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_REFUSED)
        self.assert_no_mutation()

    def test_repeated_publish_reports_already_published_without_a_second_request(self):
        self.staged()
        self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_OK, self.last_err)
        self.github.requests.clear()
        self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_OK, self.last_err)
        self.assert_no_mutation()
        self.assertIn("publish_request_sent=False", self.last_err)
        self.assertIs(json.loads(self.last_out)["published_now"], False)

    def test_lost_publish_response_is_reported_from_a_reread(self):
        release = self.staged()
        self.github.faults["drop_patch_commit"] = True
        self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_OK, self.last_err)
        self.assertIn("acknowledged=False", self.last_err)
        self.assertFalse(release["draft"])
        self.assertEqual(len(self.github.methods("PATCH")), 1)
        self.assertEqual(len([r for r in self.requests_after_patch() if r["host"] == CDN]), 3)
        self.assertIs(json.loads(self.last_out)["acknowledged"], False)

    def test_lost_publish_that_did_not_commit_is_unknown_and_not_retried(self):
        release = self.staged()
        self.github.faults["drop_patch_nocommit"] = True
        self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_UNKNOWN, self.last_err)
        self.assertEqual(len(self.github.methods("PATCH")), 1)
        self.assertTrue(release["draft"])
        self.assertIn("no retry", self.last_err)
        self.assertEqual(self.spawned, [])

    def assert_published_unverified(self, release):
        self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_PUBLISHED_UNVERIFIED, self.last_err)
        self.assertFalse(release["draft"])
        self.assertEqual(len(self.github.methods("PATCH")), 1)
        self.assertEqual([r for r in self.github.requests if r["method"] == "POST"], [])
        self.assertTrue(all(r["method"] == "GET" for r in self.requests_after_patch()))
        self.assert_no_destructive_requests()
        # Never a success record, never the anonymous install/reference run.
        self.assertEqual(self.last_out, "")
        self.assertEqual(self.spawned, [])
        self.assertIn("is published but post-publication verification failed", self.last_err)
        self.assertIn("Do not delete, recreate, replace or re-upload anything", self.last_err)
        self.assertIn(f"Recover read-only with: verify-public --repository ancilis/heel --tag {P.TAG} "
                      f"--expected-sha {self.checkout.sha} --expected-manifest-sha256 {MANIFEST_SHA}",
                      self.last_err)

    def reset(self):
        self.github.releases.clear()
        self.github.requests.clear()
        self.github.faults.clear()
        self.github.hooks.clear()
        self.github.patched = False
        self.github.tag_ref = {"ref": f"refs/tags/{P.TAG}", "object": {"type": "commit", "sha": self.checkout.sha}}
        self.spawned.clear()

    def test_tag_deleted_after_final_read_before_publish_is_bound_to_the_expected_sha(self):
        release = self.staged()
        self.github.hooks["before PATCH"] = lambda github: setattr(github, "tag_ref", None)
        self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_OK, self.last_err)
        patch = json.loads(self.github.methods("PATCH")[0]["body"])
        self.assertEqual(patch["target_commitish"], self.checkout.sha)
        self.assertEqual(release["target_commitish"], self.checkout.sha)
        # The provider recreated the tag, and only at the source; no default-branch fallback.
        self.assertEqual(self.github.implicit_tags, [self.checkout.sha])
        self.assertEqual(self.github.tag_ref["object"]["sha"], self.checkout.sha)
        self.assert_no_git_ref_request_except_reads()
        self.assert_no_destructive_requests()

    def test_fake_provider_falls_back_to_the_default_branch_without_an_explicit_target(self):
        # The model the previous test relies on: an update that omits target_commitish while the
        # tag is missing recreates the tag at the default branch.
        release = self.staged()
        self.github.tag_ref = None
        response = self.transport.send(
            "api.github.com", "PATCH", f"{REPO}/releases/{release['id']}",
            {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
            json.dumps({"draft": False, "prerelease": True}).encode(), P.MAX_JSON_BYTES,
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(self.github.implicit_tags, [self.github.default_branch_sha])

    def test_same_name_asset_replaced_after_byte_verification_is_published_unverified(self):
        changed = bytearray(CANDIDATE[P.WHEEL])
        changed[-30] ^= 1
        for label, extra in (("listing-digest", {}), ("no-listing-digest", {"_override": {"digest": None}})):
            with self.subTest(label):
                self.reset()
                release = self.staged()
                # Another writer deletes and re-uploads the wheel between the tool's last byte
                # read and its PATCH: same name and size, new id and bytes.
                self.github.hooks["before PATCH"] = lambda github, extra=extra: github.replace_asset(
                    P.WHEEL, bytes(changed), **extra)
                self.assert_published_unverified(release)
                self.assertIn(f"asset {P.WHEEL} conflicts with the candidate bytes", self.last_err)
                # Read-only recovery fails before any install or reference execution.
                self.github.requests.clear()
                self.github.faults.clear()
                self.assertEqual(self.run_tool("verify-public"), P.EXIT_FAILED, self.last_err)
                self.assertEqual(self.proof_calls, [])
                self.assertEqual(self.last_out, "")
                self.assert_no_mutation()
                self.assertTrue(all(r["authorization"] is None for r in self.github.requests))

    def test_post_publication_tag_or_source_change_is_published_unverified(self):
        def move_tag(github):
            github.tag_ref = {"ref": f"refs/tags/{P.TAG}", "object": {"type": "commit", "sha": "e" * 40}}

        cases = {
            "tag-moved": ("after PATCH", move_tag, "does not resolve to the expected source commit"),
            "tag-deleted": ("after PATCH", lambda github: setattr(github, "tag_ref", None), "does not exist"),
            # The changed target is caught by whichever of the response or the re-read sees it.
            "target-changed": ("after PATCH", lambda github: github.candidate().update(target_commitish="f" * 40),
                               "target"),
            "made-stable": ("after PATCH", lambda github: github.candidate().update(prerelease=False),
                            "not a prerelease"),
            "notes-edited": ("after PATCH", lambda github: github.candidate().update(body="edited"),
                             "release notes differ"),
            "asset-added": ("after PATCH", lambda github: github.add_asset(
                github.candidate()["id"], "notes.txt", b"x"), "unexpected asset"),
            "response-target": ("fault", "patch_response_other_target", "publication response"),
        }
        for label, (kind, action, reason) in cases.items():
            with self.subTest(label):
                self.reset()
                release = self.staged()
                if kind == "fault":
                    self.github.faults[action] = True
                else:
                    self.github.hooks[kind] = action
                self.assert_published_unverified(release)
                self.assertIn(reason, self.last_err)

    def test_conflicting_publication_acknowledgement_is_published_unverified(self):
        other = self.github.next_id + 100
        cases = {
            "draft-true": {"draft": True},
            "prerelease-false": {"prerelease": False},
            "body-edited": {"body": "edited"},
            "body-missing": {"body": None},
            "draft-string": {"draft": "false"},
            "prerelease-string": {"prerelease": "true"},
            "upload-url-other": {"upload_url": f"https://uploads.github.com{REPO}/releases/1/assets{{?name,label}}"},
            # Internally consistent but another release: the expected id stays bound.
            "other-release-id": {"id": other, "url": f"https://api.github.com{REPO}/releases/{other}",
                                 "upload_url": f"https://uploads.github.com{REPO}/releases/{other}/assets{{?name,label}}"},
        }
        for label, override in cases.items():
            with self.subTest(label):
                self.reset()
                release = self.staged()
                self.github.faults["patch_response_override"] = override
                self.assert_published_unverified(release)
                self.assertIn("publication response conflicts with the published prerelease", self.last_err)
                self.assertIn("acknowledged=True", self.last_err)
                # The stored release itself is the correct published prerelease.
                stored = P.check_release(self.github.release_record(release), sha=self.checkout.sha,
                                         draft=False, notes=P.render_release_notes(
                                             self.checkout.sha, CANDIDATE[P.MANIFEST]))
                self.assertEqual(stored, release["id"])
                # Read-only recovery establishes the actual published state without any write.
                self.github.requests.clear()
                self.github.faults.clear()
                self.proof_calls.clear()
                self.assertEqual(self.run_tool("verify-public"), P.EXIT_OK, self.last_err)
                self.assertEqual(len(self.proof_calls), 1)
                self.assert_no_mutation()
                self.assertTrue(all(r["authorization"] is None for r in self.github.requests))

    def test_conflicting_acknowledgement_with_unreliable_reread_stays_unknown(self):
        for reread in ("500", "other"):
            with self.subTest(reread):
                self.reset()
                release = self.staged()
                self.github.faults["patch_response_override"] = {"prerelease": False}
                self.github.faults["reread_after_patch"] = reread
                self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_UNKNOWN, self.last_err)
                self.assertFalse(release["draft"])
                self.assertNotIn("is published", self.last_err)
                self.assertEqual(len(self.github.methods("PATCH")), 1)
                self.assertEqual(self.spawned, [])
                self.assertEqual(self.last_out, "")
                self.assert_no_destructive_requests()

    def test_post_publication_metadata_or_byte_read_failure_is_published_unverified(self):
        for fault, value in (("asset_list_after_patch", "500"), ("cdn_after_patch", "500"),
                             ("cdn_after_patch", "drop")):
            with self.subTest(fault=fault, value=value):
                self.reset()
                release = self.staged()
                self.github.faults[fault] = value
                self.assert_published_unverified(release)

    def test_lost_publish_response_with_committed_but_replaced_bytes_is_published_unverified(self):
        changed = bytearray(CANDIDATE[P.SDIST])
        changed[-30] ^= 1
        release = self.staged()
        self.github.faults["drop_patch_commit"] = True
        self.github.hooks["after PATCH"] = lambda github: github.replace_asset(
            P.SDIST, bytes(changed), _override={"digest": None})
        self.assert_published_unverified(release)
        self.assertIn("acknowledged=False", self.last_err)

    def test_acknowledged_publish_that_still_reads_as_draft_is_unknown_and_not_retried(self):
        release = self.staged()
        self.github.faults["patch_keeps_draft"] = True
        self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_UNKNOWN, self.last_err)
        self.assertIn("acknowledged but the release still reads as a draft", self.last_err)
        self.assertTrue(release["draft"])
        self.assertEqual(len(self.github.methods("PATCH")), 1)
        self.assertEqual(self.spawned, [])
        self.assertEqual(self.last_out, "")

    def test_failed_or_unreliable_reread_after_publish_is_unknown_not_published(self):
        for reread in ("500", "drop", "other", "malformed"):
            with self.subTest(reread):
                self.reset()
                release = self.staged()
                self.github.faults["reread_after_patch"] = reread
                self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_UNKNOWN, self.last_err)
                # The server did commit, but the tool cannot establish it, so it claims neither.
                self.assertFalse(release["draft"])
                self.assertNotIn("heel-preview-release: published ", self.last_err)
                self.assertNotIn("is published", self.last_err)
                self.assertIn("no retry was sent", self.last_err)
                self.assertEqual(len(self.github.methods("PATCH")), 1)
                self.assertEqual(self.spawned, [])
                self.assertEqual(self.last_out, "")
                self.assert_no_destructive_requests()

    def test_already_published_release_with_changed_bytes_is_published_unverified_without_writes(self):
        changed = bytearray(CANDIDATE[P.WHEEL])
        changed[-30] ^= 1
        release = self.staged()
        release["draft"] = False
        self.github.replace_asset(P.WHEEL, bytes(changed), _override={"digest": None})
        self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_PUBLISHED_UNVERIFIED, self.last_err)
        self.assert_no_mutation()
        self.assertEqual(self.spawned, [])
        self.assertIn("Recover read-only with: verify-public", self.last_err)

    def test_verify_process_that_cannot_complete_is_published_unverified(self):
        self.staged()

        def timed_out(sha, manifest_sha256, reporter):
            raise subprocess.TimeoutExpired(["verify-public"], 3600)

        self.spawn = timed_out
        self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_PUBLISHED_UNVERIFIED, self.last_err)
        self.assertIn("anonymous verification failed (rc=TimeoutExpired)", self.last_err)
        self.assertEqual(self.last_out, "")

    def test_tag_moved_before_publication_is_refused(self):
        release = self.staged()
        self.github.move_tag_after_reads = 1
        self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_REFUSED, self.last_err)
        self.assertEqual(self.github.methods("PATCH"), [])
        self.assertTrue(release["draft"])

    def test_failed_anonymous_verification_after_publication_points_to_read_only_recovery(self):
        self.staged()
        self.spawn_result = 1
        self.assertEqual(self.run_tool("publish-and-verify"), P.EXIT_PUBLISHED_UNVERIFIED)
        self.assertIn("published but anonymous verification failed", self.last_err)
        self.assertIn(f"verify-public --repository ancilis/heel --tag {P.TAG}", self.last_err)
        self.assertEqual(self.last_out, "")
        # Recovery is read-only and anonymous.
        self.github.requests.clear()
        self.assertEqual(self.run_tool("verify-public"), P.EXIT_OK, self.last_err)
        self.assert_no_mutation()
        self.assertTrue(all(r["authorization"] is None for r in self.github.requests))


class VerifyPublicTests(PublisherHarness):
    def published(self, payloads=None, assets=NAMES):
        return self.github.seed_release(assets=list(assets), draft=False, payloads=payloads)

    def test_published_prerelease_is_verified_anonymously_and_read_only(self):
        self.published()
        self.assertEqual(self.run_tool("verify-public"), P.EXIT_OK, self.last_err)
        self.assert_no_mutation()
        self.assertEqual(self.token_calls, 0)
        self.assertEqual(self.gate_calls, 0)
        self.assertTrue(all(r["authorization"] is None for r in self.github.requests))
        self.assertTrue(all("Authorization" not in headers for *_, headers in self.transport.sent))
        hosts = {r["host"] for r in self.github.requests}
        self.assertEqual(hosts, {"api.github.com", "github.com", CDN})
        result = json.loads(self.last_out)
        self.assertTrue(result["anonymous_acquisition"])
        self.assertEqual({name: record["sha256"] for name, record in result["assets"].items()},
                         {name: hashlib.sha256(payload).hexdigest() for name, payload in CANDIDATE.items()})
        self.assertIn("pairing", result["not_proven"])
        acquired = self.proof_calls[0]
        self.assertFalse(acquired.is_relative_to(ROOT))
        self.assertEqual({path.name: path.read_bytes() for path in acquired.iterdir()}, CANDIDATE)
        shutil.rmtree(acquired.parent, ignore_errors=True)

    def assert_public_failure(self, code=P.EXIT_FAILED):
        self.assertEqual(self.run_tool("verify-public"), code, self.last_err)
        self.assert_no_mutation()
        self.assertEqual(self.proof_calls, [])
        self.assertEqual(self.last_out, "")

    def test_draft_stable_or_foreign_public_state_fails(self):
        self.github.seed_release(assets=list(NAMES))
        self.assert_public_failure()
        self.github.releases.clear()
        self.github.seed_release(assets=list(NAMES), draft=False, prerelease=False)
        self.assert_public_failure()
        self.github.releases.clear()
        self.github.seed_release(assets=list(NAMES), draft=False, sha="f" * 40)
        self.assert_public_failure()

    def test_corrupt_oversized_wrong_name_or_unknown_version_public_artifacts_fail(self):
        changed = bytearray(CANDIDATE[P.WHEEL])
        changed[500] ^= 1
        for label, arrange, manifest_sha in (
            ("corrupt", lambda: self.github.cdn_override.update({P.WHEEL: bytes(changed)}), MANIFEST_SHA),
            ("oversized", lambda: self.github.cdn_override.update({P.SDIST: CANDIDATE[P.SDIST] + b"x"}),
             MANIFEST_SHA),
            ("truncated", lambda: self.github.cdn_override.update({P.SDIST: CANDIDATE[P.SDIST][:-1]}),
             MANIFEST_SHA),
            ("extra-name", lambda: self.github.add_asset(self.github.candidate()["id"], "heel_sim-9.whl", b"x"),
             MANIFEST_SHA),
            ("missing", lambda: self.github.assets[self.github.candidate()["id"]].pop(), MANIFEST_SHA),
            ("expected-manifest", lambda: None, "0" * 64),
        ):
            with self.subTest(label):
                self.github.releases.clear()
                self.github.cdn_override.clear()
                self.github.requests.clear()
                self.published()
                arrange()
                self.assertEqual(self.run_tool("verify-public", extra=["--expected-manifest-sha256", manifest_sha]),
                                 P.EXIT_FAILED, self.last_err)
                self.assert_no_mutation()
                self.assertEqual(self.proof_calls, [])

    def test_unknown_version_manifest_fails_even_with_its_own_digest(self):
        manifest = json.loads(CANDIDATE[P.MANIFEST])
        manifest["version"] = "1.3.0rc6"
        payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.published(payloads={**CANDIDATE, P.MANIFEST: payload})
        self.assertEqual(self.run_tool("verify-public", extra=[
            "--expected-manifest-sha256", hashlib.sha256(payload).hexdigest()]), P.EXIT_FAILED)
        self.assertIn("candidate version", self.last_err)
        self.assert_no_mutation()

    def test_public_bytes_that_differ_from_the_accepted_digests_fail_without_install(self):
        wrong = canonical_but_unaccepted()
        self.published(payloads=wrong)
        wrong_manifest_sha = hashlib.sha256(wrong[P.MANIFEST]).hexdigest()
        self.assertEqual(self.run_tool("verify-public", extra=["--expected-manifest-sha256", wrong_manifest_sha]),
                         P.EXIT_FAILED, self.last_err)
        self.assertIn(f"public asset {P.WHEEL} is not the accepted 1.3.0rc5 artifact", self.last_err)
        self.assertEqual(self.proof_calls, [])
        self.assertEqual(self.last_out, "")
        self.assert_no_mutation()
        self.assertTrue(all(r["authorization"] is None for r in self.github.requests))

    def test_hostile_public_redirects_are_not_followed(self):
        self.published()
        for location in ("https://evil.example/x", f"http://{CDN}/blob/1", f"https://u:p@{CDN}/blob/1"):
            with self.subTest(location):
                self.transport.sent.clear()
                self.github.faults["public_location"] = location
                self.assert_public_failure()
                self.assertNotIn("evil.example", {host for host, *_ in self.transport.sent})

    def test_installed_proof_failure_is_reported_without_success(self):
        self.published()

        def failing(acquisition, work):
            raise P.ProofFailed("installed proof step pip-install failed (rc=1)")

        self.assertEqual(self.run_tool("verify-public", proof=failing), P.EXIT_FAILED)
        self.assertEqual(self.last_out, "")
        self.assertIn("pip-install failed", self.last_err)
        self.assertNotIn("installed-reference-proof result=passed", self.last_err)
        self.assert_no_mutation()

    def test_real_downloaded_wheel_installs_runner_extra_and_runs_reference_outcomes(self):
        """Actual HTTP bytes from the fake release, then the default installed proof."""
        self.assertGreaterEqual(sys.version_info[:2], (3, 11))
        probe = subprocess.run(
            [sys.executable, "-I", "-m", "pip", "--isolated", "download", "--no-deps",
             "--only-binary=:all:", "--dest", str(self.temporary / "probe"), P.RUNNER_REQUIREMENT],
            capture_output=True, text=True, timeout=180,
            env={**P.scrubbed_environment(self.temporary), "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
        if probe.returncode != 0:
            if INSTALL_REQUIRED:
                self.fail("required runner-extra installation prerequisite missing: package index")
            self.skipTest("package index unreachable for " + P.RUNNER_REQUIREMENT)
        self.published()
        code = P.main(
            ["verify-public", "--repository", "ancilis/heel", "--tag", P.TAG,
             "--expected-sha", self.checkout.sha, "--expected-manifest-sha256", MANIFEST_SHA],
            transport=self.transport, token_provider=self.token, reporter=P.Reporter(err := io.StringIO()),
            stdout=(out := io.StringIO()),
        )
        self.assertEqual(code, P.EXIT_OK, err.getvalue())
        result = json.loads(out.getvalue())
        self.addCleanup(shutil.rmtree, result["work_directory"], ignore_errors=True)
        proof = result["installed_proof"]
        self.assertEqual(proof["installed"], {"heel-sim": P.VERSION, "cryptography": "50.0.1"})
        self.assertEqual(proof["import_probe"], {"heel_version": P.VERSION, "heel_in_venv": True,
                                                 "saas_absent": True})
        self.assertEqual(proof["reference_outcomes"],
                         {"vulnerable": "verified_violation", "public": "invariant_held",
                          "hardened": "inconclusive", "error_envelope": "inconclusive"})
        self.assertEqual(proof["scope"], "packaging and synthetic reference only")
        self.assertFalse(Path(result["work_directory"]).is_relative_to(ROOT))
        self.assertEqual(self.token_calls, 0)
        self.assert_no_mutation()


# --------------------------------------------------------------------------- rc5-specific gates

# Every line the rc5 script may change relative to the reviewed, published rc4 script, by enumerated
# hunk.  Matching is by anchored content, never by line number.  E3's digest and size lines are
# derived from the pinned tables above.  E4 (PIN_STATUS = "FINAL" and the refusal of every other
# status at the start of main) is already in the rc4 script, so it is not a diff hunk here:
# CARRIED_E4 requires those lines, unchanged, in both scripts.
_E = re.escape
_WHEEL, _SDIST, _MANIFEST = "heel_sim-1.3.0rc5-py3-none-any.whl", "heel_sim-1.3.0rc5.tar.gz", "heel-open-core-manifest.json"
DIFF_REMOVED = {
    "E1": [_E('"""Stage, publish and anonymously verify the Heel runner preview 1.3.0rc4 GitHub prerelease.')],
    "E2": [_E('VERSION = "1.3.0rc4"')],
    "E3": [_E('# The exact reviewed 1.3.0rc4 bytes (source b7aee6e6); the only artifacts this tool will publish.'),
           _E(f'    WHEEL: "{INTERIM_SHA256[_WHEEL]}",'),
           _E(f'    SDIST: "{INTERIM_SHA256[_SDIST]}",'),
           _E(f'    MANIFEST: "{INTERIM_SHA256[_MANIFEST]}",'),
           _E('EXPECTED_SIZES = MappingProxyType({WHEEL: 2807548, SDIST: 599078, MANIFEST: 347})')],
    "E5": [_E('            "Adds local runner changes over 1.3.0rc3: after a terminal run, `heel runner serve` "'),
           _E('            "sends a metadata-only disclosure poll (digest, byte count and finding counts; no "'),
           _E('            "findings bytes) on the run\'s sealed result chain, and uploads the redacted findings "'),
           _E('            "once, only after a human-issued permit and a fresh check of its binding, window and "'),
           _E('            "authority; keeping the result local stops the polling. A staged poll answered with a "'),
           _E('            "non-200 or unreadable response is re-sent on its next due step, and an upload answered "'),
           _E('            "502, 503 or 504 is re-sent no sooner than 60 seconds later. Retention prune now "'),
           _E('            "finishes for runs awaiting a sharing decision and for shared runs. On Linux the "'),
           _E('            "`secret-service` vault passes one checked session bus address to `secret-tool` and "'),
           _E('            "never overwrites a locked item. Findings are unchanged from 1.3.0rc3: the paired "')],
    "E6": [_E('USER_AGENT = "heel-runner-preview-publisher-rc4"'),
           _E('        prog="publish_runner_preview_release_rc4.py",')],
    "E7": [_E('    """Peel refs/tags/v1.3.0rc4 to its commit; lightweight and annotated tags are explicit."""')],
}
DIFF_ADDED = {
    "E1": [_E('"""Stage, publish and anonymously verify the Heel runner preview 1.3.0rc5 GitHub prerelease.')],
    "E2": [_E('VERSION = "1.3.0rc5"')],
    "E3": [_E('# The exact reviewed 1.3.0rc5 bytes (source 79a1273b); the only artifacts this tool will publish.'),
           _E(f'    WHEEL: "{ACCEPTED_SHA256[_WHEEL]}",'),
           _E(f'    SDIST: "{ACCEPTED_SHA256[_SDIST]}",'),
           _E(f'    MANIFEST: "{ACCEPTED_SHA256[_MANIFEST]}",'),
           _E(f"EXPECTED_SIZES = MappingProxyType({{WHEEL: {ACCEPTED_SIZES[_WHEEL]}, SDIST: {ACCEPTED_SIZES[_SDIST]}, "
              f"MANIFEST: {ACCEPTED_SIZES[_MANIFEST]}}})")],
    "E5": [_E('            "Adds local runner changes over 1.3.0rc4: a staged disclosure poll or findings upload that "'),
           _E('            "Heel Cloud refuses with `invalid_runner_auth` is recovered through the existing sealed "'),
           _E('            "result-chain resync and retired only on the server\'s cursor proof, and nothing is re-signed "'),
           _E('            "inside recovery. A staged upload whose human permit has expired is recovered metadata-only "'),
           _E('            "on startup and on the serve step instead of stopping `heel runner serve`; an upload consumed "'),
           _E('            "without a receipt stays parked and fails closed. The slow disclosure poll step is 30 seconds. "'),
           _E('            "Findings are unchanged from 1.3.0rc4: the paired "')],
    "E6": [_E('USER_AGENT = "heel-runner-preview-publisher-rc5"'),
           _E('        prog="publish_runner_preview_release_rc5.py",')],
    "E7": [_E('    """Peel refs/tags/v1.3.0rc5 to its commit; lightweight and annotated tags are explicit."""')],
}
CARRIED_E4 = (
    'PIN_STATUS = "FINAL"\n',
    '        if PIN_STATUS != "FINAL":\n'
    '            raise Refused(f"the {VERSION} artifact pins are {PIN_STATUS}; no mode runs until they are final")\n',
)
HUNKS = {"E1", "E2", "E3", "E5", "E6", "E7"}
# Exact changed-line counts, so an allowed line cannot be repeated to smuggle in behaviour.
DIFF_REMOVED_COUNT = 20
DIFF_ADDED_COUNT = 17


def enumerated_diff(old_text: str, new_text: str) -> dict:
    """Classify every changed line of the rc4 -> rc5 diff; unclassified lines are reported."""
    import difflib

    removed, added = [], []
    for line in difflib.unified_diff(old_text.splitlines(), new_text.splitlines(), n=0, lineterm=""):
        if line.startswith(("---", "+++", "@@")):
            continue
        (removed if line[0] == "-" else added).append(line[1:])
    matched, unclassified = set(), []
    for lines, table, side in ((removed, DIFF_REMOVED, "-"), (added, DIFF_ADDED, "+")):
        for line in lines:
            found = {(side, label, pattern) for label, patterns in table.items() for pattern in patterns
                     if re.fullmatch(pattern, line)}
            if not found:
                unclassified.append(side + line)
            matched |= found
    # A hunk counts as present only when every one of its enumerated lines is in the diff.
    hits = {label for label in {*DIFF_REMOVED, *DIFF_ADDED}
            if all(("-", label, p) in matched for p in DIFF_REMOVED.get(label, []))
            and all(("+", label, p) in matched for p in DIFF_ADDED.get(label, []))}
    return {"removed": len(removed), "added": len(added), "hits": hits, "unclassified": unclassified}


class DiffBoundTests(unittest.TestCase):
    def test_rc5_script_differs_from_rc4_only_in_enumerated_hunks(self):
        rc4 = BASE_SCRIPT.read_text(encoding="utf-8")
        rc5 = SCRIPT.read_text(encoding="utf-8")
        result = enumerated_diff(rc4, rc5)
        self.assertEqual(result["unclassified"], [])
        self.assertEqual(result["hits"], HUNKS)
        self.assertEqual((result["removed"], result["added"]), (DIFF_REMOVED_COUNT, DIFF_ADDED_COUNT))
        # E4 is carried over unchanged: present exactly once in both scripts.
        for lines in CARRIED_E4:
            self.assertEqual(rc4.count(lines), 1)
            self.assertEqual(rc5.count(lines), 1)
        # The checker itself rejects an unenumerated change anywhere, including reused logic.
        for label, old, new in (
            ("transport", "MAX_REDIRECTS = 3", "MAX_REDIRECTS = 4"),
            ("draft", '"draft": True, "prerelease": True,', '"draft": True, "prerelease": False,'),
            ("allowlist", '"PATCH": re.compile', '"PUT": re.compile'),
            ("latest", '"make_latest": "false", "target_commitish": sha}', '"make_latest": "true", "target_commitish": sha}'),
            ("repeated-gate", '        if PIN_STATUS != "FINAL":\n',
             '        if PIN_STATUS != "FINAL":\n        if PIN_STATUS != "FINAL":\n'),
            ("local-digest-binding", '            raise Refused(f"{name} is not the accepted {VERSION} artifact")\n', ""),
            ("non-final-status", 'PIN_STATUS = "FINAL"\n', 'PIN_STATUS = "AWAITING-FINAL-ARTIFACT-PINS"\n'),
        ):
            with self.subTest(label):
                self.assertEqual(rc5.count(old), 1)
                mutated = enumerated_diff(rc4, rc5.replace(old, new, 1))
                self.assertTrue(mutated["unclassified"] or (mutated["removed"], mutated["added"])
                                != (DIFF_REMOVED_COUNT, DIFF_ADDED_COUNT), label)
        # Dropping the carried E4 gate, or an enumerated hunk, is also visible.
        dropped = enumerated_diff(rc4, rc5.replace(CARRIED_E4[1], "", 1))
        self.assertTrue(dropped["unclassified"])
        reverted = enumerated_diff(rc4, rc5.replace('VERSION = "1.3.0rc5"', 'VERSION = "1.3.0rc4"', 1))
        self.assertEqual(reverted["hits"], HUNKS - {"E2"})

    def test_rc1_rc2_rc3_and_rc4_publisher_files_are_byte_identical_to_the_base_blobs(self):
        for relative, blob in PROTECTED_BLOBS.items():
            with self.subTest(relative):
                path = ROOT / relative
                self.assertFalse(path.is_symlink())
                self.assertEqual(_git_blob_id(path.read_bytes()), blob)
        for fixture in ("runner_preview_rc1", "runner_preview_rc2", "runner_preview_rc3", "runner_preview_rc4"):
            present = sorted(path.relative_to(ROOT).as_posix()
                             for path in (ROOT / "tests/fixtures" / fixture).rglob("*") if path.is_file())
            self.assertEqual(present, sorted(r for r in PROTECTED_BLOBS if r.startswith(f"tests/fixtures/{fixture}/")))


class PinnedCandidateTests(unittest.TestCase):
    def test_checkout_artifacts_and_version_sources_are_the_pinned_rc5_blobs(self):
        self.assertEqual(sorted(os.listdir(ROOT / DOWNLOADS)), sorted(ACCEPTED_SHA256))
        for relative, blob in PINNED_BLOBS.items():
            with self.subTest(relative):
                path = ROOT / relative
                self.assertFalse(path.is_symlink())
                self.assertEqual(_git_blob_id(path.read_bytes()), blob)
        sources = {source: payload.decode("utf-8") for source, payload in CANDIDATE_SOURCES.items()}
        self.assertIn('version = "1.3.0rc5"', sources["pyproject.toml"])
        self.assertIn('requires-python = ">=3.11"', sources["pyproject.toml"])
        self.assertIn('runner = ["cryptography==50.0.1"]', sources["pyproject.toml"])
        self.assertEqual(json.loads(sources["release/open-core-v1.json"])["version"], "1.3.0rc5")
        self.assertIn('__version__ = "1.3.0rc5"', sources["heel/__init__.py"])
        self.assertIn('RELEASE_VERSION = "1.3.0rc5"', sources["scripts/build_open_core_release.py"])

    def test_expected_digest_constants_equal_the_committed_manifest_and_bytes(self):
        self.assertEqual(dict(P.EXPECTED_SHA256), ACCEPTED_SHA256)
        self.assertEqual(dict(P.EXPECTED_SIZES), ACCEPTED_SIZES)
        self.assertEqual(set(P.EXPECTED_SHA256), set(P.ASSET_NAMES))
        with self.assertRaises(TypeError):
            P.EXPECTED_SHA256[P.WHEEL] = "0" * 64
        for name, payload in CANDIDATE.items():
            self.assertEqual(hashlib.sha256(payload).hexdigest(), P.EXPECTED_SHA256[name])
            self.assertEqual(len(payload), P.EXPECTED_SIZES[name])
        manifest = json.loads(CANDIDATE[P.MANIFEST])
        self.assertEqual(manifest["version"], "1.3.0rc5")
        self.assertEqual({record["name"]: (record["sha256"], record["size"]) for record in manifest["artifacts"]},
                         {name: (P.EXPECTED_SHA256[name], P.EXPECTED_SIZES[name]) for name in (P.WHEEL, P.SDIST)})
        self.assertEqual(CANDIDATE[P.MANIFEST], canonical_manifest(CANDIDATE))
        self.assertEqual(P.RUNNER_REQUIREMENT, "cryptography==50.0.1")
        self.assertEqual((P.TAG, P.TITLE), ("v1.3.0rc5", "Heel runner preview 1.3.0rc5"))


class InterimPinTests(unittest.TestCase):
    """Until the final reviewed pins land, no mode reads a credential, runs a gate or sends a request."""

    def test_every_mode_refuses_while_the_pins_are_not_final(self):
        forbidden = mock.Mock(side_effect=AssertionError("network, token, gate, proof or spawn use"))
        for status in (INTERIM_STATUS, "", "final", "FINAL "):
            for mode in ("stage-draft", "publish-and-verify", "verify-public"):
                argv = [mode, "--repository", "ancilis/heel", "--tag", P.TAG, "--expected-sha", "a" * 40]
                if mode == "verify-public":
                    argv += ["--expected-manifest-sha256", MANIFEST_SHA]
                with self.subTest(status=status, mode=mode), mock.patch.object(P, "PIN_STATUS", status), \
                        mock.patch.object(P, "verify_local_candidate", forbidden), \
                        mock.patch.object(P, "gh_token", forbidden):
                    err, out = io.StringIO(), io.StringIO()
                    code = P.main(argv, transport=mock.Mock(send=forbidden), token_provider=forbidden,
                                  gate_runner=forbidden, proof_runner=forbidden, spawn_verify=forbidden,
                                  root=ROOT, reporter=P.Reporter(err), stdout=out)
                    self.assertEqual(code, P.EXIT_REFUSED)
                    self.assertEqual(out.getvalue(), "")
                    self.assertIn("no mode runs until they are final", err.getvalue())
        forbidden.assert_not_called()

    def test_isolated_script_refuses_with_an_interim_pin_status(self):
        # The committed status is FINAL; a copy carrying the interim status must refuse in a fresh process.
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(source.count('PIN_STATUS = "FINAL"\n'), 1)
        with tempfile.TemporaryDirectory(prefix="heel-rc5-interim-") as work:
            copy = Path(work) / SCRIPT.name
            copy.write_text(source.replace('PIN_STATUS = "FINAL"\n', f'PIN_STATUS = "{INTERIM_STATUS}"\n'),
                            encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-I", str(copy), "verify-public", "--repository", "ancilis/heel",
                 "--tag", P.TAG, "--expected-sha", "a" * 40, "--expected-manifest-sha256", MANIFEST_SHA],
                capture_output=True, text=True, timeout=60, cwd=work,
                env={"PATH": "/usr/bin:/bin", "HOME": work},
            )
        self.assertEqual(result.returncode, P.EXIT_REFUSED, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn(f"pins are {INTERIM_STATUS}", result.stderr)


class FinalizationTests(unittest.TestCase):
    """The pin status and the pinned digests move together; final pins never equal the interim ones."""

    def test_pin_status_is_bound_to_the_pins(self):
        self.assertIn(P.PIN_STATUS, (INTERIM_STATUS, "FINAL"))
        source = SCRIPT.read_text(encoding="utf-8")
        if P.PIN_STATUS == INTERIM_STATUS:
            # Interim: the tool carries exactly the interim digests and says so next to them.
            self.assertEqual(dict(P.EXPECTED_SHA256), INTERIM_SHA256)
            self.assertIn("# AWAITING-FINAL-ARTIFACT-PINS:", source)
        else:
            for name in P.ASSET_NAMES:
                with self.subTest(name):
                    self.assertNotEqual(P.EXPECTED_SHA256[name], INTERIM_SHA256[name])
            self.assertNotIn("AWAITING-FINAL-ARTIFACT-PINS", source)
        runbook = RUNBOOK.read_text(encoding="utf-8")
        self.assertEqual("AWAITING-FINAL-ARTIFACT-PINS" in runbook, P.PIN_STATUS == INTERIM_STATUS)
        for name in P.ASSET_NAMES:
            self.assertIn(P.EXPECTED_SHA256[name], runbook)
            self.assertIn(f"{P.EXPECTED_SIZES[name]} bytes", runbook)

    def test_interim_bytes_are_refused_once_the_pins_change(self):
        # Simulate any other pin set: the interim candidate must then be refused before any credential read.
        other = MappingProxyType({name: "0" * 64 for name in P.ASSET_NAMES})
        with tempfile.TemporaryDirectory(prefix="heel-rc5-stale-") as work:
            checkout = FixtureCheckout(Path(work))
            tokens = mock.Mock(side_effect=AssertionError("credential read"))
            with mock.patch.object(P, "PIN_STATUS", "FINAL"), mock.patch.object(P, "EXPECTED_SHA256", other):
                err = io.StringIO()
                code = P.main(["stage-draft", "--repository", "ancilis/heel", "--tag", P.TAG,
                               "--expected-sha", checkout.sha],
                              transport=mock.Mock(send=tokens), token_provider=tokens,
                              gate_runner=tokens, root=checkout.root, reporter=P.Reporter(err),
                              stdout=io.StringIO())
        self.assertEqual(code, P.EXIT_REFUSED)
        self.assertIn(f"is not the accepted {P.VERSION} artifact", err.getvalue())
        tokens.assert_not_called()


class InstalledProofTests(unittest.TestCase):
    """The default installed proof's decision rules, with the subprocess boundary faked.

    rc5 reuses the rc2 four-case proof unchanged; the reports below are the semantics pinned by
    tests/test_public_runner_preview_release.py, and the real-wheel case in VerifyPublicTests runs the
    actual installed CLI.
    """

    REPORTS = {
        "vulnerable": {"result": "verified_violation", "regression_passed": False, "evidence_state": "observed"},
        "public": {"result": "invariant_held", "regression_passed": True, "evidence_state": "observed"},
        "hardened": {"result": "inconclusive", "regression_passed": False, "evidence_state": "unknown"},
        "error_envelope": {"result": "inconclusive", "regression_passed": False, "evidence_state": "unknown"},
    }

    def run_proof(self, reports=None, cryptography="50.0.1", version=None):
        reports = reports or self.REPORTS
        self.cases: list[tuple[str, str]] = []

        def fake_run(command, **keywords):
            stdout = ""
            if command[-1] == f"./{P.WHEEL}[runner]":
                self.assertEqual(command[1:6], ["-I", "-m", "pip", "--isolated", "install"])
            elif len(command) > 3 and "m.distributions()" in command[3]:
                stdout = json.dumps({"heel-sim": version or P.VERSION, "cryptography": cryptography})
            elif len(command) > 3 and command[3] == P._IMPORT_PROBE:
                stdout = json.dumps({"heel_version": P.VERSION, "heel_in_venv": True, "saas_absent": True})
            elif command[1:3] == ["scope", "create"]:
                stdout = json.dumps({"created_scope": "scope-rc5"})
            elif command[1:3] == ["reference", "run"]:
                case, attempt = command[command.index("--case") + 1], command[command.index("--attempt") + 1]
                self.cases.append((case, attempt))
                stdout = json.dumps({**reports[case], "execution_support": "reference_only", "uploaded": False,
                                     "provenance": {"kind": "reference_product_execution", "network_calls": False}})
            return subprocess.CompletedProcess(command, 0, stdout, "")

        with tempfile.TemporaryDirectory(prefix="heel-proof-rc5-") as work, \
                mock.patch.object(P.subprocess, "run", side_effect=fake_run):
            return P.run_installed_reference_proof(Path(work), Path(work))

    def test_installed_proof_requires_the_four_reference_outcomes_for_rc5(self):
        proof = self.run_proof()
        self.assertEqual(proof["reference_outcomes"],
                         {"vulnerable": "verified_violation", "public": "invariant_held",
                          "hardened": "inconclusive", "error_envelope": "inconclusive"})
        self.assertEqual(self.cases, [("vulnerable", "5" * 32), ("public", "6" * 32),
                                      ("hardened", "7" * 32), ("error_envelope", "8" * 32)])
        self.assertEqual(proof["installed"], {"heel-sim": "1.3.0rc5", "cryptography": "50.0.1"})
        for label, reports in (
            ("rc1 hardened erratum", {**self.REPORTS, "hardened": {"result": "invariant_held", "regression_passed": True}}),
            ("rc1 error-envelope erratum",
             {**self.REPORTS, "error_envelope": {"result": "invariant_held", "regression_passed": True}}),
            ("inconclusive passing",
             {**self.REPORTS, "error_envelope": {**self.REPORTS["error_envelope"], "regression_passed": True}}),
        ):
            with self.subTest(label), self.assertRaises(P.ProofFailed):
                self.run_proof(reports)
        for keywords in ({"cryptography": "45.0.7"}, {"version": "1.3.0rc4"}):
            with self.subTest(**keywords), self.assertRaises(P.ProofFailed):
                self.run_proof(**keywords)


if __name__ == "__main__":
    unittest.main()
