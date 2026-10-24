"""Release-owner publisher for the runner preview prerelease, against a controlled fake GitHub.

Every remote call here goes to a loopback HTTP server that plays the GitHub API, upload, web and
release-asset CDN hosts.  The publisher keeps its logical ``https://`` host checks; only the
test transport maps those logical hosts to the loopback socket.  None of this is evidence of a
real GitHub publication, and no test reads a real credential.
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
from unittest import mock
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/publish_runner_preview_release.py"
# The fixed publisher names the public 1.3.0rc1 release, whatever candidate this checkout carries,
# so its input is the historical rc1 bytes: exported from the immutable rc1 commit, committed here
# and bound by git blob id, so a shallow or source-only checkout loads them without history or git.
HISTORICAL_FIXTURE = ROOT / "tests/fixtures/runner_preview_rc1"
HISTORICAL_COMMIT = "d3a5b61e6ced65f0edc5a95c128d5527d2e7222e"
HISTORICAL_BLOBS = {
    "apps/heel-cloud/public/downloads/heel_sim-1.3.0rc1-py3-none-any.whl": "6be8b96d444a8ef3ceadfd1004d354b9e7c75e24",
    "apps/heel-cloud/public/downloads/heel_sim-1.3.0rc1.tar.gz": "1d93115c17bed290f469f576900993176f5edcf7",
    "apps/heel-cloud/public/downloads/heel-open-core-manifest.json": "61691e27cadc8608c5f0e3b73e75902ca278b06b",
    "pyproject.toml": "7ce20c920e70617a7836a37794c27141b5fb4da5",
    "release/open-core-v1.json": "a6810fcac95714bf196ba58e9ba08461d4037fa5",
    "heel/__init__.py": "33d834d4701d715bc4bdc987ce389cc85cdf3dee",
    "scripts/build_open_core_release.py": "d74f7f6bf5b6dbd07aa2f0b5f12fdfe8116bf9d3",
}
INSTALL_REQUIRED = os.environ.get("HEEL_REQUIRE_RUNNER_EXTRA_INSTALL") == "1"
# A synthetic credential: it has no real-token prefix and only proves non-reflection.
TOKEN = "heelfaketoken_" + "Q7" * 15
REPO = "/repos/ancilis/heel"
CDN = "objects.githubusercontent.com"


def _load():
    spec = importlib.util.spec_from_file_location("heel_preview_publisher_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = _load()
_real_git = P._git
NAMES = P.ASSET_NAMES


class HistoricalFixtureError(Exception):
    pass


def _git_blob_id(payload: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(payload) + payload).hexdigest()


def load_historical_rc1(directory: Path = HISTORICAL_FIXTURE) -> tuple[dict[str, bytes], dict[str, bytes]]:
    """The rc1 artifacts by asset name and version sources by path, each verified by blob id."""
    layout = {f"{P.DOWNLOADS}/{name}": f"artifacts/{name}" for name in P.ASSET_NAMES}
    layout.update({source: f"version_sources/{Path(source).name}.txt" for source in P.VERSION_SOURCES})
    try:
        present = sorted(path.relative_to(directory).as_posix()
                         for path in directory.rglob("*") if not path.is_dir())
        if present != sorted([*layout.values(), "provenance.json"]):
            raise HistoricalFixtureError("fixture is not exactly the rc1 artifacts, sources and provenance")
        provenance = json.loads((directory / "provenance.json").read_text(encoding="utf-8"))
        entries = [*provenance["artifacts"], *provenance["version_sources"]]
        if (provenance["source_commit"] != HISTORICAL_COMMIT or provenance["version"] != P.VERSION
                or [entry["source_path"] for entry in entries] != list(layout)):
            raise HistoricalFixtureError("provenance does not name the rc1 commit, version and layout")
        loaded = {}
        for entry in entries:
            source = entry["source_path"]
            path = directory / layout[source]
            if path.is_symlink() or not path.is_file():
                raise HistoricalFixtureError(f"{layout[source]} is not a regular file")
            payload = path.read_bytes()
            if not (_git_blob_id(payload) == entry["git_blob"] == HISTORICAL_BLOBS[source]
                    and len(payload) == entry["size"]
                    and hashlib.sha256(payload).hexdigest() == entry["sha256"]):
                raise HistoricalFixtureError(f"{layout[source]} is not the historical rc1 blob")
            loaded[source] = payload
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise HistoricalFixtureError(f"malformed historical fixture ({type(error).__name__})") from None
    artifacts = {name: loaded[f"{P.DOWNLOADS}/{name}"] for name in P.ASSET_NAMES}
    return artifacts, {source: loaded[source] for source in P.VERSION_SOURCES}


CANDIDATE, HISTORICAL_SOURCES = load_historical_rc1()
MANIFEST_SHA = hashlib.sha256(CANDIDATE[P.MANIFEST]).hexdigest()


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
    """A temporary git checkout holding only the historical rc1 version sources and artifacts."""

    def __init__(self, temporary: Path, *, artifacts=None, pyproject_version=None):
        self.root = temporary / "checkout"
        for relative, payload in HISTORICAL_SOURCES.items():
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


class HistoricalFixtureTests(unittest.TestCase):
    """The fixture is deliberately the existing public rc1 identity, loaded offline and verified."""

    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp(prefix="heel-publisher-fixture-")).resolve()
        self.addCleanup(shutil.rmtree, self.temporary, ignore_errors=True)

    def copy(self, name="fixture") -> Path:
        target = self.temporary / name
        shutil.copytree(HISTORICAL_FIXTURE, target)
        return target

    def test_fixture_is_the_public_rc1_identity_the_fixed_publisher_names(self):
        self.assertEqual(P.VERSION, "1.3.0rc1")
        self.assertEqual(tuple(CANDIDATE), P.ASSET_NAMES)
        self.assertEqual(tuple(HISTORICAL_SOURCES), P.VERSION_SOURCES)
        checkout = FixtureCheckout(self.temporary)
        self.assertEqual(P._committed_versions(checkout.root, checkout.sha),
                         dict.fromkeys(P.VERSION_SOURCES, P.VERSION))
        for relative, payload in HISTORICAL_SOURCES.items():
            self.assertEqual((checkout.root / relative).read_bytes(), payload)
        manifest = P.verify_artifact_set(CANDIDATE)
        self.assertEqual(manifest["version"], P.VERSION)

    def test_loader_needs_no_git_history_network_or_checkout(self):
        copied = self.copy()
        self.assertFalse(copied.is_relative_to(ROOT))

        def refused(*arguments, **keywords):
            raise AssertionError("the historical fixture loader must not spawn or connect")

        with mock.patch.object(subprocess, "run", refused), \
                mock.patch.object(subprocess, "Popen", refused), \
                mock.patch.object(socket, "socket", refused):
            self.assertEqual(load_historical_rc1(copied), (CANDIDATE, HISTORICAL_SOURCES))

    def test_loader_rejects_missing_altered_relabelled_or_extra_bytes(self):
        def provenance(directory, change):
            path = directory / "provenance.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            change(document)
            path.write_text(json.dumps(document), encoding="utf-8")

        def relabel_pyproject(directory):
            # New bytes with a self-consistent provenance entry still differ from the pinned blob.
            path = directory / "version_sources/pyproject.toml.txt"
            payload = path.read_bytes().replace(b'version = "1.3.0rc1"', b'version = "1.3.0rc2"', 1)
            path.write_bytes(payload)

            def change(document):
                entry = document["version_sources"][0]
                entry.update(size=len(payload), sha256=hashlib.sha256(payload).hexdigest(),
                             git_blob=_git_blob_id(payload))
            provenance(directory, change)

        def flip_sdist_byte(directory):
            path = directory / "artifacts" / P.SDIST
            payload = bytearray(path.read_bytes())
            payload[100] ^= 1
            path.write_bytes(bytes(payload))

        def symlink_manifest(directory):
            path = directory / "artifacts" / P.MANIFEST
            outside = self.temporary / "outside.json"
            outside.write_bytes(path.read_bytes())
            path.unlink()
            path.symlink_to(outside)

        mutations = {
            "missing wheel": lambda d: (d / "artifacts" / P.WHEEL).unlink(),
            "altered sdist": flip_sdist_byte,
            "truncated version source": lambda d: (d / "version_sources/__init__.py.txt").write_bytes(b""),
            "relabelled version source": relabel_pyproject,
            "extra file": lambda d: (d / "artifacts/notes.txt").write_bytes(b"x"),
            "symlinked manifest": symlink_manifest,
            "movable reference": lambda d: provenance(d, lambda doc: doc.update(source_commit="main")),
            "other version": lambda d: provenance(d, lambda doc: doc.update(version="1.3.0rc2")),
            "reordered sources": lambda d: provenance(d, lambda doc: doc["version_sources"].reverse()),
            "malformed provenance": lambda d: (d / "provenance.json").write_bytes(b"{not json"),
            "missing provenance field": lambda d: provenance(d, lambda doc: doc.pop("artifacts")),
        }
        for index, (label, mutate) in enumerate(mutations.items()):
            with self.subTest(label):
                copied = self.copy(f"fixture-{index}")
                mutate(copied)
                with self.assertRaises(HistoricalFixtureError):
                    load_historical_rc1(copied)


class PublisherHarness(unittest.TestCase):
    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp(prefix="heel-publisher-test-")).resolve()
        self.addCleanup(shutil.rmtree, self.temporary, ignore_errors=True)
        self.assertFalse(self.temporary.is_relative_to(ROOT))
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
        runbook = (ROOT / "docs/RUNNER_PREVIEW_RELEASE.md").read_text(encoding="utf-8")
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
        self.assertIn("Heel runner preview 1.3.0rc1", notes)
        self.assertIn("prerelease", notes)
        self.assertIn("not published to PyPI", notes)
        self.assertIn("c" * 40, notes)
        for name, payload in CANDIDATE.items():
            self.assertIn(f"| `{name}` | {len(payload)} | `{hashlib.sha256(payload).hexdigest()}` |", notes)
        for claim in ("pairing", "heel runner serve", "HTTPS target traffic", "hosted findings", "launch readiness"):
            self.assertIn(claim, notes)
        self.assertNotIn("verified", notes.lower())
        self.assertNotIn("http", notes.replace("HTTPS target traffic", ""))
        self.assertNotIn(TOKEN, notes)
        # The manifest is the artifact; rendering external metadata leaves its bytes unchanged.
        self.assertEqual((HISTORICAL_FIXTURE / "artifacts" / P.MANIFEST).read_bytes(), CANDIDATE[P.MANIFEST])

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
        manifest["version"] = "1.3.0rc2"
        payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.published(payloads={**CANDIDATE, P.MANIFEST: payload})
        self.assertEqual(self.run_tool("verify-public", extra=[
            "--expected-manifest-sha256", hashlib.sha256(payload).hexdigest()]), P.EXIT_FAILED)
        self.assertIn("candidate version", self.last_err)
        self.assert_no_mutation()

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
        self.assertEqual(proof["installed"], {"heel-sim": P.VERSION, "cryptography": "45.0.7"})
        self.assertEqual(proof["import_probe"], {"heel_version": P.VERSION, "heel_in_venv": True,
                                                 "saas_absent": True})
        self.assertEqual(proof["reference_outcomes"],
                         {"vulnerable": "verified_violation", "hardened": "invariant_held"})
        self.assertEqual(proof["scope"], "packaging and synthetic reference only")
        self.assertFalse(Path(result["work_directory"]).is_relative_to(ROOT))
        self.assertEqual(self.token_calls, 0)
        self.assert_no_mutation()


if __name__ == "__main__":
    unittest.main()
