import ast
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps/heel-cloud"
BUILDER = ROOT / "scripts/build_browser_engine.py"
ARTIFACT_DIR = APP / "browser-engine"
WHEEL_NAME = "heel_browser-1.2.0-py3-none-any.whl"
DIST_INFO = "heel_browser-1.2.0.dist-info"
MODULE_PATHS = (
    "heel/__init__.py",
    "heel/browser_review.py",
    "heel/findings_sync.py",
    "heel/openapi_model.py",
    "heel/product_model.py",
    "heel/review_answers.py",
    "heel/review_contract.py",
    "heel/review_rules.py",
    "heel/review_service.py",
    "heel/static_review.py",
)
LICENSE_PATHS = (
    f"{DIST_INFO}/licenses/LICENSE",
    f"{DIST_INFO}/licenses/NOTICE",
)
METADATA_PATH = f"{DIST_INFO}/METADATA"
WHEEL_PATH = f"{DIST_INFO}/WHEEL"
RECORD_PATH = f"{DIST_INFO}/RECORD"
EXPECTED_ARCHIVE_ORDER = tuple(sorted((
    *MODULE_PATHS,
    *LICENSE_PATHS,
    METADATA_PATH,
    WHEEL_PATH,
))) + (RECORD_PATH,)


def _urlsafe_sha256(payload: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
    return "sha256=" + digest.rstrip(b"=").decode("ascii")


def _local_import_closure(entry_module: str) -> set[str]:
    pending = [entry_module]
    closure: set[str] = set()
    while pending:
        module = pending.pop()
        if module in closure:
            continue
        source = ROOT / "heel" / f"{module}.py"
        if not source.is_file():
            raise AssertionError(f"missing local dependency source: {source}")
        closure.add(module)
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level:
                if node.level != 1 or not node.module:
                    raise AssertionError(f"unsupported relative import in {source}: {ast.dump(node)}")
                pending.append(node.module.split(".", 1)[0])
    return closure


class BrowserEngineBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory()
        cls.output = Path(cls._temporary.name).resolve() / "engine"
        cls.output.mkdir()
        cls.completed = None
        if BUILDER.is_file():
            cls.completed = subprocess.run(
                [sys.executable, str(BUILDER), "--output", str(cls.output)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=30,
            )

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def _require_build(self) -> tuple[Path, Path]:
        self.assertTrue(BUILDER.is_file(), "browser engine builder is missing")
        self.assertIsNotNone(self.completed)
        self.assertEqual(self.completed.returncode, 0, self.completed.stderr)
        wheel = self.output / WHEEL_NAME
        manifest = self.output / "manifest.json"
        self.assertTrue(wheel.is_file(), "builder did not produce the pinned wheel")
        self.assertTrue(manifest.is_file(), "builder did not produce the engine manifest")
        return wheel, manifest

    def _run_builder_with_browser_review_mutation(self, mutation: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary).resolve()
            fixture_builder = fixture / "scripts" / BUILDER.name
            fixture_builder.parent.mkdir()
            shutil.copy2(BUILDER, fixture_builder)
            for relative_path in (*MODULE_PATHS, "LICENSE", "NOTICE"):
                destination = fixture / relative_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative_path, destination)
            browser_review = fixture / "heel/browser_review.py"
            browser_review.write_text(
                browser_review.read_text(encoding="utf-8") + f"\n{mutation}\n",
                encoding="utf-8",
            )
            return subprocess.run(
                [
                    sys.executable,
                    str(fixture_builder),
                    "--output",
                    str(fixture / "output"),
                ],
                cwd=fixture,
                text=True,
                capture_output=True,
                timeout=30,
            )

    def test_actual_local_import_closure_is_the_exact_wheel_module_allowlist(self):
        closure = (
            _local_import_closure("__init__")
            | _local_import_closure("browser_review")
            | _local_import_closure("findings_sync")
        )
        packaged_modules = {
            PurePosixPath(path).stem
            for path in MODULE_PATHS
        }

        self.assertEqual(closure, packaged_modules)
        self.assertNotIn("contracts", closure)
        self.assertNotIn("entitlements", closure)

    def test_package_initializer_is_subject_to_the_pure_import_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary).resolve()
            fixture_builder = fixture / "scripts" / BUILDER.name
            fixture_builder.parent.mkdir()
            shutil.copy2(BUILDER, fixture_builder)
            for relative_path in (*MODULE_PATHS, "LICENSE", "NOTICE"):
                destination = fixture / relative_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative_path, destination)
            initializer = fixture / "heel/__init__.py"
            initializer.write_text(
                initializer.read_text(encoding="utf-8") + "\nimport os\n",
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(fixture_builder),
                    "--output",
                    str(fixture / "output"),
                ],
                cwd=fixture,
                text=True,
                capture_output=True,
                timeout=30,
            )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unreviewed dependency: os", completed.stderr)

    def test_dynamic_import_evaluation_and_native_io_primitives_are_rejected(self):
        mutations = {
            "dynamic import": "__import__('socket')",
            "eval": "eval('1 + 1')",
            "exec": "exec('value = 1')",
            "compile": "compile('1 + 1', '<browser>', 'eval')",
            "open": "open('/tmp/heel-browser-policy', 'w')",
            "builtins bypass": "builtins.__import__('socket')",
            "importlib bypass": "importlib.import_module('socket')",
            "builtins mapping bypass": "__builtins__['__import__']('socket')",
            "Fable globals bypass": (
                "globals()['__builtins__']['__import__']('socket')"
            ),
            "Fable lambda globals bypass": (
                "(lambda: None).__globals__['__builtins__']['eval']('1 + 1')"
            ),
            "getattr builtins bypass": (
                "getattr(__builtins__, '__import__')('socket')"
            ),
            "function globals bypass": (
                "def heel_escape():\n"
                "    return None\n"
                "heel_escape.__globals__['__builtins__']['open']('/tmp/escape', 'w')"
            ),
            "class subclasses bypass": "().__class__.__base__.__subclasses__()",
            "reconstructed mapping keys": (
                "globals()['__built' + 'ins__']['__im' + 'port__']('socket')"
            ),
            "locals bypass": "locals()['__builtins__']['eval']('1 + 1')",
            "vars bypass": "vars(__builtins__)['exec']('value = 1')",
            "setattr reflection": "setattr(object(), 'escape', 1)",
            "delattr reflection": "delattr(object(), 'escape')",
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                completed = self._run_builder_with_browser_review_mutation(mutation)
                self.assertNotEqual(completed.returncode, 0, mutation)
                self.assertIn("forbidden dynamic primitive", completed.stderr)

        legitimate_compile = self._run_builder_with_browser_review_mutation(
            "import re\nre.compile('heel')"
        )
        self.assertEqual(legitimate_compile.returncode, 0, legitimate_compile.stderr)

    def test_imports_and_module_attributes_are_a_positive_capability_allowlist(self):
        mutations = {
            "Fable re builtins export": (
                "from re import __builtins__ as b\n"
                "b[''.join(['__im', 'port__'])]('socket')"
            ),
            "Fable re dictionary export": (
                "from re import __dict__ as namespace\n"
                "namespace[''.join(['__built', 'ins__'])]"
                "[''.join(['__im', 'port__'])]('socket')"
            ),
            "Fable dataclasses sys export": (
                "from dataclasses import sys\n"
                "sys.modules['importlib'].import_module('socket')"
            ),
            "nested re module export": (
                "import re\n"
                "re.enum.sys.modules['importlib'].import_module('socket')"
            ),
            "nested json module export": (
                "import json\n"
                "json.codecs.sys.modules['importlib'].import_module('socket')"
            ),
            "local module builtins export": (
                "from .review_contract import __builtins__ as b\n"
                "b[''.join(['__im', 'port__'])]('socket')"
            ),
            "direct module alias": "import re as regex\nregex.compile('heel')",
            "copied module alias": "import re\nregex = re\nregex.compile('heel')",
            "reviewed module rebinding": "import re\nre = None",
            "reviewed symbol alias": "from typing import Any as Anything",
            "unreviewed direct symbol": "from re import compile\ncompile('heel')",
            "unreviewed private attribute": "(lambda: None).__name__",
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                completed = self._run_builder_with_browser_review_mutation(mutation)
                self.assertNotEqual(completed.returncode, 0, mutation)
                self.assertRegex(
                    completed.stderr,
                    r"reviewed|forbidden dynamic primitive",
                )

        reviewed_capabilities = self._run_builder_with_browser_review_mutation(
            "import copy\n"
            "import hashlib\n"
            "import hmac\n"
            "import json\n"
            "import math\n"
            "import re\n"
            "from dataclasses import dataclass, field\n"
            "from typing import Any, Mapping\n"
            "from .review_contract import stable_json\n"
            "copy.deepcopy({})\n"
            "hashlib.sha256(b'heel')\n"
            "hmac.compare_digest(b'heel', b'heel')\n"
            "json.loads('{}')\n"
            "json.dumps({})\n"
            "json.JSONDecodeError\n"
            "math.isfinite(1.0)\n"
            "re.compile('heel')\n"
            "re.sub('h', 'H', 'heel')\n"
            "re.match('h', 'heel')"
        )
        self.assertEqual(
            reviewed_capabilities.returncode,
            0,
            reviewed_capabilities.stderr,
        )

    def test_calls_require_positive_reviewed_authority(self):
        mutations = {
            "breakpoint": "breakpoint()",
            "help": "help()",
            "input": "input()",
            "exit": "exit()",
            "quit": "quit()",
            "license": "license()",
            "credits": "credits()",
            "print": "print('heel')",
            "open": "open('/tmp/heel-browser-policy', 'w')",
            "unknown bare callable": "heel_unknown_callable()",
            "unknown data method": "heel_unknown.run()",
            "immediate lambda call": "(lambda: None)()",
            "subscript-selected call": "[lambda: None][0]()",
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                completed = self._run_builder_with_browser_review_mutation(mutation)
                self.assertNotEqual(completed.returncode, 0, mutation)
                self.assertRegex(
                    completed.stderr,
                    r"unreviewed call target|forbidden dynamic primitive",
                )

        reviewed_calls = self._run_builder_with_browser_review_mutation(
            "def heel_reviewed_local(value):\n"
            "    return len(value)\n"
            "heel_reviewed_local([])\n"
            "stable_json({})\n"
            "heel_values = []\n"
            "heel_values.append('heel')"
        )
        self.assertEqual(reviewed_calls.returncode, 0, reviewed_calls.stderr)

    def test_reviewed_binding_provenance_cannot_be_reassigned(self):
        mutations = {
            "Fable builtin rebound": "len = breakpoint\nlen()",
            "Fable imported function rebound": (
                "stable_json = breakpoint\nstable_json()"
            ),
            "Fable module attribute rebound": (
                "import re\nre.compile = breakpoint\nre.compile()"
            ),
            "module attribute rebound to data": "import re\nre.compile = None",
            "Fable local function rebound": (
                "def heel_local():\n"
                "    return None\n"
                "heel_local = breakpoint\n"
                "heel_local()"
            ),
            "Fable data method spoof": (
                "class HeelList:\n"
                "    append = help\n"
                "HeelList().append()"
            ),
            "parameter shadows builtin": "def heel_shadow(len):\n    return len",
            "comprehension shadows builtin": "[None for len in ()]",
            "loop shadows import": "for stable_json in ():\n    pass",
            "with shadows builtin": "with stable_json as len:\n    pass",
            "except shadows builtin": (
                "try:\n"
                "    raise ValueError('heel')\n"
                "except ValueError as len:\n"
                "    pass"
            ),
            "named expression shadows builtin": "(len := stable_json)",
            "global targets builtin": "def heel_global():\n    global len",
            "nonlocal targets local definition": (
                "def heel_outer():\n"
                "    def len():\n"
                "        return None\n"
                "    def heel_inner():\n"
                "        nonlocal len"
            ),
            "delete imported binding": "del stable_json",
            "delete local binding": (
                "def heel_local():\n    return None\ndel heel_local"
            ),
            "delete builtin binding": "del len",
            "delete module attribute": "import re\ndel re.compile",
        }
        ambient_names = (
            "breakpoint",
            "help",
            "input",
            "exit",
            "quit",
            "license",
            "credits",
            "print",
            "open",
        )
        mutations.update({
            f"ambient {name} reference": f"heel_alias = {name}"
            for name in ambient_names
        })

        for label, mutation in mutations.items():
            with self.subTest(label=label):
                completed = self._run_builder_with_browser_review_mutation(mutation)
                self.assertNotEqual(completed.returncode, 0, mutation)
                self.assertRegex(
                    completed.stderr,
                    r"ambient capability|reviewed binding|reviewed declaration binding|"
                    r"reviewed module attribute|forbidden dynamic primitive",
                )

        reviewed_declarations = self._run_builder_with_browser_review_mutation(
            "def heel_provenance_function():\n"
            "    return len(())\n"
            "class HeelProvenanceClass:\n"
            "    pass\n"
            "heel_provenance_function()\n"
            "HeelProvenanceClass()"
        )
        self.assertEqual(
            reviewed_declarations.returncode,
            0,
            reviewed_declarations.stderr,
        )

    def test_module_ambient_globals_and_attribute_writes_are_denied(self):
        object_fixture = (
            "class HeelList:\n"
            "    pass\n"
            "heel_list = HeelList()\n"
        )
        mutations = {
            "Fable loader file read": (
                object_fixture
                + "heel_list.append = __loader__.get_data\n"
                + "heel_list.append('/etc/hosts')"
            ),
            "Fable spec loader file read": (
                object_fixture
                + "heel_list.append = __spec__.loader.get_data\n"
                + "heel_list.append('/etc/hosts')"
            ),
            "reviewed data method store": object_fixture + "heel_list.append = None",
            "reviewed data method delete": object_fixture + "del heel_list.append",
            "arbitrary attribute store": object_fixture + "heel_list.escape = None",
            "arbitrary attribute delete": object_fixture + "del heel_list.escape",
            "reviewed name on wrong receiver": object_fixture + "heel_list.code = 'x'",
        }
        ambient_names = (
            "__loader__",
            "__spec__",
            "__builtins__",
            "__file__",
            "__cached__",
            "__package__",
            "__name__",
            "__doc__",
            "__annotations__",
            "__path__",
        )
        mutations.update({
            f"module ambient {name} reference": f"heel_alias = {name}"
            for name in ambient_names
        })

        for label, mutation in mutations.items():
            with self.subTest(label=label):
                completed = self._run_builder_with_browser_review_mutation(mutation)
                self.assertNotEqual(completed.returncode, 0, mutation)
                self.assertRegex(
                    completed.stderr,
                    r"forbidden dynamic primitive|unreviewed attribute write",
                )

        reviewed_writes = self._run_builder_with_browser_review_mutation(
            "class HeelReviewedWrites:\n"
            "    def __init__(self):\n"
            "        self.code = 'heel.reviewed'\n"
            "        self.public_message = 'reviewed'\n"
            "HeelReviewedWrites()"
        )
        self.assertEqual(reviewed_writes.returncode, 0, reviewed_writes.stderr)

    def test_declarations_cannot_shadow_or_replace_reviewed_bindings(self):
        mutations = {
            "function shadows imported serializer": (
                "def stable_json(value):\n"
                "    return value\n"
                "stable_json({})"
            ),
            "class shadows imported serializer": (
                "class stable_json:\n"
                "    pass\n"
                "stable_json()"
            ),
            "async function shadows imported serializer": (
                "async def stable_json(value):\n"
                "    return value"
            ),
            "function shadows safe builtin": "def len(value):\n    return 0\nlen(())",
            "class shadows safe builtin": "class len:\n    pass\nlen()",
            "function shadows module binding": "def json():\n    return None",
            "class shadows module binding": "import re\nclass re:\n    pass",
            "function shadows another imported symbol": (
                "def validate_review_envelope(value):\n"
                "    return value"
            ),
            "duplicate function declaration": (
                "def heel_once():\n"
                "    return 1\n"
                "def heel_once():\n"
                "    return 2"
            ),
            "duplicate class declaration": (
                "class HeelOnce:\n"
                "    pass\n"
                "class HeelOnce:\n"
                "    pass"
            ),
            "function replaced by class": (
                "def heel_once():\n"
                "    return 1\n"
                "class heel_once:\n"
                "    pass"
            ),
            "async function replaced by function": (
                "async def heel_once():\n"
                "    return 1\n"
                "def heel_once():\n"
                "    return 2"
            ),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                completed = self._run_builder_with_browser_review_mutation(mutation)
                self.assertNotEqual(completed.returncode, 0, mutation)
                self.assertRegex(
                    completed.stderr,
                    r"reviewed declaration binding|duplicate declaration|"
                    r"rebinds reviewed module",
                )

        reviewed_declarations = self._run_builder_with_browser_review_mutation(
            "def heel_unique_function():\n"
            "    return None\n"
            "async def heel_unique_async_function():\n"
            "    return None\n"
            "class HeelUniqueClass:\n"
            "    def heel_shared_method(self):\n"
            "        return None\n"
            "class HeelSecondUniqueClass:\n"
            "    def heel_shared_method(self):\n"
            "        return None\n"
            "heel_unique_function()\n"
            "HeelUniqueClass()\n"
            "HeelSecondUniqueClass()"
        )
        self.assertEqual(
            reviewed_declarations.returncode,
            0,
            reviewed_declarations.stderr,
        )

    def test_builder_produces_only_the_proven_browser_closure_and_metadata(self):
        wheel, _manifest = self._require_build()
        with zipfile.ZipFile(wheel) as archive:
            infos = archive.infolist()

        names = [info.filename for info in infos]
        self.assertEqual(names, list(EXPECTED_ARCHIVE_ORDER))
        self.assertEqual(len(names), len(set(names)), "wheel contains duplicate names")
        for name in names:
            path = PurePosixPath(name)
            self.assertFalse(path.is_absolute())
            self.assertNotIn("..", path.parts)
            self.assertNotIn("\\", name)
        former_namespace = "arc" + "eo"
        self.assertFalse(any(name.startswith(former_namespace + "/") for name in names))
        self.assertFalse(any("__pycache__" in name or name.endswith(".pyc") for name in names))

    def test_wheel_zip_metadata_is_pinned_and_non_executable(self):
        wheel, _manifest = self._require_build()
        with zipfile.ZipFile(wheel) as archive:
            for info in archive.infolist():
                self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0), info.filename)
                self.assertEqual(info.create_system, 3, info.filename)
                self.assertEqual(info.compress_type, zipfile.ZIP_STORED, info.filename)
                self.assertEqual(
                    stat.S_IFMT(info.external_attr >> 16),
                    stat.S_IFREG,
                    info.filename,
                )
                self.assertEqual(
                    stat.S_IMODE(info.external_attr >> 16),
                    0o644,
                    info.filename,
                )

    def test_record_hashes_sizes_order_and_self_entry_are_exact(self):
        wheel, _manifest = self._require_build()
        with zipfile.ZipFile(wheel) as archive:
            payloads = {
                name: archive.read(name)
                for name in EXPECTED_ARCHIVE_ORDER
            }
        rows = list(csv.reader(io.StringIO(payloads[RECORD_PATH].decode("utf-8"))))

        self.assertEqual([row[0] for row in rows], list(EXPECTED_ARCHIVE_ORDER))
        for path, digest, size in rows[:-1]:
            self.assertEqual(digest, _urlsafe_sha256(payloads[path]), path)
            self.assertEqual(size, str(len(payloads[path])), path)
        self.assertEqual(rows[-1], [RECORD_PATH, "", ""])

    def test_wheel_carries_exact_root_apache_license_and_notice_only(self):
        wheel, _manifest = self._require_build()
        with zipfile.ZipFile(wheel) as archive:
            self.assertEqual(
                archive.read(LICENSE_PATHS[0]),
                (ROOT / "LICENSE").read_bytes(),
            )
            self.assertEqual(
                archive.read(LICENSE_PATHS[1]),
                (ROOT / "NOTICE").read_bytes(),
            )
            metadata = archive.read(METADATA_PATH).decode("utf-8")
            wheel_metadata = archive.read(WHEEL_PATH).decode("utf-8")

        self.assertIn("Name: heel-browser\n", metadata)
        self.assertIn("Version: 1.2.0\n", metadata)
        self.assertIn("License-Expression: Apache-2.0\n", metadata)
        self.assertIn("License-File: LICENSE\n", metadata)
        self.assertIn("License-File: NOTICE\n", metadata)
        self.assertIn("Root-Is-Purelib: true\n", wheel_metadata)
        self.assertIn("Tag: py3-none-any\n", wheel_metadata)

    def test_wheel_sources_exclude_native_boundaries_and_secret_values(self):
        wheel, _manifest = self._require_build()
        with zipfile.ZipFile(wheel) as archive:
            source = "\n".join(
                archive.read(path).decode("utf-8")
                for path in MODULE_PATHS
            )

        forbidden_imports = (
            "heel.saas",
            ".mcp_server",
            ".rest",
            ".local_projects",
            ".store",
            "import socket",
            "import subprocess",
            "import urllib",
        )
        for forbidden in forbidden_imports:
            self.assertNotIn(forbidden, source)
        self.assertNotRegex(source, r"sk-live-[A-Za-z0-9_-]{12,}")
        self.assertNotRegex(source, r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

    def test_manifest_is_canonical_and_integrity_pins_the_wheel(self):
        wheel, manifest_path = self._require_build()
        raw_manifest = manifest_path.read_text(encoding="utf-8")
        manifest = json.loads(raw_manifest)
        wheel_bytes = wheel.read_bytes()

        self.assertEqual(
            raw_manifest,
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        )
        self.assertEqual(manifest, {
            "engine_version": "1.2.0",
            "schema_version": "heel.browser-engine-manifest.v1",
            "wheel": {
                "filename": WHEEL_NAME,
                "sha256": hashlib.sha256(wheel_bytes).hexdigest(),
                "size": len(wheel_bytes),
            },
        })

    def test_two_builds_are_byte_identical_and_check_mode_detects_drift(self):
        wheel, manifest = self._require_build()
        with tempfile.TemporaryDirectory() as temporary:
            other = Path(temporary).resolve()
            rebuilt = subprocess.run(
                [sys.executable, str(BUILDER), "--output", str(other)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(rebuilt.returncode, 0, rebuilt.stderr)
            self.assertEqual(wheel.read_bytes(), (other / WHEEL_NAME).read_bytes())
            self.assertEqual(manifest.read_bytes(), (other / "manifest.json").read_bytes())
            checked = subprocess.run(
                [sys.executable, str(BUILDER), "--output", str(other), "--check"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)
            (other / "manifest.json").write_text("{}\n", encoding="utf-8")
            drift = subprocess.run(
                [sys.executable, str(BUILDER), "--output", str(other), "--check"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertNotEqual(drift.returncode, 0)

    def test_builder_preserves_unrelated_output_files(self):
        self.assertTrue(BUILDER.is_file(), "browser engine builder is missing")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve()
            sentinel = output / "owner-file.txt"
            sentinel.write_text("preserve me", encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(BUILDER), "--output", str(output)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me")

    def test_builder_rejects_symlinked_output_roots_parents_and_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary).resolve()
            outside = fixture / "outside"
            outside.mkdir()

            direct_output = fixture / "direct-output"
            direct_output.symlink_to(outside, target_is_directory=True)
            direct = subprocess.run(
                [sys.executable, str(BUILDER), "--output", str(direct_output)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertNotEqual(direct.returncode, 0)
            self.assertEqual(list(outside.iterdir()), [], "builder wrote through output symlink")

            outside_engine = outside / "engine"
            outside_engine.mkdir()
            linked_parent = fixture / "linked-parent"
            linked_parent.symlink_to(outside, target_is_directory=True)
            parent_output = linked_parent / "engine"
            parent = subprocess.run(
                [sys.executable, str(BUILDER), "--output", str(parent_output)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertNotEqual(parent.returncode, 0)
            self.assertEqual(list(outside_engine.iterdir()), [], "builder wrote through linked parent")

            artifact_output = fixture / "artifact-output"
            artifact_output.mkdir()
            outside_artifact = outside / "artifact"
            outside_artifact.write_text("outside sentinel", encoding="utf-8")
            (artifact_output / WHEEL_NAME).symlink_to(outside_artifact)
            artifact = subprocess.run(
                [sys.executable, str(BUILDER), "--output", str(artifact_output)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertNotEqual(artifact.returncode, 0)
            self.assertEqual(outside_artifact.read_text(encoding="utf-8"), "outside sentinel")

    def test_builder_rejects_a_symlinked_source_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary).resolve()
            fixture_builder = fixture / "scripts" / BUILDER.name
            fixture_builder.parent.mkdir()
            shutil.copy2(BUILDER, fixture_builder)
            outside_heel = fixture / "outside-heel"
            outside_heel.mkdir()
            for relative_path in MODULE_PATHS:
                source = ROOT / relative_path
                shutil.copy2(source, outside_heel / source.name)
            (fixture / "heel").symlink_to(outside_heel, target_is_directory=True)
            shutil.copy2(ROOT / "LICENSE", fixture / "LICENSE")
            shutil.copy2(ROOT / "NOTICE", fixture / "NOTICE")

            completed = subprocess.run(
                [sys.executable, str(fixture_builder), "--output", str(fixture / "output")],
                cwd=fixture,
                text=True,
                capture_output=True,
                timeout=30,
            )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("symbolic link", completed.stderr)

    def test_builder_rejects_invocation_through_a_symlinked_repository_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            anchor = Path(temporary).resolve()
            fixture = anchor / "actual-source-root"
            fixture_builder = fixture / "scripts" / BUILDER.name
            fixture_builder.parent.mkdir(parents=True)
            shutil.copy2(BUILDER, fixture_builder)
            for relative_path in (*MODULE_PATHS, "LICENSE", "NOTICE"):
                destination = fixture / relative_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative_path, destination)
            linked_fixture = anchor / "linked-source-root"
            linked_fixture.symlink_to(fixture, target_is_directory=True)

            completed = subprocess.run(
                [
                    sys.executable,
                    str(linked_fixture / "scripts" / BUILDER.name),
                    "--output",
                    str(anchor / "output"),
                ],
                cwd=fixture,
                text=True,
                capture_output=True,
                timeout=30,
            )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("browser source root contains a symbolic link", completed.stderr)

    def test_committed_artifacts_equal_a_fresh_build(self):
        wheel, manifest = self._require_build()
        self.assertEqual(
            (ARTIFACT_DIR / WHEEL_NAME).read_bytes(),
            wheel.read_bytes(),
        )
        self.assertEqual(
            (ARTIFACT_DIR / "manifest.json").read_bytes(),
            manifest.read_bytes(),
        )


class CommercialSourceLicenseBoundaryTests(unittest.TestCase):
    def test_original_app_sources_have_the_commercial_spdx_header(self):
        header = "SPDX-License-Identifier: LicenseRef-Heel-Commercial"
        extensions = {".css", ".js", ".jsx", ".mjs", ".ts", ".tsx"}
        ignored_root_directories = {
            ".next", ".vinext", ".wrangler", "browser-engine", "coverage",
            "dist", "node_modules", "out", "outputs", "work",
        }
        sources = []
        for directory, child_directories, filenames in os.walk(APP):
            current = Path(directory)
            if current == APP:
                child_directories[:] = [
                    name for name in child_directories
                    if name not in ignored_root_directories
                ]
            if current == APP / "public":
                child_directories[:] = [
                    name for name in child_directories
                    if name != "heel-runtime"
                ]
            for filename in filenames:
                if current == APP and filename == "next-env.d.ts":
                    continue
                path = current / filename
                if path.suffix in extensions:
                    sources.append(path)

        self.assertTrue(sources)
        for source in sources:
            self.assertIn(
                header,
                source.read_text(encoding="utf-8"),
                str(source.relative_to(APP)),
            )


if __name__ == "__main__":
    unittest.main()
