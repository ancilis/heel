"""Cross-runtime contract parity for the committed browser wheel."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from heel.review_contract import validate_review_envelope
from heel.review_service import review_openapi


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps/heel-cloud"
FIXTURE = ROOT / "tests/fixtures/openapi/saas_api.json"
ENGINE = APP / "browser-engine"
PYODIDE = APP / "node_modules/pyodide"
WHEEL_NAME = "heel_browser-1.1.1-py3-none-any.whl"
MANIFEST = ENGINE / "manifest.json"
WHEEL = ENGINE / WHEEL_NAME
SUBSTANTIVE_FIELDS = (
    "schema_version",
    "engine_version",
    "product_id",
    "source_hash",
    "model_hash",
    "baseline_hash",
    "gate_status",
    "summary",
    "findings",
    "recommended_controls",
    "suggested_regressions",
    "questions",
    "safety",
)
EXPECTED_DIFFERENCES = {
    "execution_mode",
    "privacy.execution",
    "result_hash",
    "review_id",
}


NODE_REVIEW = r"""
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [pyodideRoot, wheelPath, manifestPath, fixturePath] = process.argv.slice(1);
const [wheel, manifest, source] = await Promise.all([
  readFile(wheelPath),
  readFile(manifestPath, "utf8").then(JSON.parse),
  readFile(fixturePath, "utf8"),
]);
if (
  manifest.schema_version !== "heel.browser-engine-manifest.v1"
  || manifest.engine_version !== "1.1.1"
  || manifest.wheel.filename !== "heel_browser-1.1.1-py3-none-any.whl"
  || manifest.wheel.size !== wheel.byteLength
  || manifest.wheel.sha256 !== createHash("sha256").update(wheel).digest("hex")
) throw new Error("committed browser wheel does not match its manifest");

const runtime = await import(pathToFileURL(join(pyodideRoot, "pyodide.mjs")).href);
if (runtime.version !== "314.0.3") throw new Error("unexpected Pyodide version");
const pyodide = await runtime.loadPyodide({
  cdnUrl: pyodideRoot,
  indexURL: pyodideRoot,
  lockFileURL: join(pyodideRoot, "pyodide-lock.json"),
  packageBaseUrl: pyodideRoot,
});
const sitePackages = pyodide.runPython("import sysconfig; sysconfig.get_paths()['purelib']");
pyodide.unpackArchive(new Uint8Array(wheel), "wheel", { extractDir: sitePackages });
pyodide.globals.set("heel_source", source);
try {
  const actual = pyodide.runPython(
    "from heel.browser_review import review_openapi_json\nreview_openapi_json(heel_source)",
  );
  process.stdout.write(actual);
} finally {
  pyodide.globals.delete("heel_source");
}
"""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _assert_independent_identity(
    case: unittest.TestCase, envelope: dict[str, object]
) -> None:
    body = {
        key: value
        for key, value in envelope.items()
        if key not in {"review_id", "result_hash"}
    }
    expected_hash = hashlib.sha256(
        _canonical_json(body).encode("utf-8")
    ).hexdigest()
    case.assertEqual(envelope["result_hash"], expected_hash)
    case.assertEqual(envelope["review_id"], f"review_{expected_hash[:20]}")


def _different_paths(left: object, right: object, prefix: str = "") -> set[str]:
    if type(left) is not type(right):
        return {prefix}
    if isinstance(left, dict):
        if left.keys() != right.keys():
            return {prefix}
        differences: set[str] = set()
        for key in left:
            child = f"{prefix}.{key}" if prefix else key
            differences.update(_different_paths(left[key], right[key], child))
        return differences
    if isinstance(left, list):
        if len(left) != len(right):
            return {prefix}
        differences = set()
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            differences.update(
                _different_paths(left_item, right_item, f"{prefix}[{index}]")
            )
        return differences
    return set() if left == right else {prefix}


class BrowserNativeParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        node = shutil.which("node")
        if node is None or not (PYODIDE / "pyodide.mjs").is_file():
            raise unittest.SkipTest(
                "cross-runtime parity requires Node and apps/heel-cloud npm dependencies"
            )
        cls.source = FIXTURE.read_text(encoding="utf-8")
        cls.spec = json.loads(cls.source)
        cls.native = validate_review_envelope(
            review_openapi(cls.spec, execution_mode="machine_local")
        )
        completed = subprocess.run(
            [
                node,
                "--input-type=module",
                "--eval",
                NODE_REVIEW,
                str(PYODIDE),
                str(WHEEL),
                str(MANIFEST),
                str(FIXTURE),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr or completed.stdout)
        cls.browser_text = completed.stdout
        cls.browser = validate_review_envelope(json.loads(completed.stdout))

    def test_actual_committed_pyodide_wheel_matches_native_substantive_contract(self):
        for field in SUBSTANTIVE_FIELDS:
            with self.subTest(field=field):
                self.assertEqual(self.browser[field], self.native[field])

        self.assertEqual(self.native["execution_mode"], "machine_local")
        self.assertEqual(self.browser["execution_mode"], "browser_local")
        self.assertEqual(self.native["privacy"], {
            "execution": "machine_local",
            "network_calls": False,
            "uploaded": False,
            "sync_intent": "none",
        })
        self.assertEqual(self.browser["privacy"], {
            "execution": "browser_local",
            "network_calls": False,
            "uploaded": False,
            "sync_intent": "none",
        })
        self.assertEqual(
            _different_paths(self.native, self.browser),
            EXPECTED_DIFFERENCES,
        )

    def test_each_mode_has_an_independently_valid_distinct_content_identity(self):
        _assert_independent_identity(self, self.native)
        _assert_independent_identity(self, self.browser)
        self.assertNotEqual(self.native["result_hash"], self.browser["result_hash"])
        self.assertNotEqual(self.native["review_id"], self.browser["review_id"])
        self.assertEqual(self.browser_text, _canonical_json(self.browser))


if __name__ == "__main__":
    unittest.main()
