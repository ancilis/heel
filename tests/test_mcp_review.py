import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from heel.local_projects import LocalProjectStore, StoredReviewError
from heel.mcp_server import (
    MAX_OPENAPI_PAYLOAD_BYTES,
    MCP_SCHEMA_VERSION,
    REVIEW_TOOL_NAMES,
    REVIEW_TOOL_SCHEMAS,
    TOOL_NAMES,
    HeelServer,
    ToolError,
    handle_line,
)
from heel.review_contract import ENGINE_VERSION, REVIEW_SCHEMA_VERSION, stable_json
from heel.review_export import review_to_json, review_to_markdown
from heel.store import Store


ROOT = Path(__file__).resolve().parents[1]
OPENAPI_FIXTURE = ROOT / "tests/fixtures/openapi/saas_api.json"


def _sample_spec():
    return json.loads(OPENAPI_FIXTURE.read_text(encoding="utf-8"))


def _small_spec():
    return {
        "openapi": "3.1.0",
        "info": {"title": "Agent App", "version": "1"},
        "paths": {
            "/exports": {"get": {"operationId": "exportUsers"}},
        },
    }


class MCPReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name).resolve(strict=True)
        self.env = mock.patch.dict(os.environ, {"HEEL_HOME": str(self.home)})
        self.env.start()
        self.projects = LocalProjectStore(self.home)
        self.audit = Store(str(self.home / "heel.db"))
        self.server = HeelServer(store=self.audit, projects=self.projects)
        self.caller = "mcp:test"

    def tearDown(self):
        self.audit.close()
        self.env.stop()
        self.tmp.cleanup()

    def _review(self, spec=None):
        return self.server.call_tool(
            "heel_review_openapi", {"openapi": spec or _small_spec()}, self.caller
        )

    def test_agent_gets_real_saved_local_value_from_one_call(self):
        result = self._review(_sample_spec())

        self.assertEqual(result["schema_version"], REVIEW_SCHEMA_VERSION)
        self.assertGreater(result["summary"]["findings"], 0)
        self.assertTrue(result["recommended_controls"])
        self.assertEqual(result["execution_mode"], "machine_local")
        self.assertEqual(result["privacy"], {
            "execution": "machine_local",
            "network_calls": False,
            "uploaded": False,
            "sync_intent": "none",
        })
        self.assertEqual(self.projects.get_review(result["review_id"]), result)

    def test_status_is_the_explicit_local_no_account_contract(self):
        self.assertEqual(self.server.call_tool("heel_status", {}, self.caller), {
            "engine_version": ENGINE_VERSION,
            "mcp_schema_version": MCP_SCHEMA_VERSION,
            "review_schema_version": REVIEW_SCHEMA_VERSION,
            "execution_mode": "machine_local",
            "network_calls": False,
            "cloud_sync": False,
            "account_required": False,
        })
        self.assertEqual(MCP_SCHEMA_VERSION, "heel.mcp.v1")

    def test_list_get_explain_and_both_exports_use_the_saved_review(self):
        review = self._review()
        finding = review["findings"][0]

        listed = self.server.call_tool("heel_list_reviews", {}, self.caller)
        loaded = self.server.call_tool(
            "heel_get_review", {"review_id": review["review_id"]}, self.caller
        )
        explained = self.server.call_tool("heel_explain_finding", {
            "review_id": review["review_id"],
            "surface_id": finding["surface_id"],
            "risk": finding["risk"],
        }, self.caller)
        markdown = self.server.call_tool("heel_export_review", {
            "review_id": review["review_id"], "format": "markdown",
        }, self.caller)
        json_export = self.server.call_tool("heel_export_review", {
            "review_id": review["review_id"], "format": "json",
        }, self.caller)

        self.assertEqual(listed, {"reviews": [{
            "review_id": review["review_id"],
            "product_id": review["product_id"],
            "gate_status": review["gate_status"],
        }]})
        self.assertEqual(loaded, review)
        self.assertEqual(explained["finding"], finding)
        self.assertEqual(explained["explanation"], finding["reason"])
        self.assertEqual(explained["recommended_control"], finding["control"])
        self.assertEqual(markdown, {
            "format": "markdown", "content": review_to_markdown(review),
        })
        self.assertEqual(json_export, {
            "format": "json", "content": review_to_json(review),
        })
        self.assertEqual(json.loads(json_export["content"]), review)

    def test_review_listing_is_deterministic(self):
        for title in ("Zulu Product", "Alpha Product"):
            spec = _small_spec()
            spec["info"]["title"] = title
            self._review(spec)

        first = self.server.call_tool("heel_list_reviews", {}, self.caller)
        second = self.server.call_tool("heel_list_reviews", {}, self.caller)
        self.assertEqual(first, second)
        self.assertEqual(
            [item["review_id"] for item in first["reviews"]],
            sorted(item["review_id"] for item in first["reviews"]),
        )

    def test_unknown_review_and_nonmatching_finding_are_not_found(self):
        unknown_id = "review_" + "0" * 20
        for name, arguments in (
            ("heel_get_review", {"review_id": unknown_id}),
            ("heel_export_review", {"review_id": unknown_id, "format": "json"}),
            ("heel_explain_finding", {
                "review_id": unknown_id, "surface_id": "surface", "risk": "risk",
            }),
        ):
            with self.subTest(name=name):
                with self.assertRaises(ToolError) as raised:
                    self.server.call_tool(name, arguments, self.caller)
                self.assertEqual(raised.exception.code, "not_found")

        review = self._review()
        with self.assertRaises(ToolError) as raised:
            self.server.call_tool("heel_explain_finding", {
                "review_id": review["review_id"],
                "surface_id": review["findings"][0]["surface_id"].swapcase(),
                "risk": review["findings"][0]["risk"],
            }, self.caller)
        self.assertEqual(raised.exception.code, "not_found")

    def test_server_rejects_missing_extra_and_wrong_typed_arguments(self):
        review_id = "review_" + "0" * 20
        invalid_calls = (
            ("heel_status", {"extra": True}),
            ("heel_review_openapi", {}),
            ("heel_review_openapi", {"openapi": []}),
            ("heel_review_openapi", {"openapi": _small_spec(), "extra": True}),
            ("heel_list_reviews", []),
            ("heel_list_reviews", {"extra": True}),
            ("heel_get_review", {}),
            ("heel_get_review", {"review_id": 1}),
            ("heel_get_review", {"review_id": review_id, "extra": True}),
            ("heel_explain_finding", {"review_id": review_id, "surface_id": "x"}),
            ("heel_explain_finding", {
                "review_id": review_id, "surface_id": 1, "risk": "x",
            }),
            ("heel_explain_finding", {
                "review_id": review_id, "surface_id": "x", "risk": "x", "extra": True,
            }),
            ("heel_export_review", {"review_id": review_id}),
            ("heel_export_review", {"review_id": review_id, "format": 1}),
            ("heel_export_review", {"review_id": review_id, "format": "html"}),
            ("heel_export_review", {
                "review_id": review_id, "format": "json", "extra": True,
            }),
        )
        for name, arguments in invalid_calls:
            with self.subTest(name=name, arguments=arguments):
                with self.assertRaises(ToolError) as raised:
                    self.server.call_tool(name, arguments, self.caller)
                self.assertEqual(raised.exception.code, "invalid_input")

    def test_oversized_canonical_openapi_payload_is_rejected(self):
        spec = _small_spec()
        spec["info"]["description"] = "x" * MAX_OPENAPI_PAYLOAD_BYTES
        self.assertGreater(len(stable_json(spec).encode("utf-8")), MAX_OPENAPI_PAYLOAD_BYTES)

        with self.assertRaises(ToolError) as raised:
            self._review(spec)

        self.assertEqual(raised.exception.code, "invalid_input")
        self.assertIn("2 MiB", str(raised.exception))
        self.assertEqual(self.projects.list_reviews(), [])

    def test_secret_import_and_store_errors_are_redacted(self):
        secret = "sk-live-1234567890abcdef"
        spec = _small_spec()
        spec["paths"]["/exports"]["get"]["example"] = secret
        with self.assertRaises(ToolError) as raised:
            self._review(spec)
        self.assertEqual(raised.exception.code, "invalid_input")
        self.assertNotIn(secret, str(raised.exception))

        with mock.patch.object(
            self.projects, "get_review", side_effect=StoredReviewError(secret)
        ):
            with self.assertRaises(ToolError) as stored:
                self.server.call_tool(
                    "heel_get_review", {"review_id": "review_" + "0" * 20}, self.caller
                )
        self.assertEqual(stored.exception.code, "invalid_input")
        self.assertNotIn(secret, str(stored.exception))
        self.assertNotIn("Traceback", str(stored.exception))

    def test_review_path_does_not_call_network_subprocess_or_legacy_orchestrator(self):
        blocked = AssertionError("review path attempted an external or active call")
        with (
            mock.patch("socket.socket", side_effect=blocked),
            mock.patch("urllib.request.urlopen", side_effect=blocked),
            mock.patch("subprocess.run", side_effect=blocked),
            mock.patch("subprocess.Popen", side_effect=blocked),
            mock.patch("heel.mcp_server.run_abuse", side_effect=blocked),
        ):
            result = self._review()
        self.assertGreater(result["summary"]["findings"], 0)

    def test_legacy_only_server_construction_does_not_touch_review_storage(self):
        legacy_store = Store()
        self.addCleanup(legacy_store.close)
        with mock.patch(
            "heel.mcp_server.LocalProjectStore",
            side_effect=AssertionError("review storage initialized eagerly"),
        ):
            legacy_server = HeelServer(legacy_store)
            scenarios = legacy_server.call_tool(
                "heel_list_scenarios", None, self.caller
            )
        self.assertTrue(scenarios["scenarios"])

    def test_review_audit_log_contains_only_identity_and_result_metadata(self):
        marker = "PRIVATE-SOURCE-SPEC-MARKER"
        route = "/private/source/route"
        spec = _small_spec()
        spec["paths"] = {
            route: {"get": {"operationId": "exportPrivate", "description": marker}},
        }
        review = self._review(spec)

        entries = self.audit.containment_log()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["action"], "review_openapi")
        self.assertEqual(entries[0]["caller"], self.caller)
        self.assertEqual(json.loads(entries[0]["detail"]), {
            "review_id": review["review_id"], "product_id": review["product_id"],
        })
        serialized = json.dumps(entries)
        self.assertNotIn(marker, serialized)
        self.assertNotIn(route, serialized)
        self.assertNotIn('"paths"', serialized)

    def test_review_tool_registry_is_versioned_strict_and_has_clear_no_upload_copy(self):
        expected_names = {
            "heel_status",
            "heel_review_openapi",
            "heel_list_reviews",
            "heel_get_review",
            "heel_explain_finding",
            "heel_export_review",
        }
        self.assertEqual(REVIEW_TOOL_NAMES, expected_names)
        self.assertTrue(expected_names <= TOOL_NAMES)
        self.assertEqual(
            [schema["name"] for schema in REVIEW_TOOL_SCHEMAS],
            [
                "heel_status",
                "heel_review_openapi",
                "heel_list_reviews",
                "heel_get_review",
                "heel_explain_finding",
                "heel_export_review",
            ],
        )
        for schema in REVIEW_TOOL_SCHEMAS:
            with self.subTest(tool=schema["name"]):
                self.assertFalse(schema["inputSchema"]["additionalProperties"])
                self.assertEqual(schema["inputSchema"]["type"], "object")
                self.assertIn("no upload", schema["description"].lower())

        by_name = {schema["name"]: schema["inputSchema"] for schema in REVIEW_TOOL_SCHEMAS}
        self.assertEqual(by_name["heel_review_openapi"]["required"], ["openapi"])
        self.assertEqual(
            by_name["heel_review_openapi"]["properties"]["openapi"]["type"], "object"
        )
        self.assertEqual(
            by_name["heel_explain_finding"]["required"],
            ["review_id", "surface_id", "risk"],
        )
        self.assertEqual(
            by_name["heel_export_review"]["properties"]["format"],
            {"type": "string", "enum": ["markdown", "json"]},
        )

    def test_json_rpc_initialize_list_and_call_round_trip_structured_content(self):
        session = {}
        initialized = handle_line(self.server, session, json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "clientInfo": {"name": "review-client", "version": "1"},
            },
        }))
        listed = handle_line(self.server, session, json.dumps({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        }))
        called = handle_line(self.server, session, json.dumps({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "heel_review_openapi", "arguments": {"openapi": _small_spec()},
            },
        }))

        self.assertEqual(initialized["result"]["serverInfo"]["name"], "heel")
        self.assertEqual(session["caller"], "mcp:review-client")
        self.assertIn("heel_review_openapi", {
            tool["name"] for tool in listed["result"]["tools"]
        })
        envelope = called["result"]["structuredContent"]
        self.assertEqual(json.loads(called["result"]["content"][0]["text"]), envelope)
        self.assertGreater(envelope["summary"]["findings"], 0)

    def test_actual_stdio_server_uses_one_heel_home_and_saves_the_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve(strict=True)
            requests = [
                {
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "clientInfo": {"name": "stdio-smoke", "version": "1"},
                    },
                },
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                {
                    "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {
                        "name": "heel_review_openapi",
                        "arguments": {"openapi": _small_spec()},
                    },
                },
            ]
            env = os.environ.copy()
            env["HEEL_HOME"] = str(home)
            completed = subprocess.run(
                [sys.executable, "-m", "heel.mcp_server"],
                cwd=ROOT,
                env=env,
                input="".join(json.dumps(request) + "\n" for request in requests),
                text=True,
                capture_output=True,
                timeout=30,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            responses = [json.loads(line) for line in completed.stdout.splitlines()]
            self.assertEqual([response["id"] for response in responses], [1, 2, 3])
            self.assertIn("heel_review_openapi", {
                tool["name"] for tool in responses[1]["result"]["tools"]
            })
            review = responses[2]["result"]["structuredContent"]
            self.assertTrue((home / "heel.db").is_file())
            self.assertTrue(
                (home / "reviews" / f"{review['review_id']}.json").is_file()
            )

    def test_forged_scope_mutation_remains_absent_rejected_and_logged(self):
        for name in (
            "heel_create_scope", "heel_widen_scope", "heel_add_target", "heel_set_limits",
        ):
            self.assertNotIn(name, TOOL_NAMES)

        with self.assertRaises(ToolError) as raised:
            self.server.call_tool(
                "heel_widen_scope", {"target": "prod.example"}, self.caller
            )
        self.assertEqual(raised.exception.code, "unknown_tool")
        entries = self.audit.containment_log()
        self.assertEqual(entries[-1]["action"], "reject_unknown_tool")
        self.assertEqual(entries[-1]["caller"], self.caller)


if __name__ == "__main__":
    unittest.main()
