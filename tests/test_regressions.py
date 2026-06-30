import copy
import io
import json
import os
from contextlib import redirect_stdout
from dataclasses import replace
import tempfile
import unittest

os.environ["HEEL_HOME"] = tempfile.mkdtemp()

from heel import cli  # noqa: E402
from heel import scope as scopemod  # noqa: E402
from heel.mcp_server import HeelServer, ToolError  # noqa: E402
from heel.regressions import add_regression_from_finding, run_regressions  # noqa: E402
from heel.store import Store  # noqa: E402
from heel.targets import clear_imported_targets, get_target, register_imported_target  # noqa: E402


class RegressionBase(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.environ["HEEL_HOME"] = self.home
        self.store = Store(os.path.join(self.home, "heel.db"))
        self.server = HeelServer(self.store)
        self.caller = "test-regression-agent"
        self.scope = scopemod.create_scope(["synthetic-saas", "hardened-saas"], operator="tester")
        self.run_id = self.server.heel_run(
            {"scope_id": self.scope.scope_id, "target": "synthetic-saas", "scenario_ids": ["sc.trial.serial"],
             "agent_classes": ["adversarial"]},
            self.caller,
        )["run_id"]
        self.vector = next(
            f for f in self.server.heel_get_findings({"run_id": self.run_id}, self.caller)["findings"]
            if f["affordance_id"] == "trial_signup"
        )

    def tearDown(self):
        clear_imported_targets()
        self.store.close()

    def add_trial_regression(self):
        return add_regression_from_finding(
            self.store,
            run_id=self.run_id,
            vector_id=self.vector["id"],
            name="free_trial_serial_signup",
        )

    def register_hardened_target(self):
        base = get_target("synthetic-saas")
        affs = []
        for aff in copy.deepcopy(base.affordances):
            if aff.id == "trial_signup":
                props = dict(aff.properties)
                props["identity_check"] = "strong"
                aff = replace(aff, properties=props, guard_present=True, planted_weakness=None, true_severity=None)
            affs.append(aff)
        hardened = replace(base, id="hardened-saas", affordances=affs, planted_vectors=[],
                           description="Synthetic SaaS with serial-trial control hardened.")
        hardened.requires_scope = True
        hardened.safety_metadata = {"scope_required": True, "live_probing_disabled": True}
        register_imported_target(hardened)
        return hardened


class TestAbuseRegressions(RegressionBase):
    def test_add_regression_from_finding(self):
        reg = self.add_trial_regression()

        self.assertEqual(reg["name"], "free_trial_serial_signup")
        self.assertEqual(reg["original_vector_id"], self.vector["id"])
        self.assertEqual(reg["scenario_id"], "sc.trial.serial")
        self.assertEqual(reg["source_run_id"], self.run_id)
        self.assertEqual(reg["expected_status"], "blocked")
        self.assertEqual(reg["target_affordance_pattern"]["affordance_id"], "trial_signup")
        self.assertEqual(reg["success_criterion"], {"prop": "identity_check", "equals": "email_only"})
        self.assertEqual(reg["recommended_control"], "device/identity fingerprinting + trial-per-identity limit")
        self.assertTrue(reg["safety_flags"]["canary_only"])
        self.assertTrue(reg["safety_flags"]["contained"])
        self.assertNotIn("reproduction", reg)

    def test_list_regression(self):
        reg = self.add_trial_regression()

        listed = self.store.list_regressions()

        self.assertEqual([r["regression_id"] for r in listed], [reg["regression_id"]])
        self.assertEqual(listed[0]["name"], "free_trial_serial_signup")

    def test_rerun_regression_against_same_synthetic_target_still_finds_it(self):
        self.add_trial_regression()

        results = run_regressions(
            self.store,
            self.server,
            scope_id=self.scope.scope_id,
            target="synthetic-saas",
            caller=self.caller,
        )

        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertTrue(result["previously_reachable"])
        self.assertEqual(result["current_status"], "still_reachable")
        self.assertEqual(result["control_likely"], "absent")
        self.assertIn("canary-only finding", result["evidence_summary"])
        self.assertNotIn("enumerate", result["evidence_summary"])
        self.assertNotIn("probe", result["evidence_summary"])

    def test_rerun_regression_against_hardened_fixture_reports_blocked(self):
        self.add_trial_regression()
        self.register_hardened_target()

        results = run_regressions(
            self.store,
            self.server,
            scope_id=self.scope.scope_id,
            target="hardened-saas",
            caller=self.caller,
        )

        self.assertEqual(results[0]["current_status"], "blocked")
        self.assertEqual(results[0]["control_likely"], "present")
        self.assertIn("No canary-only finding", results[0]["evidence_summary"])

    def test_regression_run_is_logged(self):
        self.add_trial_regression()

        result = run_regressions(
            self.store,
            self.server,
            scope_id=self.scope.scope_id,
            target="synthetic-saas",
            caller=self.caller,
        )[0]

        actions = [e["action"] for e in self.store.containment_log(result["run_id"])]
        self.assertIn("run_start", actions)
        self.assertIn("regression_result", actions)
        persisted = self.store.list_regression_results()
        self.assertEqual(persisted[0]["regression_id"], result["regression_id"])

    def test_no_regression_command_can_create_or_widen_scope(self):
        self.add_trial_regression()
        scope_path = os.path.join(scopemod.heel_home(), "scopes", self.scope.scope_id + ".json")
        with open(scope_path) as fh:
            before = json.load(fh)

        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.main(["regress", "run", "--scope", "scope-forged", "--target", "synthetic-saas"])

        with open(scope_path) as fh:
            after = json.load(fh)
        self.assertEqual(rc, 1)
        self.assertIn("REJECTED", out.getvalue())
        self.assertEqual(after["target_allowlist"], before["target_allowlist"])
        self.assertEqual(after["signature"], before["signature"])
        self.assertIsNone(scopemod.get_scope("scope-forged"))

    def test_cli_list_and_export_json(self):
        self.add_trial_regression()

        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main(["regress", "list"]), 0)
        listed = json.loads(out.getvalue())
        self.assertEqual(listed["regressions"][0]["name"], "free_trial_serial_signup")

        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main(["regress", "export", "--format", "json"]), 0)
        exported = json.loads(out.getvalue())
        self.assertEqual(exported["regressions"][0]["original_vector_id"], self.vector["id"])

    def test_missing_scope_is_rejected_instead_of_created(self):
        self.add_trial_regression()

        with self.assertRaises(ToolError):
            run_regressions(
                self.store,
                self.server,
                scope_id="scope-missing",
                target="synthetic-saas",
                caller=self.caller,
            )

    def test_discovered_finding_can_be_saved_as_regression(self):
        run_id = self.server.heel_run(
            {"scope_id": self.scope.scope_id, "target": "synthetic-saas", "agent_classes": ["adversarial"]},
            self.caller,
        )["run_id"]
        vector = next(
            f for f in self.server.heel_get_findings({"run_id": run_id}, self.caller)["findings"]
            if f["scenario_id"].startswith("sc.discovered.")
        )

        reg = add_regression_from_finding(
            self.store,
            run_id=run_id,
            vector_id=vector["id"],
            name="discovered_missing_control",
        )
        result = run_regressions(
            self.store,
            self.server,
            scope_id=self.scope.scope_id,
            target="synthetic-saas",
            caller=self.caller,
            regression_ids=[reg["regression_id"]],
        )[0]

        self.assertEqual(reg["scenario_id"], vector["scenario_id"])
        self.assertEqual(reg["success_criterion"]["observed"], vector["reproduction"]["observed"])
        self.assertEqual(result["current_status"], "still_reachable")
