"""
HEEL — persistence (spec §11: SQLite, Postgres-ready). Pure stdlib via sqlite3.

Stores runs, findings, and the immutable containment log. The containment table is
append-only with a per-entry hash chain (containment.py) so the audit trail is tamper-evident.
"""
from __future__ import annotations

import json
import sqlite3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(
  run_id TEXT PRIMARY KEY, scope_id TEXT, target TEXT, caller TEXT, status TEXT,
  ts REAL, error TEXT, coverage TEXT);
CREATE TABLE IF NOT EXISTS findings(
  run_id TEXT, vector_id TEXT, category TEXT, severity REAL, plausible INTEGER, json TEXT);
CREATE TABLE IF NOT EXISTS containment(
  seq INTEGER, ts REAL, run_id TEXT, caller TEXT, action TEXT, detail TEXT,
  prev_hash TEXT, entry_hash TEXT);
CREATE TABLE IF NOT EXISTS regressions(
  regression_id TEXT PRIMARY KEY, name TEXT, original_vector_id TEXT, scenario_id TEXT,
  target_affordance_pattern TEXT, success_criterion TEXT, recommended_control TEXT,
  expected_status TEXT, created_at REAL, source_run_id TEXT, safety_flags TEXT, json TEXT);
CREATE TABLE IF NOT EXISTS regression_results(
  regression_id TEXT, run_id TEXT, scope_id TEXT, target TEXT, status TEXT, created_at REAL, json TEXT);
CREATE INDEX IF NOT EXISTS idx_find_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_cont_run ON containment(run_id);
CREATE INDEX IF NOT EXISTS idx_reg_result_reg ON regression_results(regression_id);
"""


class Store:
    def __init__(self, path: str = ":memory:"):
        # check_same_thread=False: the REST/MCP servers may handle requests on worker threads
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)

    def add_run(self, run_id, scope_id, target, caller, status, ts, error=None, coverage=None):
        self.conn.execute("INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?,?)",
                          (run_id, scope_id, target, caller, status, ts, error,
                           json.dumps(coverage) if coverage else None))
        self.conn.commit()

    def set_run_status(self, run_id, status, coverage=None, error=None):
        self.conn.execute("UPDATE runs SET status=?, coverage=COALESCE(?,coverage), error=COALESCE(?,error) WHERE run_id=?",
                          (status, json.dumps(coverage) if coverage else None, error, run_id))
        self.conn.commit()

    def get_run(self, run_id):
        return self.conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()

    def scope_run_count(self, scope_id):
        return self.conn.execute("SELECT COUNT(*) FROM runs WHERE scope_id=?", (scope_id,)).fetchone()[0]

    def add_finding(self, run_id, v):
        from dataclasses import asdict
        d = asdict(v); d["category"] = v.category.value
        d["verification_status"] = v.verification_status.value
        self.conn.execute("INSERT INTO findings VALUES (?,?,?,?,?,?)",
                          (run_id, v.id, v.category.value, v.severity.score, int(v.plausible), json.dumps(d, default=str)))
        self.conn.commit()

    def get_findings(self, run_id):
        return [json.loads(r["json"]) for r in
                self.conn.execute("SELECT json FROM findings WHERE run_id=? ORDER BY severity DESC", (run_id,)).fetchall()]

    def find_vector(self, vector_id, run_id=None):
        if run_id is not None:
            r = self.conn.execute("SELECT json FROM findings WHERE vector_id=? AND run_id=? LIMIT 1",
                                  (vector_id, run_id)).fetchone()
        else:
            r = self.conn.execute("SELECT json FROM findings WHERE vector_id=? LIMIT 1", (vector_id,)).fetchone()
        return json.loads(r["json"]) if r else None

    def add_regression(self, regression):
        self.conn.execute(
            "INSERT OR REPLACE INTO regressions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                regression["regression_id"],
                regression["name"],
                regression["original_vector_id"],
                regression["scenario_id"],
                json.dumps(regression["target_affordance_pattern"], sort_keys=True, default=str),
                json.dumps(regression["success_criterion"], sort_keys=True, default=str),
                regression["recommended_control"],
                regression["expected_status"],
                regression["created_at"],
                regression["source_run_id"],
                json.dumps(regression["safety_flags"], sort_keys=True, default=str),
                json.dumps(regression, sort_keys=True, default=str),
            ),
        )
        self.conn.commit()

    def get_regression(self, regression_id):
        r = self.conn.execute("SELECT json FROM regressions WHERE regression_id=?", (regression_id,)).fetchone()
        return json.loads(r["json"]) if r else None

    def list_regressions(self):
        rows = self.conn.execute("SELECT json FROM regressions ORDER BY created_at, regression_id").fetchall()
        return [json.loads(r["json"]) for r in rows]

    def add_regression_result(self, result):
        self.conn.execute(
            "INSERT INTO regression_results VALUES (?,?,?,?,?,?,?)",
            (
                result["regression_id"],
                result["run_id"],
                result["scope_id"],
                result["target"],
                result["current_status"],
                result["created_at"],
                json.dumps(result, sort_keys=True, default=str),
            ),
        )
        self.conn.commit()

    def list_regression_results(self, regression_id=None):
        if regression_id:
            rows = self.conn.execute(
                "SELECT json FROM regression_results WHERE regression_id=? ORDER BY created_at",
                (regression_id,),
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT json FROM regression_results ORDER BY created_at").fetchall()
        return [json.loads(r["json"]) for r in rows]

    def add_containment(self, e):
        self.conn.execute("INSERT INTO containment VALUES (?,?,?,?,?,?,?,?)",
                          (e.seq, e.ts, e.run_id, e.caller_identity, e.action,
                           json.dumps(e.detail, default=str), e.prev_hash, e.entry_hash))
        self.conn.commit()

    def last_containment(self):
        return self.conn.execute("SELECT * FROM containment ORDER BY seq DESC LIMIT 1").fetchone()

    def containment_log(self, run_id=None):
        if run_id:
            rows = self.conn.execute("SELECT * FROM containment WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM containment ORDER BY seq").fetchall()
        return [dict(r) for r in rows]

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

    def __del__(self):
        self.close()
