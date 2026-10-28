"""H0B: the real closed host ingress (nginx + njs/qjs policy) between Worker/runners and the CP.

Static cases always run. Dynamic cases (G0-G9) need the fixed ``scripts/host_ingress_proof.py``
launcher: it builds the pinned runtime privately and runs this module inside isolated Linux
namespaces with ``HEEL_REQUIRE_HOST_INGRESS=1``. Under that switch a missing platform, runtime or
namespace capability fails; outside it the dynamic cases skip (the ordinary suite never claims
ingress proof). Every dynamic case records a fixed case name, safe status/reason, whether the
control plane was contacted and whether runner state changed -- never bodies or credentials.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import unicodedata
from pathlib import Path

import pytest

from tests.support import host_ingress_harness as harness

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = os.environ.get(harness.REQUIRED_ENV) == "1"
POLICY = ROOT / "deploy" / "host" / "ingress" / "policy.js"
TEMPLATE = ROOT / "deploy" / "host" / "ingress" / "nginx.conf"
LOCK = ROOT / "deploy" / "host" / "ingress" / "runtime-lock.json"


# ---------------------------------------------------------------------------------------------
# Static source/config gates (run everywhere).

def test_static_nfc_tables_are_regenerated_exactly_from_the_pinned_unicodedata():
    if unicodedata.unidata_version != harness.NFC_UNICODE_VERSION:
        if REQUIRED:
            pytest.fail("the required profile must run the pinned Python unicodedata version")
        pytest.skip(f"NFC tables are pinned to unicodedata {harness.NFC_UNICODE_VERSION}")
    assert harness.embedded_nfc_block(POLICY.read_text(encoding="utf-8")) == harness.nfc_table_block()


def test_static_policy_never_depends_on_runtime_normalize_or_dynamic_code():
    source = POLICY.read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", source)
    for forbidden in (".normalize(", "eval(", "new Function", "ngx.fetch", "internalRedirect", "readRequestText",
                      "readRequestJSON", "headersIn[", "$http_", "require("):
        assert forbidden not in code, forbidden


def test_static_required_profile_cannot_skip():
    """Only two guarded skip paths exist, both unreachable when HEEL_REQUIRE_HOST_INGRESS=1."""
    module = Path(__file__).read_text(encoding="utf-8")
    harness_source = (ROOT / "tests" / "support" / "host_ingress_harness.py").read_text(encoding="utf-8")
    assert "xfail" not in module.replace('"xfail"', "") and "xfail" not in harness_source
    calls = re.findall(r"^\s+pytest\.skip\(", module, re.M)
    assert len(calls) == 2 and len(re.findall(r"^\s+pytest\.skip\(", harness_source, re.M)) == 1
    assert "if REQUIRED:\n            pytest.fail(reason)\n        pytest.skip(reason)" in module
    assert 'if os.environ.get(REQUIRED_ENV) == "1":\n        pytest.fail(' in harness_source
    assert ("importor" + "skip") not in module and ("skip" + "if") not in module


def _code(source: str) -> str:
    return re.sub(r"//[^\n]*", "", source)


def _function(source: str, name: str) -> str:
    head = r"^(?:async )?function " + name + r"\("
    match = re.search(head + r"[^\n]*\}\n|" + head + r".*?^\}\n", source, re.M | re.S)
    assert match is not None, name
    return match.group(0)


def test_static_policy_has_no_race_and_never_clears_a_fired_timer():
    """H0BTD: clearing a timer from its own firing callback (or a microtask it runs) deletes the
    njs 1.0.2 timer event twice and kills the worker. Only settle() may clear, and only unfired.
    H0BR3: a re-arm replaces d.id before its callback returns, the final refusal keeps the reviewed
    order, and an unusable start refuses before anything is armed. Behaviour: the G0 deadline cases."""
    code = _code(POLICY.read_text(encoding="utf-8"))
    assert "Promise.race" not in code and not re.search(r"\brace\(", code)
    settle = _function(code, "settle")
    assert settle == "function settle(d) { if (!d.fired) d.env.cancel(d.id); return d.fired; }\n"
    runtime = code[code.index("const DEADLINE_RUNTIME = {"):]
    assert runtime[:runtime.index("};\n") + 3] == (
        "const DEADLINE_RUNTIME = {\n    now: () => Date.now(),\n    arm: (callback, ms) => setTimeout(callback, ms),\n"
        "    cancel: (id) => clearTimeout(id),\n    count: count,\n    refuse: sendRefusal,\n};\n")
    assert code.count("clearTimeout(") == 1 and code.count("setTimeout(") == 1 and code.count(".cancel(") == 1
    assert _function(code, "deadline") == ("function deadline(r, origin, budget, status, reason) "
                                           "{ return deadlineWith(DEADLINE_RUNTIME, r, origin, budget, status, reason); }\n")
    core = _function(code, "deadlineWith")
    assert core.count("env.arm(") == 3  # the wake-up, the one re-arm site and the zero-delay kick
    assert core.index("refuse(status, reason);") < core.index("const fire = () => {") < core.index("d.id = env.arm(fire, start[1]);")
    rearm = core[core.index("if (plan[0] === 'rearm') {"):core.index("d.fired = true;")]
    assert rearm.index("d.id = env.arm(fire, plan[1]);") < rearm.index("return;")
    final = core[core.index("d.fired = true;"):]
    for required in ("env.count('expired:' + reason);", "env.refuse(r, status, reason);", "env.arm(() => {}, 0);",
                     "throw new Error('deadline');"):
        assert required in final, required
    assert final.index("env.refuse(") < final.index("env.arm(() => {}, 0);") < final.index("throw new Error('deadline');")
    for handler, status in (("runnerAccess", 408), ("managementAccess", 408), ("runnerContent", 504)):
        body = _function(code, handler)
        assert body.startswith("async function"), handler
        assert body.count("deadline(r, ") == 1 and f", {status}, " in body, handler
        assert re.search(r"finally \{ if \(settle\(d\)\) return; \}", body), handler
        assert body.index("deadline(r, ") < body.index("await r."), handler
    assert "deadline(r, started, BODY_READ_MS, 408, 'body_timeout')" in _function(code, "runnerAccess")
    assert "deadline(r, started, BODY_READ_MS, 408, 'body_timeout')" in _function(code, "managementAccess")
    content = _function(code, "runnerContent")
    assert "deadline(r, started, TOTAL_BUDGET_MS, 504, 'timeout')" in content
    assert content.index("deadline(r, started,") < content.index("r.variables.heel_state = 'dispatch';")
    assert "const started = /^[1-9][0-9]{0,15}$/.test(t0) ? Number(t0) : NaN;" in content and "remaining" not in content
    assert "msec" not in code  # no cross-clock compensation from nginx's cached $msec
    assert "const BODY_READ_MS = 10000;" in code and "const TOTAL_BUDGET_MS = 25000;" in code
    assert "const DEADLINE_SLACK_MS = 500;" in code and round(SLACK_S * 1000) == 500
    assert "const DEADLINE_REARMS_MAX = 8;" in code


def _launcher():
    import importlib.util

    spec = importlib.util.spec_from_file_location("host_ingress_proof", ROOT / "scripts" / "host_ingress_proof.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_static_launcher_requires_every_case_function_in_this_module():
    names = re.findall(r"^def (test_[a-z0-9_]+)\(", Path(__file__).read_text(encoding="utf-8"), re.M)
    assert len(names) == len(set(names))
    assert tuple(sorted(_launcher().REQUIRED_CASES)) == tuple(sorted(names))


def test_static_launcher_has_one_fixed_profile_and_fixed_budgets():
    launcher = _launcher()
    source = (ROOT / "scripts" / "host_ingress_proof.py").read_text(encoding="utf-8")
    assert launcher.main(["--anything"]) == 2
    assert "argparse" not in source and "sys.argv[1:]" in source and source.count("sys.argv") == 1
    assert launcher.TESTS_SECONDS == 720 and launcher.LAUNCHER_SECONDS == 1200  # <=12 min tests, <=20 min launcher
    lock = launcher.load_lock(LOCK)
    assert lock["budgets"] == {"launcher_seconds": 1200, "tests_seconds": 720, "job_minutes": 30}
    assert '"HEEL_REQUIRE_HOST_INGRESS": "1"' in source and f'TEST_MODULE = "{Path(__file__).relative_to(ROOT)}"' in source
    assert "shell=True" not in source and "os.system" not in source
    assert launcher.ARTIFACT_FILES == ("summary.json", "cases.jsonl", "versions.txt", "cleanup.json", "report.txt",
                                       "build-manifest.json")


def test_static_launcher_evidence_is_fixed_fields_and_canary_scanned(tmp_path):
    launcher = _launcher()
    raw = tmp_path / "cases.raw.jsonl"
    raw.write_text("\n".join([
        json.dumps({"case": "g8.dribble_body", "gate": "G8", "status": 408, "reasons": ["expired:body_timeout", "Bearer x"],
                    "cp_contacted": False, "changed_tables": ["canary_runs", "x y"], "seam": None}),
        json.dumps({"case": "g8.x", "gate": "G8", "body": "secret"}),
        json.dumps({"case": "../escape", "gate": "G8"}),
    ]) + "\n")
    assert launcher.sanitize_cases(raw) == [{"case": "g8.dribble_body", "gate": "G8", "status": 408, "cp_contacted": False,
                                             "reasons": ["expired:body_timeout"], "changed_tables": ["canary_runs"], "seam": None}]
    out = tmp_path / "artifacts"
    out.mkdir()
    canary = "edge-" + "q" * 40
    (out / "summary.json").write_text('{"result": "FAIL"}\n')
    (out / "report.txt").write_text("failing " + canary + "\n")
    (out / "cases.jsonl").write_text("-----BEGIN PRIVATE KEY-----\n")
    assert launcher.canary_scan(out, [canary]) == ["cases.jsonl", "report.txt"]
    junit = tmp_path / "junit.xml"
    junit.write_text('<testsuite><testcase name="test_g0_a"/><testcase name="test_g8_b[x]"><skipped/></testcase>'
                     '<testcase name="test_g9_c"><failure/></testcase></testsuite>')
    summary = launcher.summarize_junit(junit)
    assert (summary["collected"], summary["passed"], summary["skipped"], summary["failed"]) == (3, 1, 1, 1)
    assert summary["failing"] == ["test_g8_b", "test_g9_c"]
    assert launcher.summarize_junit(tmp_path / "absent.xml")["collected"] == 0


def test_static_runtime_lock_pins_the_reviewed_runtime_and_records_its_lifecycle_dependency():
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    sources = {item["name"]: item for item in lock["sources"]}
    assert (sources["nginx"]["version"], sources["njs"]["version"], sources["quickjs"]["version"]) == ("1.30.6", "1.0.2", "2026-06-04")
    assert sources["njs"]["commit"] == "72e6a980b9bf2a28ae2d568bbc3b6830a5d7c39e"
    assert sources["nginx"]["sha256"] == "3cf46f5ed7504d460125866b7bea99fb357f31d887e2e63b35503310e9b8b6c8"
    assert sources["njs"]["sha256"] == "93043e263131feadfd664356b989d86aa009a0e453e33c246ee08e39d96ca45c"
    assert lock["build"]["expected_njs_engine"] == "qjs"
    (actionlint,) = lock["tools"]
    assert (actionlint["name"], actionlint["version"]) == ("actionlint", "1.7.8")
    assert actionlint["sha256"] == "be92c2652ab7b6d08425428797ceabeb16e31a781c07bc388456b4e592f3e36a"
    notes = " ".join(lock["notes"])
    for required in ("njs 1.0.2", "clearTimeout", "zero-delay", "NGX_ERROR", "re-run", "Linux"):
        assert required in notes, required
    doc = (ROOT / "docs" / "saas" / "HOST_INGRESS_PROOF.md").read_text(encoding="utf-8")
    for required in ("deadline(", "settle(", "njs 1.0.2", "never clear", "Linux", "HEEL_REQUIRE_HOST_INGRESS=1"):
        assert required.lower() in doc.lower(), required



def test_static_fake_vpc_adapter_block_is_pinned_by_both_suites():
    digest = hashlib.sha256(harness.adapter_block().encode("utf-8")).hexdigest()
    app_test = (ROOT / "apps" / "heel-cloud" / "tests" / "host-ingress.test.ts").read_text(encoding="utf-8")
    assert f'const ADAPTER_BLOCK_SHA256 = "{digest}";' in app_test
    assert '"../../tests/support/host_ingress_harness.py"' in app_test


def _render_values(**overrides) -> dict[str, str]:
    values = {
        "STATE_DIR": "/tmp/state", "POLICY_DIR": "/tmp/policy", "REGISTRY_PATH": "/tmp/registry.json",
        "CERT_PATH": "/tmp/cert.pem", "KEY_PATH": "/tmp/key.pem", "REGISTRY_OWNER_UID": "0", "BOOT_EPOCH": "boot-0123abcd",
        "PUBLIC_HOST": harness.HOST, "BACKEND_ADDRESS": "10.0.0.1", "BACKEND_PORT": "8080", "MANAGEMENT_ADDRESS": "10.0.0.2",
        "MANAGEMENT_PORT": "8443", "MANAGEMENT_PEER": "10.0.0.3", "EDGE_SECRET": "e" * 43, "OPS_PORT": "9901",
    }
    values.update(overrides)
    return values


def _render_slots(count: int = 2) -> list[dict[str, str]]:
    return [{"SLOT_ID": f"slot-{index}", "SLOT_ADDRESS": f"10.1.{index}.1", "SLOT_PORT": "443", "SLOT_PEER": f"10.1.{index}.2"}
            for index in range(count)]


def test_static_renderer_substitutes_only_reviewed_tokens_from_closed_grammars():
    template = TEMPLATE.read_text(encoding="utf-8")
    rendered = harness.render_nginx_config(template, _render_values(), _render_slots())
    assert "@@" not in rendered and rendered.count("js_access policy.runnerAccess;") == 2
    assert rendered.count('"10.1.0.1:443" "slot:slot-0";') == 1 and rendered.count('"10.1.1.1:443" "slot:slot-1";') == 1
    assert "e" * 43 not in harness.config_digest(rendered, "e" * 43)
    refused = [
        (_render_values(EDGE_SECRET="e" * 43 + ";\n    proxy_pass http://203.0.113.9"), _render_slots()),
        (_render_values(PUBLIC_HOST="attacker.invalid"), _render_slots()),
        (_render_values(BACKEND_ADDRESS="backend.invalid"), _render_slots()),
        (_render_values(STATE_DIR="/tmp/state dir"), _render_slots()),
        (_render_values(EXTRA="1"), _render_slots()),
        (_render_values(), []),
        (_render_values(), _render_slots(21)),
        (_render_values(), [{**_render_slots(1)[0], "SLOT_ID": "slot;x"}]),
    ]
    for values, slots in refused:
        with pytest.raises(harness.RenderError):
            harness.render_nginx_config(template, values, slots)
    for broken in (template.replace("# END SLOT SERVER\n", ""), template + "\nlisten @@UNREVIEWED@@;\n"):
        with pytest.raises(harness.RenderError):
            harness.render_nginx_config(broken, _render_values(), _render_slots())


def test_static_nginx_template_keeps_the_reviewed_limits_and_literal_backend():
    template = TEMPLATE.read_text(encoding="utf-8")
    code = re.sub(r"#[^\n]*", "", template)
    for line in ("worker_processes 1;", "error_log /dev/null crit;", "access_log off;", "keepalive_requests 1;",
                 "client_header_timeout 10s;", "client_body_timeout 11s;", "client_max_body_size 278528;",
                 "js_engine qjs;", "js_context_reuse 0;", "limit_conn heel_listeners 32;", "limit_conn heel_listeners 8;",
                 "proxy_next_upstream off;", "proxy_max_temp_file_size 0;", "proxy_pass_request_headers off;",
                 "proxy_connect_timeout 2s;", "proxy_read_timeout 10s;", "ssl_reject_handshake on;",
                 "proxy_pass http://@@BACKEND_ADDRESS@@:@@BACKEND_PORT@@/;", "proxy_pass http://@@BACKEND_ADDRESS@@:@@BACKEND_PORT@@;"):
        assert line in code, line
    for forbidden in ("$http_", "$host", "resolver", "$request_body", "proxy_pass $", "X-Forwarded", "real_ip", "rewrite ",
                      "return 30", "gzip on", "http2", "add_header"):
        assert forbidden not in code, forbidden
    assert code.count("proxy_pass ") == 2 and code.count("internal;") == 2

WORKFLOW = ROOT / ".github" / "workflows" / "codeql.yml"


def _job(text: str, name: str) -> str:
    match = re.search(r"^  " + re.escape(name) + r":\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text, re.M | re.S)
    assert match is not None, name
    return match.group(1)


def test_static_workflow_proof_job_is_manual_reviewed_ref_read_only_and_pinned():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "\npermissions: {}\n" in text and "pull_request_target" not in text and "secrets." not in text
    assert "inputs:" not in text and "workflow_dispatch: {}" in text
    for uses in re.findall(r"uses: (\S+)", text):
        assert re.fullmatch(r"[a-z-]+/[a-z-]+(?:/[a-z-]+)?@[0-9a-f]{40}", uses), uses
    analyzer = _job(text, "analyze")
    assert "security-events: write" in analyzer and "queries: security-extended" in analyzer and "languages: python" in analyzer
    proof = _job(text, "host-ingress-proof")
    assert ("if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/codex/self-serve-host-ingress-proof'"
            in proof)
    assert re.search(r"permissions:\n      contents: read\n    concurrency:", proof)
    assert "write" not in proof and "id-token" not in proof and "environment:" not in proof and "cache" not in proof
    assert "timeout-minutes: 30" in proof and "timeout-minutes: 20" in proof
    assert "ref: ${{ github.sha }}" in proof and "persist-credentials: false" in proof
    assert re.findall(r"^\s+run: (.+)$", proof, re.M) == ["python scripts/host_ingress_proof.py"]
    uploads = re.findall(r"^\s+host-ingress-proof/(\S+)$", proof, re.M)
    assert tuple(uploads) == _launcher().ARTIFACT_FILES
    assert "retention-days: 3" in proof and "if-no-files-found: error" in proof


def _root_reads(source: str) -> set[str]:
    """Every string-literal path joined onto ROOT in ``source``."""
    return {"/".join(re.findall(r'"([^"\n]+)"', chain)) for chain in re.findall(r'ROOT((?:\s*/\s*"[^"\n]+")+)', source)}


def test_static_launcher_stages_every_path_the_proof_module_reads(tmp_path):
    """H0BL section 3: the launcher stages a fixed allowlist of tracked files. Everything this module
    and the harness read under ROOT, and every proof file, must be inside it, and the static selection
    must pass from an exact launcher-staged copy (not only from the full checkout)."""
    launcher = _launcher()
    reads = _root_reads(Path(__file__).read_text(encoding="utf-8")) | _root_reads(
        (ROOT / "tests" / "support" / "host_ingress_harness.py").read_text(encoding="utf-8"))
    reads.discard(".git")  # only probed below, to tell the checkout from the staged copy
    assert {"scripts/host_ingress_proof.py", ".github/workflows/codeql.yml", "docs/saas/HOST_INGRESS_PROOF.md",
            "apps/heel-cloud/tests/host-ingress.test.ts", "deploy/host/ingress/policy.js"} <= reads
    needed = sorted(reads | set(launcher.PROOF_PATHS))
    assert [path for path in needed if not any(path == prefix or path.startswith(prefix + "/")
                                               for prefix in launcher.STAGE_PATHS)] == []
    if not (ROOT / ".git").exists():
        # This is the launcher's staged copy: every path the module reads is present in it.
        assert [path for path in needed if not (ROOT / path).exists()] == []
        return
    source = launcher.stage_tree(tmp_path)
    tracked = subprocess.run(["git", "ls-files", "-z", "--", *launcher.STAGE_PATHS], cwd=ROOT, capture_output=True,
                             check=True).stdout
    staged = sorted(str(path.relative_to(source)) for path in source.rglob("*") if path.is_file())
    assert staged == sorted(name for name in tracked.decode().split("\0") if name)
    assert [path for path in needed if not (source / path).exists()] == []
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider", "-k", "static", launcher.TEST_MODULE], cwd=source, capture_output=True, text=True, timeout=600,
        env={"PATH": launcher.FIXED_PATH, "LC_ALL": "C", "HOME": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1"})
    assert completed.returncode == 0, completed.stdout[-4000:]
    # The child is this interpreter: its unicodedata decides the one legitimate skip (the NFC case).
    lines = completed.stdout.splitlines()
    cases = len([case for case in launcher.REQUIRED_CASES if case.startswith("test_static_")])
    skips = [line for line in lines if line.startswith("SKIPPED")]
    if unicodedata.unidata_version == harness.NFC_UNICODE_VERSION:
        expected = f"{cases} passed, "
        assert skips == [], completed.stdout[-400:]
    else:
        expected = f"{cases - 1} passed, 1 skipped, "
        nfc = test_static_nfc_tables_are_regenerated_exactly_from_the_pinned_unicodedata.__code__
        module_lines = Path(__file__).read_text(encoding="utf-8").splitlines()
        skip_lines = [number for number in sorted({line for *_, line in nfc.co_lines() if line is not None})
                      if module_lines[number - 1].strip().startswith("pytest.skip(")]
        assert len(skip_lines) == 1
        assert skips == [f"SKIPPED [1] tests/test_host_ingress.py:{skip_lines[0]}: NFC tables are pinned to "
                         f"unicodedata {harness.NFC_UNICODE_VERSION}"], completed.stdout[-400:]
    assert re.fullmatch(re.escape(expected) + r"[0-9]+ deselected in [0-9]+\.[0-9]+s( \([0-9]+:[0-9]{2}:[0-9]{2}\))?",
                        lines[-1]), completed.stdout[-400:]


IPTABLES_SAMPLE = """# Generated by iptables-nft-save v1.8.10 (nf_tables) on Wed Oct 21 02:47:20 2026
*filter
:INPUT ACCEPT [1203:88112]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [998:120334]
:DOCKER - [0:0]
-A FORWARD -j DOCKER-USER
-A DOCKER -i docker0 -j RETURN
COMMIT
# Completed on Wed Oct 21 02:47:20 2026
"""
NFT_SAMPLE = """table ip filter {
\tchain FORWARD {
\t\ttype filter hook forward priority filter; policy drop;
\t\tcounter packets 4410 bytes 381220 jump DOCKER-USER
\t\tiifname "docker0" counter packets 0 bytes 0 accept
\t}
}
"""


def test_static_fingerprint_normaliser_strips_timestamps_and_counters():
    """H0BL section 4: only iptables-save's dated header/trailer comments and chain packet/byte
    counters are volatile; nft runs stateless. Policies, rules and every other line are kept."""
    launcher = _launcher()
    assert launcher.FINGERPRINT_COMMANDS["nft"] == ("nft", "-s", "list", "ruleset")
    assert launcher.FINGERPRINT_COMMANDS["iptables"] == ("iptables-save",)
    later = (IPTABLES_SAMPLE.replace("02:47:20", "02:58:01").replace("[1203:88112]", "[1999:140000]")
             .replace("[998:120334]", "[1500:190001]"))
    normal = launcher.normalize_fingerprint_output("iptables", IPTABLES_SAMPLE)
    assert normal == launcher.normalize_fingerprint_output("iptables", later)
    assert normal == ("*filter\n:INPUT ACCEPT [-:-]\n:FORWARD DROP [-:-]\n:OUTPUT ACCEPT [-:-]\n:DOCKER - [-:-]\n"
                      "-A FORWARD -j DOCKER-USER\n-A DOCKER -i docker0 -j RETURN\nCOMMIT\n")
    for changed in (IPTABLES_SAMPLE.replace(":FORWARD DROP", ":FORWARD ACCEPT"),
                    IPTABLES_SAMPLE.replace("-j RETURN", "-j ACCEPT"),
                    IPTABLES_SAMPLE.replace("COMMIT\n", "-A INPUT -j ACCEPT\nCOMMIT\n"),
                    IPTABLES_SAMPLE + "# Warning: iptables-legacy tables present\n"):
        assert launcher.normalize_fingerprint_output("iptables", changed) != normal
    nft_later = NFT_SAMPLE.replace("packets 4410 bytes 381220", "packets 9000 bytes 700000")
    nft_normal = launcher.normalize_fingerprint_output("nft", NFT_SAMPLE)
    assert nft_normal == launcher.normalize_fingerprint_output("nft", nft_later) and "packets" not in nft_normal
    assert launcher.normalize_fingerprint_output("nft", NFT_SAMPLE.replace("policy drop", "policy accept")) != nft_normal
    for name in ("links", "addresses", "routes4", "routes6", "netns"):
        assert launcher.normalize_fingerprint_output(name, IPTABLES_SAMPLE) == IPTABLES_SAMPLE
    # The pre-child stability check: two snapshots two seconds apart; any difference fails closed.
    snapshots = iter([{"iptables": "a", "nft": "b", "links": "c"}, {"iptables": "a2", "nft": "b", "links": "c"}])
    pauses = []
    baseline, unstable = launcher.stable_fingerprints(lambda: next(snapshots), pauses.append)
    assert pauses == [2] and unstable == ["iptables"] and baseline["iptables"] == "a2"
    steady = launcher.stable_fingerprints(lambda: {"iptables": "a", "nft": "b"}, lambda seconds: None)
    assert steady == ({"iptables": "a", "nft": "b"}, [])
    source = (ROOT / "scripts" / "host_ingress_proof.py").read_text(encoding="utf-8")
    assert 'ProofFailure("fingerprint_unstable")' in source
    assert launcher.report_lines({"result": "FAIL"}, "fingerprint_unstable", {"unstable_fingerprints": ["iptables", "x y"]})[-1:] == [
        "unstable_fingerprint iptables"]
    notes = " ".join(json.loads(LOCK.read_text(encoding="utf-8"))["notes"])
    doc = (ROOT / "docs" / "saas" / "HOST_INGRESS_PROOF.md").read_text(encoding="utf-8")
    for text in (notes, doc):
        for required in ("nft -s list ruleset", "# Generated by", "# Completed on", "fingerprint_unstable"):
            assert required in text, required


def _fake_proc(root: Path, entries: dict[int, tuple[str, int, str | None]]) -> Path:
    root.mkdir()
    for pid, (state, ppid, exe) in entries.items():
        (root / str(pid)).mkdir()
        (root / str(pid) / "stat").write_text(f"{pid} (name with ) paren) {state} {ppid} {pid} {pid} 0 -1 4194560\n")
        if exe is not None:
            (root / str(pid) / "exe").symlink_to(exe)
    (root / "self").mkdir()
    return root


def test_static_namespace_init_reaps_orphans_and_publishes_closed_leftover_records(tmp_path):
    """H0BL section 5: PID 1 of the outer namespace reaps reparented children before it counts, and a
    leftover is published only as namespace-local PID, state letter, PPID and a fixed role label."""
    launcher = _launcher()
    nginx, node, python = "/stage/runtime/nginx/sbin/nginx", "/stage/runtime/node/bin/node", "/stage/venv/bin/python"
    proc = _fake_proc(tmp_path / "proc", {1: ("S", 0, python), 7: ("Z", 1, None), 9: ("S", 1, nginx), 12: ("S", 9, nginx),
                                          15: ("R", 1, "/usr/bin/other"), 21: ("Z", 15, None), 30: ("S", 1, node)})
    calls = []

    def waitpid(pid, options):
        assert (pid, options) == (-1, os.WNOHANG)
        calls.append(pid)
        if len(calls) == 1:  # the synthetic zombie 7 (an orphan reparented to PID 1) is reaped
            shutil.rmtree(proc / "7")
            return 7, 0
        return 0, 0

    assert launcher.reap_children(waitpid) == 1 and len(calls) == 2
    roles = {nginx: "ingress_nginx", node: "worker_node", python: "suite_python"}
    records = launcher.leftover_records(proc, 1, roles)
    assert records == [{"pid": 9, "state": "S", "ppid": 1, "role": "ingress_nginx"},
                       {"pid": 12, "state": "S", "ppid": 9, "role": "ingress_nginx"},
                       {"pid": 15, "state": "R", "ppid": 1, "role": "other"},
                       {"pid": 21, "state": "Z", "ppid": 15, "role": "exited"},
                       {"pid": 30, "state": "S", "ppid": 1, "role": "worker_node"}]

    def no_children(pid, options):
        raise ChildProcessError()

    assert launcher.reap_children(no_children) == 0
    killed = []
    remaining = launcher.kill_and_reap(records, kill=lambda pid, sig: killed.append((pid, sig)),
                                       count=lambda: 0, waitpid=no_children, pause=lambda seconds: None)
    assert killed == [(9, signal.SIGKILL), (12, signal.SIGKILL), (15, signal.SIGKILL), (21, signal.SIGKILL),
                      (30, signal.SIGKILL)] and remaining == 0
    assert launcher.kill_and_reap([], kill=None, count=lambda: 3, waitpid=no_children, pause=lambda seconds: None) == 3
    dirty = records + [{"pid": "9; rm", "state": "S", "ppid": 1, "role": "other"},
                       {"pid": 40, "state": "S", "ppid": 1, "role": "/stage/venv/bin/python"},
                       {"pid": 41, "state": "?", "ppid": 1, "role": "other"},
                       {"pid": 42, "state": "S", "ppid": 1, "role": "other", "argv": "secret"},
                       {"pid": True, "state": "S", "ppid": 1, "role": "other"}]
    assert launcher.sanitize_leftovers(dirty) == records
    assert len(launcher.sanitize_leftovers([records[0]] * 100)) == launcher.LEFTOVER_RECORD_LIMIT
    me = os.getpid()
    stray = _fake_proc(tmp_path / "proc2", {1: ("S", 0, None), me: ("R", 1, None), me + 1: ("S", me, None),
                                            me + 2: ("Z", me, None), me + 3: ("S", 1, None)})
    assert harness.stray_namespace_processes(stray) == [(me + 1, "S", me), (me + 3, "S", 1)]
    lines = launcher.report_lines({"result": "FAIL"}, None, {"leftover_processes": 5, "leftover_records": records})
    assert "leftover 9 S 1 ingress_nginx" in lines and "leftover 21 Z 15 exited" in lines
    source = (ROOT / "scripts" / "host_ingress_proof.py").read_text(encoding="utf-8")
    inside = source[source.index("def _inside("):source.index("def privileged_child(")]
    assert inside.index("reap_children()") < inside.index("leftover_records(") < inside.index("kill_and_reap(")
    assert 'inner.get("leftover_processes") == 0' in source


JUNIT_FAILURES = """<testsuites><testsuite>
<testcase classname="tests.test_host_ingress" name="test_static_a"/>
<testcase classname="tests.test_host_ingress" name="test_g3_rotation">
<failure message="AssertionError: Bearer sk-SECRET-1&#10;assert {'token': 's3cret'} == {}">value = {'token': 's3cret'}
&gt;   assert value == {}, "Bearer sk-SECRET-1"
E   AssertionError: Bearer sk-SECRET-1

tests/test_host_ingress.py:1535: AssertionError</failure></testcase>
<testcase classname="tests.test_host_ingress" name="test_g8_cap">
<failure message="AssertionError: heel_session=abcdefghijkl">/tmp/heel-ingress/src/tests/test_host_ingress.py:1428:
_ _ _
tests/support/host_ingress_harness.py:2114: in probe
    out, _ = process.communicate(...)
/usr/lib/python3.13/subprocess.py:1222: TimeoutExpired</failure></testcase>
<testcase classname="tests.test_host_ingress" name="test_g6_mutated[body]">
<failure message="json.decoder.JSONDecodeError: Expecting value">tests/test_host_ingress.py:1002:
/usr/lib/python3.13/json/decoder.py:361: JSONDecodeError</failure></testcase>
<testcase classname="tests.test_host_ingress" name="test_g8_slow">
<failure message="Failed: raw body b'POST /x'">tests/test_host_ingress.py:1660: Failed</failure></testcase>
<testcase classname="tests.test_host_ingress" name="test_g9_setup">
<error message="failed on setup with &quot;RuntimeError: /home/runner/secret&quot;">tests/test_host_ingress.py:476: RuntimeError</error></testcase>
<testcase classname="tests.test_host_ingress" name="test_static_b">
<failure message="FileNotFoundError: [Errno 2] /tmp/heel-ingress/src/scripts/x">tests/test_host_ingress.py:104:
&lt;frozen importlib._bootstrap_external&gt;:1161: FileNotFoundError</failure></testcase>
<testcase classname="tests.test_host_ingress" name="test_g0_skip"><skipped message="/secret/path"/></testcase>
<testcase classname="tests.test_host_ingress" name="test_g1_nowhere"><failure message="KeyError: 'secret'">no location here</failure></testcase>
</testsuite></testsuites>"""


def test_static_report_carries_a_failure_locator_for_every_failing_case(tmp_path):
    """H0BL section 6: each failing case gets name, repository-relative test file, line and a reason
    token from a closed grammar. Messages, operands, paths, payloads and tracebacks stay private."""
    launcher = _launcher()
    junit = tmp_path / "junit.xml"
    junit.write_text(JUNIT_FAILURES)
    summary = launcher.summarize_junit(junit)
    module = launcher.TEST_MODULE
    assert summary["failure_locators"] == [
        {"case": "test_g0_skip", "file": module, "line": 0, "reason": "skipped"},
        {"case": "test_g1_nowhere", "file": module, "line": 0, "reason": "lookup_error"},
        {"case": "test_g3_rotation", "file": module, "line": 1535, "reason": "assertion_failed"},
        {"case": "test_g6_mutated", "file": module, "line": 1002, "reason": "json_decode_error"},
        {"case": "test_g8_cap", "file": module, "line": 1428, "reason": "timeout"},
        {"case": "test_g8_slow", "file": module, "line": 1660, "reason": "explicit_fail"},
        {"case": "test_g9_setup", "file": module, "line": 476, "reason": "setup_error"},
        {"case": "test_static_b", "file": module, "line": 104, "reason": "file_not_found"},
    ]
    assert {item["case"] for item in summary["failure_locators"]} == set(summary["failing"])
    assert (summary["failed"], summary["errors"], summary["skipped"], summary["passed"]) == (6, 1, 1, 1)
    lines = launcher.report_lines({"result": "FAIL", "tests": summary}, None, {})
    assert f"locator test_g3_rotation {module}:1535 assertion_failed" in lines
    assert f"locator test_g8_cap {module}:1428 timeout" in lines
    assert len([line for line in lines if line.startswith("locator ")]) == len(summary["failing"]) == 8
    published = json.dumps(summary) + "\n".join(lines)
    for private in ("SECRET", "s3cret", "heel_session", "/tmp/", "/usr/lib", "/home/runner", "POST", "Bearer", "harness.py",
                    "Errno", "Expecting", "secret"):
        assert private not in published, private
    assert launcher.sanitize_locators([
        {"case": "test_g3_rotation", "file": module, "line": 1535, "reason": "assertion_failed"},
        {"case": "test_x", "file": "/etc/passwd", "line": 1, "reason": "assertion_failed"},
        {"case": "test_x", "file": module, "line": -1, "reason": "assertion_failed"},
        {"case": "test_x", "file": module, "line": True, "reason": "assertion_failed"},
        {"case": "test_x", "file": module, "line": 1, "reason": "AssertionError: secret"},
        {"case": "test_x; rm", "file": module, "line": 1, "reason": "timeout"},
        {"case": "test_x", "file": module, "line": 1, "reason": "timeout", "message": "secret"},
    ]) == [{"case": "test_g3_rotation", "file": module, "line": 1535, "reason": "assertion_failed"}]
    # Confirmation seams: the event method from the built config and the inner pytest wall time.
    assert launcher.nginx_event_method("#ifndef NGX_HAVE_EPOLL\n#define NGX_HAVE_EPOLL  1\n#endif\n") == "NGX_HAVE_EPOLL 1"
    assert launcher.nginx_event_method("#ifndef NGX_HAVE_KQUEUE\n#define NGX_HAVE_KQUEUE  1\n#endif\n") == "NGX_HAVE_EPOLL 0"
    source = (ROOT / "scripts" / "host_ingress_proof.py").read_text(encoding="utf-8")
    assert 'timings["inner_pytest"]' in source and 'timings["privileged_child"]' in source
    assert "nginx_event_method(" in source[source.index("def stage_runtime("):source.index("def stage_python(")]


def test_static_cap_timing_telemetry_is_closed_bounded_and_published_before_the_cap_assertions(tmp_path, monkeypatch):
    """H0BR2: the G8 cap gate publishes aggregate hold timing (early and late) and probe counts in one
    closed, optional telemetry object, before any cap assertion and without changing any threshold."""
    launcher = _launcher()
    assert launcher.TELEMETRY_RANGES == harness.CAP_TIMING_RANGES
    assert launcher.TELEMETRY_NULLABLE == harness.CAP_TIMING_NULLABLE

    def ns(mark):
        return round(mark * 1e9) if type(mark) is float and mark == mark and abs(mark) != float("inf") else mark

    def hold(sent, first, received=b""):
        return {"received": received, "wall": {"sent": [sent], "first_byte": first, "closed": first,
                                               "sent_ns": [ns(sent)], "first_byte_ns": ns(first), "closed_ns": ns(first)}}

    window = (BODY_READ_S, BODY_READ_S + SLACK_S)
    # Early, inside, late by a sub-millisecond margin, late, and four holds without usable marks.
    held = [hold(1000.0, 1009.9874), hold(1000.0, 1010.25), hold(1000.0, 1010.5004), hold(1000.0, 1011.75),
            hold(1000.0, None), hold(None, 1010.2), hold(1000.0, float("nan")), {"error": "ConnectionRefusedError"}]
    # Deadline counters: deltas of the prefix sums across the holds; non-int values never count.
    counters_before = {"early:body_timeout": 3, "rearm_ms:body_timeout": 7, "expired:body_timeout": 2}
    counters_after = {"early:body_timeout": 5, "rearm_ms:body_timeout": 11, "early:timeout": 1, "rearm_ms:timeout": 2,
                      "expired:body_timeout": 10, "early_final:body_timeout": 0, "early:odd": True, "rearm_ms:odd": "9"}
    telemetry = harness.cap_timing(held, [(1001.5, 503), (1002.1, 503), (1011.6, 401)], *window, counters_before, counters_after)
    zero = {"early_fires": 0, "early_final": 0, "deadline_invalid": 0, "rearm_ms": 0}
    assert telemetry == {"holds": 8, "holds_unmeasured": 4, "holds_early": 1, "holds_late": 2, "first_byte_ms_min": 9987,
                         "first_byte_ms_max": 11750, "probes": 3, "probes_503": 2, "probes_admitted": 1,
                         "early_fires": 3, "early_final": 0, "deadline_invalid": 0, "rearm_ms": 6}
    # The maximum is the unrounded delta rounded up: 10.5004 s is late and never reads as 10500.
    edge = harness.cap_timing([hold(1000.0, 1010.5004)], [], *window, {}, {})
    assert (edge["first_byte_ms_min"], edge["first_byte_ms_max"], edge["holds_late"]) == (10500, 10501, 1)
    unusable = harness.cap_timing([hold(True, 1010.0), hold(1000.0, float("inf")), hold(0.0, 1000.0), hold("1000", 1010.0)],
                                  [(1.0, 503)], *window, None, ["early:x"])
    assert unusable == {"holds": 4, "holds_unmeasured": 4, "holds_early": 0, "holds_late": 0, "first_byte_ms_min": None,
                        "first_byte_ms_max": None, "probes": 1, "probes_503": 1, "probes_admitted": 0, **zero}
    for value in (telemetry, edge, unusable):
        assert harness.cap_timing_valid(value) and launcher.sanitize_telemetry(value) == value

    # The writer refuses anything outside the grammar; old records keep their exact fields.
    canary = "edge-" + "q" * 40
    raw = tmp_path / "cases.raw.jsonl"
    monkeypatch.setenv("HEEL_HOST_INGRESS_CASES", str(raw))
    harness.record_case("g8.listener_connection_cap", "G8")
    harness.record_case("g8.listener_connection_cap_timing", "G8", telemetry=telemetry)
    invalid = [dict(telemetry, holds=True), dict(telemetry, probes=3.0), dict(telemetry, holds_late="2"),
               dict(telemetry, extra=1), {key: value for key, value in telemetry.items() if key != "probes"},
               dict(telemetry, probes_503={"n": 2}), dict(telemetry, probes_503=[2]), dict(telemetry, first_byte_ms_max=10 ** 30),
               dict(telemetry, first_byte_ms_min=-120001), dict(telemetry, first_byte_ms_min=12000),
               dict(telemetry, holds_unmeasured=8), dict(telemetry, first_byte_ms_min=None), dict(telemetry, holds_early=4),
               dict(telemetry, probes_admitted=2), dict(telemetry, holds=9, holds_unmeasured=5),
               dict(telemetry, first_byte_ms_max=float("inf")), dict(telemetry, probes=canary), [telemetry], None,
               dict(telemetry, early_fires=True), dict(telemetry, rearm_ms=6.0), dict(telemetry, early_final="0"),
               {key: value for key, value in telemetry.items() if key != "deadline_invalid"}, dict(telemetry, early_fires=65),
               dict(telemetry, rearm_ms=4001), dict(telemetry, early_final=-1), dict(telemetry, deadline_invalid=9),
               dict(telemetry, early_fires=3, rearm_ms=2), dict(telemetry, early_fires=1, rearm_ms=501),
               dict(telemetry, early_fires=0, rearm_ms=1), {key: telemetry[key] for key in list(telemetry)[:9]}]
    for value in invalid:
        assert not harness.cap_timing_valid(value) and launcher.sanitize_telemetry(value) is None, value
        if isinstance(value, dict):
            with pytest.raises(AssertionError):
                harness.record_case("g8.invalid", "G8", telemetry=value)
    assert raw.read_text(encoding="utf-8").splitlines() == [
        '{"case": "g8.listener_connection_cap", "gate": "G8", "seam": null}',
        '{"case": "g8.listener_connection_cap_timing", "gate": "G8", "seam": null, "telemetry": ' + json.dumps(telemetry, sort_keys=True) + "}"]

    # The launcher re-checks every line: secrets, paths, nesting, NaN, huge values and oversize lines never publish.
    old = ['{"case": "g6.claim_mutated_sequence", "changed_tables": [], "cp_contacted": true, "gate": "G6", "reasons": '
           '["admitted:claim", "forwarded:claim:401"], "seam": null, "status": 401}',
           '{"case": "g3.terminal_result", "changed_tables": [], "cp_contacted": null, "gate": "G3", "reasons": [], '
           '"seam": "runner-built result, no executor", "status": null}']
    hostile = [
        json.dumps({"case": "g8.t1", "gate": "G8", "telemetry": dict(telemetry, holds="/home/runner/work")}),
        json.dumps({"case": "g8.t2", "gate": "G8", "telemetry": dict(telemetry, **{"Bearer x": 1})}),
        json.dumps({"case": "g8.t3", "gate": "G8", "telemetry": {"nested": telemetry}}),
        json.dumps({"case": "g8.t4", "gate": "G8", "telemetry": dict(telemetry, probes=canary)}),
        json.dumps({"case": "g8.t5", "gate": "G8", "telemetry": dict(telemetry, probes=True)}),
        json.dumps({"case": "g8.t6", "gate": "G8", "telemetry": dict(telemetry, holds_late=2.0)}),
        json.dumps({"case": "g8.t7", "gate": "G8", "telemetry": dict(telemetry, probes=int("9" * 3000))}),
        json.dumps({"case": "g8.t8", "gate": "G8", "telemetry": dict(telemetry, probes=float("nan"))}),
        json.dumps({"case": "g8.t9", "gate": "G8", "telemetry": telemetry, "extra": "secret"}),
        json.dumps({"case": "g8.t10", "gate": "G8", "seam": "x" * 5000}),
        "[" * 2040 + "]" * 2040, "not json", json.dumps(["g8.t11"]), json.dumps({"case": 7, "gate": "G8"}),
        json.dumps({"case": "g8.t12", "gate": ["G8"], "reasons": 5, "changed_tables": {"canary_runs": 1}}),
    ]
    with raw.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(old + hostile) + "\n")
    published = launcher.sanitize_cases(raw)
    base = {"status": None, "cp_contacted": None, "reasons": [], "changed_tables": [], "seam": None}
    assert published == [
        {"case": "g8.listener_connection_cap", "gate": "G8", **base},
        {"case": "g8.listener_connection_cap_timing", "gate": "G8", **base, "telemetry": dict(sorted(telemetry.items()))},
        json.loads(old[0]), json.loads(old[1]),
        *[{"case": f"g8.t{index}", "gate": "G8", **base, "telemetry": None} for index in range(1, 8)],
        {"case": "g8.t12", "gate": "?", **base},
    ]
    assert [json.dumps(case, sort_keys=True) for case in published[2:4]] == old
    out = tmp_path / "artifacts"
    out.mkdir()
    (out / "cases.jsonl").write_text("".join(json.dumps(case, sort_keys=True) + "\n" for case in published))
    data = (out / "cases.jsonl").read_bytes()
    assert launcher.canary_scan(out, [canary]) == []
    for private in (canary, "/home/runner", "Bearer", "secret", "NaN", "Infinity", "nested", "999"):
        assert private.encode() not in data, private
    assert max(len(line) for line in data.splitlines()) <= 512

    # Evidence first: the timing record is written although the late hold then fails the unchanged window.
    late = hold(1000.0, 1010.75, b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 27\r\n\r\n" + FIXED_REFUSAL)
    order = tmp_path / "order.jsonl"
    monkeypatch.setenv("HEEL_HOST_INGRESS_CASES", str(order))
    harness.record_case("g8.listener_connection_cap_timing", "G8", telemetry=harness.cap_timing([late], [], *window, {}, {}))
    with pytest.raises(AssertionError):
        _assert_fixed_refusal_at(late, 408, BODY_READ_S)
    (record,) = launcher.sanitize_cases(order)
    assert (record["telemetry"]["holds_late"], record["telemetry"]["first_byte_ms_max"]) == (1, 10750)
    module = Path(__file__).read_text(encoding="utf-8")
    cap = module[module.index("\ndef test_g8_listener_connection_cap_holds_at_eight"):module.index("\ndef test_g8_mixed_load_of")]
    evidence = cap.index('harness.record_case("g8.listener_connection_cap_timing", "G8",')
    assert "assert " not in cap[:evidence] and cap.index("held = [future.result() for future in holds]") < evidence
    assert cap.index("counters_before = world.env.counters()") < cap.index("pool.submit(_hold, world, raw, split)")
    assert cap[evidence:].index('assert telemetry["early_final"] == telemetry["deadline_invalid"] == 0') < cap[evidence:].index(
        "_assert_fixed_refusal_at(result, 408, BODY_READ_S)")
    for kept in ("assert [status for _sent, status in probes if status not in {401, 503}] == []",
                 "_assert_fixed_refusal_at(result, 408, BODY_READ_S)", "assert any(status == 503 for _sent, status in probes)",
                 "assert all(status == 503 for sent, status in probes if sent < min(starts) + BODY_READ_S - SLACK_S)",
                 "assert admitted_at is not None and admitted_at - max(starts) <= BODY_READ_S + SLACK_S, admitted_at",
                 'assert after["requests"] - before["requests"] == 1', "== [401] * 8", "_assert_worker_unchanged(world)"):
        assert kept in cap[evidence:], kept
    assert "pool.submit(_hold, world, raw, split) for _ in range(8)]" in cap
    assert cap.rstrip().endswith('harness.record_case("g8.listener_connection_cap", "G8")')

    # Every existing threshold is unchanged; the CPU count is an int or a fixed "unavailable".
    assert (BODY_READ_S, TOTAL_BUDGET_S, SLACK_S) == (10.0, 25.0, 0.5)
    helper = module[module.index("\ndef _assert_fixed_refusal_at("):module.index("\ndef _assert_worker_unchanged(")]
    for kept in ("assert first_ns // NS_PER_MS - t0_ns // NS_PER_MS >= round(seconds * 1000), first_ns - t0_ns",
                 "assert first is not None and first - t0 <= seconds + SLACK_S, first - t0",
                 "assert first_ns - t0_ns <= limit_ns, first_ns - t0_ns",
                 "assert closed is not None and closed - t0 <= seconds + SLACK_S, (closed or 0) - t0",
                 "assert closed_ns - t0_ns <= limit_ns, closed_ns - t0_ns",
                 "limit_ns = round((seconds + SLACK_S) * 1000) * NS_PER_MS"):
        assert kept in helper, kept
    assert "limit_conn heel_listeners 8;" in TEMPLATE.read_text(encoding="utf-8")
    assert launcher.cpu_count_line(lambda: 4) == "cpu_count 4"
    for bad in (None, 0, -1, True, 4.0, "4", 10 ** 6):
        assert launcher.cpu_count_line(lambda bad=bad: bad) == "cpu_count unavailable", bad
    launcher_source = (ROOT / "scripts" / "host_ingress_proof.py").read_text(encoding="utf-8")
    assert launcher_source.count("cpu_count_line()") == 1 and 'f"platform {sys.platform}", cpu_count_line(), time_clock_line()]' in launcher_source
    # H0BR3 clock provenance: one fixed literal or a fixed "unavailable", never the runtime's own text.
    import types

    def info(implementation):
        return lambda name: types.SimpleNamespace(implementation=implementation) if name == "time" else None

    assert launcher.time_clock_line(info("clock_gettime(CLOCK_REALTIME)")) == "time_clock CLOCK_REALTIME"
    for bad in ("GetSystemTimePreciseAsFileTime()", "clock_gettime(CLOCK_REALTIME) " + canary, None, 7, ""):
        assert launcher.time_clock_line(info(bad)) == "time_clock unavailable", bad
    assert launcher.time_clock_line(lambda name: 1 / 0) == "time_clock unavailable"
    assert launcher_source.count("time_clock_line()") == 1


def test_static_probe_marks_precede_sendall_and_every_maximum_stays_unrounded():
    """H0BR3: the probe takes an integer time_ns() mark before sendall (a lower bound of the server's
    Date.now() origin on the same CLOCK_REALTIME); the lower bound is checked on Date.now()'s integer
    millisecond grid; every maximum stays unrounded (the post-sendall float marks as before, plus the
    pre-sendall ns marks); and the telemetry classifies each hold exactly as the assertion does."""
    source = (ROOT / "tests" / "support" / "host_ingress_harness.py").read_text(encoding="utf-8")
    child = source[source.index("def _probe_child("):source.index("def _scripted_child(")]
    send = child[child.index("data = base64.b64decode(chunk)"):child.index('if config.get("shutdown_write"):')]
    assert send.index("sent_ns = time.time_ns()") < send.index("sock.sendall(data)") < send.index('wall["sent"].append(time.time())')
    assert send.index("sock.sendall(data)") < send.index('wall["sent_ns"].append(sent_ns)')
    assert 'wall["sent_ns"].append(None)' in send and 'wall["sent"].append(None)' in send
    first = child[child.index('if wall["first_byte"] is None:'):]
    assert first.index('wall["first_byte_ns"] = time.time_ns()') < first.index('wall["first_byte"] = time.time()')
    assert child.count('wall["closed_ns"] = time.time_ns()') == 2 == child.count('wall["closed"] = time.time()')

    ms = NS_PER_MS
    assert harness.NS_PER_MS == ms
    base = 1_800_000_000_000  # an epoch millisecond

    def hold(sent_ns, first_ns, *, post_send_ns=200_000, read_lag_ns=10_000, close_ns=1_000_000):
        # Float marks as the probe takes them: after sendall returns, and just after the ns mark.
        received = b"HTTP/1.1 408 Request Time-out\r\nContent-Length: 27\r\n\r\n" + FIXED_REFUSAL
        return {"received": received, "wall": {
            "sent": [(sent_ns + post_send_ns) / 1e9], "first_byte": (first_ns + read_lag_ns) / 1e9,
            "closed": (first_ns + close_ns) / 1e9, "sent_ns": [sent_ns], "first_byte_ns": first_ns,
            "closed_ns": first_ns + close_ns - read_lag_ns}}

    def failure(result, seconds):
        """The failing assertion's message (its first line), or None when the refusal passes."""
        try:
            _assert_fixed_refusal_at(result, 408, seconds)
        except AssertionError as error:
            return str(error).splitlines()[0]
        return None

    def passes(result, seconds):
        return failure(result, seconds) is None

    cases = {
        # On the grid: sent in ms 0 (late in it), first byte at ms 10000. Passes: Date.now() reads the same grid.
        "grid_boundary": (hold(base * ms + 999_999, (base + 10000) * ms), True, (0, 0, 10000, 10000)),
        "early": (hold(base * ms, (base + 9999) * ms + 999_999), False, (1, 0, 9999, 10000)),
        "inside": (hold(base * ms + 500_000, (base + 10250) * ms), True, (0, 0, 10250, 10250)),
        "upper_exact": (hold(base * ms, (base + 10500) * ms, read_lag_ns=0, close_ns=0), True, (0, 0, 10500, 10500)),
        # The precision counterexample: true delay 10500.05 ms, floored-ms delta 10500, float marks
        # inside the window (the send mark trails by 0.2 ms): the pre-send ns maximum must fail it.
        "upper_floored": (hold(base * ms + 900_000, (base + 10500) * ms + 950_000), False, (0, 1, 10500, 10501)),
        # A float-only overrun (the first-byte float read 0.6 ms after its ns mark) fails as before.
        "upper_float": (hold(base * ms, (base + 10499) * ms + 900_000, post_send_ns=0, read_lag_ns=600_000), False,
                        (0, 1, 10499, 10500)),
    }
    for label, (result, ok, (early, late, low, high)) in cases.items():
        assert passes(result, BODY_READ_S) is ok, label
        telemetry = harness.cap_timing([result], [], BODY_READ_S, BODY_READ_S + SLACK_S, {}, {})
        assert (telemetry["holds_early"], telemetry["holds_late"], telemetry["first_byte_ms_min"],
                telemetry["first_byte_ms_max"]) == (early, late, low, high), label
        assert ok == (telemetry["holds_early"] == telemetry["holds_late"] == telemetry["holds_unmeasured"] == 0), label
    upper = cases["upper_floored"][0]["wall"]
    assert upper["first_byte_ns"] // ms - upper["sent_ns"][0] // ms == 10500
    # It is the unrounded first-byte maximum that fails (its message is the ns delta), not the close.
    assert failure(cases["upper_floored"][0], BODY_READ_S) == str(10500 * ms + 50_000)
    assert upper["first_byte"] - upper["sent"][0] <= BODY_READ_S + SLACK_S < (upper["first_byte_ns"] - upper["sent_ns"][0]) / 1e9
    # The close is bounded in both domains, unrounded: exactly 10.5 s passes; 1 ns past it from the
    # pre-send mark fails although the post-sendall float marks still read inside the window.
    assert passes(hold(base * ms, (base + 10400) * ms, close_ns=100 * ms, read_lag_ns=0, post_send_ns=0), BODY_READ_S)
    late_close = hold(base * ms, (base + 10400) * ms, close_ns=100 * ms + 1, read_lag_ns=0, post_send_ns=5_000)
    assert late_close["wall"]["closed"] - late_close["wall"]["sent"][0] <= BODY_READ_S + SLACK_S and not passes(late_close, BODY_READ_S)
    assert not passes(hold(base * ms, (base + 10400) * ms, close_ns=101 * ms), BODY_READ_S)
    # The 25 s budget (the macOS d01 reading was 24.999918 s after the post-sendall mark).
    assert passes(hold(base * ms + 999_999, (base + 25000) * ms), TOTAL_BUDGET_S)
    assert not passes(hold(base * ms, (base + 24999) * ms + 999_999), TOTAL_BUDGET_S)
    # A quiet body ended by nginx's own 11 s idle backstop (reset, no byte) never passes for the JS deadline.
    backstop = hold(base * ms, (base + 11000) * ms)
    backstop["received"] = b""
    backstop["wall"].update(first_byte=None, first_byte_ns=None)
    assert not passes(backstop, BODY_READ_S)
    assert harness.cap_timing([backstop], [], BODY_READ_S, BODY_READ_S + SLACK_S, {}, {})["holds_unmeasured"] == 1
    # Missing or ill-typed ns marks are unmeasured in the telemetry and fail the assertion.
    for mutate in ({"sent_ns": [None]}, {"sent_ns": []}, {"first_byte_ns": None}, {"first_byte_ns": float(base * ms)},
                   {"sent_ns": [True]}, {"closed_ns": None}, {"first_byte_ns": str((base + 10250) * ms)}):
        result = hold(base * ms, (base + 10250) * ms)
        result["wall"].update(mutate)
        assert not passes(result, BODY_READ_S), mutate
        if "closed_ns" not in mutate:
            telemetry = harness.cap_timing([result], [], BODY_READ_S, BODY_READ_S + SLACK_S, {}, {})
            assert (telemetry["holds_unmeasured"], telemetry["first_byte_ms_min"]) == (1, None), mutate


# ---------------------------------------------------------------------------------------------
# Runtime fixtures.

def _environment() -> harness.IngressEnvironment:
    reason = harness.runtime_unavailable_reason()
    if reason is not None:
        if REQUIRED:
            pytest.fail(reason)
        pytest.skip(reason)
    installation = harness.load_installation()
    topology = harness.make_topology(installation)
    if REQUIRED and not topology.is_linux_namespaces:
        pytest.fail("the required profile runs only on the launcher's Linux namespace topology")
    return harness.IngressEnvironment(installation, topology)


def _two_slots(world) -> None:
    if "slot-b" not in world.env.slots:
        harness.require_linux_topology(world.env.topology, "a second runner slot")


@pytest.fixture(scope="module")
def policy_runtime():
    env = _environment()
    try:
        env.start_policy_selftest()
        yield env
    finally:
        env.close()


def _nfc_batch(env, strings: list[str]) -> list[str]:
    payload = "\0".join(strings).encode("utf-8")
    status, body = env.selftest("/nfc", payload)
    assert status == 200, (status, body[:64])
    result = body.decode("utf-8").split("\0")
    assert len(result) == len(strings)
    return result


def _verdict(env, raw: bytes) -> str:
    status, body = env.selftest("/canonical", raw)
    assert status == 200
    return body.decode("ascii")


# ---------------------------------------------------------------------------------------------
# G0 runtime compatibility: the policy's exact NFC and canonical scanner in the real njs/qjs.

def test_g0_runtime_has_no_native_normalize_and_policy_carries_pinned_tables(policy_runtime):
    status, body = policy_runtime.selftest("/runtime", b"")
    assert status == 200
    runtime = json.loads(body)
    # Preserved first-failure fact: njs never registers String.prototype.normalize.
    assert runtime["native_normalize"] == "undefined"
    assert runtime["eval"] == "undefined" and runtime["function_constructor"] == "undefined"
    assert runtime["nfc_unicode_version"] == harness.NFC_UNICODE_VERSION


def test_g0_nfc_of_every_code_point_matches_the_pinned_unicodedata(policy_runtime):
    if unicodedata.unidata_version != harness.NFC_UNICODE_VERSION:
        pytest.fail("comparison requires the pinned unicodedata version")
    points = [code for code in range(1, 0x110000) if not 0xD800 <= code <= 0xDFFF]
    mismatches = []
    for start in range(0, len(points), 40000):
        chunk = [chr(code) for code in points[start:start + 40000]]
        for item, got in zip(chunk, _nfc_batch(policy_runtime, chunk)):
            if got != unicodedata.normalize("NFC", item):
                mismatches.append(ord(item))
    assert mismatches == []


def _sequences() -> list[str]:
    generator = random.Random(1501)
    decomposable = [chr(code) for code in range(0x110000) if not 0xD800 <= code <= 0xDFFF
                    and unicodedata.decomposition(chr(code))[:1] not in ("", "<")]
    marks = [chr(code) for code in range(0x110000) if not 0xD800 <= code <= 0xDFFF
             and unicodedata.combining(chr(code))]
    jamo = [chr(code) for code in list(range(0x1100, 0x1113)) + list(range(0x1161, 0x1176)) + list(range(0x11A8, 0x11C3))]
    syllables = [chr(code) for code in range(0xAC00, 0xD7A4, 97)]
    vectors = []
    for item in decomposable:
        vectors.extend([item, unicodedata.normalize("NFD", item), unicodedata.normalize("NFD", item)[::-1]])
    pool = decomposable + marks + jamo + syllables + list("aeiouAEIOU ")
    for _ in range(20000):
        vectors.append("".join(generator.choice(pool) for _ in range(generator.randint(1, 8))))
    return vectors


def test_g0_nfc_of_composition_and_reordering_sequences_matches_the_pinned_unicodedata(policy_runtime):
    if unicodedata.unidata_version != harness.NFC_UNICODE_VERSION:
        pytest.fail("comparison requires the pinned unicodedata version")
    vectors = _sequences()
    mismatches = 0
    for start in range(0, len(vectors), 4000):
        chunk = vectors[start:start + 4000]
        for item, got in zip(chunk, _nfc_batch(policy_runtime, chunk)):
            mismatches += got != unicodedata.normalize("NFC", item)
    assert mismatches == 0


E_ACUTE, E_COMBINING = "é", "é"
SCANNER_CASES = [
    ("composed key is accepted", '{"' + E_ACUTE + '":1}', "accepted"),
    ("decomposed key is not canonical", '{"' + E_COMBINING + '":1}', "refused:canonical"),
    ("duplicate after NFC is refused", '{"' + E_ACUTE + '":1,"' + E_COMBINING + '":2}', "refused:json"),
    ("exact duplicate is refused", '{"a":1,"a":2}', "refused:json"),
    ("composed value is accepted", '{"a":"' + E_ACUTE + '"}', "accepted"),
    ("decomposed value is not canonical", '{"a":"' + E_COMBINING + '"}', "refused:canonical"),
    ("singleton decomposition value is not canonical", '{"a":"Å"}', "refused:canonical"),
    ("composed Hangul value is accepted", '{"a":"한"}', "accepted"),
    ("conjoining jamo value is not canonical", '{"a":"한"}', "refused:canonical"),
    ("astral keys sort by code point", '{"￿":1,"\U00010000":2}', "accepted"),
    ("astral keys in UTF-16 order are not canonical", '{"\U00010000":2,"￿":1}', "refused:canonical"),
    ("escaped non-ASCII is not canonical", '{"a":"\\u00e9"}', "refused:canonical"),
    ("escaped slash is not canonical", '{"a":"\\/"}', "refused:canonical"),
    ("whitespace is not canonical", '{"a": 1}', "refused:canonical"),
    ("unsorted keys are not canonical", '{"b":1,"a":2}', "refused:canonical"),
    ("boolean is refused", '{"a":true}', "refused:json"),
    ("fraction is refused", '{"a":1.0}', "refused:json"),
    ("negative is refused", '{"a":-1}', "refused:json"),
    ("unsafe integer is refused", '{"a":9007199254740992}', "refused:json"),
    ("lone surrogate escape is refused", '{"a":"\\ud800"}', "refused:json"),
    ("C1 control is refused", '{"a":"\u0085"}', "refused:json"),
    ("maximum nesting is accepted", '{"a":' * 16 + "1" + "}" * 16, "accepted"),
    ("nesting past the bound is refused", '{"a":' * 17 + "1" + "}" * 17, "refused:json"),
]


@pytest.mark.parametrize("label,text,expected", SCANNER_CASES, ids=[case[0] for case in SCANNER_CASES])
def test_g0_request_scanner_unicode_and_canonical_cases(policy_runtime, label, text, expected):
    assert _verdict(policy_runtime, text.encode("utf-8")) == expected


UTF8_CASES = [
    ("overlong slash", b'{"a":"\xc0\xaf"}'),
    ("overlong three byte", b'{"a":"\xe0\x80\xaf"}'),
    ("encoded surrogate", b'{"a":"\xed\xa0\x80"}'),
    ("above U+10FFFF", b'{"a":"\xf4\x90\x80\x80"}'),
    ("truncated sequence", b'{"a":"\xe2\x82"}'),
    ("bad continuation", b'{"a":"\xe2\x28\xa1"}'),
    ("lone continuation", b'{"a":"\x80"}'),
    ("five byte lead", b'{"a":"\xf8\x88\x80\x80\x80"}'),
]


@pytest.mark.parametrize("label,raw", UTF8_CASES, ids=[case[0] for case in UTF8_CASES])
def test_g0_request_scanner_refuses_invalid_utf8(policy_runtime, label, raw):
    assert _verdict(policy_runtime, raw) == "refused:utf8"


def test_g0_request_scanner_refuses_a_byte_order_mark(policy_runtime):
    assert _verdict(policy_runtime, b"\xef\xbb\xbf{}") == "refused:json"


def test_g0_request_scanner_accepts_exactly_python_canonical_bytes(policy_runtime):
    from heel.canary_contracts import canonical_bytes

    generator = random.Random(4096)
    alphabet = ["a", "Z", "_", "é", "Å", "́", "한", "하", "\U0001f600", "￿", '"', "\\", " "]

    def text() -> str:
        return "".join(generator.choice(alphabet) for _ in range(generator.randint(0, 6)))

    def value(depth: int):
        kind = generator.randint(0, 4 if depth < 4 else 2)
        if kind == 0:
            return None
        if kind == 1:
            return generator.randint(0, 2 ** 53 - 1)
        if kind == 2:
            return text()
        if kind == 3:
            return [value(depth + 1) for _ in range(generator.randint(0, 3))]
        return {text() or "k": value(depth + 1) for _ in range(generator.randint(0, 3))}

    checked = 0
    for _ in range(300):
        document = {text() or "root": value(0)}
        try:
            canonical = canonical_bytes(document)
        except ValueError:
            continue  # the CP itself refuses this document (e.g. an NFC-induced duplicate key)
        assert _verdict(policy_runtime, canonical) == "accepted"
        decomposed = unicodedata.normalize("NFD", canonical.decode("utf-8")).encode("utf-8")
        if decomposed != canonical:
            assert _verdict(policy_runtime, decomposed) in {"refused:canonical", "refused:json"}
        loose = json.dumps(json.loads(canonical), ensure_ascii=True).encode("ascii")
        if loose != canonical:
            assert _verdict(policy_runtime, loose) == "refused:canonical"
        checked += 1
    assert checked >= 200


# ---------------------------------------------------------------------------------------------
# G0 deadline helpers (H0BR3): the policy's own deadline arithmetic and lifecycle, executed by the
# pinned nginx/njs/qjs selftest. {"special": ...}, {"string": ...} and {"object": 1} carry values
# JSON cannot (NaN, Infinity, undefined, -0), numeric strings and objects.

NAN, INF, NEG_INF = {"special": "nan"}, {"special": "infinity"}, {"special": "minus_infinity"}
UNDEFINED, MINUS_ZERO, OBJECT = {"special": "undefined"}, {"special": "minus_zero"}, {"object": 1}
UNSAFE = 2 ** 53
SAFE = 2 ** 53 - 1
# Values no clock reading, origin, budget or counter may take.
NOT_SAFE_INTEGERS = [NAN, INF, NEG_INF, UNDEFINED, OBJECT, None, True, False, [], {"string": "1000"}, 1000.5, UNSAFE]


def _selftest_json(env, path: str, payload) -> object:
    status, body = env.selftest(path, json.dumps(payload).encode("utf-8"))
    assert status == 200, (path, status, body[:64])
    return json.loads(body)


def test_g0_deadline_planner_refuses_every_unusable_value_in_the_pinned_runtime(policy_runtime):
    env = policy_runtime
    start = [
        ([20000, 0, 25000], ["arm", 5000]), ([1000, 1000, 10000], ["arm", 10000]), ([10999, 1000, 10000], ["arm", 1]),
        ([11000, 1000, 10000], ["due", 0]), ([99999, 1000, 10000], ["due", 0]), ([0, 0, 1], ["arm", 1]), ([1, 0, 1], ["due", 0]),
        ([SAFE - 1, SAFE - 10000, 10000], ["arm", 1]), ([MINUS_ZERO, 0, 25000], ["arm", 25000]),
        ([999, 1000, 10000], ["invalid", 0]),  # the clock reads before the origin
        ([1000, SAFE - 9999, 10000], ["invalid", 0]),  # origin + budget is not a safe integer
        ([1000, 1000, 0], ["invalid", 0]), ([1000, 1000, -1], ["invalid", 0]), ([1000, 1000, 25001], ["invalid", 0]),
        ([-1, 0, 25000], ["invalid", 0]), ([1000, -1, 25000], ["invalid", 0]),
    ]
    for bad in NOT_SAFE_INTEGERS:
        start += [([bad, 1000, 10000], ["invalid", 0]), ([1000, bad, 10000], ["invalid", 0]), ([1000, 1000, bad], ["invalid", 0])]
    got = _selftest_json(env, "/deadline_start", [row for row, _ in start])
    assert got == [expected for _, expected in start]

    plan = [
        ([24997, 25000, 0, 0], ["rearm", 3]),  # origin 0, due 25000, woken at 24997: 3 ms early on the total budget
        ([25000, 25000, 0, 0], ["due", 0]), ([25001, 25000, 0, 0], ["due", 0]), ([9999, 10000, 0, 0], ["rearm", 1]),
        ([24500, 25000, 0, 0], ["rearm", 500]), ([24499, 25000, 0, 0], ["bound", 0]),
        ([9998, 10000, 498, 1], ["rearm", 2]), ([9998, 10000, 499, 1], ["bound", 0]),
        ([9999, 10000, 7, 7], ["rearm", 1]), ([9999, 10000, 8, 8], ["bound", 0]), ([10000, 10000, 8, 8], ["due", 0]),
        ([10000, 10000, 500, 8], ["due", 0]), ([0, SAFE, 0, 0], ["bound", 0]), ([MINUS_ZERO, 1, 0, 0], ["rearm", 1]),
        # Inconsistent or out-of-range state never plans a re-arm.
        ([9999, 10000, -1, 0], ["invalid", 0]), ([9999, 10000, 0, -1], ["invalid", 0]), ([9999, 10000, 9, 9], ["invalid", 0]),
        ([9999, 10000, 501, 1], ["invalid", 0]), ([9999, 10000, 3, 0], ["invalid", 0]), ([9999, 10000, 0, 1], ["invalid", 0]),
        ([9999, 10000, 2, 3], ["invalid", 0]), ([-1, 10000, 0, 0], ["invalid", 0]), ([9999, -1, 0, 0], ["invalid", 0]),
    ]
    for bad in NOT_SAFE_INTEGERS:
        # NaN would make "now < due" false: it must read as invalid, never as due.
        plan += [([bad, 25000, 0, 0], ["invalid", 0]), ([24997, bad, 0, 0], ["invalid", 0]),
                 ([24997, 25000, bad, 1], ["invalid", 0]), ([24997, 25000, 1, bad], ["invalid", 0])]
    got = _selftest_json(env, "/deadline_plan", [row for row, _ in plan])
    assert got == [expected for _, expected in plan]
    # Every delay a plan hands to setTimeout is an integer in (0, budget] or (0, 500]: no ToUint32 wrap.
    assert all(ms > 0 and type(ms) is int for code, ms in got if code == "rearm") and max(ms for _code, ms in got) == 500


def _script(env, clock: list, steps: list[str], *, origin=0, budget=25000, status=504, reason="timeout") -> dict:
    return _selftest_json(env, "/deadline_script", {"clock": clock, "origin": origin, "budget": budget, "status": status,
                                                    "reason": reason, "steps": steps})


def _final(timer: int, kick: int, reason: str, status: int, anomaly: str | None = None) -> list:
    counted = [["count", f"{anomaly}:{reason}", 1]] if anomaly else []
    return counted + [["count", f"expired:{reason}", 1], ["refuse", status, reason], ["arm", kick, 0],
                      ["threw", timer, "deadline"]]


def test_g0_deadline_lifecycle_under_a_scripted_clock_and_scheduler(policy_runtime):
    """The policy's deadlineWith()/settle() under a scripted clock and scheduler: cancellation before
    a wake, cancellation of the re-armed timer, expiry after re-arms, the bounds and every anomaly."""
    env = policy_runtime
    traces = []

    def run(*args, **kwargs) -> dict:
        result = _script(env, *args, **kwargs)
        traces.append((kwargs.get("budget", 25000), result["trace"]))
        return result

    # Cancelled before any wake: settle() cancels the one pending timer and nothing fires later.
    result = run([1000], ["settle", "fire"], origin=1000, budget=10000, status=408, reason="body_timeout")
    assert result["start"] == "armed" and result["state"] == {"fired": False, "rearms": 0, "extended": 0}
    assert result["trace"] == [["now", 0], ["arm", 1, 10000], ["cancel", 1, "pending"], ["settled", False], ["fire", 0]]
    # The early total deadline: armed at 20000 for due 25000, woken at 24997. It re-arms for the
    # 3 ms shortfall (d.id now names the new timer) and settle() cancels that pending timer.
    result = run([20000, 24997], ["fire", "settle", "fire"])
    assert result["trace"] == [["now", 0], ["arm", 1, 5000], ["fire", 1], ["now", 1], ["arm", 2, 3],
                               ["count", "early:timeout", 1], ["count", "rearm_ms:timeout", 3], ["returned", 1],
                               ["cancel", 2, "pending"], ["settled", False], ["fire", 0]]
    assert result["state"] == {"fired": False, "rearms": 1, "extended": 3}
    # Re-armed, then due: refusal, zero-delay kick, throw; settle() afterwards cancels nothing.
    result = run([20000, 24997, 25000], ["fire", "fire", "fire", "settle"])
    assert result["trace"] == [["now", 0], ["arm", 1, 5000], ["fire", 1], ["now", 1], ["arm", 2, 3],
                               ["count", "early:timeout", 1], ["count", "rearm_ms:timeout", 3], ["returned", 1],
                               ["fire", 2], ["now", 2], *_final(2, 3, "timeout", 504), ["fire", 3], ["returned", 3],
                               ["settled", True]]
    assert result["state"] == {"fired": True, "rearms": 1, "extended": 3}
    # Several stale wakes: each re-arm is exactly the remaining shortfall.
    result = run([0, 9998, 9999, 10000], ["fire"] * 3, budget=10000, status=408, reason="body_timeout")
    assert [entry for entry in result["trace"] if entry[0] == "arm"] == [["arm", 1, 10000], ["arm", 2, 2], ["arm", 3, 1], ["arm", 4, 0]]
    assert result["trace"][-4:] == _final(3, 4, "body_timeout", 408)
    assert result["state"] == {"fired": True, "rearms": 2, "extended": 3}
    # At most eight re-arms: the ninth early wake refuses at once and is counted as early_final.
    result = run([0] + [9999] * 9, ["fire"] * 9, budget=10000, status=408, reason="body_timeout")
    assert [entry[2] for entry in result["trace"] if entry[0] == "arm"] == [10000] + [1] * 8 + [0]
    assert result["trace"][-5:] == _final(9, 10, "body_timeout", 408, "early_final")
    assert result["state"] == {"fired": True, "rearms": 8, "extended": 8}
    # At most 500 ms re-armed in total: a 500 ms shortfall re-arms, any further shortfall refuses.
    result = run([0, 9500, 9999], ["fire"] * 2, budget=10000, status=408, reason="body_timeout")
    assert [entry[2] for entry in result["trace"] if entry[0] == "arm"] == [10000, 500, 0]
    assert result["trace"][-5:] == _final(2, 3, "body_timeout", 408, "early_final")
    result = run([0, 9499], ["fire"], budget=10000, status=408, reason="body_timeout")
    assert result["trace"][-5:] == _final(1, 2, "body_timeout", 408, "early_final")
    # An unusable clock at a wake refuses at once, counted invalid (never as due), before any arithmetic.
    for bad in NOT_SAFE_INTEGERS + [-1, {"string": "25000"}]:
        result = run([20000, bad], ["fire", "settle"])
        assert result["trace"] == [["now", 0], ["arm", 1, 5000], ["fire", 1], ["now", 1],
                                   *_final(1, 2, "timeout", 504, "deadline_invalid"), ["settled", True]], bad
    # An unusable start refuses synchronously: nothing is armed, so no ready body can settle first.
    starts = [([bad], 0, 25000) for bad in NOT_SAFE_INTEGERS] + [([20000], bad, 25000) for bad in NOT_SAFE_INTEGERS]
    starts += [([20000], 0, bad) for bad in NOT_SAFE_INTEGERS + [0, 25001, -1]] + [([1], 2, 25000), ([20000], -1, 25000)]
    for clock, origin, budget in starts:
        result = run(clock, ["fire", "settle"], origin=origin, budget=budget)
        assert result["start"] == ["refused", 504, "timeout"] and result["state"] is None, (clock, origin, budget)
        assert result["trace"] == [["now", 0], ["count", "deadline_invalid:timeout", 1], ["fire", 0]], (clock, origin, budget)
    # A budget already spent at the start is the ordinary synchronous refusal, not an anomaly.
    result = run([25000], ["fire"])
    assert result["start"] == ["refused", 504, "timeout"] and result["trace"] == [["now", 0], ["fire", 0]]
    # Every delay handed to the scheduler was an integer in [0, budget]; every re-arm in (0, 500].
    for budget, trace in traces:
        arms = [entry[2] for entry in trace if entry[0] == "arm"]
        assert all(type(ms) is int and 0 <= ms <= budget for ms in arms), arms
        assert all(type(ms) is int and 0 < ms <= 500 for ms in arms[1:] if ms != 0), arms
        assert [entry for entry in trace if entry[0] == "cancel" and entry[2] != "pending"] == []


def _native(env, token: str, query: str, pieces: list[tuple[int, bytes]], *, location: str = "deadline_native") -> dict:
    head = (f"POST /{location}?token={token}&{query} HTTP/1.1\r\nHost: selftest\r\nContent-Length: 4\r\n"
            "Connection: close\r\n\r\n").encode("ascii")
    chunks = [[delay, _b64((head if index == 0 else b"") + piece)] for index, (delay, piece) in enumerate(pieces)]
    return env.probe("ingress", mode="tcp", address="127.0.0.1", port=env.selftest_port, chunks=chunks, read_timeout=3,
                     send_after_close=True)


def _native_counts(env, token: str) -> dict:
    return _selftest_json(env, f"/deadline_counts?token={token}", None)


def test_g0_deadline_native_timers_cancel_rearm_and_expire_in_the_pinned_runtime(policy_runtime):
    """The same code with the real njs timers and request body read (js_access, as runnerAccess),
    a scripted clock only: pending cancellation, re-arm then cancellation of the new timer, expiry
    after a re-arm, and an unusable start with the body already complete. The single worker survives."""
    import time as clock

    env = policy_runtime
    pid = _native_counts(env, "pid")["worker_pid"]
    # Cancelled before the first wake: the body completes at 0.1 s; the 1 s timer never fires.
    result = _native(env, "n1", "origin=1000&budget=1000&clock=1000", [(0, b"ab"), (100, b"cd")])
    assert harness.parse_http(result["received"])[0::2] == (200, b"proceeded")
    clock.sleep(1.3)
    assert _native_counts(env, "n1") == {"now": 1, "arm": 1, "cancel": 1, "proceeded": 1, "worker_pid": pid}
    # Re-armed, then the NEW timer is cancelled: armed for 0.4 s, woken 0.4 s early by the scripted
    # clock, re-armed for 0.4 s; the body completes at 0.6 s, between the wake and the re-armed fire.
    result = _native(env, "n2", "origin=1000&budget=500&clock=1100,1100", [(0, b"ab"), (600, b"cd")])
    assert harness.parse_http(result["received"])[0::2] == (200, b"proceeded")
    clock.sleep(1.2)
    assert _native_counts(env, "n2") == {"now": 2, "arm": 2, "early:selftest": 1, "rearm_ms:selftest": 400, "cancel": 1,
                                         "proceeded": 1, "worker_pid": pid}
    # Expiry after a re-arm: the body never completes; the fixed 408 at the scripted due time.
    result = _native(env, "n3", "origin=1000&budget=200&clock=1000,1150,1200", [(0, b"ab")])
    assert harness.parse_http(result["received"])[0::2] == (408, FIXED_REFUSAL) and result.get("peer_closed")
    assert result["received"].count(b"HTTP/1.1 ") == 1
    clock.sleep(0.3)
    assert _native_counts(env, "n3") == {"now": 3, "arm": 3, "early:selftest": 1, "rearm_ms:selftest": 50,
                                         "expired:selftest": 1, "refuse": 1, "worker_pid": pid}
    # An unusable start (NaN, or a clock before the origin) with the whole body already sent: refused
    # synchronously. Arming a 0 ms timer instead would let the ready body settle it and proceed.
    for token, query in (("n4", "origin=1000&budget=500&clock=nan"), ("n5", "origin=1000&budget=500&clock=900")):
        result = _native(env, token, query, [(0, b"abcd")])
        assert harness.parse_http(result["received"])[0::2] == (408, FIXED_REFUSAL), token
        assert _native_counts(env, token) == {"now": 1, "deadline_invalid:selftest": 1, "refused_sync": 1, "worker_pid": pid}
    assert _native_counts(env, "pid") == {"worker_pid": pid}


def test_g0_native_body_idle_backstop_outlives_the_js_deadline_and_its_rearm_bound(policy_runtime):
    """H0BR3 amendment: nginx's own client_body_timeout ends a quiet body read with a reset and no
    fixed refusal, keyed from the same stale clock as the policy's deadline. It must outlive the 10 s
    JS deadline plus its 0.5 s re-arm bound, or a re-armed refusal is lost (local run d00); and it can
    never stand in for that deadline. Selftest scale: a 200 ms JS budget behind the template's margin."""
    env = policy_runtime
    template, policy = _code_conf(TEMPLATE.read_text(encoding="utf-8")), POLICY.read_text(encoding="utf-8")
    backstop_ms = harness.body_idle_backstop_ms(template)
    assert backstop_ms == 11000 and backstop_ms > round((BODY_READ_S + SLACK_S) * 1000)
    assert "const BODY_READ_MS = 10000;" in policy and "const DEADLINE_SLACK_MS = 500;" in policy
    assert harness.policy_body_read_ms(policy) == round(BODY_READ_S * 1000)
    assert "reset_timedout_connection on;" in template and template.count("client_body_timeout") == 1
    budget = harness.SELFTEST_BODY_BUDGET_MS
    assert env.selftest_backstop_ms == budget + backstop_ms - 10000 > budget + 500
    pid = _native_counts(env, "pid")["worker_pid"]
    # The largest re-arm the policy allows (the full 500 ms) still delivers the fixed refusal first.
    result = _native(env, "b1", f"origin=1000&budget={budget}&clock=1000,700,1200", [(0, b"ab")], location="deadline_backstop")
    assert harness.parse_http(result["received"])[0::2] == (408, FIXED_REFUSAL) and result.get("peer_closed")
    assert _native_counts(env, "b1") == {"now": 3, "arm": 3, "early:selftest": 1, "rearm_ms:selftest": 500,
                                         "expired:selftest": 1, "refuse": 1, "worker_pid": pid}
    # Control: an idle timer equal to the JS budget loses even a 1 ms re-arm: reset, no byte, no refusal.
    result = _native(env, "b2", f"origin=1000&budget={budget}&clock=1000,1199,1200", [(0, b"ab")],
                     location="deadline_equal_backstop")
    assert result["received"] == b"" and result.get("error") == "ConnectionResetError", result.get("error")
    assert _native_counts(env, "b2") == {"now": 2, "arm": 2, "early:selftest": 1, "rearm_ms:selftest": 1, "worker_pid": pid}
    # The backstop never stands in for the JS deadline: with the JS deadline beyond it, nginx resets at
    # the backstop with no fixed refusal, which every deadline gate's assertion refuses.
    result = _native(env, "b3", "origin=1000&budget=5000&clock=1000", [(0, b"ab")], location="deadline_backstop")
    assert result["received"] == b"" and result.get("error") == "ConnectionResetError", result.get("error")
    assert env.selftest_backstop_ms - 100 <= result["elapsed_ms"] < 3000, result["elapsed_ms"]
    assert _native_counts(env, "b3") == {"now": 1, "arm": 1, "worker_pid": pid}
    with pytest.raises(AssertionError):
        _assert_fixed_refusal_at(result, 408, budget / 1000)
    assert _native_counts(env, "pid") == {"worker_pid": pid}


def _code_conf(template: str) -> str:
    return re.sub(r"#[^\n]*", "", template)


# ---------------------------------------------------------------------------------------------
# The composed fixture: real CP (in-memory, then task-local SQLite), the reviewed nginx/policy,
# the compiled Worker management client and real runner children. Cases below share one world
# and run in file order; a failing step leaves later steps failing too (first failure preserved).

class World:
    def __init__(self, env: harness.IngressEnvironment):
        self.env = env
        self.flows = harness.IngressFlows(env)
        self.state: dict = {}


@pytest.fixture(scope="module")
def world():
    env = _environment()
    try:
        env.start_cp("memory")
        env.render()
        assert env.nginx_test() == 0
        env.start_nginx()
        env.start_worker()
        yield World(env)
    finally:
        env.close()


def _proof_headers(paired: harness.PairedSlot, *, six: bool = True, **overrides) -> list[tuple[str, str]]:
    values = {
        "X-Heel-Runner-Id": paired.runner_id, "X-Heel-Runner-Key-Id": paired.runner_key_id,
        "X-Heel-Runner-Timestamp-Ms": "1792540000000",
        "X-Heel-Runner-Nonce": base64.b64encode(b"n" * 32).decode(),
        "X-Heel-Runner-Sequence": "1",
        "X-Heel-Runner-Signature": base64.b64encode(b"s" * 64).decode(),
    }
    if not six:
        values.pop("X-Heel-Runner-Nonce")
        values.pop("X-Heel-Runner-Sequence")
    values.update(overrides)
    return [(name, value) for name, value in values.items() if value is not None]


CLAIM_BODY = b'{"schema_version":"heel.runner-claim-request.v1"}'


def _claim_request(paired, *, target=None, headers=None, body=CLAIM_BODY, extra=(), host=harness.HOST,
                   method="POST", version="HTTP/1.1", length=None) -> bytes:
    target = target or f"/v1/workspaces/{paired.workspace_id}/runners/{paired.runner_id}/claim"
    base = [("Host", host), ("Content-Type", "application/json"),
            ("Content-Length", str(len(body)) if length is None else length), ("Accept", "application/json")]
    return harness.http_request(method, target, (headers if headers is not None else base + _proof_headers(paired)) + list(extra),
                                body, version)


def _slot_wire(world, slot: str, raw: bytes, **config) -> harness.Observation:
    return harness.observe(world.env, lambda: world.env.wire(slot, raw, **config))


# ---------------------------------------------------------------------------------------------
# G3 real positive ceremony (runs first; later gates reuse its state).

def test_g3_owner_signup_and_runner_pairing_over_both_listeners(world):
    flows = world.flows
    workspace, cookie = flows.signup("owner-a@example.test")
    paired = flows.pair("slot-a", workspace, cookie)
    world.state["a"] = paired
    world.state["cookie_a"] = cookie
    counters = world.env.counters()
    assert counters.get("forwarded:pairing_exchange:201") == 1
    assert counters.get("forwarded:pairing_activate:200", 0) >= 1
    assert counters.get("admitted:management:pairing_manage", 0) >= 2
    harness.record_case("g3.pair_exchange_approve_activate", "G3")


def test_g3_signed_context_list_claim_and_projection_submission(world):
    paired = world.state["a"]
    base, binding = world.flows.authorize_binding(paired)
    runner = paired.runner
    assert runner.call("open")["ok"]
    assert runner.call("ensure_context", timeout=60)["value"] is True
    submitted = runner.call("compile_submit", timeout=60)
    assert submitted["ok"], submitted.get("error")
    world.state.update(base_a=base, binding_a=binding, submitted_a=submitted)
    counters = world.env.counters()
    for name in ("forwarded:context_list:200", "forwarded:context_claim:200", "forwarded:context_submit:201"):
        assert counters.get(name) == 1, name
    harness.record_case("g3.context_list_claim_submit", "G3")


def test_g3_human_run_approval_then_claim_passes_the_unchanged_grant_verifier(world):
    paired = world.state["a"]
    grant = world.flows.approve_run(paired, world.state["base_a"], world.state["submitted_a"])
    claimed = paired.runner.call("claim", timeout=60)
    assert claimed["ok"], claimed.get("error")
    lease = claimed["lease"]
    # coordinator.claim returned only after validate_execution_bundle accepted the CP grant against
    # the authority saved at pairing and the immutable local approval.
    assert lease["verified"] is True and lease["grant_id"] == grant["grant_id"]
    assert lease["grant_digest"] == grant["grant_digest"]
    assert lease["signing_key_id"] == world.env.cp_info["grant_key_id"]
    world.state["grant_a"] = grant
    harness.record_case("g3.claim_grant_verified", "G3")
    # G6 one-shot replay, taken before any resync can supersede the claim chain: the exact retained
    # request returns the original receipt bytes and performs no second action.
    runner = paired.runner
    indexes = runner.call("wire_find", suffix="/claim", status=200)["indexes"]
    entry = runner.call("wire", index=[i for i in indexes if "/contexts/" not in runner.call("wire", index=i)["path"]][-1])
    replies = []
    replay = harness.observe(world.env, lambda: replies.append(runner.call(
        "send", path=entry["path"], headers=entry["headers"], body_b64=entry["body_b64"])) or {"status": replies[-1]["status"]})
    assert replay.status == 200 and replay.cp_contacted and replies[-1]["digest"] == entry["digest"]
    assert replay.changed_tables == []
    world.state["claim_entry_a"] = entry
    harness.record_case("g6.claim_receipt_replay", "G6", replay)


def test_g3_heartbeat_progress_resync_and_restart_with_the_retained_key(world):
    runner = world.state["a"].runner
    assert runner.call("heartbeat", timeout=60)["active"] is True
    assert runner.call("progress", timeout=60)["status"] == "running"
    assert runner.call("heartbeat", timeout=60)["active"] is True
    assert runner.call("resync", timeout=60)["generation"] >= 1
    restarted = runner.call("restart", timeout=60)
    assert restarted["ok"] and restarted["seeds"] == 1
    assert restarted["runner_key_id"] == world.state["a"].runner_key_id
    assert restarted["grant_authority_key_id"] == world.env.cp_info["grant_key_id"]
    assert runner.call("heartbeat", timeout=60)["active"] is True
    harness.record_case("g3.heartbeat_progress_resync_restart", "G3", seam="SEAM-RUNNER-SECRET RAM backend")


def test_g3_second_slot_pairs_and_claims_independently(world):
    _two_slots(world)
    flows = world.flows
    workspace, cookie = flows.signup("owner-b@example.test")
    paired = flows.pair("slot-b", workspace, cookie)
    base, binding = flows.authorize_binding(paired, name="Other")
    runner = paired.runner
    assert runner.call("open")["ok"] and runner.call("ensure_context", timeout=60)["value"] is True
    submitted = runner.call("compile_submit", timeout=60)
    grant = flows.approve_run(paired, base, submitted)
    claimed = runner.call("claim", timeout=60)
    assert claimed["ok"] and claimed["lease"]["grant_id"] == grant["grant_id"]
    world.state.update(b=paired, cookie_b=cookie, base_b=base, binding_b=binding, submitted_b=submitted, grant_b=grant)
    harness.record_case("g3.second_slot_claim", "G3")


# ---------------------------------------------------------------------------------------------
# G1 name/binding: the compiled Worker reaches CP only through the fixed adapter destination.

def test_g1_worker_management_requests_use_name_h_at_the_fixed_private_destination(world):
    env = world.env
    reply = env.browser("GET", "/v1/me", cookie=world.state["cookie_a"],
                        headers={"Host": "attacker.invalid", "X-Forwarded-Host": "attacker.invalid",
                                 "Forwarded": "host=attacker.invalid", "X-Heel-Internal-Origin": "https://attacker.invalid"})
    assert reply["status"] == 200
    (observation,) = reply["observations"]
    assert observation["servername"] == harness.HOST and observation["authorized"] is True
    assert observation["remote"] == f"{env.management[0]}:{env.management[1]}"
    assert observation["path"] == "/v1/me"
    harness.record_case("g1.fixed_destination_name_h", "G1", seam="SEAM-FAKE-VPC adapter")


def test_g1_query_and_unrouted_paths_never_reach_the_binding(world):
    env = world.env
    for path in ("/v1/me?host=attacker.invalid", "/v1/health", "/v1/metrics",
                 f"/v1/workspaces/{world.state['a'].workspace_id}/runners/{world.state['a'].runner_id}/contexts/"
                 f"{world.state['binding_a']['binding_id']}/plan-requests/claim"):
        reply = env.browser("GET" if "plan-requests" not in path else "POST", path, cookie=world.state["cookie_a"],
                            raw=b"{}" if "plan-requests" in path else None)
        assert reply["status"] in {400, 404}, path
        assert reply["observations"] == [], path
    harness.record_case("g1.no_fallback_for_refused_routes", "G1")


# ---------------------------------------------------------------------------------------------
# G2 management boundary.

def test_g2_login_and_session_checks_continue_through_the_ingress(world):
    env = world.env
    login = env.browser("POST", "/v1/login", {"email": "owner-a@example.test", "password": "correct-horse-battery"},
                        origin=None, fetch_site=None)
    assert login["status"] == 200 and login["set_cookie"]
    wrong = env.browser("POST", "/v1/login", {"email": "owner-a@example.test", "password": "wrong-horse-battery!"},
                        origin=None, fetch_site=None)
    assert wrong["status"] in {401, 403}
    harness.record_case("g2.login_through_ingress", "G2")


def test_g2_wrong_origin_and_duplicate_credentials_are_refused_before_any_binding_call(world):
    env, paired = world.env, world.state["a"]
    path = f"/v1/workspaces/{paired.workspace_id}/runner-pairings"
    body = {"schema_version": "heel.runner-pairing-invite.v1"}
    for kwargs in ({"origin": "https://attacker.invalid"}, {"fetch_site": "cross-site"},
                   {"headers": {"Authorization": "Bearer heel_sk_private"}}):
        reply = env.browser("POST", path, body, cookie=world.state["cookie_a"], **kwargs)
        assert reply["status"] == 400 and reply["observations"] == [], kwargs
    harness.record_case("g2.worker_origin_and_credential_refusals", "G2")


def test_g2_cross_workspace_human_action_is_refused_by_the_real_cp(world):
    _two_slots(world)
    env, paired_a = world.env, world.state["a"]
    before = env.snapshot()
    reply = env.browser("POST", f"/v1/workspaces/{paired_a.workspace_id}/runners/{paired_a.runner_id}/revoke",
                        {"schema_version": "heel.runner-revoke.v1", "reason_code": "human_revocation"},
                        cookie=world.state["cookie_b"])
    after = env.snapshot()
    assert reply["status"] in {403, 404} and len(reply["observations"]) == 1
    assert before["state"] == after["state"]
    harness.record_case("g2.cross_workspace_refused_by_cp", "G2")


def _management_request(world, *, target="/v1/me", edge=None, extra=(), method="GET", body=b"", host=harness.HOST):
    env = world.env
    headers = [("Host", host), ("X-Heel-Edge-Auth", env.edge_secret if edge is None else edge),
               ("Cookie", "heel_session=" + world.state["cookie_a"].split("=", 1)[1])]
    if method == "POST":
        headers += [("Content-Type", "application/json"), ("Content-Encoding", "identity"), ("Content-Length", str(len(body)))]
    return harness.http_request(method, target, headers + list(extra), body)


MANAGEMENT_REFUSALS = [
    ("wrong edge secret", {"edge": "x" * 43}, 403),
    ("missing edge secret", {"edge": ""}, 403),
    ("internal prefix", {"target": "/__heel_cp/v1/me"}, 404),
    ("health route", {"target": "/v1/health"}, 404),
    ("metrics route", {"target": "/v1/metrics"}, 404),
    ("unknown version", {"target": "/v2/me"}, 400),
    ("query", {"target": "/v1/me?x=1"}, 400),
    ("forwarded header", {"extra": [("X-Forwarded-For", "203.0.113.9")]}, 400),
    ("caller client key on me", {"extra": [("X-Heel-Client-Key", "0" * 64)]}, 400),
    ("runner proof with a cookie", {"target": None, "method": "POST"}, 400),
    ("wrong host", {"host": harness.ALIAS_HOST}, 421),
]


@pytest.mark.parametrize("label,kwargs,expected", MANAGEMENT_REFUSALS, ids=[case[0] for case in MANAGEMENT_REFUSALS])
def test_g2_management_listener_refuses_outside_the_worker_contract_without_cp_contact(world, label, kwargs, expected):
    paired = world.state["a"]
    kwargs = dict(kwargs)
    if kwargs.get("target", "") is None:
        kwargs["target"] = f"/v1/workspaces/{paired.workspace_id}/runners/{paired.runner_id}/claim"
        kwargs["body"] = CLAIM_BODY
        kwargs["extra"] = _proof_headers(paired)
    edge = kwargs.pop("edge", None)
    raw = _management_request(world, edge=edge, **kwargs)
    if edge == "":
        raw = raw.replace(b"X-Heel-Edge-Auth: \r\n", b"")
    observation = harness.observe(world.env, lambda: world.env.wire("management", raw))
    assert observation.status == expected, (label, observation.status)
    assert not observation.cp_contacted and observation.changed_tables == []
    harness.record_case("g2.management_refusal." + re.sub(r"[^a-z0-9]+", "_", label), "G2", observation)


def test_g2_management_control_with_the_correct_edge_secret_reaches_cp(world):
    observation = harness.observe(world.env, lambda: world.env.wire("management", _management_request(world)))
    assert observation.status == 200 and observation.cp_contacted
    harness.record_case("g2.management_direct_control", "G2", observation)


# ---------------------------------------------------------------------------------------------
# G4 TLS and authority negatives.

def _tls(world, slot="slot-a", **config) -> dict:
    address, port, _peer = world.env.slots[slot]
    return world.env.probe(slot, mode="tls", address=address, port=port, **config)


def test_g4_wrong_trust_name_and_missing_sni_fail_the_handshake(world):
    env = world.env
    from tests.support.edge_tls_harness import EphemeralCA

    wrong = EphemeralCA(env.root / "probe" / "wrong-ca", names=(harness.HOST,))
    assert _tls(world, server_name=harness.HOST, ca=str(wrong.ca_path))["tls"]["ok"] is False
    assert _tls(world, server_name="other.example", ca=str(env.public_ca))["tls"]["ok"] is False
    assert _tls(world, server_name=None, ca=None)["tls"]["ok"] is False
    assert _tls(world, server_name=harness.ALIAS_HOST, ca=None)["tls"]["ok"] is False
    assert _tls(world, server_name=harness.HOST, ca=str(env.public_ca))["tls"]["ok"] is True
    runner = world.state["a"].runner
    assert runner.call("trust_failure", ca=str(wrong.ca_path))["error"] == "tls_trust_failed"
    harness.record_case("g4.trust_name_sni", "G4", seam="SEAM-TEST-CA")


@pytest.mark.parametrize("leaf", ["wrong-name", "expired"])
def test_g4_wrong_name_or_expired_ingress_leaf_is_refused_by_the_real_runner_transport(world, leaf):
    env = world.env
    try:
        env.reload_nginx(leaf)
        assert _tls(world, server_name=harness.HOST, ca=str(env.public_ca))["tls"]["ok"] is False
        assert world.state["a"].runner.call("trust_failure", ca=str(env.public_ca))["error"] == "tls_trust_failed"
    finally:
        env.reload_nginx("primary")
    harness.record_case(f"g4.leaf_{leaf.replace('-', '_')}", "G4", seam="SEAM-TEST-CA")


def test_g4_validly_certified_alias_fails_ingress_name_policy(world):
    env, paired = world.env, world.state["a"]
    try:
        env.reload_nginx("alias")
        handshake = _tls(world, server_name=harness.ALIAS_HOST, ca=str(env.public_ca))
        assert handshake["tls"]["ok"] is False
        observation = _slot_wire(world, "slot-a", _claim_request(paired, host=harness.ALIAS_HOST))
        assert observation.status == 421 and not observation.cp_contacted
        assert "refused:host" in observation.reasons
        harness.record_case("g4.alias_refused", "G4", observation)
    finally:
        env.reload_nginx("primary")


def test_g4_host_differing_from_sni_is_refused(world):
    observation = _slot_wire(world, "slot-a", _claim_request(world.state["a"], host="other.example"))
    assert observation.status == 421 and not observation.cp_contacted and "refused:host" in observation.reasons
    harness.record_case("g4.host_not_sni", "G4", observation)


def test_g4_second_valid_leaf_reload_keeps_the_same_origin_and_runner_authority(world):
    env = world.env
    try:
        env.reload_nginx("second")
        assert world.state["a"].runner.call("heartbeat", timeout=60)["active"] is True
    finally:
        env.reload_nginx("primary")
    harness.record_case("g4.second_leaf_reload", "G4", seam="test leaf reload, not public renewal")


def test_g4_wrong_runner_key_proof_passes_ingress_syntax_and_fails_cp_without_state_change(world):
    paired = world.state["a"]
    nonce = paired.runner.call("chain", operation="claim")["nonce"]
    path = f"/v1/workspaces/{paired.workspace_id}/runners/{paired.runner_id}/claim"
    signed = paired.runner.call("sign_pop", path=path, body_b64=base64.b64encode(CLAIM_BODY).decode(),
                                capability="runner_claim", nonce=nonce, sequence=1, real=False)
    headers = [("Host", harness.HOST), ("Content-Type", "application/json"), ("Content-Length", str(len(CLAIM_BODY)))]
    headers += [(name, value) for name, value in signed["headers"].items() if name != "Content-Type"]
    observation = _slot_wire(world, "slot-a", harness.http_request("POST", path, headers, CLAIM_BODY))
    assert observation.cp_contacted and observation.status == 401
    assert observation.changed_tables == []
    harness.record_case("g4.wrong_runner_key", "G4", observation)


# ---------------------------------------------------------------------------------------------
# G5 identities, lifecycle and the trusted registry.

def _swap_cases(world):
    a, b = world.state["a"], world.state["b"]
    ra, rb = world.state["submitted_a"]["run_id"], world.state["submitted_b"]["run_id"]
    ca = world.state["binding_a"]["binding_id"]
    return [
        ("workspace from slot b", _claim_request(a, target=f"/v1/workspaces/{b.workspace_id}/runners/{a.runner_id}/claim")),
        ("runner id from slot b in path", _claim_request(a, target=f"/v1/workspaces/{a.workspace_id}/runners/{b.runner_id}/claim")),
        ("runner id header from slot b", _claim_request(a, headers=[("Host", harness.HOST), ("Content-Type", "application/json"),
                                                                     ("Content-Length", str(len(CLAIM_BODY)))]
                                                        + _proof_headers(a, **{"X-Heel-Runner-Id": b.runner_id}))),
        ("key id from slot b", _claim_request(a, headers=[("Host", harness.HOST), ("Content-Type", "application/json"),
                                                           ("Content-Length", str(len(CLAIM_BODY)))]
                                              + _proof_headers(a, **{"X-Heel-Runner-Key-Id": b.runner_key_id}))),
        ("run from slot b", _claim_request(a, target=f"/v1/workspaces/{a.workspace_id}/runners/{a.runner_id}/runs/{rb}/heartbeat")),
        ("unregistered context", _claim_request(a, target=f"/v1/workspaces/{a.workspace_id}/runners/{a.runner_id}/contexts/rcb_{'0' * 32}/claim")),
        ("context digest mismatch", _claim_request(a, target=f"/v1/workspaces/{a.workspace_id}/runners/{a.runner_id}/contexts/{ca}/claim",
                                                   body=b'{"binding_digest":"' + b"0" * 64 + b'","binding_id":"' + ca.encode()
                                                   + b'","schema_version":"heel.runner-context-claim.v1"}')),
        ("run body names another run", _claim_request(a, target=f"/v1/workspaces/{a.workspace_id}/runners/{a.runner_id}/runs/{ra}/heartbeat",
                                                      body=b'{"operational_projection":{},"run_id":"' + rb.encode()
                                                      + b'","schema_version":"heel.runner-heartbeat-request.v1"}')),
    ]


def test_g5_identities_swapped_across_slots_are_refused_before_cp(world):
    _two_slots(world)
    for label, raw in _swap_cases(world):
        observation = _slot_wire(world, "slot-a", raw)
        assert observation.status in {400, 403}, (label, observation.status)
        assert not observation.cp_contacted and observation.changed_tables == [], label
        harness.record_case("g5.swap." + re.sub(r"[^a-z0-9]+", "_", label), "G5", observation)


def test_g5_slot_b_identity_presented_at_slot_a_listener_is_refused(world):
    _two_slots(world)
    b = world.state["b"]
    observation = _slot_wire(world, "slot-a", _claim_request(b))
    assert observation.status == 403 and not observation.cp_contacted
    harness.record_case("g5.foreign_slot_identity", "G5", observation)


def test_g5_well_formed_forgery_reaches_cp_and_fails_without_state_change(world):
    observation = _slot_wire(world, "slot-a", _claim_request(world.state["a"]))
    assert observation.cp_contacted and observation.status == 401 and observation.changed_tables == []
    harness.record_case("g5.forgery_fails_at_cp", "G5", observation)


def _registry_restored(world):
    world.env.registry.publish()


REGISTRY_FAULTS = [
    ("missing", lambda env: env.registry.path.unlink()),
    ("malformed", lambda env: env.registry.write_raw(b"{")),
    ("unknown field", lambda env: env.registry.write_raw(harness.canonical_registry_bytes(
        {**env.registry.document(env.registry.generation + 1), "extra": 1}))),
    ("oversize", lambda env: env.registry.write_raw(b" " * (64 * 1024 + 1))),
    ("duplicate key", lambda env: env.registry.write_raw(
        harness.canonical_registry_bytes(env.registry.document(env.registry.generation + 1))[:-1] + b',"slots":[]}')),
    ("group writable", lambda env: env.registry.write_raw(
        harness.canonical_registry_bytes(env.registry.document(env.registry.generation + 1)), mode=0o664)),
    ("symlink", lambda env: env.registry.replace_with_symlink(env.root / "probe")),
    ("wrong boot", lambda env: env.registry.write_raw(harness.canonical_registry_bytes(
        {**env.registry.document(env.registry.generation + 1), "host_boot_epoch": "boot-other-epoch"}))),
    ("expired", lambda env: env.registry.write_raw(harness.canonical_registry_bytes(
        {**env.registry.document(env.registry.generation + 1), "expires_at_ms": 1}))),
    ("stale generation", lambda env: env.registry.write_raw(harness.canonical_registry_bytes(
        env.registry.document(1)))),
    ("invalid phase", lambda env: env.registry.write_raw(harness.canonical_registry_bytes(
        {**env.registry.document(env.registry.generation + 1),
         "slots": [dict(slot, phase="paused") for slot in env.registry.document()["slots"]]}))),
]


@pytest.mark.parametrize("label,fault", REGISTRY_FAULTS, ids=[case[0] for case in REGISTRY_FAULTS])
def test_g5_unusable_registry_denies_before_cp_contact(world, label, fault):
    env = world.env
    try:
        fault(env)
        observation = _slot_wire(world, "slot-a", _claim_request(world.state["a"]))
    finally:
        with __import__("contextlib").suppress(FileNotFoundError):
            env.registry.path.unlink()
        _registry_restored(world)
    assert observation.status == 503 and not observation.cp_contacted, (label, observation.status)
    harness.record_case("g5.registry." + re.sub(r"[^a-z0-9]+", "_", label), "G5", observation)


def test_g5_registry_owned_by_another_uid_denies(world):
    env = world.env
    harness.require_linux_topology(env.topology, "UID-separated registry ownership")
    try:
        env.registry.publish()
        os.chown(env.registry.path, harness.UIDS["slot-a"], harness.UIDS["slot-a"])
        observation = _slot_wire(world, "slot-a", _claim_request(world.state["a"]))
    finally:
        _registry_restored(world)
    assert observation.status == 503 and not observation.cp_contacted
    harness.record_case("g5.registry.wrong_owner", "G5", observation)


@pytest.mark.parametrize("phase", ["closed", "invited", "pending", "retired", "stopping"])
def test_g5_slot_phase_gates_runner_claims(world, phase):
    env, paired = world.env, world.state["a"]
    slot = env.registry.slot("slot-a")
    saved = {key: getattr(slot, key) for key in ("phase", "runner", "invitation", "pairing", "contexts", "runs", "workspace_id")}
    try:
        if phase in {"closed", "retired"}:
            slot.runner = slot.invitation = slot.pairing = None
            slot.contexts, slot.runs = [], []
        elif phase == "invited":
            slot.runner = slot.pairing = None
            slot.contexts, slot.runs = [], []
            slot.invitation = {"token_sha256": "0" * 64, "pairing_id": "pending_" + "0" * 32, "expires_at_ms": 2 ** 52,
                               "expected_public_key_b64": base64.b64encode(b"k" * 32).decode(), "expected_fingerprint": "0" * 64}
        elif phase == "pending":
            slot.runner = None
            slot.contexts, slot.runs = [], []
        slot.phase = phase
        env.registry.publish()
        observation = _slot_wire(world, "slot-a", _claim_request(paired))
    finally:
        for key, value in saved.items():
            setattr(slot, key, value)
        env.registry.publish()
    assert observation.status == 403 and not observation.cp_contacted
    harness.record_case(f"g5.phase.{phase}", "G5", observation)


def test_g5_unapproved_pairing_activation_reaches_cp_and_is_refused(world):
    env, flows = world.env, world.flows
    workspace, cookie = world.state["a"].workspace_id, world.state["cookie_a"]
    token = flows.invite(workspace, cookie)
    (invited,) = env.cp_call("pairing_for_token", token=token)["rows"]
    # Pending registry for a ceremony the human never approves: the CP owns the refusal.
    slot = env.registry.slot("slot-a")
    saved = {key: getattr(slot, key) for key in ("phase", "pairing")}
    try:
        slot.pairing = dict(slot.pairing, pairing_id=invited["pairing_id"], expires_at_ms=2 ** 52)
        env.registry.publish()
        body = harness.canonical_json({"client_activation_nonce_b64": base64.b64encode(b"c" * 32).decode(),
                                       "schema_version": "heel.runner-pairing-activate.v3",
                                       "signature_b64": base64.b64encode(b"s" * 64).decode()})
        raw = harness.http_request("POST", f"/v1/runner-pairings/{invited['pairing_id']}/activate",
                                   [("Host", harness.HOST), ("Content-Type", "application/json"),
                                    ("Content-Length", str(len(body)))], body)
        observation = _slot_wire(world, "slot-a", raw)
    finally:
        for key, value in saved.items():
            setattr(slot, key, value)
        env.registry.publish()
    assert observation.cp_contacted and observation.status == 400 and observation.changed_tables == []
    harness.record_case("g5.unapproved_pairing", "G5", observation)


# ---------------------------------------------------------------------------------------------
# G6 replay.

def test_g6_reused_invitation_is_refused_by_ingress_phase_and_by_cp(world):
    paired = world.state["a"]
    (index,) = paired.runner.call("wire_find", suffix="/runner-pairings/exchange")["indexes"][:1]
    entry = paired.runner.call("wire", index=index)
    observation = harness.observe(world.env, lambda: {"status": paired.runner.call(
        "send", path=entry["path"], headers=entry["headers"], body_b64=entry["body_b64"])["status"]})
    assert observation.status == 403 and not observation.cp_contacted
    harness.record_case("g6.reused_invitation_ingress", "G6", observation)


def test_g6_exact_activation_retry_returns_the_original_receipt_without_a_second_action(world):
    paired = world.state["a"]
    indexes = paired.runner.call("wire_find", suffix="/activate", status=200)["indexes"]
    entry = paired.runner.call("wire", index=indexes[-1])
    sent = []
    observation = harness.observe(world.env, lambda: sent.append(paired.runner.call(
        "send", path=entry["path"], headers=entry["headers"], body_b64=entry["body_b64"])) or {"status": sent[-1]["status"]})
    assert observation.status == 200 and observation.cp_contacted
    assert sent[-1]["digest"] == entry["digest"]
    assert observation.changed_tables == []
    harness.record_case("g6.activation_receipt_replay", "G6", observation)


def test_g6_mutated_claim_retries_fail_without_a_second_action(world):
    _two_slots(world)
    paired = world.state["a"]
    entry = world.state["claim_entry_a"]
    replies = []

    def send(headers=None, body_b64=None, path=None):
        replies.append(paired.runner.call("send", path=path or entry["path"], headers=headers or entry["headers"],
                                          body_b64=body_b64 or entry["body_b64"]))
        return {"status": replies[-1]["status"]}

    mutated_sequence = dict(entry["headers"], **{"X-Heel-Runner-Sequence": "999"})
    mutated_signature = dict(entry["headers"], **{"X-Heel-Runner-Signature": base64.b64encode(b"z" * 64).decode()})
    mutated_body = base64.b64encode(b'{"schema_version":"heel.runner-claim-request.v2"}').decode()
    for label, kwargs in (("sequence", {"headers": mutated_sequence}), ("signature", {"headers": mutated_signature})):
        observation = harness.observe(world.env, lambda kwargs=kwargs: send(**kwargs))
        assert observation.status in {400, 401, 409}, (label, observation.status)
        assert observation.changed_tables == [], label
        harness.record_case(f"g6.claim_mutated_{label}", "G6", observation)
    # The only admissible claim body is the v1 literal: the reviewed policy refuses a mutated body at
    # ingress (403 identity) before any CP contact. Recorded first, so a failure still carries its status.
    observation = harness.observe(world.env, lambda: send(body_b64=mutated_body))
    harness.record_case("g6.claim_mutated_body", "G6", observation)
    assert observation.status == 403 and not observation.cp_contacted and observation.changed_tables == [], observation.status
    mutated_key = dict(entry["headers"], **{"X-Heel-Runner-Key-Id": world.state["b"].runner_key_id})
    observation = harness.observe(world.env, lambda: send(headers=mutated_key))
    assert observation.status == 403 and not observation.cp_contacted
    harness.record_case("g6.claim_mutated_key", "G6", observation)


def test_g6_stale_unseen_request_fails_at_cp(world):
    paired = world.state["a"]
    nonce = paired.runner.call("chain", operation="claim")["nonce"]
    path = f"/v1/workspaces/{paired.workspace_id}/runners/{paired.runner_id}/claim"
    signed = paired.runner.call("sign_pop", path=path, body_b64=base64.b64encode(CLAIM_BODY).decode(),
                                capability="runner_claim", nonce=nonce, sequence=9, real=True, timestamp_ms=1600000000000)
    headers = signed["headers"]
    observation = harness.observe(world.env, lambda: {"status": paired.runner.call(
        "send", path=path, headers=headers, body_b64=base64.b64encode(CLAIM_BODY).decode())["status"]})
    assert observation.cp_contacted and observation.status == 401 and observation.changed_tables == []
    harness.record_case("g6.stale_request", "G6", observation)


def test_g6_request_from_a_superseded_generation_fails_after_resync(world):
    paired = world.state["a"]
    indexes = paired.runner.call("wire_find", suffix="/heartbeat", status=200)["indexes"]
    entry = paired.runner.call("wire", index=indexes[0])
    assert paired.runner.call("resync", timeout=60)["ok"]
    observation = harness.observe(world.env, lambda: {"status": paired.runner.call(
        "send", path=entry["path"], headers=entry["headers"], body_b64=entry["body_b64"])["status"]})
    assert observation.cp_contacted and observation.status in {200, 401, 409}
    # A retained exact receipt may be returned, but never a second action.
    assert observation.changed_tables == []
    harness.record_case("g6.superseded_generation", "G6", observation)


# ---------------------------------------------------------------------------------------------
# G7 raw HTTP: every probe traverses the real nginx listener over TLS from the runner namespace.

def _base_headers(paired, body=CLAIM_BODY):
    return [("Host", harness.HOST), ("Content-Type", "application/json"), ("Content-Length", str(len(body)))] + _proof_headers(paired)


def _raw_cases(paired):
    claim = f"/v1/workspaces/{paired.workspace_id}/runners/{paired.runner_id}/claim"
    nonce = base64.b64encode(b"n" * 32).decode()
    base = _base_headers(paired)

    def with_headers(extra):
        return harness.http_request("POST", claim, base + extra, CLAIM_BODY)

    def without(name):
        return [(key, value) for key, value in base if key.lower() != name.lower()]

    raw = {
        "duplicate identical nonce": with_headers([("X-Heel-Runner-Nonce", nonce)]),
        "duplicate conflicting nonce": with_headers([("X-Heel-Runner-Nonce", base64.b64encode(b"m" * 32).decode())]),
        "case varied duplicate nonce": with_headers([("x-heel-runner-nonce", nonce)]),
        "duplicate host": with_headers([("Host", harness.HOST)]),
        "duplicate content length": with_headers([("Content-Length", str(len(CLAIM_BODY)))]),
        "duplicate content type": with_headers([("Content-Type", "application/json")]),
        "comma joined nonce": harness.http_request("POST", claim, without("X-Heel-Runner-Nonce") + [("X-Heel-Runner-Nonce", nonce + "," + nonce)], CLAIM_BODY),
        "bare carriage return in value": with_headers([("X-Extra", "a\rb")]),
        "nul in value": with_headers([("X-Extra", "a\0b")]),
        "obs fold continuation": harness.http_request("POST", claim, base[:1] + [("X-Folded", "a")] + base[1:], CLAIM_BODY)
        .replace(b"X-Folded: a\r\n", b"X-Folded: a\r\n continued\r\n"),
        "connection nominated proof": with_headers([("Connection", "X-Heel-Runner-Nonce")]),
        "transfer encoding with length": with_headers([("Transfer-Encoding", "chunked")]),
        "chunked without length": harness.http_request("POST", claim, without("Content-Length") + [("Transfer-Encoding", "chunked")],
                                                       b"%x\r\n" % len(CLAIM_BODY) + CLAIM_BODY + b"\r\n0\r\n\r\n"),
        "trailer header": with_headers([("Trailer", "X-Heel-Runner-Nonce")]),
        "gzip content encoding": with_headers([("Content-Encoding", "gzip")]),
        "expect continue": with_headers([("Expect", "100-continue")]),
        "unknown header": with_headers([("X-Unknown", "1")]),
        "underscore header name": with_headers([("X_Heel_Runner_Id", paired.runner_id)]),
        "overlong field": with_headers([("X-Long", "a" * 1100)]),
        "forwarded for": with_headers([("X-Forwarded-For", "203.0.113.1")]),
        "forwarded": with_headers([("Forwarded", "for=203.0.113.1")]),
        "cf connecting ip": with_headers([("CF-Connecting-IP", "203.0.113.1")]),
        "caller edge secret": with_headers([("X-Heel-Edge-Auth", "x" * 43)]),
        "cookie": with_headers([("Cookie", "heel_session=abc")]),
        "authorization": with_headers([("Authorization", "Bearer heel_sk_abc")]),
        "origin": with_headers([("Origin", harness.ORIGIN)]),
        "internal origin": with_headers([("X-Heel-Internal-Origin", "same-origin")]),
        "upgrade websocket": with_headers([("Upgrade", "websocket")]),
        "supplied slot header": with_headers([("X-Heel-Slot", "slot-b")]),
        "wrong content type": harness.http_request("POST", claim, without("Content-Type") + [("Content-Type", "text/plain")], CLAIM_BODY),
        "content type parameter": harness.http_request("POST", claim, without("Content-Type") + [("Content-Type", "application/json; charset=utf-8")], CLAIM_BODY),
        "noncanonical length": harness.http_request("POST", claim, without("Content-Length") + [("Content-Length", "0" + str(len(CLAIM_BODY)))], CLAIM_BODY),
        "noncanonical nonce": harness.http_request("POST", claim, without("X-Heel-Runner-Nonce") + [("X-Heel-Runner-Nonce", nonce[:-2] + "B=")], CLAIM_BODY),
        "noncanonical sequence": harness.http_request("POST", claim, without("X-Heel-Runner-Sequence") + [("X-Heel-Runner-Sequence", "01")], CLAIM_BODY),
        "zero sequence": harness.http_request("POST", claim, without("X-Heel-Runner-Sequence") + [("X-Heel-Runner-Sequence", "0")], CLAIM_BODY),
        "missing proof header": harness.http_request("POST", claim, without("X-Heel-Runner-Signature"), CLAIM_BODY),
        "resync forbidden nonce": harness.http_request("POST", claim.replace("/claim", "/resync/start"), base, CLAIM_BODY),
    }
    for label, target in {
        "encoded slash": claim.replace("/runners/", "/runners%2F"), "encoded dot segment": claim.replace("/claim", "/%2e/claim"),
        "percent encoded letter": claim.replace("/claim", "/cl%61im"), "backslash": claim.replace("/claim", "\\claim"),
        "double slash": claim.replace("/runners/", "/runners//"), "trailing slash": claim + "/",
        "query": claim + "?a=1", "empty query": claim + "?", "fragment": claim + "#x",
        "dot segment": claim.replace("/runners/", "/./runners/"), "uppercase version": claim.replace("/v1/", "/V1/"),
        "absolute form": "https://heel.example" + claim, "internal prefix": "/__heel_cp" + claim,
        "encoded internal prefix": "/%5F_heel_cp" + claim,
        "arbitrary project url": f"/v1/workspaces/{paired.workspace_id}/projects",
        "plan request route": f"/v1/workspaces/{paired.workspace_id}/runners/{paired.runner_id}/contexts/rcb_{'0' * 32}/plan-requests/claim",
        "health": "/v1/health", "metrics": "/v1/metrics", "suffix match": claim + "-extra",
    }.items():
        raw[label] = harness.http_request("POST", target, base, CLAIM_BODY)
    raw["get method"] = harness.http_request("GET", claim, base, CLAIM_BODY)
    raw["delete method"] = harness.http_request("DELETE", claim, base, CLAIM_BODY)
    raw["http 1.0"] = harness.http_request("POST", claim, base, CLAIM_BODY, version="HTTP/1.0")
    raw["connect"] = b"CONNECT heel.example:443 HTTP/1.1\r\nHost: heel.example\r\n\r\n"
    raw["http2 preface"] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    raw["http 0.9"] = ("GET " + claim + "\r\n").encode()
    return raw


G7_LABELS = [
    "duplicate identical nonce", "duplicate conflicting nonce", "case varied duplicate nonce", "duplicate host",
    "duplicate content length", "duplicate content type", "comma joined nonce", "bare carriage return in value",
    "nul in value", "obs fold continuation", "connection nominated proof", "transfer encoding with length",
    "chunked without length", "trailer header", "gzip content encoding", "expect continue", "unknown header",
    "underscore header name", "overlong field", "forwarded for", "forwarded", "cf connecting ip", "caller edge secret",
    "cookie", "authorization", "origin", "internal origin", "upgrade websocket", "supplied slot header",
    "wrong content type", "content type parameter", "noncanonical length", "noncanonical nonce",
    "noncanonical sequence", "zero sequence", "missing proof header", "resync forbidden nonce", "encoded slash",
    "encoded dot segment", "percent encoded letter", "backslash", "double slash", "trailing slash", "query",
    "empty query", "fragment", "dot segment", "uppercase version", "absolute form", "internal prefix",
    "encoded internal prefix", "arbitrary project url", "plan request route", "health", "metrics", "suffix match",
    "get method", "delete method", "http 1.0", "connect", "http2 preface", "http 0.9",
]


@pytest.mark.parametrize("label", G7_LABELS)
def test_g7_raw_wire_variant_is_refused_without_cp_contact(world, label):
    raw = _raw_cases(world.state["a"])[label]
    observation = _slot_wire(world, "slot-a", raw)
    assert observation.status is None or 400 <= observation.status <= 499, (label, observation.status)
    # Exact wire record: nginx sends 100 Continue only while discarding the body of a refused
    # HTTP/1.1 Expect request (ngx_http_discard_request_body); no other interim response appears.
    assert observation.interim == ([100] if label == "expect continue" else []), (label, observation.interim)
    assert not observation.cp_contacted, label
    assert observation.changed_tables == [], label
    harness.record_case("g7." + re.sub(r"[^a-z0-9]+", "_", label), "G7", observation)


def test_g7_g7_cases_cover_the_whole_table(world):
    assert sorted(_raw_cases(world.state["a"])) == sorted(G7_LABELS)


# ---------------------------------------------------------------------------------------------
# G8 caps, time and resources.

def _boundary_submission(binding: dict, projection: dict, size: int) -> bytes:
    """The runner's real compiled projection with correct identity, canonical bytes and a bounded
    padding member sized to the exact total. The padding makes it contract-invalid on purpose: no
    contract-valid submission can reach these sizes (see the carried-limit case below)."""
    pad: list[str] = []
    head = {"approval_projection": dict(projection, pad=pad), "context_binding_digest": binding["binding_digest"],
            "context_binding_id": binding["binding_id"], "schema_version": "heel.runner-approval-projection-submit.v1"}
    remaining = size - len(harness.canonical_json(head))
    while remaining > 0:
        cost = 2 + (1 if pad else 0)
        chunk = min(4000, remaining - cost)
        if remaining - cost - chunk in range(1, 4):
            chunk -= 4
        pad.append("p" * chunk)
        remaining -= chunk + cost
    body = harness.canonical_json(head)
    assert len(body) == size, (len(body), size)
    return body


def _maximal_submission_upper_bound() -> int:
    """Canonical size of a submission with every variable field at its contract maximum
    (heel/canary_contracts.py: identifiers 128 bytes, routes and origins 1,024, at most 20
    actions/versions/statuses, 4 scenarios, 9 body shapes, 2 retry codes, 999-sized integers)."""
    from heel.canary_contracts import canonical_bytes

    ident, digest, signature = "i" * 128, "f" * 64, "A" * 86 + "=="
    big = 9007199254740991
    action = {"ordinal": 19, "scenario_id": ident, "adapter_version": ident, "method": "HEAD",
              "route_template": "/" + "r" * 1023, "semantic_auth_role": ident, "assertion_class": "anonymous_authenticated",
              "allowed_status_codes": list(range(580, 600)), "side_effect_class": "read_only",
              "allowed_body_shapes": sorted(["absent", "empty", "json_object", "json_array", "json_scalar", "text", "binary", "truncated", "invalid"])}
    projection = {
        "schema_version": "heel.approval-manifest-projection.v1", "projection_id": ident, "workspace_id": ident,
        "project_id": ident, "environment": {"environment_id": ident, "verification_record_digest": digest,
                                             "origin": "https://" + "h" * 1016, "environment_class": "sandbox"},
        "runner": {"runner_id": ident, "runner_key_id": ident, "runner_version": ident, "adapter_versions": [ident] * 20},
        "compiler": {"compiler_version": ident, "engine_version": ident},
        "scenarios": [{"ordinal": 3, "scenario_id": ident, "adapter_version": ident}] * 4, "actions": [action] * 20,
        "budgets": {key: big for key in ("maximum_requests", "maximum_concurrency", "action_timeout_ms", "wall_timeout_ms",
                                         "maximum_response_bytes")},
        "egress": {"hostname": ident, "port": 443, "redirect_policy": "deny"},
        "retry_policy": {"maximum_retries": 1, "retryable_failure_codes": ["connect_error", "timeout"]},
        "compiled_at_ms": big, "manifest_digest": digest, "projection_digest": digest, "signing_key_id": ident,
        "signature_b64": signature,
    }
    body = {"schema_version": "heel.runner-approval-projection-submit.v1", "context_binding_id": "rcb_" + "0" * 32,
            "context_binding_digest": digest, "approval_projection": projection}
    return len(canonical_bytes(body))


def test_g8_largest_contract_valid_projection_submission_stays_below_the_carried_cp_framing_cap(world):
    # Carried, pre-existing limitation (protocol-contract.md): CP framing 65,536 vs handler 69,632.
    # No contract-valid submission can reach either boundary; the ingress keeps the Worker's 69,632
    # cap and repairs nothing. The boundary bytes themselves are exercised in the next case.
    bound = _maximal_submission_upper_bound()
    assert bound < 65536, bound
    harness.record_case("g8.carried_projection_cap_unreachable_by_valid_content", "G8",
                        seam="computed contract maximum below 65536")


def test_g8_projection_boundaries_with_real_pop_reach_the_handler_then_cp_framing_then_ingress(world):
    """Exact per-layer outcomes at the carried boundary. The CP parses (max 69,632) and runs
    validate_runner_approval_projection_submit before its PoP check and answers every handler
    refusal with the closed 401 invalid_runner_auth (heel/saas/http_api.py _runner_request); its
    generic framing refuses bodies above 65,536 with 413 first. The same real-PoP send of the
    unpadded real projection is accepted (201), so the signing path itself is proven."""
    paired, binding = world.state["a"], world.state["binding_a"]
    projection = world.state["submitted_a"]["projection"]
    path = f"/v1/workspaces/{paired.workspace_id}/runners/{paired.runner_id}/contexts/{binding['binding_id']}/approval-projections"
    results, replies = {}, {}
    for size in (65536, 65537, 69632):
        body = _boundary_submission(binding, projection, size)
        sent = []
        results[size] = harness.observe(world.env, lambda body=body: sent.append(paired.runner.call(
            "pop_send", path=path, body_b64=base64.b64encode(body).decode(), capability="runner_claim",
            operation="claim", realign=False, timeout=60)) or {"status": sent[-1]["status"]})
        replies[size] = sent[-1]
    body = _boundary_submission(binding, projection, 69633)
    raw = harness.http_request("POST", path, _base_headers(paired, body), body)
    results[69633] = _slot_wire(world, "slot-a", raw, read_timeout=20)
    detail = {size: (o.status, o.cp_contacted, replies.get(size, {}).get("code")) for size, o in results.items()}
    # 65,536: inside CP framing; refused by the submission handler's own contract check.
    assert (results[65536].status, replies[65536]["code"], results[65536].cp_contacted) == (401, "invalid_runner_auth", True), detail
    # 65,537 and 69,632: the CP's own pre-existing 65,536-byte framing refusal, reproduced and logged.
    assert (results[65537].status, replies[65537]["code"], results[65537].cp_contacted) == (413, None, True), detail
    assert (results[69632].status, replies[69632]["code"], results[69632].cp_contacted) == (413, None, True), detail
    # 69,633: one byte over the Worker cap, refused by the ingress before any CP contact.
    assert (results[69633].status, results[69633].cp_contacted) == (413, False), detail
    assert results[69633].body == b'{"error":"ingress refused"}' and "refused:length" in results[69633].reasons
    for size, observation in results.items():
        # Every refusal precedes the PoP transaction: no nonce, receipt, projection or run changes.
        assert observation.changed_tables == [], (size, observation.changed_tables)
        harness.record_case(f"g8.projection_size_{size}", "G8", observation)
    real = harness.canonical_json({"approval_projection": projection, "context_binding_digest": binding["binding_digest"],
                                   "context_binding_id": binding["binding_id"],
                                   "schema_version": "heel.runner-approval-projection-submit.v1"})
    accepted = paired.runner.call("pop_send", path=path, body_b64=base64.b64encode(real).decode(), capability="runner_claim",
                                  operation="claim", timeout=60)
    assert accepted["status"] in {200, 201}, accepted
    claim = _claim_request(paired, body=b" " * 257)
    observation = _slot_wire(world, "slot-a", claim)
    assert observation.status == 413 and not observation.cp_contacted
    harness.record_case("g8.claim_cap_plus_one", "G8", observation)


def test_g8_truncated_body_never_forwards_and_extra_bytes_never_reach_a_second_action(world):
    paired = world.state["a"]
    truncated = _claim_request(paired, length="100")
    observation = _slot_wire(world, "slot-a", truncated, read_timeout=14)
    assert not observation.cp_contacted and (observation.status is None or observation.status >= 400)
    harness.record_case("g8.truncated_body", "G8", observation)
    pipelined = _claim_request(paired) + _claim_request(paired)
    observation = _slot_wire(world, "slot-a", pipelined)
    assert observation.result["received"].count(b"HTTP/1.1 ") == 1
    assert world.env.snapshot()["requests"] >= 0
    harness.record_case("g8.extra_bytes_one_message", "G8", observation)


def test_g8_slow_headers_are_cut_off_without_cp_contact(world):
    paired = world.state["a"]
    raw = _claim_request(paired)
    split = raw.index(b"\r\n\r\n") + 4
    slow_headers = [[0, _b64(raw[:20])], [12000, _b64(raw[20:split])]]
    observation = harness.observe(world.env, lambda: world.env.wire("slot-a", b"", chunks=slow_headers, read_timeout=20))
    assert not observation.cp_contacted and observation.status in {None, 408}
    harness.record_case("g8.slow_headers", "G8", observation)


def test_g8_client_disconnect_mid_body_leaves_no_pending_work(world):
    paired = world.state["a"]
    raw = _claim_request(paired)
    split = raw.index(b"\r\n\r\n") + 4
    observation = harness.observe(world.env, lambda: world.env.wire(
        "slot-a", b"", chunks=[[0, base64.b64encode(raw[:split + 3]).decode()]], close_after_send=True))
    assert not observation.cp_contacted
    # The listener is still healthy afterwards (no stuck worker or leaked admission).
    after = _slot_wire(world, "slot-a", _claim_request(paired))
    assert after.status == 401 and after.cp_contacted
    harness.record_case("g8.client_disconnect", "G8", observation)


# G8 total deadlines (H0BTD section 7). Times are wall-clock marks from the probe child: t0 = the
# moment the complete header block was sent, then the first response byte and the peer's close.
# nginx's own client_body_timeout is an idle timer; only the policy deadline bounds a dribble.
# H0BR3: the policy refuses only once Date.now() reaches origin + budget, so the lower bound is
# checked on that integer-millisecond grid from the probe's time_ns() mark taken before sendall
# (never after the server's origin on the same CLOCK_REALTIME). Every maximum stays unrounded: the
# post-sendall float marks exactly as before, and the pre-sendall ns marks (stricter by the sendall).

BODY_READ_S = 10.0
TOTAL_BUDGET_S = 25.0
SLACK_S = 0.5
FIXED_REFUSAL = b'{"error":"ingress refused"}'
NS_PER_MS = 1_000_000
DEADLINE_ANOMALIES = ("early_final:", "deadline_invalid:")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _marks(result: dict) -> tuple[float, float | None, float | None]:
    wall = result.get("wall") or {}
    return wall["sent"][0], wall.get("first_byte"), wall.get("closed")


def _ns_marks(result: dict) -> tuple[object, object, object]:
    wall = result.get("wall") or {}
    return (wall.get("sent_ns") or [None])[0], wall.get("first_byte_ns"), wall.get("closed_ns")


def _assert_fixed_refusal_at(observation_or_result, status: int, seconds: float) -> None:
    result = observation_or_result.result if isinstance(observation_or_result, harness.Observation) else observation_or_result
    got, _headers, body = harness.parse_http(result["received"])
    t0, first, closed = _marks(result)
    t0_ns, first_ns, closed_ns = _ns_marks(result)
    limit_ns = round((seconds + SLACK_S) * 1000) * NS_PER_MS
    assert got == status and body == FIXED_REFUSAL, (got, body[:64])
    assert result["received"].count(b"HTTP/1.1 ") == 1
    assert type(t0_ns) is int and type(first_ns) is int and type(closed_ns) is int, (t0_ns, first_ns, closed_ns)
    assert first_ns // NS_PER_MS - t0_ns // NS_PER_MS >= round(seconds * 1000), first_ns - t0_ns
    assert first is not None and first - t0 <= seconds + SLACK_S, first - t0
    assert first_ns - t0_ns <= limit_ns, first_ns - t0_ns
    assert closed is not None and closed - t0 <= seconds + SLACK_S, (closed or 0) - t0
    assert closed_ns - t0_ns <= limit_ns, closed_ns - t0_ns


def _assert_no_deadline_anomaly(names) -> None:
    # H0BR3: early wakes re-arm (counted early:*, expected staleness); the anomaly paths never run.
    assert [name for name in names if name.startswith(DEADLINE_ANOMALIES)] == []


def _assert_worker_unchanged(world) -> None:
    # A dead worker leaks its limit_conn slots for good; only the deliberate G4 reload may
    # replace workers (the harness records the new set when it reloads).
    assert world.env.worker_pids() == world.env.expected_workers != []


def _dribble(head: bytes, body: bytes, *, every_ms: int = 1000) -> list:
    return [[0, _b64(head)]] + [[every_ms, _b64(body[index:index + 1])] for index in range(len(body))]


def test_g8_dribbled_runner_body_is_refused_at_the_total_deadline(world):
    paired = world.state["a"]
    raw = _claim_request(paired, body=CLAIM_BODY.ljust(256))
    split = raw.index(b"\r\n\r\n") + 4
    observation = harness.observe(world.env, lambda: world.env.wire(
        "slot-a", b"", chunks=_dribble(raw[:split], raw[split:]), read_timeout=5))
    _assert_fixed_refusal_at(observation, 408, BODY_READ_S)
    assert not observation.cp_contacted and observation.changed_tables == []
    assert "expired:body_timeout" in observation.reasons
    _assert_no_deadline_anomaly(observation.reasons)
    _assert_worker_unchanged(world)
    harness.record_case("g8.dribble_body", "G8", observation)


def test_g8_dribbled_management_body_is_refused_at_the_total_deadline(world):
    env = world.env
    body = b'{"email":"dribble@example.test"}'.ljust(256)
    head = harness.http_request("POST", "/v1/login", [
        ("Host", harness.HOST), ("X-Heel-Edge-Auth", env.edge_secret), ("Content-Type", "application/json"),
        ("Content-Encoding", "identity"), ("Content-Length", str(len(body)))])
    observation = harness.observe(env, lambda: env.wire("management", b"", chunks=_dribble(head, body), read_timeout=5))
    _assert_fixed_refusal_at(observation, 408, BODY_READ_S)
    assert not observation.cp_contacted and observation.changed_tables == []
    assert "expired:body_timeout" in observation.reasons
    assert not [reason for reason in observation.reasons if reason.startswith("admitted:management:")]
    _assert_no_deadline_anomaly(observation.reasons)
    _assert_worker_unchanged(world)
    harness.record_case("g8.dribble_body_management", "G8", observation)


@pytest.mark.parametrize("at_ms", [9000, 11000])
def test_g8_body_completed_either_side_of_the_deadline(world, at_ms):
    paired = world.state["a"]
    raw = _claim_request(paired)
    split = raw.index(b"\r\n\r\n") + 4
    chunks = [[0, _b64(raw[:split + 5])], [at_ms, _b64(raw[split + 5:])]]
    observation = harness.observe(world.env, lambda: world.env.wire(
        "slot-a", b"", chunks=chunks, send_after_close=True, read_timeout=5))
    if at_ms < BODY_READ_S * 1000:
        # Inside the deadline: admitted and forwarded; the real CP refuses the fixture key.
        assert observation.status == 401 and observation.cp_contacted
        assert "admitted:claim" in observation.reasons
    else:
        _assert_fixed_refusal_at(observation, 408, BODY_READ_S)
        assert not observation.cp_contacted and "admitted:claim" not in observation.reasons
    _assert_no_deadline_anomaly(observation.reasons)
    _assert_worker_unchanged(world)
    harness.record_case(f"g8.body_at_boundary_{at_ms // 1000}s", "G8", observation)


def test_g8_late_body_never_produces_a_second_response_or_cp_contact(world):
    paired = world.state["a"]
    raw = _claim_request(paired)
    split = raw.index(b"\r\n\r\n") + 4
    chunks = [[0, _b64(raw[:split + 5])], [12000, _b64(raw[split + 5:])]]
    observation = harness.observe(world.env, lambda: world.env.wire(
        "slot-a", b"", chunks=chunks, send_after_close=True, read_timeout=5))
    _assert_fixed_refusal_at(observation, 408, BODY_READ_S)
    assert not observation.cp_contacted and observation.changed_tables == []
    _assert_no_deadline_anomaly(observation.reasons)
    _assert_worker_unchanged(world)
    harness.record_case("g8.late_body", "G8", observation)


def _hold(world, raw: bytes, split: int) -> dict:
    """Complete headers and 5 body bytes, then nothing: admitted to the access phase, holding a
    connection slot while the body read waits for the deadline."""
    return world.env.wire("slot-a", b"", chunks=[[0, _b64(raw[:split + 5])]], read_timeout=BODY_READ_S + 4)


def test_g8_listener_connection_cap_holds_at_eight_and_releases_at_the_deadline(world):
    import concurrent.futures
    import time as clock

    paired = world.state["a"]
    raw = _claim_request(paired)
    split = raw.index(b"\r\n\r\n") + 4
    before = world.env.snapshot()
    counters_before = world.env.counters()
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        holds = [pool.submit(_hold, world, raw, split) for _ in range(8)]
        clock.sleep(1.5)
        probes = []
        admitted_at = None
        give_up = clock.time() + BODY_READ_S + 3
        while admitted_at is None and clock.time() < give_up:
            result = world.env.wire("slot-a", raw, read_timeout=5)
            status = harness.parse_http(result["received"])[0]
            probes.append((result["wall"]["sent"][0], status))
            if status == 401:
                admitted_at = result["wall"]["sent"][0]
            elif status != 503:
                break  # asserted below, after the timing evidence is published
            else:
                clock.sleep(0.5)
        held = [future.result() for future in holds]
    # H0BR2/H0BR3 diagnostic (separate case; g8.listener_connection_cap below stays success-only): the
    # holds classified exactly as _assert_fixed_refusal_at checks them, probe counts and the policy's
    # deadline counters across the holds, before any cap assertion.
    telemetry = harness.cap_timing(held, probes, BODY_READ_S, BODY_READ_S + SLACK_S, counters_before, world.env.counters())
    harness.record_case("g8.listener_connection_cap_timing", "G8", telemetry=telemetry)
    assert telemetry["early_final"] == telemetry["deadline_invalid"] == 0
    assert [status for _sent, status in probes if status not in {401, 503}] == []
    starts = [result["wall"]["sent"][0] for result in held]
    for result in held:
        _assert_fixed_refusal_at(result, 408, BODY_READ_S)
    assert any(status == 503 for _sent, status in probes)
    assert all(status == 503 for sent, status in probes if sent < min(starts) + BODY_READ_S - SLACK_S)
    assert admitted_at is not None and admitted_at - max(starts) <= BODY_READ_S + SLACK_S, admitted_at
    after = world.env.snapshot()
    assert after["requests"] - before["requests"] == 1  # only the admitted ninth probe reached CP
    # Every one of the eight slots is free again.
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        again = list(pool.map(lambda _: world.env.wire("slot-a", raw, read_timeout=5), range(8)))
    assert [harness.parse_http(result["received"])[0] for result in again] == [401] * 8
    _assert_worker_unchanged(world)
    harness.record_case("g8.listener_connection_cap", "G8")


def test_g8_mixed_load_of_expiring_holds_and_valid_requests(world):
    """Eight expiring holds interleaved with four valid requests. A valid request refused at the
    connection cap retries every 0.5 s, as an honest runner would within its own 30 s deadline;
    each one must reach a CP outcome within the 25 s budget and no hold may ever reach CP."""
    import concurrent.futures
    import time as clock

    paired = world.state["a"]
    raw = _claim_request(paired)
    split = raw.index(b"\r\n\r\n") + 4

    def valid() -> tuple[float, float | None, int]:
        first = clock.time()
        while clock.time() - first < TOTAL_BUDGET_S:
            status = harness.parse_http(world.env.wire("slot-a", raw, read_timeout=5)["received"])[0]
            if status != 503:
                return first, clock.time(), status
            clock.sleep(0.5)
        return first, None, 503

    before = world.env.snapshot()
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        futures = []
        for index in range(12):
            kind = "valid" if index % 3 == 2 else "hold"
            futures.append((kind, pool.submit(valid) if kind == "valid" else pool.submit(_hold, world, raw, split)))
            clock.sleep(0.1)
        outcomes = [(kind, future.result()) for kind, future in futures]
    after = world.env.snapshot()
    valid_outcomes = [outcome for kind, outcome in outcomes if kind == "valid"]
    assert len(valid_outcomes) == 4
    for first, done, status in valid_outcomes:
        assert status == 401 and done is not None and done - first <= TOTAL_BUDGET_S, (status, done)
    for kind, result in outcomes:
        if kind == "hold":
            status = harness.parse_http(result["received"])[0]
            assert status in {408, 503}, status
            if status == 408:
                _assert_fixed_refusal_at(result, 408, BODY_READ_S)
    assert after["requests"] - before["requests"] == 4
    _assert_worker_unchanged(world)
    harness.record_case("g8.mixed_load", "G8")


# ---------------------------------------------------------------------------------------------
# G3 continued: stop/stop-ack, terminal result and registered rotation (late: they end slot a's run).

def test_g3_owner_stop_then_runner_stop_ack_through_both_listeners(world):
    env, paired = world.env, world.state["a"]
    base, run_id = world.state["base_a"], world.state["submitted_a"]["run_id"]
    dashboard = world.flows.owner("GET", f"{base}/canary-runs/{run_id}", None, paired.cookie)
    stopped = world.flows.owner("POST", f"{base}/canary-runs/{run_id}/stop",
                                {"schema_version": "heel.canary-stop-request.v1", "reason_code": "operator_requested"}, paired.cookie,
                                headers={"If-Heel-Control-Generation": str(dashboard["body"]["approval_control_generation"])})
    assert stopped["status"] in {200, 201, 202}, stopped["status"]
    paired.runner.call("heartbeat", timeout=60)
    ack = paired.runner.call("stop_ack", timeout=60)
    assert ack["ok"] and ack["accepted"] is True, ack.get("error")
    env.registry.set_phase("slot-a", "stopping")
    harness.record_case("g3.stop_ack", "G3")


def test_g3_runner_signed_terminal_result_is_accepted_by_cp(world):
    result = world.state["a"].runner.call("terminal_result", timeout=60, disposition="stopped")
    assert result["ok"] and result["status"] == 200, (result.get("error"), result.get("status"))
    world.env.registry.set_phase("slot-a", "active")
    harness.record_case("g3.terminal_result", "G3", seam="runner-built result, no executor")


def _end_slot_b_run(world) -> None:
    """Slot b's run is still claimed (test_g3_second_slot_pairs_and_claims_independently), and CP refuses
    rotation while a run is claimed, running, stopping or finalizing. End it through the same owner stop ->
    runner stop-ack -> signed terminal result ceremony as slot a's run above, then restore the registry phase."""
    env, paired = world.env, world.state["b"]
    base, run_id = world.state["base_b"], world.state["submitted_b"]["run_id"]
    dashboard = world.flows.owner("GET", f"{base}/canary-runs/{run_id}", None, paired.cookie)
    stopped = harness.observe(env, lambda: world.flows.owner(
        "POST", f"{base}/canary-runs/{run_id}/stop",
        {"schema_version": "heel.canary-stop-request.v1", "reason_code": "operator_requested"}, paired.cookie,
        headers={"If-Heel-Control-Generation": str(dashboard["body"]["approval_control_generation"])}))
    harness.record_case("g3.stop_b", "G3", stopped)
    assert stopped.status in {200, 201, 202}, stopped.status
    paired.runner.call("heartbeat", timeout=60)
    ack = paired.runner.call("stop_ack", timeout=60)
    assert ack["ok"] and ack["accepted"] is True, ack.get("error")
    env.registry.set_phase(paired.slot, "stopping")
    harness.record_case("g3.stop_ack_b", "G3")
    terminal = harness.observe(env, lambda: paired.runner.call("terminal_result", timeout=60, disposition="stopped"))
    harness.record_case("g3.terminal_result_b", "G3", terminal, seam="runner-built result, no executor")
    assert terminal.result["ok"] and terminal.status == 200, (terminal.result.get("error"), terminal.status)
    env.registry.set_phase(paired.slot, "active")


def _revoke_slot_b_context(world) -> None:
    """CP also refuses rotation activation (409 runner_rotation_busy) while the old key holds an active
    runner context binding. The owner revokes slot b's binding through the management listener."""
    paired = world.state["b"]
    path = f"{world.state['base_b']}/runner-context-bindings/{world.state['binding_b']['binding_id']}/revoke"
    revoked = harness.observe(world.env, lambda: world.flows.owner(
        "POST", path, {"schema_version": "heel.runner-context-binding-revoke.v1", "reason_code": "operator_requested"},
        paired.cookie))
    harness.record_case("g3.context_revoke_b", "G3", revoked)
    assert revoked.status == 200 and revoked.result["body"]["status"] == "revoked", revoked.status


def test_g3_registered_rotation_swaps_keys_and_the_old_key_fails(world):
    _two_slots(world)
    _end_slot_b_run(world)
    _revoke_slot_b_context(world)
    env, flows, paired = world.env, world.flows, world.state["b"]
    keys = paired.runner.call("rotation_keys")
    observed = harness.observe(env, lambda: flows.owner(
        "POST", f"/v1/workspaces/{paired.workspace_id}/runners/{paired.runner_id}/rotate", {
            "schema_version": "heel.runner-rotation-start.v1", "previous_fingerprint": keys["old_fingerprint"],
            "public_key_b64": keys["public_key_b64"], "pairing_phrase": paired.pairing_phrase,
            "runner_version": "1.2.0", "adapters": {},
        }, paired.cookie))
    harness.record_case("g3.rotation_start", "G3", observed)
    started = observed.result
    assert started["status"] == 201, started["status"]
    rotation_id = started["body"]["pairing_id"]
    approved = flows.owner("POST", f"/v1/workspaces/{paired.workspace_id}/runners/{paired.runner_id}/rotations/{rotation_id}/approve",
                           {"schema_version": "heel.runner-rotation-approve.v1", "pairing_phrase": paired.pairing_phrase,
                            "fingerprint": started["body"]["fingerprint"]}, paired.cookie)
    assert approved["status"] == 200
    (row,) = env.cp_call("rotation", rotation_id=rotation_id)["rows"]
    assert row["key_id"] == keys["key_id"]
    env.registry.rotating("slot-b", {"rotation_id": rotation_id, "old_runner_key_id": paired.runner_key_id,
                                     "new_runner_key_id": keys["key_id"], "new_public_key_digest": keys["fingerprint"],
                                     "expires_at_ms": int(row["expires_at"] * 1000)})
    activated = paired.runner.call("rotation_activate", rotation_id=rotation_id, timeout=60)
    assert activated["poll_status"] == 200 and activated["activate_status"] == 200
    # Read the CP's new active key, then publish it with the rotation cleared in one registry write
    # (activate() alone would publish an active slot still carrying its rotation, which is refused).
    identity = world.flows.active_identity(harness.PairedSlot(**{**paired.__dict__, "runner_key_id": keys["key_id"]}))
    env.registry.rotated("slot-b", identity)
    old = _slot_wire(world, "slot-b", _claim_request(paired))
    assert old.status == 403 and not old.cp_contacted
    harness.record_case("g3.rotation", "G3", old)


# ---------------------------------------------------------------------------------------------
# Scripted-backend and SQLite phases (labelled seams; the real chain is repeated on SQLite).

def test_g3_g6_sqlite_repeat_of_pairing_claim_and_replay(world):
    env, flows = world.env, world.flows
    env.stop_runner("slot-a")
    env.registry.close("slot-a")
    env.start_cp("sqlite")
    workspace, cookie = flows.signup("owner-sqlite@example.test")
    paired = flows.pair("slot-a", workspace, cookie)
    base, binding = flows.authorize_binding(paired)
    runner = paired.runner
    assert runner.call("open")["ok"] and runner.call("ensure_context", timeout=60)["value"] is True
    submitted = runner.call("compile_submit", timeout=60)
    grant = flows.approve_run(paired, base, submitted)
    claimed = runner.call("claim", timeout=60)
    assert claimed["ok"] and claimed["lease"]["grant_id"] == grant["grant_id"] and claimed["lease"]["verified"]
    indexes = runner.call("wire_find", suffix="/claim", status=200)["indexes"]
    entry = runner.call("wire", index=indexes[-1])
    replay = harness.observe(env, lambda: {"status": runner.call("send", path=entry["path"], headers=entry["headers"],
                                                                 body_b64=entry["body_b64"])["status"]})
    assert replay.status == 200 and replay.changed_tables == []
    world.state.update(s=paired, base_s=base, submitted_s=submitted, grant_s=grant)
    harness.record_case("g3.sqlite_chain", "G3", replay)


def test_g4_forged_grant_from_another_key_reaches_the_unchanged_verifier_and_fails(world):
    env, flows = world.env, world.flows
    paired = world.state["s"]
    runner = paired.runner
    submitted = runner.call("compile_submit", timeout=60, projection_id="projection_forged_grant_case")
    flows.approve_run(paired, world.state["base_s"], submitted)
    env.start_cp("sqlite", port=env.backend[1] + 1, reuse=True)
    env.start_scripted([{"path_re": r"/claim$", "mutate": "resign_grant"}, {"path_re": r".", "mutate": None}],
                       upstream_port=env.backend[1] + 1)
    try:
        forged = runner.call("claim", timeout=60)
    finally:
        env.stop_scripted()
        env.start_cp("sqlite", reuse=True)
    assert forged["ok"] is False
    harness.record_case("g4.forged_grant_rejected_by_runner", "G4", seam="SEAM-SCRIPTED-BACKEND mutate")


NONCE_HEADER = ("X-Heel-Runner-Next-Nonce", "A" * 43 + "=")


def _scripted(status_line: str, headers: list[tuple[str, str]], body: str) -> str:
    lines = [status_line] + [f"{name}: {value}" for name, value in headers] + [f"Content-Length: {len(body.encode())}"]
    return "\r\n".join(lines) + "\r\n\r\n" + body


JSON_TYPE = ("Content-Type", "application/json")
SCRIPTED_RESPONSES = [
    ("redirect", _scripted("HTTP/1.0 302 Found", [("Location", "https://attacker.invalid/"), JSON_TYPE, NONCE_HEADER], "{}")),
    ("set cookie", _scripted("HTTP/1.0 200 OK", [("Set-Cookie", "a=1"), JSON_TYPE, NONCE_HEADER], "{}")),
    ("accel redirect", _scripted("HTTP/1.0 200 OK", [("X-Accel-Redirect", "/__heel_cp/v1/me"), JSON_TYPE], "{}")),
    ("wrong type", _scripted("HTTP/1.0 200 OK", [("Content-Type", "text/html"), NONCE_HEADER], "{}")),
    ("missing nonce", _scripted("HTTP/1.0 200 OK", [JSON_TYPE], "{}")),
    ("duplicate nonce", _scripted("HTTP/1.0 204 No Content", [NONCE_HEADER, NONCE_HEADER], "")),
    ("unknown status", _scripted("HTTP/1.0 418 Teapot", [JSON_TYPE, NONCE_HEADER], "{}")),
    ("malformed json", _scripted("HTTP/1.0 200 OK", [JSON_TYPE, NONCE_HEADER], "{")),
    ("unregistered grant", _scripted("HTTP/1.0 200 OK", [JSON_TYPE, NONCE_HEADER], '{"run_id":"crun_' + "0" * 32 + '"}')),
    ("oversize", _scripted("HTTP/1.0 200 OK", [JSON_TYPE, NONCE_HEADER], "{" + " " * 299998 + "}")),
    ("slow upstream", None),
]


@pytest.mark.parametrize("label,raw", SCRIPTED_RESPONSES, ids=[case[0] for case in SCRIPTED_RESPONSES])
def test_g8_scripted_upstream_responses_become_fixed_refusals(world, label, raw):
    env, paired = world.env, world.state["s"]
    rule = {"path_re": r"/claim$", "raw_b64": base64.b64encode((raw or "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}").encode("latin-1")).decode()}
    if raw is None:
        rule["delay_ms"] = 30000
    env.stop_cp()
    env.start_scripted([rule])
    try:
        result = env.wire("slot-a", _claim_request(paired), read_timeout=40)
    finally:
        env.stop_scripted()
        env.start_cp("sqlite", reuse=True)
    status, headers, body = harness.parse_http(result["received"])
    assert status in {502, 504}, (label, status)
    assert body == b'{"error":"ingress refused"}'
    names = {name.lower() for name, _value in headers}
    assert not names & {"location", "set-cookie", "x-accel-redirect"}
    if raw is None:
        assert result["elapsed_ms"] < 27000
    harness.record_case("g8.scripted." + re.sub(r"[^a-z0-9]+", "_", label), "G8", seam="SEAM-SCRIPTED-BACKEND")


# G8 total upstream budget. nginx arms proxy_read_timeout once for the whole upstream header
# (ngx_http_upstream.c:2252, no re-arm at :2511-2514) and per read for the body, so a scripted
# backend that sends its header at 1 s and then paces its body in 5 s steps stays inside every
# nginx timer: only the policy's 25 s total budget can end such an exchange.

PACED_BODY = b'{"error":"invalid_runner_auth"}'
PACED_HEAD = (b"HTTP/1.0 401 Unauthorized\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n"
              b"Content-Length: " + str(len(PACED_BODY)).encode() + b"\r\n\r\n")


def _paced_upstream(world, pieces: list[tuple[int, bytes]]) -> tuple[dict, list[dict], dict, dict]:
    env, paired = world.env, world.state["s"]
    rule = {"path_re": r"/claim$", "pieces": [[delay, _b64(piece)] for delay, piece in pieces]}
    env.stop_cp()
    counters_before = env.counters()
    env.start_scripted([rule])
    try:
        result = env.wire("slot-a", _claim_request(paired), read_timeout=TOTAL_BUDGET_S + 15)
    finally:
        env.stop_scripted()
        env.start_cp("sqlite", reuse=True)
    return result, env.scripted_events, counters_before, env.counters()


def test_g8_slow_upstream_is_cut_at_the_total_budget_without_late_delivery(world):
    body = [PACED_BODY[index:index + 6] for index in range(0, len(PACED_BODY), 6)]
    pieces = [(1000, PACED_HEAD)] + [(5000, piece) for piece in body]  # completes at 31 s
    result, events, counters_before, counters_after = _paced_upstream(world, pieces)
    _assert_fixed_refusal_at(result, 504, TOTAL_BUDGET_S)
    t0 = result["wall"]["sent"][0]
    (event,) = events
    assert event["completed"] is None and event["eof"] is not None and event["eof"] - t0 < TOTAL_BUDGET_S + 1.0
    assert counters_after.get("expired:timeout", 0) == counters_before.get("expired:timeout", 0) + 1
    assert not [key for key in counters_after if key.startswith("forwarded:") and counters_after[key] != counters_before.get(key)]
    _assert_no_deadline_anomaly(key for key in counters_after if counters_after[key] != counters_before.get(key))
    # The slot is free again and the restarted CP answers through it.
    after = _slot_wire(world, "slot-a", _claim_request(world.state["s"]))
    assert after.status == 401 and after.cp_contacted
    _assert_worker_unchanged(world)
    harness.record_case("g8.slow_upstream_total_budget", "G8", seam="SEAM-SCRIPTED-BACKEND paced")


def test_g8_upstream_reply_inside_the_budget_is_delivered_unchanged(world):
    pieces = [(1000, PACED_HEAD), (4750, PACED_BODY[:8]), (4750, PACED_BODY[8:16]), (4750, PACED_BODY[16:24]),
              (4750, PACED_BODY[24:])]  # completes at 20 s
    result, events, counters_before, counters_after = _paced_upstream(world, pieces)
    status, headers, body = harness.parse_http(result["received"])
    t0, first, _closed = _marks(result)
    assert status == 401 and body == PACED_BODY
    assert first is not None and 19.0 <= first - t0 < TOTAL_BUDGET_S, first
    (event,) = events
    assert event["completed"] is not None
    assert counters_after.get("forwarded:claim:401", 0) == counters_before.get("forwarded:claim:401", 0) + 1
    assert counters_after.get("expired:timeout", 0) == counters_before.get("expired:timeout", 0)
    _assert_no_deadline_anomaly(key for key in counters_after if counters_after[key] != counters_before.get(key))
    _assert_worker_unchanged(world)
    harness.record_case("g8.upstream_in_budget", "G8", seam="SEAM-SCRIPTED-BACKEND paced")


def test_g1_upstream_redirect_is_not_followed_by_the_worker(world):
    env = world.env
    env.stop_cp()
    env.start_scripted([{"path_re": r"/v1/me$", "raw_b64": base64.b64encode(
        b"HTTP/1.0 302 Found\r\nLocation: https://attacker.invalid/\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}").decode()}])
    try:
        reply = env.browser("GET", "/v1/me", cookie=world.state["cookie_a"])
    finally:
        seen = env.stop_scripted()
        env.start_cp("sqlite", reuse=True)
    assert reply["status"] == 502 and seen == ["GET /v1/me"]
    harness.record_case("g1.redirect_not_followed", "G1", seam="SEAM-SCRIPTED-BACKEND")


# ---------------------------------------------------------------------------------------------
# G9 isolation and cleanup (last).

def test_g9_slot_a_cannot_reach_its_sibling_cp_or_management(world):
    env = world.env
    harness.require_linux_topology(env.topology, "namespace isolation")
    targets = [(env.slots["slot-b"][0], 443), (env.backend[0], env.backend[1]), (env.management[0], env.management[1]),
               (env.slots["slot-a"][0], env.management[1]), (env.slots["slot-a"][0], env.backend[1])]
    for address, port in targets:
        result = env.probe("slot-a", mode="tcp", address=address, port=port, connect_timeout=2, read_timeout=1)
        assert result["connected"] is False, (address, port)
    harness.record_case("g9.no_sibling_cp_management_reach", "G9")


def test_g9_namespaces_have_no_default_route_and_the_outer_namespace_has_only_loopback(world):
    env = world.env
    harness.require_linux_topology(env.topology, "namespace isolation")
    for role in ("cp", "ingress", "management", "slot-a", "slot-b"):
        assert "default" not in env.topology.probe_route_table(role), role
    links = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, check=True).stdout
    assert [line.split(":")[1].strip() for line in links.splitlines()] == ["lo"]
    assert subprocess.run(["ip", "-4", "route", "show"], capture_output=True, text=True, check=True).stdout.strip() == ""
    harness.record_case("g9.routes_and_links", "G9")


def test_g9_runner_processes_have_no_capabilities(world):
    env = world.env
    harness.require_linux_topology(env.topology, "runner capability and UID checks")
    for slot, child in env.runners.items():
        status = Path(f"/proc/{child.process.pid}/status").read_text()
        fields = dict(line.split(":\t", 1) for line in status.splitlines() if ":\t" in line)
        assert int(fields["CapEff"].strip(), 16) == 0 and int(fields["CapPrm"].strip(), 16) == 0, slot
        assert fields["Uid"].split()[0] == str(harness.UIDS[slot]), slot
        assert fields["NoNewPrivs"].strip() == "1", slot
    harness.record_case("g9.runner_no_capabilities", "G9")


def test_g9_ingress_worker_survived_every_case(world):
    """Worker sentinel: no case killed the ingress worker (a replaced worker would have leaked
    every limit_conn slot it held) and the private counters endpoint still answers."""
    env = world.env
    assert env.nginx is not None and env.nginx.poll() is None
    assert env.worker_pids() == env.expected_workers != []
    counters = env.counters()
    assert counters != {}  # the private counters endpoint still answers from the same worker
    _assert_no_deadline_anomaly(counters)  # no deadline anywhere in the module refused early or on a bad clock
    harness.record_case("g9.worker_sentinel", "G9")


def test_g9_every_owned_process_and_namespace_is_removed(world, policy_runtime):
    env = world.env
    pids = [child.process.pid for child in env.children] + ([env.nginx.pid] if env.nginx else [])
    report = env.close()
    assert report["children"] >= 4 and report["nginx"] is True
    for pid in pids:
        assert harness.process_identity(pid).endswith(":unknown") or not Path(f"/proc/{pid}").exists(), pid
    if env.topology.is_linux_namespaces:
        # H0BL section 5: with both module environments closed, the only live processes left in the
        # launcher's PID namespace are pytest itself and its PPID-chain ancestors (the namespace init).
        policy_runtime.close()
        assert harness.stray_namespace_processes() == []
    harness.record_case("g9.cleanup", "G9")
