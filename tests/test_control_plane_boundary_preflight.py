"""Tests for the read-only Ubuntu 24.04 boundary prerequisite collector.

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Linux host logic runs only against synthetic fixtures (FakeHost); no host inventory is taken on the
developer machine or in ordinary CI. The bounded-process tests start only small owned,
self-terminating Python children. Nothing here invokes Docker, sudo, systemctl or a network.
"""
from __future__ import annotations

import copy
import errno
import hashlib
import importlib.util
import json
import os
import random
import re
import stat
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "control_plane_boundary_preflight.py"
WORKFLOW = ROOT / ".github" / "workflows" / "control-plane-boundary-preflight.yml"
DOC = ROOT / "docs" / "saas" / "CONTROL_PLANE_BOUNDARY_PREFLIGHT.md"
CANARY = "HEELCANARY7f3a9c"


def _load():
    spec = importlib.util.spec_from_file_location("control_plane_boundary_preflight", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


P = _load()
HEAD = "a" * 40
TREE = "b" * 40
MiB = 1024 * 1024
GiB = 1024 * MiB


def _mountinfo(extra: str = "") -> bytes:
    lines = [
        f"22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/root-{CANARY} rw,discard,secret={CANARY}",
        "23 22 0:21 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate",
        "24 22 0:25 / /run rw,nosuid,nodev,noexec,relatime shared:5 - tmpfs tmpfs rw,size=1634000k,mode=755",
        "25 22 8:17 / /mnt rw,relatime shared:2 - ext4 /dev/sdb1 rw",
    ]
    return ("\n".join(lines) + "\n" + extra).encode()


def _sudo_out(rules: str = "    (ALL) NOPASSWD: ALL\n") -> bytes:
    return (
        f"Matching Defaults entries for runner on host-{CANARY}:\n"
        "    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/bin\n\n"
        f"User runner may run the following commands on host-{CANARY}:\n" + rules
    ).encode()


def _ok(stdout: bytes, stderr: bytes = b"") -> "P.CommandResult":
    return P.CommandResult(state="ok", exit_code=0, stdout=stdout, stdout_bytes=len(stdout),
                           stdout_truncated=False, stderr_bytes=len(stderr), elapsed_ms=3, leader_reaped=True)


def _fail(state: str, exit_code=None, stderr: bytes = b"", stderr_class="empty", stdout=b"") -> "P.CommandResult":
    return P.CommandResult(state=state, exit_code=exit_code, stdout=stdout, stdout_bytes=len(stdout),
                           stdout_truncated=False, stderr_bytes=len(stderr), elapsed_ms=3, leader_reaped=True,
                           stderr_class=stderr_class)


class FakeStat:
    def __init__(self, mode, uid=0, gid=0, size=0):
        self.st_mode, self.st_uid, self.st_gid, self.st_size = mode, uid, gid, size


class FakeVfs:
    def __init__(self, frsize=4096, blocks=10 * GiB // 4096, bavail=8 * GiB // 4096, files=1_000_000, favail=900_000):
        self.f_frsize, self.f_blocks, self.f_bfree, self.f_bavail = frsize, blocks, bavail, bavail
        self.f_files, self.f_ffree, self.f_favail = files, favail, favail


BINARY = b"\x7fELF" + b"synthetic-binary" * 8
REG = stat.S_IFREG | 0o755


class FakeHost:
    """Synthetic Linux host. Every access is recorded so tests can assert read-only behaviour."""

    def __init__(self):
        self.platform_values = ("linux", "x86_64")
        self.environ = {
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24", "ImageVersion": "20261025.353.1",
            "GITHUB_RUN_ID": "41779658391", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_TOKEN": f"ghs_{CANARY}", "AWS_SECRET_ACCESS_KEY": CANARY, "HOSTNAME": CANARY,
        }
        self.files = {
            "/etc/os-release": (
                'PRETTY_NAME="Ubuntu 24.04.5 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n'
                'VERSION="24.04.5 LTS (Noble Numbat)"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\n'
                f'HOME_URL="https://{CANARY}.example/"\n').encode(),
            "/proc/1/comm": b"systemd\n",
            "/proc/self/mountinfo": _mountinfo(),
            "/sys/fs/cgroup/cgroup.controllers": b"cpuset cpu io memory hugetlb pids rdma misc\n",
            "/proc/self/cgroup": b"0::/system.slice/hosted-compute-agent.service\n",
            "/sys/fs/cgroup/system.slice/hosted-compute-agent.service/cgroup.controllers": b"cpu memory pids\n",
            "/sys/fs/cgroup/system.slice/hosted-compute-agent.service/cgroup.subtree_control": b"\n",
            "/proc/sys/kernel/unprivileged_userns_clone": b"1\n",
            "/proc/sys/kernel/apparmor_restrict_unprivileged_userns": b"1\n",
            "/proc/sys/user/max_user_namespaces": b"63570\n",
            "/sys/module/apparmor/parameters/enabled": b"Y\n",
            "/etc/apparmor.d/rootlesskit": (
                f"# {CANARY}\nabi <abi/4.0>,\ninclude <tunables/global>\n"
                "profile rootlesskit /usr/bin/rootlesskit flags=(unconfined) {\n  userns,\n}\n").encode(),
            "/sys/kernel/security/apparmor/profiles": (
                f"rootlesskit (unconfined)\n/opt/{CANARY}/bin (enforce)\nunshare (enforce)\n").encode(),
            "/etc/subuid": f"runner:100000:65536\n{CANARY}:165536:65536\n".encode(),
            "/etc/subgid": f"runner:100000:65536\n{CANARY}:165536:65536\n".encode(),
            "/etc/passwd": (f"root:x:0:0:root:/root:/bin/bash\nrunner:x:1001:1001:{CANARY},,,:/home/runner:/bin/bash\n"
                            ).encode(),
            "/etc/group": (f"root:x:0:\nadm:x:4:runner\nsudo:x:27:\ndocker:x:118:runner\nrunner:x:1001:\n"
                           f"{CANARY}:x:999:runner\n").encode(),
        }
        self.stats = {
            "/sys/fs/cgroup/system.slice/hosted-compute-agent.service/cgroup.kill": FakeStat(stat.S_IFREG | 0o200),
            "/run": FakeStat(stat.S_IFDIR | 0o755),
            "/home/runner/work": FakeStat(stat.S_IFDIR | 0o755, 1001, 1001),
            "/run/docker.sock": FakeStat(stat.S_IFSOCK | 0o660, 0, 118),
            "/run/containerd/containerd.sock": FakeStat(stat.S_IFSOCK | 0o660, 0, 0),
            "/var/lib/docker": FakeStat(stat.S_IFDIR | 0o710, 0, 0),
            "/var/lib/containerd": FakeStat(stat.S_IFDIR | 0o711, 0, 0),
        }
        self.denied: set[str] = set()
        self.links: dict[str, str] = {}
        self.binaries = {
            "/usr/bin/dockerd": BINARY, "/usr/bin/newuidmap": BINARY + b"u", "/usr/bin/newgidmap": BINARY + b"g",
            "/usr/bin/systemd-run": BINARY + b"s", "/usr/bin/unshare": BINARY + b"n", "/usr/bin/mount": BINARY + b"m",
            "/usr/bin/findmnt": BINARY + b"f",
        }
        self.binary_modes = {"/usr/bin/newuidmap": stat.S_IFREG | 0o4755, "/usr/bin/newgidmap": stat.S_IFREG | 0o4755}
        self.xattr: dict[str, object] = {}
        self.vfs = {"/run": FakeVfs(), "/home/runner/work": FakeVfs()}
        self.commands = {
            "systemctl_version": _ok(b"systemd 255 (255.4-1ubuntu8.6)\n+PAM +AUDIT +SELINUX\n"),
            "systemd_manager_version": _ok(b"Version=255.4-1ubuntu8.6\n"),
            "sudo_list": _ok(_sudo_out(), f"stderr {CANARY}".encode()),
            "git_identity": _ok(f"{HEAD}\n{TREE}\n".encode()),
            "git_status": _ok(b""),
        }
        self.identity_values = (1001, 1001, 1001, [1001, 4, 100, 118])
        self.clock_value = 1000.0
        self.clock_step = 0.0
        self.reads: list[str] = []
        self.ran: list[str] = []

    # ---- Host protocol -------------------------------------------------------------------------
    def platform(self):
        return self.platform_values

    def env(self, name):
        self.reads.append(f"env:{name}")
        return self.environ.get(name)

    def python_version(self):
        return (3, 12, 3)

    def monotonic(self):
        self.clock_value += self.clock_step
        return self.clock_value

    def uname(self):
        self.reads.append("uname")
        return ("Linux", "6.11.0-1015-azure", "x86_64")

    def cpu_online(self):
        self.reads.append("cpu")
        return 4

    def read(self, path, cap, budget):
        self.reads.append(path)
        if path in self.denied:
            raise P.HostReadError("denied")
        if path not in self.files:
            raise P.HostReadError("absent")
        data = self.files[path]
        view = {"offset": 0}

        def chunk(count):
            piece = data[view["offset"]:view["offset"] + count]
            view["offset"] += len(piece)
            return piece
        sink = bytearray()
        P.bounded_stream(chunk, cap, budget, 65536, sink.extend)
        return bytes(sink)

    def stat(self, path, follow=True):
        self.reads.append(f"stat:{path}")
        if path in self.denied:
            raise P.HostReadError("denied")
        if not follow and path in self.links:
            return FakeStat(stat.S_IFLNK | 0o777)
        target = self.links.get(path, path) if follow else path
        if target in self.binaries:
            data = self.binaries[target]
            return FakeStat(self.binary_modes.get(target, REG), 0, 0, len(data))
        if target in self.stats:
            return self.stats[target]
        raise P.HostReadError("absent")

    def realpath(self, path):
        self.reads.append(f"realpath:{path}")
        return self.links.get(path, path)

    def statvfs(self, path):
        self.reads.append(f"statvfs:{path}")
        if path not in self.vfs:
            raise P.HostReadError("absent")
        return self.vfs[path]

    def has_capability_xattr(self, path, budget):
        # Synthetic default: a delivered capability value (True). The real wrapper has no determinate
        # absence: ENODATA is ``ambiguous`` (tested against RealHost below), so a fixture "False" would be
        # a value the producer can never emit.
        self.reads.append(f"xattr:{path}")
        value = self.xattr.get(path, True)
        if isinstance(value, str):
            raise P.HostReadError(value)
        return value

    def hash_file(self, path, cap, budget):
        self.reads.append(f"hash:{path}")
        data = self.binaries[path]
        if len(data) > cap:
            raise P.HostReadError("oversize")
        view = {"offset": 0}

        def chunk(count):
            piece = data[view["offset"]:view["offset"] + count]
            view["offset"] += len(piece)
            return piece
        digest = hashlib.sha256()
        total = P.bounded_stream(chunk, cap, budget, 65536, digest.update)
        return digest.hexdigest(), total

    def identity(self):
        self.reads.append("identity")
        return self.identity_values

    def run(self, command_id, timeout):
        assert command_id in P.COMMANDS, command_id
        self.ran.append(command_id)
        return self.commands[command_id]


def _collect(host=None):
    host = host or FakeHost()
    report, commands = P.collect(host)
    P.validate_output(report)  # every collected report must satisfy the closed schema
    text = json.dumps(report, sort_keys=True) + json.dumps(commands, sort_keys=True)
    return host, report, commands, text


def _unknowns(report):
    return [value for section in P.FACT_SECTIONS for value in P._unknown_values(report.get(section, {}))]


# ---- Allowlist, no Docker, no mutation -------------------------------------------------------------

def test_command_allowlist_is_exact_and_never_invokes_docker():
    assert set(P.COMMANDS) == {"systemctl_version", "systemd_manager_version", "sudo_list", "git_identity", "git_status"}
    assert {argv[0] for argv in P.COMMANDS.values()} == {"/usr/bin/systemctl", "/usr/bin/sudo", "/usr/bin/git"}
    assert P.COMMANDS["sudo_list"] == ("/usr/bin/sudo", "-n", "-l")
    assert P.COMMANDS["git_status"] == ("/usr/bin/git", "-c", "core.fsmonitor=false", "status", "--porcelain=v1",
                                        "--untracked-files=no")
    for argv in P.COMMANDS.values():
        assert all(isinstance(part, str) for part in argv)
        assert not any("docker" in part or "containerd" in part for part in argv), argv
    for verb in ("start", "stop", "restart", "reload", "enable", "disable", "daemon-reload", "kill", "set-property"):
        assert all(verb not in argv for argv in P.COMMANDS.values())


def test_source_has_one_exec_site_no_shell_no_nss_and_no_mutating_calls():
    source = SCRIPT.read_text(encoding="utf-8")
    assert source.count("subprocess.Popen(") == 1
    for forbidden in ("shell=True", "os.system", "os.popen", "os.exec", "os.spawn", "check_output", "subprocess.run(",
                      "os.remove", "os.unlink", "rmtree", "os.rename", "os.replace", "os.chmod", "os.chown",
                      "os.setxattr", "socket.", "import socket", "urllib", "http.client", "useradd", "usermod",
                      "sysctl -w", "aa-disable", "apparmor_parser", "setns", "unshare(", "mount(", "docker info",
                      "docker ps", "docker version", "/var/run/docker.sock", "DOCKER_HOST", "os.environ.copy",
                      "dict(os.environ", "import pwd", "import grp", "getpwnam", "getgrnam", "getpwuid",
                      "getgrgid", "sudo -S", "findmnt --", "never success"):
        assert forbidden not in source, forbidden
    assert len(re.findall(r"os\.environ\b", source)) == 1  # the single allowlisted reader


def test_real_host_refuses_unlisted_command_ids_and_builds_closed_environments(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", CANARY)
    host = P.RealHost(P.ROOT)
    with pytest.raises(P.PreflightError):
        host.run("docker_info", 1.0)
    for command_id in P.COMMANDS:
        env = P.command_environment(command_id)
        assert CANARY not in json.dumps(env)
        assert set(env) <= {"PATH", "LC_ALL", "LANG", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL",
                            "GIT_OPTIONAL_LOCKS", "GIT_TERMINAL_PROMPT", "SYSTEMD_PAGER", "SYSTEMD_COLORS"}
    assert P.command_environment("git_status")["GIT_OPTIONAL_LOCKS"] == "0"


def test_environment_reader_is_an_exact_noncredential_allowlist():
    assert P.ENV_ALLOWLIST == ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS",
                               "ImageVersion", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
    host = P.RealHost(P.ROOT)
    with pytest.raises(P.PreflightError):
        host.env("GITHUB_TOKEN")


# ---- Refusal before host reads --------------------------------------------------------------------

@pytest.mark.parametrize("platform_values, env_patch, reason", [
    (("darwin", "arm64"), {}, "unsupported_platform"),
    (("linux", "aarch64"), {}, "unsupported_platform"),
    (("linux", "x86_64"), {"GITHUB_ACTIONS": None}, "not_github_hosted"),
    (("linux", "x86_64"), {"RUNNER_ENVIRONMENT": "self-hosted"}, "not_github_hosted"),
])
def test_unsupported_platform_is_refused_before_any_host_read(platform_values, env_patch, reason):
    host = FakeHost()
    host.platform_values = platform_values
    for key, value in env_patch.items():
        if value is None:
            host.environ.pop(key)
        else:
            host.environ[key] = value
    report, commands = P.collect(host)
    assert report["observation"] == "refused" and report["refusal"] == reason
    assert report["runtime_qualified"] is False and report["verdict"] == "UNPROVEN"
    assert host.ran == [] and commands == {}
    assert all(item.startswith("env:") for item in host.reads), host.reads
    P.validate_output(report)


def test_real_host_on_a_non_linux_platform_refuses_without_reading(tmp_path):
    class NonLinux(P.RealHost):
        def platform(self):
            return ("darwin", "arm64")

        def read(self, path, cap, budget):  # pragma: no cover - must not be reached
            raise AssertionError(path)

        def run(self, command_id, timeout):  # pragma: no cover - must not be reached
            raise AssertionError(command_id)

    code = P.main([], host=NonLinux(P.ROOT), output_root=tmp_path)
    assert code == P.EXIT_REFUSED
    report = json.loads((tmp_path / P.OUTPUT_DIR_NAME / "report.json").read_text())
    assert report["observation"] == "refused" and report["runtime_qualified"] is False
    commands = (tmp_path / P.OUTPUT_DIR_NAME / "commands.json").read_bytes()
    assert report["pair"]["commands_sha256"] == hashlib.sha256(commands).hexdigest()


def test_arguments_are_refused(tmp_path):
    host = FakeHost()
    assert P.main(["--path", "/etc/shadow"], host=host, output_root=tmp_path) == P.EXIT_REFUSED
    assert host.ran == [] and host.reads == []


def test_unsupported_python_is_refused():
    host = FakeHost()
    host.python_version = lambda: (3, 9, 6)
    report, _ = P.collect(host)
    assert report["refusal"] == "unsupported_python"


# ---- Complete synthetic observation (ideal positive control) ---------------------------------------

def test_complete_synthetic_host_reports_facts_but_never_qualification():
    host, report, commands, text = _collect()
    assert report["schema"] == P.SCHEMA
    assert report["observation"] == "complete" and report["incomplete_reasons"] == [], report["incomplete_reasons"]
    assert _unknowns(report) == []
    assert report["runtime_qualified"] is False and report["verdict"] == "UNPROVEN" and report["b0_effect"] == "none"
    assert report["source"] == {"head": HEAD, "tree": TREE, "worktree_clean": True, "dirty_entries": 0}
    assert report["runner"] == {"runner_os": "Linux", "runner_arch": "X64", "image_os": "ubuntu24",
                                "image_version": "20261025.353.1", "run_id": "41779658391", "run_attempt": "1"}
    assert report["python"]["version"] == "3.12.3"
    assert report["kernel"] == {"sysname": "Linux", "release": "6.11.0-1015-azure", "machine": "x86_64"}
    assert report["os_release"] == {"state": "observed", "id": "ubuntu", "version_id": "24.04",
                                    "point_version": "24.04.5", "codename": "noble"}
    assert report["cpu"] == {"online": 4}
    assert report["system_manager"] == {"pid1_comm": "systemd", "systemctl_major": 255,
                                        "systemctl_version": "255.4-1ubuntu8.6",
                                        "manager_version": "255.4-1ubuntu8.6"}
    cg = report["cgroup"]
    assert cg["filesystem"] == "cgroup2" and cg["unified"] is True and cg["mount_point_is_target"] is True
    assert cg["root_controllers"] == ["cpu", "cpuset", "hugetlb", "io", "memory", "misc", "pids", "rdma"]
    assert cg["self"]["path_class"] == "system.slice" and cg["self"]["leaf_suffix"] == "service"
    assert cg["self"]["depth"] == 2 and cg["self"]["cgroup_kill_present"] is True
    assert cg["self"]["controllers"] == ["cpu", "memory", "pids"] and cg["self"]["subtree_control"] == []
    assert cg["self"]["path_sha256"] == hashlib.sha256(b"/system.slice/hosted-compute-agent.service").hexdigest()
    bins = report["binaries"]
    assert bins["scope"] == "first_existing_entry_in_fixed_directories"
    tools = bins["tools"]
    assert tools["dockerd"]["state"] == "found_regular"
    assert tools["dockerd"]["sha256"] == hashlib.sha256(BINARY).hexdigest()
    assert tools["dockerd"]["file_capability"] is True and tools["dockerd"]["any_execute_bit"] is True
    assert tools["newuidmap"]["setuid"] is True and tools["unshare"]["setuid"] is False
    assert tools["rootlesskit"]["state"] == "absent" and tools["slirp4netns"]["state"] == "absent"
    assert report["userns"] == {"unprivileged_userns_clone": 1, "apparmor_restrict_unprivileged_userns": 1,
                                "max_user_namespaces": 63570}
    aa = report["apparmor"]
    assert aa["enabled"] == "Y" and aa["loaded_rootlesskit_mode"] == "unconfined" and aa["loaded_profile_count"] == 3
    assert aa["profiles"]["/etc/apparmor.d/rootlesskit"]["lexical_userns_rule_hint"] is True
    assert aa["profiles"]["/etc/apparmor.d/rootlesskit"]["lexical_unconfined_flag_hint"] is True
    assert aa["profiles"]["/etc/apparmor.d/usr.bin.rootlesskit"]["state"] == "absent"
    assert report["identity"] == {"scope": "process_credentials_and_local_etc_group", "uid": 1001, "euid": 1001,
                                  "gid": 1001, "groups": [4, 100, 118, 1001], "groups_total": 4,
                                  "groups_truncated": False, "is_root": False, "docker_group_local": "present",
                                  "in_docker_group": True}
    assert report["sudo"] == {"scope": "recognized_listing_not_effective_policy", "state": "listed",
                              "rule_facts": "from_listing", "nopasswd_all_rule_listed": True, "rule_lines": 1}
    assert report["proposed_identity"]["account"] == "absent"
    assert report["proposed_identity"]["subuid"]["entries"] == 0
    assert report["proposed_identity"]["subgid"]["entries"] == 0
    fs = report["filesystems"]
    assert fs["/run"]["fstype"] == "tmpfs" and fs["/run"]["mount_point"] == "/run"
    assert fs["/run"]["propagation"] == "shared" and fs["/run"]["noexec"] is True
    assert fs["/run"]["mount_point_is_target"] is True
    assert fs["/home/runner/work"]["fstype"] == "ext4" and fs["/home/runner/work"]["mount_point"] == "/"
    assert fs["/home/runner/work"]["avail_bytes"] == 8 * GiB and fs["/home/runner/work"]["free_inodes"] == 900_000
    assert fs["/home/runner/work"]["below_5gib_floor"] is False
    ep = report["shared_endpoints"]
    assert ep["/run/docker.sock"] == {"state": "present", "type": "socket", "uid": 0, "gid": 118, "mode": "0660",
                                      "symlink": False}
    assert ep["/var/lib/docker"]["type"] == "directory" and ep["/var/lib/docker"]["mode"] == "0710"
    gaps = set(report["prerequisite_gaps"])
    assert {"tool_not_found_in_fixed_dirs:rootlesskit", "proposed_identity_absent", "userns_restricted_by_apparmor",
            "shared_docker_endpoint_present"} <= gaps
    assert sorted(report["prerequisite_gaps"]) == report["prerequisite_gaps"]
    assert report["accounting"]["read_bytes_delivered"] > 0 and report["accounting"]["deadline_overrun"] is False
    assert set(commands) == set(P.COMMANDS)
    assert commands["sudo_list"]["state"] == "ok" and "stdout" not in commands["sudo_list"]
    assert commands["sudo_list"]["descendants_outside_group"] == "not_observed"
    assert CANARY not in text


def test_exit_zero_only_for_complete_observation_and_files_are_closed_and_paired(tmp_path):
    assert P.main([], host=FakeHost(), output_root=tmp_path) == P.EXIT_COMPLETE
    out = tmp_path / P.OUTPUT_DIR_NAME
    assert sorted(path.name for path in out.iterdir()) == sorted(P.ARTIFACT_FILES)
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    for path in out.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.stat().st_size <= P.REPORT_CAP
        assert CANARY not in path.read_text()
    report = json.loads((out / "report.json").read_text())
    commands_bytes = (out / "commands.json").read_bytes()
    commands = json.loads(commands_bytes)
    assert report["runtime_qualified"] is False
    assert report["pair"]["commands_sha256"] == hashlib.sha256(commands_bytes).hexdigest()
    assert commands["binding"] == {"run_id": "41779658391", "run_attempt": "1", "head": HEAD}
    assert report["runner"]["run_id"] == commands["binding"]["run_id"]


def test_existing_output_directory_is_never_reused_or_overwritten(tmp_path):
    (tmp_path / P.OUTPUT_DIR_NAME).mkdir()
    (tmp_path / P.OUTPUT_DIR_NAME / "report.json").write_text("keep")
    assert P.main([], host=FakeHost(), output_root=tmp_path) == P.EXIT_INTERNAL
    assert (tmp_path / P.OUTPUT_DIR_NAME / "report.json").read_text() == "keep"


def test_existing_empty_output_directory_is_also_refused(tmp_path):
    (tmp_path / P.OUTPUT_DIR_NAME).mkdir()
    assert P.main([], host=FakeHost(), output_root=tmp_path) == P.EXIT_INTERNAL
    assert list((tmp_path / P.OUTPUT_DIR_NAME).iterdir()) == []


def test_stale_report_after_failed_second_invocation_is_left_but_exit_is_internal(tmp_path):
    """Reviewer stale_report: the old files remain (never deleted); exit 1 binds the workflow to not upload."""
    assert P.main([], host=FakeHost(), output_root=tmp_path) == P.EXIT_COMPLETE
    before = (tmp_path / P.OUTPUT_DIR_NAME / "report.json").read_bytes()
    assert P.main([], host=FakeHost(), output_root=tmp_path) == P.EXIT_INTERNAL
    assert (tmp_path / P.OUTPUT_DIR_NAME / "report.json").read_bytes() == before
    text = WORKFLOW.read_text(encoding="utf-8")
    upload = text.split("- name: Upload the closed report and command summary", 1)[1]
    condition = upload.split("\n", 2)[1]
    assert "collector_exit == '0'" in condition and "collector_exit == '3'" in condition
    assert "collector_exit == '2'" in condition and "'1'" not in condition


# ---- Missing prerequisites stay absent, never PASS ------------------------------------------------

def test_missing_tools_ranges_and_controllers_are_determinate_facts_not_success():
    host = FakeHost()
    host.binaries = {}
    host.files["/sys/fs/cgroup/cgroup.controllers"] = b"cpuset io\n"
    host.files.pop("/proc/sys/kernel/unprivileged_userns_clone")
    host.files.pop("/etc/subuid")
    host.stats = {k: v for k, v in host.stats.items() if "docker" not in k and "containerd" not in k}
    _, report, _, text = _collect(host)
    assert report["observation"] == "complete" and report["runtime_qualified"] is False
    assert all(report["binaries"]["tools"][tool]["state"] == "absent" for tool in P.TOOLS)
    assert {"cgroup_controller_missing:cpu", "cgroup_controller_missing:memory",
            "cgroup_controller_missing:pids"} <= set(report["prerequisite_gaps"])
    assert {f"tool_not_found_in_fixed_dirs:{tool}" for tool in P.TOOLS} <= set(report["prerequisite_gaps"])
    assert report["userns"]["unprivileged_userns_clone"] == "absent"
    assert report["proposed_identity"]["subuid"]["state"] == "absent"
    assert all(item["state"] == "absent" for item in report["shared_endpoints"].values())
    assert "PASS" not in text


def test_proposed_identity_present_but_privileged_or_short_or_overlapping():
    host = FakeHost()
    host.files["/etc/passwd"] += b"heel-image-proof:x:2001:2001::/nonexistent:/bin/bash\n"
    host.files["/etc/group"] = host.files["/etc/group"].replace(b"docker:x:118:runner", b"docker:x:118:runner,heel-image-proof")
    host.files["/etc/subuid"] = b"runner:100000:65536\nheel-image-proof:120000:1000\n"
    host.files["/etc/subgid"] = b"heel-image-proof:300000:65536\n"
    _, report, _, _ = _collect(host)
    proposed = report["proposed_identity"]
    assert proposed["account"] == "present" and proposed["login_shell"] == "login"
    assert proposed["privileged_groups"] == ["docker"] and proposed["scope"] == "local_etc_passwd_and_group"
    assert proposed["subuid"] == {"state": "observed", "entries": 1, "start": 120000, "count": 1000,
                                  "sufficient": False, "overlaps_other": True}
    assert proposed["subgid"] == {"state": "observed", "entries": 1, "start": 300000, "count": 65536,
                                  "sufficient": True, "overlaps_other": False}
    gaps = set(report["prerequisite_gaps"])
    assert {"proposed_identity_login_shell", "proposed_identity_privileged_group",
            "proposed_identity_subuid_too_small", "proposed_identity_subuid_overlap"} <= gaps
    assert "proposed_identity_absent" not in gaps


def _ideal_host():
    host = FakeHost()
    host.binaries.update({f"/usr/bin/{tool}": BINARY + tool.encode() for tool in P.TOOLS})
    host.files["/proc/sys/kernel/apparmor_restrict_unprivileged_userns"] = b"0\n"
    host.files["/etc/passwd"] += b"heel-image-proof:x:2001:2001::/nonexistent:/usr/sbin/nologin\n"
    host.files["/etc/subuid"] = b"heel-image-proof:300000:65536\n"
    host.files["/etc/subgid"] = b"heel-image-proof:300000:65536\n"
    host.stats = {k: v for k, v in host.stats.items() if "docker" not in k and "containerd" not in k}
    return host


def test_ideal_installed_configuration_is_complete_with_no_gap_and_still_never_qualifies(tmp_path):
    _, report, _, text = _collect(_ideal_host())
    assert report["observation"] == "complete" and report["prerequisite_gaps"] == []
    assert report["runtime_qualified"] is False and report["verdict"] == "UNPROVEN"
    assert "installed_configuration_is_not_effective_isolation" in report["limits"]
    assert "PASS" not in text and '"qualified"' not in text
    assert P.main([], host=_ideal_host(), output_root=tmp_path) == P.EXIT_COMPLETE


# ---- One completion contract: unknown is never complete, never a negative fact ---------------------

def _deny(path):
    return lambda h: h.denied.add(path)


UNKNOWN_CASES = [
    # (mutation, required incomplete reason, gap that must NOT be derived from the unknown fact)
    (lambda h: h.commands.__setitem__("systemctl_version", _ok(f"weird {CANARY}\n".encode())), "systemctl_version:malformed", None),
    (lambda h: h.commands.__setitem__("systemd_manager_version", _ok(f"Version=$({CANARY})\n".encode())), "systemd_manager_version:malformed", None),
    (lambda h: h.commands.__setitem__("git_identity", _ok(f"{CANARY}\n{TREE}\n".encode())), "git_identity:malformed", None),
    (lambda h: h.commands.__setitem__("git_identity", _fail("timeout")), "git_identity:timeout", None),
    (lambda h: h.commands.__setitem__("sudo_list", _fail("output_cap_exceeded")), "sudo_list:output_cap_exceeded", None),
    (lambda h: h.files.__setitem__("/proc/self/mountinfo", _mountinfo(f"bad line {CANARY}\n")), "mountinfo:malformed", "cgroup_not_unified"),
    (lambda h: h.files.__setitem__("/proc/self/mountinfo", b"x" * (P.MOUNTINFO_CAP + 1)), "mountinfo:oversize", "cgroup_not_unified"),
    (lambda h: h.files.__setitem__("/proc/self/cgroup", f"0::/../{CANARY}\n".encode()), "self_cgroup:unrecognized", "self_cgroup_kill_absent"),
    (lambda h: h.files.__setitem__("/proc/self/cgroup", b"0::/a\n0::/b\n"), "self_cgroup:malformed", "self_cgroup_kill_absent"),
    (lambda h: h.files.__setitem__("/proc/1/comm", b"\xff\xfe\n"), "pid1_comm:malformed", "pid1_not_systemd"),
    (_deny("/proc/1/comm"), "pid1_comm:denied", "pid1_not_systemd"),
    (lambda h: h.files.__setitem__("/etc/os-release", f"ID={CANARY}$\nVERSION_ID=24.04\n".encode()), "os_release:malformed", "os_not_ubuntu_24_04"),
    (_deny("/etc/os-release"), "os_release:denied", "os_not_ubuntu_24_04"),
    (lambda h: h.files.__setitem__("/etc/os-release", b"NAME=x\n"), "os_release:unrecognized", "os_not_ubuntu_24_04"),
    (lambda h: h.files.__setitem__("/proc/sys/user/max_user_namespaces", f"{CANARY}\n".encode()), "max_user_namespaces:malformed", "user_namespaces_disabled"),
    (lambda h: h.files.__setitem__("/etc/subuid", f"heel-image-proof:abc:{CANARY}\n".encode()), "subuid:malformed", "proposed_identity_subuid_absent"),
    (lambda h: h.files.__setitem__("/sys/fs/cgroup/cgroup.controllers", f"cpu {CANARY.upper()}\n".encode()), "root_controllers:malformed", "cgroup_controller_missing:cpu"),
    (_deny("/proc/self/mountinfo"), "mountinfo:denied", "cgroup_not_unified"),
    # Reviewer F2 counterexamples.
    (_deny("/sys/fs/cgroup/system.slice/hosted-compute-agent.service/cgroup.kill"), "self_cgroup_kill:denied", "self_cgroup_kill_absent"),
    (lambda h: h.commands.__setitem__("sudo_list", _ok(b"not a sudo listing\n")), "sudo_list:unrecognized", None),
    (lambda h: h.files.__setitem__("/sys/kernel/security/apparmor/profiles", b"rootlesskit malformed\n"), "apparmor_loaded:malformed", None),
    (_deny("/sys/kernel/security/apparmor/profiles"), "apparmor_loaded:denied", None),
    (_deny("/etc/apparmor.d/rootlesskit"), "apparmor_profile:rootlesskit:denied", None),
    (lambda h: h.files.__setitem__("/sys/module/apparmor/parameters/enabled", b"maybe\n"), "apparmor_enabled:malformed", None),
    (lambda h: h.environ.pop("ImageVersion"), "env_image_version:unavailable", None),
    (lambda h: h.environ.pop("GITHUB_RUN_ID"), "env_run_id:unavailable", None),
    (lambda h: h.environ.pop("GITHUB_RUN_ATTEMPT"), "env_run_attempt:unavailable", None),
    (lambda h: h.xattr.__setitem__("/usr/bin/dockerd", "denied"), "binary:dockerd:denied", None),
    (lambda h: h.xattr.__setitem__("/usr/bin/dockerd", "unsupported"), "binary:dockerd:unsupported", None),
    (_deny("/etc/group"), "etc_group:denied", "proposed_identity_privileged_group"),
    (lambda h: h.files.__setitem__("/etc/group", b"+:::\n"), "etc_group:unrecognized", None),
    (_deny("/etc/passwd"), "etc_passwd:denied", "proposed_identity_absent"),
    (_deny("/etc/passwd"), "etc_passwd:denied", "proposed_identity_subuid_absent"),
    (lambda h: h.files.__setitem__("/etc/passwd", b"broken line\n"), "etc_passwd:malformed", "proposed_identity_absent"),
    (_deny("/run"), "filesystem:/run:denied", "filesystem_target_absent:/run"),
    (lambda h: h.vfs.pop("/home/runner/work"), "statvfs:/home/runner/work:absent", "work_free_bytes_below_5gib"),
    (_deny("/var/lib/docker"), "endpoint:/var/lib/docker:denied", None),
    (lambda h: setattr(h, "cpu_online", lambda: -1), "cpu_online:malformed", None),
]


@pytest.mark.parametrize("mutate, reason, forbidden_gap", UNKNOWN_CASES)
def test_unknown_facts_are_incomplete_never_negative_and_never_echoed(mutate, reason, forbidden_gap, tmp_path):
    host = FakeHost()
    mutate(host)
    _, report, _, text = _collect(host)
    assert report["observation"] == "incomplete"
    assert reason in report["incomplete_reasons"], report["incomplete_reasons"]
    assert _unknowns(report), "an unknown fact must be visible in the report, not silently dropped"
    if forbidden_gap is not None:
        assert forbidden_gap not in report["prerequisite_gaps"], report["prerequisite_gaps"]
    assert report["runtime_qualified"] is False
    assert CANARY not in text and CANARY.upper() not in text
    host2 = FakeHost()
    mutate(host2)
    assert P.main([], host=host2, output_root=tmp_path) == P.EXIT_INCOMPLETE


def test_unknown_value_without_a_reason_is_an_internal_contract_error(monkeypatch):
    monkeypatch.setattr(P._Collector, "miss", lambda self, area, kind: None)
    host = FakeHost()
    host.denied.add("/etc/os-release")
    with pytest.raises(P.PreflightError, match="unknown_fact_without_reason"):
        P.collect(host)


def test_denied_cgroup_kill_is_unknown_and_absent_cgroup_kill_is_a_gap():
    host = FakeHost()
    host.denied.add("/sys/fs/cgroup/system.slice/hosted-compute-agent.service/cgroup.kill")
    _, report, _, _ = _collect(host)
    assert report["cgroup"]["self"]["cgroup_kill_present"] == "denied"
    assert "self_cgroup_kill_absent" not in report["prerequisite_gaps"]
    host = FakeHost()
    host.stats.pop("/sys/fs/cgroup/system.slice/hosted-compute-agent.service/cgroup.kill")
    _, report, _, _ = _collect(host)
    assert report["cgroup"]["self"]["cgroup_kill_present"] is False and report["observation"] == "complete"
    assert "self_cgroup_kill_absent" in report["prerequisite_gaps"]


def test_missing_run_and_image_identity_is_incomplete_provenance():
    host = FakeHost()
    for key in ("ImageVersion", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        host.environ.pop(key)
    _, report, _, _ = _collect(host)
    assert report["observation"] == "incomplete"
    assert report["runner"]["image_version"] == "unavailable" and report["runner"]["run_id"] == "unavailable"
    assert {"env_image_version:unavailable", "env_run_id:unavailable",
            "env_run_attempt:unavailable"} <= set(report["incomplete_reasons"])


def test_membership_is_computed_from_the_full_group_list_before_marked_truncation():
    host = FakeHost()
    host.identity_values = (1001, 1001, 1001, list(range(300)))
    host.files["/etc/group"] = b"docker:x:299:runner\n"
    _, report, _, _ = _collect(host)
    identity = report["identity"]
    assert identity["in_docker_group"] is True
    assert identity["groups_truncated"] is True and identity["groups_total"] == 301
    assert len(identity["groups"]) == P.EMITTED_GROUPS
    assert report["observation"] == "complete"


def test_too_many_process_groups_is_malformed_not_truncated_membership():
    host = FakeHost()
    host.identity_values = (1001, 1001, 1001, list(range(P.MAX_PROCESS_GROUPS + 1)))
    _, report, _, _ = _collect(host)
    assert report["identity"]["uid"] == "malformed" and report["identity"]["in_docker_group"] is None
    assert "identity:malformed" in report["incomplete_reasons"]


def test_absent_local_docker_group_is_determinate_scope_data():
    host = FakeHost()
    host.files["/etc/group"] = b"root:x:0:\nrunner:x:1001:\n"
    _, report, _, _ = _collect(host)
    assert report["identity"]["docker_group_local"] == "absent" and report["identity"]["in_docker_group"] is None
    assert report["observation"] == "complete"


def test_sudo_listing_recognizes_rules_and_continuations_but_claims_only_listing():
    host = FakeHost()
    host.commands["sudo_list"] = _ok(_sudo_out("    (ALL) NOPASSWD: ALL\n    (ALL) PASSWD: ALL\n"))
    _, report, _, _ = _collect(host)
    assert report["sudo"]["state"] == "listed" and report["sudo"]["nopasswd_all_rule_listed"] is True
    assert report["sudo"]["rule_lines"] == 2 and report["sudo"]["scope"] == "recognized_listing_not_effective_policy"
    host.commands["sudo_list"] = _ok(_sudo_out("    (root) NOPASSWD: /usr/bin/a, /usr/bin/b,\n        /usr/bin/c\n"))
    _, report, _, _ = _collect(host)
    assert report["sudo"] == {"scope": "recognized_listing_not_effective_policy", "state": "listed",
                              "rule_facts": "from_listing", "rule_lines": 1, "nopasswd_all_rule_listed": False}
    host.commands["sudo_list"] = _ok(_sudo_out("    (ALL) NOPASSWD:\n        ALL\n"))
    _, report, _, _ = _collect(host)
    assert report["sudo"]["nopasswd_all_rule_listed"] is True and report["sudo"]["rule_lines"] == 1
    for bad in (b"User runner may run the following commands on h:\n", _sudo_out("  odd indent\n"),
                _sudo_out() + b"Trailing unrecognized text\n", _sudo_out() + _sudo_out()):
        host.commands["sudo_list"] = _ok(bad)
        _, report, _, _ = _collect(host)
        assert report["sudo"]["state"] == "unrecognized" and report["observation"] == "incomplete", bad


def test_denied_sudo_and_password_required_are_classified_without_raw_text():
    host = FakeHost()
    host.commands["sudo_list"] = _fail("nonzero_exit", 1, f"sudo: a password is required {CANARY}".encode(),
                                       stderr_class="password_required")
    _, report, _, text = _collect(host)
    # R2: the query outcome is known but the requested listing is not: incomplete, partial data kept.
    assert report["sudo"]["state"] == "password_required" and report["sudo"]["rule_facts"] == "unavailable"
    assert report["sudo"]["rule_lines"] is None and report["sudo"]["nopasswd_all_rule_listed"] is None
    assert report["observation"] == "incomplete" and report["incomplete_reasons"] == ["sudo_rules:unavailable"]
    host.commands["sudo_list"] = _fail("nonzero_exit", 1, stdout=b"User runner is not allowed to run sudo on h.\n")
    _, report, _, _ = _collect(host)
    assert report["sudo"]["state"] == "not_permitted"
    assert report["sudo"]["rule_facts"] == "sudo_reported_no_permission" and report["observation"] == "complete"
    host.commands["sudo_list"] = _fail("nonzero_exit", 1, stderr=b"???", stderr_class="other")
    _, report, _, _ = _collect(host)
    assert report["sudo"]["state"] == "unrecognized" and "sudo_list:unrecognized" in report["incomplete_reasons"]
    host.commands["sudo_list"] = _fail("tool_absent")
    _, report, _, _ = _collect(host)
    assert report["sudo"]["state"] == "tool_absent"
    assert CANARY not in text


def test_stderr_classifier_is_closed():
    assert P.classify_stderr(b"sudo: a password is required\n") == "password_required"
    assert P.classify_stderr(f"Sorry, user runner may not run sudo on {CANARY}.\n".encode()) == "not_permitted"
    assert P.classify_stderr(f"{CANARY}".encode()) == "other"
    assert P.classify_stderr(b"") == "empty"


def test_apparmor_loaded_list_requires_every_line_recognized():
    assert P.parse_apparmor_loaded(b"a (enforce)\nb (complain)\n") == (2, "absent")
    assert P.parse_apparmor_loaded(b"/usr/bin/rootlesskit (enforce)\n") == (1, "enforce")
    for bad in (b"rootlesskit malformed\n", b"ok (enforce)\nno-mode\n"):
        with pytest.raises(P.HostReadError) as caught:
            P.parse_apparmor_loaded(bad)
        assert caught.value.kind == "malformed"
    with pytest.raises(P.HostReadError) as caught:
        P.parse_apparmor_loaded(b"rootlesskit (enforce)\nrootlesskit (complain)\n")
    assert caught.value.kind == "ambiguous"


# ---- Real-host xattr classification (mocked; no path is inspected) -------------------------------

@pytest.mark.parametrize("raised, expected", [
    (PermissionError(errno.EACCES, "synthetic"), "denied"),
    (OSError(errno.ENOTSUP, "synthetic"), "unsupported"),
    (OSError(errno.EIO, "synthetic"), "error"),
])
def test_real_host_xattr_denial_or_error_is_not_absence(raised, expected):
    budget = P.Budget(remaining_bytes=P.XATTR_VALUE_BOUND, deadline=time.monotonic() + 5)
    with mock.patch.object(P.os, "getxattr", side_effect=raised, create=True):
        with pytest.raises(P.HostReadError) as caught:
            P.RealHost(P.ROOT).has_capability_xattr("/synthetic/never-read", budget)
    assert caught.value.kind == expected


def test_reviewer_real_host_enodata_is_ambiguous_and_only_presence_is_determinate():
    # getxattr(2): ENODATA is "does not exist, or no access". The collector does not bind the tool file's
    # filesystem/LSM stack, so one ENODATA cannot be read as absence (third review, ENODATA section).
    budget = P.Budget(remaining_bytes=P.XATTR_VALUE_BOUND + 100, deadline=time.monotonic() + 5)
    with mock.patch.object(P.os, "getxattr", side_effect=OSError(errno.ENODATA, "no attr"), create=True):
        with pytest.raises(P.HostReadError) as caught:
            P.RealHost(P.ROOT).has_capability_xattr("/synthetic/never-read", budget)
    assert caught.value.kind == "ambiguous" and budget.read_calls == 1 and budget.delivered_bytes == 0
    with mock.patch.object(P.os, "getxattr", return_value=b"\x01" * 20, create=True):
        assert P.RealHost(P.ROOT).has_capability_xattr("/synthetic/never-read", budget) is True
    assert budget.delivered_bytes == 20
    with mock.patch.object(P.os, "getxattr", None, create=True):
        with pytest.raises(P.HostReadError) as caught:
            P.RealHost(P.ROOT).has_capability_xattr("/synthetic/never-read", budget)
    assert caught.value.kind == "unavailable"


# ---- Tool inventory is a selected-path inventory -------------------------------------------------

def test_symlinked_binary_outside_fixed_roots_is_not_hashed():
    host = FakeHost()
    host.links["/usr/bin/rootlesskit"] = f"/home/runner/{CANARY}/rootlesskit"
    host.binaries[f"/home/runner/{CANARY}/rootlesskit"] = BINARY
    _, report, _, text = _collect(host)
    tool = report["binaries"]["tools"]["rootlesskit"]
    assert tool["state"] == "outside_fixed_roots" and tool["via_symlink"] is True and tool["sha256"] is None
    assert f"hash:/home/runner/{CANARY}/rootlesskit" not in host.reads
    assert "tool_not_found_in_fixed_dirs:rootlesskit" in report["prerequisite_gaps"]
    assert CANARY not in text


def test_first_existing_nonregular_entry_stops_the_selected_path_search():
    host = FakeHost()
    host.stats["/usr/local/bin/unshare"] = FakeStat(stat.S_IFDIR | 0o755)
    _, report, _, _ = _collect(host)
    tool = report["binaries"]["tools"]["unshare"]
    assert tool["state"] == "first_entry_not_regular" and tool["dir_index"] == 1
    assert "hash:/usr/bin/unshare" not in host.reads


def test_binary_over_hash_cap_is_incomplete_without_digest(monkeypatch):
    host = FakeHost()
    host.binaries["/usr/bin/dockerd"] = b"x" * 64
    monkeypatch.setattr(P, "HASH_FILE_CAP", 32)
    _, report, _, _ = _collect(host)
    tool = report["binaries"]["tools"]["dockerd"]
    assert tool["state"] == "oversize" and tool["sha256"] is None
    assert "binary:dockerd:oversize" in report["incomplete_reasons"]


def test_tool_found_only_in_bin_and_symlink_into_usr_lib_are_hashed():
    host = FakeHost()
    host.binaries.pop("/usr/bin/mount")
    host.binaries["/bin/mount"] = BINARY + b"m2"
    host.links["/usr/bin/rootlesskit"] = "/usr/lib/docker/rootlesskit"
    host.binaries["/usr/lib/docker/rootlesskit"] = BINARY + b"r"
    _, report, _, _ = _collect(host)
    mount = report["binaries"]["tools"]["mount"]
    assert mount["state"] == "found_regular" and mount["dir_index"] == 5 and mount["via_symlink"] is False
    assert mount["sha256"] == hashlib.sha256(BINARY + b"m2").hexdigest()
    rootless = report["binaries"]["tools"]["rootlesskit"]
    assert rootless["state"] == "found_regular" and rootless["via_symlink"] is True and rootless["dir_index"] == 3


# ---- Mount topology (F1) ---------------------------------------------------------------------------

HIDDEN = (b"1 0 8:1 / / rw - ext4 /dev/root rw\n"
          b"2 1 0:2 / /home rw - tmpfs tmpfs rw\n"
          b"3 2 0:3 / /home/runner/work rw shared:3 - xfs /dev/old rw\n"
          b"4 2 0:4 / /home rw - ext4 /dev/new rw\n")


def test_reviewer_hidden_descendant_mount_resolves_to_the_reachable_filesystem():
    host = FakeHost()
    host.files["/proc/self/mountinfo"] = HIDDEN
    _, report, _, _ = _collect(host)
    work = report["filesystems"]["/home/runner/work"]
    assert work["fstype"] == "ext4" and work["propagation"] == "private" and work["mount_point"] == "/home"
    assert work["mount_point_is_target"] is False


def test_mount_resolution_is_independent_of_input_order():
    lines = HIDDEN.splitlines(keepends=True)
    expected = P.resolve_visible_entry(P.parse_mountinfo(HIDDEN), "/home/runner/work")["id"]
    rng = random.Random(7)
    for _ in range(24):
        rng.shuffle(lines)
        assert P.resolve_visible_entry(P.parse_mountinfo(b"".join(lines)), "/home/runner/work")["id"] == expected == 4


def test_tucked_and_stacked_mounts_follow_parent_links():
    data = (b"10 1 8:1 / / rw - ext4 a rw\n"
            b"11 10 0:2 / /run rw shared:1 - tmpfs t rw\n"
            b"12 11 0:3 / /run rw - ramfs r rw\n"          # stacked on /run: visible
            b"13 11 0:4 / /run/x rw - xfs x rw\n"          # child of the covered /run: hidden
            b"14 12 0:5 / /run/y rw - btrfs y rw\n")       # child of the visible /run
    entries = P.parse_mountinfo(data)
    assert P.resolve_visible_entry(entries, "/run")["fstype"] == "ramfs"
    assert P.resolve_visible_entry(entries, "/run/x/deep")["fstype"] == "ramfs"
    assert P.resolve_visible_entry(entries, "/run/y")["fstype"] == "btrfs"
    assert P.resolve_visible_entry(entries, "/runx")["fstype"] == "ext4"


@pytest.mark.parametrize("data", [
    b"1 0 8:1 / / rw - ext4 a rw\n2 9 8:2 / / rw - ext4 b rw\n",                        # two roots
    b"1 0 8:1 / / rw - ext4 a rw\n2 1 0:2 / /run rw - tmpfs t rw\n3 1 0:3 / /run rw - tmpfs u rw\n",  # siblings
    b"1 0 8:1 / /run rw - ext4 a rw\n",                                                # root not at /
    b"1 0 8:1 / / rw - ext4 a rw\n2 3 0:2 / /run rw - tmpfs t rw\n3 2 0:3 / /run rw - tmpfs u rw\n",  # cycle
])
def test_ambiguous_topology_is_unknown_not_guessed(data):
    entries = P.parse_mountinfo(data)
    with pytest.raises(P.HostReadError) as caught:
        P.resolve_visible_entry(entries, "/run")
    assert caught.value.kind == "ambiguous"
    host = FakeHost()
    host.files["/proc/self/mountinfo"] = data
    _, report, _, _ = _collect(host)
    assert report["filesystems"]["/run"]["mount_state"] == "ambiguous" and report["observation"] == "incomplete"
    assert report["filesystems"]["/run"]["fstype"] is None


def test_duplicate_mount_ids_are_malformed():
    with pytest.raises(P.HostReadError):
        P.parse_mountinfo(b"1 0 8:1 / / rw - ext4 a rw\n1 1 0:2 / /run rw - tmpfs t rw\n")


def test_mountinfo_escapes_overmounts_and_propagation():
    data = (b"1 0 8:1 / / rw shared:1 - ext4 /dev/a rw\n"
            b"2 1 0:2 / /home/runner rw master:4 - xfs /dev/b rw\n"
            b"3 2 0:3 / /home/runner/work ro,nosuid unbindable - overlay overlay rw\n"
            b"4 1 0:4 / /home/runner\\040x rw - tmpfs t rw\n")
    entries = P.parse_mountinfo(data)
    assert entries[4]["mount_point"] == "/home/runner x"
    chosen = P.resolve_visible_entry(entries, "/home/runner/work/heel")
    assert chosen["fstype"] == "overlay" and chosen["propagation"] == "unbindable"
    assert chosen["options"] >= {"ro", "nosuid"}
    assert P.resolve_visible_entry(entries, "/home/runnerx")["mount_point"] == "/"
    assert P.resolve_visible_entry(entries, "/home/runner/x")["propagation"] == "slave"


def test_cgroup_visibility_uses_topology_and_mount_root():
    host = FakeHost()  # /sys/fs/cgroup hidden by a later stacked mount over /sys/fs/cgroup
    host.files["/proc/self/mountinfo"] = _mountinfo("26 23 0:30 / /sys/fs/cgroup rw - tmpfs tmpfs rw\n")
    _, report, _, _ = _collect(host)
    assert report["cgroup"]["filesystem"] == "tmpfs" and report["cgroup"]["unified"] is False
    assert "cgroup_not_unified" in report["prerequisite_gaps"]
    assert report["cgroup"]["self"]["cgroup_kill_present"] == "ambiguous" and report["observation"] == "incomplete"
    host = FakeHost()  # cgroup2 mounted from a non-root cgroup: own path mapping is not established
    host.files["/proc/self/mountinfo"] = _mountinfo().replace(b"23 22 0:21 / /sys/fs/cgroup",
                                                               b"23 22 0:21 /system.slice /sys/fs/cgroup")
    _, report, _, _ = _collect(host)
    assert report["cgroup"]["unified"] is True
    assert "self_cgroup_files:ambiguous" in report["incomplete_reasons"]


# ---- Byte accounting (F3) --------------------------------------------------------------------------

def _mock_file(chunks, size):
    queue = list(chunks)
    delivered = {"bytes": 0}

    def read_chunk(fd, count):
        piece = queue.pop(0) if queue else b""
        piece = piece[:count]
        delivered["bytes"] += len(piece)
        return piece
    return read_chunk, delivered, FakeStat(REG, size=size)


def test_reviewer_two_growing_files_are_charged_and_never_exceed_the_aggregate():
    budget = P.Budget(remaining_bytes=6, deadline=time.monotonic() + 5)
    total_delivered = 0
    kinds = []
    for _ in range(2):
        read_chunk, delivered, info = _mock_file((b"abcd", b"e"), 4)
        with mock.patch.object(P.RealHost, "_open", return_value=42), \
                mock.patch.object(P.os, "fstat", return_value=info), mock.patch.object(P.os, "set_blocking"), \
                mock.patch.object(P.os, "close"), mock.patch.object(P.os, "read", side_effect=read_chunk):
            with pytest.raises(P.HostReadError) as caught:
                P.RealHost(P.ROOT).hash_file("/synthetic/growing", 4, budget)
        kinds.append(caught.value.kind)
        total_delivered += delivered["bytes"]
    assert kinds == ["oversize", "aggregate_exhausted"]
    assert total_delivered == budget.delivered_bytes == 5 <= 6
    assert budget.remaining_bytes == 1


def test_many_failing_reads_charge_every_delivered_byte_without_refund():
    budget = P.Budget(remaining_bytes=50, deadline=time.monotonic() + 5)
    delivered_total = 0
    for _ in range(10):
        read_chunk, delivered, info = _mock_file((b"x" * 7, b"y" * 7, b"z"), 0)
        calls = {"n": 0}

        def failing(fd, count, read_chunk=read_chunk, calls=calls):
            calls["n"] += 1
            if calls["n"] == 3:
                raise OSError(errno.EIO, "synthetic")
            return read_chunk(fd, count)
        with mock.patch.object(P.RealHost, "_open", return_value=42), \
                mock.patch.object(P.os, "fstat", return_value=info), mock.patch.object(P.os, "set_blocking"), \
                mock.patch.object(P.os, "close"), mock.patch.object(P.os, "read", side_effect=failing):
            with pytest.raises(P.HostReadError):
                P.RealHost(P.ROOT).read("/synthetic/erroring", 100, budget)
        delivered_total += delivered["bytes"]
    assert delivered_total == budget.delivered_bytes <= 50
    assert budget.remaining_bytes == 50 - delivered_total


def test_real_host_read_charges_the_oversize_sentinel_and_is_bounded_before_allocation(tmp_path):
    host = P.RealHost(P.ROOT)
    big = tmp_path / "big"
    big.write_bytes(b"z" * 5000)
    budget = P.Budget(remaining_bytes=10_000, deadline=time.monotonic() + 5)
    with pytest.raises(P.HostReadError) as caught:
        host.read(str(big), 1000, budget)
    assert caught.value.kind == "oversize" and budget.delivered_bytes == 1001
    with pytest.raises(P.HostReadError) as caught:
        host.read(str(tmp_path / "nope"), 10, budget)
    assert caught.value.kind == "absent"
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(P.HostReadError) as caught:
        host.read(str(fifo), 10, budget)
    assert caught.value.kind == "not_regular"


def test_exact_cap_file_needs_an_eof_read_inside_the_remaining_aggregate(tmp_path):
    host = P.RealHost(P.ROOT)
    path = tmp_path / "exact"
    path.write_bytes(b"q" * 100)
    tight = P.Budget(remaining_bytes=100, deadline=time.monotonic() + 5)
    with pytest.raises(P.HostReadError) as caught:
        host.read(str(path), 100, tight)
    assert caught.value.kind == "aggregate_exhausted" and tight.delivered_bytes == 100 and tight.remaining_bytes == 0
    room = P.Budget(remaining_bytes=101, deadline=time.monotonic() + 5)
    assert host.read(str(path), 100, room) == b"q" * 100 and room.delivered_bytes == 100


def test_real_host_hash_is_bounded_and_charged(tmp_path):
    host = P.RealHost(P.ROOT)
    path = tmp_path / "bin"
    path.write_bytes(b"q" * 100)
    budget = P.Budget(remaining_bytes=1000, deadline=time.monotonic() + 5)
    assert host.hash_file(str(path), 200, budget) == (hashlib.sha256(b"q" * 100).hexdigest(), 100)
    assert budget.remaining_bytes == 900
    with pytest.raises(P.HostReadError):
        host.hash_file(str(path), 50, budget)
    assert budget.remaining_bytes == 900  # refused by fstat size before any read
    small = P.Budget(remaining_bytes=50, deadline=time.monotonic() + 5)
    with pytest.raises(P.HostReadError) as caught:
        host.hash_file(str(path), 200, small)
    assert caught.value.kind == "aggregate_exhausted" and small.delivered_bytes == 0


def test_budget_refuses_overdelivery():
    budget = P.Budget(remaining_bytes=3, deadline=time.monotonic() + 5)
    with pytest.raises(P.PreflightError):
        P.bounded_stream(lambda count: b"x" * (count + 1), 10, budget, 4, lambda chunk: None)


def test_collector_aggregate_is_shared_by_every_read(monkeypatch):
    monkeypatch.setattr(P, "READ_AGGREGATE_CAP", 600)
    host, report, _, _ = _collect(FakeHost())
    assert report["accounting"]["read_bytes_cap"] == 600
    assert report["accounting"]["read_bytes_delivered"] <= 600
    assert report["observation"] == "incomplete"
    assert any(reason.endswith(":aggregate_exhausted") for reason in report["incomplete_reasons"])


# ---- Deadline admission and postchecks -------------------------------------------------------------

def test_aggregate_deadline_exhaustion_skips_remaining_work_truthfully():
    host = FakeHost()
    host.clock_step = 7.0  # every clock read advances 7 s
    _, report, commands, _ = _collect(host)
    assert report["observation"] == "incomplete"
    assert any(reason.endswith(":deadline_exhausted") for reason in report["incomplete_reasons"])
    assert any(item["state"] == "deadline_exhausted" for item in commands.values())
    assert report["accounting"]["deadline_overrun"] is True
    assert report["runtime_qualified"] is False


def test_reviewer_late_final_stat_cannot_report_complete():
    host = FakeHost()
    old = host.stat

    def late_stat(path, follow=True):
        if path == "/var/lib/containerd":
            host.clock_value = 1200.0
        return old(path, follow)
    host.stat = late_stat
    _, report, _, _ = _collect(host)
    assert report["observation"] == "incomplete"
    assert "endpoint:/var/lib/containerd:deadline_overrun" in report["incomplete_reasons"]
    assert "finalization:deadline_overrun" in report["incomplete_reasons"]
    assert report["accounting"]["deadline_overrun"] is True


def test_no_operation_is_admitted_after_an_overrun():
    host = FakeHost()
    old = host.identity

    def late_identity():
        host.clock_value = 2000.0
        return old()
    host.identity = late_identity
    _, report, commands, _ = _collect(host)
    after = host.reads[host.reads.index("identity") + 1:]
    assert after == [], after
    assert commands["sudo_list"]["state"] == "deadline_exhausted"
    assert "identity:deadline_overrun" in report["incomplete_reasons"]


def test_late_finalization_is_never_written_or_published(tmp_path):
    class LateHost(FakeHost):
        def __init__(self):
            super().__init__()
            self.calls = 0

    host = LateHost()
    real_collect = P.collect

    def collect_then_stall(h, argv=(), timing=None):
        result = real_collect(h, argv, timing)
        h.clock_value += 500.0
        return result
    with mock.patch.object(P, "collect", collect_then_stall):
        assert P.main([], host=host, output_root=tmp_path) == P.EXIT_INTERNAL
    assert not (tmp_path / P.OUTPUT_DIR_NAME).exists()


# ---- Closed output schema --------------------------------------------------------------------------

def test_reviewer_unexpected_ascii_field_is_refused_by_the_closed_schema():
    report, _ = P.collect(FakeHost())
    report["unexpected_raw_field"] = "SYNTHETIC_PRIVATE_ASCII_CANARY"
    with pytest.raises(P.PreflightError, match="schema_fields"):
        P._serialize(report)
    report, _ = P.collect(FakeHost())
    report["identity"]["extra"] = 1
    with pytest.raises(P.PreflightError):
        P.validate_output(report)


@pytest.mark.parametrize("path, value", [
    (("kernel", "release"), "x" * 400),
    (("kernel", "release"), CANARY + " raw"),
    (("cpu", "online"), True),
    (("sudo", "state"), "listed-and-root"),
    (("filesystems", "/run", "fstype"), "secretfs"),
    (("runtime_qualified",), True),
    (("verdict",), "PASS"),
    (("identity", "groups"), list(range(P.EMITTED_GROUPS + 1))),
])
def test_report_validator_rejects_wrong_types_enums_and_strings(path, value):
    report, _ = P.collect(FakeHost())
    target = report
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(P.PreflightError):
        P.validate_output(report)
    with pytest.raises(P.PreflightError):
        P.validate_output({"runtime_qualified": True})


def test_node_and_size_bounds_refuse_before_json_allocation(monkeypatch):
    calls = []
    monkeypatch.setattr(P.json, "dumps", lambda *a, **k: calls.append(1) or "")
    wide = P.S_list(P.S_re(r"x{1,160}"), 10_000)
    with pytest.raises(P.PreflightError, match="output_too_many_nodes|output_oversize"):
        P._serialize(["x" * 160] * 5000, wide)
    assert calls == []  # refused by the node/size bound before any JSON allocation


def test_commands_document_is_closed_and_bound_to_the_report():
    report, commands = P.collect(FakeHost())
    doc = P._commands_document(report, commands)
    P.validate_output(doc, P.COMMANDS_SPEC)
    doc["commands"]["sudo_list"]["stdout"] = "raw"
    with pytest.raises(P.PreflightError):
        P.validate_output(doc, P.COMMANDS_SPEC)


# ---- Bounded owned subprocesses (real, small, owned Python children) ------------------------------

PY = (sys.executable, "-I", "-S", "-c")
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def _run(code, timeout=2.0, cap=1024):
    return P.run_bounded((*PY, code), env=ENV, cwd="/", timeout=timeout, stdout_cap=cap, stderr_cap=256)


def test_bounded_run_ok_and_nonzero():
    result = _run("import sys; sys.stdout.write('hello'); sys.stderr.write('err-%s' % 'x')")
    assert result.state == "ok" and result.exit_code == 0 and result.stdout == b"hello" and result.leader_reaped
    assert result.stderr_bytes == 5
    # Linux delivers to the zombie leader's group; macOS answers EPERM for a zombie-only group.
    assert result.group_signal == ("sent" if sys.platform.startswith("linux") else result.group_signal)
    assert result.group_signal in ("sent", "denied")
    result = _run("import sys; sys.exit(3)")
    assert result.state == "nonzero_exit" and result.exit_code == 3


def test_bounded_run_timeout_kills_owned_group_promptly():
    start = time.monotonic()
    result = _run("import time; time.sleep(30)", timeout=0.5)
    assert result.state == "timeout" and result.leader_reaped is True
    assert time.monotonic() - start < 3.0


def test_bounded_run_output_flood_is_capped_before_parsing():
    result = _run("import sys\nwhile True: sys.stdout.write('A' * 65536)", timeout=5.0, cap=4096)
    assert result.state == "output_cap_exceeded" and result.stdout_truncated is True
    assert len(result.stdout) <= 4096 and result.leader_reaped and result.stdout_bytes == 4097


def test_bounded_run_pipe_holder_grandchild_in_the_group_is_killed(tmp_path):
    pid_file = tmp_path / "grandchild.pid"
    code = (
        "import os, sys, time\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        "    time.sleep(30)\n"
        "    os._exit(0)\n"
        f"open({str(pid_file)!r}, 'w').write(str(pid))\n"
        "sys.stdout.write('parent-done'); sys.stdout.flush()\n"
        "os._exit(0)\n"
    )
    start = time.monotonic()
    result = _run(code, timeout=5.0)
    assert result.state == "pipe_held" and result.exit_code == 0
    assert time.monotonic() - start < 4.0
    grandchild = int(pid_file.read_text())
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            os.kill(grandchild, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        try:
            os.waitpid(grandchild, os.WNOHANG)
        except ChildProcessError:
            pass
        with pytest.raises(ProcessLookupError):
            os.kill(grandchild, 0)


def test_reviewer_escaped_pipe_closing_descendant_is_reported_as_not_observed(tmp_path):
    """F4 reproduction: a setsid'd, pipe-closing, self-terminating child is outside every guarantee."""
    ready, done = tmp_path / "ready", tmp_path / "done"
    child = (f"import pathlib,time; pathlib.Path({str(ready)!r}).write_text('ready'); "
             f"time.sleep(0.4); pathlib.Path({str(done)!r}).write_text('done')")
    leader = ("import subprocess,sys,time,pathlib\n"
              f"subprocess.Popen([sys.executable,'-I','-S','-c',{child!r}],start_new_session=True,"
              "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
              "end=time.monotonic()+1\n"
              f"while not pathlib.Path({str(ready)!r}).exists() and time.monotonic()<end: time.sleep(0.005)\n")
    result = _run(leader, timeout=2.0)
    done_at_return = done.exists()
    until = time.monotonic() + 3
    while not done.exists() and time.monotonic() < until:
        time.sleep(0.01)
    assert result.state == "ok" and result.leader_reaped is True and not done_at_return
    assert done.read_text() == "done"  # the descendant finished on its own, unobserved
    summary = result.summary()
    assert summary["descendants_outside_group"] == "not_observed" and "reaped" not in summary


def test_bounded_run_missing_tool_and_stdin_is_closed(tmp_path):
    result = P.run_bounded((str(tmp_path / "absent-tool"),), env=ENV, cwd="/", timeout=1.0,
                           stdout_cap=64, stderr_cap=64)
    assert result.state == "tool_absent" and result.exit_code is None
    result = _run("import sys; sys.stdout.write(repr(sys.stdin.read()))")
    assert result.stdout == b"''"


def test_bounded_run_rejects_non_tuple_or_shell_strings():
    with pytest.raises(P.PreflightError):
        P.run_bounded("echo hi", env=ENV, cwd="/", timeout=1.0, stdout_cap=8, stderr_cap=8)


def test_bounded_run_leader_that_closes_its_pipes_but_keeps_running_is_a_timeout():
    code = "import os, time\nos.close(1); os.close(2)\ntime.sleep(30)\n"
    start = time.monotonic()
    result = _run(code, timeout=0.6)
    assert result.state == "timeout" and result.exit_code is None and result.leader_reaped
    assert time.monotonic() - start < 3.0


def test_bounded_run_stderr_flood_is_capped_and_never_returned():
    result = _run("import sys\nwhile True: sys.stderr.write('E' * 65536)", timeout=5.0)
    assert result.state == "stderr_cap_exceeded" and result.stdout == b"" and result.leader_reaped
    assert not hasattr(result, "stderr")


def test_command_overrun_is_postchecked():
    host = FakeHost()
    real_run = host.run

    def slow(command_id, timeout):
        if command_id == "systemctl_version":
            host.clock_value += 200.0
        return real_run(command_id, timeout)
    host.run = slow
    _, report, _, _ = _collect(host)
    assert "systemctl_version:deadline_overrun" in report["incomplete_reasons"]


# ---- Misc facts ------------------------------------------------------------------------------------

def test_git_dirty_worktree_is_recorded():
    host = FakeHost()
    host.commands["git_status"] = _ok(f" M {CANARY}.py\n M b.py\n".encode())
    _, report, _, text = _collect(host)
    assert report["source"]["worktree_clean"] is False and report["source"]["dirty_entries"] == 2
    assert "source_worktree_dirty" in report["prerequisite_gaps"]
    assert CANARY not in text


def test_low_free_space_and_unexpected_os_are_gaps():
    host = FakeHost()
    host.vfs["/home/runner/work"] = FakeVfs(bavail=GiB // 4096)
    host.files["/etc/os-release"] = b'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n'
    _, report, _, _ = _collect(host)
    assert report["filesystems"]["/home/runner/work"]["below_5gib_floor"] is True
    assert {"work_free_bytes_below_5gib", "os_not_ubuntu_24_04"} <= set(report["prerequisite_gaps"])


def test_kernel_release_outside_the_token_grammar_is_malformed_and_incomplete():
    host = FakeHost()
    host.uname = lambda: ("Linux", f"6.8 {CANARY}", "x86_64")
    _, report, _, text = _collect(host)
    assert report["kernel"]["release"] == "malformed"
    assert "kernel_release:malformed" in report["incomplete_reasons"]
    assert CANARY not in text


# ---- R2: xattr admission and accounting (second review R1) -------------------------------------

def _xattr(budget, **getter_kwargs):
    getter = mock.Mock(**getter_kwargs)
    with mock.patch.object(P.os, "getxattr", getter, create=True):
        try:
            return P.RealHost(P.ROOT).has_capability_xattr("/synthetic/never-read", budget), None, getter
        except P.HostReadError as error:
            return None, error.kind, getter


@pytest.mark.parametrize("remaining", [0, 3, P.XATTR_VALUE_BOUND - 1])
def test_reviewer_xattr_without_capacity_for_its_maximum_is_never_invoked(remaining):
    budget = P.Budget(remaining_bytes=remaining, deadline=time.monotonic() + 5)
    value, kind, getter = _xattr(budget, return_value=b"\x00" * 20)
    assert (value, kind) == (None, "aggregate_exhausted")
    assert getter.call_count == 0 and budget.delivered_bytes == 0 and budget.read_calls == 0
    assert budget.remaining_bytes == remaining


def test_xattr_admitted_at_the_documented_maximum_charges_actual_delivery():
    budget = P.Budget(remaining_bytes=P.XATTR_VALUE_BOUND, deadline=time.monotonic() + 5)
    value, kind, getter = _xattr(budget, return_value=b"\x01" * 20)
    assert (value, kind) == (True, None) and getter.call_count == 1
    assert budget.delivered_bytes == 20 and budget.read_calls == 1 and budget.remaining_bytes == P.XATTR_VALUE_BOUND - 20
    exact = P.Budget(remaining_bytes=P.XATTR_VALUE_BOUND, deadline=time.monotonic() + 5)
    assert _xattr(exact, return_value=b"\x02" * P.XATTR_VALUE_BOUND)[0] is True
    assert exact.delivered_bytes == P.XATTR_VALUE_BOUND and exact.remaining_bytes == 0


@pytest.mark.parametrize("err, expected", [
    (errno.ENODATA, "ambiguous"), (errno.EACCES, "denied"), (errno.ENOTSUP, "unsupported"), (errno.E2BIG, "oversize"),
    (errno.ERANGE, "oversize"), (errno.EIO, "error"),
])
def test_xattr_errors_are_classified_counted_and_deliver_nothing(err, expected):
    budget = P.Budget(remaining_bytes=P.XATTR_VALUE_BOUND, deadline=time.monotonic() + 5)
    raised = PermissionError(err, "synthetic") if err == errno.EACCES else OSError(err, "synthetic")
    value, kind, getter = _xattr(budget, side_effect=raised)
    assert kind == expected and value is None
    assert getter.call_count == 1 and budget.read_calls == 1 and budget.delivered_bytes == 0


def test_xattr_overdelivery_is_charged_then_oversize_or_an_internal_error():
    budget = P.Budget(remaining_bytes=P.XATTR_VALUE_BOUND + 10, deadline=time.monotonic() + 5)
    value, kind, _ = _xattr(budget, return_value=b"\x03" * (P.XATTR_VALUE_BOUND + 1))
    assert (value, kind) == (None, "oversize")
    assert budget.delivered_bytes == P.XATTR_VALUE_BOUND + 1 and budget.remaining_bytes == 9  # no refund
    tight = P.Budget(remaining_bytes=P.XATTR_VALUE_BOUND, deadline=time.monotonic() + 5)
    with mock.patch.object(P.os, "getxattr", return_value=b"\x04" * (P.XATTR_VALUE_BOUND + 1), create=True):
        with pytest.raises(P.PreflightError, match="xattr_overdelivery"):
            P.RealHost(P.ROOT).has_capability_xattr("/synthetic/never-read", tight)
    with mock.patch.object(P.os, "getxattr", return_value="not-bytes", create=True):
        with pytest.raises(P.PreflightError, match="xattr_value_type"):
            P.RealHost(P.ROOT).has_capability_xattr("/synthetic/never-read", P.Budget(P.XATTR_VALUE_BOUND, 1e12))


def test_reviewer_successful_hash_leaving_little_budget_never_calls_the_xattr_getter():
    host = FakeHost()
    real_hash = host.hash_file

    def hash_then_drain(path, cap, budget):
        result = real_hash(path, cap, budget)
        budget.charge(budget.remaining_bytes - 3)  # a successful hash that leaves three bytes
        return result
    host.hash_file = hash_then_drain
    host.has_capability_xattr = lambda path, budget: P.RealHost(P.ROOT).has_capability_xattr(path, budget)
    getter = mock.Mock(return_value=b"\x00" * 20)
    with mock.patch.object(P.os, "getxattr", getter, create=True):
        _, report, _, _ = _collect(host)
    assert getter.call_count == 0
    dockerd = report["binaries"]["tools"]["dockerd"]
    assert dockerd["state"] == "found_regular" and dockerd["file_capability"] == "aggregate_exhausted"
    assert "binary:dockerd:aggregate_exhausted" in report["incomplete_reasons"] and report["observation"] == "incomplete"


# ---- R2: sudo listing completeness (second review R2) ----------------------------------------------

def test_reviewer_password_required_listing_is_incomplete_with_partial_data_and_exit_3(tmp_path):
    def host():
        h = FakeHost()
        h.commands["sudo_list"] = _fail("nonzero_exit", 1, f"a password is required {CANARY}".encode(),
                                        stderr_class="password_required")
        return h
    _, report, commands, text = _collect(host())
    assert report["sudo"] == {"scope": "recognized_listing_not_effective_policy", "state": "password_required",
                              "rule_facts": "unavailable", "rule_lines": None, "nopasswd_all_rule_listed": None}
    assert report["incomplete_reasons"] == ["sudo_rules:unavailable"] and report["observation"] == "incomplete"
    assert report["identity"]["uid"] == 1001 and report["filesystems"]["/run"]["fstype"] == "tmpfs"  # partial data
    assert commands["sudo_list"]["state"] == "nonzero_exit" and CANARY not in text
    h = host()
    assert P.main([], host=h, output_root=tmp_path) == P.EXIT_INCOMPLETE
    assert h.ran.count("sudo_list") == 1  # no retry, no escalation


def test_not_permitted_is_an_explicitly_labelled_narrower_negative_and_the_class_is_narrow():
    assert P.classify_stderr(b"sudo: you are not allowed to use this option\n") == "other"
    assert P.classify_stderr(b"Sorry, user runner may not run sudo on h.\n") == "not_permitted"
    assert P.classify_stderr(b"runner is not in the sudoers file.\n") == "not_permitted"
    assert P.classify_stderr(b"User runner is not allowed to run sudo on h.\n") == "not_permitted"
    host = FakeHost()
    host.commands["sudo_list"] = _fail("nonzero_exit", 1, stderr_class=P.classify_stderr(b"x not allowed to y"))
    _, report, _, _ = _collect(host)
    assert report["sudo"]["state"] == "unrecognized" and report["sudo"]["rule_facts"] == "unrecognized"
    assert "sudo_list:unrecognized" in report["incomplete_reasons"]
    host.commands["sudo_list"] = _fail("nonzero_exit", 1, stderr_class="not_permitted")
    _, report, _, _ = _collect(host)
    assert report["sudo"]["rule_facts"] == "sudo_reported_no_permission" and report["sudo"]["rule_lines"] is None
    assert report["observation"] == "complete"
    host.commands["sudo_list"] = _fail("tool_absent")
    _, report, _, _ = _collect(host)
    assert report["sudo"]["rule_facts"] == "not_applicable_tool_absent" and report["observation"] == "complete"


# ---- R2: structural completion contract -------------------------------------------------------------

def _leaves(value, path=()):
    if isinstance(value, dict):
        for key, item in value.items():
            if key not in ("scope", "name"):
                yield from _leaves(item, path + (key,))
    elif value is not None:
        yield path


def _set(report, path, value):
    target = report
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


OPTIONAL_FACTS = {("os_release", "point_version"), ("os_release", "codename")}


def test_every_required_fact_is_checked_structurally_for_null_and_reasonless_unknowns():
    report, _ = P.collect(_ideal_host())
    assert P._fact_contract_violations(report, []) == []
    paths = [path for section in P.FACT_SECTIONS for path in _leaves(report[section], (section,))]
    assert len(paths) > 150
    for path in (path for path in paths if path not in OPTIONAL_FACTS):
        for bad in (None, "denied"):
            mutated, _ = P.collect(_ideal_host())
            _set(mutated, path, bad)
            assert P._fact_contract_violations(mutated, []), (path, bad)


def test_reviewer_unknown_fact_missing_its_own_reason_is_an_error_even_with_other_reasons(monkeypatch):
    host = FakeHost()
    host.denied.update({"/etc/os-release", "/sys/kernel/security/apparmor/profiles"})
    real_miss = P._Collector.miss
    monkeypatch.setattr(P._Collector, "miss",
                        lambda self, area, kind: None if area == "os_release" else real_miss(self, area, kind))
    with pytest.raises(P.PreflightError, match="unknown_fact_without_reason"):
        P.collect(host)


def test_missing_sudo_rules_reason_or_inconsistent_rule_facts_is_a_contract_error(monkeypatch):
    host = FakeHost()
    host.commands["sudo_list"] = _fail("nonzero_exit", 1, stderr_class="password_required")
    real_miss = P._Collector.miss
    monkeypatch.setattr(P._Collector, "miss",
                        lambda self, area, kind: None if area == "sudo_rules" else real_miss(self, area, kind))
    with pytest.raises(P.PreflightError, match="unknown_fact_without_reason"):
        P.collect(host)
    report, _ = P.collect(FakeHost())
    report["sudo"]["rule_facts"] = "sudo_reported_no_permission"
    assert "sudo.rule_facts:inconsistent_with_state" in P._fact_contract_violations(report, [])


@pytest.mark.parametrize("mutate, reason, path", [
    (lambda h: h.environ.__setitem__("ImageOS", "error"), "env_image_os:malformed", ("runner", "image_os")),
    (lambda h: h.environ.__setitem__("ImageOS", "absent"), "env_image_os:malformed", ("runner", "image_os")),
    (lambda h: h.environ.__setitem__("RUNNER_OS", "Linux" * 20), "env_runner_os:malformed", ("runner", "runner_os")),
    (lambda h: h.files.__setitem__("/etc/os-release", b"ID=denied\nVERSION_ID=24.04\n"), "os_release:malformed",
     ("os_release", "state")),
    (lambda h: h.files.__setitem__("/etc/os-release", b"ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=error\n"),
     "os_release:malformed", ("os_release", "state")),
])
def test_reviewer_observed_strings_never_collide_with_unknown_tokens(mutate, reason, path):
    host = FakeHost()
    mutate(host)
    _, report, _, _ = _collect(host)
    assert reason in report["incomplete_reasons"] and report["observation"] == "incomplete"
    value = report
    for key in path:
        value = value[key]
    assert value == "malformed"


def test_token_backstop_refuses_independently_of_the_structural_checker(monkeypatch):
    monkeypatch.setattr(P, "_fact_contract_violations", lambda report, reasons: [])
    monkeypatch.setattr(P._Collector, "miss", lambda self, area, kind: None)
    host = FakeHost()
    host.denied.add("/etc/os-release")
    with pytest.raises(P.PreflightError, match="unknown_fact_without_reason"):
        P.collect(host)


def test_a_producer_null_where_its_state_applies_is_an_internal_error_not_complete(monkeypatch):
    real = P._Collector.sudo
    monkeypatch.setattr(P._Collector, "sudo", lambda self: dict(real(self), rule_lines=None))
    with pytest.raises(P.PreflightError, match="undetermined_required_fact"):
        P.collect(FakeHost())
    assert P.main([], host=FakeHost(), output_root=Path("/nonexistent-never-written")) == P.EXIT_INTERNAL


def test_non_string_dictionary_keys_are_a_closed_schema_refusal():
    for value in ({1: None}, {1: None, "schema": P.SCHEMA}, {None: 1}):
        with pytest.raises(P.PreflightError, match="schema_fields"):
            P.validate_output(value, P.REPORT_SPEC)


# ---- R2: propagation grammar (second review R3) ------------------------------------------------------

MALFORMED_TAGS = [b"shared:not-a-number", b"shared:", b"shared:-5", b"shared:+5", b"shared:0", b"shared:05",
                  b"shared:99999999999", b"shared:2147483648", b"shared:5 shared:6", b"shared:5 unbindable",
                  b"master:5 unbindable", b"unbindable:5", b"unbindable unbindable", b"shared:5 master:5",
                  b"propagate_from:7", b"master:7 propagate_from:7", b"master:7 shared:5", b"Shared:5",
                  b":5", b"future:"]


@pytest.mark.parametrize("tags", MALFORMED_TAGS)
def test_reviewer_malformed_recognized_propagation_metadata_is_never_complete_evidence(tags):
    host = FakeHost()
    host.files["/proc/self/mountinfo"] = _mountinfo().replace(b"shared:5", tags)
    _, report, _, _ = _collect(host)
    assert "mountinfo:malformed" in report["incomplete_reasons"] and report["observation"] == "incomplete"
    assert report["filesystems"]["/run"]["propagation"] is None
    assert report["filesystems"]["/run"]["mount_state"] == "unavailable"


@pytest.mark.parametrize("tags, expected", [
    (b"shared:2147483647", "shared"), (b"master:4", "slave"), (b"master:4 propagate_from:9", "slave"),
    (b"shared:1 master:2", "shared_and_slave"), (b"shared:1 master:2 propagate_from:3", "shared_and_slave"),
    (b"unbindable", "unbindable"), (b"", "private"),
])
def test_valid_propagation_tags_derive_the_documented_value(tags, expected):
    line = b"1 0 8:1 / / rw " + (tags + b" " if tags else b"") + b"- ext4 /dev/a rw\n"
    assert P.parse_mountinfo(line)[1]["propagation"] == expected


def test_unknown_future_optional_field_is_ignored_for_parsing_but_never_propagation_evidence():
    host = FakeHost()
    host.files["/proc/self/mountinfo"] = _mountinfo().replace(b"shared:5", f"shared:5 future_{CANARY.lower()}:7".encode())
    _, report, _, text = _collect(host)
    run = report["filesystems"]["/run"]
    assert run["mount_state"] == "resolved" and run["fstype"] == "tmpfs" and run["propagation"] == "unrecognized"
    assert report["incomplete_reasons"] == ["mount_propagation:/run:unrecognized"]
    assert CANARY.lower() not in text
    host = FakeHost()  # an unknown field on a mount that is not resolved for any target changes nothing
    host.files["/proc/self/mountinfo"] = _mountinfo().replace(b"shared:2", b"shared:2 future_tag")
    _, report, _, _ = _collect(host)
    assert report["observation"] == "complete" and report["filesystems"]["/run"]["propagation"] == "shared"


def test_mount_ids_are_bounded_digit_strings():
    for bad in (b"12345678901 0 8:1 / / rw - ext4 a rw\n", b"1 0 8:12345678901 / / rw - ext4 a rw\n",
                b"+1 0 8:1 / / rw - ext4 a rw\n"):
        with pytest.raises(P.HostReadError):
            P.parse_mountinfo(bad)


# ---- R2: early bounds (second review R4) ---------------------------------------------------------------

def _mount_table(records, final_newline):
    lines = ["1 0 0:1 / / rw - tmpfs tmpfs rw"] + [f"{i} 1 0:{i} / /tmp/m{i} rw - tmpfs tmpfs rw"
                                                   for i in range(2, records + 1)]
    return ("\n".join(lines) + ("\n" if final_newline else "")).encode()


@pytest.mark.parametrize("final_newline", [True, False])
def test_reviewer_logical_record_limit_counts_a_final_unterminated_line(final_newline):
    assert len(P.parse_mountinfo(_mount_table(P.MAX_MOUNT_ENTRIES, final_newline))) == P.MAX_MOUNT_ENTRIES
    over = _mount_table(P.MAX_MOUNT_ENTRIES + 1, final_newline)
    assert len(over) < P.MOUNTINFO_CAP
    with pytest.raises(P.HostReadError) as caught:
        P.parse_mountinfo(over)
    assert caught.value.kind == "oversize"
    host = FakeHost()
    host.files["/proc/self/mountinfo"] = over
    _, report, _, _ = _collect(host)
    assert "mountinfo:oversize" in report["incomplete_reasons"]


def test_line_bounds_are_enforced_on_bytes_before_decode():
    with pytest.raises(P.HostReadError) as caught:  # undecodable *and* too long: the bound wins, so no decode ran
        P._lines(b"\xff" * 4097, "utf-8", 10, 4096)
    assert caught.value.kind == "oversize"
    with pytest.raises(P.HostReadError) as caught:
        P._lines(b"\xff" * 4096, "utf-8", 10, 4096)
    assert caught.value.kind == "malformed"
    assert P._lines(b"a" * 4096, max_line=4096) == ["a" * 4096]
    with pytest.raises(P.PreflightError, match="lines_input_type"):
        P._lines(bytearray(b"a\n"))


@pytest.mark.parametrize("data, expected", [
    (b"", []), (b"\n", [""]), (b"a", ["a"]), (b"a\n", ["a"]), (b"a\nb", ["a", "b"]), (b"a\n\nb\n", ["a", "", "b"]),
    (b"a\r\nb\r\n", ["a\r", "b\r"]), (b"\n\n", ["", ""]),
])
def test_record_semantics_for_lf_crlf_empty_and_final_newline_are_explicit(data, expected):
    assert P._lines(data) == expected
    assert len(expected) <= 2 or P._lines(data, max_lines=len(expected)) == expected
    if expected:
        with pytest.raises(P.HostReadError):
            P._lines(data, max_lines=len(expected) - 1)


def test_cr_is_content_and_each_strict_grammar_handles_it_explicitly():
    # mountinfo: a CR inside a path is a path byte (mangle_path does not escape it). R4: a CR before LF
    # lands in the super options, whose leading access token the kernel always ends with "," or the line.
    entries = P.parse_mountinfo(b"1 0 8:1 / / rw - ext4 a rw\n2 1 0:2 / /run\r rw - tmpfs t rw\n")
    assert P.resolve_visible_entry(entries, "/run")["mount_point"] == "/"  # "/run\r" is not "/run"
    with pytest.raises(P.HostReadError):
        P.parse_mountinfo(b"1 0 8:1 / / rw - ext4 a rw\r\n")
    with pytest.raises(P.HostReadError):  # a numeric field with CR is malformed, never coerced
        P.parse_group_file(b"docker:x:118\r\n", P.PRIVILEGED_GROUPS)
    assert P.parse_passwd_file(b"heel-image-proof:x:1:1::/:/usr/sbin/nologin\r\n", "heel-image-proof")[2].endswith("\r")


class _CountedDict(dict):
    iterations = 0

    def __iter__(self):
        for key in super().__iter__():
            type(self).iterations += 1
            yield key


def test_reviewer_instrumented_oversized_dict_is_refused_before_any_key_enumeration():
    value = _CountedDict({str(i): None for i in range(4096)})
    with pytest.raises(P.PreflightError, match="schema_dict"):
        P.validate_output(value)
    assert _CountedDict.iterations == 0
    small = _CountedDict({"schema": P.SCHEMA})
    with pytest.raises(P.PreflightError, match="schema_dict"):
        P.validate_output(small, P.REPORT_SPEC)
    with pytest.raises(P.PreflightError, match="schema_list"):
        P.S_list(P.U, 4)(type("L", (list,), {})(["denied"]), P._Ctx(), 0, 0)


def test_native_oversized_dict_is_refused_by_cardinality_before_copy_or_set_building(monkeypatch):
    report, commands = P.collect(FakeHost())
    report.update({f"x{i}": None for i in range(4096)})
    monkeypatch.setattr(P, "frozenset", lambda *a: pytest.fail("set built during schema check"), raising=False)
    monkeypatch.setattr(P, "sorted", lambda *a, **k: pytest.fail("keys sorted before admission"), raising=False)
    ctx = P._Ctx()
    with pytest.raises(P.PreflightError, match="schema_fields"):
        P.REPORT_SPEC({str(i): None for i in range(4096)}, ctx, 0, 0)
    assert ctx.nodes == 1  # the refused node was admitted and counted, nothing more
    monkeypatch.setattr(P, "_commands_document", lambda *a: pytest.fail("payload built before admission"))
    with pytest.raises(P.PreflightError, match="schema_fields"):
        P._payloads(report, commands)
    source = P.inspect.getsource(P._payloads) if hasattr(P, "inspect") else Path(P.__file__).read_text()
    body = source[source.index("def _payloads"):]
    assert body.index("validate_output(report)") < body.index("dict(report)")


def test_schema_exact_types_refuse_subclasses_of_scalars():
    class S(str):
        pass

    class I(int):
        pass
    report, _ = P.collect(FakeHost())
    for path, value in ((("kernel", "release"), S("6.11.0")), (("cpu", "online"), I(4)),
                        (("source", "worktree_clean"), 1)):
        mutated, _ = P.collect(FakeHost())
        _set(mutated, path, value)
        with pytest.raises(P.PreflightError):
            P.validate_output(mutated)
    P.validate_output(report)


def test_group_member_and_mount_option_counts_are_bounded_before_split():
    with pytest.raises(P.HostReadError) as caught:  # the member count is bounded by the line byte bound
        P.parse_group_file(b"docker:x:118:" + b"a," * 32768 + b"\n", P.PRIVILEGED_GROUPS)
    assert caught.value.kind == "oversize"
    widest = b"docker:x:118:" + b",".join([b"a"] * ((P.MAX_LINE_BYTES - 13 + 1) // 2)) + b"\n"
    assert len(widest) - 1 <= P.MAX_LINE_BYTES
    assert P.parse_group_file(widest, P.PRIVILEGED_GROUPS)["docker"][1] == frozenset({"a"})
    # R4: components are unique valid tokens, so the bound is exercised with distinct future tokens.
    components = [b"rw"] + [b"f%d" % i for i in range(64)]
    with pytest.raises(P.HostReadError):
        P.parse_mountinfo(b"1 0 8:1 / / " + b",".join(components[:65]) + b" - ext4 a rw\n")
    entry = P.parse_mountinfo(b"1 0 8:1 / / " + b",".join(components[:64]) + b" - ext4 a rw\n")[1]
    assert entry["fstype"] == "ext4" and len(entry["options"]) == 64 and entry["options_state"] == "unrecognized"


# ---- R3: every /proc/self/cgroup record is validated before anything is counted or derived -------------
# Grammar: Linux v6.8 kernel/cgroup/cgroup.c proc_cgroup_show and cgroup-v1.c (see the module constants).

_SVC = b"0::/system.slice/hosted-compute-agent.service\n"
_SELF_SHAPE = ("v1_entries", "depth", "path_class", "leaf_suffix", "path_sha256")
CGROUP_UNKNOWN_CASES = [
    # Third review F1 witness: a valid v2 record plus a record with no fields.
    (_SVC + f"NOT-A-CGROUP-RECORD-{CANARY}\n".encode(), "malformed"),
    (b"0::/system.slice//hosted-compute-agent.service\n", "malformed"),
    (b"0::/system.slice/hosted-compute-agent.service/\n", "malformed"),
    (b"0::/system.slice/./x\n", "malformed"),
    (b"7:cpu:/\n\n" + _SVC, "malformed"),
    (_SVC + b"7:cpu\n", "malformed"),
    (_SVC + b"7::/\n", "malformed"),
    (b"0:cpu:/system.slice/hosted-compute-agent.service\n", "malformed"),
    (b"7:cpu:/\n7:memory:/\n" + _SVC, "malformed"),
    (_SVC + _SVC, "malformed"),
    (b"7:cpu:/\n8:cpu,cpuacct:/\n" + _SVC, "malformed"),
    (b"7:cpu,cpu:/\n" + _SVC, "malformed"),
    (b"7:name=systemd:/\n8:name=systemd:/\n" + _SVC, "malformed"),
    (b"07:cpu:/\n" + _SVC, "malformed"),
    (b"-7:cpu:/\n" + _SVC, "malformed"),
    (b":cpu:/\n" + _SVC, "malformed"),
    (b"2147483648:cpu:/\n" + _SVC, "malformed"),
    (b"12345678901:cpu:/\n" + _SVC, "malformed"),
    (b"7:cpu:legacy\n" + _SVC, "malformed"),
    (b"7:cpu:\n" + _SVC, "malformed"),
    (b"7:name=:/\n" + _SVC, "malformed"),
    (b"7:name=a,name=b:/\n" + _SVC, "malformed"),
    (b"7:name=a,cpu:/\n" + _SVC, "malformed"),
    (b"7:name=a/b:/\n" + _SVC, "malformed"),
    (b"7:name=" + b"n" * 64 + b":/\n" + _SVC, "malformed"),
    (b"7:cpu,,memory:/\n" + _SVC, "malformed"),
    (b"7:CPU:/\n" + _SVC, "malformed"),
    (b"0::/system.slice/hosted-compute-agent.service (deleted)\n", "unrecognized"),
    (f"0::/../{CANARY}\n".encode(), "unrecognized"),
    (b"7:frobnicate:/\n" + _SVC, "unrecognized"),
    (b"0::/system.slice/a b\n", "unrecognized"),
    (b"7:cpu,cpuacct:/legacy\n3:name=systemd:/x\n", "unsupported"),
    (b"", "unsupported"),
    (b"0::/" + b"a" * 509 + b"/bbb\n", "oversize"),
    (b"0::" + b"/a" * 17 + b"\n", "oversize"),
    (b"7:cpu:" + b"/a" * 1024 + b"\n" + _SVC, "oversize"),
    (b"7:" + b",".join([b"cpu"] * 17) + b":/\n" + _SVC, "oversize"),
    (b"7:" + b"c" * 513 + b":/\n" + _SVC, "oversize"),
    # Mixed severities: the most severe class wins, never a silent partial count.
    (b"7:frobnicate:/\nGARBAGE\n" + _SVC, "malformed"),
    (b"0::" + b"/a" * 17 + b"\n7:cpu\n", "malformed"),
]


@pytest.mark.parametrize("data, kind", CGROUP_UNKNOWN_CASES)
def test_reviewer_every_self_cgroup_record_is_validated_before_counting(data, kind, tmp_path):
    host = _ideal_host()
    host.files["/proc/self/cgroup"] = data
    _, report, _, text = _collect(host)
    me = report["cgroup"]["self"]
    assert me["state"] == kind and f"self_cgroup:{kind}" in report["incomplete_reasons"]
    assert all(me[key] is None for key in _SELF_SHAPE)
    assert report["observation"] == "incomplete" and "self_cgroup_kill_absent" not in report["prerequisite_gaps"]
    assert CANARY not in text and report["runtime_qualified"] is False and report["verdict"] == "UNPROVEN"
    assert P.main([], host=host, output_root=tmp_path) == P.EXIT_INCOMPLETE
    assert all(CANARY.encode() not in (tmp_path / P.OUTPUT_DIR_NAME / name).read_bytes() for name in P.ARTIFACT_FILES)


@pytest.mark.parametrize("data, v1_entries, depth, path_class", [
    (_SVC, 0, 2, "system.slice"),
    (b"12:cpu,cpuacct:/legacy\n3:name=systemd:/x\n1:blkio:/\n" + _SVC, 3, 2, "system.slice"),
    (b"1:name=" + b"n" * 63 + b":/\n" + _SVC, 1, 2, "system.slice"),
    (b"2147483647:cpuset,cpu,cpuacct,blkio,memory,devices,freezer,net_cls,perf_event,net_prio,hugetlb,pids,rdma,"
     b"misc,debug,name=all:/\n" + _SVC, 1, 2, "system.slice"),
    (b"0::/\n", 0, 0, "root"),
    (b"0::/system.slice/a:b.scope\n", 0, 2, "system.slice"),
    (b"0::" + b"".join([b"/" + b"c" * 31] * 16) + b"\n", 0, 16, "other"),
    (b"7:cpu:/\n" + _SVC.rstrip(b"\n"), 1, 2, "system.slice"),  # final record without LF
])
def test_valid_v2_and_mixed_v1_v2_records_remain_complete_positive_controls(data, v1_entries, depth, path_class,
                                                                              tmp_path):
    host = _ideal_host()
    host.files["/proc/self/cgroup"] = data
    path = data.split(b"\n")[-2 if data.endswith(b"\n") else -1].split(b":", 2)[2].decode()
    leaf = "" if path == "/" else path
    host.stats[f"/sys/fs/cgroup{leaf}/cgroup.kill"] = FakeStat(stat.S_IFREG | 0o200)
    host.files[f"/sys/fs/cgroup{leaf}/cgroup.controllers"] = b"cpu memory pids\n"
    host.files[f"/sys/fs/cgroup{leaf}/cgroup.subtree_control"] = b"\n"
    _, report, _, _ = _collect(host)
    me = report["cgroup"]["self"]
    assert me["state"] == "observed" and me["v1_entries"] == v1_entries and me["depth"] == depth
    assert me["path_class"] == path_class and me["path_sha256"] == hashlib.sha256(path.encode()).hexdigest()
    assert report["observation"] == "complete", report["incomplete_reasons"]
    assert P.main([], host=host, output_root=tmp_path) == P.EXIT_COMPLETE


def test_cgroup_record_parser_refuses_non_native_records_before_calling_their_methods():
    calls = []

    class Record(str):
        def find(self, *a):
            calls.append("find")
            return str.find(self, *a)

        def count(self, *a):
            calls.append("count")
            return str.count(self, *a)

        def split(self, *a):
            calls.append("split")
            return str.split(self, *a)
    with pytest.raises(P.PreflightError, match="cgroup_records_type"):
        P._parse_self_cgroup([Record("0::/a")])
    with pytest.raises(P.PreflightError, match="cgroup_records_type"):
        P._parse_self_cgroup(("0::/a",))
    with pytest.raises(P.PreflightError, match="controllers_input_type"):
        P._controllers(bytearray(b"cpu\n"))
    assert calls == []
    assert P._parse_self_cgroup(["0::/a"]) == (None, 0, ("a",))


def _largest_local_container(fn, *codes):
    """Trace the named code objects and return the largest list/tuple/set/dict any local ever held."""
    seen = [0]

    def local(frame, event, arg):
        for value in frame.f_locals.values():
            if type(value) in (list, tuple, set, dict):
                seen[0] = max(seen[0], len(value))
        return local

    sys.settrace(lambda frame, event, arg: local if frame.f_code in codes else None)
    try:
        result = fn()
    finally:
        sys.settrace(None)
    return seen[0], result


def _cgroup_codes():
    return (P._parse_self_cgroup.__code__, P._cgroup_path.__code__, P._cgroup_controllers.__code__)


@pytest.mark.parametrize("record, kind", [
    ("0::" + "/a" * 1024, "oversize"),                      # third review F2: 1024 components, 2051 chars
    ("0::" + "/a" * 17, "oversize"),                        # 17 components inside the 512-character bound
    ("0::/" + "a" * 512, "oversize"),                       # 513 characters, one component
    ("7:" + ",".join(["cpu"] * 1000) + ":/", "oversize"),   # 1000 controller tokens
    ("7:" + ",".join(["cpu"] * 17) + ":/", "oversize"),     # one token above the bound
])
def test_reviewer_cgroup_path_and_controller_bounds_precede_split(record, kind):
    biggest, result = _largest_local_container(lambda: P._parse_self_cgroup([record]), *_cgroup_codes())
    assert result[0] == kind
    assert biggest <= 1  # only the one-record input list; no component or token list was ever built


def test_cgroup_bounds_admit_their_exact_maxima():
    assert P._cgroup_path("0::" + "/" + "a" * 127 + ("/" + "a" * 127) * 3, 3) == (None, ("a" * 127,) * 4)  # 512
    assert P._cgroup_path("0::" + "/a" * 16, 3) == (None, ("a",) * 16)
    assert P._cgroup_path("0::" + "/" + "a" * 512, 3)[0] == "oversize"
    tokens = ",".join(P.CGROUP_V1_SUBSYSTEMS) + ",name=x"
    assert len(tokens.split(",")) == P.CGROUP_CONTROLLER_TOKENS_MAX
    line = f"7:{tokens}:/"
    assert P._cgroup_controllers(line, 2, line.rindex(":"))[0] is None


def _peak_bytes(fn):
    import tracemalloc
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        try:
            fn()
        except (P.HostReadError, P.PreflightError):
            pass
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_reviewer_bounds_precede_split_even_for_temporaries():
    # Locals tracing cannot see an unnamed temporary list, so the order of work is also measured as peak
    # allocation, calibrated in the same test: the split alone exceeds the ceiling the parser stays under.
    ceiling = 24 * 1024
    tokens = b" ".join([b"cpu"] * 1024) + b"\n"
    assert _peak_bytes(lambda: tokens.split()) > ceiling
    assert _peak_bytes(lambda: P._controllers(tokens)) < ceiling
    record = "7:" + ",".join(["cpu"] * 1300) + ":/"
    assert _peak_bytes(lambda: record.split(",")) > ceiling
    assert _peak_bytes(lambda: P._parse_self_cgroup([record])) < ceiling
    path = "0::" + "/ab" * 1300
    assert _peak_bytes(lambda: path.split("/")) > ceiling
    assert _peak_bytes(lambda: P._parse_self_cgroup([path])) < ceiling


def test_reviewer_controller_file_token_bound_precedes_split():
    biggest, _ = _largest_local_container(
        lambda: pytest.raises(P.HostReadError, P._controllers, b" ".join([b"cpu"] * 1000) + b"\n"),
        P._controllers.__code__)
    assert biggest == 0
    assert P._controllers(b" ".join([b"cpu"] * 64) + b"\n") == ["cpu"]
    with pytest.raises(P.HostReadError, match="malformed"):
        P._controllers(b" ".join([b"cpu"] * 65) + b"\n")
    for value in (b"", b"\n", b"cpu memory pids\n", b"cpu\tmemory"):
        assert P._controllers(value) == sorted({t if t in P.CONTROLLERS else "other" for t in value.decode().split()})
    for value in (b"cpu,memory\n", b"Cpu\n", b"c" * 33 + b"\n", b"cpu\x1cmemory"):
        with pytest.raises(P.HostReadError, match="malformed"):
            P._controllers(value)


# ---- R3: schema dispatch admits type/cardinality before any user-defined operation ----------------------

class _EqMarker(str):
    calls = 0

    def __eq__(self, other):
        type(self).calls += 1
        return str.__eq__(self, other)
    __hash__ = str.__hash__


@pytest.mark.parametrize("value, refusal", [
    ({"schema": _EqMarker("x"), **{str(i): None for i in range(4096)}}, "schema_fields"),   # third review F2
    ({"schema": _EqMarker(P.SCHEMA + ".commands")}, "schema_fields"),
    ({"observation": _EqMarker("refused")}, "schema_fields"),
    ({_EqMarker("schema"): P.SCHEMA + ".commands"}, "schema_fields"),
    ({1: None}, "schema_fields"),
])
def test_reviewer_validator_dispatch_never_runs_user_defined_equality_before_admission(value, refusal):
    _EqMarker.calls = 0
    with pytest.raises(P.PreflightError) as caught:
        P.validate_output(value)
    assert str(caught.value) == refusal and _EqMarker.calls == 0


@pytest.mark.parametrize("value", [None, [], "report", 0, type("D", (dict,), {})(schema=P.SCHEMA)])
def test_validator_dispatch_refuses_non_native_dicts_first(value):
    with pytest.raises(P.PreflightError, match="schema_dict"):
        P.validate_output(value)


def test_validator_dispatch_cardinality_boundary_and_real_documents():
    report, commands = P.collect(FakeHost())
    at_bound = {f"k{i}": None for i in range(P._DISPATCH_MAX_FIELDS)}
    assert len(P.REPORT_FIELDS) == P._DISPATCH_MAX_FIELDS
    with pytest.raises(P.PreflightError, match="schema_fields"):
        P.validate_output(at_bound)  # admitted by dispatch, refused by the report spec on unknown keys
    with pytest.raises(P.PreflightError, match="schema_fields"):
        P.validate_output(dict(at_bound, extra=None))  # refused by dispatch cardinality
    P.validate_output(report)
    P.validate_output(P._commands_document(report, commands))
    # Order of work: an over-bound native dict is refused before its keys are visited at dispatch.
    source = Path(P.__file__).read_text(encoding="utf-8").splitlines()
    start = next(i for i, text in enumerate(source, 1) if text.startswith("def validate_output"))
    loop = next(i for i, text in enumerate(source[start:], start + 1) if text.strip() == "for key in value:")
    visits = [0]

    def tracer(frame, event, arg):
        if frame.f_code is P.validate_output.__code__:
            def local(frame, event, arg):
                visits[0] += event == "line" and frame.f_lineno == loop + 1
                return local
            return local
        return None
    sys.settrace(tracer)
    try:
        with pytest.raises(P.PreflightError, match="schema_fields"):
            P.validate_output({str(i): None for i in range(4096)})
        assert visits[0] == 0
        with pytest.raises(P.PreflightError, match="schema_fields"):
            P.validate_output(at_bound)
        assert visits[0] == P._DISPATCH_MAX_FIELDS  # at the bound every key is type-checked once
    finally:
        sys.settrace(None)


def test_reviewer_collector_with_the_real_wrapper_reports_enodata_as_ambiguous_and_exits_3(tmp_path):
    host = _ideal_host()
    host.has_capability_xattr = lambda path, budget: P.RealHost(P.ROOT).has_capability_xattr(path, budget)
    with mock.patch.object(P.os, "getxattr", side_effect=OSError(errno.ENODATA, "synthetic"), create=True):
        _, report, _, _ = _collect(host)
        assert P.main([], host=host, output_root=tmp_path) == P.EXIT_INCOMPLETE
    dockerd = report["binaries"]["tools"]["dockerd"]
    assert dockerd["state"] == "found_regular" and dockerd["file_capability"] == "ambiguous"
    assert {f"binary:{tool}:ambiguous" for tool in P.TOOLS} <= set(report["incomplete_reasons"])
    assert report["observation"] == "incomplete"
    assert not any(gap.startswith("tool_not_found") for gap in report["prerequisite_gaps"])
    forged = json.loads(json.dumps(report))
    forged["binaries"]["tools"]["dockerd"]["file_capability"] = False
    with pytest.raises(P.PreflightError, match="schema_union"):
        P.validate_output(forged)


# ---- R3: distinguishing tests for the two R2 survivors (absolute pre-work contract) --------------------

def test_env_values_over_the_length_bound_never_reach_a_pattern(monkeypatch):
    calls = []

    class Pattern:
        def __init__(self, compiled):
            self.compiled = compiled

        def fullmatch(self, value):
            calls.append(len(value))
            return self.compiled.fullmatch(value)
    for name in list(P.ENV_PATTERNS):
        monkeypatch.setitem(P.ENV_PATTERNS, name, Pattern(P.ENV_PATTERNS[name]))
    host = FakeHost()
    host.environ["RUNNER_OS"] = "L" * (P.ENV_VALUE_MAX + 1)
    host.environ["GITHUB_RUN_ID"] = "9" * 100000
    host.environ["ImageOS"] = "u" * P.ENV_VALUE_MAX  # exactly at the bound: matched, then rejected by grammar
    _, report, _, _ = _collect(host)
    assert report["runner"]["runner_os"] == report["runner"]["run_id"] == report["runner"]["image_os"] == "malformed"
    assert max(calls) == P.ENV_VALUE_MAX and (P.ENV_VALUE_MAX + 1) not in calls and 100000 not in calls


def test_oversized_native_dict_visits_no_key_before_cardinality_refusal():
    check = P.REPORT_SPEC
    source = Path(P.__file__).read_text(encoding="utf-8").splitlines()
    loop_line = next(i for i, text in enumerate(source, 1) if "for key in value:  # at most len(allowed)" in text)
    visits = [0]

    def tracer(frame, event, arg):
        if frame.f_code is check.__code__:
            def local(frame, event, arg):
                if event == "line" and frame.f_lineno == loop_line + 1:
                    visits[0] += 1
                return local
            return local
        return None

    def run(value):
        visits[0] = 0
        sys.settrace(tracer)
        try:
            with pytest.raises(P.PreflightError, match="schema_fields"):
                check(value, P._Ctx(), 0, 0)
        finally:
            sys.settrace(None)
        return visits[0]
    width = len(P.REPORT_FIELDS) - 1  # REPORT_SPEC excludes "refusal"
    assert run({f"k{i}": None for i in range(width + 1)}) == 0   # over the bound: no key is visited
    assert run({f"k{i}": None for i in range(width)}) == 1       # at the bound: first unknown key refused


def test_mountinfo_and_account_field_counts_are_bounded_before_split():
    codes = (P.parse_mountinfo.__code__, P.parse_group_file.__code__, P.parse_passwd_file.__code__)
    wide = b"1 0 8:1 / / rw" + b" x" * 2000 + b" - ext4 a rw\n"
    biggest, _ = _largest_local_container(lambda: pytest.raises(P.HostReadError, P.parse_mountinfo, wide), *codes)
    assert biggest <= 1
    at_limit = b"1 0 8:1 / / rw " + b" ".join([b"shared:1"] + [b"future_tag"] * 53) + b" - ext4 a rw\n"
    assert at_limit.count(b" ") == P.MOUNTINFO_MAX_FIELDS - 1
    assert P.parse_mountinfo(at_limit)[1]["fstype"] == "ext4"
    with pytest.raises(P.HostReadError, match="malformed"):
        P.parse_mountinfo(at_limit.replace(b" - ext4", b" future_tag - ext4"))
    for parse, line in ((lambda d: P.parse_group_file(d, ("docker",)), b"docker:x:118:" + b":" * 3000 + b"\n"),
                        (lambda d: P.parse_passwd_file(d, "runner"), b"runner" + b":x" * 2000 + b"\n")):
        biggest, _ = _largest_local_container(lambda: pytest.raises(P.HostReadError, parse, line), *codes)
        assert biggest <= 1
    host = _ideal_host()
    host.files["/etc/subuid"] = b"heel-image-proof" + b":1" * 100 + b"\n"
    biggest, (_, report, _, _) = _largest_local_container(lambda: _collect(host), P._Collector._ranges.__code__)
    # The frame's own small result dict is a local; a split would add a 101-element list.
    assert report["proposed_identity"]["subuid"]["state"] == "malformed" and biggest < 50


# ---- Workflow and documentation contracts ----------------------------------------------------------

def test_workflow_is_a_read_only_pull_request_capture_with_fresh_output_binding():
    text = WORKFLOW.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    on_block = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    assert on_block.strip().splitlines()[0].strip() == "pull_request:"
    for forbidden in ("pull_request_target", "workflow_dispatch", "schedule", "push:", "workflow_run",
                      "repository_dispatch", "secrets.", "environment:", "apt-get", "apt install", "pip ", "npm", "setup-python",
                      "docker", "sudo", "cache", "write", "id-token", "self-hosted", "continue-on-error", "rm ",
                      "overwrite"):
        assert forbidden not in text.replace("contents: read", ""), forbidden
    paths = re.findall(r"^\s{6}- '([^']+)'$", on_block, re.M)
    assert paths == ["scripts/control_plane_boundary_preflight.py", "tests/test_control_plane_boundary_preflight.py",
                     ".github/workflows/control-plane-boundary-preflight.yml",
                     "docs/saas/CONTROL_PLANE_BOUNDARY_PREFLIGHT.md"]
    assert "github.head_ref == 'codex/control-plane-boundary-preflight'" in text
    assert "github.event.pull_request.head.repo.full_name == github.repository" in text
    uses = [line.strip() for line in lines if "uses:" in line]
    assert uses == ["- uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6",
                    "uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7"]
    assert text.count("persist-credentials: false") == 1
    assert "ref: ${{ github.event.pull_request.head.sha }}" in text
    assert text.count("runs-on: ubuntu-24.04") == 1
    minutes = [int(value) for value in re.findall(r"timeout-minutes: (\d+)", text)]
    assert minutes == [5, 3]
    assert "permissions:\n  contents: read" in text and text.count("contents: read") == 2
    assert "/usr/bin/python3 -I -B scripts/control_plane_boundary_preflight.py || rc=$?" in text
    assert 'echo "collector_exit=$rc" >> "$GITHUB_OUTPUT"' in text and 'exit "$rc"' in text
    assert "test ! -e control-plane-boundary-preflight" in text and "test ! -L control-plane-boundary-preflight" in text
    assert text.index("test ! -e control-plane-boundary-preflight") < text.index("scripts/control_plane_boundary_preflight.py ||")
    assert "name: control-plane-boundary-preflight-${{ github.run_id }}-${{ github.run_attempt }}" in text
    assert "if: always()\n" not in text
    artifact_paths = re.findall(r"^\s+control-plane-boundary-preflight/([a-z.]+)$", text, re.M)
    assert tuple(artifact_paths) == P.ARTIFACT_FILES
    assert "retention-days: 3" in text and "if-no-files-found: error" in text


def test_ordinary_ci_and_codeql_do_not_run_the_preflight():
    for name in ("ci.yml", "codeql.yml", "publish.yml", "scorecard.yml", "claude-review.yml"):
        assert "control_plane_boundary_preflight" not in (ROOT / ".github" / "workflows" / name).read_text()


def test_documentation_states_the_limits_and_exit_contract():
    text = DOC.read_text(encoding="utf-8")
    for phrase in ("runtime_qualified", "always `false`", "UNPROVEN", "not runtime qualification",
                   "NO-GO", "B0 source remains FAIL", "exit 0", "complete observation", "heel-image-proof",
                   "never executes Docker", "sudo -n -l", "Next decision inputs", "not observed",
                   "selected-path inventory", "local files only", "cooperative", "collector_exit",
                   "closed schema", "Every delivered byte", "every record validated first",
                   "never read as\n  absence", "There is no `false` value",
                   "Mount records: every consumed field validated first", "exactly one access mode",
                   "`mount_options:<target>:unrecognized`", "proof that the kernel produced it"):
        assert phrase in text, phrase
    for retracted in ("never success", "equivalent of `findmnt --target`", "does not make the\n  observation incomplete",
                      "INFERRED to mean absence"):
        assert retracted not in text, retracted
    for code in (P.EXIT_COMPLETE, P.EXIT_INTERNAL, P.EXIT_REFUSED, P.EXIT_INCOMPLETE):
        assert f"| {code} |" in text


# ---- R4: every consumed mountinfo field is validated before any mount fact is derived -----------------
# Grammar: Linux v6.8 fs/proc_namespace.c show_mountinfo/show_mnt_opts/show_type, fs/namespace.c show_path/
# mnt_alloc_id/do_new_mount, fs/seq_file.c mangle_path, include/linux/kdev_t.h (see the module constants).

_ROOT_LINE = "22 1 8:1 / / rw,relatime shared:1 - ext4 "  # prefix of the ideal root mount (resolves /home/runner/work)

# Fourth independent review witnesses: each was complete/exit 0 on 5b6c80eb.
REVIEW_MOUNT_WITNESSES = [
    ("empty_options", b"/ / rw,relatime", b"/ / "),
    ("ro_and_rw", b"/ / rw,relatime", b"/ / ro,rw,relatime"),
    ("empty_option_component", b"/ / rw,relatime", b"/ / rw,,relatime"),
    ("extra_post_separator_field", b" - tmpfs tmpfs rw,size=1634000k,mode=755",
     b" - tmpfs tmpfs rw,size=1634000k,mode=755 NOT-A-MOUNTINFO-FIELD"),
    ("empty_fstype", b" - tmpfs tmpfs ", b" -  tmpfs "),
    ("relative_root", b"8:1 / / ", b"8:1 relative / "),
]


@pytest.mark.parametrize("name, old, new", REVIEW_MOUNT_WITNESSES, ids=[w[0] for w in REVIEW_MOUNT_WITNESSES])
def test_reviewer_malformed_mount_records_are_incomplete_partial_data_and_exit_3(name, old, new, tmp_path):
    def host():
        h = FakeHost()
        assert old in h.files["/proc/self/mountinfo"]
        h.files["/proc/self/mountinfo"] = h.files["/proc/self/mountinfo"].replace(old, new)
        return h
    _, report, _, text = _collect(host())
    assert "mountinfo:malformed" in report["incomplete_reasons"] and report["observation"] == "incomplete"
    for target in P.FILESYSTEM_TARGETS:
        item = report["filesystems"][target]
        assert item["mount_state"] == "unavailable"
        assert all(item[key] is None for key in ("fstype", "propagation", *P.MOUNT_FLAGS))
        assert item["exists"] is True and item["space_state"] == "observed"  # independent facts are kept
    assert report["cgroup"]["mount_state"] == "unavailable"
    assert report["runtime_qualified"] is False and report["verdict"] == "UNPROVEN" and CANARY not in text
    assert P.main([], host=host(), output_root=tmp_path) == P.EXIT_INCOMPLETE
    written = json.loads((tmp_path / P.OUTPUT_DIR_NAME / "report.json").read_text())
    assert written["observation"] == "incomplete" and written["runtime_qualified"] is False


_BASE_RECORD = ("1", "0", "8:1", "/", "/", "rw", "-", "ext4", "src", "rw")


def _record(**replace):
    """One root mount record built from named fields; a value of None drops the field."""
    names = ("id", "parent", "dev", "root", "point", "options", "sep", "fstype", "source", "super")
    fields = dict(zip(names, _BASE_RECORD))
    fields.update(replace)
    return (" ".join(value for value in fields.values() if value is not None) + "\n").encode()


MALFORMED_MOUNT_FIELDS = [
    # mount and parent IDs: canonical decimal ints, 0..2**31-1
    dict(id=""), dict(id="01"), dict(id="-1"), dict(id="+1"), dict(id="2147483648"), dict(id="1a"),
    dict(parent=""), dict(parent="00"), dict(parent="2147483648"),
    # device: canonical MAJOR:MINOR within the 12/20-bit split
    dict(dev="8"), dict(dev="8:"), dict(dev=":1"), dict(dev="08:1"), dict(dev="8:01"), dict(dev="4096:0"),
    dict(dev="0:1048576"), dict(dev="8:1:2"), dict(dev="8-1"),
    # root: absolute, well-formed escapes, no NUL
    dict(root=""), dict(root="relative"), dict(root="/a\\"), dict(root="/a\\08"), dict(root="/a\\400"),
    dict(root="/a\\000"), dict(root="/a\x00b"), dict(root="/a\\\\134"),
    # mount point: canonical absolute after decoding only the kernel's escape set
    dict(point=""), dict(point="relative"), dict(point="/a/"), dict(point="/a//b"), dict(point="/a/./b"),
    dict(point="/a/../b"), dict(point="/a\\101"), dict(point="/a\\"), dict(point="/a\\000"), dict(point="/a\\043"),
    # per-mount options: exactly one leading access mode, non-empty unique tokens, kernel order
    dict(options=""), dict(options="ro,rw"), dict(options="rw,ro"), dict(options="nosuid"), dict(options="rw,"),
    dict(options=",rw"), dict(options="rw,,nosuid"), dict(options="RW"), dict(options="rw,nosuid,nosuid"),
    dict(options="rw,relatime,nosuid"), dict(options="rw,noexec,nodev"), dict(options="rw,size=1"),
    dict(options="rw,NOSUID"), dict(options="rw,nosuid,ro"), dict(options="rw,future,future"),
    dict(options="rw,9tag"), dict(options="rw," + "a" * 33),
    # separator and the three post-separator fields
    dict(sep=None), dict(sep="--"), dict(super=None), dict(source=None, super=None), dict(super="rw extra"),
    dict(fstype=""), dict(fstype="ext\\"), dict(fstype="a\\101"), dict(fstype="a\\000"),
    dict(super=""), dict(super="x"), dict(super="rwx"), dict(super="RO"), dict(super=",rw"), dict(super="rw\r"),
]


@pytest.mark.parametrize("change", MALFORMED_MOUNT_FIELDS, ids=lambda c: repr(c))
def test_every_consumed_mount_field_is_validated_before_derivation(change):
    assert P.parse_mountinfo(_record())[1]["access"] == "rw"  # positive control for the same template
    with pytest.raises(P.HostReadError) as caught:
        P.parse_mountinfo(_record(**change))
    assert caught.value.kind == "malformed"


def test_empty_records_and_unframed_lines_are_malformed_not_skipped():
    for data in (_record() + b"\n" + _record(id="2", parent="1", point="/run"), b"\n", _record()[:-1] + b"\r\n",
                 _record(super="rw,discard")[:-1] + b"\r\n"):
        with pytest.raises(P.HostReadError) as caught:
            P.parse_mountinfo(data)
        assert caught.value.kind == "malformed"


@pytest.mark.parametrize("change, check", [
    (dict(id="0", parent="0"), lambda e: e[0]["parent"] == 0),
    (dict(id="2147483647", parent="2147483647"), lambda e: 2147483647 in e),
    (dict(dev="4095:1048575"), lambda e: e[1]["fstype"] == "ext4"),
    (dict(dev="0:0"), lambda e: e[1]["fstype"] == "ext4"),
    (dict(root="/a//deleted"), lambda e: e[1]["root"] == "/a//deleted"),          # dentry_path of an unlinked root
    (dict(root="/a\\040b\\134c"), lambda e: e[1]["root"] == "/a b\\c"),
    (dict(point="/a\\040b\\011c\\012d\\134e"), lambda e: e[1]["mount_point"] == "/a b\tc\nd\\e"),
    (dict(point="/a\rb"), lambda e: e[1]["mount_point"] == "/a\rb"),               # raw CR is a path byte
    (dict(options="ro,nosuid,nodev,noexec,noatime,nodiratime,relatime,nosymfollow,idmapped"),
     lambda e: e[1]["access"] == "ro" and e[1]["options_state"] == "observed"
     and {"nosuid", "nodev", "noexec"} <= e[1]["options"]),
    (dict(options="rw,nosuid,future_opt,relatime"),
     lambda e: e[1]["access"] == "rw" and e[1]["options_state"] == "unrecognized"),
    (dict(source=""), lambda e: e[1]["fstype"] == "ext4"),                          # empty devname: do_new_mount
    (dict(source="-"), lambda e: e[1]["fstype"] == "ext4"),
    (dict(fstype="fuse.sshfs"), lambda e: e[1]["fstype"] == "fuse.sshfs"),
    (dict(fstype="fuse.a\\040b\\043c"), lambda e: e[1]["fstype"] == "fuse.a b#c"),
    (dict(super="ro"), lambda e: e[1]["fstype"] == "ext4"),
    (dict(super="rw,opaque=a\\040b,x"), lambda e: e[1]["fstype"] == "ext4"),
])
def test_valid_mount_records_at_each_field_boundary_are_admitted(change, check):
    entries = P.parse_mountinfo(_record(**change))
    assert check(entries)


def test_access_mode_comes_from_the_single_leading_token():
    host = FakeHost()
    host.files["/proc/self/mountinfo"] = host.files["/proc/self/mountinfo"].replace(
        b"/ / rw,relatime", b"/ / ro,nosuid,relatime")
    _, report, _, _ = _collect(host)
    work = report["filesystems"]["/home/runner/work"]
    assert (work["ro"], work["rw"], work["nosuid"], work["nodev"], work["noexec"]) == (True, False, True, False, False)
    assert report["observation"] == "complete"


def test_unknown_well_formed_option_keeps_access_mode_and_other_facts_but_not_option_flags(tmp_path):
    def host(old, new):
        h = FakeHost()
        assert old in h.files["/proc/self/mountinfo"]
        h.files["/proc/self/mountinfo"] = h.files["/proc/self/mountinfo"].replace(old, new)
        return h
    token = f"future_{CANARY.lower()}".encode()
    h = host(b"/run rw,nosuid,nodev,noexec,relatime", b"/run rw,nosuid,nodev,noexec,relatime," + token)
    _, report, _, text = _collect(h)
    run = report["filesystems"]["/run"]
    assert run["mount_state"] == "resolved" and run["fstype"] == "tmpfs" and run["propagation"] == "shared"
    assert (run["ro"], run["rw"]) == (False, True)
    assert all(run[flag] == "unrecognized" for flag in P.OPTION_FLAGS)
    assert report["incomplete_reasons"] == ["mount_options:/run:unrecognized"]
    assert CANARY.lower() not in text and report["filesystems"]["/home/runner/work"]["nosuid"] is False
    assert P.main([], host=h, output_root=tmp_path) == P.EXIT_INCOMPLETE
    # The same token on a mount that is not resolved for any target changes nothing.
    _, report, _, _ = _collect(host(b"/mnt rw,relatime", b"/mnt rw,relatime,future_opt"))
    assert report["observation"] == "complete" and report["incomplete_reasons"] == []


def test_output_contract_refuses_a_resolved_mount_without_exactly_one_access_mode():
    _, report, _, _ = _collect(FakeHost())
    reasons = report["incomplete_reasons"]
    assert P._fact_contract_violations(report, reasons) == []
    for ro, rw in ((True, True), (False, False)):
        broken = copy.deepcopy(report)
        broken["filesystems"]["/run"].update(ro=ro, rw=rw)
        assert "filesystems./run:access_mode_not_exactly_one" in P._fact_contract_violations(broken, reasons)
    unresolved = copy.deepcopy(report)
    unresolved["filesystems"]["/run"].update(mount_state="unavailable", ro=None, rw=None, mount_point=None,
                                             mount_point_is_target=None, fstype=None, propagation=None,
                                             nosuid=None, nodev=None, noexec=None)
    assert P._fact_contract_violations(unresolved, ["mount:/run:unavailable"]) == []
    unknown = copy.deepcopy(report)
    unknown["filesystems"]["/run"]["nosuid"] = "unrecognized"
    assert "filesystems./run.nosuid:unknown_without_reason" in P._fact_contract_violations(unknown, reasons)
    assert P._fact_contract_violations(unknown, ["mount_options:/run:unrecognized"]) == []


def test_schema_admits_unknown_only_for_option_flags_not_the_access_mode():
    _, report, _, _ = _collect(FakeHost())
    good = copy.deepcopy(report)
    good["filesystems"]["/run"]["nodev"] = "unrecognized"
    good["observation"], good["incomplete_reasons"], good["incomplete_reasons_total"] = (
        "incomplete", ["mount_options:/run:unrecognized"], 1)
    P.validate_output(good)
    for flag in P.ACCESS_FLAGS:
        bad = copy.deepcopy(good)
        bad["filesystems"]["/run"][flag] = "unrecognized"
        with pytest.raises(P.PreflightError):
            P.validate_output(bad)


def test_option_components_are_bounded_before_split():
    wide = b"1 0 8:1 / / rw" + b",a" * 2000 + b" - ext4 a rw\n"
    assert len(wide) - 1 <= 4096
    codes = (P.parse_mountinfo.__code__, P._mount_options.__code__)
    biggest, _ = _largest_local_container(lambda: pytest.raises(P.HostReadError, P.parse_mountinfo, wide), *codes)
    assert biggest <= 10  # the ten-field record list; never a 2001-component option list
    at_limit = b"1 0 8:1 / / rw," + b",".join(b"f%d" % i for i in range(63)) + b" - ext4 a rw\n"
    biggest, entries = _largest_local_container(lambda: P.parse_mountinfo(at_limit), *codes)
    assert len(entries[1]["options"]) == 64 and biggest <= 64
