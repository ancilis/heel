#!/usr/bin/env python3
"""Read-only Ubuntu 24.04 control-plane boundary prerequisite collector.

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Run from the repository root as exactly ``/usr/bin/python3 -I -B
scripts/control_plane_boundary_preflight.py`` with no arguments. It collects the finite read-only
observations listed in CONTROL-PLANE-BOUNDARY-FEASIBILITY/PROPOSED-SCOPE.md and writes two closed
files: ``control-plane-boundary-preflight/report.json`` and ``commands.json``.

It is a fact collector, not runtime qualification. Every report declares
``runtime_qualified=false`` and ``verdict=UNPROVEN``. It never executes or connects to Docker or
containerd, never installs anything, never changes an account, range, policy, cgroup, namespace,
mount or firewall, and never reads the general environment. The only executed programs are the
five fixed argv tuples in ``COMMANDS``. Their output is capped before parsing. Only closed enums,
numbers, approved version tokens and SHA-256 digests reach the report, and the report must match a
closed schema. Missing or denied facts are recorded as data and never become permission to act.

Observation-completion contract: every fact is either observed, determinately absent (a documented
``absent`` result such as ENOENT on a fixed path or a name not present in a fully parsed local
file), or unknown (denied, error, malformed, unrecognized, ambiguous, oversize, out of budget or
out of time). The report is ``complete`` only when no fact is unknown; every unknown value has an
``incomplete_reasons`` entry in its own area. Completion is checked structurally per required fact
(``_fact_contract_violations``), not by scanning for unknown tokens: a required fact that is null where
its controlling state says it was observed is a contract error, and observed free-grammar strings may
never equal an unknown token. Prerequisite gaps are derived only from observed or absent facts.

Exit codes: 0 complete observation; 3 incomplete observation; 2 refused (unsupported platform,
arguments or Python) before any host read; 1 internal error (for example an existing output
directory, or finalization after the cooperative deadline). Exit 0 does not mean any prerequisite
is met.
"""
from __future__ import annotations

import dataclasses
import errno
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "heel.control-plane-boundary-preflight.v3"
OUTPUT_DIR_NAME = "control-plane-boundary-preflight"
ARTIFACT_FILES = ("report.json", "commands.json")

EXIT_COMPLETE = 0
EXIT_INTERNAL = 1
EXIT_REFUSED = 2
EXIT_INCOMPLETE = 3

AGGREGATE_DEADLINE_S = 90.0
COMMAND_DEADLINE_S = 5.0
REAP_GRACE_S = 1.0
PIPE_GRACE_S = 0.5
COMMAND_STDOUT_CAP = 64 * 1024
COMMAND_STDERR_CAP = 8 * 1024
SMALL_READ_CAP = 64 * 1024
MOUNTINFO_CAP = 1024 * 1024
PROFILE_LIST_CAP = 1024 * 1024
ID_MAP_CAP = 1024 * 1024
ACCOUNT_FILE_CAP = 1024 * 1024
HASH_FILE_CAP = 256 * 1024 * 1024
READ_AGGREGATE_CAP = 1024 * 1024 * 1024
HASH_CHUNK = 1024 * 1024
SMALL_CHUNK = 64 * 1024
MAX_LINES = 65536
MAX_MOUNT_ENTRIES = 8192
MAX_LINE_BYTES = 65536
MAX_PROCESS_GROUPS = 65536
EMITTED_GROUPS = 64
# XATTR_SIZE_MAX (include/uapi/linux/limits.h). The kernel clamps getxattr to it and returns E2BIG above
# it (fs/xattr.c do_getxattr); CPython's os.getxattr only ever tries buffers of 128 and XATTR_SIZE_MAX
# bytes (Modules/posixmodule.c). os.getxattr cannot be given a smaller cap, so the collector admits it
# only when the remaining aggregate allowance covers this documented maximum (see has_capability_xattr).
XATTR_VALUE_BOUND = 65536
MOUNTINFO_MAX_FIELDS = 64  # 6 fixed + optional tags + "-" + 3; Linux v6.8 emits at most 14
MOUNT_GROUP_ID_MAX = 2 ** 31 - 1  # peer-group ids: ida_alloc_min(..., 1) int, printed with %i
# mountinfo record grammar, Linux v6.8 (fs/proc_namespace.c show_mountinfo, show_mnt_opts, show_type;
# fs/namespace.c mnt_alloc_id, show_path; fs/seq_file.c mangle_path; include/linux/kdev_t.h):
MOUNT_ID_MAX = 2 ** 31 - 1      # mount and parent ids: ida_alloc int printed with %i, never negative
DEV_MAJOR_MAX = 2 ** 12 - 1     # %u:%u of MAJOR(dev) = dev >> MINORBITS (20) of the 32-bit s_dev
DEV_MINOR_MAX = 2 ** 20 - 1     # MINOR(dev) = dev & MINORMASK
MOUNT_PATH_ESCAPES = " \t\n\\"  # seq_path_root / seq_dentry escape set for the root and mount point
MOUNT_TYPE_ESCAPES = " \t\n\\#"  # mangle() escape set for the filesystem type and subtype
MOUNT_ACCESS = ("ro", "rw")     # exactly one, always first: MNT_READONLY ? " ro" : " rw"
MOUNT_OPTION_ORDER = ("nosuid", "nodev", "noexec", "noatime", "nodiratime", "relatime", "nosymfollow",
                      "idmapped")  # show_mnt_opts emission order
MOUNT_OPTION_MAX = 64
ENV_VALUE_MAX = 64
REPORT_CAP = 64 * 1024
MAX_OUTPUT_NODES = 2048
MAX_REASONS = 128
FREE_FLOOR_BYTES = 5 * 1024 * 1024 * 1024
MIN_ID_RANGE = 65536
MIN_PYTHON = (3, 10)

PROPOSED_IDENTITY = "heel-image-proof"
PRIVILEGED_GROUPS = ("sudo", "admin", "wheel", "docker")
TOOLS = ("dockerd", "dockerd-rootless.sh", "rootlesskit", "newuidmap", "newgidmap", "slirp4netns",
         "systemd-run", "unshare", "mount", "findmnt")
TOOL_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")
TOOL_REAL_ROOTS = ("/usr/local/sbin/", "/usr/local/bin/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/", "/usr/libexec/",
                   "/usr/lib/")
APPARMOR_PROFILES = ("/etc/apparmor.d/rootlesskit", "/etc/apparmor.d/usr.bin.rootlesskit",
                     "/etc/apparmor.d/home.runner.bin.rootlesskit")
APPARMOR_ROOTLESSKIT_NAMES = ("rootlesskit", "/usr/bin/rootlesskit", "/usr/local/bin/rootlesskit")
APPARMOR_MODES = ("enforce", "complain", "unconfined", "kill", "prompt")
CGROUP_MOUNT = "/sys/fs/cgroup"
FILESYSTEM_TARGETS = ("/run", "/home/runner/work")
MOUNT_POINTS = ("/", "/run", "/home", "/home/runner", "/home/runner/work", "/mnt", "/tmp", CGROUP_MOUNT, "/sys")
SHARED_ENDPOINTS = ("/run/docker.sock", "/run/containerd/containerd.sock", "/var/lib/docker", "/var/lib/containerd")
FSTYPES = ("ext4", "xfs", "btrfs", "tmpfs", "overlay", "cgroup2", "cgroup", "vfat", "zfs", "nfs", "nfs4", "fuse",
           "fuseblk", "proc", "sysfs", "devtmpfs", "ramfs")
PROPAGATIONS = ("private", "shared", "slave", "shared_and_slave", "unbindable")
CONTROLLERS = ("cpuset", "cpu", "io", "memory", "hugetlb", "pids", "rdma", "misc")
REQUIRED_CONTROLLERS = ("cpu", "memory", "pids")
PID1_NAMES = ("systemd", "init", "tini", "docker-init", "dumb-init", "bash", "sh")
ACCESS_FLAGS = ("ro", "rw")
OPTION_FLAGS = ("nosuid", "nodev", "noexec")
MOUNT_FLAGS = ACCESS_FLAGS + OPTION_FLAGS
FILE_TYPES = ("socket", "directory", "regular", "symlink", "other")
LIMITS = (
    "installed_configuration_is_not_effective_isolation",
    "no_private_docker_lifecycle_or_hard_deadline_proof",
    "no_latency_reaping_or_cleanup_proof",
    "cooperative_deadline_synchronous_io_outer_bound_is_job_timeout",
    "leader_reaped_and_group_signalled_only_descendants_outside_group_not_observed",
    "tool_inventory_is_fixed_directories_not_path_resolution_or_capability",
    "accounts_and_groups_are_local_files_only_not_nss_or_effective_policy",
    "sudo_and_apparmor_are_recognized_listings_not_effective_policy",
    "absence_or_denial_is_data_not_authority",
    "facts_do_not_change_b0_source_fail_or_runtime_no_go",
)

ENV_ALLOWLIST = ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion",
                 "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
ENV_PATTERNS = {
    "RUNNER_OS": re.compile(r"(Linux|macOS|Windows)"),
    "RUNNER_ARCH": re.compile(r"(X64|ARM64|X86|ARM)"),
    "ImageOS": re.compile(r"[a-z0-9]{1,16}"),
    "ImageVersion": re.compile(r"[0-9]{8}\.[0-9]{1,6}(\.[0-9]{1,6})?"),
    "GITHUB_RUN_ID": re.compile(r"[0-9]{1,20}"),
    "GITHUB_RUN_ATTEMPT": re.compile(r"[0-9]{1,4}"),
}
RUNNER_FIELDS = (("RUNNER_OS", "runner_os"), ("RUNNER_ARCH", "runner_arch"), ("ImageOS", "image_os"),
                 ("ImageVersion", "image_version"), ("GITHUB_RUN_ID", "run_id"), ("GITHUB_RUN_ATTEMPT", "run_attempt"))

COMMANDS = {
    "systemctl_version": ("/usr/bin/systemctl", "--version", "--no-pager"),
    "systemd_manager_version": ("/usr/bin/systemctl", "show", "--property=Version", "--no-pager"),
    "sudo_list": ("/usr/bin/sudo", "-n", "-l"),
    "git_identity": ("/usr/bin/git", "rev-parse", "HEAD", "HEAD^{tree}"),
    "git_status": ("/usr/bin/git", "-c", "core.fsmonitor=false", "status", "--porcelain=v1", "--untracked-files=no"),
}
_BASE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}
_GIT_ENV = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0"}
_SYSTEMD_ENV = {"SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"}

VERSION_TOKEN = re.compile(r"[0-9][0-9A-Za-z.~+-]{0,63}")
KERNEL_RELEASE = re.compile(r"[0-9][0-9A-Za-z._+-]{0,63}")
HEX_OBJECT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
CGROUP_COMPONENT = re.compile(r"[A-Za-z0-9@:._\\-]{1,128}")
ACCOUNT_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\$?")
SAFE_STRING = re.compile(r"[\x20-\x7e]{0,160}")
# /proc/self/cgroup record grammar, from Linux v6.8 kernel/cgroup/cgroup.c proc_cgroup_show (pinned in the
# R3 evidence sources): "<hierarchy_id>:<controllers>:<path>\n" per visible hierarchy. The default (v2)
# hierarchy is id 0 with an empty controller field and is listed only while cgroup2 is visible; v1
# hierarchies have ids >= 1 (idr_alloc_cyclic) and a non-empty comma list of subsystem legacy names in
# subsystem order, then "name=<name>" last (cgroup-v1.c: [\w.-]+, at most 63 bytes, a root needs a name or
# a subsystem, one name per root; a subsystem binds to one root). The path is an absolute canonical cgroup
# path relative to the reader's cgroup namespace root (a path outside it begins "/.."); cgroup_mkdir refuses
# "\n" in names; a dead v2 cgroup's path is followed by " (deleted)".
CGROUP_V1_SUBSYSTEMS = ("cpuset", "cpu", "cpuacct", "blkio", "memory", "devices", "freezer", "net_cls",
                        "perf_event", "net_prio", "hugetlb", "pids", "rdma", "misc", "debug")
CGROUP_ID_MAX = 2 ** 31 - 1
CGROUP_PATH_MAX = 512          # characters (ASCII: bytes), checked before the path is sliced or split
CGROUP_DEPTH_MAX = 16          # components, counted as "/" separators before any split
CGROUP_CONTROLLER_FIELD_MAX = 512
CGROUP_CONTROLLER_TOKENS_MAX = len(CGROUP_V1_SUBSYSTEMS) + 1  # every v6.8 subsystem plus one name=
CGROUP_TOKEN = re.compile(r"[a-z_]{1,32}")
CGROUP_ROOT_NAME = re.compile(r"[A-Za-z0-9._-]{1,63}")
# cgroup.controllers / cgroup.subtree_control: at most 64 whitespace-separated [a-z_]{1,32} tokens. The
# whole value is matched on bytes before decode or split, so the token bound is enforced first.
CONTROLLER_FILE = re.compile(rb"[ \t\n]*(?:[a-z_]{1,32}(?:[ \t\n]+[a-z_]{1,32}){0,63})?[ \t\n]*")

# Unknown fact values. Any of these anywhere in a report's fact sections requires observation=incomplete.
UNKNOWN = ("denied", "error", "malformed", "oversize", "not_regular", "deadline_exhausted", "deadline_overrun",
           "aggregate_exhausted", "unrecognized", "ambiguous", "unavailable", "unsupported", "command_failed")
READ_KINDS = ("absent",) + UNKNOWN


class PreflightError(Exception):
    """Internal contract violation; never carries host-derived text."""


class HostReadError(Exception):
    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind if kind in READ_KINDS else "error"


@dataclasses.dataclass
class CommandResult:
    state: str
    exit_code: int | None
    stdout: bytes
    stdout_bytes: int
    stdout_truncated: bool
    stderr_bytes: int
    elapsed_ms: int
    leader_reaped: bool
    stderr_class: str = "empty"
    group_signal: str = "not_sent"

    def summary(self) -> dict:
        return {"state": self.state, "exit_code": self.exit_code, "stdout_bytes": self.stdout_bytes,
                "stdout_truncated": self.stdout_truncated, "stderr_bytes": self.stderr_bytes,
                "stderr_class": self.stderr_class, "elapsed_ms": self.elapsed_ms,
                "leader_reaped": self.leader_reaped, "group_signal": self.group_signal,
                "descendants_outside_group": "not_observed"}


@dataclasses.dataclass
class Budget:
    """Aggregate file-read allowance. Every delivered byte is charged before the next read; never refunded."""
    remaining_bytes: int
    deadline: float
    clock: object = time.monotonic
    delivered_bytes: int = 0
    read_calls: int = 0

    def allowance(self, wanted: int) -> int:
        return max(0, min(wanted, self.remaining_bytes))

    def charge(self, count: int) -> None:
        self.read_calls += 1
        if count < 0 or count > self.remaining_bytes:
            raise PreflightError("budget_overdelivery")
        self.remaining_bytes -= count
        self.delivered_bytes += count

    def expired(self) -> bool:
        return self.clock() >= self.deadline


def classify_stderr(data: bytes) -> str:
    if not data:
        return "empty"
    if b"a password is required" in data:
        return "password_required"
    # Only sudo's own explicit no-permission sentences; a bare "not allowed to" is not one of them.
    if (b"may not run sudo on" in data or b"is not in the sudoers file" in data
            or b"is not allowed to run sudo on" in data):
        return "not_permitted"
    if b"dubious ownership" in data:
        return "git_dubious_ownership"
    if b"not a git repository" in data:
        return "git_not_repository"
    return "other"


def command_environment(command_id: str) -> dict:
    if command_id not in COMMANDS:
        raise PreflightError("command_not_allowlisted")
    env = dict(_BASE_ENV)
    if command_id.startswith("git_"):
        env.update(_GIT_ENV)
    if command_id.startswith("systemctl") or command_id.startswith("systemd"):
        env.update(_SYSTEMD_ENV)
    return env


def _signal_group(pid: int) -> str:
    """SIGKILL the leader's original process group. Only members still in that group are reached."""
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return "no_process"
    except PermissionError:
        return "denied"
    return "sent"


def _exited_unreaped(pid: int) -> bool:
    """True once the leader has exited; WNOWAIT keeps it a zombie so its PID/PGID cannot be reused."""
    try:
        info = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        return True
    return info is not None and info.si_pid == pid


def run_bounded(argv, *, env, cwd, timeout, stdout_cap, stderr_cap, clock=time.monotonic) -> CommandResult:
    """Run one fixed argv as leader of a new process group with a deadline and byte caps on both pipes.

    Guarantees are about the leader and its original group only: the leader is reaped (or reported
    ``leader_unreaped``) and the group is signalled while the unreaped leader still pins the PGID. A
    descendant that leaves the group (``setsid``) and closes the captured pipes is not observed: the
    result can then be ``ok`` while that descendant keeps running.
    """
    if not isinstance(argv, tuple) or not argv or not all(isinstance(part, str) for part in argv):
        raise PreflightError("argv_must_be_fixed_tuple")
    start = clock()
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=dict(env), cwd=cwd, close_fds=True, start_new_session=True, shell=False)
    except FileNotFoundError:
        return CommandResult("tool_absent", None, b"", 0, False, 0, 0, True)
    except OSError:
        return CommandResult("spawn_failed", None, b"", 0, False, 0, 0, True)
    out_fd, err_fd = proc.stdout.fileno(), proc.stderr.fileno()
    caps = {out_fd: stdout_cap, err_fd: stderr_cap}
    buffers = {out_fd: bytearray(), err_fd: bytearray()}
    selector = selectors.DefaultSelector()
    for fd in caps:
        os.set_blocking(fd, False)
        selector.register(fd, selectors.EVENT_READ)
    deadline = start + timeout
    state = None
    exited_at = None
    try:
        while selector.get_map() and state is None:
            now = clock()
            if now >= deadline:
                state = "timeout"
                break
            if exited_at is None and _exited_unreaped(proc.pid):
                exited_at = now
            if exited_at is not None and now - exited_at > PIPE_GRACE_S:
                state = "pipe_held"
                break
            for key, _ in selector.select(min(deadline - now, 0.05)):
                fd = key.fd
                try:
                    chunk = os.read(fd, max(1, min(65536, caps[fd] + 1 - len(buffers[fd]))))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(fd)
                    continue
                buffers[fd] += chunk
                if len(buffers[fd]) > caps[fd]:
                    state = "output_cap_exceeded" if fd == out_fd else "stderr_cap_exceeded"
                    break
        # Both pipes reached EOF: give the leader the rest of the deadline to exit on its own, so the
        # group signal below cannot race an ordinary exit status.
        while state is None and not _exited_unreaped(proc.pid):
            if clock() >= deadline:
                state = "timeout"
                break
            time.sleep(0.01)
    finally:
        selector.close()
        # The leader is not reaped yet, so its PGID cannot belong to an unrelated process.
        group_signal = _signal_group(proc.pid)
        proc.stdout.close()
        proc.stderr.close()
    leader_reaped = True
    try:
        status = proc.wait(timeout=REAP_GRACE_S)
    except subprocess.TimeoutExpired:
        leader_reaped, status = False, None
    exit_code = status if status is not None and status >= 0 else None
    if not leader_reaped:
        state = "leader_unreaped"
    elif state is None:
        state = "ok" if status == 0 else ("nonzero_exit" if exit_code is not None else "signaled")
    elapsed = int(max(0.0, clock() - start) * 1000)
    return CommandResult(state, exit_code, bytes(buffers[out_fd][:stdout_cap]), len(buffers[out_fd]),
                         len(buffers[out_fd]) > stdout_cap, len(buffers[err_fd]), elapsed, leader_reaped,
                         classify_stderr(bytes(buffers[err_fd][:stderr_cap])), group_signal)


def bounded_stream(read_chunk, cap, budget, chunk_size, sink) -> int:
    """Read until EOF: at most cap+1 bytes from one file and never more than the aggregate allowance.

    Each delivered chunk is charged to ``budget`` immediately, before any other read, including the
    oversize sentinel byte and chunks of a read that later fails. Nothing is refunded. No read is issued
    once the aggregate allowance is spent, even just to observe EOF. ``read_chunk(n)`` returns <= n bytes.
    """
    total = 0
    while True:
        if budget.expired():
            raise HostReadError("deadline_exhausted")
        allowed = budget.allowance(min(chunk_size, cap + 1 - total))
        if allowed <= 0:
            raise HostReadError("aggregate_exhausted")
        try:
            chunk = read_chunk(allowed)
        except OSError as error:
            budget.charge(0)
            raise HostReadError("denied" if isinstance(error, PermissionError) else "error") from None
        if len(chunk) > allowed:
            raise PreflightError("read_overdelivery")
        budget.charge(len(chunk))
        if not chunk:
            return total
        total += len(chunk)
        if total > cap:
            raise HostReadError("oversize")
        sink(chunk)


def _os_error_kind(error: OSError) -> str:
    if isinstance(error, FileNotFoundError):
        return "absent"
    if isinstance(error, PermissionError):
        return "denied"
    return "error"


class RealHost:
    """The only object that touches the real host. Every method is read-only."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def platform(self):
        return (sys.platform, os.uname().machine)

    def env(self, name):
        if name not in ENV_ALLOWLIST:
            raise PreflightError("environment_name_not_allowlisted")
        return os.environ.get(name)

    def python_version(self):
        return tuple(sys.version_info[:3])

    def monotonic(self):
        return time.monotonic()

    def uname(self):
        value = os.uname()
        return (value.sysname, value.release, value.machine)

    def cpu_online(self):
        try:
            return os.sysconf("SC_NPROCESSORS_ONLN")
        except (OSError, ValueError):
            raise HostReadError("error") from None

    def _open(self, path):
        try:
            return os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | getattr(os, "O_NOCTTY", 0))
        except OSError as error:
            raise HostReadError(_os_error_kind(error)) from None

    def read(self, path, cap, budget):
        fd = self._open(path)
        try:
            try:
                info = os.fstat(fd)
            except OSError as error:
                raise HostReadError(_os_error_kind(error)) from None
            if not stat.S_ISREG(info.st_mode):
                raise HostReadError("not_regular")
            os.set_blocking(fd, True)
            data = bytearray()
            bounded_stream(lambda count: os.read(fd, count), cap, budget, SMALL_CHUNK, data.extend)
            return bytes(data)
        finally:
            os.close(fd)

    def stat(self, path, follow=True):
        try:
            return os.stat(path) if follow else os.lstat(path)
        except OSError as error:
            raise HostReadError(_os_error_kind(error)) from None

    def realpath(self, path):
        try:
            return os.path.realpath(path, strict=True)
        except OSError as error:
            raise HostReadError(_os_error_kind(error)) from None

    def statvfs(self, path):
        try:
            return os.statvfs(path)
        except OSError as error:
            raise HostReadError(_os_error_kind(error)) from None

    def has_capability_xattr(self, path, budget):
        """True only for a determinate answer: a ``security.capability`` value was delivered.

        ENODATA is ``ambiguous``, never absence. getxattr(2) documents ENODATA both for a missing attribute and
        for one the process has no access to. On the pinned Linux v6.8 path (fs/xattr.c vfs_getxattr ->
        security_inode_getxattr -> xattr_getsecurity -> commoncap cap_inode_getsecurity -> vfs_getxattr_alloc
        -> the filesystem handler) the errno comes from whichever LSM hooks and filesystem handler serve the
        tool's file, and the collector does not bind that filesystem/LSM stack. A single ENODATA observation
        cannot tell those causes apart, so it stays an unknown with a reason (``binary:<tool>:ambiguous``).

        ``os.getxattr`` takes no size cap, so it is admitted only when the remaining aggregate allowance
        is at least XATTR_VALUE_BOUND, the documented maximum it can deliver. Admission reserves nothing
        and debits nothing; the actual charge is the delivered length, debited before any error return
        and never refunded. Nothing else can consume the budget between admission and charge (single
        thread). Outcomes: ``aggregate_exhausted`` (not invoked), ``oversize`` (a per-value E2BIG/ERANGE
        or a delivered value above the bound, charged), ``denied``, ``unsupported``, ``error``,
        ``ambiguous`` (ENODATA, counted, 0 bytes) and presence (True). A value that exceeds even the
        remaining allowance cannot be accounted truthfully and is an internal error. Every getter
        invocation is a counted read call.
        Where ``os.getxattr`` does not exist (not Linux) nothing native is attempted.
        """
        getter = getattr(os, "getxattr", None)
        if getter is None:
            raise HostReadError("unavailable")
        if budget.remaining_bytes < XATTR_VALUE_BOUND:
            raise HostReadError("aggregate_exhausted")
        try:
            value = getter(path, "security.capability")
        except OSError as error:
            budget.charge(0)
            if error.errno == errno.ENODATA:
                raise HostReadError("ambiguous") from None
            if error.errno in (errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)):
                raise HostReadError("unsupported") from None
            if error.errno in (errno.E2BIG, errno.ERANGE):
                raise HostReadError("oversize") from None
            raise HostReadError("denied" if isinstance(error, PermissionError) else "error") from None
        if type(value) is not bytes:
            raise PreflightError("xattr_value_type")
        if len(value) > budget.remaining_bytes:
            raise PreflightError("xattr_overdelivery")
        budget.charge(len(value))
        if len(value) > XATTR_VALUE_BOUND:
            raise HostReadError("oversize")
        return True

    def hash_file(self, path, cap, budget):
        fd = self._open(path)
        try:
            try:
                info = os.fstat(fd)
            except OSError as error:
                raise HostReadError(_os_error_kind(error)) from None
            if not stat.S_ISREG(info.st_mode):
                raise HostReadError("not_regular")
            if info.st_size > cap:
                raise HostReadError("oversize")
            if info.st_size > budget.remaining_bytes:
                raise HostReadError("aggregate_exhausted")
            os.set_blocking(fd, True)
            digest = hashlib.sha256()
            total = bounded_stream(lambda count: os.read(fd, count), cap, budget, HASH_CHUNK, digest.update)
            return digest.hexdigest(), total
        finally:
            os.close(fd)

    def identity(self):
        return (os.getuid(), os.geteuid(), os.getgid(), os.getgroups())

    def run(self, command_id, timeout):
        if command_id not in COMMANDS:
            raise PreflightError("command_not_allowlisted")
        cwd = str(self.root) if command_id.startswith("git_") else "/"
        return run_bounded(COMMANDS[command_id], env=command_environment(command_id), cwd=cwd, timeout=timeout,
                           stdout_cap=COMMAND_STDOUT_CAP, stderr_cap=COMMAND_STDERR_CAP)


# ---- Parsers (input is already capped; every parser bounds line counts before splitting) --------

def _lines(data: bytes, encoding="ascii", max_lines=MAX_LINES, max_line=MAX_LINE_BYTES) -> list:
    """Split LF-terminated records with both bounds enforced on the raw bytes before decode or split.

    Records: LF is the only terminator; a final unterminated line is a record (so ``b"a\nb"`` is two);
    a final LF does not add an empty record; empty records are kept (parsers skip them); a CR is
    content, so CRLF input keeps a trailing ``\r`` that each strict grammar then rejects or strips
    explicitly. ``max_line`` counts bytes excluding the LF.
    """
    if type(data) is not bytes:
        raise PreflightError("lines_input_type")
    records = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
    if records > max_lines:
        raise HostReadError("oversize")
    start, size = 0, len(data)
    while start < size:
        end = data.find(b"\n", start)
        end = size if end < 0 else end
        if end - start > max_line:
            raise HostReadError("oversize")
        start = end + 1
    try:
        text = data.decode(encoding)
    except UnicodeDecodeError:
        raise HostReadError("malformed") from None
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _canonical_absolute(path: str) -> bool:
    return path == "/" or (path.startswith("/") and not path.endswith("/")
                           and all(part not in ("", ".", "..") for part in path[1:].split("/")))


_TAG_NAME = re.compile(r"[a-z_][a-z0-9_]{0,31}")
_GROUP_ID = re.compile(r"[1-9][0-9]{0,9}")
_RECOGNIZED_TAGS = ("shared", "master", "propagate_from", "unbindable")


def _propagation(optional: list) -> str:
    """Validate every optional mountinfo field, then derive propagation (proc_pid_mountinfo(5)).

    Recognized tags (kernel order shared, master, propagate_from, unbindable) must be well formed:
    ``shared``/``master``/``propagate_from`` carry a positive peer-group id without sign or leading
    zero, ``unbindable`` carries no value, none repeats, ``propagate_from`` needs a different
    ``master``, ``shared`` and ``master`` differ, and ``unbindable`` excludes both. Any violation makes
    the whole table ``malformed``. A syntactically valid unrecognized tag is ignored for parsing, as
    the format requires, but it means this mount's propagation cannot be derived: ``unrecognized``.
    Its text is never stored.
    """
    seen: dict = {}
    order = []
    unknown = False
    for tag in optional:
        name, sep, value = tag.partition(":")
        if not _TAG_NAME.fullmatch(name):
            raise HostReadError("malformed")
        if name not in _RECOGNIZED_TAGS:
            if sep and not value:
                raise HostReadError("malformed")
            unknown = True
            continue
        if name in seen:
            raise HostReadError("malformed")
        if name == "unbindable":
            if sep:
                raise HostReadError("malformed")
            seen[name] = True
        else:
            if not sep or not _GROUP_ID.fullmatch(value) or int(value) > MOUNT_GROUP_ID_MAX:
                raise HostReadError("malformed")
            seen[name] = int(value)
        order.append(_RECOGNIZED_TAGS.index(name))
    if order != sorted(order):
        raise HostReadError("malformed")
    if "propagate_from" in seen and ("master" not in seen or seen["propagate_from"] == seen["master"]):
        raise HostReadError("malformed")
    if "shared" in seen and seen.get("master") == seen["shared"]:
        raise HostReadError("malformed")
    if "unbindable" in seen and ("shared" in seen or "master" in seen):
        raise HostReadError("malformed")
    if unknown:
        return "unrecognized"
    if "unbindable" in seen:
        return "unbindable"
    if "shared" in seen and "master" in seen:
        return "shared_and_slave"
    if "shared" in seen:
        return "shared"
    if "master" in seen:
        return "slave"
    return "private"


_MOUNT_ESCAPE = re.compile(r"\\([0-3][0-7]{2})")
_DECIMAL = re.compile(r"0|[1-9][0-9]{0,9}")
_DEVICE = re.compile(r"(0|[1-9][0-9]{0,9}):(0|[1-9][0-9]{0,9})")
_OPTION_TOKEN = re.compile(r"[a-z][a-z0-9_]{0,31}")
_SUPER_ACCESS = re.compile(r"r[ow](?:,|$)")


def _mount_text(value: str, escapes) -> str:
    """Decode one escaped mountinfo field. Every backslash must start a three-digit octal escape of a
    non-NUL byte (mangle_path/seq_escape always escape the backslash itself). ``escapes`` is the
    printer's escape set; a decoded character outside it was not produced by that printer. ``None``
    admits any non-NUL escape (the mount root may come from a filesystem's own show_path)."""
    if not value or "\x00" in value or "\\" in _MOUNT_ESCAPE.sub("", value):
        raise HostReadError("malformed")

    def decode(match):
        char = chr(int(match.group(1), 8))
        if char == "\x00" or (escapes is not None and char not in escapes):
            raise HostReadError("malformed")
        return char
    return _MOUNT_ESCAPE.sub(decode, value)


def _mount_number(value: str, high: int) -> int:
    if not _DECIMAL.fullmatch(value) or int(value) > high:
        raise HostReadError("malformed")
    return int(value)


def _mount_options(value: str):
    """Per-mount options: one leading access mode, then unique tokens; recognized tokens in kernel order.

    A syntactically valid token the kernel's printer does not list is future syntax: parsing continues,
    but this mount's option flags are ``unrecognized`` (an absent known token may no longer mean "off").
    Anything else (empty component, second access mode, duplicate, order violation, other characters)
    makes the table ``malformed``. Returns (access, tokens, state)."""
    if value.count(",") >= MOUNT_OPTION_MAX:  # component count bounded before the split
        raise HostReadError("malformed")
    tokens = value.split(",")
    if tokens[0] not in MOUNT_ACCESS:
        raise HostReadError("malformed")
    seen, last, unknown = set(), -1, False
    for token in tokens[1:]:
        if token in MOUNT_ACCESS or token in seen or not _OPTION_TOKEN.fullmatch(token):
            raise HostReadError("malformed")
        seen.add(token)
        if token in MOUNT_OPTION_ORDER:
            position = MOUNT_OPTION_ORDER.index(token)
            if position < last:
                raise HostReadError("malformed")
            last = position
        else:
            unknown = True
    return tokens[0], frozenset(tokens), "unrecognized" if unknown else "observed"


def parse_mountinfo(data: bytes) -> dict:
    """Return {mount_id: entry}. Mount and parent IDs are kept: visibility is resolved from the topology.

    Every consumed field of every record is validated before any entry is stored (see the module
    constants for the pinned Linux v6.8 grammar): ids, device, root, mount point, options, optional
    tags, the ``-`` separator, then exactly three fields: a non-empty filesystem type, the source
    (may be empty; never stored) and super options led by ``ro`` or ``rw`` (the rest is filesystem
    specific and never stored). Any violation, or an empty record, makes the whole table ``malformed``.
    """
    lines = _lines(data, max_lines=MAX_MOUNT_ENTRIES, max_line=4096)
    entries = {}
    for line in lines:
        if line.count(" ") >= MOUNTINFO_MAX_FIELDS:  # field count bounded before the split
            raise HostReadError("malformed")
        if line.endswith("\r"):  # the printer ends a record with LF right after the options: CRLF framing
            raise HostReadError("malformed")
        fields = line.split(" ")
        if len(fields) < 10 or "-" not in fields[6:]:
            raise HostReadError("malformed")
        sep = fields.index("-", 6)
        if len(fields) != sep + 4:  # exactly filesystem type, source, super options
            raise HostReadError("malformed")
        mount_id = _mount_number(fields[0], MOUNT_ID_MAX)
        parent_id = _mount_number(fields[1], MOUNT_ID_MAX)
        device = _DEVICE.fullmatch(fields[2])
        if not device:
            raise HostReadError("malformed")
        _mount_number(device.group(1), DEV_MAJOR_MAX)
        _mount_number(device.group(2), DEV_MINOR_MAX)
        if mount_id in entries:
            raise HostReadError("malformed")
        root = _mount_text(fields[3], None)
        mount_point = _mount_text(fields[4], MOUNT_PATH_ESCAPES)
        if not root.startswith("/") or not _canonical_absolute(mount_point):
            raise HostReadError("malformed")
        access, options, options_state = _mount_options(fields[5])
        propagation = _propagation(fields[6:sep])
        fstype = _mount_text(fields[sep + 1], MOUNT_TYPE_ESCAPES)
        if "\x00" in fields[sep + 2] or not _SUPER_ACCESS.match(fields[sep + 3]):
            raise HostReadError("malformed")
        entries[mount_id] = {"id": mount_id, "parent": parent_id, "root": root, "mount_point": mount_point,
                             "fstype": fstype, "propagation": propagation, "access": access, "options": options,
                             "options_state": options_state}
    if not entries:
        raise HostReadError("malformed")
    return entries


def _children_index(entries: dict) -> dict:
    index: dict = {}
    for entry in entries.values():
        index.setdefault((entry["parent"], entry["mount_point"]), []).append(entry["id"])
    return index


def _top_of_stack(entries, index, mount_id, mount_point):
    seen = {mount_id}
    while True:
        above = index.get((mount_id, mount_point), [])
        if not above:
            return mount_id
        if len(above) != 1 or above[0] in seen:
            raise HostReadError("ambiguous")
        mount_id = above[0]
        seen.add(mount_id)


def resolve_visible_entry(entries: dict, path: str) -> dict:
    """The mount that is actually reachable at ``path`` from this process's root.

    Walks from the single root mount down the path components, following only mounts whose parent is
    the currently visible mount at that point, and climbing stacks at the same mount point. A mount
    below a covered (hidden) ancestor is never chosen. Input order is irrelevant. Ambiguous topology
    (no unique root, two children on one point, a cycle) is unknown, never guessed.
    """
    if not _canonical_absolute(path):
        raise HostReadError("ambiguous")
    index = _children_index(entries)
    roots = [entry for entry in entries.values() if entry["parent"] not in entries or entry["parent"] == entry["id"]]
    if len(roots) != 1 or roots[0]["mount_point"] != "/":
        raise HostReadError("ambiguous")
    for entry in entries.values():  # every mount must reach the root: an orphan cycle is inconsistent topology
        hops, cursor = 0, entry
        while cursor["id"] != roots[0]["id"]:
            hops += 1
            if hops > len(entries) or cursor["parent"] not in entries:
                raise HostReadError("ambiguous")
            cursor = entries[cursor["parent"]]
    current = _top_of_stack(entries, index, roots[0]["id"], "/")
    prefix = ""
    for part in [part for part in path.split("/") if part]:
        prefix = f"{prefix}/{part}"
        children = index.get((current, prefix), [])
        if len(children) > 1:
            raise HostReadError("ambiguous")
        if children:
            current = _top_of_stack(entries, index, children[0], prefix)
    return entries[current]


def _enum(value: str, allowed) -> str:
    return value if value in allowed else "other"


def _int_text(data: bytes, low=0, high=2 ** 63):
    if len(data) > 32:
        raise HostReadError("malformed")
    text = data.decode("ascii", "replace").strip()
    if not re.fullmatch(r"-?[0-9]{1,19}", text):
        raise HostReadError("malformed")
    value = int(text)
    if not low <= value <= high:
        raise HostReadError("malformed")
    return value


def _controllers(data: bytes) -> list:
    """Parse a cgroup.controllers/subtree_control value; byte, grammar and 64-token bounds precede split."""
    if type(data) is not bytes:
        raise PreflightError("controllers_input_type")
    if len(data) > 4096:
        raise HostReadError("oversize")
    if not CONTROLLER_FILE.fullmatch(data):  # bounded grammar on bytes: no decode, no token list yet
        raise HostReadError("malformed")
    tokens = data.decode("ascii").split()
    return sorted({token if token in CONTROLLERS else "other" for token in tokens})


_CGROUP_RANK = {"malformed": 3, "oversize": 2, "unrecognized": 1}


def _cgroup_controllers(line: str, start: int, end: int):
    """Validate a v1 controller field line[start:end]; returns (kind, subsystems, name). Bounds first."""
    if (end - start > CGROUP_CONTROLLER_FIELD_MAX
            or line.count(",", start, end) + 1 > CGROUP_CONTROLLER_TOKENS_MAX):
        return "oversize", (), None
    tokens = line[start:end].split(",")  # at most CGROUP_CONTROLLER_TOKENS_MAX short tokens
    subsystems, name, kind = [], None, None
    for index, token in enumerate(tokens):
        if token.startswith("name="):
            if index != len(tokens) - 1 or not CGROUP_ROOT_NAME.fullmatch(token[5:]):
                return "malformed", (), None
            name = token[5:]
        elif not CGROUP_TOKEN.fullmatch(token):
            return "malformed", (), None
        elif token in subsystems:
            return "malformed", (), None
        else:
            subsystems.append(token)
            if token not in CGROUP_V1_SUBSYSTEMS:
                kind = "unrecognized"  # well-formed, but not a v6.8 subsystem legacy name
    return kind, tuple(subsystems), name


def _cgroup_path(line: str, start: int):
    """Validate the path line[start:]; returns (kind, components). Length and depth precede the split."""
    size = len(line) - start
    if size > CGROUP_PATH_MAX:
        return "oversize", ()
    if size == 0 or line[start] != "/":
        return "malformed", ()
    if size == 1:
        return None, ()
    if line.count("/", start) > CGROUP_DEPTH_MAX:
        return "oversize", ()
    parts = line[start + 1:].split("/")  # at most CGROUP_DEPTH_MAX components of a <= 512-character path
    if any(part in ("", ".") for part in parts):
        return "malformed", ()  # never emitted: repeated, trailing or "." components are not canonical
    if any(part == ".." or not CGROUP_COMPONENT.fullmatch(part) for part in parts):
        # Kernel-valid but outside the supported scope: a path outside the reader's cgroup namespace root,
        # a " (deleted)" suffix, or a name outside the closed component grammar.
        return "unrecognized", ()
    return None, tuple(parts)


def _parse_self_cgroup(lines: list):
    """Validate every /proc/self/cgroup record before deriving anything.

    Returns (kind, v1_entries, components). ``kind`` is None only when every record is a recognized
    hierarchy record, ids/subsystems/names are unique, and exactly one v2 (id 0) record exists. Otherwise the
    most severe class wins: malformed (framing/grammar/duplicate/contradiction) > oversize (a sub-bound) >
    unrecognized (well-formed but outside the supported grammar) > unsupported (valid input with no v2 record,
    including empty input: the own-cgroup facts are unified-hierarchy facts).
    """
    if type(lines) is not list:
        raise PreflightError("cgroup_records_type")
    worst, v1_entries, v2_parts, v2_count = None, 0, (), 0
    ids, subsystems_seen, names = set(), set(), set()
    for line in lines:
        if type(line) is not str:  # exact native str before any method of the record is called
            raise PreflightError("cgroup_records_type")
        first = line.find(":")
        second = line.find(":", first + 1) if first >= 0 else -1
        if first <= 0 or second < 0 or first > 10:
            kind = "malformed"
        else:
            id_text = line[:first]
            if not (id_text == "0" or _GROUP_ID.fullmatch(id_text)) or int(id_text) > CGROUP_ID_MAX \
                    or id_text in ids:
                kind = "malformed"
            else:
                ids.add(id_text)
                kind = None
                if id_text == "0":
                    v2_count += 1
                    if second != first + 1:
                        kind = "malformed"  # the default hierarchy lists no controllers
                else:  # an empty v1 field is one empty token: malformed (a root needs a name or a subsystem)
                    kind, subsystems, name = _cgroup_controllers(line, first + 1, second)
                    if subsystems_seen.intersection(subsystems) or (name is not None and name in names):
                        kind = "malformed"  # a subsystem binds to one root; root names are unique
                    subsystems_seen.update(subsystems)
                    if name is not None:
                        names.add(name)
                    v1_entries += 1
                path_kind, parts = _cgroup_path(line, second + 1)
                if path_kind and _CGROUP_RANK[path_kind] > _CGROUP_RANK.get(kind, 0):
                    kind = path_kind
                if id_text == "0":
                    v2_parts = parts
        if kind and _CGROUP_RANK[kind] > _CGROUP_RANK.get(worst, 0):
            worst = kind
    if worst:
        return worst, None, ()
    if v2_count != 1:
        return "unsupported", None, ()
    return None, v1_entries, v2_parts


def _octal_mode(mode: int) -> str:
    return format(stat.S_IMODE(mode), "04o")


def _file_type(mode: int) -> str:
    for check, name in ((stat.S_ISSOCK, "socket"), (stat.S_ISDIR, "directory"), (stat.S_ISREG, "regular"),
                        (stat.S_ISLNK, "symlink")):
        if check(mode):
            return name
    return "other"


def parse_sudo_listing(data: bytes) -> dict:
    """Recognize a ``sudo -n -l`` listing. Any unrecognized line makes the whole listing unknown.

    Returns lexical facts about listed rules only (not effective authority): the rule count and whether
    a rule exactly ``(ALL[:ALL]) NOPASSWD: ALL`` is listed.
    """
    lines = _lines(data, encoding="utf-8", max_lines=4096, max_line=4096)
    section = None
    user_headers = 0
    rules: list = []
    for line in lines:
        if not line.strip():
            continue
        if not line[0].isspace():
            if re.fullmatch(r"Matching Defaults entries for \S+ on \S+:", line):
                section = "defaults"
            elif re.fullmatch(r"Runas and Command-specific defaults for \S+:", line):
                section = "defaults"
            elif re.fullmatch(r"User \S+ may run the following commands on \S+:", line):
                section, user_headers = "rules", user_headers + 1
            else:
                raise HostReadError("unrecognized")
            continue
        if section == "defaults":
            continue
        if section != "rules":
            raise HostReadError("unrecognized")
        if re.match(r"    \(", line):
            if not re.fullmatch(r"    \([^()]{1,256}\)\s+(?:[A-Z_]{2,24}:\s*)*\S.*", line):
                raise HostReadError("unrecognized")
            rules.append([line.strip()])
        elif re.match(r"\s{5,}\S", line) and rules:
            rules[-1].append(line.strip())
        else:
            raise HostReadError("unrecognized")
    if user_headers != 1 or not rules:
        raise HostReadError("unrecognized")
    joined = [" ".join(parts) for parts in rules]  # one linear join; continuations stay part of their rule
    nopasswd_all = any(re.fullmatch(r"\(ALL(?:\s*:\s*ALL)?\)\s+NOPASSWD:\s*ALL", rule) for rule in joined)
    return {"rule_lines": len(rules), "nopasswd_all_rule_listed": nopasswd_all}


_NOT_ALLOWED_STDOUT = re.compile(r"User \S+ is not allowed to run sudo on \S+\.\n?")


def parse_apparmor_loaded(data: bytes) -> tuple:
    """Every line must be ``<name> (<mode>)``; otherwise the list is malformed, never a negative."""
    lines = _lines(data, encoding="utf-8", max_lines=MAX_LINES, max_line=4096)
    count = 0
    mode = "absent"
    for line in lines:
        if not line:
            continue
        match = re.fullmatch(r"(\S(?:.{0,4000}\S)?) \(([a-z]{1,16})\)", line)
        if not match:
            raise HostReadError("malformed")
        count += 1
        if match.group(1) in APPARMOR_ROOTLESSKIT_NAMES:
            if mode != "absent":
                raise HostReadError("ambiguous")
            mode = _enum(match.group(2), APPARMOR_MODES)
    return count, mode


def parse_group_file(data: bytes, names) -> dict:
    """Strictly parse local /etc/group. Returns {name: (gid, members)} for ``names`` that are present."""
    found: dict = {}
    for line in _lines(data):
        if not line or line.startswith("#"):
            continue
        if line[0] in "+-":
            raise HostReadError("unrecognized")  # NSS compat entry: membership defined elsewhere
        if line.count(":") != 3:  # field count before the split
            raise HostReadError("malformed")
        parts = line.split(":")
        if len(parts) != 4 or not ACCOUNT_NAME.fullmatch(parts[0]) or not parts[2].isdigit() or len(parts[2]) > 10:
            raise HostReadError("malformed")
        if parts[0] not in names:
            continue
        # Member count needs no separate check: a line is at most MAX_LINE_BYTES, so fewer than 32768 members.
        members = [member for member in parts[3].split(",") if member] if parts[3] else []
        if not all(ACCOUNT_NAME.fullmatch(member) for member in members):
            raise HostReadError("malformed")
        if parts[0] in found:
            raise HostReadError("ambiguous")
        found[parts[0]] = (int(parts[2]), frozenset(members))
    return found


def parse_passwd_file(data: bytes, name: str):
    """Strictly parse local /etc/passwd. Returns (uid, gid, shell) for ``name`` or None if not listed."""
    found = None
    for line in _lines(data, max_line=4096):
        if not line or line.startswith("#"):
            continue
        if line[0] in "+-":
            raise HostReadError("unrecognized")
        if line.count(":") != 6:  # field count before the split
            raise HostReadError("malformed")
        parts = line.split(":")
        if (len(parts) != 7 or not ACCOUNT_NAME.fullmatch(parts[0]) or not parts[2].isdigit()
                or not parts[3].isdigit() or len(parts[2]) > 10 or len(parts[3]) > 10):
            raise HostReadError("malformed")
        if parts[0] == name:
            if found is not None:
                raise HostReadError("ambiguous")
            found = (int(parts[2]), int(parts[3]), parts[6])
    return found


# ---- Collector ----------------------------------------------------------------------------------

class _Collector:
    def __init__(self, host):
        self.host = host
        self.incomplete: set = set()
        self.gaps: set = set()
        self.commands: dict = {}
        self.started = host.monotonic()
        self.deadline = self.started + AGGREGATE_DEADLINE_S
        self.budget = Budget(READ_AGGREGATE_CAP, self.deadline, host.monotonic)

    def miss(self, area: str, kind: str):
        self.incomplete.add(f"{area}:{kind}")

    def expired(self) -> bool:
        return self.host.monotonic() >= self.deadline

    def attempt(self, area, fn, *args, absent_is_fact=True):
        """Deadline admission, the operation, then a postcheck. Returns (value, kind).

        kind is None on success. ``absent`` is a determinate fact when ``absent_is_fact``; every other
        kind (and absent otherwise) is recorded as an incomplete reason. A value obtained after the
        deadline is kept but marks the area incomplete; later operations are then refused.
        """
        if self.expired():
            value, kind = None, "deadline_exhausted"
        else:
            try:
                value, kind = fn(*args), None
            except HostReadError as error:
                value, kind = None, error.kind
            if self.expired():
                self.miss(area, "deadline_overrun")
        if kind is not None and not (absent_is_fact and kind == "absent"):
            self.miss(area, kind)
            if kind == "absent":
                kind = "unavailable"  # a required fact that is missing is unknown, not a determinate absence
        return value, kind

    def read(self, area, path, cap, absent_is_fact=True):
        return self.attempt(area, self.host.read, path, cap, self.budget, absent_is_fact=absent_is_fact)

    def parse(self, area, fn, *args):
        try:
            return fn(*args), None
        except HostReadError as error:
            self.miss(area, error.kind)
            return None, error.kind

    def run(self, command_id):
        if self.expired():
            result = CommandResult("deadline_exhausted", None, b"", 0, False, 0, 0, True)
        else:
            remaining = self.deadline - self.host.monotonic()
            result = self.host.run(command_id, max(0.0, min(COMMAND_DEADLINE_S, remaining)))
            if self.expired():
                self.miss(command_id, "deadline_overrun")
        self.commands[command_id] = result.summary()
        return result

    def command_value(self, command_id):
        """Returns (text, kind): kind is None, ``command_failed`` or ``malformed`` (both recorded)."""
        result = self.run(command_id)
        if result.state != "ok":
            self.miss(command_id, result.state)
            return None, "command_failed"
        try:
            return result.stdout.decode("ascii"), None
        except UnicodeDecodeError:
            self.miss(command_id, "malformed")
            return None, "malformed"

    # Individual observation groups --------------------------------------------------------------
    def source(self):
        out = {"head": None, "tree": None, "worktree_clean": None, "dirty_entries": None}
        text, kind = self.command_value("git_identity")
        if text is not None:
            lines = text.split("\n")
            if len(lines) == 3 and lines[2] == "" and all(HEX_OBJECT.fullmatch(line) for line in lines[:2]):
                out["head"], out["tree"] = lines[0], lines[1]
            else:
                self.miss("git_identity", "malformed")
                kind = "malformed"
        if kind is not None:
            out["head"] = out["tree"] = kind
        status, kind = self.command_value("git_status")
        if status is None:
            out["worktree_clean"] = kind
        else:
            entries = [line for line in status.split("\n") if line]
            out["worktree_clean"] = not entries
            out["dirty_entries"] = len(entries)
            if entries:
                self.gaps.add("source_worktree_dirty")
        return out

    def runner(self):
        out = {}
        for name, key in RUNNER_FIELDS:
            value = self.host.env(name)
            if value is None:
                out[key] = "unavailable"
                self.miss(f"env_{key}", "unavailable")  # required provenance, not a determinate absence
            elif (type(value) is str and len(value) <= ENV_VALUE_MAX and ENV_PATTERNS[name].fullmatch(value)
                  and value not in READ_KINDS):  # an observed value never equals an unknown token
                out[key] = value
            else:
                out[key] = "malformed"
                self.miss(f"env_{key}", "malformed")
        if out["image_os"] not in ("unavailable", "malformed", "ubuntu24"):
            self.gaps.add("image_os_not_ubuntu24")
        return out

    def kernel(self):
        value, kind = self.attempt("kernel", self.host.uname, absent_is_fact=False)
        if value is None:
            return {"sysname": kind, "release": kind, "machine": kind}
        sysname, release, machine = value
        if not isinstance(release, str) or not KERNEL_RELEASE.fullmatch(release):
            self.miss("kernel_release", "malformed")
            release = "malformed"
        return {"sysname": _enum(sysname, ("Linux",)), "release": release, "machine": _enum(machine, ("x86_64",))}

    def cpu(self):
        online, kind = self.attempt("cpu_online", self.host.cpu_online, absent_is_fact=False)
        if online is None:
            return {"online": kind}
        if not isinstance(online, int) or isinstance(online, bool) or not 0 < online < 65536:
            self.miss("cpu_online", "malformed")
            return {"online": "malformed"}
        return {"online": online}

    def os_release(self):
        empty = {"state": None, "id": None, "version_id": None, "point_version": None, "codename": None}
        data, kind = self.read("os_release", "/etc/os-release", SMALL_READ_CAP, absent_is_fact=False)
        if data is None:
            return dict(empty, state=kind)
        lines, bad = self.parse("os_release", _lines, data, "utf-8", 4096, 4096)
        if lines is None:
            return dict(empty, state=bad)
        fields = {}
        for line in lines:
            if "=" not in line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            if key in ("ID", "VERSION_ID", "VERSION_CODENAME", "VERSION"):
                fields[key] = value.strip().strip('"').strip("'")
        patterns = {"ID": r"[a-z0-9._-]{1,32}", "VERSION_ID": r"[0-9]{1,4}(\.[0-9]{1,4}){0,3}",
                    "VERSION_CODENAME": r"[a-z0-9]{1,32}"}
        for key, pattern in patterns.items():
            value = fields.get(key)
            if value is None and key in ("ID", "VERSION_ID"):
                self.miss("os_release", "unrecognized")
                return dict(empty, state="unrecognized")
            if value is not None and (not re.fullmatch(pattern, value) or value in READ_KINDS):
                self.miss("os_release", "malformed")
                return dict(empty, state="malformed")
        point = re.match(r"([0-9]{1,4}\.[0-9]{1,4}(?:\.[0-9]{1,4})?)", fields.get("VERSION", ""))
        result = {"state": "observed", "id": fields["ID"], "version_id": fields["VERSION_ID"],
                  "point_version": point.group(1) if point else None, "codename": fields.get("VERSION_CODENAME")}
        if result["id"] != "ubuntu" or result["version_id"] != "24.04":
            self.gaps.add("os_not_ubuntu_24_04")
        return result

    def system_manager(self):
        out = {"pid1_comm": None, "systemctl_major": None, "systemctl_version": None, "manager_version": None}
        data, kind = self.read("pid1_comm", "/proc/1/comm", 64, absent_is_fact=False)
        if data is not None:
            name = data.decode("ascii", "replace").strip()
            if re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", name):
                out["pid1_comm"] = _enum(name, PID1_NAMES)
                if out["pid1_comm"] != "systemd":
                    self.gaps.add("pid1_not_systemd")
            else:
                self.miss("pid1_comm", "malformed")
                out["pid1_comm"] = "malformed"
        else:
            out["pid1_comm"] = kind
        text, kind = self.command_value("systemctl_version")
        if text is not None:
            match = re.fullmatch(r"systemd ([0-9]{1,4}) \(([^()\s]{1,64})\)", text.split("\n")[0])
            if match and VERSION_TOKEN.fullmatch(match.group(2)):
                out["systemctl_major"], out["systemctl_version"] = int(match.group(1)), match.group(2)
            else:
                self.miss("systemctl_version", "malformed")
                kind = "malformed"
        if kind is not None:
            out["systemctl_major"] = out["systemctl_version"] = kind
        text, kind = self.command_value("systemd_manager_version")
        if text is not None:
            match = re.fullmatch(r"Version=([^\s]{1,64})\n?", text)
            if match and VERSION_TOKEN.fullmatch(match.group(1)):
                out["manager_version"] = match.group(1)
            else:
                self.miss("systemd_manager_version", "malformed")
                kind = "malformed"
        if kind is not None:
            out["manager_version"] = kind
        return out

    def _resolve(self, area, mounts, path):
        if mounts is None:
            self.miss(area, "unavailable")
            return None, "unavailable"
        return self.parse(area, resolve_visible_entry, mounts, path)

    def cgroup(self, mounts):
        out = {"mount_state": None, "filesystem": None, "mount_point_is_target": None, "unified": None,
               "root_controllers": None, "self": None}
        entry, kind = self._resolve("cgroup_mount", mounts, CGROUP_MOUNT)
        cgroup_root_ok = False
        if entry is None:
            out["mount_state"] = kind
        else:
            out["mount_state"] = "resolved"
            out["filesystem"] = _enum(entry["fstype"], FSTYPES)
            out["mount_point_is_target"] = entry["mount_point"] == CGROUP_MOUNT
            out["unified"] = entry["fstype"] == "cgroup2" and out["mount_point_is_target"]
            cgroup_root_ok = out["unified"] and entry["root"] == "/"
            if not out["unified"]:
                self.gaps.add("cgroup_not_unified")
        data, kind = self.read("root_controllers", f"{CGROUP_MOUNT}/cgroup.controllers", SMALL_READ_CAP)
        if data is not None:
            controllers, bad = self.parse("root_controllers", _controllers, data)
            out["root_controllers"] = controllers if controllers is not None else bad
        else:
            out["root_controllers"] = kind
        if isinstance(out["root_controllers"], list) or out["root_controllers"] == "absent":
            present = out["root_controllers"] if isinstance(out["root_controllers"], list) else []
            for name in REQUIRED_CONTROLLERS:
                if name not in present:
                    self.gaps.add(f"cgroup_controller_missing:{name}")
        out["self"] = self._self_cgroup(cgroup_root_ok, out["mount_state"])
        return out

    def _self_cgroup(self, cgroup_root_ok, mount_state):
        out = {"state": None, "v1_entries": None, "depth": None, "path_class": None, "leaf_suffix": None,
               "path_sha256": None, "cgroup_kill_present": None, "controllers": None, "subtree_control": None}
        data, kind = self.read("self_cgroup", "/proc/self/cgroup", SMALL_READ_CAP, absent_is_fact=False)
        if data is None:
            return dict(out, state=kind)
        lines, bad = self.parse("self_cgroup", _lines, data, "ascii", 256, 4096)
        if lines is None:
            return dict(out, state=bad)
        # Every record is validated (framing, grammar, bounds, uniqueness) before any count or derivation.
        bad, v1_entries, parts = _parse_self_cgroup(lines)
        if bad is not None:
            self.miss("self_cgroup", bad)
            return dict(out, state=bad)
        path = "/" + "/".join(parts)
        top = parts[0] if parts else ""
        leaf = parts[-1] if parts else ""
        suffix = next((s for s in ("service", "scope", "slice") if leaf.endswith("." + s)), "none" if not parts else "other")
        out.update({"state": "observed", "v1_entries": v1_entries, "depth": len(parts),
                    "path_class": "root" if not parts else _enum(top, ("system.slice", "user.slice", "init.scope")),
                    "leaf_suffix": suffix, "path_sha256": hashlib.sha256(path.encode()).hexdigest()})
        if not cgroup_root_ok:
            # The own-cgroup files are addressable under /sys/fs/cgroup only when the visible mount there
            # is the unified hierarchy mounted at its root; otherwise the mapping is not established.
            kind = "ambiguous" if mount_state == "resolved" else "unavailable"
            self.miss("self_cgroup_files", kind)
            out.update({"cgroup_kill_present": kind, "controllers": kind, "subtree_control": kind})
            return out
        base = CGROUP_MOUNT + ("/" + "/".join(parts) if parts else "")
        _, kind = self.attempt("self_cgroup_kill", self.host.stat, base + "/cgroup.kill")
        out["cgroup_kill_present"] = True if kind is None else (False if kind == "absent" else kind)
        if out["cgroup_kill_present"] is False:
            self.gaps.add("self_cgroup_kill_absent")
        for leaf_name, key in (("cgroup.controllers", "controllers"), ("cgroup.subtree_control", "subtree_control")):
            value, failure = self.read(f"self_{key}", f"{base}/{leaf_name}", SMALL_READ_CAP)
            if value is None:
                out[key] = failure
                continue
            controllers, bad = self.parse(f"self_{key}", _controllers, value)
            out[key] = controllers if controllers is not None else bad
        return out

    def binaries(self):
        out = {"scope": "first_existing_entry_in_fixed_directories", "tools": {}}
        for tool in TOOLS:
            out["tools"][tool] = self._binary(tool)
            if out["tools"][tool]["state"] in ("absent", "first_entry_not_regular", "dangling_symlink",
                                               "outside_fixed_roots"):
                self.gaps.add(f"tool_not_found_in_fixed_dirs:{tool}")
        return out

    def _binary(self, tool):
        area = f"binary:{tool}"
        base = {"state": None, "dir_index": None, "via_symlink": None, "size": None, "sha256": None, "mode": None,
                "uid": None, "setuid": None, "any_execute_bit": None, "file_capability": None}
        for index, directory in enumerate(TOOL_DIRS):
            candidate = f"{directory}/{tool}"
            link, kind = self.attempt(area, self.host.stat, candidate, False)
            if kind == "absent":
                continue
            if link is None:
                return dict(base, state=kind)
            base["dir_index"] = index
            real, kind = self.attempt(area, self.host.realpath, candidate)
            if kind == "absent":
                return dict(base, state="dangling_symlink", via_symlink=True)
            if real is None:
                return dict(base, state=kind)
            via_symlink = stat.S_ISLNK(link.st_mode) or real != candidate
            base["via_symlink"] = via_symlink
            if not real.startswith(TOOL_REAL_ROOTS) or ".." in real.split("/"):
                return dict(base, state="outside_fixed_roots")
            info, kind = self.attempt(area, self.host.stat, real)
            if kind == "absent":
                return dict(base, state="dangling_symlink")
            if info is None:
                return dict(base, state=kind)
            if not stat.S_ISREG(info.st_mode):
                return dict(base, state="first_entry_not_regular")
            hashed, kind = self.attempt(area, self.host.hash_file, real, HASH_FILE_CAP, self.budget,
                                        absent_is_fact=False)
            if hashed is None:
                return dict(base, state=kind)
            capability, kind = self.attempt(area, self.host.has_capability_xattr, real, self.budget,
                                            absent_is_fact=False)
            digest, size = hashed
            return dict(base, state="found_regular", size=size, sha256=digest, mode=_octal_mode(info.st_mode),
                        uid=int(info.st_uid), setuid=bool(info.st_mode & stat.S_ISUID),
                        any_execute_bit=bool(info.st_mode & 0o111),
                        file_capability=capability if kind is None else kind)
        return dict(base, state="absent")

    def userns(self):
        out = {}
        for name, path, high in (("unprivileged_userns_clone", "/proc/sys/kernel/unprivileged_userns_clone", 1),
                                 ("apparmor_restrict_unprivileged_userns",
                                  "/proc/sys/kernel/apparmor_restrict_unprivileged_userns", 1),
                                 ("max_user_namespaces", "/proc/sys/user/max_user_namespaces", 2 ** 31)):
            data, kind = self.read(name, path, 64)
            if data is None:
                out[name] = kind
                continue
            value, bad = self.parse(name, _int_text, data, 0, high)
            out[name] = value if value is not None else bad
        if out.get("apparmor_restrict_unprivileged_userns") == 1:
            self.gaps.add("userns_restricted_by_apparmor")
        if out.get("unprivileged_userns_clone") == 0:
            self.gaps.add("unprivileged_userns_clone_disabled")
        if out.get("max_user_namespaces") == 0:
            self.gaps.add("user_namespaces_disabled")
        return out

    def apparmor(self):
        out = {"enabled": None, "profiles": {}, "loaded_profile_count": None, "loaded_rootlesskit_mode": None}
        data, kind = self.read("apparmor_enabled", "/sys/module/apparmor/parameters/enabled", 16)
        if data is None:
            out["enabled"] = kind
        else:
            value = data.decode("ascii", "replace").strip()
            if value in ("Y", "N"):
                out["enabled"] = value
            else:
                self.miss("apparmor_enabled", "malformed")
                out["enabled"] = "malformed"
        for path in APPARMOR_PROFILES:
            area = f"apparmor_profile:{path.rsplit('/', 1)[1]}"
            data, kind = self.read(area, path, SMALL_READ_CAP)
            item = {"state": kind, "size": None, "sha256": None, "lexical_userns_rule_hint": None,
                    "lexical_unconfined_flag_hint": None}
            if data is not None:
                text = data.decode("utf-8", "replace")
                item.update({"state": "present", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                             "lexical_userns_rule_hint": bool(re.search(r"^\s*userns\s*,", text, re.M)),
                             "lexical_unconfined_flag_hint": bool(
                                 re.search(r"flags\s*=\s*\([^)]*\bunconfined\b", text))})
            out["profiles"][path] = item
        # The loaded-policy list is commonly root-only. A denial is recorded as the observed query outcome,
        # but the policy content is then unknown, so the observation is incomplete (no exception).
        data, kind = self.read("apparmor_loaded", "/sys/kernel/security/apparmor/profiles", PROFILE_LIST_CAP)
        if data is None:
            out["loaded_profile_count"] = out["loaded_rootlesskit_mode"] = kind
            return out
        parsed, bad = self.parse("apparmor_loaded", parse_apparmor_loaded, data)
        if parsed is None:
            out["loaded_profile_count"] = out["loaded_rootlesskit_mode"] = bad
        else:
            out["loaded_profile_count"], out["loaded_rootlesskit_mode"] = parsed
        return out

    def local_groups(self):
        data, kind = self.read("etc_group", "/etc/group", ACCOUNT_FILE_CAP, absent_is_fact=False)
        if data is None:
            return None, kind
        return self.parse("etc_group", parse_group_file, data, PRIVILEGED_GROUPS)

    def identity(self, groups_file):
        groups_db, groups_kind = groups_file
        out = {"scope": "process_credentials_and_local_etc_group", "uid": None, "euid": None, "gid": None,
               "groups": None, "groups_total": None, "groups_truncated": None, "is_root": None,
               "docker_group_local": None, "in_docker_group": None}
        value, kind = self.attempt("identity", self.host.identity, absent_is_fact=False)
        if value is None:
            return dict(out, uid=kind)
        uid, euid, gid, groups = value
        ids = [uid, euid, gid]
        if (not isinstance(groups, (list, tuple)) or len(groups) > MAX_PROCESS_GROUPS
                or not all(isinstance(g, int) and not isinstance(g, bool) and 0 <= g < 2 ** 32 for g in [*ids, *groups])):
            self.miss("identity", "malformed")
            return dict(out, uid="malformed")
        full = set(groups) | {gid}  # membership is computed from the full list before output truncation
        ordered = sorted(full)
        out.update({"uid": uid, "euid": euid, "gid": gid, "groups": ordered[:EMITTED_GROUPS],
                    "groups_total": len(ordered), "groups_truncated": len(ordered) > EMITTED_GROUPS,
                    "is_root": euid == 0})
        if groups_db is None:
            out["docker_group_local"] = out["in_docker_group"] = groups_kind
        elif "docker" not in groups_db:
            out["docker_group_local"] = "absent"
        else:
            out["docker_group_local"] = "present"
            out["in_docker_group"] = groups_db["docker"][0] in full
        return out

    def sudo(self):
        """``state`` is the classified query outcome; ``rule_facts`` says where the rule facts come from.

        * ``from_listing``: a fully recognized listing; ``rule_lines``/``nopasswd_all_rule_listed`` set.
        * ``sudo_reported_no_permission``: a narrower determinate negative. sudo itself answered with its
          explicit no-permission sentence; no listing exists, so the two rule fields stay null.
        * ``not_applicable_tool_absent``: no ``/usr/bin/sudo`` to ask.
        * unknown (``unavailable`` for ``password_required``, otherwise the query's unknown kind): the
          rule facts were not obtained, so a ``sudo_rules`` reason is recorded and the run is incomplete.
          The classified ``state`` is kept as useful partial data. Nothing is retried or escalated.
        """
        out = {"scope": "recognized_listing_not_effective_policy", "state": None, "rule_facts": None,
               "rule_lines": None, "nopasswd_all_rule_listed": None}
        result = self.run("sudo_list")
        if result.state == "tool_absent":
            return dict(out, state="tool_absent", rule_facts="not_applicable_tool_absent")
        if result.state == "nonzero_exit":
            if result.stderr_class == "not_permitted":
                return dict(out, state="not_permitted", rule_facts="sudo_reported_no_permission")
            if not result.stdout_truncated and _NOT_ALLOWED_STDOUT.fullmatch(result.stdout.decode("utf-8", "replace")):
                return dict(out, state="not_permitted", rule_facts="sudo_reported_no_permission")
            if result.stderr_class == "password_required":
                self.miss("sudo_rules", "unavailable")  # the query outcome is known; the listing is not
                return dict(out, state="password_required", rule_facts="unavailable")
            self.miss("sudo_list", "unrecognized")
            return dict(out, state="unrecognized", rule_facts="unrecognized")
        if result.state != "ok":
            self.miss("sudo_list", result.state)
            return dict(out, state="command_failed", rule_facts="command_failed")
        parsed, bad = self.parse("sudo_list", parse_sudo_listing, result.stdout)
        if parsed is None:
            return dict(out, state=bad, rule_facts=bad)
        return dict(out, state="listed", rule_facts="from_listing", **parsed)

    def _ranges(self, area, path, account, uid):
        out = {"state": None, "entries": None, "start": None, "count": None, "sufficient": None,
               "overlaps_other": None}
        data, kind = self.read(area, path, ID_MAP_CAP)
        if data is None:
            return dict(out, state=kind)
        lines, bad = self.parse(area, _lines, data, "ascii", MAX_LINES, 256)
        if lines is None:
            return dict(out, state=bad)
        mine, others = [], []
        for line in lines:
            if not line or line.startswith("#"):
                continue
            if line.count(":") != 2:  # field count before the split
                self.miss(area, "malformed")
                return dict(out, state="malformed")
            parts = line.split(":")
            if (len(parts) != 3 or not ACCOUNT_NAME.fullmatch(parts[0]) or not parts[1].isdigit()
                    or not parts[2].isdigit() or len(parts[1]) > 10 or len(parts[2]) > 10):
                self.miss(area, "malformed")
                return dict(out, state="malformed")
            item = (int(parts[1]), int(parts[2]))
            (mine if parts[0] == account or (uid is not None and parts[0] == str(uid)) else others).append(item)
        if not mine:
            return dict(out, state="observed", entries=0)
        start, count = mine[0]
        overlap = any(start < o_start + o_count and o_start < start + count for o_start, o_count in others)
        return dict(out, state="observed", entries=len(mine), start=start, count=count,
                    sufficient=count >= MIN_ID_RANGE, overlaps_other=overlap)

    def proposed_identity(self, groups_file):
        groups_db, groups_kind = groups_file
        out = {"name": PROPOSED_IDENTITY, "scope": "local_etc_passwd_and_group", "account": None, "uid": None,
               "gid": None, "login_shell": None, "privileged_groups": None, "privileged_groups_state": None}
        data, kind = self.read("etc_passwd", "/etc/passwd", ACCOUNT_FILE_CAP, absent_is_fact=False)
        account = None
        if data is None:
            out["account"] = kind
        else:
            account, bad = self.parse("etc_passwd", parse_passwd_file, data, PROPOSED_IDENTITY)
            out["account"] = bad if bad is not None else ("absent" if account is None else "present")
        uid = None
        if out["account"] == "absent":
            self.gaps.add("proposed_identity_absent")
        elif account is not None:
            uid, gid, shell = account
            out["uid"], out["gid"] = uid, gid
            out["login_shell"] = "nologin" if shell.rsplit("/", 1)[-1] in ("nologin", "false") else "login"
            if out["login_shell"] == "login":
                self.gaps.add("proposed_identity_login_shell")
            if groups_db is None:
                out["privileged_groups_state"] = groups_kind
            else:
                out["privileged_groups_state"] = "observed"
                out["privileged_groups"] = [name for name in PRIVILEGED_GROUPS if name in groups_db and (
                    groups_db[name][0] == gid or PROPOSED_IDENTITY in groups_db[name][1])]
                if out["privileged_groups"]:
                    self.gaps.add("proposed_identity_privileged_group")
        for kind_name in ("subuid", "subgid"):
            ranges = self._ranges(kind_name, f"/etc/{kind_name}", PROPOSED_IDENTITY, uid)
            out[kind_name] = ranges
            if out["account"] not in ("present", "absent"):
                continue  # a numeric-UID entry cannot be matched while the account is unknown: no gap
            if ranges["state"] == "absent" or ranges["entries"] == 0:
                self.gaps.add(f"proposed_identity_{kind_name}_absent")
            elif ranges["state"] == "observed":
                if ranges["entries"] > 1:
                    self.gaps.add(f"proposed_identity_{kind_name}_multiple_entries")
                if not ranges["sufficient"]:
                    self.gaps.add(f"proposed_identity_{kind_name}_too_small")
                if ranges["overlaps_other"]:
                    self.gaps.add(f"proposed_identity_{kind_name}_overlap")
        return out

    def mounts(self):
        data, _ = self.read("mountinfo", "/proc/self/mountinfo", MOUNTINFO_CAP, absent_is_fact=False)
        if data is None:
            return None
        entries, _ = self.parse("mountinfo", parse_mountinfo, data)
        return entries

    def filesystems(self, mounts):
        out = {}
        for target in FILESYSTEM_TARGETS:
            item = {"exists": None, "type": None, "realpath_is_target": None, "mount_state": None,
                    "mount_point": None, "mount_point_is_target": None, "fstype": None, "propagation": None,
                    **{flag: None for flag in MOUNT_FLAGS}, "space_state": None, "total_bytes": None,
                    "avail_bytes": None, "total_inodes": None, "free_inodes": None, "below_5gib_floor": None}
            out[target] = item
            info, kind = self.attempt(f"filesystem:{target}", self.host.stat, target)
            if info is None:
                item["exists"] = False if kind == "absent" else kind
                if kind == "absent":
                    self.gaps.add(f"filesystem_target_absent:{target}")
                continue
            item["exists"], item["type"] = True, _file_type(info.st_mode)
            real, kind = self.attempt(f"filesystem:{target}", self.host.realpath, target, absent_is_fact=False)
            if real is None:
                item["mount_state"] = item["space_state"] = kind
                continue
            item["realpath_is_target"] = real == target
            entry, kind = self._resolve(f"mount:{target}", mounts, real)
            if entry is None:
                item["mount_state"] = kind
            else:
                item.update({"mount_state": "resolved", "mount_point": _enum(entry["mount_point"], MOUNT_POINTS),
                             "mount_point_is_target": entry["mount_point"] == real,
                             "fstype": _enum(entry["fstype"], FSTYPES), "propagation": entry["propagation"],
                             **{flag: entry["access"] == flag for flag in ACCESS_FLAGS},
                             **{flag: (flag in entry["options"]) if entry["options_state"] == "observed"
                                else entry["options_state"] for flag in OPTION_FLAGS}})
                if entry["propagation"] in UNKNOWN:
                    self.miss(f"mount_propagation:{target}", entry["propagation"])
                if entry["options_state"] in UNKNOWN:
                    self.miss(f"mount_options:{target}", entry["options_state"])
            vfs, kind = self.attempt(f"statvfs:{target}", self.host.statvfs, target, absent_is_fact=False)
            if vfs is None:
                item["space_state"] = kind
                continue
            item.update({"space_state": "observed", "total_bytes": vfs.f_blocks * vfs.f_frsize,
                         "avail_bytes": vfs.f_bavail * vfs.f_frsize, "total_inodes": vfs.f_files,
                         "free_inodes": vfs.f_favail})
            item["below_5gib_floor"] = item["avail_bytes"] < FREE_FLOOR_BYTES
        if out["/home/runner/work"]["below_5gib_floor"]:
            self.gaps.add("work_free_bytes_below_5gib")
        return out

    def shared_endpoints(self):
        out = {}
        for path in SHARED_ENDPOINTS:
            item = {"state": None, "type": None, "uid": None, "gid": None, "mode": None, "symlink": None}
            out[path] = item
            link, kind = self.attempt(f"endpoint:{path}", self.host.stat, path, False)
            if link is None:
                item["state"] = kind
                continue
            info, kind = self.attempt(f"endpoint:{path}", self.host.stat, path)
            item["symlink"] = stat.S_ISLNK(link.st_mode)
            if info is None:
                item["state"] = "dangling_symlink" if kind == "absent" else kind
                continue
            item.update({"state": "present", "type": _file_type(info.st_mode), "uid": int(info.st_uid),
                         "gid": int(info.st_gid), "mode": _octal_mode(info.st_mode)})
            self.gaps.add("shared_docker_endpoint_present")
        return out


def _base(observation: str) -> dict:
    return {"schema": SCHEMA, "runtime_qualified": False, "verdict": "UNPROVEN", "b0_effect": "none",
            "observation": observation, "limits": list(LIMITS)}


def _refusal(host, argv) -> str | None:
    if argv:
        return "arguments_refused"
    system, machine = host.platform()
    if system != "linux" or machine != "x86_64":
        return "unsupported_platform"
    if host.env("GITHUB_ACTIONS") != "true" or host.env("RUNNER_ENVIRONMENT") != "github-hosted":
        return "not_github_hosted"
    if tuple(host.python_version()[:2]) < MIN_PYTHON:
        return "unsupported_python"
    return None


FACT_SECTIONS = ("python", "source", "runner", "kernel", "os_release", "cpu", "system_manager", "cgroup", "binaries",
                 "userns", "apparmor", "identity", "sudo", "proposed_identity", "filesystems", "shared_endpoints")


def _unknown_values(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _unknown_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _unknown_values(item)
    elif isinstance(value, str) and value in UNKNOWN:
        yield value


class _Contract:
    """Structural completion check of every required fact, independent of the producers.

    For each fact: an observed value passes; ``absent`` passes only where documented; an unknown token
    needs an ``incomplete_reasons`` entry in one of the fact's own areas; null passes only where the
    fact's controlling state says it was not applicable (``null_ok``). Anything else is a violation.
    """

    def __init__(self, reasons):
        self.reasons = tuple(reasons)
        self.violations: list = []

    def fact(self, path, value, areas, absent_ok=False, null_ok=False):
        if value is None:
            if not null_ok:
                self.violations.append(f"{path}:undetermined")
        elif type(value) is str and value in UNKNOWN:
            if not any(reason.startswith(area + ":") for reason in self.reasons for area in areas):
                self.violations.append(f"{path}:unknown_without_reason")
        elif type(value) is str and value == "absent" and not absent_ok:
            self.violations.append(f"{path}:absent_not_a_fact")

    def dependents(self, section, keys, applicable, areas, path):
        for key in keys:
            self.fact(f"{path}.{key}", section.get(key), areas, null_ok=not applicable)


def _fact_contract_violations(report: dict, reasons) -> list:
    k = _Contract(reasons)
    f = k.fact
    f("python.implementation", report["python"]["implementation"], ())
    f("python.version", report["python"]["version"], ())
    src = report["source"]
    f("source.head", src["head"], ("git_identity",))
    f("source.tree", src["tree"], ("git_identity",))
    f("source.worktree_clean", src["worktree_clean"], ("git_status",))
    f("source.dirty_entries", src["dirty_entries"], ("git_status",), null_ok=type(src["worktree_clean"]) is not bool)
    for _, key in RUNNER_FIELDS:
        f(f"runner.{key}", report["runner"][key], (f"env_{key}",))
    for key in ("sysname", "release", "machine"):
        f(f"kernel.{key}", report["kernel"][key], ("kernel", "kernel_release"))
    osr = report["os_release"]
    f("os_release.state", osr["state"], ("os_release",))
    observed = osr["state"] == "observed"
    k.dependents(osr, ("id", "version_id"), observed, ("os_release",), "os_release")
    for key in ("point_version", "codename"):  # optional os-release fields: null is "not listed"
        f(f"os_release.{key}", osr[key], ("os_release",), null_ok=True)
    f("cpu.online", report["cpu"]["online"], ("cpu_online",))
    sm = report["system_manager"]
    f("system_manager.pid1_comm", sm["pid1_comm"], ("pid1_comm",))
    f("system_manager.systemctl_major", sm["systemctl_major"], ("systemctl_version",))
    f("system_manager.systemctl_version", sm["systemctl_version"], ("systemctl_version",))
    f("system_manager.manager_version", sm["manager_version"], ("systemd_manager_version",))
    cg = report["cgroup"]
    f("cgroup.mount_state", cg["mount_state"], ("cgroup_mount",))
    k.dependents(cg, ("filesystem", "mount_point_is_target", "unified"), cg["mount_state"] == "resolved",
                 ("cgroup_mount",), "cgroup")
    f("cgroup.root_controllers", cg["root_controllers"], ("root_controllers",), absent_ok=True)
    me = cg["self"]
    f("cgroup.self.state", me["state"], ("self_cgroup",))
    mine = me["state"] == "observed"
    k.dependents(me, ("v1_entries", "depth", "path_class", "leaf_suffix", "path_sha256"), mine, ("self_cgroup",),
                 "cgroup.self")
    f("cgroup.self.cgroup_kill_present", me["cgroup_kill_present"], ("self_cgroup_kill", "self_cgroup_files"),
      null_ok=not mine)
    for key in ("controllers", "subtree_control"):
        f(f"cgroup.self.{key}", me[key], (f"self_{key}", "self_cgroup_files"), absent_ok=True, null_ok=not mine)
    for tool, item in report["binaries"]["tools"].items():
        area = (f"binary:{tool}",)
        f(f"binaries.{tool}.state", item["state"], area, absent_ok=True)
        found = item["state"] == "found_regular"
        k.dependents(item, ("dir_index", "via_symlink", "size", "sha256", "mode", "uid", "setuid", "any_execute_bit",
                            "file_capability"), found, area, f"binaries.{tool}")
    for key, value in report["userns"].items():
        f(f"userns.{key}", value, (key,), absent_ok=True)
    aa = report["apparmor"]
    f("apparmor.enabled", aa["enabled"], ("apparmor_enabled",), absent_ok=True)
    for path, item in aa["profiles"].items():
        area = (f"apparmor_profile:{path.rsplit('/', 1)[1]}",)
        f(f"apparmor.profiles.{path}.state", item["state"], area, absent_ok=True)
        k.dependents(item, ("size", "sha256", "lexical_userns_rule_hint", "lexical_unconfined_flag_hint"),
                     item["state"] == "present", area, f"apparmor.profiles.{path}")
    f("apparmor.loaded_profile_count", aa["loaded_profile_count"], ("apparmor_loaded",), absent_ok=True)
    f("apparmor.loaded_rootlesskit_mode", aa["loaded_rootlesskit_mode"], ("apparmor_loaded",), absent_ok=True)
    ident = report["identity"]
    f("identity.uid", ident["uid"], ("identity",))
    creds = type(ident["uid"]) is int
    k.dependents(ident, ("euid", "gid", "groups", "groups_total", "groups_truncated", "is_root"), creds, ("identity",),
                 "identity")
    f("identity.docker_group_local", ident["docker_group_local"], ("etc_group",), absent_ok=True, null_ok=not creds)
    f("identity.in_docker_group", ident["in_docker_group"], ("etc_group",),
      null_ok=ident["docker_group_local"] != "present")
    sudo = report["sudo"]
    f("sudo.state", sudo["state"], ("sudo_list",))
    f("sudo.rule_facts", sudo["rule_facts"], ("sudo_list", "sudo_rules"))
    expected = {"listed": "from_listing", "not_permitted": "sudo_reported_no_permission",
                "tool_absent": "not_applicable_tool_absent", "password_required": "unavailable"}
    if sudo["state"] in expected and sudo["rule_facts"] != expected[sudo["state"]]:
        k.violations.append("sudo.rule_facts:inconsistent_with_state")
    k.dependents(sudo, ("rule_lines", "nopasswd_all_rule_listed"), sudo["rule_facts"] == "from_listing",
                 ("sudo_list",), "sudo")
    pi = report["proposed_identity"]
    f("proposed_identity.account", pi["account"], ("etc_passwd",), absent_ok=True)
    present = pi["account"] == "present"
    k.dependents(pi, ("uid", "gid", "login_shell"), present, ("etc_passwd",), "proposed_identity")
    f("proposed_identity.privileged_groups_state", pi["privileged_groups_state"], ("etc_group",), null_ok=not present)
    f("proposed_identity.privileged_groups", pi["privileged_groups"], ("etc_group",),
      null_ok=pi["privileged_groups_state"] != "observed")
    for key in ("subuid", "subgid"):
        rng = pi[key]
        f(f"proposed_identity.{key}.state", rng["state"], (key,), absent_ok=True)
        f(f"proposed_identity.{key}.entries", rng["entries"], (key,), null_ok=rng["state"] != "observed")
        k.dependents(rng, ("start", "count", "sufficient", "overlaps_other"),
                     rng["state"] == "observed" and bool(rng["entries"]), (key,), f"proposed_identity.{key}")
    for target, item in report["filesystems"].items():
        base = (f"filesystem:{target}",)
        f(f"filesystems.{target}.exists", item["exists"], base)
        exists = item["exists"] is True
        k.dependents(item, ("type",), exists, base, f"filesystems.{target}")
        f(f"filesystems.{target}.mount_state", item["mount_state"], (f"mount:{target}", *base), null_ok=not exists)
        f(f"filesystems.{target}.space_state", item["space_state"], (f"statvfs:{target}", *base), null_ok=not exists)
        f(f"filesystems.{target}.realpath_is_target", item["realpath_is_target"], base,
          null_ok=not exists or item["mount_state"] in UNKNOWN)
        resolved = item["mount_state"] == "resolved"
        k.dependents(item, ("mount_point", "mount_point_is_target", "fstype", *ACCESS_FLAGS), resolved,
                     (f"mount:{target}",), f"filesystems.{target}")
        if resolved and not (type(item["ro"]) is bool and type(item["rw"]) is bool and item["ro"] != item["rw"]):
            k.violations.append(f"filesystems.{target}:access_mode_not_exactly_one")
        k.dependents(item, OPTION_FLAGS, resolved, (f"mount_options:{target}",), f"filesystems.{target}")
        f(f"filesystems.{target}.propagation", item["propagation"], (f"mount_propagation:{target}",),
          null_ok=not resolved)
        k.dependents(item, ("total_bytes", "avail_bytes", "total_inodes", "free_inodes", "below_5gib_floor"),
                     item["space_state"] == "observed", (f"statvfs:{target}",), f"filesystems.{target}")
    for path, item in report["shared_endpoints"].items():
        area = (f"endpoint:{path}",)
        f(f"shared_endpoints.{path}.state", item["state"], area, absent_ok=True)
        k.dependents(item, ("type", "uid", "gid", "mode"), item["state"] == "present", area, f"shared_endpoints.{path}")
        f(f"shared_endpoints.{path}.symlink", item["symlink"], area,
          null_ok=item["state"] not in ("present", "dangling_symlink"))
    return k.violations


def collect(host, argv=(), timing=None) -> tuple[dict, dict]:
    """Return (report, command summaries). Refusal happens before any host file read or command.

    ``timing`` (optional dict) receives the cooperative deadline so finalization can be postchecked.
    """
    reason = _refusal(host, list(argv))
    if reason is not None:
        report = _base("refused")
        report["refusal"] = reason
        return report, {}
    c = _Collector(host)
    version = host.python_version()
    report = _base("incomplete")
    report["python"] = {"implementation": "cpython" if sys.implementation.name == "cpython" else "other",
                        "version": ".".join(str(int(part)) for part in version[:3])}
    report["source"] = c.source()
    report["runner"] = c.runner()
    report["kernel"] = c.kernel()
    report["os_release"] = c.os_release()
    report["cpu"] = c.cpu()
    report["system_manager"] = c.system_manager()
    mounts = c.mounts()
    report["cgroup"] = c.cgroup(mounts)
    report["binaries"] = c.binaries()
    report["userns"] = c.userns()
    report["apparmor"] = c.apparmor()
    groups_file = c.local_groups()
    report["identity"] = c.identity(groups_file)
    report["sudo"] = c.sudo()
    report["proposed_identity"] = c.proposed_identity(groups_file)
    report["filesystems"] = c.filesystems(mounts)
    report["shared_endpoints"] = c.shared_endpoints()
    # Finalization postcheck: facts gathered after the cooperative deadline are never complete.
    now = host.monotonic()
    if now > c.deadline:
        c.miss("finalization", "deadline_overrun")
    if any(True for section in FACT_SECTIONS for _ in _unknown_values(report[section])) and not c.incomplete:
        raise PreflightError("unknown_fact_without_reason")
    violations = _fact_contract_violations(report, c.incomplete)  # full reason set, before truncation
    if any(v.endswith(":unknown_without_reason") for v in violations):
        raise PreflightError("unknown_fact_without_reason")
    if violations:
        raise PreflightError("undetermined_required_fact")
    reasons = sorted(c.incomplete)
    report["incomplete_reasons"] = reasons[:MAX_REASONS]
    report["incomplete_reasons_total"] = len(reasons)
    report["prerequisite_gaps"] = sorted(c.gaps)
    report["accounting"] = {"read_bytes_cap": READ_AGGREGATE_CAP, "read_bytes_delivered": c.budget.delivered_bytes,
                            "read_calls": c.budget.read_calls, "deadline_ms": int(AGGREGATE_DEADLINE_S * 1000),
                            "elapsed_ms": int(max(0.0, now - c.started) * 1000),
                            "deadline_overrun": now > c.deadline}
    report["observation"] = "incomplete" if c.incomplete else "complete"
    if timing is not None:
        timing["deadline"] = c.deadline
    return report, c.commands


# ---- Closed output schema -------------------------------------------------------------------------
# Each spec is a function (value, ctx, depth, key_len) that raises PreflightError. The context counts
# nodes and a conservative serialized-size estimate *before* json.dumps allocates anything, so the
# allocation is bounded by MAX_OUTPUT_NODES nodes of at most 160-character strings (< REPORT_CAP).

class _Ctx:
    def __init__(self):
        self.nodes = 0
        self.size = 0


def _account(ctx, depth, key_len, value_len):
    ctx.nodes += 1
    ctx.size += key_len + 4 + depth + value_len + 2
    if ctx.nodes > MAX_OUTPUT_NODES:
        raise PreflightError("output_too_many_nodes")
    if ctx.size > REPORT_CAP:
        raise PreflightError("output_oversize")


def S_null(value, ctx, depth, key_len):  # noqa: N802
    if value is not None:
        raise PreflightError("schema_type")
    _account(ctx, depth, key_len, 4)


def S_bool(value, ctx, depth, key_len):
    if type(value) is not bool:
        raise PreflightError("schema_type")
    _account(ctx, depth, key_len, 5)


def S_int(low=0, high=2 ** 63):
    def check(value, ctx, depth, key_len):
        if type(value) is not int or not low <= value <= high:
            raise PreflightError("schema_int")
        _account(ctx, depth, key_len, 20)
    return check


def S_enum(*values):
    allowed = frozenset(values)

    def check(value, ctx, depth, key_len):
        if type(value) is not str or value not in allowed:
            raise PreflightError("schema_enum")
        _account(ctx, depth, key_len, 2 * len(value) + 2)
    return check


def S_re(pattern):
    compiled = re.compile(pattern)

    def check(value, ctx, depth, key_len):
        if type(value) is not str or len(value) > 160 or not SAFE_STRING.fullmatch(value) \
                or not compiled.fullmatch(value):
            raise PreflightError("schema_string")
        _account(ctx, depth, key_len, 2 * len(value) + 2)
    return check


def S_any(*specs):
    def check(value, ctx, depth, key_len):
        for spec in specs:
            trial = _Ctx()
            trial.nodes, trial.size = ctx.nodes, ctx.size
            try:
                spec(value, trial, depth, key_len)
            except PreflightError:
                continue
            ctx.nodes, ctx.size = trial.nodes, trial.size
            return
        raise PreflightError("schema_union")
    return check


def S_list(item, max_len, distinct=False):
    def check(value, ctx, depth, key_len):
        if type(value) is not list or len(value) > max_len:
            raise PreflightError("schema_list")
        _account(ctx, depth, key_len, 2 + depth)
        for element in value:
            item(element, ctx, depth + 1, 0)
        if distinct and len(set(value)) != len(value):
            raise PreflightError("schema_list_duplicate")
    return check


def S_dict(fields: dict, optional=()):
    allowed = frozenset(fields)
    required = allowed - frozenset(optional)

    def check(value, ctx, depth, key_len):
        # Admission before any key work: exact type (no subclass hooks), node count, then cardinality.
        if type(value) is not dict:
            raise PreflightError("schema_dict")
        _account(ctx, depth, key_len, 2 + depth)
        if len(value) > len(allowed):
            raise PreflightError("schema_fields")
        for key in value:  # at most len(allowed) iterations
            if type(key) is not str or key not in allowed:
                raise PreflightError("schema_fields")
        if any(key not in value for key in required):
            raise PreflightError("schema_fields")
        for key in sorted(value):
            fields[key](value[key], ctx, depth + 1, len(key) + 2)
    return check


def _fixed_keys(keys, spec):
    return S_dict({key: spec for key in keys})


U = S_enum(*UNKNOWN)
UA = S_enum("absent", *UNKNOWN)
TOKEN = S_re(VERSION_TOKEN.pattern)
HEX64 = S_re(r"[0-9a-f]{64}")
INT = S_int()
UINT32 = S_int(0, 2 ** 32 - 1)
OPT_BOOL = S_any(S_bool, S_null)


def _true(value, ctx, depth, key_len):
    """Only a delivered capability value is determinate; there is no determinate-absence spelling."""
    if value is not True:
        raise PreflightError("schema_type")
    _account(ctx, depth, key_len, 4)


CONTROLLER_LIST = S_list(S_enum(*CONTROLLERS, "other"), 16, distinct=True)
REASON = S_re(r"[A-Za-z0-9_:./@-]{1,120}")
GAP = S_re(r"[a-z0-9_:./-]{1,96}")

_RANGE = S_dict({"state": S_any(S_enum("observed"), UA), "entries": S_any(S_int(0, MAX_LINES), S_null),
                 "start": S_any(S_int(0, 10 ** 10), S_null), "count": S_any(S_int(0, 10 ** 10), S_null),
                 "sufficient": OPT_BOOL, "overlaps_other": OPT_BOOL})
_TOOL = S_dict({"state": S_any(S_enum("found_regular", "absent", "first_entry_not_regular", "dangling_symlink",
                                      "outside_fixed_roots"), U),
                "dir_index": S_any(S_int(0, len(TOOL_DIRS) - 1), S_null), "via_symlink": OPT_BOOL,
                "size": S_any(S_int(0, HASH_FILE_CAP), S_null), "sha256": S_any(HEX64, S_null),
                "mode": S_any(S_re(r"[0-7]{4}"), S_null), "uid": S_any(UINT32, S_null), "setuid": OPT_BOOL,
                "any_execute_bit": OPT_BOOL, "file_capability": S_any(_true, U, S_null)})
_PROFILE = S_dict({"state": S_any(S_enum("present"), UA), "size": S_any(S_int(0, SMALL_READ_CAP), S_null),
                   "sha256": S_any(HEX64, S_null), "lexical_userns_rule_hint": OPT_BOOL,
                   "lexical_unconfined_flag_hint": OPT_BOOL})
_FILESYSTEM = S_dict({"exists": S_any(S_bool, U), "type": S_any(S_enum(*FILE_TYPES), S_null),
                      "realpath_is_target": OPT_BOOL, "mount_state": S_any(S_enum("resolved"), U, S_null),
                      "mount_point": S_any(S_enum(*MOUNT_POINTS, "other"), S_null), "mount_point_is_target": OPT_BOOL,
                      "fstype": S_any(S_enum(*FSTYPES, "other"), S_null),
                      "propagation": S_any(S_enum(*PROPAGATIONS), U, S_null),
                      **{flag: OPT_BOOL for flag in ACCESS_FLAGS},
                      **{flag: S_any(S_bool, U, S_null) for flag in OPTION_FLAGS}, "space_state": S_any(S_enum("observed"), U, S_null),
                      "total_bytes": S_any(INT, S_null), "avail_bytes": S_any(INT, S_null),
                      "total_inodes": S_any(INT, S_null), "free_inodes": S_any(INT, S_null),
                      "below_5gib_floor": OPT_BOOL})
_ENDPOINT = S_dict({"state": S_any(S_enum("present", "dangling_symlink"), UA),
                    "type": S_any(S_enum(*FILE_TYPES), S_null), "uid": S_any(UINT32, S_null),
                    "gid": S_any(UINT32, S_null), "mode": S_any(S_re(r"[0-7]{4}"), S_null), "symlink": OPT_BOOL})
_SELF_CGROUP = S_dict({"state": S_any(S_enum("observed"), U), "v1_entries": S_any(S_int(0, 256), S_null),
                       "depth": S_any(S_int(0, 16), S_null),
                       "path_class": S_any(S_enum("root", "system.slice", "user.slice", "init.scope", "other"), S_null),
                       "leaf_suffix": S_any(S_enum("service", "scope", "slice", "none", "other"), S_null),
                       "path_sha256": S_any(HEX64, S_null), "cgroup_kill_present": S_any(S_bool, U, S_null),
                       "controllers": S_any(CONTROLLER_LIST, UA, S_null),
                       "subtree_control": S_any(CONTROLLER_LIST, UA, S_null)})
_RUNNER_VALUE = {key: S_any(S_re(ENV_PATTERNS[name].pattern), S_enum("malformed", "unavailable"))
                 for name, key in RUNNER_FIELDS}

def _false(value, ctx, depth, key_len):
    if value is not False:
        raise PreflightError("qualification_claim")
    _account(ctx, depth, key_len, 5)


REPORT_FIELDS = {
    "schema": S_enum(SCHEMA), "runtime_qualified": _false, "verdict": S_enum("UNPROVEN"), "b0_effect": S_enum("none"),
    "observation": S_enum("complete", "incomplete", "refused"), "limits": S_list(S_enum(*LIMITS), len(LIMITS), True),
    "refusal": S_enum("arguments_refused", "unsupported_platform", "not_github_hosted", "unsupported_python"),
    "python": S_dict({"implementation": S_enum("cpython", "other"), "version": S_re(r"[0-9]{1,3}(\.[0-9]{1,4}){2}")}),
    "source": S_dict({"head": S_any(S_re(HEX_OBJECT.pattern), U), "tree": S_any(S_re(HEX_OBJECT.pattern), U),
                      "worktree_clean": S_any(S_bool, U), "dirty_entries": S_any(S_int(0, 10 ** 6), S_null)}),
    "runner": S_dict(_RUNNER_VALUE),
    "kernel": S_dict({"sysname": S_any(S_enum("Linux", "other"), U),
                      "release": S_any(S_re(KERNEL_RELEASE.pattern), U),
                      "machine": S_any(S_enum("x86_64", "other"), U)}),
    "os_release": S_dict({"state": S_any(S_enum("observed"), UA), "id": S_any(S_re(r"[a-z0-9._-]{1,32}"), S_null),
                          "version_id": S_any(S_re(r"[0-9]{1,4}(\.[0-9]{1,4}){0,3}"), S_null),
                          "point_version": S_any(S_re(r"[0-9]{1,4}\.[0-9]{1,4}(\.[0-9]{1,4})?"), S_null),
                          "codename": S_any(S_re(r"[a-z0-9]{1,32}"), S_null)}),
    "cpu": S_dict({"online": S_any(S_int(1, 65535), U)}),
    "system_manager": S_dict({"pid1_comm": S_any(S_enum(*PID1_NAMES, "other"), UA, S_null),
                              "systemctl_major": S_any(S_int(0, 9999), U),
                              "systemctl_version": S_any(TOKEN, U), "manager_version": S_any(TOKEN, U)}),
    "cgroup": S_dict({"mount_state": S_any(S_enum("resolved"), U), "filesystem": S_any(S_enum(*FSTYPES, "other"), S_null),
                      "mount_point_is_target": OPT_BOOL, "unified": OPT_BOOL,
                      "root_controllers": S_any(CONTROLLER_LIST, UA, S_null), "self": _SELF_CGROUP}),
    "binaries": S_dict({"scope": S_enum("first_existing_entry_in_fixed_directories"),
                        "tools": _fixed_keys(TOOLS, _TOOL)}),
    "userns": S_dict({"unprivileged_userns_clone": S_any(S_int(0, 1), UA),
                      "apparmor_restrict_unprivileged_userns": S_any(S_int(0, 1), UA),
                      "max_user_namespaces": S_any(S_int(0, 2 ** 31), UA)}),
    "apparmor": S_dict({"enabled": S_any(S_enum("Y", "N"), UA), "profiles": _fixed_keys(APPARMOR_PROFILES, _PROFILE),
                        "loaded_profile_count": S_any(S_int(0, MAX_LINES), UA),
                        "loaded_rootlesskit_mode": S_any(S_enum(*APPARMOR_MODES, "other"), UA)}),
    "identity": S_dict({"scope": S_enum("process_credentials_and_local_etc_group"), "uid": S_any(UINT32, U, S_null),
                        "euid": S_any(UINT32, S_null), "gid": S_any(UINT32, S_null),
                        "groups": S_any(S_list(UINT32, EMITTED_GROUPS, True), S_null),
                        "groups_total": S_any(S_int(0, MAX_PROCESS_GROUPS + 1), S_null),
                        "groups_truncated": OPT_BOOL, "is_root": OPT_BOOL,
                        "docker_group_local": S_any(S_enum("present"), UA, S_null),
                        "in_docker_group": S_any(S_bool, U, S_null)}),
    "sudo": S_dict({"scope": S_enum("recognized_listing_not_effective_policy"),
                    "state": S_any(S_enum("listed", "password_required", "not_permitted", "tool_absent"), U),
                    "rule_facts": S_any(S_enum("from_listing", "sudo_reported_no_permission",
                                               "not_applicable_tool_absent"), U),
                    "rule_lines": S_any(S_int(0, 4096), S_null), "nopasswd_all_rule_listed": OPT_BOOL}),
    "proposed_identity": S_dict({"name": S_enum(PROPOSED_IDENTITY), "scope": S_enum("local_etc_passwd_and_group"),
                                 "account": S_any(S_enum("present"), UA), "uid": S_any(UINT32, S_null),
                                 "gid": S_any(UINT32, S_null), "login_shell": S_any(S_enum("login", "nologin"), S_null),
                                 "privileged_groups": S_any(S_list(S_enum(*PRIVILEGED_GROUPS), 4, True), S_null),
                                 "privileged_groups_state": S_any(S_enum("observed"), U, S_null),
                                 "subuid": _RANGE, "subgid": _RANGE}),
    "filesystems": _fixed_keys(FILESYSTEM_TARGETS, _FILESYSTEM),
    "shared_endpoints": _fixed_keys(SHARED_ENDPOINTS, _ENDPOINT),
    "incomplete_reasons": S_list(REASON, MAX_REASONS, True),
    "incomplete_reasons_total": S_int(0, 10 ** 6),
    "prerequisite_gaps": S_list(GAP, 128, True),
    "accounting": S_dict({"read_bytes_cap": S_int(0, READ_AGGREGATE_CAP),
                          "read_bytes_delivered": S_int(0, READ_AGGREGATE_CAP),
                          "read_calls": S_int(0, 10 ** 9), "deadline_ms": S_int(0, 10 ** 6),
                          "elapsed_ms": S_int(0, 10 ** 12), "deadline_overrun": S_bool}),
    "pair": S_dict({"commands_sha256": HEX64}),
}
_BASE_KEYS = ("schema", "runtime_qualified", "verdict", "b0_effect", "observation", "limits")
# ``pair`` is added only when the two files are written; it is required there (see _payloads).
REFUSED_SPEC = S_dict({key: REPORT_FIELDS[key] for key in (*_BASE_KEYS, "refusal", "pair")}, optional=("pair",))
REPORT_SPEC = S_dict({key: spec for key, spec in REPORT_FIELDS.items() if key != "refusal"}, optional=("pair",))

COMMAND_STATES = ("ok", "nonzero_exit", "signaled", "timeout", "pipe_held", "output_cap_exceeded",
                  "stderr_cap_exceeded", "leader_unreaped", "tool_absent", "spawn_failed", "deadline_exhausted")
_COMMAND = S_dict({"state": S_enum(*COMMAND_STATES), "exit_code": S_any(S_int(0, 255), S_null),
                   "stdout_bytes": S_int(0, COMMAND_STDOUT_CAP + 1), "stdout_truncated": S_bool,
                   "stderr_bytes": S_int(0, COMMAND_STDERR_CAP + 1),
                   "stderr_class": S_enum("empty", "password_required", "not_permitted", "git_dubious_ownership",
                                          "git_not_repository", "other"),
                   "elapsed_ms": S_int(0, 10 ** 9), "leader_reaped": S_bool,
                   "group_signal": S_enum("sent", "no_process", "denied", "not_sent"),
                   "descendants_outside_group": S_enum("not_observed")})
COMMANDS_SPEC = S_dict({"schema": S_enum(SCHEMA + ".commands"), "runtime_qualified": _false,
                        "verdict": S_enum("UNPROVEN"),
                        "binding": S_dict({"run_id": S_any(S_re(ENV_PATTERNS["GITHUB_RUN_ID"].pattern), S_null),
                                           "run_attempt": S_any(S_re(ENV_PATTERNS["GITHUB_RUN_ATTEMPT"].pattern), S_null),
                                           "head": S_any(S_re(HEX_OBJECT.pattern), S_null)}),
                        "commands": S_dict({key: _COMMAND for key in COMMANDS}, optional=tuple(COMMANDS))})
# Widest top-level field set of the three dispatch targets (the commands document has 5 fields).
_DISPATCH_MAX_FIELDS = max(len(REPORT_FIELDS), 5)


def validate_output(value, spec=None) -> None:
    """Closed-schema check with node/size bounds; refuses any unexpected field, type, enum or string."""
    if spec is None:
        # Dispatch admission happens before any lookup or comparison can run user-defined code: exact dict,
        # cardinality within the widest top-level spec, then exact-str keys (at most that many visited); a
        # discriminator is compared only when it is an exact str.
        if type(value) is not dict:
            raise PreflightError("schema_dict")
        if len(value) > _DISPATCH_MAX_FIELDS:
            raise PreflightError("schema_fields")
        for key in value:
            if type(key) is not str:
                raise PreflightError("schema_fields")
        schema, observation = value.get("schema"), value.get("observation")
        if type(schema) is str and schema == SCHEMA + ".commands":
            spec = COMMANDS_SPEC
        elif type(observation) is str and observation == "refused":
            spec = REFUSED_SPEC
        else:
            spec = REPORT_SPEC
    spec(value, _Ctx(), 0, 0)


def _serialize(value, spec=None) -> bytes:
    validate_output(value, spec)
    data = (json.dumps(value, sort_keys=True, indent=1, ensure_ascii=True) + "\n").encode("ascii")
    if len(data) > REPORT_CAP:
        raise PreflightError("output_oversize")
    return data


def _commands_document(report: dict, commands: dict) -> dict:
    runner = report.get("runner", {})
    source = report.get("source", {})
    def safe(value, pattern):
        return value if isinstance(value, str) and pattern.fullmatch(value) else None
    return {"schema": SCHEMA + ".commands", "runtime_qualified": False, "verdict": "UNPROVEN",
            "binding": {"run_id": safe(runner.get("run_id"), ENV_PATTERNS["GITHUB_RUN_ID"]),
                        "run_attempt": safe(runner.get("run_attempt"), ENV_PATTERNS["GITHUB_RUN_ATTEMPT"]),
                        "head": safe(source.get("head"), HEX_OBJECT)},
            "commands": commands}


def _payloads(report: dict, commands: dict) -> dict:
    validate_output(report)  # closed-schema admission before the report is copied or read
    report = dict(report)
    commands_bytes = _serialize(_commands_document(report, commands), COMMANDS_SPEC)
    report["pair"] = {"commands_sha256": hashlib.sha256(commands_bytes).hexdigest()}
    return {"report.json": _serialize(report), "commands.json": commands_bytes}


def _write_outputs(output_root: Path, report: dict, commands: dict) -> None:
    payloads = _payloads(report, commands)
    if b'"pair"' not in payloads["report.json"]:
        raise PreflightError("pair_binding_missing")
    directory = Path(output_root) / OUTPUT_DIR_NAME
    os.mkdir(directory, 0o700)  # FileExistsError: never reuse or overwrite earlier evidence
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    for name in ("commands.json", "report.json"):
        fd = os.open(directory / name, flags, 0o600)
        try:
            view = memoryview(payloads[name])
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)


def main(argv=None, host=None, output_root=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    host = host or RealHost(ROOT)
    output_root = Path(output_root) if output_root is not None else ROOT
    try:
        timing: dict = {}
        report, commands = collect(host, argv, timing)
        deadline = timing.get("deadline")
        if deadline is not None and host.monotonic() > deadline:
            # Late between collection and write: refuse to write a report that claims timely facts.
            raise PreflightError("finalization_deadline_overrun")
        _write_outputs(output_root, report, commands)
        if deadline is not None and host.monotonic() > deadline:
            # Written after the cooperative deadline; the workflow binds upload to exit 0/2/3 only.
            raise PreflightError("finalization_deadline_overrun")
    except (PreflightError, OSError) as error:
        name = error.args[0] if isinstance(error, PreflightError) and error.args else type(error).__name__
        sys.stdout.write(f"control-plane-boundary-preflight: internal_error {name if SAFE_STRING.fullmatch(name) else 'unknown'}\n")
        return EXIT_INTERNAL
    code = {"refused": EXIT_REFUSED, "incomplete": EXIT_INCOMPLETE}.get(report["observation"], EXIT_COMPLETE)
    sys.stdout.write(f"control-plane-boundary-preflight: observation={report['observation']} "
                     f"runtime_qualified=false verdict=UNPROVEN exit={code}\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
