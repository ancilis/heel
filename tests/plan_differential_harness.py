"""Synthetic journey harness for the plan-differential runner. Tests only; not in the wheel.

    python tests/plan_differential_harness.py serve [--behavior vulnerable|hardened|envelope|subset]
    python tests/plan_differential_harness.py heel <heel arguments...>

``serve`` starts the loopback synthetic staging target and writes its port to a file.
``heel`` replaces exactly one module attribute, ``heel.runner.plan_differential._build_client``,
with the loopback factory and then calls the unmodified ``heel.cli.main``. The synthetic
origin is never resolved. The harness adds no option to the product CLI.

What this proves: request construction, Host, framing, redirect refusal, body rules,
compiler checks, gate, budget, reservation, evidence, redaction, predicates and logging
are product code. It proves nothing about TLS, DNS answers or address selection.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent))

from plan_differential_support import (  # noqa: E402
    BEHAVIORS,
    FREE_TOKEN,
    PRO_TOKEN,
    SYNTHETIC_ORIGIN,
    LoopbackFactory,
    SecondListener,
    SyntheticTarget,
)

PORT_FILE_VARIABLE = "PLAN_DIFFERENTIAL_HARNESS_PORT_FILE"


def port_file() -> Path:
    configured = os.environ.get(PORT_FILE_VARIABLE)
    if configured:
        return Path(configured)
    return Path(tempfile.gettempdir()) / "heel-plan-differential-harness.port"


def serve(behavior: str) -> int:
    second = SecondListener().start()
    target = SyntheticTarget(behavior=behavior, redirect_port=second.port).start()

    def access_log(index: int) -> None:
        # Method, path and which session; never the token.
        item = target.requests[index]
        print(f"request {index + 1}: {item['method']} {item['path']} as {item['plan']}", flush=True)

    target.on_request = access_log
    path = port_file()
    path.write_text(str(target.port), encoding="ascii")
    print(f"synthetic target for {SYNTHETIC_ORIGIN} on 127.0.0.1:{target.port} ({behavior})", flush=True)
    print(f"port file: {path}", flush=True)
    print(f"lower-plan session: {FREE_TOKEN}", flush=True)
    print(f"higher-plan session: {PRO_TOKEN}", flush=True)
    stop = threading.Event()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, lambda *_: stop.set())
    try:
        # A timed wait keeps the main thread responsive to signals on every platform.
        while not stop.wait(0.2):
            pass
    finally:
        target.stop()
        second.stop()
        try:
            path.unlink()
        except OSError:
            pass
        print(f"requests served: {len(target.seen())}; redirect listener: {len(second.seen())}", flush=True)
    return 0


def heel(arguments: list[str]) -> int:
    from heel import cli
    from heel.runner import plan_differential

    try:
        port = int(port_file().read_text(encoding="ascii"))
    except (OSError, ValueError):
        print("synthetic target is not running; start `serve` first", file=sys.stderr)
        return 2
    plan_differential._build_client = LoopbackFactory(port)
    return cli.main(arguments) or 0


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["heel"]:
        return heel(arguments[1:])
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    serving = commands.add_parser("serve", allow_abbrev=False)
    serving.add_argument("--behavior", choices=BEHAVIORS, default="vulnerable")
    commands.add_parser("heel")
    return serve(parser.parse_args(arguments).behavior)


if __name__ == "__main__":
    raise SystemExit(main())
