"""Public local campaign workflow; authorization exists only in this human CLI."""
import argparse
import json
import re
import signal
import sys
import threading
import uuid

from .campaign_contract import FAMILIES, campaign_target, validate_campaign
from .campaign_runner import authorize_campaign, compare_reports, run_campaign, verify_report
from .campaign_store import campaign_store


def prepare_campaign(plan):
    plan = validate_campaign(plan)
    return {'target': campaign_target(plan), 'campaign': plan, 'requests': sum(len(s['steps']) + len(s['cleanup']) for s in plan['scenarios']),
            'configured_families': sorted({s['family'] for s in plan['scenarios']}),
            'unconfigured_families': sorted(set(FAMILIES) - {s['family'] for s in plan['scenarios']}),
            'execution': 'requires exact human-created scope', 'credential_values_included': False}


def load_report(attempt):
    if type(attempt) is not str or not re.fullmatch('[0-9a-f]{32}', attempt):
        raise ValueError('invalid run identifier')
    with campaign_store() as store:
        report = store.read(attempt + '.json')
    if not verify_report(report):
        raise ValueError('campaign report signature invalid')
    return report


def report_markdown(report):
    lines = ['# Heel abuse campaign', '', report['name'], '',
             f"Run: `{report['run_id']}` · Requests attempted: {report['requests_attempted']}", '',
             '| Scenario | Family | Outcome | Cleanup |', '| --- | --- | --- | --- |']
    for row in report['results']:
        lines.append(f"| {row['scenario_id']} | {row['family']} | {row['outcome']} | {row['cleanup']} |")
    lines += ['', '## Coverage', '', 'Only the declared rules and observed paths were tested. Unconfigured families are untested.', '']
    for family, counts in report['coverage']['families'].items():
        lines.append(f"- {family}: {counts['configured']} configured; {counts['held']} held; {counts['violation']} violations")
    return '\n'.join(lines) + '\n'


def main(argv):
    parser = argparse.ArgumentParser(prog='heel campaign', allow_abbrev=False)
    sub = parser.add_subparsers(dest='command', required=True)
    template = sub.add_parser('template', help='print an editable campaign template')
    template.add_argument('--origin', default='http://127.0.0.1:8765')
    template.add_argument('--environment', choices=['loopback', 'sandbox', 'staging'], default='loopback')
    template.add_argument('--family', choices=FAMILIES)
    for command in ('discover', 'prepare', 'authorize', 'run'):
        child = sub.add_parser(command)
        child.add_argument('file')
        if command == 'authorize':
            child.add_argument('--operator', required=True)
            child.add_argument('--runs', type=int, default=1)
            child.add_argument('--ttl', type=int, default=3600)
            child.add_argument('--confirm', action='store_true')
        if command == 'run':
            child.add_argument('--scope', required=True)
            child.add_argument('--attempt', default=None)
    report = sub.add_parser('report')
    report.add_argument('run_id')
    report.add_argument('--format', choices=['json', 'markdown'], default='json')
    compare = sub.add_parser('compare')
    compare.add_argument('before'); compare.add_argument('after')
    demo = sub.add_parser('demo', help='serve a disposable synthetic HTTP SaaS on loopback')
    demo.add_argument('--port', type=int, default=8765)
    demo.add_argument('--hardened', action='store_true')
    args = parser.parse_args(argv)
    code = 0
    try:
        if args.command == 'template':
            from .campaign_templates import template_campaign
            result = template_campaign(args.origin, family=args.family, environment=args.environment)
        elif args.command == 'demo':
            from .campaign_demo import make_demo_server
            if not 1024 <= args.port <= 65535:
                raise ValueError('choose a loopback port from 1024 to 65535')
            server = make_demo_server(args.port, hardened=args.hardened)
            print(f'Canary-only demo at http://127.0.0.1:{args.port} ({"hardened" if args.hardened else "vulnerable"})', flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0
        elif args.command == 'report':
            result = load_report(args.run_id)
            if args.format == 'markdown':
                print(report_markdown(result), end=''); return 0
        elif args.command == 'compare':
            result = compare_reports(load_report(args.before), load_report(args.after))
            code = 1 if result['regressed'] else 2 if result['inconclusive'] else 0
        else:
            from .cli import _load_bounded_openapi
            if args.command == 'discover':
                from .campaign_discovery import discover_campaigns
                print(json.dumps(discover_campaigns(_load_bounded_openapi(args.file)), indent=2))
                return 0
            plan = validate_campaign(_load_bounded_openapi(args.file))
            if args.command == 'prepare':
                result = prepare_campaign(plan)
            elif args.command == 'authorize':
                if not args.confirm:
                    raise ValueError('inspect campaign prepare, then authorize the exact plan with --confirm')
                scope = authorize_campaign(plan, args.operator, runs=args.runs, ttl_seconds=args.ttl)
                result = {'scope_id': scope.scope_id, 'target': campaign_target(plan), 'runs_authorized': args.runs, 'expires_at': scope.expiry}
            else:
                stop = threading.Event()
                previous = None
                if threading.current_thread() is threading.main_thread():
                    previous = signal.signal(signal.SIGINT, lambda *_: stop.set())
                try:
                    result = run_campaign(plan, args.scope, args.attempt or uuid.uuid4().hex, cancellation=stop)
                finally:
                    if previous is not None:
                        signal.signal(signal.SIGINT, previous)
                coverage = result['coverage']
                code = 1 if coverage['violation'] else 2 if coverage['inconclusive'] or not coverage['held'] else 0
        print(json.dumps(result, indent=2))
        return code
    except (ValueError, OSError, RuntimeError, RecursionError):
        print('Campaign rejected: check the plan, exact signed scope, unused run ID, available credentials and private storage.', file=sys.stderr)
        return 2
