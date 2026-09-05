#!/usr/bin/env python3
"""Exercise the installed reference CLI and real MCP stdio lifecycle.

Run using the installed environment's Python from an empty private working directory.
No checkout imports, external target or publication is used.
"""
import json
import os
from pathlib import Path
import subprocess
import sys


def cli(*args, expect=0):
    result = subprocess.run([sys.executable, '-I', '-m', 'heel.cli', *args], capture_output=True,
                            text=True, timeout=30)
    assert result.returncode == expect, result.stderr
    return json.loads(result.stdout) if expect == 0 else None


def main():
    os.environ['HEEL_HOME'] = str(Path.cwd() / 'private-heel')
    plan = cli('reference', 'prepare')
    assert plan['result'] == 'hypothesis'
    scope = cli('scope', 'create', '--target', 'reference:export', '--operator', 'installed acceptance', '--confirm')
    scope_id = scope['created_scope']
    reports = []
    for number, case, expected in [(1,'vulnerable','verified_violation'),(2,'hardened','invariant_held'),
                                   (3,'error_envelope','invariant_held'),(4,'inconclusive','inconclusive')]:
        attempt = f'{number:032x}'
        report = cli('reference','run','--scope',scope_id,'--case',case,'--attempt',attempt)
        assert report['result'] == expected
        assert report['uploaded'] is False
        assert Path(os.environ['HEEL_HOME'], 'reference', attempt, 'report.json').is_file()
        cli('reference','run','--scope',scope_id,'--case',case,'--attempt',attempt,expect=2)
        reports.append({'case':case,'result':report['result'],'regression_passed':report['regression_passed']})
    cli('reference','run','--scope','missing','--case','vulnerable','--attempt','9'*32,expect=2)
    messages = [
        {'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'reference-acceptance','version':'1'}}},
        {'jsonrpc':'2.0','method':'notifications/initialized','params':{}},
        {'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}},
        {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'heel_prepare_reference','arguments':{}}},
        {'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'heel_execute_reference','arguments':{'scope_id':scope_id,'case':'hardened','attempt':'8'*32}}},
    ]
    response = subprocess.run([sys.executable,'-I','-m','heel.mcp_server'],
        input='\n'.join(json.dumps(m) for m in messages)+'\n', text=True, capture_output=True, timeout=30)
    assert response.returncode == 0, response.stderr
    values = [json.loads(line) for line in response.stdout.splitlines()]
    assert 'heel_execute_reference' in {t['name'] for t in values[1]['result']['tools']}
    assert values[-1]['result']['structuredContent']['regression_passed'] is True
    print(json.dumps({'cli':reports,'mcp':'initialize/list/prepare/execute passed','replay':'rejected','unauthorized':'rejected'},indent=2))


if __name__ == '__main__':
    main()
