import copy
import json

import pytest

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading


@pytest.fixture
def sandbox():
    state={'vulnerable':True,'requests':[],'positive':True}
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state['requests'].append(self.path)
            body={'protected_canary':'heel-canary-row'} if (self.path=='/paid' and state['positive']) or (self.path=='/free' and state['vulnerable']) else {'denied':True}
            self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers()
            self.wfile.write(json.dumps(body).encode())
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    yield f'http://127.0.0.1:{server.server_port}',state
    server.shutdown();server.server_close();thread.join()


def test_real_http_campaign_detects_fix_and_preserves_uncertainty(sandbox,tmp_path,monkeypatch):
    from heel.campaign_runner import authorize_campaign, run_campaign, compare_reports, verify_report
    monkeypatch.setenv('HEEL_HOME',str(tmp_path/'home'))
    origin,state=sandbox;p=plan(origin)
    scope=authorize_campaign(p,'local owner',runs=3)
    bad=run_campaign(p,scope.scope_id,'a'*32)
    assert bad['coverage']['violation']==1 and verify_report(bad)
    state['vulnerable']=False
    fixed=run_campaign(p,scope.scope_id,'b'*32)
    assert fixed['coverage']['held']==1
    assert compare_reports(bad,fixed)['fixed']==['export']
    state['positive']=False
    unsure=run_campaign(p,scope.scope_id,'c'*32)
    assert unsure['coverage']['inconclusive']==1
    assert state['requests']==['/paid','/free','/paid','/free','/paid']
    assert 'heel-canary-row' not in json.dumps(bad)


def test_campaign_scope_digest_replay_and_total_budget(sandbox,tmp_path,monkeypatch):
    from heel.campaign_runner import authorize_campaign, run_campaign
    monkeypatch.setenv('HEEL_HOME',str(tmp_path/'home'))
    origin,state=sandbox;p=plan(origin)
    scope=authorize_campaign(p,'owner',runs=1)
    altered=copy.deepcopy(p);altered['scenarios'][0]['steps'][0]['path']='/other'
    with pytest.raises(ValueError):run_campaign(altered,scope.scope_id,'a'*32)
    assert state['requests']==[]
    run_campaign(p,scope.scope_id,'a'*32)
    with pytest.raises(ValueError):run_campaign(p,scope.scope_id,'a'*32)
    with pytest.raises(ValueError):run_campaign(p,scope.scope_id,'b'*32)
    assert len(state['requests'])==2


def test_cancelled_campaign_does_not_contact_target(sandbox,tmp_path,monkeypatch):
    from heel.campaign_runner import authorize_campaign, run_campaign
    monkeypatch.setenv('HEEL_HOME',str(tmp_path/'home'))
    origin,state=sandbox;p=plan(origin);scope=authorize_campaign(p,'owner')
    stop=threading.Event();stop.set()
    result=run_campaign(p,scope.scope_id,'d'*32,cancellation=stop)
    assert result['coverage']['inconclusive']==1 and state['requests']==[]


def test_scope_expiring_during_rate_wait_prevents_the_next_request(sandbox,tmp_path,monkeypatch):
    from heel.campaign_runner import run_campaign
    from heel.campaign_contract import campaign_target
    from heel.scope import create_scope
    monkeypatch.setenv('HEEL_HOME',str(tmp_path/'home'))
    origin,state=sandbox;p=plan(origin);p['limits']['min_interval_ms']=1500
    scope=create_scope([campaign_target(p)],'owner',limits={'max_requests':10,'max_concurrency':1,'backoff':True},ttl_seconds=1)
    result=run_campaign(p,scope.scope_id,'5'*32)
    assert result['coverage']['inconclusive']==1
    assert state['requests']==['/paid']


def plan(origin='http://127.0.0.1:19876'):
    return {'schema_version':'heel.campaign.v1','name':'Owned sandbox',
            'origin':origin,'environment':'loopback','allow_mutations':False,
            'actors':[{'id':'owner','auth':'anonymous'}],
            'limits':{'max_requests':10,'timeout_seconds':2,'max_duration_seconds':20,'min_interval_ms':0},
            'scenarios':[{'id':'export','family':'entitlement','rule':'Only paid accounts receive protected content',
              'steps':[{'id':'positive','actor':'owner','method':'GET','path':'/paid','expected_status':[200]},
                       {'id':'negative','actor':'owner','method':'GET','path':'/free','expected_status':[200,403]}],
              'preconditions':[{'id':'fixture','left':{'step':'positive','pointer':'/protected_canary'},'op':'eq','right':'heel-canary-row'}],
              'assertions':[{'id':'protected','left':{'step':'negative','pointer':'/protected_canary'},'op':'absent'}],
              'cleanup':[]}]}


def test_campaign_contract_binds_every_action_and_rejects_mutation_without_consent():
    from heel.campaign_contract import validate_campaign, campaign_target
    original=validate_campaign(plan()); altered=copy.deepcopy(original)
    altered['scenarios'][0]['steps'][0]['path']='/another'
    assert campaign_target(original)!=campaign_target(altered)
    altered['scenarios'][0]['steps'][0].update(method='POST',json={'subject':'heel-canary-one'})
    with pytest.raises(ValueError):validate_campaign(altered)


@pytest.mark.parametrize('path',['//evil.example/x','/a/../b','/a%2fb','/a?url=https://evil.example','/a\r\nX: y'])
def test_campaign_paths_cannot_change_authority(path):
    from heel.campaign_contract import validate_campaign
    p=plan();p['scenarios'][0]['steps'][0]['path']=path
    with pytest.raises(ValueError):validate_campaign(p)


def test_campaign_rejects_unbound_references_and_empty_rules():
    from heel.campaign_contract import validate_campaign
    p=plan();p['scenarios'][0]['assertions'][0]['left']['step']='missing'
    with pytest.raises(ValueError):validate_campaign(p)
    p=plan();p['scenarios'][0]['preconditions']=[]
    with pytest.raises(ValueError):validate_campaign(p)


@pytest.mark.parametrize('origin,environment',[
    ('http://127.0.0.1:8765','staging'),('https://localhost','staging'),
    ('http://localhost:8765','loopback'),('http://169.254.169.254:8765','loopback'),
    ('https://10.0.0.1','sandbox'),('https://example.com','production'),
])
def test_egress_modes_fail_closed(origin,environment):
    from heel.campaign_contract import validate_campaign
    p=plan(origin);p['environment']=environment
    with pytest.raises(ValueError):validate_campaign(p)


def test_no_inline_credentials_in_campaign_requests():
    from heel.campaign_contract import validate_campaign
    p=plan();p['allow_mutations']=True
    p['scenarios'][0]['steps'][0].update(method='POST',json={'subject':'heel-canary-one','password':'secret'})
    with pytest.raises(ValueError):validate_campaign(p)


def test_expanded_fixtures_still_obey_request_byte_limits():
    from heel.campaign_contract import validate_campaign
    p=plan();p['allow_mutations']=True
    p['scenarios'][0]['steps'][0].update(method='POST',json={'subject':'heel-canary-'+'{run}'*400})
    with pytest.raises(ValueError):validate_campaign(p)


def test_distinct_actor_labels_cannot_reuse_the_same_credential(sandbox,tmp_path,monkeypatch):
    from heel.campaign_runner import authorize_campaign,run_campaign
    monkeypatch.setenv('HEEL_HOME',str(tmp_path/'home'))
    monkeypatch.setenv('HEEL_CANARY_FIRST','same-canary-credential')
    monkeypatch.setenv('HEEL_CANARY_SECOND','same-canary-credential')
    origin,state=sandbox;p=plan(origin)
    p['actors']=[{'id':'owner','auth':'bearer','credential_env':'HEEL_CANARY_FIRST'},
                 {'id':'outsider','auth':'bearer','credential_env':'HEEL_CANARY_SECOND'}]
    p['scenarios'][0]['steps'][1]['actor']='outsider'
    scope=authorize_campaign(p,'owner')
    with pytest.raises(ValueError):run_campaign(p,scope.scope_id,'6'*32)
    assert state['requests']==[]


def test_response_redirect_is_not_followed_and_json_absence_is_not_a_pass(tmp_path,monkeypatch):
    from heel.campaign_runner import authorize_campaign,run_campaign
    calls=[]
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(self.path);self.send_response(302);self.send_header('Location','http://127.0.0.1:9/secret');self.end_headers()
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    monkeypatch.setenv('HEEL_HOME',str(tmp_path/'home'))
    try:
        p=plan(f'http://127.0.0.1:{server.server_port}');scope=authorize_campaign(p,'owner')
        report=run_campaign(p,scope.scope_id,'8'*32)
        assert report['coverage']['inconclusive']==1 and calls==['/paid']
        assert report['results'][0]['reason']=='redirect_rejected'
    finally:server.shutdown();server.server_close();worker.join()


def test_missing_credential_and_changed_signature_do_not_pass(sandbox,tmp_path,monkeypatch):
    from heel.campaign_runner import authorize_campaign,run_campaign,verify_report
    monkeypatch.setenv('HEEL_HOME',str(tmp_path/'home'))
    monkeypatch.delenv('HEEL_CANARY_MISSING',raising=False)
    origin,state=sandbox;p=plan(origin)
    p['actors']=[{'id':'owner','auth':'bearer','credential_env':'HEEL_CANARY_MISSING'}]
    scope=authorize_campaign(p,'owner')
    report=run_campaign(p,scope.scope_id,'9'*32)
    assert report['coverage']['inconclusive']==1 and state['requests']==[]
    report['results'][0]['outcome']='held'
    assert not verify_report(report)


def test_trickling_response_obeys_absolute_deadline(tmp_path,monkeypatch):
    import time
    from heel.campaign_runner import authorize_campaign,run_campaign
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200);self.end_headers()
            try:
                for byte in b'{"protected_canary":"heel-canary-row"}':
                    self.wfile.write(bytes([byte]));self.wfile.flush();time.sleep(0.08)
            except OSError:pass
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    monkeypatch.setenv('HEEL_HOME',str(tmp_path/'home'))
    try:
        p=plan(f'http://127.0.0.1:{server.server_port}');p['limits']['timeout_seconds']=1
        scope=authorize_campaign(p,'owner');started=time.monotonic()
        result=run_campaign(p,scope.scope_id,'7'*32)
        assert time.monotonic()-started<2.5
        assert result['coverage']['inconclusive']==1
    finally:server.shutdown();server.server_close();worker.join()


def test_assertions_compare_observations_and_keep_missing_evidence_inconclusive():
    from heel.campaign_contract import evaluate_assertion
    rows={'before':{'status':200,'body':{'usage':5}},'after':{'status':200,'body':{'usage':7}}}
    assertion={'id':'meter','left':{'step':'after','pointer':'/usage'},'op':'delta_lte',
               'baseline':{'step':'before','pointer':'/usage'},'right':1}
    assert evaluate_assertion(assertion,rows) is False
    assertion['right']=2
    assert evaluate_assertion(assertion,rows) is True
    assert evaluate_assertion(assertion,{}) is None
    rows['after']['body']['usage']='7'
    assert evaluate_assertion(assertion,rows) is None


@pytest.mark.parametrize('hardened',[False,True])
def test_all_rule_families_cross_real_http_and_observe_business_state(hardened,tmp_path,monkeypatch):
    from heel.campaign_demo import make_demo_server
    from heel.campaign_templates import template_campaign
    from heel.campaign_runner import authorize_campaign,run_campaign
    from heel.campaign_contract import FAMILIES
    server=make_demo_server(0,hardened=hardened)
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    monkeypatch.setenv('HEEL_HOME',str(tmp_path/'home'))
    monkeypatch.setenv('HEEL_CANARY_OWNER','heel-canary-owner')
    monkeypatch.setenv('HEEL_CANARY_OUTSIDER','heel-canary-outsider')
    try:
        campaign=template_campaign(f'http://127.0.0.1:{server.server_port}')
        campaign['limits']['min_interval_ms']=0
        scope=authorize_campaign(campaign,'test owner')
        report=run_campaign(campaign,scope.scope_id,'e'*32)
        assert len(report['results'])==len(FAMILIES)
        assert {r['outcome'] for r in report['results']}=={'held' if hardened else 'violation'}, report
        assert all(r['cleanup']=='complete' for r in report['results'])
        assert not server.product.accounts
    finally:
        server.shutdown();server.server_close();worker.join()


def test_cli_prepare_authorize_run_report_and_mcp_existing_scope(sandbox,tmp_path,monkeypatch,capsys):
    from heel.cli import main
    from heel.mcp_server import HeelServer,TOOL_NAMES,ToolError
    from heel.store import Store
    monkeypatch.setenv('HEEL_HOME',str(tmp_path/'home'))
    origin,state=sandbox;p=plan(origin)
    path=tmp_path/'campaign.json';path.write_text(json.dumps(p))
    assert main(['campaign','prepare',str(path)])==0
    prepared=json.loads(capsys.readouterr().out)
    assert prepared['target'].startswith('campaign:')
    assert main(['campaign','authorize',str(path),'--operator','test','--runs','2','--confirm'])==0
    scope=json.loads(capsys.readouterr().out)['scope_id']
    assert main(['campaign','run',str(path),'--scope',scope,'--attempt','1'*32])==1
    report=json.loads(capsys.readouterr().out)
    assert report['coverage']['violation']==1
    assert main(['campaign','report','1'*32])==0
    assert json.loads(capsys.readouterr().out)==report
    server=HeelServer(Store(str(tmp_path/'audit.db')))
    assert 'heel_authorize_campaign' not in TOOL_NAMES
    state['vulnerable']=False
    result=server.call_tool('heel_execute_campaign',{'campaign':p,'scope_id':scope,'attempt':'2'*32},'test-agent')
    assert result['coverage']['held']==1
    with pytest.raises(ToolError):
        server.call_tool('heel_execute_campaign',{'campaign':p,'scope_id':scope,'attempt':'3'*32,'origin':'https://evil.example'},'test-agent')


def test_openapi_discovery_suggests_workflows_without_claiming_execution():
    from heel.campaign_discovery import discover_campaigns
    source={'openapi':'3.1.0','info':{'title':'My product','version':'1'},'paths':{
        '/trial':{'post':{'operationId':'claimTrial'}},
        '/usage':{'get':{'operationId':'readUsage'}},
        '/exports/{id}':{'get':{'operationId':'downloadExport'}}}}
    result=discover_campaigns(source)
    assert result['executed'] is False
    assert set(result['suggested_families']) >= {'trial_eligibility','usage_accounting','entitlement'}
    assert all(row['required_bindings'] for row in result['operations'])
