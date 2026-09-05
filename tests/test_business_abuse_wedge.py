import pytest
from heel.review_service import review_openapi, empty_product_model
from heel.static_review import review_product_models
from heel.runner.adapters import evaluate_pair


def export_spec():
    return {'openapi':'3.1.0','info':{'title':'Exports','version':'1'},'paths':{'/exports':{'get':{'operationId':'exportRows','responses':{'200':{'description':'OK'}}}}}}


def test_missing_metadata_is_questions_not_control_failures():
    review = review_openapi(export_spec())
    assert review['findings'] == []
    assert len(review['questions']) >= 2


def test_status_and_shape_alone_cannot_verify_any_boundary():
    for scenario in ('object_ownership_read','plan_entitlement_read','role_bound_read','anonymous_authenticated_read'):
        assert evaluate_pair(scenario,200,200,first_body_shape='json_object',second_body_shape='json_object').outcome == 'inconclusive'


def test_intentional_coupon_stacking_and_permitted_bulk_are_not_abuse():
    before = empty_product_model('permitted')
    after = empty_product_model('permitted')
    after['coupons_promotions'] = [{'id':'welcome','stackable':True,'redemption_limit':'none','stacking_permitted':True}]
    after['exports'] = [{'id':'public-dataset','entitlement_check':'none','quota':'none','bulk_access_permitted':True}]
    assert review_product_models(before,after).new_abuse_affordances == []

@pytest.mark.parametrize('body,status,expected', [
    (b'{"protected_canary":"heel-canary-row"}',200,True),
    (b'{"error":"forbidden"}',200,False),
    (b'{"visibility":"redacted"}',200,False),
    (b'{"visibility":"public","id":"heel-canary-row"}',200,False),
    (b'{"message":"retry"}',200,None),
    (b'{"protected_canary":"other"}',200,None),
    (b'',403,False),
])
def test_protected_content(body,status,expected):
    from heel.runner.content_assertion import protected_content
    assert protected_content(body,marker='heel-canary-row',status=status) is expected


def test_positive_control_and_fix_regression():
    assert evaluate_pair('plan_entitlement_read',200,200,first_protected=True,second_protected=True).outcome == 'observed'
    assert evaluate_pair('plan_entitlement_read',200,200,first_protected=False,second_protected=True).outcome == 'blocked'
    assert evaluate_pair('plan_entitlement_read',403,200,first_protected=False,second_protected=None).outcome == 'inconclusive'

@pytest.mark.parametrize('variant,expected', [('vulnerable','verified_violation'),('hardened','invariant_held'),('error_envelope','invariant_held'),('redacted','invariant_held'),('public','invariant_held'),('inconclusive','inconclusive')])
def test_real_reference_product_through_signed_executor(tmp_path,monkeypatch,variant,expected):
    from heel.scope import create_scope
    from heel.reference_rehearsal import run_reference, TARGET
    monkeypatch.setenv('HEEL_HOME',str(tmp_path/'home'))
    scope = create_scope([TARGET],'test operator')
    result = run_reference(scope.scope_id,variant,'a'*32)
    assert result['result'] == expected
    assert result['uploaded'] is False
    with pytest.raises((ValueError,FileExistsError)):
        run_reference(scope.scope_id,variant,'a'*32)


def test_unauthorized_and_cancelled_reference(tmp_path,monkeypatch):
    from heel.scope import create_scope
    from heel.reference_rehearsal import run_reference, TARGET
    monkeypatch.setenv('HEEL_HOME',str(tmp_path/'home'))
    with pytest.raises(ValueError):
        run_reference('missing','vulnerable','a'*32)
    scope=create_scope([TARGET],'test operator')
    result=run_reference(scope.scope_id,'vulnerable','b'*32,stop=True)
    assert result['result'] == 'inconclusive'
    assert result['regression_passed'] is False
    assert result['tested'].startswith('0 completed GET observations')


def test_library_capabilities_require_a_product_rule():
    from heel.scenarios import all_seed_scenarios
    from heel.agents import evaluate_criterion
    from heel.contracts import Affordance, Category
    aff=Affordance('rows','export',Category.DATA_HARVESTING,{'route':'/exports','export_scope':'all','export_row_limit':'unlimited'},False,1)
    scenarios=[s for s in all_seed_scenarios() if s.mechanism_id=='export-read-entitlement']
    assert scenarios
    assert not any(evaluate_criterion(s.success_criterion,aff) for s in scenarios)


def test_mcp_reference_journey(tmp_path,monkeypatch):
    from heel.scope import create_scope
    from heel.mcp_server import HeelServer
    from heel.reference_rehearsal import TARGET
    monkeypatch.setenv('HEEL_HOME',str(tmp_path/'home'))
    server=HeelServer()
    plan=server.call_tool('heel_prepare_reference',{},'test')
    assert plan['result']=='hypothesis'
    scope=create_scope([TARGET],'human test operator')
    result=server.call_tool('heel_execute_reference',{'scope_id':scope.scope_id,'case':'hardened','attempt':'f'*32},'test')
    assert result['regression_passed']


def test_model_rules_and_sequences_cannot_claim_execution():
    from heel.product_model import validate_product_model
    model=empty_product_model('lifecycle')
    model['business_rules']=[{'id':'trial','statement':'one trial per subject','source':'product owner','evidence_state':'customer_declared'}]
    model['lifecycle_sequences']=[{'id':'retry','rule_id':'trial','actions':[
        {'ordinal':0,'actor':'customer','action':'claim trial','preconditions':['eligible'],'state_changes':['consumed']},
        {'ordinal':1,'actor':'customer','action':'change login','preconditions':['consumed'],'state_changes':['login changed']},
    ],'executed':False}]
    assert validate_product_model(model).ok
    model['lifecycle_sequences'][0]['executed']=True
    assert not validate_product_model(model).ok
    model['lifecycle_sequences'][0]['executed']=False
    model['business_rules'][0]['evidence_state']='verified'
    assert not validate_product_model(model).ok


def test_duplicate_operation_representation_is_one_exposure_per_invariant():
    spec=export_spec()
    spec['paths']['/exports']['get']['x-heel-control']={'entitlement_check':False,'rate_limit':False}
    review=review_openapi(spec)
    assert len(review['findings'])==2
    assert len({f['risk'] for f in review['findings']})==2
    assert all(f['evidence_state']=='inferred' and f['execution_disposition']=='static_only' for f in review['findings'])


def test_private_evidence_and_real_fix_regression(tmp_path,monkeypatch):
    import json
    from heel.scope import create_scope
    from heel.reference_rehearsal import run_reference, TARGET
    from heel.runner.http_transport import normalize_target_origin, TransportFailure
    monkeypatch.setenv('HEEL_HOME',str(tmp_path/'home'))
    scope=create_scope([TARGET],'test operator')
    vulnerable=run_reference(scope.scope_id,'vulnerable','1'*32)
    fixed=run_reference(scope.scope_id,'hardened','2'*32)
    assert vulnerable['invariant']==fixed['invariant']
    assert [o['protected_content'] for o in vulnerable['invariant_observations']] == [True,True]
    assert {o['actor']:o['protected_content'] for o in fixed['invariant_observations']} == {'lower_plan':False,'higher_plan':True}
    assert fixed['regression_passed']
    assert 'synthetic-basic-session' not in json.dumps(vulnerable)
    assert 'synthetic-paid-session' not in json.dumps(vulnerable)
    assert (tmp_path/'home/reference'/('1'*32)/'report.json').stat().st_mode & 0o777 == 0o600
    for origin in ('http://127.0.0.1','https://localhost','https://10.0.0.1'):
        with pytest.raises(TransportFailure): normalize_target_origin(origin)


def test_investigations_not_lost_from_unknown_metadata_markdown():
    from heel.review_export import review_to_markdown
    text=review_to_markdown(review_openapi(export_spec()))
    assert 'Unanswered questions' in text
    assert 'No findings does not establish complete coverage or launch safety' in text


def test_untrusted_business_context_never_certifies_sequence_or_crashes():
    from heel.product_model import validate_product_model
    model=empty_product_model('untrusted')
    model['business_rules']=[{'id':'r','statement':'one allowance','source':'owner','evidence_state':[]}]
    model['lifecycle_sequences']=[{'rule_id':[]}]
    assert not validate_product_model(model).ok
    model['business_rules'][0]['evidence_state']='customer_declared'
    model['lifecycle_sequences']=[{'rule_id':'r','evidence_state':'verified','executed':False,
        'actions':[{'ordinal':0,'actor':'customer','action':'read'}]}]
    assert not validate_product_model(model).ok
