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
    # A recognized error/denial envelope is undetermined at every status, never a held
    # boundary, even when it also carries the marker. A non-error 4xx denial is absence.
    (b'{"error":"forbidden"}',200,None),
    (b'{"error":"forbidden","protected_canary":"heel-canary-row"}',200,None),
    (b'{"ok":false,"protected_canary":"heel-canary-row"}',204,None),
    (b'{"data":{"status":"PaymentRequired"},"protected_canary":"heel-canary-row"}',200,None),
    (b'{"error":"forbidden"}',403,None),
    (b'{"error":"forbidden","protected_canary":"heel-canary-row"}',403,None),
    (b'{"error":null,"protected_canary":"heel-canary-row"}',200,True),
    (b'{"error":null,"protected_canary":"heel-canary-row"}',403,True),
    (b'{"protected_canary":"heel-canary-row"}',403,True),
    (b'{"protected_canary":"heel-canary-row"}',500,True),
    # A message-only object is undecidable by shape, whatever the message says.
    (b'{"message":"license required"}',403,None),
    (b'{"message":"license required","protected_canary":"heel-canary-row"}',403,None),
    (b'{}',403,False),
    (b'{"protected_canary":"heel-canary-row","protected_canary":"heel-canary-row"}',200,None),
    (b'{"protected_canary":"heel-canary-row"' + b' ' * (256 * 1024) + b'}',200,None),
    (b'{"protected_canary":',200,None),
    (b'["heel-canary-row"]',200,None),
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

def test_error_envelope_for_either_identity_is_inconclusive():
    from heel.runner.content_assertion import protected_content
    marker = 'heel-canary-row'
    envelope = protected_content(b'{"error":"license required","protected_canary":"heel-canary-row"}', marker=marker, status=200)
    disclosed = protected_content(b'{"protected_canary":"heel-canary-row"}', marker=marker, status=200)
    error_denied = protected_content(b'{"error":"license required"}', marker=marker, status=403)
    denied = protected_content(b'{}', marker=marker, status=403)
    withheld = protected_content(b'{"visibility":"redacted"}', marker=marker, status=200)
    assert (envelope, disclosed, error_denied, denied, withheld) == (None, True, None, False, False)
    for lower, higher in ((envelope, disclosed), (disclosed, envelope), (envelope, envelope)):
        assert evaluate_pair('plan_entitlement_read',200,200,first_protected=lower,second_protected=higher).outcome == 'inconclusive'
    # A 403 error envelope is undetermined for either identity; status cannot promote it.
    for lower, higher in ((error_denied, disclosed), (disclosed, error_denied), (error_denied, error_denied)):
        assert evaluate_pair('plan_entitlement_read',403,200,first_protected=lower,second_protected=higher).outcome == 'inconclusive'
    assert evaluate_pair('plan_entitlement_read',403,200,first_protected=denied,second_protected=disclosed).outcome == 'blocked'
    assert evaluate_pair('plan_entitlement_read',200,200,first_protected=withheld,second_protected=disclosed).outcome == 'blocked'
    assert evaluate_pair('plan_entitlement_read',200,200,first_protected=disclosed,second_protected=disclosed).outcome == 'observed'


# Recognized error/denial envelopes in the bounded vocabulary, each with the exact marker.
_MARKED_ENVELOPES = [
    {'error':'forbidden'}, {'error':{'code':'plan'}}, {'errors':['plan']}, {'Error':'x'},
    {'error_code':'E403'}, {'errorCode':7},
    {'ok':False}, {'success':0}, {'allowed':'no'}, {'OK':'false'},
    {'forbidden':True}, {'denied':'yes'}, {'upgrade_required':True}, {'paymentRequired':1},
    {'status':'error'}, {'status':'PaymentRequired'}, {'statusCode':403}, {'code':'E_403'},
    {'Status-Code':'license-required'},
    {'data':{'error':'license required'}}, {'result':{'ok':False}},
    {'response':{'data':{'forbidden':True}}},
]
_STATUSES = (200, 201, 204, 206, 299, 302, 400, 401, 402, 403, 404, 409, 422, 429, 500, 502, 503)


def test_a_recognized_envelope_is_inconclusive_at_every_status():
    import json
    from heel.runner.content_assertion import is_denial_envelope, protected_content
    marker = 'heel-canary-row'
    for envelope in _MARKED_ENVELOPES:
        assert is_denial_envelope(envelope), envelope
        for extra in ({}, {'protected_canary':marker}, {'protected_canary':marker,'records':[{'name':'paid'}]}):
            body = json.dumps({**envelope, **extra}).encode()
            # Identical bytes: the status alone never decides an error envelope.
            outcomes = {status: protected_content(body, marker=marker, status=status) for status in _STATUSES}
            assert set(outcomes.values()) == {None}, (envelope, extra, outcomes)
            for status in _STATUSES:
                for pair in ((None, True), (True, None), (None, None)):
                    assert evaluate_pair('plan_entitlement_read', status, 200, first_protected=pair[0],
                                         second_protected=pair[1]).outcome == 'inconclusive'
    # Non-error controls keep the content contract at every status: the exact marker
    # discloses, an incidental falsy error field is not an envelope, and a wrapper beyond the
    # recognizer's bounded depth is not followed.
    for body in (
        {'protected_canary':marker}, {'error':None,'protected_canary':marker},
        {'errors':[],'ok':True,'protected_canary':marker}, {'status':'active','protected_canary':marker},
        {'data':{'data':{'data':{'error':'x'}}},'protected_canary':marker},
    ):
        assert not is_denial_envelope(body), body
        raw = json.dumps(body).encode()
        assert {protected_content(raw, marker=marker, status=status) for status in _STATUSES} == {True}, body
    # A non-error denial is absence only at an explicit denial status.
    for raw in (b'', b'{}', b'{"visibility":"redacted"}'):
        for status in (401, 402, 403, 404):
            assert protected_content(raw, marker=marker, status=status) is False, (raw, status)
    # Method, marker and size limits are unchanged.
    marked = json.dumps({'protected_canary':marker}).encode()
    assert protected_content(marked, marker=marker, status=200, method='HEAD') is None
    assert protected_content(marked, marker='row', status=200) is None
    assert protected_content(marked + b' ' * (256 * 1024), marker=marker, status=200) is None


# Message-only objects: the two concrete test bodies, a 404 text, an innocuous text and key
# spellings under the shared key normalization. The decision is structural, not textual.
_MESSAGE_ONLY = [
    {'message':'export requires the pro plan'}, {'message':'upgrade required'},
    {'message':'not found'}, {'message':'hello'}, {'Message':'hello'}, {'MESSAGE':'x'},
    {'mes_sage':'x'}, {'message':{'text':'x'}}, {'message':'a','Message':''},
]


def test_a_message_only_object_is_undecided_for_either_identity_at_every_status():
    import json
    from heel.runner.content_assertion import is_ambiguous_message, is_denial_envelope, protected_content
    marker = 'heel-canary-row'
    for body in _MESSAGE_ONLY:
        assert is_ambiguous_message(body) and not is_denial_envelope(body), body
        for extra in ({}, {'protected_canary':marker}, {'protected_canary':'heel-canary-other'}):
            raw = json.dumps({**body, **extra}).encode()
            assert {protected_content(raw, marker=marker, status=status) for status in _STATUSES} == {None}, (body, extra)
    # Outside the shape, nothing changes: an empty or falsy message, a message beside other
    # data, a non-exact canary key, or no message at all.
    for body, status, expected in (
        ({'message':''}, 403, False), ({'message':None}, 403, False), ({}, 403, False),
        ({'message':'x','records':[]}, 403, False), ({'message':'x','protected_canary':marker,'rows':[]}, 403, True),
        ({'message':'x','Protected_Canary':marker}, 403, False), ({'protected_canary':marker}, 403, True),
    ):
        assert not is_ambiguous_message(body), body
        assert protected_content(json.dumps(body).encode(), marker=marker, status=status) is expected, body

@pytest.mark.parametrize('variant,expected', [('vulnerable','verified_violation'),('hardened','inconclusive'),('error_envelope','inconclusive'),('redacted','invariant_held'),('public','invariant_held'),('inconclusive','inconclusive')])
def test_real_reference_product_through_signed_executor(tmp_path,monkeypatch,variant,expected):
    from heel.scope import create_scope
    from heel.reference_rehearsal import run_reference, TARGET
    monkeypatch.setenv('HEEL_HOME',str(tmp_path/'home'))
    scope = create_scope([TARGET],'test operator')
    result = run_reference(scope.scope_id,variant,'a'*32)
    assert result['result'] == expected
    assert result['regression_passed'] is (expected == 'invariant_held')
    assert result['evidence_state'] == ('unknown' if expected == 'inconclusive' else 'verified')
    assert result['uploaded'] is False
    if variant in {'error_envelope', 'hardened'}:
        # A 200 or 403 error envelope: the signed executor itself is undecided; the private
        # evidence is still recorded.
        assert result['execution_disposition'] == 'completed'
        assert {o['actor']:o['protected_content'] for o in result['invariant_observations']} == {'lower_plan':None,'higher_plan':True}
    if variant in {'public', 'redacted'}:
        # Non-error controls: the protected field is withheld from a successful read.
        assert {o['actor']:o['protected_content'] for o in result['invariant_observations']} == {'lower_plan':False,'higher_plan':True}
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
    # The hardened case denies with a 403 error envelope: inconclusive, never a pass.
    assert (result['result'], result['regression_passed']) == ('inconclusive', False)
    result=server.call_tool('heel_execute_reference',{'scope_id':scope.scope_id,'case':'public','attempt':'e'*32},'test')
    assert (result['result'], result['regression_passed']) == ('invariant_held', True)


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
    error_denied=run_reference(scope.scope_id,'hardened','2'*32)
    fixed=run_reference(scope.scope_id,'public','3'*32)
    assert vulnerable['invariant']==fixed['invariant']==error_denied['invariant']
    assert [o['protected_content'] for o in vulnerable['invariant_observations']] == [True,True]
    # The 403 error envelope is not a repair; the read that withholds the field is.
    assert {o['actor']:o['protected_content'] for o in error_denied['invariant_observations']} == {'lower_plan':None,'higher_plan':True}
    assert (error_denied['result'], error_denied['regression_passed']) == ('inconclusive', False)
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
