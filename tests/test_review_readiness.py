import copy
import json

from heel.browser_review import review_openapi_json
from heel.review_service import empty_product_model, review_openapi
from heel.static_review import review_product_models


def spec():
    return {'openapi':'3.1.0','info':{'title':'Review','version':'1'},
            'paths':{'/exports':{'get':{'operationId':'export'}}}}


def test_negative_answers_create_declared_gaps_without_verifying_behavior():
    source=spec()
    questions=review_openapi(source)['questions']
    answers=[{'surface':q['surface'],'field':q['field'],'value':'not_enforced'} for q in questions]
    review=json.loads(review_openapi_json(json.dumps(source),json.dumps(answers)))
    assert {f['risk'] for f in review['findings']} >= {'export_without_entitlement','export_without_tenant_quota'}
    assert all(f['evidence_state']=='inferred' for f in review['findings'])
    assert review['gate_status']!='pass'


def test_bulk_permission_keeps_required_paid_entitlement():
    before=empty_product_model('paid')
    after=copy.deepcopy(before)
    after['exports']=[{'id':'paid','bulk_access_permitted':True,'required_plan':'pro',
                       'reachable_by_plan':'free','entitlement_check':False,'quota':False}]
    review=review_product_models(before,after)
    assert [f.risk for f in review.new_abuse_affordances]==['export_without_entitlement']


def test_removed_control_is_a_qualified_change():
    after=empty_product_model('paid')
    before=copy.deepcopy(after)
    before['declared_controls']=[{'id':'gate','status':'enabled'}]
    review=review_product_models(before,after)
    assert review.changed_surfaces[0].change_type=='removed'
    assert review.launch_gate_status=='warn'
    assert review.new_abuse_affordances[0].evidence_state=='inferred'


def test_required_plan_keeps_enforcement_question():
    source=spec();source['paths']['/exports']['get']['x-heel-plan']='pro'
    assert 'entitlement_check' in {q['field'] for q in review_openapi(source)['questions']}


def test_guided_answers_support_a_modest_api():
    source=spec();source['paths']={f'/resource/{i}':{'get':{'operationId':f'read{i}'}} for i in range(33)}
    answers=[{'surface':q['surface'],'field':q['field'],'value':'enforced'} for q in review_openapi(source)['questions']]
    review=json.loads(review_openapi_json(json.dumps(source),json.dumps(answers)))
    assert review['questions']==[]
