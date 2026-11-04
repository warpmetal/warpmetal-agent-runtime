"""Fresh scoped SOURCE authority. Never reads a live key/ledger or re-signs history.

Uses the byte-pinned owner schemas and synthetic P-256 keys solely to exercise the
real signed Store/native consumers. The generic two-request case is NOT authority2
SOURCE10, historical-offset recovery, or permission for LIVE selected26.
"""
import base64
import hashlib
import json
import os
import sys
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

publication_only = sys.argv[-1:] == ['--source-local-publication']
metadata_only = sys.argv[-1:] == ['--source-transport-metadata'] or publication_only
authorization_only = sys.argv[-1:] == ['--child-authorization-observer']
flash_boundary = '--flash-provider-boundary' in sys.argv[4:]
coding_result_boundary = '--coding-result-boundary' in sys.argv[4:]
integration_result_boundary = '--integration-result-boundary' in sys.argv[4:]
integration_delivery_boundary = '--integration-delivery-boundary' in sys.argv[4:]
reviewer_delivery_boundary = '--reviewer-delivery-boundary' in sys.argv[4:]
assert not integration_delivery_boundary or integration_result_boundary
assert not reviewer_delivery_boundary or (flash_boundary and not integration_result_boundary and not coding_result_boundary)
# Fresh opt-in SOURCE observations exercise the actual node-auth TLS client.
# Preserve every default placeholder; never rewrite already signed originals.
source_node_hash = hashlib.sha256(b'synthetic-node').hexdigest() if reviewer_delivery_boundary or (integration_delivery_boundary and os.environ.get('WARPMETAL_CHILD_INTEGRATION_OBSERVATION_BOUNDARY') == '1') else 'a'*64
approved_source_boundary = '--approved-source-reference-boundary' in sys.argv[4:]
worker_source_boundary = '--worker-source-read-boundary' in sys.argv[4:]
worker_source_bytes = b'SOURCE full worker Plan bytes\n'
worker_source_reference = {'path':'source/approved.txt','sourceDigest':'sha256:'+hashlib.sha256(worker_source_bytes).hexdigest(),'status':'accepted'}
assert not (coding_result_boundary and integration_result_boundary)
assert not (coding_result_boundary or integration_result_boundary) or flash_boundary
selected_kind = 'reviewer' if reviewer_delivery_boundary else 'integrator' if integration_result_boundary else 'coding_worker'
schemas, predecessor, destination = map(Path, sys.argv[1:4])
docs = {p.name: json.loads(p.read_bytes()) for p in schemas.glob('*.json')}
if integration_delivery_boundary:
    integrator_raw = Path(os.environ['WARPMETAL_INTEGRATOR_SCHEMA_SOURCE']).read_bytes()
    assert hashlib.sha256(integrator_raw).hexdigest() == '7a05be5f6af976d76e6b68495c6c31d10660348787dd62e5ea81525183e6062c'
    docs['workspace-child-integrator-v1.schema.json'] = json.loads(integrator_raw)
if reviewer_delivery_boundary:
    reviewer_raw = Path(os.environ['WARPMETAL_REVIEWER_SCHEMA_SOURCE']).read_bytes()
    assert hashlib.sha256(reviewer_raw).hexdigest() == '001af7e4e908618dd93edddfae16ebc3c5d62f1f2864f20df8c7d64fc0dd2254'
    docs['workspace-child-reviewer-v1.schema.json'] = json.loads(reviewer_raw)
assert hashlib.sha256((schemas/'workspace-workflow-budget-v2.schema.json').read_bytes()).hexdigest() == '389206ceed518078af6ab324ed8edf6addb7b265471f139ccdc0585daf1447d2'
by_id = {d['$id']: d for d in docs.values() if '$id' in d}
registry = Registry().with_resources((k, Resource.from_contents(v)) for k, v in by_id.items())
budget = docs['workspace-workflow-budget-v2.schema.json']
child = docs['workspace-child-product-v1.schema.json']
manager = docs['workspace-workflow-manager-v1.proposal.schema.json']
domain = docs['workspace-workflow-v1.schema.json']
producer = docs['workspace-workflow-producer-v1.schema.json']
cell = docs['cell-lifecycle-v3.schema.json']
flash_budget = docs['workspace-workflow-budget-v3.schema.json'] if flash_boundary else None
flash_child = docs['workspace-child-provider-v2.schema.json'] if flash_boundary else None
if flash_boundary:
    assert hashlib.sha256((schemas/'workspace-workflow-budget-v3.schema.json').read_bytes()).hexdigest() == 'e4e6850d744296937d1d5609f9738f2c8f3ade7cf3d0c3402cfa9198cdd4e130'
    assert hashlib.sha256((schemas/'deepseek-flash-responses-e2-v2.json').read_bytes()).hexdigest() == '3082b57ec287f3b32451a970104bd0b170c2b5873f9efbe91380bc3b4212281f'
provider_fields = {'providerPolicyDigest': flash_budget['$defs']['providerPolicyDigest']['const'], 'accountingVersion': 2} if flash_boundary else {}
policy_version = 2 if flash_boundary else 1
H = 'sha256:'+'a'*64
now = datetime.now(timezone.utc).replace(microsecond=0)
stamp = now.isoformat().replace('+00:00','Z')
expiry = (now+timedelta(seconds=115)).isoformat().replace('+00:00','Z')

def canonical(v): return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def digest(v): return 'sha256:'+hashlib.sha256(canonical(v)).hexdigest()
def byte_digest(v): return 'sha256:'+hashlib.sha256(v).hexdigest()
def validate(doc, name, value):
    Draft202012Validator({'$ref':doc['$id']+'#/$defs/'+name},registry=registry).validate(value)

def sample(s, doc):
    if '$ref' in s:
        url,_,pointer=urljoin(doc['$id'],s['$ref']).partition('#')
        selected=by_id[url]; sub=selected
        for key in (pointer.strip('/').split('/') if pointer else []): sub=sub[key.replace('~1','/').replace('~0','~')]
        return sample(sub,selected)
    if 'const' in s:return deepcopy(s['const'])
    if 'enum' in s:return deepcopy(s['enum'][0])
    if 'oneOf' in s:return sample(s['oneOf'][0],doc)
    if 'allOf' in s and 'type' not in s:
        out={}
        for part in s['allOf']:
            v=sample(part,doc)
            if isinstance(v,dict):out.update(v)
        return out
    kind=s.get('type')
    if kind=='object':return {k:sample(s['properties'][k],doc) for k in s.get('required',[])}
    if kind=='array':return [sample(s['items'],doc) for _ in range(s.get('minItems',0))]
    if kind in ('integer','number'):return s.get('minimum',1)
    if kind=='boolean':return False
    if kind=='null':return None
    if kind=='string':
        pattern=s.get('pattern','')
        if s.get('format')=='date-time':return stamp
        if 'sha256' in pattern:return H
        if '{64}' in pattern:return 'a'*64
        if pattern.startswith('^ses_'):return 'ses_synthetic'
        if pattern.startswith('^msg_'):return 'msg_synthetic'
        return 'synthetic'
    return {}

key=ec.generate_private_key(ec.SECP256R1()); root_key=ec.generate_private_key(ec.SECP256R1())
pub=lambda k:k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
operator, root_pem = pub(key),pub(root_key)
def envelope(v,k=key,key_id='source_operator'):
    return {'payload':v,'keyId':key_id,'signature':base64.b64encode(k.sign(canonical(v),ec.ECDSA(hashes.SHA256()))).decode()}

seed=json.loads(predecessor.read_bytes())
intent=deepcopy(seed['specimens'][2 if integration_result_boundary or reviewer_delivery_boundary else 1]['context']['target']['members']['first'])
intent['notAfter']=expiry
scope=intent['scope']; owner=scope['owner']; owner['sandboxId']='sbx_synthetic_product'
scope['workspace']['projectId']='global'
intent['prepareBody']['instance']='source_product'
intent['prepareBody']['profile']['profileDigest']=scope['approvedProfile']['profileDigest']
intent['prepareBody']['workspaceSelection']['selectionId']=scope['workspace']['selectionId']
if flash_boundary:
    intent['prepareBody']['authority'].update(providerId='deepseek', modelId='deepseek-flash', authMode='api_key')
    intent['prepareBody']['credentialBinding'].update(providerId='deepseek', authMode='api_key')
source_manager_application = None
if ((integration_delivery_boundary and os.environ.get('WARPMETAL_INTEGRATOR_MANAGER_SOURCE') == '1') or
        (reviewer_delivery_boundary and os.environ.get('WARPMETAL_REVIEWER_MANAGER_SOURCE') == '1')):
    from integrator_delivery_fixture import source_application
    source_producer = {'keyId':'source_root','keySHA256':byte_digest(root_pem),'serverId':owner['serverId'],'nodeTokenHash':source_node_hash}
    source_manager_application = source_application(intent, producer, sample, digest, stamp, expiry, source_producer, lambda v: envelope(v, root_key, 'source_root'), validate)
    scope['configurationDigest'] = source_manager_application['operation']['configurationDigest']
if worker_source_boundary:
    assert coding_result_boundary and not integration_result_boundary
    intent['prepareBody']['content']['context']=worker_source_bytes.decode()
    intent['prepareBody']['content']['workflowPacket']['planRef']=worker_source_reference
    intent['plan']['planRef']=worker_source_reference
if integration_delivery_boundary:
    from integrator_delivery_fixture import content as integration_content, policy as integration_policy
    target_binding = sample(domain['$defs']['binding'], domain)
    target_binding.update(executionId='source_author_execution', preparationId='source_author_preparation',
        nativeSessionId='ses_source_author', nativeProjectId='global',
        nativeLocationDigest=digest({'directory':str(destination.parent/'work'),'projectId':'global','workspaceId':None}),
        **{k:scope['workspace'][k] for k in ('projectId','workspaceEpoch','selectionId','scopeRevision','rootAttestation')})
    integration_sources = integration_content(intent, target_binding, stamp, digest, byte_digest)
    validate(domain, 'resultDetail', integration_sources['targetDetail'])
if reviewer_delivery_boundary:
    from reviewer_delivery_fixture import content as reviewer_content, policy as reviewer_policy
    target_binding = sample(domain['$defs']['binding'], domain)
    target_binding.update(executionId='source_author_execution', preparationId='source_author_preparation',
        nativeSessionId='ses_source_author', nativeProjectId='global',
        nativeLocationDigest=digest({'directory':str(destination.parent/'work'),'projectId':'global','workspaceId':None}),
        **{k:scope['workspace'][k] for k in ('projectId','workspaceEpoch','selectionId','scopeRevision','rootAttestation')})
    reviewer_sources = reviewer_content(intent, target_binding, stamp, canonical, digest, byte_digest)
    validate(domain, 'resultDetail', reviewer_sources['targetDetail'])
intent['prepareBodyDigest']=digest(intent['prepareBody']);intent['lifecycleRequestDigest']=intent['prepareBodyDigest'][7:]
intent['intentDigest']=digest({k:v for k,v in intent.items() if k!='intentDigest'})
if reviewer_delivery_boundary: validate(manager, 'approvedWorkIntent', intent)
ref={k:intent[k] for k in ('intentId','intentRevision','intentDigest')}

entry=sample(cell['$defs']['cellServiceV3'],cell)
entry.update(formatVersion=3,targetKind='cell_session',operationId='source_service_operation',launchOperationId=intent['prepareBody']['operationId'],
    lifecyclePhase='prepare',preparationId='source_preparation',controllerId=owner['controllerId'],controllerRevision=1,authorityRevision=1,
    actionRevision=1,desiredRevision=1,desiredState='active',sessionMode='create_initial',serviceRegistrationId='source_child_service',
    ownerCellId=owner['cellId'],ownerRole='manager',ownerGeneration=1,sandboxId=owner['sandboxId'],sandboxGeneration=1,serviceGeneration=1,
    configDigest=scope['configurationDigest'],fence='a'*64,attempt=1,instance='source_product',role='worker',nativeProjectId='global',workspaceEpoch=scope['workspace']['workspaceEpoch'],
    workspace={k:scope['workspace'][k] for k in ('selectionId','projectId','workspaceEpoch','scopeRevision','rootAttestation')},
    instructions={'instructionRevision':1,'instructionDigest':H},profile=intent['prepareBody']['profile'],authority=intent['prepareBody']['authority'],
    credentialBinding=intent['prepareBody']['credentialBinding'],parentIdentity=intent['prepareBody']['parentIdentity'],requestDigest=intent['lifecycleRequestDigest'])
if reviewer_delivery_boundary: entry['role']='reviewer'
entry['nativeSessionId']='ses_'+base64.b32encode(hashlib.sha256(entry['launchOperationId'].encode()).digest()).decode().rstrip('=')
input_id='msg_'+entry['nativeSessionId'][4:]
text='Complete explicitly synthetic input. Only the approved native read leaf; then original result.'
if coding_result_boundary: text='Complete explicitly synthetic input. Write the approved output once; then original result.'
if integration_result_boundary: text='Complete explicitly synthetic integration input. Update the approved existing candidate file once; then original integration candidate.'
if worker_source_boundary or integration_delivery_boundary or reviewer_delivery_boundary: text=canonical({'formatVersion':1,'kind':'workspace_workflow_packet','content':intent['prepareBody']['content']}).decode()
entry['instructions']['instructionDigest']=byte_digest(text.encode())
tuple_=sample(cell['$defs']['preparedTuple'],cell)
for k in ('controllerId','controllerRevision','authorityRevision','serviceRegistrationId','serviceGeneration','sandboxId','sandboxGeneration','requestDigest','configDigest','credentialBinding','authority','attempt','fence'):tuple_[k]=entry[k]
tuple_.update(operationId=entry['launchOperationId'],profileDigest=entry['profile']['profileDigest'],workspaceDigest=digest(entry['workspace']),**entry['parentIdentity'])
receipt={'formatVersion':3,'preparedTuple':tuple_,'credentialId':'source_credential','nativeCredentialId':'source_native_credential'}
preimage={k:v for k,v in receipt.items() if k!='formatVersion'}
receipt['bindingDigest']=digest(preimage);receipt['preparedReceiptDigest']=digest({**preimage,'bindingDigest':receipt['bindingDigest']})
app=sample(manager['$defs']['artifactApplicability'],manager)
for k in ('accountId','taskId','serverId','sandboxId','sandboxGeneration'):app[k]=owner[k]
app['native'].update(version='2.0.14-wm.6');app['runtime'].update(version='0.1.52')
app['profile'].update(setupOperationId=entry['profile']['setupOperationId'],profileId='opencode',revision=1,profileDigest=entry['profile']['profileDigest'],bundleDigest=scope['approvedProfile']['bundleDigest'])
app['connection']=entry['credentialBinding'];app['model'].update(engineProfileVersion='opencode-2.0.14',adapterVersion='team-adapter-1')
if flash_boundary:
    app.update(formatVersion=2, providerPolicyDigest=provider_fields['providerPolicyDigest'])
    app['native']['version']='2.0.14-wm.8';app['runtime']['version']='0.1.54-e2.1'
    app['model'].update(providerId='deepseek', modelId='deepseek-flash', authMode='api_key', endpoint='https://api.deepseek.com/responses')
    validate(flash_budget, 'artifactApplicability2', app)
controls={k:v['const'] for k,v in budget['$defs']['controls']['properties'].items() if 'const' in v};controls['maxConcurrentPhysicalRequests']=1
tariff={k:v['const'] for k,v in budget['$defs']['tariff']['properties'].items()}
allocation={'name':'codingWorker','allocationId':intent['allocationId'],'kind':'coding_worker','scope':owner,'sourceId':intent['intentId'],
    'scopeDigest':digest(scope),'tupleDigest':digest(app),'preparationOrdinal':1,'firstPhysicalIndex':1,'lastPhysicalIndex':2,'modelRequests':2,'accessRequests':0,'usdMicros':842000,'dependsOn':[]}
demand={'formatVersion':2,'caseId':'source_case','caseManifestDigest':app['caseManifestDigest'],'ledgerId':'model-qualification-and-product',
    'candidateInventoryDigest':H,'accountScopeDigest':digest(owner),'pricingDigest':digest({'modelId':'gpt-4.1-mini-2025-04-14','inputMicrosPerMillion':400000,'cachedInputMicrosPerMillion':100000,'outputMicrosPerMillion':1600000}),
    'tupleInventoryDigest':H,'requestReserveMicros':421000,'allocations':[allocation],'controls':controls,'tariff':tariff,'declaredAt':stamp,'notAfter':expiry}
case={'formatVersion':2,'caseId':demand['caseId'],'caseManifestDigest':app['caseManifestDigest'],'ledgerId':demand['ledgerId'],'requests':2,'modelRequests':2,'accessRequests':0,'preparations':1,
    'qualificationTuples':1,'usdMicros':842000,'physicalCeiling':2,'usdCeilingMicros':842000,'pricingDigest':demand['pricingDigest'],'operatorKeySHA256':byte_digest(operator),
    'demandManifestDigest':digest(demand),'tupleInventoryDigest':H,'controlsDigest':digest(controls)}
if flash_boundary:
    # Fresh SOURCE authority over the complete selected graph, never a copied
    # accepted financial case or a continuation of its durable ledger. All keys
    # above are ephemeral, all native/installed facts remain synthetic.
    controls={k:v['const'] for k,v in flash_budget['$defs']['controls']['properties'].items()}
    tariff=deepcopy(flash_budget['$defs']['tariff']['const'])
    pricing=digest({'modelId':'deepseek-flash','inputMicrosPerMillion':300000,'cachedInputMicrosPerMillion':300000,'outputMicrosPerMillion':1200000})
    peer_owner={**owner,'sandboxId':'sbx_synthetic_peer','cellId':'source_peer_cell','controllerId':'source_peer_controller'}
    peer_app={**app,'sandboxId':peer_owner['sandboxId']}
    roster=[('primary_access','access',1,1,0),('primary_qual','qualification',2,3,1),
        ('foreman','parent',4,4,2),('manager_initial','parent',5,5,3),('coding','coding_worker',6,7,4),
        ('manager_integrate','parent',8,8,5),('integrator','integrator',9,10,6),('manager_review','parent',11,11,7),
        ('reviewer','reviewer',12,12,8),('manager_accept','parent',13,13,9),('followup','parent',14,14,10),
        ('peer_access','access',15,15,0),('peer_qual','qualification',16,17,11),('peer_advice','parent',18,18,12),('continuation','parent',19,19,13)]
    allocations=[]
    for name,kind,first,last,ordinal in roster:
        selected_owner=peer_owner if name.startswith('peer_') else owner
        selected_app=peer_app if name.startswith('peer_') else app
        item={'name':name,'allocationId':intent['allocationId'] if kind==selected_kind else 'source_allocation_'+name,
            'kind':kind,'scope':selected_owner,'sourceId':intent['intentId'] if kind==selected_kind else 'source_'+name,
            'scopeDigest':digest(scope) if kind==selected_kind else digest(selected_owner),'tupleDigest':digest(selected_app),
            'preparationOrdinal':ordinal,'firstPhysicalIndex':first,'lastPhysicalIndex':last,'modelRequests':0 if kind=='access' else last-first+1,
            'accessRequests':1 if kind=='access' else 0,'usdMicros':421000*(last-first+1),'dependsOn':[allocations[-1]['allocationId']] if allocations else []}
        allocations.append(item)
    allocation=next(item for item in allocations if item['kind']==selected_kind)
    demand={**demand,**provider_fields,'formatVersion':3,'caseId':'source_flash_'+byte_digest(operator)[7:23],
        'accountScopeDigest':digest(owner),'pricingDigest':pricing,'tupleInventoryDigest':digest([app,peer_app]),
        'allocations':allocations,'controls':controls,'tariff':tariff,'maximumExposureMicros':3000000,'physicalRequestLimit':19}
    case={**case,**provider_fields,'formatVersion':3,'caseId':demand['caseId'],'requests':19,'modelRequests':17,'accessRequests':2,
        'preparations':13,'qualificationTuples':2,'usdMicros':3000000,'physicalCeiling':19,'usdCeilingMicros':3000000,
        'pricingDigest':pricing,'demandManifestDigest':digest(demand),'tupleInventoryDigest':demand['tupleInventoryDigest'],'controlsDigest':digest(controls)}
    validate(flash_budget, 'typedCase', case);validate(flash_budget, 'demandManifest', demand)
handle=sample(manager['$defs']['intentHandle'],manager);handle.update(intent=ref,owner=owner,allocationId=intent['allocationId'],notAfter=expiry)
root=sample(child['$defs']['rootScope'],child);root.update(workspace=scope['workspace'],registeredSourceId='source_registered',runtimeRevision=1,
    producer={'keyId':'source_root','keySHA256':byte_digest(root_pem),'serverId':owner['serverId'],'nodeTokenHash':source_node_hash})
qualification={'qualificationId':'source_qualification','tupleDigest':digest(app),'evidenceDigest':H,'validUntil':expiry}
prep={'preparationId':entry['preparationId'],'preparedTuple':tuple_,'preparedTupleDigest':digest(tuple_),'sessionId':entry['nativeSessionId'],'inputId':input_id}
instructions={'instructionRevision':1,'instructionDigest':entry['instructions']['instructionDigest'],'inputId':input_id,'inputDigest':byte_digest(text.encode()),'inputByteCount':len(text.encode())}
reservation={k:allocation[k] for k in ('allocationId','preparationOrdinal','firstPhysicalIndex','lastPhysicalIndex','modelRequests','accessRequests','usdMicros')}
reservation.update(reservationId='source_reservation',ledgerId=demand['ledgerId'],demandManifestDigest=case['demandManifestDigest'])
budget_=sample(child['$defs']['budget'],child);budget_.update(modelRequests=2,turns=2,inputTokens=2095152,outputTokens=2000,usdMicros=842000,pricingDigest=case['pricingDigest'])
requests=[{'requestIndex':i,'physicalIndex':allocation['firstPhysicalIndex']+i-1,'toolChoice':'approved_native_tools' if i==1 else 'none','toolKind':'native' if i==1 else None,'nativeToolName':None,
    'maxInputTokens':1047576,'maxOutputTokens':1000,'maxUsdMicros':421000,'parallelToolCalls':False} for i in (1,2)]
workload={'kind':'integration2' if integration_result_boundary else 'coding2','nativeToolNames':['write' if coding_result_boundary or integration_result_boundary else 'read'],'requests':requests,'terminalOutput':'integration_candidate' if integration_result_boundary else 'result','codemodeDisabled':True,'delegationDisabled':True,'hostNetworkDisabled':True}
if reviewer_delivery_boundary:
    budget_.update(modelRequests=1,turns=1,inputTokens=1047576,outputTokens=1000,usdMicros=421000)
    workload.update(kind='review1',nativeToolNames=[],terminalOutput='review_evidence',
        requests=[{**requests[0],'toolChoice':'none','toolKind':None}])
p={'formatVersion':policy_version,**provider_fields,'targetKind':'cell_session','mode':'real_provider','stage':'prepare','purpose':selected_kind,'case':case,'handle':handle,'intent':intent,'scope':scope,'root':root,
    'applicability':app,'qualification':qualification,'preparation':prep,'instructions':instructions,'reservation':reservation,'budget':budget_,'workload':workload,'toolRequirements':[],'issuedAt':stamp,'expiresAt':expiry}
binding=sample(domain['$defs']['binding'],domain)
for k in ('serviceRegistrationId','serviceGeneration','sandboxGeneration','attempt','fence','packetId','packetRevision','parentExecutionId','parentPacketId','profileDigest','configDigest'):binding[k]=tuple_[k]
binding.update(executionId='source_execution',preparationId=entry['preparationId'],nativeSessionId=entry['nativeSessionId'],nativeProjectId='global',nativeLocationDigest=digest({'directory':str(destination.parent/'work'),'projectId':'global','workspaceId':None}),
    instructionRevision=1,instructionDigest=instructions['instructionDigest'],**{k:scope['workspace'][k] for k in ('projectId','workspaceEpoch','selectionId','scopeRevision','rootAttestation')})
assignment={'formatVersion':1,'assignmentId':'source_assignment','assignmentDigest':H,'executionId':binding['executionId'],'purpose':intent['purpose'],'plan':intent['plan'],'target':intent['target'],'createdAt':stamp}
q={'formatVersion':policy_version,**provider_fields,'targetKind':'cell_session','mode':'real_provider','stage':'product','purpose':p['purpose'],'preparationPolicyDigest':digest(p),'intent':ref,
    **{k:p[k] for k in ('case','scope','root','applicability','qualification','reservation','budget','workload','instructions')},
    'preparedReceipt':receipt,'binding':binding,'assignment':assignment,'sourceReads':[],'tools':[],'reviewDelivery':None,'issuedAt':stamp,'expiresAt':expiry}
source_roots={}
if integration_delivery_boundary:
    source_roots, integration_originals = integration_policy(q, p, root, binding, assignment, input_id, text,
        integration_sources, expiry, canonical, digest, validate, docs['workspace-child-integrator-v1.schema.json'])
if reviewer_delivery_boundary:
    source_roots, reviewer_originals = reviewer_policy(q, p, root, binding, assignment, input_id, text,
        reviewer_sources, expiry, canonical, digest, validate, docs['workspace-child-reviewer-v1.schema.json'])
if approved_source_boundary or worker_source_boundary:
    # Explicit SOURCE authorities, signed below with the rest of this fresh
    # policy. No file read/receipt or packet-source completeness is supplied.
    reference=worker_source_reference if worker_source_boundary else {'path':'source/approved.txt','sourceDigest':byte_digest(b'SOURCE reference projection'),'status':'accepted'}
    for name in (('source_projection_a',) if worker_source_boundary else ('source_projection_a','source_projection_b')):
        read_root=sample(child['$defs']['readRootAuthorization'],child)
        read_root.update(formatVersion=1,binding=binding,assignmentId=assignment['assignmentId'],use='tool_input',
            rootKind='workspace',workspace=root['workspace'],registeredSourceId=name,rootAttestation=root['workspace']['rootAttestation'],
            producer=root['producer'],candidateDescriptorDigest=root['candidateDescriptorDigest'],installedManifestDigest=None,expiresAt=expiry)
        grant={'formatVersion':1,'binding':binding,'assignmentId':assignment['assignmentId'],'use':'tool_input',
            'reference':reference,'artifact':None,'byteCount':len(worker_source_bytes if worker_source_boundary else b'SOURCE reference projection'),'rootGrantDigest':digest(read_root),
            'manifestDigest':digest([reference]),'candidate':None,'expiresAt':expiry}
        read={'grant':grant,'root':read_root};validate(child,'sourceReadScope',read)
        q['sourceReads'].append(read);source_roots[digest(read_root)]=read_root
b={'formatVersion':policy_version,**provider_fields,'purpose':p['purpose'],'case':case,'allocationId':allocation['allocationId'],'intent':ref,'policyDigest':digest(q),
    'preparedReceiptDigest':receipt['preparedReceiptDigest'],'assignmentDigest':assignment['assignmentDigest'],'modelRequests':2,'usdMicros':842000,'expiresAt':expiry}
if reviewer_delivery_boundary: b.update(modelRequests=1,usdMicros=421000)
grant=sample(cell['$defs']['executionGrant'],cell)
for k in ('controllerId','controllerRevision','authorityRevision','attempt','fence','parentExecutionId','parentPacketId','packetId','packetRevision','configDigest','profileDigest','workspaceDigest'):grant[k]=tuple_[k]
grant.update(grantId='source_grant',operationId=entry['launchOperationId'],sessionId=entry['nativeSessionId'],inputId=input_id,
    credentialBindingDigest=digest(tuple_['credentialBinding']),preparedReceiptDigest=receipt['preparedReceiptDigest'],expiresAt=expiry)
execute_entry={**entry,'lifecyclePhase':'execute','preparedReceiptDigest':receipt['preparedReceiptDigest'],'executionGrant':grant}
observation={'formatVersion':1,'purpose':'child_product_authorization','taskId':owner['taskId'],'nodeTokenHash':source_node_hash,'preparationId':prep['preparationId'],
    'preparedReceiptDigest':receipt['preparedReceiptDigest'],'authorizationSha256':byte_digest(b'Bearer explicitly-synthetic'),'root':root,'observedAt':stamp}
obs=envelope(observation,root_key,'source_root')
a={'formatVersion':policy_version,**provider_fields,'targetKind':'cell_session','mode':'real_provider','purpose':p['purpose'],'caseId':case['caseId'],'caseManifestDigest':case['caseManifestDigest'],'demandManifestDigest':case['demandManifestDigest'],
    'allocationId':allocation['allocationId'],'intent':ref,'preparationId':prep['preparationId'],'preparationPolicyDigest':digest(p),'preparedTupleDigest':digest(tuple_),
    'preparedReceiptDigest':receipt['preparedReceiptDigest'],'assignmentDigest':assignment['assignmentDigest'],'policyDigest':digest(q),'policyBindingDigest':digest(b),'reservation':reservation,'grant':grant,'grantDigest':digest(grant),
    'authorizationObservationDigest':digest(obs),'authorizationSha256':observation['authorizationSha256'],'issuedAt':stamp,'expiresAt':expiry}
g={'formatVersion':3 if flash_boundary else 2,**provider_fields,'targetKind':'cell_session','phase':'prepare','preparationId':prep['preparationId'],'demand':envelope(demand),'preparationPolicy':envelope(p),'policy':None,'policyBinding':None,'activation':None,'authorizationObservation':None}
def delivery(g):
    d={'formatVersion':2,'targetKind':'cell_session','purpose':'child_product_execution','phase':g['phase'],'preparationId':prep['preparationId'],'preparedTupleDigest':digest(tuple_),
        'preparationPolicyDigest':digest(p),'policyDigest':digest(q) if g['phase']=='execute' else None,'generationDigest':digest(g)}
    successor = integration_delivery_boundary and g['phase']=='execute'
    reviewer_successor = reviewer_delivery_boundary and g['phase']=='execute'
    out={'formatVersion':5 if reviewer_successor else 4 if successor else 3 if flash_boundary else 2,'descriptor':d,'generation':g}
    validate(docs['workspace-child-reviewer-v1.schema.json'] if reviewer_successor else docs['workspace-child-integrator-v1.schema.json'] if successor else flash_child if flash_boundary else budget,'controlDelivery',out)
    return out
prepare_control=delivery(g)
g={**g,'phase':'execute','policy':envelope(q),'policyBinding':envelope(b),'activation':envelope(a),'authorizationObservation':obs}
if integration_delivery_boundary: g['formatVersion']=4
if reviewer_delivery_boundary: g['formatVersion']=5
execute_control=delivery(g)
w={'OperatorKeyID':'source_operator','Applicability':app,'QualifiedApplicability':app,'Qualification':qualification,'Case':case,'Scope':scope,'Intent':intent,'Handle':handle,'Root':root,
    'ProducerPEM':base64.b64encode(root_pem).decode(),'Preparation':prep,'Instructions':instructions,'ActualReceipt':receipt,'Binding':binding,'Assignment':assignment,'Grant':grant,'Authorization':observation,
    'SigningNotBefore':stamp,'ProductSigningNotBefore':stamp,'ActivationSigningNotBefore':stamp,'AuthorizedUntil':expiry,'InstalledTools':{},'SourceRoots':source_roots,'Input':base64.b64encode(text.encode()).decode(),
    'ReviewReads':[],'ReviewCompilation':None,'Entry':execute_entry,'AcceptedPreparationEnvelope':g['preparationPolicy'],'AcceptedDemandEnvelope':g['demand']}
if reviewer_delivery_boundary: w['ReviewCompilation']=intent['reviewInput']
validate(cell,'cellServiceV3',entry);validate(cell,'cellServiceV3',execute_entry)
packet={'authoritySynthetic':True,'liveAuthorized':False,'prepare':prepare_control,'execute':execute_control,'witness':w,'prepareEntry':entry,'operatorPEM':base64.b64encode(operator).decode(),'firstText':text}
if coding_result_boundary:
    packet['codingResultBoundary']=True
if worker_source_boundary:
    packet['workerSourceBoundary']=True
    packet['workerSourceBytes']=base64.b64encode(worker_source_bytes).decode()
    packet['workerSourceReference']=worker_source_reference
if coding_result_boundary or integration_result_boundary:
    packet['producerPrivatePEM']=base64.b64encode(root_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())).decode()
if integration_result_boundary:
    packet['integrationResultBoundary']=True
if integration_delivery_boundary:
    packet['integrationDeliveryBoundary']=True
    packet['integrationOriginals']=integration_originals
    consumer={'profile':[entry['profile']['profileRevision'],entry['profile']['profileDigest']],
        'native':app['native'],'runtime':app['runtime'],'sandbox':app['sandbox'],'adapterVersion':'source-integrator-input-reader',
        'evidenceClass':'source','childProductSchemaSHA256':'7a05be5f6af976d76e6b68495c6c31d10660348787dd62e5ea81525183e6062c',
        'budgetSchemaSHA256':'e4e6850d744296937d1d5609f9738f2c8f3ade7cf3d0c3402cfa9198cdd4e130'}
    config_digest=digest({'classification':'declared SOURCE installed inputs, no installed acceptance'})
    packet['integrationInstalledFacts']={}
    for phase in ('prepare','execute'):
        inputs={'workload':workload,'sourceReads':q['sourceReads'] if phase=='execute' else [],'tools':[],
            'reviewDelivery':None,'integrationDelivery':q['integrationDelivery'] if phase=='execute' else None}
        observed={'formatVersion':2,'purpose':'child_product_installed_inputs','evidenceClass':'source','configDigest':config_digest,
            'taskId':app['taskId'],'nodeTokenHash':root['producer']['nodeTokenHash'],'preparationId':prep['preparationId'],
            'intentDigest':intent['intentDigest'],'preparedTupleDigest':prep['preparedTupleDigest'],'applicabilityDigest':digest(app),
            'root':root,'assignmentDigest':assignment['assignmentDigest'] if phase=='execute' else None,'consumerDigest':digest(consumer),
            'inputs':inputs,'observedAt':stamp,'notAfter':expiry}
        signed=envelope(observed,root_key,'source_root')
        validate(docs['workspace-child-integrator-v1.schema.json'],'installedInputEnvelope',signed)
        packet['integrationInstalledFacts'][phase]={'evidenceClass':'source','configDigest':config_digest,'applicability':app,
            'producerPEM':base64.b64encode(root_pem).decode(),'consumer':consumer,'observation':signed}
if reviewer_delivery_boundary:
    packet.update(reviewerDeliveryBoundary=True,reviewerOriginals=reviewer_originals,
        producerPrivatePEM=base64.b64encode(root_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())).decode())
    consumer={'profile':[entry['profile']['profileRevision'],entry['profile']['profileDigest']],
        'native':app['native'],'runtime':app['runtime'],'sandbox':app['sandbox'],'adapterVersion':'source-reviewer-input-reader',
        'evidenceClass':'source','childProductSchemaSHA256':'001af7e4e908618dd93edddfae16ebc3c5d62f1f2864f20df8c7d64fc0dd2254',
        'budgetSchemaSHA256':'e4e6850d744296937d1d5609f9738f2c8f3ade7cf3d0c3402cfa9198cdd4e130'}
    config_digest=digest({'classification':'declared SOURCE reviewer installed inputs, no installed acceptance'})
    packet['reviewerInstalledFacts']={}
    for phase in ('prepare','execute'):
        inputs={'workload':workload,'sourceReads':q['sourceReads'] if phase=='execute' else [],
            'artifactReads':q['artifactReads'] if phase=='execute' else [],'tools':[],
            'reviewDelivery':q['reviewDelivery'] if phase=='execute' else None}
        observed={'formatVersion':3,'purpose':'child_product_installed_inputs','evidenceClass':'source','configDigest':config_digest,
            'taskId':app['taskId'],'nodeTokenHash':root['producer']['nodeTokenHash'],'preparationId':prep['preparationId'],
            'intentDigest':intent['intentDigest'],'preparedTupleDigest':prep['preparedTupleDigest'],'applicabilityDigest':digest(app),
            'root':root,'assignmentDigest':assignment['assignmentDigest'] if phase=='execute' else None,'consumerDigest':digest(consumer),
            'inputs':inputs,'observedAt':stamp,'notAfter':expiry}
        signed=envelope(observed,root_key,'source_root')
        validate(docs['workspace-child-reviewer-v1.schema.json'],'installedInputEnvelope',signed)
        packet['reviewerInstalledFacts'][phase]={'evidenceClass':'source','configDigest':config_digest,'applicability':app,
            'producerPEM':base64.b64encode(root_pem).decode(),'consumer':consumer,'observation':signed}
if sys.argv[-1:] == ['--normal-firsttask-delivery-templates']:
    # Fresh unsigned shapes ONLY. The existing owner journey supplies its own
    # separate SOURCE operator; these are not retained accepted originals.
    packet['authorityTemplate']=sample(budget['$defs']['authority2'],budget)
if authorization_only:
    association=sample(manager['$defs']['actualPreparationAssociation'],manager)
    association.update(formatVersion=1,handleId=handle['handleId'],intent=ref,preparationId=entry['preparationId'],preparedReceipt=receipt,binding=binding)
    association['assignmentBody'].update(binding=binding)
    association['associationDigest']=digest({k:v for k,v in association.items() if k!='associationDigest'})
    validate(manager,'actualPreparationAssociation',association)
    grant_intent={'formatVersion':policy_version,'handleId':handle['handleId'],'preparationAssociationDigest':association['associationDigest'],
        'policyDigest':digest(q),'policyBindingDigest':digest(b),'assignment':assignment,'reservation':reservation,
        'grant':grant,'grantDigest':digest(grant),'notBefore':stamp,'expiresAt':expiry,'state':'committed_activation_pending'}
    validate(flash_child if flash_boundary else child,'grantIntent',grant_intent)
    packet['authorizationIntent']={'preparationId':entry['preparationId'],'preparationAssociation':association,
        'policy':g['policy'],'policyBinding':g['policyBinding'],'grantIntent':grant_intent}
if metadata_only:
    source = docs['workspace-source-local-transport-v1.schema.json']
    assert hashlib.sha256((schemas/'workspace-source-local-transport-v1.schema.json').read_bytes()).hexdigest() == '7c5bb10ec9df270ca82a9e14df2956063911f8e186436d84e91f01a336662745'
    profile={'profileId':app['profile']['profileId'],'profileRevision':app['profile']['revision'],'profileDigest':app['profile']['profileDigest'],'bundleDigest':app['profile']['bundleDigest']}
    candidate={k:app[k] for k in ('backend','native','runtime','sandbox')}
    candidate['profileBundleDigest']=profile['bundleDigest']
    authority={**candidate,'evidenceClass':'source','operator':{'keyId':'source_operator','keySHA256':byte_digest(operator)[7:]},'producer':{'keyId':'source_root','keySHA256':byte_digest(root_pem)[7:],'nodeTokenHash':source_node_hash}}
    if publication_only:authority.update(caseId='source_local_case',caseManifestDigest=app['caseManifestDigest'])
    fixture_key=pub(ec.generate_private_key(ec.SECP256R1()))
    permission=envelope({'formatVersion':1,'purpose':'source_installed_transport_permission','candidateInventoryDigest':digest(candidate),'profile':profile,'fixtureKeySHA256':byte_digest(fixture_key),'oracles':['http_cancel','tool_cancel','controller_deadline'],'issuedAt':stamp,'expiresAt':expiry})
    ref=digest(permission)
    adoption=envelope({'formatVersion':1,'purpose':'source_installed_profile_adoption','candidateInventoryDigest':digest(candidate),'profile':profile,'sourceTransportPermissionDigest':ref,'observedAt':stamp,'expiresAt':expiry},root_key,'source_root')
    local_entries=[{'oracle':oracle,'targetKind':'controller_activity' if n==3 else 'cell_session','targetId':tuple_['operationId'] if n==1 else 'source_target_'+str(n),'sourceId':entry['serviceRegistrationId'] if n==1 else 'source_service_'+str(n),'requestDigest':tuple_['requestDigest'] if n==1 else H,'localPreparationOrdinal':n,'localDeliveryOrdinal':n} for n,oracle in enumerate(['http_cancel','tool_cancel','controller_deadline'],1)]
    local_entries[2]['targetId']='msg_source_deadline'
    if publication_only:local_entries[1]['requestDigest']=H[7:]
    case3=envelope({'formatVersion':1,'purpose':'source_local_transport_case3','evidenceClass':'source','caseId':'source_local_case','authorityDigest':digest(authority),'candidateInventoryDigest':digest(candidate),'sourceTransportPermissionDigest':ref,'scope':owner,'tupleDigest':digest(app),'entries':local_entries,'providerRequests':0,'localDeliveries':3,'nativePreparations':3,'maxConcurrentPhysicalRequests':1,'retries':0,'issuedAt':stamp,'expiresAt':expiry})
    profile_metadata={'formatVersion':1,'evidenceClass':'source','profile':profile,'candidateInventoryDigest':digest(candidate),'sourceTransportPermissionDigest':ref,'permission':permission,'adoption':adoption}
    qual={**qualification,'activationDigest':H}
    prepare_metadata={'formatVersion':1,'evidenceClass':'source','targetKind':'cell_session','phase':'prepare','preparationId':entry['preparationId'],'profileMetadata':profile_metadata,'localCase':case3,'entry':local_entries[0],'applicability':app,'qualification':qual,'preparedTuple':tuple_,'preparedReceipt':None,'grant':None,'grantEnvelope':None,'fixtureCredentialKind':'synthetic_transport_authorization','providerRequests':0,'executionAuthority':False}
    prepare_metadata['basisDigest']=digest(prepare_metadata)
    control_metadata={**prepare_metadata,'phase':'execute','preparedReceipt':receipt,'grant':grant}
    control_metadata.pop('basisDigest');control_metadata['basisDigest']=digest(control_metadata)
    for value in (prepare_metadata,control_metadata):validate(source,'control',value)
    # A detached PARENT prepared tuple is required for metadata reader coverage;
    # no parent grant is asserted as local execution authority while its wire waits.
    parent_tuple=sample(producer['$defs']['controllerPreparedTuple'],producer)
    parent_tuple.update(owner=owner,serviceRegistrationId=local_entries[2]['sourceId'],inputId=local_entries[2]['targetId'],inputDigest=H,credentialBinding=app['connection'],authority={k:app['model'][k] for k in ('providerId','modelId','authMode')})
    parent_tuple['nativeRegistration']['nativeProjectId']='global'
    parent_metadata={**prepare_metadata,'targetKind':'controller_activity','preparationId':'source_parent_preparation','entry':local_entries[2],'preparedTuple':parent_tuple}
    parent_metadata.pop('basisDigest');parent_metadata['basisDigest']=digest(parent_metadata)
    validate(source,'control',parent_metadata)
    packet.update(sourceAuthority=authority,sourcePrepare=prepare_metadata,sourceControl=control_metadata,sourceParentPrepare=parent_metadata,producerPEM=base64.b64encode(root_pem).decode(),fixtureSigningPEM=base64.b64encode(fixture_key).decode(),legacyDetachedEnvelopeSignature=base64.b64encode(key.sign(canonical(permission),ec.ECDSA(hashes.SHA256()))).decode())
    if publication_only:
        local_grants=docs['workspace-source-local-grant-v1.schema.json']
        originals=docs['workspace-source-local-originals-v1.schema.json']
        assert hashlib.sha256((schemas/'workspace-source-local-grant-v1.schema.json').read_bytes()).hexdigest() == '57d1636fe3fb74e15ad1ae3ab263157559e2b7c6480eeaa77a5c4c15cb057117'
        specimens=[]
        for ordinal in (1,2,3):
            target='controller_activity' if ordinal==3 else 'cell_session'
            identifier='source_parent_preparation' if ordinal==3 else ('source_preparation' if ordinal==1 else 'source_tool_preparation')
            tuple_original=deepcopy(parent_tuple if ordinal==3 else tuple_)
            selected_entry=local_entries[ordinal-1]
            tuple_original['serviceRegistrationId']=selected_entry['sourceId']
            if ordinal==2:
                tuple_original['operationId']=selected_entry['targetId']
                tuple_original['requestDigest']=selected_entry['requestDigest']
            actual_receipt={'formatVersion':1 if ordinal==3 else 3,'preparedTuple':tuple_original,
                'credentialId':'source_credential_'+str(ordinal),'nativeCredentialId':'source_native_credential_'+str(ordinal)}
            if ordinal==3:actual_receipt.update(preparationId=identifier,targetKind=target)
            preimage={k:v for k,v in actual_receipt.items() if k not in ('formatVersion','targetKind')}
            actual_receipt['bindingDigest']=digest(preimage)
            actual_receipt['preparedReceiptDigest']=digest(preimage|{'bindingDigest':actual_receipt['bindingDigest']})
            native=deepcopy(grant) if ordinal!=3 else sample(producer['$defs']['controllerActivityGrant'],producer)
            session='ses_source_parent' if ordinal==3 else ('ses_source_tool' if ordinal==2 else grant['sessionId'])
            input_='msg_source_deadline' if ordinal==3 else ('msg_source_tool' if ordinal==2 else grant['inputId'])
            native.update(grantId='source_local_grant_'+str(ordinal),preparedReceiptDigest=actual_receipt['preparedReceiptDigest'],expiresAt=expiry)
            if ordinal==3:
                tuple_original['nativeRegistration']['nativeSessionId']=session
                # Rebind the immutable receipt after the independently fixed session.
                preimage={k:v for k,v in actual_receipt.items() if k not in ('formatVersion','targetKind','bindingDigest','preparedReceiptDigest')}
                actual_receipt['bindingDigest']=digest(preimage)
                actual_receipt['preparedReceiptDigest']=digest(preimage|{'bindingDigest':actual_receipt['bindingDigest']})
                native.update(preparationId=identifier,preparedReceiptDigest=actual_receipt['preparedReceiptDigest'],reservationId='local_reservation_'+str(ordinal),
                    caseId='source_local_case',caseManifestDigest=app['caseManifestDigest'],policyDigest=ref,
                    requestIndex=1,physicalIndex=3,maxInputTokens=1046576,maxOutputTokens=1000,maxUsdMicros=421000,deadlineAt=expiry)
            else:
                native.update(operationId=tuple_original['operationId'],sessionId=session,inputId=input_)
            metadata={**prepare_metadata,'targetKind':target,'phase':'execute','preparationId':identifier,
                'entry':selected_entry,'preparedTuple':tuple_original,'preparedReceipt':actual_receipt,'grant':native,'grantEnvelope':None}
            metadata.pop('basisDigest');metadata['basisDigest']=digest(metadata)
            validate(source,'control',metadata)
            registered={'sandboxId':owner['sandboxId'],'sandboxGeneration':1,'nativeInstance':'source_instance_'+str(ordinal),
                'nativeIdentityDigest':digest({'detachedIdentity':ordinal}),'registrationDigest':digest({'detachedRegistration':ordinal})}
            owning={'serviceRegistrationId':selected_entry['sourceId'],'serviceGeneration':tuple_original['serviceGeneration'],
                'operationId':'source_parent_operation' if ordinal==3 else tuple_original['operationId'],'desiredRevision':1,'actionRevision':1,'configDigest':tuple_original['configDigest'],'desiredState':'active'}
            original_control=owning|{'controlRevision':1}
            current=original_control|{'controlDigest':digest(original_control),'observedAt':stamp,'expiresAt':expiry}
            current_envelope=envelope({'formatVersion':1,'purpose':'source_current_control_observation','scope':owner,
                'candidateInventoryDigest':digest(candidate),'targetKind':target,'preparationId':identifier,
                'registeredProcess':registered,'currentControl':current},root_key,'source_root')
            current_response={'observation':current_envelope,'controlBase64':base64.b64encode(canonical(original_control)).decode()}
            validate(originals,'currentControlResponse',current_response)
            retained={'fullManifestDigest':H,'allocationId':'local_allocation_'+str(ordinal),'reservationId':'local_reservation_'+str(ordinal),'reservedUsdMicros':421000}
            selection={'formatVersion':1,'purpose':'source_local_execution_grant','evidenceClass':'source',
                'grantId':native['grantId'],'requestId':'source_local_request_'+str(ordinal),'targetKind':target,'preparationId':identifier,
                'preparedTupleDigest':digest(tuple_original),'preparedReceiptDigest':actual_receipt['preparedReceiptDigest'],
                'credentialId':actual_receipt['credentialId'],'nativeCredentialId':actual_receipt['nativeCredentialId'],
                'authorityDigest':digest(authority),'caseId':'source_local_case','localCaseEnvelopeDigest':digest(case3),
                'entry':selected_entry,'candidateInventoryDigest':digest(candidate),'sourceTransportPermissionDigest':ref,
                'scope':owner,'qualification':qual,'sessionId':session,'inputId':input_,'nativeGrant':native,
                'registeredProcess':registered,'currentControl':current,'retainedExposure':retained,
                'providerRequests':0,'maxConcurrentPhysicalRequests':1,'retries':0,'issuedAt':stamp,'deadlineAt':expiry,'expiresAt':expiry}
            validate(local_grants,'localGrant',selection)
            selection_envelope=envelope(selection)
            admission={'formatVersion':1 if ordinal==3 else 3,'targetKind':target,'preparedReceipt':actual_receipt,'grant':native}
            header=deepcopy(observation) if ordinal!=3 else {'formatVersion':1,'targetKind':'controller_authorization'}
            header.update(preparationId=identifier,preparedReceiptDigest=actual_receipt['preparedReceiptDigest'],authorizationSha256=byte_digest(b'Bearer explicitly-synthetic'))
            header_envelope=envelope(header,root_key,'source_root')
            activation={'formatVersion':1,'purpose':'source_local_execution_activation','evidenceClass':'source',
                'targetKind':target,'preparationId':identifier,'grantId':native['grantId'],'grantEnvelopeDigest':digest(selection_envelope),
                'admissionDigest':digest(admission),'preparedReceiptDigest':actual_receipt['preparedReceiptDigest'],
                'sourceTransportPermissionDigest':ref,'originalAuthorizationObservationDigest':digest(header_envelope),
                'authorizationSha256':header['authorizationSha256'],'currentControl':current,'issuedAt':stamp,'deadlineAt':expiry,'expiresAt':expiry}
            published={'formatVersion':1,'purpose':'source_local_published_control','evidenceClass':'source','targetKind':target,
                'preparationId':identifier,'selection':selection_envelope,'admission':admission,'activation':envelope(activation),'currentControl':current}
            validate(local_grants,'localPublishedControl',published)
            specimens.append({'metadata':metadata,'published':published,'owning':owning,'registered':registered,
                'currentResponse':current_response,'admission':admission,'authorizationObservation':header_envelope,
                'authorizationSha256':header['authorizationSha256'],'retainedExposure':retained})
        packet['sourcePublications']=specimens
        packet['publicationOperatorSigningPEM']=base64.b64encode(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())).decode()
if source_manager_application is not None:
    packet['managerSourceApplication'] = source_manager_application
with destination.open('x') as f:
    if coding_result_boundary or integration_result_boundary: destination.chmod(0o600)
    json.dump(packet,f,ensure_ascii=False,sort_keys=True,separators=(',',':') if publication_only else (', ', ': '))
print('fresh synthetic signed complete prepare/execute owner-schema validation GREEN; no LIVE permission')
