"""Explicit SOURCE originals for the existing child boundary, never target acceptance."""
import base64
from copy import deepcopy


def content(intent, target_binding, stamp, digest, byte_digest):
    plan_bytes = b'SOURCE integrator plan: update the accepted target once.\n'
    target_bytes = b'SOURCE author target before exclusive integration handoff.\n'
    plan = {'path': 'plans/source-integration.md', 'sourceDigest': byte_digest(plan_bytes), 'status': 'accepted'}
    target = {'path': 'output/coding/entry.txt', 'sourceDigest': byte_digest(target_bytes), 'status': 'accepted'}
    artifact = {'artifactId': 'source_target_artifact', 'digest': target['sourceDigest'], 'byteCount': len(target_bytes), 'contentType': 'text/plain'}
    prepared = intent['prepareBody']['content']
    prepared['context'] = 'Approved full plan:\n' + plan_bytes.decode() + 'Approved full target:\n' + target_bytes.decode()
    prepared['workflowPacket']['planRef'] = plan
    prepared['workflowPacket']['writeScope'] = {'mode': 'exclusive', 'paths': ['output/coding']}
    intent['plan']['planRef'] = plan
    intent['plan']['contentDigest'] = plan['sourceDigest']
    # Exact detached SOURCE result original; never an accepted backend result.
    result = {'outcome': 'completed', 'consumedRefs': [], 'mismatches': [], 'stateEvidence': [],
              'outputs': [{'type': 'document', 'sourceRefs': [plan], 'method': 'Declared SOURCE author fixture', 'output': artifact}],
              'effectReceipts': [], 'remainingWork': []}
    original = {'binding': target_binding, 'assignmentId': 'source_author_assignment', 'result': result}
    intent['target']['resultDigest'] = digest(original)
    receipt = {'formatVersion': 1, **intent['target'], 'executionId': target_binding['executionId'],
               'assignmentId': original['assignmentId'], 'state': 'reported', 'createdAt': stamp}
    detail = {'formatVersion': 1, 'receipt': receipt, **original, 'latestDecision': None}
    return {'plan': plan, 'planBytes': plan_bytes, 'target': target, 'targetBytes': target_bytes,
            'artifact': artifact, 'targetBinding': target_binding, 'targetDetail': detail}


def policy(q, p, root, binding, assignment, input_id, first_text, source, expiry, canonical, digest, validate, schema):
    target_binding = source['targetBinding']
    scopes, spans, roots = [], [], {}
    raw_input = first_text.encode()
    for kind, reference, raw, artifact in (
        ('packet_source', source['plan'], source['planBytes'], None),
        ('target_artifact', source['target'], source['targetBytes'], source['artifact']),
    ):
        use = 'integration_' + kind
        read_root = {'formatVersion': 2, 'binding': binding, 'assignmentId': assignment['assignmentId'], 'use': use,
                     'rootKind': 'workspace', 'workspace': root['workspace'], 'registeredSourceId': root['registeredSourceId'],
                     'rootAttestation': root['workspace']['rootAttestation'], 'producer': root['producer'],
                     'candidateDescriptorDigest': root['candidateDescriptorDigest'], 'expiresAt': expiry}
        grant = {'formatVersion': 2, 'binding': binding, 'assignmentId': assignment['assignmentId'], 'use': use,
                 'reference': reference, 'artifact': artifact, 'byteCount': len(raw), 'rootGrantDigest': digest(read_root),
                 'manifestDigest': digest([artifact] if artifact else [reference]), 'target': assignment['target'],
                 'targetBinding': target_binding, 'expiresAt': expiry}
        scope = {'grant': grant, 'root': read_root}
        validate(schema, 'integrationSourceScope', scope)
        fragment = canonical(raw.decode())[1:-1]
        assert raw_input.count(fragment) == 1
        spans.append({'kind': kind, 'reference': reference, 'artifact': artifact, 'rootGrantDigest': digest(read_root),
                      'encoding': 'json_string_fragment_utf8', 'byteCount': len(raw),
                      'offset': raw_input.index(fragment), 'length': len(fragment)})
        scopes.append(scope)
        roots[digest(read_root)] = read_root
    delivery = {'formatVersion': 1, 'deliveryPlanId': 'source_integration_delivery', 'intent': q['intent'],
                'binding': binding, 'assignment': assignment, 'target': assignment['target'], 'targetBinding': target_binding,
                'inputId': input_id, 'inputDigest': p['instructions']['inputDigest'], 'inputByteCount': len(raw_input),
                'spans': spans, 'notAfter': expiry}
    delivery['deliveryPlanDigest'] = digest(delivery)
    q.update(formatVersion=3, sourceReads=scopes, integrationDelivery=delivery)
    validate(schema, 'productPolicy', q)
    return roots, {'classification': 'declared SOURCE target and bytes; no accepted result, ROOT custody, or read ACK',
                   'targetBinding': target_binding, 'targetDetail': source['targetDetail'], 'artifact': source['artifact'], 'reference': source['target'],
                   'targetBase64': base64.b64encode(source['targetBytes']).decode(),
                   'packetBase64': base64.b64encode(source['planBytes']).decode()}


def source_application(intent, producer_doc, sample, digest, stamp, expiry, producer, envelope, validate):
    """Fresh complete declared SOURCE application, never an installed/root claim."""
    from copy import deepcopy
    scope = intent['scope']; owner = scope['owner']; engine = intent['prepareBody']['profile']
    approved = scope['approvedProfile']
    selection = {'authority': intent['prepareBody']['authority'], 'credentialBinding': intent['prepareBody']['credentialBinding']}
    limits = {k: None for k in ('maxActiveChildren','modelRequests','modelTurns','inputTokens','outputTokens','usdMicros','wallClockSeconds')}
    config = {'formatVersion':1,'workspaceName':'Declared SOURCE integration','purpose':'Exercise current application join before target delivery',
        'profiles':[{'profileId':'source_profile','name':'SOURCE profile','description':'','approvedProfile':approved,'tools':[],'modelSelection':selection}],
        'roles':{'managerProfileId':'source_profile','advisorProfileId':'source_profile'},'lanes':[],'limits':limits}
    deps = {'formatVersion':1,'phase':'prompt_free','setupReceipts':[{'setupOperationId':engine['setupOperationId'],'receiptDigest':digest('SOURCE setup receipt')}],
        'profiles':[{'approvedProfile':approved,'entryPath':'AGENTS.md','files':[{'path':'AGENTS.md','sha256':digest('SOURCE profile bytes'),'byteCount':1}]}],'roles':[],'tools':[]}
    for role in ('manager','orchestrator'):
        binding = {'owner':owner,'role':role,'serviceRegistrationId':'source_parent_'+role,'serviceGeneration':1,'approvedProfile':approved}
        deps['roles'].append({'binding':binding,'projection':{'nativeAgentId':'warpmetal-controller-'+role,'systemDigest':digest('SOURCE '+role),'approvedProfile':approved,'modelSelection':selection,'toolsDisabled':True,'mcpDisabled':True},
            'instructions':{'instructionRevision':1,'instructionDigest':digest('SOURCE '+role)},'workspace':scope['workspace'],'profile':engine})
    op = {'formatVersion':1,'kind':'configuration_application','operationId':'source_integration_application','operationDigest':'','accountId':owner['accountId'],'taskId':owner['taskId'],'serverId':owner['serverId'],'sandboxId':owner['sandboxId'],'sandboxGeneration':owner['sandboxGeneration'],
        'setupIntentId':'source_setup_intent','configurationId':'source_configuration','configurationRevision':1,'configurationDigest':digest(config),'targetRuntimeRevision':1,
        'setupOperationIds':[engine['setupOperationId']],'profiles':[approved],'materializerDigest':digest('SOURCE materializer'),'roleBindings':[r['binding'] for r in deps['roles']],
        'limits':limits,'configuration':config,'dependencies':deps,'dependencyDigest':digest(deps),
        'connectionRevisionDigest':digest([{'profileId':'source_profile','credentialBinding':selection['credentialBinding']}]),
        'modelAuthorityDigest':digest([{'profileId':'source_profile','authority':selection['authority']}]),'producer':producer,'expiresAt':expiry}
    op['operationDigest']=digest({k:v for k,v in op.items() if k!='operationDigest'})
    validate(producer_doc,'applicationOperation',op)
    payload=sample(producer_doc['$defs']['applicationPayload'],producer_doc)
    payload.update(requestId='source_application_proof',taskId=owner['taskId'],nodeTokenHash=producer['nodeTokenHash'],issuedAt=stamp,notAfter=expiry,operationId=op['operationId'],operationDigest=op['operationDigest'])
    native=payload['nativeReceipt']; native.update(operationId=op['operationId'],operationDigest=op['operationDigest'],observedAt=stamp,serviceRegistrationId=deps['roles'][0]['binding']['serviceRegistrationId'],nativeSessionId='ses_source_manager',nativeProjectId='global',nativeLocationDigest=digest('SOURCE registered parent location'),rootAttestation=scope['workspace']['rootAttestation'])
    readback=native['readback'];readback.update(operation=op,appliedRuntimeRevision=1,setupReceipts=deps['setupReceipts'],profiles=deps['profiles'],limits=limits,materializerDigest=op['materializerDigest'],dependencyDigest=op['dependencyDigest'])
    readback['roleBindings']=[]
    for dep in deps['roles']:
        applied=sample(producer_doc['$defs']['appliedRole'],producer_doc);applied['binding']=dep['binding']
        applied['nativeRegistration'].update(registeredSourceId='source_'+dep['binding']['role'],workspaceEpoch=scope['workspace']['workspaceEpoch'],nativeSessionId='ses_source_'+dep['binding']['role'],nativeProjectId='global',nativeLocationDigest=digest('SOURCE registered parent location'))
        applied['nativeRoleReadback'].update(role=dep['binding']['role'],nativeAgentId=dep['projection']['nativeAgentId'],sessionAgentId=dep['projection']['nativeAgentId'],parentSessionId=None,roleAgentDigest=digest(dep['projection']))
        readback['roleBindings'].append(applied)
    proof=envelope(payload)
    validate(producer_doc,'applicationEnvelope',proof)
    return {'classification':'declared SOURCE application/configuration and acceptance, not installed ROOT/backend acceptance','operation':deepcopy(op),'envelope':proof}
