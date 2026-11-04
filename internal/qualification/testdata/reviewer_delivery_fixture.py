"""Fresh SOURCE reviewer layout. No accepted target, role lease or read credit."""
import base64
import hashlib


def content(intent, target_binding, stamp, canonical, digest, byte_digest):
    plan_bytes = b'SOURCE reviewer plan: independently compare original and candidate.\n'
    target_bytes = b'SOURCE original author artifact before integration.\n'
    candidate_bytes = b'SOURCE current candidate after independent integration.\n'
    plan = {'path': 'plans/source-review.md', 'sourceDigest': byte_digest(plan_bytes), 'status': 'accepted'}
    target = {'path': 'output/coding/entry.txt', 'sourceDigest': byte_digest(target_bytes), 'status': 'accepted'}
    candidate_ref = {**target, 'sourceDigest': byte_digest(candidate_bytes)}
    artifact = {'artifactId': 'source_target_artifact', 'digest': target['sourceDigest'], 'byteCount': len(target_bytes), 'contentType': 'text/plain'}
    result = {'outcome': 'completed', 'consumedRefs': [], 'mismatches': [], 'stateEvidence': [],
              'outputs': [{'type': 'document', 'sourceRefs': [plan], 'method': 'Declared SOURCE author', 'output': artifact}],
              'effectReceipts': [], 'remainingWork': []}
    original = {'binding': target_binding, 'assignmentId': 'source_author_assignment', 'result': result}
    intent.update(purpose='review', target={'resultId': 'synthetic_result', 'resultRevision': 1, 'resultDigest': digest(original)})
    receipt = {'formatVersion': 1, **intent['target'], 'executionId': target_binding['executionId'],
               'assignmentId': original['assignmentId'], 'state': 'reported', 'createdAt': stamp}
    detail = {'formatVersion': 1, 'receipt': receipt, **original, 'latestDecision': None}
    candidate = {'integration': {'receiptId': 'source_integration', 'receiptDigest': digest('declared SOURCE integration')},
                 'afterDigest': digest([candidate_ref]), 'manifestDigest': digest([artifact])}
    prepared = intent['prepareBody']['content']
    prepared['context'] = ('Approved full plan:\n' + plan_bytes.decode() + 'Original target artifact:\n' + target_bytes.decode()
                           + 'Current candidate:\n' + candidate_bytes.decode())
    prepared['constraints'] = 'Return exact JSON with only disposition and findings; approve requires empty findings. No Markdown or tools.'
    prepared['workflowPacket']['planRef'] = plan
    prepared['workflowPacket']['writeScope'] = {'mode': 'exclusive', 'paths': ['output/review']}
    intent['prepareBody']['role'] = 'reviewer'
    intent['plan']['planRef'] = plan
    intent['plan']['contentDigest'] = plan['sourceDigest']
    first_text = canonical({'formatVersion': 1, 'kind': 'workspace_workflow_packet', 'content': prepared})
    input_id = 'msg_' + base64.b32encode(hashlib.sha256(intent['prepareBody']['operationId'].encode()).digest()).decode().rstrip('=')
    intent.update(targetReceipt=receipt, candidate=candidate, tools=[],
                  reviewInput={'inputId': input_id, 'inputDigest': byte_digest(first_text), 'inputByteCount': len(first_text),
                               'candidate': candidate, 'manifestDigest': digest([artifact])})
    intent['packetContentDigest'] = digest(prepared)
    return {'plan': plan, 'planBytes': plan_bytes, 'target': target, 'targetBytes': target_bytes,
            'candidateReference': candidate_ref, 'candidateBytes': candidate_bytes, 'candidate': candidate,
            'artifact': artifact, 'targetBinding': target_binding, 'targetDetail': detail}


def policy(q, p, root, binding, assignment, input_id, first_text, source, expiry, canonical, digest, validate, schema):
    scopes, spans, roots = [], [], {}
    raw_input = first_text.encode()
    manifest_digest = digest([source['artifact']])
    for kind, reference, raw in (
        ('packet_source', source['plan'], source['planBytes']),
        ('candidate_source', source['candidateReference'], source['candidateBytes']),
    ):
        use = 'review_' + kind
        read_root = {'formatVersion': 1, 'binding': binding, 'assignmentId': assignment['assignmentId'], 'use': use,
                     'rootKind': 'workspace', 'workspace': root['workspace'], 'registeredSourceId': root['registeredSourceId'],
                     'rootAttestation': root['workspace']['rootAttestation'], 'producer': root['producer'],
                     'candidateDescriptorDigest': root['candidateDescriptorDigest'], 'installedManifestDigest': None, 'expiresAt': expiry}
        grant = {'formatVersion': 1, 'binding': binding, 'assignmentId': assignment['assignmentId'], 'use': use,
                 'reference': reference, 'artifact': None, 'byteCount': len(raw), 'rootGrantDigest': digest(read_root),
                 'manifestDigest': manifest_digest, 'candidate': source['candidate'] if kind == 'candidate_source' else None,
                 'expiresAt': expiry}
        scope = {'grant': grant, 'root': read_root}
        validate(schema, 'physicalSourceScope', scope)
        fragment = canonical(raw.decode())[1:-1]
        assert raw_input.count(fragment) == 1
        spans.append({'kind': kind, 'reference': reference, 'artifact': None, 'rootGrantDigest': digest(read_root),
                      'encoding': 'json_string_fragment_utf8', 'byteCount': len(raw),
                      'offset': raw_input.index(fragment), 'length': len(fragment)})
        scopes.append(scope)
        roots[digest(read_root)] = read_root
    authority = {'formatVersion': 1, 'purpose': 'reviewer_target_artifact', 'binding': binding,
                 'assignmentId': assignment['assignmentId'], 'target': assignment['target'], 'targetBinding': source['targetBinding'],
                 'artifact': source['artifact'], 'reference': source['target'], 'manifestDigest': manifest_digest,
                 'candidate': source['candidate'], 'producer': root['producer'],
                 'candidateDescriptorDigest': root['candidateDescriptorDigest'], 'expiresAt': expiry}
    validate(schema, 'artifactAuthority', authority)
    fragment = canonical(source['targetBytes'].decode())[1:-1]
    assert raw_input.count(fragment) == 1
    spans.append({'kind': 'target_artifact', 'reference': source['target'], 'artifact': source['artifact'],
                  'artifactAuthorityDigest': digest(authority), 'encoding': 'json_string_fragment_utf8',
                  'byteCount': len(source['targetBytes']), 'offset': raw_input.index(fragment), 'length': len(fragment)})
    delivery = {'formatVersion': 2, 'deliveryPlanId': 'source_review_delivery', 'intent': q['intent'],
                'binding': binding, 'assignment': assignment, 'target': assignment['target'], 'candidate': source['candidate'],
                'inputId': input_id, 'inputDigest': p['instructions']['inputDigest'], 'inputByteCount': len(raw_input),
                'spans': sorted(spans, key=lambda s: s['offset']), 'assessmentPath': 'output/review/assessment.json', 'notAfter': expiry}
    delivery['deliveryPlanDigest'] = digest(delivery)
    q.update(formatVersion=4, sourceReads=scopes, artifactReads=[authority], reviewDelivery=delivery)
    validate(schema, 'productPolicy', q)
    return roots, {'classification': 'declared SOURCE originals; no accepted result, own role lease, ROOT custody or read ACK',
                   'targetDetail': source['targetDetail'], 'artifact': source['artifact'], 'reference': source['target'],
                   'targetBase64': base64.b64encode(source['targetBytes']).decode(),
                   'packetBase64': base64.b64encode(source['planBytes']).decode(),
                   'candidateBase64': base64.b64encode(source['candidateBytes']).decode()}
