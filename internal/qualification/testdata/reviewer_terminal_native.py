"""Same signed q4 SOURCE terminal DATA supplier; frozen Sandbox capture consumer.

Provider output and native execution are explicitly detached SOURCE suppliers.
No native binary/model/ROOT signer runs; actual SQLite and private output do.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

packet, base = map(Path, sys.argv[1:])
f = json.loads(packet.read_bytes())
sandbox = Path(os.environ['WARPMETAL_PRODUCT_SOURCE_NATIVE_SCRIPT']).resolve().parents[1]
sys.path[:0] = [str(sandbox/'tests'), str(sandbox/'runner')]
from test_sv09_attachment_boundary import create_native_fixture, append_event
from warpmetal_reviewer_capture import capture_assessment
from warpmetal_sv09_tools import ChildSelection, canonical, digest

c = f['execute']; q = c['generation']['policy']['payload']; grant = c['generation']['activation']['payload']['grant']
receipt = q['preparedReceipt']; entry = f['witness']['Entry']; work = base/'work'
prepared = json.loads((base/'prepared-native-observation.json').read_bytes())['session']
assert prepared['agent'] == 'warpmetal-managed'
session = {'id':entry['nativeSessionId'],'parentID':prepared['parentId'],'projectID':entry['nativeProjectId'],'location':{'directory':str(work)}}
selected = ChildSelection(session['id'],session['parentID'],session['projectID'],str(work),None,canonical(receipt),canonical(grant),q['case']['caseManifestDigest'])
database = base/'reviewer-terminal-source.sqlite'
create_native_fixture(database,selected,session,receipt,grant)
database.chmod(0o600)
assessment = '{"disposition":"approve","findings":[]}'
response = {'type':'response.completed','response':{'id':'resp_detached_source_reviewer','model':receipt['preparedTuple']['authority']['modelId'],'status':'completed',
    'output':[{'type':'message','role':'assistant','content':[{'type':'output_text','text':assessment}]}]}}
raw_response = b'data: '+canonical(response)+b'\n\n'
(base/'reviewer-terminal-source-response.body').write_bytes(raw_response)
(base/'reviewer-terminal-source-response.body').chmod(0o600)
with sqlite3.connect(database) as db:
    db.execute('UPDATE session_v2 SET agent=?,model=?',(prepared['agent'],json.dumps(prepared['model'])))
    row=json.loads(db.execute('SELECT data FROM event WHERE seq=1').fetchone()[0]);row['item']['payload']['text']=f['firstText']
    db.execute('UPDATE event SET data=? WHERE seq=1',(json.dumps(row),))
    row=json.loads(db.execute('SELECT data FROM event WHERE seq=4').fetchone()[0]);row.update(agent=prepared['agent'],model=prepared['model'])
    db.execute('UPDATE event SET data=? WHERE seq=4',(json.dumps(row),))
    for seq,kind,data in [(5,'session.text.started.1',{'ordinal':0,'meta':False}),(6,'session.text.ended.1',{'ordinal':0,'meta':False,'text':assessment}),
                         (7,'session.step.ended.1',{'finish':'stop'}),(8,'session.execution.succeeded.1',{})]:
        append_event(db,selected,seq,kind,{'assistantMessageID':'msg_synthetic_assistant',**data})
    db.execute('UPDATE event_sequence SET seq=8');db.execute('UPDATE session_guard_state SET execution_terminal_seq=8')
original = {'generationDigest':c['descriptor']['generationDigest'],'sessionId':selected.session_id,'inputId':grant['inputId'],'requestIndex':1,
            'output':response['response']['output'],'responseDigest':'sha256:'+hashlib.sha256(raw_response).hexdigest()}
class SourceAuthority:
    def control(self): return c
    def retained_database(self): return database
    def reviewer_original(self): return original

authority=SourceAuthority();authority.selected=selected
authority.root_fd=os.open(work,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
journal=base/'reviewer-terminal-private';journal.mkdir(mode=0o700)
authority.journal_fd=os.open(journal,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
    proof=capture_assessment(authority)
    output=base/'reviewer-terminal-capture.json';output.write_bytes(canonical(proof));output.chmod(0o400)
    assert (work/q['reviewDelivery']['assessmentPath']).read_bytes()==assessment.encode()
    print(json.dumps({'classification':'signed q4 selection, detached provider/native DATA, actual frozen SQLite terminal capture','nativeExecutable':0,'provider':0,'rootSigner':0}))
finally:
    os.close(authority.journal_fd);os.close(authority.root_fd)
