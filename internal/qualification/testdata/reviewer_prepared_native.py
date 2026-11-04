"""SOURCE native DATA supplier for the existing signed reviewer journey.

The actual fixed reader consumes SQLite. No native executable, key, signer,
backend role operation, admission or consumed grant is produced by this fixture.
"""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys

packet, output = map(Path, sys.argv[1:3])
reopen = sys.argv[3:] == ["--reopen"]
assert not sys.argv[3:] or reopen
value = json.loads(packet.read_bytes())
path = Path(os.environ['WARPMETAL_PRODUCT_SOURCE_NATIVE_SCRIPT']).resolve().parents[1] / 'runner/warpmetal_child_prepared.py'
spec = importlib.util.spec_from_file_location('source_prepared_reader', path)
reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)
database = packet.with_suffix('.sqlite')
s, receipt = value['session'], value['receipt']
b = receipt['preparedTuple']['credentialBinding']
if not reopen:
    with sqlite3.connect(database) as db:
        db.executescript('''CREATE TABLE session_v2(id TEXT,project_id TEXT,parent_id TEXT,fork_session_id TEXT,directory TEXT,workspace_id TEXT,agent TEXT,model TEXT,time_archived INTEGER,time_suspended INTEGER);
        CREATE TABLE session_credential_binding(session_id TEXT,format_version INTEGER,credential_id TEXT,native_credential_id TEXT,connection_id TEXT,connection_revision INTEGER,provider_id TEXT,auth_mode TEXT,binding_digest TEXT,prepared_receipt_digest TEXT,prepared_tuple_json TEXT,state TEXT);
        CREATE TABLE session_execution_grant(grant_id TEXT,session_id TEXT);CREATE TABLE session_guard_receipt(session_id TEXT);CREATE TABLE session_inbox(id TEXT,session_id TEXT);
        CREATE TABLE session_guard_state(session_id TEXT,input_seq INTEGER,admission_seq INTEGER,context_seq INTEGER,execution_started_seq INTEGER,execution_terminal_seq INTEGER);
        CREATE TABLE event_sequence(aggregate_id TEXT,seq INTEGER);CREATE TABLE event(id TEXT,aggregate_id TEXT,seq INTEGER,created INTEGER,type TEXT,data TEXT);''')
        db.execute('INSERT INTO session_v2 VALUES(?,?,?,NULL,?,NULL,?,?,NULL,NULL)',(s['id'],s['projectId'],s['parentId'],s['directory'],s['agent'],json.dumps(s['model'])))
        db.execute('INSERT INTO session_credential_binding VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(s['id'],3,receipt['credentialId'],receipt['nativeCredentialId'],b['connectionId'],b['connectionRevision'],b['providerId'],b['authMode'],receipt['bindingDigest'],receipt['preparedReceiptDigest'],json.dumps(receipt['preparedTuple']),'bound'))
        db.execute('INSERT INTO session_guard_state VALUES(?,NULL,NULL,NULL,NULL,NULL)',(s['id'],))
        db.execute('INSERT INTO event_sequence VALUES(?,0)',(s['id'],))
        db.execute("INSERT INTO event VALUES('created',?,0,1,'session.created.2',?)",(s['id'],json.dumps({'sessionID':s['id'],'projectID':s['projectId'],'parentID':s['parentId'],'location':{'directory':s['directory']}})))
    database.chmod(0o600)
capture = reader.capture(database, s['id'])
output.write_text(json.dumps(capture,sort_keys=True,separators=(',',':')))
output.chmod(0o600)
