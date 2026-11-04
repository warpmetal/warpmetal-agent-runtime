"""Offline validation of emitted Runtime source facts against F1's ONE contract."""
import hashlib
import json
from pathlib import Path
import sys
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

contracts, evidence = map(Path, sys.argv[1:])
path = contracts / "workspace-workflow-producer-v1.schema.json"
raw = path.read_bytes()
assert hashlib.sha256(raw).hexdigest() == "60bf59da8175cf0e6aad2b282963bb43ff01ab06125f728958bf972dd80ff4af"
schema = json.loads(raw)
registry = Registry()
for candidate in contracts.glob("*.schema.json"):
    value = json.loads(candidate.read_bytes())
    if "$id" in value:
        registry = registry.with_resource(value["$id"], Resource.from_contents(value))
facts = json.loads(evidence.read_bytes())
checked = 0
def validate(name, value):
    global checked
    Draft202012Validator({"$ref": schema["$id"] + "#/$defs/" + name}, registry=registry).validate(value)
    checked += 1

validate("applicationEnvelope", facts["envelope"])
for parent, report in zip(facts["parents"], facts["reports"], strict=True):
    validate("parentServiceIntent", parent)
    validate("parentServiceReport", report)
    unsigned = {k: v for k, v in report.items() if k != "receiptDigest"}
    canonical = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    assert "sha256:" + hashlib.sha256(canonical).hexdigest() == report["receiptDigest"]
for call in facts["helperCalls"]:
    if call["action"] == "register-source":
        validate("parentSourceRegistration", call["request"]["registration"])
    if call["action"] == "start":
        validate("parentServiceIntent", call["request"]["controllerParent"])
        validate("roleAgentProjection", call["request"]["roleProjection"])
print(json.dumps({"schemaSHA256": hashlib.sha256(raw).hexdigest(), "checks": checked,
                  "result": "source_wire_only_not_backend_or_installed_acceptance"}, indent=2))
