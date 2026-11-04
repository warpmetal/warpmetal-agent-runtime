"""Fresh, explicitly detached SOURCE inputs for the existing SQLite journey.

No backend, enrollment, provider, native, or ROOT operation occurs here. Unsigned
structural templates are selected before generating any key, digest or signature.
The real Go boundary measures SQLite and retains its own first signed opening.
"""
import base64
import copy
import datetime as dt
import hashlib
import json
import pathlib
import sys
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import Draft202012Validator
from referencing import Registry, Resource


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def write(path, value, private=False):
    path.write_bytes(value if isinstance(value, bytes) else canonical(value))
    path.chmod(0o600 if private else 0o644)


def main():
    frozen, old_source, old_schemas, output = map(pathlib.Path, sys.argv[1:])
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    documents = {}
    for directory in (old_schemas, frozen / "base", frozen):
        for path in directory.glob("*.schema.json"):
            document = json.loads(path.read_bytes())
            documents[document["$id"]] = document
    registry = Registry().with_resources((uri, Resource.from_contents(doc)) for uri, doc in documents.items())

    def validate(name, definition, value):
        uri = "https://api.warpmetal.com/contracts/" + name
        Draft202012Validator({"$ref": uri + "#/$defs/" + definition}, registry=registry).validate(value)

    now = dt.datetime.now(dt.timezone.utc)
    stamp = lambda x: x.isoformat().replace("+00:00", "Z")
    old = json.loads(old_source.read_bytes())
    if "old" in old:  # Prior packet is an unsigned template only, never a reissued original.
        old = {"authority": old["old"]["authority"], "demand": old["old"]["demand"]["payload"]}
    examples = json.loads((frozen / "structural-instances.json").read_bytes())["examples"]
    multi = (frozen / "full21-financial-examples.json").exists()
    current = {key: copy.deepcopy(next(x["value"] for x in examples if x["definition"] == definition))
               for key, definition in (("authority", "authority5" if multi else "authority4"), ("demand", "demandManifest"))}
    operator, producer = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    public = lambda key: key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    op_public, producer_public = public(operator), public(producer)
    private_path = output / "producer.private.pem"
    write(private_path, producer.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), True)
    write(output / "operator.public.pem", op_public)
    write(output / "producer.public.pem", producer_public)
    token_hash = hashlib.sha256(b"explicit-family-source-node").hexdigest()

    def envelope(payload):
        signature = operator.sign(canonical(payload), ec.ECDSA(hashes.SHA256()))
        operator.public_key().verify(signature, canonical(payload), ec.ECDSA(hashes.SHA256()))
        return {"payload": payload, "keyId": "source_family_operator", "signature": base64.b64encode(signature).decode()}

    def build(template, version):
        authority, demand = copy.deepcopy(template["authority"]), copy.deepcopy(template["demand"])
        case_id = "source_family_" + str(version) + "_" + uuid.uuid4().hex[:12]
        case_digest = digest({"sourceOnly": True, "caseId": case_id, "createdAt": stamp(now)})
        authority["caseId"], authority["caseManifestDigest"] = case_id, case_digest
        authority["operator"] = {"keyId": "source_family_operator", "keyPath": str(output / "operator.public.pem"), "keySHA256": digest(op_public)[7:]}
        authority["producer"] = {"keyId": "source_family_producer", "keyPath": str(output / "producer.public.pem"), "keySHA256": digest(producer_public)[7:], "nodeTokenHash": token_hash}
        authority["evidenceRoot"] = str(output)
        inventory = authority["tupleInventory"]
        inventory["caseId"], inventory["observedAt"] = case_id, stamp(now)
        tuple_map = {}
        for item in inventory["tuples"]:
            previous = item["tupleDigest"]
            item["applicability"]["caseManifestDigest"] = case_digest
            item["tupleDigest"] = digest(item["applicability"])
            tuple_map[previous] = item["tupleDigest"]
        for allocation in demand["allocations"]:
            allocation["tupleDigest"] = tuple_map[allocation["tupleDigest"]]
        demand.update(caseId=case_id, caseManifestDigest=case_digest,
                      tupleInventoryDigest=digest(inventory), declaredAt=stamp(now), notAfter=stamp(now + dt.timedelta(minutes=4)))
        case = authority["case"]
        case.update(caseId=case_id, caseManifestDigest=case_digest, operatorKeySHA256=digest(op_public),
                    demandManifestDigest=digest(demand), tupleInventoryDigest=digest(inventory), controlsDigest=digest(demand["controls"]))
        opening = {"formatVersion": 2, "accountingVersion": 2, "ledgerId": case["ledgerId"],
                   "providerPolicyDigest": case["providerPolicyDigest"], "authorityDigest": digest(authority),
                   "demandManifestDigest": digest(demand), "surface": "backend", "caseId": case_id,
                   "candidateInventoryDigest": demand["candidateInventoryDigest"], "accountScopeDigest": demand["accountScopeDigest"],
                   "ownerConsentDigest": digest({"sourceOnlyConsent": case_id}),
                   "snapshot": {key: 0 for key in ("physicalRequests", "modelRequests", "turns", "preparations", "reservedUsdMicros", "actualUsdMicros")},
                   "historyDigest": digest([]), "observedAt": stamp(now), "notAfter": stamp(now + dt.timedelta(minutes=4))}
        signed_demand, signed_opening = envelope(demand), envelope(opening)
        budget = "workspace-workflow-budget-v%d.schema.json" % version
        accounting = "workspace-provider-accounting-v%d.schema.json" % (version - 1)
        validate(budget, "authority%d" % version, authority)
        validate(budget, "demandManifestEnvelope", signed_demand)
        validate(accounting, "openingEnvelope", signed_opening)
        assert digest(demand) == case["demandManifestDigest"] and digest(inventory) == case["tupleInventoryDigest"]
        assert sum(a["modelRequests"] for a in demand["allocations"]) == case["modelRequests"]
        assert sum(a["accessRequests"] for a in demand["allocations"]) == case["accessRequests"]
        assert [i for a in demand["allocations"] for i in range(a["firstPhysicalIndex"], a["lastPhysicalIndex"] + 1)] == list(range(1, case["requests"] + 1))
        return {"authority": authority, "demand": signed_demand, "backendOpening": signed_opening}

    predecessor = build(old, 3)
    participants = []
    if multi:
        # Reuse only frozen unsigned public shapes. Fresh identities, keys and
        # exact original signatures are created before any SQLite observation.
        authority, demand = copy.deepcopy(current["authority"]), copy.deepcopy(current["demand"])
        case_id = "source_family_5_" + uuid.uuid4().hex[:12]
        case_digest = digest({"sourceOnly": True, "caseId": case_id, "createdAt": stamp(now)})
        authority.update(caseId=case_id, caseManifestDigest=case_digest, evidenceRoot=str(output))
        authority["operator"] = copy.deepcopy(predecessor["authority"]["operator"])
        inventory = authority["tupleInventory"]
        inventory.update(caseId=case_id, observedAt=stamp(now))
        tuple_map = {}
        for entry in inventory["tuples"]:
            previous = entry["tupleDigest"]
            entry["applicability"]["caseManifestDigest"] = case_digest
            entry["tupleDigest"] = digest(entry["applicability"])
            tuple_map[previous] = entry["tupleDigest"]
        for allocation in demand["allocations"]:
            allocation["tupleDigest"] = tuple_map[allocation["tupleDigest"]]
        for index, participant in enumerate(authority["participantInventory"]["participants"]):
            key = ec.generate_private_key(ec.SECP256R1())
            raw_public = public(key)
            key_id = "source_family_participant_" + str(index + 1)
            node_hash = hashlib.sha256((case_id + ":node:" + str(index)).encode()).hexdigest()
            local_root = output / ("participant-%d" % (index + 1))
            local_root.mkdir(mode=0o700)
            key_path = local_root / "producer.private.pem"
            write(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), True)
            participant["producer"] = {"keyId": key_id, "keySHA256": digest(raw_public)[7:], "nodeTokenHash": node_hash,
                                       "publicKeyBase64": base64.b64encode(raw_public).decode()}
            participant.pop("participantId")
            participant["participantId"] = digest(participant)
            participants.append({"participantId": participant["participantId"], "producer": {
                "keyId": key_id, "keyPath": str(key_path), "keySHA256": digest(raw_public), "nodeTokenHash": node_hash,
                "serverId": participant["serverId"], "evidenceRoot": str(local_root)}})
        pi = authority["participantInventory"]
        pi["caseId"] = case_id
        pi["participants"].sort(key=lambda p: p["participantId"])
        participants.sort(key=lambda p: p["participantId"])
        demand.update(caseId=case_id, caseManifestDigest=case_digest, tupleInventoryDigest=digest(inventory),
                      participantInventoryDigest=digest(pi), declaredAt=stamp(now), notAfter=stamp(now + dt.timedelta(minutes=4)))
        case = authority["case"]
        case.update(caseId=case_id, caseManifestDigest=case_digest, operatorKeySHA256=digest(op_public),
                    demandManifestDigest=digest(demand), tupleInventoryDigest=digest(inventory),
                    participantInventoryDigest=digest(pi), controlsDigest=digest(demand["controls"]))
        consents = []
        for entry in inventory["tuples"]:
            participant = next(p for p in pi["participants"] if p["taskId"] == entry["applicability"]["taskId"])
            consents.append({"participantId": participant["participantId"], "tupleDigest": entry["tupleDigest"],
                             "ownerConsentDigest": digest({"sourceOnlyConsent": case_id, "taskId": participant["taskId"]})})
        opening = {"formatVersion": 3, "accountingVersion": 2, "ledgerId": case["ledgerId"],
                   "providerPolicyDigest": case["providerPolicyDigest"], "authorityDigest": digest(authority),
                   "demandManifestDigest": digest(demand), "participantInventoryDigest": digest(pi), "surface": "backend",
                   "caseId": case_id, "candidateInventoryDigest": demand["candidateInventoryDigest"],
                   "accountScopeDigest": demand["accountScopeDigest"],
                   "ownerConsents": sorted(consents, key=lambda c: (c["participantId"], c["tupleDigest"])),
                   "snapshot": {key: 0 for key in ("physicalRequests", "modelRequests", "turns", "preparations", "reservedUsdMicros", "actualUsdMicros")},
                   "historyDigest": digest([]), "observedAt": stamp(now), "notAfter": stamp(now + dt.timedelta(minutes=4))}
        successor = {"authority": authority, "demand": envelope(demand), "backendOpening": envelope(opening)}
        validate("workspace-workflow-budget-v5.schema.json", "authority5", authority)
        validate("workspace-workflow-budget-v5.schema.json", "demandManifestEnvelope", successor["demand"])
        validate("workspace-provider-accounting-v4.schema.json", "backendOpeningEnvelope3", successor["backendOpening"])
        assert len({p["taskId"] for p in pi["participants"]}) == len({p["producer"]["keySHA256"] for p in pi["participants"]}) == 2
        for allocation in demand["allocations"]:
            assert sum(allocation["scope"] in p["scopes"] for p in pi["participants"]) == 1
        assert [i for a in demand["allocations"] for i in range(a["firstPhysicalIndex"], a["lastPhysicalIndex"] + 1)] == list(range(1, 22))
    else:
        successor = build(current, 4)
    server_id = predecessor["authority"]["tupleInventory"]["tuples"][0]["applicability"]["serverId"]
    packet = {"phase": "successor-family", "root": str(output), "old": predecessor, "current": successor,
              "operatorPublicKeyBase64": base64.b64encode(op_public).decode(),
              "producer": {"keyId": "source_family_producer", "keyPath": str(private_path), "keySHA256": digest(producer_public),
                           "nodeTokenHash": token_hash, "serverId": server_id, "evidenceRoot": str(output)}}
    if multi:
        packet["participants"] = participants
    write(output / "packet.json", packet, True)
    write(output / "fixture-validation.json", {"classification": "SOURCE keys/authority/installation/native metadata; actual fresh signatures; no backend enrollment/ROOT/provider/native",
          "schemaValidation": "authority3+demand3+opening2 and " + ("authority5+demand5+backendOpening3" if multi else "authority4+demand4+opening2") + " passed", "createdAt": stamp(now),
          "packetSHA256": digest(canonical(packet)), "frozenManifestSHA256": digest((frozen / "manifest.json").read_bytes()),
          "currentCounts": successor["authority"]["case"], "predecessorCounts": predecessor["authority"]["case"]})


if __name__ == "__main__":
    main()
