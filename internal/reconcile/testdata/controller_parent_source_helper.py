"""Source-only adapter for the EXISTING Sandbox Supervisor subprocess fixture.

Native engine installation/HTTP are the test stand-in, not installed wm.5 or
controllerBinding. Runtime input bytes pass unchanged to the actual Supervisor.
Only Go-created temporary roots/processes are used and stopped at EOF.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

if sys.argv[1:2] == ["--delivery-root-overlay"]:
    # Compiler-only SOURCE ownership/root-write supplier for the SAME Go journey.
    # No production option/hook exists. Preserve crypto, canonical bytes, modes,
    # links, read/append/fsync, journals and HTTP; substitute unavailable host UID
    # and root's ability to create/rename beneath a read-only directory ONLY.
    repo, destination = map(Path, sys.argv[2:4])
    destination.mkdir()
    replacements = {}
    for leaf in ("producer.go", "store.go", "child_product_adopt.go", "controller_activation_adopt.go"):
        original = (repo / "internal/qualification" / leaf).resolve()
        text = original.read_text()
        if leaf == "producer.go":
            old = "owner.Uid != 0 ||"
            assert text.count(old) == 1
            text = text.replace(old, "(owner.Uid != 0 && owner.Uid != uint32(os.Getuid())) ||")
        elif leaf == "store.go":
            old = "if payload {\n\t\t\texpected = s.MappedUID"
            assert text.count(old) == 1
            text = text.replace(old, "if !payload && owner.Uid == uint32(os.Getuid()) { expected = uint32(os.Getuid()) }\n\t\t" + old)
        else:
            text = text.replace("os.Mkdir(", "sourceRootMkdir(").replace("os.Rename(", "sourceRootRename(")
            if leaf == "controller_activation_adopt.go":
                text += '''
// Test compiler overlay ONLY: emulate root creation/rename without weakening
// protected read modes or replacing any payload/signature/first-byte check.
func sourceRootMkdir(name string, mode os.FileMode) error {
 parent:=filepath.Dir(name); st,e:=os.Stat(parent); if e!=nil{return e}
 if e=os.Chmod(parent,st.Mode().Perm()|0200);e!=nil{return e}
 defer os.Chmod(parent,st.Mode().Perm())
 return os.Mkdir(name,mode)
}
func sourceRootRename(old,new string) error {
 parent:=filepath.Dir(new); st,e:=os.Stat(parent);if e!=nil{return e}
 moved,e:=os.Stat(old);if e!=nil{return e}
 if e=os.Chmod(old,moved.Mode().Perm()|0200);e!=nil{return e}
 defer func(){if _,e:=os.Stat(new);e==nil{os.Chmod(new,moved.Mode().Perm())}else{os.Chmod(old,moved.Mode().Perm())}}()
 if e=os.Chmod(parent,st.Mode().Perm()|0200);e!=nil{return e}
 defer os.Chmod(parent,st.Mode().Perm())
 return os.Rename(old,new)
}
'''
        copy = destination / leaf
        copy.write_text(text)
        replacements[str(original)] = str(copy.resolve())
    manifest = destination / "overlay.json"
    manifest.write_text(json.dumps({"Replace": replacements}, indent=2, sort_keys=True)+"\n")
    print(manifest)
    sys.exit(0)

sys.path.insert(0, os.environ["F3_SANDBOX_SOURCE"])
from tests.test_opencode_supervisor import SupervisorCase, _load_supervisor

case = SupervisorCase()
initial = json.loads(sys.stdin.readline())
case.root = Path(os.path.realpath(initial["root"]))
case.module = _load_supervisor()
case.supervisor = case.module.Supervisor(root=case.root)
# Exact source module metadata replaces unavailable installed root ownership only.
# The protected loader and actual HTTP binding getter still execute. This is not
# installed evidence or an operator/authority supplier.
transport = Path(case.module.__file__).with_name("warpmetal_controller_transport.py")
trusted = {transport, *transport.parents}
original_lstat = Path.lstat
def source_metadata(path, *args, **kwargs):
    result = original_lstat(path, *args, **kwargs)
    if path in trusted:
        values = list(result)
        values[0] &= ~0o022
        values[4] = 0
        return os.stat_result(values)
    return result
patch.object(Path, "lstat", source_metadata).start()
installed = case.install(initial["profileDigest"], version=initial["version"], revision=initial["profileRevision"])
(installed / "install/fixture-providers.json").write_text(json.dumps({"controllerBindingFixture": True}))
entry = b"Reviewed source fixture e\xcc\x81\xe2\x80\xa8\r\n"
files = [("expert/README.md", "100644", entry), ("expert/support.bin", "100755", b"\x00\xffinert")]
manifest = {"formatVersion": 1, "repository": {"id": 1, "owner": "approved-source-fixture", "name": "expertise"},
            "commitSha": "a" * 40, "rootTreeSha": "b" * 40, "approvedPaths": ["expert"], "files": []}
blobs = {}
for path, mode, raw in files:
    sha = "sha256:" + hashlib.sha256(raw).hexdigest()
    manifest["files"].append({"path": path, "gitMode": mode,
        "gitBlobSha": hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest(),
        "sizeBytes": len(raw), "sha256": sha})
    blobs[sha] = base64.b64encode(raw).decode()
composer = case.module._controller_profile_module()
bundle_digest = composer.digest(manifest)
bundle = {"manifest": manifest, "bundleDigest": bundle_digest, "blobs": blobs}
reference = {"profileId": "expert_source", "profileRevision": 1,
             "profileDigest": "sha256:" + "c" * 64, "bundleDigest": bundle_digest}
expected = {"approvedProfile": reference, "entryPath": "expert/README.md", "files": [
    {"path": f["path"], "sha256": f["sha256"], "byteCount": f["sizeBytes"]} for f in manifest["files"]]}
instructions = {role: composer.compose_profile_system(role, expected, bundle).decode()
                for role in ("manager", "orchestrator")}
print(json.dumps({"bundle": bundle, "expected": expected, "instructions": instructions}), flush=True)
instances = {}
try:
    for line in sys.stdin:
        message = json.loads(line)
        command, request = message["action"], message["request"]
        if command == "start":
            instances[request["instance"]] = {k: request[k] for k in ("schemaVersion", "sandboxId", "instance", "profileId")}
        try:
            result = case.supervisor.run(command, request)
        except Exception as error:
            result = {"sourceFixtureError": str(error)}
        print(json.dumps(result), flush=True)
finally:
    for request in instances.values():
        case.supervisor.run("stop", request)
    # ONLY this fixture's Go-created expertise tree. Published source files are
    # intentionally read-only; return temporary directories to cleanup ownership.
    expertise = case.root / ".warpmetal/expertise"
    if expertise.is_dir():
        for directory, _, _ in os.walk(expertise):
            os.chmod(directory, 0o700)
