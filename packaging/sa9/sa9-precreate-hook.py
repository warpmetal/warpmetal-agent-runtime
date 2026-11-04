#!/usr/bin/python3
"""WarpMetal SA9 OCI `precreate` configuration hook (childless procfs witness).

A formatVersion 2 cell sandbox must give its worker a private PID namespace
with its own procfs. A fresh `mount("proc", ...)` inside the worker's nested
bubblewrap jail is refused by the kernel (`mount_too_revealing` /
`mnt_already_visible`) because the container's `/proc` carries inherited
`MNT_LOCKED` submounts. The reviewed fix is to have the OCI runtime mount a
fixed childless procfs witness, at container creation and therefore *before*
crun drops to UID 1000 with an empty capability set, at a destination that is
outside every worker bind source.

This hook is a Podman `precreate` config filter:
  * it receives the proposed OCI runtime config as JSON on standard input;
  * it appends exactly one mount
      {destination, type=proc, source=proc, options=[rw,nosuid,nodev,noexec,relatime]}
    at `/warpmetal-proc-witness`;
  * it writes the (possibly unchanged) config as JSON on standard output.

Safety properties, matching the frozen SA9 invariants:
  * Allowlist: the OCI annotation `io.warpmetal.cell.lifecycle` must equal
    `sa9-proc-witness-v1` (Podman additionally matches this in the hook
    configuration `when.annotations`). Any other container is passed through
    byte-exact, so a legacy Team/member or unrelated host container never gets
    the witness.
  * Idempotent: a mount whose destination already exists is never appended
    again, so reconciler re-create cannot accumulate duplicate mounts.
  * Fail-closed: unparseable or unexpected input exits non-zero, which makes
    Podman refuse the container rather than launch a cell without the witness.
"""

import json
import sys

ANNOTATION_KEY = "io.warpmetal.cell.lifecycle"
ANNOTATION_VALUE = "sa9-proc-witness-v1"
DESTINATION = "/warpmetal-proc-witness"
WITNESS = {
    "destination": DESTINATION,
    "type": "proc",
    "source": "proc",
    "options": ["rw", "nosuid", "nodev", "noexec", "relatime"],
}


def _fail(message):
    sys.stderr.write("sa9-precreate-hook: %s\n" % message)
    return 1


def main():
    raw = sys.stdin.buffer.read()
    if not raw:
        return _fail("empty OCI config on stdin")
    try:
        config = json.loads(raw)
    except ValueError as exc:
        return _fail("invalid OCI config JSON: %s" % exc)
    if not isinstance(config, dict):
        return _fail("OCI config is not a JSON object")

    annotations = config.get("annotations")
    if not isinstance(annotations, dict) or annotations.get(ANNOTATION_KEY) != ANNOTATION_VALUE:
        # Not an allowlisted cell lifecycle container: emit the input unchanged
        # so this hook is a no-op for every other container.
        sys.stdout.buffer.write(raw)
        return 0

    mounts = config.get("mounts")
    if mounts is None:
        mounts = []
        config["mounts"] = mounts
    if not isinstance(mounts, list):
        return _fail("OCI config mounts is not a list")
    for mount in mounts:
        if isinstance(mount, dict) and mount.get("destination") == DESTINATION:
            # Already present: idempotent no-op.
            sys.stdout.buffer.write(raw)
            return 0

    mounts.append(dict(WITNESS))
    sys.stdout.write(json.dumps(config))
    return 0


if __name__ == "__main__":
    sys.exit(main())
