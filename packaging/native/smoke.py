#!/usr/bin/env python3
"""Authenticated Linux binary smoke for the WarpMetal native package.

Starts the built binary with a fresh isolated home/XDG tree and a fresh
fixture nonce, then verifies:

  - anonymous GET /api/session/<id>/inbox/guard is rejected with HTTP 401
  - an authenticated guard GET returns the exact contract141 snapshot for a
    fresh inactive session (expected nativeGuardVersion, null watermarks,
    active false, numeric epoch-millisecond observedAt, non-negative
    logCursor)
  - default retention: an unguarded queue/resume=false input becomes visible in
    the durable guard snapshot (non-null inputSeq); no provider credentials are
    inherited, so no paid model execution can occur
  - a wrong-sessionID guard in the exact tested guard shape is refused with the
    deterministic typed code guard_session_mismatch, and its closed receipt plus
    the input watermark survive a genuine server restart

The nonce is a per-run fixture, never printed, never inherited by children
other than the server process, and the curl config is removed afterwards.
Provider credential environment is not inherited: the child environment is
constructed from scratch.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

GUARD_RECEIPT_KEYS = {
    "formatVersion",
    "sessionID",
    "inboxID",
    "guardID",
    "bindingDigest",
    "state",
    "admittedAt",
    "availableAt",
    "settledAt",
    "refusalCode",
    "logCursor",
}

GUARD_KEYS = {
    "formatVersion",
    "nativeGuardVersion",
    "sessionID",
    "inputSeq",
    "executionStartedSeq",
    "executionTerminalSeq",
    "contextSeq",
    "active",
    "observedAt",
    "logCursor",
}


def fail(message: str) -> None:
    print(f"native-smoke: {message}", file=sys.stderr)
    raise SystemExit(1)


def run_curl(config: Path | None, args: list[str]) -> str:
    command = ["curl", "-sS", "--max-time", "10"]
    if config is not None:
        command += ["--config", str(config)]
    command += args
    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.returncode != 0:
        fail("curl_failed")
    return completed.stdout


def status_curl(config: Path | None, url: str) -> str:
    return run_curl(config, ["-o", "/dev/null", "-w", "%{http_code}", url]).strip()


def quiet_status(config: Path | None, url: str) -> str | None:
    command = ["curl", "-sS", "--max-time", "10"]
    if config is not None:
        command += ["--config", str(config)]
    command += ["-o", "/dev/null", "-w", "%{http_code}", url]
    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--guard-version", required=True)
    args = parser.parse_args()

    if shutil.which("curl") is None:
        fail("curl_missing")
    binary = Path(args.binary).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        fail("binary_missing")

    work = Path(args.workdir).resolve()
    if work.exists():
        fail("workdir_must_not_exist")
    work.mkdir(parents=True, mode=0o700)
    home = work / "home"
    tmp = work / "tmp"
    xdg = work / "xdg"
    for relative in ("config", "data", "cache", "state"):
        (xdg / relative).mkdir(parents=True, mode=0o700)
    home.mkdir(mode=0o700)
    tmp.mkdir(mode=0o700)
    cwd = work / "work"
    cwd.mkdir(mode=0o700)

    nonce = secrets.token_urlsafe(24)
    config = work / "curl.conf"
    descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(f'user = "opencode:{nonce}"\n')
        handle.flush()
        os.fsync(handle.fileno())

    environment = {
        "HOME": str(home),
        "PATH": f"{binary.parent}:/usr/bin:/bin",
        "TMPDIR": str(tmp),
        "XDG_CONFIG_HOME": str(xdg / "config"),
        "XDG_DATA_HOME": str(xdg / "data"),
        "XDG_CACHE_HOME": str(xdg / "cache"),
        "XDG_STATE_HOME": str(xdg / "state"),
        "OPENCODE_SERVER_PASSWORD": nonce,
        "OPENCODE_DISABLE_AUTOUPDATE": "1",
        "OPENCODE_DISABLE_MODELS_FETCH": "1",
        "OPENCODE_DISABLE_FILEWATCHER": "1",
    }

    log_path = work / "server.log"
    process: subprocess.Popen[bytes] | None = None

    def launch(log_mode: str = "wb") -> tuple[subprocess.Popen[bytes], str]:
        port = free_port()
        base = f"http://127.0.0.1:{port}"
        with log_path.open(log_mode) as log:
            launched = subprocess.Popen(
                [str(binary), "serve", "--hostname", "127.0.0.1", "--port", str(port)],
                cwd=str(cwd),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        for _ in range(60):
            if quiet_status(config, f"{base}/api/session") == "200":
                return launched, base
            if launched.poll() is not None:
                fail("server_exited_early")
            time.sleep(1)
        fail("server_not_ready")

    def stop(instance: subprocess.Popen[bytes]) -> None:
        if instance.poll() is None:
            try:
                os.killpg(instance.pid, signal.SIGTERM)
                instance.wait(timeout=10)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(instance.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def post_json(url: str, payload: dict) -> tuple[str, str]:
        body_path = work / "response.json"
        status = run_curl(
            config,
            ["-X", "POST", "-H", "content-type: application/json", "-d", json.dumps(payload),
             "-o", str(body_path), "-w", "%{http_code}", url],
        ).strip()
        return status, body_path.read_text(encoding="utf-8") if body_path.exists() else ""

    def guard_receipt(base: str, inbox_id: str, guard_id: str) -> dict:
        raw = run_curl(
            config,
            [f"{base}/api/session/{session_id}/inbox/{inbox_id}/guard-receipt?guardID={guard_id}"],
        )
        return json.loads(raw)["data"]

    try:
        process, base = launch()

        # Anonymous access must be rejected; no credential material is sent.
        anonymous = status_curl(None, f"{base}/api/session")
        if anonymous != "401":
            fail(f"anonymous_status_unexpected:{anonymous}")

        created = run_curl(
            config,
            ["-X", "POST", "-H", "content-type: application/json", "-d", "{}", f"{base}/api/session"],
        )
        try:
            session_id = json.loads(created)["data"]["id"]
        except (KeyError, TypeError, ValueError):
            fail("session_create_response_invalid")
        if not isinstance(session_id, str) or not session_id:
            fail("session_id_invalid")

        anonymous_guard = status_curl(None, f"{base}/api/session/{session_id}/inbox/guard")
        if anonymous_guard != "401":
            fail(f"anonymous_guard_status_unexpected:{anonymous_guard}")

        raw_guard = run_curl(config, [f"{base}/api/session/{session_id}/inbox/guard"])
        try:
            snapshot = json.loads(raw_guard)["data"]
        except (KeyError, TypeError, ValueError):
            fail("guard_response_invalid")
        if set(snapshot) != GUARD_KEYS:
            fail("guard_keys_unexpected")
        if snapshot["formatVersion"] != 1:
            fail("guard_format_version_unexpected")
        if snapshot["nativeGuardVersion"] != args.guard_version:
            fail("guard_version_unexpected")
        if snapshot["sessionID"] != session_id:
            fail("guard_session_mismatch")
        for key in ("inputSeq", "executionStartedSeq", "executionTerminalSeq", "contextSeq"):
            if snapshot[key] is not None:
                fail("guard_watermark_unexpected")
        if snapshot["active"] is not False:
            fail("guard_active_unexpected")
        observed_at = snapshot["observedAt"]
        if isinstance(observed_at, bool) or not isinstance(observed_at, int) or observed_at <= 0:
            fail("guard_observed_at_unexpected")
        cursor = snapshot["logCursor"]
        if cursor is not None and (isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0):
            fail("guard_log_cursor_unexpected")

        # Bounded default-serve durability checks (no provider credentials exist
        # in this environment, so no paid model call can succeed or be billed).
        # 1) An UNGUARDED queue/resume=false input proves the default-mode input
        #    watermark is persisted with no provider execution. Guarded
        #    consumption itself stays an SF source journey, not a fake inactive
        #    admission here.
        # 2) A deliberately wrong-sessionID guard in the exact tested guard shape
        #    produces a deterministic typed guard_session_mismatch refusal whose
        #    closed receipt survives a genuine server restart.
        admit_id = "msg_native_smoke_admitted"
        admit_status, admit_response = post_json(
            f"{base}/api/session/{session_id}/prompt",
            {
                "id": admit_id,
                "text": "native smoke unguarded queue input",
                "delivery": "queue",
                "resume": False,
            },
        )
        if admit_status != "200":
            fail(f"unguarded_input_prompt_status:{admit_status}:{admit_response[:160]}")
        input_snapshot: dict = {}
        for _ in range(30):
            input_snapshot = json.loads(
                run_curl(config, [f"{base}/api/session/{session_id}/inbox/guard"])
            )["data"]
            if input_snapshot.get("inputSeq") is not None:
                break
            time.sleep(0.2)
        if input_snapshot.get("inputSeq") is None:
            fail("input_watermark_not_persisted")

        refuse_id = "msg_native_smoke_refused"
        refuse_guard_id = "guard_native_smoke_refused"
        refuse_status, refuse_response = post_json(
            f"{base}/api/session/{session_id}/prompt",
            {
                "id": refuse_id,
                "text": "native smoke typed refusal",
                "delivery": "queue",
                "resume": False,
                "guard": {
                    "formatVersion": 1,
                    "guardID": refuse_guard_id,
                    "sessionID": session_id + "_other",
                    "inputSeq": None,
                    "executionStartedSeq": 0,
                    "contextSeq": None,
                    "expiresAt": int(time.time() * 1000) + 60_000,
                    "bindingDigest": "sha256:" + "e" * 64,
                },
            },
        )
        if refuse_status != "409" or "guard_session_mismatch" not in refuse_response:
            fail(f"typed_refusal_unexpected:{refuse_status}:{refuse_response[:160]}")
        receipt = guard_receipt(base, refuse_id, refuse_guard_id)
        if set(receipt) != GUARD_RECEIPT_KEYS:
            fail("refusal_receipt_keys_unexpected")
        if receipt["state"] != "refused" or receipt["refusalCode"] != "guard_session_mismatch":
            fail("refusal_receipt_state_unexpected")
        if (receipt["sessionID"], receipt["inboxID"], receipt["guardID"]) != (session_id, refuse_id, refuse_guard_id):
            fail("refusal_receipt_identity_mismatch")

        # Genuine restart: the durable guard projection and the exact typed
        # refusal receipt must survive the same isolated home/data tree.
        stop(process)
        process, base = launch("ab")
        receipt_after = guard_receipt(base, refuse_id, refuse_guard_id)
        if receipt_after != receipt:
            fail("refusal_receipt_not_durable_across_restart")
        guard_after = json.loads(
            run_curl(config, [f"{base}/api/session/{session_id}/inbox/guard"])
        )["data"]
        if guard_after.get("inputSeq") is None:
            fail("input_watermark_not_durable_across_restart")
        if guard_after["inputSeq"] != input_snapshot["inputSeq"]:
            fail("input_watermark_changed_across_restart")

        if nonce.encode() in log_path.read_bytes():
            fail("credential_logged")
        print(f"native-smoke: ok version={args.version} guard={args.guard_version} durable=1")
        return 0
    finally:
        if process is not None:
            stop(process)
        if config.exists():
            config.unlink()


if __name__ == "__main__":
    sys.exit(main())
