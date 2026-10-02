#!/usr/bin/env python3
"""Authenticated Linux binary smoke for the WarpMetal native package.

Starts the built binary with a fresh isolated home/XDG tree and a fresh
fixture nonce, then verifies:

  - anonymous GET /api/session/<id>/inbox/guard is rejected with HTTP 401
  - an authenticated guard GET returns the exact contract141 snapshot for a
    fresh inactive session (expected nativeGuardVersion, null watermarks,
    active false, numeric epoch-millisecond observedAt, non-negative
    logCursor)

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

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    log_path = work / "server.log"
    process: subprocess.Popen[bytes] | None = None
    try:
        with log_path.open("wb") as log:
            process = subprocess.Popen(
                [str(binary), "serve", "--hostname", "127.0.0.1", "--port", str(port)],
                cwd=str(cwd),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        ready = False
        for _ in range(60):
            if quiet_status(config, f"{base}/api/session") == "200":
                ready = True
                break
            if process.poll() is not None:
                fail("server_exited_early")
            time.sleep(1)
        if not ready:
            fail("server_not_ready")

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

        if nonce.encode() in log_path.read_bytes():
            fail("credential_logged")
        print(f"native-smoke: ok version={args.version} guard={args.guard_version}")
        return 0
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        if config.exists():
            config.unlink()


if __name__ == "__main__":
    sys.exit(main())
