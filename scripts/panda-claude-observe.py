#!/usr/bin/env python3
"""CCBaga pilot: read-only local app inventory and opt-in SV Claude status.

The default action only checks known macOS app-bundle locations. The separate
--sv option invokes ONE fixed Python probe via existing strict SSH; it does not
install apps, log in, inspect credentials, relay tokens or start model calls.
Not a production CCBaga GUI integration or account eligibility check.
"""
from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import stat
import subprocess
import sys
from pathlib import Path

SCHEMA = "panda.ccbaga.claude-observation.v1"
APP_IDS = {
    "CCBaga-A.app": "ai.local.requirement-french",
    "CCBaga-B.app": "ai.local.requirement-french.browser",
}
HOST_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}\Z")
VERSION_PATTERN = re.compile(r"\b\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?\b")

# Deliberately independent of ~/.ssh/config aliases, proxy commands, remote
# scripts and any untrusted CCBaga network Skill. No user-supplied remote code.
SV_PROBE = r'''
import json
import os
import pwd
import re
import subprocess
from pathlib import Path

out = {
    "schema": "panda.ccbaga.sv-claude-observation.v1",
    "identity": "MISMATCH",
    "uid": os.getuid(),
    "cli": "UNKNOWN",
    "version": None,
    "auth": "UNKNOWN",
}
if os.getuid() != 1000 or pwd.getpwuid(os.getuid()).pw_name != "ubuntu":
    print(json.dumps(out, sort_keys=True))
    raise SystemExit(0)
out["identity"] = "EXPECTED"
cli = Path("/home/ubuntu/.local/bin/claude")
if not cli.is_file():
    out["cli"] = "NOT_FOUND_AT_EXPECTED_PATH"
    print(json.dumps(out, sort_keys=True))
    raise SystemExit(0)
out["cli"] = "PRESENT"
env = {"HOME": "/home/ubuntu", "PATH": "/home/ubuntu/.local/bin:/usr/local/bin:/usr/bin:/bin",
       "LANG": "C", "LC_ALL": "C"}
def check(arguments):
    try:
        return subprocess.run(arguments, capture_output=True, text=True,
                              timeout=12, env=env, stdin=subprocess.DEVNULL,
                              check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None

version_result = check([str(cli), "--version"])
if version_result is not None and version_result.returncode == 0:
    match = re.search(r"\b\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?\b", version_result.stdout[:200])
    if match:
        out["version"] = match.group(0)

auth_result = check([str(cli), "auth", "status", "--text"])
if auth_result is not None:
    result = (auth_result.stdout + "\n" + auth_result.stderr).lower()[:4096]
    if any(s in result for s in ("not logged in", "not signed in", "not authenticated", "logged out")):
        out["auth"] = "NOT_SIGNED_IN"
    elif auth_result.returncode == 0 and (
        "logged in" in result or "signed in" in result or "authenticated" in result
    ):
        out["auth"] = "SIGNED_IN"
    elif auth_result.returncode != 0:
        out["auth"] = "NOT_SIGNED_IN_OR_ERROR"
# NOTE: raw stdout/stderr NEVER leave SV, even on login failures.
print(json.dumps(out, sort_keys=True))
'''


def local_inventory(home: Path = None, system_app_dir: Path = None) -> dict:
    """Check only standard locations, never scan credentials or start programs."""
    home = home or Path.home()
    system_app_dir = system_app_dir or Path("/Applications")
    applications = {}
    for bundle, expected_id in APP_IDS.items():
        records = []
        for parent in (system_app_dir, home / "Applications"):
            folder = parent / bundle
            if not folder.exists() and not folder.is_symlink():
                continue
            if folder.is_symlink() or not folder.is_dir():
                records.append({"location": str(folder), "state": "UNTRUSTED_PATH"})
                continue
            info = folder / "Contents" / "Info.plist"
            try:
                if info.is_symlink() or not info.is_file():
                    raise ValueError("Info.plist not regular")
                data = plistlib.loads(info.read_bytes())
                bundle_id = data.get("CFBundleIdentifier")
                version = data.get("CFBundleShortVersionString")
                matching = bundle_id == expected_id
                record = {"location": str(folder),
                          "state": "FOUND_BUNDLE_ID_MATCH" if matching else "BUNDLE_ID_MISMATCH"}
                if matching and isinstance(version, str) and VERSION_PATTERN.fullmatch(version):
                    record["version"] = version
                records.append(record)
            except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
                records.append({"location": str(folder), "state": "UNREADABLE_METADATA"})
        applications[bundle] = {
            "state": "FOUND" if any(r["state"] == "FOUND_BUNDLE_ID_MATCH" for r in records)
                     else ("NOT_IN_STANDARD_LOCATIONS" if not records else "NEEDS_REVIEW"),
            "locations": records,
        }
    return {"schema": SCHEMA, "scope": "MAC_STANDARD_APP_LOCATIONS_ONLY",
            "applications": applications, "signed_or_running": "NOT_CHECKED"}


def check_identity_key(path: Path) -> Path:
    """Refuse paths that could reference an untrusted/nonprivate SSH identity."""
    if path.is_symlink():
        raise ValueError("SSH_IDENTITY_SYMLINK_DENIED")
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ValueError("SSH_IDENTITY_NOT_PRIVATE_OR_NOT_OWNED")
    return path.resolve()


def safe_remote_result(payload: str) -> dict:
    # Parse a single bounded record; never echo raw remote output or ssh stderr.
    if len(payload) > 4096:
        raise ValueError("REMOTE_OUTPUT_TOO_LARGE")
    value = json.loads(payload)
    if not isinstance(value, dict) or value.get("schema") != "panda.ccbaga.sv-claude-observation.v1":
        raise ValueError("REMOTE_SCHEMA_MISMATCH")
    uid = value.get("uid")
    if type(uid) is not int or uid != 1000 or value.get("identity") != "EXPECTED":
        raise ValueError("SV_USER_IDENTITY_MISMATCH")
    if value.get("cli") not in {"PRESENT", "NOT_FOUND_AT_EXPECTED_PATH", "UNKNOWN"}:
        raise ValueError("SV_CLI_STATE_INVALID")
    if value.get("auth") not in {"UNKNOWN", "SIGNED_IN", "NOT_SIGNED_IN", "NOT_SIGNED_IN_OR_ERROR"}:
        raise ValueError("SV_AUTH_STATE_INVALID")
    version = value.get("version")
    if version is not None and (not isinstance(version, str) or
                                VERSION_PATTERN.fullmatch(version) is None):
        raise ValueError("SV_VERSION_INVALID")
    return {"schema": SCHEMA, "scope": "SV_READ_ONLY_STATUS_ONLY",
            "identity": "ubuntu/1000", "cli": value["cli"],
            "version": version, "auth": value["auth"],
            "credential_values_read": False, "eligibility_verified": False}


def remote_status(host: str, identity: Path, executor=subprocess.run) -> dict:
    if not HOST_PATTERN.fullmatch(host) or ".." in host or host.endswith("."):
        raise ValueError("HOST_NOT_ALLOWED")
    key = check_identity_key(identity)
    argv = ["ssh", "-T", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
            "-o", "IdentitiesOnly=yes", "-o", "ForwardAgent=no",
            "-o", "ClearAllForwardings=yes", "-o", "RequestTTY=no",
            "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
            "-o", "ConnectTimeout=7", "-o", "ConnectionAttempts=1",
            "-i", str(key), "-l", "ubuntu", "--", host, "python3 -"]
    try:
        result = executor(argv, input=SV_PROBE, capture_output=True, text=True,
                          timeout=40, check=False)
    except subprocess.TimeoutExpired:
        raise ValueError("SSH_TIMEOUT") from None
    except OSError:
        raise ValueError("SSH_EXECUTION_ERROR") from None
    if result.returncode != 0:
        raise ValueError("SSH_FAILED")
    try:
        return safe_remote_result(result.stdout.strip())
    except (ValueError, json.JSONDecodeError):
        raise ValueError("REMOTE_STATUS_UNVERIFIABLE") from None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sv", action="store_true", help="Opt in to fixed SV read-only SSH probe")
    parser.add_argument("--host", help="Previously verified SV hostname or IPv4")
    parser.add_argument("--identity-file", type=Path, help="Existing local SSH private-key path")
    args = parser.parse_args(argv)
    if not args.sv and (args.host or args.identity_file):
        parser.error("--host/--identity-file are only valid with --sv")
    if args.sv and (not args.host or not args.identity_file):
        parser.error("--sv requires --host and --identity-file")
    try:
        result = remote_status(args.host, args.identity_file) if args.sv else local_inventory()
    except (ValueError, OSError):
        # No raw exception messages; they may contain system paths or ssh details.
        print(json.dumps({"schema": SCHEMA, "status": "HOLD_UNVERIFIED"}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
