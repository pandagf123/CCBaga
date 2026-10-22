#!/usr/bin/env python3
# [INPUT]: Existing local CCBaga app bundles and (only when explicitly opted in) a pinned SV SSH identity/known_hosts.
# [OUTPUT]: Allowlists of local bundle metadata or sanitized remote Claude CLI state; no account secrets.
# [POS]: Non-GUI, non-installing P2 observation pilot for CCBaga Issue #2; host source verification remains external.
# [PROTOCOL]: Keep docs, negative tests and .github/workflows file map updated on boundary changes.
"""CCBaga pilot: read-only local app inventory and opt-in SV Claude status.

The default action only checks known macOS app-bundle locations. The separate
--sv option invokes ONE fixed Python probe via existing strict SSH; it does not
install apps, log in, export credential values, relay tokens or start model calls.
Not a production CCBaga GUI integration or account eligibility check.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import plistlib
import re
import stat
import subprocess
from pathlib import Path

SCHEMA = "panda.ccbaga.claude-observation.v1"
APP_IDS = {
    "CCBaga-A.app": "ai.local.requirement-french",
    "CCBaga-B.app": "ai.local.requirement-french.browser",
}
SV_HOST = "43.135.166.3"  # Pinned current authorized SV instance, not caller selected.
SV_ED25519_HOST_FINGERPRINT = "SHA256:5XKggGGuBQp2IFHpTAucXUYNQFgulagChJZuMIgxu0I"
SV_KEY_RELATIVE = ".ssh/sv-ubuntu-admin/sv-ubuntu-admin-ed25519"
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
try:
    resolved_cli = cli.resolve(strict=True)
    expected_dir = Path("/home/ubuntu/.local/share/claude/versions").resolve(strict=True)
    trusted_cli = (resolved_cli.parent == expected_dir
                   and resolved_cli.is_file()
                   and resolved_cli.stat().st_uid == 1000
                   and resolved_cli.stat().st_mode & 0o022 == 0)
except (OSError, RuntimeError):
    trusted_cli = False
if not trusted_cli:
    out["cli"] = "NOT_FOUND_OR_UNTRUSTED"
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

# The official CLI may inspect its local credential store internally.
# This observer emits only a bounded status enum, never CLI stdout/stderr.
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
            contents = folder / "Contents"
            info = contents / "Info.plist"
            try:
                # Explicitly reject intermediate symlinks before reading plist.
                if (folder.is_symlink() or not folder.is_dir()
                    or contents.is_symlink() or not contents.is_dir()
                    or info.is_symlink() or not info.is_file()):
                    records.append({"location": str(folder), "state": "UNTRUSTED_PATH"})
                    continue
                if info.stat().st_size > 1024 * 1024:
                    raise ValueError("Oversized bundle metadata")
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



def check_known_host(known_hosts: Path, lookup=subprocess.run,
                     expected_fingerprint: str = SV_ED25519_HOST_FINGERPRINT) -> Path:
    """Match fixed IP to an independently pinned ED25519 key from existing known_hosts.

    ssh-keygen -F supports hashed known_hosts entries; it does not contact SV.
    """
    if known_hosts.is_symlink():
        raise ValueError("KNOWN_HOSTS_SYMLINK_DENIED")
    st = known_hosts.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
        raise ValueError("KNOWN_HOSTS_UNTRUSTED")
    safe_path = known_hosts.resolve(strict=True)
    try:
        r = lookup(["ssh-keygen", "-F", SV_HOST, "-f", str(safe_path)],
                   capture_output=True, text=True, timeout=6, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("KNOWN_HOSTS_LOOKUP_FAILED") from None
    if r.returncode != 0:
        raise ValueError("SV_HOST_KEY_NOT_FOUND")
    fingerprints = []
    for line in r.stdout.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 3 or fields[1] != "ssh-ed25519":
            continue
        try:
            raw_key = base64.b64decode(fields[2], validate=True)
        except Exception:
            raise ValueError("KNOWN_HOST_KEY_INVALID") from None
        if not raw_key:
            raise ValueError("KNOWN_HOST_KEY_INVALID")
        digest = base64.b64encode(hashlib.sha256(raw_key).digest()).decode("ascii").rstrip("=")
        fingerprints.append("SHA256:" + digest)
    if not fingerprints or any(f != expected_fingerprint for f in fingerprints):
        raise ValueError("SV_HOST_KEY_PIN_MISMATCH")
    return safe_path



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
    if value.get("cli") not in {"PRESENT", "NOT_FOUND_OR_UNTRUSTED", "UNKNOWN"}:
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
            "credential_values_transmitted": False, "eligibility_verified": False}


def remote_status(host: str, identity: Path, executor=subprocess.run,
                  known_hosts: Path = None, lookup=subprocess.run,
                  expected_identity: Path = None,
                  expected_host_fingerprint: str = SV_ED25519_HOST_FINGERPRINT) -> dict:
    if host != SV_HOST:
        raise ValueError("HOST_NOT_ALLOWED")
    expected_identity = expected_identity or (Path.home() / SV_KEY_RELATIVE)
    key = check_identity_key(identity)
    if identity.absolute() != expected_identity.absolute():
        raise ValueError("SSH_IDENTITY_PATH_MISMATCH")
    kh = check_known_host(known_hosts or (Path.home() / ".ssh" / "known_hosts"),
                          lookup=lookup, expected_fingerprint=expected_host_fingerprint)
    # -F /dev/null prevents silently consuming ~/.ssh/config. Host and identity
    # are explicit and pinned, as is the server's expected ED25519 host key.
    argv = ["ssh", "-F", "/dev/null", "-T",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={kh}", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "VerifyHostKeyDNS=no", "-o", "UpdateHostKeys=no",
            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
            "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
            "-o", "RequestTTY=no", "-o", "ControlMaster=no",
            "-o", "ControlPath=none", "-o", "CanonicalizeHostname=no",
            "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "ConnectTimeout=7", "-o", "ConnectionAttempts=1",
            "-i", str(key), "-l", "ubuntu", "--", SV_HOST, "python3 -"]
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
    args = parser.parse_args(argv)
    try:
        result = remote_status(SV_HOST, Path.home() / SV_KEY_RELATIVE) if args.sv else local_inventory()
    except (ValueError, OSError):
        # No raw exception messages; they may contain system paths or ssh details.
        print(json.dumps({"schema": SCHEMA, "status": "HOLD_UNVERIFIED"}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
