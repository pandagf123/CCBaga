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
import errno
import hashlib
import json
import os
import plistlib
import pwd
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
# macOS SIP-protected, absolute OpenSSH binaries; caller PATH is not trusted.
LOCAL_SSH = "/usr/bin/ssh"
LOCAL_SSH_KEYGEN = "/usr/bin/ssh-keygen"
REMOTE_PYTHON = "/usr/bin/python3"  # Ubuntu system interpreter, no remote PATH resolution.


def validate_system_executable(path: str) -> str:
    """Ensure a pinned system tool is a root-owned, executable regular file."""
    if not path.startswith("/usr/bin/"):
        raise ValueError("SYSTEM_TOOL_PATH_NOT_PINNED")
    try:
        st = os.lstat(path)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
            or st.st_mode & 0o022 or not st.st_mode & 0o111):
            raise ValueError("SYSTEM_TOOL_NOT_TRUSTED")
    except OSError:
        raise ValueError("SYSTEM_TOOL_UNAVAILABLE") from None
    return path


def restricted_process_environment() -> dict[str, str]:
    """Refuse caller PATH, PYTHONPATH, DYLD and other inherited executable hooks."""
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "HOME": str(trusted_account_home())}

VERSION_PATTERN = re.compile(r"\b\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?\b")

# Deliberately independent of ~/.ssh/config aliases, proxy commands, remote
# scripts and any untrusted CCBaga network Skill. No user-supplied remote code.
SV_PROBE = r'''
import json
import os
import pwd
import re
import stat
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
# Reject redirecting the official version-root through a symlink; the
# launcher symlink itself is normal, but only its canonical target executes.
version_root = Path("/home/ubuntu/.local/share/claude/versions")
try:
    for parent in (Path("/home/ubuntu"), Path("/home/ubuntu/.local"),
                   Path("/home/ubuntu/.local/share"),
                   Path("/home/ubuntu/.local/share/claude"), version_root):
        st = parent.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, 1000)
                or st.st_mode & 0o022):
            raise ValueError("UNTRUSTED_VERSION_DIRECTORY")
    resolved_cli = cli.resolve(strict=True)
    exe_stat = resolved_cli.lstat()
    trusted_cli = (resolved_cli.parent == version_root
                   and stat.S_ISREG(exe_stat.st_mode)
                   and exe_stat.st_uid == 1000
                   and exe_stat.st_mode & 0o022 == 0)
except (OSError, RuntimeError, ValueError):
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

version_result = check([str(resolved_cli), "--version"])
if version_result is not None and version_result.returncode == 0:
    match = re.search(r"\b\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?\b", version_result.stdout[:200])
    if match:
        out["version"] = match.group(0)

# The official CLI may inspect its local credential store internally.
# This observer emits only a bounded status enum, never CLI stdout/stderr.
auth_result = check([str(resolved_cli), "auth", "status", "--text"])
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


def _read_bundle_plist(parent: Path, bundle_name: str) -> tuple[str, dict | None]:
    """Inspect each path through O_NOFOLLOW directory descriptors, not path reopens."""
    dirs = []
    file_descriptor = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        parent_fd = os.open(parent, flags)
        dirs.append(parent_fd)
        try:
            bundle_fd = os.open(bundle_name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            return ("ABSENT", None)
        dirs.append(bundle_fd)
        contents_fd = os.open("Contents", flags, dir_fd=bundle_fd)
        dirs.append(contents_fd)
        file_descriptor = os.open("Info.plist", os.O_RDONLY | os.O_NOFOLLOW |
                                  os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=contents_fd)
        info_stat = os.fstat(file_descriptor)
        if not stat.S_ISREG(info_stat.st_mode) or info_stat.st_size > 1024 * 1024:
            return ("UNREADABLE_METADATA", None)
        with os.fdopen(os.dup(file_descriptor), "rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            return ("UNREADABLE_METADATA", None)
        return ("PRESENT", plistlib.loads(data))
    except FileNotFoundError:
        # A missing standard parent is absent; a missing component inside an
        # existing bundle is malformed/unreadable, not a proved valid app.
        return ("ABSENT", None) if not dirs else ("UNREADABLE_METADATA", None)
    except (PermissionError, IsADirectoryError):
        return ("UNREADABLE_STANDARD_PATH", None)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            return ("UNTRUSTED_PATH", None)
        return ("UNREADABLE_STANDARD_PATH", None)
    except (ValueError, TypeError, plistlib.InvalidFileException):
        return ("UNREADABLE_METADATA", None)
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        for fd in reversed(dirs):
            os.close(fd)


def local_inventory(home: Path = None, system_app_dir: Path = None) -> dict:
    """Descriptor-based standard-location checks; errors never mean proven absence."""
    home = home if home is not None else trusted_account_home()
    system_app_dir = system_app_dir or Path("/Applications")
    applications = {}
    for bundle, expected_id in APP_IDS.items():
        records = []
        for parent in (system_app_dir, home / "Applications"):
            state, data = _read_bundle_plist(parent, bundle)
            if state == "ABSENT":
                continue
            folder = parent / bundle
            if state == "PRESENT":
                bundle_id = data.get("CFBundleIdentifier") if isinstance(data, dict) else None
                version = data.get("CFBundleShortVersionString") if isinstance(data, dict) else None
                matching = bundle_id == expected_id
                state = "FOUND_BUNDLE_ID_MATCH" if matching else "BUNDLE_ID_MISMATCH"
                record = {"location": str(folder), "state": state}
                if matching and isinstance(version, str) and VERSION_PATTERN.fullmatch(version):
                    record["version"] = version
            else:
                record = {"location": str(folder), "state": state}
            records.append(record)
        if any(r["state"] == "FOUND_BUNDLE_ID_MATCH" for r in records):
            total_state = "FOUND"
        elif not records:
            total_state = "NOT_IN_STANDARD_LOCATIONS"
        else:
            total_state = "NEEDS_REVIEW"
        applications[bundle] = {"state": total_state, "locations": records}
    return {"schema": SCHEMA, "scope": "MAC_STANDARD_APP_LOCATIONS_ONLY",
            "applications": applications, "signed_or_running": "NOT_CHECKED"}



def trusted_account_home() -> Path:
    """Use the POSIX account record, never caller-controlled HOME."""
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        if not home.is_absolute() or ".." in home.parts:
            raise ValueError("ACCOUNT_HOME_INVALID")
        path = Path("/")
        for name in home.parts[1:]:
            path = path / name
            st = os.lstat(path)
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, os.getuid())
                or (st.st_mode & 0o022 and not (
                    st.st_uid == 0 and st.st_mode & stat.S_ISVTX
                ))):
                raise ValueError("ACCOUNT_HOME_ANCESTRY_UNTRUSTED")
        if os.lstat(home).st_uid != os.getuid():
            raise ValueError("ACCOUNT_HOME_OWNER_MISMATCH")
    except (KeyError, OSError, RuntimeError):
        raise ValueError("ACCOUNT_HOME_UNAVAILABLE") from None
    return home


def _trusted_sensitive_path(home: Path, relative: str, path: Path,
                            marker: str) -> os.stat_result:
    """Check every home-relative component by lstat, rejecting symlink ancestors."""
    expected = home / relative
    if path.is_symlink():
        raise ValueError(marker + "_SYMLINK_DENIED")
    if path.absolute() != expected:
        raise ValueError(marker + "_PATH_MISMATCH")
    current = home
    for name in Path(relative).parts[:-1]:
        current = current / name
        try:
            st = os.lstat(current)
        except OSError:
            raise ValueError(marker + "_ANCESTRY_UNVERIFIABLE") from None
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid()
            or st.st_mode & 0o022):
            raise ValueError(marker + "_ANCESTRY_UNTRUSTED")
    try:
        result = os.lstat(expected)
    except OSError:
        raise ValueError(marker + "_FILE_UNVERIFIABLE") from None
    if not stat.S_ISREG(result.st_mode) or result.st_uid != os.getuid():
        raise ValueError(marker + "_FILE_UNTRUSTED")
    return result


def check_identity_key(path: Path, home: Path = None) -> Path:
    """Require owner-private file with symlink-free, pinned user-home ancestry."""
    home = home if home is not None else trusted_account_home()
    st = _trusted_sensitive_path(home, SV_KEY_RELATIVE, path, "SSH_IDENTITY")
    if st.st_mode & 0o077:
        raise ValueError("SSH_IDENTITY_NOT_PRIVATE_OR_NOT_OWNED")
    return path


def check_known_host(known_hosts: Path, lookup=subprocess.run,
                     expected_fingerprint: str = SV_ED25519_HOST_FINGERPRINT,
                     home: Path = None) -> Path:
    """Match fixed IP to an independently pinned ED25519 key from existing known_hosts.

    ssh-keygen -F supports hashed known_hosts entries; it does not contact SV.
    """
    home = home if home is not None else trusted_account_home()
    st = _trusted_sensitive_path(home, ".ssh/known_hosts", known_hosts, "KNOWN_HOSTS")
    if st.st_mode & 0o022:
        raise ValueError("KNOWN_HOSTS_UNTRUSTED")
    safe_path = known_hosts

    try:
        r = lookup([validate_system_executable(LOCAL_SSH_KEYGEN), "-F", SV_HOST, "-f", str(safe_path)],
                   capture_output=True, text=True, timeout=6, check=False,
                   env=restricted_process_environment())
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
    if not isinstance(value.get("cli"), str) or value["cli"] not in {"PRESENT", "NOT_FOUND_OR_UNTRUSTED", "UNKNOWN"}:
        raise ValueError("SV_CLI_STATE_INVALID")
    if not isinstance(value.get("auth"), str) or value["auth"] not in {"UNKNOWN", "SIGNED_IN", "NOT_SIGNED_IN", "NOT_SIGNED_IN_OR_ERROR"}:
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
                  expected_host_fingerprint: str = SV_ED25519_HOST_FINGERPRINT) -> dict:
    if host != SV_HOST:
        raise ValueError("HOST_NOT_ALLOWED")
    home = trusted_account_home()
    expected_identity = home / SV_KEY_RELATIVE
    if identity.is_symlink():
        raise ValueError("SSH_IDENTITY_SYMLINK_DENIED")
    if identity.absolute() != expected_identity.absolute():
        raise ValueError("SSH_IDENTITY_PATH_MISMATCH")
    key = check_identity_key(identity, home=home)
    kh = check_known_host(known_hosts or (home / ".ssh" / "known_hosts"),
                          lookup=lookup, expected_fingerprint=expected_host_fingerprint,
                          home=home)
    # -F /dev/null prevents silently consuming ~/.ssh/config. Host and identity
    # are explicit and pinned, as is the server's expected ED25519 host key.
    argv = [validate_system_executable(LOCAL_SSH), "-F", "/dev/null", "-T",
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
            "-i", str(key), "-l", "ubuntu", "--", SV_HOST, REMOTE_PYTHON + " -"]
    try:
        result = executor(argv, input=SV_PROBE, capture_output=True, text=True,
                          timeout=40, check=False, env=restricted_process_environment())
    except subprocess.TimeoutExpired:
        raise ValueError("SSH_TIMEOUT") from None
    except OSError:
        raise ValueError("SSH_EXECUTION_ERROR") from None
    if result.returncode != 0:
        raise ValueError("SSH_FAILED")
    try:
        return safe_remote_result(result.stdout.strip())
    except (ValueError, TypeError, json.JSONDecodeError):
        raise ValueError("REMOTE_STATUS_UNVERIFIABLE") from None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sv", action="store_true", help="Opt in to fixed SV read-only SSH probe")
    args = parser.parse_args(argv)
    try:
        result = remote_status(SV_HOST, trusted_account_home() / SV_KEY_RELATIVE) if args.sv else local_inventory()
    except (ValueError, OSError):
        # No raw exception messages; they may contain system paths or ssh details.
        print(json.dumps({"schema": SCHEMA, "status": "HOLD_UNVERIFIED"}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
