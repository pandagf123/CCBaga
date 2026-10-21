#!/usr/bin/env python3
# [INPUT]: Aggregate host metadata; fixed official TLS targets only with explicit --network.
# [OUTPUT]: Sanitized JSON readiness observations and fail-closed status; no credentials or files.
# [POS]: Read-only stdlib preflight for a separately authorized Claude Code pilot.
# [PROTOCOL]: Update this header, the Skill contract, and skills/CLAUDE.md when behavior changes.
"""Non-mutating Linux host preflight for an optional official Claude Code pilot.

This program never reads Claude credentials, launches Claude, invokes shell
commands, uses sudo, or changes system configuration. Network checks require
an explicit --network flag and only attempt public TLS handshakes.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import socket
import ssl
import sys
from typing import Any

SCHEMA = "panda.host-preflight.v1"
HOSTS = ("claude.ai", "api.anthropic.com", "downloads.claude.ai")
# Effective Linux MemTotal screening threshold for a nominal 4 GB VM.
# MemTotal excludes kernel-reserved memory; this is not physical-capacity proof.
MIN_MEMORY_MIB = 3600
MIN_FREE_MIB = 1024
SUPPORTED_ARCHES = {"x86_64", "aarch64", "arm64"}


def memory_mib() -> int | None:
    """Read only aggregate host capacity, never process data."""
    try:
        with open("/proc/meminfo", encoding="ascii") as source:
            for line in source:
                match = re.fullmatch(r"MemTotal:\s+(\d+)\s+kB\s*", line)
                if match:
                    return int(match.group(1)) // 1024
    except (OSError, UnicodeError, ValueError):
        pass
    return None


def free_mib() -> int | None:
    try:
        info = os.statvfs("/")
        return (info.f_bavail * info.f_frsize) // (1024 * 1024)
    except (OSError, AttributeError):
        return None


def simple_check(value: bool | None) -> str:
    if value is None:
        return "UNKNOWN"
    return "PASS" if value else "FAIL"


def classify(observed: dict[str, Any]) -> dict[str, str]:
    """Pure decision logic; unknown observations must never be treated as pass."""
    checks = {
        "linux": simple_check(observed.get("os") == "linux" if observed.get("os") else None),
        "supported_arch": simple_check(
            observed.get("arch") in SUPPORTED_ARCHES if observed.get("arch") else None
        ),
        "non_root": simple_check(observed.get("non_root")),
        "memory_minimum": simple_check(
            observed["memory_mib"] >= MIN_MEMORY_MIB
            if observed.get("memory_mib") is not None else None
        ),
        "free_disk_minimum": simple_check(
            observed["root_free_mib"] >= MIN_FREE_MIB
            if observed.get("root_free_mib") is not None else None
        ),
    }
    return checks


def tls_probe(host: str, timeout: float) -> str:
    """Verify certificate-validated TLS only. Never send auth or HTTP data."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as secured:
                secured.settimeout(timeout)
                return "PASS" if secured.version() else "UNKNOWN"
    except (OSError, ssl.SSLError, TimeoutError):
        return "FAIL"


def build_report(network: bool = False, timeout: float = 3.0) -> dict[str, Any]:
    system = platform.system().lower()
    arch = platform.machine().lower() or None
    euid = os.geteuid() if hasattr(os, "geteuid") else None
    observed = {
        "os": system or None,
        "arch": arch,
        "non_root": None if euid is None else euid != 0,
        "memory_mib": memory_mib() if system == "linux" else None,
        "root_free_mib": free_mib(),
        "claude_cli_on_path": bool(shutil.which("claude")),
    }
    checks = classify(observed)
    state = "BLOCKED" if "FAIL" in checks.values() else (
        "UNKNOWN" if "UNKNOWN" in checks.values() else "READY_FOR_INSTALL_REVIEW"
    )
    network_results = (
        {host: tls_probe(host, timeout) for host in HOSTS} if network else None
    )
    return {
        "schema": SCHEMA,
        "host_scope": "current_process_host_only",
        "decision": state,
        "observed": observed,
        "checks": checks,
        "network": {
            "performed": network,
            "kind": "direct_certificate_validated_tls_handshake",
            "results": network_results,
        },
        "limitations": [
            "No Claude login or account eligibility is checked.",
            "No API subscription, authorized region, VPN or browser is assessed.",
            "The effective memory threshold is a screening heuristic; verify physical RAM separately.",
            "Direct TLS does not prove Claude CLI proxy routing or DNS/WebRTC privacy.",
            "No credentials, local Claude identity, SSH keys or project files are read.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--network", action="store_true",
        help="Explicitly attempt TLS handshakes to three official Claude domains",
    )
    parser.add_argument(
        "--timeout", type=float, default=3.0,
        help="Per-host network timeout in seconds (1..10, used only with --network)",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 10:
        parser.error("--timeout must be between 1 and 10 seconds")
    report = build_report(network=args.network, timeout=args.timeout)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    # Nonzero means host review failed, not that anything was changed.
    return 0 if report["decision"] == "READY_FOR_INSTALL_REVIEW" else 2


if __name__ == "__main__":
    sys.exit(main())
