---
name: panda-host-preflight
description: Non-mutating, sanitized Linux host capacity and official Claude Code CLI preflight for authorized SV/MACP pilot evaluation. Use before proposing a separately approved Claude Code installation. No identity resets, fingerprint spoofing, provider-ban avoidance, or privileged changes.
---

# Panda Host Preflight (read-only P0)

## Purpose
Check only host readiness for a **separately authorized, legitimate** official Claude Code pilot. This Skill does not install or authenticate Claude, bypass provider restrictions, or configure a VPS proxy.

## Safety boundary
- Read-only Python standard library; no external shell, sudo, root access, package installation, Git mutation, system settings or credential access.
- Do not inspect Claude configuration files, OAuth caches, SSH credentials, API keys, private Git repositories, shell history, hostnames, public IPs or process arguments.
- No network request in default mode. --network is an explicit opt-in to direct, certificate-validated TLS handshakes with claude.ai, api.anthropic.com and downloads.claude.ai, no HTTP requests or tokens.
- Never claim DNS/WebRTC leak safety, account authorization, provider support or that successful TLS implies a working authenticated CLI.
- Only execute on the specifically approved target host via an existing authorized non-commercial execution channel. Running on a different computer proves nothing about SV.
- Existing MACP/PAC authority, exclusive Writer locks and production approvals are unchanged.

## Run
From the repository root on the approved target host:

    python3 skills/panda-host-preflight/scripts/preflight.py

Only if explicit network probing is approved:

    python3 skills/panda-host-preflight/scripts/preflight.py --network

Offline unit tests, safe on a standalone clone:

    python3 -m unittest discover -s skills/panda-host-preflight/tests -v

The report is structured JSON on standard output. Capture the complete JSON and process exit status; preserve original evidence locally or in a separately approved evidence store. Do not paste private credentials to any log. No credentials should appear in this program's output.

## Result interpretation
- READY_FOR_INSTALL_REVIEW: OS/arch, non-root, >= 4096 MiB physical RAM and >= 1024 MiB free root filesystem observed. Not permission to install, not account readiness.
- BLOCKED: at least one required condition actually failed; stop and investigate.
- UNKNOWN: incomplete observation; fail closed instead of guessing.
- claude_cli_on_path only means a command of that name resolves on the current PATH. It is not executed, authenticated or checked for provenance.
- If --network was requested, each TLS result is separate from host readiness. Any TLS failure is a connectivity concern; it does not automatically identify the cause.

## Next gates, not performed by this Skill
1. Independent review of this diff, test results and target-host ownership.
2. Explicit host-specific approval before official Claude Code installation; keep SSH, UFW, sysctl, proxies and other agents intact.
3. Verify legitimate account/service eligibility using official authorization; avoid account suspension circumvention.
4. Use isolated non-root executor, constrained worktree, resource limits and MACP single-Writer approval before any writable task.
