# Panda CCBaga fork: bounded P0 engineering pilot

## Target and status
- Source: user-owned fork pandagf123/CCBaga; upstream liseami/CCBaga remains an untrusted third-party input.
- Feature branch: feat/sv-claude-readonly-preflight-20261021, based on bdfb90ceadfc5fae6772ffff597bddecb0b73cc3.
- Work delivered: standalone, dependency-free and opt-in-network read-only host diagnostic tool with offline unit tests.
- Not delivered: complete upstream security certification, executable review of Fingerprint Chromium, live SV inspection, any Claude installation, authenticated login or a MACP production integration.

## Why this scope
The upstream CCBaga desktop UI targets local browser and identity management. Its separate ccbaga-network Skill controls Debian 12/13 VPS network infrastructure using root, Xray, SSH and firewall changes. This is incompatible with the current SV Ubuntu 26.04 and the user's requirement not to disturb existing MACP/PAC execution infrastructure.

## Preliminary upstream issues to examine before adoption
1. skills/ccbaga-network/scripts/setup-vps.sh: default ENABLE_SUB=1; UFW opens 8443/tcp, serves credential-bearing Clash config over plain HTTP; modifies system SSH, sysctl, firewall and services. Do not execute on SV.
2. scripts/fetch-browser.py: pinned SHA-256 is good transport-integrity control, but upstream third-party Fingerprint Chromium binaries require independent provenance/build/release review.
3. src-tauri/src/identities/store.rs and codec.rs: encrypted identity vault and staged recovery are promising, but sensitive keys and ciphertext are stored on the same device. Read and assess all filesystem, recovery, and import paths before reusing.
4. Browser localhost server: inspect origin/session handling, rate/resource limits, and reporting schemas. Localhost-only is not equivalent to an OS security boundary.
5. No general claim about provider risk engines: device/browser environment checks cannot establish that any service will accept an account.

## Explicit non-goals
- No bypass of revoked/blocked Anthropic accounts or anti-fraud systems.
- No fingerprint or identity-marker rotation functionality in the fork pilot.
- No automatic upstream synchronization, commercial RDC usage, shell credential extraction, or replacement of existing SV proxy configuration.
- No new ongoing scheduler, Writer, SSH host, production trigger or main merge.

## Acceptance checklist
- [x] Feature branch isolated from main.
- [x] Preflight and offline tests added to fork.
- [ ] Offline tests run against exact committed source.
- [ ] Remote branch fetch-back matches intended contents.
- [ ] Draft PR created for review.
- [ ] Independent reviewer accepts the bounded code, vulnerabilities catalogued.
- [ ] Actual target-host read-only evidence captured by an authorized channel.
- [ ] Separate approved official Claude installation, if legal account/service access is available.

## Follow-on architecture (only after authorization)
- MACP capability: provider-independent read-only environment check, never credentials or identity spoofing.
- MACP coordinator: provider startup requires runtime availability + valid approval + exclusive Writer lock; local snapshots do not prove process death.
- WORK-OS: optional displays of already authorized evidence, not a new source of truth replacing PAC #27.
