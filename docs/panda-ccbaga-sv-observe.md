<!--
[INPUT]: Mac Studio bounded installation receipt, CCBaga source inventory, pinned SV SSH host and existing official CLI.
[OUTPUT]: Read-only P2 pilot acceptance gates, exact CLI usage and security caveats.
[POS]: CCBaga project documentation for native app discovery and remote status-view planning.
[PROTOCOL]: Update with scripts, tests and workflow map; never claim CI is a real host installation.
-->
# CCBaga x SV Claude status observation: bounded pilot

Scope: GitHub CCBaga Issue #2. This is a source-only, opt-in, read-only pilot. It does not yet add a button to CCBaga-A; it does not install, start, authenticate or control Claude.

## Existing capabilities

CCBaga-A manages **local** macOS Claude Code/Desktop identities, local CLI installation maintenance and local network diagnostics. These are not remote SV functions. Its Pro/Max/Team/API badges reflect local account metadata and do not prove Anthropic server eligibility, live billing or Apple subscription status. Identity export and import are same-operating-system only. Never copy Mac Keychain, saved OAuth or browser cookies to SV.

The independently installed SV official Claude Code stable 2.1.304 is the server-side installed executable. No authorized account login has yet been evidenced.

## First action: identify Mac Studio's installed GUI, without installing it

On Mac Studio, the **existing** CCBaga Codex owner (only after confirming no conflict with the MACP P0-M native writer) can run in an existing checked-out repo:

    python3 scripts/panda-claude-observe.py

Without flags, this reads only /Applications/CCBaga-A.app, /Applications/CCBaga-B.app and the corresponding paths under the current user's ~/Applications. The code parses Info.plist after refusing symlinked app-bundle, Contents, or plist components, bounds the metadata size to 1 MiB, and compares exact bundle IDs. It does not start apps, scan user secrets or invoke network operations. A NOT_IN_STANDARD_LOCATIONS result is **not** proof that no debug or staging build exists elsewhere. Confirm any actual bundle's real path, code-signature status and version separately before considering a GUI launch. Do not reinstall or launch a bundled browser to determine whether an application already exists.

## Optional second action: source-review-gated remote status

Only once the independent security reviewer has inspected this source and runtime Owner/locks are verified, a human operator may explicitly choose SV observation in the Mac Studio terminal:

    python3 scripts/panda-claude-observe.py --sv

The tool pins SV to the existing approved IP 43.135.166.3, SSH username ubuntu, exact local identity path ~/.ssh/sv-ubuntu-admin/sv-ubuntu-admin-ed25519, and the previously witnessed ED25519 server host-key fingerprint. It rejects a missing/ambiguous/mismatched key in the user's existing known_hosts, accepts its hashed entries only after ssh-keygen -F verification, and does not create or rewrite keys. The fixed argv explicitly specifies -F /dev/null to ignore the user's ~/.ssh/config, the pinned known_hosts file and ED25519 host-key algorithm, BatchMode, IdentitiesOnly, no SSH agent, proxy/jump, multiplexing or forwarding. This status-only tool exposes no arbitrary host or key option. The pinned trust data must be reviewed again if the authorized SV or its host key intentionally changes. The fixed remote Python payload validates ubuntu UID1000 and checks that the official versioned executable resolves under ubuntu's installed Claude versions directory, is owned by UID1000 and is not group/world writable. It queries only the installed Claude version and its local auth status. It never captures or prints raw login output, email, token, OAuth URL, key or account ID; the returned schema includes limited version and enum status. No Claude auth login, model prompt, subscription purchase or API traffic is requested. UNKNOWN/HOLD is always safer than inventing an authenticated result. A CLI auth-status command may have internal undocumented bookkeeping; this is a bounded observational mode, not a formal immutable-filesystem guarantee.

## Acceptance gates

1. Exact-head CI verifies local bundle discovery and no-network mocked SSH, wrong identity/key, token leak, output format, timeout and unauthorized command behavior.
2. An independent non-author review must inspect the implementation and harden any shortcomings before a live SV probe or GUI integration.
3. The original MACP P0-M Studio Writer, P0-R SV Writer and their locks are never interrupted by CCBaga; avoid a second Codex Writer while they own their sessions.
4. Host results must distinguish local app presence, signature check, SV CLI version, live SV auth state, and separately verified provider eligibility. Local metadata badges are not remote login proof.
5. OAuth, account eligibility, paid models and production MACP/Herdr routing remain separate approval gates and must not be automated by this source-only pilot.

## Exclusions

No sudo/root, commercial RDC, system SSH/proxy/TUN/DNS changes, GUI automatic installation, bundled Chromium download/execution, fingerprint or regional changes, identity cleaning/export/restore, token transfer, extra scheduler, main merge, or amend/rebase/reset/force push. Existing CCBaga PRs #1/#3/#4 are untouched.

## Native Mac Studio survey evidence (2026-10-22)

[Issue #2 receipt #6339465202](https://github.com/pandagf123/CCBaga/issues/2#issuecomment-6339465202): four standard bundle paths absent; Spotlight and bounded process queries empty; local repo is a clean source checkout only. Several Downloads and Library/Caches subdirectories were unreadable. Record as **SOURCE_ONLY / NOT_FOUND_AT_CHECKED_PATHS**, not full-disk absence. No app bundle, valid signer, notarization or Gatekeeper result was found or tested.

SV read-only SSH/prior PR #1 offline preflight succeeded for ubuntu UID1000. This does not override the original [official stable 2.1.304 signed install receipt](https://github.com/pandagf123/CCBaga/issues/2#issuecomment-6320601018), does not prove a live subscription or authorized Anthropic account, and does not authorize running the new opt-in --sv probe until independent review. PR #5's 18 initial tests and cross-platform Checks ran, but the macOS installation boundary step was skipped.

## Separate isolated GUI acceptance

Before optionally installing CCBaga-A, pin upstream v0.2.49 tag + commit and specific asset hash, cross-check GitHub provenance/attestation where available, verify actual signed Apple bundles, notarization ticket and Gatekeeper in a disposable **nonproduction** macOS account or VM. A release workflow or upstream checksum alone does not establish publisher trust. No download/install/start is authorized by this source-only document.

## 2026-10-22 response to independent CHANGES_REQUIRED on feb866675

Independent review [PR #5 #6340225036](https://github.com/pandagf123/CCBaga/pull/5#issuecomment-6340225036) identified four findings. The isolated source correction replaces PATH-resolved SSH and ssh-keygen with root-owned, non-writable, absolute macOS system executables at /usr/bin/ssh and /usr/bin/ssh-keygen, invokes a fixed /usr/bin/python3 interpreter on SV, and uses a restricted local subprocess environment. The Ubuntu probe refuses symlinks in the Claude version-root ancestry, executes the previously checked canonical versioned Claude binary path rather than the launcher symlink, and retains UID1000/permissions checks. The local CCBaga bundle inspector now uses O_DIRECTORY/O_NOFOLLOW descriptor-relative opens from standard application directories through Contents to Info.plist; fstat constrains the file to a regular file and at most 1 MiB. Any denied/unreadable standard path returns NEEDS_REVIEW, not NOT_IN_STANDARD_LOCATIONS.

These corrections are **source-only** and do not promise immunity to same-user process memory tampering, all possible system filesystem races, publisher authenticity, or Anthropic entitlement. They **do not** authorize running the remote --sv probe or installing CCBaga-A. CI success is distinct from independent review and real host observation. Retain Draft status and require a new separate reviewer verdict on the *new exact SHA*, then a fresh native Mac Studio owner/lock admission before any live test.

## 2026-10-22 security review response: b979565 independent verdict

The pinned [PR #5 reviewer](https://github.com/pandagf123/CCBaga/pull/5#issuecomment-6342384096) returned Standards=ACCEPT_BOUNDED and Security/Spec=CHANGES_REQUIRED for exact head b979565d186c0382fd42a6624498338306df8d4b. This verdict is retained against that exact prior head, NOT automatically transferred to later revisions.

Three minimal corrections are implemented in the isolated PR source (not yet independently accepted):
1. The embedded SV Python probe imports **stat** explicitly. The dedicated offline fixture now **executes the actual embedded probe** in a temporary directory with a synthetic self-owned CLI stub; no real SV path, Claude executable, accounts, network, model, or token is used.
2. Identity/key and known_hosts paths are derived from the operating system **POSIX account home via pwd.getpwuid**, never caller HOME. The account home ancestry is verified for owner, directory type, no symlinks and unsafe writable components, and the pinned home-relative .ssh and identity subdirectories are individually lstat-verified with no symlink traversal. Any ambiguous path fails closed; nothing is created or rewritten.
3. The sanitized remote status decoder type-checks cli/auth strings before set membership (including JSON arrays and objects) and rejects malformed fields. The boundary converts invalid output to a redacted HOLD; raw stderr/credential values are not copied to GitHub or callers.

Synthetic fixture tests also cover untrusted HOME and symlinked key/known_hosts parents. The account-home trust checks may conservatively deny valid nonstandard or symlinked macOS homes; that is an intended HOLD instead of relaxing trust. Under documented same-UID attacker or executable changes, these observations are not a full attestation. Do not run --sv or install CCBaga-A until exact-final-HEAD CI plus genuinely independent Security/Spec review and native host admission. Keep PR Draft, no main merge.
