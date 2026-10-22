# CCBaga x SV Claude status observation: bounded pilot

Scope: GitHub CCBaga Issue #2. This is a source-only, opt-in, read-only pilot. It does not yet add a button to CCBaga-A; it does not install, start, authenticate or control Claude.

## Existing capabilities

CCBaga-A manages **local** macOS Claude Code/Desktop identities, local CLI installation maintenance and local network diagnostics. These are not remote SV functions. Its Pro/Max/Team/API badges reflect local account metadata and do not prove Anthropic server eligibility, live billing or Apple subscription status. Identity export and import are same-operating-system only. Never copy Mac Keychain, saved OAuth or browser cookies to SV.

The independently installed SV official Claude Code stable 2.1.304 is the server-side installed executable. No authorized account login has yet been evidenced.

## First action: identify Mac Studio's installed GUI, without installing it

On Mac Studio, the **existing** CCBaga Codex owner (only after confirming no conflict with the MACP P0-M native writer) can run in an existing checked-out repo:

    python3 scripts/panda-claude-observe.py

Without flags, this reads only /Applications/CCBaga-A.app, /Applications/CCBaga-B.app and the corresponding paths under the current user's ~/Applications. The code parses Info.plist and compares exact bundle IDs. It does not start apps, scan user secrets or invoke network operations. A NOT_IN_STANDARD_LOCATIONS result is **not** proof that no debug or staging build exists elsewhere. Confirm any actual bundle's real path, code-signature status and version separately before considering a GUI launch. Do not reinstall or launch a bundled browser to determine whether an application already exists.

## Optional second action: source-review-gated remote status

Only once the independent security reviewer has inspected this source and runtime Owner/locks are verified, a human operator may explicitly choose SV observation in the Mac Studio terminal:

    python3 scripts/panda-claude-observe.py --sv --host VERIFIED_EXISTING_SV_HOST --identity-file EXISTING_MAC_STUDIO_UBUNTU_PRIVATE_KEY_PATH

The tool uses a fixed SSH argv with StrictHostKeyChecking, BatchMode, IdentitiesOnly, no proxy/jump injection, no forwarding and the already authorized private key. The fixed remote Python payload validates ubuntu UID1000 and queries only the installed Claude version and its local auth status. It never captures or prints raw login output, email, token, OAuth URL, key or account ID; the returned schema includes limited version and enum status. No Claude auth login, model prompt, subscription purchase or API traffic is requested. UNKNOWN/HOLD is always safer than inventing an authenticated result. A CLI auth-status command may have internal undocumented bookkeeping; this is a bounded observational mode, not a formal immutable-filesystem guarantee.

## Acceptance gates

1. Exact-head CI verifies local bundle discovery and no-network mocked SSH, wrong identity/key, token leak, output format, timeout and unauthorized command behavior.
2. An independent non-author review must inspect the implementation and harden any shortcomings before a live SV probe or GUI integration.
3. The original MACP P0-M Studio Writer, P0-R SV Writer and their locks are never interrupted by CCBaga; avoid a second Codex Writer while they own their sessions.
4. Host results must distinguish local app presence, signature check, SV CLI version, live SV auth state, and separately verified provider eligibility. Local metadata badges are not remote login proof.
5. OAuth, account eligibility, paid models and production MACP/Herdr routing remain separate approval gates and must not be automated by this source-only pilot.

## Exclusions

No sudo/root, commercial RDC, system SSH/proxy/TUN/DNS changes, GUI automatic installation, bundled Chromium download/execution, fingerprint or regional changes, identity cleaning/export/restore, token transfer, extra scheduler, main merge, or amend/rebase/reset/force push. Existing CCBaga PRs #1/#3/#4 are untouched.
