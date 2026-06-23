# Changelog

All notable changes to ReKey are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/); versions track the marketing
version (`CFBundleShortVersionString`).

ReKey ships through two channels off one codebase:
- **App Store** — "ReKey - Website Password Audit", the pure-auditor build. Entries
  tagged **[auditor]** reach it.
- **GitHub .dmg** — the full build, which also includes the `rekey-cleanup` CLI and
  the Cull deletion flow. Entries tagged **[cli]** / **[cull]** apply to this channel
  only (they are compiled out / unreachable in the App Store build).

Entries tagged **[internal]** are refactors with no user-facing behavior change.

## [Unreleased]

### Changed
- **The "may not have saved" warning no longer looks like a password-health finding.**
  It used to share the orange/red of the finding badges, so a possibly-failed fix
  blended in with "reused/compromised" flags. The per-account marker is now a quiet
  label paired with a prominent **Reopen** button (the action stands out), and the
  top banner uses the accent color — red stays reserved for Compromised. [auditor]

## [1.1.0] — 2026-06-23

### Security
- **rekey-cleanup backup snapshots are now owner-only and prune-safe.** Pre-delete
  store backups are created `0700`/`0600` (not world-readable), and the snapshot
  pruner only ever touches ReKey's own timestamped backup directories — so pointing
  `--backup-dir` at a shared folder can't expose the copy or delete unrelated dirs. [cli]
- **Breach-check requests are never cached to disk.** The Have I Been Pwned check now
  uses a private, cache-less session, so the password-derived hash prefix in each
  request can't be written to the on-disk URL cache. [auditor]
- **Plaintext passwords are scrubbed from memory when no longer referenced.** The
  in-memory password wrapper now zeroes its buffer as soon as the last copy is
  released, instead of leaving cleartext lingering in memory for the whole session.
  (The wrapper is also now thoroughly tested.) [auditor]
- **The "change password" link can't be redirected off-site.** When ReKey resolves
  a site's change-password page, it now only trusts a redirect that stays on the
  same site over https, and only opens https URLs from its curated map — so a rogue
  redirect or open-redirect can't send you to an attacker's look-alike form. [auditor]
- **The save-verification fingerprint on disk is no longer brute-forceable.** When
  you mark a fix done, ReKey records a hash of the old/new password (never the
  password) to later confirm the change saved. That hash is now a keyed HMAC whose
  key lives in the Keychain, so the value in the preferences file can't be used to
  recover the (often weak) password offline. [auditor]
- **A copied password no longer survives quitting the app.** The Fix Queue already
  auto-clears the clipboard 90s after a copy; now quitting inside that window clears
  it immediately too — but only if the clipboard still holds the value ReKey wrote,
  so it never wipes something you copied afterward. [auditor]
- **Passphrase entropy is now guaranteed.** The bundled EFF wordlist is verified at
  load to be the full, unique 7,776-word set; a short or duplicate-laden list now
  fails loudly instead of silently producing lower-entropy passphrases. Self-test
  checks completeness, and the generator exposes whether passphrases are available
  so the UI can degrade gracefully. [auditor]
- **Hardened generated cleanup scripts against malicious CSV-derived values.** A
  site or username taken from an untrusted CSV export is now sanitized before it
  reaches a generated `rekey-cleanup` script, so it stays inert data and can't alter
  the script's structure. [cli][cull]
- **A crafted CSV value can no longer be read as a command-line flag.** `rekey-cleanup`
  now treats each interpolated site/username strictly as a value, so it can't be
  promoted into a flag (and the tool stays dry-run by default — a real delete still
  needs an explicit `--confirm`). [cli]
- **Anchored `rekey-cleanup delete --site` to the exact host.** A loose `--site`
  value could delete look-alike domains (e.g. `nodepositcasino.com` for `casino.com`);
  `delete` now matches the full host or a subdomain (as `purge` already did) and
  removes exactly the rows it displays. `list --site` keeps substring matching for
  discovery. [cli]

### Fixed
- **Importing or securely deleting a large file no longer freezes the window.** The
  file read and the secure-overwrite-and-delete now run off the main thread, so the
  UI stays responsive. [auditor]
- **A huge file dropped in the watched folder (or picked) is no longer read into
  memory.** Imports over a generous size cap are skipped with a clear message instead
  of risking an out-of-memory hang on a file far too large to be a password export. [auditor]
- **A background auto-import during an audit can't corrupt the results.** An audit
  now discards its result if the imported credentials changed while it was running
  (and a new import or re-run cancels the in-flight HIBP check instead of leaving it
  to overwrite the current view). [auditor]
- **An incomplete breach check no longer reads as a clean result.** If Have I Been
  Pwned can't be reached for some passwords (offline or the service didn't respond),
  Findings now shows how many couldn't be checked rather than silently treating them
  as safe — re-run when back online to confirm. [auditor]
- **Strong passwords using non-Latin scripts or emoji are no longer mislabeled "Weak."**
  The weak-password check judged length by character count, so a short-looking but
  high-entropy password (e.g. CJK or emoji) read as weak; it now weights non-ASCII
  characters by the larger alphabet they draw from. [auditor]
- **A redundant duplicate copy of a login on the same site is no longer hidden** when
  that login is also reused or breached. The Findings list now shows a "Duplicate on
  site" badge alongside the primary issue, so you don't miss the extra copy to clean
  up. [auditor]

### Changed
- Extracted a single, unit-tested `CleanupScript` library as the one source of truth
  for every `rekey-cleanup` command string and purge block, replacing three
  divergent copies across the UI layer; moved the CLI's logic into a testable
  `CleanupCLI` library behind a thin executable entrypoint. [internal]

### Tests
- Added a test target for the previously-untested `rekey-cleanup` CLI, plus
  builder-level tests for the smuggling, flag-injection, and host-anchoring
  defenses (test count 224 → 247). [cli]

## [1.0.0] — 2026-06-22

- Initial release. Imports password CSVs from Chrome, Arc, Brave, Edge, Firefox, and
  Apple Passwords; audits for reuse, weak/short passwords, known breaches
  (Have I Been Pwned via k-anonymity), cross-ecosystem duplicates, and stray
  blank-username entries; guided Fix Queue that generates strong replacements and
  opens each site's own change-password page. GitHub .dmg adds the `rekey-cleanup`
  CLI and the Cull mark-for-deletion flow.
