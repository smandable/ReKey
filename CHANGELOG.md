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

## [Unreleased] — 1.1.0

### Security
- **A copied password no longer survives quitting the app.** The Fix Queue already
  auto-clears the clipboard 90s after a copy; now quitting inside that window clears
  it immediately too — but only if the clipboard still holds the value ReKey wrote,
  so it never wipes something you copied afterward. [auditor]
- **Passphrase entropy is now guaranteed.** The bundled EFF wordlist is verified at
  load to be the full, unique 7,776-word set; a short or duplicate-laden list now
  fails loudly instead of silently producing lower-entropy passphrases. Self-test
  checks completeness, and the generator exposes whether passphrases are available
  so the UI can degrade gracefully. [auditor]
- **Closed a heredoc target-smuggling hole in generated cleanup scripts (critical).**
  A site or username derived from an untrusted CSV could embed a newline or the
  literal heredoc delimiter and smuggle extra delete targets — or arbitrary shell —
  into a generated `rekey-cleanup purge` script. Script bodies are now sanitized
  (every control character is neutralized) and the closing delimiter is chosen to
  avoid any data line, so a value can no longer add, drop, or terminate a line. [cli][cull]
- **Closed a flag-injection path on `rekey-cleanup` values.** A `--`-shaped value
  (e.g. a username of `--confirm`) could be parsed as a real flag and turn a
  preview into a live delete. Values are now quoted when they lead with `-`, and the
  CLI binds each value-flag's argument greedily so a `--`-shaped value is always
  consumed as data, never promoted to a flag (failing safe toward a dry run). [cli]
- **Anchored `rekey-cleanup delete --site` to the exact host.** A loose `--site`
  value could delete look-alike domains (e.g. `nodepositcasino.com` for `casino.com`);
  `delete` now matches the full host or a subdomain (as `purge` already did) and
  removes exactly the rows it displays. `list --site` keeps substring matching for
  discovery. [cli]

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
