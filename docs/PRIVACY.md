# ReKey — Privacy Policy

_Last updated: 2026-06-22_

ReKey is a local-first password-health auditor for macOS. It is designed so that
your passwords never leave your Mac. **ReKey collects no personal data, has no
user accounts, and contains no analytics, telemetry, advertising, or tracking of
any kind.**

## What ReKey does on your device

- You **export** password CSVs from your browsers / Apple Passwords and import
  them into ReKey. ReKey reads only the files you explicitly choose (or, if you
  opt in, a folder you pick for auto-import).
- Imported passwords are held **in memory only** — never written to disk, never
  logged. The source CSV stays on disk until you securely delete it (an action
  ReKey offers and you confirm).
- The audit (reuse detection, strength checks, grouping) runs **entirely on your
  device**.

## The only data that leaves your device

ReKey makes two kinds of network request, both initiated by you and neither of
which collects, stores, links, or shares any personal data:

1. **Breach check via Have I Been Pwned (k-anonymity).** To tell you whether a
   password appears in a known breach, ReKey hashes the password with SHA-1 on
   your device and sends only the **first 5 characters of that hash** to
   `api.pwnedpasswords.com`. The full hash and the password itself never leave
   your Mac. The service returns a list of matching hash suffixes, and ReKey
   completes the match locally. This is the standard
   [k-anonymity model](https://haveibeenpwned.com/API/v3#PwnedPasswords); the
   5-character prefix cannot identify your password. A padding header is sent so
   response size doesn't leak how many matches there were.

2. **Resolving a change-password page.** When you choose to fix a specific
   account, ReKey makes an on-demand request to **that site's own domain** to
   find its `/.well-known/change-password` page (a published web standard),
   falling back to a small bundled map or the site's home page. This happens one
   site at a time, only for the account you're fixing — ReKey never pings your
   whole list of accounts, and never sends this information anywhere but the
   site you're changing your password on.

No other servers are contacted. There is no ReKey server.

## Data collection summary (App Store privacy labels)

- **Data used to track you:** none.
- **Data linked to you:** none.
- **Data not linked to you:** none collected.

## Optional folder access

If you enable auto-import, ReKey stores a security-scoped bookmark to the single
folder you pick (e.g. Downloads) so it can watch for new exports across launches.
This bookmark stays on your device and is used only to read recognized password
CSVs you place there.

## The separate `rekey-cleanup` tool

Outright deletion of stale logins from browser stores is **not** part of the App
Store app (a sandboxed app cannot, and should not, write to other apps' data).
That capability lives in a separate, optional command-line tool,
[`rekey-cleanup`](https://github.com/smandable/ReKey), that you build and run
yourself. It operates entirely locally, backs up each store before changing it,
and likewise sends nothing anywhere.

## Contact

Questions: open an issue at <https://github.com/smandable/ReKey> or email
smandable@gmail.com.
