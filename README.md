# Rekey

A **local-first password health auditor** for macOS. Rekey imports CSVs you
export from Chrome, Arc, Firefox, and Apple Passwords, finds **reused** and
**compromised** passwords, groups them alphabetically by site, generates strong
replacements, and routes you to each site's change-password page. **Every change
is approved by you, and Rekey never changes a password itself.**

Bundle ID: `com.seanmandable.rekey` · macOS 15+ · Swift 6 · arm64.

---

## What Rekey guarantees

These are hard constraints of the **`Rekey.app`** auditor, enforced by the
architecture. (There is one separate, opt-in command-line tool, `rekey-cleanup`,
that *can* delete logins — see [Deleting stale logins](#deleting-stale-logins-rekey-cleanup)
below. It is not part of the sandboxed app and the app never links it.)

- **The app never edits your credentials and never writes to any browser, Apple
  Passwords, or the system keychain.** It generates a new password and opens the
  site's change page; *you* make the change, and your browser's own "save
  password?" prompt stores it.
- **No automated form-filling, browser driving, or password rotation.**
- **v1 reads only user-exported CSV files.** It does not read browser databases
  or keychains, and does not touch the Chromium Safe Storage key or Firefox NSS.
- **Plaintext passwords live in memory only** — never written to disk, never
  logged, never transmitted. The lone exception is the Have I Been Pwned check,
  which uses k-anonymity: only the **first 5 characters of a SHA-1 hash** ever
  leave the device.
- **No analytics, telemetry, or crash reporting.** The only network calls are the
  HIBP range query and the on-demand resolution of a single site's
  change-password URL when you choose to fix it. Reset URLs are resolved lazily,
  one at a time — never by batch-pinging your whole account list.
- **App Sandbox is on.** Entitlements: outgoing network client; read-write to
  user-selected files (so the source CSV can be securely deleted); and an
  app-scope bookmark, used only if you turn on the opt-in auto-import folder
  watcher (to remember the folder across launches). Nothing else.

A `Secret` wrapper holds every password; its `description`/`debugDescription` are
redacted, so a password can never be accidentally logged or string-interpolated.

---

## Build & run

There are two ways to build the app — an Xcode project and a pure-CLI script —
both backed by the same Swift package, so the code and tests are identical.

**Xcode** (`Rekey.xcodeproj`): open it and run the **Rekey** scheme (⌘R). The app
target links the local Swift package's `RekeyUI` product and is configured for
App Sandbox with `App/Rekey.entitlements`, bundle id `com.seanmandable.rekey`,
macOS 15, Swift 6. (Xcode also auto-generates schemes for the package products;
the shared **Rekey** scheme is the app.)

```bash
# Or build the app from the command line, no Xcode UI:
xcodebuild -project Rekey.xcodeproj -scheme Rekey -configuration Release build

# Run the full test suite (91 tests, no network — HIBP & reset are mocked)
swift test

# Run from source (dev)
swift run Rekey

# Build the sandboxed, signed Rekey.app without Xcode at all
./Scripts/build_app.sh
open Rekey.app
```

`Scripts/build_app.sh` builds the release binary, assembles `Rekey.app`, copies
the vendored resource bundles into `Contents/Resources`, and ad-hoc codesigns it
with `App/Rekey.entitlements` — useful for a no-Xcode pipeline. (Notarization and
Sparkle auto-update are out of scope for this build.)

You can sanity-check the packaged bundle's resource loading without opening a
window:

```bash
Rekey.app/Contents/MacOS/Rekey --selftest
```

---

## Exporting your passwords

| Browser | How to export |
|---|---|
| **Chrome** | Settings → Autofill → Password Manager → ⋮ → Export passwords |
| **Arc / Brave / Edge / Opera / Vivaldi** | Same as Chrome — they're all Chromium and export an identical CSV. Rekey can't tell them apart from the file, so pick the right one in the **"label it"** menu before importing. Any other Chromium browser works too (choose *Chromium*). |
| **Firefox** (and forks: LibreWolf, Waterfox, Tor Browser) | about:logins → ⋯ → Export Logins. Forks share Firefox's format and are detected automatically. |
| **Apple Passwords / Safari** | Passwords app → File → Export All Passwords (or ⋯ → Export) |
| **Anything else** | If a CSV has recognizable `url`/`username`/`password` columns, Rekey maps them fuzzily; truly unknown layouts fall back to manual column mapping. |

⚠️ A plaintext password CSV in `~/Downloads` is the single biggest real-world
risk. After importing, use Rekey's **Securely delete** button (it overwrites the
file's bytes, then unlinks it).

**Auto-import (optional).** On the Import screen you can *Choose folder…* to watch
a folder (e.g. Downloads). Rekey then imports any recognized password CSV that
appears there automatically (and only recognized ones — a random CSV is left
alone), then prompts you to securely delete it. You still export manually — there
is no API to automate the export, and Rekey deliberately doesn't read your
browser stores directly. The watched folder is remembered across launches via a
security-scoped bookmark; *Stop* forgets it.

---

## How it works

1. **Import** — detects each format by header name (not position), parses with a
   correct RFC 4180 parser (quoted fields, embedded commas/newlines, escaped
   quotes, BOM, CRLF), and canonicalizes URLs to their registrable domain via a
   vendored Public Suffix List (so `mail.google.com` and `accounts.google.com`
   group under `google.com`, and `bbc.co.uk` resolves correctly). Blank-password
   rows (passkeys, federated sign-in) are skipped and counted. TOTP seeds are
   flagged but never stored.
2. **Audit** — buckets passwords in memory to find reuse across sites and
   duplicates within a site, and checks each against HIBP. Findings are grouped
   by registrable domain, alphabetically, with "shared with: …" clustering.
3. **Fix queue** — for each credential you choose to fix, a preview card shows the
   masked old password (with reveal), a freshly generated replacement (with
   regenerate + policy controls + a passphrase option), and the resolved change
   URL. **Approve** copies the new password, opens the change page, and clears
   the clipboard ~90s later. You change it on the site and mark it done.

### Password generation

CSPRNG only (`SecRandomCopyBytes`), rejection sampling to avoid modulo bias, at
least one character from each required class. Configurable length, character
classes, "avoid look-alikes" (`Il1O0`), a letters-and-digits-only mode for
picky sites, and a diceware passphrase mode (vendored EFF large wordlist).

### Reset routing

Tries `https://{domain}/.well-known/change-password` (the same mechanism Safari
and Chrome use), following redirects, with a control-probe to avoid trusting
servers that 200 everything. Falls back to a curated map
(`Sources/ResetRouter/Resources/FallbackMap.json`, easy to extend), and finally
to the site root with a clear "find the setting yourself" note. **No LLM ever
guesses a reset URL** — a guessed URL is worse than none.

Each fix-queue card shows **how** the URL was resolved: a green
*"Supports .well-known/change-password"* badge when the site exposes the W3C
standard, a *"Known change page"* badge for curated entries, or a *"No change
page found"* note for the site-root fallback. This indication only appears in the
fix queue, never in the findings list — resolution is resolved lazily, per item,
so the app never broadcasts your whole account list by probing every domain.

---

## Deleting stale logins (`rekey-cleanup`)

After you change a password, the browser usually *updates* the saved login in
place — but sometimes it saves a brand-new entry instead, leaving a stale
duplicate with the dead password. The browser's save dialog can't remove that;
deletion is a browser-local action. `rekey-cleanup` is a **separate, opt-in
command-line tool** for exactly this.

It is deliberately **not** part of `Rekey.app`: the app stays sandboxed and never
touches any store. (After you mark a fix *done*, the fix-queue card shows an
optional "Old login still saved?" section with the manual steps and a
copy-paste `rekey-cleanup` command pre-filled for that site — guidance only; the
app never runs it.)

This tool isn't sandboxed (it has to reach the browser's profile), so it's
quarantined with heavy guardrails:

- **Decrypt-free.** It matches and deletes purely on *plaintext* index fields
  (Chromium `origin_url`/`username_value`/`signon_realm`/`rowid`; Firefox
  `hostname`/`guid`). It never reads the encrypted password blob, so it never
  needs the Chromium Safe Storage key, Firefox NSS/`key4.db`, or the keychain.
  (Trade-off: Firefox usernames are encrypted, so Firefox logins are identified
  by host + GUID + date, shown as `(encrypted)`.)
- **Dry-run by default.** `delete` shows what it *would* remove and changes
  nothing unless you pass `--confirm`.
- **Won't run with the browser open.** Writing under a live browser is the
  classic corruption path, so a confirmed delete is refused until you quit it.
- **Backs up first.** The store (plus Chromium WAL/SHM sidecars) is copied to
  `~/Library/Application Support/Rekey/Backups/<browser>-<timestamp>/` before any
  write. If the backup fails, nothing is deleted.
- **Transactional / atomic.** Chromium deletes run in a SQLite transaction
  (rollback on any error); Firefox is rewritten atomically (temp file + rename),
  preserving every other login and all unknown fields.
- **Never deletes blindly.** A delete requires a filter (`--site`, `--username`,
  or `--id`); it refuses to wipe the whole store.
- **Known schemas only.** It bails on an unrecognized store shape rather than
  guessing.

**Apple Passwords is not supported** — iCloud Keychain has no third-party delete
API. Supported: Chrome, Arc, Brave, Edge, Opera, Vivaldi, Chromium, Firefox.

```bash
swift run rekey-cleanup help

# See what's saved (run this to find ids):
swift run rekey-cleanup list --browser chrome --site github.com

# Preview a delete (dry run — nothing changes):
swift run rekey-cleanup delete --browser chrome --site github.com --username old@example.com

# Quit the browser, then actually delete (auto-backs-up first):
swift run rekey-cleanup delete --browser chrome --site github.com --username old@example.com --confirm
```

> **On the relaxed constraint:** the original spec forbade *all* store writes.
> That rule still holds for `Rekey.app`. This tool is the explicit, isolated
> exception — and even here, "no corruption" can't be *guaranteed* (browser
> sync can resurrect a deleted entry; recent Chrome app-bound encryption is
> hardening this surface), so the guardrails above are risk *reduction*, and the
> automatic backup is your undo.

## Project layout

```
Sources/
  Model/             Secret (redacted), ImportedCredential, findings, FixItem, resource resolver
  ImportKit/         RFC 4180 CSV parser, format detection, normalization, PSL eTLD+1   (+ PSL data)
  AuditEngine/       reuse/duplicate analysis + compromise orchestration
  HIBPClient/        HIBP k-anonymity range client (SHA-1, Add-Padding, dedup, cache)
  PasswordGenerator/ CSPRNG generator + diceware passphrases                            (+ EFF wordlist)
  ResetRouter/       well-known + curated fallback, lazy by construction                (+ FallbackMap)
  FixQueue/          preview/approve state machine + clipboard hygiene
  RekeyUI/           SwiftUI: Import, Findings, Fix Queue (no logic)
  RekeyApp/          @main entry point
  BrowserStore/      OPT-IN, separate: decrypt-free Chromium/Firefox login delete (not linked by the app)
  RekeyCleanup/      OPT-IN, separate: the `rekey-cleanup` CLI
Tests/               Swift Testing suites + synthetic fixtures (Tests/Fixtures)
App/                 Info.plist, Rekey.entitlements
Scripts/build_app.sh assembles + signs the sandboxed .app
```

Every logic module is free of any SwiftUI import and independently unit-tested.
Networking (HIBP, reset router) is injected behind protocols, so the engines test
with no network and the live clients are wired in only at the app layer.
