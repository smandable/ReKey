# Rekey

A **local-first password health auditor** for macOS. Rekey imports CSVs you
export from Chrome, Arc, Firefox, and Apple Passwords, finds **reused** and
**compromised** passwords, groups them alphabetically by site, generates strong
replacements, and routes you to each site's change-password page. **Every change
is approved by you, and Rekey never changes a password itself.**

Bundle ID: `com.seanmandable.rekey` · macOS 15+ · Swift 6 · arm64.

---

## What Rekey guarantees

These are hard constraints, enforced by the architecture:

- **It never edits your credentials and never writes to any browser, Apple
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
- **App Sandbox is on.** Entitlements: outgoing network client, and read-write to
  user-selected files (so the source CSV can be securely deleted). Nothing else.

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
Tests/               Swift Testing suites + synthetic fixtures (Tests/Fixtures)
App/                 Info.plist, Rekey.entitlements
Scripts/build_app.sh assembles + signs the sandboxed .app
```

Every logic module is free of any SwiftUI import and independently unit-tested.
Networking (HIBP, reset router) is injected behind protocols, so the engines test
with no network and the live clients are wired in only at the app layer.
