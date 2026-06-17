# ReKey test fixtures

All credentials here are synthetic. The values are fake and exist only to exercise the importer, the reuse and compromise logic, and the HIBP client against mocked responses. Nothing here is a real secret.

Drop the four CSVs into `Tests/Fixtures/` in the repo. Saved as UTF-8, no BOM, LF line endings.

## Files and expected format detection

| File | Expected `BrowserSource` | Header |
|---|---|---|
| `chrome.csv` | `chrome` | lowercase `name,url,username,password,note` |
| `arc.csv` | `arc` (or `chrome`) | identical Chromium layout |
| `firefox.csv` | `firefox` | lowercase nine-column |
| `apple_passwords.csv` | `applePasswords` | capitalized `Title,URL,Username,Password,Notes,OTPAuth` |

Arc and Chrome are identical in format. The detector should classify both as Chromium. `arc.csv` exists to exercise the "tag this file as Arc on import" path, since the CSV alone cannot distinguish the two.

## Rows that should be SKIPPED (empty password) and counted

- `chrome.csv`: `news.example.net` (federated "Signed in with Google", blank password)
- `apple_passwords.csv`: `passkey.example.com` (passkey-only, blank password)

Two skipped rows total. Everything else is a valid credential.

## TOTP handling

- `apple_passwords.csv` `bank.example.com` carries an `OTPAuth` value. The importer should set `hasTOTP = true` and must NOT store or surface the seed (`JBSWY3DPEHPK3PXP`).

## Expected findings after a full merged import

Passwords are matched across all four files (the auditor merges every source), so several findings span browsers.

**Reused across sites**
- `Tr0ub4dour&3`: `github.com` (chrome, two usernames) and `bank.example.com` (apple). Reused across two registrable domains, and also a within-site duplicate on `github.com`.
- `hunter2`: `example.com` (chrome) and `example.org` (firefox). Cross-browser reuse.
- `password`: `reddit.com` (chrome), `forum.example.com` (firefox), `watch.example.tv` (apple), `figma.com` (arc). Reused across four registrable domains AND compromised. Spans all four sources.

**Duplicated within a site**
- `github.com`: `Tr0ub4dour&3` under two usernames (`sean`, `sean-work`).

**Compromised** (per the HIBP mock below)
- Every `password` entry: `reddit.com`, `forum.example.com`, `watch.example.tv`, `figma.com`.

**Not flagged** (unique, clean)
- `gitlab.com` `J7#mK9$pL2@xQ` (arc)
- `shop.example.org` `Pä$$wörd🔑` (firefox, unicode, multi-byte UTF-8)
- `notes.example.io` `s3cr3t-Vault-Key` (apple)

Note `example.com` shows up under one registrable domain with two different passwords on different subdomains (`example.com` root with `hunter2`, `forum.example.com` with `password`). The domain grouping should cluster both under `example.com` for display while keeping the two passwords distinct for reuse analysis. No within-site duplicate there, since the passwords differ.

## HIBP mock

Do not hit the live API in tests. Mock `URLProtocol` so the range endpoint returns a hit only for `password`:

- `SHA-1("password")` = `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`
- Request path prefix: `5BAA6`
- For a request to `/range/5BAA6`, return one body line: `1E4C9B93F3F0682250B6CF8331B7EE68FD8:99999`
- For every other prefix, return an empty body (or padded zero-count lines if you are exercising `Add-Padding` handling).

That yields `breachCount = 99999` for the `password` entries and "not found" for everything else.

## CRLF and BOM cases (synthesize in-test, do not commit)

These fixtures are LF with no BOM on purpose, so git autocrlf settings and editors do not silently rewrite the bytes and break the very thing you are testing. Produce the BOM and CRLF cases inside the test from a clean base string, which also keeps the assertion next to the transform:

```swift
// UTF-8 BOM prepended, LF -> CRLF: proves the parser strips the BOM
// before header detection and treats CRLF as a record separator.
let base = try String(contentsOf: appleFixtureURL, encoding: .utf8)
let crlf = base.replacingOccurrences(of: "\n", with: "\r\n")
let withBOM = "\u{FEFF}" + crlf
let data = Data(withBOM.utf8)
// feed `data` to the parser; expect detection == .applePasswords and the
// same parsed rows as the clean fixture.
```

The embedded-newline-inside-quotes case IS committed: `apple_passwords.csv`, the `Vault Notes` row has a real newline inside the quoted `Notes` field. That one survives git intact, and it verifies the parser uses quote state rather than splitting on every newline.
