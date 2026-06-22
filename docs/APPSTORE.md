# ReKey — App Store Connect metadata (draft)

Copy-paste into App Store Connect. Character limits noted; everything here
describes the **App Store (pure-auditor) build** — it deliberately does **not**
mention deletion or the `rekey-cleanup` CLI, which aren't part of this app.

---

## App record (permanent, non-localized)
- Bundle ID: `com.seanmandable.rekey`
- SKU: `com.seanmandable.rekey`
- Platform: macOS · Primary language: English

## Name (≤30)
ReKey - Website Password Audit
<!-- exactly 30 chars (the limit). The in-app name / CFBundleName stays "ReKey";
     this is only the App Store listing name. Reserve it in App Store Connect to
     confirm availability (the authoritative check). -->

## Subtitle (≤30)
Find reused & breached logins
<!-- complements the name without repeating "password/audit". alternates:
     "Spot weak & reused logins" (25) · "Your password health, checked" (29) -->

## Category
Primary: Utilities

## Promotional text (≤170, editable anytime without review)
ReKey checks the passwords you export from your browsers and Apple Passwords for
reuse and known breaches — then helps you replace the weak ones. All on your Mac.

## Keywords (≤100, comma-separated, no spaces)
password,security,audit,breach,reuse,pwned,login,strength,privacy,duplicate,checkup,health,hibp

## Description (≤4000)
ReKey is a local-first password health auditor for your Mac. It turns the
password CSVs you export from your browsers and Apple Passwords into a clear,
prioritized to-do list — which logins are weak, reused, or caught in a known data
breach — and walks you through fixing them, one site at a time.

Everything happens on your Mac. ReKey has no account, no servers, and no
analytics. Your passwords are held in memory only — never written to disk, never
logged.

WHAT IT DOES
• Import the CSVs you export from Chrome, Arc, Brave, Edge, Firefox, and Apple
  Passwords — ReKey audits them all together.
• Find reused passwords across every browser, weak or short passwords, and
  logins that appear in known breaches.
• Check against Have I Been Pwned using k-anonymity: only the first 5 characters
  of a hash ever leave your Mac — never your actual password.
• Generate strong replacements (random or passphrase), tuned to your defaults.
• Fix queue: ReKey opens each site's own change-password page in your browser,
  and your browser saves the new one. You approve every change.

PRIVACY BY DESIGN
• ReKey never edits your credentials and never writes to any browser, Apple
  Passwords, or the system keychain.
• No analytics, telemetry, advertising, or tracking of any kind.
• The only data that ever leaves your Mac is the k-anonymity breach-check prefix
  and an on-demand lookup of the change-password page for the one site you're
  fixing.
• Sandboxed, and it reads only the files you explicitly choose.

ReKey doesn't store your passwords — it's the checkup, not the vault. Run it
whenever you want a fast, honest read on the health of your logins.

## Support URL
https://github.com/smandable/ReKey

## Marketing URL (optional)
https://github.com/smandable/ReKey

## Privacy Policy URL
https://github.com/smandable/ReKey/blob/master/docs/PRIVACY.md

## What's New (version 1.0)
First release.

---

## App privacy answers (App Store Connect → App Privacy)
- Do you or your third-party partners collect data from this app? **No.**
  (HIBP receives only a non-identifying 5-character hash prefix; change-password
  lookups go to the user's own target site. Neither is collected, stored, linked,
  or used for tracking.)

## Notes for the reviewer (App Review Information → Notes)
ReKey is a read-only password-health auditor. It imports password CSVs the user
exports themselves, finds reused/weak/breached passwords, and opens each site's
own change-password page in the user's browser so the user can update it — ReKey
never writes to any browser store, Apple Passwords, or the keychain.

Two network behaviors, both user-initiated and privacy-preserving:
1) Breach check via Have I Been Pwned using k-anonymity — only the first 5
   characters of a SHA-1 hash are sent to api.pwnedpasswords.com; the password
   and full hash never leave the device.
2) When the user chooses to fix one account, ReKey requests that site's own
   /.well-known/change-password page (a web standard), one site at a time.

Note: the public GitHub repository also contains a separate, optional
command-line tool (rekey-cleanup) for power users. It is NOT part of this app,
is not bundled, and is not referenced anywhere in this sandboxed build.
