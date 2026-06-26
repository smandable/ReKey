# ReKey — App Store Text

<!--
App Store Connect listing copy for the Mac App Store build of ReKey
("ReKey - Website Password Audit"). This is the PURE-AUDITOR build: it must NOT
mention credential deletion, the Cull tab, or the `rekey-cleanup` CLI — none of
those ship in the sandboxed App Store app. Operational metadata that doesn't fit
this listing format (IAP setup, reviewer notes, App Privacy answers) lives in
docs/APPSTORE.md.
-->

## App Name
ReKey - Website Password Audit
<!-- The App Store listing name (exactly 30 chars — plain "ReKey" was taken).
     The in-app name / CFBundleName stays "ReKey". -->

## Subtitle (30 characters max)
Find reused & breached logins
<!-- alternates: "Spot weak & reused logins" (25) · "Your password health, checked" (29) -->


## Promotional Text (170 characters max)
Shown above the description on your App Store page. Can be updated anytime without a new app review.

```
ReKey checks the passwords you export from your browsers and Apple Passwords for reuse and known breaches — then helps you replace the weak ones. All on your Mac.
```

## Description

```
ReKey is a local-first password health auditor for your Mac. It turns the password CSVs you export from your browsers and Apple Passwords into a clear, prioritized to-do list — which logins are weak, reused, or caught in a known data breach — and walks you through fixing them, one site at a time.

Everything happens on your Mac. No account, no servers, no analytics. Your passwords are held in memory only — never written to disk, never logged.

IMPORT EVERYTHING
Export your saved logins from Chrome, Arc, Brave, Edge, Firefox, or Apple Passwords and drop the CSV into ReKey. It audits them all together, so a password reused across two different browsers is caught instead of hidden by the split.

SEE WHAT'S WRONG
ReKey sorts your logins into a prioritized list: passwords reused across sites, weak or short ones, logins exposed in a known breach, the same account saved in both Apple Passwords and a browser, and entries saved with no username. The fixes that matter most rise to the top.

CHECKED AGAINST KNOWN BREACHES
ReKey checks every password against Have I Been Pwned using k-anonymity: only the first five characters of a hash ever leave your Mac — never your actual password, and never the full hash.

GUIDED FIXES
For each weak or breached login, ReKey generates a strong replacement — random or a memorable passphrase, tuned to your defaults — and opens that site's own change-password page in your browser. You set the new password; your browser saves it. ReKey never changes a password itself, and you approve every step.

PRIVACY FIRST
ReKey is the checkup, not the vault. It never edits your credentials and never writes to any browser, Apple Passwords, or the system keychain. No analytics, telemetry, advertising, or tracking of any kind. It's sandboxed and reads only the files you explicitly choose. The only things that ever leave your Mac are the k-anonymity breach-check prefix and an on-demand lookup of the change page for the one site you're fixing.

FREE TO AUDIT
The full import and audit — every finding — is free. Unlocking the guided fix tools (strong-password generation and opening each site's change page) is a single one-time purchase. No subscription.

ReKey runs on any Mac with macOS 15 (Sequoia) or later. Run it whenever you want a fast, honest read on the health of your logins.
```

## Keywords (100 characters max, comma-separated)

Note: the app name ("ReKey - Website Password Audit") and subtitle ("Find
reused & breached logins") are already search-indexed, so their words (rekey,
website, password, audit, reused, breached, logins) are deliberately NOT
repeated here. Apple auto-combines single keywords, so no multi-word phrases /
spaces.

```
security,pwned,strength,privacy,duplicate,checkup,health,hibp,weak,leak,exposed,compromised,scanner
```

## What's New (Version 1.1.2)
```
- The one-time unlock for the guided fix tools is now available.
- Reliability and polish improvements.
```

### Previous versions

```
Version 1.1.1 — A clearer unlock paywall: progress while the price loads and a Try Again option if it doesn't, instead of an inactive button.
Version 1.0 — Initial release.
```

## Support URL
https://github.com/smandable/ReKey

## Marketing URL (optional)
https://github.com/smandable/ReKey

## Copyright
© 2026 Sean Mandable
