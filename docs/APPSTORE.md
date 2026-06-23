# ReKey — App Store Connect operational metadata

This file holds the **operational** App Store Connect settings that don't fit the
listing-copy format: the app record, pricing & in-app purchase, App Privacy
answers, and reviewer notes.

**Listing copy** — App Name, Subtitle, Promotional Text, Description, Keywords,
What's New, and Support/Marketing URLs — lives in
[`app-store-text.md`](app-store-text.md) (the canonical going-forward file). Keep
that one current; this file rarely changes.

Everything here describes the **App Store (pure-auditor) build** — it deliberately
does **not** mention deletion, the Cull tab, or the `rekey-cleanup` CLI, which
aren't part of this app.

---

## App record (permanent, non-localized)
- Bundle ID: `com.seanmandable.rekey`
- SKU: `com.seanmandable.rekey`
- Platform: macOS · Primary language: English
- Category: Primary **Utilities**

## Pricing & in-app purchase
- **App price: Free** (Tier 0). The audit + Findings are fully free.
- **One in-app purchase** unlocks the Fix Queue (generate replacements + open each
  change page). Create it in App Store Connect → your app → In-App Purchases:
  - Type: **Non-Consumable**
  - Reference Name: `Unlock Fixing`
  - Product ID: `com.seanmandable.rekey.unlock`  ← must match `Store.unlockProductID`
  - Price: **$12.99** (select the $12.99 price point; the old numbered "tiers" are deprecated)
  - Display Name: `Unlock Fixing`
  - Description: "Unlock the Fix Queue: generate strong replacements and open each
    site's change-password page. A one-time purchase."
  - Submit the IAP **together with** the app's first version (review them as a pair).
- Enroll in the **App Store Small Business Program** (one-time, App Store Connect) →
  Apple's cut drops 30% → 15%, so $12.99 nets ≈ $11.04.

## Privacy Policy URL
https://github.com/smandable/ReKey/blob/master/docs/PRIVACY.md

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

Free / paid split: importing and the full audit (the Findings list) are FREE. The
Fix Queue (generate replacements + open each change page) is unlocked by a single
non-consumable in-app purchase ("Unlock Fixing"). To test it, use a sandbox Apple
ID: open the Fix Queue tab to see the paywall, purchase the unlock, and the queue
becomes available; "Restore Purchase" is on the paywall and in Settings.

Two network behaviors, both user-initiated and privacy-preserving:
1) Breach check via Have I Been Pwned using k-anonymity — only the first 5
   characters of a SHA-1 hash are sent to api.pwnedpasswords.com; the password
   and full hash never leave the device.
2) When the user chooses to fix one account, ReKey requests that site's own
   /.well-known/change-password page (a web standard), one site at a time.

Note: the public GitHub repository also contains a separate, optional
command-line tool (rekey-cleanup) for power users. It is NOT part of this app,
is not bundled, and is not referenced anywhere in this sandboxed build.
