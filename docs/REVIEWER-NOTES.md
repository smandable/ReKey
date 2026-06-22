# Reviewer test packet

Paste the block below into **App Store Connect → your version → App Review
Information → Notes** (or into the Resolution Center if the reviewer asks how to
test). It fits the 4000-character limit. The sample passwords are deliberately
weak/breached fakes — they genuinely appear in Have I Been Pwned, so the
"compromised" flags light up for real, while the accounts are fictional.

---

```
HOW TO TEST ReKey

ReKey audits password CSVs that the user exports from their browser or Apple
Passwords — it never reads any browser, Apple Passwords, or the keychain
directly. To test without your own data, use the sample CSV at the bottom.

1. Copy the SAMPLE CSV below and save it as a plain-text file named sample.csv.
2. In ReKey, on the Import tab, click "Import CSV…" and choose sample.csv.
3. Open the Findings tab. You'll see reused, weak, and breached passwords
   flagged. The "breached" flags are real: those sample passwords appear in the
   Have I Been Pwned database, checked via k-anonymity — only the first 5
   characters of a SHA-1 hash ever leave the device, never the password.

The import and the full audit (Findings) are FREE.

4. To test the in-app purchase ("Unlock Fixing", non-consumable): open the
   Fix Queue tab. The paywall appears there even with no data imported. Tap
   "Unlock — $12.99" to buy in the sandbox, or "Restore Purchase" (also in
   Settings). After unlocking, the Fix Queue shows each flagged login with a
   generated strong replacement and a button that opens that site's own
   change-password page in the default browser, where the user makes the change.
   ReKey never changes or stores a password itself.

Network use is limited to: (a) the k-anonymity prefix to api.pwnedpasswords.com,
and (b) on-demand lookup of one site's change-password page when the user fixes
it. No accounts, no analytics, no tracking.

SAMPLE CSV (save as sample.csv):
name,url,username,password,note
StreamFlix,https://streamflix.com/login,demo.user@example.com,Summer2019!,
BookNest,https://booknest.com/account,demo.user@example.com,Summer2019!,
Pinspire,https://pinspire.com/signin,demo.user@example.com,Summer2019!,
GameHub,https://gamehub.com/login,demo.user@example.com,Summer2019!,
CloudStash,https://cloudstash.com/login,demo.user@example.com,password123,
WorkLink,https://worklink.com/auth,demo.user@example.com,qwerty123,
PhotoEdit,https://photoedit.com/login,demo.user@example.com,letmein1,
ShopMart,https://shopmart.com/account,demo.user@example.com,iloveyou,
OldForum,https://oldforum.com/ucp.php,demouser,123456,
DealsWeekly,https://dealsweekly.com/signup,demouser,abc123,
SecureBank,https://securebank-demo.com/login,demo.user@example.com,7Gx!q2&vLp9@Rm,
PrivMail,https://privmail-demo.com/login,demo.user@example.com,kT4#nW8$zB1!cF6,
```
