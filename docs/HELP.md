# ReKey — Help & FAQ

The same guidance lives in the app under the **Help** section (sidebar). This
file mirrors it for reading on GitHub.

## Deleting compromised passwords — why the warnings sometimes linger

Chrome's and Firefox's "compromised passwords" warnings flag passwords
**currently saved in that browser**, matched against known breaches. Delete the
saved login and there's nothing left to flag — so its warning drops off. But
*"the warning disappeared"* and *"the risk is gone"* aren't the same thing, and a
few things can quietly bring entries — and their warnings — back.

### 1. Chrome sync decides whether a deletion sticks

With sync **on**, your saved passwords live in your Google Account
([passwords.google.com](https://passwords.google.com)) and sync down to every
signed-in device. Deleting there is authoritative — it propagates **down** to all
your devices and doesn't come back up, because nothing sits above the account
store to restore it.

ReKey's `rekey-cleanup` instead edits Chrome's **local** store. With sync on, the
account store can re-push those entries on the next launch and undo the deletion.
So if you use Chrome sync, delete from **Google Password Manager**
(passwords.google.com), or verify on a few that a local deletion sticks. With
sync **off**, the local store is the source of truth and `rekey-cleanup`'s
deletion is the real thing.

### 2. Each store only warns about itself

Chrome warns about Chrome's store, Firefox about Firefox's — they don't share.
And **Apple Passwords / iCloud Keychain** has its own breach warnings that
`rekey-cleanup` can't touch (there's no third-party delete API). If the same
login also lives there, that warning stays until you remove it by hand in
**System Settings → Passwords**.

### 3. The warning going away isn't the risk going away

Deleting a saved entry only stops the manager from nagging. It doesn't change the
password on the live site, and the breach itself is permanent.

- An account you're **done with** → deleting is the right call. That's **Cull**.
- An account you **still use** → deleting just hides the warning and leaves you
  exposed if you reuse that password. **Change it instead**, in the **Fix Queue**.

### 4. Logging in again re-creates the entry

Sign in to a site and the browser offers to save the password again → it
reappears (and syncs back up). That's *new* data, not a restore — the most common
reason a "deleted" password comes back.

### 5. The count can take a moment

Chrome re-runs Password Checkup periodically or on demand, so the number may not
drop right away. Re-run the check to confirm.

---

**One caution:** deleting *everything* from your password manager wipes the good
logins too — the ones you still use and want autofilled. Remove the dead or
compromised subset, not the whole vault.
