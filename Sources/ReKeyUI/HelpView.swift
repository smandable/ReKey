import SwiftUI

/// In-app help, a first-class sidebar section. Its first topic — why a
/// compromised-password warning can linger after you delete the saved login —
/// is deep-linked from the Cull script panel ("Why a warning can linger →") in
/// the direct build. The copy here is deliberately tool-agnostic (it never names
/// `rekey-cleanup` or the Cull tab) so it reads correctly in the App Store
/// build too, which is a pure auditor; `docs/HELP.md` carries the fuller,
/// tool-naming version for people reading the full product on GitHub.
struct HelpView: View {
    @Bindable var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("Help").font(.largeTitle.bold())

                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Chrome's and Firefox's “compromised passwords” warnings flag passwords **currently saved in that browser**, matched against known breaches. Delete the saved login and there's nothing left to flag — so its warning drops off. But *“the warning disappeared”* and *“the risk is gone”* aren't the same thing, and a few things can quietly bring entries — and their warnings — back.")
                            .fixedSize(horizontal: false, vertical: true)

                        Divider()

                        Text("**1. Chrome sync decides whether a deletion sticks.** With sync on, your saved passwords live in your Google Account ([passwords.google.com](https://passwords.google.com)) and sync down to every signed-in device. Deleting there is authoritative — it propagates **down** to all your devices and doesn't come back up, because nothing sits above the account store to restore it. Deleting from a browser's **local** store instead (rather than the account) can be undone: with sync on, the account store can re-push those entries on the next launch. So if you use Chrome sync, delete from **Google Password Manager** (passwords.google.com), or verify a local deletion actually sticks. With sync **off**, the local store is the source of truth and a local deletion is the real thing.")
                            .fixedSize(horizontal: false, vertical: true)

                        Text("**2. Each store only warns about itself.** Chrome warns about Chrome's store, Firefox about Firefox's — they don't share. And **Apple Passwords / iCloud Keychain** has its own breach warnings that no third-party tool can delete (there's no third-party delete API). If the same login also lives there, that warning stays until you remove it by hand in System Settings → Passwords.")
                            .fixedSize(horizontal: false, vertical: true)

                        Text("**3. The warning going away isn't the risk going away.** Deleting a saved entry only stops the manager from nagging. It doesn't change the password on the live site, and the breach itself is permanent. For an account you're **done with**, deleting it from the browser (or Google Password Manager) is the right call. For one you **still use**, deleting just hides the warning and leaves you exposed if you reuse that password — change it instead, which is what the **Fix Queue** is for.")
                            .fixedSize(horizontal: false, vertical: true)

                        Text("**4. Logging in again re-creates the entry.** Sign in to a site and the browser offers to save the password again → it reappears (and syncs back up). That's new data, not a restore — the most common reason a “deleted” password comes back.")
                            .fixedSize(horizontal: false, vertical: true)

                        Text("**5. The count can take a moment.** Chrome re-runs Password Checkup periodically or on demand, so the number may not drop right away. Re-run the check to confirm.")
                            .fixedSize(horizontal: false, vertical: true)

                        Divider()

                        Text("**One caution:** deleting *everything* from your password manager wipes the good logins too — the ones you still use and want autofilled. Remove the dead or compromised subset, not the whole vault.")
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .font(.callout)
                    .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                } label: {
                    Label("Deleting compromised passwords — why the warnings sometimes linger",
                          systemImage: "checkmark.shield")
                }

                // Act on the advice above without hunting through the sidebar.
                HStack(spacing: 10) {
                    // The Cull tab is direct-build only (App Store build has no
                    // outright-delete flow), so only offer the jump there.
                    #if !MAS_BUILD
                    Button { model.section = .cull } label: {
                        Label("Cull dead logins", systemImage: "trash")
                    }
                    #endif
                    Button { model.section = .fixing } label: {
                        Label("Re-key in Fix Queue", systemImage: "checkmark.shield")
                    }
                }
            }
            .padding(20)
            .frame(maxWidth: 720, alignment: .leading)
        }
        .frame(maxWidth: .infinity)
    }
}
