import SwiftUI

/// Shown in place of the Fix Queue (App Store build) until the one-time unlock is
/// purchased. The audit and findings are free; this gates only the fixing tools.
/// Never shown in the direct build, where `store.isUnlocked` is always true.
struct PaywallView: View {
    @Bindable var store: Store
    var waitingCount: Int = 0

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                Image(systemName: "checkmark.shield.fill")
                    .font(.system(size: 46)).foregroundStyle(.tint)
                Text("Unlock fixing").font(.largeTitle.bold())

                if waitingCount > 0 {
                    Text("You have **\(waitingCount)** login\(waitingCount == 1 ? "" : "s") flagged — unlock to fix them.")
                        .multilineTextAlignment(.center).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Text("Your audit is free. Unlock the fix tools whenever you're ready.")
                        .foregroundStyle(.secondary)
                }

                VStack(alignment: .leading, spacing: 10) {
                    benefit("wand.and.stars", "Generate strong, unique replacements")
                    benefit("arrow.up.right.square", "Open each site's change-password page")
                    benefit("checkmark.circle", "Track what's fixed across re-imports")
                }
                .frame(maxWidth: 380, alignment: .leading)
                .padding(.vertical, 6)

                // The price only exists once the product loads. Rather than show a
                // permanently-greyed Unlock button when it doesn't, show progress
                // while fetching and an explicit Try Again when it failed or came
                // back empty (e.g. the store wasn't reachable, or the IAP isn't
                // available in this storefront yet).
                if let price = store.displayPrice {
                    Button {
                        Task { await store.purchase() }
                    } label: {
                        Text("Unlock — \(price)").frame(maxWidth: 300)
                    }
                    .controlSize(.large).buttonStyle(.borderedProminent)
                    .disabled(store.working)
                } else if store.loadingProduct {
                    ProgressView("Contacting the App Store…")
                        .controlSize(.small).frame(maxWidth: 300)
                } else {
                    Button("Try Again") { Task { await store.loadProduct() } }
                        .controlSize(.large).buttonStyle(.borderedProminent)
                        .frame(maxWidth: 300)
                }

                Button("Restore Purchase") { Task { await store.restore() } }
                    .buttonStyle(.link).disabled(store.working)

                if store.working { ProgressView().controlSize(.small) }
                if let error = store.lastError {
                    Text(error).font(.caption).foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Text("A one-time purchase — not a subscription. ReKey never sells anything else and never sees your passwords.")
                    .font(.caption2).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 4)
            }
            .padding(40)
            .frame(maxWidth: 520)
            .frame(maxWidth: .infinity)
        }
        .frame(maxWidth: .infinity)
        .task {
            // Re-attempt the load when the paywall appears if the price isn't in
            // yet — covers the launch fetch coming back empty before the store was
            // ready. No-op if a load is already in flight or the price is loaded.
            if store.displayPrice == nil { await store.loadProduct() }
        }
    }

    private func benefit(_ icon: String, _ text: String) -> some View {
        Label(text, systemImage: icon).font(.callout)
    }
}
