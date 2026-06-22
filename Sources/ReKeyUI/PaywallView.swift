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

                Button {
                    Task { await store.purchase() }
                } label: {
                    Text(store.displayPrice.map { "Unlock — \($0)" } ?? "Unlock")
                        .frame(maxWidth: 300)
                }
                .controlSize(.large).buttonStyle(.borderedProminent)
                .disabled(store.displayPrice == nil || store.working)

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
    }

    private func benefit(_ icon: String, _ text: String) -> some View {
        Label(text, systemImage: icon).font(.callout)
    }
}
