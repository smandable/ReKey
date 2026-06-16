import SwiftUI
import AppKit
import Model
import PasswordGenerator

/// Step 3: the fix queue. Each item is a preview/approve card. Approving copies
/// the new password and opens the change page — the user makes the actual
/// change on the site. Nothing here edits a credential or writes to any store.
struct FixQueueView: View {
    @Bindable var model: AppModel

    var body: some View {
        Group {
            if model.fixQueue.items.isEmpty {
                ContentUnavailableView(
                    "Fix queue is empty",
                    systemImage: "checkmark.shield",
                    description: Text("Add flagged credentials from the Findings tab to queue them for fixing.")
                )
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        header
                        ForEach(model.fixQueue.items) { item in
                            FixCard(model: model, item: item)
                        }
                    }
                    .padding(20)
                    .frame(maxWidth: 760, alignment: .leading)
                }
                .frame(maxWidth: .infinity)
            }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Fix queue").font(.largeTitle.bold())
            Text("Review each change, then Approve. Rekey copies the new password and opens the site's change page — you make the change there, and your browser offers to save it. Rekey never changes a password for you.")
                .foregroundStyle(.secondary)
        }
    }
}

/// One preview/approve card.
private struct FixCard: View {
    @Bindable var model: AppModel
    let item: FixItem

    @State private var revealOld = false
    @State private var revealNew = true
    @State private var style: Style = .strong
    @State private var length: Double = 20
    @State private var avoidAmbiguous = true
    @State private var showCleanup = false
    @State private var copiedCommand = false

    enum Style: String, CaseIterable, Identifiable {
        case strong = "Strong"
        case lettersDigits = "Letters + digits"
        case passphrase = "Passphrase"
        var id: String { rawValue }
    }

    private var clearSeconds: Int {
        Int(model.fixQueue.clipboardClearAfter.components.seconds)
    }

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                headerRow
                Divider()
                oldPasswordRow
                newPasswordRow
                policyRow
                changeURLRow
                Divider()
                actionRow
                if item.status == .done {
                    staleLoginGuidance
                }
            }
            .padding(8)
        }
    }

    /// Guidance (only) for removing a stale old saved login after a fix is done.
    /// Rekey never deletes it — this is manual steps plus a copy-paste command
    /// for the separate `rekey-cleanup` tool.
    @ViewBuilder
    private var staleLoginGuidance: some View {
        let source = model.credential(item.credentialID)?.source ?? .unknown
        DisclosureGroup(isExpanded: $showCleanup) {
            VStack(alignment: .leading, spacing: 8) {
                Text("If your browser saved a **new** entry instead of updating, an old login for **\(item.registrableDomain)** with the previous password may still be saved. Rekey never deletes it for you — here's how:")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Label(StaleLoginGuidance.manualSteps(for: source, domain: item.registrableDomain),
                      systemImage: "hand.point.right")
                    .font(.caption)

                if let command = StaleLoginGuidance.cliCommand(for: source,
                                                               domain: item.registrableDomain,
                                                               username: item.username) {
                    Text("Or copy this and run it yourself in **Terminal** (Rekey never runs it). As written it just previews; to actually delete, quit \(source.displayName), then re-run it with `--confirm` added:")
                        .font(.caption2).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(alignment: .top) {
                        Text(command)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                            .padding(6)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
                        Button {
                            copyCommand(command)
                        } label: {
                            Image(systemName: copiedCommand ? "checkmark" : "doc.on.doc")
                        }
                        .buttonStyle(.borderless)
                        .help("Copy command")
                    }
                }
            }
            .padding(.top, 6)
        } label: {
            Label("Old login still saved? Optional cleanup", systemImage: "trash.slash")
                .font(.caption.weight(.medium))
        }
    }

    private func copyCommand(_ command: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(command, forType: .string)
        copiedCommand = true
    }

    private var headerRow: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(item.registrableDomain).font(.headline)
                Text(item.username.isEmpty ? "(no username)" : item.username)
                    .font(.subheadline).foregroundStyle(.secondary)
            }
            Spacer()
            statusBadge
        }
    }

    private var oldPasswordRow: some View {
        HStack {
            Text("Current").frame(width: 86, alignment: .leading).foregroundStyle(.secondary)
            Text(revealOld ? (model.credential(item.credentialID)?.password.reveal() ?? "—") : item.oldPasswordMasked)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
            Spacer()
            Button { revealOld.toggle() } label: {
                Image(systemName: revealOld ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .help(revealOld ? "Hide" : "Reveal current password")
        }
    }

    private var newPasswordRow: some View {
        HStack {
            Text("New").frame(width: 86, alignment: .leading).foregroundStyle(.secondary)
            Text(revealNew ? item.newPassword.reveal() : item.newPassword.masked())
                .font(.system(.body, design: .monospaced))
                .foregroundStyle(.primary)
                .textSelection(.enabled)
            Spacer()
            Button { revealNew.toggle() } label: {
                Image(systemName: revealNew ? "eye.slash" : "eye")
            }.buttonStyle(.borderless)
            Button { regenerate() } label: {
                Image(systemName: "arrow.clockwise")
            }.buttonStyle(.borderless).help("Generate another")
        }
    }

    private var policyRow: some View {
        HStack(spacing: 12) {
            Picker("Style", selection: $style) {
                ForEach(Style.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 280)
            .onChange(of: style) { _, _ in regenerate() }

            if style != .passphrase {
                Stepper("Length \(Int(length))", value: $length, in: 12...64, step: 1)
                    .onChange(of: length) { _, _ in regenerate() }
                Toggle("No look-alikes", isOn: $avoidAmbiguous)
                    .onChange(of: avoidAmbiguous) { _, _ in regenerate() }
                    .help("Exclude easily-confused characters: I l 1 O 0")
            }
            Spacer()
        }
        .font(.caption)
        .disabled(item.status != .pending)
    }

    @ViewBuilder
    private var changeURLRow: some View {
        let source = model.fixQueue.resolutionSources[item.id]
        HStack(alignment: .top) {
            Text("Change at").frame(width: 86, alignment: .leading).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 4) {
                if let url = item.changeURL {
                    Text(url.absoluteString)
                        .font(.caption).foregroundStyle(.blue).lineLimit(2)
                        .textSelection(.enabled)
                } else {
                    Text("Will open the site root.").font(.caption).foregroundStyle(.orange)
                }
                if let source {
                    ResetSourceBadge(source: source)
                    Text(ResetSourceBadge.explanation(source))
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
            Spacer()
        }
    }

    private var actionRow: some View {
        HStack {
            if item.status == .pending {
                Label("Approving copies the new password and opens the change page.", systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary)
            } else if item.status == .opened {
                Label("Copied to clipboard (auto-clears in ~\(clearSeconds)s). Change it on the site, then mark done.", systemImage: "doc.on.clipboard")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            switch item.status {
            case .pending:
                Button("Skip", role: .cancel) { model.fixQueue.skip(itemID: item.id) }
                Button {
                    model.fixQueue.approve(itemID: item.id)
                } label: { Label("Approve", systemImage: "checkmark") }
                    .buttonStyle(.borderedProminent)
            case .opened:
                Button("Mark done") { model.fixQueue.markDone(itemID: item.id) }
                    .buttonStyle(.borderedProminent)
            case .done:
                Label("Done", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
            case .skipped:
                Label("Skipped", systemImage: "minus.circle").foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var statusBadge: some View {
        switch item.status {
        case .pending: Text("Pending").foregroundStyle(.secondary)
        case .opened: Text("Opened").foregroundStyle(.blue)
        case .done: Text("Done").foregroundStyle(.green)
        case .skipped: Text("Skipped").foregroundStyle(.secondary)
        }
    }

    private func regenerate() {
        switch style {
        case .passphrase:
            try? model.fixQueue.regeneratePassphrase(itemID: item.id)
        case .strong:
            var p = PasswordPolicy.strong
            p.length = Int(length)
            p.avoidAmbiguous = avoidAmbiguous
            try? model.fixQueue.regenerate(itemID: item.id, policy: p)
        case .lettersDigits:
            var p = PasswordPolicy.strong
            p.length = Int(length)
            p.avoidAmbiguous = avoidAmbiguous
            p.lettersAndDigitsOnly = true
            p.useSymbols = false
            try? model.fixQueue.regenerate(itemID: item.id, policy: p)
        }
    }
}
