import SwiftUI
import AppKit
import Model
import PasswordGenerator

/// Step 3: the fix queue. Each item is a preview card whose "Copy & open" action
/// copies the new password and opens the change page — the user makes the actual
/// change on the site. Nothing here edits a credential or writes to any store.
struct FixQueueView: View {
    @Bindable var model: AppModel
    @State private var cleanupConfirm = true
    @State private var cleanupCopied = false
    @State private var copiedLine: String?
    @State private var showRunHelp = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                header
                if model.fixQueue.items.isEmpty {
                    ContentUnavailableView(
                        "Fix queue is empty",
                        systemImage: "checkmark.shield",
                        description: Text("Add flagged credentials from the Findings tab to queue them for fixing.")
                    )
                    .frame(maxWidth: .infinity)
                    .padding(.top, 40)
                } else {
                    ForEach(model.fixQueue.items) { item in
                        FixCard(model: model, item: item)
                    }
                    cleanupSection
                }
            }
            .padding(20)
            .frame(maxWidth: 760, alignment: .leading)
        }
        .frame(maxWidth: .infinity)
    }

    /// One script that removes the stale old saved logins for every account the
    /// user has marked done — across all browsers — with Copy / Save / Append so a
    /// multi-session cleanup can accumulate into a single file.
    @ViewBuilder
    private var cleanupSection: some View {
        let runnable = model.fixedCleanupRunnableCommands()
        let manualCount = model.fixedCleanupManualSiteCount()
        if !runnable.isEmpty || manualCount > 0 {
            let script = model.fixedCleanupScript(confirm: cleanupConfirm)
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Cleanup script — remove the old logins you've replaced", systemImage: "trash.slash")
                        .font(.headline)
                    Text("One script to delete the stale saved logins for the accounts you've marked done, across every browser. Quit those browsers first — rekey-cleanup backs up each store before deleting and won't run while a browser is open.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if manualCount > 0 {
                        Label("\(manualCount) site(s) need manual removal — the entry you fixed has no username and the site has other logins, so a site delete would take them too. The script shows how to remove just the stray one by id (it isn't auto-deleted).", systemImage: "exclamationmark.triangle.fill")
                            .font(.caption).foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Toggle("Include `--confirm` — actually delete (otherwise it only previews)", isOn: cleanupConfirmBinding)
                        .font(.caption)
                    scriptBlock(script)
                    HStack {
                        Button { copyCleanup(script) } label: {
                            Label(cleanupCopied ? "Copied" : "Copy all", systemImage: cleanupCopied ? "checkmark" : "doc.on.doc")
                                .foregroundStyle(cleanupCopied ? AnyShapeStyle(.green) : AnyShapeStyle(.primary))
                        }
                        Button { saveCleanup(script) } label: {
                            Label("Save as new file…", systemImage: "square.and.arrow.down")
                        }
                        .help("Write the whole current script to a new .sh file you name — everything you've fixed this session.")
                        Button { appendCleanup(runnable) } label: {
                            Label("Add to existing file…", systemImage: "doc.badge.plus")
                        }
                        .help("Add these commands to a cleanup script you saved before (skipping any already in it), so fixes from several sessions accumulate in one file.")
                        Spacer()
                    }
                    runHelp
                }
                .padding(6)
            }
        }
    }

    /// The script, one line per row, with a copy button beside each runnable
    /// `rekey-cleanup` command (comments/blank lines have none).
    private func scriptBlock(_ script: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            ForEach(Array(script.split(separator: "\n", omittingEmptySubsequences: false).enumerated()), id: \.offset) { _, raw in
                let line = String(raw)
                HStack(alignment: .top, spacing: 6) {
                    Text(line.isEmpty ? " " : line)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    if line.hasPrefix("rekey-cleanup") {
                        Button { copyScriptLine(line) } label: {
                            Image(systemName: copiedLine == line ? "checkmark" : "doc.on.doc")
                                .foregroundStyle(copiedLine == line ? AnyShapeStyle(.green) : AnyShapeStyle(.secondary))
                        }
                        .buttonStyle(.borderless).controlSize(.small)
                        .help("Copy this command")
                    }
                }
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
    }

    /// Collapsible instructions for actually running the script (the app can't —
    /// rekey-cleanup is a separate, sandbox-free tool you run in Terminal).
    private var runHelp: some View {
        DisclosureGroup(isExpanded: $showRunHelp) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Rekey can't run this itself — deleting browser stores is exactly what the sandboxed app must not do, so `rekey-cleanup` is a separate tool you run in Terminal.")
                    .fixedSize(horizontal: false, vertical: true)
                Text("1. Install the tool once, from the Rekey project folder:")
                codeLine("swift build -c release --product rekey-cleanup")
                codeLine("sudo cp .build/release/rekey-cleanup /usr/local/bin/")
                Text("2. Quit the browser(s) the script touches.")
                Text("3. Run a saved script, or paste a single copied line:")
                codeLine("sh ~/Downloads/rekey-cleanup.sh")
                Text("Not installing? Run a line from the Rekey folder with `swift run` instead, e.g. `swift run rekey-cleanup delete --browser arc --site bjs.com --confirm`.")
                    .fixedSize(horizontal: false, vertical: true)
            }
            .font(.caption).foregroundStyle(.secondary)
            .padding(.top, 4)
        } label: {
            Label("How to run this", systemImage: "terminal").font(.caption.weight(.medium))
        }
    }

    private func codeLine(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text(text)
                .font(.system(.caption2, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button { copyScriptLine(text) } label: {
                Image(systemName: copiedLine == text ? "checkmark" : "doc.on.doc")
                    .foregroundStyle(copiedLine == text ? AnyShapeStyle(.green) : AnyShapeStyle(.secondary))
            }
            .buttonStyle(.borderless).controlSize(.small)
            .help("Copy")
        }
        .padding(6)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
    }

    private func copyScriptLine(_ line: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(line, forType: .string)
        copiedLine = line
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(1.5))
            if copiedLine == line { copiedLine = nil }
        }
    }

    private var cleanupConfirmBinding: Binding<Bool> {
        Binding(get: { cleanupConfirm }, set: { cleanupConfirm = $0; cleanupCopied = false })
    }

    private func copyCleanup(_ script: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(script, forType: .string)
        cleanupCopied = true
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(1.5))
            cleanupCopied = false
        }
    }

    private func saveCleanup(_ script: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "rekey-cleanup.sh"
        panel.canCreateDirectories = true
        panel.message = "Save the cleanup script. Review it, then run it in Terminal."
        if panel.runModal() == .OK, let url = panel.url {
            try? script.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    /// Append the commands to an existing script the user picks, skipping any line
    /// already present — so re-appending after more fixes doesn't duplicate.
    private func appendCleanup(_ commands: [String]) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "Choose a cleanup script to append these commands to (duplicates are skipped)."
        guard panel.runModal() == .OK, let url = panel.url else { return }

        let existing = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        let existingLines = Set(
            existing.split(separator: "\n", omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: .whitespaces) }
        )
        let toAdd = commands
            .map { cleanupConfirm ? $0 + " --confirm" : $0 }
            .filter { !existingLines.contains($0) }
        guard !toAdd.isEmpty else { return }

        var out = existing
        if !out.isEmpty && !out.hasSuffix("\n") { out += "\n" }
        out += toAdd.joined(separator: "\n") + "\n"
        try? out.write(to: url, atomically: true, encoding: .utf8)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Fix queue").font(.largeTitle.bold())
            Text("Review each change, then Copy & open: Rekey copies the new password and opens the site's change page — you make the change there, and your browser offers to save it. Rekey never changes a password for you.")
                .foregroundStyle(.secondary)
            HStack(spacing: 8) {
                Image(systemName: "safari")
                Text("Open change pages in:")
                Picker("Open change pages in", selection: browserSelection) {
                    ForEach(model.availableBrowsers) { Text($0.name).tag($0.id) }
                }
                .labelsHidden()
                .frame(maxWidth: 220)
                .help("Choose which browser Rekey opens change-password pages in. 'Default browser' follows your macOS setting.")
            }
            .font(.callout)
            .padding(.top, 2)

            Label("On iPhone or iPad? After changing a password, make sure the new value lands in the store your phone autofills from — iCloud Keychain (Apple) and Chrome/Google don't sync to each other.", systemImage: "iphone")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 2)
        }
    }

    private var browserSelection: Binding<String> {
        Binding(get: { model.selectedBrowserID }, set: { model.selectBrowser(id: $0) })
    }
}

/// One preview/approve card.
private struct FixCard: View {
    @Bindable var model: AppModel
    let item: FixItem

    @State private var revealOld: Bool
    @State private var revealNew: Bool
    @State private var style: Style
    @State private var length: Double
    @State private var avoidAmbiguous: Bool
    @State private var showCleanup = false
    @State private var copiedCommand = false
    /// Which password field was just copied, for a transient checkmark.
    @State private var copiedField: CopiedField?

    /// Seed the per-card controls from the saved Settings defaults.
    init(model: AppModel, item: FixItem) {
        self.model = model
        self.item = item
        let show = Prefs.showPasswordsValue()
        _revealOld = State(initialValue: show)
        _revealNew = State(initialValue: show)
        let g = Prefs.currentGeneration()
        _style = State(initialValue: Style(rawValue: g.style) ?? .strong)
        _length = State(initialValue: Double(g.length))
        _avoidAmbiguous = State(initialValue: g.avoidLookAlikes)
    }

    enum Style: String, CaseIterable, Identifiable {
        case strong = "Strong"
        case lettersDigits = "Letters + digits"
        case passphrase = "Passphrase"
        var id: String { rawValue }
    }

    enum CopiedField: Equatable { case username, current, new }

    /// The live current-password secret (nil if the credential is no longer
    /// loaded). Copying it copies the real value even while it's masked on screen.
    private var currentPassword: Secret? {
        model.credential(item.credentialID)?.password
    }

    /// This account is also saved in the other ecosystem (Apple ↔ browser).
    private var isCrossEcosystem: Bool {
        model.isCrossEcosystem(item.credentialID)
    }

    /// Reminder that the matching copy in the other (non-syncing) store also needs
    /// updating — the thing that bites on iPhone/iPad.
    @ViewBuilder
    private var crossEcosystemNote: some View {
        let other = (model.credential(item.credentialID)?.source.isApple ?? false) ? "a browser" : "Apple Passwords"
        Label("This account is also saved in \(other) — the stores don't sync, so after you change it here, update the copy in \(other) too, or your iPhone may keep autofilling the old password.", systemImage: "iphone")
            .font(.caption).foregroundStyle(.orange)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
            .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }

    private var clearSeconds: Int {
        Int(model.fixQueue.clipboardClearAfter.components.seconds)
    }

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                headerRow
                Divider()
                usernameRow
                oldPasswordRow
                newPasswordRow
                policyRow
                changeURLRow
                Divider()
                actionRow
                if isCrossEcosystem {
                    crossEcosystemNote
                }
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
                                .foregroundStyle(copiedCommand ? AnyShapeStyle(.green) : AnyShapeStyle(.secondary))
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
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(1.5))
            copiedCommand = false
        }
    }

    private var headerRow: some View {
        HStack {
            Text(item.registrableDomain).font(.headline)
            Spacer()
            statusBadge
        }
    }

    private var usernameRow: some View {
        HStack(spacing: 4) {
            Text("Username").frame(width: 86, alignment: .leading).foregroundStyle(.secondary)
            Text(item.username.isEmpty ? "(no username)" : item.username)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
            Spacer()
            copyButton(copied: copiedField == .username, help: "Copy username") {
                copyText(item.username)
                flashCopied(.username)
            }
            .disabled(item.username.isEmpty)
        }
    }

    /// Copy non-secret text (the username) to the clipboard. Unlike a password,
    /// it isn't scheduled for auto-clear.
    private func copyText(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    /// Uniform width for each trailing icon button so the show/hide and copy
    /// columns line up across both rows (and don't shift when eye↔eye.slash).
    private static let iconWidth: CGFloat = 22

    private var oldPasswordRow: some View {
        HStack(spacing: 4) {
            Text("Current").frame(width: 86, alignment: .leading).foregroundStyle(.secondary)
            Text(revealOld ? (currentPassword?.reveal() ?? "—") : item.oldPasswordMasked)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
            Spacer()
            iconButton(systemName: revealOld ? "eye.slash" : "eye",
                       help: revealOld ? "Hide" : "Reveal current password") {
                revealOld.toggle()
            }
            copyButton(copied: copiedField == .current,
                       help: "Copy current password to paste into the site (clipboard auto-clears in ~\(clearSeconds)s)") {
                if let pw = currentPassword {
                    model.fixQueue.copySecret(pw)
                    flashCopied(.current)
                }
            }
            .disabled(currentPassword == nil)
        }
    }

    private var newPasswordRow: some View {
        HStack(spacing: 4) {
            Text("New").frame(width: 86, alignment: .leading).foregroundStyle(.secondary)
            if revealNew {
                // Editable: the user can tweak the generated value (e.g. remove a
                // character a site won't accept) without regenerating.
                TextField("New password", text: newPasswordBinding)
                    .textFieldStyle(.plain)
                    .font(.system(.body, design: .monospaced))
                    .disabled(!isEditable)
            } else {
                Text(item.newPassword.masked())
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(.primary)
            }
            Spacer()
            iconButton(systemName: "arrow.clockwise", help: "Generate another") {
                regenerate()
            }
            .disabled(!isEditable)
            iconButton(systemName: revealNew ? "eye.slash" : "eye",
                       help: revealNew ? "Hide" : "Reveal/edit new password") {
                revealNew.toggle()
            }
            copyButton(copied: copiedField == .new,
                       help: "Copy new password to paste into the site (clipboard auto-clears in ~\(clearSeconds)s)") {
                model.fixQueue.copySecret(item.newPassword)
                flashCopied(.new)
            }
        }
    }

    /// Two-way binding to the item's new password for the editable field.
    private var newPasswordBinding: Binding<String> {
        Binding(
            get: { item.newPassword.reveal() },
            set: { model.fixQueue.setNewPassword(itemID: item.id, to: $0) }
        )
    }

    /// Policy/edit controls are live while the fix is still in play (pending or
    /// opened) — so the user can tweak after approving too, e.g. if the site
    /// rejected the password — and lock once it's done or skipped.
    private var isEditable: Bool {
        item.status == .pending || item.status == .opened
    }

    /// A fixed-width borderless icon button, so trailing controls form aligned
    /// columns across the Current/New rows.
    private func iconButton(systemName: String, help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: systemName).frame(width: Self.iconWidth)
        }
        .buttonStyle(.borderless)
        .help(help)
    }

    /// A clipboard icon button that flips to a green checkmark right after a copy.
    private func copyButton(copied: Bool, help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: copied ? "checkmark" : "doc.on.doc")
                .foregroundStyle(copied ? AnyShapeStyle(.green) : AnyShapeStyle(.secondary))
                .frame(width: Self.iconWidth)
        }
        .buttonStyle(.borderless)
        .help(help)
    }

    private func flashCopied(_ field: CopiedField) {
        copiedField = field
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(1.5))
            if copiedField == field { copiedField = nil }
        }
    }

    private var policyRow: some View {
        HStack(spacing: 12) {
            styleSelector

            if style != .passphrase {
                Stepper("Length \(Int(length))", value: $length, in: 12...64, step: 1)
                    .onChange(of: length) { _, _ in regenerate() }
                Toggle("No look-alikes", isOn: $avoidAmbiguous)
                    .onChange(of: avoidAmbiguous) { _, _ in regenerate() }
                HelpHint("\"No look-alikes\" excludes the characters that are easy to confuse when reading or typing a password by hand — capital I, lowercase l, the digit 1, capital O, and zero 0.")
            }
            Spacer()
        }
        .font(.caption)
        .disabled(!isEditable)
    }

    /// Segmented-style picker built from plain Buttons. A native segmented
    /// `Picker` was unreliable here (same control-selection quirk as the sidebar
    /// `List`), so each style is an explicit button that sets the style and
    /// regenerates.
    private var styleSelector: some View {
        HStack(spacing: 0) {
            ForEach(Style.allCases) { option in
                Button {
                    style = option
                    regenerate()
                } label: {
                    Text(option.rawValue)
                        .font(.caption)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 4)
                        .padding(.horizontal, 8)
                        .foregroundStyle(style == option ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
                        .background(style == option ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.clear))
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .frame(width: 300)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.quaternary))
    }

    @ViewBuilder
    private var changeURLRow: some View {
        let source = model.fixQueue.resolutionSources[item.id]
        HStack(alignment: .top) {
            Text("Change at").frame(width: 86, alignment: .leading).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 4) {
                if let url = item.changeURL {
                    // Clickable so the page can be re-opened any time (e.g. after
                    // closing the tab), in the user's chosen browser.
                    Button {
                        model.fixQueue.openChangePage(itemID: item.id)
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "arrow.up.right.square")
                            Text(url.absoluteString).lineLimit(2).multilineTextAlignment(.leading)
                        }
                        .font(.caption).foregroundStyle(.blue)
                    }
                    .buttonStyle(.plain)
                    .help("Open this change page in your chosen browser")
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
                Label("Copy & open copies the new password and opens the change page in your browser.", systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary)
            } else if item.status == .opened {
                Label("Copied to clipboard (auto-clears in ~\(clearSeconds)s). Change it on the site, then mark done.", systemImage: "doc.on.clipboard")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            switch item.status {
            case .pending:
                Button("Skip", role: .cancel) { model.recordFixSkipped(item) }
                Button {
                    model.fixQueue.approve(itemID: item.id)
                } label: { Label("Copy & open", systemImage: "doc.on.doc") }
                    .buttonStyle(.borderedProminent)
            case .opened:
                Button("Mark done") { model.recordFixDone(item) }
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
