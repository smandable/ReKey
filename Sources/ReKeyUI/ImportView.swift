import SwiftUI
import UniformTypeIdentifiers
import Model
import ImportKit

/// Step 1: import exported CSVs. Shows detected format, a skipped-row summary,
/// and a prominent secure-delete prompt for each source file.
struct ImportView: View {
    @Bindable var model: AppModel
    @State private var showingPicker = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                importErrorBanner

                GroupBox {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Text("If importing a Chromium browser, label it:")
                            Picker("Chromium browser", selection: $model.chromiumSource) {
                                ForEach(BrowserSource.chromiumFamily, id: \.self) { source in
                                    Text(source.displayName).tag(source)
                                }
                            }
                            .labelsHidden()
                            .frame(maxWidth: 180)
                            .help("Chrome, Arc, Brave, Edge, Opera, and Vivaldi all export identical CSVs, so ReKey can't tell them apart. Pick the right one before importing. (Firefox and Apple Passwords are detected automatically.)")
                        }
                        Button {
                            showingPicker = true
                        } label: {
                            Label("Import CSV…", systemImage: "square.and.arrow.down")
                        }
                        .controlSize(.large)
                    }
                    .padding(6)
                }

                watchFolderBox

                if !model.files.isEmpty {
                    ForEach(model.files) { file in
                        fileCard(file)
                    }
                    auditBar
                }

                multiBrowserNote
                privacyNote
            }
            .padding(20)
            .frame(maxWidth: 720, alignment: .leading)
        }
        .frame(maxWidth: .infinity)
        .fileImporter(
            isPresented: $showingPicker,
            allowedContentTypes: [.commaSeparatedText, .text, UTType(filenameExtension: "csv") ?? .data],
            allowsMultipleSelection: true
        ) { result in
            switch result {
            case .success(let urls):
                for url in urls { model.importFile(at: url) }
            case .failure(let error):
                model.reportImportError("Couldn't open that file: \(error.localizedDescription)")
            }
        }
    }

    @ViewBuilder
    private var importErrorBanner: some View {
        if let error = model.auditError {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                Text(error)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button { model.auditError = nil } label: {
                    Image(systemName: "xmark.circle.fill")
                }
                .buttonStyle(.borderless).foregroundStyle(.secondary)
                .help("Dismiss")
                .accessibilityLabel("Dismiss error")
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
        }
    }

    private var watchFolderBox: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                if let folder = model.watchedFolder {
                    HStack {
                        Image(systemName: "eye.fill").foregroundStyle(.green)
                        Text("Watching **\(folder.lastPathComponent)** — new password exports import automatically.")
                            .font(.callout)
                        Spacer()
                        Button("Stop") { model.stopWatching() }.controlSize(.small)
                    }
                    if let message = model.autoImportMessage {
                        Label(message, systemImage: "checkmark.circle")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } else if let remembered = model.rememberedWatchFolder {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Auto-import paused").font(.callout.weight(.medium))
                            Text("ReKey lost its grant for **\(remembered.lastPathComponent)** (folder access doesn't survive a re-signed or updated app). Re-watch to resume — the picker is pre-pointed there.")
                                .font(.caption).foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer()
                        Button { model.chooseWatchFolder() } label: {
                            Label("Re-watch \(remembered.lastPathComponent)", systemImage: "eye")
                        }
                        .controlSize(.small)
                    }
                } else {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Auto-import").font(.callout.weight(.medium))
                            Text("Watch a folder (e.g. Downloads) and import recognized password CSVs as they appear — you still export manually.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button { model.chooseWatchFolder() } label: {
                            Label("Choose folder…", systemImage: "eye")
                        }
                        .controlSize(.small)
                    }
                }
            }
            .padding(6)
        }
    }

    private var multiBrowserNote: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Switched browsers over the years?", systemImage: "arrow.triangle.branch")
                .font(.headline)
            Text("""
            Export and import from **every** browser you've used (Chrome, Firefox, Arc, …) — ReKey audits them together, so a password reused across them is caught.

            • **Fixing** opens each change page in your **default browser**, and that browser saves the new password. So set your macOS default (System Settings → Desktop & Dock → Default web browser) to the browser you want to keep using — it becomes your single, current store.
            • **Old copies** left in the browsers you've stopped using don't disappear. ReKey never deletes them; you remove them yourself with the `rekey-cleanup` Terminal tool — each fixed item shows the exact command, and you can inventory a whole browser with `rekey-cleanup list --browser chrome`.
            """)
            .font(.callout)
            .foregroundStyle(.secondary)
        }
        .padding(.top, 4)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Import passwords")
                .font(.largeTitle.bold())
            Text("Export a CSV from Chrome, Arc, Firefox, or Apple Passwords, then import it here. ReKey reads only the files you choose — it never touches your browsers or Apple Passwords directly.")
                .foregroundStyle(.secondary)
        }
    }

    private func fileCard(_ file: ImportedFile) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Image(systemName: "doc.text")
                    Text(file.displayName).font(.headline)
                    Spacer()
                    BrowserSourcePill(source: file.result.source)
                }

                HStack(spacing: 16) {
                    Label("\(file.result.credentials.count) credentials", systemImage: "key")
                    if file.result.skipped.count > 0 {
                        Label("\(file.result.skipped.count) skipped", systemImage: "minus.circle")
                            .foregroundStyle(.secondary)
                            .help(skipReasons(file))
                    }
                }
                .font(.subheadline)

                if let url = file.url {
                    if file.sourceDeleted {
                        Label("Source file securely deleted", systemImage: "checkmark.seal.fill")
                            .font(.caption).foregroundStyle(.green)
                    } else {
                        HStack(spacing: 8) {
                            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                            Text("This plaintext CSV is still on disk at \(url.path).")
                                .font(.caption).foregroundStyle(.secondary)
                            Spacer()
                            Button(role: .destructive) {
                                model.securelyDeleteSource(of: file)
                            } label: {
                                Label("Securely delete", systemImage: "trash")
                            }
                            .controlSize(.small)
                        }
                        .padding(8)
                        .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                    }
                }

                HStack {
                    Spacer()
                    Button("Remove", role: .cancel) { model.removeFile(file) }
                        .controlSize(.small)
                }
            }
            .padding(6)
        }
    }

    private func skipReasons(_ file: ImportedFile) -> String {
        let reasons = Dictionary(grouping: file.result.skipped, by: \.reason)
            .map { "\($0.value.count) × \($0.key.rawValue)" }
            .sorted()
        return "Skipped: " + reasons.joined(separator: ", ")
            + ". Blank-password rows are usually passkeys or 'sign in with…' entries."
    }

    private var auditBar: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("\(model.allCredentials.count) credentials from \(model.files.count) file(s)" +
                     (model.totalSkipped > 0 ? " · \(model.totalSkipped) skipped" : ""))
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    Task { await model.runAudit() }
                } label: {
                    Label(model.isAuditing ? "Auditing…" : "Run audit", systemImage: "magnifyingglass")
                }
                .keyboardShortcut(.defaultAction)
                .disabled(model.isAuditing || model.allCredentials.isEmpty)
                .controlSize(.large)
            }

            if model.isAuditing {
                auditProgress
            }
        }
    }

    /// Determinate bar + live phase/count while the audit runs. The
    /// compromised-password check (one HIBP lookup per distinct password) is the
    /// long pole, so a large import shows a real countdown rather than a spinner.
    private var auditProgress: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let fraction = model.auditFraction {
                ProgressView(value: fraction).progressViewStyle(.linear)
            } else {
                ProgressView().progressViewStyle(.linear)   // indeterminate
            }
            if let status = model.auditStatusText {
                Text(status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .contentTransition(.numericText())
                    .animation(.default, value: status)
            }
        }
        .padding(10)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }

    private var privacyNote: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("How ReKey protects you", systemImage: "lock.shield")
                .font(.headline)
            Text("• Passwords stay in memory only — never written to disk, logged, or sent anywhere.\n• The only network calls are the Have I Been Pwned check (which sends just the first 5 characters of a SHA-1 hash) and resolving a single site's change-password page when you choose to fix it.\n• ReKey never changes a password for you. It opens the site's change page; you make the change, and your browser saves it.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .padding(.top, 8)
    }
}
