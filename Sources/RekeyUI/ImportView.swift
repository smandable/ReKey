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
                            .help("Chrome, Arc, Brave, Edge, Opera, and Vivaldi all export identical CSVs, so Rekey can't tell them apart. Pick the right one before importing. (Firefox and Apple Passwords are detected automatically.)")
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

                if !model.files.isEmpty {
                    ForEach(model.files) { file in
                        fileCard(file)
                    }
                    auditBar
                }

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
            if case let .success(urls) = result {
                for url in urls { model.importFile(at: url) }
            }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Import passwords")
                .font(.largeTitle.bold())
            Text("Export a CSV from Chrome, Arc, Firefox, or Apple Passwords, then import it here. Rekey reads only the files you choose — it never touches your browsers or Apple Passwords directly.")
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
                    Text(file.result.source.displayName)
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 7).padding(.vertical, 3)
                        .background(file.result.source.badgeColor.opacity(0.18), in: Capsule())
                        .foregroundStyle(file.result.source.badgeColor)
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
        HStack {
            Text("\(model.allCredentials.count) credentials from \(model.files.count) file(s)" +
                 (model.totalSkipped > 0 ? " · \(model.totalSkipped) skipped" : ""))
                .foregroundStyle(.secondary)
            Spacer()
            Button {
                Task { await model.runAudit() }
            } label: {
                if model.isAuditing {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Run audit", systemImage: "magnifyingglass")
                }
            }
            .keyboardShortcut(.defaultAction)
            .disabled(model.isAuditing || model.allCredentials.isEmpty)
            .controlSize(.large)
        }
    }

    private var privacyNote: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("How Rekey protects you", systemImage: "lock.shield")
                .font(.headline)
            Text("• Passwords stay in memory only — never written to disk, logged, or sent anywhere.\n• The only network calls are the Have I Been Pwned check (which sends just the first 5 characters of a SHA-1 hash) and resolving a single site's change-password page when you choose to fix it.\n• Rekey never changes a password for you. It opens the site's change page; you make the change, and your browser saves it.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .padding(.top, 8)
    }
}
