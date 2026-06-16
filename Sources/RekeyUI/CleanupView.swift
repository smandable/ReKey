import SwiftUI
import AppKit
import Model

/// Step 4 (optional): clean up logins left in browsers you've migrated away from.
/// The app never deletes — it builds a `rekey-cleanup` script you review and run.
struct CleanupView: View {
    @Bindable var model: AppModel

    private typealias Candidate = CleanupPlanner.Candidate

    @State private var keep: BrowserSource?
    @State private var selected: Set<String> = []
    @State private var confirm = false
    @State private var copied = false

    private var importedBrowsers: [BrowserSource] {
        CleanupPlanner.importedBrowsers(in: model.allCredentials)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                header
                if model.allCredentials.isEmpty {
                    unavailable("Nothing imported yet", "Import your browsers' CSVs first, then come back to clean up the old ones.")
                } else if importedBrowsers.count < 2 {
                    unavailable("Only one browser imported", "Import from the browsers you've migrated away from to find stale logins to remove.")
                } else if let keep {
                    content(keep)
                }
            }
            .padding(20)
            .frame(maxWidth: 820, alignment: .leading)
        }
        .frame(maxWidth: .infinity)
        .onAppear(perform: ensureKeep)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Clean up old browsers").font(.largeTitle.bold())
            Text("After you've migrated to one browser, remove the stale logins left in the others. Pick the browser you're keeping; Rekey lists the sites saved in your *other* browsers and builds a `rekey-cleanup` script you review and run. **Rekey never deletes anything itself** — the script does, after you quit those browsers, and it backs up each store first. (Apple Passwords isn't supported — no delete API.)")
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private func content(_ keep: BrowserSource) -> some View {
        let candidates = CleanupPlanner.candidates(from: model.allCredentials, keep: keep)

        HStack {
            Text("Browser you're keeping:")
            Picker("Browser you're keeping", selection: keepBinding) {
                ForEach(importedBrowsers, id: \.self) { Text($0.displayName).tag(Optional($0)) }
            }
            .labelsHidden()
            .frame(maxWidth: 200)
            Spacer()
        }

        if candidates.isEmpty {
            unavailable("Nothing to clean up", "No removable logins from browsers other than \(keep.displayName).")
        } else {
            summary(candidates, keep: keep)
            ForEach(browsers(in: candidates), id: \.self) { browser in
                browserGroup(browser, candidates.filter { $0.browser == browser }, keep: keep)
            }
            scriptSection(candidates)
        }
    }

    private func summary(_ candidates: [Candidate], keep: BrowserSource) -> some View {
        let safe = candidates.filter(\.fullySafe).count
        let sole = candidates.count - safe
        return Text("**\(candidates.count)** site(s) saved in other browsers — **\(safe)** also exist in \(keep.displayName) (pre-selected, safe to remove); **\(sole)** exist only in the old browser (unchecked — deleting loses the password).")
            .font(.callout).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func browserGroup(_ browser: BrowserSource, _ candidates: [Candidate], keep: BrowserSource) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    BrowserSourcePill(source: browser)
                    Text("\(candidates.count) site(s)").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                }
                ForEach(candidates) { candidate in
                    candidateRow(candidate, keep: keep)
                }
            }
            .padding(6)
        }
    }

    private func candidateRow(_ candidate: Candidate, keep: BrowserSource) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Toggle("", isOn: selectionBinding(for: candidate)).labelsHidden()
            VStack(alignment: .leading, spacing: 2) {
                Text(candidate.domain).font(.body.weight(.medium))
                Text(candidate.usernames.joined(separator: ", "))
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                if candidate.fullySafe {
                    Label("Also saved in \(keep.displayName)", systemImage: "checkmark.seal")
                        .font(.caption2).foregroundStyle(.green)
                } else {
                    Label("\(candidate.soleCopyUsernames.count) login(s) here aren't in \(keep.displayName) — removing the site loses them",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.caption2).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer()
        }
    }

    @ViewBuilder
    private func scriptSection(_ candidates: [Candidate]) -> some View {
        let chosen = candidates.filter { selected.contains($0.id) }
        let script = CleanupPlanner.script(for: chosen, confirm: confirm)

        Divider()
        Toggle("Include `--confirm` — actually delete (otherwise the script only previews what would be removed)", isOn: confirmBinding)
            .font(.callout)

        if chosen.isEmpty {
            Text("Select sites above to build the cleanup script.").font(.caption).foregroundStyle(.secondary)
        } else {
            Text(script)
                .font(.system(.caption2, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
            HStack {
                Button { copyScript(script) } label: {
                    Label(copied ? "Copied" : "Copy script", systemImage: copied ? "checkmark" : "doc.on.doc")
                }
                Button { saveScript(script) } label: {
                    Label("Save .sh…", systemImage: "square.and.arrow.down")
                }
                Spacer()
                Text("\(chosen.count) site(s) selected").font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func unavailable(_ title: String, _ message: String) -> some View {
        ContentUnavailableView(title, systemImage: "trash.slash", description: Text(message))
            .frame(maxWidth: .infinity)
            .padding(.top, 30)
    }

    // MARK: - State plumbing

    private var keepBinding: Binding<BrowserSource?> {
        Binding(get: { keep }, set: { keep = $0; resetSelection() })
    }
    private var confirmBinding: Binding<Bool> {
        Binding(get: { confirm }, set: { confirm = $0; copied = false })
    }
    private func selectionBinding(for candidate: Candidate) -> Binding<Bool> {
        Binding(
            get: { selected.contains(candidate.id) },
            set: { isOn in
                if isOn { selected.insert(candidate.id) } else { selected.remove(candidate.id) }
                copied = false
            }
        )
    }

    private func ensureKeep() {
        guard keep == nil else { return }
        let browsers = importedBrowsers
        guard !browsers.isEmpty else { return }
        // Default to the most-represented source — most likely the primary.
        let counts = Dictionary(grouping: model.allCredentials, by: \.source).mapValues(\.count)
        keep = browsers.max { (counts[$0] ?? 0) < (counts[$1] ?? 0) }
        resetSelection()
    }

    private func resetSelection() {
        guard let keep else { return }
        let candidates = CleanupPlanner.candidates(from: model.allCredentials, keep: keep)
        selected = Set(candidates.filter(\.fullySafe).map(\.id))   // safe duplicates by default
        copied = false
    }

    private func browsers(in candidates: [Candidate]) -> [BrowserSource] {
        var seen: [BrowserSource] = []
        for c in candidates where !seen.contains(c.browser) { seen.append(c.browser) }
        return seen.sorted { $0.displayName < $1.displayName }
    }

    private func copyScript(_ script: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(script, forType: .string)
        copied = true
    }

    private func saveScript(_ script: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "rekey-cleanup.sh"
        panel.canCreateDirectories = true
        panel.message = "Save the cleanup script. Review it, then run it in Terminal."
        if panel.runModal() == .OK, let url = panel.url {
            try? script.write(to: url, atomically: true, encoding: .utf8)
        }
    }
}
