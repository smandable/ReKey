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
    @State private var confirm = true   // default to a runnable (deleting) script, like the Fix Queue cleanup
    @State private var copied = false

    private var importedBrowsers: [BrowserSource] {
        CleanupPlanner.importedBrowsers(in: model.allCredentials)
    }

    var body: some View {
        ScrollView {
            // LazyVStack, not VStack: a browser you've migrated away from can hold
            // hundreds/thousands of sites; building every candidate row up front
            // froze the main thread. Lazy renders only what's on screen.
            LazyVStack(alignment: .leading, spacing: 10) {
                header
                if model.allCredentials.isEmpty {
                    unavailable("Nothing imported yet", "Import your browsers' CSVs first, then come back to clean up the old ones.")
                } else if importedBrowsers.count < 2 {
                    unavailable("Only one browser imported", "Import from the browsers you've migrated away from to find stale logins to remove.")
                } else if let keep {
                    keepPicker
                    if candidates.isEmpty {
                        unavailable("Nothing to clean up", "No removable logins from browsers other than \(keep.displayName).")
                    } else {
                        summary(candidates, keep: keep)
                        // Flat ForEach of browser-header + candidate rows, a direct
                        // child of the LazyVStack so the rows materialize lazily.
                        ForEach(rows(for: candidates)) { row in rowView(row, keep: keep) }
                        scriptSection(candidates)
                    }
                }
            }
            .padding(20)
            .frame(maxWidth: 820, alignment: .leading)
        }
        .frame(maxWidth: .infinity)
        .onAppear(perform: ensureKeep)
    }

    /// Candidate (old-browser, site) rows for the currently-kept browser. Cheap
    /// (O(n)); recomputed per render so it tracks the live import and selection.
    private var candidates: [Candidate] {
        guard let keep else { return [] }
        return CleanupPlanner.candidates(from: model.allCredentials, keep: keep)
    }

    private var keepPicker: some View {
        HStack {
            Text("Browser you're keeping:")
            Picker("Browser you're keeping", selection: keepBinding) {
                ForEach(importedBrowsers, id: \.self) { Text($0.displayName).tag(Optional($0)) }
            }
            .labelsHidden().pickerStyle(.menu).frame(maxWidth: 200)
            Spacer()
        }
    }

    /// Flatten candidates into one browser header followed by its rows — a flat
    /// list the LazyVStack can render on demand (a GroupBox per browser couldn't).
    private func rows(for candidates: [Candidate]) -> [CleanupRow] {
        var out: [CleanupRow] = []
        for browser in browsers(in: candidates) {
            let group = candidates.filter { $0.browser == browser }
            out.append(.header(browser, count: group.count))
            out.append(contentsOf: group.map { CleanupRow.candidate($0) })
        }
        return out
    }

    @ViewBuilder
    private func rowView(_ row: CleanupRow, keep: BrowserSource) -> some View {
        switch row {
        case let .header(browser, count):
            HStack(spacing: 8) {
                BrowserSourcePill(source: browser)
                Text("\(count) site(s)").font(.caption).foregroundStyle(.secondary)
                Spacer()
            }
            .padding(.top, 8)
        case let .candidate(candidate):
            candidateRow(candidate, keep: keep)
                .padding(.vertical, 2)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Clean up old browsers").font(.largeTitle.bold())
            Text("After you've migrated to one browser, remove the stale logins left in the others. Pick the browser you're keeping; ReKey lists the sites saved in your *other* browsers and builds a `rekey-cleanup` script you review and run. **ReKey never deletes anything itself** — the script does, after you quit those browsers, and it backs up each store first. (Apple Passwords isn't supported — no delete API.)")
                .foregroundStyle(.secondary)
        }
    }

    private func summary(_ candidates: [Candidate], keep: BrowserSource) -> some View {
        let safe = candidates.filter(\.fullySafe).count
        let sole = candidates.count - safe
        return Text("**\(candidates.count)** site(s) saved in other browsers — **\(safe)** also exist in \(keep.displayName) (pre-selected, safe to remove); **\(sole)** exist only in the old browser (unchecked — deleting loses the password).")
            .font(.callout).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
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
                        .foregroundStyle(copied ? AnyShapeStyle(.green) : AnyShapeStyle(.primary))
                }
                Button { saveScript(script) } label: {
                    Label("Save script…", systemImage: "square.and.arrow.down")
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
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(1.5))
            copied = false
        }
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

/// One row of the flattened Clean Up list: a per-browser section header, or a
/// candidate site to (optionally) remove. Flat rows (vs nested GroupBoxes) are
/// what let the LazyVStack render them on demand.
private enum CleanupRow: Identifiable {
    case header(BrowserSource, count: Int)
    case candidate(CleanupPlanner.Candidate)

    var id: String {
        switch self {
        case let .header(browser, _): return "h:\(browser.rawValue)"
        case let .candidate(candidate): return "c:\(candidate.id)"
        }
    }
}
