import SwiftUI
import AppKit
import Model

/// A compact, bulk "mark for deletion" list. Built for culling at scale — a
/// browser you've migrated away from can hold hundreds of dead logins for sites
/// you'll never revisit. Unlike the Fix Queue (which re-keys an account), Cull
/// removes the login outright: each marked login becomes a `rekey-cleanup delete`
/// line in a script you review and run. **ReKey never deletes anything itself.**
struct CullView: View {
    @Bindable var model: AppModel

    @State private var excluded: Set<BrowserSource> = []   // browsers hidden from the list (empty = all shown)
    @State private var search = ""
    @State private var confirm = true   // default to a runnable (deleting) script, like the Fix Queue cleanup
    @State private var forceManual = false   // force-delete the no-username manual sites precisely
    @State private var hideMarked = false    // hide already-marked logins while hunting for more
    @State private var copied = false
    @State private var copyGen = 0   // invalidates a pending "Copied" reset when a newer copy/toggle happens
    @State private var showScript = false

    /// Only browsers `rekey-cleanup` can actually delete from (Chromium + Firefox)
    /// — Apple Passwords has no delete API, so its logins aren't cullable here.
    private var cullableBrowsers: [BrowserSource] {
        CleanupPlanner.importedBrowsers(in: model.allCredentials).filter(\.cleanupSupported)
    }

    /// Every deletable login, after the browser filter and search, sorted for scanning.
    private var shown: [ImportedCredential] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        return model.allCredentials
            .filter { $0.source.cleanupSupported }
            .filter { !excluded.contains($0.source) }
            .filter { !hideMarked || !model.isMarkedForDeletion($0) }
            .filter { q.isEmpty || $0.site.lowercased().contains(q) || $0.username.lowercased().contains(q) }
            .sorted { ($0.site, $0.username, $0.source.displayName) < ($1.site, $1.username, $1.source.displayName) }
    }

    /// How many of the currently-shown logins are marked — the count "Clear shown"
    /// would remove, and the pivot for whether a global "Clear all" is offered.
    private var shownMarkedCount: Int {
        shown.lazy.filter { model.isMarkedForDeletion($0) }.count
    }

    var body: some View {
        // Single ScrollView root, matching the other detail views (Findings /
        // Clean Up / Fix Queue). A height-hugging VStack wrapping a greedy
        // ScrollView made NavigationSplitView collapse the sidebar. The row list
        // stays a LazyVStack inside this ScrollView, so it's still lazy at scale.
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                header
                if model.allCredentials.isEmpty {
                    unavailable("Nothing imported yet",
                                "Import your browsers' CSVs first, then come back to cull the dead logins.")
                } else if cullableBrowsers.isEmpty {
                    unavailable("No deletable logins",
                                "Only sources rekey-cleanup supports (Chrome, Arc, Firefox, …) can be culled here. Apple Passwords has no delete API.")
                } else {
                    controls
                    if model.markedForDeletionCount > 0 { scriptPanel }
                    Divider().padding(.vertical, 2)
                    if shown.isEmpty {
                        unavailable("No matches",
                                    "No login matches your filter. Clear the search or include another browser.")
                    } else {
                        LazyVStack(spacing: 1) {
                            ForEach(shown) { cred in row(cred) }
                        }
                    }
                }
            }
            .padding(20)
            .frame(maxWidth: 820, alignment: .leading)
        }
        .frame(maxWidth: .infinity)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Cull old logins").font(.largeTitle.bold())
            Text("Flag logins for sites you'll never revisit — they don't need a new password, you just want them gone. Each one you mark becomes a `rekey-cleanup delete` line in a script you review and run. This removes the login **entirely** (not re-keyed, like the Fix Queue). **ReKey never deletes anything itself** — the script does, after you quit the browser, and it backs up the store first. (Apple Passwords can't be removed by the tool — no delete API — so it isn't shown here.)")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - Controls

    private var controls: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Browser multi-select: tap a pill to include/exclude that browser, so
            // you can cull e.g. Chrome + Firefox while leaving Arc untouched.
            if cullableBrowsers.count > 1 {
                HStack(spacing: 6) {
                    Image(systemName: "line.3.horizontal.decrease.circle").foregroundStyle(.secondary)
                    ForEach(cullableBrowsers, id: \.self) { browserPill($0) }
                    Spacer()
                }
            }

            HStack(spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("Search site or username", text: $search).textFieldStyle(.plain)
                    if !search.isEmpty {
                        Button { search = "" } label: { Image(systemName: "xmark.circle.fill") }
                            .buttonStyle(.borderless).foregroundStyle(.secondary)
                            .help("Clear").accessibilityLabel("Clear search")
                    }
                }
                .padding(6)
                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
                .frame(maxWidth: 260)
                Spacer()
            }

            HStack(spacing: 12) {
                Text("\(shown.count) shown · \(model.markedForDeletionCount) marked")
                    .font(.caption).foregroundStyle(.secondary)
                Toggle("Hide marked", isOn: $hideMarked)
                    .toggleStyle(.checkbox).font(.caption)
                    .help("Hide logins you've already marked, so you can keep searching for more without seeing the ones you've handled.")
                Spacer()
                Button("Mark all \(shown.count) shown") { model.markForDeletion(shown) }
                    .controlSize(.small)
                    .disabled(shown.isEmpty || shown.allSatisfy { model.isMarkedForDeletion($0) })
                    .help("Mark every login currently shown (the included browsers + search). Handy for a near-empty browser: mark all, then un-mark the few you keep.")
                Button("Clear \(shownMarkedCount) shown") { model.unmarkForDeletion(shown) }
                    .controlSize(.small)
                    .disabled(shownMarkedCount == 0)
                    .help("Clear the deletion marks on the logins currently shown (the included browsers + search) — the mirror of “Mark all shown”. Nothing is deleted.")
                // Global escape, shown only when marks exist outside the current
                // filter (so it isn't redundant with "Clear shown").
                if model.markedForDeletionCount > shownMarkedCount {
                    Button("Clear all (\(model.markedForDeletionCount))") { model.unmarkAllForDeletion() }
                        .controlSize(.small)
                        .help("Clear every deletion mark across all browsers — including \(model.markedForDeletionCount - shownMarkedCount) not matched by the current filter. Nothing is deleted.")
                }
            }
        }
    }

    /// A toggle pill for including/excluding one browser from the cull list.
    private func browserPill(_ browser: BrowserSource) -> some View {
        let isOn = !excluded.contains(browser)
        return Button {
            if isOn { excluded.insert(browser) } else { excluded.remove(browser) }
        } label: {
            HStack(spacing: 4) {
                Image(systemName: isOn ? "checkmark.circle.fill" : "circle")
                Text(browser.displayName)
            }
            .font(.caption)
            .foregroundStyle(isOn ? AnyShapeStyle(.primary) : AnyShapeStyle(.secondary))
            .padding(.vertical, 3).padding(.horizontal, 9)
            .background(isOn ? AnyShapeStyle(Color.accentColor.opacity(0.18)) : AnyShapeStyle(Color.clear), in: Capsule())
            .overlay(Capsule().strokeBorder(.quaternary))
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .help(isOn ? "Showing \(browser.displayName) — tap to hide it from the cull"
                   : "Hidden — tap to include \(browser.displayName)")
        .accessibilityLabel(browser.displayName)
        .accessibilityValue(isOn ? "Included" : "Excluded")
    }

    // MARK: - Marked summary + script

    private var scriptPanel: some View {
        let marked = model.markedForDeletionCount
        let manual = model.deletionManualSiteCount()
        let forceable = model.deletionForceableManualSiteCount()
        let script = model.deletionCleanupScript(confirm: confirm, forceManual: forceManual)
        return GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                Label("\(marked) login\(marked == 1 ? "" : "s") marked for deletion", systemImage: "trash")
                    .font(.headline)
                Text("Save and run this `rekey-cleanup.sh` yourself — one batched command per browser deletes the marked logins and prints a per-browser summary. Quit the affected browser(s) first; the tool backs up each store before deleting and won't run while a browser is open.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                // Chrome-sync caution — surfaced before a large purge. Full detail in Help.
                VStack(alignment: .leading, spacing: 3) {
                    Label("Using Chrome sync? Delete from Google Password Manager (passwords.google.com) — editing Chrome's local store here can be undone when the account re-syncs. And deleting only silences the warning; it doesn't change the password on the live site.", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Why a warning can linger after deleting →") { model.section = .help }
                        .buttonStyle(.link).font(.caption)
                }
                if forceable > 0 {
                    Toggle(isOn: $forceManual) {
                        Text("Force \(forceable) no-username removal\(forceable == 1 ? "" : "s") — logins you marked that have no username on a site with named logins. On: the script deletes just the no-username row(s) precisely (named logins left alone). Off: they're listed as a manual id-step.")
                    }
                    .font(.caption)
                }
                if manual - forceable > 0 {
                    Label("\(manual - forceable) Firefox site(s) still need manual removal by id — Firefox encrypts usernames, so the tool can't single out the no-username row. See the script's comments.", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Toggle("Include `--confirm` — actually delete (otherwise it only previews)", isOn: confirmBinding)
                    .font(.caption)
                HStack {
                    Button { copyScript(script) } label: {
                        Label(copied ? "Copied" : "Copy all", systemImage: copied ? "checkmark" : "doc.on.doc")
                            .foregroundStyle(copied ? AnyShapeStyle(.green) : AnyShapeStyle(.primary))
                    }
                    Button { saveScript(script) } label: {
                        Label("Save as rekey-cleanup.sh…", systemImage: "square.and.arrow.down")
                    }
                    .help("Write the deletion script to a .sh file you name, then run it in Terminal.")
                    Button { appendToExisting() } label: {
                        Label("Add to existing file…", systemImage: "doc.badge.plus")
                    }
                    .help("Append these purge commands to a rekey-cleanup.sh you saved before, so culls from several sessions run from one file. The file's grand total is regenerated at the bottom to cover every session; purge is idempotent, so a re-listed site just reports \"already gone\".")
                    Spacer()
                }
                DisclosureGroup(isExpanded: $showScript) {
                    Text(script.isEmpty ? "Mark a login below to build the script." : script)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                        .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
                } label: {
                    Label("Preview script", systemImage: "terminal").font(.caption.weight(.medium))
                }
            }
            .padding(6)
        }
    }

    // MARK: - One compact row (the whole row toggles, for fast culling)

    private func row(_ cred: ImportedCredential) -> some View {
        let marked = model.isMarkedForDeletion(cred)
        return Button {
            if marked { model.unmarkForDeletion(cred) } else { model.markForDeletion(cred) }
        } label: {
            HStack(spacing: 10) {
                Image(systemName: marked ? "checkmark.square.fill" : "square")
                    .foregroundStyle(marked ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.secondary))
                Text(cred.site)
                    .fontWeight(.medium)
                    .strikethrough(marked, color: .secondary)
                    .foregroundStyle(marked ? AnyShapeStyle(.secondary) : AnyShapeStyle(.primary))
                    .lineLimit(1)
                Text(cred.username.isEmpty ? "(no username)" : cred.username)
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                Spacer(minLength: 8)
                BrowserSourcePill(source: cred.source)
            }
            .padding(.vertical, 4).padding(.horizontal, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
            .background(marked ? Color.accentColor.opacity(0.10) : Color.clear,
                        in: RoundedRectangle(cornerRadius: 5))
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(cred.site), \(cred.username.isEmpty ? "no username" : cred.username), \(cred.source.displayName)")
        .accessibilityValue(marked ? "Marked for deletion" : "Not marked")
        .accessibilityHint("Activates to toggle deletion")
    }

    private func unavailable(_ title: String, _ message: String) -> some View {
        ContentUnavailableView(title, systemImage: "trash", description: Text(message))
            .frame(maxWidth: .infinity).padding(.top, 30)
    }

    // MARK: - State plumbing + file actions

    private var confirmBinding: Binding<Bool> {
        // Toggling confirm changes the script, so clear the "Copied" feedback and
        // invalidate any in-flight reset timer.
        Binding(get: { confirm }, set: { confirm = $0; copyGen += 1; copied = false })
    }

    private func copyScript(_ script: String) {
        guard !script.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(script, forType: .string)
        copied = true
        copyGen += 1
        let gen = copyGen
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(1.5))
            if copyGen == gen { copied = false }   // only the latest copy resets the badge
        }
    }

    private func saveScript(_ script: String) {
        guard !script.isEmpty else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "rekey-cleanup.sh"
        panel.canCreateDirectories = true
        panel.message = "Save the deletion script. Review it, then run it in Terminal."
        if panel.runModal() == .OK, let url = panel.url {
            try? script.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    /// Append this session's purge command blocks to a script the user already
    /// saved, so culls from several sessions accumulate in one file. When the file
    /// was saved with deletable targets, the blocks are spliced in above its grand
    /// total and that total is regenerated at the bottom — one trailing summary
    /// covering every session, not a stranded mid-file one.
    private func appendToExisting() {
        guard !model.deletionAppendableScript(confirm: confirm, forceManual: forceManual).isEmpty else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "Choose a rekey-cleanup.sh to append these purge commands to."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let existing = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        guard let out = model.deletionScriptAppending(to: existing, confirm: confirm, forceManual: forceManual) else { return }
        try? out.write(to: url, atomically: true, encoding: .utf8)
    }

}
