import SwiftUI
import Model
import AuditEngine

/// Step 2: findings. Grouped by registrable domain; sorted **worst-first** by
/// default (highest severity, biggest reuse cluster, important domains) so you
/// work the riskiest accounts first, with an A–Z option.
struct FindingsView: View {
    @Bindable var model: AppModel
    @State private var onlyIssues = true
    @State private var sortByPriority = true
    @State private var showIgnored = false
    @State private var searchText = ""
    /// Shared with the Fix Queue and the Settings screen; passwords shown by default.
    @AppStorage(Prefs.showPasswords) private var showPasswords = true

    var body: some View {
        Group {
            if let report = model.report {
                content(report)
            } else {
                ContentUnavailableView(
                    "No audit yet",
                    systemImage: "magnifyingglass",
                    description: Text("Import your CSVs and run the audit to see findings here.")
                )
            }
        }
    }

    private func content(_ report: AuditReport) -> some View {
        let base = sortByPriority ? report.prioritizedDomainGroups : report.domainGroups
        let groups = base.filter { group in
            guard onlyIssues else { return true }
            return hasActiveIssue(group, report) || (showIgnored && hasIgnoredIssue(group, report))
        }
        let query = searchText.trimmingCharacters(in: .whitespaces).lowercased()
        let searched = query.isEmpty ? groups : groups.filter { group in
            group.registrableDomain.lowercased().contains(query)
                || group.credentials.contains {
                    $0.username.lowercased().contains(query) || $0.site.lowercased().contains(query)
                }
        }
        return ScrollView {
            // LazyVStack, NOT VStack: at thousands of credentials a plain VStack
            // builds every domain section + row up front on the main thread, which
            // beachballs right after an audit of a big import. Lazy renders only
            // what's on screen.
            LazyVStack(alignment: .leading, spacing: 12) {
                summary(report)
                unsavedFixBanner
                searchBar

                if searched.isEmpty {
                    emptyState(searching: !query.isEmpty)
                } else {
                    ForEach(searched) { group in
                        domainSection(group, report: report)
                    }
                }
            }
            .padding(20)
            .frame(maxWidth: 760, alignment: .leading)
        }
        .frame(maxWidth: .infinity)
    }

    private var searchBar: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField("Search site or username", text: $searchText)
                .textFieldStyle(.plain)
            if !searchText.isEmpty {
                Button { searchText = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.borderless).foregroundStyle(.secondary)
                    .help("Clear")
                    .accessibilityLabel("Clear search")
            }
        }
        .padding(8)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }

    @ViewBuilder
    private func emptyState(searching: Bool) -> some View {
        if searching {
            ContentUnavailableView(
                "No matches for “\(searchText)”",
                systemImage: "magnifyingglass",
                description: Text("No \(onlyIssues ? "flagged " : "")site or username matches your search. Clear the search or turn off “Only issues” to widen it.")
            )
            .frame(maxWidth: .infinity).padding(.top, 40)
        } else {
            ContentUnavailableView(
                onlyIssues ? "No issues found" : "No sites",
                systemImage: "checkmark.seal",
                description: Text(onlyIssues ? "None of your imported passwords are reused, breached, or weak." : "Import some credentials first.")
            )
            .frame(maxWidth: .infinity).padding(.top, 40)
        }
    }

    /// Top-of-Findings heads-up when a re-import shows fixed accounts still on the
    /// old password — so a missed save is impossible to scroll past.
    @ViewBuilder
    private var unsavedFixBanner: some View {
        let n = model.unsavedFixCount
        if n > 0 {
            Label("\(n) fixed account\(n == 1 ? "" : "s") may not have saved — your latest import still shows the old password. Look for the orange “May not have saved” flag below and Reopen to redo it.",
                  systemImage: "exclamationmark.triangle.fill")
                .font(.callout).foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
        }
    }

    private func summary(_ report: AuditReport) -> some View {
        let progress = model.fixProgress
        let ignored = ignoredCount(report)
        let crossEco = crossEcosystemAccounts(report)
        let multiBrowser = multiBrowserAccountCount(report)
        var parts = ["\(report.findingsByCredential.count) reused/compromised",
                     "\(report.weak.count) weak",
                     "across \(report.flaggedDomainGroups.count) sites"]
        if crossEco > 0 { parts.append("\(crossEco) in Apple + a browser") }
        if multiBrowser > 0 { parts.append("\(multiBrowser) in 2+ browsers") }
        if ignored > 0 { parts.append("\(ignored) ignored") }
        let summaryLine = parts.joined(separator: " · ") + "."
        return HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Findings").font(.largeTitle.bold())
                Text(summaryLine)
                    .foregroundStyle(.secondary)
                if progress.total > 0 {
                    HStack(spacing: 8) {
                        ProgressView(value: Double(progress.done), total: Double(max(progress.total, 1)))
                            .frame(width: 200)
                        Text("Fixed \(progress.done) of \(progress.total)")
                            .font(.callout.weight(.medium))
                            .foregroundStyle(progress.done == progress.total ? .green : .secondary)
                    }
                    .padding(.top, 2)
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 8) {
                // Buttons, not a segmented Picker (inert on this macOS — same quirk
                // as the sidebar List and the generator style selector).
                HStack(spacing: 0) {
                    sortButton("Priority", selected: sortByPriority) { sortByPriority = true }
                    sortButton("A–Z", selected: !sortByPriority) { sortByPriority = false }
                }
                .frame(width: 150)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.quaternary))
                Toggle("Only issues", isOn: $onlyIssues).toggleStyle(.switch)
                Toggle("Show passwords", isOn: $showPasswords).toggleStyle(.switch)
                if ignored > 0 {
                    Toggle("Show ignored", isOn: $showIgnored).toggleStyle(.switch)
                }
                Button { Task { await model.enqueueAllFlagged() } } label: {
                    Label("Add all to queue", systemImage: "checkmark.shield")
                }
                .disabled(report.findingsByCredential.isEmpty)
            }
        }
    }

    private func domainSection(_ group: DomainGroup, report: AuditReport) -> some View {
        // Hide ignored accounts unless the user is reviewing them.
        let creds = group.credentials.filter { showIgnored || !model.isIgnored($0) }
        return GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(group.registrableDomain).font(.title3.weight(.semibold))
                    Spacer()
                    if creds.count > 1 {
                        if model.canQueueGroup(group) {
                            Button("Queue all") { Task { await model.enqueueGroup(group) } }
                                .controlSize(.small)
                                .help("Add every still-actionable account on this site to the Fix Queue.")
                        }
                        if model.canIgnoreGroup(group) {
                            Button("Ignore all") { model.ignoreGroup(group) }
                                .controlSize(.small)
                                .help("Ignore every active finding on this site (reversible with “Show ignored”).")
                        }
                    }
                }
                ForEach(creds) { cred in
                    CredentialRow(model: model, cred: cred, report: report, revealPassword: showPasswords)
                    if cred.id != creds.last?.id { Divider() }
                }
            }
            .padding(8)
        }
    }

    private func isFlagged(_ cred: ImportedCredential, _ report: AuditReport) -> Bool {
        report.findingsByCredential[cred.id] != nil
            || report.weak.contains(cred.id)
            || report.crossEcosystemDuplicates.contains(cred.id)
            || report.strayBlankUsername.contains(cred.id)
            || cred.username.isEmpty   // blank-username (stray or "no username") — surface for review
    }
    /// Distinct accounts saved in both an Apple and a non-Apple store.
    private func crossEcosystemAccounts(_ report: AuditReport) -> Int {
        var keys = Set<String>()
        for cred in report.credentials where report.crossEcosystemDuplicates.contains(cred.id) {
            keys.insert("\(cred.registrableDomain)|\(cred.username)")
        }
        return keys.count
    }
    /// One segment of the Buttons-based sort selector.
    private func sortButton(_ label: String, selected: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(label)
                .font(.caption)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 4)
                .foregroundStyle(selected ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
                .background(selected ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.clear))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    /// Distinct accounts saved across 2+ different browsers (don't sync).
    private func multiBrowserAccountCount(_ report: AuditReport) -> Int {
        var keys = Set<String>()
        for cred in report.credentials where report.multiBrowserAccounts[cred.id] != nil {
            keys.insert("\(cred.registrableDomain)|\(cred.username)")
        }
        return keys.count
    }
    /// A domain still has an *active* (non-ignored) finding.
    private func hasActiveIssue(_ group: DomainGroup, _ report: AuditReport) -> Bool {
        group.credentials.contains { isFlagged($0, report) && !model.isIgnored($0) }
    }
    /// A domain has a finding the user has ignored (for the "Show ignored" view).
    private func hasIgnoredIssue(_ group: DomainGroup, _ report: AuditReport) -> Bool {
        group.credentials.contains { isFlagged($0, report) && model.isIgnored($0) }
    }
    /// Distinct ignored accounts among flagged credentials.
    private func ignoredCount(_ report: AuditReport) -> Int {
        var keys = Set<String>()
        for cred in model.allCredentials where isFlagged(cred, report) && model.isIgnored(cred) {
            keys.insert(AppModel.progressKey(for: cred))
        }
        return keys.count
    }

}

/// One credential within a domain group: labeled username + password (so you can
/// see what's actually being reused), the source, any finding badges, and the
/// fix control.
private struct CredentialRow: View {
    @Bindable var model: AppModel
    let cred: ImportedCredential
    let report: AuditReport
    /// Driven by the list-wide "Hide passwords" setting.
    let revealPassword: Bool

    var body: some View {
        let finding = report.findingsByCredential[cred.id]
        let isWeak = report.weak.contains(cred.id)
        let isCrossEcosystem = report.crossEcosystemDuplicates.contains(cred.id)
        let isStray = report.strayBlankUsername.contains(cred.id)
        // Blank username but the ONLY login for its site (not a stray): a real
        // login saved without a name (reset/sign-up page) — review, don't delete.
        let isNoUsername = cred.username.isEmpty && !isStray
        let hasSecurityIssue = finding != nil || isWeak
        let ignored = model.isIgnored(cred)
        // Same account also saved in other browsers (don't sync to each other).
        let otherBrowsers = model.otherBrowsers(for: cred)
        let isMultiBrowser = !otherBrowsers.isEmpty
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    if cred.username.isEmpty {
                        // The browser saved this login with no username — let the user
                        // type the real one (usually their email) as a recognition
                        // label here. Display only: the fix/cleanup still use the
                        // browser's actual (blank) username, which is what the store
                        // has, so a cleanup match isn't broken by the typed email.
                        HStack(spacing: 4) {
                            Text("Username:").foregroundStyle(.secondary)
                            TextField("add username…", text: usernameBinding)
                                .textFieldStyle(.roundedBorder)
                                .frame(maxWidth: 240)
                        }
                        .font(.callout)
                    } else {
                        fieldLine("Username:", value: cred.username)
                    }
                    HStack(spacing: 4) {
                        Text("Password:").foregroundStyle(.secondary)
                        Text(revealPassword ? cred.password.reveal() : cred.password.masked())
                            .font(.system(.callout, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    .font(.callout)
                    Text(cred.rawURL).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                BrowserSourcePill(source: cred.source)
                if cred.hasTOTP {
                    Image(systemName: "clock.badge.checkmark").foregroundStyle(.secondary)
                        .help("This entry also has a one-time-code (TOTP) set up.")
                }
            }

            if hasSecurityIssue || isCrossEcosystem || isStray || isNoUsername || isMultiBrowser {
                HStack(spacing: 6) {
                    if ignored && (hasSecurityIssue || isStray || isNoUsername) {
                        PillBadge(icon: "bell.slash.fill", text: "Ignored", color: .gray)
                        Spacer()
                        Button("Un-ignore") { model.unignoreFinding(for: cred) }
                            .controlSize(.small)
                    } else {
                        if let finding {
                            FindingBadge(kind: finding.kind, breachCount: finding.breachCount)
                        }
                        if isWeak {
                            PillBadge(icon: "exclamationmark.shield.fill", text: "Weak", color: .yellow)
                        }
                        if isCrossEcosystem {
                            PillBadge(icon: "iphone",
                                      text: cred.source.isApple ? "Also in a browser" : "Also in Apple Passwords",
                                      color: .orange)
                        }
                        if isMultiBrowser {
                            PillBadge(icon: "rectangle.on.rectangle",
                                      text: "In \(otherBrowsers.count + 1) browsers",
                                      color: .orange)
                        }
                        if isStray {
                            PillBadge(icon: "person.crop.circle.badge.questionmark", text: "No username", color: .gray)
                        }
                        if isNoUsername {
                            PillBadge(icon: "person.crop.circle", text: "No username", color: .gray)
                        }
                        Spacer()
                        if hasSecurityIssue || isStray || isNoUsername {
                            // Blank-username entries are fixable too: the username
                            // (usually an email) is often just missing from the export,
                            // not absent — so offer Add to queue, not delete-only.
                            fixControl
                            Button("Ignore") { model.ignoreFinding(for: cred) }
                                .controlSize(.small)
                                .help((isStray || isNoUsername)
                                    ? "Real account? Keep it (Ignore) or fix it. A leftover? Delete it in your browser first, then Ignore."
                                    : "Hide this finding — you've reviewed and accepted it. Bring it back with 'Show ignored'.")
                        }
                    }
                }
                if !(ignored && (hasSecurityIssue || isStray || isNoUsername)) {
                    if isCrossEcosystem {
                        Text("Saved in both Apple Passwords and a browser — these don't sync, so update both or your iPhone may keep autofilling the old password.")
                            .font(.caption).foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if isMultiBrowser {
                        Text("Also saved in \(otherBrowsers.map(\.displayName).joined(separator: ", ")) — these browsers don't sync to each other, so changing the password here leaves the others on the old one. A password manager keeps one copy everywhere.")
                            .font(.caption).foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if isStray {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("No username saved on this one, though the site also has a login *with* one. Your browser likely stored it without a username (common on multi-step sign-in forms) — making this a **real second account** — or it's a leftover duplicate of the other.")
                            Text("• Real account? Add the username above (so you recognize it), then **Add to queue** and fix it.")
                            Text("• A leftover? \(StaleLoginGuidance.manualSteps(for: cred.source, domain: cred.site)) Then **Ignore**.")
                        }
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                        .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                    }
                    if isNoUsername {
                        Text("No username saved — your browser stored this login without one (common when the username and password are on separate pages), not that the account isn't real. Type the username above to label it as yours here, then **Add to queue** to fix it, or **Ignore** to keep it. The real fix is to add the username to this entry in your browser's Password Manager — then autofill works and it stops showing up here.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if hasSecurityIssue, let cluster = report.cluster(for: cred.id), cluster.isAcrossSites {
                        let others = cluster.registrableDomains.filter { $0 != cred.registrableDomain }
                        if !others.isEmpty {
                            Text("Same password as: \(others.joined(separator: ", "))")
                                .font(.caption).foregroundStyle(.orange)
                        }
                    }
                }
            }
        }
        .opacity(ignored && (hasSecurityIssue || isStray || isNoUsername) ? 0.65 : 1)
        .padding(.vertical, 2)
    }

    private func fieldLine(_ label: String, value: String) -> some View {
        HStack(spacing: 4) {
            Text(label).foregroundStyle(.secondary)
            Text(value).fontWeight(.medium).textSelection(.enabled)
        }
        .font(.callout)
    }

    /// Two-way binding to the user-supplied username for a blank-username login.
    private var usernameBinding: Binding<String> {
        Binding(
            get: { model.effectiveUsername(for: cred) },
            set: { model.setUsername($0, for: cred) }
        )
    }

    @ViewBuilder
    private var fixControl: some View {
        if model.isFixed(cred) {
            HStack(spacing: 8) {
                if model.fixMaySaveFailed(cred) {
                    Label("May not have saved", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption2.weight(.medium)).foregroundStyle(.orange)
                        .help("Your latest import still shows the OLD password for this account — the change may not have saved to the browser. Reopen to redo it.")
                } else {
                    Label("Fixed", systemImage: "checkmark.circle.fill")
                        .font(.caption2.weight(.medium)).foregroundStyle(.green)
                }
                Button("Reopen") { model.unmarkFixed(for: cred) }
                    .controlSize(.small)
                    .help("Not actually fixed? Mark it un-fixed so you can queue and redo it — e.g. the new password never got saved to the browser.")
            }
        } else if model.fixQueue.items.contains(where: { $0.credentialID == cred.id }) {
            Label("In fix queue", systemImage: "checkmark").font(.caption2).foregroundStyle(.green)
        } else {
            Button("Add to queue") { Task { await model.enqueueFix(for: cred) } }.controlSize(.small)
        }
    }
}
