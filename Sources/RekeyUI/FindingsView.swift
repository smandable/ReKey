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
        return ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                summary(report)

                if groups.isEmpty {
                    ContentUnavailableView(
                        onlyIssues ? "No issues found" : "No sites",
                        systemImage: "checkmark.seal",
                        description: Text(onlyIssues ? "None of your imported passwords are reused, breached, or weak." : "Import some credentials first.")
                    )
                    .frame(maxWidth: .infinity)
                    .padding(.top, 40)
                } else {
                    ForEach(groups) { group in
                        domainSection(group, report: report)
                    }
                }
            }
            .padding(20)
            .frame(maxWidth: 760, alignment: .leading)
        }
        .frame(maxWidth: .infinity)
    }

    private func summary(_ report: AuditReport) -> some View {
        let progress = model.fixProgress
        let ignored = ignoredCount(report)
        let crossEco = crossEcosystemAccounts(report)
        return HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Findings").font(.largeTitle.bold())
                Text("\(report.findingsByCredential.count) reused/compromised · \(report.weak.count) weak · across \(report.flaggedDomainGroups.count) sites"
                     + (crossEco > 0 ? " · \(crossEco) in Apple + a browser" : "")
                     + (ignored > 0 ? " · \(ignored) ignored" : "") + ".")
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
                Picker("Sort", selection: $sortByPriority) {
                    Text("Priority").tag(true)
                    Text("A–Z").tag(false)
                }
                .pickerStyle(.segmented).labelsHidden().frame(width: 150)
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
                Text(group.registrableDomain).font(.title3.weight(.semibold))
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
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    fieldLine("Username:", value: cred.username.isEmpty ? "(none)" : cred.username)
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

            if hasSecurityIssue || isCrossEcosystem || isStray || isNoUsername {
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
                        if isStray {
                            PillBadge(icon: "person.crop.circle.badge.questionmark", text: "Likely stray", color: .gray)
                        }
                        if isNoUsername {
                            PillBadge(icon: "person.crop.circle", text: "No username", color: .gray)
                        }
                        Spacer()
                        if isStray {
                            // No "Add to queue" — there's no account behind a blank
                            // username; the right action is delete-in-browser.
                            Button("Ignore") { model.ignoreFinding(for: cred) }
                                .controlSize(.small)
                                .help("Delete the entry in your browser first, then Ignore it here.")
                        } else if hasSecurityIssue {
                            fixControl
                            Button("Ignore") { model.ignoreFinding(for: cred) }
                                .controlSize(.small)
                                .help("Hide this finding — you've reviewed and accepted it. Bring it back with 'Show ignored'.")
                        } else if isNoUsername {
                            Button("Ignore") { model.ignoreFinding(for: cred) }
                                .controlSize(.small)
                                .help("Hide this once you've reviewed it.")
                        }
                    }
                }
                if !(ignored && (hasSecurityIssue || isStray || isNoUsername)) {
                    if isCrossEcosystem {
                        Text("Saved in both Apple Passwords and a browser — these don't sync, so update both or your iPhone may keep autofilling the old password.")
                            .font(.caption).foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if isStray {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Likely a leftover save — there's no account behind a blank username, so **Fixing won't help.** Instead:")
                            Text("1. \(StaleLoginGuidance.manualSteps(for: cred.source, domain: cred.registrableDomain))")
                            Text("2. Then click **Ignore** here to clear it.")
                        }
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                        .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                    }
                    if isNoUsername {
                        Text("Saved without a username — likely captured on a reset or sign-up page. It's probably a real login (deleting would lose the password); just confirm the account before changing it.")
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

    @ViewBuilder
    private var fixControl: some View {
        if model.isFixed(cred) {
            Label("Fixed", systemImage: "checkmark.circle.fill")
                .font(.caption2.weight(.medium)).foregroundStyle(.green)
        } else if model.fixQueue.items.contains(where: { $0.credentialID == cred.id }) {
            Label("In fix queue", systemImage: "checkmark").font(.caption2).foregroundStyle(.green)
        } else {
            Button("Add to queue") { Task { await model.enqueueFix(for: cred) } }.controlSize(.small)
        }
    }
}
