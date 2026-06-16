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
        let groups = onlyIssues ? base.filter(\.hasFinding) : base
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
        return HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Findings").font(.largeTitle.bold())
                Text("\(report.findingsByCredential.count) reused/compromised · \(report.weak.count) weak · across \(report.flaggedDomainGroups.count) sites.")
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
                Button { Task { await model.enqueueAllFlagged() } } label: {
                    Label("Fix all", systemImage: "checkmark.shield")
                }
                .disabled(report.findingsByCredential.isEmpty)
            }
        }
    }

    private func domainSection(_ group: DomainGroup, report: AuditReport) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                Text(group.registrableDomain).font(.title3.weight(.semibold))
                ForEach(group.credentials) { cred in
                    credentialRow(cred, report: report)
                    if cred.id != group.credentials.last?.id { Divider() }
                }
            }
            .padding(8)
        }
    }

    private func credentialRow(_ cred: ImportedCredential, report: AuditReport) -> some View {
        let finding = report.findingsByCredential[cred.id]
        let isWeak = report.weak.contains(cred.id)
        let hasIssue = finding != nil || isWeak
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(cred.username.isEmpty ? "(no username)" : cred.username).font(.body.weight(.medium))
                    Text(cred.rawURL).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                BrowserSourcePill(source: cred.source)
                if cred.hasTOTP {
                    Image(systemName: "clock.badge.checkmark").foregroundStyle(.secondary)
                        .help("This entry also has a one-time-code (TOTP) set up.")
                }
            }

            if hasIssue {
                HStack(spacing: 6) {
                    if let finding {
                        FindingBadge(kind: finding.kind, breachCount: finding.breachCount)
                    }
                    if isWeak {
                        PillBadge(icon: "exclamationmark.shield.fill", text: "Weak", color: .yellow)
                    }
                    Spacer()
                    fixControl(for: cred)
                }
                if let cluster = report.cluster(for: cred.id), cluster.isAcrossSites {
                    let others = cluster.registrableDomains.filter { $0 != cred.registrableDomain }
                    if !others.isEmpty {
                        Text("Shared with: \(others.joined(separator: ", "))")
                            .font(.caption).foregroundStyle(.orange)
                    }
                }
            }
        }
        .padding(.vertical, 2)
    }

    @ViewBuilder
    private func fixControl(for cred: ImportedCredential) -> some View {
        if model.isFixed(cred) {
            Label("Fixed", systemImage: "checkmark.circle.fill")
                .font(.caption2.weight(.medium)).foregroundStyle(.green)
        } else if model.fixQueue.items.contains(where: { $0.credentialID == cred.id }) {
            Label("In fix queue", systemImage: "checkmark").font(.caption2).foregroundStyle(.green)
        } else {
            Button("Fix this") { Task { await model.enqueueFix(for: cred) } }.controlSize(.small)
        }
    }
}
