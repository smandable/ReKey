import SwiftUI
import Model
import AuditEngine

/// Step 2: findings, grouped by registrable domain and sorted alphabetically.
/// Flagged credentials show badges; reused passwords cluster their "shared
/// with" domains so the user fixes every site, not just one.
struct FindingsView: View {
    @Bindable var model: AppModel
    @State private var onlyIssues = true

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
        let groups = onlyIssues ? report.flaggedDomainGroups : report.domainGroups
        return ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                summary(report)

                if groups.isEmpty {
                    ContentUnavailableView(
                        onlyIssues ? "No issues found" : "No sites",
                        systemImage: "checkmark.seal",
                        description: Text(onlyIssues ? "None of your imported passwords are reused or known to be breached." : "Import some credentials first.")
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
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("Findings").font(.largeTitle.bold())
                Text("\(report.findingsByCredential.count) of \(report.credentials.count) credentials need attention across \(report.flaggedDomainGroups.count) sites.")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 8) {
                Toggle("Only issues", isOn: $onlyIssues).toggleStyle(.switch)
                Button {
                    Task { await model.enqueueAllFlagged() }
                } label: {
                    Label("Fix all", systemImage: "checkmark.shield")
                }
                .disabled(report.findingsByCredential.isEmpty)
            }
        }
    }

    private func domainSection(_ group: DomainGroup, report: AuditReport) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                Text(group.registrableDomain)
                    .font(.title3.weight(.semibold))
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
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(cred.username.isEmpty ? "(no username)" : cred.username)
                        .font(.body.weight(.medium))
                    Text(cred.rawURL).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                Text(cred.source.displayName)
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(cred.source.badgeColor.opacity(0.15), in: Capsule())
                    .foregroundStyle(cred.source.badgeColor)
                if cred.hasTOTP {
                    Image(systemName: "clock.badge.checkmark").foregroundStyle(.secondary)
                        .help("This entry also has a one-time-code (TOTP) set up.")
                }
            }

            if let finding {
                HStack(spacing: 6) {
                    FindingBadge(kind: finding.kind, breachCount: finding.breachCount)
                    if model.fixQueue.items.contains(where: { $0.credentialID == cred.id }) {
                        Label("In fix queue", systemImage: "checkmark").font(.caption2).foregroundStyle(.green)
                    } else {
                        Button("Fix this") { Task { await model.enqueueFix(for: cred) } }
                            .controlSize(.small)
                    }
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
}
