import Foundation
import Model

/// A registrable domain and the credentials grouped under it, for the findings
/// view (which lists sites alphabetically).
public struct DomainGroup: Identifiable, Sendable, Equatable {
    public var id: String { registrableDomain }
    public let registrableDomain: String
    /// Credentials under this domain, sorted by username.
    public let credentials: [ImportedCredential]
    /// Highest finding severity among this group's credentials (-1 if none),
    /// for optional severity-first sorting in the UI.
    public let highestSeverity: Int
    /// Whether any credential in this group has a finding.
    public var hasFinding: Bool { highestSeverity >= 0 }
}

/// The complete audit result the UI renders.
public struct AuditReport: Sendable {
    /// All valid imported credentials that were audited.
    public let credentials: [ImportedCredential]
    /// The single most relevant finding per credential (nil-absent = clean).
    public let findingsByCredential: [UUID: AuditFinding]
    /// Shared-password clusters for the "shared with …" UI.
    public let clusters: [ReuseCluster]
    /// Compromised status per credential (includes `.unknown`).
    public let compromised: [UUID: CompromisedStatus]
    /// Credentials reused across sites.
    public let reusedAcrossSites: Set<UUID>
    /// Credentials duplicated within a site.
    public let duplicatedWithinSite: Set<UUID>
    /// All domains, grouped, sorted alphabetically by registrable domain.
    public let domainGroups: [DomainGroup]

    /// Only the domain groups that contain at least one finding, alphabetical.
    public var flaggedDomainGroups: [DomainGroup] {
        domainGroups.filter(\.hasFinding)
    }

    /// The cluster (if any) that a given credential belongs to.
    public func cluster(for credentialID: UUID) -> ReuseCluster? {
        clusters.first { $0.credentialIDs.contains(credentialID) }
    }
}

/// Orchestrates a full audit: reuse/duplicate analysis plus the compromised
/// check, combined into per-credential findings and an alphabetical,
/// domain-grouped report.
///
/// The compromised check is injected as `any CompromiseChecking`, so the engine
/// is fully testable without a network and the concrete HIBP client is wired in
/// only at the app layer.
public struct AuditCoordinator: Sendable {
    private let checker: any CompromiseChecking

    public init(compromiseChecker: any CompromiseChecking) {
        self.checker = compromiseChecker
    }

    public func audit(credentials: [ImportedCredential]) async -> AuditReport {
        let reuse = ReuseAnalyzer.analyze(credentials)

        // Compromised check. The checker dedupes by value internally; pass all.
        var secrets: [UUID: Secret] = [:]
        for c in credentials { secrets[c.id] = c.password }
        let compromised = await checker.check(secrets)

        // Combine into one primary finding per credential.
        var findingsByCredential: [UUID: AuditFinding] = [:]
        for c in credentials {
            let status = compromised[c.id] ?? .unknown
            let isComp = status.isCompromised
            let isReused = reuse.reusedAcrossSites.contains(c.id)
            let isDup = reuse.duplicatedWithinSite.contains(c.id)

            let kind: FindingKind?
            switch (isComp, isReused, isDup) {
            case (true, true, _):   kind = .compromisedAndReused
            case (true, false, _):  kind = .compromised
            case (false, true, _):  kind = .reusedAcrossSites
            case (false, false, true): kind = .duplicatedWithinSite
            default:                kind = nil
            }

            if let kind {
                findingsByCredential[c.id] = AuditFinding(
                    kind: kind,
                    credentialIDs: [c.id],
                    breachCount: status.breachCount
                )
            }
        }

        // Group by registrable domain, alphabetical.
        let grouped = Dictionary(grouping: credentials, by: \.registrableDomain)
        let domainGroups: [DomainGroup] = grouped
            .map { (domain, creds) in
                let severity = creds
                    .compactMap { findingsByCredential[$0.id]?.kind.severity }
                    .max() ?? -1
                return DomainGroup(
                    registrableDomain: domain,
                    credentials: creds.sorted { $0.username < $1.username },
                    highestSeverity: severity
                )
            }
            .sorted { $0.registrableDomain < $1.registrableDomain }

        return AuditReport(
            credentials: credentials,
            findingsByCredential: findingsByCredential,
            clusters: reuse.clusters,
            compromised: compromised,
            reusedAcrossSites: reuse.reusedAcrossSites,
            duplicatedWithinSite: reuse.duplicatedWithinSite,
            domainGroups: domainGroups
        )
    }
}
