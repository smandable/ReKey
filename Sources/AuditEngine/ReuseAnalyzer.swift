import Foundation
import Model

/// A set of credentials that share one password value. Used to render the
/// "shared with: …" clustering so the user fixes every site that shares a
/// password, not just one.
public struct ReuseCluster: Identifiable, Sendable, Equatable {
    public let id: UUID
    public let credentialIDs: [UUID]
    /// Distinct registrable domains in this cluster, sorted.
    public let registrableDomains: [String]
    /// True when the password is shared across two or more registrable domains
    /// (the high-signal "reused across sites" case).
    public let isAcrossSites: Bool

    public init(id: UUID = UUID(), credentialIDs: [UUID], registrableDomains: [String], isAcrossSites: Bool) {
        self.id = id
        self.credentialIDs = credentialIDs
        self.registrableDomains = registrableDomains
        self.isAcrossSites = isAcrossSites
    }
}

/// Result of reuse/duplicate analysis over a set of credentials.
public struct ReuseAnalysis: Sendable, Equatable {
    /// Clusters of 2+ credentials sharing a password (across sites and/or within
    /// a site).
    public let clusters: [ReuseCluster]
    /// Credentials whose password is reused across 2+ registrable domains.
    public let reusedAcrossSites: Set<UUID>
    /// Credentials whose password is duplicated within a single registrable
    /// domain under different usernames.
    public let duplicatedWithinSite: Set<UUID>
}

/// Finds reused and duplicated passwords.
///
/// Bucketing is done by hashing each password **in memory** (SHA-256, only for
/// bucketing — not a security primitive) and comparing hashes. The plaintext and
/// the hash→credential map are never persisted.
public enum ReuseAnalyzer {

    public static func analyze(_ credentials: [ImportedCredential]) -> ReuseAnalysis {
        // Bucket credentials by the SHA-256 of their password value.
        var buckets: [Data: [ImportedCredential]] = [:]
        for c in credentials {
            buckets[c.password.sha256(), default: []].append(c)
        }

        var clusters: [ReuseCluster] = []
        var reusedAcrossSites: Set<UUID> = []
        var duplicatedWithinSite: Set<UUID> = []

        // Iterate in a stable order (by smallest credential id in each bucket) so
        // output is deterministic regardless of dictionary ordering. Sort keys
        // are computed once, not per comparison.
        let orderedGroups = buckets.values
            .map { (sortKey: $0.map(\.id.uuidString).min() ?? "", group: $0) }
            .sorted { $0.sortKey < $1.sortKey }

        for (_, group) in orderedGroups {
            guard group.count >= 2 else { continue }

            let domains = Set(group.map(\.registrableDomain))
            let acrossSites = domains.count >= 2

            // Within-site duplicate: same registrable domain, 2+ distinct usernames.
            var withinIDs: [UUID] = []
            for (_, sub) in Dictionary(grouping: group, by: \.registrableDomain) {
                let usernames = Set(sub.map(\.username))
                if sub.count >= 2 && usernames.count >= 2 {
                    withinIDs.append(contentsOf: sub.map(\.id))
                }
            }

            if acrossSites {
                reusedAcrossSites.formUnion(group.map(\.id))
            }
            duplicatedWithinSite.formUnion(withinIDs)

            if acrossSites || !withinIDs.isEmpty {
                clusters.append(ReuseCluster(
                    credentialIDs: group.map(\.id),
                    registrableDomains: domains.sorted(),
                    isAcrossSites: acrossSites
                ))
            }
        }

        return ReuseAnalysis(
            clusters: clusters,
            reusedAcrossSites: reusedAcrossSites,
            duplicatedWithinSite: duplicatedWithinSite
        )
    }
}
