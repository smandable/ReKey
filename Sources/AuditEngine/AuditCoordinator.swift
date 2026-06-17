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
    /// Credentials with a weak password (short / low-variety / common).
    public let weak: Set<UUID>
    /// Credentials whose (site, username) account is saved in BOTH an Apple store
    /// and a non-Apple (browser) store. These copies don't sync to each other, so
    /// changing one leaves the other stale — most painfully on iPhone/iPad, where
    /// autofill may come from whichever store you *didn't* update.
    public let crossEcosystemDuplicates: Set<UUID>
    /// Blank-username logins on a site that also has a named login — flagged for
    /// review: could be a leftover/partial save, or a real second account the
    /// browser stored without a username (e.g. a multi-step sign-in form). The UI
    /// offers fixing (and supplying the email) as well as deleting, not just junk.
    public let strayBlankUsername: Set<UUID>
    /// The same (site, username) account saved in 2+ different BROWSER stores
    /// (Arc/Chrome/Firefox/… — Apple↔browser is `crossEcosystemDuplicates`). These
    /// silos don't sync, so a fix in one leaves the others on the old password.
    /// Maps each such credential to the browser stores its account spans, for a
    /// "consolidate into one password manager" nudge.
    public let multiBrowserAccounts: [UUID: [BrowserSource]]
    /// All domains, grouped, sorted alphabetically by registrable domain.
    public let domainGroups: [DomainGroup]

    /// id → its reuse cluster, precomputed so `cluster(for:)` is O(1). A credential
    /// belongs to at most one cluster (clusters partition by password value).
    private let clusterIndex: [UUID: ReuseCluster]

    public init(
        credentials: [ImportedCredential],
        findingsByCredential: [UUID: AuditFinding],
        clusters: [ReuseCluster],
        compromised: [UUID: CompromisedStatus],
        reusedAcrossSites: Set<UUID>,
        duplicatedWithinSite: Set<UUID>,
        weak: Set<UUID>,
        crossEcosystemDuplicates: Set<UUID>,
        strayBlankUsername: Set<UUID>,
        multiBrowserAccounts: [UUID: [BrowserSource]],
        domainGroups: [DomainGroup]
    ) {
        self.credentials = credentials
        self.findingsByCredential = findingsByCredential
        self.clusters = clusters
        self.compromised = compromised
        self.reusedAcrossSites = reusedAcrossSites
        self.duplicatedWithinSite = duplicatedWithinSite
        self.weak = weak
        self.crossEcosystemDuplicates = crossEcosystemDuplicates
        self.strayBlankUsername = strayBlankUsername
        self.multiBrowserAccounts = multiBrowserAccounts
        self.domainGroups = domainGroups
        // Precompute id → cluster. The old per-call linear scan of every cluster
        // made prioritized sorting and per-row "shared with" lookups O(n²)+, which
        // froze the UI at thousands of credentials.
        var index: [UUID: ReuseCluster] = [:]
        for cluster in clusters {
            for id in cluster.credentialIDs { index[id] = cluster }
        }
        self.clusterIndex = index
    }

    /// Only the domain groups that contain at least one finding, alphabetical.
    public var flaggedDomainGroups: [DomainGroup] {
        domainGroups.filter(\.hasFinding)
    }

    /// Domain groups sorted **worst-first**: highest severity, then biggest reuse
    /// cluster, then important domains, then alphabetical. For the priority view.
    public var prioritizedDomainGroups: [DomainGroup] {
        domainGroups.sorted { a, b in
            if a.highestSeverity != b.highestSeverity { return a.highestSeverity > b.highestSeverity }
            let ca = maxClusterSize(for: a), cb = maxClusterSize(for: b)
            if ca != cb { return ca > cb }
            let ia = DomainPriority.isImportant(a.registrableDomain) ? 1 : 0
            let ib = DomainPriority.isImportant(b.registrableDomain) ? 1 : 0
            if ia != ib { return ia > ib }
            return a.registrableDomain < b.registrableDomain
        }
    }

    /// Size of the largest reuse cluster any credential in `group` belongs to.
    public func maxClusterSize(for group: DomainGroup) -> Int {
        group.credentials.compactMap { cluster(for: $0.id)?.credentialIDs.count }.max() ?? 0
    }

    /// The cluster (if any) that a given credential belongs to. O(1).
    public func cluster(for credentialID: UUID) -> ReuseCluster? {
        clusterIndex[credentialID]
    }
}

/// A coarse progress signal emitted while an audit runs, so the UI can show a
/// determinate bar and phase label instead of an indeterminate spinner.
///
/// The compromised check dominates the wall-clock time (one network round-trip
/// per distinct password), so its phase carries a `done`/`total` count; the
/// surrounding analysis/grouping phases are fast and unmeasured.
public struct AuditProgress: Sendable, Equatable {
    public enum Phase: Sendable, Equatable {
        /// Local reuse/duplicate analysis (fast).
        case analyzing
        /// Checking passwords against Have I Been Pwned. `done` of `total`
        /// distinct password ranges have resolved; `total == 0` means nothing
        /// needed fetching (e.g. all cached or all blank).
        case checkingCompromise(done: Int, total: Int)
        /// Scoring weakness and grouping the report (fast).
        case finalizing
    }
    public let phase: Phase
    public init(phase: Phase) { self.phase = phase }
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

    /// - Parameter onProgress: invoked as the audit advances through its phases.
    ///   May be called from any thread; defaults to a no-op.
    public func audit(
        credentials: [ImportedCredential],
        onProgress: @Sendable (AuditProgress) -> Void = { _ in }
    ) async -> AuditReport {
        onProgress(AuditProgress(phase: .analyzing))
        let reuse = ReuseAnalyzer.analyze(credentials)

        // Compromised check. The checker dedupes by value internally; pass all.
        var secrets: [UUID: Secret] = [:]
        for c in credentials { secrets[c.id] = c.password }
        let compromised = await checker.check(secrets) { done, total in
            onProgress(AuditProgress(phase: .checkingCompromise(done: done, total: total)))
        }

        onProgress(AuditProgress(phase: .finalizing))

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

        // Weak-password scan (independent of reuse/compromise).
        var weak: Set<UUID> = []
        for c in credentials where PasswordStrength.isWeak(c.password) { weak.insert(c.id) }

        // Cross-ecosystem duplicates: the same (site, username) account saved in
        // both an Apple store and a non-Apple store. These don't sync to each
        // other, so a fix in one place won't reach the other (notably on iOS).
        var crossEcosystem: Set<UUID> = []
        for (_, group) in Dictionary(grouping: credentials, by: { "\($0.registrableDomain)|\($0.username)" }) {
            let hasApple = group.contains { $0.source.isApple }
            let hasNonApple = group.contains { !$0.source.isApple }
            if hasApple && hasNonApple { crossEcosystem.formUnion(group.map(\.id)) }
        }

        // Stray blank-username entries: a login with no username on a site that
        // also has a real (named) login — likely a leftover save to delete.
        var strayBlank: Set<UUID> = []
        for (_, group) in Dictionary(grouping: credentials, by: \.registrableDomain) {
            guard group.contains(where: { !$0.username.isEmpty }) else { continue }
            for c in group where c.username.isEmpty { strayBlank.insert(c.id) }
        }

        // Same account saved across 2+ different browsers (non-Apple silos that
        // don't sync). Map each such credential to the browser stores its account
        // spans, so the UI can nudge "consolidate into one password manager".
        var multiBrowser: [UUID: [BrowserSource]] = [:]
        for (_, group) in Dictionary(grouping: credentials, by: { "\($0.registrableDomain)|\($0.username)" }) {
            let browsers = Set(group.map(\.source).filter { !$0.isApple })
            guard browsers.count >= 2 else { continue }
            let sorted = browsers.sorted { $0.displayName < $1.displayName }
            for c in group where !c.source.isApple { multiBrowser[c.id] = sorted }
        }

        // A credential's issue severity = its finding severity, or 0 if it's only
        // weak (low priority but still flagged), or -1 if clean.
        func severity(of id: UUID) -> Int {
            let finding = findingsByCredential[id]?.kind.severity ?? -1
            let weakSeverity = weak.contains(id) ? 0 : -1
            return max(finding, weakSeverity)
        }

        // Group by registrable domain, alphabetical.
        let grouped = Dictionary(grouping: credentials, by: \.registrableDomain)
        let domainGroups: [DomainGroup] = grouped
            .map { (domain, creds) in
                let highest = creds.map { severity(of: $0.id) }.max() ?? -1
                return DomainGroup(
                    registrableDomain: domain,
                    credentials: creds.sorted { $0.username < $1.username },
                    highestSeverity: highest
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
            weak: weak,
            crossEcosystemDuplicates: crossEcosystem,
            strayBlankUsername: strayBlank,
            multiBrowserAccounts: multiBrowser,
            domainGroups: domainGroups
        )
    }
}
