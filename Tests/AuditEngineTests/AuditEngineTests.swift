import Testing
import Foundation
import Model
import ImportKit
import Synchronization
import TestSupport
@testable import AuditEngine

/// A stub compromise checker: treats listed plaintext values as breached,
/// everything else clean. Mirrors the HIBP mock (only "password" is breached).
///
/// Implements only `check(_:)`, so it exercises the default (no-op) progress
/// path of `CompromiseChecking`.
struct StubChecker: CompromiseChecking {
    let compromised: Set<String>
    let count: Int
    func check(_ secrets: [UUID: Secret]) async -> [UUID: CompromisedStatus] {
        secrets.mapValues { compromised.contains($0.reveal()) ? .compromised(breachCount: count) : .clean }
    }
}

/// A checker that DOES report progress, so the coordinator's forwarding of the
/// compromised-check phase can be observed.
struct ProgressStubChecker: CompromiseChecking {
    func check(_ secrets: [UUID: Secret]) async -> [UUID: CompromisedStatus] {
        secrets.mapValues { _ in .clean }
    }
    func check(
        _ secrets: [UUID: Secret],
        onProgress: @Sendable (Int, Int) -> Void
    ) async -> [UUID: CompromisedStatus] {
        onProgress(0, 2)
        onProgress(1, 2)
        onProgress(2, 2)
        return await check(secrets)
    }
}

@Suite("Audit over the merged four-browser import")
struct AuditEngineTests {

    /// Import all four fixtures and merge their credentials (the app audits
    /// every source together).
    func mergedCredentials() throws -> [ImportedCredential] {
        let importer = CSVImporter()
        var all: [ImportedCredential] = []
        all += try importer.import(data: Fixtures.data("chrome.csv")).credentials
        all += try importer.import(data: Fixtures.data("arc.csv"), chromiumSource: .arc).credentials
        all += try importer.import(data: Fixtures.data("firefox.csv")).credentials
        all += try importer.import(data: Fixtures.data("apple_passwords.csv")).credentials
        return all
    }

    func report() async throws -> AuditReport {
        let creds = try mergedCredentials()
        let coordinator = AuditCoordinator(compromiseChecker: StubChecker(compromised: ["password"], count: 99999))
        return await coordinator.audit(credentials: creds)
    }

    private func id(_ r: AuditReport, _ domain: String, _ username: String) -> UUID? {
        r.credentials.first { $0.registrableDomain == domain && $0.username == username }?.id
    }

    // MARK: - Progress

    @Test("Progress phases run analyzing → compromised-check → finalizing, in order")
    func progressPhasesInOrder() async throws {
        let creds = try mergedCredentials()
        let coordinator = AuditCoordinator(compromiseChecker: ProgressStubChecker())
        let phases = Mutex<[AuditProgress.Phase]>([])
        _ = await coordinator.audit(credentials: creds) { progress in
            phases.withLock { $0.append(progress.phase) }
        }

        let recorded = phases.withLock { $0 }
        #expect(recorded.first == .analyzing)
        #expect(recorded.last == .finalizing)
        #expect(recorded.contains(.checkingCompromise(done: 2, total: 2)))
        // analyzing strictly precedes the compromise ticks, which precede finalizing.
        let analyzingIdx = recorded.firstIndex(of: .analyzing)
        let finalizingIdx = recorded.firstIndex(of: .finalizing)
        let compIdx = recorded.firstIndex { if case .checkingCompromise = $0 { return true }; return false }
        #expect(analyzingIdx != nil && finalizingIdx != nil && compIdx != nil)
        if let a = analyzingIdx, let c = compIdx, let f = finalizingIdx {
            #expect(a < c && c < f)
        }
    }

    @Test("A checker without progress support still reports analyzing + finalizing")
    func progressFallbackForNonReportingChecker() async throws {
        let creds = try mergedCredentials()
        let coordinator = AuditCoordinator(compromiseChecker: StubChecker(compromised: [], count: 0))
        let phases = Mutex<[AuditProgress.Phase]>([])
        _ = await coordinator.audit(credentials: creds) { progress in
            phases.withLock { $0.append(progress.phase) }
        }
        // StubChecker uses the default no-op progress path, so no compromise tick
        // is emitted — only the coordinator's own bookend phases.
        #expect(phases.withLock { $0 } == [.analyzing, .finalizing])
    }

    // MARK: - Cluster lookup (O(1) index)

    @Test("cluster(for:) returns the shared-password cluster for members, nil for uniques")
    func clusterLookup() async {
        func cred(_ domain: String, pw: String) -> ImportedCredential {
            ImportedCredential(source: .chrome, title: nil, rawURL: "https://\(domain)/",
                               registrableDomain: domain, username: "u",
                               password: Secret(pw), notes: nil, hasTOTP: false)
        }
        let a = cred("a.com", pw: "shared-PW")     // ┐ same password across two sites
        let b = cred("b.com", pw: "shared-PW")     // ┘ → one cross-site reuse cluster
        let solo = cred("c.com", pw: "unique-PW")  // not reused → no cluster

        let coordinator = AuditCoordinator(compromiseChecker: StubChecker(compromised: [], count: 0))
        let r = await coordinator.audit(credentials: [a, b, solo])

        let clusterA = r.cluster(for: a.id)
        #expect(clusterA != nil)
        #expect(Set(clusterA?.credentialIDs ?? []) == [a.id, b.id])   // both members → same cluster
        #expect(r.cluster(for: b.id)?.id == clusterA?.id)
        #expect(r.cluster(for: solo.id) == nil)                       // unique password → nil
    }

    // MARK: - Cross-ecosystem duplicates

    @Test("Flags accounts saved in BOTH an Apple and a non-Apple store; nothing else")
    func crossEcosystemDuplicates() async {
        func cred(_ source: BrowserSource, _ domain: String, _ user: String) -> ImportedCredential {
            ImportedCredential(source: source, title: nil, rawURL: "https://\(domain)/",
                               registrableDomain: domain, username: user,
                               password: Secret(UUID().uuidString), notes: nil, hasTOTP: false)
        }
        let appleChase  = cred(.applePasswords, "chase.com", "me@x.com")   // ┐ same account,
        let chromeChase = cred(.chrome,         "chase.com", "me@x.com")   // ┘ Apple + browser → flagged
        let chromeOnly  = cred(.chrome,         "github.com", "me@x.com")  // browser only → not
        let appleOnly   = cred(.applePasswords, "icloud.com", "me@x.com")  // Apple only → not
        let arcChase    = cred(.arc,            "chase.com", "other@x.com")// different username → not
        let ffReddit    = cred(.firefox,        "reddit.com", "u")         // ┐ both non-Apple →
        let chromeReddit = cred(.chrome,        "reddit.com", "u")         // ┘ not cross-ecosystem

        let coordinator = AuditCoordinator(compromiseChecker: StubChecker(compromised: [], count: 0))
        let r = await coordinator.audit(credentials: [
            appleChase, chromeChase, chromeOnly, appleOnly, arcChase, ffReddit, chromeReddit,
        ])

        #expect(r.crossEcosystemDuplicates == [appleChase.id, chromeChase.id])
    }

    @Test("Flags an account saved across 2+ browsers; Apple-only pairings don't count")
    func multiBrowserAccounts() async {
        func cred(_ source: BrowserSource, _ domain: String, _ user: String) -> ImportedCredential {
            ImportedCredential(source: source, title: nil, rawURL: "https://\(domain)/",
                               registrableDomain: domain, username: user,
                               password: Secret(UUID().uuidString), notes: nil, hasTOTP: false)
        }
        let arcGH    = cred(.arc,     "github.com", "sean")   // ┐ same account in 3 browsers
        let chromeGH = cred(.chrome,  "github.com", "sean")   // │ → all flagged, span = 3
        let ffGH     = cred(.firefox, "github.com", "sean")   // ┘
        let soloArc  = cred(.arc,     "solo.com",   "sean")   // one browser → not flagged
        let appleX   = cred(.applePasswords, "x.com", "sean") // ┐ Apple + 1 browser → cross-eco,
        let chromeX  = cred(.chrome,         "x.com", "sean") // ┘ only 1 non-Apple → not multi-browser

        let coordinator = AuditCoordinator(compromiseChecker: StubChecker(compromised: [], count: 0))
        let r = await coordinator.audit(credentials: [arcGH, chromeGH, ffGH, soloArc, appleX, chromeX])

        for c in [arcGH, chromeGH, ffGH] {
            #expect(r.multiBrowserAccounts[c.id]?.count == 3)
        }
        #expect(r.multiBrowserAccounts[soloArc.id] == nil)
        #expect(r.multiBrowserAccounts[chromeX.id] == nil)   // Apple+Chrome is cross-eco, not multi-browser
        #expect(r.multiBrowserAccounts[appleX.id] == nil)
    }

    @Test("Flags a blank-username login only when the site also has a real one")
    func strayBlankUsername() async {
        func cred(_ source: BrowserSource, _ domain: String, _ user: String) -> ImportedCredential {
            ImportedCredential(source: source, title: nil, rawURL: "https://\(domain)/",
                               registrableDomain: domain, username: user,
                               password: Secret(UUID().uuidString), notes: nil, hasTOTP: false)
        }
        let blankWithReal = cred(.arc,    "bestbuy.com", "")          // stray: real sibling exists
        let realBestbuy   = cred(.arc,    "bestbuy.com", "me@x.com")
        let blankAlone    = cred(.chrome, "example.com", "")          // blank but no real sibling → not stray
        let normal        = cred(.chrome, "github.com", "me@x.com")

        let coordinator = AuditCoordinator(compromiseChecker: StubChecker(compromised: [], count: 0))
        let r = await coordinator.audit(credentials: [blankWithReal, realBestbuy, blankAlone, normal])

        #expect(r.strayBlankUsername == [blankWithReal.id])
    }

    @Test("12 credentials across 8 registrable domains, alphabetical")
    func grouping() async throws {
        let r = try await report()
        #expect(r.credentials.count == 12)
        #expect(r.domainGroups.map(\.registrableDomain) == [
            "example.com", "example.io", "example.org", "example.tv",
            "figma.com", "github.com", "gitlab.com", "reddit.com",
        ])
        // example.com clusters three subdomains (root, forum, bank).
        #expect(r.domainGroups.first { $0.registrableDomain == "example.com" }?.credentials.count == 3)
    }

    @Test("Reused across sites: Tr0ub4dour&3, hunter2, password")
    func reusedAcrossSites() async throws {
        let r = try await report()
        // 9 credentials are reused across sites.
        #expect(r.reusedAcrossSites.count == 9)
        // Tr0ub4dour&3 on github.com (x2) and example.com(bank).
        #expect(r.reusedAcrossSites.contains(try #require(id(r, "github.com", "sean"))))
        #expect(r.reusedAcrossSites.contains(try #require(id(r, "github.com", "sean-work"))))
        #expect(r.reusedAcrossSites.contains(try #require(id(r, "example.com", "sean"))))   // bank
        // hunter2 cross-browser: example.com root + example.org.
        #expect(r.reusedAcrossSites.contains(try #require(id(r, "example.com", "user@example.com"))))
        #expect(r.reusedAcrossSites.contains(try #require(id(r, "example.org", "user@example.org"))))
    }

    @Test("Duplicated within a site: github.com under two usernames")
    func duplicatedWithinSite() async throws {
        let r = try await report()
        let gh1 = try #require(id(r, "github.com", "sean"))
        let gh2 = try #require(id(r, "github.com", "sean-work"))
        #expect(r.duplicatedWithinSite == Set([gh1, gh2]))
    }

    @Test("A within-site duplicate masked by a higher-severity finding survives in the set")
    func withinSiteDupSurvivesMasking() async throws {
        let r = try await report()
        let gh1 = try #require(id(r, "github.com", "sean"))
        // Its PRIMARY finding is the higher-severity reuse, which previously hid
        // the within-site-duplicate kind entirely…
        #expect(r.findingsByCredential[gh1]?.kind == .reusedAcrossSites)
        // …but the within-site-duplicate signal is NOT lost — it stays in the set,
        // which the Findings UI now surfaces as a secondary "Duplicate on site" badge.
        #expect(r.duplicatedWithinSite.contains(gh1))
    }

    @Test("Compromised: every 'password' entry across all four sources")
    func compromised() async throws {
        let r = try await report()
        let passwordCreds = [
            try #require(id(r, "reddit.com", "seanm")),
            try #require(id(r, "figma.com", "sean@icloud.com")),
            try #require(id(r, "example.com", "seanm")),         // forum
            try #require(id(r, "example.tv", "sean@icloud.com")), // watch
        ]
        for c in passwordCreds {
            #expect(r.compromised[c] == .compromised(breachCount: 99999))
            // password is reused across 4 domains too -> compromisedAndReused.
            #expect(r.findingsByCredential[c]?.kind == .compromisedAndReused)
            #expect(r.findingsByCredential[c]?.breachCount == 99999)
        }
    }

    @Test("Finding kinds: reuse vs compromise vs clean")
    func findingKinds() async throws {
        let r = try await report()
        // github.com/sean: reused (and a within-site dup) but not compromised.
        #expect(r.findingsByCredential[try #require(id(r, "github.com", "sean"))]?.kind == .reusedAcrossSites)
        // Clean, unique passwords have no finding.
        #expect(r.findingsByCredential[try #require(id(r, "gitlab.com", "sean"))] == nil)
        #expect(r.findingsByCredential[try #require(id(r, "example.io", "sean"))] == nil)
        #expect(r.findingsByCredential[try #require(id(r, "example.org", "buyer@example.org"))] == nil) // unicode pw, unique
    }

    @Test("Clusters surface the shared-with domains")
    func clusters() async throws {
        let r = try await report()
        // The password cluster spans four registrable domains.
        let pwCluster = r.clusters.first { $0.registrableDomains.contains("figma.com") }
        #expect(pwCluster?.isAcrossSites == true)
        #expect(pwCluster?.registrableDomains == ["example.com", "example.tv", "figma.com", "reddit.com"])
        // 3 clusters total (Tr0ub4dour&3, hunter2, password); singletons excluded.
        #expect(r.clusters.count == 3)
    }

    @Test("Unknown compromise status never crashes and yields no compromised finding")
    func unknownStatus() async throws {
        let creds = try mergedCredentials()
        struct OfflineChecker: CompromiseChecking {
            func check(_ secrets: [UUID: Secret]) async -> [UUID: CompromisedStatus] {
                secrets.mapValues { _ in .unknown }
            }
        }
        let r = await AuditCoordinator(compromiseChecker: OfflineChecker()).audit(credentials: creds)
        // No compromised findings, but reuse findings still present.
        #expect(r.findingsByCredential.values.allSatisfy { $0.kind != .compromised && $0.kind != .compromisedAndReused })
        #expect(r.reusedAcrossSites.count == 9)
        // And the run is reported as INCOMPLETE — every credential is unknown, so
        // "no compromised finding" mustn't read as a clean bill of health.
        #expect(r.breachCheckUnknown == Set(creds.map(\.id)))
    }

    @Test("A fully-checked run reports no unknown breach statuses")
    func noUnknownWhenChecked() async throws {
        let r = try await report()   // StubChecker returns a definitive status for every entry
        #expect(r.breachCheckUnknown.isEmpty)
    }
}
