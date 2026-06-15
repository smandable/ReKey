import Testing
import Foundation
import Model
import ImportKit
import TestSupport
@testable import AuditEngine

/// A stub compromise checker: treats listed plaintext values as breached,
/// everything else clean. Mirrors the HIBP mock (only "password" is breached).
struct StubChecker: CompromiseChecking {
    let compromised: Set<String>
    let count: Int
    func check(_ secrets: [UUID: Secret]) async -> [UUID: CompromisedStatus] {
        secrets.mapValues { compromised.contains($0.reveal()) ? .compromised(breachCount: count) : .clean }
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
    }
}
