import Testing
import Foundation
import Model
@testable import ReKeyUI

/// A simple openable gate for deterministic async coordination in tests.
private actor Gate {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func open() {
        isOpen = true
        for w in waiters { w.resume() }
        waiters.removeAll()
    }
    func wait() async {
        if isOpen { return }
        await withCheckedContinuation { waiters.append($0) }
    }
}

/// A compromise checker that signals when it starts and blocks until released, so
/// a test can hold an audit "in flight" while it mutates state.
private struct GatedChecker: CompromiseChecking {
    let entered: Gate
    let release: Gate
    func check(_ secrets: [UUID: Secret]) async -> [UUID: CompromisedStatus] {
        await entered.open()   // tell the test the audit is mid-check
        await release.wait()   // block until the test lets it finish
        return secrets.mapValues { _ in .clean }
    }
}

@MainActor
@Suite("Audit / import race", .serialized)
struct AuditRaceTests {
    private let csvA = "name,url,username,password,note\nA,https://a-site.com/,u,Pw-AAAA-1!,\n"
    private let csvB = "name,url,username,password,note\nB,https://b-site.com/,u,Pw-BBBB-2!,\n"

    @Test("An import during an audit discards the stale audit result")
    func staleAuditDiscardedAfterImport() async {
        let entered = Gate(), release = Gate()
        AppModel.compromiseCheckerOverride = GatedChecker(entered: entered, release: release)
        defer { AppModel.compromiseCheckerOverride = nil }

        let model = AppModel()
        model.importData(Data(csvA.utf8), displayName: "a.csv")
        #expect(model.report == nil)

        model.startAudit()
        await entered.wait()                                   // audit is blocked mid-check

        // A concurrent import changes the credentials and invalidates the audit.
        model.importData(Data(csvB.utf8), displayName: "b.csv")
        await release.open()                                         // let the stale audit run on
        await model.awaitAuditForTesting()

        // The stale audit must NOT have written a report over the invalidated state.
        #expect(model.report == nil)
        #expect(!model.isAuditing)
    }

    @Test("A normal audit (no concurrent import) writes the report")
    func normalAuditWritesReport() async {
        let entered = Gate(), release = Gate()
        AppModel.compromiseCheckerOverride = GatedChecker(entered: entered, release: release)
        defer { AppModel.compromiseCheckerOverride = nil }

        let model = AppModel()
        model.importData(Data(csvA.utf8), displayName: "a.csv")
        model.startAudit()
        await entered.wait()
        await release.open()
        await model.awaitAuditForTesting()

        #expect(model.report != nil)
        #expect(model.section == .findings)
        #expect(!model.isAuditing)
    }
}
