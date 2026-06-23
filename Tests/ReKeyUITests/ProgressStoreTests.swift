import Testing
import Foundation
@testable import ReKeyUI

@MainActor
@Suite("Progress store", .serialized)
struct ProgressStoreTests {
    private let suite = "rekey.progressstore.test"
    private func freshDefaults() -> UserDefaults {
        let d = UserDefaults(suiteName: suite)!
        d.removePersistentDomain(forName: suite)
        return d
    }
    private let recordKey: (String, String) -> String = { "\($0)::\($1)" }

    @Test("Round-trips every collection")
    func roundTrip() {
        let d = freshDefaults()
        var s = ProgressState()
        s.completed = ["a|x", "b|y"]
        s.skipped = ["s|1"]
        s.ignored = ["i|1"]
        s.deletion = ["c|z"]
        s.saveRecords = ["rk1": FixSaveRecord(progressKey: "a|x", oldHash: "O", newHash: "N", source: "chrome")]
        s.usernameOverrides = ["chrome|site": "me@x.com"]
        ProgressStore.save(s, to: d)

        let loaded = ProgressStore.load(from: d, recordKey: recordKey)
        #expect(loaded.completed == ["a|x", "b|y"])
        #expect(loaded.skipped == ["s|1"])
        #expect(loaded.ignored == ["i|1"])
        #expect(loaded.deletion == ["c|z"])
        #expect(loaded.saveRecords["rk1"]?.oldHash == "O")
        #expect(loaded.saveRecords["rk1"]?.newHash == "N")
        #expect(loaded.saveRecords["rk1"]?.source == "chrome")
        #expect(loaded.usernameOverrides["chrome|site"] == "me@x.com")
    }

    @Test("A future schema version yields an empty state (not misread)")
    func futureSchema() {
        let d = freshDefaults()
        var s = ProgressState(); s.completed = ["a|x"]
        ProgressStore.save(s, to: d)
        d.set(999, forKey: ProgressStore.schemaKey)
        #expect(ProgressStore.load(from: d, recordKey: recordKey).completed.isEmpty)
    }

    @Test("Legacy 3-element save records migrate through recordKey")
    func legacyMigration() {
        let d = freshDefaults()
        // Old format: the dictionary KEY was the progressKey, value [old, new, source].
        d.set(["acct|x": ["OLD", "NEW", "firefox"]], forKey: ProgressStore.saveRecordsKey)
        d.set(ProgressStore.schemaVersion, forKey: ProgressStore.schemaKey)

        let loaded = ProgressStore.load(from: d, recordKey: recordKey)
        let rk = recordKey("acct|x", "firefox")   // "acct|x::firefox"
        #expect(loaded.saveRecords[rk]?.progressKey == "acct|x")
        #expect(loaded.saveRecords[rk]?.oldHash == "OLD")
        #expect(loaded.saveRecords[rk]?.source == "firefox")
    }
}
