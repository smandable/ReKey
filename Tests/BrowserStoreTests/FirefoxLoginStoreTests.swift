import Testing
import Foundation
import Model
@testable import BrowserStore

@Suite("Firefox login store")
struct FirefoxLoginStoreTests {

    private func makeStore(version: Int = 3) -> (FirefoxLoginStore, URL) {
        let dir = TestStores.tempDir()
        let url = dir.appendingPathComponent("logins.json")
        TestStores.makeFirefox(at: url, version: version, logins: [
            TestStores.firefoxLogin(guid: "{aaaa-1111}", host: "https://github.com"),
            TestStores.firefoxLogin(guid: "{bbbb-2222}", host: "https://example.com"),
        ])
        return (FirefoxLoginStore(loginsURL: url), dir)
    }

    @Test("Validate accepts v3 and rejects an unknown version")
    func validate() throws {
        let (good, _) = makeStore()
        #expect(throws: Never.self) { try good.validate() }
        let (bad, _) = makeStore(version: 99)
        #expect(throws: LoginStoreError.self) { try bad.validate() }
    }

    @Test("List maps host/guid; usernames are encrypted (not shown)")
    func list() throws {
        let (store, _) = makeStore()
        let all = try store.list(matching: LoginFilter())
        #expect(all.count == 2)
        #expect(all.allSatisfy { $0.usernameIsEncrypted && $0.username == nil })
        let github = try store.list(matching: LoginFilter(site: "github"))
        #expect(github.count == 1)
        #expect(github.first?.id == "{aaaa-1111}")
        #expect(github.first?.createdAt != nil)
    }

    @Test("Delete removes only the matched login and preserves all other data")
    func delete() throws {
        let (store, dir) = makeStore()
        let backup = dir.appendingPathComponent("backup")

        let outcome = try store.delete(matching: LoginFilter(identifiers: ["{aaaa-1111}"]),
                                       backupDirectory: backup)
        #expect(outcome.deletedCount == 1)
        #expect(FileManager.default.fileExists(atPath: backup.appendingPathComponent("logins.json").path))

        // Only github is gone.
        let remaining = try store.list(matching: LoginFilter())
        #expect(remaining.map(\.id) == ["{bbbb-2222}"])

        // Unknown top-level keys and per-login fields survived.
        let root = TestStores.readFirefoxRoot(store.loginsURL)
        #expect(root["potentiallyVulnerablePasswords"] != nil)
        #expect(root["dismissedBreachAlertsByLoginGUID"] != nil)
        #expect((root["version"] as? Int) == 3)
        let logins = root["logins"] as? [[String: Any]] ?? []
        #expect(logins.count == 1)
        #expect((logins.first?["customUnknownField"] as? String) == "keep-me")
        #expect((logins.first?["encryptedPassword"] as? String) != nil)
    }

    @Test("A guid-less entry is never collaterally deleted when matching by site")
    func guidlessNotCollateral() throws {
        let dir = TestStores.tempDir()
        let url = dir.appendingPathComponent("logins.json")
        var guidless = TestStores.firefoxLogin(guid: "", host: "https://github.com")
        guidless["guid"] = ""   // malformed: empty guid, same host as a real entry
        TestStores.makeFirefox(at: url, logins: [
            TestStores.firefoxLogin(guid: "{real-guid}", host: "https://github.com"),
            guidless,
        ])
        let store = FirefoxLoginStore(loginsURL: url)

        // Deleting by site matches BOTH, but only the entry with a real guid is
        // removed; the guid-less one survives (can't be uniquely targeted).
        let outcome = try store.delete(matching: LoginFilter(site: "github"),
                                       backupDirectory: dir.appendingPathComponent("b"))
        #expect(outcome.deletedCount == 1)
        #expect(outcome.deleted.first?.id == "{real-guid}")

        let logins = TestStores.readFirefoxRoot(url)["logins"] as? [[String: Any]] ?? []
        #expect(logins.count == 1)
        #expect((logins.first?["guid"] as? String) == "")   // the guid-less one remains
    }

    @Test("A duplicate non-empty guid doesn't collaterally delete a non-matching sibling")
    func duplicateGuidNoCollateral() throws {
        let dir = TestStores.tempDir()
        let url = dir.appendingPathComponent("logins.json")
        // A corrupt store: two entries share guid "{dup}" — one on github (matches
        // --site github), one on example.com (does NOT).
        TestStores.makeFirefox(at: url, logins: [
            TestStores.firefoxLogin(guid: "{dup}", host: "https://github.com"),
            TestStores.firefoxLogin(guid: "{dup}", host: "https://example.com"),
        ])
        let store = FirefoxLoginStore(loginsURL: url)

        let outcome = try store.delete(matching: LoginFilter(site: "github"),
                                       backupDirectory: dir.appendingPathComponent("b"))
        #expect(outcome.deletedCount == 1)                        // only the matching entry
        let logins = TestStores.readFirefoxRoot(url)["logins"] as? [[String: Any]] ?? []
        #expect(logins.count == 1)
        #expect((logins.first?["hostname"] as? String) == "https://example.com")  // sibling survives
    }

    @Test("Validate rejects a JSON with version+logins that isn't a Firefox store (no nextId)")
    func validateRejectsNonFirefoxJSON() throws {
        let dir = TestStores.tempDir()
        let url = dir.appendingPathComponent("notes.json")
        try Data(#"{"version":3,"logins":[]}"#.utf8).write(to: url)
        #expect(throws: LoginStoreError.self) {
            try FirefoxLoginStore(loginsURL: url).validate()
        }
    }

    @Test("Version 2 is accepted: validate/list/delete all work")
    func version2() throws {
        let (store, dir) = makeStore(version: 2)
        #expect(throws: Never.self) { try store.validate() }
        #expect(try store.list(matching: LoginFilter()).count == 2)
        let outcome = try store.delete(matching: LoginFilter(site: "github"),
                                       backupDirectory: dir.appendingPathComponent("b"))
        #expect(outcome.deletedCount == 1)
    }

    @Test("Backup failure aborts the delete (file untouched)")
    func backupFailureAborts() throws {
        let (store, dir) = makeStore()
        // Pre-create a NON-empty backup dir so StoreBackup.copy refuses it.
        let backup = dir.appendingPathComponent("backup")
        try FileManager.default.createDirectory(at: backup, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: backup.appendingPathComponent("occupied"))

        let before = try Data(contentsOf: store.loginsURL)
        #expect(throws: LoginStoreError.self) {
            _ = try store.delete(matching: LoginFilter(site: "github"), backupDirectory: backup)
        }
        // The store must be untouched when backup fails.
        #expect(try Data(contentsOf: store.loginsURL) == before)
    }

    @Test("Delete refuses without a filter; file untouched")
    func deleteNoFilter() throws {
        let (store, dir) = makeStore()
        let before = try Data(contentsOf: store.loginsURL)
        #expect(throws: LoginStoreError.noFilter) {
            _ = try store.delete(matching: LoginFilter(), backupDirectory: dir.appendingPathComponent("b"))
        }
        let after = try Data(contentsOf: store.loginsURL)
        #expect(before == after)
    }
}
