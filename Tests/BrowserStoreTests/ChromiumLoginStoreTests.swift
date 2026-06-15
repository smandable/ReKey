import Testing
import Foundation
import Model
@testable import BrowserStore

@Suite("Chromium login store")
struct ChromiumLoginStoreTests {

    private func makeStore(_ rows: [TestStores.ChromiumRow], includeRealm: Bool = true) -> (ChromiumLoginStore, URL) {
        let dir = TestStores.tempDir()
        let dbURL = dir.appendingPathComponent("Login Data")
        TestStores.makeChromium(at: dbURL, includeRealm: includeRealm, rows: rows)
        return (ChromiumLoginStore(browser: .chrome, databaseURL: dbURL), dir)
    }

    private let sampleRows = [
        TestStores.ChromiumRow(origin: "https://github.com/", realm: "https://github.com/", username: "sean", created: 13_350_000_000_000_000),
        TestStores.ChromiumRow(origin: "https://github.com/", realm: "https://github.com/", username: "sean-work", created: 13_350_000_000_000_000),
        TestStores.ChromiumRow(origin: "https://example.com/", realm: "https://example.com/", username: "bob", created: 13_350_000_000_000_000),
    ]

    @Test("Validate accepts a known schema and rejects a missing column")
    func validate() throws {
        let (good, _) = makeStore(sampleRows)
        #expect(throws: Never.self) { try good.validate() }

        let (bad, _) = makeStore(sampleRows, includeRealm: false)
        #expect(throws: LoginStoreError.self) { try bad.validate() }
    }

    @Test("List returns rows and honors filters")
    func list() throws {
        let (store, _) = makeStore(sampleRows)
        #expect(try store.list(matching: LoginFilter()).count == 3)
        #expect(try store.list(matching: LoginFilter(site: "github")).count == 2)
        #expect(try store.list(matching: LoginFilter(username: "sean")).count == 1)
        let github = try store.list(matching: LoginFilter(site: "github.com"))
        #expect(github.allSatisfy { !$0.usernameIsEncrypted })
        #expect(github.first?.createdAt != nil)
    }

    @Test("Delete removes only matched rows, after backing up")
    func delete() throws {
        let (store, dir) = makeStore(sampleRows)
        let backup = dir.appendingPathComponent("backup")

        let outcome = try store.delete(matching: LoginFilter(username: "sean"), backupDirectory: backup)
        #expect(outcome.deletedCount == 1)
        #expect(outcome.deleted.first?.username == "sean")

        // Backup of the DB exists before the delete took effect.
        #expect(FileManager.default.fileExists(atPath: backup.appendingPathComponent("Login Data").path))

        // Only the matched row is gone.
        #expect(TestStores.chromiumRowCount(store.databaseURL) == 2)
        let remaining = try store.list(matching: LoginFilter()).map(\.username)
        #expect(Set(remaining) == Set(["sean-work", "bob"]))
    }

    @Test("Delete by specific rowid")
    func deleteByID() throws {
        let (store, dir) = makeStore(sampleRows)
        let all = try store.list(matching: LoginFilter())
        let targetID = try #require(all.first { $0.username == "bob" }?.id)
        let outcome = try store.delete(matching: LoginFilter(identifiers: [targetID]),
                                       backupDirectory: dir.appendingPathComponent("b"))
        #expect(outcome.deletedCount == 1)
        #expect(try store.list(matching: LoginFilter(username: "bob")).isEmpty)
        #expect(TestStores.chromiumRowCount(store.databaseURL) == 2)
    }

    @Test("Delete refuses without a filter")
    func deleteNoFilter() throws {
        let (store, dir) = makeStore(sampleRows)
        #expect(throws: LoginStoreError.noFilter) {
            _ = try store.delete(matching: LoginFilter(), backupDirectory: dir.appendingPathComponent("b"))
        }
        // Nothing deleted.
        #expect(TestStores.chromiumRowCount(store.databaseURL) == 3)
    }
}
