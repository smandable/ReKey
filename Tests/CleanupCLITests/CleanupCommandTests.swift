import Testing
import Foundation
import SQLite3
import Model
import BrowserStore
@testable import CleanupCLI

/// Build synthetic Chromium "Login Data" stores in a temp dir and inspect them.
private enum Store {
    struct Row { let origin: String; let username: String }

    static func make(_ rows: [Row]) -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("rekey-cli-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("Login Data")
        var db: OpaquePointer?
        sqlite3_open(url.path, &db); defer { sqlite3_close(db) }
        sqlite3_exec(db, """
            CREATE TABLE logins (origin_url TEXT, signon_realm TEXT, username_value TEXT,
            password_value BLOB, date_created INTEGER, date_last_used INTEGER);
            """, nil, nil, nil)
        for r in rows {
            sqlite3_exec(db, "INSERT INTO logins (origin_url, signon_realm, username_value, date_created) "
                + "VALUES ('\(r.origin)', '\(r.origin)', '\(r.username)', 0);", nil, nil, nil)
        }
        return url
    }

    static func rowCount(_ url: URL) -> Int {
        var db: OpaquePointer?
        sqlite3_open(url.path, &db); defer { sqlite3_close(db) }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM logins", -1, &stmt, nil) == SQLITE_OK else { return -1 }
        defer { sqlite3_finalize(stmt) }
        return sqlite3_step(stmt) == SQLITE_ROW ? Int(sqlite3_column_int64(stmt, 0)) : -1
    }

    static func origins(_ url: URL) -> [String] {
        var db: OpaquePointer?
        sqlite3_open(url.path, &db); defer { sqlite3_close(db) }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT origin_url FROM logins ORDER BY origin_url", -1, &stmt, nil) == SQLITE_OK
        else { return [] }
        defer { sqlite3_finalize(stmt) }
        var out: [String] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let c = sqlite3_column_text(stmt, 0) { out.append(String(cString: c)) }
        }
        return out
    }

    static func backupDir(for store: URL) -> URL {
        store.deletingLastPathComponent().appendingPathComponent("backups", isDirectory: true)
    }
}

private struct FixedChecker: RunningBrowserChecking {
    let running: Bool
    func isRunning(_ browser: BrowserSource) -> Bool { running }
}

/// Run the CLI swallowing output, returning the exit code.
private func runCLI(_ args: [String], running: Bool = false,
                    targets: [String] = []) -> Int32 {
    CleanupCommand.run(
        arguments: args,
        runningChecker: FixedChecker(running: running),
        readTargets: { targets },
        out: { _ in }, err: { _ in }
    )
}

@Suite("rekey-cleanup CLI — destructive-path contract")
struct CleanupCommandTests {

    @Test("No --confirm is a DRY RUN: deletes nothing")
    func dryRunDeletesNothing() {
        let store = Store.make([.init(origin: "https://github.com/a", username: "u1"),
                                .init(origin: "https://github.com/b", username: "u2")])
        let code = runCLI(["delete", "--browser", "chrome", "--path", store.path,
                           "--backup-dir", Store.backupDir(for: store).path, "--site", "github.com"])
        #expect(code == 0)
        #expect(Store.rowCount(store) == 2)   // untouched
    }

    @Test("--confirm while the browser is running: exits non-zero, deletes nothing")
    func refusesWhileRunning() {
        let store = Store.make([.init(origin: "https://github.com/a", username: "u1"),
                                .init(origin: "https://github.com/b", username: "u2")])
        let code = runCLI(["delete", "--browser", "chrome", "--path", store.path,
                           "--backup-dir", Store.backupDir(for: store).path,
                           "--site", "github.com", "--confirm"], running: true)
        #expect(code == 2)
        #expect(Store.rowCount(store) == 2)   // nothing deleted
    }

    @Test("A delete with no filter is refused")
    func refusesWithoutFilter() {
        let store = Store.make([.init(origin: "https://github.com/a", username: "u1")])
        let code = runCLI(["delete", "--browser", "chrome", "--path", store.path,
                           "--backup-dir", Store.backupDir(for: store).path, "--confirm"])
        #expect(code == 1)
        #expect(Store.rowCount(store) == 1)
    }

    @Test("A value starting with -- is NOT parsed as a flag (no injected --confirm)")
    func dashDashValueIsNotAFlag() {
        // Old non-greedy parser: --username gets "", --confirm becomes a real flag →
        // site-only delete of BOTH github logins. Greedy parser: --username swallows
        // "--confirm" as its (non-matching) value, no confirm → nothing deleted.
        let store = Store.make([.init(origin: "https://github.com/a", username: "u1"),
                                .init(origin: "https://github.com/b", username: "u2")])
        let code = runCLI(["delete", "--browser", "chrome", "--path", store.path,
                           "--backup-dir", Store.backupDir(for: store).path,
                           "--site", "github.com", "--username", "--confirm"], running: false)
        #expect(code == 0)
        #expect(Store.rowCount(store) == 2)   // the smuggled --confirm did NOT delete
    }

    @Test("delete --site is anchored to the host: a substring sibling is spared")
    func anchoredDeleteSparesSibling() {
        let store = Store.make([
            .init(origin: "https://casino.com/a", username: "u1"),
            .init(origin: "https://casino.com/b", username: "u2"),
            .init(origin: "https://nodepositcasino.com/x", username: "u3"),   // substring, different host
        ])
        let code = runCLI(["delete", "--browser", "chrome", "--path", store.path,
                           "--backup-dir", Store.backupDir(for: store).path,
                           "--site", "casino.com", "--confirm"], running: false)
        #expect(code == 0)
        #expect(Store.rowCount(store) == 1)
        #expect(Store.origins(store) == ["https://nodepositcasino.com/x"])   // sibling survives
    }

    @Test("A bare substring --site matches no exact host on delete: nothing happens")
    func bareSubstringDeletesNothing() {
        let store = Store.make([
            .init(origin: "https://casino.com/a", username: "u1"),
            .init(origin: "https://nodepositcasino.com/x", username: "u2"),
        ])
        let code = runCLI(["delete", "--browser", "chrome", "--path", store.path,
                           "--backup-dir", Store.backupDir(for: store).path,
                           "--site", "casino", "--confirm"], running: false)   // bare "casino", not a full host
        #expect(code == 0)
        #expect(Store.rowCount(store) == 2)   // anchoring excluded both — no over-broad sweep
    }

    @Test("purge anchors each target to its host (a substring sibling is spared)")
    func purgeAnchorsTargets() {
        let store = Store.make([
            .init(origin: "https://casino.com/a", username: "u1"),
            .init(origin: "https://nodepositcasino.com/x", username: "u2"),
        ])
        let code = runCLI(["purge", "--browser", "chrome", "--path", store.path,
                           "--backup-dir", Store.backupDir(for: store).path, "--confirm"],
                          running: false, targets: ["casino.com"])
        #expect(code == 0)
        #expect(Store.origins(store) == ["https://nodepositcasino.com/x"])
    }

    @Test("An unknown command is rejected")
    func unknownCommand() {
        #expect(runCLI(["frobnicate", "--browser", "chrome"]) == 1)
    }

    @Test("Ownership check distinguishes our files from foreign ones")
    func ownershipCheck() {
        let store = Store.make([.init(origin: "https://x.com/a", username: "u")])
        #expect(CleanupCommand.ownedByCurrentUser(store))           // a file we created
        if getuid() != 0 {                                         // skip if running as root
            #expect(!CleanupCommand.ownedByCurrentUser(URL(fileURLWithPath: "/usr/bin/true")))
        }
    }
}
