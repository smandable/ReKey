import Foundation
import SQLite3
@testable import BrowserStore

/// Helpers to build synthetic browser stores in a temp directory.
enum TestStores {
    static func tempDir() -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("rekey-bstore-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    struct ChromiumRow {
        let origin: String
        let realm: String
        let username: String
        let created: Int64
    }

    /// Create a Chromium-like "Login Data" SQLite DB. If `includeRealm` is false,
    /// the `signon_realm` column is omitted (to exercise the schema guard).
    static func makeChromium(at url: URL, includeRealm: Bool = true, rows: [ChromiumRow]) {
        var db: OpaquePointer?
        sqlite3_open(url.path, &db)
        defer { sqlite3_close(db) }
        let realmCol = includeRealm ? "signon_realm TEXT, " : ""
        sqlite3_exec(db, """
            CREATE TABLE logins (origin_url TEXT, \(realmCol)username_value TEXT,
            password_value BLOB, date_created INTEGER, date_last_used INTEGER);
            """, nil, nil, nil)
        for r in rows {
            let cols = includeRealm
                ? "(origin_url, signon_realm, username_value, date_created)"
                : "(origin_url, username_value, date_created)"
            let vals = includeRealm
                ? "('\(r.origin)', '\(r.realm)', '\(r.username)', \(r.created))"
                : "('\(r.origin)', '\(r.username)', \(r.created))"
            sqlite3_exec(db, "INSERT INTO logins \(cols) VALUES \(vals);", nil, nil, nil)
        }
    }

    /// Count rows currently in the logins table (for assertions).
    static func chromiumRowCount(_ url: URL) -> Int {
        var db: OpaquePointer?
        sqlite3_open(url.path, &db)
        defer { sqlite3_close(db) }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM logins", -1, &stmt, nil) == SQLITE_OK else { return -1 }
        defer { sqlite3_finalize(stmt) }
        return sqlite3_step(stmt) == SQLITE_ROW ? Int(sqlite3_column_int64(stmt, 0)) : -1
    }

    /// Write a Firefox logins.json (version 3) with the given logins plus some
    /// extra top-level keys to verify they survive a delete.
    static func makeFirefox(at url: URL, version: Int = 3, logins: [[String: Any]]) {
        let root: [String: Any] = [
            "nextId": logins.count + 1,
            "logins": logins,
            "potentiallyVulnerablePasswords": [],
            "dismissedBreachAlertsByLoginGUID": [:],
            "version": version,
        ]
        let data = try! JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        try! data.write(to: url)
    }

    static func firefoxLogin(guid: String, host: String, created: Int = 1_700_000_000_000) -> [String: Any] {
        [
            "id": Int.random(in: 1...9999),
            "hostname": host,
            "httpRealm": NSNull(),
            "formSubmitURL": host,
            "usernameField": "",
            "passwordField": "",
            "encryptedUsername": "MEnc\(guid)",
            "encryptedPassword": "MEncP\(guid)",
            "guid": guid,
            "encType": 1,
            "timeCreated": created,
            "timeLastUsed": created,
            "timePasswordChanged": created,
            "timesUsed": 3,
            // an unknown per-login field that must survive a delete elsewhere:
            "customUnknownField": "keep-me",
        ]
    }

    static func readFirefoxRoot(_ url: URL) -> [String: Any] {
        let data = try! Data(contentsOf: url)
        return (try! JSONSerialization.jsonObject(with: data)) as! [String: Any]
    }
}
