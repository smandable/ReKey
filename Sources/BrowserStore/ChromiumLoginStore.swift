import Foundation
import SQLite3
import Model

/// Reads and prunes a Chromium "Login Data" SQLite store. Matches and deletes
/// purely on the plaintext index columns (`origin_url`, `signon_realm`,
/// `username_value`, `rowid`) — the encrypted `password_value` blob is never
/// read, so this never needs the Safe Storage key.
public struct ChromiumLoginStore: LoginStore {
    public let browser: BrowserSource
    public let databaseURL: URL

    public init(browser: BrowserSource, databaseURL: URL) {
        self.browser = browser
        self.databaseURL = databaseURL
    }

    public func validate() throws {
        try requireFile()
        let db = try open(readOnly: true)
        defer { sqlite3_close(db) }
        try requireColumns(tableColumns(db, table: "logins"))
    }

    public func list(matching filter: LoginFilter) throws -> [StoredLogin] {
        try requireFile()
        let db = try open(readOnly: true)
        defer { sqlite3_close(db) }
        let columns = tableColumns(db, table: "logins")
        try requireColumns(columns)
        return try queryLogins(db, columns: columns).filter(filter.matches)
    }

    public func delete(matching filter: LoginFilter, backupDirectory: URL) throws -> DeleteOutcome {
        guard !filter.isEmpty else { throw LoginStoreError.noFilter }
        let matches = try list(matching: filter)
        guard !matches.isEmpty else { return DeleteOutcome(deleted: [], backupPath: backupDirectory) }

        // Back up the DB (and any WAL/SHM sidecars) BEFORE touching it.
        try StoreBackup.copy(files: storeFiles(), into: backupDirectory)

        let db = try open(readOnly: false)
        defer { sqlite3_close(db) }
        try exec(db, "BEGIN IMMEDIATE")
        do {
            for login in matches {
                // rowids come from String(rowid) in list(); a non-integer here
                // means something is wrong — fail loudly (and roll back) rather
                // than silently under-delete what the user asked to remove.
                guard let rowid = Int64(login.id) else {
                    throw LoginStoreError.sqlite("unexpected non-integer rowid '\(login.id)'")
                }
                var stmt: OpaquePointer?
                guard sqlite3_prepare_v2(db, "DELETE FROM logins WHERE rowid = ?", -1, &stmt, nil) == SQLITE_OK else {
                    throw LoginStoreError.sqlite(lastError(db))
                }
                defer { sqlite3_finalize(stmt) }
                sqlite3_bind_int64(stmt, 1, rowid)
                guard sqlite3_step(stmt) == SQLITE_DONE else {
                    throw LoginStoreError.sqlite(lastError(db))
                }
            }
            try exec(db, "COMMIT")
        } catch {
            try? exec(db, "ROLLBACK")
            throw error
        }
        // Fold the WAL back into the main .db so the live file is self-contained
        // (best-effort; the commit already succeeded and the pre-delete backup
        // captured all three files for recovery).
        try? exec(db, "PRAGMA wal_checkpoint(TRUNCATE)")
        return DeleteOutcome(deleted: matches, backupPath: backupDirectory)
    }

    // MARK: - Files

    private func storeFiles() -> [URL] {
        [databaseURL,
         URL(fileURLWithPath: databaseURL.path + "-wal"),
         URL(fileURLWithPath: databaseURL.path + "-shm")]
    }

    private func requireFile() throws {
        guard FileManager.default.fileExists(atPath: databaseURL.path) else {
            throw LoginStoreError.fileNotFound(databaseURL)
        }
    }

    // MARK: - SQLite

    private func open(readOnly: Bool) throws -> OpaquePointer {
        var handle: OpaquePointer?
        let flags = readOnly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE
        guard sqlite3_open_v2(databaseURL.path, &handle, flags, nil) == SQLITE_OK, let handle else {
            let message = handle.map { lastError($0) } ?? "couldn't open database"
            if let handle { sqlite3_close(handle) }
            throw LoginStoreError.sqlite(message)
        }
        sqlite3_busy_timeout(handle, 2000)
        return handle
    }

    private func tableColumns(_ db: OpaquePointer, table: String) -> Set<String> {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "PRAGMA table_info(\(table))", -1, &stmt, nil) == SQLITE_OK else {
            return []
        }
        defer { sqlite3_finalize(stmt) }
        var columns: Set<String> = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let c = sqlite3_column_text(stmt, 1) { columns.insert(String(cString: c)) }
        }
        return columns
    }

    private func requireColumns(_ columns: Set<String>) throws {
        guard !columns.isEmpty else { throw LoginStoreError.unrecognizedSchema("no 'logins' table") }
        for col in ["origin_url", "username_value", "signon_realm"] where !columns.contains(col) {
            throw LoginStoreError.unrecognizedSchema("logins table missing column '\(col)'")
        }
    }

    private func queryLogins(_ db: OpaquePointer, columns: Set<String>) throws -> [StoredLogin] {
        let createdExpr = columns.contains("date_created") ? "date_created" : "0"
        let lastUsedExpr = columns.contains("date_last_used") ? "date_last_used" : "0"
        let sql = "SELECT rowid, origin_url, signon_realm, username_value, \(createdExpr), \(lastUsedExpr) FROM logins"

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw LoginStoreError.sqlite(lastError(db))
        }
        defer { sqlite3_finalize(stmt) }

        var result: [StoredLogin] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let rowid = sqlite3_column_int64(stmt, 0)
            result.append(StoredLogin(
                id: String(rowid),
                browser: browser,
                origin: text(stmt, 1) ?? "",
                signonRealm: text(stmt, 2),
                username: text(stmt, 3) ?? "",
                usernameIsEncrypted: false,
                createdAt: chromiumDate(sqlite3_column_int64(stmt, 4)),
                lastUsedAt: chromiumDate(sqlite3_column_int64(stmt, 5))
            ))
        }
        return result
    }

    private func text(_ stmt: OpaquePointer?, _ index: Int32) -> String? {
        guard let c = sqlite3_column_text(stmt, index) else { return nil }
        return String(cString: c)
    }

    /// Chromium timestamps are microseconds since 1601-01-01 UTC.
    private func chromiumDate(_ micros: Int64) -> Date? {
        guard micros > 0 else { return nil }
        let unix = Double(micros) / 1_000_000.0 - 11_644_473_600.0
        return Date(timeIntervalSince1970: unix)
    }

    private func exec(_ db: OpaquePointer, _ sql: String) throws {
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            throw LoginStoreError.sqlite(lastError(db))
        }
    }

    private func lastError(_ db: OpaquePointer) -> String {
        String(cString: sqlite3_errmsg(db))
    }
}
