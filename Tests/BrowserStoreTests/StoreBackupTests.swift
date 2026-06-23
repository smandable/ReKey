import Testing
import Foundation
@testable import BrowserStore

@Suite("Store backup")
struct StoreBackupTests {

    @Test("Pruning keeps the newest N backups per label and ignores foreign dirs")
    func prune() throws {
        let fm = FileManager.default
        let root = TestStores.tempDir()
        func mk(_ name: String) throws { try fm.createDirectory(at: root.appendingPathComponent(name), withIntermediateDirectories: true) }
        // 7 chrome (sortable by embedded timestamp), 2 arc, 1 unrelated dir.
        // Names use the real "<label>-<8 digits>-<6 digits>-<6 hex>" shape.
        for d in 1...7 { try mk("chrome-2026010\(d)-000000-aaaaa\(d)") }
        for h in 1...2 { try mk("arc-20260101-00000\(h)-bbbbb\(h)") }
        try mk("not-a-backup")
        // Foreign dirs with 4+ dash segments that AREN'T ReKey backups (the old
        // "4+ segments" heuristic would have grouped + pruned these in bulk).
        for y in 2018...2025 { try mk("my-vacation-photos-\(y)") }

        StoreBackup.pruneOldBackups(root: root, keepPerLabel: 3)

        let left = Set(try fm.contentsOfDirectory(atPath: root.path))
        #expect(left.filter { $0.hasPrefix("chrome-") }.count == 3)   // newest 3 kept
        #expect(left.contains("chrome-20260107-000000-aaaaa7"))       // newest survives
        #expect(!left.contains("chrome-20260101-000000-aaaaa1"))      // oldest pruned
        #expect(left.filter { $0.hasPrefix("arc-") }.count == 2)      // under the cap, untouched
        #expect(left.contains("not-a-backup"))                        // foreign dir left alone
        #expect(left.filter { $0.hasPrefix("my-vacation-photos-") }.count == 8)  // all foreign dirs survive
    }

    @Test("Backup directory + copied plaintext-bearing files are owner-only (0700/0600)")
    func backupPermissions() throws {
        let fm = FileManager.default
        let dir = TestStores.tempDir()
        let src = dir.appendingPathComponent("Login Data")
        try Data("plaintext-index".utf8).write(to: src)
        let backup = dir.appendingPathComponent("snap")

        try StoreBackup.copy(files: [src], into: backup)
        let dirPerms = (try fm.attributesOfItem(atPath: backup.path)[.posixPermissions] as? Int) ?? 0
        let filePerms = (try fm.attributesOfItem(atPath: backup.appendingPathComponent("Login Data").path)[.posixPermissions] as? Int) ?? 0
        #expect(dirPerms == 0o700)
        #expect(filePerms == 0o600)
    }

    @Test("Copies files into a fresh directory")
    func copies() throws {
        let dir = TestStores.tempDir()
        let src = dir.appendingPathComponent("Login Data")
        try Data("db".utf8).write(to: src)
        let backup = dir.appendingPathComponent("backup")

        try StoreBackup.copy(files: [src, dir.appendingPathComponent("Login Data-wal")], into: backup)
        #expect(FileManager.default.fileExists(atPath: backup.appendingPathComponent("Login Data").path))
        // Non-existent sidecar is simply skipped.
        #expect(!FileManager.default.fileExists(atPath: backup.appendingPathComponent("Login Data-wal").path))
    }

    @Test("Refuses to clobber a non-empty existing backup directory")
    func refusesNonEmpty() throws {
        let dir = TestStores.tempDir()
        let src = dir.appendingPathComponent("Login Data")
        try Data("db".utf8).write(to: src)
        let backup = dir.appendingPathComponent("backup")

        try StoreBackup.copy(files: [src], into: backup)        // first run: ok
        #expect(throws: LoginStoreError.self) {                 // second run into same dir: refused
            try StoreBackup.copy(files: [src], into: backup)
        }
    }

    // MARK: Rekey → ReKey backup-dir migration

    @Test("Migrates a legacy Rekey backup dir to ReKey, preserving the snapshot")
    func migratesLegacyBackupDir() throws {
        let fm = FileManager.default
        let appSupport = TestStores.tempDir()
        // Pre-rebrand layout: one snapshot under "Rekey/Backups".
        let snap = appSupport.appendingPathComponent("Rekey/Backups/chrome-20260101-000000-aa1", isDirectory: true)
        try fm.createDirectory(at: snap, withIntermediateDirectories: true)
        try Data("snapshot".utf8).write(to: snap.appendingPathComponent("Login Data"))

        StoreBackup.migrateLegacyBackupRoot(inApplicationSupport: appSupport)

        // The directory now reads exactly "ReKey" and the snapshot survived intact.
        let names = Set(try fm.contentsOfDirectory(atPath: appSupport.path))
        #expect(names.contains("ReKey"))
        #expect(!names.contains("Rekey"))
        let moved = appSupport.appendingPathComponent("ReKey/Backups/chrome-20260101-000000-aa1/Login Data")
        #expect(fm.fileExists(atPath: moved.path))
        #expect(try Data(contentsOf: moved) == Data("snapshot".utf8))
    }

    @Test("Migration is a no-op (and non-destructive) when the dir is already ReKey")
    func migrationIdempotent() throws {
        let fm = FileManager.default
        let appSupport = TestStores.tempDir()
        let snap = appSupport.appendingPathComponent("ReKey/Backups/arc-20260101-000000-bb1", isDirectory: true)
        try fm.createDirectory(at: snap, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: snap.appendingPathComponent("Login Data"))

        StoreBackup.migrateLegacyBackupRoot(inApplicationSupport: appSupport)  // run twice
        StoreBackup.migrateLegacyBackupRoot(inApplicationSupport: appSupport)

        #expect(try fm.contentsOfDirectory(atPath: appSupport.path) == ["ReKey"])
        #expect(fm.fileExists(atPath: snap.appendingPathComponent("Login Data").path))
    }

    @Test("Migration does nothing when there is no prior backup directory")
    func migrationNoLegacyDir() throws {
        let fm = FileManager.default
        let appSupport = TestStores.tempDir()
        StoreBackup.migrateLegacyBackupRoot(inApplicationSupport: appSupport)
        #expect((try? fm.contentsOfDirectory(atPath: appSupport.path))?.isEmpty ?? true)
    }
}
