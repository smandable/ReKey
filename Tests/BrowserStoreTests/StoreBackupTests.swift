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
        for d in 1...7 { try mk("chrome-202601\(String(format: "%02d", d))-000000-aa\(d)") }
        for h in 1...2 { try mk("arc-20260101-00000\(h)-bb\(h)") }
        try mk("not-a-backup")

        StoreBackup.pruneOldBackups(root: root, keepPerLabel: 3)

        let left = Set(try fm.contentsOfDirectory(atPath: root.path))
        #expect(left.filter { $0.hasPrefix("chrome-") }.count == 3)   // newest 3 kept
        #expect(left.contains("chrome-20260107-000000-aa7"))          // newest survives
        #expect(!left.contains("chrome-20260101-000000-aa1"))         // oldest pruned
        #expect(left.filter { $0.hasPrefix("arc-") }.count == 2)      // under the cap, untouched
        #expect(left.contains("not-a-backup"))                        // foreign dir left alone
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
}
