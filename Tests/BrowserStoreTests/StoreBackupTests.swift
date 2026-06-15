import Testing
import Foundation
@testable import BrowserStore

@Suite("Store backup")
struct StoreBackupTests {

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
