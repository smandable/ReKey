import Testing
import Foundation
@testable import ImportKit

@Suite("Folder scan for auto-import")
struct FolderScanTests {
    private func tempDir() -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rekey-scan-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func write(_ name: String, in dir: URL, modified: Date) -> URL {
        let url = dir.appendingPathComponent(name)
        try? Data("url,username,password\nhttps://x/,u,p\n".utf8).write(to: url)
        try? FileManager.default.setAttributes([.modificationDate: modified], ofItemAtPath: url.path)
        return url
    }

    @Test("Only .csv files are listed, oldest first")
    func listsCSVs() {
        let dir = tempDir()
        let t0 = Date(timeIntervalSince1970: 1_000_000)
        _ = write("a.csv", in: dir, modified: t0.addingTimeInterval(20))
        _ = write("b.csv", in: dir, modified: t0.addingTimeInterval(10))
        _ = write("notes.txt", in: dir, modified: t0)

        let files = FolderScan.csvFiles(in: dir)
        #expect(files.map { $0.url.lastPathComponent } == ["b.csv", "a.csv"])
    }

    @Test("Fresh files are those modified at/after the threshold and unseen")
    func freshFiltering() throws {
        let dir = tempDir()
        let now = Date(timeIntervalSince1970: 2_000_000)
        let old = write("old.csv", in: dir, modified: now.addingTimeInterval(-3600))   // stale
        let fresh = write("fresh.csv", in: dir, modified: now.addingTimeInterval(30))   // new

        let threshold = now.addingTimeInterval(-300)
        let result = FolderScan.freshCSVs(in: dir, since: threshold, seen: [])
        #expect(result.map { $0.url.lastPathComponent } == ["fresh.csv"])
        _ = (old, fresh)

        // Once its signature is seen, it's excluded (use the scanner's own entry,
        // since it resolves the canonical path).
        let entry = try #require(result.first)
        #expect(FolderScan.freshCSVs(in: dir, since: threshold, seen: [entry.signature]).isEmpty)
    }
}
