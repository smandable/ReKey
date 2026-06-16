import Testing
import Foundation
@testable import RekeyUI

private func tempDir() -> URL {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rekey-fw-\(UUID().uuidString)")
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

@MainActor
@Suite("Folder watcher lifecycle")
struct FolderWatcherTests {
    /// Reference box so the escaping onChange closure can flip a flag the test reads.
    final class Flag { var value = false }
    /// Reference box for counting onChange calls.
    final class Counter { var value = 0 }

    @Test("Polls on an interval even with no filesystem events (external/network-volume fallback)")
    func pollsWithoutFilesystemEvents() async throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let watcher = FolderWatcher(pollInterval: 0.05)
        let counter = Counter()
        watcher.onChange = { counter.value += 1 }
        watcher.start(url: dir)
        // No file changes occur, so any onChange must come from the poll timer —
        // this is exactly the path that rescues external/network-volume folders
        // where kqueue/vnode events are never delivered.
        try await Task.sleep(for: .milliseconds(300))
        watcher.stop()
        #expect(counter.value >= 2)
    }

    @Test("Fires onChange on a directory change; start/stop are idempotent")
    func firesAndTearsDown() async throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let watcher = FolderWatcher()
        let flag = Flag()
        watcher.onChange = { flag.value = true }
        watcher.start(url: dir)
        watcher.start(url: dir)   // re-start replaces cleanly (no double-fd leak/crash)

        try Data("x".utf8).write(to: dir.appendingPathComponent("a.csv"))

        // Wait up to ~3s for the filesystem event (delivered on the main queue,
        // which drains while we await).
        for _ in 0..<60 where !flag.value { try await Task.sleep(for: .milliseconds(50)) }
        #expect(flag.value)

        watcher.stop()
        watcher.stop()   // idempotent — must not double-close / crash
    }
}

@MainActor
@Suite("Auto-import gating")
struct AutoImportTests {
    @Test("Starting a watch imports a recognized export and ignores a non-password CSV")
    func gatesOnRecognizedFormat() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        try Data("name,url,username,password,note\nGitHub,https://github.com/,sean,Tr0ub4dour&3,\n".utf8)
            .write(to: dir.appendingPathComponent("passwords.csv"))
        try Data("col1,col2\nfoo,bar\n".utf8)   // not a recognized password export
            .write(to: dir.appendingPathComponent("spreadsheet.csv"))

        let model = AppModel()
        // startWatching scans existing fresh CSVs synchronously, so this is
        // deterministic without waiting on filesystem events.
        model.startWatching(dir)
        defer { model.stopWatching() }

        #expect(model.watchedFolder == dir)
        #expect(model.allCredentials.count == 1)
        #expect(model.allCredentials.first?.registrableDomain == "github.com")
    }
}
