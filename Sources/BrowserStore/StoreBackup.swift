import Foundation

/// Copies a store's files into a timestamped backup directory *before* any
/// destructive write. If anything here throws, the caller must not proceed with
/// the delete.
public enum StoreBackup {
    /// Default backup root: ~/Library/Application Support/Rekey/Backups
    public static func defaultBackupRoot() -> URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return appSupport.appendingPathComponent("Rekey/Backups", isDirectory: true)
    }

    /// Compute (but don't create) a unique backup directory for a run.
    public static func backupDirectory(root: URL, label: String, timestamp: String) -> URL {
        root.appendingPathComponent("\(label)-\(timestamp)", isDirectory: true)
    }

    /// Keep only the most recent `keepPerLabel` backup directories per browser
    /// label under `root`, deleting older ones so recovery snapshots (copies of
    /// the browser's store) don't accumulate without bound. Best-effort and
    /// silent: a pruning failure must never fail an already-completed cleanup, and
    /// only Rekey's own `<label>-<timestamp>-<rand>` directories are ever touched.
    public static func pruneOldBackups(root: URL, keepPerLabel: Int = 10) {
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(
            at: root, includingPropertiesForKeys: [.isDirectoryKey]) else { return }

        var byLabel: [String: [URL]] = [:]
        for dir in entries {
            guard (try? dir.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true else { continue }
            // "<label>-<yyyyMMdd>-<HHmmss>-<rand>" → 4+ dash segments; label is all
            // but the last three. Anything else isn't ours — skip it.
            let parts = dir.lastPathComponent.split(separator: "-")
            guard parts.count >= 4 else { continue }
            let label = parts.dropLast(3).joined(separator: "-")
            byLabel[label, default: []].append(dir)
        }
        for (_, dirs) in byLabel where dirs.count > keepPerLabel {
            // Name sorts chronologically (timestamp embedded), so newest-first.
            let sorted = dirs.sorted { $0.lastPathComponent > $1.lastPathComponent }
            for old in sorted.dropFirst(keepPerLabel) { try? fm.removeItem(at: old) }
        }
    }

    /// Copy every existing file in `files` into `directory` (created if needed),
    /// preserving filenames. Returns the directory. Throws on any failure.
    @discardableResult
    public static func copy(files: [URL], into directory: URL) throws -> URL {
        let fm = FileManager.default
        // Never overwrite an existing backup: a non-empty target directory would
        // clobber an earlier run's recovery snapshot. Refuse rather than destroy it.
        if let existing = try? fm.contentsOfDirectory(atPath: directory.path), !existing.isEmpty {
            throw LoginStoreError.backupFailed("backup directory already exists and is not empty: \(directory.path)")
        }
        do {
            try fm.createDirectory(at: directory, withIntermediateDirectories: true)
        } catch {
            throw LoginStoreError.backupFailed("couldn't create \(directory.path): \(error.localizedDescription)")
        }
        for file in files where fm.fileExists(atPath: file.path) {
            let dest = directory.appendingPathComponent(file.lastPathComponent)
            do {
                if fm.fileExists(atPath: dest.path) { try fm.removeItem(at: dest) }
                try fm.copyItem(at: file, to: dest)
            } catch {
                throw LoginStoreError.backupFailed("couldn't copy \(file.lastPathComponent): \(error.localizedDescription)")
            }
        }
        return directory
    }
}
