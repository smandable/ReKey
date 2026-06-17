import Foundation

/// Copies a store's files into a timestamped backup directory *before* any
/// destructive write. If anything here throws, the caller must not proceed with
/// the delete.
public enum StoreBackup {
    /// Default backup root: ~/Library/Application Support/ReKey/Backups
    public static func defaultBackupRoot() -> URL {
        applicationSupport().appendingPathComponent("ReKey/Backups", isDirectory: true)
    }

    private static func applicationSupport() -> URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
    }

    /// One-time migration of the recovery-snapshot directory after the app was
    /// renamed "Rekey" → "ReKey". Pre-rebrand, snapshots lived under
    /// `Application Support/Rekey/Backups`; this brings the directory's casing in
    /// line and carries any existing snapshots across so none are orphaned.
    ///
    /// On the usual case-insensitive volume `Rekey` and `ReKey` resolve to the
    /// same folder, so this is a case-only fix done via a staging hop (a direct
    /// case-only rename is rejected there). On a case-sensitive volume they are
    /// distinct directories, so the legacy tree is moved — or merged when a
    /// `ReKey` tree already exists. Idempotent and best-effort: a failure must
    /// never block a cleanup, and only our own directory is ever touched.
    public static func migrateLegacyBackupRoot() {
        migrateLegacyBackupRoot(inApplicationSupport: applicationSupport())
    }

    /// Testable core of ``migrateLegacyBackupRoot()``, operating on an explicit
    /// Application Support directory.
    static func migrateLegacyBackupRoot(inApplicationSupport appSupport: URL) {
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(atPath: appSupport.path) else { return }
        // Our directory under any casing ("Rekey", "ReKey", …).
        let ours = entries.filter { $0.caseInsensitiveCompare("ReKey") == .orderedSame }
        guard !ours.isEmpty else { return }     // nothing of ours yet
        if ours == ["ReKey"] { return }         // already correctly cased

        let current = appSupport.appendingPathComponent("ReKey", isDirectory: true)

        // Case-sensitive volume carrying both a legacy "Rekey" and a "ReKey": merge.
        if ours.count >= 2 {
            let legacyName = ours.first { $0 != "ReKey" } ?? ours[0]
            mergeBackupTree(from: appSupport.appendingPathComponent(legacyName, isDirectory: true),
                            into: current, using: fm)
            return
        }

        // A single directory whose case isn't exactly "ReKey" → rename it. Stage
        // through a distinct name so it also works on a case-insensitive volume,
        // where a direct case-only rename throws.
        let legacy = appSupport.appendingPathComponent(ours[0], isDirectory: true)
        let staging = appSupport.appendingPathComponent("ReKey.migrating", isDirectory: true)
        try? fm.removeItem(at: staging)         // clear a stale staging dir from an interrupted run
        do {
            try fm.moveItem(at: legacy, to: staging)
            try fm.moveItem(at: staging, to: current)
        } catch {
            // Best-effort rollback so legacy snapshots are never stranded.
            if fm.fileExists(atPath: staging.path) && !fm.fileExists(atPath: legacy.path) {
                try? fm.moveItem(at: staging, to: legacy)
            }
        }
    }

    /// Move every snapshot from a legacy `…/Backups` into the current one,
    /// keeping the legacy copy on any name clash, then drop the legacy tree if it
    /// was fully carried over.
    private static func mergeBackupTree(from legacy: URL, into current: URL, using fm: FileManager) {
        let legacyBackups = legacy.appendingPathComponent("Backups", isDirectory: true)
        let currentBackups = current.appendingPathComponent("Backups", isDirectory: true)
        guard fm.fileExists(atPath: legacyBackups.path) else { return }
        try? fm.createDirectory(at: currentBackups, withIntermediateDirectories: true)
        var carriedAll = true
        for name in (try? fm.contentsOfDirectory(atPath: legacyBackups.path)) ?? [] {
            let dst = currentBackups.appendingPathComponent(name)
            if fm.fileExists(atPath: dst.path) { carriedAll = false; continue }
            do { try fm.moveItem(at: legacyBackups.appendingPathComponent(name), to: dst) }
            catch { carriedAll = false }
        }
        if carriedAll { try? fm.removeItem(at: legacy) }
    }

    /// Compute (but don't create) a unique backup directory for a run.
    public static func backupDirectory(root: URL, label: String, timestamp: String) -> URL {
        root.appendingPathComponent("\(label)-\(timestamp)", isDirectory: true)
    }

    /// Keep only the most recent `keepPerLabel` backup directories per browser
    /// label under `root`, deleting older ones so recovery snapshots (copies of
    /// the browser's store) don't accumulate without bound. Best-effort and
    /// silent: a pruning failure must never fail an already-completed cleanup, and
    /// only ReKey's own `<label>-<timestamp>-<rand>` directories are ever touched.
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
