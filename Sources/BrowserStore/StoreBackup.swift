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
            // Only ReKey's own "<label>-<yyyyMMdd>-<HHmmss>-<rand6>" snapshots — match
            // the exact timestamp/rand shape so an UNRELATED directory under a
            // user-supplied --backup-dir (e.g. "my-vacation-photos-2024") can't be
            // mistaken for a backup and pruned. Label is everything before the tail.
            guard let label = reKeyBackupLabel(of: dir.lastPathComponent) else { continue }
            byLabel[label, default: []].append(dir)
        }
        for (_, dirs) in byLabel where dirs.count > keepPerLabel {
            // Name sorts chronologically (timestamp embedded), so newest-first.
            let sorted = dirs.sorted { $0.lastPathComponent > $1.lastPathComponent }
            for old in sorted.dropFirst(keepPerLabel) { try? fm.removeItem(at: old) }
        }
    }

    /// The label of a ReKey backup directory name, or nil if `name` isn't one.
    /// Requires the exact tail `…-<8 digits>-<6 digits>-<6 hex>` that
    /// `backupDirectory(root:label:timestamp:)` produces.
    static func reKeyBackupLabel(of name: String) -> String? {
        let parts = name.split(separator: "-")
        guard parts.count >= 4 else { return nil }
        let date = parts[parts.count - 3], time = parts[parts.count - 2], rand = parts[parts.count - 1]
        guard date.count == 8, date.allSatisfy(\.isNumber),
              time.count == 6, time.allSatisfy(\.isNumber),
              rand.count == 6, rand.allSatisfy(\.isHexDigit) else { return nil }
        return parts.dropLast(3).joined(separator: "-")
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
            // 0700: the snapshot holds a copy of the browser's store (plaintext
            // index fields), so keep it owner-only rather than the default 0755 that
            // could leave it group/other-readable under a custom --backup-dir.
            try fm.createDirectory(at: directory, withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o700])
        } catch {
            throw LoginStoreError.backupFailed("couldn't create \(directory.path): \(error.localizedDescription)")
        }
        for file in files where fm.fileExists(atPath: file.path) {
            let dest = directory.appendingPathComponent(file.lastPathComponent)
            do {
                if fm.fileExists(atPath: dest.path) { try fm.removeItem(at: dest) }
                try fm.copyItem(at: file, to: dest)
                // Owner-only: don't let the plaintext-bearing copy inherit world-readable perms.
                try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: dest.path)
            } catch {
                throw LoginStoreError.backupFailed("couldn't copy \(file.lastPathComponent): \(error.localizedDescription)")
            }
        }
        return directory
    }
}
