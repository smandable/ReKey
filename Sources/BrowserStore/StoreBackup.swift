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
