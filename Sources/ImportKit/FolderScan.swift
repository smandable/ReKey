import Foundation

/// Finds CSV files in a folder for the auto-import watcher. Pure and testable;
/// the live filesystem watching lives in the UI layer.
public enum FolderScan {
    public struct Entry: Sendable, Equatable {
        public let url: URL
        public let modified: Date
        public init(url: URL, modified: Date) {
            self.url = url
            self.modified = modified
        }
        /// Identity for "already handled": path + modification second. A
        /// re-export (new mtime) to the same name produces a new signature.
        public var signature: String { "\(url.path)|\(Int(modified.timeIntervalSince1970))" }
    }

    /// All `*.csv` files directly in `directory`, oldest first.
    public static func csvFiles(in directory: URL) -> [Entry] {
        let fm = FileManager.default
        guard let urls = try? fm.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles, .skipsSubdirectoryDescendants]
        ) else { return [] }

        return urls.compactMap { url -> Entry? in
            guard url.pathExtension.lowercased() == "csv" else { return nil }
            let modified = (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate)
                ?? Date(timeIntervalSince1970: 0)
            return Entry(url: url, modified: modified)
        }
        .sorted { $0.modified < $1.modified }
    }

    /// CSVs worth importing: modified at/after `threshold` and not already in
    /// `seen` (by signature). The threshold keeps a freshly-exported file from
    /// being ignored while stale CSVs already in the folder are left alone.
    public static func freshCSVs(in directory: URL, since threshold: Date, seen: Set<String>) -> [Entry] {
        csvFiles(in: directory).filter { $0.modified >= threshold && !seen.contains($0.signature) }
    }
}
