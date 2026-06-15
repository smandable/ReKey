import Foundation

/// Finds CSV files in a folder for the auto-import watcher. Pure and testable;
/// the live filesystem watching lives in the UI layer.
public enum FolderScan {
    public struct Entry: Sendable, Equatable {
        public let url: URL
        public let modified: Date
        public let size: Int
        public init(url: URL, modified: Date, size: Int = 0) {
            self.url = url
            self.modified = modified
            self.size = size
        }
        /// Identity for "already handled": path + full-precision mtime + size, so
        /// a re-export to the same name within the same second (changed content)
        /// still gets a fresh signature rather than being skipped.
        public var signature: String { "\(url.path)|\(modified.timeIntervalSince1970)|\(size)" }
    }

    /// All `*.csv` files directly in `directory`, oldest first.
    public static func csvFiles(in directory: URL) -> [Entry] {
        let fm = FileManager.default
        guard let urls = try? fm.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey],
            options: [.skipsHiddenFiles, .skipsSubdirectoryDescendants]
        ) else { return [] }

        return urls.compactMap { url -> Entry? in
            guard url.pathExtension.lowercased() == "csv" else { return nil }
            let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
            let modified = values?.contentModificationDate ?? Date(timeIntervalSince1970: 0)
            return Entry(url: url, modified: modified, size: values?.fileSize ?? 0)
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
