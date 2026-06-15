import Foundation

/// Loads the curated change-password fallback map bundled with this module.
///
/// The JSON shape is:
/// ```json
/// { "version": 1, "comment": "…", "entries": { "<domain>": "<changeURL>", … } }
/// ```
/// Only the `entries` dictionary is consumed — `version`/`comment` are metadata.
///
/// This loader never throws and never crashes: any failure (missing resource,
/// malformed JSON, wrong shape) yields an empty map. The router degrades to the
/// site-root behavior, which is always safe.
enum FallbackMapLoader {
    /// The decoded top-level document. Only `entries` is used downstream.
    private struct Document: Decodable {
        let entries: [String: String]
    }

    /// Load the bundled `FallbackMap.json` "entries" dictionary.
    ///
    /// - Returns: domain → change-URL string map, or empty on any failure.
    static func loadBundled() -> [String: String] {
        guard let url = Bundle.module.url(forResource: "FallbackMap", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let doc = try? JSONDecoder().decode(Document.self, from: data)
        else {
            return [:]
        }
        return doc.entries
    }
}
