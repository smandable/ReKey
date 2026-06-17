import Foundation

/// Locates a vendored resource across the contexts ReKey runs in.
///
/// Why this exists: SwiftPM's generated `Bundle.module` accessor looks for
/// `<Name>.bundle` next to `Bundle.main.bundleURL`, which for a packaged `.app`
/// is the bundle **root** — a location codesign can't seal. So the packaging
/// step places the resource bundles under `Contents/Resources` (sealed,
/// standard), and this resolver checks there first. `Bundle.module` is consulted
/// only as a lazy fallback (`@autoclosure`), so for the packaged app — where the
/// `Contents/Resources` candidate matches — the accessor is never evaluated and
/// can't trip its own `fatalError`. For `swift test` / `swift run`, the
/// candidates miss and the fallback resolves normally.
public enum ReKeyResources {
    public static func url(
        forResource name: String,
        withExtension ext: String,
        moduleBundleName: String,
        fallback: @autoclosure () -> Bundle
    ) -> URL? {
        let fm = FileManager.default
        let filename = "\(name).\(ext)"

        var candidates: [URL] = []
        if let resources = Bundle.main.resourceURL {
            candidates.append(resources.appendingPathComponent("\(moduleBundleName).bundle"))
            candidates.append(resources)
        }
        // SwiftPM accessor's location (app root / next to the executable's bundle).
        candidates.append(Bundle.main.bundleURL.appendingPathComponent("\(moduleBundleName).bundle"))

        for base in candidates {
            let candidate = base.appendingPathComponent(filename)
            if fm.fileExists(atPath: candidate.path) { return candidate }
        }

        // Lazy fallback — only evaluated if nothing above matched.
        return fallback().url(forResource: name, withExtension: ext)
    }
}
