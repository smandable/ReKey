import Foundation
import Model

/// The Mozilla Public Suffix List, used to compute the registrable domain
/// (eTLD+1) of a host.
///
/// A naive "last two labels" rule is wrong for multi-part suffixes: `bbc.co.uk`
/// must resolve to `bbc.co.uk` (not `co.uk`) and `a.b.ck` must respect the
/// `*.ck` wildcard. This implements the official PSL algorithm including
/// wildcard (`*`) and exception (`!`) rules.
///
/// The list is **vendored** (bundled as a resource) and parsed locally; it is
/// never fetched at runtime.
public struct PublicSuffixList: Sendable {
    private let rules: Set<String>        // exact rules, e.g. "com", "co.uk"
    private let wildcards: Set<String>    // for rule "*.ck" -> stores "ck"
    private let exceptions: Set<String>   // for rule "!www.ck" -> stores "www.ck"

    /// Build from the raw `.dat` text.
    public init(data text: String) {
        var rules = Set<String>()
        var wildcards = Set<String>()
        var exceptions = Set<String>()

        text.enumerateLines { line, _ in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // Skip comments and blanks. Comments start with "//".
            guard !trimmed.isEmpty, !trimmed.hasPrefix("//") else { return }
            // A rule may have a trailing comment? The PSL puts comments on their
            // own lines, so the whole line is the rule. Lowercase for matching.
            let rule = trimmed.lowercased()
            if rule.hasPrefix("!") {
                exceptions.insert(String(rule.dropFirst()))
            } else if rule.hasPrefix("*.") {
                wildcards.insert(String(rule.dropFirst(2)))
            } else {
                rules.insert(rule)
            }
        }

        self.rules = rules
        self.wildcards = wildcards
        self.exceptions = exceptions
    }

    /// Load the vendored list bundled with this module.
    public static func bundled() -> PublicSuffixList {
        guard
            let url = RekeyResources.url(forResource: "public_suffix_list", withExtension: "dat",
                                         moduleBundleName: "Rekey_ImportKit", fallback: .module),
            let text = try? String(contentsOf: url, encoding: .utf8)
        else {
            // Fall back to an empty list (default rule "*" still applies, so
            // eTLD+1 degrades to last-two-labels) rather than crashing.
            return PublicSuffixList(data: "")
        }
        return PublicSuffixList(data: text)
    }

    /// Number of labels in the public suffix (eTLD) of `host`.
    private func publicSuffixLabelCount(_ labels: [String]) -> Int {
        guard !labels.isEmpty else { return 0 }

        // Exception rules win outright. An exception "!www.ck" means the public
        // suffix is the rule minus its leftmost label.
        for k in 0..<labels.count {
            let candidate = labels[k...].joined(separator: ".")
            if exceptions.contains(candidate) {
                return labels.count - (k + 1)
            }
        }

        // Otherwise the prevailing rule is the longest matching normal or
        // wildcard rule.
        var best = 0
        for k in 0..<labels.count {
            let candidate = labels[k...].joined(separator: ".")
            let labelCount = labels.count - k
            if rules.contains(candidate) {
                best = max(best, labelCount)
            }
            // Wildcard "*.X" matches a candidate "<anyLabel>.X": the labels after
            // position k must equal a stored wildcard tail, and label k is the "*".
            if k + 1 <= labels.count {
                let afterStar = labels[(k + 1)...].joined(separator: ".")
                if !afterStar.isEmpty, wildcards.contains(afterStar) {
                    best = max(best, labelCount)
                }
            }
        }

        // Default rule "*": an unmatched name has a public suffix of one label.
        return best == 0 ? 1 : best
    }

    /// The registrable domain (eTLD+1) of `host`, or nil if `host` is itself a
    /// public suffix (e.g. "co.uk") or has no host.
    ///
    /// `host` should already be lowercased with any `www.` stripped, but this is
    /// defensive and lowercases again.
    public func registrableDomain(of host: String) -> String? {
        let cleaned = host.lowercased()
        let labels = cleaned.split(separator: ".", omittingEmptySubsequences: true).map(String.init)
        guard !labels.isEmpty else { return nil }

        let suffixLen = publicSuffixLabelCount(labels)
        guard labels.count > suffixLen else {
            return nil   // host is a public suffix itself; no registrable domain
        }
        return labels.suffix(suffixLen + 1).joined(separator: ".")
    }
}
