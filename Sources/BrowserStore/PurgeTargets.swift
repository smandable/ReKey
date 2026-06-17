import Foundation

/// Parsing and precise host-matching for the `rekey-cleanup purge` batch command,
/// factored out of the CLI so it's unit-testable.
public enum PurgeTargets {
    /// One purge target: a site, and (Chromium only) the username to scope to.
    public struct Target: Equatable, Sendable {
        public let site: String
        public let username: String?
        public init(site: String, username: String?) {
            self.site = site
            self.username = username
        }
    }

    /// Parse stdin lines — `site` or `site<TAB>username` (username optional). Blank
    /// lines and `#` comments are skipped; surrounding whitespace is trimmed; an
    /// empty username becomes nil.
    public static func parse(_ lines: [String]) -> [Target] {
        var out: [Target] = []
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            let parts = trimmed.split(separator: "\t", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            let site = parts[0].trimmingCharacters(in: .whitespaces)
            guard !site.isEmpty else { continue }
            let user = parts.count > 1 ? parts[1].trimmingCharacters(in: .whitespaces) : ""
            out.append(Target(site: site, username: user.isEmpty ? nil : user))
        }
        return out
    }

    /// Whether a stored login's `origin` belongs to the target `site`: its host
    /// equals `site` (case-insensitive) or is a subdomain of it. This anchors the
    /// match so `LoginFilter`'s broad origin SUBSTRING test can't sweep in an
    /// unrelated domain — e.g. target "casino.com" must match "www.casino.com" but
    /// NOT "nodepositcasino.com" or "casino.com.evil.test".
    public static func originBelongsToSite(_ origin: String, site: String) -> Bool {
        let target = site.lowercased()
        guard !target.isEmpty else { return false }
        let host = (URLComponents(string: origin)?.host ?? origin).lowercased()
        return host == target || host.hasSuffix("." + target)
    }
}
