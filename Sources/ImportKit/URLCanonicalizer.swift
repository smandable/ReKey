import Foundation

/// Turns a raw exported URL into a host and a registrable domain for grouping
/// and display. The original URL is kept separately on the credential for the
/// reset-routing step — canonicalization is for grouping only, never for
/// matching passwords.
public struct URLCanonicalizer: Sendable {
    private let psl: PublicSuffixList

    public init(psl: PublicSuffixList) {
        self.psl = psl
    }

    /// Convenience initializer using the vendored Public Suffix List.
    public init() {
        self.psl = .bundled()
    }

    /// Extract the host: lowercase it and strip a single leading `www.`.
    /// Returns nil if no host could be parsed.
    public func host(fromRawURL raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        // Ensure a scheme so URLComponents can find the host. If there's no
        // "scheme://", prepend a placeholder.
        let withScheme: String
        if trimmed.contains("://") {
            withScheme = trimmed
        } else {
            withScheme = "https://" + trimmed
        }

        guard
            let components = URLComponents(string: withScheme),
            var host = components.host?.lowercased(),
            !host.isEmpty
        else {
            return nil
        }

        // IPv6 literals come bracketed from URLComponents on some platforms.
        if host.hasPrefix("["), host.hasSuffix("]") {
            host = String(host.dropFirst().dropLast())
        }
        if host.hasPrefix("www.") {
            host.removeFirst(4)
        }
        return host
    }

    /// The registrable domain (eTLD+1) for grouping, e.g. `accounts.google.com`
    /// -> `google.com`. Falls back to the bare host if no eTLD+1 can be derived
    /// (e.g. the host is itself a public suffix, or an IP / single label).
    public func registrableDomain(fromRawURL raw: String) -> String? {
        guard let host = host(fromRawURL: raw) else { return nil }
        // IP literals have no registrable domain — return them verbatim so
        // distinct devices (192.168.1.1 vs 10.0.1.1) don't collapse to a bogus
        // "1.1" via the PSL default rule.
        if Self.isIPLiteral(host) { return host }
        return psl.registrableDomain(of: host) ?? host
    }

    /// True for an IPv4 literal (four all-digit dot labels) or an IPv6 literal
    /// (contains a colon).
    static func isIPLiteral(_ host: String) -> Bool {
        if host.contains(":") { return true }   // IPv6
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        return labels.count == 4 && labels.allSatisfy { !$0.isEmpty && $0.allSatisfy(\.isNumber) }
    }
}
