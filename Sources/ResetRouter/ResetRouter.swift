import Foundation

/// How a change-password URL was determined.
public enum ResetSource: Sendable, Equatable {
    /// Resolved via the W3C `/.well-known/change-password` convention (and the
    /// server passed the control-probe heuristic, so we trust it).
    case wellKnown
    /// Looked up in the curated, bundled fallback map.
    case fallbackMap
    /// Neither well-known nor the map matched; we fall back to the bare site
    /// root and ask the user to find the setting themselves. Not confident.
    case siteRoot
}

/// The resolved change-password destination for a single registrable domain.
public struct ResetResolution: Sendable, Equatable {
    /// The URL to open. For `.siteRoot` this is `https://{domain}/`.
    public let url: URL
    /// How `url` was determined.
    public let source: ResetSource

    /// Whether we believe `url` is an actual change-password page. `false` only
    /// for `.siteRoot`, where the UI must tell the user to locate the setting.
    public var isConfident: Bool { source != .siteRoot }

    public init(url: URL, source: ResetSource) {
        self.url = url
        self.source = source
    }
}

/// Resolves the URL a user should open to change their password for a site.
///
/// ## Resolution order
/// 1. **Well-known** — `GET https://{domain}/.well-known/change-password`,
///    following redirects. Trusted only when it passes the control probe below.
/// 2. **Fallback map** — a curated, bundled domain → change-URL table.
/// 3. **Site root** — `https://{domain}/`, not confident.
///
/// ## Control-probe heuristic (why well-known alone isn't enough)
/// Many servers return `200` for *every* path, including ones that don't exist,
/// so a `200` on `/.well-known/change-password` doesn't prove support. To detect
/// this, we *also* request a random, certainly-nonexistent path under
/// `/.well-known/`. We trust well-known only when:
///
/// - the change-password path resolves to `2xx` (after redirects), **and**
/// - the control path returns a not-found status (`>= 400`).
///
/// If the control path *also* returns `200`, the server doesn't do proper 404s,
/// so its `200` on the change-password path is meaningless — we do **not** trust
/// well-known and fall through to the map / site root.
///
/// ## Lazy by construction (privacy)
/// There is deliberately **no batch API** and **nothing pings at import time**.
/// Only a single-domain `resolveChangeURL(for:)` exists, invoked lazily when the
/// user actually wants to fix one credential. A batch resolver would broadcast
/// the user's entire account list to all those domains the moment they import —
/// exactly the kind of leak a local-first auditor must avoid. Resolving one
/// domain only reveals that one domain, at the moment the user acts on it.
///
/// No URL is ever guessed heuristically or by an LLM: the only sources are the
/// well-known probe, the curated map, and the site root.
public struct ResetRouter: Sendable {
    private let session: URLSession
    private let fallbackMap: [String: String]

    /// - Parameters:
    ///   - session: injected for tests; defaults to `.shared`.
    ///   - fallbackMap: domain → change-URL overrides. `nil` (the default)
    ///     loads the bundled `FallbackMap.json` `entries`.
    public init(session: URLSession = .shared, fallbackMap: [String: String]? = nil) {
        self.session = session
        self.fallbackMap = fallbackMap ?? FallbackMapLoader.loadBundled()
    }

    /// Resolve the change-password URL for one registrable domain.
    ///
    /// Never throws: network failures collapse to the fallback map or site root.
    public func resolveChangeURL(for registrableDomain: String) async -> ResetResolution {
        let domain = normalize(registrableDomain)

        if let resolved = await wellKnownURL(for: domain) {
            return ResetResolution(url: resolved, source: .wellKnown)
        }

        if let mapped = fallbackMap[domain], let url = URL(string: mapped) {
            return ResetResolution(url: url, source: .fallbackMap)
        }

        return ResetResolution(url: siteRoot(for: domain), source: .siteRoot)
    }

    // MARK: - Well-known probing

    /// Returns the final change-password URL if well-known is genuinely
    /// supported (passes the control-probe heuristic), else `nil`.
    private func wellKnownURL(for domain: String) async -> URL? {
        guard let changeURL = URL(string: "https://\(domain)/.well-known/change-password"),
              let controlURL = controlURL(for: domain)
        else { return nil }

        // The change-password path must resolve to 2xx (after redirects).
        guard let change = await probe(changeURL), (200..<300).contains(change.status) else {
            return nil
        }

        // The control path must be a real not-found. If it's also a success,
        // the server 200s everything and we can't trust the change result.
        guard let control = await probe(controlURL), control.status >= 400 else {
            return nil
        }

        // Prefer the final (post-redirect) URL the change request landed on.
        return change.finalURL ?? changeURL
    }

    /// A random, certainly-nonexistent path under `/.well-known/`, used to learn
    /// whether the server returns honest 404s.
    private func controlURL(for domain: String) -> URL? {
        let nonce = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        return URL(string: "https://\(domain)/.well-known/rekey-control-\(nonce)")
    }

    private struct ProbeResult {
        let status: Int
        let finalURL: URL?
    }

    /// Perform a redirect-following GET and report the final status + URL.
    /// Any thrown error (offline, DNS, TLS, …) collapses to `nil`.
    private func probe(_ url: URL) async -> ProbeResult? {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        // A change-password probe is a nicety, not a blocker — don't let a slow or
        // blackholing host hold it open for URLSession's 60s default.
        request.timeoutInterval = 6
        do {
            let (_, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else { return nil }
            return ProbeResult(status: http.statusCode, finalURL: http.url)
        } catch {
            return nil
        }
    }

    // MARK: - Helpers

    private func siteRoot(for domain: String) -> URL {
        URL(string: "https://\(domain)/") ?? URL(string: "https://example.invalid/")!
    }

    /// Lowercase and strip a trailing dot / surrounding whitespace. Keeps the
    /// caller's registrable domain otherwise intact (no parsing of subdomains —
    /// the input is already an eTLD+1).
    private func normalize(_ domain: String) -> String {
        var d = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while d.hasSuffix(".") { d.removeLast() }
        return d
    }
}
