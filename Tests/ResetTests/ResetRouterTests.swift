import Foundation
import Testing
@testable import ResetRouter

/// All tests drive a `MockURLProtocol` — no live network is ever touched.
///
/// Routing notes: the change-password path is
/// `https://{domain}/.well-known/change-password`; the router's *control* path
/// is a random `https://{domain}/.well-known/rekey-control-<nonce>`. Handlers
/// below match the change path by suffix and treat everything else under
/// `/.well-known/` as the control path.
@Suite(.serialized)
struct ResetRouterTests {

    private let changePath = "/.well-known/change-password"

    private func isChangePath(_ url: URL) -> Bool {
        url.path == changePath
    }

    private func isControlPath(_ url: URL) -> Bool {
        url.path.hasPrefix("/.well-known/rekey-control-")
    }

    /// well-known 200 but the CONTROL probe errors (offline/DNS) => we can't
    /// confirm the server does honest 404s, so well-known is NOT trusted and we
    /// fall through (here, to `.siteRoot` with an empty map).
    @Test func wellKnownNotTrustedWhenControlProbeErrors() async {
        MockURLProtocol.handler = { [self] url in
            if isControlPath(url) { return .failure(.cannotFindHost) }
            return .status(200)
        }
        defer { MockURLProtocol.handler = nil }

        let router = ResetRouter(session: .mocked(), fallbackMap: [:])
        let result = await router.resolveChangeURL(for: "example.com")
        #expect(result.source == .siteRoot)
        #expect(result.isConfident == false)
    }

    /// well-known 200 + control 404 => `.wellKnown`, final URL is the change URL.
    @Test func wellKnownSupportedWhenControlIs404() async {
        MockURLProtocol.handler = { [self] url in
            if isChangePath(url) { return .status(200) }
            if isControlPath(url) { return .status(404) }
            return .status(404)
        }
        defer { MockURLProtocol.handler = nil }

        let router = ResetRouter(session: .mocked(), fallbackMap: [:])
        let result = await router.resolveChangeURL(for: "example.com")

        #expect(result.source == .wellKnown)
        #expect(result.url == URL(string: "https://example.com/.well-known/change-password"))
        #expect(result.isConfident)
    }

    /// well-known 200 but control ALSO 200 => server 200s everything; not
    /// trusted. With an empty map this falls through to `.siteRoot`.
    @Test func wellKnownNotTrustedWhenControlAlso200() async {
        MockURLProtocol.handler = { _ in .status(200) }
        defer { MockURLProtocol.handler = nil }

        let router = ResetRouter(session: .mocked(), fallbackMap: [:])
        let result = await router.resolveChangeURL(for: "example.com")

        #expect(result.source == .siteRoot)
        #expect(result.url == URL(string: "https://example.com/"))
        #expect(!result.isConfident)
    }

    /// well-known 200 + control 200, but domain IS in the map => the map wins
    /// over the untrusted well-known result.
    @Test func untrustedWellKnownFallsThroughToMap() async {
        MockURLProtocol.handler = { _ in .status(200) }
        defer { MockURLProtocol.handler = nil }

        let mapped = "https://acme.example/change"
        let router = ResetRouter(session: .mocked(), fallbackMap: ["acme.example": mapped])
        let result = await router.resolveChangeURL(for: "acme.example")

        #expect(result.source == .fallbackMap)
        #expect(result.url == URL(string: mapped))
        #expect(result.isConfident)
    }

    /// well-known 404, domain in map => `.fallbackMap` with the mapped URL.
    @Test func wellKnown404UsesFallbackMap() async {
        MockURLProtocol.handler = { _ in .status(404) }
        defer { MockURLProtocol.handler = nil }

        let mapped = "https://paypal.com/myaccount/security/password/change"
        let router = ResetRouter(session: .mocked(), fallbackMap: ["paypal.com": mapped])
        let result = await router.resolveChangeURL(for: "paypal.com")

        #expect(result.source == .fallbackMap)
        #expect(result.url == URL(string: mapped))
        #expect(result.isConfident)
    }

    /// well-known 404, not in map => `.siteRoot`, not confident, root URL.
    @Test func wellKnown404NotInMapUsesSiteRoot() async {
        MockURLProtocol.handler = { _ in .status(404) }
        defer { MockURLProtocol.handler = nil }

        let router = ResetRouter(session: .mocked(), fallbackMap: [:])
        let result = await router.resolveChangeURL(for: "nowhere.example")

        #expect(result.source == .siteRoot)
        #expect(result.isConfident == false)
        #expect(result.url == URL(string: "https://nowhere.example/"))
    }

    /// well-known 301 -> real change page 200 (control 404) => `.wellKnown`
    /// with the FINAL redirected URL.
    @Test func wellKnownRedirectUsesFinalURL() async {
        let finalChange = "https://account.example.com/security/change-password"
        MockURLProtocol.handler = { [self] url in
            if isChangePath(url) { return .redirect(to: finalChange) }
            if url.absoluteString == finalChange { return .status(200) }
            if isControlPath(url) { return .status(404) }
            return .status(404)
        }
        defer { MockURLProtocol.handler = nil }

        let router = ResetRouter(session: .mocked(), fallbackMap: [:])
        let result = await router.resolveChangeURL(for: "example.com")

        #expect(result.source == .wellKnown)
        #expect(result.url == URL(string: finalChange))
        #expect(result.isConfident)
    }

    /// Network error on the probe collapses to fallback / site root (never
    /// throws, never trusts well-known).
    @Test func networkErrorFallsThroughToSiteRoot() async {
        MockURLProtocol.handler = nil // protocol fails the request

        let router = ResetRouter(session: .mocked(), fallbackMap: [:])
        let result = await router.resolveChangeURL(for: "offline.example")

        #expect(result.source == .siteRoot)
        #expect(!result.isConfident)
    }

    /// Domain matching is case-insensitive and tolerant of a trailing dot.
    @Test func domainIsNormalized() async {
        MockURLProtocol.handler = { _ in .status(404) }
        defer { MockURLProtocol.handler = nil }

        let mapped = "https://github.com/settings/security"
        let router = ResetRouter(session: .mocked(), fallbackMap: ["github.com": mapped])
        let result = await router.resolveChangeURL(for: "GitHub.com.")

        #expect(result.source == .fallbackMap)
        #expect(result.url == URL(string: mapped))
    }

    /// The bundled map (passing `nil`) loads and contains a known entry.
    @Test func bundledMapLoads() async {
        let router = ResetRouter(session: .mocked(), fallbackMap: nil)
        // 404 everything so it can't pass well-known and must consult the map.
        MockURLProtocol.handler = { _ in .status(404) }
        defer { MockURLProtocol.handler = nil }

        let result = await router.resolveChangeURL(for: "github.com")
        #expect(result.source == .fallbackMap)
        #expect(result.url == URL(string: "https://github.com/settings/security"))
    }
}
