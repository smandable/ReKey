import Foundation

/// Abstraction over change-password URL resolution.
///
/// Lets the fix queue depend on resolution without the concrete `ResetRouter`
/// (and its `URLSession`), so the queue is testable without any network and the
/// router is injected at the app layer. Single-domain only, on purpose — there
/// is no batch resolution (privacy: it would broadcast the user's whole account
/// list to every domain).
public protocol ChangeURLResolving: Sendable {
    func resolveChangeURL(for registrableDomain: String) async -> ResetResolution
}

extension ResetRouter: ChangeURLResolving {}
