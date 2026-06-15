import Foundation

/// Abstraction over the compromised-password check.
///
/// Lets the audit engine orchestrate the check without importing the networking
/// module, so `AuditEngine` is unit-testable with an in-memory stub and the
/// concrete HIBP client is injected by the app at the top level.
public protocol CompromiseChecking: Sendable {
    /// Check a batch of secrets keyed by credential id.
    ///
    /// Implementations must dedupe by password value internally and must return
    /// `.unknown` for any entry they couldn't resolve (offline / request failed)
    /// rather than throwing — a partial result is always preferable to failing
    /// the whole audit. Every input key must appear in the output.
    func check(_ secrets: [UUID: Secret]) async -> [UUID: CompromisedStatus]
}
