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

    /// Progress-reporting variant of `check(_:)`.
    ///
    /// `onProgress(done, total)` reports how many of the `total` distinct lookups
    /// the implementation has completed. `total` is the deduped unit of work (for
    /// HIBP, the number of distinct hash-range requests), so it is typically far
    /// smaller than `secrets.count`; `total == 0` means there was nothing to fetch
    /// (e.g. everything was cached). The callback may be invoked from any thread.
    ///
    /// This is a customization point with a default implementation that ignores
    /// progress and delegates to `check(_:)`, so existing conformers (and test
    /// stubs) need not implement it.
    func check(
        _ secrets: [UUID: Secret],
        onProgress: @Sendable (_ done: Int, _ total: Int) -> Void
    ) async -> [UUID: CompromisedStatus]
}

public extension CompromiseChecking {
    func check(
        _ secrets: [UUID: Secret],
        onProgress: @Sendable (_ done: Int, _ total: Int) -> Void
    ) async -> [UUID: CompromisedStatus] {
        await check(secrets)
    }
}
