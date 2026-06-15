import Foundation
import Model
#if canImport(AppKit)
import AppKit
#endif

/// Checks whether a browser is currently running. Writing to a store while its
/// browser is open is the classic corruption path, so a delete is refused
/// unless this returns false. Injectable so tests can simulate both states.
public protocol RunningBrowserChecking: Sendable {
    func isRunning(_ browser: BrowserSource) -> Bool
}

#if canImport(AppKit)
/// Real check via `NSRunningApplication`, matched on bundle identifier.
public struct SystemRunningBrowserChecker: RunningBrowserChecking {
    public init() {}
    public func isRunning(_ browser: BrowserSource) -> Bool {
        guard let bundleID = BrowserPaths.bundleIdentifier(for: browser) else { return false }
        return !NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).isEmpty
    }
}
#endif
