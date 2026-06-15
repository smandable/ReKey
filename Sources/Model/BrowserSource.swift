import Foundation

/// Which password manager a credential was exported from.
///
/// Arc and Chrome are both Chromium and emit byte-identical CSV layouts, so the
/// format detector cannot tell them apart from the file alone. `arc` is only
/// ever assigned when the user explicitly tags a file as Arc at import time;
/// otherwise Chromium files map to `chrome`.
public enum BrowserSource: String, Sendable, CaseIterable, Codable {
    case chrome
    case arc
    case firefox
    case applePasswords
    case unknown

    /// Human-facing label for the findings/UI.
    public var displayName: String {
        switch self {
        case .chrome: return "Chrome"
        case .arc: return "Arc"
        case .firefox: return "Firefox"
        case .applePasswords: return "Apple Passwords"
        case .unknown: return "Unknown"
        }
    }
}
