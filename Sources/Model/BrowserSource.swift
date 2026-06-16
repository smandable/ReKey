import Foundation

/// Which password manager a credential was exported from.
///
/// Many Mac browsers share an export format, so the CSV alone can't always
/// identify the specific browser:
/// - **Chromium family** (Chrome, Arc, Brave, Edge, Opera, Vivaldi, …) all emit
///   the byte-identical `name,url,username,password,note` layout. The detector
///   classifies them all as Chromium; the *specific* label is chosen by the user
///   at import time (defaulting to Chrome).
/// - **Gecko family** (Firefox, LibreWolf, Waterfox, Tor Browser, …) all emit
///   the Firefox layout and are labeled `firefox`.
/// - **Apple Passwords / Safari** has its own capitalized layout.
public enum BrowserSource: String, Sendable, CaseIterable, Codable {
    // Chromium family
    case chrome
    case arc
    case brave
    case edge
    case opera
    case vivaldi
    /// Any other Chromium-based browser the user didn't pick specifically.
    case chromium

    // Gecko family
    case firefox

    // Apple / WebKit
    case applePasswords

    case unknown

    /// Human-facing label for the findings/UI.
    public var displayName: String {
        switch self {
        case .chrome: return "Chrome"
        case .arc: return "Arc"
        case .brave: return "Brave"
        case .edge: return "Microsoft Edge"
        case .opera: return "Opera"
        case .vivaldi: return "Vivaldi"
        case .chromium: return "Chromium"
        case .firefox: return "Firefox"
        case .applePasswords: return "Apple Passwords"
        case .unknown: return "Unknown"
        }
    }

    /// Chromium-based browsers, which all share the same CSV layout. The user
    /// picks which one a Chromium file came from at import time.
    public static let chromiumFamily: [BrowserSource] =
        [.chrome, .arc, .brave, .edge, .opera, .vivaldi, .chromium]

    public var isChromiumFamily: Bool {
        BrowserSource.chromiumFamily.contains(self)
    }

    /// Apple's password store (iCloud Keychain / Passwords app). It doesn't sync
    /// with browser/Google stores, so an account saved both here and in a browser
    /// must be updated in both — the split that bites on iPhone/iPad.
    public var isApple: Bool { self == .applePasswords }

    /// Whether the opt-in `rekey-cleanup` tool can delete logins for this source.
    /// Apple Passwords has no third-party delete API; `unknown` can't be targeted.
    public var cleanupSupported: Bool {
        isChromiumFamily || self == .firefox
    }

    /// The `--browser` argument for `rekey-cleanup`, or nil if unsupported.
    public var cleanupCLIName: String? {
        cleanupSupported ? rawValue : nil
    }
}
