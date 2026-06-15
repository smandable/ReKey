import Foundation
import Model

/// Default on-disk locations and bundle identifiers for the browsers this tool
/// supports. `--path` always overrides these.
public enum BrowserPaths {

    /// macOS bundle identifier, used to detect whether the browser is running.
    public static func bundleIdentifier(for browser: BrowserSource) -> String? {
        switch browser {
        case .chrome: return "com.google.Chrome"
        case .arc: return "company.thebrowser.Browser"
        case .brave: return "com.brave.Browser"
        case .edge: return "com.microsoft.edgemac"
        case .opera: return "com.operasoftware.Opera"
        case .vivaldi: return "com.vivaldi.Vivaldi"
        case .chromium: return "org.chromium.Chromium"
        case .firefox: return "org.mozilla.firefox"
        case .applePasswords, .unknown: return nil
        }
    }

    /// Whether this tool supports operating on the browser's store. Delegates to
    /// the model so there's a single source of truth (Apple Passwords has no
    /// third-party delete API; `unknown` can't be targeted).
    public static func isSupported(_ browser: BrowserSource) -> Bool {
        browser.cleanupSupported
    }

    /// Application Support subdirectory holding the browser's profiles.
    private static func appSupportSubpath(for browser: BrowserSource) -> String? {
        switch browser {
        case .chrome: return "Google/Chrome"
        case .arc: return "Arc/User Data"
        case .brave: return "BraveSoftware/Brave-Browser"
        case .edge: return "Microsoft Edge"
        case .vivaldi: return "Vivaldi"
        case .chromium: return "Chromium"
        case .opera: return "com.operasoftware.Opera"
        case .firefox: return "Firefox"
        case .applePasswords, .unknown: return nil
        }
    }

    private static var applicationSupport: URL? {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
    }

    /// Best-effort default store file for a browser/profile. Returns nil if it
    /// can't be resolved (the caller should ask the user for `--path`).
    public static func defaultStoreURL(for browser: BrowserSource, profile: String?) -> URL? {
        guard let appSupport = applicationSupport,
              let sub = appSupportSubpath(for: browser) else { return nil }
        let base = appSupport.appendingPathComponent(sub, isDirectory: true)

        if browser == .firefox {
            return firefoxLoginsURL(in: base, profile: profile)
        }

        // Opera keeps a flat profile (Login Data directly under the base).
        if browser == .opera {
            return base.appendingPathComponent("Login Data")
        }

        // Other Chromium browsers: <base>/<profile>/Login Data.
        let profileDir = (profile?.isEmpty == false) ? profile! : "Default"
        return base.appendingPathComponent(profileDir, isDirectory: true)
            .appendingPathComponent("Login Data")
    }

    /// Resolve Firefox's `logins.json`. With no explicit profile, prefer a
    /// `*.default-release` profile, then `*.default`, else the first profile.
    private static func firefoxLoginsURL(in firefoxBase: URL, profile: String?) -> URL? {
        let profilesDir = firefoxBase.appendingPathComponent("Profiles", isDirectory: true)
        let fm = FileManager.default

        if let profile, !profile.isEmpty {
            return profilesDir.appendingPathComponent(profile, isDirectory: true)
                .appendingPathComponent("logins.json")
        }

        guard let entries = try? fm.contentsOfDirectory(at: profilesDir,
                                                        includingPropertiesForKeys: nil) else {
            return nil
        }
        let dirs = entries.filter { (try? $0.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true }
        func pick(_ suffix: String) -> URL? { dirs.first { $0.lastPathComponent.hasSuffix(suffix) } }
        let chosen = pick(".default-release") ?? pick(".default") ?? dirs.sorted { $0.lastPathComponent < $1.lastPathComponent }.first
        return chosen?.appendingPathComponent("logins.json")
    }
}
