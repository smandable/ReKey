import Foundation
import Model

/// Builds the (guidance-only) advice shown after a fix is done, for removing a
/// stale saved login if the browser saved a new entry instead of updating.
///
/// The sandboxed app never deletes anything; this is text plus a copy-paste
/// command for the separate `rekey-cleanup` tool.
enum StaleLoginGuidance {
    /// Manual, in-browser steps to delete the old entry.
    static func manualSteps(for source: BrowserSource, domain: String) -> String {
        switch source {
        case .firefox:
            return "Firefox → about:logins → find \(domain) → Remove."
        case .applePasswords:
            return "Open the Passwords app → find \(domain) → right-click → Delete."
        case .chrome, .arc, .brave, .edge, .opera, .vivaldi, .chromium:
            return "\(source.displayName) → Settings → Password Manager → \(domain) → Delete."
        case .unknown:
            return "Open your browser's password manager → find \(domain) → delete the old entry."
        }
    }

    /// A ready-to-run `rekey-cleanup` command (dry-run; the user adds `--confirm`
    /// after quitting the browser). Nil when the tool doesn't support the source.
    static func cliCommand(for source: BrowserSource, domain: String, username: String) -> String? {
        guard let browser = source.cleanupCLIName else { return nil }
        var command = "rekey-cleanup delete --browser \(browser) --site \(domain)"
        // Firefox usernames are encrypted, so the tool can't filter by them;
        // only Chromium narrows by username.
        if source.isChromiumFamily, !username.isEmpty {
            command += " --username \(shellQuote(username))"
        }
        return command
    }

    private static func shellQuote(_ value: String) -> String {
        let safe = value.allSatisfy { $0.isLetter || $0.isNumber || "@._-+".contains($0) }
        if safe { return value }
        return "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
