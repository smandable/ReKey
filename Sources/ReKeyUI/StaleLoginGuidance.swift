import Foundation
import Model
import CleanupScript

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
    /// Delegates to ``CleanupScriptBuilder/deleteCommand`` — the single source of
    /// truth for the `delete --site` command string.
    static func cliCommand(for source: BrowserSource, domain: String, username: String) -> String? {
        CleanupScriptBuilder.deleteCommand(browser: source, site: domain, username: username, confirm: false)
    }
}
