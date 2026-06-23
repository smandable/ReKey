import Foundation
import Model

// CleanupScript — the single, unit-testable source of truth for the
// `rekey-cleanup` command strings and `purge` heredoc blocks that ReKey
// generates and tells the user to run in a non-sandboxed shell.
//
// This is security-load-bearing: the same plaintext that flows in from an
// attacker-influenceable CSV (a site/username) is interpolated into destructive
// shell commands. Keeping it here — out of the SwiftUI views and AppModel, and
// with no duplicate copies — is what lets the smuggling defenses below be tested
// once and trusted everywhere.

/// One (browser, site, username) the cleanup script should target. For a safe
/// target, `username` is "" when the delete is site-level (Firefox — encrypted
/// usernames — or a blank-username login).
public struct CleanupTarget: Sendable {
    public let source: BrowserSource
    public let site: String
    public let username: String
    public init(source: BrowserSource, site: String, username: String) {
        self.source = source
        self.site = site
        self.username = username
    }
}

/// A site that a one-line `--site` delete can't safely clean: the entry the user
/// fixed/marked has no username to target and the site has other saved logins
/// that the delete would also remove. Surfaced so the cleanup script can give
/// id-based instructions instead.
public struct ManualCleanupSite: Sendable {
    public let domain: String
    public let browser: BrowserSource
    public let loginCount: Int
    public init(domain: String, browser: BrowserSource, loginCount: Int) {
        self.domain = domain
        self.browser = browser
        self.loginCount = loginCount
    }
}

public enum CleanupScriptBuilder {

    // MARK: - Single-line `delete` / `list` commands

    /// The canonical `rekey-cleanup delete --site` command — the single source of
    /// truth all the call sites route through. Returns nil when the tool can't
    /// delete for this source (Apple Passwords / unknown). Only Chromium narrows
    /// by username (Firefox usernames are encrypted, so the tool can't filter by
    /// them). Every interpolated value is shell-quoted via `shellArgument`.
    public static func deleteCommand(
        browser: BrowserSource, site: String, username: String?, confirm: Bool
    ) -> String? {
        guard let cli = browser.cleanupCLIName else { return nil }
        var cmd = "rekey-cleanup delete --browser \(cli) --site \(site.shellArgument)"
        if browser.isChromiumFamily, let username, !username.isEmpty {
            cmd += " --username \(username.shellArgument)"
        }
        if confirm { cmd += " --confirm" }
        return cmd
    }

    /// The canonical `rekey-cleanup list --site` command (discovery only — `list`
    /// never deletes). Nil when the source is unsupported.
    public static func listCommand(browser: BrowserSource, site: String) -> String? {
        guard let cli = browser.cleanupCLIName else { return nil }
        return "rekey-cleanup list --browser \(cli) --site \(site.shellArgument)"
    }

    // MARK: - `purge` heredoc blocks (the cull/aggregate batch path)

    /// Shared body builder: one `purge` heredoc per browser for the safe targets,
    /// then a `--no-username` block per browser for the forced sites, then any
    /// still-manual sites as commented `list` → `delete --id` steps. When
    /// `tallyVar` is set, each purge appends to `$<tallyVar>` for a grand total.
    ///
    /// Targets reach the heredoc body verbatim, on their own line, as `site` or
    /// `site<TAB>username`. Each field is run through ``sanitizeHeredocField`` and
    /// the closing delimiter is chosen by ``heredocDelimiter(avoiding:)`` so that
    /// a crafted site/username can neither add, drop, nor *terminate* a line —
    /// closing the target-smuggling / shell-injection hole.
    public static func purgeBlocks(
        safe: [CleanupTarget],
        forced: [ManualCleanupSite],
        stillManual: [ManualCleanupSite],
        confirm: Bool,
        tallyVar: String?
    ) -> [String] {
        let confirmFlag = confirm ? " --confirm" : ""
        let tally = tallyVar.map { " --tally \"$\($0)\"" } ?? ""
        var lines: [String] = []

        let byBrowser = Dictionary(grouping: safe, by: \.source)
        for browser in byBrowser.keys.sorted(by: { $0.displayName < $1.displayName }) {
            let cli = browser.cleanupCLIName ?? browser.rawValue
            let group = byBrowser[browser]!.sorted { $0.site < $1.site }
            let body = group.map { bodyLine(site: $0.site, username: $0.username) }
            lines.append("# \(browser.displayName) — \(group.count) site(s)")
            lines += heredoc(command: "rekey-cleanup purge --browser \(cli)\(confirmFlag)\(tally)",
                             body: body)
        }

        if !forced.isEmpty {
            // Force the no-username removals precisely: --no-username deletes only
            // the empty-username rows on each site, leaving the named siblings.
            let forcedByBrowser = Dictionary(grouping: forced, by: \.browser)
            for browser in forcedByBrowser.keys.sorted(by: { $0.displayName < $1.displayName }) {
                let cli = browser.cleanupCLIName ?? browser.rawValue
                let sites = forcedByBrowser[browser]!.sorted { $0.domain < $1.domain }
                let body = sites.map { bodyLine(site: $0.domain, username: "") }
                lines.append("# \(browser.displayName) — \(sites.count) site(s), no-username rows only (forced)")
                lines += heredoc(command: "rekey-cleanup purge --browser \(cli) --no-username\(confirmFlag)\(tally)",
                                 body: body)
            }
        }

        if !stillManual.isEmpty {
            lines.append("# ⚠︎ Manual deletion — these have no username on a site that has other saved")
            lines.append("#    logins, so deleting by site would remove them too. Remove just the one you")
            lines.append("#    marked, by id:")
            for site in stillManual {
                let cli = site.browser.cleanupCLIName ?? site.browser.rawValue
                lines.append("#    \(site.domain) (\(site.browser.displayName), \(site.loginCount) logins):")
                if let list = listCommand(browser: site.browser, site: site.domain) {
                    lines.append("#      \(list)")
                }
                lines.append("#      rekey-cleanup delete --browser \(cli) --id <id-of-the-login-you-marked> --confirm")
            }
        }
        return lines
    }

    // MARK: - Heredoc smuggling defenses

    /// The base closing delimiter for a `purge` target heredoc.
    public static let heredocDelimiterBase = "REKEY_TARGETS"

    /// One target line for the heredoc body: `site` or `site<TAB>username`, with
    /// both fields sanitized so the single inserted tab is the only field
    /// separator and the value occupies exactly one line.
    static func bodyLine(site: String, username: String) -> String {
        let s = sanitizeHeredocField(site)
        let u = sanitizeHeredocField(username)
        return u.isEmpty ? s : "\(s)\t\(u)"
    }

    /// Replace every control character (newline, carriage return, tab, and any
    /// other C0/C1 control) with a space, so a field can't introduce a new line,
    /// corrupt the `site<TAB>username` split, or sneak in the closing delimiter on
    /// its own line. A real domain/username never contains these; a sanitized odd
    /// value simply won't match any stored login downstream — a safe no-op.
    public static func sanitizeHeredocField(_ s: String) -> String {
        let space = Unicode.Scalar(0x20)!
        var view = String.UnicodeScalarView()
        view.reserveCapacity(s.unicodeScalars.count)
        for scalar in s.unicodeScalars {
            view.append(CharacterSet.controlCharacters.contains(scalar) ? space : scalar)
        }
        return String(view)
    }

    /// Pick a heredoc delimiter that does not appear as any body line, so the
    /// heredoc can't be terminated early by a value equal to the delimiter. Body
    /// lines are already single-line (sanitized); the `site<TAB>username` form
    /// contains a tab so can never equal the tab-free delimiter — only a bare
    /// `site == REKEY_TARGETS` could collide, and this steps to `REKEY_TARGETS_2`,
    /// `_3`, … until clear. Terminates because the body is finite.
    static func heredocDelimiter(avoiding body: [String]) -> String {
        let used = Set(body)
        guard used.contains(heredocDelimiterBase) else { return heredocDelimiterBase }
        var n = 2
        while used.contains("\(heredocDelimiterBase)_\(n)") { n += 1 }
        return "\(heredocDelimiterBase)_\(n)"
    }

    /// Assemble one quoted heredoc: command line, sanitized body, collision-free
    /// delimiter, and a trailing blank line. Empty (all-control) body lines are
    /// dropped — the parser would skip them anyway, and emitting them risks a
    /// blank that reads oddly. The delimiter is single-quoted (`<<'DELIM'`) so the
    /// body is never shell-evaluated.
    static func heredoc(command: String, body: [String]) -> [String] {
        let clean = body.filter { !$0.isEmpty }
        let delim = heredocDelimiter(avoiding: clean)
        var out = ["\(command) <<'\(delim)'"]
        out.append(contentsOf: clean)
        out.append(delim)
        out.append("")
        return out
    }
}
