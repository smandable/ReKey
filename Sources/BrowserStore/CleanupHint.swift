import Foundation
import Model

/// Hints that turn a *silent* miss into a visible one. When a delete/list filter
/// matches nothing, the user has no way to tell "already clean" apart from "the
/// login is here, just under a username/id your filter didn't match" — e.g. an
/// entry saved with a blank username slipping past `--username`.
public enum CleanupHint {

    /// One-line hint for an empty exact-filter result when the *same site* still
    /// has logins under a different or blank username/id. Returns nil when no hint
    /// is warranted: no site to broaden on, the filter was already site-only (so
    /// nothing was narrowed away), or the site genuinely has no logins.
    public static func unmatchedFilter(
        filter: LoginFilter,
        browser: BrowserSource,
        siteMatchCount: Int
    ) -> String? {
        guard let site = filter.site, !site.isEmpty else { return nil }
        // Only meaningful if the filter was narrower than site-only — otherwise the
        // site-only count IS what we just queried, and there's nothing to suggest.
        let narrowed = (filter.username?.isEmpty == false) || !filter.identifiers.isEmpty
        guard narrowed, siteMatchCount > 0 else { return nil }

        let noun = siteMatchCount == 1 ? "login" : "logins"
        let verb = siteMatchCount == 1 ? "exists" : "exist"
        return "Note: \(siteMatchCount) other \(noun) for \"\(site)\" \(verb) under a different or blank "
            + "username/id. Inspect: rekey-cleanup list --browser \(browser.rawValue) --site \(site)"
    }

    /// A delete that matched exactly one login via a site/username filter (not
    /// pinned by `--id`). On its own, a lone match is indistinguishable from the
    /// user's *current* login: when a browser updates a login in place (rather
    /// than leaving a stale duplicate), the only entry left IS the live one. So a
    /// blind `--confirm` here would delete a real saved login — worth a caution,
    /// and a refusal unless the user re-targets it precisely by id.
    public static func isLoneBroadMatch(matchCount: Int, filter: LoginFilter) -> Bool {
        matchCount == 1 && filter.identifiers.isEmpty
    }

    /// Caution for a lone broad match, ending with the exact `--id` command to use
    /// once the user has confirmed the entry is the *old* one.
    public static func loneMatchCaution(
        login: StoredLogin,
        filter: LoginFilter,
        browser: BrowserSource
    ) -> String {
        var idCommand = "rekey-cleanup delete --browser \(browser.rawValue)"
        if let site = filter.site, !site.isEmpty { idCommand += " --site \(site)" }
        if let user = filter.username, !user.isEmpty { idCommand += " --username \(user)" }
        idCommand += " --id \(login.id) --confirm"

        return """
        Only 1 login matches. If your browser updated this login in place when you changed the
        password, THIS IS YOUR CURRENT login — not a stale duplicate — and deleting it removes
        your real saved login. A lone match is safe to delete only once you've confirmed it's
        the OLD entry (e.g. a leftover duplicate the browser saved alongside the new one).
        If it really is the old one, target it precisely by id:
          \(idCommand)
        """
    }
}
