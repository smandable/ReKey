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
}
