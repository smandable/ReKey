import Testing
import Model
@testable import BrowserStore

@Suite("Cleanup hint")
struct CleanupHintTests {

    @Test("Surfaces a same-site login a narrower filter skipped (e.g. blank username)")
    func hintsWhenSiteHasOtherLogins() {
        let filter = LoginFilter(site: "creativecircle.com", username: "smandable@gmail.com")
        let hint = CleanupHint.unmatchedFilter(filter: filter, browser: .chrome, siteMatchCount: 1)
        #expect(hint != nil)
        #expect(hint!.contains("creativecircle.com"))
        #expect(hint!.contains("1 other login"))      // singular
        #expect(hint!.contains("exists"))
        #expect(hint!.contains("--browser chrome --site creativecircle.com"))  // runnable
    }

    @Test("Pluralizes when several other logins exist")
    func pluralizes() {
        let filter = LoginFilter(site: "example.com", identifiers: ["7"])
        let hint = CleanupHint.unmatchedFilter(filter: filter, browser: .arc, siteMatchCount: 3)
        #expect(hint?.contains("3 other logins") == true)
        #expect(hint?.contains("exist") == true)
        #expect(hint?.contains("--browser arc") == true)
    }

    @Test("No hint when the filter was already site-only (nothing was narrowed)")
    func noHintForSiteOnlyFilter() {
        let filter = LoginFilter(site: "example.com")
        #expect(CleanupHint.unmatchedFilter(filter: filter, browser: .chrome, siteMatchCount: 5) == nil)
    }

    @Test("No hint without a site to broaden on, or when the site has nothing")
    func noHintWhenUnwarranted() {
        // No site (username-only filter) — nothing to suggest.
        #expect(CleanupHint.unmatchedFilter(
            filter: LoginFilter(username: "x@y.com"), browser: .chrome, siteMatchCount: 4) == nil)
        // Site narrowed by username, but the site genuinely has no logins.
        #expect(CleanupHint.unmatchedFilter(
            filter: LoginFilter(site: "nope.com", username: "x@y.com"), browser: .chrome, siteMatchCount: 0) == nil)
    }
}
