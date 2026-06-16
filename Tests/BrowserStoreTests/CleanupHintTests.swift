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

    // MARK: - Lone-match guard

    @Test("A single match without --id is a lone broad match (guard applies)")
    func loneBroadMatchDetection() {
        let siteFilter = LoginFilter(site: "fcpeuro.com")
        #expect(CleanupHint.isLoneBroadMatch(matchCount: 1, filter: siteFilter))
        // Pinned by --id → the user identified the exact row, so not guarded.
        #expect(!CleanupHint.isLoneBroadMatch(matchCount: 1, filter: LoginFilter(site: "fcpeuro.com", identifiers: ["212"])))
        // More than one match, or none, isn't the lone-match case.
        #expect(!CleanupHint.isLoneBroadMatch(matchCount: 2, filter: siteFilter))
        #expect(!CleanupHint.isLoneBroadMatch(matchCount: 0, filter: siteFilter))
    }

    @Test("Lone-match caution warns it may be the current login and gives the --id command")
    func loneMatchCautionText() {
        let login = StoredLogin(id: "212", browser: .arc, origin: "https://identity.fcpeuro.com/",
                                signonRealm: nil, username: "", usernameIsEncrypted: false,
                                createdAt: nil, lastUsedAt: nil)
        let filter = LoginFilter(site: "fcpeuro.com")
        let text = CleanupHint.loneMatchCaution(login: login, filter: filter, browser: .arc)
        #expect(text.contains("CURRENT"))                 // names the risk
        #expect(text.contains("Only 1 login matches"))
        #expect(text.contains("--browser arc --site fcpeuro.com --id 212 --confirm"))  // exact re-target
    }
}
