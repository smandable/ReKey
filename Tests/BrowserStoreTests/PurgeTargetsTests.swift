import Testing
import Foundation
@testable import BrowserStore

@Suite("Purge targets (stdin parse + host-match anchor)")
struct PurgeTargetsTests {

    // MARK: - parse

    @Test("Parses site and site<TAB>username; trims and skips blanks/comments")
    func parseBasics() {
        let targets = PurgeTargets.parse([
            "7bitcasino.com\tsmandable",
            "casinomoons.com",            // no username → nil
            "",                           // blank → skipped
            "   ",                        // whitespace-only → skipped
            "# a comment",                // comment → skipped
            "  spaced.com \t  user  ",    // surrounding whitespace trimmed
        ])
        #expect(targets == [
            .init(site: "7bitcasino.com", username: "smandable"),
            .init(site: "casinomoons.com", username: nil),
            .init(site: "spaced.com", username: "user"),
        ])
    }

    @Test("Empty / comment-only input yields no targets")
    func parseEmpty() {
        #expect(PurgeTargets.parse([]).isEmpty)
        #expect(PurgeTargets.parse(["", "  ", "# only comments"]).isEmpty)
    }

    @Test("A tab with an empty username field becomes nil, not an empty string")
    func parseTabEmptyUser() {
        #expect(PurgeTargets.parse(["site.com\t"]) == [.init(site: "site.com", username: nil)])
    }

    // MARK: - originBelongsToSite (the anti-over-match anchor)

    @Test("Host equal to the target site matches (any path/port)")
    func matchExact() {
        #expect(PurgeTargets.originBelongsToSite("https://7bitcasino.com/", site: "7bitcasino.com"))
        #expect(PurgeTargets.originBelongsToSite("https://7bitcasino.com/login?x=1", site: "7bitcasino.com"))
    }

    @Test("A subdomain of the target matches (bare-domain target catches www/lobby)")
    func matchSubdomain() {
        #expect(PurgeTargets.originBelongsToSite("https://www.coolcat-casino.com/", site: "coolcat-casino.com"))
        #expect(PurgeTargets.originBelongsToSite("https://lobby.coolcat-casino.com:2072/", site: "coolcat-casino.com"))
    }

    @Test("A merely-similar domain must NOT match — the over-match guard")
    func rejectsSimilar() {
        #expect(!PurgeTargets.originBelongsToSite("https://nodepositcasino.com/", site: "casino.com"))
        #expect(!PurgeTargets.originBelongsToSite("https://casino.com.evil.test/", site: "casino.com"))
        #expect(!PurgeTargets.originBelongsToSite("https://argocasino37.com/", site: "argocasino.com"))
        #expect(!PurgeTargets.originBelongsToSite("https://evilcoolcat-casino.com/", site: "coolcat-casino.com"))
    }

    @Test("Case-insensitive; an unrelated host does not match")
    func caseAndMismatch() {
        #expect(PurgeTargets.originBelongsToSite("https://WWW.Example.COM/", site: "example.com"))
        #expect(!PurgeTargets.originBelongsToSite("https://other.com/", site: "example.com"))
    }
}
