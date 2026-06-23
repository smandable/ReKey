import Testing
import Foundation
import Model
@testable import CleanupScript

@Suite("Cleanup script builder — single source of truth")
struct CleanupCommandStringTests {
    @Test("delete --site: Chromium carries --browser/--site/--username")
    func chromiumDelete() {
        let cmd = CleanupScriptBuilder.deleteCommand(browser: .chrome, site: "github.com",
                                                     username: "old@example.com", confirm: false)
        #expect(cmd == "rekey-cleanup delete --browser chrome --site github.com --username old@example.com")
    }

    @Test("delete --site: Firefox omits --username (encrypted there)")
    func firefoxDelete() {
        let cmd = CleanupScriptBuilder.deleteCommand(browser: .firefox, site: "example.org",
                                                     username: "someone", confirm: false)
        #expect(cmd == "rekey-cleanup delete --browser firefox --site example.org")
    }

    @Test("delete --site: --confirm appended only when requested")
    func confirmSuffix() {
        let cmd = CleanupScriptBuilder.deleteCommand(browser: .chrome, site: "x.com",
                                                     username: nil, confirm: true)
        #expect(cmd == "rekey-cleanup delete --browser chrome --site x.com --confirm")
    }

    @Test("delete --site: unsupported source yields nil")
    func unsupported() {
        #expect(CleanupScriptBuilder.deleteCommand(browser: .applePasswords, site: "x.com",
                                                   username: "u", confirm: true) == nil)
        #expect(CleanupScriptBuilder.deleteCommand(browser: .unknown, site: "x.com",
                                                   username: "u", confirm: false) == nil)
    }

    @Test("list --site routed through the builder")
    func list() {
        #expect(CleanupScriptBuilder.listCommand(browser: .brave, site: "site.io")
                == "rekey-cleanup list --browser brave --site site.io")
        #expect(CleanupScriptBuilder.listCommand(browser: .applePasswords, site: "x") == nil)
    }

    @Test("Odd usernames/sites are shell-quoted")
    func quoting() {
        let cmd = CleanupScriptBuilder.deleteCommand(browser: .chrome, site: "a b.com",
                                                     username: "a b;rm", confirm: false)
        #expect(cmd?.contains("--site 'a b.com'") == true)
        #expect(cmd?.contains("--username 'a b;rm'") == true)
    }

    @Test("A --flag-shaped username is quoted, never emitted as a bare flag")
    func flagShapedValueQuoted() {
        let cmd = CleanupScriptBuilder.deleteCommand(browser: .chrome, site: "github.com",
                                                     username: "--confirm", confirm: false)
        // It must be single-quoted, not a bare `--confirm` token.
        #expect(cmd == "rekey-cleanup delete --browser chrome --site github.com --username '--confirm'")
        #expect(cmd?.hasSuffix("--username --confirm") == false)
    }
}

@Suite("shellArgument quoting")
struct ShellArgumentTests {
    @Test("Clean domains/emails/ids pass through unquoted")
    func cleanPassthrough() {
        #expect("github.com".shellArgument == "github.com")
        #expect("old@example.com".shellArgument == "old@example.com")
        #expect("a_b-c.d+e".shellArgument == "a_b-c.d+e")
    }

    @Test("A leading dash forces quoting (so it can't masquerade as a flag)")
    func leadingDashQuoted() {
        #expect("--confirm".shellArgument == "'--confirm'")
        #expect("-rf".shellArgument == "'-rf'")
        // An interior dash is still fine unquoted.
        #expect("my-site.com".shellArgument == "my-site.com")
    }

    @Test("Shell metacharacters are single-quoted with embedded quotes escaped")
    func metacharsQuoted() {
        #expect("a b".shellArgument == "'a b'")
        #expect("a;rm -rf".shellArgument == "'a;rm -rf'")
        #expect("it's".shellArgument == "'it'\\''s'")
        #expect("".shellArgument == "''")
    }
}

@Suite("purge heredoc — target-smuggling resistance")
struct HeredocSmugglingTests {
    private func target(_ source: BrowserSource, _ site: String, _ user: String = "") -> CleanupTarget {
        CleanupTarget(source: source, site: site, username: user)
    }

    /// Locate the first `purge … <<'DELIM'` block and return (delimiter, body
    /// lines strictly between the command and the matching closing delimiter).
    private func firstHeredoc(_ lines: [String]) -> (delim: String, body: [String])? {
        guard let cmdIdx = lines.firstIndex(where: { $0.contains(" <<'") }) else { return nil }
        let cmd = lines[cmdIdx]
        guard let open = cmd.range(of: "<<'"), let close = cmd.range(of: "'", range: open.upperBound..<cmd.endIndex)
        else { return nil }
        let delim = String(cmd[open.upperBound..<close.lowerBound])
        var body: [String] = []
        for line in lines[(cmdIdx + 1)...] {
            if line == delim { return (delim, body) }
            body.append(line)
        }
        return nil   // never closed — a bug we want the tests to catch
    }

    @Test("An embedded newline can't add a target line")
    func newlineCantAddLine() {
        let evil = "evil.com\nREKEY_TARGETS\nrm -rf $HOME"
        let lines = CleanupScriptBuilder.purgeBlocks(safe: [target(.chrome, evil)],
                                                     forced: [], stillManual: [], confirm: true, tallyVar: nil)
        let hd = try! #require(firstHeredoc(lines))
        // Exactly one target → exactly one body line, and it carries no newline.
        #expect(hd.body.count == 1)
        #expect(!hd.body[0].contains("\n"))
        #expect(!hd.body[0].contains("\r"))
        // The injected `rm -rf` and the smuggled delimiter survive only as inert
        // text inside the single body line — never as their own lines.
        #expect(lines.filter { $0 == hd.delim }.count == 1)   // only the closing delimiter
        #expect(!lines.contains("rm -rf $HOME"))
    }

    @Test("A carriage return / tab can't split a field or line")
    func crTabCantSplit() {
        let lines = CleanupScriptBuilder.purgeBlocks(
            safe: [target(.chrome, "a.com\r\nb.com", "user\tinjected")],
            forced: [], stillManual: [], confirm: false, tallyVar: nil)
        let hd = try! #require(firstHeredoc(lines))
        #expect(hd.body.count == 1)
        // The body line is `site<TAB>username`; sanitization means the inserted
        // separator is the ONLY tab present.
        #expect(hd.body[0].filter { $0 == "\t" }.count == 1)
    }

    @Test("A site equal to the delimiter doesn't terminate the heredoc early")
    func delimiterEqualSiteIsContained() {
        let lines = CleanupScriptBuilder.purgeBlocks(
            safe: [target(.chrome, "REKEY_TARGETS"), target(.chrome, "ok.com")],
            forced: [], stillManual: [], confirm: false, tallyVar: nil)
        let hd = try! #require(firstHeredoc(lines))
        // Delimiter must have moved off the colliding value…
        #expect(hd.delim != "REKEY_TARGETS")
        // …and BOTH targets are present as body lines (none lost to early close).
        #expect(hd.body.count == 2)
        #expect(hd.body.contains("REKEY_TARGETS"))
        #expect(hd.body.contains("ok.com"))
        #expect(lines.filter { $0 == hd.delim }.count == 1)
    }

    @Test("Normal targets round-trip: site and site<TAB>username")
    func normalRoundTrip() {
        let lines = CleanupScriptBuilder.purgeBlocks(
            safe: [target(.chrome, "site-level.com"), target(.chrome, "named.com", "alice")],
            forced: [], stillManual: [], confirm: true, tallyVar: "REKEY_TALLY")
        let hd = try! #require(firstHeredoc(lines))
        #expect(hd.delim == "REKEY_TARGETS")
        #expect(hd.body.contains("site-level.com"))
        #expect(hd.body.contains("named.com\talice"))
        // Tally + confirm are threaded into the command line.
        #expect(lines.contains { $0.hasPrefix("rekey-cleanup purge") && $0.contains("--confirm") && $0.contains("--tally \"$REKEY_TALLY\"") })
    }

    @Test("sanitizeHeredocField replaces every control char with a space")
    func sanitize() {
        #expect(CleanupScriptBuilder.sanitizeHeredocField("a\nb\tc\rd") == "a b c d")
        #expect(CleanupScriptBuilder.sanitizeHeredocField("plain.com") == "plain.com")
    }
}
