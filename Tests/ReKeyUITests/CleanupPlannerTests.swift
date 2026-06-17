import Testing
import Foundation
import Model
@testable import ReKeyUI

@Suite("Cleanup planner")
struct CleanupPlannerTests {
    private func cred(_ source: BrowserSource, _ domain: String, _ user: String) -> ImportedCredential {
        ImportedCredential(source: source, title: nil, rawURL: "https://\(domain)/",
                           registrableDomain: domain, username: user,
                           password: Secret("pw"), notes: nil, hasTOTP: false)
    }

    /// Arc is the keeper. Chrome has a duplicate (github) and a sole copy
    /// (chromeonly). Firefox has two sole copies at one site. Apple is present
    /// but unsupported by the cleanup tool.
    private var creds: [ImportedCredential] {
        [
            cred(.arc, "github.com", "sean"),
            cred(.chrome, "github.com", "sean"),       // duplicate of the Arc one
            cred(.chrome, "chromeonly.com", "bob"),    // only in Chrome
            cred(.firefox, "ff.com", "u1"),            // only in Firefox
            cred(.firefox, "ff.com", "u2"),
            cred(.applePasswords, "icloud.com", "me"), // unsupported — never a candidate
        ]
    }

    @Test("Candidates exclude the kept browser and Apple Passwords; safety is per-username")
    func candidates() {
        let cands = CleanupPlanner.candidates(from: creds, keep: .arc)
        #expect(cands.count == 3)
        #expect(!cands.contains { $0.browser == .applePasswords })
        #expect(!cands.contains { $0.browser == .arc })

        let github = try! #require(cands.first { $0.browser == .chrome && $0.domain == "github.com" })
        #expect(github.fullySafe)                       // also saved in Arc
        #expect(github.soleCopyUsernames.isEmpty)

        let chromeOnly = try! #require(cands.first { $0.domain == "chromeonly.com" })
        #expect(!chromeOnly.fullySafe)
        #expect(chromeOnly.soleCopyUsernames == ["bob"])

        let ff = try! #require(cands.first { $0.browser == .firefox })
        #expect(ff.usernames == ["u1", "u2"])
        #expect(!ff.fullySafe)
        #expect(ff.soleCopyUsernames == ["u1", "u2"])   // neither is in Arc
    }

    @Test("Commands are site-level; Firefox never carries a username")
    func commands() {
        let cands = CleanupPlanner.candidates(from: creds, keep: .arc)
        let github = cands.first { $0.domain == "github.com" }!
        #expect(CleanupPlanner.command(for: github, confirm: false) == "rekey-cleanup delete --browser chrome --site github.com")
        #expect(CleanupPlanner.command(for: github, confirm: true)?.hasSuffix("--confirm") == true)

        let ff = cands.first { $0.browser == .firefox }!
        #expect(CleanupPlanner.command(for: ff, confirm: false) == "rekey-cleanup delete --browser firefox --site ff.com")
    }

    @Test("Script previews by default and gains --confirm when requested")
    func script() {
        let cands = CleanupPlanner.candidates(from: creds, keep: .arc)
        let preview = CleanupPlanner.script(for: cands, confirm: false)
        #expect(preview.contains("rekey-cleanup delete --browser chrome --site github.com"))
        #expect(preview.contains("PREVIEW ONLY"))
        #expect(!preview.contains("github.com --confirm"))   // no command line got --confirm

        let real = CleanupPlanner.script(for: cands, confirm: true)
        #expect(real.contains("--site github.com --confirm"))
        #expect(!real.contains("PREVIEW ONLY"))
        #expect(CleanupPlanner.script(for: [], confirm: false).isEmpty)
    }

    @Test("Command-list script wraps with header, previews by default, gains --confirm")
    func scriptFromCommands() {
        let commands = [
            "rekey-cleanup delete --browser chrome --site chase.com --username smandable1",
            "rekey-cleanup delete --browser firefox --site chase.com",
        ]
        let preview = CleanupPlanner.script(commands: commands, confirm: false)
        #expect(preview.contains("#!/bin/sh"))
        #expect(preview.contains("PREVIEW ONLY"))
        #expect(preview.contains(commands[0]))
        #expect(preview.contains(commands[1]))
        // No command line got --confirm (the "(no --confirm)" banner doesn't count).
        #expect(!preview.contains("smandable1 --confirm"))
        #expect(!preview.contains("chase.com --confirm"))

        let real = CleanupPlanner.script(commands: commands, confirm: true)
        #expect(real.contains("--username smandable1 --confirm"))
        #expect(real.contains("--site chase.com --confirm"))   // firefox line
        #expect(!real.contains("PREVIEW ONLY"))

        #expect(CleanupPlanner.script(commands: [], confirm: false).isEmpty)
    }

    @Test("Imported browsers lists every distinct source")
    func importedBrowsers() {
        let browsers = CleanupPlanner.importedBrowsers(in: creds)
        #expect(Set(browsers) == Set([.arc, .chrome, .firefox, .applePasswords]))
    }
}
