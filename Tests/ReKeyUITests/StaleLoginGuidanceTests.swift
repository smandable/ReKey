import Testing
import Model
@testable import ReKeyUI

@Suite("Stale-login cleanup guidance")
struct StaleLoginGuidanceTests {
    @Test("Chromium command includes --browser, --site, and --username")
    func chromium() {
        let cmd = StaleLoginGuidance.cliCommand(for: .chrome, domain: "github.com", username: "old@example.com")
        #expect(cmd == "rekey-cleanup delete --browser chrome --site github.com --username old@example.com")
    }

    @Test("Firefox omits --username (encrypted there)")
    func firefox() {
        let cmd = StaleLoginGuidance.cliCommand(for: .firefox, domain: "example.org", username: "someone")
        #expect(cmd == "rekey-cleanup delete --browser firefox --site example.org")
    }

    @Test("Apple Passwords has no command (no delete API)")
    func apple() {
        #expect(StaleLoginGuidance.cliCommand(for: .applePasswords, domain: "x.com", username: "u") == nil)
    }

    @Test("Odd usernames are shell-quoted")
    func quoting() {
        let cmd = StaleLoginGuidance.cliCommand(for: .chrome, domain: "x.com", username: "a b;rm")
        #expect(cmd?.contains("--username 'a b;rm'") == true)
    }

    @Test("Manual steps name the domain")
    func manual() {
        #expect(StaleLoginGuidance.manualSteps(for: .firefox, domain: "site.io").contains("site.io"))
        #expect(StaleLoginGuidance.manualSteps(for: .applePasswords, domain: "site.io").contains("Passwords app"))
    }
}
