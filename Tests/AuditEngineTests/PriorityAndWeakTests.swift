import Testing
import Foundation
import Model
@testable import AuditEngine

@Suite("Weak scoring and priority ranking")
struct PriorityAndWeakTests {
    @Test("Weak heuristic flags short/common/low-variety, passes strong")
    func weak() {
        #expect(PasswordStrength.isWeak(Secret("hunter2")))        // 6 chars
        #expect(PasswordStrength.isWeak(Secret("password")))       // common
        #expect(PasswordStrength.isWeak(Secret("12345678")))       // all digits
        #expect(PasswordStrength.isWeak(Secret("aaaaaaaa")))       // <=2 distinct
        #expect(PasswordStrength.isWeak(Secret("letmein9")))       // short + low variety
        #expect(!PasswordStrength.isWeak(Secret("Tr0ub4dour&3")))
        #expect(!PasswordStrength.isWeak(Secret("J7#mK9$pL2@xQ")))
    }

    @Test("Important-domain heuristic")
    func important() {
        #expect(DomainPriority.isImportant("google.com"))
        #expect(DomainPriority.isImportant("chase.com"))
        #expect(DomainPriority.isImportant("mylocalbank.com"))     // keyword "bank"
        #expect(DomainPriority.isImportant("fastmail.com"))
        #expect(!DomainPriority.isImportant("example.xyz"))
    }

    @Test("Prioritized groups are worst-first; clean last")
    func prioritized() async {
        func c(_ dom: String, _ pw: String) -> ImportedCredential {
            ImportedCredential(source: .chrome, title: nil, rawURL: "https://\(dom)/",
                               registrableDomain: dom, username: "u",
                               password: Secret(pw), notes: nil, hasTOTP: false)
        }
        let creds = [
            c("zzz-bad.com", "reused1"), c("aaa-bad.com", "reused1"),   // compromised+reused (sev 3)
            c("mmm-mid.com", "sharedmid"), c("nnn-mid.com", "sharedmid"), // reused (sev 1)
            c("weak.com", "weakpw12"),               // weak-only (sev 0)
            c("clean.com", "Str0ng&UniqueX9z"),      // clean (sev -1)
        ]
        let report = await AuditCoordinator(compromiseChecker: StubChecker(compromised: ["reused1"], count: 5))
            .audit(credentials: creds)

        let severities = report.prioritizedDomainGroups.map(\.highestSeverity)
        #expect(severities == severities.sorted(by: >))            // non-increasing
        #expect(report.prioritizedDomainGroups.first?.highestSeverity == 3)
        #expect(report.prioritizedDomainGroups.last?.registrableDomain == "clean.com")
        #expect(report.weak.count == 5)                            // all but the strong/unique one
    }
}
