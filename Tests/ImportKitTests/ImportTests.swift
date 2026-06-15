import Testing
import Foundation
@testable import ImportKit
import Model
import TestSupport

@Suite("Format detection")
struct FormatDetectionTests {
    @Test("Each fixture is classified correctly from its header")
    func detect() throws {
        func headers(_ name: String) throws -> [String] {
            try CSVParser.parse(Fixtures.data(name)).headers
        }
        #expect(FormatDetector.detect(headers: try headers("chrome.csv")) == .chromium)
        #expect(FormatDetector.detect(headers: try headers("arc.csv")) == .chromium)
        #expect(FormatDetector.detect(headers: try headers("firefox.csv")) == .firefox)
        #expect(FormatDetector.detect(headers: try headers("apple_passwords.csv")) == .applePasswords)
    }

    @Test("Apple wins on Title even without OTPAuth; Firefox on its marker columns")
    func priority() {
        #expect(FormatDetector.detect(headers: ["Title", "URL", "Username", "Password"]) == .applePasswords)
        #expect(FormatDetector.detect(headers: ["url", "username", "password", "guid"]) == .firefox)
        #expect(FormatDetector.detect(headers: ["name", "url", "username", "password", "note"]) == .chromium)
        #expect(FormatDetector.detect(headers: ["foo", "bar"]) == .unknown)
    }
}

@Suite("End-to-end import")
struct ImportTests {
    let importer = CSVImporter()

    private func cred(_ result: ImportResult, domain: String, username: String) -> ImportedCredential? {
        result.credentials.first { $0.registrableDomain == domain && $0.username == username }
    }

    @Test("Chrome: 4 credentials, 1 skipped (blank-password federated row)")
    func chrome() throws {
        let r = try importer.import(data: Fixtures.data("chrome.csv"))
        #expect(r.source == .chrome)
        #expect(r.credentials.count == 4)
        #expect(r.skipped.count == 1)
        #expect(r.skipped.first?.reason == .blankPassword)
        #expect(r.skipped.first?.rawURL == "https://news.example.net/")

        // www. is stripped for grouping.
        #expect(cred(r, domain: "reddit.com", username: "seanm") != nil)
        // Title comes from the Chromium `name` column.
        #expect(cred(r, domain: "github.com", username: "sean")?.title == "GitHub")
    }

    @Test("Arc: same layout, labeled .arc when the user tags the file")
    func arc() throws {
        let r = try importer.import(data: Fixtures.data("arc.csv"), arcTagged: true)
        #expect(r.source == .arc)
        #expect(r.credentials.count == 2)
        #expect(cred(r, domain: "figma.com", username: "sean@icloud.com") != nil)
        // Without the tag it's labeled chrome.
        let untagged = try importer.import(data: Fixtures.data("arc.csv"))
        #expect(untagged.source == .chrome)
    }

    @Test("Firefox: 3 credentials, unicode password preserved exactly")
    func firefox() throws {
        let r = try importer.import(data: Fixtures.data("firefox.csv"))
        #expect(r.source == .firefox)
        #expect(r.credentials.count == 3)
        #expect(r.skipped.isEmpty)

        let shop = try #require(cred(r, domain: "example.org", username: "buyer@example.org"))
        #expect(shop.password.reveal() == "Pä$$wörd🔑")
        // forum.example.com groups under example.com.
        #expect(cred(r, domain: "example.com", username: "seanm") != nil)
    }

    @Test("Apple: 3 credentials, 1 skipped passkey; TOTP flagged, seed never stored")
    func apple() throws {
        let r = try importer.import(data: Fixtures.data("apple_passwords.csv"))
        #expect(r.source == .applePasswords)
        #expect(r.credentials.count == 3)
        #expect(r.skipped.count == 1)
        #expect(r.skipped.first?.reason == .blankPassword)   // passkey-only row

        let bank = try #require(cred(r, domain: "example.com", username: "sean"))
        #expect(bank.hasTOTP == true)

        // The TOTP seed must not survive anywhere on the credential.
        let seed = "JBSWY3DPEHPK3PXP"
        let haystack = [bank.title, bank.notes, bank.username, bank.rawURL,
                        bank.registrableDomain, bank.password.reveal()].compactMap { $0 }
        #expect(haystack.allSatisfy { !$0.contains(seed) })

        // The Vault Notes embedded newline survived into notes.
        let vault = try #require(cred(r, domain: "example.io", username: "sean"))
        #expect(vault.notes == "first line\nsecond line")
        #expect(vault.hasTOTP == false)
    }

    @Test("BOM + CRLF variant of the Apple fixture parses to the same credentials")
    func bomAndCRLF() throws {
        let base = try Fixtures.string("apple_passwords.csv")
        let crlf = base.replacingOccurrences(of: "\n", with: "\r\n")
        let withBOM = "\u{FEFF}" + crlf
        let data = Data(withBOM.utf8)

        let table = try CSVParser.parse(data)
        #expect(FormatDetector.detect(headers: table.headers) == .applePasswords)

        let r = try importer.import(data: data)
        #expect(r.detectedFormat == .applePasswords)
        #expect(r.credentials.count == 3)
        #expect(r.skipped.count == 1)

        // Domain/username/password are unaffected by line-ending changes.
        let fingerprint = Set(r.credentials.map { "\($0.registrableDomain)|\($0.username)|\($0.password.reveal())" })
        #expect(fingerprint.contains("example.com|sean|Tr0ub4dour&3"))
        #expect(fingerprint.contains("example.tv|sean@icloud.com|password"))
    }

    @Test("Unknown layout: fuzzy mapping works; unmappable columns throw")
    func fuzzy() throws {
        // `secret` is not a recognized password header -> required cols missing.
        #expect(throws: ImportError.self) {
            _ = try importer.import(text: "website,login,secret\nhttps://acme.example/,bob,hunter2\n")
        }
        // Recognizable headers map fuzzily.
        let r = try importer.import(text: "website,login,password\nhttps://acme.example/,bob,hunter2\n")
        #expect(r.detectedFormat == .unknown)
        #expect(r.source == .unknown)
        #expect(r.credentials.count == 1)
        #expect(r.credentials.first?.username == "bob")
        #expect(r.credentials.first?.registrableDomain == "acme.example")
    }
}
