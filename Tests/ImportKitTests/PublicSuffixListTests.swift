import Testing
import Foundation
@testable import ImportKit

@Suite("Public Suffix List — registrable domain (eTLD+1)")
struct PublicSuffixListTests {
    let psl = PublicSuffixList.bundled()

    @Test("Simple TLDs")
    func simple() {
        #expect(psl.registrableDomain(of: "google.com") == "google.com")
        #expect(psl.registrableDomain(of: "accounts.google.com") == "google.com")
        #expect(psl.registrableDomain(of: "mail.google.com") == "google.com")
        #expect(psl.registrableDomain(of: "example.org") == "example.org")
        #expect(psl.registrableDomain(of: "shop.example.org") == "example.org")
    }

    @Test("ccTLDs used by the fixtures")
    func ccTLDs() {
        #expect(psl.registrableDomain(of: "watch.example.tv") == "example.tv")
        #expect(psl.registrableDomain(of: "notes.example.io") == "example.io")
        #expect(psl.registrableDomain(of: "news.example.net") == "example.net")
    }

    @Test("Multi-part suffixes resolve correctly, not by last-two-labels")
    func multiPart() {
        #expect(psl.registrableDomain(of: "bbc.co.uk") == "bbc.co.uk")
        #expect(psl.registrableDomain(of: "news.bbc.co.uk") == "bbc.co.uk")
        // A bare public suffix has no registrable domain.
        #expect(psl.registrableDomain(of: "co.uk") == nil)
        #expect(psl.registrableDomain(of: "com") == nil)
    }

    @Test("Wildcard and exception rules")
    func wildcardException() {
        // *.ck means one label under .ck is part of the suffix.
        #expect(psl.registrableDomain(of: "a.b.ck") == "a.b.ck")
        // !www.ck is an exception: www.ck IS registrable.
        #expect(psl.registrableDomain(of: "www.ck") == "www.ck")
    }
}
