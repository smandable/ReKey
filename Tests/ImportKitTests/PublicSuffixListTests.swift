import Testing
import Foundation
@testable import ImportKit

@Suite("Public Suffix List — registrable domain (eTLD+1)")
struct PublicSuffixListTests {
    let psl = PublicSuffixList.bundled()

    @Test("Bundled list is populated; the empty fallback isn't, and degrades visibly")
    func populationSignal() {
        #expect(psl.isPopulated)                              // the real bundled list
        let empty = PublicSuffixList(data: "")
        #expect(!empty.isPopulated)                           // the silent-degradation fallback
        // The empty list falls back to last-two-labels — wrong for multi-part TLDs —
        // which is exactly why isPopulated must flag it.
        #expect(empty.registrableDomain(of: "news.bbc.co.uk") == "co.uk")
        #expect(psl.registrableDomain(of: "news.bbc.co.uk") == "bbc.co.uk")
    }

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

@Suite("URL canonicalization — IP literals and edge cases")
struct URLCanonicalizerTests {
    let canon = URLCanonicalizer()

    @Test("IPv4 hosts are returned verbatim, not collapsed via the PSL")
    func ipv4() {
        #expect(canon.registrableDomain(fromRawURL: "https://192.168.1.1/login") == "192.168.1.1")
        #expect(canon.registrableDomain(fromRawURL: "https://10.0.0.5:8080/") == "10.0.0.5")
        // Distinct LAN devices must stay distinct (the bug: all became "1.1").
        #expect(canon.registrableDomain(fromRawURL: "https://10.0.1.1/") != canon.registrableDomain(fromRawURL: "https://172.16.1.1/"))
    }

    @Test("IPv6 hosts are returned verbatim")
    func ipv6() {
        #expect(URLCanonicalizer.isIPLiteral("2001:db8::1"))
        #expect(canon.registrableDomain(fromRawURL: "https://[2001:db8::1]/") == "2001:db8::1")
    }

    @Test("Normal hosts still resolve to eTLD+1")
    func normal() {
        #expect(canon.registrableDomain(fromRawURL: "https://accounts.google.com/") == "google.com")
        #expect(canon.registrableDomain(fromRawURL: "https://www.reddit.com/") == "reddit.com")
        #expect(!URLCanonicalizer.isIPLiteral("example.com"))
        #expect(!URLCanonicalizer.isIPLiteral("1.com"))   // not 4 all-digit labels
    }
}
