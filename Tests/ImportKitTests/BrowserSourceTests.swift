import Testing
import Model

@Suite("BrowserSource cleanup support")
struct BrowserSourceTests {
    @Test("Chromium family and Firefox map to a cleanup CLI name")
    func supported() {
        #expect(BrowserSource.chrome.cleanupCLIName == "chrome")
        #expect(BrowserSource.brave.cleanupCLIName == "brave")
        #expect(BrowserSource.vivaldi.cleanupCLIName == "vivaldi")
        #expect(BrowserSource.firefox.cleanupCLIName == "firefox")
        #expect(BrowserSource.firefox.cleanupSupported)
    }

    @Test("Apple Passwords and unknown have no cleanup CLI (no delete API)")
    func unsupported() {
        #expect(BrowserSource.applePasswords.cleanupCLIName == nil)
        #expect(BrowserSource.unknown.cleanupCLIName == nil)
        #expect(!BrowserSource.applePasswords.cleanupSupported)
    }

    @Test("A brand in the filename picks the specific Chromium browser")
    func filenameHintMatches() {
        #expect(BrowserSource.chromiumHint(forFilename: "Arc Passwords.csv") == .arc)
        #expect(BrowserSource.chromiumHint(forFilename: "brave_passwords.csv") == .brave)
        #expect(BrowserSource.chromiumHint(forFilename: "Microsoft Edge.csv") == .edge)
        #expect(BrowserSource.chromiumHint(forFilename: "opera-export.csv") == .opera)
        #expect(BrowserSource.chromiumHint(forFilename: "Vivaldi.csv") == .vivaldi)
        #expect(BrowserSource.chromiumHint(forFilename: "Chrome Passwords.csv") == .chrome)
        #expect(BrowserSource.chromiumHint(forFilename: "Chromium.csv") == .chromium)
        #expect(BrowserSource.chromiumHint(forFilename: "ARC PASSWORDS.CSV") == .arc)   // case-insensitive
    }

    @Test("A name without a recognizable brand yields no hint")
    func filenameHintMisses() {
        #expect(BrowserSource.chromiumHint(forFilename: "passwords.csv") == nil)
        #expect(BrowserSource.chromiumHint(forFilename: "export-2026.csv") == nil)
        // Whole-token match: a substring like the "arc" in "search" must NOT hit.
        #expect(BrowserSource.chromiumHint(forFilename: "search-export.csv") == nil)
        #expect(BrowserSource.chromiumHint(forFilename: "March logins.csv") == nil)
    }
}
