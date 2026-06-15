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
}
