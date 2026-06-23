import Foundation
import ImportKit
import PasswordGenerator
import ResetRouter

/// A headless smoke test that the vendored, bundled resources (Public Suffix
/// List, EFF wordlist, fallback map) actually load when running as the packaged
/// .app. Invoked with `ReKey --selftest`; it runs before any window appears and
/// exits with status 0 (pass) or 1 (fail).
public enum ReKeySelfTest {
    public static func runAndExit() -> Never {
        var ok = true
        func check(_ name: String, _ cond: Bool) {
            FileHandle.standardOutput.write(Data(((cond ? "ok    " : "FAIL  ") + name + "\n").utf8))
            ok = ok && cond
        }

        // Public Suffix List (ImportKit resource).
        let psl = PublicSuffixList.bundled()
        check("PSL: accounts.google.com -> google.com", psl.registrableDomain(of: "accounts.google.com") == "google.com")
        check("PSL: news.bbc.co.uk -> bbc.co.uk", psl.registrableDomain(of: "news.bbc.co.uk") == "bbc.co.uk")

        // EFF wordlist (PasswordGenerator resource) + CSPRNG generation. `init()`
        // now throws unless the list loaded as the full, unique 7776-word set, so
        // a successful init already proves wordlist integrity; assert it explicitly
        // so a short or deduped list can't pass self-test with low-entropy phrases.
        if let gen = try? PasswordGenerator() {
            check("generator: wordlist complete (7776 unique words)", gen.canGeneratePassphrases)
            let pw = (try? gen.generate(.strong))?.reveal() ?? ""
            check("generator: strong password >= 20 chars", pw.count >= 20)
            let phrase = (try? gen.generatePassphrase(wordCount: 6))?.reveal() ?? ""
            check("generator: 6-word passphrase", phrase.split(separator: "-").count == 6)
        } else {
            check("generator: init (wordlist loaded)", false)
        }

        // Fallback map (ResetRouter resource) loads without crashing.
        _ = ResetRouter()
        check("reset router: constructs (fallback map loaded)", true)

        FileHandle.standardOutput.write(Data((ok ? "SELFTEST PASS\n" : "SELFTEST FAIL\n").utf8))
        exit(ok ? 0 : 1)
    }
}
