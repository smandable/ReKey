import Testing
import Foundation
import Model
@testable import PasswordGenerator
@testable import ReKeyUI

/// The standalone Generate tab's logic layer. Uses throwaway UserDefaults
/// suites so seeding tests don't touch (or depend on) the real preferences.
@MainActor
@Suite("Standalone generator panel")
struct GeneratorPanelTests {
    private func freshDefaults() -> UserDefaults {
        UserDefaults(suiteName: "GeneratorPanelTests-\(UUID().uuidString)")!
    }

    /// A generator whose wordlist passes the integrity check but is fully
    /// synthetic — no hyphens, so passphrase word counts are assertable by
    /// splitting on the separator (the real EFF list has 4 hyphenated words).
    private func syntheticGenerator() -> PasswordGenerator {
        PasswordGenerator(words: (0..<Wordlist.expectedCount).map { "w\($0)" })
    }

    @Test("No password material exists until the tab is first shown")
    func lazyFirstGeneration() throws {
        let panel = GeneratorPanel(generator: .bestEffort(), defaults: freshDefaults())
        #expect(panel.current == nil)
        panel.ensureGenerated()
        let first = try #require(panel.current).reveal()
        #expect(first.count == Prefs.defaultLength)
        // Re-appearing must not silently replace a value the user may be using.
        panel.ensureGenerated()
        #expect(panel.current?.reveal() == first)
    }

    @Test("Options seed from the saved Settings defaults")
    func seedsFromDefaults() {
        let d = freshDefaults()
        d.set(Prefs.styleLettersDigits, forKey: Prefs.defaultPwStyle)
        d.set(30, forKey: Prefs.defaultPwLength)
        d.set(true, forKey: Prefs.avoidLookAlikes)
        let panel = GeneratorPanel(generator: .bestEffort(), defaults: d)
        #expect(panel.style == .lettersDigits)
        #expect(panel.length == 30)
        #expect(panel.avoidLookAlikes)
    }

    @Test("A stored out-of-range length is clamped to the control's bounds")
    func lengthSeedIsClamped() {
        let d = freshDefaults()
        d.set(500, forKey: Prefs.defaultPwLength)
        let panel = GeneratorPanel(generator: .bestEffort(), defaults: d)
        #expect(panel.length == GeneratorPanel.lengthRange.upperBound)
    }

    @Test("Changing an option regenerates so the value matches the controls")
    func optionChangeRegenerates() throws {
        let panel = GeneratorPanel(generator: .bestEffort(), defaults: freshDefaults())
        panel.ensureGenerated()
        panel.length = 32
        #expect(try #require(panel.current).reveal().count == 32)
    }

    @Test("Letters + digits style emits no symbols")
    func lettersDigitsStyle() throws {
        let panel = GeneratorPanel(generator: .bestEffort(), defaults: freshDefaults())
        panel.length = 64
        panel.style = .lettersDigits
        let value = try #require(panel.current).reveal()
        #expect(value.allSatisfy { $0.isLetter || $0.isNumber })
    }

    @Test("No look-alikes excludes the ambiguous characters")
    func noLookAlikes() throws {
        let panel = GeneratorPanel(generator: .bestEffort(), defaults: freshDefaults())
        panel.length = 64
        panel.avoidLookAlikes = true
        let value = try #require(panel.current).reveal()
        #expect(!value.contains { "Il1O0".contains($0) })
    }

    @Test("Passphrase style honors the word count")
    func passphraseWordCount() throws {
        let panel = GeneratorPanel(generator: syntheticGenerator(), defaults: freshDefaults())
        panel.style = .passphrase
        panel.wordCount = 5
        let phrase = try #require(panel.current).reveal()
        #expect(phrase.split(separator: "-").count == 5)
    }

    @Test("A degraded wordlist disables passphrases and falls back gracefully")
    func degradedWordlist() {
        let degraded = PasswordGenerator(words: [])
        let d = freshDefaults()
        d.set(Prefs.stylePassphrase, forKey: Prefs.defaultPwStyle)

        let panel = GeneratorPanel(generator: degraded, defaults: d)
        #expect(!panel.canGeneratePassphrases)
        // The saved passphrase default can't be honored — seed falls back.
        #expect(panel.style == .strong)
        panel.ensureGenerated()
        #expect(panel.current != nil)     // character generation still works

        // Forcing passphrase anyway (the UI disables it) fails soft, and
        // switching back recovers.
        panel.style = .passphrase
        #expect(panel.current == nil)
        #expect(panel.lastError != nil)
        panel.style = .strong
        #expect(panel.current != nil)
        #expect(panel.lastError == nil)
    }

    @Test("Entropy readout matches the engine's estimates")
    func entropyReadout() {
        let panel = GeneratorPanel(generator: .bestEffort(), defaults: freshDefaults())
        panel.style = .strong
        panel.length = 20
        panel.avoidLookAlikes = false
        #expect(panel.entropyBits == 128)   // 20 × log2(86) = 128.5…
        panel.avoidLookAlikes = true
        #expect(panel.entropyBits == 126)   // 20 × log2(81) = 126.8…
        panel.style = .passphrase
        panel.wordCount = 6
        #expect(panel.entropyBits == 77)    // 6 × log2(7776) = 77.5…
    }
}
