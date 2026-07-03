import Foundation
import Observation
import Model
import PasswordGenerator

/// State + logic for the standalone **Generate** tab: a one-off password maker
/// independent of the audit → fix workflow. The value is never tied to a
/// credential and never persisted — it lives in memory until regenerated, and
/// copying goes through the Fix Queue's clipboard hygiene (concealed marker,
/// timed auto-clear, clear-on-quit) via `AppModel.copyGeneratedPassword()`.
///
/// SwiftUI-free (`@Observable` only), like `FixQueue`, so it stays in the
/// logic layer and is directly testable.
@MainActor
@Observable
public final class GeneratorPanel {
    /// The generation styles offered, mirroring the Fix Queue card's. Raw
    /// values are the persisted `Prefs` style strings, so the saved Settings
    /// defaults round-trip.
    public enum Style: String, CaseIterable, Identifiable, Sendable {
        case strong = "Strong"
        case lettersDigits = "Letters + digits"
        case passphrase = "Passphrase"
        public var id: String { rawValue }
    }

    /// Same bounds as the Fix Queue's per-card length control.
    public static let lengthRange = 12...64
    /// 4 words ≈ 51 bits (a sane floor) up to 10 ≈ 129 bits; 6 is the default.
    public static let wordCountRange = 4...10

    // Changing any option regenerates immediately (mirroring the fix card's
    // controls), so the value on screen always matches the options shown.
    // `didSet` doesn't fire during init, so seeding below stays generation-free.
    public var style: Style { didSet { regenerate() } }
    public var length: Int { didSet { regenerate() } }
    public var avoidLookAlikes: Bool { didSet { regenerate() } }
    public var wordCount: Int { didSet { regenerate() } }

    /// The current generated value — nil before first use or after a failure.
    public private(set) var current: Secret?
    /// Human-readable reason generation failed (nil whenever `current` is set).
    public private(set) var lastError: String?

    /// False when the bundled wordlist failed to load (a corrupt app bundle) —
    /// the UI disables the Passphrase style instead of failing on selection.
    public let canGeneratePassphrases: Bool

    private let generator: PasswordGenerator

    /// Seeds the options from the saved Settings defaults, like a new fix card.
    public init(generator: PasswordGenerator, defaults: UserDefaults = .standard) {
        self.generator = generator
        self.canGeneratePassphrases = generator.canGeneratePassphrases
        let g = Prefs.currentGeneration(defaults)
        // A passphrase default can't be honored on a degraded wordlist — fall
        // back to Strong rather than landing the tab on a broken selection.
        let seeded = Style(rawValue: g.style) ?? .strong
        self.style = (seeded == .passphrase && !generator.canGeneratePassphrases) ? .strong : seeded
        self.length = min(max(g.length, Self.lengthRange.lowerBound), Self.lengthRange.upperBound)
        self.avoidLookAlikes = g.avoidLookAlikes
        self.wordCount = 6
    }

    /// Generate the first value lazily — when the tab first appears — so no
    /// password material is created at launch for a tab that's never visited.
    public func ensureGenerated() {
        if current == nil && lastError == nil { regenerate() }
    }

    /// Replace the current value with a fresh one under the current options.
    public func regenerate() {
        do {
            current = style == .passphrase
                ? try generator.generatePassphrase(wordCount: wordCount)
                : try generator.generate(currentPolicy)
            lastError = nil
        } catch PasswordError.wordlistUnavailable {
            current = nil
            lastError = "The passphrase word list couldn't be loaded — the app bundle may be damaged. Character passwords still work; reinstall ReKey to restore passphrases."
        } catch {
            current = nil
            lastError = "Couldn't generate a password: \(error)"
        }
    }

    /// ≈ bits of entropy of a value generated under the current options — exact
    /// for passphrases, a hair optimistic for character styles (see
    /// `PasswordPolicy.estimatedEntropyBits`). Truncated for display.
    public var entropyBits: Int {
        if style == .passphrase {
            return Int(PasswordGenerator.passphraseEntropyBits(wordCount: wordCount))
        }
        return Int(currentPolicy.estimatedEntropyBits)
    }

    /// The `PasswordPolicy` the current options describe (character styles only;
    /// the mapping lives in `Prefs.generation` so Settings, the fix cards, and
    /// this tab can never drift apart).
    private var currentPolicy: PasswordPolicy {
        Prefs.generation(style: style.rawValue, length: length, avoidLookAlikes: avoidLookAlikes).policy
    }
}
