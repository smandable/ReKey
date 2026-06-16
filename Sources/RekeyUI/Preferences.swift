import Foundation
import PasswordGenerator

/// Persisted user preferences (UserDefaults keys) plus pure helpers, shared by the
/// Settings screen, the audit list, and the fix queue. No passwords are stored —
/// only display and generation preferences.
enum Prefs {
    static let showPasswords = "rekey.showPasswords"
    static let defaultPwStyle = "rekey.defaultPwStyle"      // one of the style* values below
    static let defaultPwLength = "rekey.defaultPwLength"
    static let avoidLookAlikes = "rekey.avoidLookAlikes"

    // Style values (also the raw values of FixCard.Style, so they round-trip).
    static let styleStrong = "Strong"
    static let styleLettersDigits = "Letters + digits"
    static let stylePassphrase = "Passphrase"

    static let defaultLength = 20

    /// Whether passwords are revealed by default (true when unset).
    static func showPasswordsValue(_ d: UserDefaults = .standard) -> Bool {
        d.object(forKey: showPasswords) as? Bool ?? true
    }

    /// The current new-password generation defaults, with fallbacks.
    static func currentGeneration(_ d: UserDefaults = .standard) -> (style: String, length: Int, avoidLookAlikes: Bool) {
        (
            d.string(forKey: defaultPwStyle) ?? styleStrong,
            d.object(forKey: defaultPwLength) as? Int ?? defaultLength,
            d.object(forKey: avoidLookAlikes) as? Bool ?? true
        )
    }

    /// Map a style choice to how the fix queue should generate it: a passphrase,
    /// or a `PasswordPolicy` for the character-based styles.
    static func generation(style: String, length: Int, avoidLookAlikes: Bool) -> (passphrase: Bool, policy: PasswordPolicy) {
        switch style {
        case stylePassphrase:
            return (true, .strong)   // policy unused for passphrases
        case styleLettersDigits:
            return (false, PasswordPolicy(length: length, useSymbols: false,
                                          avoidAmbiguous: avoidLookAlikes, lettersAndDigitsOnly: true))
        default:
            return (false, PasswordPolicy(length: length, avoidAmbiguous: avoidLookAlikes))
        }
    }
}
