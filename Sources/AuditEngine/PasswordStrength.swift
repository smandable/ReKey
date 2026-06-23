import Foundation
import Model

/// Heuristic "weak password" scorer, complementing reuse/compromise to match the
/// spirit of Google's "weak passwords" category (short / low-variety / common).
/// Not a precise strength meter — a fast, conservative flag.
public enum PasswordStrength {
    public static func isWeak(_ secret: Secret) -> Bool {
        let pw = secret.reveal()

        if Set(pw).count <= 2 { return true }                // "aaaaaaaa", "🎉🎉🎉🎉", "abababab"
        if pw.allSatisfy(\.isNumber) { return true }         // all digits (PINs, dates)
        if commonPasswords.contains(pw.lowercased()) { return true }

        // Judge length by an entropy-aware "effective length": a non-ASCII grapheme
        // (CJK, accented, emoji, …) draws from a far larger alphabet than a single
        // ASCII character, so it counts for more. Plain grapheme count would flag a
        // short but high-entropy non-ASCII password ("日本語パスワード", "🎉🎊🎈🎆🎇")
        // as weak.
        let effectiveLength = pw.reduce(0) { $0 + ($1.isASCII ? 1 : 3) }
        if effectiveLength < 8 { return true }               // genuinely too short

        var classes = 0
        if pw.contains(where: \.isLowercase) { classes += 1 }
        if pw.contains(where: \.isUppercase) { classes += 1 }
        if pw.contains(where: \.isNumber) { classes += 1 }
        if pw.contains(where: { !$0.isLetter && !$0.isNumber && !$0.isWhitespace }) { classes += 1 }
        if pw.contains(where: { !$0.isASCII }) { classes += 1 }   // large-alphabet scripts/emoji

        // Short and low-variety (e.g. "letmein99").
        if effectiveLength < 12 && classes <= 2 { return true }
        return false
    }

    static let commonPasswords: Set<String> = [
        "password", "password1", "passw0rd", "123456", "1234567", "12345678", "123456789",
        "1234567890", "qwerty", "qwertyuiop", "letmein", "welcome", "admin", "iloveyou",
        "monkey", "dragon", "abc123", "football", "baseball", "login", "starwars", "trustno1",
        "sunshine", "master", "hello", "freedom", "whatever", "ninja", "azerty", "000000",
        "111111", "121212", "superman", "hunter2", "qazwsx", "google", "zxcvbnm", "asdfghjkl",
    ]
}
