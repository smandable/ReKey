import Foundation
import Model

/// Heuristic "weak password" scorer, complementing reuse/compromise to match the
/// spirit of Google's "weak passwords" category (short / low-variety / common).
/// Not a precise strength meter — a fast, conservative flag.
public enum PasswordStrength {
    public static func isWeak(_ secret: Secret) -> Bool {
        let pw = secret.reveal()
        let count = pw.count

        if count < 8 { return true }                         // too short
        if pw.allSatisfy(\.isNumber) { return true }         // all digits (PINs, dates)
        if Set(pw).count <= 2 { return true }                // e.g. "aaaaaaaa", "abababab"
        if commonPasswords.contains(pw.lowercased()) { return true }

        var classes = 0
        if pw.contains(where: \.isLowercase) { classes += 1 }
        if pw.contains(where: \.isUppercase) { classes += 1 }
        if pw.contains(where: \.isNumber) { classes += 1 }
        if pw.contains(where: { !$0.isLetter && !$0.isNumber && !$0.isWhitespace }) { classes += 1 }

        // Short and low-variety (e.g. "letmein99").
        if count < 12 && classes <= 2 { return true }
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
