import CryptoKit
import Foundation
import Model

/// SHA-1 hashing utilities for the HIBP "Pwned Passwords" k-anonymity API.
///
/// SHA-1 is REQUIRED here: the Pwned Passwords range API is keyed on SHA-1 of
/// the UTF-8 password bytes. This is *not* a security-sensitive use of SHA-1 —
/// only the first 5 hex characters of the digest ever leave the device, and the
/// remaining 35 are matched locally. Do not "upgrade" this to SHA-256.
enum HIBPHashing {
    /// The full uppercase hex SHA-1 of a secret, split into the 5-char range
    /// prefix and the 35-char suffix used for local matching.
    struct HashParts: Hashable, Sendable {
        /// First 5 uppercase hex characters — the only thing sent to the API.
        let prefix: String
        /// Remaining 35 uppercase hex characters — matched locally, never sent.
        let suffix: String
    }

    /// Compute the SHA-1 hash parts for a secret.
    ///
    /// Hashes the password's raw UTF-8 bytes (accessed through the scoped
    /// `withUTF8` accessor so the plaintext is never copied into a `String`),
    /// hex-encodes UPPERCASE, then splits into prefix (5) + suffix (35).
    static func hashParts(for secret: Secret) -> HashParts {
        let hex = secret.withUTF8 { bytes in
            var hasher = Insecure.SHA1()
            hasher.update(data: bytes)
            return uppercaseHex(hasher.finalize())
        }
        // A SHA-1 digest is always 40 hex chars, so these splits are safe.
        let prefix = String(hex.prefix(5))
        let suffix = String(hex.dropFirst(5))
        return HashParts(prefix: prefix, suffix: suffix)
    }

    /// Uppercase hex-encode a digest's bytes without intermediate allocations
    /// per byte beyond the result string.
    private static func uppercaseHex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        let table: [Character] = Array("0123456789ABCDEF")
        var chars: [Character] = []
        chars.reserveCapacity(40)
        for byte in digest {
            chars.append(table[Int(byte >> 4)])
            chars.append(table[Int(byte & 0x0F)])
        }
        return String(chars)
    }
}
