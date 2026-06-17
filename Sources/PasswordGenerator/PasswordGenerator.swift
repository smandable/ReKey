import Foundation
import Security
import Model

/// A CSPRNG-backed password and passphrase generator.
///
/// All randomness flows through ``randomIndex(upperBound:)``, which draws bytes
/// from `SecRandomCopyBytes` and maps them to a uniform integer using rejection
/// sampling — so there is no modulo bias. No other source of entropy
/// (`arc4random`, `Int.random`, `UUID`, …) is ever used for password material.
public struct PasswordGenerator: Sendable {
    /// The cached diceware words (7776 entries for the EFF large list).
    private let words: [String]

    /// Loads and caches the wordlist. Throws ``PasswordError/wordlistUnavailable``
    /// if the bundled resource cannot be read.
    public init() throws {
        self.words = try Wordlist.load()
    }

    private init(words: [String]) { self.words = words }

    /// Construction that never throws, for the app's long-lived generator: if the
    /// bundled wordlist can't be read (a corrupt app bundle), character-based
    /// generation still works and only passphrase generation fails — gracefully,
    /// not as a launch crash.
    public static func bestEffort() -> PasswordGenerator {
        PasswordGenerator(words: (try? Wordlist.load()) ?? [])
    }

    // MARK: - Unbiased randomness

    /// Returns a uniformly random integer in `[0, upperBound)` using rejection
    /// sampling over raw CSPRNG bytes, eliminating modulo bias.
    ///
    /// We read the smallest number of bytes `k` such that `256^k >= upperBound`,
    /// interpret them as a big-endian unsigned integer in `[0, 256^k)`, and
    /// reject any draw that falls in the biased tail
    /// `>= floor(256^k / upperBound) * upperBound`. The accepted region is an
    /// exact multiple of `upperBound`, so reducing modulo `upperBound` is
    /// perfectly uniform.
    ///
    /// - Throws: ``PasswordError/invalidArgument(_:)`` if `upperBound <= 0`, or
    ///   ``PasswordError/randomGenerationFailed`` if the CSPRNG fails.
    static func randomIndex(upperBound: Int) throws -> Int {
        guard upperBound > 0 else {
            throw PasswordError.invalidArgument("upperBound must be > 0, got \(upperBound)")
        }
        // Trivial case: only one valid value, no randomness needed.
        if upperBound == 1 { return 0 }

        let n = UInt64(upperBound)

        // Smallest byte count k such that 256^k >= n, capped at 8 (UInt64).
        // `range` is 256^k, computed as a UInt64; for k == 8 it overflows to 0,
        // which we treat as the full 2^64 space (handled below).
        var byteCount = 1
        var range: UInt64 = 256
        while range < n && byteCount < 8 {
            byteCount += 1
            // Guard the final shift: 256^8 == 2^64 overflows UInt64.
            if byteCount == 8 {
                range = 0 // sentinel meaning "2^64"
            } else {
                range &*= 256
            }
        }

        // acceptLimit = largest multiple of n that fits in [0, range); draws
        // >= acceptLimit are in the biased tail and rejected.
        //
        // For the sentinel range == 2^64 (byteCount == 8) we can't represent
        // range in a UInt64, so compute (2^64 mod n) without overflow:
        //   2^64 mod n == ((0 - n) mod n) using wraparound arithmetic,
        // then acceptLimit == 2^64 - remainder == (0 - remainder) wrapped.
        // `wholeSpaceValid` is true when range is already an exact multiple of
        // n (remainder == 0) — then there is no biased tail and every draw is
        // accepted. This also avoids a degenerate acceptLimit == 0 in the 2^64
        // branch (which would otherwise reject everything and loop forever).
        let acceptLimit: UInt64
        let wholeSpaceValid: Bool
        if range == 0 {
            let remainder = (0 &- n) % n   // (2^64) mod n
            wholeSpaceValid = remainder == 0
            acceptLimit = 0 &- remainder   // 2^64 - remainder, wrapped into UInt64
        } else {
            let remainder = range % n
            wholeSpaceValid = remainder == 0
            acceptLimit = range - remainder
        }

        while true {
            let draw = try randomU64(byteCount: byteCount)
            // For range == 2^64 the whole UInt64 space is valid; otherwise draw
            // is already < range by construction.
            if wholeSpaceValid || draw < acceptLimit {
                return Int(draw % n)
            }
            // else: in the biased tail — reject and re-draw.
        }
    }

    /// Read `byteCount` (1...8) random bytes from the CSPRNG and assemble them
    /// big-endian into a `UInt64` in `[0, 256^byteCount)`.
    private static func randomU64(byteCount: Int) throws -> UInt64 {
        precondition((1...8).contains(byteCount))
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let status = bytes.withUnsafeMutableBytes { buffer -> Int32 in
            SecRandomCopyBytes(kSecRandomDefault, byteCount, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw PasswordError.randomGenerationFailed
        }
        var value: UInt64 = 0
        for byte in bytes {
            value = (value << 8) | UInt64(byte)
        }
        return value
    }

    /// Fisher–Yates shuffle driven entirely by ``randomIndex(upperBound:)``.
    private static func shuffled<T>(_ array: [T]) throws -> [T] {
        var result = array
        guard result.count > 1 else { return result }
        var i = result.count - 1
        while i > 0 {
            let j = try randomIndex(upperBound: i + 1)
            result.swapAt(i, j)
            i -= 1
        }
        return result
    }

    // MARK: - Password generation

    /// Generate a random password satisfying `policy`.
    ///
    /// The alphabet is the union of the enabled classes (with ambiguous
    /// characters removed and symbols dropped when `lettersAndDigitsOnly`). The
    /// result is guaranteed to contain at least one character from each enabled
    /// class; this requires `length >= enabledClasses.count`.
    ///
    /// - Throws: ``PasswordError/noClassesEnabled`` if no class is enabled, or
    ///   ``PasswordError/lengthTooSmallForClasses(length:requiredClasses:)`` if
    ///   the length cannot accommodate one of each class.
    public func generate(_ policy: PasswordPolicy = .strong) throws -> Secret {
        let classes = policy.enabledClasses
        guard !classes.isEmpty else {
            throw PasswordError.noClassesEnabled
        }

        // Per-class allowed characters (ambiguous already removed). A class with
        // an empty allowed set can't fulfil its guarantee.
        let perClassChars: [[Character]] = classes.map { policy.allowedCharacters(for: $0) }
        guard perClassChars.allSatisfy({ !$0.isEmpty }) else {
            // Not reachable for the built-in classes, but guard defensively.
            throw PasswordError.noClassesEnabled
        }

        let requiredClasses = classes.count
        let length = policy.length // already clamped to >= minimumLength in init
        guard length >= requiredClasses else {
            throw PasswordError.lengthTooSmallForClasses(
                length: length,
                requiredClasses: requiredClasses
            )
        }

        // Full alphabet (union of all enabled classes' allowed characters).
        let alphabet: [Character] = perClassChars.flatMap { $0 }

        var chars: [Character] = []
        chars.reserveCapacity(length)

        // 1. One guaranteed character from each enabled class.
        for classChars in perClassChars {
            let idx = try Self.randomIndex(upperBound: classChars.count)
            chars.append(classChars[idx])
        }

        // 2. Fill the remainder uniformly from the full alphabet.
        let remaining = length - requiredClasses
        for _ in 0..<remaining {
            let idx = try Self.randomIndex(upperBound: alphabet.count)
            chars.append(alphabet[idx])
        }

        // 3. Shuffle so the guaranteed characters aren't pinned to the front.
        //    Fisher–Yates over a CSPRNG keeps the distribution unbiased.
        chars = try Self.shuffled(chars)

        // All characters are ASCII (single-byte), so UTF-8 encoding is direct.
        let bytes = Array(String(chars).utf8)
        return Secret(utf8Bytes: bytes)
    }

    // MARK: - Passphrase generation

    /// Generate a diceware-style passphrase by drawing `wordCount` words
    /// uniformly from the bundled list (rejection sampling over 7776), joined by
    /// `separator`.
    ///
    /// - Parameters:
    ///   - wordCount: Number of words (must be >= 1).
    ///   - separator: String placed between words.
    ///   - capitalizeWords: Capitalize the first letter of each word.
    ///   - includeNumber: Append a single random digit (0–9) to the phrase.
    /// - Throws: ``PasswordError/invalidArgument(_:)`` if `wordCount < 1`.
    public func generatePassphrase(
        wordCount: Int = 6,
        separator: String = "-",
        capitalizeWords: Bool = false,
        includeNumber: Bool = false
    ) throws -> Secret {
        guard wordCount >= 1 else {
            throw PasswordError.invalidArgument("wordCount must be >= 1, got \(wordCount)")
        }
        guard !words.isEmpty else { throw PasswordError.wordlistUnavailable }

        var picked: [String] = []
        picked.reserveCapacity(wordCount)
        for _ in 0..<wordCount {
            let idx = try Self.randomIndex(upperBound: words.count)
            var word = words[idx]
            if capitalizeWords {
                word = word.prefix(1).uppercased() + word.dropFirst()
            }
            picked.append(word)
        }

        var phrase = picked.joined(separator: separator)

        if includeNumber {
            let digit = try Self.randomIndex(upperBound: 10)
            phrase += String(digit)
        }

        return Secret(utf8Bytes: Array(phrase.utf8))
    }
}
