import Foundation
import Model

/// Loads and caches the vendored EFF large diceware wordlist.
///
/// The file is bundled via `Bundle.module` and contains 7776 TAB-separated
/// lines of the form `<dice-number>\t<word>`. We parse out the second column
/// (the words) once, at `PasswordGenerator` init time, and reuse the array for
/// every passphrase.
enum Wordlist {
    /// Name of the bundled resource (sans extension).
    static let resourceName = "eff_large_wordlist"
    static let resourceExtension = "txt"

    /// The expected number of words in the EFF large list (6^5).
    static let expectedCount = 7776

    /// Parse the bundled wordlist into its words. Throws if the resource is
    /// missing, unreadable, or malformed.
    static func load() throws -> [String] {
        guard let url = ReKeyResources.url(
            forResource: resourceName,
            withExtension: resourceExtension,
            moduleBundleName: "ReKey_PasswordGenerator",
            fallback: .module
        ) else {
            throw PasswordError.wordlistUnavailable
        }

        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw PasswordError.wordlistUnavailable
        }

        guard let contents = String(data: data, encoding: .utf8) else {
            throw PasswordError.wordlistUnavailable
        }

        return try parse(contents)
    }

    /// Parse `<dice-number>\t<word>` lines into their words and verify the result
    /// is exactly `expected` distinct words. The count + uniqueness checks are the
    /// point: a list that came up short (dropped/malformed lines) or carried
    /// duplicates would quietly lower passphrase entropy below the advertised
    /// log2(7776) ≈ 12.9 bits per word, so we fail loudly instead.
    ///
    /// `expected` is a parameter (defaulting to the EFF count) so the integrity
    /// rules are unit-testable against small synthetic lists.
    static func parse(_ contents: String, expected: Int = expectedCount) throws -> [String] {
        var words: [String] = []
        words.reserveCapacity(expected)

        // Split on any newline; tolerate trailing blank lines and \r\n.
        for rawLine in contents.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            // Each line: "<dice-number>\t<word>". Take the column after the tab.
            guard let tabIndex = rawLine.firstIndex(of: "\t") else { continue }
            let word = rawLine[rawLine.index(after: tabIndex)...]
                .trimmingCharacters(in: .whitespaces)
            if !word.isEmpty {
                words.append(word)
            }
        }

        guard words.count == expected else {
            throw PasswordError.wordlistInvalid(
                "expected \(expected) words, parsed \(words.count)")
        }
        guard Set(words).count == words.count else {
            throw PasswordError.wordlistInvalid("wordlist contains duplicate entries")
        }

        return words
    }
}
