import Foundation

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
        guard let url = Bundle.module.url(
            forResource: resourceName,
            withExtension: resourceExtension
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

        var words: [String] = []
        words.reserveCapacity(expectedCount)

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

        guard !words.isEmpty else {
            throw PasswordError.wordlistUnavailable
        }

        return words
    }
}
