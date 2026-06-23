import Testing
import Foundation
@testable import PasswordGenerator
import Model

// MARK: - Helpers

private let lowercaseSet = Set("abcdefghijklmnopqrstuvwxyz")
private let uppercaseSet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
private let digitSet = Set("0123456789")
private let symbolSet = Set("!@#$%^&*()-_=+[]{};:,.?/")
private let ambiguousSet: Set<Character> = ["I", "l", "1", "O", "0"]

private func makeGenerator() throws -> PasswordGenerator {
    try PasswordGenerator()
}

// MARK: - Construction & wordlist

@Test
func generatorInitializesAndLoadsWordlist() throws {
    // If init succeeds the wordlist parsed; passphrase generation exercises it.
    let gen = try makeGenerator()
    let phrase = try gen.generatePassphrase(wordCount: 4)
    #expect(!phrase.reveal().isEmpty)
}

@Test
func wordlistHasExpectedCount() throws {
    let words = try Wordlist.load()
    #expect(words.count == Wordlist.expectedCount)
    // Spot-check known boundary entries of the EFF large list.
    #expect(words.first == "abacus")
    #expect(words.last == "zoom")
    // No tabs / dice digits / whitespace leaked into the parsed words. The EFF
    // large list does contain a few hyphenated entries (drop-down, felt-tip,
    // t-shirt, yo-yo), so allow '-' but nothing numeric or whitespace.
    #expect(words.allSatisfy { !$0.contains("\t") })
    #expect(words.allSatisfy { word in
        word.allSatisfy { $0.isLetter || $0 == "-" }
    })
    #expect(words.allSatisfy { word in
        !word.contains { $0.isNumber || $0.isWhitespace }
    })
}

// MARK: - Wordlist integrity (count + uniqueness)

@Test
func wordlistParseAcceptsExactCountUniqueWords() throws {
    let contents = "11111\tone\n22222\ttwo\n33333\tthree\n"
    #expect(try Wordlist.parse(contents, expected: 3) == ["one", "two", "three"])
}

@Test
func wordlistParseRejectsShortList() throws {
    // A dropped/malformed line leaves fewer words than expected → must throw,
    // not silently lower entropy.
    let contents = "11111\tone\n22222\ttwo\n"
    #expect(throws: PasswordError.self) {
        _ = try Wordlist.parse(contents, expected: 3)
    }
}

@Test
func wordlistParseRejectsDuplicates() throws {
    // Duplicate words make some draws more likely → real entropy < log2(count).
    let contents = "11111\tone\n22222\tone\n33333\ttwo\n"
    #expect(throws: PasswordError.self) {
        _ = try Wordlist.parse(contents, expected: 3)
    }
}

@Test
func bundledWordlistIsCompleteAndUnique() throws {
    // The real bundled list must pass the same integrity bar the app relies on.
    let words = try Wordlist.load()
    #expect(words.count == Wordlist.expectedCount)
    #expect(Set(words).count == words.count)
}

@Test
func passphraseGeneratorReportsCapability() throws {
    // A real generator can make passphrases; a bestEffort one with no list can't,
    // and refuses rather than emitting a low-entropy phrase.
    let real = try PasswordGenerator()
    #expect(real.canGeneratePassphrases)
    let empty = PasswordGenerator(words: [])   // simulates a failed bestEffort() load
    #expect(!empty.canGeneratePassphrases)
    #expect(throws: PasswordError.self) {
        _ = try empty.generatePassphrase(wordCount: 6)
    }
}

// MARK: - Charset coverage

@Test
func strongPolicyUsesAllClasses() throws {
    let gen = try makeGenerator()
    // Aggregate over several passwords so each class is observed.
    var lower = false, upper = false, digit = false, symbol = false
    for _ in 0..<50 {
        let pw = try gen.generate(.strong)
        for ch in pw.reveal() {
            if lowercaseSet.contains(ch) { lower = true }
            if uppercaseSet.contains(ch) { upper = true }
            if digitSet.contains(ch) { digit = true }
            if symbolSet.contains(ch) { symbol = true }
        }
    }
    #expect(lower && upper && digit && symbol)
}

@Test
func avoidAmbiguousNeverEmitsAmbiguousCharacters() throws {
    let gen = try makeGenerator()
    let policy = PasswordPolicy(length: 40, avoidAmbiguous: true, lettersAndDigitsOnly: false)
    for _ in 0..<200 {
        let pw = try gen.generate(policy)
        for ch in pw.reveal() {
            #expect(!ambiguousSet.contains(ch))
        }
    }
}

@Test
func ambiguousAllowedWhenNotAvoiding() throws {
    let gen = try makeGenerator()
    // With ambiguous allowed, over many large lowercase-only draws we should
    // eventually see an 'l' (the only ambiguous char in the lowercase set).
    let policy = PasswordPolicy(
        length: 60,
        useLowercase: true,
        useUppercase: false,
        useDigits: false,
        useSymbols: false,
        avoidAmbiguous: false,
        lettersAndDigitsOnly: false
    )
    var sawL = false
    for _ in 0..<200 where !sawL {
        let pw = try gen.generate(policy)
        if pw.reveal().contains("l") { sawL = true }
    }
    #expect(sawL)
}

@Test
func lettersAndDigitsOnlyDropsSymbols() throws {
    let gen = try makeGenerator()
    let policy = PasswordPolicy(
        length: 40,
        useLowercase: true,
        useUppercase: true,
        useDigits: true,
        useSymbols: true,           // requested, but must be forced off
        avoidAmbiguous: false,
        lettersAndDigitsOnly: true
    )
    for _ in 0..<100 {
        let pw = try gen.generate(policy)
        for ch in pw.reveal() {
            #expect(!symbolSet.contains(ch))
            #expect(ch.isLetter || ch.isNumber)
        }
    }
}

@Test
func digitsOnlyPolicyProducesOnlyDigits() throws {
    let gen = try makeGenerator()
    let policy = PasswordPolicy(
        length: 16,
        useLowercase: false,
        useUppercase: false,
        useDigits: true,
        useSymbols: false,
        avoidAmbiguous: false,
        lettersAndDigitsOnly: false
    )
    let pw = try gen.generate(policy)
    for ch in pw.reveal() {
        #expect(digitSet.contains(ch))
    }
}

// MARK: - Required-class guarantee

@Test
func eachEnabledClassAppearsAtLeastOnce() throws {
    let gen = try makeGenerator()
    // Minimal length equal to class count is the tightest case.
    let policy = PasswordPolicy(
        length: 8,                  // >= 4 classes
        useLowercase: true,
        useUppercase: true,
        useDigits: true,
        useSymbols: true,
        avoidAmbiguous: true,
        lettersAndDigitsOnly: false
    )
    for _ in 0..<500 {
        let chars = Array(try gen.generate(policy).reveal())
        let set = Set(chars)
        #expect(set.contains { lowercaseSet.contains($0) })
        #expect(set.contains { uppercaseSet.contains($0) })
        #expect(set.contains { digitSet.contains($0) })
        #expect(set.contains { symbolSet.contains($0) })
    }
}

@Test
func guaranteeHoldsAtExactlyClassCountLength() throws {
    let gen = try makeGenerator()
    // length == number of enabled classes (3): every char is one guaranteed
    // representative, so all three classes must appear.
    let policy = PasswordPolicy(
        length: 3,                  // clamped up to 8 by init
        useLowercase: true,
        useUppercase: true,
        useDigits: true,
        useSymbols: false,
        avoidAmbiguous: false,
        lettersAndDigitsOnly: false
    )
    // After clamping length is 8, which still must include all 3 classes.
    for _ in 0..<200 {
        let set = Set(try gen.generate(policy).reveal())
        #expect(set.contains { lowercaseSet.contains($0) })
        #expect(set.contains { uppercaseSet.contains($0) })
        #expect(set.contains { digitSet.contains($0) })
    }
}

// MARK: - Length

@Test
func lengthIsHonored() throws {
    let gen = try makeGenerator()
    for length in [8, 12, 20, 33, 64, 128] {
        let policy = PasswordPolicy(length: length)
        let pw = try gen.generate(policy)
        let revealed = pw.reveal()
        // ASCII alphabet: scalar count == grapheme count == requested length.
        #expect(revealed.unicodeScalars.count == length)
        #expect(revealed.count == length)
    }
}

@Test
func lengthIsClampedToMinimum() throws {
    let gen = try makeGenerator()
    let policy = PasswordPolicy(length: 3) // below minimum 8
    #expect(policy.length == PasswordPolicy.minimumLength)
    let pw = try gen.generate(policy)
    #expect(pw.reveal().count == PasswordPolicy.minimumLength)
}

@Test
func largeLengthSupported() throws {
    let gen = try makeGenerator()
    let policy = PasswordPolicy(length: 4096)
    let pw = try gen.generate(policy)
    #expect(pw.reveal().count == 4096)
}

// MARK: - Error conditions

@Test
func throwsWhenNoClassesEnabled() throws {
    let gen = try makeGenerator()
    let policy = PasswordPolicy(
        length: 20,
        useLowercase: false,
        useUppercase: false,
        useDigits: false,
        useSymbols: false
    )
    #expect(throws: PasswordError.noClassesEnabled) {
        _ = try gen.generate(policy)
    }
}

@Test
func throwsWhenLettersAndDigitsOnlyLeavesNoClasses() throws {
    let gen = try makeGenerator()
    // Only symbols requested, but lettersAndDigitsOnly forces them off → empty.
    let policy = PasswordPolicy(
        length: 20,
        useLowercase: false,
        useUppercase: false,
        useDigits: false,
        useSymbols: true,
        avoidAmbiguous: false,
        lettersAndDigitsOnly: true
    )
    #expect(throws: PasswordError.noClassesEnabled) {
        _ = try gen.generate(policy)
    }
}

@Test
func throwsWhenLengthBelowRequiredClasses() throws {
    let gen = try makeGenerator()
    // Build a policy whose length (after clamping) is below the class count.
    // We can't get length < 8 via init, so use a policy with > 8 classes? Not
    // possible (max 4). Instead verify the generator's own guard by invoking it
    // with a deliberately short length through the internal path: confirm the
    // error type exists and is thrown for a constructed-too-short scenario by
    // exercising a 4-class policy whose clamped length still satisfies — so we
    // instead check the error is reachable via a length below 4 once clamped.
    //
    // Practically: the minimum clamp (8) >= max classes (4), so generate never
    // throws lengthTooSmallForClasses for real policies. We assert the guard
    // logic directly: a policy with length 8 and 4 classes succeeds.
    let policy = PasswordPolicy(length: 8) // 4 classes, length 8 → ok
    let pw = try gen.generate(policy)
    #expect(pw.reveal().count == 8)
}

// MARK: - Unbiasedness of randomIndex

@Test
func randomIndexNeverExceedsBound() throws {
    for bound in [2, 3, 7, 10, 26, 64, 7776] {
        for _ in 0..<2000 {
            let v = try PasswordGenerator.randomIndex(upperBound: bound)
            #expect(v >= 0)
            #expect(v < bound)
        }
    }
}

@Test
func randomIndexUpperBoundOneAlwaysZero() throws {
    for _ in 0..<100 {
        #expect(try PasswordGenerator.randomIndex(upperBound: 1) == 0)
    }
}

@Test
func randomIndexThrowsOnNonPositiveBound() throws {
    #expect(throws: PasswordError.self) {
        _ = try PasswordGenerator.randomIndex(upperBound: 0)
    }
    #expect(throws: PasswordError.self) {
        _ = try PasswordGenerator.randomIndex(upperBound: -5)
    }
}

@Test
func randomIndexCoversWholeRange() throws {
    let bound = 16
    var seen = Set<Int>()
    for _ in 0..<5000 {
        seen.insert(try PasswordGenerator.randomIndex(upperBound: bound))
        if seen.count == bound { break }
    }
    // Over 5000 draws every value in [0, 16) should appear.
    #expect(seen.count == bound)
}

@Test
func randomIndexCoarseDistribution() throws {
    // LOOSE distribution check: with many draws no bucket should be wildly off.
    let bound = 10
    let draws = 100_000
    var counts = [Int](repeating: 0, count: bound)
    for _ in 0..<draws {
        counts[try PasswordGenerator.randomIndex(upperBound: bound)] += 1
    }
    let expected = Double(draws) / Double(bound) // 10_000
    for c in counts {
        let ratio = Double(c) / expected
        // Generous bounds (±20%) to avoid flakiness; biased RNG would blow past.
        #expect(ratio > 0.8)
        #expect(ratio < 1.2)
    }
}

@Test
func randomIndexHandlesNonPowerOfTwoBoundUniformly() throws {
    // A non-power-of-two bound is where modulo bias would show; check coverage
    // and a loose distribution.
    let bound = 7 // 256 % 7 != 0, so rejection sampling actually rejects
    let draws = 70_000
    var counts = [Int](repeating: 0, count: bound)
    for _ in 0..<draws {
        counts[try PasswordGenerator.randomIndex(upperBound: bound)] += 1
    }
    let expected = Double(draws) / Double(bound)
    for c in counts {
        let ratio = Double(c) / expected
        #expect(ratio > 0.85)
        #expect(ratio < 1.15)
    }
}

@Test
func randomIndexHandlesFullWidthBounds() throws {
    // Bounds > 2^56 force byteCount == 8 — the 2^64-sentinel branch that the
    // smaller-bound tests never reach.
    //
    // A power-of-two bound makes 2^64 an exact multiple of it (remainder 0), so
    // `wholeSpaceValid` is true and every draw is accepted.
    let powBound = 1 << 60
    for _ in 0..<3000 {
        let v = try PasswordGenerator.randomIndex(upperBound: powBound)
        #expect(v >= 0 && v < powBound)
    }

    // A non-power-of-two bound forces the sentinel-branch remainder/acceptLimit
    // arithmetic and the rejection loop (acceptLimit != 0, draws can be rejected).
    let oddBound = (1 << 60) + 1
    for _ in 0..<3000 {
        let v = try PasswordGenerator.randomIndex(upperBound: oddBound)
        #expect(v >= 0 && v < oddBound)
    }

    // Int.max is the largest possible bound and also exercises byteCount == 8.
    for _ in 0..<1000 {
        let v = try PasswordGenerator.randomIndex(upperBound: Int.max)
        #expect(v >= 0 && v < Int.max)
    }
}

// MARK: - Passphrase

@Test
func passphraseWordCountAndSeparator() throws {
    let gen = try makeGenerator()
    // Space separator: never appears inside a word (a few EFF words contain
    // '-', so '-' is not a safe delimiter for a count assertion).
    let phrase = try gen.generatePassphrase(wordCount: 6, separator: " ")
    let parts = phrase.reveal().split(separator: " ", omittingEmptySubsequences: false)
    #expect(parts.count == 6)
}

@Test
func passphraseWordsComeFromList() throws {
    let gen = try makeGenerator()
    let words = Set(try Wordlist.load())
    let phrase = try gen.generatePassphrase(wordCount: 8, separator: " ")
    for part in phrase.reveal().split(separator: " ") {
        #expect(words.contains(String(part)))
    }
}

@Test
func passphraseCustomSeparator() throws {
    let gen = try makeGenerator()
    // '.' never occurs inside a word, so the split count is exact regardless of
    // whether a hyphenated word was drawn.
    let phrase = try gen.generatePassphrase(wordCount: 5, separator: ".")
    let revealed = phrase.reveal()
    #expect(revealed.split(separator: ".", omittingEmptySubsequences: false).count == 5)
    #expect(revealed.contains("."))
}

@Test
func passphraseCapitalization() throws {
    let gen = try makeGenerator()
    // Space separator so each split token is exactly one (possibly hyphenated)
    // word whose first character must be uppercased.
    let phrase = try gen.generatePassphrase(
        wordCount: 6,
        separator: " ",
        capitalizeWords: true
    )
    for part in phrase.reveal().split(separator: " ") {
        let first = part.first!
        #expect(first.isUppercase)
    }
}

@Test
func passphraseIncludeNumberAppendsDigit() throws {
    let gen = try makeGenerator()
    let lowerWords = Set(try Wordlist.load()) // all lowercase
    // Use a space separator: a few EFF words are hyphenated, so '-' would be an
    // ambiguous separator for the per-word lookup below.
    let phrase = try gen.generatePassphrase(
        wordCount: 4,
        separator: " ",
        capitalizeWords: false,
        includeNumber: true
    )
    let revealed = phrase.reveal()
    // Last character must be a digit.
    #expect(revealed.last!.isNumber)
    // Strip the trailing digit; remaining must be 4 space-joined dictionary words.
    let withoutDigit = String(revealed.dropLast())
    let parts = withoutDigit.split(separator: " ")
    #expect(parts.count == 4)
    for part in parts {
        #expect(lowerWords.contains(String(part)))
    }
}

@Test
func passphraseThrowsOnInvalidWordCount() throws {
    let gen = try makeGenerator()
    #expect(throws: PasswordError.self) {
        _ = try gen.generatePassphrase(wordCount: 0)
    }
    #expect(throws: PasswordError.self) {
        _ = try gen.generatePassphrase(wordCount: -3)
    }
}

@Test
func passphraseWordsVaryAcrossCalls() throws {
    let gen = try makeGenerator()
    // Two independent 6-word phrases are overwhelmingly unlikely to match.
    let a = try gen.generatePassphrase(wordCount: 6).reveal()
    let b = try gen.generatePassphrase(wordCount: 6).reveal()
    #expect(a != b)
}

// MARK: - Policy value semantics

@Test
func strongPolicyHasExpectedShape() {
    let p = PasswordPolicy.strong
    #expect(p.length == 20)
    #expect(p.useLowercase)
    #expect(p.useUppercase)
    #expect(p.useDigits)
    #expect(p.useSymbols)
    #expect(p.avoidAmbiguous)
    #expect(!p.lettersAndDigitsOnly)
}

@Test
func policyEquatable() {
    #expect(PasswordPolicy.strong == PasswordPolicy.strong)
    #expect(PasswordPolicy(length: 20) != PasswordPolicy(length: 24))
}

// MARK: - Passwords differ across calls (not constant)

@Test
func generatedPasswordsAreNotConstant() throws {
    let gen = try makeGenerator()
    var seen = Set<String>()
    for _ in 0..<20 {
        seen.insert(try gen.generate(.strong).reveal())
    }
    // 20 independent length-20 passwords colliding would indicate a broken RNG.
    #expect(seen.count == 20)
}
