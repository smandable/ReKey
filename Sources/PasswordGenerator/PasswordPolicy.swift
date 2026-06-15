import Foundation

/// Errors thrown when a policy is impossible to satisfy or randomness fails.
public enum PasswordError: Error, Sendable, Equatable {
    /// No character classes were enabled (after applying `lettersAndDigitsOnly`).
    case noClassesEnabled
    /// The requested length is smaller than the number of enabled classes, so
    /// the "at least one of each enabled class" guarantee cannot be met.
    case lengthTooSmallForClasses(length: Int, requiredClasses: Int)
    /// An invalid argument was supplied (e.g. non-positive word count).
    case invalidArgument(String)
    /// The bundled wordlist could not be located or parsed.
    case wordlistUnavailable
    /// The system CSPRNG (`SecRandomCopyBytes`) failed.
    case randomGenerationFailed
}

/// A character class that may participate in a generated password. Each enabled
/// class is guaranteed to contribute at least one character.
enum CharacterClass: CaseIterable, Sendable {
    case lowercase
    case uppercase
    case digits
    case symbols

    /// The full character set for this class, *before* removing ambiguous
    /// characters. ASCII only, so each character is a single UTF-8 byte.
    var characters: [Character] {
        switch self {
        case .lowercase: return Array("abcdefghijklmnopqrstuvwxyz")
        case .uppercase: return Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        case .digits:    return Array("0123456789")
        case .symbols:   return Array("!@#$%^&*()-_=+[]{};:,.?/")
        }
    }
}

/// The set of ambiguous characters excluded when `avoidAmbiguous` is set:
/// capital-I, lowercase-L, digit-one, capital-O, digit-zero.
let ambiguousCharacters: Set<Character> = ["I", "l", "1", "O", "0"]

/// Describes the shape of a generated password.
public struct PasswordPolicy: Sendable, Equatable {
    /// Total length in characters. Defaults to 20. Values below 8 are raised to
    /// 8 (enforced minimum). Large values are permitted.
    public var length: Int

    public var useLowercase: Bool
    public var useUppercase: Bool
    public var useDigits: Bool
    public var useSymbols: Bool

    /// Exclude the ambiguous characters `I l 1 O 0` from the alphabet.
    public var avoidAmbiguous: Bool

    /// When `true`, symbols are forced OFF regardless of `useSymbols` — for
    /// sites that reject non-alphanumeric characters.
    public var lettersAndDigitsOnly: Bool

    /// The minimum permitted length. Any smaller request is clamped up to this.
    public static let minimumLength = 8

    public init(
        length: Int = 20,
        useLowercase: Bool = true,
        useUppercase: Bool = true,
        useDigits: Bool = true,
        useSymbols: Bool = true,
        avoidAmbiguous: Bool = true,
        lettersAndDigitsOnly: Bool = false
    ) {
        // Enforce the minimum length; allow arbitrarily large values.
        self.length = max(length, Self.minimumLength)
        self.useLowercase = useLowercase
        self.useUppercase = useUppercase
        self.useDigits = useDigits
        self.useSymbols = useSymbols
        self.avoidAmbiguous = avoidAmbiguous
        self.lettersAndDigitsOnly = lettersAndDigitsOnly
    }

    /// A strong default: length 20, all classes on, ambiguous characters
    /// avoided, symbols allowed.
    public static let strong = PasswordPolicy(
        length: 20,
        useLowercase: true,
        useUppercase: true,
        useDigits: true,
        useSymbols: true,
        avoidAmbiguous: true,
        lettersAndDigitsOnly: false
    )

    /// Whether symbols ultimately participate, taking `lettersAndDigitsOnly`
    /// into account.
    var symbolsEffective: Bool {
        useSymbols && !lettersAndDigitsOnly
    }

    /// The enabled classes, in a stable order, with `lettersAndDigitsOnly`
    /// already applied (symbols dropped when set).
    var enabledClasses: [CharacterClass] {
        var classes: [CharacterClass] = []
        if useLowercase { classes.append(.lowercase) }
        if useUppercase { classes.append(.uppercase) }
        if useDigits { classes.append(.digits) }
        if symbolsEffective { classes.append(.symbols) }
        return classes
    }

    /// The allowed characters for a given class under this policy (ambiguous
    /// characters removed when `avoidAmbiguous`). May be empty if every member
    /// of the class is ambiguous (not possible for the built-in classes).
    func allowedCharacters(for cls: CharacterClass) -> [Character] {
        let base = cls.characters
        guard avoidAmbiguous else { return base }
        return base.filter { !ambiguousCharacters.contains($0) }
    }
}
