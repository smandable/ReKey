import Foundation

/// The CSV layout a file appears to use, decided from its header row.
public enum DetectedFormat: Sendable, Equatable {
    /// Apple Passwords / Safari: `Title,URL,Username,Password,Notes,OTPAuth`.
    case applePasswords
    /// Firefox: `url,username,password,httpRealm,formActionOrigin,guid,...`.
    case firefox
    /// Chromium (Chrome and Arc are byte-identical): `name,url,username,password,note`.
    case chromium
    /// Could not be classified; caller should attempt a fuzzy column map.
    case unknown
}

/// Decides the export format from the header row.
///
/// Detection is by column **name**, never by position, because the layouts
/// drift across browser versions. Run case-sensitively against the parsed
/// header, in priority order (Apple's capitalized columns and Firefox's
/// distinctive columns are checked before the generic Chromium trio).
public enum FormatDetector {
    public static func detect(headers: [String]) -> DetectedFormat {
        let set = Set(headers)

        // 1. Apple Passwords: the `OTPAuth` column or the capitalized `Title`.
        if set.contains("OTPAuth") || set.contains("Title") {
            return .applePasswords
        }

        // 2. Firefox: any of its distinctive lowercase columns.
        if set.contains("httpRealm") || set.contains("formActionOrigin") || set.contains("guid") {
            return .firefox
        }

        // 3. Chromium: the lowercase required trio (optional name/note).
        if set.contains("url") && set.contains("username") && set.contains("password") {
            return .chromium
        }

        // 4. Unknown — fuzzy mapping happens in the normalizer.
        return .unknown
    }
}
