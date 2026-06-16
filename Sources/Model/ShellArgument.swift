import Foundation

public extension String {
    /// This string as one safely-quoted POSIX shell argument, for building the
    /// `rekey-cleanup` commands/scripts Rekey generates (and tells the user to run
    /// in a non-sandboxed shell).
    ///
    /// Values made only of letters/digits and `@._-+` (clean domains, emails, row
    /// ids) pass through unquoted for readability; anything else — notably shell
    /// metacharacters that a crafted CSV `url` could smuggle into a `--site` value —
    /// is single-quoted with embedded `'` escaped, so it can't break out of its
    /// argument and inject commands.
    var shellArgument: String {
        let safe = !isEmpty && allSatisfy { $0.isLetter || $0.isNumber || "@._-+".contains($0) }
        if safe { return self }
        return "'" + replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
