import Foundation

public extension String {
    /// This string as one safely-quoted POSIX shell argument, for building the
    /// `rekey-cleanup` commands/scripts ReKey generates (and tells the user to run
    /// in a non-sandboxed shell).
    ///
    /// Values made only of letters/digits and `@._-+` (clean domains, emails, row
    /// ids) pass through unquoted for readability; anything else — notably shell
    /// metacharacters that a crafted CSV `url` could smuggle into a `--site` value —
    /// is single-quoted with embedded `'` escaped, so it can't break out of its
    /// argument and inject commands.
    ///
    /// A leading `-` is treated as unsafe and quoted even though `-` is otherwise
    /// in the readable set: an unquoted value like `--confirm` would render as a
    /// bare token that a getopt-style parser could mistake for a real flag.
    /// (Quoting alone doesn't stop a parser from re-reading `--confirm` as a flag —
    /// `rekey-cleanup`'s own parser additionally binds each value to its flag
    /// greedily so a `--`-leading value can never float free — but emitting it
    /// quoted makes the intent unambiguous and defends any other consumer.)
    var shellArgument: String {
        let safe = !isEmpty && first != "-"
            && allSatisfy { $0.isLetter || $0.isNumber || "@._-+".contains($0) }
        if safe { return self }
        return "'" + replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
