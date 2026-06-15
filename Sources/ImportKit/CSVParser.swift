import Foundation

/// A parsed CSV table: the header row plus the data rows, fields preserved
/// verbatim.
public struct CSVTable: Sendable, Equatable {
    public let headers: [String]
    public let rows: [[String]]

    public init(headers: [String], rows: [[String]]) {
        self.headers = headers
        self.rows = rows
    }

    /// Index of a header by exact (case-sensitive) name, or nil.
    public func columnIndex(_ name: String) -> Int? {
        headers.firstIndex(of: name)
    }
}

public enum CSVParseError: Error, Equatable {
    case empty
}

/// A correct RFC 4180 CSV parser.
///
/// Handles: quoted fields, commas inside quotes, newlines inside quotes,
/// escaped double-quotes (`""`), a UTF-8 BOM, and both `\n` and `\r\n` (and lone
/// `\r`) line endings. Fields are returned **verbatim** — no trimming — so a
/// password is never altered by the parser. (Whitespace trimming of non-secret
/// fields like URL/username happens later, in normalization.)
public enum CSVParser {

    public static func parse(_ data: Data) throws -> CSVTable {
        // Decode as UTF-8. A leading BOM in the bytes is handled by the String
        // scanner below as well, but strip it here too for safety.
        guard let text = String(data: data, encoding: .utf8) else {
            throw CSVParseError.empty
        }
        return try parse(text)
    }

    public static func parse(_ text: String) throws -> CSVTable {
        let records = parseRecords(text)
        guard let header = records.first else { throw CSVParseError.empty }
        let rows = Array(records.dropFirst())
        return CSVTable(headers: header, rows: rows)
    }

    /// Core state machine. Returns every record (including the header) as an
    /// array of verbatim field strings.
    ///
    /// Scans over **Unicode scalars**, not `Character`s: in Swift `"\r\n"` is a
    /// single grapheme cluster, so a `Character`-based scan would never see the
    /// `\r` and `\n` separately and would miss CRLF record boundaries.
    static func parseRecords(_ input: String) -> [[String]] {
        var scalars = Array(input.unicodeScalars)
        // Strip a leading UTF-8 BOM (U+FEFF) if present.
        if let first = scalars.first, first == "\u{FEFF}" {
            scalars.removeFirst()
        }

        let comma: Unicode.Scalar = ","
        let quote: Unicode.Scalar = "\""
        let cr: Unicode.Scalar = "\r"
        let lf: Unicode.Scalar = "\n"

        var records: [[String]] = []
        var record: [String] = []
        var field = String.UnicodeScalarView()
        var inQuotes = false
        // Whether we've seen any content (scalars, an opened quote, or a finished
        // field) since the last record terminator. Distinguishes a real final
        // record from the empty tail left by a trailing newline.
        var pending = false

        var i = 0
        let n = scalars.count
        while i < n {
            let c = scalars[i]
            if inQuotes {
                if c == quote {
                    if i + 1 < n && scalars[i + 1] == quote {
                        field.append(quote)   // escaped quote ""
                        i += 2
                    } else {
                        inQuotes = false      // closing quote
                        i += 1
                    }
                } else {
                    field.append(c)           // literal (incl. comma / newline)
                    i += 1
                }
            } else {
                if c == quote {
                    inQuotes = true
                    pending = true
                    i += 1
                } else if c == comma {
                    record.append(String(field))
                    field = String.UnicodeScalarView()
                    pending = true
                    i += 1
                } else if c == cr || c == lf {
                    if c == cr && i + 1 < n && scalars[i + 1] == lf {
                        i += 1                 // consume the \n of a \r\n pair
                    }
                    record.append(String(field))
                    records.append(record)
                    record = []
                    field = String.UnicodeScalarView()
                    pending = false
                    i += 1
                } else {
                    field.append(c)
                    pending = true
                    i += 1
                }
            }
        }

        // Flush any trailing record that wasn't terminated by a newline.
        if pending || !record.isEmpty {
            record.append(String(field))
            records.append(record)
        }
        return records
    }
}
