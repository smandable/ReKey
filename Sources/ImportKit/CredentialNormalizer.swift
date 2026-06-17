import Foundation
import Model

/// Why a row was dropped during import (surfaced in the "skipped N rows"
/// summary).
public enum SkipReason: String, Sendable, Equatable {
    /// No password — passkey-only or federated "sign in with…" entries.
    case blankPassword
    /// No URL.
    case blankURL
    /// Required columns (url/username/password) couldn't be located in the row.
    case unmappableRow
}

/// A row that didn't become a credential, with enough context for the summary.
public struct SkippedRow: Sendable, Equatable {
    /// 1-based index among data rows (header excluded).
    public let rowNumber: Int
    public let reason: SkipReason
    public let rawURL: String?

    public init(rowNumber: Int, reason: SkipReason, rawURL: String?) {
        self.rowNumber = rowNumber
        self.reason = reason
        self.rawURL = rawURL
    }
}

/// The outcome of importing one CSV file.
public struct ImportResult: Sendable {
    public let source: BrowserSource
    public let detectedFormat: DetectedFormat
    public let credentials: [ImportedCredential]
    public let skipped: [SkippedRow]

    public init(
        source: BrowserSource,
        detectedFormat: DetectedFormat,
        credentials: [ImportedCredential],
        skipped: [SkippedRow]
    ) {
        self.source = source
        self.detectedFormat = detectedFormat
        self.credentials = credentials
        self.skipped = skipped
    }
}

public enum ImportError: Error, Equatable {
    case emptyFile
    /// Couldn't find url/username/password columns even with fuzzy matching;
    /// the UI should offer a manual column-mapping step.
    case unrecognizedColumns
}

/// Maps a detected/parsed CSV into normalized ``ImportedCredential`` values.
///
/// Column access is always by header **name**, order-insensitive. Non-secret
/// fields (URL, username, title, notes) are whitespace-trimmed; the password is
/// taken **verbatim** so it is never altered. The TOTP seed, when present, is
/// read only to set `hasTOTP` and is otherwise discarded.
public struct CSVImporter: Sendable {
    private let canonicalizer: URLCanonicalizer

    public init(canonicalizer: URLCanonicalizer) {
        self.canonicalizer = canonicalizer
    }

    /// Uses the vendored Public Suffix List.
    public init() {
        self.canonicalizer = URLCanonicalizer()
    }

    /// Import CSV bytes. `chromiumSource` labels which Chromium-based browser a
    /// Chromium-format file came from (they're indistinguishable by content);
    /// it's ignored for Firefox and Apple formats. Defaults to Chrome.
    public func `import`(data: Data, chromiumSource: BrowserSource = .chrome) throws -> ImportResult {
        let table = try CSVParser.parse(data)
        return try makeResult(from: table, chromiumSource: chromiumSource)
    }

    public func `import`(text: String, chromiumSource: BrowserSource = .chrome) throws -> ImportResult {
        let table = try CSVParser.parse(text)
        return try makeResult(from: table, chromiumSource: chromiumSource)
    }

    // MARK: - Internals

    struct ColumnMap {
        let url: Int
        let username: Int
        let password: Int
        let title: Int?
        let notes: Int?
        let otpauth: Int?
    }

    func makeResult(from table: CSVTable, chromiumSource: BrowserSource) throws -> ImportResult {
        guard !table.headers.isEmpty else { throw ImportError.emptyFile }

        let format = FormatDetector.detect(headers: table.headers)
        guard let columns = resolveColumns(format: format, headers: table.headers) else {
            throw ImportError.unrecognizedColumns
        }
        let source = browserSource(for: format, chromiumSource: chromiumSource)

        var credentials: [ImportedCredential] = []
        var skipped: [SkippedRow] = []

        for (offset, row) in table.rows.enumerated() {
            let rowNumber = offset + 1
            let rawURLField = field(row, columns.url).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            // Password is taken verbatim — never trimmed.
            let passwordField = field(row, columns.password)

            guard let password = passwordField, !password.isEmpty else {
                skipped.append(SkippedRow(rowNumber: rowNumber, reason: .blankPassword, rawURL: rawURLField))
                continue
            }
            guard let rawURL = rawURLField, !rawURL.isEmpty else {
                skipped.append(SkippedRow(rowNumber: rowNumber, reason: .blankURL, rawURL: rawURLField))
                continue
            }

            let username = field(row, columns.username)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let title = trimmedNonEmpty(field(row, columns.title))
            let notes = trimmedNonEmpty(field(row, columns.notes))
            let otp = field(row, columns.otpauth)
            let hasTOTP = !(otp ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty

            let registrableDomain = canonicalizer.registrableDomain(fromRawURL: rawURL) ?? rawURL
            let host = canonicalizer.host(fromRawURL: rawURL) ?? ""
            let secret = Secret(password)
            // Stable across re-imports of the same login (see deterministicID).
            let id = ImportedCredential.deterministicID(
                source: source, registrableDomain: registrableDomain,
                username: username, passwordHash: secret.sha256().base64EncodedString())

            credentials.append(ImportedCredential(
                id: id,
                source: source,
                title: title,
                rawURL: rawURL,
                registrableDomain: registrableDomain,
                host: host,
                username: username,
                password: secret,
                notes: notes,
                hasTOTP: hasTOTP
            ))
        }

        return ImportResult(
            source: source,
            detectedFormat: format,
            credentials: credentials,
            skipped: skipped
        )
    }

    private func browserSource(for format: DetectedFormat, chromiumSource: BrowserSource) -> BrowserSource {
        switch format {
        case .applePasswords: return .applePasswords
        case .firefox: return .firefox
        // Chromium browsers are indistinguishable by content; honor the user's
        // chosen label, but only if it's actually a Chromium-family browser.
        case .chromium: return chromiumSource.isChromiumFamily ? chromiumSource : .chrome
        case .unknown: return .unknown
        }
    }

    /// Resolve logical columns to indices. By exact name for known formats, with
    /// a case-insensitive fuzzy fallback for unknown layouts.
    func resolveColumns(format: DetectedFormat, headers: [String]) -> ColumnMap? {
        func index(_ name: String) -> Int? { headers.firstIndex(of: name) }

        switch format {
        case .chromium:
            guard let u = index("url"), let n = index("username"), let p = index("password") else { return nil }
            return ColumnMap(url: u, username: n, password: p,
                             title: index("name"), notes: index("note"), otpauth: nil)
        case .firefox:
            guard let u = index("url"), let n = index("username"), let p = index("password") else { return nil }
            return ColumnMap(url: u, username: n, password: p,
                             title: nil, notes: nil, otpauth: nil)
        case .applePasswords:
            guard let u = index("URL"), let n = index("Username"), let p = index("Password") else { return nil }
            return ColumnMap(url: u, username: n, password: p,
                             title: index("Title"), notes: index("Notes"), otpauth: index("OTPAuth"))
        case .unknown:
            return fuzzyColumns(headers: headers)
        }
    }

    /// Best-effort mapping for unrecognized layouts.
    private func fuzzyColumns(headers: [String]) -> ColumnMap? {
        let lower = headers.map { $0.lowercased() }
        func find(_ candidates: [String]) -> Int? {
            for c in candidates { if let i = lower.firstIndex(of: c) { return i } }
            return nil
        }
        guard
            let u = find(["url", "website", "login_uri", "uri", "login_url", "site"]),
            let p = find(["password", "pass", "pwd"])
        else { return nil }
        let n = find(["username", "login", "email", "user", "user_name"]) ?? u
        return ColumnMap(url: u, username: n, password: p,
                         title: find(["name", "title"]), notes: find(["note", "notes", "comment"]), otpauth: find(["otpauth", "otp", "totp"]))
    }

    private func field(_ row: [String], _ index: Int?) -> String? {
        guard let i = index, i >= 0, i < row.count else { return nil }
        return row[i]
    }

    private func trimmedNonEmpty(_ s: String?) -> String? {
        guard let t = s?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty else { return nil }
        return t
    }
}
