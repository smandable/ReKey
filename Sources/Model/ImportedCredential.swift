import Foundation
import CryptoKit

/// One credential after CSV parsing + normalization. This is the canonical unit
/// the audit engine, findings view, and fix queue all operate on.
///
/// `password` is a ``Secret`` so it can never be accidentally logged. The TOTP
/// seed from the source row is **not** stored: only the boolean `hasTOTP` is
/// kept, per the hard constraints.
public struct ImportedCredential: Identifiable, Sendable, Equatable {
    public let id: UUID
    public let source: BrowserSource
    public let title: String?
    /// The original, full URL as exported (scheme + host + path). Kept verbatim
    /// because the reset router needs the real URL, not the canonical domain.
    public let rawURL: String
    /// eTLD+1 computed via the Public Suffix List, lowercased, `www.` stripped.
    /// Used for grouping and reuse analysis (e.g. `accounts.google.com` ->
    /// `google.com`). Empty string only if the URL had no resolvable host.
    public let registrableDomain: String
    /// The full host as exported (lowercased, `www.` stripped), e.g.
    /// `amerihome.loanadministration.com` — the *actual* site the login lives on,
    /// not the collapsed domain. Empty when no host could be parsed.
    public let host: String
    public let username: String
    public let password: Secret
    public let notes: String?
    /// True when the source row carried a TOTP / `otpauth://` seed. The seed
    /// itself is intentionally discarded.
    public let hasTOTP: Bool

    public init(
        id: UUID = UUID(),
        source: BrowserSource,
        title: String?,
        rawURL: String,
        registrableDomain: String,
        host: String = "",
        username: String,
        password: Secret,
        notes: String?,
        hasTOTP: Bool
    ) {
        self.id = id
        self.source = source
        self.title = title
        self.rawURL = rawURL
        self.registrableDomain = registrableDomain
        self.host = host
        self.username = username
        self.password = password
        self.notes = notes
        self.hasTOTP = hasTOTP
    }

    /// The site the user actually logs in to: the full host when known, else the
    /// registrable domain. This is what the fix queue shows, opens, and cleans —
    /// `registrableDomain` stays for reuse grouping (eTLD+1).
    public var site: String { host.isEmpty ? registrableDomain : host }

    /// A copy stamped with a different browser source, with its stable `id`
    /// recomputed to match. Used when correcting a mislabeled Chromium import
    /// (Arc CSVs are indistinguishable from Chrome by content): the result is
    /// identical to what a fresh import under `newSource` would have produced,
    /// so re-import dedup stays consistent.
    public func relabeled(to newSource: BrowserSource) -> ImportedCredential {
        ImportedCredential(
            id: Self.deterministicID(
                source: newSource,
                registrableDomain: registrableDomain,
                username: username,
                passwordHash: password.sha256().base64EncodedString()),
            source: newSource,
            title: title,
            rawURL: rawURL,
            registrableDomain: registrableDomain,
            host: host,
            username: username,
            password: password,
            notes: notes,
            hasTOTP: hasTOTP)
    }

    /// A STABLE id derived from the fields that identify this exact saved login,
    /// so re-importing the same export (or an auto-import poll) yields the same id
    /// — queued fix items and progress keep resolving across a re-import instead of
    /// orphaning on a fresh random UUID. Two genuinely different logins still
    /// differ (the inputs match the import-dedup key, so same-id ⇔ exact duplicate).
    public static func deterministicID(
        source: BrowserSource,
        registrableDomain: String,
        username: String,
        passwordHash: String
    ) -> UUID {
        let key = "\(source.rawValue)\u{1}\(registrableDomain)\u{1}\(username)\u{1}\(passwordHash)"
        let d = Array(SHA256.hash(data: Data(key.utf8)))   // 32 bytes; take the first 16 for the UUID
        return UUID(uuid: (d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
                           d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]))
    }
}
