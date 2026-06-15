import Foundation

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
        self.username = username
        self.password = password
        self.notes = notes
        self.hasTOTP = hasTOTP
    }
}
