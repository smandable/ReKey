import Foundation

/// Where a fix is in the approval flow. The only irreversible action — actually
/// changing the password on the site — is performed by the human, not the app.
public enum FixStatus: String, Sendable, Equatable, Codable, CaseIterable {
    /// In the queue, awaiting the user's explicit approval.
    case pending
    /// New password copied to clipboard and change page opened in the browser.
    case opened
    /// User confirmed they changed it on the site (browser saved the new value).
    case done
    /// User chose not to fix this one.
    case skipped
}

/// One row in the fix queue: a preview/approve card. The app generates the new
/// password and resolves the change URL, but never performs the change itself.
public struct FixItem: Identifiable, Sendable, Equatable {
    public let id: UUID
    /// The credential this fix targets.
    public let credentialID: UUID
    /// eTLD+1, for cleanup grouping / sibling analysis.
    public let registrableDomain: String
    /// The actual host the login lives on (e.g. `amerihome.loanadministration.com`).
    /// Empty falls back to `registrableDomain` via `site`.
    public let host: String
    public let username: String
    /// Masked old password for display (never the real value).
    public let oldPasswordMasked: String
    /// Freshly generated replacement. Held in memory only.
    public var newPassword: Secret
    /// Resolved change-password URL, or nil if resolution missed (then the UI
    /// opens the site root and tells the user to find settings themselves).
    public var changeURL: URL?
    public var status: FixStatus

    public init(
        id: UUID = UUID(),
        credentialID: UUID,
        registrableDomain: String,
        host: String = "",
        username: String,
        oldPasswordMasked: String,
        newPassword: Secret,
        changeURL: URL? = nil,
        status: FixStatus = .pending
    ) {
        self.id = id
        self.credentialID = credentialID
        self.registrableDomain = registrableDomain
        self.host = host
        self.username = username
        self.oldPasswordMasked = oldPasswordMasked
        self.newPassword = newPassword
        self.changeURL = changeURL
        self.status = status
    }

    /// The site the user acts on: the full host when known, else the registrable
    /// domain. What the card displays, opens, and cleans.
    public var site: String { host.isEmpty ? registrableDomain : host }
}
