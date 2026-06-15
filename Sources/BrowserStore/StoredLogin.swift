import Foundation
import Model

/// One saved login as it exists in a browser's store, identified by its
/// plaintext index fields only. The encrypted password (and, for Firefox, the
/// encrypted username) is never read — deletion matches on these unencrypted
/// columns, so this tool never needs the Safe Storage key or NSS.
public struct StoredLogin: Sendable, Equatable, Identifiable {
    /// Stable identifier for targeting a delete: SQLite `rowid` (Chromium) or
    /// `guid` (Firefox).
    public let id: String
    public let browser: BrowserSource
    /// `origin_url` (Chromium) or `hostname` (Firefox).
    public let origin: String
    public let signonRealm: String?
    /// Plaintext username (Chromium). `nil` when it can't be read without
    /// decryption (Firefox), with `usernameIsEncrypted == true`.
    public let username: String?
    public let usernameIsEncrypted: Bool
    public let createdAt: Date?
    public let lastUsedAt: Date?

    public init(
        id: String, browser: BrowserSource, origin: String, signonRealm: String?,
        username: String?, usernameIsEncrypted: Bool, createdAt: Date?, lastUsedAt: Date?
    ) {
        self.id = id
        self.browser = browser
        self.origin = origin
        self.signonRealm = signonRealm
        self.username = username
        self.usernameIsEncrypted = usernameIsEncrypted
        self.createdAt = createdAt
        self.lastUsedAt = lastUsedAt
    }
}

/// A filter selecting which logins to list or delete. At least one criterion
/// must be set before a delete is allowed (never bulk-delete everything).
public struct LoginFilter: Sendable, Equatable {
    /// Case-insensitive substring match on the origin/host (and signon realm).
    public var site: String?
    /// Exact username match (Chromium only — Firefox usernames are encrypted).
    public var username: String?
    /// Target specific rows/guids precisely.
    public var identifiers: Set<String>

    public init(site: String? = nil, username: String? = nil, identifiers: Set<String> = []) {
        self.site = site
        self.username = username
        self.identifiers = identifiers
    }

    public var isEmpty: Bool {
        (site?.isEmpty ?? true) && (username?.isEmpty ?? true) && identifiers.isEmpty
    }

    func matches(_ login: StoredLogin) -> Bool {
        if !identifiers.isEmpty, !identifiers.contains(login.id) { return false }
        if let site, !site.isEmpty {
            let hay = (login.origin + " " + (login.signonRealm ?? "")).lowercased()
            if !hay.contains(site.lowercased()) { return false }
        }
        if let username, !username.isEmpty {
            if login.username != username { return false }
        }
        return true
    }
}

/// Result of a delete, including where the pre-delete backup was written.
public struct DeleteOutcome: Sendable, Equatable {
    public let deleted: [StoredLogin]
    public let backupPath: URL
    public var deletedCount: Int { deleted.count }
}

public enum LoginStoreError: Error, CustomStringConvertible, Equatable {
    case fileNotFound(URL)
    case unrecognizedSchema(String)
    case backupFailed(String)
    case sqlite(String)
    case io(String)
    /// A delete was requested with no filter — refused, to avoid wiping the store.
    case noFilter

    public var description: String {
        switch self {
        case .fileNotFound(let url): return "Store not found at \(url.path). Pass --path to point at it directly."
        case .unrecognizedSchema(let why): return "Unrecognized store schema: \(why). Refusing to touch it."
        case .backupFailed(let why): return "Backup failed (\(why)); nothing was deleted."
        case .sqlite(let msg): return "SQLite error: \(msg)"
        case .io(let msg): return "I/O error: \(msg)"
        case .noFilter: return "Refusing to delete without a filter (--site, --username, or --id)."
        }
    }
}

/// A browser login store that can be listed and (decrypt-free) pruned.
public protocol LoginStore: Sendable {
    var browser: BrowserSource { get }
    /// Throw `unrecognizedSchema`/`fileNotFound` if this isn't a store shape we
    /// know how to touch safely.
    func validate() throws
    func list(matching filter: LoginFilter) throws -> [StoredLogin]
    /// Back up the store into `backupDirectory`, then delete the matched logins.
    /// If backup fails, nothing is deleted. The caller must have already checked
    /// that the browser is not running.
    func delete(matching filter: LoginFilter, backupDirectory: URL) throws -> DeleteOutcome
}
