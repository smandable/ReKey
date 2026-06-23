import Foundation
import Model

/// Reads and prunes a Firefox `logins.json`. Usernames and passwords there are
/// NSS-encrypted, so logins are identified by `hostname` + `guid` + timestamps,
/// never by decrypted username — this never touches `key4.db` / NSS.
///
/// Deletes preserve the entire file: the JSON is round-tripped through a
/// dictionary so unknown top-level keys (e.g. `potentiallyVulnerablePasswords`,
/// `dismissedBreachAlertsByLoginGUID`) and unknown per-login fields survive
/// untouched. Only matched `logins` entries are removed, and the write is atomic.
public struct FirefoxLoginStore: LoginStore {
    public var browser: BrowserSource { .firefox }
    public let loginsURL: URL

    /// `logins.json` schema versions we know how to edit safely.
    private static let supportedVersions: Set<Int> = [2, 3]

    public init(loginsURL: URL) { self.loginsURL = loginsURL }

    public func validate() throws {
        _ = try readRoot()
    }

    public func list(matching filter: LoginFilter) throws -> [StoredLogin] {
        let root = try readRoot()
        let logins = (root["logins"] as? [[String: Any]]) ?? []
        return logins.map(makeStoredLogin).filter(filter.matches)
    }

    public func delete(matching filter: LoginFilter, backupDirectory: URL) throws -> DeleteOutcome {
        guard !filter.isEmpty else { throw LoginStoreError.noFilter }
        var root = try readRoot()
        let loginsArray = (root["logins"] as? [[String: Any]]) ?? []

        // Only entries with a real guid can be uniquely (and safely) targeted.
        // An entry with a missing/empty guid is never deletable — otherwise the
        // empty-string sentinel would collide and collateral-delete *every*
        // guid-less entry when one is matched by site.
        let deletable = loginsArray.map(makeStoredLogin).filter(filter.matches).filter { !$0.id.isEmpty }
        guard !deletable.isEmpty else { return DeleteOutcome(deleted: [], backupPath: backupDirectory) }

        // Back up BEFORE writing.
        try StoreBackup.copy(files: [loginsURL], into: backupDirectory)

        // Remove exactly the entries that THEMSELVES match (and carry a real guid) —
        // judged per entry, NOT by guid-set membership. A corrupt store with a
        // duplicate non-empty guid would otherwise collaterally delete a
        // non-matching sibling that merely shares that guid. Guid-less entries are
        // never deletable, so they're always kept.
        let remaining = loginsArray.filter { entry in
            let login = makeStoredLogin(entry)
            return login.id.isEmpty || !filter.matches(login)
        }
        root["logins"] = remaining

        guard JSONSerialization.isValidJSONObject(root) else {
            throw LoginStoreError.io("refusing to write malformed JSON")
        }
        let out: Data
        do {
            out = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        } catch {
            throw LoginStoreError.io("couldn't serialize logins.json: \(error.localizedDescription)")
        }
        do {
            try out.write(to: loginsURL, options: .atomic)   // temp file + rename
        } catch {
            throw LoginStoreError.io("couldn't write logins.json: \(error.localizedDescription)")
        }
        return DeleteOutcome(deleted: deletable, backupPath: backupDirectory)
    }

    // MARK: - Helpers

    private func readRoot() throws -> [String: Any] {
        guard FileManager.default.fileExists(atPath: loginsURL.path) else {
            throw LoginStoreError.fileNotFound(loginsURL)
        }
        let data: Data
        do { data = try Data(contentsOf: loginsURL) }
        catch { throw LoginStoreError.io(error.localizedDescription) }

        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw LoginStoreError.unrecognizedSchema("logins.json is not a JSON object")
        }
        guard let version = root["version"] as? Int, Self.supportedVersions.contains(version) else {
            let shown = root["version"].map { "\($0)" } ?? "missing"
            throw LoginStoreError.unrecognizedSchema("logins.json version \(shown) not supported")
        }
        guard root["logins"] is [Any] else {
            throw LoginStoreError.unrecognizedSchema("logins.json has no 'logins' array")
        }
        // `nextId` is a core Firefox logins.json field. Requiring it keeps a
        // misdirected --path from rewriting some *other* JSON file that merely
        // happens to have a `version` + `logins` array.
        guard root["nextId"] != nil else {
            throw LoginStoreError.unrecognizedSchema("logins.json is missing 'nextId' — doesn't look like a Firefox login store")
        }
        return root
    }

    private func makeStoredLogin(_ entry: [String: Any]) -> StoredLogin {
        StoredLogin(
            id: (entry["guid"] as? String) ?? "",
            browser: .firefox,
            origin: (entry["hostname"] as? String) ?? (entry["origin"] as? String) ?? "",
            signonRealm: entry["httpRealm"] as? String,
            username: nil,
            usernameIsEncrypted: true,
            createdAt: firefoxDate(entry["timeCreated"]),
            lastUsedAt: firefoxDate(entry["timeLastUsed"])
        )
    }

    /// Firefox stores milliseconds since the Unix epoch.
    private func firefoxDate(_ value: Any?) -> Date? {
        let ms: Double?
        switch value {
        case let d as Double: ms = d
        case let i as Int: ms = Double(i)
        case let n as NSNumber: ms = n.doubleValue
        default: ms = nil
        }
        guard let ms, ms > 0 else { return nil }
        return Date(timeIntervalSince1970: ms / 1000.0)
    }
}
