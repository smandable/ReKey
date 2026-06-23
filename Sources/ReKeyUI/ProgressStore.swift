import Foundation

/// Hashes captured when a fix is marked done, so a later re-import can tell
/// whether the change actually saved — only hashes are kept, never a password.
/// The hashes are *keyed* HMACs (key in the Keychain, see `FixVerificationKey`),
/// not plain digests, so the value persisted to UserDefaults can't be used to
/// brute-force the real (often weak) password offline.
struct FixSaveRecord: Sendable {
    let progressKey: String
    let oldHash: String
    let newHash: String
    let source: String
}

/// The persisted fix-progress snapshot: site+username keys, deletion marks, and
/// save-verification HMACs only — NEVER a password. A plain value type so it
/// round-trips cleanly through ``ProgressStore``.
struct ProgressState {
    var completed: Set<String> = []
    var skipped: Set<String> = []
    var ignored: Set<String> = []
    var deletion: Set<String> = []
    var saveRecords: [String: FixSaveRecord] = [:]   // recKey -> record
    var usernameOverrides: [String: String] = [:]
}

/// Loads and saves ``ProgressState`` to `UserDefaults`, owning the on-disk format
/// and schema versioning. Extracted from `AppModel` so the persistence layer is a
/// single, independently-testable unit (and `AppModel` is that much less of a god
/// object).
enum ProgressStore {
    /// On-disk shape version. Bump it and add a migration branch in `load` whenever
    /// the stored key/value format changes, so an old plist isn't silently misread.
    static let schemaVersion = 1

    static let schemaKey = "rekey.progressSchemaVersion"
    static let completedKey = "rekey.completedKeys"
    static let skippedKey = "rekey.skippedKeys"
    static let ignoredKey = "rekey.ignoredKeys"
    static let deletionKey = "rekey.deletionKeys"
    static let saveRecordsKey = "rekey.fixSaveRecords"
    static let usernameOverridesKey = "rekey.usernameOverrides"

    static func save(_ state: ProgressState, to defaults: UserDefaults) {
        defaults.set(schemaVersion, forKey: schemaKey)
        defaults.set(Array(state.completed), forKey: completedKey)
        defaults.set(Array(state.skipped), forKey: skippedKey)
        defaults.set(Array(state.ignored), forKey: ignoredKey)
        defaults.set(Array(state.deletion), forKey: deletionKey)
        // [recKey: [progressKey, oldHash, newHash, source]] — plist-native, hashes only.
        defaults.set(state.saveRecords.mapValues { [$0.progressKey, $0.oldHash, $0.newHash, $0.source] },
                     forKey: saveRecordsKey)
        defaults.set(state.usernameOverrides, forKey: usernameOverridesKey)
    }

    /// Load the persisted state. A FUTURE schema version (a newer build wrote these,
    /// or the plist was tampered) yields an EMPTY, rebuildable state rather than a
    /// misread one. `recordKey` rebuilds a record key from (progressKey, source) for
    /// the legacy 3-element value format.
    static func load(from defaults: UserDefaults,
                     recordKey: (_ progressKey: String, _ source: String) -> String) -> ProgressState {
        let storedVersion = (defaults.object(forKey: schemaKey) as? Int) ?? schemaVersion
        guard storedVersion <= schemaVersion else {
            FileHandle.standardError.write(Data("ReKey: persisted progress is schema v\(storedVersion); this build understands v\(schemaVersion). Not loading it.\n".utf8))
            return ProgressState()
        }

        var state = ProgressState()
        state.completed = Set(defaults.stringArray(forKey: completedKey) ?? [])
        state.skipped = Set(defaults.stringArray(forKey: skippedKey) ?? [])
        state.ignored = Set(defaults.stringArray(forKey: ignoredKey) ?? [])
        state.deletion = Set(defaults.stringArray(forKey: deletionKey) ?? [])

        let raw = defaults.dictionary(forKey: saveRecordsKey) as? [String: [String]] ?? [:]
        for (storedKey, v) in raw {
            if v.count == 4 {                       // current: key is recKey, value carries progressKey
                state.saveRecords[storedKey] = FixSaveRecord(progressKey: v[0], oldHash: v[1], newHash: v[2], source: v[3])
            } else if v.count == 3 {                // legacy: key WAS the progressKey, value [old,new,source]
                state.saveRecords[recordKey(storedKey, v[2])] =
                    FixSaveRecord(progressKey: storedKey, oldHash: v[0], newHash: v[1], source: v[2])
            }
        }
        state.usernameOverrides = defaults.dictionary(forKey: usernameOverridesKey) as? [String: String] ?? [:]
        return state
    }
}
