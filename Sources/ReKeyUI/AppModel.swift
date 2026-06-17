import Foundation
import Security
import Observation
import AppKit
import Model
import ImportKit
import AuditEngine
import HIBPClient
import PasswordGenerator
import ResetRouter
import FixQueue

/// One imported CSV file and what came of it.
public struct ImportedFile: Identifiable, Sendable {
    public let id = UUID()
    /// Source URL on disk, if it came from the file picker (nil for in-memory).
    public let url: URL?
    public let displayName: String
    public let result: ImportResult
    public var sourceDeleted: Bool = false
}

/// A site that a one-line `--site` delete can't safely clean: the entry the user
/// fixed has no username to target and the site has other saved logins that the
/// delete would also remove. Surfaced so the cleanup script can give id-based
/// instructions instead.
public struct ManualCleanupSite: Sendable {
    public let domain: String
    public let browser: BrowserSource
    public let loginCount: Int
}

/// The fixed-login cleanup split into commands safe to run and sites needing
/// manual, id-based removal.
public struct FixedCleanupPlan: Sendable {
    public var safeCommands: [String]
    public var manualSites: [ManualCleanupSite]
}

/// Hashes captured when a fix is marked done, so a later re-import can tell
/// whether the change actually saved — only hashes are kept, never a password,
/// matching the rest of the persisted progress.
private struct FixSaveRecord: Sendable {
    let progressKey: String
    let oldHash: String
    let newHash: String
    let source: String
}

/// App-wide coordinator. Owns imports, the audit, and the fix queue, and wires
/// the concrete networking clients (HIBP, reset router) to the engines.
///
/// `@Observable` from the Observation framework — no SwiftUI import here, so the
/// model stays in the logic layer and the views merely render it.
@MainActor
@Observable
public final class AppModel {
    public enum Section: String, CaseIterable, Identifiable, Sendable {
        case importing = "Import"
        case findings = "Findings"
        case fixing = "Fix Queue"
        case cull = "Cull"
        case cleanup = "Clean Up"
        case settings = "Settings"
        public var id: String { rawValue }
        public var systemImage: String {
            switch self {
            case .importing: return "square.and.arrow.down"
            case .findings: return "list.bullet.rectangle"
            case .fixing: return "checkmark.shield"
            case .cull: return "trash"
            case .cleanup: return "trash.slash"
            case .settings: return "gearshape"
            }
        }
    }

    public var section: Section = .importing
    public private(set) var files: [ImportedFile] = []
    public private(set) var report: AuditReport?
    public var isAuditing = false
    public var auditError: String?

    /// Live progress of the running audit (nil when not auditing). Private so the
    /// AuditEngine type doesn't leak into the views — they read the derived
    /// `auditStatusText` / `auditFraction` instead.
    private var auditProgress: AuditProgress?

    /// Human-readable status line for the current audit phase, or nil when idle.
    public var auditStatusText: String? {
        guard isAuditing else { return nil }
        switch auditProgress?.phase {
        case .none, .analyzing:
            return "Analyzing reuse and duplicates…"
        case let .checkingCompromise(done, total):
            guard total > 0 else { return "Checking passwords against Have I Been Pwned…" }
            return "Checking passwords against Have I Been Pwned — \(done.formatted()) of \(total.formatted()) distinct passwords"
        case .finalizing:
            return "Finalizing report…"
        }
    }

    /// Determinate progress in 0...1 for the compromised-check phase, or nil when
    /// progress is indeterminate (analysis/finalizing, or nothing to fetch).
    public var auditFraction: Double? {
        guard case let .checkingCompromise(done, total)? = auditProgress?.phase, total > 0 else {
            return nil
        }
        return min(1, Double(done) / Double(total))
    }

    /// Which Chromium-based browser the next imported Chromium file is from. The
    /// CSV can't tell Chrome/Arc/Brave/Edge/Opera/Vivaldi apart, so the user
    /// picks. Ignored for Firefox and Apple Passwords files.
    public var chromiumSource: BrowserSource = .chrome

    // MARK: Auto-import (folder watch)
    /// Folder being watched for freshly-exported CSVs (nil = not watching).
    public private(set) var watchedFolder: URL?
    /// Last auto-import status line for the UI.
    public private(set) var autoImportMessage: String?

    private let folderWatcher = FolderWatcher()
    /// Guards scanWatchedFolder against re-entry from overlapping watch events.
    private var isScanning = false
    private var watchStart = Date.distantPast
    private var seenSignatures: Set<String> = []
    /// Import files modified within this grace window before watching started, so
    /// an export finished moments earlier is still picked up.
    private let importGraceSeconds: TimeInterval = 300
    private let bookmarkKey = "rekey.watchedFolderBookmark"
    /// The folder's plain path, kept separately from the security-scoped bookmark.
    /// Survives a bookmark that can't be resolved (e.g. the app was re-signed), so
    /// the UI can offer a pre-pointed one-click "re-watch" instead of a from-scratch
    /// pick. Cleared only when the user explicitly stops watching.
    private let watchPathKey = "rekey.watchedFolderPath"
    /// A previously-watched folder we no longer hold access to (the bookmark failed
    /// to resolve), surfaced as a one-click re-watch. nil while actively watching.
    public var rememberedWatchFolder: URL? {
        guard watchedFolder == nil,
              let path = UserDefaults.standard.string(forKey: watchPathKey) else { return nil }
        return URL(fileURLWithPath: path, isDirectory: true)
    }
    /// The bookmark-restored folder for which we hold a security scope (nil for
    /// picker-granted folders, which don't need an explicit scope).
    private var scopedURL: URL?

    public let fixQueue: FixQueue

    // MARK: Fix progress (persisted across launches — site+username keys only, NO passwords)
    public private(set) var completedKeys: Set<String> = []
    public private(set) var skippedKeys: Set<String> = []
    /// Findings the user has reviewed and chosen to ignore (accepted risk). Keyed
    /// by site+username like the others — no passwords. Ignored findings drop out
    /// of the active list and don't count toward fix progress.
    public private(set) var ignoredKeys: Set<String> = []
    /// Logins the user has flagged to delete outright (not fix). Keyed
    /// per-BROWSER (account + source), because deletion targets one browser's
    /// saved copy — deleting the Chrome login must not touch the Arc one. No
    /// passwords; feeds the `rekey-cleanup` deletion script. Persisted, and never
    /// auto-pruned: a mark for a login absent from the current import is harmless
    /// (both `markedForDeletionCount` and the plan filter to present credentials)
    /// and simply re-applies if that login is imported again.
    public private(set) var deletionKeys: Set<String> = []
    private let completedDefaultsKey = "rekey.completedKeys"
    private let skippedDefaultsKey = "rekey.skippedKeys"
    private let ignoredDefaultsKey = "rekey.ignoredKeys"
    private let saveRecordsDefaultsKey = "rekey.fixSaveRecords"
    private let usernameOverridesDefaultsKey = "rekey.usernameOverrides"
    private let deletionDefaultsKey = "rekey.deletionKeys"

    /// Old/new password hashes per fixed account (progressKey), so a later import
    /// can verify the change saved. Hashes only — no passwords. Persisted.
    /// Note: unsalted SHA-256, so a weak/known password is in principle
    /// offline-guessable from the hash. Accepted: this host already holds the
    /// plaintext store ReKey imported, and the hash is only an equality token —
    /// never the password — so it leaks nothing the host doesn't already have.
    private var fixSaveRecords: [String: FixSaveRecord] = [:]
    /// Usernames the user types for blank-username logins (a recognition label —
    /// the browser saved the login without a username). Keyed by source|site,
    /// persisted. DISPLAY ONLY: it never flows into the fix or the cleanup, which
    /// must match the browser's actual stored (blank) username.
    ///
    /// Privacy: these labels (often an email) persist in cleartext in UserDefaults
    /// — the one user-entered value ReKey stores in the clear. Accepted: it's the
    /// user's own email for an account whose plaintext store this host already
    /// holds, it's never a password, and labels surviving a re-import is the
    /// feature's whole point.
    private var usernameOverrides: [String: String] = [:]
    /// Save-verification keys (progressKey + source) whose most recent re-import of
    /// that source still shows the OLD password (not the new) — the change likely
    /// didn't save. Derived on import; not persisted.
    public private(set) var unsavedFixKeys: Set<String> = []

    /// Composite key for a save record / unsaved flag: account + source, so the
    /// same account fixed in two browsers is tracked separately.
    private static func saveRecordKey(_ progressKey: String, _ sourceRaw: String) -> String {
        "\(progressKey)\u{1}\(sourceRaw)"
    }

    /// Browser-independent identity for "this account is fixed" — changing the
    /// password on the site resolves it regardless of which browser saved it.
    ///
    /// Known limitation: two genuinely different *blank-username* logins on the
    /// same registrable domain collapse to one key ("domain|"), so fixing or
    /// ignoring one marks both. This is accepted: a usernameless login carries no
    /// stable identity that survives a password change (the password itself is the
    /// only differentiator, and it changes on fix), so there's nothing reliable to
    /// distinguish them by. Rare in practice (two anonymous accounts on one site).
    public static func progressKey(for credential: ImportedCredential) -> String {
        "\(credential.registrableDomain)|\(credential.username)"
    }
    public func isFixed(_ credential: ImportedCredential) -> Bool {
        completedKeys.contains(Self.progressKey(for: credential))
    }

    /// Whether the user has ignored this account's finding.
    public func isIgnored(_ credential: ImportedCredential) -> Bool {
        ignoredKeys.contains(Self.progressKey(for: credential))
    }

    /// Ignore an account's finding (accepted risk). Reversible via `unignoreFinding`.
    public func ignoreFinding(for credential: ImportedCredential) {
        ignoredKeys.insert(Self.progressKey(for: credential))
        saveProgress()
    }

    /// Un-ignore: bring the finding back into the active list.
    public func unignoreFinding(for credential: ImportedCredential) {
        ignoredKeys.remove(Self.progressKey(for: credential))
        saveProgress()
    }

    // MARK: - Mark for deletion (cull)

    /// Per-(account, browser) key for "delete this login". Unlike fix/ignore
    /// (browser-independent), a deletion targets one browser's stored copy, so
    /// the same account in two browsers is marked independently. It still inherits
    /// `progressKey`'s blank-username limitation: two usernameless logins on the
    /// same domain in the SAME browser collapse to one key (see `progressKey`).
    public static func deletionKey(for credential: ImportedCredential) -> String {
        saveRecordKey(progressKey(for: credential), credential.source.rawValue)
    }

    public func isMarkedForDeletion(_ credential: ImportedCredential) -> Bool {
        deletionKeys.contains(Self.deletionKey(for: credential))
    }

    /// Flag a login for outright deletion (added to the cull cleanup script).
    public func markForDeletion(_ credential: ImportedCredential) {
        deletionKeys.insert(Self.deletionKey(for: credential))
        saveProgress()
    }

    public func unmarkForDeletion(_ credential: ImportedCredential) {
        deletionKeys.remove(Self.deletionKey(for: credential))
        saveProgress()
    }

    /// Bulk-mark (e.g. "mark all shown") — one save, not one per login.
    public func markForDeletion(_ credentials: [ImportedCredential]) {
        guard !credentials.isEmpty else { return }
        for c in credentials { deletionKeys.insert(Self.deletionKey(for: c)) }
        saveProgress()
    }

    /// Clear every deletion mark.
    public func unmarkAllForDeletion() {
        guard !deletionKeys.isEmpty else { return }
        deletionKeys.removeAll()
        saveProgress()
    }

    /// Marked logins present in the current import (the ones the script can act on).
    public var markedForDeletionCount: Int {
        allCredentials.lazy.filter { self.isMarkedForDeletion($0) }.count
    }

    /// (fixed, total) over flagged credentials, deduped by site+username. Ignored
    /// findings are excluded from both counts — they're not part of the work.
    public var fixProgress: (done: Int, total: Int) {
        guard let report else { return (0, 0) }
        var flagged = Set<String>()
        for cred in allCredentials
        where (report.findingsByCredential[cred.id] != nil || report.weak.contains(cred.id)) && !isIgnored(cred) {
            flagged.insert(Self.progressKey(for: cred))
        }
        return (flagged.intersection(completedKeys).count, flagged.count)
    }

    // MARK: Change-page browser preference
    /// A browser the user can route change pages to. `appURL == nil` is the
    /// "system default" option.
    public struct BrowserChoice: Identifiable, Hashable, Sendable {
        public let id: String        // "" for default, else the app path
        public let name: String
        public let appURL: URL?
    }

    /// "Default browser" plus every installed browser, for the picker.
    public let availableBrowsers: [BrowserChoice]
    /// The currently selected browser's id ("" = system default).
    public private(set) var selectedBrowserID: String = ""

    private let browserOpener: BrowserOpener
    private let browserPrefKey = "rekey.changePageBrowserPath"

    private let importer = CSVImporter()
    private let hibp = HIBPClient()

    public init() {
        let opener = BrowserOpener()
        self.browserOpener = opener
        self.availableBrowsers = Self.discoverBrowsers()

        // bestEffort, not try!: the diceware wordlist is bundled, so it only fails
        // to load if the app bundle is corrupt — but that must not crash the app at
        // launch. Character-based generation still works; only passphrases degrade.
        let generator = PasswordGenerator.bestEffort()
        self.fixQueue = FixQueue(
            generator: generator,
            router: ResetRouter(),
            clipboard: Clipboard(),
            opener: opener
        )
        loadBrowserPreference()
        loadProgress()
        restoreWatchedFolder()
    }

    // MARK: - Fix progress persistence

    /// Mark a fix done — advances the queue item and records it persistently.
    public func recordFixDone(_ item: FixItem) {
        fixQueue.markDone(itemID: item.id)
        guard let cred = credential(item.credentialID) else { return }
        let key = Self.progressKey(for: cred)
        completedKeys.insert(key)
        skippedKeys.remove(key)
        // Remember the old and new password hashes (not the passwords) so the next
        // re-import of this source can confirm the change actually saved. Don't
        // evaluate now: the current import predates the fix and still shows the old
        // password — it's checked when the source is next re-imported.
        // Keyed by account AND source, so the same account fixed in two browsers
        // verifies each independently instead of the later fix overwriting the first.
        let recKey = Self.saveRecordKey(key, cred.source.rawValue)
        fixSaveRecords[recKey] = FixSaveRecord(
            progressKey: key,
            oldHash: cred.password.sha256().base64EncodedString(),
            newHash: item.newPassword.sha256().base64EncodedString(),
            source: cred.source.rawValue
        )
        unsavedFixKeys.remove(recKey)
        saveProgress()
    }

    /// Skip a fix — advances the queue item and records it persistently.
    public func recordFixSkipped(_ item: FixItem) {
        fixQueue.skip(itemID: item.id)
        guard let cred = credential(item.credentialID) else { return }
        skippedKeys.insert(Self.progressKey(for: cred))
        saveProgress()
    }

    /// Un-mark a credential as fixed — for when the change didn't actually take
    /// (e.g. the new password never got saved to the browser). Clears the
    /// persisted completed key so the finding returns to the active list with an
    /// "Add to queue" action. Does not touch any saved password.
    public func unmarkFixed(for credential: ImportedCredential) {
        let key = Self.progressKey(for: credential)
        completedKeys.remove(key)
        // Drop this account's save records / flags across every source.
        for recKey in fixSaveRecords.filter({ $0.value.progressKey == key }).map(\.key) {
            fixSaveRecords.removeValue(forKey: recKey)
            unsavedFixKeys.remove(recKey)
        }
        saveProgress()
    }

    /// Whether this credential's account-in-this-browser still shows the OLD
    /// password after a fix — the change may not have saved. Surfaced as a warning
    /// (with Reopen) in Findings.
    public func fixMaySaveFailed(_ credential: ImportedCredential) -> Bool {
        unsavedFixKeys.contains(Self.saveRecordKey(Self.progressKey(for: credential), credential.source.rawValue))
    }

    /// How many distinct accounts present in the current import look maybe-unsaved —
    /// for the Findings banner.
    public var unsavedFixCount: Int {
        guard !unsavedFixKeys.isEmpty else { return 0 }
        var accounts = Set<String>()
        for cred in allCredentials where fixMaySaveFailed(cred) {
            accounts.insert(Self.progressKey(for: cred))
        }
        return accounts.count
    }

    private static func usernameOverrideKey(for cred: ImportedCredential) -> String {
        "\(cred.source.rawValue)|\(cred.site)"
    }

    /// The username to SHOW for a credential: its real one, or — for a
    /// blank-username login — a label the user typed (the email the browser didn't
    /// save). For display only; the fix/cleanup use the real (blank) username.
    public func effectiveUsername(for cred: ImportedCredential) -> String {
        if !cred.username.isEmpty { return cred.username }
        return usernameOverrides[Self.usernameOverrideKey(for: cred)] ?? ""
    }

    /// Record (or clear, when blank) the username the user supplies for a
    /// blank-username login. No-op on a login that already has one.
    public func setUsername(_ username: String, for cred: ImportedCredential) {
        guard cred.username.isEmpty else { return }
        let key = Self.usernameOverrideKey(for: cred)
        let trimmed = username.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { usernameOverrides.removeValue(forKey: key) }
        else { usernameOverrides[key] = trimmed }
        saveProgress()
    }

    private func saveProgress() {
        UserDefaults.standard.set(Array(completedKeys), forKey: completedDefaultsKey)
        UserDefaults.standard.set(Array(skippedKeys), forKey: skippedDefaultsKey)
        UserDefaults.standard.set(Array(ignoredKeys), forKey: ignoredDefaultsKey)
        UserDefaults.standard.set(Array(deletionKeys), forKey: deletionDefaultsKey)
        // [recKey: [progressKey, oldHash, newHash, source]] — plist-native, hashes only.
        UserDefaults.standard.set(fixSaveRecords.mapValues { [$0.progressKey, $0.oldHash, $0.newHash, $0.source] },
                                  forKey: saveRecordsDefaultsKey)
        UserDefaults.standard.set(usernameOverrides, forKey: usernameOverridesDefaultsKey)
    }

    private func loadProgress() {
        completedKeys = Set(UserDefaults.standard.stringArray(forKey: completedDefaultsKey) ?? [])
        skippedKeys = Set(UserDefaults.standard.stringArray(forKey: skippedDefaultsKey) ?? [])
        ignoredKeys = Set(UserDefaults.standard.stringArray(forKey: ignoredDefaultsKey) ?? [])
        deletionKeys = Set(UserDefaults.standard.stringArray(forKey: deletionDefaultsKey) ?? [])
        let raw = UserDefaults.standard.dictionary(forKey: saveRecordsDefaultsKey) as? [String: [String]] ?? [:]
        fixSaveRecords = [:]
        for (storedKey, v) in raw {
            if v.count == 4 {                       // current: key is recKey, value carries progressKey
                fixSaveRecords[storedKey] = FixSaveRecord(progressKey: v[0], oldHash: v[1], newHash: v[2], source: v[3])
            } else if v.count == 3 {                // legacy: key WAS the progressKey, value [old,new,source]
                let recKey = Self.saveRecordKey(storedKey, v[2])
                fixSaveRecords[recKey] = FixSaveRecord(progressKey: storedKey, oldHash: v[0], newHash: v[1], source: v[2])
            }
        }
        usernameOverrides = UserDefaults.standard.dictionary(forKey: usernameOverridesDefaultsKey) as? [String: String] ?? [:]
    }

    // MARK: - Change-page browser

    private static func discoverBrowsers() -> [BrowserChoice] {
        var choices = [BrowserChoice(id: "", name: "Default browser", appURL: nil)]
        if let sample = URL(string: "https://example.com") {
            let installed = NSWorkspace.shared.urlsForApplications(toOpen: sample)
                .map { BrowserChoice(id: $0.path, name: $0.deletingPathExtension().lastPathComponent, appURL: $0) }
                .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
            choices.append(contentsOf: installed)
        }
        return choices
    }

    /// Choose which browser change pages open in, persisting the choice. Picking
    /// a browser that isn't in `availableBrowsers` is ignored.
    public func selectBrowser(id: String) {
        guard let choice = availableBrowsers.first(where: { $0.id == id }) else { return }
        selectedBrowserID = choice.id
        browserOpener.targetAppURL = choice.appURL
        if choice.appURL == nil {
            UserDefaults.standard.removeObject(forKey: browserPrefKey)
        } else {
            UserDefaults.standard.set(choice.id, forKey: browserPrefKey)
        }
    }

    private func loadBrowserPreference() {
        let stored = UserDefaults.standard.string(forKey: browserPrefKey) ?? ""
        // Only honor it if that browser is still installed; otherwise fall back.
        if !stored.isEmpty, let choice = availableBrowsers.first(where: { $0.id == stored }) {
            selectedBrowserID = choice.id
            browserOpener.targetAppURL = choice.appURL
        } else {
            selectedBrowserID = ""
            browserOpener.targetAppURL = nil
        }
    }

    // MARK: - Derived

    /// All valid imported credentials, cached (rebuilt only when `files` changes)
    /// so the audit, the fix queue, and per-row lookups don't re-flatten on every
    /// access.
    public private(set) var allCredentials: [ImportedCredential] = []
    private var credentialIndex: [UUID: ImportedCredential] = [:]

    public var totalSkipped: Int {
        files.reduce(0) { $0 + $1.result.skipped.count }
    }

    /// O(1) lookup by id.
    public func credential(_ id: UUID) -> ImportedCredential? {
        credentialIndex[id]
    }

    /// Whether this credential's account is saved in both an Apple and a
    /// non-Apple store (a cross-ecosystem duplicate from the last audit) — copies
    /// that don't sync to each other, notably on iPhone/iPad.
    public func isCrossEcosystem(_ credentialID: UUID) -> Bool {
        report?.crossEcosystemDuplicates.contains(credentialID) ?? false
    }

    /// The other browser stores this same account is also saved in (besides its
    /// own) — copies that don't sync. Empty unless it's in 2+ browsers.
    public func otherBrowsers(for cred: ImportedCredential) -> [BrowserSource] {
        (report?.multiBrowserAccounts[cred.id] ?? []).filter { $0 != cred.source }
    }

    private func reindexCredentials() {
        // Collapse exact duplicates: the same (browser, site, username, password)
        // exported as multiple rows — e.g. one Arc login associated with two
        // subdomains becomes two identical CSV rows. Keep the first occurrence.
        var seen = Set<String>()
        var deduped: [ImportedCredential] = []
        for c in files.flatMap(\.result.credentials) {
            let key = [c.source.rawValue, c.registrableDomain, c.username, c.password.sha256().base64EncodedString()]
                .joined(separator: "\u{1}")
            if seen.insert(key).inserted { deduped.append(c) }
        }
        allCredentials = deduped
        credentialIndex = Dictionary(allCredentials.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
    }

    /// After importing `source`, re-check that source's fixed accounts against the
    /// freshly imported passwords. The strong signal is the negative: the account
    /// still hashes to the OLD password and the new one is nowhere in this source —
    /// the change likely didn't save. A site can mangle a generated password, so
    /// "new isn't present" alone never triggers; "still old" does. Only this
    /// source's records are touched, so importing a *different* browser can't
    /// false-flag fixes whose store wasn't re-exported.
    private func verifyFixes(against source: BrowserSource) {
        for (recKey, record) in fixSaveRecords where record.source == source.rawValue {
            let hashes = Set(
                allCredentials
                    .filter { $0.source == source && Self.progressKey(for: $0) == record.progressKey }
                    .map { $0.password.sha256().base64EncodedString() }
            )
            let key = recKey
            if hashes.isEmpty || hashes.contains(record.newHash) {
                unsavedFixKeys.remove(key)        // not in this import, or new password saved
            } else if hashes.contains(record.oldHash) {
                unsavedFixKeys.insert(key)        // only the old password remains — likely didn't save
            } else {
                unsavedFixKeys.remove(key)        // changed to something else (out-of-band) — neutral
            }
        }
    }

    // MARK: - Import

    /// Import a file selected via the file picker (security-scoped URL).
    public func importFile(at url: URL) {
        let didScope = url.startAccessingSecurityScopedResource()
        defer { if didScope { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url) else {
            auditError = "Couldn't read “\(url.lastPathComponent)” — the file may have moved or be unreadable."
            return
        }
        ingest(data: data, url: url, displayName: url.lastPathComponent)
    }

    /// Surface a file-picker failure (e.g. a permissions error) — set by the view.
    public func reportImportError(_ message: String) {
        auditError = message
    }

    /// Import raw CSV bytes (e.g. drag-and-drop), without a source file on disk.
    public func importData(_ data: Data, displayName: String) {
        ingest(data: data, url: nil, displayName: displayName)
    }

    private func ingest(data: Data, url: URL?, displayName: String) {
        do {
            let result = try importer.import(data: data, chromiumSource: chromiumSource)
            files.append(ImportedFile(url: url, displayName: displayName, result: result))
            reindexCredentials()
            verifyFixes(against: result.source)
            // A fresh import invalidates the previous audit.
            report = nil
            auditError = nil                 // a good import clears any prior error
        } catch {
            auditError = "Couldn't import “\(displayName)”: \(error.localizedDescription). Make sure it's an unmodified password CSV exported from a browser or Apple Passwords."
        }
    }

    public func removeFile(_ file: ImportedFile) {
        files.removeAll { $0.id == file.id }
        reindexCredentials()
        report = nil
    }

    /// Best-effort secure delete of a source CSV: overwrite the bytes with random
    /// data, then unlink. A plaintext password CSV in ~/Downloads is the single
    /// biggest real-world risk, so this is a first-class step.
    @discardableResult
    public func securelyDeleteSource(of file: ImportedFile) -> Bool {
        guard let url = file.url else { return false }
        let ok = Self.secureDelete(url)
        if ok, let i = files.firstIndex(where: { $0.id == file.id }) {
            files[i].sourceDeleted = true
        }
        return ok
    }

    static func secureDelete(_ url: URL) -> Bool {
        let fm = FileManager.default
        let size = ((try? fm.attributesOfItem(atPath: url.path))?[.size] as? Int) ?? 0

        // Overwrite the bytes before unlinking. If the overwrite fails, report
        // failure honestly — otherwise we'd tell the user a plaintext password
        // file was wiped when only the directory entry was removed.
        if size > 0 {
            do {
                let handle = try FileHandle(forWritingTo: url)
                defer { try? handle.close() }
                try handle.seek(toOffset: 0)
                var remaining = size
                let chunk = 64 * 1024
                while remaining > 0 {
                    let n = min(chunk, remaining)
                    var bytes = [UInt8](repeating: 0, count: n)
                    // CSPRNG for consistency; even zeros would suffice for a wipe.
                    if SecRandomCopyBytes(kSecRandomDefault, n, &bytes) != errSecSuccess {
                        bytes = [UInt8](repeating: 0, count: n)
                    }
                    try handle.write(contentsOf: Data(bytes))
                    remaining -= n
                }
                try handle.synchronize()
            } catch {
                return false
            }
        }
        do { try fm.removeItem(at: url); return true } catch { return false }
    }

    // MARK: - Auto-import (folder watch)

    /// Prompt for a folder to watch for exported CSVs.
    public func chooseWatchFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Watch"
        panel.message = "Choose a folder to watch for exported password CSVs (e.g. Downloads). ReKey auto-imports recognized exports as they appear."
        // Pre-point at a previously-watched folder so re-granting access is one click.
        if let remembered = rememberedWatchFolder { panel.directoryURL = remembered }
        if panel.runModal() == .OK, let url = panel.url {
            startWatching(url)
        }
    }

    public func startWatching(_ url: URL) {
        // Release any previously bookmark-scoped folder before switching.
        releaseScopedAccess()
        watchedFolder = url
        watchStart = Date()
        seenSignatures = []
        autoImportMessage = nil
        folderWatcher.onChange = { [weak self] in self?.scanWatchedFolder() }
        folderWatcher.start(url: url)
        saveBookmark(url)
        UserDefaults.standard.set(url.path, forKey: watchPathKey)   // remembered for one-click re-watch
        scanWatchedFolder()   // catch an export that just finished
    }

    public func stopWatching() {
        folderWatcher.stop()
        releaseScopedAccess()
        watchedFolder = nil
        autoImportMessage = nil
        UserDefaults.standard.removeObject(forKey: bookmarkKey)
        UserDefaults.standard.removeObject(forKey: watchPathKey)   // explicit stop → forget it
    }

    /// Balance any `startAccessingSecurityScopedResource()` started for a restored
    /// bookmark. Picker-granted folders aren't scoped, so only the bookmark URL is
    /// tracked here.
    private func releaseScopedAccess() {
        if let scoped = scopedURL {
            scoped.stopAccessingSecurityScopedResource()
            scopedURL = nil
        }
    }

    private func scanWatchedFolder() {
        guard let dir = watchedFolder else { return }
        // Reentrancy guard: the vnode source and the poll timer can both fire
        // onChange. The scan is synchronous on the main actor today (so it can't
        // truly re-enter), but guard anyway so a future async import path can't
        // double-process the same export.
        guard !isScanning else { return }
        isScanning = true
        defer { isScanning = false }
        let threshold = watchStart.addingTimeInterval(-importGraceSeconds)
        for entry in FolderScan.freshCSVs(in: dir, since: threshold, seen: seenSignatures) {
            seenSignatures.insert(entry.signature)
            autoImport(entry.url)
        }
    }

    private func autoImport(_ url: URL) {
        // Skip anything already imported, and anything that isn't a recognized
        // password export (so a random CSV in the folder is left alone).
        if files.contains(where: { $0.url?.path == url.path }) { return }
        guard let data = try? Data(contentsOf: url),
              let table = try? CSVParser.parse(data),
              FormatDetector.detect(headers: table.headers) != .unknown else { return }
        ingest(data: data, url: url, displayName: url.lastPathComponent)
        let count = files.last?.result.credentials.count ?? 0
        autoImportMessage = "Auto-imported \(url.lastPathComponent) — \(count) credential(s). Remember to securely delete it below."
    }

    // MARK: Security-scoped bookmark persistence

    private func saveBookmark(_ url: URL) {
        if let data = try? url.bookmarkData(options: .withSecurityScope) {
            UserDefaults.standard.set(data, forKey: bookmarkKey)
        }
    }

    private func restoreWatchedFolder() {
        guard let data = UserDefaults.standard.data(forKey: bookmarkKey) else { return }
        var stale = false
        guard let url = try? URL(resolvingBookmarkData: data, options: .withSecurityScope,
                                 relativeTo: nil, bookmarkDataIsStale: &stale),
              url.startAccessingSecurityScopedResource() else {
            UserDefaults.standard.removeObject(forKey: bookmarkKey)
            return
        }
        startWatching(url)      // releaseScopedAccess() at top releases any prior
        scopedURL = url         // we now own the scope for this bookmark URL
    }

    // MARK: - Audit

    /// Run reuse/duplicate analysis and the HIBP compromised check. This is the
    /// only credential-touching network call (k-anonymity: only 5-char SHA-1
    /// prefixes leave the device).
    public func runAudit() async {
        guard !allCredentials.isEmpty else { return }
        isAuditing = true
        auditError = nil
        auditProgress = nil
        defer { isAuditing = false; auditProgress = nil }

        // Progress arrives from background threads (the HIBP actor and the
        // coordinator). Funnel it through an AsyncStream so updates land on the
        // main actor in order; `.bufferingNewest(1)` coalesces bursts to the
        // latest value so a flood of ticks can't outrun the UI.
        let (stream, continuation) = AsyncStream.makeStream(
            of: AuditProgress.self,
            bufferingPolicy: .bufferingNewest(1)
        )
        let consumer = Task { @MainActor in
            for await progress in stream { self.auditProgress = progress }
        }

        let coordinator = AuditCoordinator(compromiseChecker: hibp)
        let report = await coordinator.audit(credentials: allCredentials) { progress in
            continuation.yield(progress)
        }
        continuation.finish()
        await consumer.value

        self.report = report
        self.section = .findings
    }

    // MARK: - Fix queue bridge

    public func enqueueFix(for credential: ImportedCredential) async {
        let g = currentGenerationChoice()
        _ = try? await fixQueue.enqueue(credential: credential,
                                        policy: g.passphrase ? nil : g.policy,
                                        passphrase: g.passphrase)
    }

    /// The user's saved new-password defaults (type / length / look-alikes), as a
    /// generation choice the fix queue can apply when it creates the item — so the
    /// replacement is generated once, up front, with the right policy.
    private func currentGenerationChoice() -> (passphrase: Bool, policy: PasswordPolicy) {
        let prefs = Prefs.currentGeneration()
        return Prefs.generation(style: prefs.style, length: prefs.length, avoidLookAlikes: prefs.avoidLookAlikes)
    }

    // MARK: - Aggregated cleanup script (across all fixed logins)

    /// One deduped `rekey-cleanup delete` command per login the user has marked
    /// **done** in the fix queue, across every browser — the basis for a single
    /// script that removes all the stale old saved logins at once.
    ///
    /// Sources the tool can't clean (e.g. Apple Passwords) are skipped. Firefox
    /// commands are site-level because its usernames are encrypted, so several
    /// fixed Firefox logins on one site collapse to a single command.
    public func fixedCleanupPlan() -> FixedCleanupPlan {
        Self.cleanupPlan(forDone: fixQueue.items, source: { credential($0)?.source ?? .unknown }) { source, domain in
            allCredentials.filter { $0.source == source && $0.site == domain }.count
        }
    }

    /// Safe-to-run delete commands for everything fixed (no `--confirm`).
    public func fixedCleanupRunnableCommands() -> [String] { fixedCleanupPlan().safeCommands }

    /// How many sites need manual id-based cleanup (site-level delete would hit
    /// siblings) — for the UI warning.
    public func fixedCleanupManualSiteCount() -> Int { fixedCleanupPlan().manualSites.count }

    /// The full cleanup script: safe commands plus, for any site a `--site` delete
    /// can't safely target, commented `list` → `delete --id` instructions instead
    /// of a delete that would remove siblings.
    public func fixedCleanupScript(confirm: Bool) -> String {
        let plan = fixedCleanupPlan()
        guard !plan.safeCommands.isEmpty || !plan.manualSites.isEmpty else { return "" }
        var lines = plan.safeCommands.map { confirm ? $0 + " --confirm" : $0 }
        if !plan.manualSites.isEmpty {
            lines.append("")
            lines.append("# ⚠︎ Manual cleanup — the entry you fixed here has no username and the site has")
            lines.append("#    other saved logins, so a --site delete would remove them too. Delete just the")
            lines.append("#    stray entry by id:")
            for site in plan.manualSites {
                let cli = site.browser.cleanupCLIName ?? site.browser.rawValue
                lines.append("#    \(site.domain) (\(site.browser.displayName), \(site.loginCount) logins):")
                lines.append("#      rekey-cleanup list --browser \(cli) --site \(site.domain.shellArgument)")
                lines.append("#      rekey-cleanup delete --browser \(cli) --id <id-of-the-blank-username-row> --confirm")
            }
        }
        return CleanupPlanner.script(lines: lines, confirm: confirm)
    }

    /// One (source, site, username) the cleanup script should target. For a safe
    /// target, `username` is "" when the delete is site-level (Firefox — encrypted
    /// usernames — or a blank-username login).
    public struct CleanupTarget: Sendable {
        public let source: BrowserSource
        public let site: String
        public let username: String
    }

    /// Pure core (testable): partition targets into ones that delete cleanly and
    /// ones needing a manual id step — a site-level delete that would also remove
    /// logins NOT among the targets (`siblingCount` on a (browser, site) exceeds
    /// how many of its logins are targets). Safe targets are normalized (username
    /// dropped where the store can't filter by it, or where it's blank) and
    /// deduped, so each maps to exactly one delete.
    static func classifyCleanup(
        targets: [CleanupTarget],
        siblingCount: (BrowserSource, String) -> Int
    ) -> (safe: [CleanupTarget], manualSites: [ManualCleanupSite]) {
        var targetedPerSite: [String: Int] = [:]
        for t in targets where t.source.cleanupSupported {
            targetedPerSite["\(t.source.rawValue)|\(t.site)", default: 0] += 1
        }

        var safe: [CleanupTarget] = []; var seenSafe = Set<String>()
        var manual: [ManualCleanupSite] = []; var seenSite = Set<String>()
        for t in targets {
            guard t.source.cleanupSupported else { continue }   // Apple/unknown: tool can't delete
            // Only Chromium can target by username (Firefox usernames are encrypted).
            let user = (t.source.isChromiumFamily && !t.username.isEmpty) ? t.username : ""
            let key = "\(t.source.rawValue)|\(t.site)"
            if user.isEmpty, siblingCount(t.source, t.site) > (targetedPerSite[key] ?? 0) {
                if seenSite.insert(key).inserted {
                    manual.append(ManualCleanupSite(domain: t.site, browser: t.source,
                                                    loginCount: siblingCount(t.source, t.site)))
                }
            } else if seenSafe.insert("\(key)|\(user)").inserted {
                safe.append(CleanupTarget(source: t.source, site: t.site, username: user))
            }
        }
        return (safe, manual)
    }

    /// Cleanup plan as deduped `rekey-cleanup delete` command strings (the
    /// fix-queue stale-removal path keeps its one-command-per-site form).
    static func cleanupPlan(
        targets: [CleanupTarget],
        siblingCount: (BrowserSource, String) -> Int
    ) -> FixedCleanupPlan {
        let (safe, manual) = classifyCleanup(targets: targets, siblingCount: siblingCount)
        let commands = safe.compactMap {
            StaleLoginGuidance.cliCommand(for: $0.source, domain: $0.site, username: $0.username)
        }
        return FixedCleanupPlan(safeCommands: commands, manualSites: manual)
    }

    /// Cleanup plan for the logins marked **done** in the fix queue — removing
    /// the stale old saved entries after a re-key.
    static func cleanupPlan(
        forDone items: [FixItem],
        source: (UUID) -> BrowserSource,
        siblingCount: (BrowserSource, String) -> Int
    ) -> FixedCleanupPlan {
        let targets = items.filter { $0.status == .done }
            .map { CleanupTarget(source: source($0.credentialID), site: $0.site, username: $0.username) }
        return cleanupPlan(targets: targets, siblingCount: siblingCount)
    }

    // MARK: - Cull (mark-for-deletion) cleanup script

    /// Safe (browser, site, username) targets for the marked-for-deletion logins,
    /// plus sites needing a manual id step (deleting by site would catch logins
    /// you didn't mark). Sources the tool can't clean are dropped.
    public func deletionPlan() -> (safe: [CleanupTarget], manualSites: [ManualCleanupSite]) {
        let targets = allCredentials
            .filter { isMarkedForDeletion($0) }
            .map { Self.CleanupTarget(source: $0.source, site: $0.site, username: $0.username) }
        return Self.classifyCleanup(targets: targets) { source, domain in
            allCredentials.filter { $0.source == source && $0.site == domain }.count
        }
    }

    /// Marked sites needing manual, id-based deletion — for the UI warning.
    public func deletionManualSiteCount() -> Int { deletionPlan().manualSites.count }

    /// Of the manual sites, how many the tool can force-delete precisely: the
    /// no-username rows on a Chromium site (readable usernames). Firefox manual
    /// sites are excluded — their usernames are encrypted, so a blank one can't be
    /// told from a named one without the row id.
    public func deletionForceableManualSiteCount() -> Int {
        deletionPlan().manualSites.filter { $0.browser.isChromiumFamily }.count
    }

    /// The cull deletion script: one `rekey-cleanup purge` per browser — targets
    /// piped via stdin, deleting the marked logins outright (no lone-login guard)
    /// with a single per-browser summary line. With `forceManual`, Chromium
    /// no-username sites are force-deleted precisely (`purge --no-username`, which
    /// removes only the empty-username rows, never the named siblings); any
    /// remaining manual sites (Firefox) stay as commented `list` → `delete --id`
    /// steps. Empty when nothing is marked.
    public func deletionCleanupScript(confirm: Bool, forceManual: Bool = false) -> String {
        let (safe, manualSites) = deletionPlan()
        let forced = forceManual ? manualSites.filter { $0.browser.isChromiumFamily } : []
        let stillManual = forceManual ? manualSites.filter { !$0.browser.isChromiumFamily } : manualSites
        guard !safe.isEmpty || !forced.isEmpty || !stillManual.isEmpty else { return "" }

        var lines: [String] = []
        let needsTally = !safe.isEmpty || !forced.isEmpty
        if needsTally {
            lines.append("REKEY_TALLY=\"$(mktemp -t rekey-cull-tally)\"")
            lines.append("trap 'rm -f \"$REKEY_TALLY\"' EXIT")
            lines.append("")
        }
        lines += Self.purgeBlockLines(safe: safe, forced: forced, stillManual: stillManual,
                                      confirm: confirm, tallyVar: needsTally ? "REKEY_TALLY" : nil)
        if needsTally {
            // Grand total across every browser's purge (a blank line, then the sum).
            let verb = confirm ? "Deleted" : "Would delete"
            lines.append("awk '{d+=$1; s+=$2} END {printf \"\\n\(verb) %d login(s) across %d site(s).\\n\", d, s}' \"$REKEY_TALLY\"")
        }
        return CleanupPlanner.script(lines: lines, purpose: "remove the logins you marked for deletion.", confirm: confirm)
    }

    /// The purge command blocks alone — no shebang/header, no tally or grand total
    /// — for appending to an existing rekey-cleanup.sh. Each block prints its own
    /// per-browser summary; purge is idempotent, so a target already removed in an
    /// earlier block just reports "already gone". Empty when nothing is marked.
    public func deletionAppendableScript(confirm: Bool, forceManual: Bool = false) -> String {
        let (safe, manualSites) = deletionPlan()
        let forced = forceManual ? manualSites.filter { $0.browser.isChromiumFamily } : []
        let stillManual = forceManual ? manualSites.filter { !$0.browser.isChromiumFamily } : manualSites
        let lines = Self.purgeBlockLines(safe: safe, forced: forced, stillManual: stillManual,
                                         confirm: confirm, tallyVar: nil)
        return lines.isEmpty ? "" : lines.joined(separator: "\n")
    }

    /// Shared body builder: one `purge` heredoc per browser for the safe targets,
    /// then a `--no-username` block per browser for the forced sites, then any
    /// still-manual sites as commented `list` → `delete --id` steps. When
    /// `tallyVar` is set, each purge appends to `$<tallyVar>` for a grand total.
    private static func purgeBlockLines(
        safe: [CleanupTarget],
        forced: [ManualCleanupSite],
        stillManual: [ManualCleanupSite],
        confirm: Bool,
        tallyVar: String?
    ) -> [String] {
        let confirmFlag = confirm ? " --confirm" : ""
        let tally = tallyVar.map { " --tally \"$\($0)\"" } ?? ""
        var lines: [String] = []

        let byBrowser = Dictionary(grouping: safe, by: \.source)
        for browser in byBrowser.keys.sorted(by: { $0.displayName < $1.displayName }) {
            let cli = browser.cleanupCLIName ?? browser.rawValue
            let group = byBrowser[browser]!.sorted { $0.site < $1.site }
            lines.append("# \(browser.displayName) — \(group.count) site(s)")
            lines.append("rekey-cleanup purge --browser \(cli)\(confirmFlag)\(tally) <<'REKEY_TARGETS'")
            // Heredoc body is raw stdin (a quoted delimiter, so it's never
            // shell-evaluated) — site/username can't inject. Tab-separated;
            // username omitted when empty (site-level).
            for t in group {
                lines.append(t.username.isEmpty ? t.site : "\(t.site)\t\(t.username)")
            }
            lines.append("REKEY_TARGETS")
            lines.append("")
        }

        if !forced.isEmpty {
            // Force the no-username removals precisely: --no-username deletes only
            // the empty-username rows on each site, leaving the named siblings.
            let forcedByBrowser = Dictionary(grouping: forced, by: \.browser)
            for browser in forcedByBrowser.keys.sorted(by: { $0.displayName < $1.displayName }) {
                let cli = browser.cleanupCLIName ?? browser.rawValue
                let sites = forcedByBrowser[browser]!.sorted { $0.domain < $1.domain }
                lines.append("# \(browser.displayName) — \(sites.count) site(s), no-username rows only (forced)")
                lines.append("rekey-cleanup purge --browser \(cli) --no-username\(confirmFlag)\(tally) <<'REKEY_TARGETS'")
                for s in sites { lines.append(s.domain) }
                lines.append("REKEY_TARGETS")
                lines.append("")
            }
        }

        if !stillManual.isEmpty {
            lines.append("# ⚠︎ Manual deletion — these have no username on a site that has other saved")
            lines.append("#    logins, so deleting by site would remove them too. Remove just the one you")
            lines.append("#    marked, by id:")
            for site in stillManual {
                let cli = site.browser.cleanupCLIName ?? site.browser.rawValue
                lines.append("#    \(site.domain) (\(site.browser.displayName), \(site.loginCount) logins):")
                lines.append("#      rekey-cleanup list --browser \(cli) --site \(site.domain.shellArgument)")
                lines.append("#      rekey-cleanup delete --browser \(cli) --id <id-of-the-login-you-marked> --confirm")
            }
        }
        return lines
    }

    public func enqueueAllFlagged() async {
        guard let report else { return }
        let g = currentGenerationChoice()
        // Append every flagged credential up front so the whole batch shows at once.
        // Mirror the fix-progress denominator — finding OR weak, minus ignored/fixed —
        // so "Add all" actually clears the bar instead of silently dropping weak ones.
        let ids = allCredentials
            .filter { (report.findingsByCredential[$0.id] != nil || report.weak.contains($0.id))
                      && !isFixed($0) && !isIgnored($0) }
            .compactMap {
                try? fixQueue.appendPending(credential: $0,
                                            policy: g.passphrase ? nil : g.policy,
                                            passphrase: g.passphrase)
            }
        section = .fixing
        // …then resolve their change URLs in bounded-concurrency batches, so one
        // slow host doesn't gate the rest but a huge import doesn't fire hundreds of
        // probes at once. (Items already show; this just fills in the precise URLs.)
        let queue = fixQueue
        let batchSize = 8
        for start in stride(from: 0, to: ids.count, by: batchSize) {
            let chunk = ids[start..<min(start + batchSize, ids.count)]
            await withTaskGroup(of: Void.self) { group in
                for id in chunk { group.addTask { await queue.resolveChangeURL(itemID: id) } }
            }
        }
    }

    // MARK: - Bulk actions per domain group

    /// Credentials in this group still worth queueing: a finding or weak, and not
    /// already fixed, ignored, or queued.
    private func queueableCreds(in group: DomainGroup) -> [ImportedCredential] {
        guard let report else { return [] }
        return group.credentials.filter { cred in
            (report.findingsByCredential[cred.id] != nil || report.weak.contains(cred.id))
                && !isFixed(cred) && !isIgnored(cred)
                && !fixQueue.items.contains { $0.credentialID == cred.id }
        }
    }
    public func canQueueGroup(_ group: DomainGroup) -> Bool { !queueableCreds(in: group).isEmpty }
    public func enqueueGroup(_ group: DomainGroup) async {
        for cred in queueableCreds(in: group) { await enqueueFix(for: cred) }
        section = .fixing
    }

    /// Active, ignorable findings in this group (matches the per-row Ignore button).
    private func ignorableCreds(in group: DomainGroup) -> [ImportedCredential] {
        guard let report else { return [] }
        return group.credentials.filter { cred in
            !isIgnored(cred) && (report.findingsByCredential[cred.id] != nil
                || report.weak.contains(cred.id)
                || report.strayBlankUsername.contains(cred.id)
                || cred.username.isEmpty)
        }
    }
    public func canIgnoreGroup(_ group: DomainGroup) -> Bool { !ignorableCreds(in: group).isEmpty }
    public func ignoreGroup(_ group: DomainGroup) {
        let creds = ignorableCreds(in: group)
        guard !creds.isEmpty else { return }
        for cred in creds { ignoredKeys.insert(Self.progressKey(for: cred)) }
        saveProgress()
    }
}
