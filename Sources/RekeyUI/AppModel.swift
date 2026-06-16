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
        public var id: String { rawValue }
        public var systemImage: String {
            switch self {
            case .importing: return "square.and.arrow.down"
            case .findings: return "list.bullet.rectangle"
            case .fixing: return "checkmark.shield"
            }
        }
    }

    public var section: Section = .importing
    public private(set) var files: [ImportedFile] = []
    public private(set) var report: AuditReport?
    public var isAuditing = false
    public var auditError: String?

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
    private var watchStart = Date.distantPast
    private var seenSignatures: Set<String> = []
    /// Import files modified within this grace window before watching started, so
    /// an export finished moments earlier is still picked up.
    private let importGraceSeconds: TimeInterval = 300
    private let bookmarkKey = "rekey.watchedFolderBookmark"
    /// The bookmark-restored folder for which we hold a security scope (nil for
    /// picker-granted folders, which don't need an explicit scope).
    private var scopedURL: URL?

    public let fixQueue: FixQueue

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

        // The diceware wordlist is a bundled resource we ship, so this only
        // fails if the app bundle is corrupt — in which case the generator is
        // unusable regardless. Fail fast rather than limp along.
        let generator = try! PasswordGenerator()
        self.fixQueue = FixQueue(
            generator: generator,
            router: ResetRouter(),
            clipboard: Clipboard(),
            opener: opener
        )
        loadBrowserPreference()
        restoreWatchedFolder()
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

    private func reindexCredentials() {
        allCredentials = files.flatMap(\.result.credentials)
        credentialIndex = Dictionary(allCredentials.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
    }

    // MARK: - Import

    /// Import a file selected via the file picker (security-scoped URL).
    public func importFile(at url: URL) {
        let didScope = url.startAccessingSecurityScopedResource()
        defer { if didScope { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url) else { return }
        ingest(data: data, url: url, displayName: url.lastPathComponent)
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
            // A fresh import invalidates the previous audit.
            report = nil
        } catch {
            auditError = "Couldn't import \(displayName): \(error)"
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
        panel.message = "Choose a folder to watch for exported password CSVs (e.g. Downloads). Rekey auto-imports recognized exports as they appear."
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
        scanWatchedFolder()   // catch an export that just finished
    }

    public func stopWatching() {
        folderWatcher.stop()
        releaseScopedAccess()
        watchedFolder = nil
        autoImportMessage = nil
        UserDefaults.standard.removeObject(forKey: bookmarkKey)
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
        defer { isAuditing = false }

        let coordinator = AuditCoordinator(compromiseChecker: hibp)
        let report = await coordinator.audit(credentials: allCredentials)
        self.report = report
        self.section = .findings
    }

    // MARK: - Fix queue bridge

    public func enqueueFix(for credential: ImportedCredential) async {
        _ = try? await fixQueue.enqueue(credential: credential)
    }

    public func enqueueAllFlagged() async {
        guard let report else { return }
        for cred in allCredentials where report.findingsByCredential[cred.id] != nil {
            _ = try? await fixQueue.enqueue(credential: cred)
        }
        section = .fixing
    }
}
