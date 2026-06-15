import Foundation
import Security
import Observation
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

    /// When importing a Chromium file, treat it as Arc (the CSV can't tell them
    /// apart, so the user decides).
    public var treatChromiumAsArc = false

    public let fixQueue: FixQueue

    private let importer = CSVImporter()
    private let hibp = HIBPClient()

    public init() {
        // The diceware wordlist is a bundled resource we ship, so this only
        // fails if the app bundle is corrupt — in which case the generator is
        // unusable regardless. Fail fast rather than limp along.
        let generator = try! PasswordGenerator()
        self.fixQueue = FixQueue(
            generator: generator,
            router: ResetRouter(),
            clipboard: Clipboard(),
            opener: WorkspaceURLOpener()
        )
    }

    // MARK: - Derived

    public var allCredentials: [ImportedCredential] {
        files.flatMap(\.result.credentials)
    }

    public var totalSkipped: Int {
        files.reduce(0) { $0 + $1.result.skipped.count }
    }

    public func credential(_ id: UUID) -> ImportedCredential? {
        allCredentials.first { $0.id == id }
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
            let result = try importer.import(data: data, arcTagged: treatChromiumAsArc)
            files.append(ImportedFile(url: url, displayName: displayName, result: result))
            // A fresh import invalidates the previous audit.
            report = nil
        } catch {
            auditError = "Couldn't import \(displayName): \(error)"
        }
    }

    public func removeFile(_ file: ImportedFile) {
        files.removeAll { $0.id == file.id }
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
        let size = (try? fm.attributesOfItem(atPath: url.path)[.size] as? Int) ?? 0
        if size > 0, let handle = try? FileHandle(forWritingTo: url) {
            defer { try? handle.close() }
            var remaining = size
            let chunk = 64 * 1024
            try? handle.seek(toOffset: 0)
            while remaining > 0 {
                let n = min(chunk, remaining)
                var bytes = [UInt8](repeating: 0, count: n)
                // Use the CSPRNG for consistency with the rest of the app; even
                // zeros would suffice for a pre-unlink wipe.
                if SecRandomCopyBytes(kSecRandomDefault, n, &bytes) != errSecSuccess {
                    bytes = [UInt8](repeating: 0, count: n)
                }
                handle.write(Data(bytes))
                remaining -= n
            }
            try? handle.synchronize()
        }
        do { try fm.removeItem(at: url); return true } catch { return false }
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
