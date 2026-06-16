import Foundation
import Observation
import Model
import PasswordGenerator
import ResetRouter
#if canImport(AppKit)
import AppKit
#endif

/// Opens a URL in the user's default browser. Abstracted so tests can observe
/// what would be opened without launching anything.
public protocol URLOpening: Sendable {
    @MainActor func open(_ url: URL)
}

#if canImport(AppKit)
/// Opens URLs via `NSWorkspace`. When `targetAppURL` is nil the system default
/// browser is used; otherwise the chosen browser app is launched. If the chosen
/// app can't open the URL (moved/removed), it falls back to the default.
@MainActor
public final class BrowserOpener: URLOpening {
    /// The browser app bundle to open in, or nil for the system default.
    public var targetAppURL: URL?

    public init(targetAppURL: URL? = nil) {
        self.targetAppURL = targetAppURL
    }

    public func open(_ url: URL) {
        guard let app = targetAppURL else {
            NSWorkspace.shared.open(url)
            return
        }
        NSWorkspace.shared.open([url], withApplicationAt: app, configuration: NSWorkspace.OpenConfiguration()) { _, error in
            if error != nil {
                Task { @MainActor in NSWorkspace.shared.open(url) }
            }
        }
    }
}
#endif

/// The preview / approve state machine.
///
/// This is the *only* place a change is initiated, and every item requires
/// explicit per-item approval. Approving does exactly three things — copy the
/// new password to the clipboard, open the change page, and mark the item
/// `opened`. It never changes the password itself; the human does that on the
/// site, and the browser's native "save password?" prompt is the storage path.
///
/// SwiftUI-free: observable via the `Observation` framework, not SwiftUI.
@MainActor
@Observable
public final class FixQueue {
    public private(set) var items: [FixItem] = []
    /// Resolution provenance per item, so the UI can say "couldn't resolve,
    /// opening site root" when appropriate.
    public private(set) var resolutionSources: [UUID: ResetSource] = [:]

    private let generator: PasswordGenerator
    private let router: any ChangeURLResolving
    private let clipboard: Clipboard
    private let opener: any URLOpening
    private let defaultPolicy: PasswordPolicy

    /// How long after a copy the clipboard auto-clears (if the value is still
    /// present). Surfaced so the UI can tell the user.
    public let clipboardClearAfter: Duration

    public init(
        generator: PasswordGenerator,
        router: any ChangeURLResolving,
        clipboard: Clipboard,
        opener: any URLOpening,
        defaultPolicy: PasswordPolicy = .strong,
        clipboardClearAfter: Duration = .seconds(90)
    ) {
        self.generator = generator
        self.router = router
        self.clipboard = clipboard
        self.opener = opener
        self.defaultPolicy = defaultPolicy
        self.clipboardClearAfter = clipboardClearAfter
    }

    // MARK: - Building the queue

    /// Add a credential to the fix queue: append it immediately, then resolve its
    /// change-password URL and fill it in. No-op if already queued; returns the id.
    ///
    /// This is the single-add path. A batch (`enqueueAllFlagged`) instead calls
    /// `appendPending` for every item up front and then `resolveChangeURL(itemID:)`
    /// concurrently, so the whole queue shows at once and one slow host doesn't gate
    /// the rest.
    @discardableResult
    public func enqueue(
        credential: ImportedCredential,
        policy: PasswordPolicy? = nil,
        passphrase: Bool = false
    ) async throws -> UUID? {
        guard let id = try appendPending(credential: credential, policy: policy, passphrase: passphrase)
        else { return nil }
        await resolveChangeURL(itemID: id)
        return id
    }

    /// Append a pending item immediately — no network — with the site root as a
    /// usable placeholder change URL. Returns the new id, or nil if the credential
    /// is already queued. Generating and appending with no `await` in between also
    /// closes the duplicate-enqueue race.
    @discardableResult
    public func appendPending(
        credential: ImportedCredential,
        policy: PasswordPolicy? = nil,
        passphrase: Bool = false
    ) throws -> UUID? {
        guard !items.contains(where: { $0.credentialID == credential.id }) else { return nil }

        let newPassword = try passphrase
            ? generator.generatePassphrase()
            : generator.generate(policy ?? defaultPolicy)

        let item = FixItem(
            credentialID: credential.id,
            registrableDomain: credential.registrableDomain,
            host: credential.host,
            username: credential.username,
            oldPasswordMasked: credential.password.masked(),
            newPassword: newPassword,
            changeURL: URL(string: "https://\(credential.site)/"),
            status: .pending
        )
        items.append(item)
        resolutionSources[item.id] = .siteRoot
        return item.id
    }

    /// Resolve an already-appended item's change-password URL (a network probe)
    /// and fill it in, upgrading the site-root placeholder. Safe to run
    /// concurrently across items — each touches only its own row and re-checks the
    /// item still exists after the await.
    public func resolveChangeURL(itemID: UUID) async {
        guard let i = index(of: itemID) else { return }
        let site = items[i].site
        let resolution = await router.resolveChangeURL(for: site)
        guard let j = index(of: itemID) else { return }
        items[j].changeURL = resolution.url
        resolutionSources[itemID] = resolution.source
    }

    /// Generate a fresh replacement password for an item (regenerate button +
    /// per-item policy controls in the preview card).
    public func regenerate(itemID: UUID, policy: PasswordPolicy? = nil) throws {
        guard let i = index(of: itemID) else { return }
        items[i].newPassword = try generator.generate(policy ?? defaultPolicy)
    }

    /// Generate a diceware passphrase as the replacement, for users who prefer
    /// one (the "passcode if available" idea maps to picking the strongest thing
    /// a site will accept).
    public func regeneratePassphrase(itemID: UUID, wordCount: Int = 6) throws {
        guard let i = index(of: itemID) else { return }
        items[i].newPassword = try generator.generatePassphrase(wordCount: wordCount)
    }

    /// Replace an item's new password with a user-edited value — the preview field
    /// is editable so the user can tweak it (e.g. drop a character a site rejects)
    /// without regenerating from scratch.
    public func setNewPassword(itemID: UUID, to value: String) {
        guard let i = index(of: itemID) else { return }
        items[i].newPassword = Secret(value)
    }

    /// Whether the change URL was confidently resolved (well-known or fallback)
    /// vs. a site-root fallback the user must navigate themselves.
    public func isChangeURLConfident(_ itemID: UUID) -> Bool {
        guard let source = resolutionSources[itemID] else { return false }
        return source != .siteRoot
    }

    // MARK: - The one approval action

    /// Approve an item. Exactly three effects: copy the new password, open the
    /// change page, mark `opened`. Then schedule the clipboard auto-clear.
    /// Does NOT and CANNOT change the password on the site.
    public func approve(itemID: UUID) {
        guard let i = index(of: itemID), items[i].status == .pending else { return }

        copySecret(items[i].newPassword)              // 1. copy (+ auto-clear)
        if let url = items[i].changeURL {             // 2. open
            opener.open(url)
        }
        items[i].status = .opened                     // 3. status
    }

    /// Copy a secret to the clipboard with the same hygiene as Approve: the
    /// plaintext is written, and an auto-clear is scheduled by hash so we don't
    /// hold the password alive for the whole timeout. Used by the per-field copy
    /// buttons so the user can paste the current password (many sites require it
    /// to authorize the change) and the new one into the site's form.
    public func copySecret(_ secret: Secret) {
        clipboard.copy(secret)
        scheduleClipboardClear(matchingHash: secret.sha256())
    }

    /// Open (or re-open) an item's change page in the chosen browser, without
    /// touching its status or the clipboard — for the clickable link, so a closed
    /// tab can be brought back any time.
    public func openChangePage(itemID: UUID) {
        guard let i = index(of: itemID), let url = items[i].changeURL else { return }
        opener.open(url)
    }

    /// User confirms they changed the password on the site (the browser saved
    /// it). Terminal state.
    public func markDone(itemID: UUID) {
        setStatus(itemID, to: .done, from: [.opened])
    }

    /// User chooses not to fix this one. Allowed from any non-terminal state.
    public func skip(itemID: UUID) {
        guard let i = index(of: itemID), items[i].status != .done else { return }
        items[i].status = .skipped
    }

    /// Remove an item from the queue entirely.
    public func remove(itemID: UUID) {
        items.removeAll { $0.id == itemID }
        resolutionSources[itemID] = nil
    }

    // MARK: - Clipboard hygiene

    /// After the timeout, clear the clipboard if it still holds the copied value
    /// (compared by hash, so no plaintext is captured). If the user copied
    /// something else in the meantime, leave it.
    private func scheduleClipboardClear(matchingHash digest: Data) {
        let delay = clipboardClearAfter
        let clipboard = self.clipboard
        Task { @MainActor in
            try? await Task.sleep(for: delay)
            clipboard.clearIfMatchesHash(digest)
        }
    }

    // MARK: - Helpers

    private func index(of itemID: UUID) -> Int? {
        items.firstIndex { $0.id == itemID }
    }

    private func setStatus(_ itemID: UUID, to status: FixStatus, from allowed: Set<FixStatus>) {
        guard let i = index(of: itemID), allowed.contains(items[i].status) else { return }
        items[i].status = status
    }
}
