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
/// Opens URLs via `NSWorkspace` in the default browser.
public struct WorkspaceURLOpener: URLOpening {
    public init() {}
    @MainActor public func open(_ url: URL) {
        NSWorkspace.shared.open(url)
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

    /// Add a credential to the fix queue: generate a replacement and resolve its
    /// change-password URL lazily (this is the user acting on this specific
    /// item — resolution is never batched across the whole account list).
    ///
    /// No-op if the credential is already queued. Returns the new item's id.
    @discardableResult
    public func enqueue(credential: ImportedCredential, policy: PasswordPolicy? = nil) async throws -> UUID? {
        guard !items.contains(where: { $0.credentialID == credential.id }) else { return nil }

        let newPassword = try generator.generate(policy ?? defaultPolicy)
        let resolution = await router.resolveChangeURL(for: credential.registrableDomain)

        let item = FixItem(
            credentialID: credential.id,
            registrableDomain: credential.registrableDomain,
            username: credential.username,
            oldPasswordMasked: credential.password.masked(),
            newPassword: newPassword,
            changeURL: resolution.url,
            status: .pending
        )
        items.append(item)
        resolutionSources[item.id] = resolution.source
        return item.id
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
        let value = items[i].newPassword.reveal()

        clipboard.copy(items[i].newPassword)          // 1. copy
        if let url = items[i].changeURL {             // 2. open
            opener.open(url)
        }
        items[i].status = .opened                     // 3. status

        scheduleClipboardClear(value: value)
    }

    /// User confirms they changed the password on the site (the browser saved
    /// it). Terminal state.
    public func markDone(itemID: UUID) {
        setStatus(itemID, to: .done, from: [.opened, .approved])
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

    /// After the timeout, clear the clipboard if it still holds the copied
    /// value. If the user copied something else in the meantime, leave it.
    private func scheduleClipboardClear(value: String) {
        let delay = clipboardClearAfter
        let clipboard = self.clipboard
        Task { @MainActor in
            try? await Task.sleep(for: delay)
            clipboard.clearIfMatches(value)
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
