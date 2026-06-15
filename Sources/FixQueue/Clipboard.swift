import Foundation
import Model
#if canImport(AppKit)
import AppKit
#endif

/// Minimal pasteboard surface so the clipboard can be faked in tests without
/// touching the real system pasteboard.
@MainActor
public protocol PasteboardWriting: AnyObject {
    func writeString(_ value: String)
    func readString() -> String?
    func clearContents()
}

/// Clipboard with hygiene: copies a secret, and can clear itself only if the
/// value it wrote is still present (so we never wipe something the user copied
/// afterwards). The password is never put into any persistent state.
@MainActor
public final class Clipboard {
    private let pasteboard: any PasteboardWriting

    public init(pasteboard: any PasteboardWriting) {
        self.pasteboard = pasteboard
    }

    #if canImport(AppKit)
    /// System clipboard backed by `NSPasteboard.general`.
    public convenience init() {
        self.init(pasteboard: SystemPasteboard())
    }
    #endif

    /// Copy the secret's plaintext to the clipboard. This is one of the few
    /// places the value is deliberately revealed.
    public func copy(_ secret: Secret) {
        pasteboard.writeString(secret.reveal())
    }

    /// Current clipboard string (used to decide whether auto-clear should fire).
    public func contents() -> String? {
        pasteboard.readString()
    }

    /// Unconditionally clear the clipboard.
    public func clear() {
        pasteboard.clearContents()
    }

    /// Clear the clipboard **only** if it still holds `value`. Returns whether a
    /// clear happened. This is the auto-clear primitive: if the user has since
    /// copied something else, we leave it alone.
    @discardableResult
    public func clearIfMatches(_ value: String) -> Bool {
        guard pasteboard.readString() == value else { return false }
        pasteboard.clearContents()
        return true
    }
}

#if canImport(AppKit)
/// Real `NSPasteboard.general` adapter.
@MainActor
final class SystemPasteboard: PasteboardWriting {
    private let board = NSPasteboard.general

    func writeString(_ value: String) {
        board.clearContents()
        board.setString(value, forType: .string)
    }

    func readString() -> String? {
        board.string(forType: .string)
    }

    func clearContents() {
        board.clearContents()
    }
}
#endif
