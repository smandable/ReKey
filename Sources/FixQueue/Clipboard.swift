import Foundation
import Model
#if canImport(AppKit)
import AppKit
#endif

/// Minimal pasteboard surface so the clipboard can be faked in tests without
/// touching the real system pasteboard.
@MainActor
public protocol PasteboardWriting: AnyObject {
    /// Write `value` to the pasteboard marked as concealed/sensitive, and return
    /// the pasteboard's change count *after* the write — a token the caller can
    /// hand to ``Clipboard/clearIfUnchanged(since:)`` to tell whether anything
    /// else has been copied since.
    func writeConcealedString(_ value: String) -> Int
    /// The pasteboard's current change count. This is metadata, not the clipboard
    /// *contents*, so reading it never trips macOS 15.4+'s "<app> accessed the
    /// clipboard" alert the way reading the string back would.
    var changeCount: Int { get }
    /// Clear all contents.
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

    /// Copy the secret's plaintext to the clipboard, marked concealed so
    /// clipboard-history managers (Maccy, Raycast, Alfred, 1Password, …) skip
    /// storing it. This is one of the few places the value is deliberately
    /// revealed. Returns a change-count token for ``clearIfUnchanged(since:)``.
    @discardableResult
    public func copy(_ secret: Secret) -> Int {
        pasteboard.writeConcealedString(secret.reveal())
    }

    /// Clear the clipboard only if nothing has been copied since the write that
    /// produced `token` (i.e. the change count is unchanged). This is the sole
    /// auto-clear primitive. Comparing change *counts* — never contents — means
    /// the timer doesn't read the clipboard at all, so it neither keeps the
    /// plaintext alive for the whole timeout nor trips macOS 15.4+'s
    /// pasteboard-read alert; and if the user copied something else in the
    /// meantime (any change bumps the count), we leave it alone.
    @discardableResult
    public func clearIfUnchanged(since token: Int) -> Bool {
        guard pasteboard.changeCount == token else { return false }
        pasteboard.clearContents()
        return true
    }
}

#if canImport(AppKit)
/// Real `NSPasteboard.general` adapter.
@MainActor
final class SystemPasteboard: PasteboardWriting {
    private let board = NSPasteboard.general

    /// The community-standard marker (nspasteboard.org) that 1Password, KeePassXC,
    /// Bitwarden, and the popular clipboard-history managers honor: items carrying
    /// it are kept out of clipboard history. Only the *presence* of the type is the
    /// signal, so the marker's own payload is irrelevant.
    private static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")

    @discardableResult
    func writeConcealedString(_ value: String) -> Int {
        board.clearContents()
        board.setString(value, forType: .string)
        board.setString("", forType: Self.concealedType)
        return board.changeCount
    }

    var changeCount: Int { board.changeCount }

    func clearContents() {
        board.clearContents()
    }
}
#endif
