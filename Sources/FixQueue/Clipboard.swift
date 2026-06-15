import Foundation
import CryptoKit
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

    /// Clear the clipboard only if the SHA-256 of its current contents matches
    /// `digest`. This is the sole auto-clear primitive: the timer decides whether
    /// to wipe *without* holding the plaintext password alive for the whole
    /// timeout (the caller passes only a hash), and if the user has since copied
    /// something else, we leave it alone.
    @discardableResult
    public func clearIfMatchesHash(_ digest: Data) -> Bool {
        guard let current = pasteboard.readString() else { return false }
        let currentDigest = Data(SHA256.hash(data: Data(current.utf8)))
        guard currentDigest == digest else { return false }
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
