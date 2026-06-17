import Foundation
import CryptoKit

/// A wrapper around a plaintext password value.
///
/// Design goals (see ReKey hard constraints):
/// - The value is **never** revealed by `description` / `debugDescription`, so
///   `print(secret)`, `"\(secret)"`, logging, and `os_log` interpolation all
///   emit a redacted placeholder instead of the password. Access to the real
///   value is *explicit* via ``reveal()`` / ``withUTF8(_:)``.
/// - Backed by a UTF-8 byte buffer so it can be hashed (HIBP / bucketing) and
///   copied to the clipboard without round-tripping through a `String` that
///   might be retained by the runtime, and so it can be best-effort zeroed.
/// - `Sendable` value type, safe to pass across the strict-concurrency boundary.
///
/// Plaintext lives in memory only. It is never written to disk, never logged,
/// and never transmitted (the single exception is the HIBP k-anonymity check,
/// which sends only the first 5 hex chars of the SHA-1 — see HIBPClient).
public struct Secret: Sendable, Hashable {
    /// UTF-8 bytes of the password. Private so callers must go through the
    /// explicit accessors rather than reaching in.
    private var storage: [UInt8]

    /// Create a secret from a `String`. The string's bytes are copied into the
    /// internal buffer.
    public init(_ value: String) {
        self.storage = Array(value.utf8)
    }

    /// Create a secret directly from UTF-8 bytes (e.g. from a generator).
    public init(utf8Bytes: [UInt8]) {
        self.storage = utf8Bytes
    }

    /// Whether the password is empty (zero bytes).
    public var isEmpty: Bool { storage.isEmpty }

    /// Number of UTF-8 bytes. NOT the character count; use ``reveal()`` and
    /// count graphemes if you need user-facing length. Exposed because it is
    /// non-sensitive and handy for sanity checks.
    public var byteCount: Int { storage.count }

    /// Explicitly reveal the plaintext value as a `String`. Call this only at a
    /// genuine boundary: hashing, clipboard copy, or a deliberate reveal in the
    /// UI. Never log the result.
    public func reveal() -> String {
        String(decoding: storage, as: UTF8.self)
    }

    /// Explicitly access the raw UTF-8 bytes within a closure (for hashing).
    /// Scoped so callers don't hold the buffer longer than needed.
    public func withUTF8<T>(_ body: ([UInt8]) throws -> T) rethrows -> T {
        try body(storage)
    }

    /// Best-effort overwrite of the backing buffer with zeros. A value type has
    /// no deinit, so this is opt-in: call it when you are truly done with a
    /// secret (e.g. after the clipboard auto-clear fires). Note that copies made
    /// earlier are independent and unaffected.
    public mutating func zero() {
        for i in storage.indices { storage[i] = 0 }
        storage.removeAll(keepingCapacity: false)
    }

    /// A masked representation safe to render in the UI: a fixed run of bullets
    /// that does not leak the real length. Use this for `oldPasswordMasked`.
    public func masked() -> String {
        String(repeating: "•", count: 8)
    }

    /// SHA-256 of the password's UTF-8 bytes, as `Data`. For in-memory bucketing
    /// and constant-input comparison (reuse analysis, clipboard auto-clear) —
    /// never a security primitive, and never persisted or transmitted.
    public func sha256() -> Data {
        withUTF8 { Data(SHA256.hash(data: Data($0))) }
    }
}

// MARK: - Redaction

extension Secret: CustomStringConvertible, CustomDebugStringConvertible {
    /// Redacted: interpolating or printing a `Secret` never leaks the value.
    public var description: String { "Secret(redacted)" }
    /// Redacted in the debugger / `dump` as well.
    public var debugDescription: String { "Secret(redacted)" }
}
