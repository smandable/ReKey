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
    /// Heap buffer holding the plaintext UTF-8 bytes, behind a reference type so
    /// the bytes are scrubbed in `deinit` when the LAST `Secret` referencing them
    /// is dropped — automatic, reliable zeroing without relying on opt-in calls,
    /// and without the copy-on-write footgun a bare `[UInt8]` has (mutating a
    /// shared array zeroes a fresh copy, not the bytes you meant to erase).
    ///
    /// `@unchecked Sendable`: `bytes` is written only in `init` and the
    /// single-owner `deinit`; every other access is a read, so sharing the buffer
    /// across `Secret` copies and actors is safe.
    private final class Buffer: @unchecked Sendable {
        var bytes: [UInt8]
        init(_ bytes: [UInt8]) { self.bytes = bytes }
        deinit {
            // Best-effort overwrite of the buffer we own. (Earlier String/Array
            // copies the runtime may have made are independent and unaffected.)
            for i in bytes.indices { bytes[i] = 0 }
        }
    }
    private var buffer: Buffer

    /// Create a secret from a `String`. The string's bytes are copied into the
    /// internal buffer.
    public init(_ value: String) {
        self.buffer = Buffer(Array(value.utf8))
    }

    /// Create a secret directly from UTF-8 bytes (e.g. from a generator).
    public init(utf8Bytes: [UInt8]) {
        self.buffer = Buffer(utf8Bytes)
    }

    /// Whether the password is empty (zero bytes).
    public var isEmpty: Bool { buffer.bytes.isEmpty }

    /// Number of UTF-8 bytes. NOT the character count; use ``reveal()`` and
    /// count graphemes if you need user-facing length. Exposed because it is
    /// non-sensitive and handy for sanity checks.
    public var byteCount: Int { buffer.bytes.count }

    /// Explicitly reveal the plaintext value as a `String`. Call this only at a
    /// genuine boundary: hashing, clipboard copy, or a deliberate reveal in the
    /// UI. Never log the result.
    public func reveal() -> String {
        String(decoding: buffer.bytes, as: UTF8.self)
    }

    /// Explicitly access the raw UTF-8 bytes within a closure (for hashing).
    /// Scoped so callers don't hold the buffer longer than needed.
    public func withUTF8<T>(_ body: ([UInt8]) throws -> T) rethrows -> T {
        try body(buffer.bytes)
    }

    /// Drop this `Secret`'s reference to the plaintext early. If it was the last
    /// reference the buffer's `deinit` scrubs the bytes; copies held elsewhere keep
    /// their own reference (and are scrubbed when they, too, are dropped). The bytes
    /// are normally zeroed automatically on dealloc — this just makes it explicit
    /// when you're done early (e.g. after a clipboard auto-clear).
    public mutating func zero() {
        buffer = Buffer([])
    }

    /// A masked representation safe to render in the UI: a fixed run of bullets
    /// that does not leak the real length. Use this for `oldPasswordMasked`.
    public func masked() -> String {
        String(repeating: "•", count: 8)
    }

    /// SHA-256 of the password's UTF-8 bytes, as `Data`. For in-memory bucketing
    /// and constant-input comparison (reuse analysis) — never a security
    /// primitive, and never persisted or transmitted.
    public func sha256() -> Data {
        withUTF8 { Data(SHA256.hash(data: Data($0))) }
    }

    /// Keyed HMAC-SHA256 of the password's UTF-8 bytes. Unlike ``sha256()``, this
    /// is safe to persist: without `key` the output reveals nothing about the
    /// password, so a value written to disk can't be brute-forced offline. Used
    /// for save-verification, where `key` is a per-install secret in the Keychain.
    public func hmac(key: SymmetricKey) -> Data {
        withUTF8 { Data(HMAC<SHA256>.authenticationCode(for: Data($0), using: key)) }
    }

    // Value semantics over the bytes (the buffer is an implementation detail, so
    // never compare/hash by reference identity): two secrets with the same
    // plaintext are equal and hash alike.
    public static func == (lhs: Secret, rhs: Secret) -> Bool {
        lhs.buffer.bytes == rhs.buffer.bytes
    }
    public func hash(into hasher: inout Hasher) {
        hasher.combine(buffer.bytes)
    }
}

// MARK: - Redaction

extension Secret: CustomStringConvertible, CustomDebugStringConvertible {
    /// Redacted: interpolating or printing a `Secret` never leaks the value.
    public var description: String { "Secret(redacted)" }
    /// Redacted in the debugger / `dump` as well.
    public var debugDescription: String { "Secret(redacted)" }
}
