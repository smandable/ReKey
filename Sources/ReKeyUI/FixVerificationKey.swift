import Foundation
import Security
import CryptoKit

/// A per-install random key, kept in the Keychain, used to HMAC the
/// save-verification password hashes that ReKey persists to UserDefaults.
///
/// The save-verification feature records a hash of the old and new password when
/// a fix is marked done, so a later re-import can tell whether the change saved.
/// Storing a *plain* SHA-256 of a real (often weak) password on disk is an
/// offline-recoverable fingerprint; keying the hash with a secret that lives only
/// in the Keychain makes the persisted value useless to anyone who reads the
/// preferences plist but not the Keychain.
enum FixVerificationKey {
    private static let service = "com.seanmandable.rekey.fix-verify"
    private static let account = "hmac-key-v1"

    /// Fetch the existing key, or create and store a new random 32-byte one.
    /// Returns nil when the Keychain is unavailable (e.g. an unsigned `swift test`
    /// binary with no keychain entitlement); callers then skip save-verification
    /// rather than fall back to an unkeyed, brute-forceable hash.
    static func loadOrCreate() -> SymmetricKey? {
        load() ?? create()
    }

    private static func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            // iOS-style keychain semantics that behave correctly in the app sandbox.
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    private static func load() -> SymmetricKey? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data, data.count == 32 else { return nil }
        return SymmetricKey(data: data)
    }

    private static func create() -> SymmetricKey? {
        var keyBytes = Data(count: 32)
        let drawn = keyBytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        guard drawn == errSecSuccess else { return nil }

        var add = baseQuery()
        add[kSecValueData as String] = keyBytes
        // Device-only (never synced) and available after first unlock — a
        // background re-import shouldn't depend on the screen being unlocked.
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let status = SecItemAdd(add as CFDictionary, nil)
        if status == errSecDuplicateItem { return load() }   // raced another instance
        guard status == errSecSuccess else { return nil }
        return SymmetricKey(data: keyBytes)
    }
}
