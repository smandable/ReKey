import Foundation
#if MAS_BUILD
import StoreKit
#endif

/// The one-time "unlock fixing" in-app purchase, for the App Store build only.
///
/// The App Store version is free to download and run the full audit; the Fix
/// Queue (generate replacements + open each change page) is gated behind a single
/// non-consumable purchase. In the direct (non-MAS) build there is no IAP and
/// everything is unlocked, so this whole type collapses to `isUnlocked = true` —
/// which is also why the test suite (built without `MAS_BUILD`) never touches
/// StoreKit.
@MainActor
@Observable
public final class Store {
    /// Must match the non-consumable product created in App Store Connect.
    public static let unlockProductID = "com.seanmandable.rekey.unlock"

    /// Whether the fix workflow is available. Always true in the direct build.
    public private(set) var isUnlocked: Bool
    /// Localized price string for the paywall button (nil until the product loads).
    public private(set) var displayPrice: String?
    /// True while a purchase or restore is in flight.
    public private(set) var working = false
    /// User-facing message from the last store operation, if any.
    public var lastError: String?

    #if MAS_BUILD
    private var product: Product?
    private var updatesTask: Task<Void, Never>?

    public init() {
        isUnlocked = false
        // Catch purchases approved out-of-band (Ask to Buy, another device) for the
        // app's lifetime. AppModel holds the Store for the whole session, so this
        // task is intentionally long-lived.
        updatesTask = Task { [weak self] in
            for await update in Transaction.updates {
                if case .verified(let t) = update { await t.finish() }
                await self?.refresh()
            }
        }
        Task { await loadProduct(); await refresh() }
    }
    // No deinit: the Store lives for the whole app session (held by AppModel), so
    // the Transaction.updates listener is intentionally app-lifetime; [weak self]
    // already prevents a retain cycle. (A deinit can't touch the main-actor-isolated
    // task under Swift 6 anyway.)

    private func loadProduct() async {
        do {
            product = try await Product.products(for: [Self.unlockProductID]).first
            displayPrice = product?.displayPrice
        } catch {
            lastError = "Couldn't reach the App Store — check your connection and try again."
        }
    }

    /// Re-evaluate the unlock from the user's current entitlements.
    public func refresh() async {
        var unlocked = false
        for await result in Transaction.currentEntitlements {
            if case .verified(let t) = result,
               t.productID == Self.unlockProductID, t.revocationDate == nil {
                unlocked = true
            }
        }
        isUnlocked = unlocked
    }

    /// Buy the unlock.
    public func purchase() async {
        guard let product, !working else { return }
        working = true; defer { working = false }
        lastError = nil
        do {
            switch try await product.purchase() {
            case .success(let verification):
                switch verification {
                case .verified(let t):
                    await t.finish()
                    isUnlocked = true
                case .unverified(let t, _):
                    // Acknowledge so it doesn't linger in Transaction.updates, but
                    // never unlock on a transaction that failed verification.
                    await t.finish()
                    lastError = "Couldn't verify that purchase. Please try again."
                }
            case .userCancelled, .pending:
                break
            @unknown default:
                break
            }
        } catch {
            lastError = "Purchase didn't complete: \(error.localizedDescription)"
        }
    }

    /// Restore a previous purchase (App Store account sync). Required affordance.
    public func restore() async {
        guard !working else { return }
        working = true; defer { working = false }
        lastError = nil
        do {
            try await AppStore.sync()
        } catch StoreKitError.userCancelled {
            return                                  // user backed out — not an error
        } catch {
            lastError = "Couldn't reach the App Store to restore — check your connection and try again."
            return                                  // don't mislead with "no purchase found" on a sync failure
        }
        await refresh()
        if !isUnlocked { lastError = "No previous purchase found on this Apple ID." }
    }
    #else
    public init() { isUnlocked = true }   // direct build: no IAP, fully unlocked
    public func purchase() async {}
    public func restore() async {}
    public func refresh() async {}
    #endif
}
