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
    /// True while the initial product fetch is in flight — distinct from `working`
    /// (a purchase/restore). Lets the paywall show a spinner instead of a dead,
    /// unexplained Unlock button before the price arrives.
    public private(set) var loadingProduct = false
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

    /// Fetch the unlock product so the paywall can show its price and enable the
    /// Unlock button. Public + re-callable so a "Try Again" affordance can retry.
    ///
    /// `Product.products(for:)` does NOT throw when the product simply isn't
    /// purchasable in the current storefront yet — it returns an empty array. That
    /// is the normal outcome when the Paid Apps Agreement isn't in effect, the IAP
    /// metadata is incomplete, or the store is momentarily unreachable. We surface
    /// our own message for that case so the paywall never shows a silently-disabled
    /// button with no explanation (which reads as a broken purchase).
    public func loadProduct() async {
        guard !loadingProduct else { return }
        loadingProduct = true; defer { loadingProduct = false }
        lastError = nil
        do {
            let match = try await Product.products(for: [Self.unlockProductID]).first
            product = match
            displayPrice = match?.displayPrice
            if match == nil {
                lastError = "The App Store didn't return the unlock. Please try again in a moment."
            }
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
    public func loadProduct() async {}
    public func purchase() async {}
    public func restore() async {}
    public func refresh() async {}
    #endif
}
