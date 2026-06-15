import Foundation
import Model

/// Builds the right ``LoginStore`` for a browser + store file.
public enum LoginStoreFactory {
    public static func make(browser: BrowserSource, storeURL: URL) throws -> any LoginStore {
        guard BrowserPaths.isSupported(browser) else {
            throw LoginStoreError.unrecognizedSchema(
                "\(browser.displayName) isn't supported (Apple Passwords has no third-party delete API)."
            )
        }
        if browser == .firefox {
            return FirefoxLoginStore(loginsURL: storeURL)
        }
        return ChromiumLoginStore(browser: browser, databaseURL: storeURL)
    }
}
