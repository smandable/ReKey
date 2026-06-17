import Testing
import Foundation
@testable import ReKeyUI

// Serialized: these tests mutate the shared UserDefaults key the preference uses,
// so they must not run in parallel with each other.
@MainActor
@Suite(.serialized)
struct BrowserPreferenceTests {
    private let key = "rekey.changePageBrowserPath"
    private func clear() { UserDefaults.standard.removeObject(forKey: key) }

    @Test("Defaults to the system browser, which is the first option")
    func defaults() {
        clear(); defer { clear() }
        let model = AppModel()
        #expect(model.availableBrowsers.first?.appURL == nil)   // "Default browser" first
        #expect(model.availableBrowsers.first?.id == "")
        #expect(model.selectedBrowserID == "")
    }

    @Test("Selecting a real browser updates, persists, and reloads")
    func selectAndPersist() {
        clear(); defer { clear() }
        let model = AppModel()
        // Use whatever real browser the test machine has (Safari is always present).
        guard let real = model.availableBrowsers.first(where: { $0.appURL != nil }) else { return }

        model.selectBrowser(id: real.id)
        #expect(model.selectedBrowserID == real.id)

        // A fresh model restores the persisted choice (browser still installed).
        #expect(AppModel().selectedBrowserID == real.id)

        // Reset to default clears it.
        model.selectBrowser(id: "")
        #expect(model.selectedBrowserID == "")
        #expect(AppModel().selectedBrowserID == "")
    }

    @Test("An unknown browser id is ignored")
    func ignoresUnknown() {
        clear(); defer { clear() }
        let model = AppModel()
        model.selectBrowser(id: "/Applications/DoesNotExist.app")
        #expect(model.selectedBrowserID == "")
    }
}
