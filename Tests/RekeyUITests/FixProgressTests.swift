import Testing
import Foundation
import Model
@testable import RekeyUI

// Serialized: mutates the shared UserDefaults progress keys.
@MainActor
@Suite(.serialized)
struct FixProgressTests {
    private let completedKey = "rekey.completedKeys"
    private let skippedKey = "rekey.skippedKeys"
    private func clear() {
        UserDefaults.standard.removeObject(forKey: completedKey)
        UserDefaults.standard.removeObject(forKey: skippedKey)
    }
    private let csv = "name,url,username,password,note\nGitHub,https://github.com/,sean,Tr0ub4dour&3,\n"

    private func item(for cred: ImportedCredential) -> FixItem {
        FixItem(credentialID: cred.id, registrableDomain: cred.registrableDomain,
                username: cred.username, oldPasswordMasked: "••••",
                newPassword: Secret("placeholder"), status: .opened)
    }

    @Test("Marking done records the account and persists across a relaunch")
    func persistsDone() throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.importData(Data(csv.utf8), displayName: "chrome.csv")
        let cred = try #require(model.allCredentials.first)
        #expect(!model.isFixed(cred))

        model.recordFixDone(item(for: cred))
        #expect(model.isFixed(cred))

        // A fresh model (new credential UUIDs) still sees it fixed — the key is
        // site+username, not the volatile id, and no password is persisted.
        let reloaded = AppModel()
        reloaded.importData(Data(csv.utf8), displayName: "chrome.csv")
        let reCred = try #require(reloaded.allCredentials.first)
        #expect(reloaded.isFixed(reCred))
        #expect(!reloaded.completedKeys.contains { $0.contains("Tr0ub4dour") })  // never stores the password
    }

    @Test("Reopen un-marks a fixed account so it can be redone")
    func unmarkFixed() throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.importData(Data(csv.utf8), displayName: "chrome.csv")
        let cred = try #require(model.allCredentials.first)

        model.recordFixDone(item(for: cred))
        #expect(model.isFixed(cred))

        model.unmarkFixed(for: cred)
        #expect(!model.isFixed(cred))
        // And it stays un-fixed across a relaunch.
        let reloaded = AppModel()
        reloaded.importData(Data(csv.utf8), displayName: "chrome.csv")
        let reCred = try #require(reloaded.allCredentials.first)
        #expect(!reloaded.isFixed(reCred))
    }

    @Test("Skipping records the account without marking it fixed")
    func persistsSkip() throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.importData(Data(csv.utf8), displayName: "chrome.csv")
        let cred = try #require(model.allCredentials.first)

        model.recordFixSkipped(item(for: cred))
        #expect(model.skippedKeys.contains(AppModel.progressKey(for: cred)))
        #expect(!model.isFixed(cred))
    }
}
