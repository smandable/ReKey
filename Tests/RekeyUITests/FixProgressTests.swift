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
        UserDefaults.standard.removeObject(forKey: "rekey.fixSaveRecords")
        UserDefaults.standard.removeObject(forKey: "rekey.usernameOverrides")
    }
    private let csv = "name,url,username,password,note\nGitHub,https://github.com/,sean,Tr0ub4dour&3,\n"
    private func csv(password: String) -> String {
        "name,url,username,password,note\nGitHub,https://github.com/,sean,\(password),\n"
    }

    private func item(for cred: ImportedCredential, newPassword: String = "placeholder") -> FixItem {
        FixItem(credentialID: cred.id, registrableDomain: cred.registrableDomain,
                username: cred.username, oldPasswordMasked: "••••",
                newPassword: Secret(newPassword), status: .opened)
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

    @Test("A re-import still showing the old password flags the fix as maybe-unsaved")
    func detectsUnsavedFix() throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.importData(Data(csv.utf8), displayName: "browser.csv")        // old: Tr0ub4dour&3
        let cred = try #require(model.allCredentials.first)
        model.recordFixDone(item(for: cred, newPassword: "N3w-Str0ng-pw!"))
        #expect(model.isFixed(cred))
        #expect(!model.fixMaySaveFailed(cred))   // not flagged yet — same import predates the fix

        // Relaunch + re-import a CSV that STILL shows the old password.
        let reopened = AppModel()
        reopened.importData(Data(csv.utf8), displayName: "browser.csv")
        let reCred = try #require(reopened.allCredentials.first)
        #expect(reopened.fixMaySaveFailed(reCred))   // old password still present → warn
        #expect(reopened.unsavedFixCount == 1)       // surfaced in the banner count
    }

    @Test("A re-import showing the new password clears the fix (saved OK)")
    func savedFixNotFlagged() throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.importData(Data(csv.utf8), displayName: "browser.csv")
        let cred = try #require(model.allCredentials.first)
        model.recordFixDone(item(for: cred, newPassword: "N3w-Str0ng-pw!"))

        let reopened = AppModel()
        reopened.importData(Data(csv(password: "N3w-Str0ng-pw!").utf8), displayName: "browser.csv")
        let reCred = try #require(reopened.allCredentials.first)
        #expect(!reopened.fixMaySaveFailed(reCred))

        // An out-of-band change (neither old nor new) is treated as neutral, not a failure.
        let other = AppModel()
        other.importData(Data(csv(password: "something-else-entirely").utf8), displayName: "browser.csv")
        let otherCred = try #require(other.allCredentials.first)
        #expect(!other.fixMaySaveFailed(otherCred))
    }

    @Test("A user-supplied username on a blank login flows into the fix and persists")
    func usernameOverride() async throws {
        clear(); defer { clear() }
        let blankCsv = "name,url,username,password,note\nThing,https://thing.example/,,Weakpw123,\n"
        let model = AppModel()
        model.importData(Data(blankCsv.utf8), displayName: "b.csv")
        let cred = try #require(model.allCredentials.first)
        #expect(cred.username.isEmpty)
        #expect(model.effectiveUsername(for: cred) == "")

        model.setUsername("me@email.com", for: cred)
        #expect(model.effectiveUsername(for: cred) == "me@email.com")

        await model.enqueueFix(for: cred)
        #expect(model.fixQueue.items.first?.username == "me@email.com")   // carried into the fix

        // Persists across a relaunch + re-import (keyed by source|site).
        let reopened = AppModel()
        reopened.importData(Data(blankCsv.utf8), displayName: "b.csv")
        let reCred = try #require(reopened.allCredentials.first)
        #expect(reopened.effectiveUsername(for: reCred) == "me@email.com")
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
