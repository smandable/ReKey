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

    @Test("A typed username labels a blank login (display only) and persists; the fix keeps the blank store identity")
    func usernameOverride() async throws {
        clear(); defer { clear() }
        let blankCsv = "name,url,username,password,note\nThing,https://thing.example/,,Weakpw123,\n"
        let model = AppModel()
        model.importData(Data(blankCsv.utf8), displayName: "b.csv")
        let cred = try #require(model.allCredentials.first)
        #expect(cred.username.isEmpty)
        #expect(model.effectiveUsername(for: cred) == "")

        model.setUsername("me@email.com", for: cred)
        #expect(model.effectiveUsername(for: cred) == "me@email.com")   // shown in Findings

        // Display only: the fix keeps the browser's real (blank) username, so the
        // cleanup still matches the store entry.
        await model.enqueueFix(for: cred)
        #expect(model.fixQueue.items.first?.username == "")

        // The label persists across a relaunch + re-import (keyed by source|site).
        let reopened = AppModel()
        reopened.importData(Data(blankCsv.utf8), displayName: "b.csv")
        let reCred = try #require(reopened.allCredentials.first)
        #expect(reopened.effectiveUsername(for: reCred) == "me@email.com")
    }

    @Test("deterministicID is stable for the same login and differs by password")
    func deterministicIDStability() {
        let a = ImportedCredential.deterministicID(source: .arc, registrableDomain: "x.com", username: "u", passwordHash: "h1")
        let b = ImportedCredential.deterministicID(source: .arc, registrableDomain: "x.com", username: "u", passwordHash: "h1")
        let c = ImportedCredential.deterministicID(source: .arc, registrableDomain: "x.com", username: "u", passwordHash: "h2")
        #expect(a == b)
        #expect(a != c)
    }

    @Test("A queued fix survives a re-import (deterministic ids — no orphaned items)")
    func deterministicIDsSurviveReimport() async throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.importData(Data(csv.utf8), displayName: "b.csv")
        let cred = try #require(model.allCredentials.first)
        await model.enqueueFix(for: cred)
        let item = try #require(model.fixQueue.items.first)
        #expect(item.credentialID == cred.id)

        // Re-import the same data (as an auto-import poll would). Before deterministic
        // ids this minted a fresh UUID, orphaning the queued item so Mark done no-op'd.
        model.importData(Data(csv.utf8), displayName: "b.csv")
        #expect(model.allCredentials.first?.id == cred.id)     // stable id
        #expect(model.credential(item.credentialID) != nil)    // queued item still resolves
        model.recordFixDone(item)
        #expect(model.isFixed(cred))                           // not a silent no-op
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
