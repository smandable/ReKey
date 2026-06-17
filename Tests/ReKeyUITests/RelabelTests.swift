import Testing
import Foundation
import Model
@testable import ReKeyUI

// AppModel is @MainActor; `.serialized` keeps the UserDefaults-touching cases
// from interleaving with the other progress/deletion suites.
@MainActor
@Suite("Relabel a mislabeled Chromium import", .serialized)
struct RelabelTests {

    // Clear only `deletionKeys` — it's ours alone. `usernameOverrides` is shared
    // with FixProgressTests, which yields concurrently, so wiping the whole dict
    // would clobber its persisted entry; the username test below cleans up just
    // its own keys instead.
    private func clear() {
        UserDefaults.standard.removeObject(forKey: "rekey.deletionKeys")
    }
    private let csv = "name,url,username,password,note\nGitHub,https://github.com/,sean,pw,\n"

    @Test("Relabeling re-derives the file's credentials under the new browser")
    func relabels() throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.chromiumSource = .chrome
        model.importData(Data(csv.utf8), displayName: "Arc Passwords.csv")
        let file = try #require(model.files.first)
        #expect(file.result.source == .chrome)                          // mislabeled at import
        #expect(model.allCredentials.allSatisfy { $0.source == .chrome })

        model.relabelChromium(file, to: .arc)
        let relabeled = try #require(model.files.first)
        #expect(relabeled.result.source == .arc)
        #expect(relabeled.result.detectedFormat == .chromium)           // detection unchanged
        #expect(model.allCredentials.allSatisfy { $0.source == .arc })  // creds re-derived
        // Re-derived ids match a fresh import under Arc (deterministic id folds in source).
        let arc = try #require(model.allCredentials.first)
        #expect(arc.id == ImportedCredential.deterministicID(
            source: .arc, registrableDomain: arc.registrableDomain,
            username: arc.username, passwordHash: arc.password.sha256().base64EncodedString()))
    }

    @Test("A deletion mark survives a relabel (re-keyed to the new browser)")
    func deletionMarkMigrates() throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.chromiumSource = .chrome
        model.importData(Data(csv.utf8), displayName: "Arc Passwords.csv")
        let chrome = try #require(model.allCredentials.first)
        model.markForDeletion(chrome)
        #expect(model.markedForDeletionCount == 1)

        model.relabelChromium(try #require(model.files.first), to: .arc)
        let arc = try #require(model.allCredentials.first)
        #expect(arc.source == .arc)
        #expect(model.isMarkedForDeletion(arc))      // mark followed the relabel
        #expect(model.markedForDeletionCount == 1)   // not dropped, not duplicated
    }

    @Test("A typed username for a blank login follows the relabel")
    func usernameOverrideMigrates() throws {
        clear(); defer { clear() }
        let blank = "name,url,username,password,note\nGitHub,https://github.com/,,pw,\n"
        let model = AppModel()
        model.chromiumSource = .chrome
        model.importData(Data(blank.utf8), displayName: "Arc Passwords.csv")
        let chrome = try #require(model.allCredentials.first)
        model.setUsername("sean@example.com", for: chrome)
        #expect(model.effectiveUsername(for: chrome) == "sean@example.com")

        model.relabelChromium(try #require(model.files.first), to: .arc)
        let arc = try #require(model.allCredentials.first)
        #expect(arc.source == .arc)
        #expect(model.effectiveUsername(for: arc) == "sean@example.com")
        model.setUsername("", for: arc)   // remove just our own override key (shared store)
    }

    @Test("Relabel is a no-op for same-source and for a non-Chromium target")
    func chromiumNoOps() throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.chromiumSource = .chrome
        model.importData(Data(csv.utf8), displayName: "chrome.csv")
        let file = try #require(model.files.first)

        model.relabelChromium(file, to: .chrome)                              // same source
        #expect(try #require(model.files.first).result.source == .chrome)
        model.relabelChromium(try #require(model.files.first), to: .firefox)  // not a Chromium target
        #expect(try #require(model.files.first).result.source == .chrome)
    }

    @Test("A Firefox-detected file can't be relabeled to a Chromium brand")
    func detectedFormatGuard() throws {
        clear(); defer { clear() }
        let firefox = """
        url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged
        https://github.com/,sean,pw,,https://github.com,{11111111-1111-1111-1111-111111111111},0,0,0
        """
        let model = AppModel()
        model.importData(Data(firefox.utf8), displayName: "Arc Passwords.csv")  // misleading name
        let file = try #require(model.files.first)
        #expect(file.result.source == .firefox)        // detected unambiguously
        #expect(file.result.detectedFormat == .firefox)

        model.relabelChromium(file, to: .arc)
        #expect(try #require(model.files.first).result.source == .firefox)   // refused
    }
}
