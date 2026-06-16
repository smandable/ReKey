import Testing
import Foundation
import Model
@testable import RekeyUI

@MainActor
@Suite("Fixed-login cleanup commands")
struct FixedCleanupCommandsTests {
    private func item(_ domain: String, _ user: String, status: FixStatus = .done) -> FixItem {
        FixItem(credentialID: UUID(), registrableDomain: domain, username: user,
                oldPasswordMasked: "••••", newPassword: Secret("x"), status: status)
    }

    @Test("Per-username for Chromium, one site-level line for Firefox; Apple + non-done excluded")
    func aggregatesAndDedupes() {
        // Two Chase logins fixed in Chrome (distinct usernames), two more in
        // Firefox (collapse to one site-level delete), one Apple (no command),
        // and a still-pending item that must be ignored.
        let chrome1 = item("chase.com", "smandable1")
        let chrome2 = item("chase.com", "smandable2")
        let ff1 = item("chase.com", "u1")
        let ff2 = item("chase.com", "u2")
        let apple = item("icloud.com", "me")
        let pending = item("x.com", "p", status: .pending)

        let source: [UUID: BrowserSource] = [
            chrome1.credentialID: .chrome, chrome2.credentialID: .chrome,
            ff1.credentialID: .firefox, ff2.credentialID: .firefox,
            apple.credentialID: .applePasswords, pending.credentialID: .chrome,
        ]
        let cmds = AppModel.cleanupCommands(forDone: [chrome1, chrome2, ff1, ff2, apple, pending]) {
            source[$0] ?? .unknown
        }

        #expect(cmds == [
            "rekey-cleanup delete --browser chrome --site chase.com --username smandable1",
            "rekey-cleanup delete --browser chrome --site chase.com --username smandable2",
            "rekey-cleanup delete --browser firefox --site chase.com",
        ])
    }
}

@MainActor
@Suite(.serialized)   // mutates the shared UserDefaults ignored keys
struct IgnoreFindingTests {
    private let ignoredKey = "rekey.ignoredKeys"
    private func clear() { UserDefaults.standard.removeObject(forKey: ignoredKey) }
    private let csv = "name,url,username,password,note\nGitHub,https://github.com/,sean,Tr0ub4dour&3,\n"

    @Test("Ignoring an account persists across a relaunch (by site+username); un-ignore clears it")
    func ignorePersists() throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.importData(Data(csv.utf8), displayName: "chrome.csv")
        let cred = try #require(model.allCredentials.first)
        #expect(!model.isIgnored(cred))

        model.ignoreFinding(for: cred)
        #expect(model.isIgnored(cred))

        // A fresh model with new credential UUIDs still sees it ignored — the key
        // is site+username, and no password is stored.
        let reloaded = AppModel()
        reloaded.importData(Data(csv.utf8), displayName: "chrome.csv")
        let reCred = try #require(reloaded.allCredentials.first)
        #expect(reloaded.isIgnored(reCred))
        #expect(!reloaded.ignoredKeys.contains { $0.contains("Tr0ub4dour") })   // never the password

        reloaded.unignoreFinding(for: reCred)
        #expect(!reloaded.isIgnored(reCred))
    }
}

@MainActor
@Suite("Secure delete")
struct SecureDeleteTests {
    private func tempFile(_ contents: String, perms: Int? = nil) -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("rekey-sd-\(UUID().uuidString).csv")
        try? Data(contents.utf8).write(to: url)
        if let perms { try? FileManager.default.setAttributes([.posixPermissions: perms], ofItemAtPath: url.path) }
        return url
    }

    @Test("Overwrites and unlinks a file, reporting success")
    func happyPath() {
        let url = tempFile("url,username,password\nhttps://x/,u,hunter2\n")
        #expect(AppModel.secureDelete(url) == true)
        #expect(!FileManager.default.fileExists(atPath: url.path))
    }

    @Test("Empty file: skips overwrite, still unlinks and succeeds")
    func emptyFile() {
        let url = tempFile("")
        #expect(AppModel.secureDelete(url) == true)
        #expect(!FileManager.default.fileExists(atPath: url.path))
    }

    @Test("Overwrite failure reports false and leaves the file (no false success)")
    func overwriteFailureIsHonest() {
        // Read-only file: the overwrite open() fails, so we must report failure
        // and NOT have removed the file (the bug this guards against: try? +
        // reporting success).
        let url = tempFile("secret-bytes-that-must-not-be-claimed-wiped", perms: 0o400)
        defer {
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            try? FileManager.default.removeItem(at: url)
        }
        #expect(AppModel.secureDelete(url) == false)
        #expect(FileManager.default.fileExists(atPath: url.path))
    }
}
