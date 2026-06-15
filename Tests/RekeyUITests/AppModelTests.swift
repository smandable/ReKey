import Testing
import Foundation
import Model
@testable import RekeyUI

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
