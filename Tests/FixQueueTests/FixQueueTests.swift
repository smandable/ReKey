import Testing
import Foundation
import CryptoKit
import Model
import PasswordGenerator
import ResetRouter
@testable import FixQueue

// MARK: - Test doubles

@MainActor
final class FakePasteboard: PasteboardWriting {
    var value: String?
    func writeString(_ value: String) { self.value = value }
    func readString() -> String? { value }
    func clearContents() { value = nil }
}

@MainActor
final class FakeOpener: URLOpening {
    var opened: [URL] = []
    func open(_ url: URL) { opened.append(url) }
}

struct StubRouter: ChangeURLResolving {
    let resolution: ResetResolution
    func resolveChangeURL(for registrableDomain: String) async -> ResetResolution {
        // Echo the domain into a well-known-style URL unless a fixed one was set.
        resolution
    }
}

@MainActor
private func makeQueue(
    resolution: ResetResolution = ResetResolution(url: URL(string: "https://acme.example/.well-known/change-password")!, source: .wellKnown),
    pasteboard: FakePasteboard = FakePasteboard(),
    opener: FakeOpener = FakeOpener(),
    clearAfter: Duration = .seconds(90)
) throws -> (FixQueue, FakePasteboard, FakeOpener) {
    let queue = FixQueue(
        generator: try PasswordGenerator(),
        router: StubRouter(resolution: resolution),
        clipboard: Clipboard(pasteboard: pasteboard),
        opener: opener,
        clipboardClearAfter: clearAfter
    )
    return (queue, pasteboard, opener)
}

private func credential(domain: String = "acme.example", username: String = "bob", password: String = "old-secret") -> ImportedCredential {
    ImportedCredential(
        source: .chrome, title: "Acme", rawURL: "https://\(domain)/",
        registrableDomain: domain, username: username,
        password: Secret(password), notes: nil, hasTOTP: false
    )
}

// MARK: - Tests

@MainActor
@Suite("Fix queue state machine")
struct FixQueueTests {

    @Test("Enqueue builds a pending item with a masked old password and a new one")
    func enqueue() async throws {
        let (queue, _, _) = try makeQueue()
        let cred = credential()
        let id = try await queue.enqueue(credential: cred)
        let item = try #require(queue.items.first)
        #expect(queue.items.count == 1)
        #expect(item.id == id)
        #expect(item.status == .pending)
        #expect(item.registrableDomain == "acme.example")
        #expect(item.username == "bob")
        // Old password is masked — never the real value.
        #expect(item.oldPasswordMasked != "old-secret")
        #expect(!item.newPassword.reveal().isEmpty)
        #expect(item.changeURL?.absoluteString == "https://acme.example/.well-known/change-password")
        #expect(queue.isChangeURLConfident(item.id) == true)
    }

    @Test("Enqueue is idempotent per credential")
    func dedup() async throws {
        let (queue, _, _) = try makeQueue()
        let cred = credential()
        _ = try await queue.enqueue(credential: cred)
        let second = try await queue.enqueue(credential: cred)
        #expect(second == nil)
        #expect(queue.items.count == 1)
    }

    @Test("Approve copies the new password, opens the URL, and marks opened")
    func approve() async throws {
        let (queue, pasteboard, opener) = try makeQueue()
        let id = try #require(try await queue.enqueue(credential: credential()))
        let newValue = try #require(queue.items.first?.newPassword.reveal())

        queue.approve(itemID: id)

        #expect(pasteboard.value == newValue)            // 1. copied
        #expect(opener.opened == [URL(string: "https://acme.example/.well-known/change-password")!])  // 2. opened
        #expect(queue.items.first?.status == .opened)    // 3. status
    }

    @Test("Approve is only valid from pending; done/skip transitions")
    func transitions() async throws {
        let (queue, _, _) = try makeQueue()
        let id = try #require(try await queue.enqueue(credential: credential()))

        queue.markDone(itemID: id)                       // not allowed from pending
        #expect(queue.items.first?.status == .pending)

        queue.approve(itemID: id)
        #expect(queue.items.first?.status == .opened)
        queue.approve(itemID: id)                        // no-op now
        #expect(queue.items.first?.status == .opened)

        queue.markDone(itemID: id)
        #expect(queue.items.first?.status == .done)
    }

    @Test("Skip moves a pending item to skipped")
    func skip() async throws {
        let (queue, _, _) = try makeQueue()
        let id = try #require(try await queue.enqueue(credential: credential()))
        queue.skip(itemID: id)
        #expect(queue.items.first?.status == .skipped)
    }

    @Test("cancelOpen backs an opened item out to pending")
    func cancelOpen() async throws {
        let (queue, _, _) = try makeQueue()
        let id = try #require(try await queue.enqueue(credential: credential()))
        queue.approve(itemID: id)
        #expect(queue.items.first?.status == .opened)
        queue.cancelOpen(itemID: id)
        #expect(queue.items.first?.status == .pending)
        // No-op from other states.
        queue.skip(itemID: id)
        queue.cancelOpen(itemID: id)
        #expect(queue.items.first?.status == .skipped)
    }

    @Test("Regenerate replaces the new password")
    func regenerate() async throws {
        let (queue, _, _) = try makeQueue()
        let id = try #require(try await queue.enqueue(credential: credential()))
        let before = try #require(queue.items.first?.newPassword.reveal())
        try queue.regenerate(itemID: id)
        let after = try #require(queue.items.first?.newPassword.reveal())
        #expect(before != after)
    }

    @Test("Enqueue with passphrase:true builds the item with a multi-word value")
    func enqueuePassphrase() async throws {
        let (queue, _, _) = try makeQueue()
        _ = try #require(try await queue.enqueue(credential: credential(), passphrase: true))
        let pw = try #require(queue.items.first?.newPassword.reveal())
        #expect(pw.split(separator: "-").count == 6)   // diceware, default separator
    }

    @Test("Enqueue resolves the change URL and fills it in (placeholder upgraded)")
    func enqueueResolvesURL() async throws {
        // Stub resolves to a well-known URL; after enqueue the item carries it,
        // not the site-root placeholder it was appended with.
        let (queue, _, _) = try makeQueue()
        _ = try #require(try await queue.enqueue(credential: credential()))
        #expect(queue.items.first?.changeURL?.absoluteString == "https://acme.example/.well-known/change-password")
    }

    @Test("Enqueue targets the real host (subdomain), not the collapsed eTLD+1")
    func enqueueUsesHostNotRegistrableDomain() async throws {
        let (queue, _, _) = try makeQueue()
        let cred = ImportedCredential(
            source: .arc, title: nil,
            rawURL: "https://amerihome.loanadministration.com/login",
            registrableDomain: "loanadministration.com",
            host: "amerihome.loanadministration.com",
            username: "me", password: Secret("x"), notes: nil, hasTOTP: false
        )
        let id = try #require(try queue.appendPending(credential: cred))
        let item = try #require(queue.items.first { $0.id == id })
        // Display + cleanup use the real host; eTLD+1 stays for grouping.
        #expect(item.site == "amerihome.loanadministration.com")
        #expect(item.registrableDomain == "loanadministration.com")
        // The change page opens the actual subdomain, not loanadministration.com.
        #expect(item.changeURL?.absoluteString == "https://amerihome.loanadministration.com/")
    }

    @Test("appendPending shows the item instantly; resolveChangeURL upgrades it later")
    func appendThenResolve() async throws {
        let (queue, _, _) = try makeQueue()                 // stub resolves to well-known
        let id = try #require(try queue.appendPending(credential: credential()))
        // Visible at once, with a usable placeholder and not-yet-resolved source.
        #expect(queue.items.count == 1)
        #expect(queue.items.first?.changeURL != nil)
        #expect(queue.resolutionSources[id] == .siteRoot)
        // The probe upgrades the URL and records the real source.
        await queue.resolveChangeURL(itemID: id)
        #expect(queue.items.first?.changeURL?.absoluteString == "https://acme.example/.well-known/change-password")
        #expect(queue.resolutionSources[id] == .wellKnown)
    }

    @Test("Regenerate as a passphrase replaces with a multi-word value")
    func regeneratePassphrase() async throws {
        let (queue, _, _) = try makeQueue()
        let id = try #require(try await queue.enqueue(credential: credential()))
        let before = try #require(queue.items.first?.newPassword.reveal())
        try queue.regeneratePassphrase(itemID: id, wordCount: 6)
        let after = try #require(queue.items.first?.newPassword.reveal())
        #expect(after != before)
        #expect(!after.isEmpty)
        #expect(after.split(separator: "-").count == 6)   // default separator
    }

    @Test("Site-root resolution is flagged as not confident")
    func siteRootNotConfident() async throws {
        let resolution = ResetResolution(url: URL(string: "https://acme.example/")!, source: .siteRoot)
        let (queue, _, _) = try makeQueue(resolution: resolution)
        let id = try #require(try await queue.enqueue(credential: credential()))
        #expect(queue.isChangeURLConfident(id) == false)
    }

    @Test("Resolution source (incl. well-known support) is recorded per item")
    func resolutionSourceRecorded() async throws {
        for source in [ResetSource.wellKnown, .fallbackMap, .siteRoot] {
            let res = ResetResolution(url: URL(string: "https://acme.example/x")!, source: source)
            let (queue, _, _) = try makeQueue(resolution: res)
            let id = try #require(try await queue.enqueue(credential: credential()))
            #expect(queue.resolutionSources[id] == source)
            #expect(queue.isChangeURLConfident(id) == (source != .siteRoot))
        }
    }

    @Test("Hash-based clear wipes only on a matching value")
    func clearIfMatchesHash() {
        let pb = FakePasteboard()
        let clip = Clipboard(pasteboard: pb)
        clip.copy(Secret("abc123"))
        let digest = Data(SHA256.hash(data: Data("abc123".utf8)))
        // Different contents -> no clear.
        pb.value = "different"
        #expect(clip.clearIfMatchesHash(digest) == false)
        #expect(pb.value == "different")
        // Matching contents -> clear.
        pb.value = "abc123"
        #expect(clip.clearIfMatchesHash(digest) == true)
        #expect(pb.value == nil)
    }

    @Test("Auto-clear timer wipes the clipboard after approve")
    func autoClearFires() async throws {
        let (queue, pasteboard, _) = try makeQueue(clearAfter: .milliseconds(40))
        let id = try #require(try await queue.enqueue(credential: credential()))
        let value = try #require(queue.items.first?.newPassword.reveal())
        queue.approve(itemID: id)
        #expect(pasteboard.value == value)
        try await Task.sleep(for: .milliseconds(250))
        #expect(pasteboard.value == nil)   // auto-cleared
    }

    @Test("Auto-clear leaves a clipboard the user has since overwritten")
    func autoClearRespectsUser() async throws {
        let (queue, pasteboard, _) = try makeQueue(clearAfter: .milliseconds(40))
        let id = try #require(try await queue.enqueue(credential: credential()))
        queue.approve(itemID: id)
        pasteboard.value = "something the user copied"
        try await Task.sleep(for: .milliseconds(250))
        #expect(pasteboard.value == "something the user copied")
    }

    @Test("Editing the new password replaces it with the typed value")
    func setNewPassword() async throws {
        let (queue, _, _) = try makeQueue()
        let id = try #require(try await queue.enqueue(credential: credential()))
        queue.setNewPassword(itemID: id, to: "Custom-Pw-123")
        #expect(queue.items.first?.newPassword.reveal() == "Custom-Pw-123")
    }

    @Test("openChangePage re-opens the URL without changing status or the clipboard")
    func openChangePage() async throws {
        let (queue, pasteboard, opener) = try makeQueue()
        let id = try #require(try await queue.enqueue(credential: credential()))
        queue.openChangePage(itemID: id)
        #expect(opener.opened == [URL(string: "https://acme.example/.well-known/change-password")!])
        #expect(queue.items.first?.status == .pending)   // status untouched
        #expect(pasteboard.value == nil)                 // nothing copied
    }

    @Test("copySecret puts the plaintext on the clipboard without opening anything")
    func copySecretWritesValue() async throws {
        let (queue, pasteboard, opener) = try makeQueue()
        queue.copySecret(Secret("paste-this-current-password"))
        #expect(pasteboard.value == "paste-this-current-password")
        #expect(opener.opened.isEmpty)   // copy buttons never navigate
    }

    @Test("copySecret schedules the same hash-based auto-clear as approve")
    func copySecretAutoClears() async throws {
        let (queue, pasteboard, _) = try makeQueue(clearAfter: .milliseconds(40))
        queue.copySecret(Secret("temp-current-pw"))
        #expect(pasteboard.value == "temp-current-pw")
        try await Task.sleep(for: .milliseconds(250))
        #expect(pasteboard.value == nil)   // auto-cleared by the scheduled timer
    }
}
