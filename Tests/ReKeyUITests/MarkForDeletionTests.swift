import Testing
import Foundation
import Model
import CleanupScript
@testable import ReKeyUI

// AppModel is @MainActor, so these run serialized on the main actor; `.serialized`
// keeps the UserDefaults-touching integration tests from interleaving.
@MainActor
@Suite("Mark for deletion (cull)", .serialized)
struct MarkForDeletionTests {

    // MARK: - Pure planner core (safe `--site`/`--username` vs manual id-step)

    private func target(_ source: BrowserSource, _ site: String, _ user: String) -> CleanupTarget {
        CleanupTarget(source: source, site: site, username: user)
    }

    @Test("isReKeyCleanupScript accepts a generated script and rejects an unrelated file")
    func recognizesReKeyScript() {
        let real = CleanupPlanner.script(commands: ["rekey-cleanup delete --browser chrome --site x.com"], confirm: false)
        #expect(AppModel.isReKeyCleanupScript(real))
        #expect(!AppModel.isReKeyCleanupScript("#!/bin/sh\necho not mine\n"))
        #expect(!AppModel.isReKeyCleanupScript(""))
    }

    @Test("A Chromium login with a username deletes precisely by --username")
    func chromiumPreciseDelete() {
        // Even with siblings on the site, a username-scoped delete is safe.
        let plan = AppModel.cleanupPlan(targets: [target(.chrome, "x.com", "u@e.com")]) { _, _ in 3 }
        #expect(plan.manualSites.isEmpty)
        #expect(plan.safeCommands == ["rekey-cleanup delete --browser chrome --site x.com --username u@e.com"])
    }

    @Test("A blank-username login on a multi-login site needs a manual id step")
    func blankUsernameSiblingsManual() {
        // 1 marked, 3 total on the site → a --site delete would take the other 2.
        let plan = AppModel.cleanupPlan(targets: [target(.chrome, "x.com", "")]) { _, _ in 3 }
        #expect(plan.safeCommands.isEmpty)
        #expect(plan.manualSites.count == 1)
        #expect(plan.manualSites.first?.domain == "x.com")
        #expect(plan.manualSites.first?.loginCount == 3)
    }

    @Test("A blank-username login that's the only one on its site deletes by --site")
    func blankUsernameSoleSafe() {
        let plan = AppModel.cleanupPlan(targets: [target(.chrome, "x.com", "")]) { _, _ in 1 }
        #expect(plan.manualSites.isEmpty)
        #expect(plan.safeCommands == ["rekey-cleanup delete --browser chrome --site x.com"])
    }

    @Test("Firefox deletes by site; safe only when every login on the site is marked")
    func firefoxSiteLevel() {
        // Encrypted usernames → always site-level. Both logins marked of 2 total → safe.
        let allMarked = AppModel.cleanupPlan(
            targets: [target(.firefox, "x.com", "a"), target(.firefox, "x.com", "b")]
        ) { _, _ in 2 }
        #expect(allMarked.manualSites.isEmpty)
        #expect(allMarked.safeCommands == ["rekey-cleanup delete --browser firefox --site x.com"])

        // Only 1 marked of 3 → manual (a site delete would catch the unmarked 2).
        let partial = AppModel.cleanupPlan(targets: [target(.firefox, "x.com", "a")]) { _, _ in 3 }
        #expect(partial.safeCommands.isEmpty)
        #expect(partial.manualSites.count == 1)
    }

    @Test("Apple Passwords can't be targeted by the tool — skipped, no command")
    func appleSkipped() {
        let plan = AppModel.cleanupPlan(targets: [target(.applePasswords, "x.com", "u")]) { _, _ in 1 }
        #expect(plan.safeCommands.isEmpty)
        #expect(plan.manualSites.isEmpty)
    }

    @Test("Duplicate targets collapse to one command")
    func dedup() {
        let plan = AppModel.cleanupPlan(
            targets: [target(.chrome, "x.com", "u"), target(.chrome, "x.com", "u")]
        ) { _, _ in 1 }
        #expect(plan.safeCommands == ["rekey-cleanup delete --browser chrome --site x.com --username u"])
    }

    // MARK: - AppModel integration

    // Clear ONLY our own key — wiping the shared fix-progress keys would clobber
    // a concurrently-yielded FixProgressTests run. AppModel loads and echoes the
    // other keys back unchanged, so they're left intact.
    private func clear() { UserDefaults.standard.removeObject(forKey: "rekey.deletionKeys") }
    private let csv = "name,url,username,password,note\nGitHub,https://github.com/,sean,pw,\n"

    @Test("Marking a login for deletion is per-browser — the same account elsewhere is untouched")
    func perBrowserMark() throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.chromiumSource = .chrome
        model.importData(Data(csv.utf8), displayName: "chrome.csv")
        let chrome = try #require(model.allCredentials.first { $0.source == .chrome })
        model.chromiumSource = .arc
        model.importData(Data(csv.utf8), displayName: "arc.csv")
        let arc = try #require(model.allCredentials.first { $0.source == .arc })

        model.markForDeletion(chrome)
        #expect(model.isMarkedForDeletion(chrome))
        #expect(!model.isMarkedForDeletion(arc))     // same account, other browser — not touched

        // Marking the Arc copy too produces a separate purge batch per browser.
        model.markForDeletion(arc)
        let script = model.deletionCleanupScript(confirm: false)
        #expect(script.contains("rekey-cleanup purge --browser chrome"))
        #expect(script.contains("rekey-cleanup purge --browser arc"))
        #expect(script.contains("github.com\tsean"))   // the account is a target under each browser
    }

    @Test("A marked blank-username login on a multi-login site builds a manual id-step script")
    func manualOnlyScript() throws {
        clear(); defer { clear() }
        let twoRows = "name,url,username,password,note\nGitHub,https://github.com/,sean,pw,\nGitHub,https://github.com/,,pw2,\n"
        let model = AppModel()
        model.chromiumSource = .chrome
        model.importData(Data(twoRows.utf8), displayName: "chrome.csv")
        let blank = try #require(model.allCredentials.first { $0.username.isEmpty })
        model.markForDeletion(blank)

        // A site-level delete would also remove the `sean` sibling, so there's no
        // safe purge target — only a commented id-based step.
        #expect(model.deletionPlan().safe.isEmpty)
        #expect(model.deletionManualSiteCount() == 1)
        let script = model.deletionCleanupScript(confirm: false)
        #expect(!script.contains("purge"))   // nothing safe to batch
        #expect(script.contains("Manual deletion"))
        #expect(script.contains("delete --browser chrome --id"))
    }

    @Test("A script can carry both a purge batch and a manual id-step")
    func mixedSafeAndManual() throws {
        clear(); defer { clear() }
        let csv = """
        name,url,username,password,note
        GitHub,https://github.com/,sean,pw,
        Example,https://example.com/,alice,pw,
        Example,https://example.com/,,pw2,
        """
        let model = AppModel()
        model.chromiumSource = .chrome
        model.importData(Data(csv.utf8), displayName: "chrome.csv")
        let github = try #require(model.allCredentials.first { $0.site == "github.com" })
        let blank = try #require(model.allCredentials.first { $0.username.isEmpty })
        model.markForDeletion(github)   // safe → purge batch
        model.markForDeletion(blank)    // blank username on a site with a named sibling → manual

        let script = model.deletionCleanupScript(confirm: true)
        #expect(script.contains("rekey-cleanup purge --browser chrome --confirm --tally \"$REKEY_TALLY\" <<'REKEY_TARGETS'"))
        #expect(script.contains("github.com\tsean"))           // safe target batched
        #expect(script.contains("Manual deletion"))            // manual section present
        #expect(script.contains("rekey-cleanup list --browser chrome --site example.com"))
    }

    @Test("Appendable script is just purge blocks — no shebang, tally, or grand total")
    func appendableScript() throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.chromiumSource = .chrome
        model.importData(Data(csv.utf8), displayName: "chrome.csv")
        let cred = try #require(model.allCredentials.first)
        model.markForDeletion(cred)
        let body = model.deletionAppendableScript(confirm: true)
        #expect(body.contains("rekey-cleanup purge --browser chrome --confirm <<'REKEY_TARGETS'"))   // no --tally
        #expect(body.contains("github.com\tsean"))
        #expect(!body.contains("#!/bin/sh"))     // no header
        #expect(!body.contains("REKEY_TALLY"))   // no tally machinery
        #expect(!body.contains("awk"))           // no grand total
    }

    @Test("forceManual emits a --no-username purge block for a Chromium no-username site")
    func forceManualScript() throws {
        clear(); defer { clear() }
        let csv = """
        name,url,username,password,note
        Example,https://example.com/,alice,pw,
        Example,https://example.com/,,pw2,
        """
        let model = AppModel()
        model.chromiumSource = .chrome
        model.importData(Data(csv.utf8), displayName: "chrome.csv")
        let blank = try #require(model.allCredentials.first { $0.username.isEmpty })
        model.markForDeletion(blank)
        #expect(model.deletionForceableManualSiteCount() == 1)

        // Off: stays a manual id-step.
        let plain = model.deletionCleanupScript(confirm: true, forceManual: false)
        #expect(!plain.contains("--no-username"))
        #expect(plain.contains("Manual deletion"))

        // On: a precise --no-username purge block, and no leftover manual section.
        let forced = model.deletionCleanupScript(confirm: true, forceManual: true)
        #expect(forced.contains("rekey-cleanup purge --browser chrome --no-username --confirm --tally \"$REKEY_TALLY\" <<'REKEY_TARGETS'"))
        #expect(forced.contains("example.com"))
        #expect(!forced.contains("Manual deletion"))
    }

    @Test("Firefox per-site classification is independent across sites")
    func firefoxMultiSite() {
        // x.com: 1 of 2 marked → manual. y.com: 1 of 1 marked → safe.
        let plan = AppModel.cleanupPlan(targets: [
            target(.firefox, "x.com", "a"),
            target(.firefox, "y.com", "b"),
        ]) { _, site in site == "x.com" ? 2 : 1 }
        #expect(plan.safeCommands == ["rekey-cleanup delete --browser firefox --site y.com"])
        #expect(plan.manualSites.count == 1)
        #expect(plan.manualSites.first?.domain == "x.com")
    }

    @Test("A mark for a login absent from the current import is invisible")
    func staleMarksInvisible() throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.chromiumSource = .chrome
        model.importData(Data(csv.utf8), displayName: "chrome.csv")
        let cred = try #require(model.allCredentials.first)
        model.markForDeletion(cred)
        #expect(model.markedForDeletionCount == 1)

        // Relaunch and import data that no longer contains that login.
        let reloaded = AppModel()
        reloaded.chromiumSource = .chrome
        reloaded.importData(Data("name,url,username,password,note\nOther,https://other.com/,bob,pw,\n".utf8),
                            displayName: "chrome.csv")
        #expect(reloaded.markedForDeletionCount == 0)                      // stale key not counted
        #expect(reloaded.deletionCleanupScript(confirm: false).isEmpty)    // and not in the script
    }

    @Test("markForDeletion([]) is a no-op")
    func emptyBulkMark() {
        clear(); defer { clear() }
        let model = AppModel()
        model.markForDeletion([])
        #expect(model.deletionKeys.isEmpty)
        #expect(model.markedForDeletionCount == 0)
    }

    @Test("Marks persist across a relaunch and build a purge target")
    func persistsAndScripts() throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.chromiumSource = .chrome
        model.importData(Data(csv.utf8), displayName: "chrome.csv")
        let cred = try #require(model.allCredentials.first)
        model.markForDeletion(cred)
        #expect(model.markedForDeletionCount == 1)
        let script = model.deletionCleanupScript(confirm: false)
        #expect(script.contains("rekey-cleanup purge --browser chrome"))
        #expect(script.contains("github.com\tsean"))

        // A fresh model re-imports the same data and still sees the mark (keyed by
        // site+username+source, not the volatile credential id).
        let reloaded = AppModel()
        reloaded.chromiumSource = .chrome
        reloaded.importData(Data(csv.utf8), displayName: "chrome.csv")
        let reCred = try #require(reloaded.allCredentials.first)
        #expect(reloaded.isMarkedForDeletion(reCred))
    }

    @Test("--confirm lands on the purge command when requested")
    func confirmFlag() throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.chromiumSource = .chrome
        model.importData(Data(csv.utf8), displayName: "chrome.csv")
        let cred = try #require(model.allCredentials.first)
        model.markForDeletion(cred)
        let confirmed = model.deletionCleanupScript(confirm: true)
        #expect(confirmed.contains("rekey-cleanup purge --browser chrome --confirm --tally \"$REKEY_TALLY\" <<'REKEY_TARGETS'"))
        #expect(confirmed.contains("Deleted %d login(s) across %d site(s)"))   // grand-total awk line
        // Preview mode: the purge command carries no --confirm, and the total reads "Would delete".
        let preview = model.deletionCleanupScript(confirm: false)
        #expect(preview.contains("rekey-cleanup purge --browser chrome --tally \"$REKEY_TALLY\" <<'REKEY_TARGETS'"))
        #expect(preview.contains("Would delete %d login(s) across %d site(s)"))
    }

    @Test("classifyCleanup drops Firefox usernames (encrypted store) → site-only targets")
    func classifyFirefoxSiteOnly() {
        let (safe, manual) = AppModel.classifyCleanup(targets: [target(.firefox, "x.com", "alice")]) { _, _ in 1 }
        #expect(manual.isEmpty)
        #expect(safe.count == 1)
        #expect(safe.first?.source == .firefox)
        #expect(safe.first?.site == "x.com")
        #expect(safe.first?.username == "")   // username dropped — Firefox can't filter by it
    }

    @Test("classifyCleanup keeps a Chromium username and dedups identical targets")
    func classifyChromiumKeepsUsername() {
        let (safe, _) = AppModel.classifyCleanup(targets: [
            target(.chrome, "x.com", "u"),
            target(.chrome, "x.com", "u"),
        ]) { _, _ in 5 }
        #expect(safe.count == 1)
        #expect(safe.first?.username == "u")
    }

    @Test("Bulk unmark clears only the passed-in subset, leaving other marks")
    func bulkUnmarkScoped() throws {
        clear(); defer { clear() }
        let csv = """
        name,url,username,password,note
        GitHub,https://github.com/,sean,pw,
        Example,https://example.com/,alice,pw,
        Other,https://other.com/,bob,pw,
        """
        let model = AppModel()
        model.chromiumSource = .chrome
        model.importData(Data(csv.utf8), displayName: "chrome.csv")
        model.markForDeletion(model.allCredentials)
        #expect(model.markedForDeletionCount == 3)

        // Clear just the two non-GitHub logins (e.g. a "github" search would leave
        // only GitHub shown — this is the inverse: clear everything else).
        let subset = model.allCredentials.filter { $0.site != "github.com" }
        model.unmarkForDeletion(subset)
        #expect(model.markedForDeletionCount == 1)
        let github = try #require(model.allCredentials.first { $0.site == "github.com" })
        #expect(model.isMarkedForDeletion(github))   // the unscoped mark survives
    }

    @Test("Clear all marks empties the selection and the script")
    func clearAll() throws {
        clear(); defer { clear() }
        let model = AppModel()
        model.importData(Data(csv.utf8), displayName: "chrome.csv")
        let cred = try #require(model.allCredentials.first)
        model.markForDeletion(cred)
        #expect(model.markedForDeletionCount == 1)
        model.unmarkAllForDeletion()
        #expect(model.markedForDeletionCount == 0)
        #expect(model.deletionCleanupScript(confirm: false).isEmpty)
    }

    // MARK: - Reconcile marks on re-import (auto-clear vanished logins)

    @Test("Re-importing a browser drops marks for logins it no longer holds")
    func reconcileDropsVanished() throws {
        clear(); defer { clear() }
        let two = """
        name,url,username,password,note
        GitHub,https://github.com/,sean,pw,
        Example,https://example.com/,alice,pw,
        """
        let model = AppModel(); model.chromiumSource = .chrome
        model.importData(Data(two.utf8), displayName: "chrome.csv")
        model.markForDeletion(model.allCredentials)   // mark both
        #expect(model.markedForDeletionCount == 2)

        // A fresh Chrome export that no longer has example.com (it was culled).
        let reloaded = AppModel(); reloaded.chromiumSource = .chrome
        reloaded.importData(Data(csv.utf8), displayName: "chrome.csv")   // github only
        reloaded.reconcileDeletionMarks()
        let github = try #require(reloaded.allCredentials.first)
        #expect(reloaded.isMarkedForDeletion(github))    // still-present login keeps its mark
        #expect(reloaded.deletionKeys.count == 1)        // vanished mark dropped from the store, not just hidden
    }

    @Test("Reconcile leaves marks for a browser absent from the current import")
    func reconcileKeepsAbsentBrowser() throws {
        clear(); defer { clear() }
        let model = AppModel(); model.chromiumSource = .chrome
        model.importData(Data(csv.utf8), displayName: "chrome.csv")     // github chrome
        let github = try #require(model.allCredentials.first)
        model.markForDeletion(github)

        // New session imports ONLY Firefox — Chrome wasn't re-exported, so its mark must stay.
        let reloaded = AppModel()
        let firefox = """
        url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged
        https://other.com/,bob,pw,,https://other.com,{11111111-1111-1111-1111-111111111111},0,0,0
        """
        reloaded.importData(Data(firefox.utf8), displayName: "firefox.csv")
        reloaded.reconcileDeletionMarks()
        #expect(reloaded.deletionKeys.contains(AppModel.deletionKey(for: github)))   // kept (chrome not re-imported)
        #expect(reloaded.markedForDeletionCount == 0)                                // just not counted (absent here)
    }

    // MARK: - Append consolidates the grand total

    @Test("Appending to a saved script rewrites one trailing grand total")
    func appendConsolidatesTotal() throws {
        clear(); defer { clear() }
        let model = AppModel(); model.chromiumSource = .chrome
        model.importData(Data(csv.utf8), displayName: "chrome.csv")     // github chrome
        model.markForDeletion(try #require(model.allCredentials.first))
        let saved = model.deletionCleanupScript(confirm: true)
        #expect(saved.components(separatedBy: AppModel.cullTotalSentinel).count == 2)   // exactly one total

        // A second session marks a different login and appends to the saved file.
        model.unmarkAllForDeletion()
        let m2 = AppModel(); m2.chromiumSource = .chrome
        m2.importData(Data("name,url,username,password,note\nExample,https://example.com/,alice,pw,\n".utf8),
                      displayName: "chrome.csv")
        m2.markForDeletion(try #require(m2.allCredentials.first))
        let appended = try #require(m2.deletionScriptAppending(to: saved, confirm: true))

        #expect(appended.components(separatedBy: AppModel.cullTotalSentinel).count == 2)   // still one total
        let total = AppModel.cullTotalLine(confirm: true)
        #expect(appended.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix(total))  // …at the very bottom
        #expect(appended.contains("github.com\tsean"))      // original target preserved
        #expect(appended.contains("example.com\talice"))    // new session's target spliced in above the total
        // Both blocks feed the same tally, so the single bottom total sums them.
        #expect(appended.components(separatedBy: "--tally \"$REKEY_TALLY\"").count == 3)   // 2 purge blocks
    }

    @Test("Appending to a script with no grand total falls back to plain blocks")
    func appendLegacyFallback() throws {
        clear(); defer { clear() }
        let model = AppModel(); model.chromiumSource = .chrome
        model.importData(Data(csv.utf8), displayName: "chrome.csv")
        model.markForDeletion(try #require(model.allCredentials.first))
        let legacy = "#!/bin/sh\necho hi\n"   // no REKEY_TALLY setup, no sentinel
        let out = try #require(model.deletionScriptAppending(to: legacy, confirm: true))
        #expect(out.hasPrefix("#!/bin/sh\necho hi"))
        #expect(out.contains("github.com\tsean"))
        #expect(!out.contains(AppModel.cullTotalSentinel))   // no consolidated total invented
        #expect(!out.contains("--tally"))                    // plain, self-summarizing blocks
    }
}
