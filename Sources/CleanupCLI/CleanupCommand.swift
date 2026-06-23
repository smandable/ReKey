import Foundation
import Model
import BrowserStore

// CleanupCLI — the rekey-cleanup command's logic, extracted from the executable
// `main` into a library so it is unit-testable. The executable target is a thin
// entrypoint that calls `CleanupCommand.run` with the real argv, running-browser
// checker, and store factory.
//
// Safety model (unchanged from the original tool):
//   • Dry-run by DEFAULT. `delete`/`purge` show what they would remove and do
//     nothing unless you pass --confirm.
//   • Refuses to delete unless you give a filter (--site / --username / --id).
//   • Refuses to write while the target browser is running.
//   • Backs up the store (incl. WAL/SHM sidecars) before any write.
//   • Never decrypts anything: it matches only on plaintext index fields.
//   • Apple Passwords is unsupported (no third-party delete API).

public enum CleanupCommand {
    /// Builds the right `LoginStore` for a (browser, store file). Injectable so
    /// tests can substitute a synthetic store.
    public typealias StoreFactory = (BrowserSource, URL) throws -> any LoginStore

    /// Run the CLI against an explicit argument list (the program name already
    /// dropped) with injected collaborators, returning the process exit code.
    ///
    /// - Parameters:
    ///   - arguments: argv without the executable name.
    ///   - runningChecker: decides whether the target browser is open (a write is
    ///     refused while it is — the classic corruption path).
    ///   - makeStore: builds the `LoginStore`; defaults to the real factory.
    ///   - readTargets: supplies `purge` stdin lines; defaults to reading stdin.
    ///   - out / err: stdout / stderr sinks; default to print / standard error.
    public static func run(
        arguments: [String],
        runningChecker: RunningBrowserChecking,
        makeStore: StoreFactory = LoginStoreFactory.make,
        readTargets: () -> [String] = CleanupCommand.readStdinLines,
        out: (String) -> Void = { print($0) },
        err: (String) -> Void = { FileHandle.standardError.write(Data(($0 + "\n").utf8)) }
    ) -> Int32 {
        let raw = arguments
        var command: String?
        var opts: [String: [String]] = [:]
        let flagOnly: Set<String> = ["--confirm", "--help", "-h", "--no-username"]

        var i = 0
        while i < raw.count {
            let arg = raw[i]
            if arg.hasPrefix("--") || arg == "-h" {
                if flagOnly.contains(arg) {
                    opts[arg, default: []].append("true"); i += 1
                } else {
                    // A value flag binds the NEXT token as its value — greedily,
                    // even if that token starts with "--". This is deliberate: a
                    // crafted CSV value like "--confirm" that reaches here is
                    // swallowed as the (non-matching) value, never promoted to a
                    // real flag. The only cost is that a genuinely value-less flag
                    // eats the following token, which always fails safe (toward a
                    // dry run / no match), never toward an unintended delete.
                    if i + 1 < raw.count {
                        opts[arg, default: []].append(raw[i + 1]); i += 2
                    } else {
                        opts[arg, default: []].append(""); i += 1
                    }
                }
            } else if command == nil {
                command = arg; i += 1
            } else {
                i += 1
            }
        }

        func opt(_ key: String) -> String? { opts["--" + key]?.last }
        func optList(_ key: String) -> [String] { opts["--" + key] ?? [] }
        func flag(_ key: String) -> Bool { opts["--" + key] != nil }

        if command == nil || command == "help" || flag("help") || flag("h") {
            out(usageText)
            return command == nil ? 1 : 0
        }

        guard command == "list" || command == "delete" || command == "purge" else {
            err("Unknown command '\(command!)'. Try: rekey-cleanup help")
            return 1
        }

        // Resolve browser + store path.
        guard let browserName = opt("browser"), let browser = BrowserSource(rawValue: browserName) else {
            err("Pass --browser <chrome|arc|brave|edge|opera|vivaldi|chromium|firefox>.")
            return 1
        }
        guard BrowserPaths.isSupported(browser) else {
            err("\(browser.displayName) isn't supported by this tool.")
            return 1
        }

        let storeURL: URL
        if let path = opt("path") {
            storeURL = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
        } else if let resolved = BrowserPaths.defaultStoreURL(for: browser, profile: opt("profile")) {
            storeURL = resolved
        } else {
            err("Couldn't locate \(browser.displayName)'s store. Pass --path to the Login Data / logins.json file.")
            return 1
        }

        let filter = LoginFilter(
            site: opt("site"),
            username: opt("username"),
            identifiers: Set(optList("id"))
        )

        do {
            let store = try makeStore(browser, storeURL)
            try store.validate()

            switch command {
            case "list":
                let logins = try store.list(matching: filter)
                out("\(browser.displayName) — \(storeURL.path)")
                emitTable(logins, out: out)
                out("\n\(logins.count) login(s)\(filter.isEmpty ? "" : " matching filter").")
                if logins.isEmpty { printUnmatchedHint(store: store, filter: filter, browser: browser, out: out) }
                return 0

            case "delete":
                if filter.isEmpty {
                    err("Refusing to delete without a filter. Use --site, --username, or --id (run `list` first to see ids).")
                    return 1
                }
                let rawMatches = try store.list(matching: filter)
                // --site is an unanchored origin SUBSTRING in the store filter, so
                // on a DELETE re-anchor to the exact host (or a subdomain of it) —
                // the same guard `purge` uses — so a loose --site can't sweep an
                // unrelated domain (e.g. "casino.com" catching "nodepositcasino.com").
                // A precise --id delete bypasses anchoring (it's already exact).
                let matches: [StoredLogin]
                if let site = filter.site, !site.isEmpty, filter.identifiers.isEmpty {
                    matches = rawMatches.filter { PurgeTargets.originBelongsToSite($0.origin, site: site) }
                } else {
                    matches = rawMatches
                }

                // Compact label so a batch cleanup reads as one tidy line per site
                // instead of a repeated header + table + warning block.
                let site = filter.site ?? ""
                let label = site.isEmpty ? browser.displayName : "\(browser.rawValue) · \(site)"

                if matches.isEmpty {
                    out("\(label): no saved login matches — nothing to delete.")
                    if rawMatches.isEmpty {
                        printUnmatchedHint(store: store, filter: filter, browser: browser, out: out)
                    } else {
                        // Substring hits existed but none was on the exact host — say
                        // so, since `delete` anchors --site to a full host on purpose.
                        out("    (\(rawMatches.count) login(s) loosely contain \"\(site)\" but aren't on that exact host — `delete` matches the full host. Target one precisely with --id from `list`.)")
                    }
                    return 0
                }

                // A lone match by site/username (no --id) is almost always the user's
                // CURRENT login — the browser updated it in place, leaving no old
                // duplicate. So in a cleanup there's nothing to remove: report it on one
                // calm line and don't delete. (A precise --id delete isn't a lone broad
                // match, so it falls through and runs.)
                if CleanupHint.isLoneBroadMatch(matchCount: matches.count, filter: filter) {
                    let m = matches[0]
                    out("\(label): only your current login is saved (id \(m.id)) — no older duplicate, nothing to clean.")
                    if !flag("confirm") {
                        out("    (if you know a stale copy exists: \(CleanupHint.idForceCommand(login: m, filter: filter, browser: browser)))")
                    }
                    return 0
                }

                // 2+ matches, or a precise --id delete: show the detail.
                out("\(browser.displayName) — \(storeURL.path)")
                emitTable(matches, out: out)

                // After anchoring, matches all belong to the site or a subdomain. If
                // they still span more than one host (i.e. subdomains), say so so an
                // over-broad filter is obvious before a --confirm.
                if filter.identifiers.isEmpty {
                    let hosts = Set(matches.map { host(ofOrigin: $0.origin) })
                    if hosts.count > 1 {
                        let sample = hosts.sorted().prefix(4).joined(separator: ", ")
                        out("\n⚠️  These \(matches.count) matches span \(hosts.count) different sites (\(sample)\(hosts.count > 4 ? ", …" : "")) — your --site value may be too broad. Target one with --id if it caught the wrong sites.")
                    }
                }

                if !flag("confirm") {
                    out("\nDRY RUN: \(matches.count) login(s) would be deleted.")
                    out("Re-run with --confirm to delete them (the browser must be quit first).")
                    return 0
                }

                // Real delete: guardrails. Ownership first (refuse a foreign file),
                // then the running-browser check as late as possible before the write
                // to keep the TOCTOU window minimal.
                guard Self.ownedByCurrentUser(storeURL) else {
                    err("\nRefusing to modify \(storeURL.path): it isn't owned by your user account.")
                    return 1
                }
                if runningChecker.isRunning(browser) {
                    err("\n\(browser.displayName) is running. Quit it completely, then re-run with --confirm.")
                    return 2
                }
                let backupDir = resolveBackupDir(opt: opt, browser: browser)
                // Delete exactly the (anchored) set we just displayed — what you see
                // is what gets removed, with no list/delete filter divergence.
                let outcome = try store.delete(matching: LoginFilter(identifiers: Set(matches.map(\.id))),
                                               backupDirectory: backupDir)
                out("\nBacked up to: \(outcome.backupPath.path)")
                out("Deleted \(outcome.deletedCount) login(s).")
                // Keep the recovery snapshots from piling up forever (best-effort).
                StoreBackup.pruneOldBackups(root: backupDir.deletingLastPathComponent())
                return 0

            case "purge":
                // Batch outright-delete: read "site<TAB>username" targets from stdin
                // (username optional). Unlike `delete`, there is NO lone-current-login
                // guard — purge means "remove these accounts entirely". One backup for
                // the whole batch, one summary line.
                let targets = PurgeTargets.parse(readTargets())
                guard !targets.isEmpty else {
                    err("\(browser.displayName): no targets on stdin — nothing to purge.")
                    return 1
                }
                // Optional cross-browser tally file: the cull script passes --tally and
                // sums these "<deleted> <sites>" lines into a grand total at the end.
                let tallyPath = opt("tally")
                func appendTally(_ count: Int, _ sites: Int) {
                    guard let tallyPath else { return }
                    let line = "\(count) \(sites)\n"
                    if let fh = FileHandle(forWritingAtPath: tallyPath) {
                        defer { try? fh.close() }
                        fh.seekToEndOfFile()
                        fh.write(Data(line.utf8))
                    } else {
                        try? line.write(toFile: tallyPath, atomically: true, encoding: .utf8)
                    }
                }
                // Collect every matching login once (deduped by id), so the whole
                // browser's deletions show in ONE table under ONE header.
                var byID: [String: StoredLogin] = [:]
                var sitesTouched = Set<String>()
                var matchedTargets = 0
                // --no-username: delete ONLY the no-username rows on each site (a
                // readable Chromium plaintext blank), never the named siblings — the
                // "force the manual no-username removals" path. Skips Firefox (its
                // usernames are encrypted, so blank can't be told from named).
                let noUsername = flag("no-username")
                for t in targets {
                    // LoginFilter.site is a broad origin SUBSTRING match, so re-anchor
                    // each hit to the target host (or a subdomain of it) — never delete
                    // a merely-similar domain (e.g. "nodepositcasino.com" for "casino.com").
                    let found = try store.list(matching: LoginFilter(site: t.site, username: t.username))
                        .filter { PurgeTargets.originBelongsToSite($0.origin, site: t.site) }
                        .filter { !noUsername || (!$0.usernameIsEncrypted && ($0.username ?? "").isEmpty) }
                    if !found.isEmpty {
                        matchedTargets += 1
                        sitesTouched.insert(t.site)
                        for m in found { byID[m.id] = m }
                    }
                }
                let clean = targets.count - matchedTargets
                let cleanNote = clean > 0 ? "; \(clean) already gone" : ""
                guard !byID.isEmpty else {
                    appendTally(0, 0)
                    out("\(browser.displayName): nothing to delete — all \(targets.count) target(s) already gone.")
                    return 0
                }
                let matched = byID.values.sorted { ($0.origin, $0.id) < ($1.origin, $1.id) }
                out("\(browser.displayName) — \(storeURL.path)")
                emitTable(matched, out: out)   // one consolidated table for the batch (grouped by site)

                if !flag("confirm") {
                    appendTally(matched.count, sitesTouched.count)
                    out("\nDRY RUN: would delete \(matched.count) login(s) across \(sitesTouched.count) site(s)\(cleanNote). Re-run with --confirm.")
                    return 0
                }
                guard Self.ownedByCurrentUser(storeURL) else {
                    err("\nRefusing to modify \(storeURL.path): it isn't owned by your user account.")
                    return 1
                }
                if runningChecker.isRunning(browser) {
                    err("\n\(browser.displayName) is running. Quit it completely, then re-run with --confirm.")
                    return 2
                }
                let backupDir = resolveBackupDir(opt: opt, browser: browser)
                let outcome = try store.delete(matching: LoginFilter(identifiers: Set(byID.keys)),
                                               backupDirectory: backupDir)
                StoreBackup.pruneOldBackups(root: backupDir.deletingLastPathComponent())
                appendTally(outcome.deletedCount, sitesTouched.count)
                out("\nBacked up to: \(outcome.backupPath.path)")
                out("Deleted \(outcome.deletedCount) login(s) across \(sitesTouched.count) site(s)\(cleanNote).")
                return 0

            default:
                return 1
            }
        } catch let error as LoginStoreError {
            err("\n\(error.description)")
            return 1
        } catch {
            err("\n\(error.localizedDescription)")
            return 1
        }
    }

    // MARK: - Backups

    /// The pre-delete backup directory: a custom --backup-dir, or the default
    /// recovery root (migrating the legacy name first). The returned URL's parent
    /// is the prune root.
    private static func resolveBackupDir(opt: (String) -> String?, browser: BrowserSource) -> URL {
        let backupRoot: URL
        if let custom = opt("backup-dir") {
            backupRoot = URL(fileURLWithPath: (custom as NSString).expandingTildeInPath)
        } else {
            // One-time: bring the recovery-snapshot dir up to the new name
            // (Rekey/Backups → ReKey/Backups) before we read or write it, so older
            // snapshots stay alongside this run's and get pruned together.
            StoreBackup.migrateLegacyBackupRoot()
            backupRoot = StoreBackup.defaultBackupRoot()
        }
        return StoreBackup.backupDirectory(root: backupRoot, label: browser.rawValue, timestamp: timestamp())
    }

    // MARK: - stdin

    /// Read every line from stdin (newlines stripped) — the `purge` target source.
    public static func readStdinLines() -> [String] {
        var lines: [String] = []
        while let line = readLine(strippingNewline: true) { lines.append(line) }
        return lines
    }

    // MARK: - Output helpers

    /// Whether the store file is owned by the current user. A misdirected --path
    /// could otherwise have rekey-cleanup rewrite another user's (or a system) file
    /// the process merely has write permission to — so refuse anything we don't own.
    static func ownedByCurrentUser(_ url: URL) -> Bool {
        guard let owner = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.ownerAccountID] as? NSNumber
        else { return false }
        return owner.uintValue == UInt(getuid())
    }

    /// Host of a stored login's origin URL, for the over-match (multi-site) warning.
    static func host(ofOrigin origin: String) -> String {
        URLComponents(string: origin)?.host ?? origin
    }

    /// After an empty exact-filter result, check whether the same site has logins
    /// under a different/blank username or id and print a one-line hint if so — so a
    /// silent miss (e.g. a blank-username entry skipped by `--username`) is visible.
    static func printUnmatchedHint(store: any LoginStore, filter: LoginFilter,
                                   browser: BrowserSource, out: (String) -> Void) {
        // Only worth a second query when the filter was narrower than site-only.
        guard let site = filter.site, !site.isEmpty,
              (filter.username?.isEmpty == false) || !filter.identifiers.isEmpty else { return }
        let siteMatches = (try? store.list(matching: LoginFilter(site: site)))?.count ?? 0
        if let hint = CleanupHint.unmatchedFilter(filter: filter, browser: browser, siteMatchCount: siteMatches) {
            out(hint)
        }
    }

    static func emitTable(_ logins: [StoredLogin], out: (String) -> Void) {
        guard !logins.isEmpty else { return }
        let df = DateFormatter()
        df.locale = Locale(identifier: "en_US_POSIX")
        df.dateFormat = "yyyy-MM-dd"
        out("")
        out("  #  id           origin                                   username")
        out("  -  -----------  ---------------------------------------  --------------------")
        for (index, login) in logins.enumerated() {
            let id = login.id.padding(toLength: 11, withPad: " ", startingAt: 0)
            let origin = String(login.origin.prefix(39)).padding(toLength: 39, withPad: " ", startingAt: 0)
            let user = login.usernameIsEncrypted ? "(encrypted)" : (login.username ?? "")
            let created = login.createdAt.map { " · created \(df.string(from: $0))" } ?? ""
            out(String(format: "  %d  %@  %@  %@%@", index + 1, id, origin, user, created))
        }
    }

    static func timestamp() -> String {
        let df = DateFormatter()
        // Pin locale + calendar so the fixed-format backup-directory name is stable
        // regardless of the user's locale (e.g. non-Gregorian calendars).
        df.locale = Locale(identifier: "en_US_POSIX")
        df.calendar = Calendar(identifier: .gregorian)
        df.dateFormat = "yyyyMMdd-HHmmss"
        // Append a short random suffix so two runs in the same second never collide
        // on a backup directory (StoreBackup also refuses a non-empty target).
        return df.string(from: Date()) + "-" + String(UUID().uuidString.prefix(6))
    }

    static let usageText = """
    rekey-cleanup — delete stale saved logins from a browser's store (opt-in, separate from ReKey.app).

    USAGE
      rekey-cleanup list   --browser <name> [--profile <p>] [--path <file>] [--site <s>] [--username <u>] [--id <id>]
      rekey-cleanup delete --browser <name> [filters] [--confirm] [--backup-dir <dir>]

    BROWSERS
      chrome, arc, brave, edge, opera, vivaldi, chromium, firefox
      (Apple Passwords is unsupported — no third-party delete API.)

    FILTERS (delete requires at least one)
      --site <substr>     for `list`, an origin/host substring; for `delete`, anchored to the full host (or a subdomain)
      --username <u>      exact username (Chromium only; Firefox usernames are encrypted)
      --id <identifier>   target a specific row/guid (repeatable; see `list`)

    SAFETY
      • `delete` is a DRY RUN unless you pass --confirm.
      • Writing is refused while the browser is running — quit it first.
      • The store is backed up before any delete (default: ~/Library/Application Support/ReKey/Backups).
      • Nothing is ever decrypted; matching uses plaintext fields only.

    EXAMPLES
      rekey-cleanup list   --browser chrome --site github.com
      rekey-cleanup delete --browser chrome --site github.com --username old@example.com
      rekey-cleanup delete --browser firefox --id '{xxxxxxxx-....}' --confirm
    """
}
