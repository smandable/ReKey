import Foundation
import Model
import BrowserStore

// rekey-cleanup — a SEPARATE, opt-in tool to delete stale saved logins from a
// browser's store. It is deliberately not part of the sandboxed Rekey.app.
//
// Safety model:
//   • Dry-run by DEFAULT. `delete` shows what it would remove and does nothing
//     unless you pass --confirm.
//   • Refuses to delete unless you give a filter (--site / --username / --id).
//   • Refuses to write while the target browser is running.
//   • Backs up the store (incl. WAL/SHM sidecars) before any write.
//   • Never decrypts anything: it matches only on plaintext index fields.
//   • Apple Passwords is unsupported (no third-party delete API).

let runningChecker: RunningBrowserChecking = SystemRunningBrowserChecker()

func run() -> Int32 {
    let raw = Array(CommandLine.arguments.dropFirst())
    var command: String?
    var opts: [String: [String]] = [:]
    let flagOnly: Set<String> = ["--confirm", "--help", "-h"]

    var i = 0
    while i < raw.count {
        let arg = raw[i]
        if arg.hasPrefix("--") || arg == "-h" {
            if flagOnly.contains(arg) {
                opts[arg, default: []].append("true"); i += 1
            } else {
                opts[arg, default: []].append(i + 1 < raw.count ? raw[i + 1] : ""); i += 2
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
        printUsage()
        return command == nil ? 1 : 0
    }

    guard command == "list" || command == "delete" else {
        FileHandle.standardError.write(Data("Unknown command '\(command!)'. Try: rekey-cleanup help\n".utf8))
        return 1
    }

    // Resolve browser + store path.
    guard let browserName = opt("browser"), let browser = BrowserSource(rawValue: browserName) else {
        printErr("Pass --browser <chrome|arc|brave|edge|opera|vivaldi|chromium|firefox>.")
        return 1
    }
    guard BrowserPaths.isSupported(browser) else {
        printErr("\(browser.displayName) isn't supported by this tool.")
        return 1
    }

    let storeURL: URL
    if let path = opt("path") {
        storeURL = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
    } else if let resolved = BrowserPaths.defaultStoreURL(for: browser, profile: opt("profile")) {
        storeURL = resolved
    } else {
        printErr("Couldn't locate \(browser.displayName)'s store. Pass --path to the Login Data / logins.json file.")
        return 1
    }

    let filter = LoginFilter(
        site: opt("site"),
        username: opt("username"),
        identifiers: Set(optList("id"))
    )

    do {
        let store = try LoginStoreFactory.make(browser: browser, storeURL: storeURL)
        try store.validate()

        switch command {
        case "list":
            let logins = try store.list(matching: filter)
            print("\(browser.displayName) — \(storeURL.path)")
            printTable(logins)
            print("\n\(logins.count) login(s)\(filter.isEmpty ? "" : " matching filter").")
            return 0

        case "delete":
            if filter.isEmpty {
                printErr("Refusing to delete without a filter. Use --site, --username, or --id (run `list` first to see ids).")
                return 1
            }
            let matches = try store.list(matching: filter)
            print("\(browser.displayName) — \(storeURL.path)")
            printTable(matches)
            if matches.isEmpty {
                print("\nNo logins match the filter; nothing to delete.")
                return 0
            }

            if !flag("confirm") {
                print("\nDRY RUN: \(matches.count) login(s) would be deleted.")
                print("Re-run with --confirm to delete them (the browser must be quit first).")
                return 0
            }

            // Real delete: guardrails.
            if runningChecker.isRunning(browser) {
                printErr("\n\(browser.displayName) is running. Quit it completely, then re-run with --confirm.")
                return 2
            }
            let backupRoot = opt("backup-dir").map { URL(fileURLWithPath: ($0 as NSString).expandingTildeInPath) }
                ?? StoreBackup.defaultBackupRoot()
            let backupDir = StoreBackup.backupDirectory(root: backupRoot, label: browser.rawValue, timestamp: timestamp())

            let outcome = try store.delete(matching: filter, backupDirectory: backupDir)
            print("\nBacked up to: \(outcome.backupPath.path)")
            print("Deleted \(outcome.deletedCount) login(s).")
            return 0

        default:
            return 1
        }
    } catch let error as LoginStoreError {
        printErr("\n\(error.description)")
        return 1
    } catch {
        printErr("\n\(error.localizedDescription)")
        return 1
    }
}

// MARK: - Output

func printTable(_ logins: [StoredLogin]) {
    guard !logins.isEmpty else { return }
    let df = DateFormatter()
    df.locale = Locale(identifier: "en_US_POSIX")
    df.dateFormat = "yyyy-MM-dd"
    print("")
    print("  #  id           origin                                   username")
    print("  -  -----------  ---------------------------------------  --------------------")
    for (index, login) in logins.enumerated() {
        let id = login.id.padding(toLength: 11, withPad: " ", startingAt: 0)
        let origin = String(login.origin.prefix(39)).padding(toLength: 39, withPad: " ", startingAt: 0)
        let user = login.usernameIsEncrypted ? "(encrypted)" : (login.username ?? "")
        let created = login.createdAt.map { " · created \(df.string(from: $0))" } ?? ""
        print(String(format: "  %d  %@  %@  %@%@", index + 1, id, origin, user, created))
    }
}

func timestamp() -> String {
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

func printErr(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}

func printUsage() {
    print("""
    rekey-cleanup — delete stale saved logins from a browser's store (opt-in, separate from Rekey.app).

    USAGE
      rekey-cleanup list   --browser <name> [--profile <p>] [--path <file>] [--site <s>] [--username <u>] [--id <id>]
      rekey-cleanup delete --browser <name> [filters] [--confirm] [--backup-dir <dir>]

    BROWSERS
      chrome, arc, brave, edge, opera, vivaldi, chromium, firefox
      (Apple Passwords is unsupported — no third-party delete API.)

    FILTERS (delete requires at least one)
      --site <substr>     match origin/host substring
      --username <u>      exact username (Chromium only; Firefox usernames are encrypted)
      --id <identifier>   target a specific row/guid (repeatable; see `list`)

    SAFETY
      • `delete` is a DRY RUN unless you pass --confirm.
      • Writing is refused while the browser is running — quit it first.
      • The store is backed up before any delete (default: ~/Library/Application Support/Rekey/Backups).
      • Nothing is ever decrypted; matching uses plaintext fields only.

    EXAMPLES
      rekey-cleanup list   --browser chrome --site github.com
      rekey-cleanup delete --browser chrome --site github.com --username old@example.com
      rekey-cleanup delete --browser firefox --id '{xxxxxxxx-....}' --confirm
    """)
}

exit(run())
