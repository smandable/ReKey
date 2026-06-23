import Foundation
import BrowserStore
import CleanupCLI

// rekey-cleanup — a SEPARATE, opt-in tool to delete stale saved logins from a
// browser's store. It is deliberately not part of the sandboxed ReKey.app.
//
// All logic lives in the unit-tested `CleanupCLI` library; this executable is a
// thin entrypoint that wires in the real argv, running-browser checker, and
// store factory. See `CleanupCommand` for the safety model.

exit(CleanupCommand.run(
    arguments: Array(CommandLine.arguments.dropFirst()),
    runningChecker: SystemRunningBrowserChecker()
))
