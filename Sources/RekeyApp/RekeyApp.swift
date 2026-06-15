import SwiftUI
import RekeyUI

/// Rekey — a local-first password health auditor.
///
/// Thin entry point: all UI lives in `RekeyUI`, all logic in the engine
/// modules. The app never edits credentials or writes to any browser, Apple
/// Passwords, or the system keychain.
@main
struct RekeyApp: App {
    init() {
        // Headless resource smoke test for packaging verification; runs before
        // any window and exits.
        if CommandLine.arguments.contains("--selftest") {
            RekeySelfTest.runAndExit()
        }
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .frame(minWidth: 720, minHeight: 520)
        }
        .defaultSize(width: 940, height: 700)
    }
}
