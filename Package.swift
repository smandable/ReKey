// swift-tools-version: 6.0
import PackageDescription

// ReKey — local-first password health auditor.
//
// Architecture: every piece of logic lives in a SwiftUI-free, independently
// testable library target. UI sits on top in `ReKeyUI`, and `ReKeyApp` is the
// thin @main executable. The sandboxed .app is assembled from `ReKeyApp` by
// Scripts/build_app.sh (codesign + entitlements); there is no .xcodeproj.
let package = Package(
    name: "ReKey",
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "ReKey", targets: ["ReKeyApp"]),
        .library(name: "ReKeyCore", targets: [
            "Model", "ImportKit", "AuditEngine", "HIBPClient",
            "PasswordGenerator", "ResetRouter", "FixQueue",
        ]),
        // Exposed so the Xcode app target can link the UI from the local package.
        .library(name: "ReKeyUI", targets: ["ReKeyUI"]),
        // SEPARATE, opt-in cleanup tool. Deliberately NOT part of the sandboxed
        // app: it does direct (but decrypt-free) deletes from browser stores.
        .executable(name: "rekey-cleanup", targets: ["ReKeyCleanup"]),
    ],
    targets: [
        // MARK: Core logic (no SwiftUI)
        .target(name: "Model"),
        .target(
            name: "ImportKit",
            dependencies: ["Model"],
            resources: [.copy("Resources/public_suffix_list.dat")]
        ),
        .target(name: "HIBPClient", dependencies: ["Model"]),
        .target(
            name: "PasswordGenerator",
            dependencies: ["Model"],
            resources: [.copy("Resources/eff_large_wordlist.txt")]
        ),
        .target(
            name: "ResetRouter",
            dependencies: ["Model"],
            resources: [.copy("Resources/FallbackMap.json")]
        ),
        .target(name: "AuditEngine", dependencies: ["Model", "ImportKit", "HIBPClient"]),
        .target(name: "FixQueue", dependencies: ["Model", "PasswordGenerator", "ResetRouter"]),

        // MARK: Opt-in cleanup tool (separate from the sandboxed app)
        .target(
            name: "BrowserStore",
            dependencies: ["Model"],
            linkerSettings: [.linkedLibrary("sqlite3")]
        ),
        // Single, unit-testable source of truth for the rekey-cleanup command
        // strings + purge heredoc blocks the app generates (security-critical).
        .target(name: "CleanupScript", dependencies: ["Model"]),
        // The rekey-cleanup CLI's logic, extracted into a library so it can be
        // unit-tested (the executable target itself can't be imported by tests).
        .target(name: "CleanupCLI", dependencies: ["BrowserStore", "Model"]),
        .executableTarget(name: "ReKeyCleanup", dependencies: ["CleanupCLI", "BrowserStore"]),

        // MARK: UI + app
        .target(name: "ReKeyUI", dependencies: [
            "Model", "ImportKit", "AuditEngine", "HIBPClient",
            "PasswordGenerator", "ResetRouter", "FixQueue", "CleanupScript",
        ]),
        .executableTarget(name: "ReKeyApp", dependencies: ["ReKeyUI"]),

        // MARK: Test support (regular target, lives under Tests/, loads fixtures)
        .target(name: "TestSupport", dependencies: ["Model"], path: "Tests/TestSupport"),

        // MARK: Tests (Swift Testing)
        .testTarget(name: "ImportKitTests", dependencies: ["ImportKit", "TestSupport"]),
        .testTarget(name: "AuditEngineTests", dependencies: ["AuditEngine", "ImportKit", "HIBPClient", "TestSupport"]),
        .testTarget(name: "HIBPTests", dependencies: ["HIBPClient", "TestSupport"]),
        .testTarget(name: "GenerationTests", dependencies: ["PasswordGenerator"]),
        .testTarget(name: "ResetTests", dependencies: ["ResetRouter"]),
        .testTarget(name: "FixQueueTests", dependencies: ["FixQueue", "Model", "PasswordGenerator", "ResetRouter"]),
        .testTarget(name: "BrowserStoreTests", dependencies: ["BrowserStore"]),
        .testTarget(name: "CleanupScriptTests", dependencies: ["CleanupScript", "Model"]),
        .testTarget(name: "CleanupCLITests", dependencies: ["CleanupCLI", "BrowserStore", "Model"]),
        .testTarget(name: "ReKeyUITests", dependencies: ["ReKeyUI", "Model", "PasswordGenerator"]),
    ]
)
