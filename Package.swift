// swift-tools-version: 6.0
import PackageDescription

// Rekey — local-first password health auditor.
//
// Architecture: every piece of logic lives in a SwiftUI-free, independently
// testable library target. UI sits on top in `RekeyUI`, and `RekeyApp` is the
// thin @main executable. The sandboxed .app is assembled from `RekeyApp` by
// Scripts/build_app.sh (codesign + entitlements); there is no .xcodeproj.
let package = Package(
    name: "Rekey",
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "Rekey", targets: ["RekeyApp"]),
        .library(name: "RekeyCore", targets: [
            "Model", "ImportKit", "AuditEngine", "HIBPClient",
            "PasswordGenerator", "ResetRouter", "FixQueue",
        ]),
        // Exposed so the Xcode app target can link the UI from the local package.
        .library(name: "RekeyUI", targets: ["RekeyUI"]),
        // SEPARATE, opt-in cleanup tool. Deliberately NOT part of the sandboxed
        // app: it does direct (but decrypt-free) deletes from browser stores.
        .executable(name: "rekey-cleanup", targets: ["RekeyCleanup"]),
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
        .executableTarget(name: "RekeyCleanup", dependencies: ["BrowserStore"]),

        // MARK: UI + app
        .target(name: "RekeyUI", dependencies: [
            "Model", "ImportKit", "AuditEngine", "HIBPClient",
            "PasswordGenerator", "ResetRouter", "FixQueue",
        ]),
        .executableTarget(name: "RekeyApp", dependencies: ["RekeyUI"]),

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
        .testTarget(name: "RekeyUITests", dependencies: ["RekeyUI", "Model"]),
    ]
)
