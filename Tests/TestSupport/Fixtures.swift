import Foundation

/// Locates the committed fixture CSVs for tests.
///
/// The files live at `<repo>/Tests/Fixtures/`. We resolve them relative to this
/// source file via `#filePath` rather than through an SPM resource bundle, so a
/// single copy of the fixtures is shared by every test target with no per-target
/// `.copy(...)` wiring.
public enum Fixtures {
    /// `<repo>/Tests/Fixtures/`
    public static var directory: URL {
        URL(fileURLWithPath: #filePath)      // .../Tests/TestSupport/Fixtures.swift
            .deletingLastPathComponent()     // .../Tests/TestSupport
            .deletingLastPathComponent()     // .../Tests
            .appendingPathComponent("Fixtures", isDirectory: true)
    }

    public static func url(_ name: String) -> URL {
        directory.appendingPathComponent(name)
    }

    /// Raw bytes of a fixture (use when you need to feed exact bytes to the
    /// parser, e.g. to verify BOM / CRLF handling).
    public static func data(_ name: String) throws -> Data {
        try Data(contentsOf: url(name))
    }

    /// UTF-8 contents of a fixture as a `String`.
    public static func string(_ name: String) throws -> String {
        try String(contentsOf: url(name), encoding: .utf8)
    }

    public static var chromeCSV: URL { url("chrome.csv") }
    public static var arcCSV: URL { url("arc.csv") }
    public static var firefoxCSV: URL { url("firefox.csv") }
    public static var appleCSV: URL { url("apple_passwords.csv") }
}
