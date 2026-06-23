import Foundation
import Model
import Synchronization
import Testing

@testable import HIBPClient

/// Tests for the HIBP k-anonymity client. The live API is never contacted — all
/// traffic is served by `MockURLProtocol`.
///
/// Reference: SHA-1("password") == 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8,
/// so the range prefix is "5BAA6" and the suffix is
/// "1E4C9B93F3F0682250B6CF8331B7EE68FD8".
@Suite(.serialized)
struct HIBPClientTests {
    private static let passwordPrefix = "5BAA6"
    private static let passwordSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

    /// Default handler: real match for the "password" prefix, empty padded body
    /// otherwise.
    private func installDefaultHandler() {
        MockURLProtocol.setHandler { request in
            let prefix = request.url.map { String($0.lastPathComponent) } ?? ""
            if prefix == Self.passwordPrefix {
                // One real match plus a discarded padding line.
                let body = "\(Self.passwordSuffix):99999\r\n0000000000000000000000000000000000A:0"
                return .success(status: 200, body: body)
            }
            // Unrelated prefixes: only padding (zero-count) lines.
            return .success(status: 200, body: "0123456789012345678901234567890123A:0\r\nABCDEF0123456789012345678901234567B:0")
        }
    }

    @Test
    func parseRangeHandlesAdversarialBodies() {
        func parse(_ s: String) -> [String: Int] { HIBPClient.parseRange(Data(s.utf8)) }
        // Empty / non-UTF8 / no valid lines.
        #expect(HIBPClient.parseRange(Data()).isEmpty)
        #expect(HIBPClient.parseRange(Data([0xFF, 0xFE, 0xFF])).isEmpty)   // invalid UTF-8
        #expect(parse("\n\n  \n").isEmpty)
        #expect(parse("garbage-without-colon").isEmpty)
        // Non-numeric / zero (padding) / negative counts are dropped.
        #expect(parse("ABCDE:notanumber").isEmpty)
        #expect(parse("ABCDE:0").isEmpty)
        #expect(parse("ABCDE:-5").isEmpty)
        // Extra colons → the count slice isn't an Int → skipped.
        #expect(parse("ABCDE:1:2").isEmpty)
        // Valid lines parse; suffix uppercased; surrounding whitespace tolerated.
        #expect(parse("abcde:7") == ["ABCDE": 7])
        #expect(parse("ABCDE: 42 ") == ["ABCDE": 42])
        // Mixed garbage + valid: only the valid lines survive; CRLF handled.
        #expect(parse("bad\r\nGOOD1:3\nzero:0\nGOOD2:9") == ["GOOD1": 3, "GOOD2": 9])
    }

    @Test
    func knownPasswordIsCompromised() async {
        MockURLProtocol.reset()
        installDefaultHandler()
        let session = MockURLProtocol.makeSession()
        let client = HIBPClient(session: session)

        let id = UUID()
        let result = await client.check([id: Secret("password")])

        #expect(result[id] == .compromised(breachCount: 99999))
    }

    @Test
    func uniquePasswordIsClean() async {
        MockURLProtocol.reset()
        installDefaultHandler()
        let session = MockURLProtocol.makeSession()
        let client = HIBPClient(session: session)

        // A random password is overwhelmingly unlikely to match the served body.
        let id = UUID()
        let unique = "rnd-\(UUID().uuidString)-\(UUID().uuidString)"
        let result = await client.check([id: Secret(unique)])

        #expect(result[id] == .clean)
    }

    @Test
    func everyInputKeyAppearsInOutput() async {
        MockURLProtocol.reset()
        installDefaultHandler()
        let session = MockURLProtocol.makeSession()
        let client = HIBPClient(session: session)

        let a = UUID(), b = UUID(), c = UUID()
        let result = await client.check([
            a: Secret("password"),
            b: Secret("another-\(UUID().uuidString)"),
            c: Secret(""), // empty -> .unknown
        ])

        #expect(result.count == 3)
        #expect(result[a] == .compromised(breachCount: 99999))
        #expect(result[b] == .clean)
        #expect(result[c] == .unknown)
    }

    @Test
    func emptyPasswordIsUnknown() async {
        MockURLProtocol.reset()
        installDefaultHandler()
        let session = MockURLProtocol.makeSession()
        let client = HIBPClient(session: session)

        let id = UUID()
        let result = await client.check([id: Secret("")])
        #expect(result[id] == .unknown)
    }

    @Test
    func zeroCountPaddingLinesAreDiscarded() async {
        MockURLProtocol.reset()
        // Serve the real suffix BUT with a zero count, plus other padding. If
        // the client mistakenly honored ":0" it would count it as a match;
        // instead the password must be reported clean.
        MockURLProtocol.setHandler { request in
            let prefix = request.url.map { String($0.lastPathComponent) } ?? ""
            if prefix == Self.passwordPrefix {
                let body = "\(Self.passwordSuffix):0\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA:0"
                return .success(status: 200, body: body)
            }
            return .success(status: 200, body: "")
        }
        let session = MockURLProtocol.makeSession()
        let client = HIBPClient(session: session)

        let id = UUID()
        let result = await client.check([id: Secret("password")])
        #expect(result[id] == .clean)
    }

    @Test
    func sharedPasswordTriggersExactlyOneRequest() async {
        MockURLProtocol.reset()
        installDefaultHandler()
        let session = MockURLProtocol.makeSession()
        let client = HIBPClient(session: session)

        let a = UUID(), b = UUID()
        // Two distinct credentials, same password -> same prefix -> one request.
        let result = await client.check([
            a: Secret("password"),
            b: Secret("password"),
        ])

        #expect(result[a] == .compromised(breachCount: 99999))
        #expect(result[b] == .compromised(breachCount: 99999))
        #expect(MockURLProtocol.requestCount == 1)
        #expect(MockURLProtocol.requestedPrefixes == [Self.passwordPrefix])
    }

    @Test
    func cacheAvoidsRepeatRequestsAcrossCalls() async {
        MockURLProtocol.reset()
        installDefaultHandler()
        let session = MockURLProtocol.makeSession()
        let client = HIBPClient(session: session)

        let id1 = UUID()
        _ = await client.check([id1: Secret("password")])
        #expect(MockURLProtocol.requestCount == 1)

        // Second call for the same prefix should hit the in-memory cache.
        let id2 = UUID()
        let result = await client.check([id2: Secret("password")])
        #expect(result[id2] == .compromised(breachCount: 99999))
        #expect(MockURLProtocol.requestCount == 1)
    }

    @Test
    func transientFailureIsRetriedThenSucceeds() async {
        MockURLProtocol.reset()
        // Fail the first request for the password prefix, succeed on the retry.
        // The mock records each request before invoking the handler, so the
        // count of prior requests for this prefix is the attempt number.
        MockURLProtocol.setHandler { request in
            let prefix = String(request.url!.lastPathComponent)
            let attempt = MockURLProtocol.requestedPrefixes.filter { $0 == prefix }.count
            guard prefix == Self.passwordPrefix else { return .success(status: 200, body: "") }
            if attempt == 1 { return .failure(URLError(.timedOut)) }
            return .success(status: 200, body: "\(Self.passwordSuffix):42")
        }
        let session = MockURLProtocol.makeSession()
        let client = HIBPClient(session: session, maxRetries: 2)

        let id = UUID()
        let result = await client.check([id: Secret("password")])
        #expect(result[id] == .compromised(breachCount: 42))
        // Exactly two requests for the prefix: one failure, one success.
        #expect(MockURLProtocol.requestedPrefixes.filter { $0 == Self.passwordPrefix }.count == 2)
    }

    @Test
    func offlineSessionYieldsUnknownWithoutThrowing() async {
        MockURLProtocol.reset()
        // Every request fails — simulates being offline.
        MockURLProtocol.setHandler { _ in
            .failure(URLError(.notConnectedToInternet))
        }
        let session = MockURLProtocol.makeSession()
        // No retries so the test is fast.
        let client = HIBPClient(session: session, maxRetries: 0)

        let id = UUID()
        let result = await client.check([id: Secret("password")])
        #expect(result[id] == .unknown)
    }

    @Test
    func addPaddingHeaderIsSentOnEveryRequest() async {
        MockURLProtocol.reset()
        installDefaultHandler()
        let session = MockURLProtocol.makeSession()
        let client = HIBPClient(session: session)

        _ = await client.check([
            UUID(): Secret("password"),
            UUID(): Secret("hello-\(UUID().uuidString)"),
        ])

        #expect(MockURLProtocol.requestCount >= 1)
        #expect(MockURLProtocol.allRequestsHadAddPadding)
    }

    @Test
    func onlyFiveCharPrefixLeavesTheDevice() async {
        MockURLProtocol.reset()
        installDefaultHandler()
        let session = MockURLProtocol.makeSession()
        let client = HIBPClient(session: session)

        _ = await client.check([UUID(): Secret("password")])

        // The requested path must be exactly the 5-char prefix — never the full
        // hash or the suffix.
        for url in MockURLProtocol.requestedURLs {
            let last = url.lastPathComponent
            #expect(last.count == 5)
            #expect(!last.contains(Self.passwordSuffix))
        }
    }

    @Test
    func emptyInputReturnsEmptyAndMakesNoRequests() async {
        MockURLProtocol.reset()
        installDefaultHandler()
        let session = MockURLProtocol.makeSession()
        let client = HIBPClient(session: session)

        let result = await client.check([:])
        #expect(result.isEmpty)
        #expect(MockURLProtocol.requestCount == 0)
    }

    // MARK: - Progress reporting

    @Test
    func progressClimbsMonotonicallyToTheDistinctRangeCount() async {
        MockURLProtocol.reset()
        installDefaultHandler()
        let session = MockURLProtocol.makeSession()
        let client = HIBPClient(session: session, maxConcurrentRequests: 2)

        // Distinct passwords -> distinct prefixes (collision is astronomically
        // unlikely), so each is its own unit of fetch work.
        let secrets: [UUID: Secret] = [
            UUID(): Secret("password"),
            UUID(): Secret("alpha-\(UUID().uuidString)"),
            UUID(): Secret("beta-\(UUID().uuidString)"),
        ]
        let ticks = Mutex<[(done: Int, total: Int)]>([])
        _ = await client.check(secrets) { done, total in
            ticks.withLock { $0.append((done, total)) }
        }

        let recorded = ticks.withLock { $0 }
        #expect(!recorded.isEmpty)
        let total = recorded.first!.total
        #expect(total >= 1)
        // `total` is constant across every tick.
        #expect(Set(recorded.map(\.total)) == [total])
        // Starts at the initial 0, ends having resolved every range.
        #expect(recorded.first?.done == 0)
        #expect(recorded.map(\.done).max() == total)
        // `done` never decreases.
        #expect(recorded.map(\.done) == recorded.map(\.done).sorted())
    }

    @Test
    func progressTotalIsZeroWhenEverythingIsCached() async {
        MockURLProtocol.reset()
        installDefaultHandler()
        let session = MockURLProtocol.makeSession()
        let client = HIBPClient(session: session)

        // Warm the cache for the password prefix.
        _ = await client.check([UUID(): Secret("password")])

        // A second check for the same prefix fetches nothing, so total == 0.
        let ticks = Mutex<[(done: Int, total: Int)]>([])
        _ = await client.check([UUID(): Secret("password")]) { done, total in
            ticks.withLock { $0.append((done, total)) }
        }
        let recorded = ticks.withLock { $0 }
        #expect(recorded.count == 1)
        #expect(recorded.first?.done == 0)
        #expect(recorded.first?.total == 0)
    }

    // MARK: - Pure-function checks

    @Test
    func sha1HashPartsMatchKnownVector() {
        let parts = HIBPHashing.hashParts(for: Secret("password"))
        #expect(parts.prefix == "5BAA6")
        #expect(parts.suffix == "1E4C9B93F3F0682250B6CF8331B7EE68FD8")
    }

    @Test
    func parseRangeUppercasesAndDropsZeroCounts() {
        // Mixed casing on the suffix, CRLF separators, and zero-count padding.
        let body = "abc123def4567890abcdef0123456789012:42\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0"
        let parsed = HIBPClient.parseRange(Data(body.utf8))
        #expect(parsed["ABC123DEF4567890ABCDEF0123456789012"] == 42)
        // Zero-count line discarded entirely.
        #expect(parsed["FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"] == nil)
        #expect(parsed.count == 1)
    }
}
