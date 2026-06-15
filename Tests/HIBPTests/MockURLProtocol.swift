import Foundation

/// A `URLProtocol` that intercepts every request issued through a session
/// configured with it, so HIBP tests never touch the live API.
///
/// All mutable test configuration / recording lives behind a single lock-guarded
/// `Storage` instance so it is concurrency-safe under Swift 6 strict checking.
/// Tests set a `handler` closure that maps a request to either a response/body
/// or an error, and read `requestedPrefixes` / `requestCount` afterward to
/// assert on dedup behavior.
final class MockURLProtocol: URLProtocol, @unchecked Sendable {
    /// Outcome a handler can return for a given request.
    enum Outcome {
        /// Serve an HTTP response with the given status and UTF-8 body.
        case success(status: Int, body: String)
        /// Fail the request with the given error (simulates offline).
        case failure(Error)
    }

    /// Lock-guarded mutable state shared across all protocol instances.
    private final class Storage: @unchecked Sendable {
        let lock = NSLock()
        var handler: (@Sendable (URLRequest) -> Outcome)?
        var requestedURLs: [URL] = []
        var addPaddingHeaderSeen: [Bool] = []
    }

    /// The single immutable container; its contents are mutated under `lock`.
    private static let storage = Storage()

    /// Install the request handler and reset recorded state.
    static func setHandler(_ handler: @escaping @Sendable (URLRequest) -> Outcome) {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        storage.handler = handler
        storage.requestedURLs = []
        storage.addPaddingHeaderSeen = []
    }

    /// Clear all state between tests.
    static func reset() {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        storage.handler = nil
        storage.requestedURLs = []
        storage.addPaddingHeaderSeen = []
    }

    /// Every URL that was requested, in order.
    static var requestedURLs: [URL] {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        return storage.requestedURLs
    }

    /// Just the 5-char range prefixes that were requested.
    static var requestedPrefixes: [String] {
        requestedURLs.map { String($0.lastPathComponent) }
    }

    /// Total number of intercepted requests.
    static var requestCount: Int {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        return storage.requestedURLs.count
    }

    /// Whether every intercepted request carried `Add-Padding: true`.
    static var allRequestsHadAddPadding: Bool {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        return !storage.addPaddingHeaderSeen.isEmpty
            && storage.addPaddingHeaderSeen.allSatisfy { $0 }
    }

    // MARK: URLProtocol

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let request = self.request
        let storage = Self.storage

        storage.lock.lock()
        if let url = request.url {
            storage.requestedURLs.append(url)
        }
        let hadPadding = request.value(forHTTPHeaderField: "Add-Padding") == "true"
        storage.addPaddingHeaderSeen.append(hadPadding)
        let handler = storage.handler
        storage.lock.unlock()

        guard let handler, let url = request.url else {
            let error = NSError(domain: "MockURLProtocol", code: -1)
            client?.urlProtocol(self, didFailWithError: error)
            return
        }

        switch handler(request) {
        case let .success(status, body):
            let response = HTTPURLResponse(
                url: url,
                statusCode: status,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "text/plain"]
            )!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data(body.utf8))
            client?.urlProtocolDidFinishLoading(self)
        case let .failure(error):
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

extension MockURLProtocol {
    /// Build an ephemeral `URLSession` that routes all traffic through the mock.
    static func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return URLSession(configuration: config)
    }
}
