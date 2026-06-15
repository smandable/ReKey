import Foundation

/// A `URLProtocol` that serves canned responses, including redirect chains, with
/// no live network. Routing is by a caller-supplied closure so tests can match
/// on the request URL (the router's control path contains a random nonce, so we
/// match by path prefix rather than exact equality).
///
/// Configure `MockURLProtocol.handler` before each test and reset it after.
/// Install it via `URLSessionConfiguration.protocolClasses`.
final class MockURLProtocol: URLProtocol, @unchecked Sendable {

    /// A canned outcome for a request: either a terminal HTTP response or a
    /// redirect to another URL (which the URL loading system will follow,
    /// re-entering this protocol for the destination).
    enum Outcome {
        /// Respond with `status` and stop.
        case status(Int)
        /// Reply `301` to `location`; the loader follows it.
        case redirect(to: String, status: Int = 301)
    }

    /// The routing closure. Set per-test. Receives the request URL.
    nonisolated(unsafe) static var handler: (@Sendable (URL) -> Outcome)?

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url, let handler = MockURLProtocol.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }

        switch handler(url) {
        case let .status(code):
            let response = HTTPURLResponse(
                url: url,
                statusCode: code,
                httpVersion: "HTTP/1.1",
                headerFields: nil
            )!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocolDidFinishLoading(self)

        case let .redirect(location, code):
            guard let target = URL(string: location) else {
                client?.urlProtocol(self, didFailWithError: URLError(.badURL))
                return
            }
            let response = HTTPURLResponse(
                url: url,
                statusCode: code,
                httpVersion: "HTTP/1.1",
                headerFields: ["Location": location]
            )!
            var redirectRequest = URLRequest(url: target)
            redirectRequest.httpMethod = request.httpMethod
            // Telling the client about a redirect makes URLSession follow it,
            // re-entering this protocol for `target`.
            client?.urlProtocol(self, wasRedirectedTo: redirectRequest, redirectResponse: response)
        }
    }

    override func stopLoading() {}
}

extension URLSession {
    /// A session whose only protocol is `MockURLProtocol` — no live traffic.
    static func mocked() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return URLSession(configuration: config)
    }
}
