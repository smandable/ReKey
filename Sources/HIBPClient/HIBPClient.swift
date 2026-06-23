import Foundation
import Model

/// A client for the Have I Been Pwned "Pwned Passwords" range API using
/// k-anonymity.
///
/// Privacy model: for each distinct password we compute its SHA-1 and send ONLY
/// the first 5 hex characters of that digest (the "range prefix") to the API.
/// The API replies with every breached suffix sharing that prefix, and we match
/// our 35-char suffix locally. The password, the full hash, and any credential
/// identifier never leave the device.
///
/// Resilience: requests time out, retry with exponential backoff, and run with
/// bounded concurrency. Any range that ultimately fails (e.g. offline) yields
/// `.unknown` for its entries — `check(_:)` never throws and always returns an
/// entry for every input key.
public actor HIBPClient {
    /// Injected session — tests pass an ephemeral session wired to a mock
    /// `URLProtocol` so the live API is never contacted.
    private let session: URLSession
    /// Max range requests in flight at once.
    private let maxConcurrentRequests: Int
    /// Max retry attempts per request after the initial try.
    private let maxRetries: Int
    /// Per-request timeout in seconds.
    private let requestTimeout: TimeInterval

    /// In-memory cache of range responses, keyed by 5-char prefix, for the
    /// lifetime of this client. Maps suffix -> breach count for that prefix.
    /// A cached value of `nil` is never stored; failures are not cached so a
    /// later check can retry once connectivity returns.
    private var rangeCache: [String: [String: Int]] = [:]

    public init(
        session: URLSession? = nil,
        maxConcurrentRequests: Int = 4,
        maxRetries: Int = 2
    ) {
        // Default to an ephemeral, cache-less session (NOT URLSession.shared): a
        // range request's URL carries the first 5 hex of the password's SHA-1, and
        // the shared session's on-disk URLCache would persist those password-derived
        // prefixes (and responses) to disk. Tests inject their own mock session.
        self.session = session ?? HIBPClient.makeEphemeralSession()
        self.maxConcurrentRequests = max(1, maxConcurrentRequests)
        self.maxRetries = max(0, maxRetries)
        self.requestTimeout = 10
    }

    /// A private, ephemeral URLSession with caching fully disabled, so no
    /// password-derived hash prefix is ever written to disk.
    private static func makeEphemeralSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        return URLSession(configuration: config)
    }

    /// Check a batch of secrets keyed by credential id.
    ///
    /// - Dedupes by SHA-1 so identical passwords (even across different ids)
    ///   produce exactly one range request for their shared prefix.
    /// - Empty-password entries resolve to `.unknown`.
    /// - Every input key appears in the output.
    public func check(_ secrets: [UUID: Secret]) async -> [UUID: CompromisedStatus] {
        await check(secrets, onProgress: { _, _ in })
    }

    public func check(
        _ secrets: [UUID: Secret],
        onProgress: @Sendable (_ done: Int, _ total: Int) -> Void
    ) async -> [UUID: CompromisedStatus] {
        guard !secrets.isEmpty else { return [:] }

        // 1. Compute hash parts once per id (skip empties), and gather the set
        //    of distinct prefixes that aren't already cached.
        var partsByID: [UUID: HIBPHashing.HashParts] = [:]
        var prefixesToFetch: Set<String> = []
        for (id, secret) in secrets {
            guard !secret.isEmpty else { continue }
            let parts = HIBPHashing.hashParts(for: secret)
            partsByID[id] = parts
            if rangeCache[parts.prefix] == nil {
                prefixesToFetch.insert(parts.prefix)
            }
        }

        // 2. Fetch the missing ranges with bounded concurrency, reporting one
        //    progress tick per range as it resolves. Results merge into the
        //    cache. A `nil` result means the range could not be resolved
        //    (offline / repeated failure) and is left uncached. The total is the
        //    deduped fetch count — work already cached costs nothing here.
        let total = prefixesToFetch.count
        onProgress(0, total)
        if !prefixesToFetch.isEmpty {
            let fetched = await fetchRanges(Array(prefixesToFetch)) { done in
                onProgress(done, total)
            }
            for (prefix, suffixes) in fetched {
                rangeCache[prefix] = suffixes
            }
        }

        // 3. Resolve every input key.
        var result: [UUID: CompromisedStatus] = [:]
        result.reserveCapacity(secrets.count)
        for (id, _) in secrets {
            guard let parts = partsByID[id] else {
                // Empty password.
                result[id] = .unknown
                continue
            }
            guard let suffixes = rangeCache[parts.prefix] else {
                // Range failed to resolve.
                result[id] = .unknown
                continue
            }
            if let count = suffixes[parts.suffix] {
                result[id] = .compromised(breachCount: count)
            } else {
                result[id] = .clean
            }
        }
        return result
    }

    /// Fetch each prefix's range, with at most `maxConcurrentRequests` requests
    /// in flight. Returns only successfully resolved prefixes; failures are
    /// omitted so the caller treats them as `.unknown`.
    ///
    /// `onRangeDone(done)` is called once per range as it resolves, with the
    /// running count of completed ranges (1...prefixes.count), so callers can
    /// report determinate progress.
    private func fetchRanges(
        _ prefixes: [String],
        onRangeDone: @Sendable (_ done: Int) -> Void = { _ in }
    ) async -> [String: [String: Int]] {
        await withTaskGroup(
            of: (String, [String: Int]?).self,
            returning: [String: [String: Int]].self
        ) { group in
            var resolved: [String: [String: Int]] = [:]
            var index = 0
            var completed = 0
            let inFlightLimit = min(maxConcurrentRequests, prefixes.count)

            // Capture immutable copies for use inside the @Sendable closures.
            let session = self.session
            let maxRetries = self.maxRetries
            let timeout = self.requestTimeout

            // Seed up to the concurrency limit.
            while index < inFlightLimit {
                let prefix = prefixes[index]
                group.addTask {
                    let suffixes = await Self.fetchRange(
                        prefix: prefix,
                        session: session,
                        maxRetries: maxRetries,
                        timeout: timeout
                    )
                    return (prefix, suffixes)
                }
                index += 1
            }

            // Drain and refill to keep the pipeline bounded.
            while let (prefix, suffixes) = await group.next() {
                completed += 1
                onRangeDone(completed)
                if let suffixes {
                    resolved[prefix] = suffixes
                }
                if index < prefixes.count {
                    let nextPrefix = prefixes[index]
                    group.addTask {
                        let s = await Self.fetchRange(
                            prefix: nextPrefix,
                            session: session,
                            maxRetries: maxRetries,
                            timeout: timeout
                        )
                        return (nextPrefix, s)
                    }
                    index += 1
                }
            }
            return resolved
        }
    }

    /// Perform a single range request (with retries + backoff) and parse it.
    /// Returns `nil` if the request ultimately fails so the entry becomes
    /// `.unknown`. Static + given all inputs so it's a plain `@Sendable` closure
    /// body with no actor hop.
    private static func fetchRange(
        prefix: String,
        session: URLSession,
        maxRetries: Int,
        timeout: TimeInterval
    ) async -> [String: Int]? {
        guard let url = URL(string: "https://api.pwnedpasswords.com/range/\(prefix)") else {
            return nil
        }

        var attempt = 0
        while true {
            do {
                var request = URLRequest(url: url, timeoutInterval: timeout)
                request.httpMethod = "GET"
                // k-anonymity padding: ask the API to pad responses with bogus
                // zero-count lines so the response size doesn't leak how many
                // real suffixes share this prefix.
                request.setValue("true", forHTTPHeaderField: "Add-Padding")

                let (data, response) = try await session.data(for: request)

                if let http = response as? HTTPURLResponse,
                   !(200...299).contains(http.statusCode) {
                    throw HIBPError.badStatus(http.statusCode)
                }

                return parseRange(data)
            } catch {
                if attempt >= maxRetries {
                    return nil
                }
                // Exponential backoff: 200ms, 400ms, 800ms, … capped so a large
                // maxRetries can't overflow the shift (traps) or sleep absurdly.
                let shift = min(attempt, 20)
                let delayNanos = UInt64(200_000_000) << UInt64(shift)
                try? await Task.sleep(nanoseconds: delayNanos)
                attempt += 1
            }
        }
    }

    /// Parse a range response body into a suffix -> count map.
    ///
    /// Body format: CRLF-separated lines of "SUFFIX:COUNT". We uppercase the
    /// suffix for case-insensitive local matching and DISCARD padding lines
    /// whose COUNT is 0 (these are bogus entries added by `Add-Padding`).
    static func parseRange(_ data: Data) -> [String: Int] {
        guard let body = String(data: data, encoding: .utf8) else { return [:] }
        var result: [String: Int] = [:]
        // Split on any newline form. We split on Unicode *scalars* (not
        // Characters) because a CRLF pair forms a single grapheme cluster, so a
        // Character-level split would not see the line break between "...:N" and
        // the next suffix. `\u{0085}` and `\u{2028}/\u{2029}` are also treated
        // as line breaks for safety.
        let lineBreaks: Set<Unicode.Scalar> = ["\r", "\n", "\u{0085}", "\u{2028}", "\u{2029}"]
        let lines = body.unicodeScalars.split(whereSeparator: { lineBreaks.contains($0) })
        for scalars in lines {
            let line = String(String.UnicodeScalarView(scalars))
            guard let colon = line.firstIndex(of: ":") else { continue }
            let suffix = line[line.startIndex..<colon].uppercased()
            let countSlice = line[line.index(after: colon)...]
            guard let count = Int(countSlice.trimmingCharacters(in: .whitespaces)) else {
                continue
            }
            // Discard padding lines (count == 0): never a real match.
            guard count > 0 else { continue }
            result[suffix] = count
        }
        return result
    }

    private enum HIBPError: Error {
        case badStatus(Int)
    }
}

extension HIBPClient: CompromiseChecking {}
