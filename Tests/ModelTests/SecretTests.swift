import Testing
import Foundation
import CryptoKit
@testable import Model

@Suite("Secret — plaintext wrapper")
struct SecretTests {
    @Test("Round-trips a value and reports byte count / emptiness")
    func roundTrip() {
        let s = Secret("hunter2")
        #expect(s.reveal() == "hunter2")
        #expect(s.byteCount == 7)
        #expect(!s.isEmpty)
        #expect(Secret("").isEmpty)
        #expect(Secret("").byteCount == 0)
    }

    @Test("Initializes from raw UTF-8 bytes")
    func fromBytes() {
        let bytes = Array("café".utf8)            // 'é' is 2 bytes → 5 bytes, 4 graphemes
        let s = Secret(utf8Bytes: bytes)
        #expect(s.reveal() == "café")
        #expect(s.byteCount == 5)
    }

    @Test("NEVER leaks the value via description / debugDescription / interpolation")
    func redaction() {
        let s = Secret("S3cr3t-Pa$$w0rd")
        #expect(s.description == "Secret(redacted)")
        #expect(s.debugDescription == "Secret(redacted)")
        #expect("\(s)" == "Secret(redacted)")
        #expect(!"\(s)".contains("S3cr3t"))
        var dumped = ""
        dump(s, to: &dumped)
        #expect(!dumped.contains("S3cr3t"))
    }

    @Test("masked() hides the value and the real length")
    func masked() {
        #expect(Secret("abc").masked() == Secret("a-much-longer-password").masked())
        #expect(!Secret("abc").masked().contains("a"))
    }

    @Test("withUTF8 exposes the exact bytes, scoped")
    func withUTF8() {
        let s = Secret("åß∂")
        let captured = s.withUTF8 { Array($0) }
        #expect(captured == Array("åß∂".utf8))
    }

    @Test("Value semantics: equal/hash by plaintext, not buffer identity")
    func valueSemantics() {
        let a = Secret("same")
        let b = Secret("same")
        let c = Secret("different")
        #expect(a == b)                          // distinct buffers, equal bytes
        #expect(a != c)
        #expect(Set([a, b, c]).count == 2)       // a and b collapse
        #expect(a.hashValue == b.hashValue)
    }

    @Test("zero() drops the plaintext for this copy without disturbing other copies")
    func zeroing() {
        var s = Secret("temporary")
        let copy = s                              // shares the buffer
        s.zero()
        #expect(s.isEmpty)                        // this copy no longer holds the value
        #expect(s.reveal() == "")
        #expect(copy.reveal() == "temporary")     // an independent copy is unaffected
    }

    @Test("sha256 is deterministic and matches a plain digest of the bytes")
    func sha256() {
        let s = Secret("password")
        let expected = Data(SHA256.hash(data: Data("password".utf8)))
        #expect(s.sha256() == expected)
        #expect(s.sha256() == Secret("password").sha256())
        #expect(s.sha256() != Secret("password1").sha256())
    }

    @Test("hmac depends on the key and never equals the plain digest")
    func hmac() {
        let s = Secret("password")
        let k1 = SymmetricKey(data: Data(repeating: 1, count: 32))
        let k2 = SymmetricKey(data: Data(repeating: 2, count: 32))
        #expect(s.hmac(key: k1) == Secret("password").hmac(key: k1))   // stable per key
        #expect(s.hmac(key: k1) != s.hmac(key: k2))                    // key-dependent
        #expect(s.hmac(key: k1) != s.sha256())                         // not the unkeyed digest
    }
}
