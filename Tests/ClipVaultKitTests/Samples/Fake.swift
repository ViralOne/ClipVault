import Foundation

/// Builds token-shaped test values at runtime, so no real-looking secret is
/// ever committed to the repository (and secret scanners stay quiet).
/// Deterministic: the same call always returns the same string.
enum Fake {
    static let lower = "abcdefghijklmnopqrstuvwxyz"
    static let upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    static let digits = "0123456789"
    static let hexLower = "0123456789abcdef"
    static let hexUpper = "0123456789ABCDEF"
    static let alnum = lower + upper + digits
    static let lowerAlnum = lower + digits
    static let upperAlnum = upper + digits
    static let base64 = alnum + "+/"
    static let base64URL = alnum + "-_"

    static func string(_ length: Int, _ alphabet: String = alnum, seed: UInt64 = 1) -> String {
        let characters = Array(alphabet)
        var state = seed &* 6364136223846793005 &+ 1442695040888963407
        return String((0..<length).map { _ in
            state = state &* 6364136223846793005 &+ 1442695040888963407
            return characters[Int((state >> 33) % UInt64(characters.count))]
        })
    }

    static func alnum(_ n: Int, seed: UInt64 = 1) -> String { string(n, alnum, seed: seed) }
    static func hex(_ n: Int, seed: UInt64 = 1) -> String { string(n, hexLower, seed: seed) }
    static func hexUpper(_ n: Int, seed: UInt64 = 1) -> String { string(n, hexUpper, seed: seed) }
    static func digits(_ n: Int, seed: UInt64 = 1) -> String { string(n, digits, seed: seed) }
    static func lower(_ n: Int, seed: UInt64 = 1) -> String { string(n, lowerAlnum, seed: seed) }
    static func upper(_ n: Int, seed: UInt64 = 1) -> String { string(n, upperAlnum, seed: seed) }
    static func b64(_ n: Int, seed: UInt64 = 1) -> String { string(n, base64, seed: seed) }
    static func b64url(_ n: Int, seed: UInt64 = 1) -> String { string(n, base64URL, seed: seed) }
    static func uuid(seed: UInt64 = 1) -> String {
        let h = hex(32, seed: seed)
        let c = Array(h)
        return [0..<8, 8..<12, 12..<16, 16..<20, 20..<32].map { String(c[$0]) }.joined(separator: "-")
    }
}

/// A value that must be detected as `kind`.
struct SecretSample {
    let kind: String
    let value: String
    init(_ kind: String, _ value: String) {
        self.kind = kind
        self.value = value
    }
}

enum SecretSamples {
    static let all: [SecretSample] = cloud + developer + ai + saas + keys
}
