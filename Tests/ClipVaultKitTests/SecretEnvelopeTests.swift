import CryptoKit
import Foundation
import XCTest
@testable import ClipVaultKit

final class SecretEnvelopeTests: XCTestCase {

    func testRoundTrip() throws {
        let key = P256.KeyAgreement.PrivateKey()
        let secret = Data("sk-proj-\(UUID().uuidString)".utf8)
        let envelope = try SecretEnvelope.seal(secret, to: key.publicKey)

        XCTAssertTrue(SecretEnvelope.isEnvelope(envelope))
        XCTAssertEqual(try SecretEnvelope.open(envelope, with: key), secret)
    }

    func testCiphertextDoesNotContainPlaintext() throws {
        let key = P256.KeyAgreement.PrivateKey()
        let secret = Data(String(repeating: "A", count: 64).utf8)
        let envelope = try SecretEnvelope.seal(secret, to: key.publicKey)
        XCTAssertNil(envelope.range(of: Data(String(repeating: "A", count: 8).utf8)))
    }

    func testEachSealIsDifferent() throws {
        let key = P256.KeyAgreement.PrivateKey()
        let secret = Data("same value".utf8)
        XCTAssertNotEqual(
            try SecretEnvelope.seal(secret, to: key.publicKey),
            try SecretEnvelope.seal(secret, to: key.publicKey)
        )
    }

    func testWrongKeyCannotOpen() throws {
        let owner = P256.KeyAgreement.PrivateKey()
        let attacker = P256.KeyAgreement.PrivateKey()
        let envelope = try SecretEnvelope.seal(Data("token".utf8), to: owner.publicKey)

        XCTAssertThrowsError(try SecretEnvelope.open(envelope, with: attacker)) { error in
            XCTAssertEqual(error as? SecretEnvelopeError, .authenticationFailed)
        }
    }

    func testTamperedCiphertextIsRejected() throws {
        let key = P256.KeyAgreement.PrivateKey()
        var envelope = try SecretEnvelope.seal(Data("token".utf8), to: key.publicKey)
        envelope[envelope.count - 1] ^= 0x01
        XCTAssertThrowsError(try SecretEnvelope.open(envelope, with: key))
    }

    func testTamperedHeaderIsRejected() throws {
        let key = P256.KeyAgreement.PrivateKey()
        var envelope = try SecretEnvelope.seal(Data("token".utf8), to: key.publicKey)
        // Swap in a different, valid ephemeral key: the shared secret and the
        // authenticated header both change.
        let other = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        envelope.replaceSubrange(1...65, with: other)
        XCTAssertThrowsError(try SecretEnvelope.open(envelope, with: key))
    }

    func testMalformedAndUnknownVersion() throws {
        let key = P256.KeyAgreement.PrivateKey()
        XCTAssertThrowsError(try SecretEnvelope.open(Data([1, 2, 3]), with: key)) { error in
            XCTAssertEqual(error as? SecretEnvelopeError, .malformed)
        }
        var envelope = try SecretEnvelope.seal(Data("token".utf8), to: key.publicKey)
        envelope[0] = 9
        XCTAssertThrowsError(try SecretEnvelope.open(envelope, with: key)) { error in
            XCTAssertEqual(error as? SecretEnvelopeError, .unsupportedVersion(9))
        }
    }

    func testSecureEnclaveRoundTripWhenAvailable() throws {
        guard SecureEnclave.isAvailable else { throw XCTSkip("No Secure Enclave") }
        // No user-presence flag here, so the test runs unattended.
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], nil
        )!
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        } catch {
            throw XCTSkip("Secure Enclave key creation unavailable: \(error)")
        }
        let restored = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: key.dataRepresentation)
        let secret = Data("hvs.\(UUID().uuidString)".utf8)
        let envelope = try SecretEnvelope.seal(secret, to: restored.publicKey)
        XCTAssertEqual(try SecretEnvelope.open(envelope, with: restored), secret)
    }

    func testDigestIsKeyedAndStable() {
        let key = SymmetricKey(size: .bits256)
        let other = SymmetricKey(size: .bits256)
        XCTAssertEqual(SecretDigest.digest("abc", key: key), SecretDigest.digest("abc", key: key))
        XCTAssertNotEqual(SecretDigest.digest("abc", key: key), SecretDigest.digest("abd", key: key))
        XCTAssertNotEqual(SecretDigest.digest("abc", key: key), SecretDigest.digest("abc", key: other))
    }
}
