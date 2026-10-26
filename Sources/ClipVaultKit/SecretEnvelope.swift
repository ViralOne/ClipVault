import CryptoKit
import Foundation

/// A private key that can perform P-256 key agreement. The app uses a Secure
/// Enclave key whose use requires Touch ID or the login password; tests use a
/// software key.
public protocol SecretKeyAgreement {
    var publicKey: P256.KeyAgreement.PublicKey { get }
    func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws -> SharedSecret
}

extension P256.KeyAgreement.PrivateKey: SecretKeyAgreement {}
extension SecureEnclave.P256.KeyAgreement.PrivateKey: SecretKeyAgreement {}

public enum SecretEnvelopeError: Error, Equatable {
    case malformed
    case unsupportedVersion(UInt8)
    case authenticationFailed
}

/// ECIES-style envelope for secret values.
///
/// Sealing needs only the recipient's public key, so new secrets are captured
/// without prompting. Opening needs the matching private key; when that key
/// lives in the Secure Enclave with a user-presence access control, the value
/// cannot be decrypted — by this app or anything that has copied its files and
/// Keychain items — without the user authenticating on this Mac.
///
/// Layout: `version (1) | ephemeral public key, X9.63 (65) | AES-GCM combined`.
public enum SecretEnvelope {
    public static let version: UInt8 = 1
    private static let publicKeyLength = 65
    private static let info = Data("ClipVault secret envelope v1".utf8)

    public static func seal(_ plaintext: Data, to recipient: P256.KeyAgreement.PublicKey) throws -> Data {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let ephemeralPublic = ephemeral.publicKey.x963Representation
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let key = derivedKey(shared, ephemeralPublic: ephemeralPublic, recipient: recipient)

        var header = Data([version])
        header.append(ephemeralPublic)
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: header)
        guard let combined = box.combined else { throw SecretEnvelopeError.malformed }
        return header + combined
    }

    public static func open(_ envelope: Data, with privateKey: SecretKeyAgreement) throws -> Data {
        let bytes = [UInt8](envelope)
        guard bytes.count > 1 + publicKeyLength + 28 else { throw SecretEnvelopeError.malformed }
        guard bytes[0] == version else { throw SecretEnvelopeError.unsupportedVersion(bytes[0]) }

        let ephemeralPublic = Data(bytes[1...publicKeyLength])
        let header = Data(bytes[0...publicKeyLength])
        let combined = Data(bytes[(publicKeyLength + 1)...])

        let sender: P256.KeyAgreement.PublicKey
        do {
            sender = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic)
        } catch {
            throw SecretEnvelopeError.malformed
        }

        let shared = try privateKey.sharedSecretFromKeyAgreement(with: sender)
        let key = derivedKey(shared, ephemeralPublic: ephemeralPublic, recipient: privateKey.publicKey)
        do {
            let box = try AES.GCM.SealedBox(combined: combined)
            return try AES.GCM.open(box, using: key, authenticating: header)
        } catch {
            throw SecretEnvelopeError.authenticationFailed
        }
    }

    public static func isEnvelope(_ data: Data) -> Bool {
        data.first == version && data.count > 1 + publicKeyLength + 28
    }

    private static func derivedKey(
        _ shared: SharedSecret,
        ephemeralPublic: Data,
        recipient: P256.KeyAgreement.PublicKey
    ) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: ephemeralPublic + recipient.x963Representation,
            sharedInfo: info,
            outputByteCount: 32
        )
    }
}

/// Keyed digest used to de-duplicate secrets without keeping their value.
public enum SecretDigest {
    public static func digest(_ value: String, key: SymmetricKey) -> String {
        let subkey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: key,
            info: Data("ClipVault secret digest v1".utf8),
            outputByteCount: 32
        )
        let mac = HMAC<SHA256>.authenticationCode(for: Data(value.utf8), using: subkey)
        return Data(mac).base64EncodedString()
    }
}
