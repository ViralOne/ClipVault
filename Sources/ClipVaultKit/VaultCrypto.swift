import CryptoKit
import Foundation
import Security

public enum VaultError: LocalizedError {
    case keychain(OSStatus)
    case keychainUnavailable
    case corruptCiphertext

    public var errorDescription: String? {
        switch self {
        case .keychain(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            return "Keychain error: \(message)"
        case .keychainUnavailable:
            return "The encryption key could not be read from the login Keychain."
        case .corruptCiphertext:
            return "The encrypted history file could not be decrypted."
        }
    }
}

/// Minimal generic-password Keychain access. Items are device-only, never
/// synchronised, and readable only while the Mac is unlocked.
public enum Keychain {
    public static func read(service: String, account: String) throws -> Data? {
        var query = baseQuery(service: service, account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else { throw VaultError.keychainUnavailable }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw VaultError.keychain(status)
        }
    }

    /// Adds an item. Returns false when one already exists, so a concurrent
    /// writer's value wins instead of being overwritten.
    @discardableResult
    public static func add(_ data: Data, service: String, account: String, label: String) throws -> Bool {
        var add = baseQuery(service: service, account: account)
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        add[kSecAttrSynchronizable as String] = false
        add[kSecAttrLabel as String] = label

        let status = SecItemAdd(add as CFDictionary, nil)
        switch status {
        case errSecSuccess: return true
        case errSecDuplicateItem: return false
        default: throw VaultError.keychain(status)
        }
    }

    public static func delete(service: String, account: String) {
        SecItemDelete(baseQuery(service: service, account: account) as CFDictionary)
    }

    private static func baseQuery(service: String, account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }
}

/// AES-256-GCM seal/open with a 256-bit key stored as a device-only item in the
/// user's login Keychain. The key is never written to disk by the app.
public final class VaultCrypto {
    public static let shared = VaultCrypto()

    private let service: String
    private let account: String
    private let lock = NSLock()
    private var cachedKey: SymmetricKey?

    /// 0.3 moved to a new item: the sandboxed, hardened build has a different
    /// code signature, so it cannot (and should not) silently read the key an
    /// older build created.
    public init(service: String = "app.clipvault.ClipVault", account: String = "vault-key") {
        self.service = service
        self.account = account
    }

    public func encryptionKey() throws -> SymmetricKey {
        lock.lock()
        defer { lock.unlock() }

        if let cachedKey { return cachedKey }

        if let existing = try Keychain.read(service: service, account: account) {
            guard existing.count == 32 else { throw VaultError.keychainUnavailable }
            let key = SymmetricKey(data: existing)
            cachedKey = key
            return key
        }

        let key = SymmetricKey(size: .bits256)
        let bytes = key.withUnsafeBytes { Data($0) }
        let added = try Keychain.add(
            bytes,
            service: service,
            account: account,
            label: "ClipVault history encryption key"
        )
        if !added {
            // A concurrent instance created it first; use that one.
            guard let existing = try Keychain.read(service: service, account: account),
                  existing.count == 32 else { throw VaultError.keychainUnavailable }
            cachedKey = SymmetricKey(data: existing)
            return cachedKey!
        }
        cachedKey = key
        return key
    }

    /// Deletes the Keychain key. Everything sealed with it becomes unreadable;
    /// the next seal creates a new key.
    public func resetKey() {
        lock.lock()
        cachedKey = nil
        Keychain.delete(service: service, account: account)
        lock.unlock()
    }

    public func seal(_ plaintext: Data) throws -> Data {
        let key = try encryptionKey()
        guard let combined = try AES.GCM.seal(plaintext, using: key).combined else {
            throw VaultError.corruptCiphertext
        }
        return combined
    }

    public func open(_ ciphertext: Data) throws -> Data {
        let key = try encryptionKey()
        do {
            let box = try AES.GCM.SealedBox(combined: ciphertext)
            return try AES.GCM.open(box, using: key)
        } catch {
            throw VaultError.corruptCiphertext
        }
    }
}
