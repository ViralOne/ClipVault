import Foundation
import ClipVaultKit

/// Encrypted blobs for image history. Each image is sealed separately so the
/// small history JSON does not have to be rewritten when a screenshot arrives.
///
/// Every file is sealed with the vault key. An image whose recognised text is
/// a secret is additionally sealed to the Secure Enclave inside that layer, and
/// is never kept in the decrypted cache.
final class ImageStore {
    static let shared = ImageStore()

    let directory: URL
    private let cache = NSCache<NSString, NSData>()

    private init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        directory = base
            .appendingPathComponent("ClipVault", isDirectory: true)
            .appendingPathComponent("images", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        cache.countLimit = 100
        cache.totalCostLimit = 120 * 1024 * 1024
    }

    /// Stores encrypted bytes and returns the filename used in `HistoryItem`.
    func save(_ data: Data, id: UUID) -> String? {
        let filename = "\(id.uuidString).bin"
        guard write(data, filename: filename) else { return nil }
        cache.setObject(data as NSData, forKey: filename as NSString, cost: data.count)
        return filename
    }

    /// Replaces a file's contents with a Secure Enclave envelope.
    @discardableResult
    func replaceWithEnvelope(_ envelope: Data, filename: String) -> Bool {
        cache.removeObject(forKey: filename as NSString)
        return write(envelope, filename: filename)
    }

    /// Plain image bytes, or the Secure Enclave envelope for a sealed image.
    func data(filename: String) -> Data? {
        if let cached = cache.object(forKey: filename as NSString) {
            return cached as Data
        }
        let url = directory.appendingPathComponent(filename)
        guard
            let sealed = try? Data(contentsOf: url),
            let plaintext = try? VaultCrypto.shared.open(sealed)
        else {
            return nil
        }
        // PNG and JPEG never start with the envelope version byte.
        if !SecretEnvelope.isEnvelope(plaintext) {
            cache.setObject(plaintext as NSData, forKey: filename as NSString, cost: plaintext.count)
        }
        return plaintext
    }

    func delete(filename: String) {
        cache.removeObject(forKey: filename as NSString)
        try? FileManager.default.removeItem(at: directory.appendingPathComponent(filename))
    }

    func deleteAll() {
        cache.removeAllObjects()
        try? FileManager.default.removeItem(at: directory)
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    var sizeOnDisk: Int {
        let keys: [URLResourceKey] = [.fileSizeKey]
        guard let files = try? FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: keys
        ) else { return 0 }
        return files.reduce(0) { total, url in
            let size = (try? url.resourceValues(forKeys: Set(keys)).fileSize) ?? 0
            return total + size
        }
    }

    private func write(_ data: Data, filename: String) -> Bool {
        do {
            let url = directory.appendingPathComponent(filename)
            let sealed = try VaultCrypto.shared.seal(data)
            try sealed.write(to: url, options: [.atomic])
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            return true
        } catch {
            return false
        }
    }
}
