import Combine
import CryptoKit
import Foundation
import LocalAuthentication
import ClipVaultKit

/// Plain content of an item, ready to be written to the pasteboard.
struct ClipPayload {
    var text: String?
    var imageData: Data?
    var uti: String
    var isSecret: Bool
}

enum UnsealError: LocalizedError {
    case unavailable

    var errorDescription: String? {
        "This secret can't be unsealed on this Mac. It was sealed to a Secure Enclave key that no longer exists."
    }
}

/// Encrypted, on-device clipboard history.
///
/// Text and OCR results live in one AES-256-GCM sealed JSON file. Images are
/// sealed separately in `Application Support/ClipVault/images`. The vault key
/// lives in the login Keychain. Secret values get a second layer: they are
/// sealed to a Secure Enclave key that needs Touch ID or the login password.
/// If the key or a file cannot be read the store keeps working in memory and
/// never overwrites unreadable data.
@MainActor
final class HistoryStore: ObservableObject {
    @Published private(set) var items: [HistoryItem] = []
    @Published private(set) var isEphemeral = false
    @Published private(set) var lastError: String?

    let directory: URL
    let fileURL: URL
    private let ioQueue = DispatchQueue(label: "app.clipvault.history-io", qos: .utility)

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        directory = base.appendingPathComponent("ClipVault", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        fileURL = directory.appendingPathComponent("history.enc")
        load()
        sealUnsealedSecrets()
    }

    var storageSummary: String {
        isEphemeral ? "Memory only — encrypted file unavailable" : "Encrypted at rest · AES-256-GCM"
    }

    var secretCount: Int { items.filter(\.isSecret).count }
    var imageCount: Int { items.filter(\.isImage).count }
    var pinnedCount: Int { items.filter(\.pinned).count }

    var bytesOnDisk: Int {
        let historySize = (try? fileURL.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        return historySize + ImageStore.shared.sizeOnDisk
    }

    // MARK: - Adding

    func add(text: String, sourceApp: String?, bundleID: String?, secretKind: String?) {
        let capped = text.count > 200_000 ? String(text.prefix(200_000)) : text
        guard !capped.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }

        if let secretKind {
            addSecret(capped, kind: secretKind, sourceApp: sourceApp, bundleID: bundleID)
            return
        }

        if let index = items.firstIndex(where: { !$0.isImage && !$0.isSecret && $0.text == capped }) {
            refresh(index, sourceApp: sourceApp, bundleID: bundleID)
        } else {
            insertNew(HistoryItem(text: capped, sourceApp: sourceApp, sourceBundleID: bundleID))
        }
        enforceLimit()
        pruneInMemory()
        persist()
    }

    private func addSecret(_ text: String, kind: String, sourceApp: String?, bundleID: String?) {
        let digest = try? SecretDigest.digest(text, key: VaultCrypto.shared.encryptionKey())

        // The same secret copied twice refreshes the existing entry. A plain
        // copy of the same text is replaced so the value is not kept twice.
        if let index = items.firstIndex(where: { item in
            guard !item.isImage, item.secretKind != nil else { return false }
            if let digest, item.secretDigest == digest { return true }
            return !item.isSealed && item.text == text
        }) {
            refresh(index, sourceApp: sourceApp, bundleID: bundleID)
            persist()
            return
        }
        if let plain = items.firstIndex(where: { !$0.isImage && !$0.isSecret && $0.text == text }) {
            removeItems(IndexSet(integer: plain), persistChanges: false)
        }

        var item = HistoryItem(text: text, sourceApp: sourceApp, sourceBundleID: bundleID, secretKind: kind)
        item.secretPreview = SecretDetector.mask(text)
        item.secretDigest = digest
        sealText(&item)
        insertNew(item)
        enforceLimit()
        pruneInMemory()
        persist()
    }

    @discardableResult
    func addImage(
        _ data: Data,
        hash: String,
        uti: String,
        sourceApp: String?,
        bundleID: String?,
        width: Int,
        height: Int
    ) -> (id: UUID, isNew: Bool)? {
        // A repeated image keeps its earlier OCR result and seal.
        if let index = items.firstIndex(where: { $0.imageHash == hash }) {
            refresh(index, sourceApp: sourceApp, bundleID: bundleID)
            persist()
            return items.first { $0.imageHash == hash }.map { ($0.id, false) }
        }

        let itemID = UUID()
        guard let filename = ImageStore.shared.save(data, id: itemID) else {
            lastError = "Could not store an image in the encrypted store."
            return nil
        }

        insertNew(HistoryItem(
            id: itemID,
            kind: .image,
            text: "",
            sourceApp: sourceApp,
            sourceBundleID: bundleID,
            imageFile: filename,
            imageUTI: uti,
            imageWidth: width,
            imageHeight: height,
            imageHash: hash
        ))
        enforceLimit()
        pruneInMemory()
        persist()
        return (itemID, true)
    }

    /// Attaches OCR output. When the recognised text is a secret, both the text
    /// and the image bytes are sealed to the Secure Enclave.
    func attachImageInsight(id: UUID, ocrText: String?, secretKind: String?, imageData: Data?) {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return }
        // Never downgrade an item that is already secret or sealed.
        guard !items[index].isSecret, !items[index].isSealed, !items[index].imageSealed else { return }
        items[index].ocrText = ocrText
        items[index].ocrSecretKind = secretKind
        if secretKind != nil {
            sealImage(&items[index], plaintext: imageData)
        }
        persist()
    }

    // MARK: - Reading

    /// Image bytes for a non-sealed image.
    func imageData(for item: HistoryItem) -> Data? {
        guard let filename = item.imageFile, !item.imageSealed else { return nil }
        return ImageStore.shared.data(filename: filename)
    }

    /// Content of a non-secret item. Secrets go through `unseal`.
    func payload(for item: HistoryItem) -> ClipPayload? {
        guard !item.isSecret else { return nil }
        if item.isImage {
            guard let data = imageData(for: item) else { return nil }
            return ClipPayload(text: nil, imageData: data, uti: item.imageUTI ?? "public.png", isSecret: false)
        }
        return ClipPayload(text: item.text, imageData: nil, uti: "public.utf8-plain-text", isSecret: false)
    }

    /// Decrypts a secret item. `context` must already be authenticated.
    func unseal(_ item: HistoryItem, context: LAContext) throws -> ClipPayload {
        let vault = SecretVault.shared

        var text: String?
        if let envelope = item.sealedSecret {
            guard vault.isAvailable else { throw UnsealError.unavailable }
            text = String(decoding: try openSealed(envelope, vault: vault, context: context), as: UTF8.self)
        } else {
            text = item.isImage ? item.ocrText : item.text
        }

        var imageData: Data?
        if item.isImage, let filename = item.imageFile {
            guard let stored = ImageStore.shared.data(filename: filename) else { throw VaultError.corruptCiphertext }
            if item.imageSealed {
                guard vault.isAvailable else { throw UnsealError.unavailable }
                imageData = try openSealed(stored, vault: vault, context: context)
            } else {
                imageData = stored
            }
        }

        return ClipPayload(
            text: text,
            imageData: imageData,
            uti: item.isImage ? (item.imageUTI ?? "public.png") : "public.utf8-plain-text",
            isSecret: true
        )
    }

    /// A sealed value that no longer opens was sealed to an earlier key.
    private func openSealed(_ envelope: Data, vault: SecretVault, context: LAContext) throws -> Data {
        do {
            return try vault.open(envelope, context: context)
        } catch SecretEnvelopeError.authenticationFailed, SecretEnvelopeError.malformed {
            throw UnsealError.unavailable
        }
    }

    // MARK: - Ordering

    func togglePin(_ id: UUID) {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return }
        var item = items.remove(at: index)
        item.pinned.toggle()
        // Pinned items form one block at the top; an unpinned item goes to the
        // top of the rest.
        let insertAt = item.pinned ? 0 : items.firstIndex(where: { !$0.pinned }) ?? items.count
        items.insert(item, at: insertAt)
        persist()
    }

    /// Moves one item by `offset` positions within its group (pinned or not).
    /// Used by the ↑/↓ reorder actions.
    func move(_ id: UUID, by offset: Int) {
        guard offset != 0, let index = items.firstIndex(where: { $0.id == id }) else { return }
        let target = index + offset
        guard items.indices.contains(target), items[target].pinned == items[index].pinned else { return }
        items.swapAt(index, target)
        persist()
    }

    func canMove(_ id: UUID, by offset: Int) -> Bool {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return false }
        let target = index + offset
        return items.indices.contains(target) && items[target].pinned == items[index].pinned
    }

    /// SwiftUI list reorder semantics over the full, unfiltered list. Pinned
    /// items stay grouped at the top afterwards.
    func move(from source: IndexSet, to destination: Int) {
        guard !source.isEmpty else { return }
        var reordered = items
        reordered.move(fromOffsets: source, toOffset: destination)
        items = reordered.filter(\.pinned) + reordered.filter { !$0.pinned }
        persist()
    }

    // MARK: - Removing

    func delete(_ id: UUID) {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return }
        removeItems(IndexSet(integer: index))
    }

    /// Removes items copied since `date` whose value is one of `texts`. Used to
    /// drop onboarding samples, including secrets matched by their digest.
    func deleteItems(matching texts: [String], since date: Date) {
        guard !texts.isEmpty else { return }
        let plain = Set(texts)
        let digests: Set<String>
        if let key = try? VaultCrypto.shared.encryptionKey() {
            digests = Set(texts.map { SecretDigest.digest($0, key: key) })
        } else {
            digests = []
        }
        let offsets = IndexSet(items.indices.filter { index in
            let item = items[index]
            guard !item.isImage, item.createdAt >= date else { return false }
            if let digest = item.secretDigest, digests.contains(digest) { return true }
            return !item.isSealed && plain.contains(item.text)
        })
        if !offsets.isEmpty { removeItems(offsets) }
    }

    func clearAll(keepPinned: Bool = false) {
        let offsets = IndexSet(items.indices.filter { !keepPinned || !items[$0].pinned })
        removeItems(offsets)
    }

    func removeSecrets() {
        let offsets = IndexSet(items.indices.filter { items[$0].isSecret })
        guard !offsets.isEmpty else { return }
        removeItems(offsets)
    }

    /// Deletes encrypted files as well as the in-memory copy. Used to recover
    /// from a key or file that can no longer be read.
    func resetVault() {
        flush()
        VaultCrypto.shared.resetKey()
        try? FileManager.default.removeItem(at: fileURL)
        ImageStore.shared.deleteAll()
        items.removeAll()
        isEphemeral = false
        lastError = nil
    }

    // MARK: - Persistence

    /// Retries a load that failed because the Keychain was still locked, for
    /// example right after login. Items captured meanwhile are kept.
    func retryLoadIfNeeded() {
        guard isEphemeral,
              FileManager.default.fileExists(atPath: fileURL.path),
              let ciphertext = try? Data(contentsOf: fileURL),
              let plaintext = try? VaultCrypto.shared.open(ciphertext),
              let decoded = try? JSONDecoder.vault.decode([HistoryItem].self, from: plaintext) else { return }
        let captured = items
        let merged = captured + decoded.filter { old in !captured.contains { $0.id == old.id } }
        items = merged.filter(\.pinned) + merged.filter { !$0.pinned }
        isEphemeral = false
        lastError = nil
        sealUnsealedSecrets()
        persist()
    }

    private func load() {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return }
        do {
            let ciphertext = try Data(contentsOf: fileURL)
            let plaintext = try VaultCrypto.shared.open(ciphertext)
            let decoded = try JSONDecoder.vault.decode([HistoryItem].self, from: plaintext)
            items = decoded.filter(\.pinned) + decoded.filter { !$0.pinned }
            pruneInMemory()
        } catch {
            isEphemeral = true
            lastError = "Could not read history: \(error.localizedDescription)"
        }
    }

    private func persist() {
        guard !isEphemeral else { return }
        let snapshot = items
        let url = fileURL
        ioQueue.async { [weak self] in
            do {
                let data = try JSONEncoder.vault.encode(snapshot)
                let sealed = try VaultCrypto.shared.seal(data)
                try sealed.write(to: url, options: [.atomic])
                try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
                Task { @MainActor in
                    if self?.lastError?.hasPrefix("Could not save") == true { self?.lastError = nil }
                }
            } catch {
                Task { @MainActor in
                    self?.lastError = "Could not save history: \(error.localizedDescription)"
                }
            }
        }
    }

    /// Waits for pending writes. Called before quitting.
    func flush() {
        ioQueue.sync {}
    }

    // MARK: - Secure Enclave sealing

    private func sealText(_ item: inout HistoryItem) {
        guard SecretVault.shared.isAvailable, !item.isImage, !item.isSealed else { return }
        guard let envelope = try? SecretVault.shared.seal(item.text) else { return }
        item.sealedSecret = envelope
        item.text = ""
    }

    private func sealImage(_ item: inout HistoryItem, plaintext: Data?) {
        let vault = SecretVault.shared
        guard vault.isAvailable else { return }

        if let ocr = item.ocrText, item.sealedSecret == nil,
           let envelope = try? vault.seal(ocr) {
            item.sealedSecret = envelope
            item.ocrText = nil
        }

        guard !item.imageSealed, let filename = item.imageFile else { return }
        let bytes = plaintext ?? ImageStore.shared.data(filename: filename)
        guard let bytes,
              let envelope = try? vault.seal(bytes),
              ImageStore.shared.replaceWithEnvelope(envelope, filename: filename) else { return }
        item.imageSealed = true
    }

    /// Seals secrets saved before Secure Enclave sealing existed, or while the
    /// key was unavailable.
    private func sealUnsealedSecrets() {
        guard SecretVault.shared.isAvailable, !isEphemeral else { return }
        var changed = false

        for index in items.indices where items[index].isSecret {
            var item = items[index]
            if item.isImage {
                guard item.sealedSecret == nil || !item.imageSealed else { continue }
                sealImage(&item, plaintext: nil)
            } else {
                guard !item.isSealed else { continue }
                if item.secretPreview == nil { item.secretPreview = SecretDetector.mask(item.text) }
                if item.secretDigest == nil, let key = try? VaultCrypto.shared.encryptionKey() {
                    item.secretDigest = SecretDigest.digest(item.text, key: key)
                }
                sealText(&item)
            }
            if item != items[index] {
                items[index] = item
                changed = true
            }
        }
        if changed { persist() }
    }

    // MARK: - Helpers

    private func insertNew(_ item: HistoryItem) {
        let insertAt = items.firstIndex(where: { !$0.pinned }) ?? items.count
        items.insert(item, at: item.pinned ? 0 : insertAt)
    }

    /// A repeated copy moves to the top of its group with a fresh timestamp.
    private func refresh(_ index: Int, sourceApp: String?, bundleID: String?) {
        var item = items.remove(at: index)
        item.createdAt = Date()
        if let sourceApp { item.sourceApp = sourceApp }
        if let bundleID { item.sourceBundleID = bundleID }
        if item.pinned {
            items.insert(item, at: index)
        } else {
            insertNew(item)
        }
    }

    private func enforceLimit() {
        let limit = max(10, UserDefaults.standard.integer(forKey: Prefs.historyLimit))
        while items.count > limit {
            guard let index = items.lastIndex(where: { !$0.pinned }) else { break }
            removeItems(IndexSet(integer: index), persistChanges: false)
        }
    }

    private func pruneInMemory() {
        let days = UserDefaults.standard.integer(forKey: Prefs.retentionDays)
        guard days > 0 else { return }
        guard let cutoff = Calendar.current.date(byAdding: .day, value: -days, to: Date()) else { return }
        for index in items.indices.reversed()
        where !items[index].pinned && items[index].createdAt < cutoff {
            removeItems(IndexSet(integer: index), persistChanges: false)
        }
    }

    private func removeItems(_ offsets: IndexSet, persistChanges: Bool = true) {
        for index in offsets.sorted(by: >) where items.indices.contains(index) {
            if let file = items[index].imageFile {
                ImageStore.shared.delete(filename: file)
            }
            items.remove(at: index)
        }
        if persistChanges { persist() }
    }
}

extension JSONEncoder {
    static var vault: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }
}

extension JSONDecoder {
    static var vault: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
