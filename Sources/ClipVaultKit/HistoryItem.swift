import Foundation

/// One entry in the local clipboard history.
///
/// Text items keep their value in `text`. Image items keep their bytes in an
/// encrypted file referenced by `imageFile`, plus the text recognised by OCR in
/// `ocrText`. A non-nil `secretKind` (text) or `ocrSecretKind` (image) means the
/// item contains a secret.
///
/// When the Secure Enclave is available a secret's value is moved out of
/// `text`/`ocrText` into `sealedSecret`, an envelope that only opens after the
/// user authenticates. The item then carries just a masked preview, its length
/// and a keyed digest used for de-duplication.
public struct HistoryItem: Identifiable, Codable, Hashable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case text
        case image
    }

    public var id: UUID
    public var kind: Kind
    public var text: String
    public var createdAt: Date
    public var sourceApp: String?
    public var sourceBundleID: String?
    public var secretKind: String?
    public var pinned: Bool
    public var characterCount: Int

    // Secrets sealed to the Secure Enclave
    public var sealedSecret: Data?
    public var secretPreview: String?
    public var secretDigest: String?

    // Image items
    public var imageFile: String?
    public var imageUTI: String?
    public var imageWidth: Int
    public var imageHeight: Int
    public var imageHash: String?
    public var imageSealed: Bool
    public var ocrText: String?
    public var ocrSecretKind: String?

    public init(
        id: UUID = UUID(),
        kind: Kind = .text,
        text: String,
        createdAt: Date = Date(),
        sourceApp: String? = nil,
        sourceBundleID: String? = nil,
        secretKind: String? = nil,
        pinned: Bool = false,
        imageFile: String? = nil,
        imageUTI: String? = nil,
        imageWidth: Int = 0,
        imageHeight: Int = 0,
        imageHash: String? = nil,
        ocrText: String? = nil,
        ocrSecretKind: String? = nil
    ) {
        self.id = id
        self.kind = kind
        self.text = text
        self.createdAt = createdAt
        self.sourceApp = sourceApp
        self.sourceBundleID = sourceBundleID
        self.secretKind = secretKind
        self.pinned = pinned
        self.characterCount = text.count
        self.imageFile = imageFile
        self.imageUTI = imageUTI
        self.imageWidth = imageWidth
        self.imageHeight = imageHeight
        self.imageHash = imageHash
        self.imageSealed = false
        self.ocrText = ocrText
        self.ocrSecretKind = ocrSecretKind
    }

    public var isImage: Bool { kind == .image }

    /// True when the value or the text recognised inside an image is secret.
    public var isSecret: Bool { secretKind != nil || ocrSecretKind != nil }

    /// True only for images whose recognised text contains a secret.
    public var hasSecretText: Bool { ocrSecretKind != nil }

    /// True when the secret value is not in memory and must be unsealed.
    public var isSealed: Bool { sealedSecret != nil }

    public var displayKind: String? { secretKind ?? ocrSecretKind }

    public var title: String {
        if isSecret { return "•••• \(displayKind ?? "Secret")" }
        return isImage ? imageTitle : textTitle
    }

    public var textTitle: String {
        let firstLine = text.split(whereSeparator: { $0.isNewline }).first.map(String.init) ?? text
        let trimmed = firstLine.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? "Whitespace" : trimmed
    }

    public var imageTitle: String {
        if let ocrSecretKind {
            return "Image · \(ocrSecretKind.lowercased())"
        }
        if let ocrText,
           let firstLine = ocrText.split(whereSeparator: { $0.isNewline }).first {
            let trimmed = String(firstLine).trimmingCharacters(in: .whitespaces)
            if !trimmed.isEmpty { return trimmed }
        }
        return "Image"
    }

    public var kindLabel: String {
        if isImage {
            if let ocrSecretKind { return "Image · \(ocrSecretKind)" }
            if ocrText != nil { return "Image · text detected" }
            return "Image · \(imageWidth)×\(imageHeight)"
        }
        if let secretKind { return secretKind }
        if isLink { return "Link" }
        return text.contains("\n") ? "Multi-line text" : "Text"
    }

    public var maskedPreview: String {
        if isImage {
            return ocrSecretKind == nil ? "Image" : "Image · secret text"
        }
        if let secretPreview { return secretPreview }
        return SecretDetector.mask(text)
    }

    /// OCR text is searchable only when it is not secret, so a search cannot be
    /// used to probe hidden content.
    public var searchableOCRText: String? {
        guard isImage, ocrSecretKind == nil else { return nil }
        return ocrText
    }

    public var maskedOCRPreview: String {
        if ocrSecretKind != nil { return "••••••••" }
        guard let ocrText else { return "No text recognised" }
        return SecretDetector.mask(ocrText)
    }

    public var isLink: Bool {
        guard !isImage, !isSecret else { return false }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.contains(where: \.isWhitespace) else { return false }
        return trimmed.hasPrefix("http://") || trimmed.hasPrefix("https://")
    }

    /// Rough "is this source code" check used to pick a monospaced preview.
    public var looksLikeCode: Bool {
        guard !isImage, !isSecret else { return false }
        let markers = ["{", "}", ";", "()", "=>", "->", "func ", "let ", "const ", "def ", "import ", "</", "$ "]
        let hits = markers.filter { text.contains($0) }.count
        return hits >= 2 || (text.contains("\n") && hits >= 1)
    }

    public var wordCount: Int {
        text.split(whereSeparator: { $0.isWhitespace || $0.isNewline }).count
    }

    // MARK: - Codable

    private enum CodingKeys: String, CodingKey {
        case id, kind, text, createdAt, sourceApp, sourceBundleID, secretKind, pinned, characterCount
        case sealedSecret, secretPreview, secretDigest
        case imageFile, imageUTI, imageWidth, imageHeight, imageHash, imageSealed, ocrText, ocrSecretKind
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        text = try container.decodeIfPresent(String.self, forKey: .text) ?? ""
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        sourceApp = try container.decodeIfPresent(String.self, forKey: .sourceApp)
        sourceBundleID = try container.decodeIfPresent(String.self, forKey: .sourceBundleID)
        secretKind = try container.decodeIfPresent(String.self, forKey: .secretKind)
        pinned = try container.decodeIfPresent(Bool.self, forKey: .pinned) ?? false
        characterCount = try container.decodeIfPresent(Int.self, forKey: .characterCount) ?? text.count
        sealedSecret = try container.decodeIfPresent(Data.self, forKey: .sealedSecret)
        secretPreview = try container.decodeIfPresent(String.self, forKey: .secretPreview)
        secretDigest = try container.decodeIfPresent(String.self, forKey: .secretDigest)
        imageFile = try container.decodeIfPresent(String.self, forKey: .imageFile)
        imageUTI = try container.decodeIfPresent(String.self, forKey: .imageUTI)
        imageWidth = try container.decodeIfPresent(Int.self, forKey: .imageWidth) ?? 0
        imageHeight = try container.decodeIfPresent(Int.self, forKey: .imageHeight) ?? 0
        imageHash = try container.decodeIfPresent(String.self, forKey: .imageHash)
        imageSealed = try container.decodeIfPresent(Bool.self, forKey: .imageSealed) ?? false
        ocrText = try container.decodeIfPresent(String.self, forKey: .ocrText)
        ocrSecretKind = try container.decodeIfPresent(String.self, forKey: .ocrSecretKind)

        let decodedKind = try container.decodeIfPresent(Kind.self, forKey: .kind)
        if let decodedKind {
            kind = decodedKind
        } else {
            kind = imageFile == nil ? .text : .image
        }
    }
}

// MARK: - Filtering

public enum HistoryFilter {
    /// Filters in the stored order, so a manual reorder is preserved. Nothing
    /// is sorted here: pinned items move to the top when they are pinned.
    public static func apply(_ items: [HistoryItem], query: String) -> [HistoryItem] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return items }
        return items.filter { matches($0, needle: needle) }
    }

    public static func matches(_ item: HistoryItem, needle: String) -> Bool {
        let source = item.sourceApp ?? ""
        if source.localizedCaseInsensitiveContains(needle) { return true }

        if item.isSecret {
            // A secret can be found by its kind or masked prefix, never by
            // its hidden content.
            let kind = item.displayKind ?? ""
            return kind.localizedCaseInsensitiveContains(needle)
                || item.maskedPreview.localizedCaseInsensitiveContains(needle)
        }

        if item.isImage {
            if item.title.localizedCaseInsensitiveContains(needle) { return true }
            if let ocr = item.searchableOCRText,
               ocr.localizedCaseInsensitiveContains(needle) {
                return true
            }
            return item.kindLabel.localizedCaseInsensitiveContains(needle)
        }

        return item.text.localizedCaseInsensitiveContains(needle)
    }
}
