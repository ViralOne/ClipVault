import Foundation
import XCTest
@testable import ClipVaultKit

final class HistoryItemTests: XCTestCase {

    func testLegacyTextItemDecodesWithoutImageFields() throws {
        let json = """
        {
          "id": "C0FFEE00-1111-2222-3333-444455556666",
          "text": "hello world",
          "createdAt": "2026-01-02T03:04:05Z"
        }
        """
        let item = try decoder.decode(HistoryItem.self, from: Data(json.utf8))

        XCTAssertEqual(item.kind, .text)
        XCTAssertFalse(item.isImage)
        XCTAssertEqual(item.text, "hello world")
        XCTAssertEqual(item.characterCount, 11)
        XCTAssertNil(item.imageFile)
        XCTAssertNil(item.ocrText)
    }

    func testImageWithSearchableOCRText() {
        let item = HistoryItem(
            kind: .image,
            text: "",
            imageFile: "image.bin",
            imageUTI: "public.png",
            imageWidth: 800,
            imageHeight: 400,
            imageHash: "abc",
            ocrText: "Deployment notes\nRun the migration",
            ocrSecretKind: nil
        )

        XCTAssertTrue(item.isImage)
        XCTAssertFalse(item.isSecret)
        XCTAssertEqual(item.title, "Deployment notes")
        XCTAssertEqual(item.searchableOCRText, "Deployment notes\nRun the migration")
        XCTAssertEqual(item.kindLabel, "Image · text detected")
    }

    func testSecretOCRTextIsNotSearchable() {
        let item = HistoryItem(
            kind: .image,
            text: "",
            imageFile: "image.bin",
            imageWidth: 800,
            imageHeight: 400,
            ocrText: "ghp_" + String(repeating: "Zx", count: 18),
            ocrSecretKind: "GitHub token"
        )

        XCTAssertTrue(item.isSecret)
        XCTAssertTrue(item.hasSecretText)
        XCTAssertNil(item.searchableOCRText)
        XCTAssertEqual(item.maskedPreview, "Image · secret text")
        XCTAssertEqual(item.kindLabel, "Image · GitHub token")
        XCTAssertEqual(item.maskedOCRPreview, "••••••••")
    }

    func testImageRoundTripKeepsOCRFields() throws {
        let original = HistoryItem(
            kind: .image,
            text: "",
            sourceApp: "Preview",
            imageFile: "abc.bin",
            imageUTI: "public.jpeg",
            imageWidth: 640,
            imageHeight: 480,
            imageHash: "deadbeef",
            ocrText: "Invoice 42",
            ocrSecretKind: nil
        )

        let data = try encoder.encode(original)
        let decoded = try decoder.decode(HistoryItem.self, from: data)

        XCTAssertEqual(decoded.id, original.id)
        XCTAssertEqual(decoded.kind, .image)
        XCTAssertEqual(decoded.imageFile, "abc.bin")
        XCTAssertEqual(decoded.imageUTI, "public.jpeg")
        XCTAssertEqual(decoded.imageWidth, 640)
        XCTAssertEqual(decoded.imageHeight, 480)
        XCTAssertEqual(decoded.ocrText, "Invoice 42")
        XCTAssertEqual(decoded.sourceApp, "Preview")
    }

    func testSealedFieldsRoundTrip() throws {
        var item = HistoryItem(text: "", sourceApp: "Terminal", sourceBundleID: "com.apple.Terminal", secretKind: "AWS access key")
        item.sealedSecret = Data([1, 2, 3])
        item.secretPreview = "AKIA••••••••"
        item.secretDigest = "digest"
        item.imageSealed = true

        let decoded = try decoder.decode(HistoryItem.self, from: encoder.encode(item))
        XCTAssertEqual(decoded.sealedSecret, Data([1, 2, 3]))
        XCTAssertEqual(decoded.secretPreview, "AKIA••••••••")
        XCTAssertEqual(decoded.secretDigest, "digest")
        XCTAssertEqual(decoded.sourceBundleID, "com.apple.Terminal")
        XCTAssertTrue(decoded.imageSealed)
        XCTAssertTrue(decoded.isSealed)
    }

    func testLinkAndCodeDetection() {
        XCTAssertTrue(HistoryItem(text: "https://developer.apple.com/documentation").isLink)
        XCTAssertFalse(HistoryItem(text: "see https://apple.com for more").isLink)
        XCTAssertTrue(HistoryItem(text: "let item = NSPasteboardItem()\nitem.setString(text, forType: .string)").looksLikeCode)
        XCTAssertFalse(HistoryItem(text: "Can you review the onboarding copy before the sync?").looksLikeCode)
        XCTAssertEqual(HistoryItem(text: "one two  three\nfour").wordCount, 4)
    }

    // MARK: - Helpers

    private var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    private var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
