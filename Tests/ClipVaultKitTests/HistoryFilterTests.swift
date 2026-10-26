import Foundation
import XCTest
@testable import ClipVaultKit

final class HistoryFilterTests: XCTestCase {

    private let token = "ghp_" + String(repeating: "Q7", count: 18)

    private lazy var items: [HistoryItem] = makeItems()

    private func makeItems() -> [HistoryItem] {
        var sealed = HistoryItem(text: "", sourceApp: "Terminal", secretKind: "GitHub token")
        sealed.secretPreview = SecretDetector.mask(token)
        sealed.sealedSecret = Data([1])
        return [
            HistoryItem(text: "Lunch at 12:30", sourceApp: "Messages"),
            HistoryItem(text: token, sourceApp: "Terminal", secretKind: "GitHub token"),
            sealed,
            HistoryItem(kind: .image, text: "", sourceApp: "Preview", imageFile: "a.bin", ocrText: "Invoice 42"),
            HistoryItem(kind: .image, text: "", imageFile: "b.bin", ocrText: "password hunter2", ocrSecretKind: "Secret in password")
        ]
    }

    func testEmptyQueryKeepsOrder() {
        XCTAssertEqual(HistoryFilter.apply(items, query: "  ").map(\.id), items.map(\.id))
    }

    func testMatchesTextAndSource() {
        XCTAssertEqual(HistoryFilter.apply(items, query: "lunch").count, 1)
        XCTAssertEqual(HistoryFilter.apply(items, query: "messages").count, 1)
    }

    func testMatchesNonSecretOCRText() {
        XCTAssertEqual(HistoryFilter.apply(items, query: "invoice").first?.sourceApp, "Preview")
    }

    func testSecretContentIsNotSearchable() {
        XCTAssertTrue(HistoryFilter.apply(items, query: "Q7Q7Q7").isEmpty)
        XCTAssertTrue(HistoryFilter.apply(items, query: "hunter2").isEmpty)
    }

    func testSecretsMatchByKind() {
        XCTAssertEqual(HistoryFilter.apply(items, query: "github").count, 2)
    }

    func testSealedSecretTitleNeverShowsValue() {
        let item = items[2]
        XCTAssertTrue(item.isSealed)
        XCTAssertEqual(item.title, "•••• GitHub token")
        XCTAssertEqual(item.maskedPreview, "ghp_••••••••")
    }
}
