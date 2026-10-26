import CoreGraphics
import CoreText
import Foundation
import ImageIO
import XCTest
@testable import ClipVaultKit

final class OCRServiceTests: XCTestCase {

    func testRecognizesRenderedText() async throws {
        let data = try makeImageData(text: "ClipVault OCR 4821")
        let text = await OCRService.recognizeText(in: data)
        XCTAssertTrue(
            text.lowercased().contains("clipvault"),
            "OCR did not find the rendered text. Got: \(text)"
        )
    }

    func testBlankImageReturnsNoText() async throws {
        let data = try makeImageData(text: " ")
        let text = await OCRService.recognizeText(in: data)
        XCTAssertTrue(text.isEmpty)
    }

    // MARK: - Helpers

    private func makeImageData(text: String) throws -> Data {
        let width = 1_000
        let height = 300
        guard let context = CGContext(
            data: nil,
            width: width,
            height: height,
            bitsPerComponent: 8,
            bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        ) else {
            throw XCTSkip("Could not create a bitmap context")
        }

        context.setFillColor(CGColor(gray: 1, alpha: 1))
        context.fill(CGRect(x: 0, y: 0, width: width, height: height))

        let font = CTFontCreateWithName("Helvetica-Bold" as CFString, 76, nil)
        let attributes: [NSAttributedString.Key: Any] = [
            .font: font,
            .foregroundColor: CGColor(gray: 0, alpha: 1)
        ]
        let line = CTLineCreateWithAttributedString(
            NSAttributedString(string: text, attributes: attributes)
        )
        context.textPosition = CGPoint(x: 40, y: 110)
        CTLineDraw(line, context)

        guard let image = context.makeImage() else {
            throw XCTSkip("Could not render the test image")
        }

        let output = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(
            output,
            "public.png" as CFString,
            1,
            nil
        ) else {
            throw XCTSkip("Could not create an image destination")
        }
        CGImageDestinationAddImage(destination, image, nil)
        guard CGImageDestinationFinalize(destination) else {
            throw XCTSkip("Could not encode the test image")
        }
        return output as Data
    }
}
