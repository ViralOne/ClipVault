import Foundation
import XCTest
@testable import ClipVaultKit

final class SecretPatternTests: XCTestCase {

    func testEveryPatternCompiles() {
        XCTAssertEqual(SecretDetector.patternCount, SecretPatterns.all.count)
    }

    func testKeywordsAreLowercase() {
        for pattern in SecretPatterns.all {
            for keyword in pattern.keywords {
                XCTAssertEqual(keyword, keyword.lowercased(), "\(pattern.kind): keyword \(keyword)")
                XCTAssertFalse(keyword.isEmpty, pattern.kind)
            }
        }
    }

    func testEveryKindHasASample() {
        let sampled = Set(SecretSamples.all.map(\.kind))
        let coreKinds = Set(SecretPatterns.core.map(\.kind))
        let missing = Set(SecretPatterns.all.map(\.kind))
            .subtracting(coreKinds)
            .subtracting(sampled)
        XCTAssertTrue(missing.isEmpty, "No sample for: \(missing.sorted().joined(separator: ", "))")
    }

    func testSamplesAreDetectedAsTheirKind() {
        var failures: [String] = []
        for sample in SecretSamples.all {
            let kind = SecretDetector.detect(sample.value)?.kind
            if kind != sample.kind {
                failures.append("\(sample.kind) → \(kind ?? "nil")")
            }
        }
        XCTAssertTrue(failures.isEmpty, "\(failures.count) samples misdetected:\n" + failures.joined(separator: "\n"))
    }

    func testSamplesInsideSurroundingText() {
        var failures: [String] = []
        for sample in SecretSamples.all where !sample.value.contains("\n") {
            let text = "Here you go: \(sample.value) — keep it safe."
            if SecretDetector.detect(text) == nil { failures.append(sample.kind) }
        }
        XCTAssertTrue(failures.isEmpty, "Not found in text: \(failures.joined(separator: ", "))")
    }

    /// Ordinary things people copy must never be flagged.
    func testOrdinaryTextIsNotSecret() {
        let corpus = [
            "Can you review the onboarding copy before the 3pm sync? Comments are on steps 2 and 4.",
            "Lunch at 12:30, bring the slides",
            "1 Infinite Loop, Cupertino, CA 95014",
            "https://developer.apple.com/documentation/appkit/nspasteboard",
            "https://github.com/ViralOne/ClipVault/pull/42/files",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://docs.google.com/document/d/1A2b3C4d5E6f7G8h9I0j/edit",
            "git push origin main",
            "brew install --cask clipvault",
            "docker run -p 8080:80 nginx:1.27-alpine",
            "kubectl get pods -n kube-system",
            "npm install --save-dev typescript@5.6.3",
            "let total = items.reduce(0) { $0 + $1.price }",
            "func application(_ application: NSApplication, open urls: [URL]) {}",
            "SELECT id, email FROM users WHERE created_at > now() - interval '7 days';",
            "export PATH=\"/opt/homebrew/bin:$PATH\"",
            "API_KEY=your_api_key_here",
            "PASSWORD=changeme",
            "123e4567-e89b-12d3-a456-426614174000",
            "9fceb02d0ae598e95dc970b74767f19372d61af8",
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "#ff8800 rgb(255, 136, 0)",
            "+1 (555) 010-9999",
            "Order #A1B2-C3D4-E5F6 shipped on 2026-10-26",
            "The quick brown fox jumps over the lazy dog, again and again.",
            "ISBN 978-0-13-468599-1",
            "lorem ipsum dolor sit amet, consectetur adipiscing elit",
            "/Users/someone/Library/Application Support/App/file.json",
            "com.apple.Safari",
            "v1.2.3-beta.4+build.567",
            "Bearer token goes in the Authorization header",
            "Version 26.0 (25A354)",
            "€1,299.00 incl. VAT",
            "Meeting ID: 845 1234 5678"
        ]
        for text in corpus {
            XCTAssertNil(SecretDetector.detect(text), "False positive (\(SecretDetector.detect(text)?.kind ?? "")): \(text)")
        }
    }

    func testLargeTextIsFast() {
        let paragraph = "The quick brown fox jumps over the lazy dog. let value = compute(42); https://example.com/path?q=1\n"
        let text = String(repeating: paragraph, count: 2_000) // ~200 KB
        let start = Date()
        _ = SecretDetector.detect(text)
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertLessThan(elapsed, 1.5, "Detection on 200 KB took \(elapsed) s")
    }
}
