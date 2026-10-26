import XCTest
@testable import ClipVaultKit

final class SecretDetectorTests: XCTestCase {

    private func repeats(_ fragment: String, _ count: Int) -> String {
        String(repeating: fragment, count: count)
    }

    func testGitHubToken() {
        let token = "ghp_" + repeats("a", 36)
        let match = SecretDetector.detect(token)
        XCTAssertEqual(match?.kind, "GitHub token")
        XCTAssertEqual(match?.confidence, .high)
    }

    func testOpenAIKey() {
        let key = "sk-proj-" + repeats("A1b2", 8)
        XCTAssertEqual(SecretDetector.detect(key)?.kind, "OpenAI API key")
    }

    func testAWSKey() {
        let key = "AKIA" + repeats("Q", 16)
        XCTAssertEqual(SecretDetector.detect(key)?.kind, "AWS access key")
    }

    func testSlackToken() {
        let token = "xoxb-" + repeats("1", 12)
        XCTAssertEqual(SecretDetector.detect(token)?.kind, "Slack token")
    }

    func testPrivateKeyBlock() {
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
        XCTAssertEqual(SecretDetector.detect(key)?.kind, "Private key")
    }

    func testMongoConnectionString() {
        let value = "mongodb+srv://admin:s3cretPass@cluster0.example.mongodb.net/db"
        XCTAssertEqual(SecretDetector.detect(value)?.kind, "MongoDB connection string")
    }

    func testAuthorizationHeader() {
        let value = "Authorization: Bearer abcdef1234567890abcdef"
        XCTAssertEqual(SecretDetector.detect(value)?.kind, "Authorization header")
    }

    func testSecretAssignment() {
        let text = "SLACK_BOT_TOKEN=\"abc123def456ghi789\""
        let match = SecretDetector.detect(text)
        XCTAssertEqual(match?.kind, "Secret in SLACK_BOT_TOKEN")
        XCTAssertEqual(match?.confidence, .heuristic)
    }

    func testPlaceholderAssignmentIsNotSecret() {
        XCTAssertNil(SecretDetector.detect("API_KEY=\"your_api_key_here\""))
        XCTAssertNil(SecretDetector.detect("PASSWORD=\"changeme\""))
        XCTAssertNil(SecretDetector.detect("PASSWORD=${DB_PASSWORD}"))
    }

    func testHighEntropyFallback() {
        XCTAssertEqual(SecretDetector.detect("Zx8Kq2Lm9Pw4Rt7Yv1Nb6Hs3Jd5Fg0")?.kind, "High-entropy string")
    }

    func testDeclaredConcealedWins() {
        let match = SecretDetector.detect("plain looking text", declaredConcealed: true)
        XCTAssertEqual(match?.kind, "Password manager item")
    }

    func testNormalTextIsNotSecret() {
        XCTAssertNil(SecretDetector.detect("Hello there, this is a normal sentence with 2026 in it."))
        XCTAssertNil(SecretDetector.detect("https://github.com/example/ClipVault/blob/main/README.md"))
        XCTAssertNil(SecretDetector.detect("let total = items.count * 2"))
    }

    func testUUIDIsNotSecret() {
        XCTAssertNil(SecretDetector.detect("123e4567-e89b-12d3-a456-426614174000"))
    }

    func testGitCommitHashIsNotSecret() {
        XCTAssertNil(SecretDetector.detect("9fceb02d0ae598e95dc970b74767f19372d61af8"))
    }

    func testMaskHidesSecretBody() {
        let token = "ghp_" + repeats("z", 36)
        let masked = SecretDetector.mask(token)
        XCTAssertEqual(masked, "ghp_••••••••")
        XCTAssertFalse(masked.contains(repeats("z", 8)))
    }

    func testMaskHidesShortValuesEntirely() {
        XCTAssertEqual(SecretDetector.mask("short"), "••••••••")
    }

    func testMaskKeepsOnlyPublishedPrefixes() {
        XCTAssertEqual(SecretDetector.mask("sk-proj-" + repeats("A1b2", 8)), "sk-proj-••••••••")
        XCTAssertEqual(SecretDetector.mask("AKIA" + repeats("Q", 16)), "AKIA••••••••")
        XCTAssertEqual(SecretDetector.mask("xoxb-" + repeats("1", 20)), "xoxb-••••••••")
    }

    func testMaskNeverLeaksPasswordPrefixes() {
        XCTAssertEqual(SecretDetector.mask("correct-horse-battery-staple"), "••••••••")
        XCTAssertEqual(SecretDetector.mask("hunter2hunter2hunter2"), "••••••••")
        XCTAssertEqual(SecretDetector.mask("Zx8Kq2Lm9Pw4Rt7Yv1Nb6Hs3Jd5Fg0"), "••••••••")
    }

    func testMaskPrivateKey() {
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
        XCTAssertEqual(SecretDetector.mask(key), "Secret key ••••••••")
    }

    func testHistoryItemMasksSecretPreview() {
        let item = HistoryItem(
            text: "ghp_" + repeats("z", 36),
            secretKind: "GitHub token"
        )
        XCTAssertTrue(item.isSecret)
        XCTAssertEqual(item.maskedPreview, "ghp_••••••••")
        XCTAssertEqual(item.kindLabel, "GitHub token")
    }
}
