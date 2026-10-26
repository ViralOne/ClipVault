import Foundation

public struct SecretMatch: Equatable, Sendable {
    public enum Confidence: String, Sendable {
        /// The value matches a published token format.
        case high
        /// The value looks secret-ish (assignment name, entropy) but has no
        /// published format. Treat as a secret, may need review.
        case heuristic
    }

    public let kind: String
    public let confidence: Confidence

    public init(kind: String, confidence: Confidence = .high) {
        self.kind = kind
        self.confidence = confidence
    }
}

/// On-device secret detection.
///
/// Runs a fixed table of token formats first (cheap, precise), then a
/// key-name-aware assignment scan, then a high-entropy fallback. Compiled
/// regexes are created once and are safe to reuse across threads.
public enum SecretDetector {

    // MARK: - Public API

    public static func detect(_ text: String, declaredConcealed: Bool = false) -> SecretMatch? {
        // Anything a password manager marked concealed is a secret regardless
        // of what the text looks like.
        if declaredConcealed {
            return SecretMatch(kind: "Password manager item")
        }

        let sample = text.count > 200_000 ? String(text.prefix(200_000)) : text
        guard sample.utf8.count >= 8 else { return nil }
        let fullRange = NSRange(sample.startIndex..., in: sample)
        // Keywords are a cheap pre-filter: a pattern's regex only runs when
        // the text contains one of them.
        // Literal NSString search, each distinct keyword checked once.
        let lowered = sample.lowercased() as NSString
        var seen: [String: Bool] = [:]
        func contains(_ keyword: String) -> Bool {
            if let known = seen[keyword] { return known }
            let found = lowered.range(of: keyword, options: .literal).location != NSNotFound
            seen[keyword] = found
            return found
        }

        for pattern in compiledPatterns {
            if !pattern.keywords.isEmpty, !pattern.keywords.contains(where: contains) { continue }
            if pattern.regex.firstMatch(in: sample, options: [], range: fullRange) != nil {
                return SecretMatch(kind: pattern.kind, confidence: pattern.confidence)
            }
        }

        if let kind = assignmentKind(in: sample) {
            return SecretMatch(kind: kind, confidence: .heuristic)
        }

        if containsHighEntropyToken(sample) {
            return SecretMatch(kind: "High-entropy string", confidence: .heuristic)
        }

        return nil
    }

    /// Masks a value for display. Only a token's public type prefix (`ghp_`,
    /// `sk-`, `xoxb-`, `AKIA`) is kept, so users can recognise the kind of key;
    /// passwords and unprefixed values are hidden completely.
    public static func mask(_ text: String) -> String {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "••••••••" }
        if trimmed.contains("PRIVATE KEY-----") || trimmed.contains("AGE-SECRET-KEY-") {
            return "Secret key ••••••••"
        }
        let firstLine = String(trimmed.prefix(while: { !$0.isNewline }))
        guard firstLine.count > 16, let prefix = publicPrefix(of: firstLine) else { return "••••••••" }
        return prefix + "••••••••"
    }

    /// Published type markers of structured tokens. Longest match wins.
    private static let publicPrefixes: [String] = [
        "github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat-",
        "sk-ant-", "sk-proj-", "sk-svcacct-", "sk-admin-", "sk_live_", "sk_test_",
        "rk_live_", "rk_test_", "whsec_", "gsk_", "xai-", "r8_", "hf_", "pcsk_",
        "xoxb-", "xoxp-", "xoxa-", "xoxo-", "xoxs-", "xoxr-",
        "npm_", "pypi-", "dckr_pat_", "AKIA", "ASIA", "AIza", "GOCSPX-",
        "dop_v1_", "vercel_", "nfp_", "sbp_", "tskey-", "shpat_", "shpca_", "shppa_", "shpss_",
        "ntn_", "lin_api_", "figd_", "ATATT3", "sntrys_", "PMAK-", "hvs.", "hvb.", "hvr.",
        "CFPAT-", "pul-", "polar_oat_", "polar_sk_", "pdl_live_", "SG.", "dapi", "eyJ"
    ]

    static func publicPrefix(of value: String) -> String? {
        publicPrefixes
            .filter { value.hasPrefix($0) }
            .max(by: { $0.count < $1.count })
    }

    // MARK: - Token formats

    private struct CompiledPattern {
        let kind: String
        let regex: NSRegularExpression
        let keywords: [String]
        let confidence: SecretMatch.Confidence
    }

    /// Specific formats first, broad ones (generic URLs, bare hex keys) last,
    /// so the most precise kind wins.
    private static let compiledPatterns: [CompiledPattern] = {
        let ordered = SecretPatterns.all.filter { !$0.broad } + SecretPatterns.all.filter(\.broad)
        return ordered.compactMap { pattern in
            do {
                let regex = try NSRegularExpression(pattern: pattern.pattern)
                return CompiledPattern(
                    kind: pattern.kind,
                    regex: regex,
                    keywords: pattern.keywords.map { $0.lowercased() },
                    confidence: pattern.confidence
                )
            } catch {
                // A malformed pattern is a programming error; the test suite
                // compiles every pattern, release builds skip it.
                assertionFailure("Invalid secret pattern \(pattern.kind): \(error)")
                return nil
            }
        }
    }()

    /// Number of patterns that compiled. Used by tests.
    public static var patternCount: Int { compiledPatterns.count }

    // MARK: - Key/value assignments

    private static let assignmentRegex = try! NSRegularExpression(
        pattern: #"(?im)^[ \t]*(?:export[ \t]+)?["']?([A-Za-z_][A-Za-z0-9_.-]{1,63})["']?[ \t]*[:=][ \t]*["']?([^\s"']{10,})["']?[ \t]*$"#
    )

    private static func assignmentKind(in text: String) -> String? {
        let range = NSRange(text.startIndex..., in: text)
        let matches = assignmentRegex.matches(in: text, options: [], range: range)
        for match in matches.prefix(40) {
            guard
                let nameRange = Range(match.range(at: 1), in: text),
                let valueRange = Range(match.range(at: 2), in: text)
            else { continue }

            let name = String(text[nameRange])
            let value = String(text[valueRange])
            guard looksLikeSecretName(name), looksLikeSecretValue(value) else { continue }
            return "Secret in \(name)"
        }
        return nil
    }

    private static func looksLikeSecretName(_ name: String) -> Bool {
        let lower = name.lowercased()
        let strongMarkers = [
            "password", "passwd", "pwd", "secret", "token", "credential",
            "apikey", "api_key", "api-key", "privatekey", "private_key",
            "private-key", "access_key", "accesskey", "client_secret",
            "clientsecret", "auth_token", "authtoken"
        ]
        if strongMarkers.contains(where: { lower.contains($0) }) { return true }
        if lower.hasSuffix("key") {
            return lower.contains("api") || lower.contains("secret")
                || lower.contains("private") || lower.contains("access")
        }
        return false
    }

    private static func looksLikeSecretValue(_ value: String) -> Bool {
        let lower = value.lowercased()
        let placeholders = [
            "your_", "your-", "xxx", "changeme", "change_me", "example",
            "placeholder", "todo", "redacted", "***", "{{", "$(", "${",
            "null", "true", "false", "none"
        ]
        if placeholders.contains(where: { lower.contains($0) }) { return false }
        if lower == "null" || lower == "nil" { return false }
        if lower.hasPrefix("http://") || lower.hasPrefix("https://") { return false }
        if lower.hasPrefix("/") || lower.hasPrefix("./") || lower.hasPrefix("~/") { return false }
        if lower.hasPrefix("<") || lower.hasSuffix(">") { return false }
        // Code, not data: calls, optional chains, subscripts, scopes,
        // trailing commas and dotted member paths.
        let codeMarkers = ["(", ")", "?.", "::", "[", "]", "->", "=>"]
        if codeMarkers.contains(where: value.contains) || value.hasSuffix(",") || value.hasSuffix(";") { return false }
        if value.range(of: #"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$"#, options: .regularExpression) != nil {
            return false
        }

        // A value must look like data, not a sentence.
        let hasDigit = value.contains(where: { $0.isNumber })
        let hasSymbol = value.contains(where: { !$0.isLetter && !$0.isNumber })
        guard value.count >= 12, hasDigit || hasSymbol else { return false }
        return true
    }

    // MARK: - Entropy fallback

    private static func containsHighEntropyToken(_ text: String) -> Bool {
        let tokens = text.split { !($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }
        for token in tokens {
            let value = String(token)
            guard value.count >= 28, value.count <= 128 else { continue }

            var hasLower = false
            var hasUpper = false
            var hasDigit = false
            for character in value {
                if character.isLowercase { hasLower = true }
                else if character.isUppercase { hasUpper = true }
                else if character.isNumber { hasDigit = true }
            }
            guard hasDigit, hasLower, hasUpper else { continue }

            // Alphabets and digit runs are not keys.
            if ["abcdefghij", "ABCDEFGHIJ", "0123456789"].contains(where: value.contains) { continue }

            // A bare 40-character SHA-1 is almost always a commit id.
            if value.count == 40, value.allSatisfy({ $0.isHexDigit }) { continue }
            if value.lowercased().hasPrefix("sha1") || value.lowercased().hasPrefix("sha256") { continue }

            if shannonEntropy(value) >= 4.0 { return true }
        }
        return false
    }

    private static func shannonEntropy(_ value: String) -> Double {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty else { return 0 }
        var counts: [UInt8: Int] = [:]
        for byte in bytes { counts[byte, default: 0] += 1 }
        let total = Double(bytes.count)
        return -counts.values.reduce(0.0) { partial, count in
            let probability = Double(count) / total
            return partial + probability * log2(probability)
        }
    }
}
