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

        for pattern in compiledPatterns where pattern.regex.firstMatch(in: sample, options: [], range: fullRange) != nil {
            return SecretMatch(kind: pattern.kind, confidence: pattern.confidence)
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

    private struct Definition {
        let kind: String
        let pattern: String
        let confidence: SecretMatch.Confidence

        init(_ kind: String, _ pattern: String, _ confidence: SecretMatch.Confidence = .high) {
            self.kind = kind
            self.pattern = pattern
            self.confidence = confidence
        }
    }

    private struct CompiledPattern {
        let kind: String
        let regex: NSRegularExpression
        let confidence: SecretMatch.Confidence
    }

    private static let definitions: [Definition] = [
        // Keys and certificates
        Definition("Private key", #"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"#),
        Definition("Age secret key", #"\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b"#),
        Definition("JWT", #"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"#),

        // AI providers
        Definition("Anthropic API key", #"\bsk-ant-[A-Za-z0-9_-]{20,}\b"#),
        Definition("OpenAI API key", #"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b"#),
        Definition("Groq API key", #"\bgsk_[A-Za-z0-9]{30,}\b"#),
        Definition("xAI API key", #"\bxai-[A-Za-z0-9]{30,}\b"#),
        Definition("Replicate token", #"\br8_[A-Za-z0-9]{30,}\b"#),
        Definition("Hugging Face token", #"\bhf_[A-Za-z0-9]{30,}\b"#),
        Definition("Pinecone API key", #"\bpcsk_[A-Za-z0-9_-]{30,}\b"#),

        // Source control and packages
        Definition("GitHub token", #"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})\b"#),
        Definition("GitLab token", #"\bglpat-[A-Za-z0-9_-]{20,}\b"#),
        Definition("npm token", #"\bnpm_[A-Za-z0-9]{36}\b"#),
        Definition("PyPI token", #"\bpypi-[A-Za-z0-9_-]{40,}\b"#),
        Definition("Docker access token", #"\bdckr_pat_[A-Za-z0-9_-]{20,}\b"#),
        Definition("Airtable token", #"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b"#),

        // Cloud
        Definition("AWS access key", #"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)[A-Z0-9]{16}\b"#),
        Definition("AWS secret key", #"(?i)aws_?secret_?access_?key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}"#),
        Definition("Google API key", #"\bAIza[0-9A-Za-z_-]{35}\b"#),
        Definition("Google OAuth secret", #"\bGOCSPX-[A-Za-z0-9_-]{20,}\b"#),
        Definition("Cloudflare API token", #"(?i)(?:cloudflare|cf)[_-]?(?:api[_-]?)?(?:token|key)["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{40}"#),
        Definition("DigitalOcean token", #"\bdop_v1_[a-f0-9]{64}\b"#),
        Definition("Vercel token", #"\bvercel_[A-Za-z0-9]{24,}\b"#),
        Definition("Netlify token", #"\bnfp_[A-Za-z0-9]{36,}\b"#),
        Definition("Supabase service key", #"\bsbp_[a-f0-9]{40}\b"#),
        Definition("Azure storage key", #"(?i)\b(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{60,}"#),
        Definition("Firebase server key", #"\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{80,}\b"#),
        Definition("Tailscale key", #"\btskey-[a-z]+-[A-Za-z0-9]{20,}\b"#),

        // SaaS and infrastructure
        Definition("Stripe secret key", #"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b"#),
        Definition("Stripe webhook secret", #"\bwhsec_[A-Za-z0-9+/=]{20,}\b"#),
        Definition("Slack token", #"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"#),
        Definition("Slack webhook", #"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"#),
        Definition("Discord bot token", #"\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b"#),
        Definition("Discord webhook", #"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"#),
        Definition("Telegram bot token", #"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}\b"#),
        Definition("Twilio API key", #"\bSK[0-9a-fA-F]{32}\b"#),
        Definition("SendGrid API key", #"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"#),
        Definition("Mailgun API key", #"\bkey-[0-9a-zA-Z]{32}\b"#),
        Definition("Mailchimp API key", #"\b[0-9a-f]{32}-us\d{1,2}\b"#),
        Definition("Shopify access token", #"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"#),
        Definition("Notion token", #"\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\b"#),
        Definition("Linear API key", #"\blin_api_[A-Za-z0-9]{40,}\b"#),
        Definition("Figma token", #"\bfigd_[A-Za-z0-9_-]{40,}\b"#),
        Definition("Atlassian token", #"\bATATT3[A-Za-z0-9_\-=]{80,}\b"#),
        Definition("Sentry auth token", #"\bsntrys_[A-Za-z0-9_\-=]{40,}\b"#),
        Definition("Postman API key", #"\bPMAK-[a-f0-9]{24,}-[a-f0-9]{24,}\b"#),
        Definition("Doppler token", #"\bdp\.(?:pt|st|sa|scim)\.[A-Za-z0-9]{40,}\b"#),
        Definition("HashiCorp Vault token", #"\b(?:hvs|hvb|hvr)\.[A-Za-z0-9_-]{20,}\b"#),
        Definition("Databricks token", #"\bdapi[a-f0-9]{32}(?:-\d+)?\b"#),
        Definition("Contentful token", #"\bCFPAT-[A-Za-z0-9_-]{40,}\b"#),
        Definition("Pulumi token", #"\bpul-[a-f0-9]{40}\b"#),
        Definition("Resend API key", #"\bre_[A-Za-z0-9]{20,}\b"#),
        Definition("Polar access token", #"\bpolar_(?:oat|sk|at)_[A-Za-z0-9]{20,}\b"#),
        Definition("Paddle API key", #"\bpdl_live_[A-Za-z0-9_]{20,}\b"#),

        // Data stores and headers
        Definition("MongoDB connection string", #"\bmongodb(?:\+srv)?://[^\s"'<>]+:[^\s"'<>@]+@[^\s"'<>]+"#),
        Definition("Database URL", #"\b(?:postgres(?:ql)?|mysql|mariadb|redis|rediss|amqp|amqps)://[^\s:@/"'<>]+:[^\s@/"'<>]+@[^\s"'<>]+"#),
        Definition("Authorization header", #"(?i)\bauthorization\s*:\s*(?:basic|bearer)\s+[A-Za-z0-9\-._~+/=]{10,}"#),

        // Crypto wallets
        Definition("Ethereum private key", #"\b0x[a-fA-F0-9]{64}\b"#),
        Definition("Bitcoin private key", #"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"#)
    ]

    private static let compiledPatterns: [CompiledPattern] = definitions.map { definition in
        // A malformed pattern is a programming error; crash loudly in debug and
        // skip in release rather than take the app down at runtime.
        do {
            let regex = try NSRegularExpression(pattern: definition.pattern)
            return CompiledPattern(kind: definition.kind, regex: regex, confidence: definition.confidence)
        } catch {
            assertionFailure("Invalid secret pattern \(definition.kind): \(error)")
            return CompiledPattern(
                kind: definition.kind,
                regex: try! NSRegularExpression(pattern: "a^"),
                confidence: definition.confidence
            )
        }
    }

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
