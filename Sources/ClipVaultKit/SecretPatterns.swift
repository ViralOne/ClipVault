import Foundation

/// One published secret format.
public struct SecretPattern: Sendable {
    /// Shown to the user, e.g. "GitHub token".
    public let kind: String
    /// ICU regular expression (NSRegularExpression).
    public let pattern: String
    /// Lowercase substrings, at least one of which must appear in the text
    /// for the regex to run. Empty means always run. Use them for speed.
    public let keywords: [String]
    /// Broad patterns (generic URLs, bare hex) run after all specific ones.
    public let broad: Bool
    public let confidence: SecretMatch.Confidence

    public init(
        _ kind: String,
        _ pattern: String,
        keywords: [String] = [],
        broad: Bool = false,
        confidence: SecretMatch.Confidence = .high
    ) {
        self.kind = kind
        self.pattern = pattern
        self.keywords = keywords
        self.broad = broad
        self.confidence = confidence
    }
}

/// The pattern table, split by category across `SecretPatterns+*.swift`.
public enum SecretPatterns {
    public static let all: [SecretPattern] = core + cloud + developer + ai + saas + keys

    static let core: [SecretPattern] = [
        // Keys and certificates
        SecretPattern("Private key", #"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"#),
        SecretPattern("Age secret key", #"\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b"#),
        SecretPattern("JWT", #"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"#),

        // AI providers
        SecretPattern("Anthropic API key", #"\bsk-ant-[A-Za-z0-9_-]{20,}\b"#),
        SecretPattern("OpenAI API key", #"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b"#),
        SecretPattern("Groq API key", #"\bgsk_[A-Za-z0-9]{30,}\b"#),
        SecretPattern("xAI API key", #"\bxai-[A-Za-z0-9]{30,}\b"#),
        SecretPattern("Replicate token", #"\br8_[A-Za-z0-9]{30,}\b"#),
        SecretPattern("Hugging Face token", #"\bhf_[A-Za-z0-9]{30,}\b"#),
        SecretPattern("Pinecone API key", #"\bpcsk_[A-Za-z0-9_-]{30,}\b"#),

        // Source control and packages
        SecretPattern("GitHub token", #"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})\b"#),
        SecretPattern("GitLab token", #"\bglpat-[A-Za-z0-9_-]{20,}\b"#),
        SecretPattern("npm token", #"\bnpm_[A-Za-z0-9]{36}\b"#),
        SecretPattern("PyPI token", #"\bpypi-[A-Za-z0-9_-]{40,}\b"#),
        SecretPattern("Docker access token", #"\bdckr_pat_[A-Za-z0-9_-]{20,}\b"#),
        SecretPattern("Airtable token", #"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b"#),

        // Cloud
        SecretPattern("AWS access key", #"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)[A-Z0-9]{16}\b"#),
        SecretPattern("AWS secret key", #"(?i)aws_?secret_?access_?key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}"#),
        SecretPattern("Google API key", #"\bAIza[0-9A-Za-z_-]{35}\b"#),
        SecretPattern("Google OAuth secret", #"\bGOCSPX-[A-Za-z0-9_-]{20,}\b"#),
        SecretPattern("Cloudflare API token", #"(?i)(?:cloudflare|cf)[_-]?(?:api[_-]?)?(?:token|key)["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{40}"#),
        SecretPattern("DigitalOcean token", #"\bdop_v1_[a-f0-9]{64}\b"#),
        SecretPattern("Vercel token", #"\bvercel_[A-Za-z0-9]{24,}\b"#),
        SecretPattern("Netlify token", #"\bnfp_[A-Za-z0-9]{36,}\b"#),
        SecretPattern("Supabase service key", #"\bsbp_[a-f0-9]{40}\b"#),
        SecretPattern("Azure storage key", #"(?i)\b(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{60,}"#),
        SecretPattern("Firebase server key", #"\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{80,}\b"#),
        SecretPattern("Tailscale key", #"\btskey-[a-z]+-[A-Za-z0-9]{20,}\b"#),

        // SaaS and infrastructure
        SecretPattern("Stripe secret key", #"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b"#),
        SecretPattern("Stripe webhook secret", #"\bwhsec_[A-Za-z0-9+/=]{20,}\b"#),
        SecretPattern("Slack token", #"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"#),
        SecretPattern("Slack webhook", #"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"#),
        SecretPattern("Discord bot token", #"\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b"#, broad: true),
        SecretPattern("Discord webhook", #"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"#),
        SecretPattern("Telegram bot token", #"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}\b"#, broad: true),
        SecretPattern("Twilio API key", #"\bSK[0-9a-fA-F]{32}\b"#, broad: true),
        SecretPattern("SendGrid API key", #"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"#),
        SecretPattern("Mailgun API key", #"\bkey-[0-9a-zA-Z]{32}\b"#, broad: true),
        SecretPattern("Mailchimp API key", #"\b[0-9a-f]{32}-us\d{1,2}\b"#, broad: true),
        SecretPattern("Shopify access token", #"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"#),
        SecretPattern("Notion token", #"\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\b"#),
        SecretPattern("Linear API key", #"\blin_api_[A-Za-z0-9]{40,}\b"#),
        SecretPattern("Figma token", #"\bfigd_[A-Za-z0-9_-]{40,}\b"#),
        SecretPattern("Atlassian token", #"\bATATT3[A-Za-z0-9_\-=]{80,}\b"#),
        SecretPattern("Sentry auth token", #"\bsntrys_[A-Za-z0-9_\-=]{40,}\b"#),
        SecretPattern("Postman API key", #"\bPMAK-[a-f0-9]{24,}-[a-f0-9]{24,}\b"#),
        SecretPattern("Doppler token", #"\bdp\.(?:pt|st|sa|scim)\.[A-Za-z0-9]{40,}\b"#),
        SecretPattern("HashiCorp Vault token", #"\b(?:hvs|hvb|hvr)\.[A-Za-z0-9_-]{20,}\b"#),
        SecretPattern("Databricks token", #"\bdapi[a-f0-9]{32}(?:-\d+)?\b"#),
        SecretPattern("Contentful token", #"\bCFPAT-[A-Za-z0-9_-]{40,}\b"#),
        SecretPattern("Pulumi token", #"\bpul-[a-f0-9]{40}\b"#),
        SecretPattern("Resend API key", #"\bre_[A-Za-z0-9]{20,}\b"#),
        SecretPattern("Polar access token", #"\bpolar_(?:oat|sk|at)_[A-Za-z0-9]{20,}\b"#),
        SecretPattern("Paddle API key", #"\bpdl_live_[A-Za-z0-9_]{20,}\b"#),

        // Data stores and headers
        SecretPattern("MongoDB connection string", #"\bmongodb(?:\+srv)?://[^\s"'<>]+:[^\s"'<>@]+@[^\s"'<>]+"#),
        SecretPattern("Database URL", #"\b(?:postgres(?:ql)?|mysql|mariadb|redis|rediss|amqp|amqps)://[^\s:@/"'<>]+:[^\s@/"'<>]+@[^\s"'<>]+"#, broad: true),
        SecretPattern("Authorization header", #"(?i)\bauthorization\s*:\s*(?:basic|bearer)\s+[A-Za-z0-9\-._~+/=]{10,}"#, broad: true),

        // Crypto wallets
        SecretPattern("Ethereum private key", #"\b0x[a-fA-F0-9]{64}\b"#, broad: true),
        SecretPattern("Bitcoin private key", #"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"#, broad: true)
    ]
}
