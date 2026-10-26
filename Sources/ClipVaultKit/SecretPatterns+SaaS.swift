import Foundation

// Payments, commerce, communication, marketing and business SaaS.
//
// Sources: gitleaks default config, trufflehog detectors, GitHub secret
// scanning partner list, provider docs. Formats without a distinctive prefix
// only match next to an assignment whose name mentions the provider.
extension SecretPatterns {

    /// `<provider…name> = value`, `"provider_key": "value"`, `PROVIDER_TOKEN=value`.
    /// `names` is matched case-insensitively and must not follow a letter or
    /// digit; `value` is case-sensitive and must end at a token boundary.
    private static func assigned(_ names: String, _ value: String) -> String {
        #"(?<![A-Za-z0-9])(?i:(?:"# + names + #")[\w.-]{0,30})["']?\s*(?:[:=]|=>)\s*["']?(?:"# + value + #")(?![A-Za-z0-9_-])"#
    }

    private static let uuidPattern = #"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"#

    static let saas: [SecretPattern] = [
        // MARK: Payments
        // Square: before Facebook, whose tokens also start with EAA.
        SecretPattern("Square access token", #"\b(?:EAAA[A-Za-z0-9_+=-]{60}|sq0atp-[A-Za-z0-9_-]{22,60})(?![A-Za-z0-9_+=-])"#, keywords: ["eaaa", "sq0atp-"]),
        SecretPattern("Square application secret", #"\b(?:sandbox-)?sq0csp-[A-Za-z0-9_-]{40,50}(?![A-Za-z0-9_-])"#, keywords: ["sq0csp-"]),
        SecretPattern("Braintree access token", #"\baccess_token\$(?:production|sandbox)\$[0-9a-z]{16}\$[0-9a-f]{32}\b"#, keywords: ["access_token$"]),
        SecretPattern("Braintree private key", assigned("braintree", "[0-9a-f]{32}"), keywords: ["braintree"]),
        SecretPattern("PayPal client secret", assigned(#"paypal[\w.-]{0,20}secret"#, "[A-Za-z0-9_-]{80}"), keywords: ["paypal"]),
        SecretPattern("Adyen API key", #"\bAQE[A-Za-z0-9+/]{40,}={0,2}-[A-Za-z0-9+/]{30,}={0,2}"#, keywords: ["aqe"]),
        SecretPattern("Razorpay key secret", assigned(#"razorpay[\w.-]{0,20}secret"#, "[A-Za-z0-9]{24}"), keywords: ["razorpay"]),
        SecretPattern("Flutterwave secret key", #"\bFLWSECK(?:_TEST)?-[A-Za-z0-9]{32}-X\b"#, keywords: ["flwseck"]),
        SecretPattern("Mollie API key", assigned("mollie", "(?:live|test)_[A-Za-z0-9]{30}|access_[A-Za-z0-9]{40}"), keywords: ["mollie"]),
        SecretPattern("GoCardless access token", assigned("gocardless", "(?:live|sandbox)_[A-Za-z0-9_=-]{40}"), keywords: ["gocardless"]),
        SecretPattern("Coinbase API secret", assigned(#"coinbase[\w.-]{0,20}(?:secret|token|key)"#, "[A-Za-z0-9_+/=-]{32,88}"), keywords: ["coinbase"]),
        SecretPattern("Plaid access token", #"\baccess-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"#, keywords: ["access-"]),
        SecretPattern("Plaid secret", assigned(#"plaid[\w.-]{0,20}secret"#, "[a-z0-9]{30}"), keywords: ["plaid"]),
        SecretPattern("Wise API token", assigned(#"(?:transferwise|wise)[\w.-]{0,20}(?:token|key)"#, uuidPattern), keywords: ["wise"]),
        SecretPattern("Paddle sandbox API key", #"\bpdl_sdbx_[A-Za-z0-9_]{20,}"#, keywords: ["pdl_sdbx_"]),
        SecretPattern("Polar token", #"\bpolar_(?:pat|rt|cst|whs)_[A-Za-z0-9_]{20,}"#, keywords: ["polar_"]),
        SecretPattern("Checkout.com secret key", #"\bsk_(?:test_|sbox_)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b|\bsk_sbox_[a-z0-9]{26,30}\b"#, keywords: ["sk_"]),
        SecretPattern("Recharge API token", #"\bsk(?:_test)?_(?:1|2|3|5|10)x[123]_[0-9a-fA-F]{64}\b"#, keywords: ["sk_"]),
        SecretPattern("Pagar.me API key", #"\bak_(?:live|test)_[A-Za-z0-9]{30}\b"#, keywords: ["ak_"]),
        SecretPattern("Xendit secret key", #"\bxnd_(?:production|development)_[A-Za-z0-9+/=_-]{40,}"#, keywords: ["xnd_"]),
        SecretPattern("Mercado Pago access token", #"\bAPP_USR-\d{16}-\d{6}-[a-f0-9]{32}-\d{6,12}\b"#, keywords: ["app_usr-"]),
        SecretPattern("Midtrans server key", #"\b(?:SB-)?Mid-server-[A-Za-z0-9_-]{20,}"#, keywords: ["mid-server-"]),
        SecretPattern("Ramp API secret", #"\bramp_(?:sec|tok)_[A-Za-z0-9]{40,}\b"#, keywords: ["ramp_"]),
        SecretPattern("Mercury API token", #"\bsecret-token:mercury_(?:production|sandbox)_[A-Za-z0-9_]{20,}"#, keywords: ["mercury_"]),
        SecretPattern("Chargebee API key", assigned("chargebee", "(?:live|test)_[A-Za-z0-9]{20,40}"), keywords: ["chargebee"]),
        SecretPattern("Binance API secret", assigned(#"binance[\w.-]{0,20}secret"#, "[A-Za-z0-9]{64}"), keywords: ["binance"]),
        SecretPattern("Kraken API secret", assigned(#"kraken[\w.-]{0,20}(?:secret|private)"#, "[A-Za-z0-9+/]{80,90}={0,2}"), keywords: ["kraken"]),
        SecretPattern("Onfido API token", #"\bapi_(?:live|sandbox)(?:_(?:us|ca))?\.[A-Za-z0-9_-]{11}\.[A-Za-z0-9_-]{32}(?![A-Za-z0-9_-])"#, keywords: ["api_"]),
        SecretPattern("Persona API key", #"\bpersona_(?:production|sandbox)_[A-Za-z0-9-]{32,}"#, keywords: ["persona_"]),

        // MARK: Commerce and shipping
        SecretPattern("WooCommerce API key", #"\b(?:ck|cs)_[a-f0-9]{40}\b"#, keywords: ["ck_", "cs_"]),
        SecretPattern("BigCommerce access token", assigned(#"bigcommerce[\w.-]{0,20}(?:token|secret)"#, "[a-z0-9]{30,40}"), keywords: ["bigcommerce"]),
        SecretPattern("Shopify partner token", #"\bprtapi_[a-f0-9]{32}\b"#, keywords: ["prtapi_"]),
        SecretPattern("Amazon LWA client secret", #"\bamzn1\.oa2-cs\.v1\.[a-f0-9]{64}\b"#, keywords: ["amzn1.oa2-cs"]),
        SecretPattern("Amazon LWA token", #"\bAtz[ar]\|[A-Za-z0-9_+/=-]{80,}"#, keywords: ["atz"]),
        SecretPattern("eBay client secret", #"\b(?:PRD|SBX)-[0-9a-f]{12}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}\b"#, keywords: ["prd-", "sbx-"]),
        SecretPattern("Etsy API key", assigned("etsy", "[a-z0-9]{24}"), keywords: ["etsy"]),
        SecretPattern("Gumroad access token", assigned("gumroad", "[A-Za-z0-9_-]{43}"), keywords: ["gumroad"]),
        SecretPattern("Shippo API token", #"\bshippo_(?:live|test)_[a-fA-F0-9]{40}\b"#, keywords: ["shippo_"]),
        SecretPattern("EasyPost API key", #"\bEZ[AT]K[A-Za-z0-9]{54}\b"#, keywords: ["ez"]),
        SecretPattern("Duffel access token", #"\bduffel_(?:live|test)_[A-Za-z0-9_=-]{43}(?![A-Za-z0-9_=-])"#, keywords: ["duffel_"]),
        SecretPattern("Lob API key", assigned("lob", "(?:live|test)_[a-f0-9]{35}"), keywords: ["lob"]),

        // MARK: Messaging and voice
        SecretPattern("Twilio credentials", #"\bAC[0-9a-f]{32}:[0-9a-f]{32}\b"#, keywords: ["ac"]),
        SecretPattern("Twilio auth token", assigned(#"twilio[\w.-]{0,20}(?:auth|secret)"#, "[0-9a-f]{32}"), keywords: ["twilio"]),
        SecretPattern("Telnyx API key", #"\bKEY[0-9A-F]{32}_[A-Za-z0-9]{22}\b"#, keywords: ["key"]),
        SecretPattern("Vonage API secret", assigned(#"(?:vonage|nexmo)[\w.-]{0,20}secret"#, "[A-Za-z0-9]{16}"), keywords: ["vonage", "nexmo"]),
        SecretPattern("MessageBird API key", assigned("message[_-]?bird", "[A-Za-z0-9_-]{25}"), keywords: ["bird"]),
        SecretPattern("Plivo auth token", assigned(#"plivo[\w.-]{0,20}(?:token|secret)"#, "[A-Za-z0-9_-]{40}"), keywords: ["plivo"]),
        SecretPattern("Sinch API secret", assigned(#"sinch[\w.-]{0,20}(?:secret|token)"#, "[A-Za-z0-9]{32}"), keywords: ["sinch"]),
        SecretPattern("OneSignal API key", #"\bos_v2_(?:app|org)_[a-z0-9]{40,}"#, keywords: ["os_v2_"]),
        SecretPattern("LINE channel access token", assigned(#"line[\w.-]{0,20}(?:token|secret)"#, "[A-Za-z0-9+/]{171,172}={0,1}"), keywords: ["line"]),

        // MARK: Chat and meetings
        SecretPattern("Slack app token", #"\bxapp-\d-[A-Z0-9]{9,}-\d{10,}-[a-f0-9]{32,}\b"#, keywords: ["xapp-"]),
        SecretPattern("Slack refresh token", #"\bxoxe-\d-[A-Za-z0-9]{140,}"#, keywords: ["xoxe-"]),
        SecretPattern("Slack workflow webhook", #"https://hooks\.slack\.com/(?:workflows|triggers)/T[A-Z0-9]{6,}/[A-Za-z0-9]+/[A-Za-z0-9]{16,}(?:/[A-Za-z0-9]+)?"#, keywords: ["hooks.slack.com"]),
        SecretPattern("Discord client secret", assigned(#"discord[\w.-]{0,20}secret"#, "[A-Za-z0-9_-]{32}"), keywords: ["discord"]),
        SecretPattern("Microsoft Teams webhook", #"https://[A-Za-z0-9-]+\.webhook\.office\.com/webhookb2/[0-9a-f-]{36}@[0-9a-f-]{36}/IncomingWebhook/[A-Za-z0-9]{32}/[0-9a-f-]{36}"#, keywords: ["webhook.office.com"]),
        SecretPattern("Teams workflow webhook", #"https://[a-z0-9]+\.\d+\.environment\.api\.powerplatform\.com(?::\d+)?/powerautomate/automations/direct/workflows/[a-f0-9]{32}/triggers/manual/paths/invoke\?[^\s"'<>]*sig=[A-Za-z0-9_-]+"#, keywords: ["powerplatform.com"]),
        SecretPattern("Zoom client secret", assigned(#"zoom[\w.-]{0,20}secret"#, "[A-Za-z0-9]{32}"), keywords: ["zoom"]),
        SecretPattern("Webex access token", #"\b[A-Za-z0-9]{64}_[A-Za-z0-9]{4}_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"#, keywords: ["_pf84_", "webex"]),
        SecretPattern("Webex client secret", assigned(#"webex[\w.-]{0,20}secret"#, "[a-f0-9]{64}"), keywords: ["webex"]),
        SecretPattern("Mattermost access token", assigned("mattermost", "[a-z0-9]{26}"), keywords: ["mattermost"]),
        SecretPattern("Rocket.Chat auth token", assigned(#"rocket[._-]?chat[\w.-]{0,20}(?:token|secret)"#, "[A-Za-z0-9_-]{43}"), keywords: ["rocket"]),
        SecretPattern("Zulip API key", assigned("zulip", "[A-Za-z0-9]{32}"), keywords: ["zulip"]),

        // MARK: Email and marketing
        SecretPattern("Brevo API key", #"\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b"#, keywords: ["xkeysib-"]),
        SecretPattern("Brevo SMTP key", #"\bxsmtpsib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b"#, keywords: ["xsmtpsib-"]),
        SecretPattern("MailerSend API token", #"\bmlsn\.[a-f0-9]{64}\b"#, keywords: ["mlsn."]),
        SecretPattern("Mailgun key", assigned("mailgun", "[a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8}"), keywords: ["mailgun"]),
        SecretPattern("Mandrill API key", assigned("mandrill", "(?:md-)?[A-Za-z0-9_-]{22}"), keywords: ["mandrill"]),
        SecretPattern("Postmark server token", assigned("postmark", uuidPattern), keywords: ["postmark"]),
        SecretPattern("Mailjet API secret", assigned(#"mailjet[\w.-]{0,20}(?:secret|private|key)"#, "[a-f0-9]{32}"), keywords: ["mailjet"]),
        SecretPattern("SparkPost API key", assigned("sparkpost", "[a-f0-9]{40}"), keywords: ["sparkpost"]),
        SecretPattern("Loops API key", assigned(#"loops[\w.-]{0,20}(?:key|token)"#, "[a-f0-9]{32}"), keywords: ["loops"]),
        SecretPattern("Customer.io API key", assigned("customer[_.-]?io", "[A-Za-z0-9]{20,40}"), keywords: ["customer"]),
        SecretPattern("Klaviyo private API key", #"\bpk_(?:[A-Za-z0-9]{6}_)?[a-f0-9]{34}\b"#, keywords: ["pk_"]),
        SecretPattern("MailerLite API key", assigned("mailerlite", "[a-z0-9]{32}"), keywords: ["mailerlite"]),
        SecretPattern("ActiveCampaign API key", assigned("active[_-]?campaign", "[a-f0-9]{72}"), keywords: ["campaign"]),
        SecretPattern("Iterable API key", assigned("iterable", "[a-f0-9]{32}"), keywords: ["iterable"]),
        SecretPattern("Braze REST API key", assigned("braze", uuidPattern), keywords: ["braze"]),
        SecretPattern("Omnisend API key", assigned("omnisend", "[A-Za-z0-9-]{75}"), keywords: ["omnisend"]),
        SecretPattern("Elastic Email API key", assigned("elastic[_-]?email", "[A-Za-z0-9_-]{96}"), keywords: ["elastic"]),
        SecretPattern("GetResponse API key", assigned("getresponse", "[a-z0-9]{32}"), keywords: ["getresponse"]),
        SecretPattern("Beamer API key", assigned("beamer", "b_[A-Za-z0-9=_-]{44}"), keywords: ["beamer"]),

        // MARK: CRM and support
        SecretPattern("HubSpot private app token", #"\bpat-(?:na|eu|ap)\d-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"#, keywords: ["pat-"]),
        SecretPattern("HubSpot API key", assigned("hubspot", uuidPattern), keywords: ["hubspot"]),
        SecretPattern("Salesforce access token", #"\b00D[A-Za-z0-9]{12}![A-Za-z0-9_.]{80,}"#, keywords: ["00d"]),
        SecretPattern("Salesforce refresh token", #"\b5Aep861[A-Za-z0-9._=]{80,}"#, keywords: ["5aep861"]),
        SecretPattern("Salesforce consumer secret", assigned(#"(?:salesforce|sfdc)[\w.-]{0,20}secret"#, "[A-F0-9]{64}|[0-9]{19}"), keywords: ["salesforce", "sfdc"]),
        SecretPattern("Pipedrive API token", assigned("pipedrive", "[A-Za-z0-9]{40}"), keywords: ["pipedrive"]),
        SecretPattern("Close API key", #"\bapi_[A-Za-z0-9]{20,24}\.[A-Za-z0-9]{20,24}\b"#, keywords: ["api_"]),
        SecretPattern("Copper API key", assigned("copper", "[a-f0-9]{32}"), keywords: ["copper"]),
        SecretPattern("Zoho OAuth token", #"\b1000\.[a-f0-9]{32}\.[a-f0-9]{32}\b"#, keywords: ["1000."]),
        SecretPattern("Intercom access token", #"\bdG9rO[A-Za-z0-9+/]{50,}={0,2}"#, keywords: ["dg9ro"]),
        SecretPattern("Zendesk API token", assigned("zendesk", "[A-Za-z0-9]{40}"), keywords: ["zendesk"]),
        SecretPattern("Freshdesk API key", assigned("freshdesk", "[A-Za-z0-9]{20}"), keywords: ["freshdesk"]),
        SecretPattern("Help Scout API key", assigned("help[_-]?scout", "[a-z0-9]{40}"), keywords: ["scout"]),

        // MARK: Productivity and files
        SecretPattern("Asana personal access token", #"\b[12]/\d{16,}(?:/\d{16,})?:[A-Za-z0-9]{32,}\b"#, keywords: ["1/", "2/"]),
        SecretPattern("Asana client secret", assigned(#"asana[\w.-]{0,20}secret"#, "[a-z0-9]{32}"), keywords: ["asana"]),
        SecretPattern("ClickUp personal token", #"\bpk_\d{6,10}_[A-Z0-9]{32}\b"#, keywords: ["pk_"]),
        SecretPattern("Trello token", #"\bATTA[a-fA-F0-9]{60,}\b"#, keywords: ["atta"]),
        SecretPattern("Trello legacy token", assigned(#"trello[\w.-]{0,20}(?:token|secret)"#, "[a-f0-9]{64}"), keywords: ["trello"]),
        SecretPattern("Todoist API token", assigned("todoist", "[a-f0-9]{40}"), keywords: ["todoist"]),
        SecretPattern("Miro access token", #"\beyJtaXJvLm9yaWdpbiI6I[A-Za-z0-9]{6,}_[A-Za-z0-9_-]{20,}"#, keywords: ["eyjtaxjv"]),
        SecretPattern("Smartsheet access token", assigned("smartsheet", "[A-Za-z0-9]{26}|[A-Za-z0-9]{37}"), keywords: ["smartsheet"]),
        SecretPattern("Coda API token", assigned("coda", uuidPattern), keywords: ["coda"]),
        SecretPattern("Airtable legacy API key", assigned("airtable", "key[A-Za-z0-9]{14}"), keywords: ["airtable"]),
        SecretPattern("Dropbox short-lived token", #"\bsl\.(?:u\.)?[A-Za-z0-9_-]{130,}"#, keywords: ["sl."]),
        SecretPattern("Dropbox long-lived token", assigned("dropbox", "[A-Za-z0-9]{11}AAAAAAAAAA[A-Za-z0-9_=-]{43}"), keywords: ["dropbox"]),
        SecretPattern("Box access token", assigned(#"box[\w.-]{0,20}(?:token|secret)"#, "[A-Za-z0-9]{32}"), keywords: ["box"]),
        SecretPattern("DocuSign secret", assigned("docusign", uuidPattern), keywords: ["docusign"]),
        SecretPattern("Dropbox Sign API key", assigned("hellosign|dropbox[_-]?sign", "[a-f0-9]{64}"), keywords: ["hellosign", "dropbox"]),
        SecretPattern("PandaDoc API key", assigned("pandadoc", "[a-f0-9]{40}"), keywords: ["pandadoc"]),
        SecretPattern("Zapier webhook", #"https://hooks\.zapier\.com/hooks/catch/\d+/[A-Za-z0-9]{4,}"#, keywords: ["hooks.zapier.com"]),
        SecretPattern("Google OAuth access token", #"\bya29\.[A-Za-z0-9_-]{30,}"#, keywords: ["ya29."]),
        SecretPattern("Google OAuth refresh token", #"(?<![A-Za-z0-9/])1//0[A-Za-z0-9_-]{40,}"#, keywords: ["1//0"]),

        // MARK: Social and media
        SecretPattern("Twitter bearer token", #"\bA{22}[A-Za-z0-9%]{80,100}"#, keywords: ["aaaaaaaaaaaaaaaaaaaaaa"]),
        SecretPattern("Twitter API secret", assigned(#"twitter[\w.-]{0,20}secret"#, "[A-Za-z0-9]{45,50}"), keywords: ["twitter"]),
        SecretPattern("Twitter access token", assigned("twitter", "[0-9]{15,25}-[A-Za-z0-9]{20,40}"), keywords: ["twitter"]),
        SecretPattern("Facebook access token", #"\bEAA[A-Za-z0-9]{100,}"#, keywords: ["eaa"]),
        SecretPattern("Facebook app secret", assigned(#"(?:facebook|fb)[\w.-]{0,20}secret"#, "[a-f0-9]{32}"), keywords: ["facebook", "fb"]),
        SecretPattern("Instagram access token", #"\bIG(?:QV|AA)[A-Za-z0-9_-]{100,}"#, keywords: ["igqv", "igaa"]),
        SecretPattern("LinkedIn client secret", #"\bWPL_AP\d\.[A-Za-z0-9._+/=-]{20,}"#, keywords: ["wpl_ap"]),
        SecretPattern("LinkedIn legacy client secret", assigned(#"linked[_-]?in[\w.-]{0,20}secret"#, "[A-Za-z0-9]{16}"), keywords: ["linked"]),
        SecretPattern("Pinterest token", #"\bpin[ar]_[A-Za-z0-9]{40,}"#, keywords: ["pin"]),
        SecretPattern("TikTok access token", assigned("tiktok", "(?:act|rft)\\.[A-Za-z0-9_-]{30,}(?:![0-9]{4})?"), keywords: ["tiktok"]),
        SecretPattern("Reddit client secret", assigned(#"reddit[\w.-]{0,20}secret"#, "[A-Za-z0-9_-]{27,30}"), keywords: ["reddit"]),
        SecretPattern("Spotify client secret", assigned(#"spotify[\w.-]{0,20}secret"#, "[a-f0-9]{32}"), keywords: ["spotify"]),
        SecretPattern("Twitch token", assigned("twitch", "[a-z0-9]{30}"), keywords: ["twitch"])
    ]
}
