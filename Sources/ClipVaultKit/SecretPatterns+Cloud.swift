import Foundation

// Cloud, hosting and infrastructure.
//
// Sources: gitleaks default config, trufflehog detectors, Microsoft
// security-utilities identifiable-key definitions (Azure), GitHub secret
// scanning partner list, and provider documentation (Vercel, Supabase).
extension SecretPatterns {
    private static let cloudUUID = #"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"#

    /// A provider-specific value assigned to a name that mentions the
    /// provider, e.g. `HEROKU_API_KEY=…`. `names` is a regex alternation
    /// (matched case-insensitively), `value` is matched case-sensitively.
    private static func cloudNamed(_ names: String, _ value: String) -> String {
        #"(?i)(?<![A-Za-z0-9])(?:"# + names + #")[\w.-]{0,30}["']?\s*(?:=>|:=|[:=])\s*["']?(?-i:"# + value + #")(?![A-Za-z0-9_+/=-])"#
    }

    static let cloud: [SecretPattern] = [
        // MARK: AWS
        SecretPattern("AWS session token", #"(?i)aws_?session_?token["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{100,}"#,
                      keywords: ["session_token", "sessiontoken"]),
        SecretPattern("AWS STS session token", #"\b(?:IQoJb3JpZ2luX2Vj|FwoGZXIvYXdzE)[A-Za-z0-9/+=]{100,}"#,
                      keywords: ["iqojb3jpz2lux2vj", "fwogzxivyxdze"]),
        SecretPattern("AWS secret key (named)", #"(?i)aws[\w.-]{0,20}?(?:secret|_sk\b)[\w.-]{0,20}["']?\s*[:=]\s*["']?[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"#,
                      keywords: ["aws"]),
        SecretPattern("Amazon Bedrock API key", #"\bABSK[A-Za-z0-9+/]{109,269}={0,2}"#, keywords: ["absk"]),
        SecretPattern("Amazon Bedrock short-term key", #"\bbedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t[A-Za-z0-9+/=%_-]{20,}"#,
                      keywords: ["bedrock-api-key-"]),
        SecretPattern("AWS AppSync API key", #"\bda2-[a-z0-9]{26}\b"#, keywords: ["da2-"]),
        SecretPattern("Amazon MWS auth token", #"\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"#,
                      keywords: ["amzn.mws."]),
        SecretPattern("AWS presigned URL", #"(?i)[?&]X-Amz-Signature=[a-f0-9]{64}\b"#, keywords: ["x-amz-signature="]),

        // MARK: Google Cloud and Firebase
        SecretPattern("Google service account JSON", #""type"\s*:\s*"service_account""#, keywords: ["service_account"]),
        SecretPattern("Google service account key ID", #""private_key_id"\s*:\s*"[a-f0-9]{40}""#, keywords: ["private_key_id"]),
        SecretPattern("Google user credentials JSON", #""type"\s*:\s*"authorized_user""#, keywords: ["authorized_user"]),
        SecretPattern("Google OAuth client secret (legacy)",
                      #"(?s)\.apps\.googleusercontent\.com.{0,500}?["']?client_secret["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{24}\b"#,
                      keywords: ["googleusercontent.com"]),
        SecretPattern("Google OAuth access token", #"\bya29\.[0-9A-Za-z_-]{30,}"#, keywords: ["ya29."]),
        SecretPattern("Google OAuth refresh token", #"(?<![\w/])1//0[0-9A-Za-z_-]{40,}"#, keywords: ["1//0"]),
        SecretPattern("Google Cloud signed URL", #"(?i)[?&]X-Goog-Signature=[a-f0-9]{256,}"#, keywords: ["x-goog-signature="]),
        SecretPattern("Firebase database secret", cloudNamed("firebase", #"[A-Za-z0-9]{40}"#), keywords: ["firebase"]),

        // MARK: Azure identifiable keys (Microsoft security-utilities)
        SecretPattern("Azure AD client secret", #"(?<![A-Za-z0-9_~.+/-])[A-Za-z0-9_~.-]{3}[78]Q~[A-Za-z0-9_~.-]{31,34}(?![A-Za-z0-9_~.+/-])"#,
                      keywords: ["q~"]),
        SecretPattern("Azure Function key", #"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{44}AzFu[A-Za-z0-9_-]{5}[AQgw]==(?![A-Za-z0-9_-])"#,
                      keywords: ["azfu"]),
        SecretPattern("Azure AI Search key", #"(?<![A-Za-z0-9+/_-])[A-Za-z0-9]{42}AzSe[A-D][A-Za-z0-9]{5}(?![A-Za-z0-9+/=_-])"#,
                      keywords: ["azse"]),
        SecretPattern("Azure Relay key", #"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{33}\+ARm[A-P][A-Za-z0-9+/]{5}=(?![A-Za-z0-9+/=_-])"#,
                      keywords: ["+arm"]),
        SecretPattern("Azure Event Hubs key", #"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{33}\+AEh[A-P][A-Za-z0-9+/]{5}=(?![A-Za-z0-9+/=_-])"#,
                      keywords: ["+aeh"]),
        SecretPattern("Azure Service Bus key", #"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{33}\+ASb[A-P][A-Za-z0-9+/]{5}=(?![A-Za-z0-9+/=_-])"#,
                      keywords: ["+asb"]),
        SecretPattern("Azure IoT key", #"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{33}AIoT[A-P][A-Za-z0-9+/]{5}=(?![A-Za-z0-9+/=_-])"#,
                      keywords: ["aiot"]),
        SecretPattern("Azure Event Grid key", #"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{33}AZEG[A-P][A-Za-z0-9+/]{5}=(?![A-Za-z0-9+/=_-])"#,
                      keywords: ["azeg"]),
        SecretPattern("Azure Cache for Redis key", #"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{33}AzCa[A-P][A-Za-z0-9+/]{5}=(?![A-Za-z0-9+/=_-])"#,
                      keywords: ["azca"]),
        SecretPattern("Azure Storage account key", #"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{76}\+ASt[A-Za-z0-9+/]{5}[AQgw]==(?![A-Za-z0-9+/=_-])"#,
                      keywords: ["+ast"]),
        SecretPattern("Azure Cosmos DB key", #"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{76}ACDb[A-Za-z0-9+/]{5}[AQgw]==(?![A-Za-z0-9+/=_-])"#,
                      keywords: ["acdb"]),
        SecretPattern("Azure Batch key", #"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{76}\+ABa[A-Za-z0-9+/]{5}[AQgw]==(?![A-Za-z0-9+/=_-])"#,
                      keywords: ["+aba"]),
        SecretPattern("Azure ML web service key", #"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{76}\+AMC[A-Za-z0-9+/]{5}[AQgw]==(?![A-Za-z0-9+/=_-])"#,
                      keywords: ["+amc"]),
        SecretPattern("Azure API Management key", #"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{76}APIM[A-Za-z0-9+/]{5}[AQgw]==(?![A-Za-z0-9+/=_-])"#,
                      keywords: ["apim"]),
        SecretPattern("Azure Container Registry key", #"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{42}\+ACR[A-D][A-Za-z0-9+/]{5}(?![A-Za-z0-9+/=_-])"#,
                      keywords: ["+acr"]),
        SecretPattern("Azure DevOps PAT", #"(?<![A-Za-z0-9])[A-Za-z0-9]{52}JQQJ99[A-Za-z0-9][A-L][A-Za-z0-9]{12}AAAAAZDO[A-Za-z0-9]{4}(?:[A-Za-z0-9]{2}==)?"#,
                      keywords: ["jqqj"]),
        SecretPattern("Azure DevOps PAT (legacy)", cloudNamed(#"azure[_-]?devops|azdo|ado[_-]?(?:pat|token)|vsts"#, #"[a-z2-7]{52}"#),
                      keywords: ["devops", "azdo", "ado_", "ado-", "vsts"]),
        // Generic Common Annotated Security Key (Azure AI services, Maps,
        // Communication Services, ...). Broad so specific kinds win.
        SecretPattern("Azure annotated key", #"(?<![A-Za-z0-9])[A-Za-z0-9]{52}JQQJ9[9DH][A-Za-z0-9][A-L][A-Za-z0-9]{16}[A-Za-z][A-Za-z0-9]{7}"#,
                      keywords: ["jqqj"], broad: true),

        // MARK: Azure connection strings, URLs and files
        SecretPattern("Azure App Configuration connection string", #"Endpoint=https://[A-Za-z0-9-]+\.azconfig\.io;Id=[^;\s]+;Secret=[A-Za-z0-9+/=]{20,}"#,
                      keywords: ["azconfig.io"]),
        SecretPattern("Azure Service Bus connection string", #"(?i)Endpoint=sb://[a-z0-9.-]+/?;SharedAccessKeyName=[^;\s]+;SharedAccessKey=[A-Za-z0-9+/=]{40,}"#,
                      keywords: ["endpoint=sb://"]),
        SecretPattern("Azure IoT Hub connection string", #"(?i)HostName=[a-z0-9.-]+\.azure-devices\.net;[^\s"']*?SharedAccessKey=[A-Za-z0-9+/=]{40,}"#,
                      keywords: ["azure-devices.net"]),
        SecretPattern("Azure SignalR connection string", #"(?i)Endpoint=https://[a-z0-9-]+\.service\.signalr\.net;AccessKey=[A-Za-z0-9+/=]{40,}"#,
                      keywords: ["signalr.net"]),
        SecretPattern("Azure Web PubSub connection string", #"(?i)Endpoint=https://[a-z0-9-]+\.webpubsub\.azure\.com;AccessKey=[A-Za-z0-9+/=]{40,}"#,
                      keywords: ["webpubsub.azure.com"]),
        SecretPattern("Azure Communication Services connection string", #"(?i)endpoint=https://[a-z0-9.-]+\.communication\.azure\.com/?;accesskey=[A-Za-z0-9+/=]{40,}"#,
                      keywords: ["communication.azure.com"]),
        SecretPattern("Azure Logic Apps URL", #"https://[a-z0-9.-]+\.logic\.azure\.com(?::443)?/workflows/[0-9a-f]{32}/triggers/[^\s"'<>]*?[?&]sig=[A-Za-z0-9_-]{30,}"#,
                      keywords: ["logic.azure.com"]),
        SecretPattern("Azure SAS token", #"(?i)\bsv=\d{4}-\d{2}-\d{2}&[^\s"'<>]*?\bsig=[A-Za-z0-9%+/=]{30,}|[?&]sig=[A-Za-z0-9%+/=]{30,}[^\s"'<>]*?&sv=\d{4}-\d{2}-\d{2}\b"#,
                      keywords: ["sig="]),
        SecretPattern("Azure Entra refresh token", #"\b[01]\.A[\w-]{50,}(?:\.\d)?\.Ag[\w-]{250,}"#, keywords: ["0.a", "1.a"]),
        SecretPattern("Azure publish profile password", #"\buserPWD="[A-Za-z0-9]{40,}""#, keywords: ["userpwd="]),
        SecretPattern("Azure management certificate", #"\bManagementCertificate="[A-Za-z0-9+/=]{100,}""#, keywords: ["managementcertificate="]),

        // MARK: Asian and other public clouds
        SecretPattern("Alibaba Cloud access key ID", #"\bLTAI[A-Za-z0-9]{12,20}\b"#, keywords: ["ltai"]),
        SecretPattern("Alibaba Cloud secret", cloudNamed(#"alibaba|aliyun|alicloud|ali_cloud"#, #"[A-Za-z0-9]{30}"#),
                      keywords: ["alibaba", "aliyun", "alicloud", "ali_cloud"]),
        SecretPattern("Tencent Cloud SecretId", #"\bAKID[A-Za-z0-9]{32}\b"#, keywords: ["akid"]),
        SecretPattern("Tencent Cloud SecretKey", cloudNamed(#"tencent|qcloud|tccli"#, #"[A-Za-z0-9]{32}"#),
                      keywords: ["tencent", "qcloud", "tccli"]),
        SecretPattern("Huawei Cloud key", cloudNamed(#"huawei|hwcloud"#, #"(?:[A-Za-z0-9]{40}|[A-Z0-9]{20})"#),
                      keywords: ["huawei", "hwcloud"]),
        SecretPattern("Oracle Cloud secret key", cloudNamed(#"oci|oracle[_-]?cloud"#, #"[A-Za-z0-9+/]{43}=?"#),
                      keywords: ["oci", "oracle"]),
        SecretPattern("IBM Cloud API key", cloudNamed("ibm", #"[A-Za-z0-9_-]{44}"#), keywords: ["ibm"]),
        SecretPattern("Yandex Cloud API key", #"\bAQVN[A-Za-z0-9_-]{35,38}\b"#, keywords: ["aqvn"]),
        SecretPattern("Yandex Cloud IAM token", #"\bt1\.[A-Za-z0-9_-]+={0,2}\.[A-Za-z0-9_-]{86}={0,2}"#, keywords: ["t1."]),
        SecretPattern("Yandex Cloud static key", cloudNamed("yandex", #"YC[A-Za-z0-9_-]{38}"#), keywords: ["yandex"]),
        SecretPattern("Yandex OAuth token", #"\by[0-3]_[A-Za-z0-9_-]{55}\b"#, keywords: ["y0_", "y1_", "y2_", "y3_"]),

        // MARK: VPS and bare-metal hosting
        SecretPattern("DigitalOcean OAuth token", #"\bdoo_v1_[a-f0-9]{64}\b"#, keywords: ["doo_v1_"]),
        SecretPattern("DigitalOcean refresh token", #"\bdor_v1_[a-f0-9]{64}\b"#, keywords: ["dor_v1_"]),
        SecretPattern("DigitalOcean Spaces secret", cloudNamed(#"do[_-]?spaces|spaces[_-]?secret|digitalocean"#, #"[A-Za-z0-9/+]{43}"#),
                      keywords: ["spaces", "digitalocean"]),
        SecretPattern("Linode token", cloudNamed("linode", #"[a-f0-9]{64}"#), keywords: ["linode"]),
        SecretPattern("Vultr API key", cloudNamed("vultr", #"[A-Z0-9]{36}"#), keywords: ["vultr"]),
        SecretPattern("Hetzner Cloud token", cloudNamed("hetzner|hcloud", #"[A-Za-z0-9]{64}"#), keywords: ["hetzner", "hcloud"]),
        SecretPattern("Scaleway access key", #"\bSCW[A-Z0-9]{17}\b"#, keywords: ["scw"]),
        SecretPattern("Scaleway secret key", cloudNamed("scaleway|scw", cloudUUID), keywords: ["scaleway", "scw"]),
        SecretPattern("OVHcloud API secret", cloudNamed("ovh", #"[A-Za-z0-9]{32}"#), keywords: ["ovh"]),
        SecretPattern("Exoscale API key", #"\bEXO[a-f0-9]{24}\b"#, keywords: ["exo"]),
        SecretPattern("Equinix Metal token", cloudNamed(#"equinix|metal[_-]auth|metal[_-]token|packet[_-]auth|packet[_-]token"#, #"[A-Za-z0-9]{32}"#),
                      keywords: ["equinix", "metal", "packet"]),

        // MARK: CDN and edge
        SecretPattern("Cloudflare Origin CA key", #"\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b"#, keywords: ["v1.0-"]),
        SecretPattern("Cloudflare global API key", cloudNamed(#"cloudflare|cf[_-](?:api|global|auth)"#, #"[a-f0-9]{37}"#),
                      keywords: ["cloudflare", "cf_", "cf-"]),
        SecretPattern("Cloudflare API token (prefixed)", #"\bcf[ua]t_[A-Za-z0-9]{40}[a-f0-9]{8}\b"#, keywords: ["cfut_", "cfat_"]),
        SecretPattern("Cloudflare API key (prefixed)", #"\bcfk_[A-Za-z0-9]{40}[a-f0-9]{8}\b"#, keywords: ["cfk_"]),
        SecretPattern("Cloudflare Tunnel token", #"\beyJhIjoi[A-Za-z0-9+/]{60,}={0,2}"#, keywords: ["eyjhijoi"]),
        SecretPattern("Cloudflare R2 secret", cloudNamed("r2", #"[a-f0-9]{64}"#), keywords: ["r2"]),
        SecretPattern("Fastly API token", cloudNamed("fastly", #"[A-Za-z0-9_-]{32}"#), keywords: ["fastly"]),
        SecretPattern("Akamai EdgeGrid token", #"\bakab-[a-z0-9]{16}-[a-z0-9]{16}\b"#, keywords: ["akab-"]),

        // MARK: Platforms as a service
        SecretPattern("Heroku API key (HRKU)", #"\bHRKU-AA[0-9A-Za-z_-]{58}\b"#, keywords: ["hrku-aa"]),
        SecretPattern("Heroku API key", cloudNamed("heroku", cloudUUID), keywords: ["heroku"]),
        SecretPattern("Fly.io macaroon", #"\bFlyV1 fm\d+_[A-Za-z0-9+/=,_-]{100,}"#, keywords: ["flyv1"]),
        SecretPattern("Fly.io token", #"\b(?:fo1_[\w-]{43}|fm1[ar]_[A-Za-z0-9+/]{100,}={0,3}|fm2_[A-Za-z0-9+/]{100,}={0,3})"#,
                      keywords: ["fo1_", "fm1", "fm2_"]),
        SecretPattern("Render API key", #"\brnd_(?=[A-Za-z]*[0-9])[A-Za-z0-9]{24,}\b"#, keywords: ["rnd_"]),
        SecretPattern("Railway token", cloudNamed("railway", cloudUUID), keywords: ["railway"]),
        SecretPattern("Netlify token (legacy)", cloudNamed("netlify", #"[A-Za-z0-9_-]{40,46}"#), keywords: ["netlify"]),
        SecretPattern("Vercel token (prefixed)", #"\b(?:vcp|vci|vca|vcr|vck)_(?=[A-Za-z]*[0-9])(?=[a-z0-9]*[A-Z])[A-Za-z0-9]{24,}\b"#,
                      keywords: ["vcp_", "vci_", "vca_", "vcr_", "vck_"]),
        SecretPattern("Vercel token (legacy)", cloudNamed("vercel", #"[A-Za-z0-9]{24}"#), keywords: ["vercel"]),
        SecretPattern("Supabase secret key", #"\bsb_secret_[A-Za-z0-9_-]{20,}"#, keywords: ["sb_secret_"]),
        SecretPattern("Supabase OAuth token", #"\bsbp_oauth_[a-f0-9]{40}\b"#, keywords: ["sbp_oauth_"]),
        SecretPattern("Deno Deploy token", #"\bdd[pw]_[A-Za-z0-9]{36}\b"#, keywords: ["ddp_", "ddw_"]),
        SecretPattern("Lambda Cloud API key", #"\bsecret_[a-z0-9][a-z0-9-]{0,63}_[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\.[A-Za-z0-9]{32}\b"#,
                      keywords: ["secret_"]),
        SecretPattern("SaladCloud API key", #"\bsalad_cloud_[0-9A-Za-z]{1,7}_[0-9A-Za-z]{7,235}\b"#, keywords: ["salad_cloud_"]),
        SecretPattern("Scalingo API token", #"\btk-us-[\w-]{48}\b"#, keywords: ["tk-us-"]),

        // MARK: Infrastructure as code and secrets managers
        SecretPattern("Terraform Cloud token", #"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70}"#, keywords: ["atlasv1"]),
        SecretPattern("HashiCorp Vault token (legacy)", cloudNamed("vault", #"s\.[A-Za-z0-9]{24}"#), keywords: ["vault"]),
        SecretPattern("HCP client secret", #"(?i)hcp[_-]?client[_-]?secret["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{40,}"#, keywords: ["hcp"]),
        SecretPattern("Consul ACL token", cloudNamed("consul", cloudUUID), keywords: ["consul"]),
        SecretPattern("Nomad token", cloudNamed("nomad", cloudUUID), keywords: ["nomad"]),
        SecretPattern("Infisical token", #"\bst\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[0-9a-f]{32}(?:\.[0-9a-f]{32})?\b"#,
                      keywords: ["st."]),
        SecretPattern("1Password service account token", #"\bops_eyJ[A-Za-z0-9+/]{250,}={0,3}"#, keywords: ["ops_eyj"]),
        SecretPattern("1Password secret key", #"\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b"#,
                      keywords: ["a3-"]),
        SecretPattern("Bitwarden access token", #"\b0\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[A-Za-z0-9]{20,40}:[A-Za-z0-9+/]{20,50}={0,2}"#,
                      keywords: ["0."]),
        SecretPattern("Infracost API key", #"\bico-[A-Za-z0-9]{32}\b"#, keywords: ["ico-"]),
        SecretPattern("Defined Networking API key", #"\bdnkey-[A-Za-z0-9=_-]{26}-[A-Za-z0-9=_-]{52}"#, keywords: ["dnkey-"]),

        // MARK: Containers and orchestration
        SecretPattern("Kubernetes bootstrap token", #"(?i)(?:--token[= ]|bootstrap[\w.-]{0,20}token["']?\s*[:=]\s*["']?)[a-z0-9]{6}\.[a-z0-9]{16}\b"#,
                      keywords: ["--token", "bootstrap"]),
        SecretPattern("Kubeconfig client key", #"client-key-data:\s*[A-Za-z0-9+/=]{100,}"#, keywords: ["client-key-data"]),
        SecretPattern("Kubernetes Secret manifest",
                      #"(?s)\bkind:[ \t]*["']?Secret["']?[ \t]*\r?\n.{0,400}?\b(?:data|stringData):[ \t]*\r?\n[ \t]+[\w.-]+:[ \t]*["']?[^\s"']{8,}|\b(?:data|stringData):[ \t]*\r?\n[ \t]+[\w.-]+:[ \t]*["']?[^\s"']{8,}.{0,400}?\bkind:[ \t]*["']?Secret["']?[ \t]*(?:\r?\n|$)"#,
                      keywords: ["kind:"]),
        SecretPattern("OpenShift token", #"\bsha256~[\w-]{43}(?![\w-])"#, keywords: ["sha256~"]),
        SecretPattern("Rancher API token", #"\btoken-[a-z0-9]{5}:[a-z0-9]{54}\b"#, keywords: ["token-"]),
        SecretPattern("Portainer token", cloudNamed("portainer", #"ptr_[A-Za-z0-9/_+=-]{20,60}"#), keywords: ["portainer"]),
        SecretPattern("Docker Swarm join token", #"\bSWMTKN-1-[a-z0-9]{50}-[a-z0-9]{25}\b"#, keywords: ["swmtkn-1-"]),
        SecretPattern("Docker Swarm unlock key", #"\bSWMKEY-1-[A-Za-z0-9+/]{43}"#, keywords: ["swmkey-1-"]),

        // MARK: Identity, networking and storage
        SecretPattern("Harness API key", #"\b(?:pat|sat)\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{20}\b"#, keywords: ["pat.", "sat."]),
        SecretPattern("Okta API token", cloudNamed("okta", #"00[A-Za-z0-9_=-]{40}"#), keywords: ["okta"]),
        SecretPattern("Auth0 client secret", cloudNamed("auth0", #"[A-Za-z0-9_-]{64,}"#), keywords: ["auth0"]),
        SecretPattern("ngrok token", #"(?i)ngrok[\w .:-]{0,30}?(?:authtoken|api[_-]?key|token)["']?\s*[:= ]\s*["']?(?-i:[0-9A-Za-z]{20,30}_[0-9A-Za-z]{20,25})\b"#,
                      keywords: ["ngrok"]),
        SecretPattern("Cloudsmith API key", cloudNamed("cloudsmith", #"[a-f0-9]{40}"#), keywords: ["cloudsmith"]),
        SecretPattern("Backblaze B2 application key", cloudNamed("b2|backblaze", #"K\d{3}[A-Za-z0-9+/]{27}"#), keywords: ["b2", "backblaze"]),
        SecretPattern("Wasabi secret key", cloudNamed("wasabi", #"[A-Za-z0-9/+]{40}"#), keywords: ["wasabi"]),
        SecretPattern("MinIO secret", #"(?i)\bMINIO_(?:ROOT_PASSWORD|SECRET_KEY)["']?\s*[:=]\s*["']?[^\s"'$]{8,}"#, keywords: ["minio_"]),
        SecretPattern("JumpCloud API key", cloudNamed("jumpcloud", #"[A-Za-z0-9]{40}"#), keywords: ["jumpcloud"]),
        SecretPattern("Cisco Meraki API key", cloudNamed("meraki", #"[a-f0-9]{40}"#), keywords: ["meraki"])
    ]
}
