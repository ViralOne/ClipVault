import Foundation

extension SecretSamples {
    static let cloud: [SecretSample] = [
        // AWS
        SecretSample("AWS session token", "aws_session_token = " + Fake.b64(320)),
        SecretSample("AWS STS session token", "IQoJb3JpZ2luX2Vj" + Fake.alnum(300, seed: 2)),
        SecretSample("AWS secret key (named)", "AWS_SECRET_KEY=" + Fake.alnum(40, seed: 3)),
        SecretSample("Amazon Bedrock API key", "ABSK" + Fake.alnum(132, seed: 4)),
        SecretSample("Amazon Bedrock short-term key", "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t" + Fake.alnum(200, seed: 5)),
        SecretSample("AWS AppSync API key", "da2-" + Fake.lower(26, seed: 6)),
        SecretSample("Amazon MWS auth token", "amzn.mws." + Fake.uuid(seed: 7)),
        SecretSample("AWS presigned URL",
                     "https://bucket.s3.amazonaws.com/report.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20261026T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature="
                        + Fake.hex(64, seed: 9)),

        // Google Cloud and Firebase
        SecretSample("Google service account JSON",
                     #"{"type": "service_account", "project_id": "demo", "client_email": "svc@demo.iam.gserviceaccount.com"}"#),
        SecretSample("Google service account key ID", #"{"private_key_id": ""# + Fake.hex(40, seed: 10) + #""}"#),
        SecretSample("Google user credentials JSON",
                     #"{"account": "", "type": "authorized_user", "universe_domain": "googleapis.com"}"#),
        SecretSample("Google OAuth client secret (legacy)",
                     #"{"installed":{"client_id":""# + Fake.digits(12, seed: 11) + "-" + Fake.lower(32, seed: 11)
                        + #".apps.googleusercontent.com","client_secret":""# + Fake.alnum(24, seed: 11) + #""}}"#),
        SecretSample("Google OAuth access token", "ya29." + Fake.b64url(120, seed: 12)),
        SecretSample("Google OAuth refresh token", "1//0" + Fake.alnum(100, seed: 13)),
        SecretSample("Google Cloud signed URL",
                     "https://storage.googleapis.com/bucket/obj?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=" + Fake.hex(512, seed: 14)),
        SecretSample("Firebase database secret", "FIREBASE_SECRET=" + Fake.alnum(40, seed: 15)),

        // Azure identifiable keys
        SecretSample("Azure AD client secret", Fake.alnum(3, seed: 16) + "8Q~" + Fake.alnum(34, seed: 16)),
        SecretSample("Azure Function key", Fake.alnum(44, seed: 17) + "AzFu" + Fake.alnum(5, seed: 17) + "A=="),
        SecretSample("Azure AI Search key", Fake.alnum(42, seed: 18) + "AzSeB" + Fake.alnum(5, seed: 18)),
        SecretSample("Azure Relay key", Fake.alnum(33, seed: 19) + "+ARmC" + Fake.alnum(5, seed: 19) + "="),
        SecretSample("Azure Event Hubs key", Fake.alnum(33, seed: 20) + "+AEhD" + Fake.alnum(5, seed: 20) + "="),
        SecretSample("Azure Service Bus key", Fake.alnum(33, seed: 21) + "+ASbE" + Fake.alnum(5, seed: 21) + "="),
        SecretSample("Azure IoT key", Fake.alnum(33, seed: 22) + "AIoTF" + Fake.alnum(5, seed: 22) + "="),
        SecretSample("Azure Event Grid key", Fake.alnum(33, seed: 23) + "AZEGG" + Fake.alnum(5, seed: 23) + "="),
        SecretSample("Azure Cache for Redis key", Fake.alnum(33, seed: 24) + "AzCaH" + Fake.alnum(5, seed: 24) + "="),
        SecretSample("Azure Storage account key", Fake.alnum(76, seed: 25) + "+ASt" + Fake.alnum(5, seed: 25) + "g=="),
        SecretSample("Azure Cosmos DB key", Fake.alnum(76, seed: 26) + "ACDb" + Fake.alnum(5, seed: 26) + "Q=="),
        SecretSample("Azure Batch key", Fake.alnum(76, seed: 27) + "+ABa" + Fake.alnum(5, seed: 27) + "w=="),
        SecretSample("Azure ML web service key", Fake.alnum(76, seed: 28) + "+AMC" + Fake.alnum(5, seed: 28) + "A=="),
        SecretSample("Azure API Management key", Fake.alnum(76, seed: 29) + "APIM" + Fake.alnum(5, seed: 29) + "A=="),
        SecretSample("Azure Container Registry key", Fake.alnum(42, seed: 30) + "+ACRA" + Fake.alnum(5, seed: 30)),
        SecretSample("Azure DevOps PAT",
                     Fake.alnum(52, seed: 31) + "JQQJ99" + "xB" + Fake.alnum(12, seed: 31) + "AAAAAZDO" + Fake.alnum(4, seed: 31)),
        SecretSample("Azure DevOps PAT (legacy)", "AZURE_DEVOPS_PAT=" + Fake.string(52, "abcdefghijklmnopqrstuvwxyz234567", seed: 32)),
        SecretSample("Azure annotated key",
                     Fake.alnum(52, seed: 33) + "JQQJ99" + "kC" + Fake.alnum(16, seed: 33) + "Q" + Fake.alnum(7, seed: 33)),

        // Azure connection strings, URLs and files
        SecretSample("Azure App Configuration connection string",
                     "Endpoint=https://myconfig.azconfig.io;Id=" + Fake.alnum(12, seed: 34) + ";Secret=" + Fake.alnum(44, seed: 34)),
        SecretSample("Azure Service Bus connection string",
                     "Endpoint=sb://mybus.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey="
                        + Fake.alnum(43, seed: 35) + "="),
        SecretSample("Azure IoT Hub connection string",
                     "HostName=myhub.azure-devices.net;DeviceId=sensor-1;SharedAccessKey=" + Fake.alnum(43, seed: 36) + "="),
        SecretSample("Azure SignalR connection string",
                     "Endpoint=https://mysignalr.service.signalr.net;AccessKey=" + Fake.alnum(43, seed: 37) + "=;Version=1.0;"),
        SecretSample("Azure Web PubSub connection string",
                     "Endpoint=https://mypubsub.webpubsub.azure.com;AccessKey=" + Fake.alnum(43, seed: 38) + "=;Version=1.0;"),
        SecretSample("Azure Communication Services connection string",
                     "endpoint=https://mycomms.communication.azure.com/;accesskey=" + Fake.alnum(86, seed: 39) + "=="),
        SecretSample("Azure Logic Apps URL",
                     "https://prod-01.westus.logic.azure.com:443/workflows/" + Fake.hex(32, seed: 40)
                        + "/triggers/manual/paths/invoke?api-version=2016-10-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig="
                        + Fake.b64url(43, seed: 40)),
        SecretSample("Azure SAS token",
                     "https://acct.blob.core.windows.net/files/report.pdf?sv=2022-11-02&ss=b&srt=co&sp=r&se=2026-12-31T00:00:00Z&spr=https&sig="
                        + Fake.alnum(43, seed: 42) + "%3D"),
        SecretSample("Azure Entra refresh token", "0.A" + Fake.b64url(60, seed: 43) + ".Ag" + Fake.b64url(300, seed: 43) + "x"),
        SecretSample("Azure publish profile password",
                     #"<publishProfile profileName="app - Web Deploy" userName="$app" userPWD=""# + Fake.alnum(60, seed: 44) + #"" />"#),
        SecretSample("Azure management certificate", #"ManagementCertificate=""# + Fake.alnum(400, seed: 45) + #"""#),

        // Asian and other public clouds
        SecretSample("Alibaba Cloud access key ID", "LTAI" + Fake.alnum(20, seed: 46)),
        SecretSample("Alibaba Cloud secret", "ALIBABA_CLOUD_ACCESS_KEY_SECRET=" + Fake.alnum(30, seed: 47)),
        SecretSample("Tencent Cloud SecretId", "AKID" + Fake.alnum(32, seed: 48)),
        SecretSample("Tencent Cloud SecretKey", "TENCENTCLOUD_SECRET_KEY=" + Fake.alnum(32, seed: 49)),
        SecretSample("Huawei Cloud key", "HUAWEICLOUD_SDK_SK=" + Fake.alnum(40, seed: 50)),
        SecretSample("Oracle Cloud secret key", "OCI_SECRET_KEY=" + Fake.alnum(43, seed: 51) + "="),
        SecretSample("IBM Cloud API key", "IBMCLOUD_API_KEY=" + Fake.b64url(43, seed: 52) + "x"),
        SecretSample("Yandex Cloud API key", "AQVN" + Fake.alnum(36, seed: 53)),
        SecretSample("Yandex Cloud IAM token", "t1." + Fake.b64url(60, seed: 54) + "." + Fake.alnum(86, seed: 54)),
        SecretSample("Yandex Cloud static key", "YANDEX_ACCESS_KEY_ID=YC" + Fake.alnum(38, seed: 55)),
        SecretSample("Yandex OAuth token", "y0_" + Fake.alnum(55, seed: 56)),

        // VPS and bare-metal hosting
        SecretSample("DigitalOcean OAuth token", "doo_v1_" + Fake.hex(64, seed: 57)),
        SecretSample("DigitalOcean refresh token", "dor_v1_" + Fake.hex(64, seed: 58)),
        SecretSample("DigitalOcean Spaces secret", "DO_SPACES_SECRET=" + Fake.alnum(43, seed: 59)),
        SecretSample("Linode token", "LINODE_TOKEN=" + Fake.hex(64, seed: 60)),
        SecretSample("Vultr API key", "VULTR_API_KEY=" + Fake.upper(36, seed: 61)),
        SecretSample("Hetzner Cloud token", "HCLOUD_TOKEN=" + Fake.alnum(64, seed: 62)),
        SecretSample("Scaleway access key", "SCW" + Fake.upper(17, seed: 63)),
        SecretSample("Scaleway secret key", "SCW_SECRET_KEY=" + Fake.uuid(seed: 64)),
        SecretSample("OVHcloud API secret", "OVH_APPLICATION_SECRET=" + Fake.alnum(32, seed: 65)),
        SecretSample("Exoscale API key", "EXO" + Fake.hex(24, seed: 66)),
        SecretSample("Equinix Metal token", "METAL_AUTH_TOKEN=" + Fake.alnum(32, seed: 67)),

        // CDN and edge
        SecretSample("Cloudflare Origin CA key", "v1.0-" + Fake.hex(24, seed: 68) + "-" + Fake.hex(146, seed: 68)),
        SecretSample("Cloudflare global API key", "CLOUDFLARE_GLOBAL_API_KEY=" + Fake.hex(37, seed: 69)),
        SecretSample("Cloudflare API token (prefixed)", "cfut_" + Fake.alnum(40, seed: 70) + Fake.hex(8, seed: 70)),
        SecretSample("Cloudflare API key (prefixed)", "cfk_" + Fake.alnum(40, seed: 71) + Fake.hex(8, seed: 71)),
        SecretSample("Cloudflare Tunnel token", "eyJhIjoi" + Fake.alnum(180, seed: 72)),
        SecretSample("Cloudflare R2 secret", "R2_SECRET_ACCESS_KEY=" + Fake.hex(64, seed: 73)),
        SecretSample("Fastly API token", "FASTLY_API_TOKEN=" + Fake.alnum(32, seed: 74)),
        SecretSample("Akamai EdgeGrid token", "client_token = akab-" + Fake.lower(16, seed: 75) + "-" + Fake.lower(16, seed: 75)),

        // Platforms as a service
        SecretSample("Heroku API key (HRKU)", "HRKU-AA" + Fake.alnum(58, seed: 76)),
        SecretSample("Heroku API key", "HEROKU_API_KEY=" + Fake.uuid(seed: 77)),
        SecretSample("Fly.io macaroon", "FlyV1 fm2_" + Fake.b64(600, seed: 78)),
        SecretSample("Fly.io token", "fo1_" + Fake.alnum(43, seed: 79)),
        SecretSample("Render API key", "rnd_" + Fake.alnum(31, seed: 80) + "7"),
        SecretSample("Railway token", "RAILWAY_TOKEN=" + Fake.uuid(seed: 81)),
        SecretSample("Netlify token (legacy)", "NETLIFY_AUTH_TOKEN=" + Fake.alnum(43, seed: 82)),
        SecretSample("Vercel token (prefixed)", "vcp_" + Fake.alnum(30, seed: 83) + "A1"),
        SecretSample("Vercel token (legacy)", "VERCEL_TOKEN=" + Fake.alnum(24, seed: 84)),
        SecretSample("Supabase secret key", "sb_secret_" + Fake.b64url(31, seed: 85) + "x"),
        SecretSample("Supabase OAuth token", "sbp_oauth_" + Fake.hex(40, seed: 86)),
        SecretSample("Deno Deploy token", "ddp_" + Fake.alnum(36, seed: 87)),
        SecretSample("Lambda Cloud API key",
                     "secret_mykey_" + Fake.hex(12, seed: 88) + "4" + Fake.hex(3, seed: 88) + "a" + Fake.hex(15, seed: 88)
                        + "." + Fake.alnum(32, seed: 88)),
        SecretSample("SaladCloud API key", "salad_cloud_user_" + Fake.alnum(40, seed: 89)),
        SecretSample("Scalingo API token", "tk-us-" + Fake.alnum(48, seed: 90)),

        // Infrastructure as code and secrets managers
        SecretSample("Terraform Cloud token", Fake.alnum(14, seed: 91) + ".atlasv1." + Fake.alnum(67, seed: 91)),
        SecretSample("HashiCorp Vault token (legacy)", "VAULT_TOKEN=s." + Fake.alnum(24, seed: 92)),
        SecretSample("HCP client secret", "HCP_CLIENT_SECRET=" + Fake.alnum(64, seed: 93)),
        SecretSample("Consul ACL token", "CONSUL_HTTP_TOKEN=" + Fake.uuid(seed: 94)),
        SecretSample("Nomad token", "NOMAD_TOKEN=" + Fake.uuid(seed: 95)),
        SecretSample("Infisical token", "st." + Fake.uuid(seed: 96) + "." + Fake.hex(32, seed: 96) + "." + Fake.hex(32, seed: 97)),
        SecretSample("1Password service account token", "ops_eyJ" + Fake.alnum(400, seed: 98)),
        SecretSample("1Password secret key",
                     "A3-" + Fake.upper(6, seed: 99) + "-" + Fake.upper(11, seed: 99) + "-" + Fake.upper(5, seed: 100)
                        + "-" + Fake.upper(5, seed: 101) + "-" + Fake.upper(5, seed: 102)),
        SecretSample("Bitwarden access token",
                     "0." + Fake.uuid(seed: 103) + "." + Fake.alnum(30, seed: 103) + ":" + Fake.alnum(22, seed: 103) + "=="),
        SecretSample("Infracost API key", "ico-" + Fake.alnum(32, seed: 104)),
        SecretSample("Defined Networking API key", "dnkey-" + Fake.upper(26, seed: 105) + "-" + Fake.upper(52, seed: 105)),

        // Containers and orchestration
        SecretSample("Kubernetes bootstrap token",
                     "kubeadm join 10.0.0.5:6443 --token " + Fake.lower(6, seed: 106) + "." + Fake.lower(16, seed: 106)),
        SecretSample("Kubeconfig client key", "    client-key-data: " + Fake.alnum(400, seed: 107)),
        SecretSample("Kubernetes Secret manifest",
                     "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ntype: Opaque\ndata:\n  password: " + Fake.alnum(24, seed: 108) + "\n"),
        SecretSample("OpenShift token", "sha256~" + Fake.alnum(43, seed: 109)),
        SecretSample("Rancher API token", "token-" + Fake.lower(5, seed: 110) + ":" + Fake.lower(54, seed: 110)),
        SecretSample("Portainer token", "PORTAINER_TOKEN=ptr_" + Fake.alnum(43, seed: 111)),
        SecretSample("Docker Swarm join token", "SWMTKN-1-" + Fake.lower(50, seed: 112) + "-" + Fake.lower(25, seed: 112)),
        SecretSample("Docker Swarm unlock key", "SWMKEY-1-" + Fake.alnum(43, seed: 113)),

        // Identity, networking and storage
        SecretSample("Harness API key",
                     "pat." + Fake.alnum(22, seed: 114) + "." + Fake.hex(24, seed: 114) + "." + Fake.alnum(20, seed: 114)),
        SecretSample("Okta API token", "OKTA_API_TOKEN=00" + Fake.alnum(40, seed: 115)),
        SecretSample("Auth0 client secret", "AUTH0_CLIENT_SECRET=" + Fake.alnum(64, seed: 116)),
        SecretSample("ngrok token", "ngrok config add-authtoken " + Fake.alnum(27, seed: 117) + "_" + Fake.alnum(21, seed: 117)),
        SecretSample("Cloudsmith API key", "CLOUDSMITH_API_KEY=" + Fake.hex(40, seed: 118)),
        SecretSample("Backblaze B2 application key", "B2_APPLICATION_KEY=K004" + Fake.alnum(27, seed: 119)),
        SecretSample("Wasabi secret key", "WASABI_SECRET_KEY=" + Fake.alnum(40, seed: 120)),
        SecretSample("MinIO secret", "MINIO_ROOT_PASSWORD=" + Fake.alnum(24, seed: 121)),
        SecretSample("JumpCloud API key", "JUMPCLOUD_API_KEY=" + Fake.alnum(40, seed: 122)),
        SecretSample("Cisco Meraki API key", "MERAKI_DASHBOARD_API_KEY=" + Fake.hex(40, seed: 123))
    ]
}
