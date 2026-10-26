import Foundation

private let base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
private let bech32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
private let base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
private let djangoChars = "abcdefghijklmnopqrstuvwxyz0123456789!@#%^&*(-_=+)"
private let cryptChars = "./" + Fake.alnum

private func b58(_ n: Int, seed: UInt64 = 1) -> String { Fake.string(n, base58, seed: seed) }
private func b32(_ n: Int, seed: UInt64 = 1) -> String { Fake.string(n, base32, seed: seed) }
private func bc32(_ n: Int, seed: UInt64 = 1) -> String { Fake.string(n, bech32, seed: seed) }
private func crypt(_ n: Int, seed: UInt64 = 1) -> String { Fake.string(n, cryptChars, seed: seed) }
private let byteArray = "[" + (0..<64).map { String(($0 * 37 + 11) % 256) }.joined(separator: ",") + "]"

extension SecretSamples {
    static let keys: [SecretSample] = [
        // Key blocks and key files
        SecretSample("PGP private key", "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----\n\n" + Fake.b64(64) + "\n"),
        SecretSample("PuTTY private key", "PuTTY-User-" + "Key-File-3: ssh-ed25519\nEncryption: none\nComment: laptop"),
        SecretSample("SSH.com private key", "---- BEGIN " + "SSH2 ENCRYPTED PRIVATE KEY ----\n" + Fake.b64(64)),
        SecretSample("OpenVPN static key", "-----BEGIN " + "OpenVPN Static key V1-----\n" + Fake.hex(32)),
        SecretSample("OpenSSH private key body", "b3BlbnNzaC1rZXkt" + "djEA" + Fake.b64(120)),
        SecretSample("WireGuard private key", "[Interface]\nPrivateKey = " + Fake.b64(42) + "A="),
        SecretSample("WireGuard preshared key", "[Peer]\nPresharedKey = " + Fake.b64(42, seed: 2) + "Q="),
        SecretSample("Minisign or signify secret key", "untrusted " + "comment: minisign encrypted secret key\nRW" + Fake.b64(150)),
        SecretSample("JSON Web Key (private)", #"{"kty":"OKP","crv":"Ed25519","x":""# + Fake.b64url(43) + #"","d":""# + Fake.b64url(43, seed: 2) + #""}"#),
        SecretSample("Tink plaintext keyset", #"{"primaryKeyId": 1234567, "key": [{"keyData": {"typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey", "value": ""# + Fake.b64(44) + #"", "keyMaterialType": "SYMMETRIC"}}]}"#),

        // Kubernetes, containers and registries
        SecretSample("Kubeconfig client key", "    client-key-data: " + "LS0tLS1CRUdJTi" + Fake.b64(200)),
        SecretSample("Base64-encoded private key", "LS0tLS1CRUdJTi" + "BQUklWQVRFIEtFWS0tLS0t" + Fake.b64(80)),
        SecretSample("Kubeconfig user token", "users:\n- name: admin\n  user:\n    token: " + Fake.alnum(48)),
        SecretSample("Kubernetes bootstrap token", "kubeadm join 10.0.0.1:6443 --token " + Fake.lower(6) + "." + Fake.lower(16, seed: 2)),
        SecretSample("Kubernetes Secret manifest", "apiVersion: v1\nkind: " + "Secret\nmetadata:\n  name: app\ndata:\n  db-pass: " + Fake.b64(24)),
        SecretSample("Docker registry auth", #"{"auths": {"registry.example.com": {"auth": ""# + Fake.b64(32) + #""}}}"#),
        SecretSample("npm registry password", "//npm.example.com/:_pass" + "word=" + Fake.b64(24)),
        SecretSample("Yarn registry token", "npmAuth" + "Token: " + Fake.uuid(seed: 3)),
        SecretSample("PyPI config password", "[pypi]\nusername = deploy\npassword = " + Fake.alnum(24)),
        SecretSample("Composer auth credentials", #"{"github-oauth": {"github.com": ""# + Fake.hex(40) + #""}}"#),
        SecretSample("Maven server password", "<server>\n  <id>releases</id>\n  <username>ci</username>\n  <password>" + Fake.alnum(20) + "</password>\n</server>"),
        SecretSample("NuGet config password", #"<add key="ClearTextPassword" value=""# + Fake.alnum(20) + #"" />"#),
        SecretSample("netrc credentials", "machine api.example.com login deploy password " + Fake.alnum(20)),
        SecretSample("Ansible password variable", "ansible_become_pass: " + Fake.alnum(16)),

        // URLs and connection strings
        SecretSample("Git credentials in URL", "https://ci-bot:" + Fake.alnum(32) + "@gitlab.com/group/repo.git"),
        SecretSample("SQLAlchemy database URL", "postgresql+psycopg2://app:" + Fake.alnum(20) + "@db.internal:5432/app"),
        SecretSample("Neo4j connection string", "neo4j+s://neo4j:" + Fake.alnum(20) + "@abcd1234.databases.neo4j.io"),
        SecretSample("File transfer credentials in URL", "sftp://deploy:" + Fake.alnum(16) + "@files.example.com/uploads"),
        SecretSample("Mail server credentials in URL", "smtps://mailer:" + Fake.alnum(16) + "@smtp.example.com:465"),
        SecretSample("JDBC connection string", "jdbc:sqlserver://db.internal:1433;databaseName=app;user=app;password=" + Fake.alnum(16)),
        SecretSample("Oracle connection string", "jdbc:oracle:thin:app/" + Fake.alnum(14) + "@db.internal:1521/ORCL"),
        SecretSample("ODBC connection string", "Driver={PostgreSQL Unicode};Host=db.internal;Database=app;Uid=app;Pwd=" + Fake.alnum(18) + ";"),
        SecretSample("PostgreSQL password file entry", "db.internal:5432:app:appuser:" + Fake.alnum(18)),
        SecretSample("LDAP bind password", "ldapsearch -x -H ldap://dc.internal -D \"cn=admin,dc=corp\" -w " + Fake.alnum(14) + " -b dc=corp"),
        SecretSample("Message broker credentials in URL", "mqtts://sensor:" + Fake.alnum(16) + "@broker.example.com:8883"),
        SecretSample("Database credentials in URL", "couchbases://app:" + Fake.alnum(16) + "@cb.internal/bucket"),
        SecretSample("Credentials in URL", "https://admin:" + Fake.alnum(16) + "@grafana.example.com/d/abc"),

        // Command line
        SecretSample("curl basic auth", "curl -u admin:" + Fake.alnum(16) + " https://api.example.com/v1/status"),
        SecretSample("MySQL CLI password", "mysql -h db.internal -u root -p" + Fake.alnum(14) + " app"),
        SecretSample("Redis CLI password", "redis-cli -h cache.internal -a " + Fake.alnum(20) + " ping"),
        SecretSample("sshpass password", "ssh" + "pass" + " -p " + Fake.alnum(14) + " ssh deploy@10.0.0.5"),
        SecretSample("Keytool password", "keytool -list -keystore app.jks -storepass " + Fake.alnum(14)),
        SecretSample("OpenSSL password argument", "openssl pkcs12 -in cert.p12 -out cert.pem -passin pass:" + Fake.alnum(14)),
        SecretSample("PowerShell plaintext password", "$pw = ConvertTo-SecureString \"" + Fake.alnum(14) + "\" -AsPlainText -Force"),
        SecretSample("Windows net use password", "net use Z: \\\\fileserver\\share " + Fake.alnum(12) + " /user:CORP\\svc"),
        SecretSample("Password on command line", "deploy-tool push --password " + Fake.alnum(16) + " --env prod"),

        // HTTP, OAuth and tokens
        SecretSample("API key header", "X-Api-Key: " + Fake.alnum(32)),
        SecretSample("OAuth client secret", #"{"client_id": "app", "client_secret": ""# + Fake.alnum(32) + #""}"#),
        SecretSample("JWE token", "eyJ" + Fake.b64url(30) + "." + Fake.b64url(40) + "." + Fake.b64url(16) + "." + Fake.b64url(60) + "." + Fake.b64url(22)),
        SecretSample("PASETO token", "v4." + "local." + Fake.b64url(90)),
        SecretSample("PASERK secret key", "k4." + "secret." + Fake.b64url(86)),
        SecretSample("TOTP secret", "otpauth://totp/Example:alice@example.com?secret=" + b32(32) + "&issuer=Example"),
        SecretSample("Password in URL query", "https://router.local/login.cgi?user=admin&password=" + Fake.alnum(14)),
        SecretSample("Token in URL query", "https://api.example.com/v2/items?access_token=" + Fake.alnum(40)),

        // Framework and app secrets
        SecretSample("Rails secret_key_base", "secret_key_base: " + Fake.hex(128)),
        SecretSample("Rails master key", "RAILS_MASTER_KEY=" + Fake.hex(32)),
        SecretSample("Django secret key", "SECRET_KEY = 'django-" + "insecure-" + Fake.string(50, djangoChars) + "'"),
        SecretSample("Laravel app key", "APP_KEY=base64:" + Fake.b64(43) + "="),
        SecretSample("WordPress auth salt", "define( 'AUTH_KEY', '" + Fake.b64(64) + "' );"),
        SecretSample("WordPress database password", "define( 'DB_PASSWORD', '" + Fake.alnum(16) + "' );"),
        SecretSample("Jenkins encrypted secret", "<password>{AQAAABAAAA" + Fake.b64(60) + "}</password>"),
        SecretSample("FileZilla saved password", "<Pass encoding=\"base64\">" + Fake.b64(20) + "</Pass>"),
        SecretSample("RDP file password", "password 51:b:" + Fake.hexUpper(200)),

        // Network devices and Wi-Fi
        SecretSample("Wi-Fi QR password", "WIFI:T:WPA;S:Office;P:" + Fake.alnum(16) + ";;"),
        SecretSample("Wi-Fi passphrase", "network={\n  ssid=\"Office\"\n  psk=\"" + Fake.alnum(16) + "\"\n}"),
        SecretSample("IPsec pre-shared key", "203.0.113.5 198.51.100.7 : PSK \"" + Fake.alnum(24) + "\""),
        SecretSample("Cisco type 7 password", "username admin privilege 15 password 7 0822" + Fake.hexUpper(16)),
        SecretSample("Juniper $9$ secret", "authentication-key \"$9$" + Fake.alnum(24) + "\";"),
        SecretSample("SNMP community string", "snmp-server community " + Fake.alnum(12) + " RW"),

        // Password hashes
        SecretSample("bcrypt hash", "$2b$12$" + crypt(53)),
        SecretSample("Unix crypt hash", "root:$6$" + crypt(16) + "$" + crypt(86, seed: 2) + ":19500:0:99999:7:::"),
        SecretSample("Apache htpasswd hash", "admin:$apr1$" + crypt(8) + "$" + crypt(22, seed: 2)),
        SecretSample("Argon2 hash", "$argon2id$v=19$m=65536,t=3,p=4$" + Fake.b64(22) + "$" + Fake.b64(43, seed: 2)),
        SecretSample("PBKDF2 password hash", "pbkdf2_sha256$870000$" + Fake.alnum(22) + "$" + Fake.b64(43) + "="),

        // Crypto wallets
        SecretSample("Bitcoin extended private key", "xprv" + b58(107)),
        SecretSample("Nostr private key", "nsec1" + bc32(58)),
        SecretSample("Ethereum keystore", #"{"version":3,"crypto":{"cipher":"aes-128-ctr","ciphertext":""# + Fake.hex(64) + #"","kdf":"scrypt","mac":""# + Fake.hex(64, seed: 2) + #""}}"#),
        SecretSample("Solana keypair", byteArray),
        SecretSample("Solana private key", "Phantom private key: " + b58(88)),
        SecretSample("Cardano signing key", "addr_xsk1" + bc32(150)),
        SecretSample("Cardano key file", #"{"type": "PaymentSigningKeyShelley_ed25519", "description": "Payment Signing Key", "cborHex": "5820"# + Fake.hex(64) + #""}"#),
        SecretSample("Tendermint validator key", #""priv_key": {"type": "tendermint/PrivKeyEd25519", "value": ""# + Fake.b64(86) + #"=="}"#),
        SecretSample("LND macaroon", "0201036c6e64" + Fake.hex(240)),
        SecretSample("Stellar secret seed", "SB" + b32(54))
    ]
}
