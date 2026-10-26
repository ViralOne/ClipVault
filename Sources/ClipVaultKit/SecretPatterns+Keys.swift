import Foundation

// Private keys, crypto wallets, auth formats and connection strings.
//
// Provider-independent formats. Sources: gitleaks config (private-key,
// curl-auth-user, kubernetes-secret-yaml, nuget-config-password), trufflehog
// detectors (jdbc, ftp, ldap, sqlserver, uri, privatekey), and the published
// file formats themselves (RFC 4716, PuTTY, WireGuard, OpenVPN, BIP-32,
// NIP-19, CIP-5, SEP-23, PASETO/PASERK, RFC 7516/7517, Key URI format).
extension SecretPatterns {

    /// Rejects obvious placeholder values: `password`, `changeme`, `${VAR}`,
    /// `<token>`, `xxx`, `***`, `{{ var }}`, `%(var)s`, `!vault`, `...`.
    private static let notPlaceholder =
        #"(?!(?i:password\b|passwd\b|pass\b|pwd\b|secret\b|changeme|change_me|changeit|example|placeholder|your[_-]|redacted|xxx|\*{2,}|<|\$\{|\$\(|\$[A-Za-z_]|\{\{|\{your|\{pass|%\(|!vault|\.\.\.))"#

    private static func v(_ before: String, _ after: String) -> String {
        before + notPlaceholder + after
    }

    static let keys: [SecretPattern] = [
        // MARK: Key blocks and key files not covered by the core PEM pattern
        SecretPattern("PGP private key", #"-----BEGIN PGP (?:PRIVATE|SECRET) KEY BLOCK-----"#,
                      keywords: ["-----begin pgp"]),
        SecretPattern("PuTTY private key", #"PuTTY-User-Key-File-[1-3]:\s*[a-z0-9@.-]+"#,
                      keywords: ["putty-user-key-file-"]),
        SecretPattern("SSH.com private key", #"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"#,
                      keywords: ["begin ssh2 encrypted"]),
        SecretPattern("OpenVPN static key", #"-----BEGIN OpenVPN (?:Static key V1|tls-crypt-v2 (?:client|server) key)-----"#,
                      keywords: ["-----begin openvpn"]),
        SecretPattern("OpenSSH private key body", #"\bb3BlbnNzaC1rZXktdjEA[A-Za-z0-9+/]{60,}"#,
                      keywords: ["b3blbnnzac1rzxktdje"]),
        SecretPattern("WireGuard private key", #"(?i:\bPrivateKey)\s*=\s*[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]="#,
                      keywords: ["privatekey"]),
        SecretPattern("WireGuard preshared key", #"(?i:\bPresharedKey)\s*=\s*[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]="#,
                      keywords: ["presharedkey"]),
        SecretPattern("Minisign or signify secret key", #"untrusted comment: [^\r\n]{0,80}secret key\r?\n[ \t]*RW[A-Za-z0-9+/]{80,}={0,2}"#,
                      keywords: ["untrusted comment"]),
        SecretPattern("JSON Web Key (private)", #"(?s)\{(?=[^{}]{0,4000}?"kty"\s*:\s*"(?:RSA|EC|OKP|oct)")(?=[^{}]{0,4000}?"[dk]"\s*:\s*"[A-Za-z0-9_-]{16,}")"#,
                      keywords: ["\"kty\""]),
        SecretPattern("Tink plaintext keyset", #"(?s)"primaryKeyId".{0,4000}?"keyMaterialType"\s*:\s*"(?:SYMMETRIC|ASYMMETRIC_PRIVATE)""#,
                      keywords: ["primarykeyid"]),

        // MARK: Kubernetes, containers and package registries
        SecretPattern("Kubeconfig client key", #"client-key-data:\s*["']?[A-Za-z0-9+/]{40,}={0,2}"#,
                      keywords: ["client-key-data"]),
        SecretPattern("Base64-encoded private key", #"\bLS0tLS1CRUdJTi[A-Za-z0-9+/]{0,60}?(?:UFJJVkFURSBLRVk|QUklWQVRFIEtFW|BSSVZBVEUgS0VZ)"#,
                      keywords: ["ls0tls1crudjti"]),
        SecretPattern("Kubeconfig user token", v(#"(?s)\busers:.{0,500}?\btoken:\s*["']?"#, #"[A-Za-z0-9._~+/=-]{20,}"#),
                      keywords: ["users:"]),
        SecretPattern("Kubernetes bootstrap token", #"(?:--(?:discovery-)?token[= ]|\btoken:\s*["']?)\b[a-z0-9]{6}\.[a-z0-9]{16}\b"#,
                      keywords: ["token"]),
        SecretPattern("Kubernetes Secret manifest", #"(?s)\bkind:\s*["']?Secret\b.{0,400}?\b(?:data|stringData):[ \t]*\r?\n[ \t]+[\w.-]+:[ \t]*["']?(?!\{\{)[A-Za-z0-9+/=._-]{8,}|\b(?:data|stringData):[ \t]*\r?\n[ \t]+[\w.-]+:[ \t]*["']?(?!\{\{)[A-Za-z0-9+/=._-]{8,}.{0,400}?\bkind:\s*["']?Secret\b"#,
                      keywords: ["kind:"]),
        SecretPattern("Docker registry auth", #""(?:auth|identitytoken)"\s*:\s*"[A-Za-z0-9+/]{12,}={0,2}""#,
                      keywords: ["\"auth\"", "\"identitytoken\""]),
        SecretPattern("npm registry password", v(#"(?i)(?:(?:^|[\s:])_password|(?:^|\s)_auth(?:Token)?)\s*=\s*["']?"#, #"[A-Za-z0-9+/=._-]{16,}"#),
                      keywords: ["_auth", "_password"]),
        SecretPattern("Yarn registry token", v(#"\bnpmAuth(?:Token|Ident)\s*:\s*["']?"#, #"[A-Za-z0-9+/=._:-]{16,}"#),
                      keywords: ["npmauth"]),
        SecretPattern("PyPI config password", v(#"(?s)\[(?:pypi|testpypi)\][^\[]{0,300}?\bpassword\s*[:=]\s*"#, #"\S{8,}"#),
                      keywords: ["[pypi]", "[testpypi]"]),
        SecretPattern("Composer auth credentials", v(#"(?s)"http-basic"\s*:\s*\{.{0,300}?"password"\s*:\s*""#, #"[^"]{6,}""#)
                      + "|" + v(#""(?:github-oauth|gitlab-token|gitlab-oauth|bitbucket-oauth)"\s*:\s*\{\s*"[^"]+"\s*:\s*""#, #"[A-Za-z0-9._-]{16,}""#),
                      keywords: ["http-basic", "-oauth", "gitlab-token"]),
        SecretPattern("Maven server password", v(#"(?s)<server>.{0,400}?<password>"#, #"[^<\s]{6,}</password>"#),
                      keywords: ["<server>"]),
        SecretPattern("NuGet config password", v(#"(?i)<add\s+key="(?:ClearText)?Password"\s+value=""#, #"[^"]{8,}"\s*/>"#),
                      keywords: ["password\""]),
        SecretPattern("netrc credentials", v(#"(?s)\bmachine\s+\S+\s+(?:(?:login|account|port)\s+\S+\s+){0,3}password\s+"#, #"\S{4,}"#),
                      keywords: ["machine"]),
        SecretPattern("Ansible password variable", v(#"\bansible_(?:ssh_|become_|sudo_)?pass(?:word)?\b["']?\s*[:=]\s*["']?"#, #"[^\s"'{]{4,}"#),
                      keywords: ["ansible_"]),

        // MARK: Credentials in URLs and connection strings
        SecretPattern("Git credentials in URL", v(#"\bhttps?://[^\s:@/"'<>]{1,100}:"#, #"[^\s:@/"'<>]{6,}@(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org|dev\.azure\.com|[\w-]+\.visualstudio\.com|codeberg\.org|gitea\.com|git\.sr\.ht)\b"#),
                      keywords: ["://"]),
        SecretPattern("SQLAlchemy database URL", v(#"\b(?:postgres(?:ql)?|mysql|mariadb|oracle|mssql|snowflake|redshift|cockroachdb|db2|sybase|firebird|teradata)\+[a-z0-9_]+://[^\s:@/"'<>]+:"#, #"[^\s@/"'<>]{3,}@[^\s"'<>]+"#),
                      keywords: ["://"]),
        SecretPattern("Neo4j connection string", v(#"\b(?:bolt|neo4j)(?:\+s|\+ssc)?://[^\s:@/"'<>]+:"#, #"[^\s@/"'<>]{3,}@[^\s"'<>]+"#),
                      keywords: ["://"]),
        SecretPattern("File transfer credentials in URL", v(#"\b(?:s?ftps?|scp|smb|cifs|webdavs?|davs?|rsync)://[^\s:@/"'<>]+:"#, #"[^\s@/"'<>]{3,}@[^\s"'<>]+"#),
                      keywords: ["://"]),
        SecretPattern("Mail server credentials in URL", v(#"\b(?:smtps?|submissions?|imaps?|pop3s?)://[^\s:@/"'<>]+:"#, #"[^\s@/"'<>]{3,}@[^\s"'<>]+"#),
                      keywords: ["://"]),
        SecretPattern("JDBC connection string", v(#"(?i)\bjdbc:[a-z0-9:]+[^\s"'<>]*?[;?&:]password="#, #"[^;&\s"'<>]{3,}"#),
                      keywords: ["jdbc:"]),
        SecretPattern("Oracle connection string", v(#"(?i)\b(?:jdbc:oracle:(?:thin|oci8?):|sqlplus\s+(?:-[sSlL]\s+)*)[^\s/@:"']+/"#, #"[^\s/@"']{3,}@"#),
                      keywords: ["jdbc:oracle", "sqlplus"]),
        SecretPattern("ODBC connection string", v(#"(?i)\b(?:address|addr|network address|host|driver|dsn)\s*=[^;\n]{1,200};(?:[^;\n]{0,200};){0,12}?[ \t]*(?:password|pwd)\s*=\s*"#, #"[^;\s'"]{4,}"#),
                      keywords: ["password", "pwd"]),
        SecretPattern("PostgreSQL password file entry", v(#"(?:^|\s)[^:\s#]+:(?:\d{2,5}|\*):[^:\s]+:[^:\s]+:"#, #"[^:\s]{4,}(?=$|\s)"#),
                      keywords: [":5432:", ":6432:", ":*:"]),
        SecretPattern("LDAP bind password", v(#"\bldap(?:search|modify|add|delete|passwd|whoami|compare|modrdn)\b[^\n]{0,300}?\s-w\s+["']?"#, #"[^\s"']{4,}"#)
                      + "|" + v(#"(?i)\b(?:bind_?pw|bind_?password|bind_?credential|ldap_?bind_?password|ldap_?password|manager_?password)\b["']?\s*[:=]\s*["']?"#, #"[^\s"']{6,}"#),
                      keywords: ["ldap", "bind"]),
        SecretPattern("Message broker credentials in URL", v(#"\b(?:mqtts?|nats|stomp(?:\+ssl)?|kafka|pulsar(?:\+ssl)?)://[^\s:@/"'<>]+:"#, #"[^\s@/"'<>]{3,}@[^\s"'<>]+"#),
                      keywords: ["://"], broad: true),
        SecretPattern("Database credentials in URL", v(#"\b(?:mssql|sqlserver|oracle|cockroachdb|couchbases?|couchdb|cassandra|scylla|snowflake|redshift|db2|influxdb|memcached?|elasticsearch|opensearch|arangodb|rethinkdb|surrealdb|tidb|vertica|presto|trino|hive2?)://[^\s:@/"'<>]+:"#, #"[^\s@/"'<>]{3,}@[^\s"'<>]+"#),
                      keywords: ["://"], broad: true),
        SecretPattern("Credentials in URL", v(#"\b[A-Za-z][A-Za-z0-9+.-]{1,30}://[^\s:@/"'<>]{1,100}:"#, #"(?!(?:\*+|x+|pw)@)[^\s:@/"'<>]{3,200}@[A-Za-z0-9][A-Za-z0-9.-]*"#),
                      keywords: ["://"], broad: true),

        // MARK: Command-line credentials
        SecretPattern("curl basic auth", v(#"\bcurl\b[^\n]{0,300}?\s(?:-u|--user)[ =]?["']?[^\s:"'$<-][^\s:"'$<]{1,63}:"#, #"[^\s"'$<]{4,}"#),
                      keywords: ["curl"]),
        SecretPattern("MySQL CLI password", v(#"\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^\n]{0,200}?\s(?:-p|--password=)["']?"#, #"[^\s"'-][^\s"']{3,}"#),
                      keywords: ["mysql", "mariadb"]),
        SecretPattern("Redis CLI password", v(#"\bredis-cli\b[^\n]{0,200}?\s(?:-a|--pass)\s+["']?"#, #"[^\s"'-][^\s"']{5,}"#),
                      keywords: ["redis-cli"]),
        SecretPattern("sshpass password", v(#"\bsshpass\s+-p\s*["']?"#, #"[^\s"'-][^\s"']{3,}"#),
                      keywords: ["sshpass"]),
        SecretPattern("Keytool password", #"\bkeytool\b[^\n]{0,300}?\s-(?:src|dest)?(?:store|key)pass\s+["']?(?!changeit\b)"# + notPlaceholder + #"[^\s"'-][^\s"']{3,}"#,
                      keywords: ["keytool"]),
        SecretPattern("OpenSSL password argument", v(#"\bopenssl\b[^\n]{0,300}?\s-pass(?:in|out)?\s+["']?pass:"#, #"[^\s"']{4,}"#),
                      keywords: ["openssl"]),
        SecretPattern("PowerShell plaintext password", v(#"(?i)ConvertTo-SecureString\s+(?:-String\s+)?["']"#, #"[^"'\n]{4,}["']\s+-AsPlainText"#),
                      keywords: ["convertto-securestring"]),
        SecretPattern("Windows net use password", v(#"(?i)\bnet\s+use\b[^\n]{0,200}?\s/user:\S+\s+"#, #"[^\s/*]{4,}"#)
                      + "|" + v(#"(?i)\bnet\s+use\s+(?:[a-z]:\s+)?\\\\\S+\s+"#, #"[^\s/*]{4,}\s+/user:"#),
                      keywords: ["net use"]),
        SecretPattern("Password on command line", v(#"(?:^|\s)--(?:(?:http-|ftp-|proxy-|db-|admin-)?password|passwd|pass|client-secret|api-key|token)[= ]["']?"#, #"[^\s"'-][^\s"']{5,}"#),
                      keywords: ["--"], broad: true),

        // MARK: HTTP, OAuth and token formats
        SecretPattern("API key header", v(#"(?i)\b(?:x-api-key|x-auth-token|x-access-token|x-apikey|api-key)\s*:\s*"#, #"[A-Za-z0-9._~+/=-]{16,}"#),
                      keywords: ["api-key", "-token", "apikey"]),
        SecretPattern("OAuth client secret", v(#""client_secret"\s*:\s*""#, #"[A-Za-z0-9._~+/=-]{16,}""#)
                      + "|" + v(#"[?&]client_secret="#, #"[A-Za-z0-9._~%+/=-]{16,}"#),
                      keywords: ["client_secret"]),
        SecretPattern("JWE token", #"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"#,
                      keywords: ["eyj"]),
        SecretPattern("PASETO token", #"\bv[1-4]\.(?:local|public)\.[A-Za-z0-9_-]{40,}(?:\.[A-Za-z0-9_-]+)?"#,
                      keywords: [".local.", ".public."]),
        SecretPattern("PASERK secret key", #"\bk[1-4]\.(?:local|secret|local-wrap|secret-wrap|local-pw|secret-pw)\.[A-Za-z0-9_.-]{40,}"#,
                      keywords: [".local", ".secret"]),
        SecretPattern("TOTP secret", #"(?i)\botpauth://[th]otp/[^\s?]*\?(?:[^\s#]*&)?secret=[A-Z2-7]{16,}|\botpauth-migration://offline\?data=[A-Za-z0-9%+/=]{20,}"#,
                      keywords: ["otpauth"]),
        SecretPattern("Password in URL query", v(#"[?&](?:password|passwd|pwd|pass)="#, #"[^&\s#"'<>]{6,}"#),
                      keywords: ["pass", "pwd="], broad: true),
        SecretPattern("Token in URL query", v(#"[?&](?:access_token|refresh_token|id_token|auth_token|private_token|api_key|apikey|api-key)="#, #"[A-Za-z0-9._~%+/=-]{16,}"#),
                      keywords: ["token=", "api"], broad: true),

        // MARK: Framework and app secrets
        SecretPattern("Rails secret_key_base", #"(?i)\bsecret_key_base\b["']?\s*[:=]\s*["']?[a-f0-9]{64,}"#,
                      keywords: ["secret_key_base"]),
        SecretPattern("Rails master key", #"\bRAILS_MASTER_KEY\s*[:=]\s*["']?[a-f0-9]{32}\b"#,
                      keywords: ["rails_master_key"]),
        SecretPattern("Django secret key", #"\bdjango-insecure-[a-z0-9!@#$%^&*(\-_=+)]{40,}|\bSECRET_KEY\s*=\s*["'][a-z0-9!@#$%^&*(\-_=+)]{50}["']"#,
                      keywords: ["django-insecure-", "secret_key"]),
        SecretPattern("Laravel app key", #"\bAPP_KEY\s*=\s*["']?base64:[A-Za-z0-9+/]{43}="#,
                      keywords: ["app_key"]),
        SecretPattern("WordPress auth salt", #"define\(\s*['"](?:AUTH|SECURE_AUTH|LOGGED_IN|NONCE)_(?:KEY|SALT)['"]\s*,\s*['"](?!put your unique phrase)[^'"]{32,}['"]"#,
                      keywords: ["define"]),
        SecretPattern("WordPress database password", v(#"define\(\s*['"]DB_PASSWORD['"]\s*,\s*['"](?!password_here)"#, #"[^'"]{4,}['"]"#),
                      keywords: ["db_password"]),
        SecretPattern("Jenkins encrypted secret", #"\{AQAAABAAAA[A-Za-z0-9+/]{20,}={0,2}\}"#,
                      keywords: ["{aqaaabaaaa"]),
        SecretPattern("FileZilla saved password", #"<Pass\s+encoding="base64"\s*>[A-Za-z0-9+/]{4,}={0,2}</Pass>"#,
                      keywords: ["<pass "]),
        SecretPattern("RDP file password", #"\bpassword 51:b:[0-9A-Fa-f]{32,}"#,
                      keywords: ["password 51:b:"]),

        // MARK: Network devices and Wi-Fi
        SecretPattern("Wi-Fi QR password", #"\bWIFI:(?:[A-Z]:(?:[^;\\]|\\.)*;)*?P:(?:[^;\\]|\\.){8,63};"#,
                      keywords: ["wifi:"]),
        SecretPattern("Wi-Fi passphrase", #"(?m)(?:^|\s)(?:wpa_passphrase\s*=\s*\S{8,63}|psk\s*=\s*(?:"[^"\n]{8,63}"|[0-9a-f]{64}\b))"#,
                      keywords: ["wpa_passphrase", "psk"]),
        SecretPattern("IPsec pre-shared key", #"(?:^|\s):\s*PSK\s+["'][^"'\n]{6,}["']"#,
                      keywords: ["psk"]),
        SecretPattern("Cisco type 7 password", #"\b(?:password|secret|key-string|key)\s+7\s+[01]\d[0-9A-F]{6,}\b"#,
                      keywords: [" 7 "]),
        SecretPattern("Juniper $9$ secret", #""\$9\$[^"\s]{8,}""#,
                      keywords: ["$9$"]),
        SecretPattern("SNMP community string", #"\bsnmp-server community\s+(?!(?:public|private)\b)\S{4,}\s+(?:RO|RW)\b"#,
                      keywords: ["snmp-server community"]),

        // MARK: Password hashes
        SecretPattern("bcrypt hash", #"\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}"#,
                      keywords: ["$2"]),
        SecretPattern("Unix crypt hash", #"\$(?:1|5|6)\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{22,86}|\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{1,86}\$[./A-Za-z0-9]{43}"#,
                      keywords: ["$"]),
        SecretPattern("Apache htpasswd hash", #"\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}|\{SHA\}[A-Za-z0-9+/]{27}="#,
                      keywords: ["$apr1$", "{sha}"]),
        SecretPattern("Argon2 hash", #"\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{11,}\$[A-Za-z0-9+/]{16,}"#,
                      keywords: ["$argon2"]),
        SecretPattern("PBKDF2 password hash", #"\bpbkdf2_sha(?:256|1)\$\d{4,}\$[A-Za-z0-9./+]{6,}\$[A-Za-z0-9+/]{43}="#,
                      keywords: ["pbkdf2_sha"]),

        // MARK: Crypto wallets
        SecretPattern("Bitcoin extended private key", #"\b(?:[xyztuv]|[YZUV])prv[1-9A-HJ-NP-Za-km-z]{107,108}\b"#,
                      keywords: ["prv"]),
        SecretPattern("Nostr private key", #"\bnsec1[02-9ac-hj-np-z]{58}\b"#,
                      keywords: ["nsec1"]),
        SecretPattern("Ethereum keystore", #"(?s)"[Cc]rypto"\s*:\s*\{(?=.{0,1500}?"ciphertext"\s*:\s*"[0-9a-f]{32,}")(?=.{0,1500}?"kdf"\s*:)"#,
                      keywords: ["ciphertext"]),
        SecretPattern("Solana keypair", #"\[\s*(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\s*,\s*){63}(?:25[0-5]|2[0-4]\d|1?\d?\d)\s*\]"#,
                      keywords: ["["]),
        SecretPattern("Solana private key", #"(?i:\b(?:solana|phantom)[\w .-]{0,20}?(?:private|secret)?[_ -]?key)\b["']?\s*[:=]?\s*["']?[1-9A-HJ-NP-Za-km-z]{86,88}\b"#,
                      keywords: ["solana", "phantom"]),
        SecretPattern("Cardano signing key", #"\b(?:root_xsk|acct_xsk|addr_xsk|stake_xsk|policy_sk|ed25519e?_sk|ed25519_bip32_sk|kes_sk|vrf_sk)1[02-9ac-hj-np-z]{50,}\b"#,
                      keywords: ["_xsk1", "_sk1"]),
        SecretPattern("Cardano key file", #"(?s)"type"\s*:\s*"[A-Za-z]*SigningKey[A-Za-z0-9_]*".{0,300}?"cborHex"\s*:\s*"[0-9a-f]{64,}""#,
                      keywords: ["signingkey"]),
        SecretPattern("Tendermint validator key", #""type"\s*:\s*"tendermint/PrivKey(?:Ed25519|Secp256k1)"\s*,\s*"value"\s*:\s*"[A-Za-z0-9+/]{40,}={0,2}""#,
                      keywords: ["tendermint/privkey"]),
        SecretPattern("LND macaroon", #"\b0201036c6e64[0-9a-f]{100,}\b"#,
                      keywords: ["0201036c6e64"]),
        // Stellar secret seeds (SEP-23 strkey, version byte 18 << 3) have no
        // other context, so this one runs without a keyword.
        SecretPattern("Stellar secret seed", #"\bS[A-D][A-Z2-7]{54}\b"#,
                      broad: true)
    ]
}
