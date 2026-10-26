import Foundation

// AI/ML providers, data platforms and databases.
//
// Sources: gitleaks and betterleaks configs, trufflehog detectors, GitHub
// secret-scanning partner list, provider documentation. Formats that start
// with `sk-` are omitted: the core OpenAI pattern claims them first.
extension SecretPatterns {

    /// `<provider name>…key = value`: the provider name, an optional suffix
    /// such as `_API_KEY`, an assignment, then a case-sensitive value.
    private static func assigned(_ names: String, _ value: String) -> String {
        #"(?i)(?:"# + names + #")[\w.-]{0,30}?["']?\s*(?:=|:|=>|:=)\s*["']?(?-i:"# + value + #")(?![A-Za-z0-9_])"#
    }

    static let ai: [SecretPattern] = [
        // MARK: AI model providers
        SecretPattern("Perplexity API key", #"\bpplx-[A-Za-z0-9]{48}\b"#, keywords: ["pplx-"]),
        SecretPattern("Together AI API key", #"\btgp_v1_[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])"#, keywords: ["tgp_v1_"]),
        SecretPattern("Together AI legacy key", assigned(#"together[\w.-]{0,20}?(?:key|token)"#, #"[a-f0-9]{64}"#), keywords: ["together"]),
        SecretPattern("Fireworks AI API key", #"\bfw_(?=[A-Za-z]*\d)[A-Za-z0-9]{20,40}\b"#, keywords: ["fw_"]),
        SecretPattern("Hugging Face org token", #"\bapi_org_[A-Za-z]{34}\b"#, keywords: ["api_org_"]),
        SecretPattern("Cohere API key", assigned("cohere|co_api_key", #"[A-Za-z0-9]{40}"#), keywords: ["cohere", "co_api_key"]),
        SecretPattern("Mistral API key", assigned("mistral", #"[A-Za-z0-9]{32}"#), keywords: ["mistral"]),
        SecretPattern("Cerebras API key", #"\bcsk-[a-z0-9]{48}\b"#, keywords: ["csk-"]),
        SecretPattern("NVIDIA API key", #"\bnvapi-[A-Za-z0-9_-]{60,70}(?![A-Za-z0-9_-])"#, keywords: ["nvapi-"]),
        SecretPattern("Azure OpenAI key", assigned(#"azure[_.-]?openai"#, #"[A-Za-z0-9]{32}(?:[A-Za-z0-9]{52})?"#), keywords: ["azure"]),
        SecretPattern("Google Gemini API key", #"\bAQ\.Ab8RN6[A-Za-z0-9_-]{44}(?![A-Za-z0-9_-])"#, keywords: ["aq.ab8rn6"]),
        SecretPattern("Upstage API key", assigned("upstage", #"up_[A-Za-z0-9]{29,47}|[A-Za-z0-9]{40,50}"#), keywords: ["upstage"]),
        SecretPattern("Z.ai API key", assigned(#"zhipu|z_?ai|glm"#, #"[a-f0-9]{32}\.[A-Za-z0-9]{16}"#), keywords: ["zhipu", "ai", "glm"]),
        SecretPattern("Ollama API key", assigned("ollama", #"[a-f0-9]{32}\.[A-Za-z0-9_-]{24}"#), keywords: ["ollama"]),
        SecretPattern("Anyscale API key", #"\besecret_[A-Za-z0-9]{20,}\b"#, keywords: ["esecret_"]),
        SecretPattern("LlamaCloud API key", #"\bllx-[A-Za-z0-9]{44,52}\b"#, keywords: ["llx-"]),
        SecretPattern("Voyage AI API key", assigned("voyage", #"(?:pa|al)-[A-Za-z0-9_-]{43}"#), keywords: ["voyage"]),
        SecretPattern("Jina AI API key", #"\bjina_[A-Za-z0-9_-]{50,70}(?![A-Za-z0-9_-])"#, keywords: ["jina_"]),

        // MARK: Speech, vision and media
        SecretPattern("ElevenLabs API key", #"\bsk_[a-f0-9]{48}\b"#, keywords: ["sk_"]),
        SecretPattern("ElevenLabs legacy key", assigned(#"elevenlabs|xi[_-]api[_-]key"#, #"[a-f0-9]{32}"#), keywords: ["elevenlabs", "xi"]),
        SecretPattern("Cartesia API key", #"\bsk_car_[A-Za-z0-9_]{20,}\b"#, keywords: ["sk_car_"]),
        SecretPattern("AssemblyAI API key", assigned("assemblyai|assembly_ai", #"[a-z0-9]{32}"#), keywords: ["assembl"]),
        SecretPattern("Deepgram API key", assigned("deepgram", #"[a-f0-9]{40}"#), keywords: ["deepgram"]),
        SecretPattern("Clarifai API key", assigned("clarifai", #"[A-Za-z0-9]{32}"#), keywords: ["clarifai"]),
        SecretPattern("fal.ai API key", assigned(#"fal[_.-]?ai|fal[_-]key|fal[_-]api"#, #"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}:[a-f0-9]{32}"#), keywords: ["fal"]),
        SecretPattern("Retell AI API key", assigned("retell", #"key_[a-f0-9]{28}"#), keywords: ["retell"]),

        // MARK: Agents, search and tooling
        SecretPattern("Tavily API key", #"\btvly-(?:dev-|prod-)?[A-Za-z0-9]{24,}\b"#, keywords: ["tvly-"]),
        SecretPattern("Firecrawl API key", #"\bfc-[a-f0-9]{32}\b"#, keywords: ["fc-"]),
        SecretPattern("E2B API key", #"\be2b_[a-f0-9]{40}\b"#, keywords: ["e2b_"]),
        SecretPattern("Browserbase API key", #"\bbb_live_[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"#, keywords: ["bb_live_"]),
        SecretPattern("Mem0 API key", assigned("mem0", #"m0-[A-Za-z0-9]{24,44}"#), keywords: ["mem0"]),
        SecretPattern("Brave Search API key", #"\bBSA[A-Za-z0-9_-]{24,40}\b"#, keywords: ["bsa"]),
        SecretPattern("Kagi API key", assigned("kagi", #"[A-Za-z0-9_-]{11}\.[A-Za-z0-9_-]{43}"#), keywords: ["kagi"]),
        SecretPattern("Exa API key", assigned(#"\bexa[_.-]?(?:api[_.-]?)?key"#, #"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"#), keywords: ["exa"]),
        SecretPattern("SerpApi key", assigned(#"serp[_-]?api"#, #"[a-f0-9]{64}"#), keywords: ["serp"]),
        SecretPattern("PromptLayer API key", assigned("promptlayer|prompt_layer", #"pl_[A-Za-z0-9]{32}"#), keywords: ["prompt"]),

        // MARK: Compute for ML
        SecretPattern("RunPod API key", #"\brpa_[A-Z0-9]{40}[A-Za-z0-9]{6}\b"#, keywords: ["rpa_"]),
        SecretPattern("Modal token secret", assigned(#"modal[\w.-]{0,20}?(?:secret|token)"#, #"as-[A-Za-z0-9]{22}"#), keywords: ["modal"]),

        // MARK: ML experiment tracking
        SecretPattern("LangSmith API key", #"\blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}\b"#, keywords: ["lsv2_"]),
        SecretPattern("Weights & Biases API key", #"\bwandb_v1_[A-Za-z0-9]{27}_[A-Za-z0-9]{49}\b"#, keywords: ["wandb_v1_"]),
        SecretPattern("Weights & Biases legacy key", assigned("wandb", #"[a-f0-9]{40}"#), keywords: ["wandb"]),
        SecretPattern("Comet API key", assigned(#"comet[_.-]?(?:ml)?[_.-]?api"#, #"[A-Za-z0-9]{25}"#), keywords: ["comet"]),
        SecretPattern("Neptune API token", #"\beyJhcGlfYWRkcmVzcyI6[A-Za-z0-9+/]{40,}={0,2}"#, keywords: ["eyjhcglfywrkcmvzcyi6"]),
        SecretPattern("DVC Studio token", #"\bisat_[A-Za-z0-9]{40,}\b"#, keywords: ["isat_"]),
        SecretPattern("Logfire token", #"\bpylf_v\d_[a-z]{2,4}_[A-Za-z0-9]{30,}\b"#, keywords: ["pylf_v"]),
        SecretPattern("Kaggle API key", #"(?s)"username"\s*:\s*"[^"\n]+"\s*,\s*"key"\s*:\s*"[a-f0-9]{32}""#, keywords: ["\"key\""]),

        // MARK: Vector databases
        SecretPattern("Pinecone legacy key", assigned("pinecone", #"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"#), keywords: ["pinecone"]),
        SecretPattern("Weaviate API key", assigned("weaviate", #"[A-Za-z0-9]{32,64}"#), keywords: ["weaviate"]),
        SecretPattern("Qdrant API key", assigned("qdrant", #"[A-Za-z0-9_.|=-]{32,128}"#), keywords: ["qdrant"]),
        SecretPattern("Chroma Cloud API key", assigned("chroma", #"ck-[A-Za-z0-9]{30,64}"#), keywords: ["chroma"]),
        SecretPattern("Zilliz API key", assigned(#"zilliz|milvus"#, #"[a-f0-9]{104}"#), keywords: ["zilliz", "milvus"]),
        SecretPattern("Upstash token", assigned("upstash", #"A[A-Za-z0-9]{3}AS[A-Za-z0-9_-]{30,90}={0,2}"#), keywords: ["upstash"]),

        // MARK: Data platforms and warehouses
        SecretPattern("Databricks OAuth secret", #"\bdose[a-f0-9]{32}\b"#, keywords: ["dose"]),
        SecretPattern("Snowflake access token", assigned(#"snowflake[_.-]?(?:programmatic[_.-]?)?(?:access[_.-]?)?token|snowflake[_.-]?pat"#, #"[A-Za-z0-9_.-]{100,500}"#), keywords: ["snowflake"]),
        SecretPattern("Snowflake password", assigned(#"snowflake[\w.-]{0,20}?(?:password|passwd|pwd)"#, #"[^\s"']{8,128}"#), keywords: ["snowflake"]),
        SecretPattern("ClickHouse Cloud API secret", #"\b4b1d[A-Za-z0-9]{38}\b"#, keywords: ["4b1d"]),
        SecretPattern("Databento API key", assigned("databento", #"db-[A-Za-z0-9]{29}"#), keywords: ["databento"]),

        // MARK: Hosted databases
        SecretPattern("PlanetScale service token", #"\bpscale_tkn_[A-Za-z0-9_=.-]{32,64}\b"#, keywords: ["pscale_tkn_"]),
        SecretPattern("PlanetScale password", #"\bpscale_pw_[A-Za-z0-9_=.-]{32,64}\b"#, keywords: ["pscale_pw_"]),
        SecretPattern("PlanetScale OAuth token", #"\bpscale_oauth_[A-Za-z0-9_=.-]{32,64}\b"#, keywords: ["pscale_oauth_"]),
        SecretPattern("Neon API key", #"\bnapi_[A-Za-z0-9]{64}\b"#, keywords: ["napi_"]),
        SecretPattern("Xata API key", #"\bxau_[A-Za-z0-9]{30,}\b"#, keywords: ["xau_"]),
        SecretPattern("MongoDB Atlas service account secret", #"\bmdb_sa_sk_[A-Za-z0-9_-]{40}(?![A-Za-z0-9_-])"#, keywords: ["mdb_sa_sk_"]),
        SecretPattern("MongoDB Atlas API key", assigned(#"(?:mongodb[_.-]?)?atlas[\w.-]{0,12}?private"#, #"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"#), keywords: ["atlas"]),
        SecretPattern("DataStax Astra token", #"\bAstraCS:[A-Za-z0-9]{24}:[a-f0-9]{64}\b"#, keywords: ["astracs:"]),
        SecretPattern("CockroachDB Cloud API key", #"\bCCDB1_[A-Za-z0-9]{22}_[A-Za-z0-9]{40}\b"#, keywords: ["ccdb1_"]),
        SecretPattern("Couchbase Capella API key", assigned(#"couchbase|capella"#, #"[A-Za-z0-9+/]{60,120}={0,2}"#), keywords: ["couchbase", "capella"]),
        SecretPattern("InfluxDB token", assigned("influx", #"[A-Za-z0-9_-]{86}=="#), keywords: ["influx"]),
        SecretPattern("Aiven service password", #"\bAVNS_[A-Za-z0-9_-]{19,}(?![A-Za-z0-9_-])"#, keywords: ["avns_"]),
        SecretPattern("Aiven auth token", assigned("aiven", #"[A-Za-z0-9/+=]{372}"#), keywords: ["aiven"]),
        SecretPattern("Redis Cloud API key", assigned(#"redis[_.-]?cloud|rediscloud"#, #"[A-Za-z0-9]{40,60}"#), keywords: ["redis"]),
        SecretPattern("Convex deploy key", #"\b(?:prod|dev|preview):[a-z]+-[a-z]+-\d{2,4}\|[A-Za-z0-9_=-]{40,}"#, keywords: ["|"]),

        // MARK: Search engines
        SecretPattern("Elastic Cloud API key", #"\bessu_[A-Za-z0-9_-]{60,200}={0,2}"#, keywords: ["essu_"]),
        SecretPattern("Elasticsearch API key header", #"(?i)\bauthorization\s*:\s*ApiKey\s+[A-Za-z0-9+/_-]{20,}={0,2}"#, keywords: ["apikey"]),
        SecretPattern("Meilisearch key", assigned(#"meili(?:search)?"#, #"[A-Za-z0-9_-]{16,64}"#), keywords: ["meili"]),
        SecretPattern("Typesense API key", assigned("typesense", #"[A-Za-z0-9]{32}"#), keywords: ["typesense"]),
        SecretPattern("Coveo API key", #"\bxx[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b"#, keywords: ["xx"]),

        // MARK: Streaming
        SecretPattern("Confluent API secret", assigned("confluent", #"[A-Za-z0-9+/]{64}"#), keywords: ["confluent"]),
        SecretPattern("Kafka SASL password", #"(?i)LoginModule\s+required\b[^;]*?\bpassword\s*=\s*"[^"\s]{6,}""#, keywords: ["loginmodule"]),

        // MARK: Product analytics
        SecretPattern("Segment public API token", #"\bsgp_[A-Za-z0-9]{64}\b"#, keywords: ["sgp_"]),
        SecretPattern("Segment write key", assigned(#"segment[\w.-]{0,20}?(?:write|key|secret|token)"#, #"[A-Za-z0-9]{32}"#), keywords: ["segment"]),
        SecretPattern("Mixpanel secret", assigned("mixpanel", #"[a-f0-9]{32}"#), keywords: ["mixpanel"]),
        SecretPattern("Amplitude secret key", assigned(#"amplitude[\w.-]{0,20}?(?:secret|private)"#, #"[a-f0-9]{32}"#), keywords: ["amplitude"]),
        SecretPattern("FullStory API key", #"\b(?:na1|eu1)\.[A-Za-z0-9+/]{60,}={0,2}"#, keywords: ["na1.", "eu1."]),
        SecretPattern("Plausible API key", assigned(#"plausible[\w.-]{0,20}?(?:key|token)"#, #"[A-Za-z0-9_-]{64}"#), keywords: ["plausible"]),
        SecretPattern("Keen API key", assigned(#"keen[_.-]?(?:io)?[_.-]?(?:master|write|read)"#, #"[A-Z0-9]{64}"#), keywords: ["keen"]),

        // MARK: Pipelines and BI
        SecretPattern("Fivetran API secret", assigned("fivetran", #"[A-Za-z0-9]{32}"#), keywords: ["fivetran"]),
        SecretPattern("Airbyte client secret", assigned(#"airbyte[\w.-]{0,20}?secret"#, #"[A-Za-z0-9]{32,64}"#), keywords: ["airbyte"]),
        SecretPattern("dbt Cloud service token", #"\bdbtc_[A-Za-z0-9_-]{30,}(?![A-Za-z0-9_-])"#, keywords: ["dbtc_"]),
        SecretPattern("dbt Cloud personal token", #"\bdbtu_[A-Za-z0-9_-]{30,}(?![A-Za-z0-9_-])"#, keywords: ["dbtu_"]),
        SecretPattern("Tableau access token", #"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{22}==:[A-Za-z0-9]{32}\b"#, keywords: ["==:"]),
        SecretPattern("Looker client secret", assigned(#"looker[\w.-]{0,20}?secret"#, #"[A-Za-z0-9]{24}"#), keywords: ["looker"]),
        SecretPattern("Metabase API key", assigned("metabase|mb_api", #"mb_[A-Za-z0-9+/]{40,}={0,2}"#), keywords: ["metabase", "mb_api"])
    ]
}
