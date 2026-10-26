import Foundation

extension SecretSamples {
    private static let letters = Fake.lower + Fake.upper

    static let ai: [SecretSample] = [
        // AI model providers
        SecretSample("Perplexity API key", "pplx-" + Fake.alnum(48)),
        SecretSample("Together AI API key", "tgp_v1_" + Fake.alnum(43)),
        SecretSample("Together AI legacy key", "TOGETHER_API_KEY=" + Fake.hex(64)),
        SecretSample("Fireworks AI API key", "fw_" + Fake.alnum(30)),
        SecretSample("Hugging Face org token", "api_org_" + Fake.string(34, letters)),
        SecretSample("Cohere API key", "COHERE_API_KEY=" + Fake.alnum(40)),
        SecretSample("Mistral API key", "MISTRAL_API_KEY=" + Fake.alnum(32)),
        SecretSample("Cerebras API key", "csk-" + Fake.lower(48)),
        SecretSample("NVIDIA API key", "nvapi-" + Fake.alnum(64)),
        SecretSample("Azure OpenAI key", "AZURE_OPENAI_API_KEY=" + Fake.alnum(32)),
        SecretSample("Google Gemini API key", "AQ.Ab8RN6" + Fake.alnum(44)),
        SecretSample("Upstage API key", "UPSTAGE_API_KEY=up_" + Fake.alnum(40)),
        SecretSample("Z.ai API key", "ZHIPUAI_API_KEY=" + Fake.hex(32) + "." + Fake.alnum(16)),
        SecretSample("Ollama API key", "OLLAMA_API_KEY=" + Fake.hex(32) + "." + Fake.alnum(24)),
        SecretSample("Anyscale API key", "esecret_" + Fake.alnum(30)),
        SecretSample("LlamaCloud API key", "llx-" + Fake.alnum(48)),
        SecretSample("Voyage AI API key", "VOYAGE_API_KEY=pa-" + Fake.alnum(43)),
        SecretSample("Jina AI API key", "jina_" + Fake.alnum(60)),

        // Speech, vision and media
        SecretSample("ElevenLabs API key", "sk_" + Fake.hex(48)),
        SecretSample("ElevenLabs legacy key", "ELEVENLABS_API_KEY=" + Fake.hex(32)),
        SecretSample("Cartesia API key", "sk_car_" + Fake.alnum(24)),
        SecretSample("AssemblyAI API key", "ASSEMBLYAI_API_KEY=" + Fake.lower(32)),
        SecretSample("Deepgram API key", "DEEPGRAM_API_KEY=" + Fake.hex(40)),
        SecretSample("Clarifai API key", "CLARIFAI_PAT=" + Fake.alnum(32)),
        SecretSample("fal.ai API key", "FAL_KEY=" + Fake.uuid() + ":" + Fake.hex(32, seed: 2)),
        SecretSample("Retell AI API key", "RETELL_API_KEY=key_" + Fake.hex(28)),

        // Agents, search and tooling
        SecretSample("Tavily API key", "tvly-dev-" + Fake.alnum(32)),
        SecretSample("Firecrawl API key", "fc-" + Fake.hex(32)),
        SecretSample("E2B API key", "e2b_" + Fake.hex(40)),
        SecretSample("Browserbase API key", "bb_live_" + Fake.alnum(27)),
        SecretSample("Mem0 API key", "MEM0_API_KEY=m0-" + Fake.alnum(40)),
        SecretSample("Brave Search API key", "BSA" + Fake.alnum(27)),
        SecretSample("Kagi API key", "KAGI_API_KEY=" + Fake.alnum(11) + "." + Fake.alnum(43, seed: 2)),
        SecretSample("Exa API key", "EXA_API_KEY=" + Fake.uuid()),
        SecretSample("SerpApi key", "SERPAPI_API_KEY=" + Fake.hex(64)),
        SecretSample("PromptLayer API key", "PROMPTLAYER_API_KEY=pl_" + Fake.alnum(32)),

        // Compute for ML
        SecretSample("RunPod API key", "rpa_" + Fake.upper(40) + Fake.alnum(6, seed: 2)),
        SecretSample("Modal token secret", "MODAL_TOKEN_SECRET=as-" + Fake.alnum(22)),

        // ML experiment tracking
        SecretSample("LangSmith API key", "lsv2_pt_" + Fake.hex(32) + "_" + Fake.hex(10, seed: 2)),
        SecretSample("Weights & Biases API key", "wandb_v1_" + Fake.alnum(27) + "_" + Fake.alnum(49, seed: 2)),
        SecretSample("Weights & Biases legacy key", "WANDB_API_KEY=" + Fake.hex(40)),
        SecretSample("Comet API key", "COMET_API_KEY=" + Fake.alnum(25)),
        SecretSample("Neptune API token", "eyJhcGlfYWRkcmVzcyI6" + Fake.alnum(120)),
        SecretSample("DVC Studio token", "isat_" + Fake.alnum(48)),
        SecretSample("Logfire token", "pylf_v1_us_" + Fake.alnum(40)),
        SecretSample("Kaggle API key", #"{"username":"someone","key":""# + Fake.hex(32) + #""}"#),

        // Vector databases
        SecretSample("Pinecone legacy key", "PINECONE_API_KEY=" + Fake.uuid()),
        SecretSample("Weaviate API key", "WEAVIATE_API_KEY=" + Fake.alnum(40)),
        SecretSample("Qdrant API key", "QDRANT_API_KEY=" + Fake.alnum(48)),
        SecretSample("Chroma Cloud API key", "CHROMA_API_KEY=ck-" + Fake.alnum(44)),
        SecretSample("Zilliz API key", "ZILLIZ_API_KEY=" + Fake.hex(104)),
        SecretSample("Upstash token", "UPSTASH_REDIS_REST_TOKEN=A" + Fake.alnum(3) + "AS" + Fake.alnum(60, seed: 2)),

        // Data platforms and warehouses
        SecretSample("Databricks OAuth secret", "dose" + Fake.hex(32)),
        SecretSample("Snowflake access token", "SNOWFLAKE_TOKEN=" + Fake.alnum(200)),
        SecretSample("Snowflake password", "SNOWFLAKE_PASSWORD=" + Fake.alnum(16)),
        SecretSample("ClickHouse Cloud API secret", "4b1d" + Fake.alnum(38)),
        SecretSample("Databento API key", "DATABENTO_API_KEY=db-" + Fake.alnum(29)),

        // Hosted databases
        SecretSample("PlanetScale service token", "pscale_tkn_" + Fake.alnum(43)),
        SecretSample("PlanetScale password", "pscale_pw_" + Fake.alnum(43)),
        SecretSample("PlanetScale OAuth token", "pscale_oauth_" + Fake.alnum(43)),
        SecretSample("Neon API key", "napi_" + Fake.lower(64)),
        SecretSample("Xata API key", "xau_" + Fake.alnum(32)),
        SecretSample("MongoDB Atlas service account secret", "mdb_sa_sk_" + Fake.alnum(40)),
        SecretSample("MongoDB Atlas API key", "MONGODB_ATLAS_PRIVATE_KEY=" + Fake.uuid()),
        SecretSample("DataStax Astra token", "AstraCS:" + Fake.alnum(24) + ":" + Fake.hex(64)),
        SecretSample("CockroachDB Cloud API key", "CCDB1_" + Fake.alnum(22) + "_" + Fake.alnum(40, seed: 2)),
        SecretSample("Couchbase Capella API key", "COUCHBASE_API_SECRET=" + Fake.alnum(80)),
        SecretSample("InfluxDB token", "INFLUXDB_TOKEN=" + Fake.alnum(86) + "=="),
        SecretSample("Aiven service password", "AVNS_" + Fake.alnum(23)),
        SecretSample("Aiven auth token", "AIVEN_TOKEN=" + Fake.alnum(372)),
        SecretSample("Redis Cloud API key", "REDIS_CLOUD_API_KEY=" + Fake.alnum(50)),
        SecretSample("Convex deploy key", "prod:happy-otter-123|" + Fake.alnum(80)),

        // Search engines
        SecretSample("Elastic Cloud API key", "essu_" + Fake.alnum(80)),
        SecretSample("Elasticsearch API key header", "Authorization: ApiKey " + Fake.alnum(60)),
        SecretSample("Meilisearch key", "MEILI_MASTER_KEY=" + Fake.alnum(32)),
        SecretSample("Typesense API key", "TYPESENSE_API_KEY=" + Fake.alnum(32)),
        SecretSample("Coveo API key", "xx" + Fake.uuid()),

        // Streaming
        SecretSample("Confluent API secret", "CONFLUENT_API_SECRET=" + Fake.b64(64)),
        SecretSample("Kafka SASL password",
                     #"org.apache.kafka.common.security.plain.PlainLoginModule required username="app" password=""# + Fake.alnum(24) + #"";"#),

        // Product analytics
        SecretSample("Segment public API token", "sgp_" + Fake.alnum(64)),
        SecretSample("Segment write key", "SEGMENT_WRITE_KEY=" + Fake.alnum(32)),
        SecretSample("Mixpanel secret", "MIXPANEL_API_SECRET=" + Fake.hex(32)),
        SecretSample("Amplitude secret key", "AMPLITUDE_SECRET_KEY=" + Fake.hex(32)),
        SecretSample("FullStory API key", "na1." + Fake.alnum(100)),
        SecretSample("Plausible API key", "PLAUSIBLE_API_KEY=" + Fake.alnum(64)),
        SecretSample("Keen API key", "KEEN_MASTER_KEY=" + Fake.upper(64)),

        // Pipelines and BI
        SecretSample("Fivetran API secret", "FIVETRAN_API_SECRET=" + Fake.alnum(32)),
        SecretSample("Airbyte client secret", "AIRBYTE_CLIENT_SECRET=" + Fake.alnum(40)),
        SecretSample("dbt Cloud service token", "dbtc_" + Fake.alnum(40)),
        SecretSample("dbt Cloud personal token", "dbtu_" + Fake.alnum(40)),
        SecretSample("Tableau access token", Fake.alnum(22) + "==:" + Fake.alnum(32, seed: 2)),
        SecretSample("Looker client secret", "LOOKER_CLIENT_SECRET=" + Fake.alnum(24)),
        SecretSample("Metabase API key", "METABASE_API_KEY=mb_" + Fake.alnum(44))
    ]
}
