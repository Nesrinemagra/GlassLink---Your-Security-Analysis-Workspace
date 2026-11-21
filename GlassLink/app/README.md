# ThreatGuard — integrated desktop application

Java 21 + JavaFX desktop UI connected directly to the ScamHunter detection backend.

## Run
1. Install JDK 21 and Maven.
2. Copy `config.properties.example` to `config.properties`.
3. Add your VirusTotal API key to `config.properties`:
   `virustotal.api.key=YOUR_VIRUSTOTAL_API_KEY`
   or set `VIRUSTOTAL_API_KEY` as an environment variable.
4. From this folder run: `mvn clean javafx:run`
5. Run backend tests with: `mvn test`

## Detection behaviour
- URL: VirusTotal URL analysis. A URL is `Safe` only when an existing VirusTotal analysis reports no malicious/suspicious detections; a 404/missing report is `Not Verified`, not `Safe`; a malicious/suspicious result is `Danger`. Missing key, network/API errors, or unknown responses are `Not Verified`.
- Message: local rule-based scoring. Medium/High scores are `Suspect`; low scores are `Low Risk`. Messages are not externally verified and must not be described as `Safe`.
- Batch scan: reads `type,content` CSV using the backend CSV parser and evaluates each row in the background.

`Auto Detect` treats input beginning with an HTTP(S) URL as a URL; other text is treated as a message.

## AI Analysis tab
- The **AI Analysis** tab is independent from Single Scan and Batch Scan. It has its own backend model and never
  merges AI output into RuleAnalyzer or VirusTotal results.
- It analyzes both URLs and messages for phishing/security indicators and shows a Type / Status / Risk table plus
  short **AI Insights** bullet points.
- The Java app keeps inference keys in backend config only; no AI key is ever placed in FXML, controllers, or chat.
- `ai.provider` selects the provider:
  - `opencode`: sends the prompt to the local OpenCode service's stateless endpoint
    (`POST /api/experimental/generate/text`) using the local service password from
    `~/.local/state/opencode/service.json` (`XDG_STATE_HOME/opencode/service.json` when set).
  - `openai-compatible`: calls an OpenAI-compatible `/chat/completions` endpoint directly. Defaults are Groq's free
    OpenAI-compatible base URL and `openai/gpt-oss-20b`.
  - `auto`: tries OpenCode first, then falls back to the OpenAI-compatible provider.
- Optional backend-only overrides are documented in `config.properties.example` (`ai.opencode.url`,
  `ai.opencode.service-file`, `ai.opencode.model`, `ai.openai.base.url`, `ai.openai.model`,
  `ai.openai.api.key`, `ai.timeout.seconds`, or matching `OPENCODE_*` / `AI_*` / `GROQ_*` environment variables).
- To use the free Groq fallback: sign in at `https://console.groq.com`, create a key at
  `https://console.groq.com/keys`, and set `ai.openai.api.key` in `config.properties` (or `GROQ_API_KEY` in the
  backend environment). Keep `ai.provider=openai-compatible` to bypass OpenCode quota issues.
- Connection, authentication, missing configuration, model/provider, quota, and response errors are reported in the
  result card instead of being silently replaced.
- Loading, empty, invalid-input, error, and success states are all shown in the result card.

## API key safety
Do not commit `config.properties`. Rotate any API key that was previously committed or shared in an archive.
