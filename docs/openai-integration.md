# Optional OpenAI Analysis Boundary

**Status:** Implemented as an opt-in adapter; disabled by default.  
**Authority:** Supplementary explanation only. Deterministic policy and Rust enforcement remain authoritative.

## Activation

The adapter is not called by /v1/check-tx. To instantiate it deliberately, set:

- SENTINELAI_OPENAI_ENABLED=true
- OPENAI_API_KEY (secret manager/environment only; never commit it)
- SENTINELAI_OPENAI_MODEL (choose and verify a currently supported model)

Optional settings:

- SENTINELAI_OPENAI_BASE_URL (default https://api.openai.com/v1)
- SENTINELAI_OPENAI_TIMEOUT_SECONDS (default 15)
- SENTINELAI_OPENAI_MAX_OUTPUT_TOKENS (default 500)
- SENTINELAI_OPENAI_CACHE_MODE=implicit|explicit (default implicit)
- SENTINELAI_OPENAI_CACHE_TTL=30m|12h (default 30m)
- SENTINELAI_OPENAI_EXPLICIT_CACHE_SUPPORTED=true only after verifying the selected model's current documentation
- SENTINELAI_OPENAI_LEGACY_CACHE_RETENTION=in_memory|24h for supported earlier models
- SENTINELAI_OPENAI_INPUT_PRICE_PER_MILLION, SENTINELAI_OPENAI_CACHED_INPUT_PRICE_PER_MILLION, and SENTINELAI_OPENAI_OUTPUT_PRICE_PER_MILLION for cost estimates from verified prices

No .env file or credentials are included. The module performs no request at import time. Tests use httpx.MockTransport; they do not contact OpenAI.

## Calling the provider

Construct OpenAIResponsesProvider(OpenAISettings.from_env()) only in an explicitly enabled application workflow, then call await provider.analyze(RiskAnalysisContext(...)). The caller should persist the provider's last_usage, last_provider_request_id, last_model, last_latency_ms, last_prompt_version, and last_prompt_prefix_hash via the telemetry helpers/table. The adapter is deliberately not wired into transaction evaluation or signing.

For per-tenant cache accounting, pass a stable opaque tenant scope as cache_scope; only a SHA-256-derived key is sent to OpenAI. Do not pass a raw customer identifier.

## Prompt caching notes

- The developer prompt is static and precedes the dynamic transaction evidence.
- The output schema is stable; no tools are currently defined.
- Explicit mode places a breakpoint after the static developer message and requires an explicit compatibility opt-in.
- The static prompt has not been tokenizer-measured and may be below the 1,024 visible-token minimum documented for GPT-5.6+; do not claim cache hits until usage telemetry proves them.
- Do not pad prompts solely to cross the cache threshold. Add only useful stable context, then measure cost and quality.
- For models before GPT-5.6, use implicit caching and only set legacy retention where the selected model supports it.
- Model prices and cache-read rates are configuration inputs, not hard-coded assumptions. Missing prices mean cost remains unknown.

## Telemetry and cost

UsageMetrics.from_response parses input, cached, cache-write, TTL-specific write, and output token counts. calculate_cost_usd requires model-specific input, cached-input, and output prices. It refuses to price a request when a cache-write TTL breakdown is incomplete rather than silently double-counting or guessing.

model_usage_events stores token counts, request metadata, prompt version/hash, latency, status, and optional estimated cost. It intentionally stores no prompt or transaction content.

## Operational safeguards

- No retries: a timeout or provider error is surfaced once to avoid duplicate spend.
- Request timeout is bounded.
- Provider error messages omit response bodies.
- Responses API store is set to false.
- Structured output is validated with Pydantic and rejects extra fields.
- Output schema has no decision/action field.
- Missing/invalid output is an analysis failure, never an ALLOW.
- The deterministic API and Rust enforcement paths do not depend on provider availability.

## Current validation boundary

The adapter can be tested offline with mock transport. No live OpenAI API call, model selection, credential configuration, production database migration, or deployment is performed by this implementation change.
