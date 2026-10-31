from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Literal

CacheMode = Literal["implicit", "explicit"]
CacheTtl = Literal["30m", "12h"]
LegacyRetention = Literal["in_memory", "24h"]


@dataclass(frozen=True)
class OpenAISettings:
    """Runtime configuration. Disabled by default; secrets are env-only."""

    enabled: bool = False
    api_key: str | None = None
    model: str | None = None
    base_url: str = "https://api.openai.com/v1"
    timeout_seconds: float = 15.0
    max_output_tokens: int = 500
    cache_mode: CacheMode = "implicit"
    cache_ttl: CacheTtl = "30m"
    explicit_cache_supported: bool = False
    legacy_cache_retention: LegacyRetention | None = None
    input_price_per_million: float | None = None
    cached_input_price_per_million: float | None = None
    output_price_per_million: float | None = None

    @classmethod
    def from_env(cls) -> "OpenAISettings":
        enabled = os.getenv("SENTINELAI_OPENAI_ENABLED", "false").strip().lower() in {
            "1", "true", "yes", "on"
        }
        cache_mode = os.getenv("SENTINELAI_OPENAI_CACHE_MODE", "implicit").strip().lower()
        if cache_mode not in {"implicit", "explicit"}:
            raise ValueError("SENTINELAI_OPENAI_CACHE_MODE must be implicit or explicit")
        cache_ttl = os.getenv("SENTINELAI_OPENAI_CACHE_TTL", "30m").strip().lower()
        if cache_ttl not in {"30m", "12h"}:
            raise ValueError("SENTINELAI_OPENAI_CACHE_TTL must be 30m or 12h")
        legacy_retention = os.getenv("SENTINELAI_OPENAI_LEGACY_CACHE_RETENTION")
        if legacy_retention not in {None, "in_memory", "24h"}:
            raise ValueError("legacy cache retention must be in_memory or 24h")
        explicit_supported = os.getenv(
            "SENTINELAI_OPENAI_EXPLICIT_CACHE_SUPPORTED", "false"
        ).strip().lower() in {"1", "true", "yes", "on"}

        def optional_price(name: str) -> float | None:
            raw = os.getenv(name)
            if raw is None or not raw.strip():
                return None
            value = float(raw)
            if value < 0:
                raise ValueError(f"{name} must be non-negative")
            return value

        timeout = float(os.getenv("SENTINELAI_OPENAI_TIMEOUT_SECONDS", "15"))
        max_output = int(os.getenv("SENTINELAI_OPENAI_MAX_OUTPUT_TOKENS", "500"))
        if timeout <= 0 or max_output <= 0:
            raise ValueError("timeout and max output tokens must be positive")

        return cls(
            enabled=enabled,
            api_key=os.getenv("OPENAI_API_KEY"),
            model=os.getenv("SENTINELAI_OPENAI_MODEL"),
            base_url=os.getenv("SENTINELAI_OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
            timeout_seconds=timeout,
            max_output_tokens=max_output,
            cache_mode=cache_mode,  # type: ignore[arg-type]
            cache_ttl=cache_ttl,  # type: ignore[arg-type]
            explicit_cache_supported=explicit_supported,
            legacy_cache_retention=legacy_retention,  # type: ignore[arg-type]
            input_price_per_million=optional_price("SENTINELAI_OPENAI_INPUT_PRICE_PER_MILLION"),
            cached_input_price_per_million=optional_price("SENTINELAI_OPENAI_CACHED_INPUT_PRICE_PER_MILLION"),
            output_price_per_million=optional_price("SENTINELAI_OPENAI_OUTPUT_PRICE_PER_MILLION"),
        )

    def validate_for_request(self) -> None:
        if not self.enabled:
            raise ValueError("OpenAI analysis is disabled; set SENTINELAI_OPENAI_ENABLED=true")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is required when OpenAI analysis is enabled")
        if not self.model:
            raise ValueError("SENTINELAI_OPENAI_MODEL is required when OpenAI analysis is enabled")
        if self.cache_mode == "explicit" and not self.explicit_cache_supported:
            raise ValueError(
                "explicit caching requires a model verified to support explicit breakpoints"
            )


def cache_key_for_scope(scope: str) -> str:
    """Return a stable, non-reversible cache-accounting key for a tenant scope."""
    if not scope or not scope.strip():
        raise ValueError("cache scope must not be empty")
    digest = hashlib.sha256(scope.encode("utf-8")).hexdigest()[:48]
    return f"sentinelai:{digest}"
