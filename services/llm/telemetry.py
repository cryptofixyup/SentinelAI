from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class UsageMetrics:
    input_tokens: int = 0
    cached_tokens: int = 0
    cache_write_tokens: int = 0
    ttl_30m_tokens: int = 0
    ttl_12h_tokens: int = 0
    output_tokens: int = 0

    @classmethod
    def from_response(cls, response: dict[str, Any]) -> "UsageMetrics":
        usage = response.get("usage") or {}
        details = usage.get("input_tokens_details") or {}
        write_details = details.get("cache_write_tokens_details") or {}
        values = cls(
            input_tokens=int(usage.get("input_tokens") or 0),
            cached_tokens=int(details.get("cached_tokens") or 0),
            cache_write_tokens=int(details.get("cache_write_tokens") or 0),
            ttl_30m_tokens=int(write_details.get("ttl_30m_tokens") or 0),
            ttl_12h_tokens=int(write_details.get("ttl_12h_tokens") or 0),
            output_tokens=int(usage.get("output_tokens") or 0),
        )
        if min(asdict(values).values()) < 0:
            raise ValueError("usage token counts cannot be negative")
        if values.cached_tokens + values.cache_write_tokens > values.input_tokens:
            raise ValueError("cached and cache-write tokens exceed total input tokens")
        if values.ttl_30m_tokens + values.ttl_12h_tokens > values.cache_write_tokens:
            raise ValueError("TTL write breakdown exceeds total cache-write tokens")
        return values

    def calculate_cost_usd(
        self,
        *,
        input_price_per_million: float,
        cached_input_price_per_million: float,
        output_price_per_million: float,
    ) -> float:
        """Calculate cost from model-specific prices; no prices are guessed."""
        prices = (input_price_per_million, cached_input_price_per_million, output_price_per_million)
        if any(price < 0 for price in prices):
            raise ValueError("prices must be non-negative")
        if self.cache_write_tokens != self.ttl_30m_tokens + self.ttl_12h_tokens:
            raise ValueError("cannot price cache writes without a complete TTL breakdown")
        ordinary_tokens = self.input_tokens - self.cached_tokens - self.cache_write_tokens
        input_cost = (
            ordinary_tokens * input_price_per_million
            + self.cached_tokens * cached_input_price_per_million
            + self.ttl_30m_tokens * 1.25 * input_price_per_million
            + self.ttl_12h_tokens * 2.5 * input_price_per_million
        ) / 1_000_000
        output_cost = self.output_tokens * output_price_per_million / 1_000_000
        return input_cost + output_cost


def usage_event_record(
    *,
    model: str,
    provider_request_id: str | None,
    prompt_version: str,
    prompt_prefix_hash: str,
    usage: UsageMetrics,
    latency_ms: int,
    status: str,
    estimated_cost_usd: float | None = None,
) -> dict[str, Any]:
    """Create a DB-ready record containing metadata only, never prompt content."""
    if status not in {"succeeded", "failed"}:
        raise ValueError("status must be succeeded or failed")
    if latency_ms < 0:
        raise ValueError("latency_ms cannot be negative")
    if len(prompt_prefix_hash) != 64:
        raise ValueError("prompt_prefix_hash must be a SHA-256 hex digest")
    return {
        "provider": "openai",
        "model": model,
        "provider_request_id": provider_request_id,
        "prompt_version": prompt_version,
        "prompt_prefix_hash": prompt_prefix_hash,
        **asdict(usage),
        "latency_ms": latency_ms,
        "status": status,
        "estimated_cost_usd": estimated_cost_usd,
    }
