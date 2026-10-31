from __future__ import annotations

import hashlib
import time
from typing import Any

import httpx

from services.llm.configuration import OpenAISettings, cache_key_for_scope
from services.llm.prompts.risk_analysis import RISK_ANALYSIS_DEVELOPER_PROMPT, prompt_prefix
from services.llm.prompts.versions import PROMPT_VERSION
from services.llm.schemas import RiskAnalysis, RiskAnalysisContext
from services.llm.validation.response_validator import InvalidModelOutput, validate_analysis_json
from services.llm.telemetry import UsageMetrics


class ProviderError(RuntimeError):
    """Safe provider failure; response bodies and secrets are never included."""


class OpenAIResponsesProvider:
    """Optional Responses API adapter. It is never invoked by deterministic checks."""

    def __init__(self, settings: OpenAISettings, client: httpx.AsyncClient | None = None) -> None:
        settings.validate_for_request()
        self.settings = settings
        self._client = client
        self.last_usage = UsageMetrics()
        self.last_provider_request_id: str | None = None
        self.last_model = settings.model
        self.last_latency_ms = 0
        self.last_prompt_version = PROMPT_VERSION
        self.last_prompt_prefix_hash = self.prefix_hash()

    @staticmethod
    def prefix_hash() -> str:
        return hashlib.sha256(prompt_prefix().encode("utf-8")).hexdigest()

    def build_payload(
        self,
        context: RiskAnalysisContext,
        *,
        cache_scope: str | None = None,
    ) -> dict[str, Any]:
        developer_block: dict[str, Any] = {
            "type": "input_text",
            "text": RISK_ANALYSIS_DEVELOPER_PROMPT,
        }
        if self.settings.cache_mode == "explicit":
            developer_block["prompt_cache_breakpoint"] = {"mode": "explicit"}

        payload: dict[str, Any] = {
            "model": self.settings.model,
            "store": False,
            "max_output_tokens": self.settings.max_output_tokens,
            "input": [
                {"role": "developer", "content": [developer_block]},
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": context.model_dump_json(exclude_none=True),
                        }
                    ],
                },
            ],
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "sentinelai_risk_analysis",
                    "strict": True,
                    "schema": RiskAnalysis.model_json_schema(),
                }
            },
        }
        if self.settings.explicit_cache_supported:
            payload["prompt_cache_options"] = {
                "mode": self.settings.cache_mode,
                "ttl": self.settings.cache_ttl,
            }
        elif self.settings.legacy_cache_retention:
            payload["prompt_cache_retention"] = self.settings.legacy_cache_retention

        if cache_scope:
            payload["prompt_cache_key"] = cache_key_for_scope(cache_scope)
        return payload

    async def analyze(
        self,
        context: RiskAnalysisContext,
        *,
        cache_scope: str | None = None,
    ) -> RiskAnalysis:
        payload = self.build_payload(context, cache_scope=cache_scope)
        headers = {
            "Authorization": f"Bearer {self.settings.api_key}",
            "Content-Type": "application/json",
        }
        started = time.perf_counter()
        try:
            if self._client is not None:
                response = await self._client.post(
                    f"{self.settings.base_url}/responses",
                    headers=headers,
                    json=payload,
                    timeout=self.settings.timeout_seconds,
                )
            else:
                async with httpx.AsyncClient(timeout=self.settings.timeout_seconds) as client:
                    response = await client.post(
                        f"{self.settings.base_url}/responses",
                        headers=headers,
                        json=payload,
                    )
            response.raise_for_status()
            body = response.json()
        except httpx.TimeoutException as exc:
            raise ProviderError("OpenAI request timed out") from exc
        except httpx.HTTPStatusError as exc:
            raise ProviderError(f"OpenAI returned HTTP {exc.response.status_code}") from exc
        except (httpx.RequestError, ValueError) as exc:
            raise ProviderError("OpenAI request failed or returned invalid JSON") from exc

        raw_output = self._extract_output_text(body)
        try:
            analysis = validate_analysis_json(raw_output)
            usage = UsageMetrics.from_response(body)
        except (InvalidModelOutput, TypeError, ValueError) as exc:
            raise ProviderError("OpenAI returned invalid structured output or usage metadata") from exc

        self.last_usage = usage
        self.last_provider_request_id = response.headers.get("x-request-id")
        self.last_model = str(body.get("model") or self.settings.model)
        self.last_latency_ms = max(0, int((time.perf_counter() - started) * 1000))
        self.last_prompt_version = PROMPT_VERSION
        self.last_prompt_prefix_hash = self.prefix_hash()
        return analysis

    @staticmethod
    def _extract_output_text(body: dict[str, Any]) -> str:
        chunks: list[str] = []
        for item in body.get("output") or []:
            if item.get("type") != "message":
                continue
            for content in item.get("content") or []:
                if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                    chunks.append(content["text"])
        if not chunks:
            raise ProviderError("OpenAI response contained no structured text output")
        return "\n".join(chunks)
