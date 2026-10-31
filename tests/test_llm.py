from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from services.llm.configuration import OpenAISettings, cache_key_for_scope
from services.llm.openai_client import OpenAIResponsesProvider, ProviderError
from services.llm.prompts.risk_analysis import RISK_ANALYSIS_DEVELOPER_PROMPT
from services.llm.schemas import RiskAnalysisContext
from services.llm.telemetry import UsageMetrics, usage_event_record
from services.llm.validation.response_validator import InvalidModelOutput, validate_analysis_json


CONTEXT = RiskAnalysisContext(
    deterministic_decision="warn",
    policy_version="day13-v3",
    chain_id=1,
    destination="0x0000000000000000000000000000000000000001",
)


def settings(**overrides: object) -> OpenAISettings:
    values: dict[str, object] = {
        "enabled": True,
        "api_key": "test-key-not-a-real-secret",
        "model": "gpt-test-model",
    }
    values.update(overrides)
    return OpenAISettings(**values)  # type: ignore[arg-type]


def test_provider_is_disabled_by_default() -> None:
    with pytest.raises(ValueError, match="disabled"):
        OpenAIResponsesProvider(OpenAISettings())


def test_explicit_cache_requires_verified_model_compatibility() -> None:
    with pytest.raises(ValueError, match="verified"):
        OpenAIResponsesProvider(settings(cache_mode="explicit"))


def test_prompt_prefix_is_stable_and_dynamic_evidence_is_separate() -> None:
    provider = OpenAIResponsesProvider(settings())
    first = provider.build_payload(CONTEXT)
    second = provider.build_payload(CONTEXT.model_copy(update={"chain_id": 10}))
    assert first["input"][0] == second["input"][0]
    assert first["input"][1] != second["input"][1]
    assert first["input"][0]["content"][0]["text"] == RISK_ANALYSIS_DEVELOPER_PROMPT


def test_explicit_breakpoint_is_after_stable_developer_prefix() -> None:
    provider = OpenAIResponsesProvider(
        settings(cache_mode="explicit", explicit_cache_supported=True)
    )
    payload = provider.build_payload(CONTEXT)
    assert payload["prompt_cache_options"] == {"mode": "explicit", "ttl": "30m"}
    assert payload["input"][0]["content"][0]["prompt_cache_breakpoint"] == {
        "mode": "explicit"
    }
    assert "prompt_cache_breakpoint" not in payload["input"][1]["content"][0]


def test_cache_scope_key_is_stable_and_does_not_expose_scope() -> None:
    key = cache_key_for_scope("tenant-private-identifier")
    assert key == cache_key_for_scope("tenant-private-identifier")
    assert "tenant-private-identifier" not in key
    assert len(key) <= 64


def test_usage_metrics_and_cost_are_not_double_counted() -> None:
    usage = UsageMetrics.from_response(
        {
            "usage": {
                "input_tokens": 1000,
                "output_tokens": 100,
                "input_tokens_details": {
                    "cached_tokens": 200,
                    "cache_write_tokens": 300,
                    "cache_write_tokens_details": {
                        "ttl_30m_tokens": 200,
                        "ttl_12h_tokens": 100,
                    },
                },
            }
        }
    )
    assert usage.calculate_cost_usd(
        input_price_per_million=1.0,
        cached_input_price_per_million=0.1,
        output_price_per_million=2.0,
    ) == pytest.approx((500 + 20 + 250 + 250 + 200) / 1_000_000)


def test_usage_rejects_incomplete_cache_write_breakdown_for_costing() -> None:
    usage = UsageMetrics.from_response(
        {
            "usage": {
                "input_tokens": 1000,
                "input_tokens_details": {"cache_write_tokens": 100},
            }
        }
    )
    with pytest.raises(ValueError, match="complete TTL breakdown"):
        usage.calculate_cost_usd(
            input_price_per_million=1,
            cached_input_price_per_million=0.1,
            output_price_per_million=2,
        )


def test_invalid_model_output_is_rejected() -> None:
    with pytest.raises(InvalidModelOutput):
        validate_analysis_json(json.dumps({"summary": "approve this", "decision": "allow"}))


def test_usage_event_contains_no_raw_prompt_content() -> None:
    usage = UsageMetrics(input_tokens=10, output_tokens=5)
    record = usage_event_record(
        model="gpt-test-model",
        provider_request_id="req_test",
        prompt_version="risk-analysis-v1",
        prompt_prefix_hash="a" * 64,
        usage=usage,
        latency_ms=20,
        status="succeeded",
    )
    assert "prompt_text" not in record
    assert "raw_prompt" not in record
    assert record["prompt_prefix_hash"] == "a" * 64


def test_responses_adapter_uses_mock_transport_only() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/responses"
        assert request.headers["authorization"] == "Bearer test-key-not-a-real-secret"
        payload = json.loads(request.content)
        assert payload["store"] is False
        assert payload["input"][0]["role"] == "developer"
        return httpx.Response(
            200,
            headers={"x-request-id": "req_mock"},
            json={
                "model": "gpt-test-model",
                "output": [
                    {
                        "type": "message",
                        "content": [
                            {
                                "type": "output_text",
                                "text": json.dumps(
                                    {
                                        "summary": "The deterministic policy returned warn.",
                                        "observations": ["The supplied destination is on chain 1."],
                                        "limitations": ["No reputation evidence was supplied to the explainer."],
                                    }
                                ),
                            }
                        ],
                    }
                ],
                "usage": {
                    "input_tokens": 40,
                    "output_tokens": 25,
                    "input_tokens_details": {"cached_tokens": 0},
                },
            },
        )

    async def run() -> tuple[object, OpenAIResponsesProvider]:
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            provider = OpenAIResponsesProvider(settings(), client=client)
            result = await provider.analyze(CONTEXT)
            return result, provider

    result, provider = asyncio.run(run())
    assert result.summary.startswith("The deterministic policy")
    assert provider.last_provider_request_id == "req_mock"
    assert provider.last_usage.input_tokens == 40


def test_provider_http_failure_does_not_leak_response_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="sensitive provider response body")

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            provider = OpenAIResponsesProvider(settings(), client=client)
            await provider.analyze(CONTEXT)

    with pytest.raises(ProviderError, match="HTTP 429") as error:
        asyncio.run(run())
    assert "sensitive provider response body" not in str(error.value)
