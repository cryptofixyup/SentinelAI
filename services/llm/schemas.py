from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RiskAnalysisContext(BaseModel):
    """Minimal deterministic evidence; no signing payloads, secrets, or sender identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    deterministic_decision: str = Field(pattern="^(allow|warn|block)$")
    policy_version: str = Field(min_length=1, max_length=64)
    chain_id: int = Field(gt=0)
    destination: str = Field(min_length=1, max_length=128)
    destination_reputation_status: str = Field(pattern="^(trusted|unknown|malicious)$")
    destination_reputation_confidence: str = Field(pattern="^(low|medium|high)$")
    is_unlimited_approval: bool = False
    spender: str | None = Field(default=None, max_length=128)
    spender_reputation_status: str | None = Field(
        default=None, pattern="^(trusted|unknown|malicious)$"
    )
    spender_reputation_confidence: str | None = Field(
        default=None, pattern="^(low|medium|high)$"
    )


class RiskAnalysis(BaseModel):
    """Explanatory output only; deliberately contains no action/decision field."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    summary: str = Field(min_length=1, max_length=800)
    observations: list[str] = Field(max_length=5)
    limitations: list[str] = Field(max_length=5)
