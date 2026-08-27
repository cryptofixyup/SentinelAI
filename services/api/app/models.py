from pydantic import BaseModel, ConfigDict, Field, field_validator

from services.api.app.validation import normalize_address


class ReputationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(pattern="^(trusted|unknown|malicious)$")
    confidence: str = Field(pattern="^(low|medium|high)$")


class CheckTransactionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chain_id: int = Field(gt=0)
    destination: str
    is_unlimited_approval: bool = False
    spender: str | None = None
    destination_reputation: ReputationInput
    spender_reputation: ReputationInput | None = None

    @field_validator("destination")
    @classmethod
    def validate_destination(cls, value: str) -> str:
        return normalize_address(value)

    @field_validator("spender")
    @classmethod
    def validate_spender(cls, value: str | None) -> str | None:
        return normalize_address(value) if value is not None else None


class CheckTransactionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: str = Field(pattern="^(allow|warn|block)$")
    policy_version: str
