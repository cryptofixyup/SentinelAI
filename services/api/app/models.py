from pydantic import BaseModel, ConfigDict, Field


class ReputationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(pattern="^(trusted|unknown|malicious)$")
    confidence: str = Field(pattern="^(low|medium|high)$")


class CheckTransactionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    destination: str = Field(min_length=1)
    is_unlimited_approval: bool = False
    spender: str | None = None
    destination_reputation: ReputationInput
    spender_reputation: ReputationInput | None = None


class CheckTransactionResponse(BaseModel):
    decision: str
    policy_version: str
