from fastapi import FastAPI

from services.api.app.models import CheckTransactionRequest, CheckTransactionResponse
from services.intelligence.sentinel_risk.engine import (
    Confidence,
    Reputation,
    ReputationStatus,
    TransactionFacts,
    evaluate_transaction,
)

POLICY_VERSION = "day13-v3"

app = FastAPI(title="SentinelAI API", version="0.1.0")


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/check-tx", response_model=CheckTransactionResponse, tags=["risk"])
def check_transaction(request: CheckTransactionRequest) -> CheckTransactionResponse:
    tx = TransactionFacts(
        destination=request.destination,
        is_unlimited_approval=request.is_unlimited_approval,
        spender=request.spender,
    )
    destination_reputation = Reputation(
        status=ReputationStatus(request.destination_reputation.status),
        confidence=Confidence(request.destination_reputation.confidence),
    )
    spender_reputation = (
        Reputation(
            status=ReputationStatus(request.spender_reputation.status),
            confidence=Confidence(request.spender_reputation.confidence),
        )
        if request.spender_reputation
        else None
    )

    decision = evaluate_transaction(
        tx,
        destination_reputation,
        spender_reputation,
    )

    return CheckTransactionResponse(
        decision=decision.value,
        policy_version=POLICY_VERSION,
    )
