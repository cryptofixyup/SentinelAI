from services.intelligence.sentinel_risk.engine import (
    Confidence,
    Decision,
    Reputation,
    ReputationStatus,
    TransactionFacts,
    evaluate_transaction,
)


def reputation(status: ReputationStatus, confidence: Confidence) -> Reputation:
    return Reputation(status=status, confidence=confidence)


def test_high_confidence_malicious_destination_blocks() -> None:
    decision = evaluate_transaction(
        TransactionFacts(destination="0xdead"),
        reputation(ReputationStatus.MALICIOUS, Confidence.HIGH),
    )

    assert decision is Decision.BLOCK


def test_unknown_destination_warns() -> None:
    decision = evaluate_transaction(
        TransactionFacts(destination="0xunknown"),
        reputation(ReputationStatus.UNKNOWN, Confidence.LOW),
    )

    assert decision is Decision.WARN


def test_unlimited_approval_to_malicious_spender_blocks() -> None:
    decision = evaluate_transaction(
        TransactionFacts(
            destination="0xtoken",
            spender="0xspender",
            is_unlimited_approval=True,
        ),
        reputation(ReputationStatus.TRUSTED, Confidence.HIGH),
        reputation(ReputationStatus.MALICIOUS, Confidence.HIGH),
    )

    assert decision is Decision.BLOCK


def test_unlimited_approval_without_malicious_spender_only_warns() -> None:
    decision = evaluate_transaction(
        TransactionFacts(
            destination="0xtoken",
            spender="0xspender",
            is_unlimited_approval=True,
        ),
        reputation(ReputationStatus.TRUSTED, Confidence.HIGH),
        reputation(ReputationStatus.UNKNOWN, Confidence.LOW),
    )

    assert decision is Decision.WARN
