from dataclasses import dataclass
from enum import StrEnum


class Decision(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class ReputationStatus(StrEnum):
    TRUSTED = "trusted"
    UNKNOWN = "unknown"
    MALICIOUS = "malicious"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Reputation:
    status: ReputationStatus
    confidence: Confidence


@dataclass(frozen=True)
class TransactionFacts:
    destination: str
    is_unlimited_approval: bool = False
    spender: str | None = None


def evaluate_transaction(
    tx: TransactionFacts,
    destination_reputation: Reputation,
    spender_reputation: Reputation | None = None,
) -> Decision:
    """Apply the minimal deterministic policy.

    Only independently high-confidence malicious evidence can BLOCK.
    Unknown or unavailable evidence never becomes an implicit ALLOW.
    """
    if (
        destination_reputation.status is ReputationStatus.MALICIOUS
        and destination_reputation.confidence is Confidence.HIGH
    ):
        return Decision.BLOCK

    if (
        tx.is_unlimited_approval
        and tx.spender
        and spender_reputation
        and spender_reputation.status is ReputationStatus.MALICIOUS
        and spender_reputation.confidence is Confidence.HIGH
    ):
        return Decision.BLOCK

    if (
        destination_reputation.status is ReputationStatus.UNKNOWN
        or destination_reputation.confidence is Confidence.LOW
    ):
        return Decision.WARN

    if tx.is_unlimited_approval:
        return Decision.WARN

    return Decision.ALLOW
