from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ZERO = "0x0000000000000000000000000000000000000000"


@dataclass(frozen=True)
class Score:
    signer_independence: float
    key_security: float
    execution_security: float
    transaction_controls: float
    recovery_resilience: float
    monitoring_response: float

    @property
    def total(self) -> int:
        value = (0.25 * self.signer_independence + 0.15 * self.key_security + 0.20 * self.execution_security + 0.15 * self.transaction_controls + 0.15 * self.recovery_resilience + 0.10 * self.monitoring_response)
        return round(max(0.0, min(100.0, value)))


def signer_independence(signer: dict[str, Any]) -> int:
    fields = {"key_generation_verified": 20, "hardware_independent": 15, "software_independent": 10, "administrator_independent": 15, "geography_independent": 15, "backup_independent": 10, "communications_independent": 5, "recovery_independent": 10}
    return sum(weight for field, weight in fields.items() if signer.get(field) is True)


def _is_zero(address: Any) -> bool:
    return isinstance(address, str) and address.lower() == ZERO


def _allowlisted(item: dict[str, Any] | None, entries: list[dict[str, Any]], chain_id: int) -> bool:
    if not item:
        return True
    address = str(item.get("address", "")).lower()
    code_hash = str(item.get("code_hash", "")).lower()
    return any(int(e.get("chain_id", -1)) == chain_id and str(e.get("address", "")).lower() == address and str(e.get("code_hash", "")).lower() == code_hash for e in entries)


def _audited(item: dict[str, Any] | None, entries: list[dict[str, Any]], chain_id: int) -> bool:
    if not item:
        return True
    return any(int(e.get("chain_id", -1)) == chain_id and str(e.get("address", "")).lower() == str(item.get("address", "")).lower() and str(e.get("code_hash", "")).lower() == str(item.get("code_hash", "")).lower() and e.get("audit_status") in {"audited", "reviewed"} for e in entries)


def _decision_for_risk(risk: int) -> str:
    if risk <= 19: return "ALLOW"
    if risk <= 39: return "ALLOW_WITH_CONTROLS"
    if risk <= 79: return "REVIEW"
    return "BLOCK"


def transaction_risk(tx: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    rules: list[str] = []
    weighted = (("unknown_destination", 20), ("unverified_contract", 15), ("first_interaction", 10), ("token_approval", 15), ("unlimited_approval", 30), ("ownership_change", 40), ("threshold_change", 40), ("signer_change", 35), ("module_change", 40), ("guard_change", 35), ("fallback_change", 35), ("delegatecall", 40), ("unbounded_external_execution", 35), ("simulation_mismatch", 50), ("simulation_unavailable_high_value", 30), ("policy_violation", 40))
    for field, weight in weighted:
        if tx.get(field) is True:
            score += weight
            rules.append(field)
    if tx.get("denylisted_destination") is True:
        return 100, rules + ["denylisted_destination"]
    if tx.get("calldata_decoded") is False:
        rules.append("calldata_undecoded")
        score += 30 if tx.get("high_value") else 10
    return min(score, 100), rules


def evaluate_custody(state: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    owners = state.get("owners", [])
    threshold = int(state.get("threshold", 0))
    chain_id = int(state.get("chain_id", 0))
    hard_blocks: list[str] = []

    if threshold < int(policy["custody"]["minimum_threshold"]): hard_blocks.append("threshold_below_minimum")
    if policy["custody"]["require_threshold_below_signer_count"] and not threshold < len(owners): hard_blocks.append("threshold_not_below_signer_count")
    hard_blocks.extend(str(item) for item in state.get("hard_blocks", []) if item)

    signer_scores = [signer_independence(s) for s in state.get("signers", [])]
    min_signer = min(signer_scores) if signer_scores else 0
    if min_signer < int(policy["custody"]["minimum_signer_independence"]): hard_blocks.append("signer_independence_below_minimum")

    allow = policy["allowlists"]
    modules = state.get("modules", [])
    guards = state.get("guards", [])
    module_guard = state.get("module_guard")
    fallback = state.get("fallback_handler")

    if any(not _allowlisted(m, allow["modules"], chain_id) for m in modules): hard_blocks.append("unknown_module")
    if any(not _allowlisted(g, allow["guards"], chain_id) for g in guards): hard_blocks.append("unknown_guard")
    if module_guard and not _allowlisted(module_guard, allow["module_guards"], chain_id): hard_blocks.append("unknown_module_guard")
    if fallback and not _allowlisted(fallback, allow["fallback_handlers"], chain_id): hard_blocks.append("unknown_fallback")

    recovery = float(state.get("recovery_score", 0))
    if recovery < int(policy["custody"]["minimum_recovery_score"]): hard_blocks.append("recovery_score_below_minimum")

    transaction = state.get("transaction")
    tx_score, tx_rules = (0, []) if transaction is None else transaction_risk(transaction)
    configured_hard_blocks = set(policy.get("hard_blocks", []))
    hard_blocks.extend(r for r in tx_rules if r in configured_hard_blocks)
    if "denylisted_destination" in tx_rules: hard_blocks.append("denylisted_destination")

    extension_entries = allow["modules"] + allow["guards"] + allow["module_guards"] + allow["fallback_handlers"]
    active_extensions = modules + guards + ([module_guard] if module_guard else []) + ([fallback] if fallback else [])
    execution = 100 if all(_audited(x, extension_entries, chain_id) for x in active_extensions) else 0

    score = Score(min_signer, float(state.get("key_security_score", 100)), execution, max(0, 100 - tx_score), recovery, float(state.get("monitoring_score", 100)))
    decision = "BLOCK" if hard_blocks else _decision_for_risk(tx_score)
    if not hard_blocks and score.total < 40: decision = "BLOCK"
    elif not hard_blocks and score.total < 70 and decision == "ALLOW": decision = "ALLOW_WITH_CONTROLS"

    return {"custody_risk_score": score.total, "transaction_risk_score": tx_score, "transaction_rules": tx_rules, "signer_independence_min": min_signer, "hard_blocks": sorted(set(hard_blocks)), "decision": decision}
