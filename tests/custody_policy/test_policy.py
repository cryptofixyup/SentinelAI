import pytest

from services.custody_policy.policy import load_policy
from services.custody_policy.scoring import evaluate_custody, signer_independence, transaction_risk


@pytest.fixture
def policy():
    return load_policy()


def signer(independent=True):
    return {name: independent for name in (
        "key_generation_verified", "hardware_independent", "software_independent",
        "administrator_independent", "geography_independent", "backup_independent",
        "communications_independent", "recovery_independent",
    )}


def test_signer_independence_is_deterministic():
    assert signer_independence(signer()) == 100
    assert signer_independence(signer(False)) == 0


def test_transaction_risk_is_deterministic():
    score, rules = transaction_risk({"token_approval": True, "unlimited_approval": True})
    assert score == 45
    assert rules == ["token_approval", "unlimited_approval"]


def test_denylisted_destination_is_hard_block():
    score, rules = transaction_risk({"denylisted_destination": True})
    assert score == 100
    assert rules == ["denylisted_destination"]


def test_healthy_3_of_5_can_pass(policy):
    state = {
        "owners": ["a", "b", "c", "d", "e"], "threshold": 3,
        "signers": [signer() for _ in range(5)], "modules": [], "guards": [],
        "fallback_handler": {}, "recovery_score": 95, "key_security_score": 95,
        "monitoring_score": 95, "transaction": {"calldata_decoded": True},
    }
    result = evaluate_custody(state, policy)
    assert result["hard_blocks"] == []
    assert result["decision"] == "ALLOW"
    assert result["custody_risk_score"] >= 90


def test_n_of_n_blocks(policy):
    state = {
        "owners": ["a", "b", "c"], "threshold": 3,
        "signers": [signer() for _ in range(3)], "modules": [], "guards": [],
        "fallback_handler": {}, "recovery_score": 95,
    }
    result = evaluate_custody(state, policy)
    assert "threshold_not_below_signer_count" in result["hard_blocks"]
    assert result["decision"] == "BLOCK"


def test_unknown_module_blocks(policy):
    state = {
        "owners": ["a", "b", "c"], "threshold": 2,
        "signers": [signer() for _ in range(3)],
        "modules": [{"allowlisted": False, "audited": False}], "guards": [],
        "fallback_handler": {}, "recovery_score": 95,
    }
    result = evaluate_custody(state, policy)
    assert "unknown_module" in result["hard_blocks"]
    assert result["decision"] == "BLOCK"


def test_simulation_mismatch_is_hard_block(policy):
    state = {
        "owners": ["a", "b", "c"], "threshold": 2,
        "signers": [signer() for _ in range(3)], "modules": [], "guards": [],
        "fallback_handler": {}, "recovery_score": 95,
        "transaction": {"simulation_mismatch": True, "calldata_decoded": True},
    }
    result = evaluate_custody(state, policy)
    assert "simulation_mismatch" in result["hard_blocks"]
    assert result["decision"] == "BLOCK"
