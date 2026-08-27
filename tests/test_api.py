from fastapi.testclient import TestClient

from services.api.app.main import app


client = TestClient(app)
VALID_DESTINATION = "0x000000000000000000000000000000000000dEaD"
VALID_UNKNOWN = "0x0000000000000000000000000000000000000001"


def test_high_confidence_malicious_destination_blocks() -> None:
    response = client.post(
        "/v1/check-tx",
        json={
            "chain_id": 1,
            "destination": VALID_DESTINATION,
            "destination_reputation": {
                "status": "malicious",
                "confidence": "high",
            },
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "decision": "block",
        "policy_version": "day13-v3",
    }


def test_unknown_destination_never_becomes_allow() -> None:
    response = client.post(
        "/v1/check-tx",
        json={
            "chain_id": 1,
            "destination": VALID_UNKNOWN,
            "destination_reputation": {
                "status": "unknown",
                "confidence": "low",
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "warn"


def test_invalid_ethereum_address_is_rejected() -> None:
    response = client.post(
        "/v1/check-tx",
        json={
            "chain_id": 1,
            "destination": "0xdead",
            "destination_reputation": {
                "status": "trusted",
                "confidence": "high",
            },
        },
    )

    assert response.status_code == 422


def test_extra_request_fields_are_rejected() -> None:
    response = client.post(
        "/v1/check-tx",
        json={
            "chain_id": 1,
            "destination": VALID_DESTINATION,
            "unexpected": True,
            "destination_reputation": {
                "status": "trusted",
                "confidence": "high",
            },
        },
    )

    assert response.status_code == 422
