from fastapi.testclient import TestClient

from services.api.app.main import app


client = TestClient(app)


def test_high_confidence_malicious_destination_blocks() -> None:
    response = client.post(
        "/v1/check-tx",
        json={
            "destination": "0xdead",
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
            "destination": "0xunknown",
            "destination_reputation": {
                "status": "unknown",
                "confidence": "low",
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "warn"


def test_extra_request_fields_are_rejected() -> None:
    response = client.post(
        "/v1/check-tx",
        json={
            "destination": "0xdead",
            "unexpected": True,
            "destination_reputation": {
                "status": "trusted",
                "confidence": "high",
            },
        },
    )

    assert response.status_code == 422
