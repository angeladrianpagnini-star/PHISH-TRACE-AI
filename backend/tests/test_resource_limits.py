import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import main


@pytest.fixture
def guarded_client(monkeypatch):
    monkeypatch.setattr(
        main, "PUBLIC_REQUESTS_PER_MINUTE", 3
    )

    app = FastAPI()

    @app.post("/analyze")
    @app.post("/correlate")
    async def public_endpoint():
        return {"status": "ok"}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    app.add_middleware(main.PublicResourceGuard)

    with TestClient(app) as client:
        yield client


def test_json_request_size_limit(guarded_client):
    response = guarded_client.post(
        "/correlate",
        content=b"x" * (main.MAX_JSON_REQUEST + 1),
    )

    assert response.status_code == 413


def test_upload_request_size_limit(guarded_client):
    response = guarded_client.post(
        "/analyze",
        content=b"x" * (main.MAX_UPLOAD_REQUEST + 1),
    )

    assert response.status_code == 413


def test_streamed_request_size_limit(guarded_client):
    def chunks():
        yield b"x" * main.MAX_JSON_REQUEST
        yield b"x"

    response = guarded_client.post(
        "/correlate",
        content=chunks(),
    )

    assert response.status_code == 413


def test_public_rate_limit(guarded_client):
    for _ in range(3):
        response = guarded_client.post(
            "/correlate", json={}
        )
        assert response.status_code == 200

    response = guarded_client.post(
        "/correlate", json={}
    )

    assert response.status_code == 429
    assert "Retry-After" in response.headers


def test_health_remains_available(guarded_client):
    for _ in range(4):
        guarded_client.post("/correlate", json={})

    assert guarded_client.get("/health").status_code == 200


def test_campaign_maximum():
    with TestClient(main.app) as client:
        response = client.post(
            "/correlate/campaign",
            json={
                "analyses": [
                    {} for _ in range(
                        main.MAX_CAMPAIGN_ANALYSES + 1
                    )
                ]
            },
        )

    assert response.status_code == 413
