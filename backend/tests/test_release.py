from fastapi.testclient import TestClient
import main


def test_release_health_metadata(monkeypatch):
    monkeypatch.delenv("SOC_API_KEY", raising=False)
    monkeypatch.delenv(
        "RAILWAY_GIT_COMMIT_SHA", raising=False
    )
    monkeypatch.setenv("BUILD_COMMIT", "test-commit")

    with TestClient(main.app) as client:
        response = client.get("/health")

    assert response.status_code == 200

    health = response.json()

    assert health["status"] == "ok"
    assert health["version"] == "0.4.0-rc.1"
    assert health["release_channel"] == "public-demo"
    assert health["build_commit"] == "test-commit"
    assert health["soc_enabled"] is False


def test_health_does_not_expose_soc_secret(monkeypatch):
    key = "test-only-" + "a" * 64

    monkeypatch.setenv("SOC_API_KEY", key)

    with TestClient(main.app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["soc_enabled"] is True
    assert key not in response.text
