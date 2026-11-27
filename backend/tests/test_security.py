import secrets

import pytest
from fastapi.testclient import TestClient

import main


SOC_ROUTES = [
    ("POST", "/incidents"),
    ("GET", "/incidents"),
    ("GET", "/incidents/RC-TEST"),
    ("GET", "/incidents/RC-TEST/events"),
    ("PATCH", "/incidents/RC-TEST/assignment"),
    ("PATCH", "/incidents/RC-TEST/state"),
]


@pytest.fixture
def security_client(monkeypatch, tmp_path):
    repository = main.IncidentRepository(
        tmp_path / "security_test.db"
    )

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    with TestClient(main.app) as client:
        yield client


def send_request(client, method, path, headers=None):
    kwargs = {"headers": headers or {}}

    if method in ("POST", "PATCH"):
        kwargs["json"] = {}

    return client.request(method, path, **kwargs)


@pytest.mark.parametrize("method,path", SOC_ROUTES)
def test_soc_disabled(
    security_client, monkeypatch, method, path
):
    monkeypatch.delenv("SOC_API_KEY", raising=False)

    response = send_request(
        security_client, method, path
    )

    assert response.status_code == 503


@pytest.mark.parametrize("method,path", SOC_ROUTES)
def test_soc_missing_key(
    security_client, monkeypatch, method, path
):
    monkeypatch.setenv(
        "SOC_API_KEY", secrets.token_hex(32)
    )

    response = send_request(
        security_client, method, path
    )

    assert response.status_code == 401


@pytest.mark.parametrize("method,path", SOC_ROUTES)
def test_soc_invalid_key(
    security_client, monkeypatch, method, path
):
    monkeypatch.setenv(
        "SOC_API_KEY", secrets.token_hex(32)
    )

    response = send_request(
        security_client,
        method,
        path,
        {"X-SOC-API-Key": "invalid-test-key"},
    )

    assert response.status_code == 401


def test_soc_valid_key(
    security_client, monkeypatch
):
    key = secrets.token_hex(32)
    monkeypatch.setenv("SOC_API_KEY", key)

    response = security_client.get(
        "/incidents",
        headers={"X-SOC-API-Key": key},
    )

    assert response.status_code == 200
    assert response.json() == []


def test_public_health_without_soc_key(
    security_client, monkeypatch
):
    monkeypatch.delenv("SOC_API_KEY", raising=False)

    response = security_client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.parametrize("method,path", SOC_ROUTES)
def test_soc_weak_server_key(
    security_client, monkeypatch, method, path
):
    monkeypatch.setenv("SOC_API_KEY", "weak-key")

    response = send_request(
        security_client,
        method,
        path,
        {"X-SOC-API-Key": "weak-key"},
    )

    assert response.status_code == 503
