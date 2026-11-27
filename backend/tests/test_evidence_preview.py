import hashlib

import pytest
from fastapi.testclient import TestClient

import main


SYNTHETIC_EMAIL = (
    b"From: sender@example.com\r\n"
    b"To: recipient@example.org\r\n"
    b"Subject: Synthetic release test\r\n"
    b"Message-ID: <release-test@example.com>\r\n"
    b"\r\n"
    b"This is a synthetic test message.\r\n"
)


@pytest.fixture
def evidence_client(monkeypatch, tmp_path):
    repository = main.IncidentRepository(
        tmp_path / "evidence_test.db"
    )

    monkeypatch.setattr(
        main, "incident_repository", repository
    )

    monkeypatch.delenv("SOC_API_KEY", raising=False)

    with TestClient(main.app) as client:
        yield client, repository


def analyze_synthetic_email(client):
    response = client.post(
        "/analyze",
        files={
            "file": (
                "release-test.eml",
                SYNTHETIC_EMAIL,
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 200

    return response.json()


def test_public_analysis_and_evidence_preview(evidence_client):
    client, repository = evidence_client

    analysis = analyze_synthetic_email(client)

    response = client.post(
        "/evidence/preview",
        json=analysis,
    )

    assert response.status_code == 200

    evidence = response.json()

    assert evidence["retention"]["persisted"] is False
    assert evidence["retention"]["mode"] == "preview"
    assert evidence["evidence"] == analysis
    assert evidence["evidence_origin"] == "CLIENT_SUPPLIED_ANALYSIS"
    assert evidence["integrity_verified"] is False

    expected_hash = hashlib.sha256(
        SYNTHETIC_EMAIL
    ).hexdigest()

    assert analysis["sha256"] == expected_hash
    assert evidence["evidence_metadata"]["sha256"] == expected_hash

    assert repository.list() == []
    assert repository.list_audit_events(
        evidence["incident_id"]
    ) == []


def test_preview_does_not_enable_soc_access(evidence_client):
    client, repository = evidence_client

    analysis = analyze_synthetic_email(client)

    preview = client.post(
        "/evidence/preview",
        json=analysis,
    )

    assert preview.status_code == 200

    incident_id = preview.json()["incident_id"]

    assert client.get("/incidents").status_code == 503

    assert client.get(
        f"/incidents/{incident_id}"
    ).status_code == 503

    assert client.post(
        "/incidents",
        json=analysis,
    ).status_code == 503

    assert repository.list() == []


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"risk": None, "sha256": "a" * 64},
        {"risk": {}, "sha256": "invalid"},
        {"risk": {}, "sha256": None},
    ],
)
def test_preview_rejects_invalid_analysis(
    evidence_client, payload
):
    client, repository = evidence_client

    response = client.post(
        "/evidence/preview",
        json=payload,
    )

    assert response.status_code == 400
    assert repository.list() == []


def test_preview_never_persists_repeated_requests(
    evidence_client
):
    client, repository = evidence_client

    analysis = analyze_synthetic_email(client)

    first = client.post(
        "/evidence/preview", json=analysis
    )

    second = client.post(
        "/evidence/preview", json=analysis
    )

    assert first.status_code == 200
    assert second.status_code == 200

    assert (
        first.json()["incident_id"]
        != second.json()["incident_id"]
    )

    assert repository.list() == []
