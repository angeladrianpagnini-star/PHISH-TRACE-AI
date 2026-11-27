import pytest

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from main import app, get_cors_allowed_origins


OFFICIAL = "https://phish-trace-ai-psi.vercel.app"

CANDIDATE = (
    "https://phish-trace-arf07dcd5-phish-trace-lab.vercel.app"
)

BRANCH = (
    "https://phish-trace-ai-git-release-public-demo"
    "-phish-trace-lab.vercel.app"
)

UNTRUSTED = "https://phish-trace-ai-untrusted.vercel.app"


@pytest.fixture
def cors_client():
    test_app = FastAPI()

    test_app.add_middleware(
        CORSMiddleware,
        allow_origins=get_cors_allowed_origins(
            f"{CANDIDATE},{BRANCH}"
        ),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @test_app.get("/health")
    def health():
        return {"status": "ok"}

    return TestClient(test_app)


def test_default_origins():
    assert get_cors_allowed_origins("") == [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        OFFICIAL,
    ]


def test_candidate_requires_configuration():
    assert CANDIDATE not in get_cors_allowed_origins("")


def test_environment_configuration(monkeypatch):
    monkeypatch.setenv(
        "CORS_ALLOWED_ORIGINS",
        f"{CANDIDATE},{BRANCH}",
    )

    origins = get_cors_allowed_origins()

    assert CANDIDATE in origins
    assert BRANCH in origins
    assert OFFICIAL in origins


def test_duplicate_origins_are_removed():
    origins = get_cors_allowed_origins(
        f" {OFFICIAL}, {CANDIDATE}, {CANDIDATE}, "
    )

    assert origins.count(OFFICIAL) == 1
    assert origins.count(CANDIDATE) == 1


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "https://*.vercel.app",
        "http://untrusted.example",
        "https://user:password@example.com",
        "https://example.com/path",
        "https://example.com?query=1",
        "https://example.com#fragment",
        "https://example.com:0",
        "https://example.com:65536",
        "null",
        "javascript:alert(1)",
        "https://",
    ],
)
def test_invalid_configured_origins(origin):
    with pytest.raises(ValueError):
        get_cors_allowed_origins(origin)


@pytest.mark.parametrize(
    "origin",
    [
        OFFICIAL,
        CANDIDATE,
        BRANCH,
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
)
def test_allowed_health_origins(cors_client, origin):
    response = cors_client.get(
        "/health",
        headers={"Origin": origin},
    )

    assert response.status_code == 200
    assert (
        response.headers["access-control-allow-origin"]
        == origin
    )


@pytest.mark.parametrize(
    "origin",
    [
        UNTRUSTED,
        "https://untrusted.example",
        OFFICIAL + ".untrusted.example",
        "null",
    ],
)
def test_rejected_health_origins(cors_client, origin):
    response = cors_client.get(
        "/health",
        headers={"Origin": origin},
    )

    assert response.status_code == 200
    assert (
        "access-control-allow-origin"
        not in response.headers
    )


@pytest.mark.parametrize(
    "origin",
    [OFFICIAL, CANDIDATE, BRANCH],
)
def test_allowed_preflight(cors_client, origin):
    response = cors_client.options(
        "/analyze",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert (
        response.headers["access-control-allow-origin"]
        == origin
    )


@pytest.mark.parametrize(
    "origin",
    [UNTRUSTED, "https://untrusted.example", "null"],
)
def test_rejected_preflight(cors_client, origin):
    response = cors_client.options(
        "/analyze",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 400
    assert (
        "access-control-allow-origin"
        not in response.headers
    )


def test_real_application_official_origin():
    client = TestClient(app)

    response = client.get(
        "/health",
        headers={"Origin": OFFICIAL},
    )

    assert response.status_code == 200
    assert (
        response.headers["access-control-allow-origin"]
        == OFFICIAL
    )


def test_real_application_rejects_untrusted_origin():
    client = TestClient(app)

    response = client.options(
        "/analyze",
        headers={
            "Origin": UNTRUSTED,
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 400
    assert (
        "access-control-allow-origin"
        not in response.headers
    )


def test_cors_does_not_enable_soc(monkeypatch):
    monkeypatch.delenv("SOC_API_KEY", raising=False)

    client = TestClient(app)

    response = client.get(
        "/incidents",
        headers={"Origin": OFFICIAL},
    )

    assert response.status_code == 503
