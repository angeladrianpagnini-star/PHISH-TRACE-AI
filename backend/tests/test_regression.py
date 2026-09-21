from main import (
    build_risk,
    build_social_engineering_findings,
    normalize_text,
)


def finding_ids(findings):
    return {finding["id"] for finding in findings}


def test_normalize_text_handles_spanish_accents():
    text = normalize_text("Verificá tu contraseña inmediatamente")

    assert "verifica" in text
    assert "contrasena" in text
    assert "inmediatamente" in text


def test_benign_text_has_no_social_engineering_findings():
    text = normalize_text(
        "Reunión de equipo confirmada para mañana a las 10."
    )

    findings = build_social_engineering_findings(text)

    assert findings == []


def test_credential_request_is_detected():
    text = normalize_text(
        "Para continuar ingrese su usuario y contraseña."
    )

    findings = build_social_engineering_findings(text)

    assert "SOCIAL_CREDENTIAL_REQUEST" in finding_ids(findings)


def test_verification_and_urgency_are_detected():
    text = normalize_text(
        "Verificá tu cuenta inmediatamente."
    )

    findings = build_social_engineering_findings(text)
    ids = finding_ids(findings)

    assert "SOCIAL_ACCOUNT_VERIFICATION" in ids
    assert "SOCIAL_URGENCY" in ids


def test_restriction_threat_is_detected():
    text = normalize_text(
        "Su cuenta será restringida."
    )

    findings = build_social_engineering_findings(text)

    assert "SOCIAL_RESTRICTION_THREAT" in finding_ids(findings)


def test_context_only_findings_do_not_inflate_score():
    findings = [
        {
            "id": "URL_SHORTENER_PRESENT",
            "title": "URL shortener detected",
        },
        {
            "id": "SOCIAL_LEGAL_PRETEXT",
            "title": "Legal or judicial pretext detected",
        },
    ]

    risk = build_risk(findings)

    assert risk["score"] == 0
    assert risk["classification"] == "LOW"
    assert risk["confidence"] == "LOW"
    assert risk["reasons"] == []


def test_contextual_combination_has_expected_weight():
    findings = [
        {
            "id": "URL_SHORTENER_WITH_LEGAL_PRETEXT",
            "title": "URL shortener used inside a legal or judicial pretext",
        }
    ]

    risk = build_risk(findings)

    assert risk["score"] == 12
    assert risk["classification"] == "LOW"
    assert risk["confidence"] == "MEDIUM"


def test_institutional_claim_free_webmail_has_expected_weight():
    findings = [
        {
            "id": "INSTITUTIONAL_CLAIM_FREE_WEBMAIL",
            "title": "Institutional claim sent from a public webmail domain",
        }
    ]

    risk = build_risk(findings)

    assert risk["score"] == 25
    assert risk["classification"] == "SUSPICIOUS"
    assert risk["confidence"] == "MEDIUM"


def test_unverified_authentication_result_does_not_raise_risk():
    findings = [
        {
            "id": "AUTH_DMARC_FAIL",
            "title": "Reported DMARC result: fail",
            "evidence": {
                "verified": False,
            },
        }
    ]

    risk = build_risk(findings)

    assert risk["score"] == 0
    assert risk["classification"] == "LOW"
    assert risk["reasons"] == []


def test_risk_score_is_capped_at_100():
    findings = [
        {
            "id": "IDENTITY_REPLY_TO_MISMATCH",
            "title": "Reply-To mismatch",
        },
        {
            "id": "INSTITUTIONAL_CLAIM_FREE_WEBMAIL",
            "title": "Institutional claim from public webmail",
        },
        {
            "id": "SOCIAL_CREDENTIAL_REQUEST",
            "title": "Credential request",
        },
        {
            "id": "ATTACHMENT_DANGEROUS_EXTENSION",
            "title": "Dangerous attachment",
        },
        {
            "id": "URL_DOMAIN_DIFFERS_FROM_SENDER",
            "title": "URL domain mismatch",
        },
    ]

    risk = build_risk(findings)

    assert risk["score"] == 100
    assert risk["classification"] == "CRITICAL"
    assert risk["confidence"] == "HIGH"

def test_case_001_judicial_impersonation_end_to_end():
    import asyncio
    from io import BytesIO

    from fastapi import UploadFile
    from main import analyze_email

    eml_path = "../dataset/CASE-001-JUDICIAL.eml"
    raw = open(eml_path, "rb").read()

    upload = UploadFile(
        filename="CASE-001-JUDICIAL.eml",
        file=BytesIO(raw),
    )

    result = asyncio.run(analyze_email(upload))

    ids = finding_ids(result["findings"])

    # Contextual / institutional evidence
    assert "SOCIAL_LEGAL_PRETEXT" in ids
    assert "URL_SHORTENER_PRESENT" in ids
    assert "URL_SHORTENER_WITH_LEGAL_PRETEXT" in ids
    assert "INSTITUTIONAL_CLAIM_FREE_WEBMAIL" in ids

    # Social-engineering evidence
    assert "SOCIAL_ACCOUNT_VERIFICATION" in ids
    assert "SOCIAL_URGENCY" in ids

    # URL/domain evidence is extracted, never visited
    assert "tinyurl.com" in result["indicators"]["url_domains"]
    assert result["security"]["urls_visited"] is False

    # Safety invariants
    assert result["security"]["active_html_executed"] is False
    assert result["security"]["attachments_executed"] is False
    assert result["security"]["remote_content_loaded"] is False

    # Original evidence integrity
    assert len(result["sha256"]) == 64
    assert result["filename"] == "CASE-001-JUDICIAL.eml"

    # The combined evidence must elevate the message,
    # without coupling the test to one exact future score.
    assert result["risk"]["score"] > 0
    assert result["risk"]["classification"] in {
        "SUSPICIOUS",
        "HIGH",
        "CRITICAL",
    }

def test_formal_spanish_account_verification_is_detected():
    text = normalize_text(
        "Debe verificar su cuenta inmediatamente."
    )

    findings = build_social_engineering_findings(text)

    assert "SOCIAL_ACCOUNT_VERIFICATION" in finding_ids(findings)

def test_empty_eml_is_rejected():
    import asyncio
    from io import BytesIO

    import pytest
    from fastapi import HTTPException, UploadFile
    from main import analyze_email

    raw = open("../dataset/EMPTY.eml", "rb").read()

    upload = UploadFile(
        filename="EMPTY.eml",
        file=BytesIO(raw),
    )

    with pytest.raises(HTTPException) as exc:
        asyncio.run(analyze_email(upload))

    assert exc.value.status_code == 400
    assert exc.value.detail == "The uploaded file is empty."


def test_non_eml_extension_is_rejected():
    import asyncio
    from io import BytesIO

    import pytest
    from fastapi import HTTPException, UploadFile
    from main import analyze_email

    raw = open("../dataset/INVALID.txt", "rb").read()

    upload = UploadFile(
        filename="INVALID.txt",
        file=BytesIO(raw),
    )

    with pytest.raises(HTTPException) as exc:
        asyncio.run(analyze_email(upload))

    assert exc.value.status_code == 400
    assert exc.value.detail == "Only .eml files are accepted."


def test_html_content_remains_inert():
    import asyncio
    from io import BytesIO

    from fastapi import UploadFile
    from main import analyze_email

    raw = open("../dataset/HTML-INERT.eml", "rb").read()

    upload = UploadFile(
        filename="HTML-INERT.eml",
        file=BytesIO(raw),
    )

    result = asyncio.run(analyze_email(upload))

    assert result["security"]["active_html_executed"] is False
    assert result["security"]["remote_content_loaded"] is False
    assert result["security"]["urls_visited"] is False

    assert "https://remote.example/image.png" in result["urls"]
    assert "https://example.example/login" in result["urls"]


def test_attachment_is_extracted_but_never_executed():
    import asyncio
    from io import BytesIO

    from fastapi import UploadFile
    from main import analyze_email

    raw = open("../dataset/ATTACHMENT-TEST.eml", "rb").read()

    upload = UploadFile(
        filename="ATTACHMENT-TEST.eml",
        file=BytesIO(raw),
    )

    result = asyncio.run(analyze_email(upload))

    assert result["security"]["attachments_executed"] is False
    assert len(result["attachments"]) >= 1

    filenames = {
        attachment.get("filename")
        for attachment in result["attachments"]
    }

    assert "note.txt" in filenames


def test_reported_authentication_remains_unverified():
    import asyncio
    from io import BytesIO

    from fastapi import UploadFile
    from main import analyze_email

    raw = open("../dataset/DS-AUTH-UNTRUSTED.eml", "rb").read()

    upload = UploadFile(
        filename="DS-AUTH-UNTRUSTED.eml",
        file=BytesIO(raw),
    )

    result = asyncio.run(analyze_email(upload))

    auth = result["authentication_results"]

    assert auth["verified"] is False
    assert auth["trust"] == "unknown"

    assert auth["parsed"]["spf"] == "fail"
    assert auth["parsed"]["dkim"] == "fail"
    assert auth["parsed"]["dmarc"] == "fail"

    ids = finding_ids(result["findings"])

    assert "AUTH_SPF_FAIL" in ids
    assert "AUTH_DKIM_FAIL" in ids
    assert "AUTH_DMARC_FAIL" in ids

    # Reported authentication is evidence, but because it has not
    # been independently verified it must not increase the risk score.
    assert result["risk"]["score"] == 0

def test_eml_over_10mb_is_rejected():
    import asyncio
    from io import BytesIO

    import pytest
    from fastapi import HTTPException, UploadFile
    from main import MAX_EML_SIZE, analyze_email

    raw = b"A" * (MAX_EML_SIZE + 1)

    upload = UploadFile(
        filename="OVERSIZED.eml",
        file=BytesIO(raw),
    )

    with pytest.raises(HTTPException) as exc:
        asyncio.run(analyze_email(upload))

    assert exc.value.status_code == 413
    assert exc.value.detail == "The .eml file exceeds the 10 MB limit."


def test_ds07_high_signal_phishing_case():
    import asyncio
    from io import BytesIO

    from fastapi import UploadFile
    from main import analyze_email

    raw = open("../dataset/DS-07.eml", "rb").read()

    upload = UploadFile(
        filename="DS-07.eml",
        file=BytesIO(raw),
    )

    result = asyncio.run(analyze_email(upload))
    ids = finding_ids(result["findings"])

    # Identity / infrastructure inconsistencies
    assert "IDENTITY_REPLY_TO_MISMATCH" in ids
    assert "IDENTITY_RETURN_PATH_MISMATCH" in ids
    assert "URL_DOMAIN_DIFFERS_FROM_SENDER" in ids

    # Social-engineering indicators
    assert "SOCIAL_CREDENTIAL_REQUEST" in ids
    assert "SOCIAL_URGENCY" in ids
    assert "SOCIAL_RESTRICTION_THREAT" in ids

    # Dangerous attachment metadata is detected
    assert "ATTACHMENT_DANGEROUS_EXTENSION" in ids

    filenames = {
        attachment.get("filename")
        for attachment in result["attachments"]
    }

    assert "security_update.exe" in filenames

    # Safety invariants remain enforced even for a high-signal sample
    assert result["security"]["attachments_executed"] is False
    assert result["security"]["urls_visited"] is False
    assert result["security"]["active_html_executed"] is False
    assert result["security"]["remote_content_loaded"] is False

    # Multiple independent signals should produce a high-risk result.
    assert result["risk"]["score"] >= 50
    assert result["risk"]["classification"] in {
        "HIGH",
        "CRITICAL",
    }

def test_ds10_ds11_shared_infrastructure_correlation():
    import asyncio
    from io import BytesIO

    from fastapi import UploadFile
    from main import analyze_email, correlate_analyses

    async def analyze(path, filename):
        raw = open(path, "rb").read()

        upload = UploadFile(
            filename=filename,
            file=BytesIO(raw),
        )

        return await analyze_email(upload)

    analysis_a = asyncio.run(
        analyze("../dataset/DS-10.eml", "DS-10.eml")
    )

    analysis_b = asyncio.run(
        analyze("../dataset/DS-11.eml", "DS-11.eml")
    )

    correlation = correlate_analyses(
        analysis_a,
        analysis_b,
    )

    shared = {
        (item["type"], item["value"])
        for item in correlation["shared_indicators"]
    }

    assert (
        "reply_to_domain",
        "secure-access.example",
    ) in shared

    assert (
        "return_path_domain",
        "secure-access.example",
    ) in shared

    assert (
        "url_domain",
        "login.secure-access.example",
    ) in shared

    assert correlation["shared_indicator_count"] == 3
    assert correlation["relationship"] == "RELATED_CAMPAIGN"
    assert correlation["confidence"] == "HIGH"
    assert correlation["attribution"] == "NOT_DETERMINED"

    assert correlation["correlated_risk"]["score"] == 75
    assert correlation["correlated_risk"]["classification"] == "CRITICAL"
    assert (
        correlation["correlated_risk"]["correlation_floor_applied"]
        is True
    )


def test_correlation_does_not_claim_attribution():
    from main import correlate_analyses

    analysis_a = {
        "indicators": {
            "email_domains": {
                "reply_to": "shared.example",
                "return_path": "shared.example",
            },
            "url_domains": [
                "login.shared.example",
            ],
        },
        "risk": {
            "score": 60,
        },
    }

    analysis_b = {
        "indicators": {
            "email_domains": {
                "reply_to": "shared.example",
                "return_path": "shared.example",
            },
            "url_domains": [
                "login.shared.example",
            ],
        },
        "risk": {
            "score": 60,
        },
    }

    correlation = correlate_analyses(
        analysis_a,
        analysis_b,
    )

    assert correlation["relationship"] == "RELATED_CAMPAIGN"
    assert correlation["attribution"] == "NOT_DETERMINED"


def test_no_shared_infrastructure_returns_no_relationship():
    from main import correlate_analyses

    analysis_a = {
        "indicators": {
            "email_domains": {
                "reply_to": "alpha.example",
                "return_path": "alpha.example",
            },
            "url_domains": [
                "login.alpha.example",
            ],
        },
        "risk": {
            "score": 10,
        },
    }

    analysis_b = {
        "indicators": {
            "email_domains": {
                "reply_to": "beta.example",
                "return_path": "beta.example",
            },
            "url_domains": [
                "login.beta.example",
            ],
        },
        "risk": {
            "score": 10,
        },
    }

    correlation = correlate_analyses(
        analysis_a,
        analysis_b,
    )

    assert correlation["shared_indicator_count"] == 0
    assert (
        correlation["relationship"]
        == "NO_TECHNICAL_RELATIONSHIP"
    )
    assert correlation["confidence"] == "LOW"
    assert correlation["attribution"] == "NOT_DETERMINED"
    assert correlation["correlated_risk"]["score"] == 10
    assert (
        correlation["correlated_risk"]["correlation_floor_applied"]
        is False
    )

def test_build_campaign_requires_at_least_two_analyses():
    import pytest
    from main import build_campaign

    with pytest.raises(ValueError):
        build_campaign([])

    with pytest.raises(ValueError):
        build_campaign(
            [
                {
                    "filename": "only-one.eml",
                    "sha256": "a" * 64,
                    "indicators": {
                        "email_domains": {},
                        "url_domains": [],
                    },
                    "risk": {
                        "score": 10,
                    },
                }
            ]
        )


def test_build_campaign_groups_related_messages():
    from main import build_campaign

    analyses = [
        {
            "filename": "CORP-A.eml",
            "sha256": "a" * 64,
            "indicators": {
                "email_domains": {
                    "from": "company-a.example",
                    "reply_to": "shared.example",
                    "return_path": "shared.example",
                },
                "url_domains": [
                    "login.shared.example",
                ],
            },
            "risk": {
                "score": 60,
            },
        },
        {
            "filename": "CORP-B.eml",
            "sha256": "b" * 64,
            "indicators": {
                "email_domains": {
                    "from": "company-b.example",
                    "reply_to": "shared.example",
                    "return_path": "shared.example",
                },
                "url_domains": [
                    "login.shared.example",
                ],
            },
            "risk": {
                "score": 55,
            },
        },
        {
            "filename": "UNRELATED.eml",
            "sha256": "c" * 64,
            "indicators": {
                "email_domains": {
                    "from": "unrelated.example",
                    "reply_to": "other.example",
                    "return_path": "other.example",
                },
                "url_domains": [
                    "login.other.example",
                ],
            },
            "risk": {
                "score": 20,
            },
        },
    ]

    campaign = build_campaign(analyses)

    assert campaign["analysis_count"] == 3
    assert campaign["related_message_count"] == 2
    assert campaign["relationship"] == "RELATED_CAMPAIGN"
    assert campaign["confidence"] == "HIGH"
    assert campaign["attribution"] == "NOT_DETERMINED"

    assert set(campaign["related_filenames"]) == {
        "CORP-A.eml",
        "CORP-B.eml",
    }

    shared = {
        (item["type"], item["value"])
        for item in campaign["shared_indicators"]
    }

    assert (
        "reply_to_domain",
        "shared.example",
    ) in shared

    assert (
        "return_path_domain",
        "shared.example",
    ) in shared

    assert (
        "url_domain",
        "login.shared.example",
    ) in shared

    assert campaign["aggregate_risk"]["score"] == 75
    assert campaign["aggregate_risk"]["classification"] == "CRITICAL"


def test_build_campaign_does_not_create_false_campaign():
    from main import build_campaign

    analyses = [
        {
            "filename": "A.eml",
            "sha256": "a" * 64,
            "indicators": {
                "email_domains": {
                    "reply_to": "alpha.example",
                    "return_path": "alpha.example",
                },
                "url_domains": [
                    "login.alpha.example",
                ],
            },
            "risk": {
                "score": 10,
            },
        },
        {
            "filename": "B.eml",
            "sha256": "b" * 64,
            "indicators": {
                "email_domains": {
                    "reply_to": "beta.example",
                    "return_path": "beta.example",
                },
                "url_domains": [
                    "login.beta.example",
                ],
            },
            "risk": {
                "score": 15,
            },
        },
    ]

    campaign = build_campaign(analyses)

    assert campaign["analysis_count"] == 2
    assert campaign["related_message_count"] == 0
    assert campaign["relationship"] == "NO_TECHNICAL_RELATIONSHIP"
    assert campaign["confidence"] == "LOW"
    assert campaign["shared_indicators"] == []
    assert campaign["related_filenames"] == []
    assert campaign["attribution"] == "NOT_DETERMINED"
    assert campaign["aggregate_risk"]["score"] == 15
    assert campaign["aggregate_risk"]["classification"] == "LOW"
