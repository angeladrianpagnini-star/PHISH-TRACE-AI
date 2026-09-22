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

def test_correlate_campaign_endpoint_returns_campaign():
    import asyncio

    from main import correlate_campaign

    analyses = [
        {
            "filename": "CORP-A.eml",
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
        },
        {
            "filename": "CORP-B.eml",
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
                "score": 55,
            },
        },
        {
            "filename": "UNRELATED.eml",
            "indicators": {
                "email_domains": {
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

    result = asyncio.run(
        correlate_campaign(
            {
                "analyses": analyses,
            }
        )
    )

    assert result["analysis_count"] == 3
    assert result["related_message_count"] == 2
    assert result["relationship"] == "RELATED_CAMPAIGN"
    assert result["confidence"] == "HIGH"
    assert result["attribution"] == "NOT_DETERMINED"

    assert set(result["related_filenames"]) == {
        "CORP-A.eml",
        "CORP-B.eml",
    }

    assert result["aggregate_risk"]["score"] == 75
    assert result["aggregate_risk"]["classification"] == "CRITICAL"


def test_correlate_campaign_endpoint_rejects_less_than_two():
    import asyncio

    import pytest
    from fastapi import HTTPException

    from main import correlate_campaign

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            correlate_campaign(
                {
                    "analyses": [
                        {
                            "filename": "ONLY.eml",
                            "indicators": {
                                "email_domains": {},
                                "url_domains": [],
                            },
                            "risk": {
                                "score": 10,
                            },
                        }
                    ],
                }
            )
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == (
        "At least two analyses are required."
    )


def test_correlate_campaign_endpoint_rejects_invalid_payload():
    import asyncio

    import pytest
    from fastapi import HTTPException

    from main import correlate_campaign

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            correlate_campaign(
                {
                    "analyses": "not-a-list",
                }
            )
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == (
        "analyses must be a list."
    )

def test_campaign_id_is_deterministic():
    from main import build_campaign

    analysis_a = {
        "filename": "CORP-A.eml",
        "sha256": "a" * 64,
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
        "filename": "CORP-B.eml",
        "sha256": "b" * 64,
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
            "score": 55,
        },
    }

    campaign_first = build_campaign(
        [
            analysis_a,
            analysis_b,
        ]
    )

    campaign_second = build_campaign(
        [
            analysis_b,
            analysis_a,
        ]
    )

    assert campaign_first["relationship"] == "RELATED_CAMPAIGN"
    assert campaign_second["relationship"] == "RELATED_CAMPAIGN"

    assert campaign_first["campaign_id"] == campaign_second["campaign_id"]

    assert campaign_first["campaign_id"].startswith(
        "CAMPAIGN-"
    )

    assert len(campaign_first["campaign_id"]) == 21


def test_campaign_id_changes_when_shared_evidence_changes():
    from main import build_campaign

    campaign_alpha = build_campaign(
        [
            {
                "filename": "ALPHA-A.eml",
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
                    "score": 60,
                },
            },
            {
                "filename": "ALPHA-B.eml",
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
                    "score": 55,
                },
            },
        ]
    )

    campaign_beta = build_campaign(
        [
            {
                "filename": "BETA-A.eml",
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
                    "score": 60,
                },
            },
            {
                "filename": "BETA-B.eml",
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
                    "score": 55,
                },
            },
        ]
    )

    assert campaign_alpha["relationship"] == "RELATED_CAMPAIGN"
    assert campaign_beta["relationship"] == "RELATED_CAMPAIGN"

    assert campaign_alpha["campaign_id"] != campaign_beta["campaign_id"]


def test_no_relationship_has_no_campaign_id():
    from main import build_campaign

    result = build_campaign(
        [
            {
                "filename": "A.eml",
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
    )

    assert result["relationship"] == "NO_TECHNICAL_RELATIONSHIP"
    assert result["campaign_id"] is None


def test_incident_data_model_preserves_legacy_contract():
    from main import build_incident

    analysis = {
        "filename": "INCIDENT-TEST.eml",
        "sha256": "a" * 64,
        "message_id": "<incident-test@example.com>",
        "risk": {
            "score": 82,
            "classification": "CRITICAL",
            "confidence": "HIGH",
            "scoring_version": "1.2",
        },
    }

    result = build_incident(analysis)

    assert result["incident_id"].startswith("INC-")
    assert result["created_at"]
    assert result["status"] == "OPEN"
    assert result["retention"] == {
        "mode": "explicit",
        "persisted": False,
    }
    assert result["evidence"] == analysis


def test_incident_data_model_adds_soc_fields():
    from main import build_incident

    analysis = {
        "filename": "SOC-TEST.eml",
        "sha256": "b" * 64,
        "message_id": "<soc-test@example.com>",
        "risk": {
            "score": 82,
            "classification": "CRITICAL",
            "confidence": "HIGH",
            "scoring_version": "1.2",
        },
    }

    result = build_incident(analysis)

    assert result["schema_version"] == "1.0"
    assert result["updated_at"] == result["created_at"]
    assert result["incident_type"] == "PHISHING_EMAIL"

    assert result["severity"] == "CRITICAL"
    assert result["priority"] == "P1"

    assert result["lifecycle"] == {
        "state": "NEW",
        "closed_at": None,
    }

    assert result["ownership"] == {
        "queue": "SOC",
        "assigned_to": None,
    }

    assert result["risk"] == {
        "score": 82,
        "classification": "CRITICAL",
        "confidence": "HIGH",
        "scoring_version": "1.2",
    }

    assert result["evidence_metadata"] == {
        "filename": "SOC-TEST.eml",
        "sha256": "b" * 64,
        "message_id": "<soc-test@example.com>",
    }


def test_incident_priority_mapping():
    from main import build_incident

    expected = {
        "CRITICAL": "P1",
        "HIGH": "P2",
        "SUSPICIOUS": "P3",
        "LOW": "P4",
    }

    for severity, priority in expected.items():
        result = build_incident(
            {
                "risk": {
                    "score": 50,
                    "classification": severity,
                    "confidence": "MEDIUM",
                    "scoring_version": "1.2",
                }
            }
        )

        assert result["severity"] == severity
        assert result["priority"] == priority


def test_incident_unknown_severity_falls_back_to_low():
    from main import build_incident

    result = build_incident(
        {
            "risk": {
                "score": 0,
                "classification": "UNKNOWN_VALUE",
                "confidence": "LOW",
                "scoring_version": "1.2",
            }
        }
    )

    assert result["severity"] == "LOW"
    assert result["priority"] == "P4"


def test_incident_without_risk_uses_safe_defaults():
    from main import build_incident

    analysis = {
        "filename": "NO-RISK.eml",
        "sha256": "c" * 64,
        "message_id": "<no-risk@example.com>",
    }

    result = build_incident(analysis)

    assert result["severity"] == "LOW"
    assert result["priority"] == "P4"
    assert result["risk"]["score"] == 0
    assert result["risk"]["classification"] == "LOW"
    assert result["risk"]["confidence"] == "LOW"
    assert result["risk"]["scoring_version"] is None


def test_incident_lifecycle_full_transition_path():
    from main import build_incident, transition_incident

    incident = build_incident(
        {
            "filename": "LIFECYCLE.eml",
            "sha256": "d" * 64,
            "message_id": "<lifecycle@example.com>",
            "risk": {
                "score": 75,
                "classification": "CRITICAL",
                "confidence": "HIGH",
                "scoring_version": "1.2",
            },
        }
    )

    triaged = transition_incident(incident, "TRIAGED")
    in_progress = transition_incident(triaged, "IN_PROGRESS")
    resolved = transition_incident(in_progress, "RESOLVED")
    closed = transition_incident(resolved, "CLOSED")

    assert triaged["lifecycle"]["state"] == "TRIAGED"
    assert in_progress["lifecycle"]["state"] == "IN_PROGRESS"
    assert resolved["lifecycle"]["state"] == "RESOLVED"
    assert closed["lifecycle"]["state"] == "CLOSED"

    assert triaged["status"] == "OPEN"
    assert in_progress["status"] == "OPEN"
    assert resolved["status"] == "OPEN"
    assert closed["status"] == "CLOSED"

    assert closed["lifecycle"]["closed_at"] is not None
    assert closed["lifecycle"]["closed_at"] == closed["updated_at"]


def test_incident_lifecycle_allows_triaged_to_resolved():
    from main import build_incident, transition_incident

    incident = build_incident({"risk": {"classification": "HIGH"}})
    triaged = transition_incident(incident, "TRIAGED")
    resolved = transition_incident(triaged, "RESOLVED")

    assert resolved["lifecycle"]["state"] == "RESOLVED"
    assert resolved["status"] == "OPEN"
    assert resolved["lifecycle"]["closed_at"] is None


def test_incident_lifecycle_rejects_invalid_transition():
    import pytest

    from main import build_incident, transition_incident

    incident = build_incident({"risk": {"classification": "LOW"}})

    with pytest.raises(
        ValueError,
        match="Invalid incident transition: NEW -> RESOLVED",
    ):
        transition_incident(incident, "RESOLVED")


def test_incident_lifecycle_closed_is_terminal():
    import pytest

    from main import build_incident, transition_incident

    incident = build_incident({})
    triaged = transition_incident(incident, "TRIAGED")
    resolved = transition_incident(triaged, "RESOLVED")
    closed = transition_incident(resolved, "CLOSED")

    with pytest.raises(
        ValueError,
        match="Invalid incident transition: CLOSED -> TRIAGED",
    ):
        transition_incident(closed, "TRIAGED")


def test_incident_lifecycle_rejects_unknown_current_state():
    import pytest

    from main import transition_incident

    incident = {
        "status": "OPEN",
        "lifecycle": {
            "state": "UNKNOWN_STATE",
            "closed_at": None,
        },
    }

    with pytest.raises(
        ValueError,
        match="Unknown incident lifecycle state: UNKNOWN_STATE",
    ):
        transition_incident(incident, "TRIAGED")


def test_incident_lifecycle_normalizes_target_state():
    from main import build_incident, transition_incident

    incident = build_incident({})
    updated = transition_incident(incident, "triaged")

    assert updated["lifecycle"]["state"] == "TRIAGED"


def test_incident_transition_preserves_original_record():
    from main import build_incident, transition_incident

    incident = build_incident(
        {
            "filename": "IMMUTABLE.eml",
            "sha256": "e" * 64,
            "message_id": "<immutable@example.com>",
        }
    )

    original_evidence = incident["evidence"]
    updated = transition_incident(incident, "TRIAGED")

    assert incident["lifecycle"]["state"] == "NEW"
    assert incident["status"] == "OPEN"
    assert incident["lifecycle"]["closed_at"] is None

    assert updated["incident_id"] == incident["incident_id"]
    assert updated["created_at"] == incident["created_at"]
    assert updated["evidence"] == original_evidence
    assert updated["evidence"] is incident["evidence"]


def test_incident_repository_persists_and_retrieves(tmp_path):
    from main import IncidentRepository, build_incident

    db_path = tmp_path / "incidents.db"
    repository = IncidentRepository(db_path)

    incident = build_incident(
        {
            "filename": "PERSIST.eml",
            "sha256": "f" * 64,
            "message_id": "<persist@example.com>",
            "risk": {
                "score": 75,
                "classification": "CRITICAL",
                "confidence": "HIGH",
                "scoring_version": "1.2",
            },
        }
    )

    repository.save(incident)
    stored = repository.get(incident["incident_id"])

    assert db_path.exists()
    assert stored == incident
    assert stored["incident_id"] == incident["incident_id"]
    assert stored["evidence"]["filename"] == "PERSIST.eml"


def test_incident_repository_returns_none_for_unknown_id(tmp_path):
    from main import IncidentRepository

    repository = IncidentRepository(tmp_path / "incidents.db")

    assert repository.get("INC-UNKNOWN") is None


def test_incident_repository_lists_saved_incidents(tmp_path):
    from main import IncidentRepository, build_incident

    repository = IncidentRepository(tmp_path / "incidents.db")

    first = build_incident(
        {
            "filename": "FIRST.eml",
            "risk": {"classification": "LOW"},
        }
    )
    second = build_incident(
        {
            "filename": "SECOND.eml",
            "risk": {"classification": "HIGH"},
        }
    )

    repository.save(first)
    repository.save(second)

    incidents = repository.list()
    ids = {item["incident_id"] for item in incidents}

    assert len(incidents) == 2
    assert ids == {
        first["incident_id"],
        second["incident_id"],
    }


def test_incident_repository_updates_existing_incident(tmp_path):
    from main import (
        IncidentRepository,
        build_incident,
        transition_incident,
    )

    repository = IncidentRepository(tmp_path / "incidents.db")

    incident = build_incident(
        {
            "filename": "UPDATE.eml",
            "risk": {"classification": "HIGH"},
        }
    )

    repository.save(incident)

    updated = transition_incident(incident, "TRIAGED")
    repository.save(updated)

    stored = repository.get(incident["incident_id"])
    incidents = repository.list()

    assert len(incidents) == 1
    assert stored["incident_id"] == incident["incident_id"]
    assert stored["lifecycle"]["state"] == "TRIAGED"
    assert stored["status"] == "OPEN"


def test_incident_repository_survives_reinstantiation(tmp_path):
    from main import IncidentRepository, build_incident

    db_path = tmp_path / "incidents.db"

    first_repository = IncidentRepository(db_path)

    incident = build_incident(
        {
            "filename": "RESTART.eml",
            "risk": {"classification": "SUSPICIOUS"},
        }
    )

    first_repository.save(incident)

    second_repository = IncidentRepository(db_path)
    stored = second_repository.get(incident["incident_id"])

    assert stored == incident
    assert stored["evidence"]["filename"] == "RESTART.eml"


def test_incident_api_persists_created_incident(
    tmp_path,
    monkeypatch,
):
    import asyncio
    import main

    db_path = tmp_path / "api-incidents.db"
    repository = main.IncidentRepository(db_path)

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    analysis = {
        "filename": "API-PERSIST.eml",
        "sha256": "b" * 64,
        "message_id": "<api-persist@example.com>",
        "risk": {
            "score": 75,
            "classification": "CRITICAL",
            "confidence": "HIGH",
            "scoring_version": "1.2",
        },
    }

    incident = asyncio.run(
        main.create_incident(analysis)
    )

    assert incident["status"] == "OPEN"
    assert incident["severity"] == "CRITICAL"
    assert incident["priority"] == "P1"
    assert incident["lifecycle"]["state"] == "NEW"
    assert incident["retention"]["mode"] == "explicit"
    assert incident["retention"]["persisted"] is True
    assert incident["evidence"] == analysis

    stored = repository.get(incident["incident_id"])

    assert stored is not None
    assert stored == incident
    assert stored["retention"]["persisted"] is True

    connection = repository._connect()

    try:
        row = connection.execute(
            """
            SELECT
                incident_id,
                status,
                severity,
                priority,
                lifecycle_state,
                incident_json
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident["incident_id"],),
        ).fetchone()
    finally:
        connection.close()

    assert row is not None
    assert row["incident_id"] == incident["incident_id"]
    assert row["status"] == "OPEN"
    assert row["severity"] == "CRITICAL"
    assert row["priority"] == "P1"
    assert row["lifecycle_state"] == "NEW"
    assert '"persisted": true' in row["incident_json"]


def test_incident_api_returns_500_when_persistence_fails(
    monkeypatch,
):
    import asyncio
    import main
    from fastapi import HTTPException

    class FailingIncidentRepository:
        def save(self, incident):
            raise RuntimeError(
                "simulated database failure"
            )

    monkeypatch.setattr(
        main,
        "incident_repository",
        FailingIncidentRepository(),
    )

    try:
        asyncio.run(
            main.create_incident(
                {
                    "filename": "FAIL.eml",
                    "risk": {
                        "classification": "HIGH",
                    },
                }
            )
        )
    except HTTPException as exc:
        assert exc.status_code == 500
        assert exc.detail == "Incident persistence failed."
    else:
        raise AssertionError(
            "Expected HTTPException was not raised."
        )


def test_incident_retrieval_api_lists_incidents(
    tmp_path,
    monkeypatch,
):
    import asyncio
    import main

    repository = main.IncidentRepository(
        tmp_path / "retrieval-list.db"
    )

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    first = main.build_incident(
        {
            "filename": "FIRST.eml",
            "risk": {
                "score": 50,
                "classification": "HIGH",
                "confidence": "MEDIUM",
                "scoring_version": "1.2",
            },
        }
    )
    first["retention"]["persisted"] = True
    repository.save(first)

    second = main.build_incident(
        {
            "filename": "SECOND.eml",
            "risk": {
                "score": 75,
                "classification": "CRITICAL",
                "confidence": "HIGH",
                "scoring_version": "1.2",
            },
        }
    )
    second["retention"]["persisted"] = True
    repository.save(second)

    incidents = asyncio.run(
        main.list_incidents()
    )

    assert len(incidents) == 2

    incident_ids = {
        incident["incident_id"]
        for incident in incidents
    }

    assert incident_ids == {
        first["incident_id"],
        second["incident_id"],
    }


def test_incident_retrieval_api_gets_incident_by_id(
    tmp_path,
    monkeypatch,
):
    import asyncio
    import main

    repository = main.IncidentRepository(
        tmp_path / "retrieval-get.db"
    )

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    incident = main.build_incident(
        {
            "filename": "GET-BY-ID.eml",
            "sha256": "c" * 64,
            "message_id": "<get-by-id@example.com>",
            "risk": {
                "score": 75,
                "classification": "CRITICAL",
                "confidence": "HIGH",
                "scoring_version": "1.2",
            },
        }
    )
    incident["retention"]["persisted"] = True

    repository.save(incident)

    result = asyncio.run(
        main.get_incident(
            incident["incident_id"]
        )
    )

    assert result == incident
    assert result["incident_id"] == incident["incident_id"]
    assert result["evidence"]["filename"] == "GET-BY-ID.eml"
    assert result["retention"]["persisted"] is True


def test_incident_retrieval_api_returns_404_for_unknown_id(
    tmp_path,
    monkeypatch,
):
    import asyncio
    import main
    from fastapi import HTTPException

    repository = main.IncidentRepository(
        tmp_path / "retrieval-404.db"
    )

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    try:
        asyncio.run(
            main.get_incident(
                "INC-UNKNOWN"
            )
        )
    except HTTPException as exc:
        assert exc.status_code == 404
        assert exc.detail == "Incident not found."
    else:
        raise AssertionError(
            "Expected HTTPException was not raised."
        )


def test_incident_retrieval_api_returns_500_on_repository_failure(
    monkeypatch,
):
    import asyncio
    import main
    from fastapi import HTTPException

    class FailingIncidentRepository:
        def list(self):
            raise RuntimeError(
                "simulated database failure"
            )

        def get(self, incident_id):
            raise RuntimeError(
                "simulated database failure"
            )

    monkeypatch.setattr(
        main,
        "incident_repository",
        FailingIncidentRepository(),
    )

    for operation in (
        lambda: main.list_incidents(),
        lambda: main.get_incident("INC-FAIL"),
    ):
        try:
            asyncio.run(operation())
        except HTTPException as exc:
            assert exc.status_code == 500
            assert exc.detail == "Incident retrieval failed."
        else:
            raise AssertionError(
                "Expected HTTPException was not raised."
            )


def test_incident_state_api_persists_valid_transition(
    tmp_path,
    monkeypatch,
):
    import asyncio
    import main

    repository = main.IncidentRepository(
        tmp_path / "state-valid.db"
    )

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    incident = main.build_incident(
        {
            "filename": "STATE.eml",
            "risk": {
                "score": 75,
                "classification": "CRITICAL",
                "confidence": "HIGH",
                "scoring_version": "1.2",
            },
        }
    )
    incident["retention"]["persisted"] = True
    repository.save(incident)

    original_updated_at = incident["updated_at"]

    updated = asyncio.run(
        main.update_incident_state(
            incident["incident_id"],
            {"state": "TRIAGED"},
        )
    )

    assert updated["lifecycle"]["state"] == "TRIAGED"
    assert updated["status"] == "OPEN"
    assert updated["updated_at"] >= original_updated_at

    stored = repository.get(
        incident["incident_id"]
    )

    assert stored == updated
    assert stored["lifecycle"]["state"] == "TRIAGED"


def test_incident_state_api_persists_full_lifecycle(
    tmp_path,
    monkeypatch,
):
    import asyncio
    import main

    repository = main.IncidentRepository(
        tmp_path / "state-full.db"
    )

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    incident = main.build_incident(
        {
            "filename": "FULL-LIFECYCLE.eml",
            "risk": {
                "classification": "HIGH",
            },
        }
    )
    incident["retention"]["persisted"] = True
    repository.save(incident)

    incident_id = incident["incident_id"]

    for state in (
        "TRIAGED",
        "IN_PROGRESS",
        "RESOLVED",
        "CLOSED",
    ):
        updated = asyncio.run(
            main.update_incident_state(
                incident_id,
                {"state": state},
            )
        )

        assert updated["lifecycle"]["state"] == state

    stored = repository.get(incident_id)

    assert stored is not None
    assert stored["status"] == "CLOSED"
    assert stored["lifecycle"]["state"] == "CLOSED"
    assert stored["lifecycle"]["closed_at"] is not None


def test_incident_state_api_requires_state(
    tmp_path,
    monkeypatch,
):
    import asyncio
    import main
    from fastapi import HTTPException

    repository = main.IncidentRepository(
        tmp_path / "state-required.db"
    )

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    for payload in ({}, {"state": ""}, {"state": "   "}):
        try:
            asyncio.run(
                main.update_incident_state(
                    "INC-ANY",
                    payload,
                )
            )
        except HTTPException as exc:
            assert exc.status_code == 400
            assert exc.detail == "Incident state is required."
        else:
            raise AssertionError(
                "Expected HTTPException was not raised."
            )


def test_incident_state_api_returns_404_for_unknown_incident(
    tmp_path,
    monkeypatch,
):
    import asyncio
    import main
    from fastapi import HTTPException

    repository = main.IncidentRepository(
        tmp_path / "state-404.db"
    )

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    try:
        asyncio.run(
            main.update_incident_state(
                "INC-UNKNOWN",
                {"state": "TRIAGED"},
            )
        )
    except HTTPException as exc:
        assert exc.status_code == 404
        assert exc.detail == "Incident not found."
    else:
        raise AssertionError(
            "Expected HTTPException was not raised."
        )


def test_incident_state_api_rejects_invalid_transition(
    tmp_path,
    monkeypatch,
):
    import asyncio
    import main
    from fastapi import HTTPException

    repository = main.IncidentRepository(
        tmp_path / "state-invalid.db"
    )

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    incident = main.build_incident(
        {
            "filename": "INVALID-STATE.eml",
            "risk": {
                "classification": "HIGH",
            },
        }
    )
    incident["retention"]["persisted"] = True
    repository.save(incident)

    try:
        asyncio.run(
            main.update_incident_state(
                incident["incident_id"],
                {"state": "CLOSED"},
            )
        )
    except HTTPException as exc:
        assert exc.status_code == 409
        assert (
            exc.detail
            == "Invalid incident transition: NEW -> CLOSED"
        )
    else:
        raise AssertionError(
            "Expected HTTPException was not raised."
        )

    stored = repository.get(
        incident["incident_id"]
    )

    assert stored is not None
    assert stored["lifecycle"]["state"] == "NEW"


def test_incident_state_api_returns_500_on_retrieval_failure(
    monkeypatch,
):
    import asyncio
    import main
    from fastapi import HTTPException

    class FailingGetRepository:
        def get(self, incident_id):
            raise RuntimeError(
                "simulated retrieval failure"
            )

    monkeypatch.setattr(
        main,
        "incident_repository",
        FailingGetRepository(),
    )

    try:
        asyncio.run(
            main.update_incident_state(
                "INC-FAIL",
                {"state": "TRIAGED"},
            )
        )
    except HTTPException as exc:
        assert exc.status_code == 500
        assert exc.detail == "Incident retrieval failed."
    else:
        raise AssertionError(
            "Expected HTTPException was not raised."
        )


def test_incident_state_api_returns_500_on_persistence_failure(
    monkeypatch,
):
    import asyncio
    import main
    from fastapi import HTTPException

    incident = main.build_incident(
        {
            "filename": "SAVE-FAIL.eml",
            "risk": {
                "classification": "HIGH",
            },
        }
    )
    incident["retention"]["persisted"] = True

    class FailingSaveRepository:
        def get(self, incident_id):
            return incident

        def save(self, updated_incident):
            raise RuntimeError(
                "simulated persistence failure"
            )

    monkeypatch.setattr(
        main,
        "incident_repository",
        FailingSaveRepository(),
    )

    try:
        asyncio.run(
            main.update_incident_state(
                incident["incident_id"],
                {"state": "TRIAGED"},
            )
        )
    except HTTPException as exc:
        assert exc.status_code == 500
        assert exc.detail == "Incident persistence failed."
    else:
        raise AssertionError(
            "Expected HTTPException was not raised."
        )


def test_incident_assignment_api_assigns_and_persists(
    tmp_path,
    monkeypatch,
):
    import asyncio
    import main

    repository = main.IncidentRepository(
        tmp_path / "assignment.db"
    )

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    incident = main.build_incident(
        {
            "filename": "ASSIGN.eml",
            "risk": {
                "classification": "HIGH",
            },
        }
    )
    incident["retention"]["persisted"] = True
    repository.save(incident)

    original_updated_at = incident["updated_at"]

    updated = asyncio.run(
        main.update_incident_assignment(
            incident["incident_id"],
            {"assigned_to": "analyst-01"},
        )
    )

    assert updated["ownership"] == {
        "queue": "SOC",
        "assigned_to": "analyst-01",
    }
    assert updated["updated_at"] >= original_updated_at

    stored = repository.get(
        incident["incident_id"]
    )

    assert stored == updated


def test_incident_assignment_api_trims_assignee(
    tmp_path,
    monkeypatch,
):
    import asyncio
    import main

    repository = main.IncidentRepository(
        tmp_path / "assignment-trim.db"
    )

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    incident = main.build_incident(
        {
            "filename": "TRIM.eml",
            "risk": {
                "classification": "HIGH",
            },
        }
    )
    incident["retention"]["persisted"] = True
    repository.save(incident)

    updated = asyncio.run(
        main.update_incident_assignment(
            incident["incident_id"],
            {"assigned_to": "  analyst-02  "},
        )
    )

    assert updated["ownership"]["assigned_to"] == "analyst-02"


def test_incident_assignment_api_allows_unassignment(
    tmp_path,
    monkeypatch,
):
    import asyncio
    import main

    repository = main.IncidentRepository(
        tmp_path / "unassignment.db"
    )

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    incident = main.build_incident(
        {
            "filename": "UNASSIGN.eml",
            "risk": {
                "classification": "HIGH",
            },
        }
    )
    incident["retention"]["persisted"] = True
    incident["ownership"]["assigned_to"] = "analyst-01"
    repository.save(incident)

    updated = asyncio.run(
        main.update_incident_assignment(
            incident["incident_id"],
            {"assigned_to": None},
        )
    )

    assert updated["ownership"] == {
        "queue": "SOC",
        "assigned_to": None,
    }

    stored = repository.get(
        incident["incident_id"]
    )

    assert stored["ownership"]["assigned_to"] is None


def test_incident_assignment_api_requires_assigned_to(
    tmp_path,
    monkeypatch,
):
    import asyncio
    import main
    from fastapi import HTTPException

    repository = main.IncidentRepository(
        tmp_path / "assignment-required.db"
    )

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    try:
        asyncio.run(
            main.update_incident_assignment(
                "INC-ANY",
                {},
            )
        )
    except HTTPException as exc:
        assert exc.status_code == 400
        assert exc.detail == "assigned_to is required."
    else:
        raise AssertionError(
            "Expected HTTPException was not raised."
        )


def test_incident_assignment_api_rejects_invalid_assignee(
    tmp_path,
    monkeypatch,
):
    import asyncio
    import main
    from fastapi import HTTPException

    repository = main.IncidentRepository(
        tmp_path / "assignment-invalid.db"
    )

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    for assigned_to in ("", "   ", 123, True, []):
        try:
            asyncio.run(
                main.update_incident_assignment(
                    "INC-ANY",
                    {"assigned_to": assigned_to},
                )
            )
        except HTTPException as exc:
            assert exc.status_code == 400
            assert (
                exc.detail
                == "assigned_to must be a non-empty string or null."
            )
        else:
            raise AssertionError(
                "Expected HTTPException was not raised."
            )


def test_incident_assignment_api_returns_404_for_unknown_incident(
    tmp_path,
    monkeypatch,
):
    import asyncio
    import main
    from fastapi import HTTPException

    repository = main.IncidentRepository(
        tmp_path / "assignment-404.db"
    )

    monkeypatch.setattr(
        main,
        "incident_repository",
        repository,
    )

    try:
        asyncio.run(
            main.update_incident_assignment(
                "INC-UNKNOWN",
                {"assigned_to": "analyst-01"},
            )
        )
    except HTTPException as exc:
        assert exc.status_code == 404
        assert exc.detail == "Incident not found."
    else:
        raise AssertionError(
            "Expected HTTPException was not raised."
        )


def test_incident_assignment_api_returns_500_on_retrieval_failure(
    monkeypatch,
):
    import asyncio
    import main
    from fastapi import HTTPException

    class FailingGetRepository:
        def get(self, incident_id):
            raise RuntimeError(
                "simulated retrieval failure"
            )

    monkeypatch.setattr(
        main,
        "incident_repository",
        FailingGetRepository(),
    )

    try:
        asyncio.run(
            main.update_incident_assignment(
                "INC-FAIL",
                {"assigned_to": "analyst-01"},
            )
        )
    except HTTPException as exc:
        assert exc.status_code == 500
        assert exc.detail == "Incident retrieval failed."
    else:
        raise AssertionError(
            "Expected HTTPException was not raised."
        )


def test_incident_assignment_api_returns_500_on_persistence_failure(
    monkeypatch,
):
    import asyncio
    import main
    from fastapi import HTTPException

    incident = main.build_incident(
        {
            "filename": "ASSIGN-SAVE-FAIL.eml",
            "risk": {
                "classification": "HIGH",
            },
        }
    )
    incident["retention"]["persisted"] = True

    class FailingSaveRepository:
        def get(self, incident_id):
            return incident

        def save(self, updated_incident):
            raise RuntimeError(
                "simulated persistence failure"
            )

    monkeypatch.setattr(
        main,
        "incident_repository",
        FailingSaveRepository(),
    )

    try:
        asyncio.run(
            main.update_incident_assignment(
                incident["incident_id"],
                {"assigned_to": "analyst-01"},
            )
        )
    except HTTPException as exc:
        assert exc.status_code == 500
        assert exc.detail == "Incident persistence failed."
    else:
        raise AssertionError(
            "Expected HTTPException was not raised."
        )


def test_incident_audit_event_builder():
    import main

    event = main.build_incident_audit_event(
        "INC-TEST-001",
        "state_changed",
        {
            "from": "NEW",
            "to": "TRIAGED",
        },
        actor="analyst-01",
    )

    assert event["schema_version"] == "1.0"
    assert event["event_id"].startswith("EVT-")
    assert event["incident_id"] == "INC-TEST-001"
    assert event["event_type"] == "STATE_CHANGED"
    assert event["actor"] == "analyst-01"
    assert event["details"] == {
        "from": "NEW",
        "to": "TRIAGED",
    }
    assert event["created_at"]


def test_incident_audit_event_builder_normalizes_actor():
    import main

    event = main.build_incident_audit_event(
        "INC-TEST-002",
        "assignment_changed",
        {},
        actor="  analyst-02  ",
    )

    assert event["actor"] == "analyst-02"


def test_incident_audit_event_builder_allows_system_actor():
    import main

    event = main.build_incident_audit_event(
        "INC-TEST-003",
        "created",
        {},
    )

    assert event["actor"] is None


def test_incident_audit_repository_appends_and_lists(
    tmp_path,
):
    import main

    repository = main.IncidentRepository(
        tmp_path / "audit.db"
    )

    first = main.build_incident_audit_event(
        "INC-AUDIT-001",
        "created",
        {"status": "OPEN"},
    )

    second = main.build_incident_audit_event(
        "INC-AUDIT-001",
        "state_changed",
        {
            "from": "NEW",
            "to": "TRIAGED",
        },
        actor="analyst-01",
    )

    repository.append_audit_event(first)
    repository.append_audit_event(second)

    events = repository.list_audit_events(
        "INC-AUDIT-001"
    )

    assert len(events) == 2
    assert events[0] == first
    assert events[1] == second


def test_incident_audit_repository_filters_by_incident(
    tmp_path,
):
    import main

    repository = main.IncidentRepository(
        tmp_path / "audit-filter.db"
    )

    first = main.build_incident_audit_event(
        "INC-A",
        "created",
        {},
    )

    second = main.build_incident_audit_event(
        "INC-B",
        "created",
        {},
    )

    repository.append_audit_event(first)
    repository.append_audit_event(second)

    events_a = repository.list_audit_events("INC-A")
    events_b = repository.list_audit_events("INC-B")

    assert events_a == [first]
    assert events_b == [second]


def test_incident_audit_repository_empty_history(
    tmp_path,
):
    import main

    repository = main.IncidentRepository(
        tmp_path / "audit-empty.db"
    )

    assert repository.list_audit_events(
        "INC-UNKNOWN"
    ) == []


def test_incident_audit_repository_is_append_only(
    tmp_path,
):
    import sqlite3
    import main

    repository = main.IncidentRepository(
        tmp_path / "audit-append-only.db"
    )

    event = main.build_incident_audit_event(
        "INC-AUDIT-002",
        "created",
        {},
    )

    repository.append_audit_event(event)

    try:
        repository.append_audit_event(event)
    except sqlite3.IntegrityError:
        pass
    else:
        raise AssertionError(
            "Duplicate audit event must not overwrite existing history."
        )

    events = repository.list_audit_events(
        "INC-AUDIT-002"
    )

    assert events == [event]


def test_incident_audit_repository_survives_reinstantiation(
    tmp_path,
):
    import main

    db_path = tmp_path / "audit-reopen.db"

    first_repository = main.IncidentRepository(
        db_path
    )

    event = main.build_incident_audit_event(
        "INC-AUDIT-003",
        "created",
        {},
    )

    first_repository.append_audit_event(event)

    second_repository = main.IncidentRepository(
        db_path
    )

    events = second_repository.list_audit_events(
        "INC-AUDIT-003"
    )

    assert events == [event]
