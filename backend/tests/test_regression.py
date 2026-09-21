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
