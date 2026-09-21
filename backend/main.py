import hashlib
import re
import secrets
import unicodedata
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

MAX_EML_SIZE = 10 * 1024 * 1024
URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)

SHORTENER_DOMAINS = {
    "abre.ai",
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tinyurl.com",
}

FREE_WEBMAIL_DOMAINS = {
    "gmail.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "yahoo.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
}

LEGAL_PRETEXT_TERMS = (
    "juzgado",
    "tribunal",
    "camara de apelaciones",
    "expediente",
    "demanda",
    "proceso judicial",
    "notificacion judicial",
    "notificacion electronica",
    "plazo procesal",
    "proveido",
    "court notice",
    "legal proceeding",
)

INSTITUTIONAL_CLAIM_TERMS = (
    "juzgado",
    "tribunal",
    "camara de apelaciones",
    "poder judicial",
    "sistema de administracion de justicia",
    "jurisdiccion federal",
    "comunicado oficial",
    "official court notice",
)

app = FastAPI(
    title="PHISH-TRACE AI API",
    version="0.3.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://phish-trace-ai-psi.vercel.app",
    ],
    allow_origin_regex=r"^https://phish-trace-ai(?:-[a-z0-9-]+)?\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "PHISH-TRACE AI API"
    }


def extract_urls(message) -> list[str]:
    urls: list[str] = []

    for part in message.walk():
        content_type = part.get_content_type()

        if content_type not in {"text/plain", "text/html"}:
            continue

        try:
            payload = part.get_content()
        except Exception:
            continue

        if not isinstance(payload, str):
            continue

        urls.extend(URL_PATTERN.findall(payload))

    return sorted(set(urls))


def extract_attachments(message) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []

    for part in message.walk():
        filename = part.get_filename()

        if not filename:
            continue

        payload = part.get_payload(decode=True) or b""

        attachments.append(
            {
                "filename": filename,
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "executed": False,
            }
        )

    return attachments


def extract_email_domain(value: str) -> str:
    if not value:
        return ""

    _, address = parseaddr(value)

    if "@" not in address:
        return ""

    return address.rsplit("@", 1)[1].lower().strip()


def extract_url_domain(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def parse_reported_authentication(value: str) -> dict[str, str]:
    text = value.lower()

    results = {
        "spf": "not_available",
        "dkim": "not_available",
        "dmarc": "not_available",
    }

    for mechanism in results:
        match = re.search(
            rf"\b{mechanism}\s*=\s*([a-z0-9_-]+)",
            text
        )
        if match:
            results[mechanism] = match.group(1)

    return results


def normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return "".join(
        char
        for char in normalized
        if not unicodedata.combining(char)
    ).lower()


def extract_text_content(message) -> str:
    chunks: list[str] = []

    for part in message.walk():
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue

        try:
            payload = part.get_content()
        except Exception:
            continue

        if isinstance(payload, str):
            chunks.append(payload)

    return normalize_text("\n".join(chunks))


def build_social_engineering_findings(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    credential_terms = (
        "username and password",
        "password",
        "login credentials",
        "credentials",
        "usuario y contrasena",
        "nombre de usuario y contrasena",
        "contrasena",
        "credenciales",
    )

    verification_terms = (
        "verify your account",
        "account verification",
        "confirm your account",
        "verify it immediately",
        "verifica tu cuenta",
        "verificar tu cuenta",
        "verifique su cuenta",
        "verificar su cuenta",
        "confirma tu cuenta",
        "confirmar tu cuenta",
        "confirme su cuenta",
        "confirmar su cuenta",
        "valida tu cuenta",
        "validar tu cuenta",
        "valide su cuenta",
        "validar su cuenta",
        "validacion de cuenta",
    )

    urgency_terms = (
        "urgent",
        "immediately",
        "today",
        "as soon as possible",
        "urgente",
        "inmediatamente",
        "de inmediato",
    )

    restriction_terms = (
        "account will be restricted",
        "account suspension",
        "access will be suspended",
        "temporary account suspension",
        "cuenta sera restringida",
        "cuenta restringida",
        "cuenta suspendida",
        "suspension de cuenta",
        "acceso sera suspendido",
        "acceso suspendido",
        "acceso bloqueado",
    )

    if any(term in text for term in credential_terms):
        findings.append(
            {
                "id": "SOCIAL_CREDENTIAL_REQUEST",
                "category": "social_engineering",
                "severity": "high",
                "title": "Message requests account credentials",
                "evidence": {
                    "detected": True,
                },
            }
        )

    if any(term in text for term in verification_terms):
        findings.append(
            {
                "id": "SOCIAL_ACCOUNT_VERIFICATION",
                "category": "social_engineering",
                "severity": "medium",
                "title": "Message requests account verification",
                "evidence": {
                    "detected": True,
                },
            }
        )

    if any(term in text for term in urgency_terms):
        findings.append(
            {
                "id": "SOCIAL_URGENCY",
                "category": "social_engineering",
                "severity": "medium",
                "title": "Urgency language detected",
                "evidence": {
                    "detected": True,
                },
            }
        )

    if any(term in text for term in restriction_terms):
        findings.append(
            {
                "id": "SOCIAL_RESTRICTION_THREAT",
                "category": "social_engineering",
                "severity": "medium",
                "title": "Threat of account restriction or suspension detected",
                "evidence": {
                    "detected": True,
                },
            }
        )

    return findings


def build_contextual_findings(
    message,
    from_domain: str,
    url_domains: list[str],
    subject: str,
    text_content: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    combined_text = normalize_text(
        f"{subject}\n{text_content}"
    )

    shortener_domains = sorted(
        domain
        for domain in url_domains
        if domain in SHORTENER_DOMAINS
    )

    if shortener_domains:
        findings.append(
            {
                "id": "URL_SHORTENER_PRESENT",
                "category": "infrastructure",
                "severity": "medium",
                "title": "URL shortener detected",
                "evidence": {
                    "domains": shortener_domains,
                    "urls_visited": False,
                },
            }
        )

    legal_terms_found = sorted(
        {
            term
            for term in LEGAL_PRETEXT_TERMS
            if term in combined_text
        }
    )

    if legal_terms_found:
        findings.append(
            {
                "id": "SOCIAL_LEGAL_PRETEXT",
                "category": "social_engineering",
                "severity": "medium",
                "title": "Legal or judicial pretext detected",
                "evidence": {
                    "matched_terms": legal_terms_found,
                },
            }
        )

    if shortener_domains and legal_terms_found:
        findings.append(
            {
                "id": "URL_SHORTENER_WITH_LEGAL_PRETEXT",
                "category": "social_engineering",
                "severity": "high",
                "title": "URL shortener used inside a legal or judicial pretext",
                "evidence": {
                    "domains": shortener_domains,
                    "matched_terms": legal_terms_found,
                    "urls_visited": False,
                },
            }
        )

    institutional_terms_found = sorted(
        {
            term
            for term in INSTITUTIONAL_CLAIM_TERMS
            if term in combined_text
        }
    )

    if (
        from_domain in FREE_WEBMAIL_DOMAINS
        and institutional_terms_found
    ):
        findings.append(
            {
                "id": "INSTITUTIONAL_CLAIM_FREE_WEBMAIL",
                "category": "identity",
                "severity": "high",
                "title": "Institutional claim sent from a public webmail domain",
                "evidence": {
                    "from_domain": from_domain,
                    "matched_terms": institutional_terms_found,
                },
            }
        )

    scl_raw = str(
        message.get("X-MS-Exchange-Organization-SCL", "")
    ).strip()

    mailbox_delivery = str(
        message.get("X-Microsoft-Antispam-Mailbox-Delivery", "")
    )

    try:
        scl = int(scl_raw)
    except (TypeError, ValueError):
        scl = None

    junk_by_scl = scl is not None and scl >= 5
    junk_by_delivery = "rf:junkemail" in mailbox_delivery.lower()

    if junk_by_scl or junk_by_delivery:
        findings.append(
            {
                "id": "PROVIDER_JUNK_VERDICT",
                "category": "provider_signal",
                "severity": "medium",
                "title": "Mail provider classified the message as junk",
                "evidence": {
                    "scl": scl,
                    "junk_email_flag": junk_by_delivery,
                },
            }
        )

    return findings


def build_findings(
    from_domain: str,
    reply_to_domain: str,
    return_path_domain: str,
    url_domains: list[str],
    reported_auth: dict[str, str],
    attachments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if (
        from_domain
        and reply_to_domain
        and from_domain != reply_to_domain
    ):
        findings.append(
            {
                "id": "IDENTITY_REPLY_TO_MISMATCH",
                "category": "identity",
                "severity": "high",
                "title": "Reply-To domain differs from From domain",
                "evidence": {
                    "from_domain": from_domain,
                    "reply_to_domain": reply_to_domain,
                },
            }
        )

    if (
        from_domain
        and return_path_domain
        and from_domain != return_path_domain
    ):
        findings.append(
            {
                "id": "IDENTITY_RETURN_PATH_MISMATCH",
                "category": "identity",
                "severity": "medium",
                "title": "Return-Path domain differs from From domain",
                "evidence": {
                    "from_domain": from_domain,
                    "return_path_domain": return_path_domain,
                },
            }
        )

    for mechanism in ("spf", "dkim", "dmarc"):
        result = reported_auth.get(mechanism, "not_available")

        if result in {"fail", "softfail", "neutral", "temperror", "permerror"}:
            findings.append(
                {
                    "id": f"AUTH_{mechanism.upper()}_{result.upper()}",
                    "category": "authentication",
                    "severity": "medium",
                    "title": f"Reported {mechanism.upper()} result: {result}",
                    "evidence": {
                        "source": "Authentication-Results header",
                        "trust": "unknown",
                        "verified": False,
                        "reported_result": result,
                    },
                }
            )

    unrelated_url_domains = sorted(
        {
            domain
            for domain in url_domains
            if domain and from_domain and domain != from_domain
        }
    )

    if unrelated_url_domains:
        findings.append(
            {
                "id": "URL_DOMAIN_DIFFERS_FROM_SENDER",
                "category": "infrastructure",
                "severity": "medium",
                "title": "One or more URL domains differ from sender domain",
                "evidence": {
                    "from_domain": from_domain,
                    "url_domains": unrelated_url_domains,
                },
            }
        )

    for attachment in attachments:
        filename = attachment["filename"].lower()

        if filename.endswith(
            (
                ".exe",
                ".scr",
                ".bat",
                ".cmd",
                ".js",
                ".vbs",
                ".ps1",
                ".msi",
            )
        ):
            findings.append(
                {
                    "id": "ATTACHMENT_DANGEROUS_EXTENSION",
                    "category": "attachment",
                    "severity": "high",
                    "title": "Attachment has a potentially dangerous executable extension",
                    "evidence": {
                        "filename": attachment["filename"],
                        "executed": False,
                    },
                }
            )

    return findings



RISK_WEIGHTS = {
    "IDENTITY_REPLY_TO_MISMATCH": 25,
    "IDENTITY_RETURN_PATH_MISMATCH": 5,
    "URL_DOMAIN_DIFFERS_FROM_SENDER": 18,
    "URL_SHORTENER_PRESENT": 0,
    "URL_SHORTENER_WITH_LEGAL_PRETEXT": 12,
    "INSTITUTIONAL_CLAIM_FREE_WEBMAIL": 25,
    "PROVIDER_JUNK_VERDICT": 8,
    "SOCIAL_CREDENTIAL_REQUEST": 25,
    "SOCIAL_ACCOUNT_VERIFICATION": 8,
    "SOCIAL_URGENCY": 8,
    "SOCIAL_RESTRICTION_THREAT": 8,
    "ATTACHMENT_DANGEROUS_EXTENSION": 20,
    "AUTH_SPF_FAIL": 4,
    "AUTH_SPF_SOFTFAIL": 2,
    "AUTH_DKIM_FAIL": 4,
    "AUTH_DMARC_FAIL": 8,
}


def build_risk(findings: list[dict[str, Any]]) -> dict[str, Any]:
    reasons: list[dict[str, Any]] = []
    raw_score = 0

    for finding in findings:
        finding_id = finding.get("id", "")
        weight = RISK_WEIGHTS.get(finding_id, 0)

        if finding_id.startswith("AUTH_"):
            evidence = finding.get("evidence", {})
            if not evidence.get("verified", False):
                continue

        if weight <= 0:
            continue

        raw_score += weight

        reasons.append(
            {
                "finding": finding_id,
                "weight": weight,
                "reason": finding.get("title", finding_id),
            }
        )

    score = min(raw_score, 100)

    if score <= 24:
        classification = "LOW"
    elif score <= 49:
        classification = "SUSPICIOUS"
    elif score <= 74:
        classification = "HIGH"
    else:
        classification = "CRITICAL"

    weighted_findings = len(reasons)

    if weighted_findings >= 3:
        confidence = "HIGH"
    elif weighted_findings >= 1:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return {
        "score": score,
        "classification": classification,
        "confidence": confidence,
        "reasons": reasons,
        "scoring_version": "1.2",
    }


def correlate_analyses(
    analysis_a: dict[str, Any],
    analysis_b: dict[str, Any],
) -> dict[str, Any]:
    shared: list[dict[str, str]] = []

    indicators_a = analysis_a.get("indicators", {})
    indicators_b = analysis_b.get("indicators", {})

    email_a = indicators_a.get("email_domains", {})
    email_b = indicators_b.get("email_domains", {})

    reply_to_a = email_a.get("reply_to", "")
    reply_to_b = email_b.get("reply_to", "")

    if reply_to_a and reply_to_a == reply_to_b:
        shared.append(
            {
                "type": "reply_to_domain",
                "value": reply_to_a,
            }
        )

    return_path_a = email_a.get("return_path", "")
    return_path_b = email_b.get("return_path", "")

    if return_path_a and return_path_a == return_path_b:
        shared.append(
            {
                "type": "return_path_domain",
                "value": return_path_a,
            }
        )

    url_domains_a = set(indicators_a.get("url_domains", []))
    url_domains_b = set(indicators_b.get("url_domains", []))

    for domain in sorted(url_domains_a & url_domains_b):
        shared.append(
            {
                "type": "url_domain",
                "value": domain,
            }
        )

    shared_count = len(shared)

    if shared_count >= 3:
        relationship = "RELATED_CAMPAIGN"
        confidence = "HIGH"
    elif shared_count == 2:
        relationship = "POSSIBLY_RELATED"
        confidence = "MEDIUM"
    elif shared_count == 1:
        relationship = "WEAK_RELATIONSHIP"
        confidence = "LOW"
    else:
        relationship = "NO_TECHNICAL_RELATIONSHIP"
        confidence = "LOW"

    correlated_risk = max(
        analysis_a.get("risk", {}).get("score", 0),
        analysis_b.get("risk", {}).get("score", 0),
    )

    correlation_floor_applied = False

    if relationship == "RELATED_CAMPAIGN" and correlated_risk >= 50:
        correlated_risk = max(correlated_risk, 75)
        correlation_floor_applied = True

    return {
        "relationship": relationship,
        "confidence": confidence,
        "shared_indicators": shared,
        "shared_indicator_count": shared_count,
        "attribution": "NOT_DETERMINED",
        "correlated_risk": {
            "score": correlated_risk,
            "classification": (
                "CRITICAL"
                if correlated_risk >= 75
                else "HIGH"
                if correlated_risk >= 50
                else "SUSPICIOUS"
                if correlated_risk >= 25
                else "LOW"
            ),
            "correlation_floor_applied": correlation_floor_applied,
        },
    }



def build_campaign(
    analyses: list[dict[str, Any]],
) -> dict[str, Any]:
    if len(analyses) < 2:
        raise ValueError(
            "At least two analyses are required to build a campaign."
        )

    related_indexes: set[int] = set()
    related_pairs: list[dict[str, Any]] = []
    shared_map: dict[tuple[str, str], dict[str, str]] = {}

    aggregate_score = max(
        analysis.get("risk", {}).get("score", 0)
        for analysis in analyses
    )

    strongest_relationship = "NO_TECHNICAL_RELATIONSHIP"
    strongest_confidence = "LOW"

    relationship_rank = {
        "NO_TECHNICAL_RELATIONSHIP": 0,
        "WEAK_RELATIONSHIP": 1,
        "POSSIBLY_RELATED": 2,
        "RELATED_CAMPAIGN": 3,
    }

    confidence_rank = {
        "LOW": 0,
        "MEDIUM": 1,
        "HIGH": 2,
    }

    for index_a in range(len(analyses)):
        for index_b in range(index_a + 1, len(analyses)):
            correlation = correlate_analyses(
                analyses[index_a],
                analyses[index_b],
            )

            relationship = correlation["relationship"]
            confidence = correlation["confidence"]

            if (
                relationship_rank.get(relationship, 0)
                > relationship_rank.get(strongest_relationship, 0)
            ):
                strongest_relationship = relationship

            if (
                confidence_rank.get(confidence, 0)
                > confidence_rank.get(strongest_confidence, 0)
            ):
                strongest_confidence = confidence

            if relationship == "RELATED_CAMPAIGN":
                related_indexes.update(
                    {
                        index_a,
                        index_b,
                    }
                )

                related_pairs.append(
                    {
                        "analysis_a": index_a,
                        "analysis_b": index_b,
                        "filename_a": analyses[index_a].get(
                            "filename",
                            f"analysis-{index_a + 1}",
                        ),
                        "filename_b": analyses[index_b].get(
                            "filename",
                            f"analysis-{index_b + 1}",
                        ),
                        "relationship": relationship,
                        "confidence": confidence,
                        "shared_indicators": correlation[
                            "shared_indicators"
                        ],
                    }
                )

                for indicator in correlation["shared_indicators"]:
                    key = (
                        indicator["type"],
                        indicator["value"],
                    )
                    shared_map[key] = indicator

    related_filenames = [
        analyses[index].get(
            "filename",
            f"analysis-{index + 1}",
        )
        for index in sorted(related_indexes)
    ]

    shared_indicators = [
        shared_map[key]
        for key in sorted(shared_map)
    ]

    if related_indexes:
        relationship = "RELATED_CAMPAIGN"
        confidence = strongest_confidence

        if aggregate_score >= 50:
            aggregate_score = max(
                aggregate_score,
                75,
            )
    else:
        relationship = strongest_relationship
        confidence = strongest_confidence

    classification = (
        "CRITICAL"
        if aggregate_score >= 75
        else "HIGH"
        if aggregate_score >= 50
        else "SUSPICIOUS"
        if aggregate_score >= 25
        else "LOW"
    )

    return {
        "analysis_count": len(analyses),
        "related_message_count": len(related_indexes),
        "relationship": relationship,
        "confidence": confidence,
        "related_filenames": related_filenames,
        "shared_indicators": shared_indicators,
        "shared_indicator_count": len(shared_indicators),
        "related_pairs": related_pairs,
        "attribution": "NOT_DETERMINED",
        "aggregate_risk": {
            "score": aggregate_score,
            "classification": classification,
        },
    }

@app.post("/correlate")
async def correlate(payload: dict[str, Any]):
    analysis_a = payload.get("analysis_a")
    analysis_b = payload.get("analysis_b")

    if not isinstance(analysis_a, dict) or not isinstance(analysis_b, dict):
        raise HTTPException(
            status_code=400,
            detail="analysis_a and analysis_b are required.",
        )

    return correlate_analyses(analysis_a, analysis_b)

@app.post("/incidents")
async def create_incident(analysis: dict[str, Any]):
    created_at = datetime.now(timezone.utc)

    incident_id = (
        f"INC-{created_at.strftime('%Y%m%d')}-"
        f"{secrets.token_hex(4).upper()}"
    )

    return {
        "incident_id": incident_id,
        "created_at": created_at.isoformat(),
        "status": "OPEN",
        "retention": {
            "mode": "explicit",
            "persisted": False,
        },
        "evidence": analysis,
    }


@app.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):
    filename = file.filename or "unknown.eml"

    if not filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are accepted."
        )

    raw = await file.read(MAX_EML_SIZE + 1)

    if not raw:
        raise HTTPException(
            status_code=400,
            detail="The uploaded file is empty."
        )

    if len(raw) > MAX_EML_SIZE:
        raise HTTPException(
            status_code=413,
            detail="The .eml file exceeds the 10 MB limit."
        )

    file_sha256 = hashlib.sha256(raw).hexdigest()

    # Preserve the SHA-256 of the exact original evidence.
    # Normalize a possible UTF-8 BOM only for parsing.
    parse_raw = raw
    if parse_raw.startswith(b"\xef\xbb\xbf"):
        parse_raw = parse_raw[3:]

    try:
        message = BytesParser(policy=policy.default).parsebytes(parse_raw)
    except Exception:
        raise HTTPException(
            status_code=422,
            detail="The .eml file could not be parsed safely."
        )

    from_value = str(message.get("from", ""))
    reply_to_value = str(message.get("reply-to", ""))
    return_path_value = str(message.get("return-path", ""))
    authentication_value = str(message.get("authentication-results", ""))

    urls = extract_urls(message)
    attachments = extract_attachments(message)
    text_content = extract_text_content(message)

    from_domain = extract_email_domain(from_value)
    reply_to_domain = extract_email_domain(reply_to_value)
    return_path_domain = extract_email_domain(return_path_value)

    url_domains = sorted(
        {
            domain
            for domain in (extract_url_domain(url) for url in urls)
            if domain
        }
    )

    reported_auth = parse_reported_authentication(authentication_value)

    findings = build_findings(
        from_domain=from_domain,
        reply_to_domain=reply_to_domain,
        return_path_domain=return_path_domain,
        url_domains=url_domains,
        reported_auth=reported_auth,
        attachments=attachments,
    )

    findings.extend(
        build_social_engineering_findings(text_content)
    )

    findings.extend(
        build_contextual_findings(
            message=message,
            from_domain=from_domain,
            url_domains=url_domains,
            subject=str(message.get("subject", "")),
            text_content=text_content,
        )
    )

    risk = build_risk(findings)

    result = {
        "filename": filename,
        "size_bytes": len(raw),
        "sha256": file_sha256,
        "subject": str(message.get("subject", "")),
        "from": from_value,
        "to": str(message.get("to", "")),
        "reply_to": reply_to_value,
        "return_path": return_path_value,
        "message_id": str(message.get("message-id", "")),
        "authentication_results": {
            "reported": authentication_value,
            "trust": "unknown",
            "verified": False,
            "parsed": reported_auth,
        },
        "urls": urls,
        "attachments": attachments,
        "indicators": {
            "email_domains": {
                "from": from_domain,
                "reply_to": reply_to_domain,
                "return_path": return_path_domain,
            },
            "url_domains": url_domains,
        },
        "findings": findings,
        "risk": risk,
        "security": {
            "active_html_executed": False,
            "attachments_executed": False,
            "urls_visited": False,
            "remote_content_loaded": False,
        },
    }

    return result

