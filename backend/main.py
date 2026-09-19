import hashlib
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

MAX_EML_SIZE = 10 * 1024 * 1024
URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)

app = FastAPI(
    title="PHISH-TRACE AI API",
    version="0.3.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
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
        "security": {
            "active_html_executed": False,
            "attachments_executed": False,
            "urls_visited": False,
            "remote_content_loaded": False,
        },
    }

    return result
