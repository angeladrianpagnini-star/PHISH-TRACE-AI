import hashlib
import re
from email import policy
from email.parser import BytesParser
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

MAX_EML_SIZE = 10 * 1024 * 1024
URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)

app = FastAPI(
    title="PHISH-TRACE AI API",
    version="0.2.0"
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

    # Preserve the SHA-256 of the exact original evidence, but normalize
    # a possible UTF-8 BOM only for parsing.
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

    result = {
        "filename": filename,
        "size_bytes": len(raw),
        "sha256": file_sha256,
        "subject": str(message.get("subject", "")),
        "from": str(message.get("from", "")),
        "to": str(message.get("to", "")),
        "reply_to": str(message.get("reply-to", "")),
        "return_path": str(message.get("return-path", "")),
        "message_id": str(message.get("message-id", "")),
        "authentication_results": {
            "reported": str(message.get("authentication-results", "")),
            "trust": "unknown",
            "verified": False,
        },
        "urls": extract_urls(message),
        "attachments": extract_attachments(message),
        "security": {
            "active_html_executed": False,
            "attachments_executed": False,
            "urls_visited": False,
            "remote_content_loaded": False,
        },
    }

    return result

