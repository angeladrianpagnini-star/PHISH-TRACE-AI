# Development Log

## 2026-09-19 - H0

- Official TLN Cybersecurity Challenge 2026 rules reviewed.
- AI use explicitly permitted subject to disclosure.
- Development environment verified.
- Git repository initialized after official hackathon opening.
- PHISH-TRACE AI implementation begins from an empty repository.

### Verified environment

- Git 2.54.0
- Node.js 22.20.0
- npm 10.9.3
- Python 3.13.15

### Initial scope

Upload -> Analyze -> Explain -> Incident -> Evidence

### Status

H0 baseline.

## 2026-09-19 - P0 implementation

### Secure intake
- Next.js frontend and FastAPI backend established.
- Unknown .eml files accepted as untrusted input.
- Maximum input size enforced.
- Original message SHA-256 generated.
- MIME content parsed without executing active content.
- Attachments extracted as metadata and hashes only.
- URLs extracted without automatic visits.
- Remote content is not loaded.

### Deterministic analysis
- Sender, Reply-To and Return-Path domains extracted.
- URL domains extracted.
- Identity and infrastructure mismatches detected.
- Dangerous attachment extensions detected.
- Social-engineering indicators detected.
- Authentication-Results preserved as reported evidence.
- Unverified authentication headers do not affect risk scoring.

### Explainable risk
- Risk scoring model v1.1 implemented.
- LOW, SUSPICIOUS, HIGH and CRITICAL classifications implemented.
- Confidence level exposed.
- Every weighted signal is exposed through human-readable reasons.
- Authentication PASS does not reduce risk.

### Incident and evidence workflow
- Explicit incident creation implemented.
- Unique incident IDs generated.
- Incident timestamp and OPEN status exposed.
- Analyze-by-default / retain-by-choice behavior maintained.
- Server persistence explicitly reported as false in current implementation.
- Analysis evidence preserved inside the incident object.
- JSON evidence export implemented in the frontend.

### Validation
- DS-AUTH-UNTRUSTED: 0 / LOW / LOW.
- DS-06: 67 / HIGH / HIGH.
- DS-07: 100 / CRITICAL / HIGH.
- DS-07 SHA-256 preserved through incident creation.
- Consecutive incident creation generates distinct incident IDs.
- Selecting a new .eml clears the previous analysis and incident from the UI.
- Production frontend build completed successfully.

### Current status
P0 implementation complete pending final regression and MVP checkpoint.
