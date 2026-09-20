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

## 2026-09-19 - P1 production deployment

### Campaign correlation
- Deterministic correlation between analyzed emails implemented.
- Shared Reply-To, Return-Path and URL domains are identified.
- Correlation confidence and relationship classification exposed.
- Correlation does not determine attacker identity or legal attribution.
- Contextual risk escalation implemented for strongly related campaigns.

### Threat visualization
- Interactive threat graph implemented.
- Baseline email, current email and shared technical indicators are visualized.
- Visualization remains evidence-based and does not imply attribution.

### Human-controlled remediation
- Relevant operational actors are presented after analysis.
- SOC / Security Operations: ACKNOWLEDGE.
- Email / Identity Administrator: REMEDIATE.
- Incident Response / Evidence Custodian: PRESERVE.
- Actions are recommendations only and remain human-controlled.

### Production deployment
- Backend deployed to Railway.
- Frontend deployed to Vercel.
- Production CORS restricted to localhost development and the production Vercel origin.
- Public backend health endpoint validated.
- Public frontend-to-backend connectivity validated.

### Production regression
- DS-AUTH-UNTRUSTED: 0 / LOW / LOW.
- DS-06: 67 / HIGH / HIGH.
- DS-07: 100 / CRITICAL / HIGH.
- Incident creation and JSON evidence export validated.
- DS-10 / DS-11 correlation validated:
  - Relationship: RELATED_CAMPAIGN.
  - Confidence: HIGH.
  - Shared technical indicators: 3.
  - Standalone risk: 64 / HIGH.
  - Contextual risk: 75 / CRITICAL.
  - Attribution: NOT_DETERMINED.
- Threat Graph rendered successfully in production.
- Remediation Actors rendered successfully in production.
- Security controls confirmed: no active HTML execution, no attachment execution, no automatic URL visits and no remote-content loading.

### Production checkpoint
- Commit: 9b81644
- Tag: p1-production-green

### Status
P1 production deployment and regression validation complete.


## 2026-09-20 - Post-submission real-world hardening

### Real-world validation trigger
- A real unsolicited message using a judicial/labor-court pretext was analyzed after the TLN submission had closed.
- Submitted scoring v1.1 classified the message as 18 / LOW / MEDIUM.
- The gap was traced to missing contextual signals rather than MIME parsing, hashing or evidence-preservation failures.

### Scoring v1.2
- URL shortener detection added as an informational signal.
- Legal/judicial pretext detection added as an informational signal.
- Composite shortener + legal-pretext rule added.
- Institutional claim from public webmail detection added.
- Provider Junk verdict detection added.
- Generic URL shorteners remain weight 0 in isolation to reduce false positives.

### Validation
- Judicial real-world case: 63 / HIGH / HIGH / v1.2.
- Promotional shortener control: 18 / LOW / MEDIUM / v1.2.
- Full regression preserved all expected dataset results.
- DS-10 / DS-11 correlation remained RELATED_CAMPAIGN / HIGH with 3 shared indicators, contextual risk 75 / CRITICAL and attribution NOT_DETERMINED.

### Isolation
- Submitted TLN version remains on `main` at commit `2b5f7ec`.
- Post-submission work remains on `post-submission-judicial-hardening`.
- Validated hardening checkpoint: `74a2bb5`.
- Tag: `post-submission-judicial-hardening-green`.
- Separate Railway backend and Vercel preview validated end-to-end.

### Documentation
- Detailed case record: `docs/POST_SUBMISSION_JUDICIAL_VALIDATION.md`.

### Status
Post-submission scoring v1.2 validated in an isolated deployment.
