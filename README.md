# PHISH-TRACE AI

**From Suspicious Email to Actionable Evidence**

Public release: **0.4.0-rc.1**
Risk scoring model: **v1.2**
Release date: **2026-11-27**

PHISH-TRACE AI is a cybersecurity platform for passive
email analysis, explainable risk assessment, technical
campaign correlation and evidence preparation.

## Public demonstration

Frontend:
https://phish-trace-ai-psi.vercel.app/

Backend:
https://phish-trace-ai-v1-2-backend-production.up.railway.app

Health endpoint:
https://phish-trace-ai-v1-2-backend-production.up.railway.app/health

Use synthetic or appropriately anonymized messages only.
Do not upload confidential or personal information.

## Core workflow

Upload -> Analyze -> Explain -> Correlate -> Evidence Preview

## Public capabilities

- Passive .eml analysis, up to 10 MiB per file.
- SHA-256 fingerprinting of original message bytes.
- MIME and attachment metadata extraction.
- Identity and infrastructure mismatch detection.
- Social-engineering indicators.
- Explainable deterministic risk scoring.
- Pairwise technical correlation.
- Multi-email campaign correlation.
- Interactive technical correlation graph.
- Human-controlled response recommendations.
- Non-persistent evidence preview and JSON export.

## Security principles

- Email content is treated as untrusted input.
- Active HTML and JavaScript are not executed.
- Attachments are not executed.
- URLs are not automatically visited.
- Remote email content is not loaded.
- Authentication headers are reported evidence,
  not independently verified authentication results.
- Authentication PASS does not establish message safety.
- Technical correlation does not establish attacker
  identity, causality or legal responsibility.
- Analyze by default. Retain by choice.

## Architecture

- Frontend: Next.js, TypeScript and React Flow.
- Backend: Python 3.13.15 and FastAPI.
- Backend deployment: Railway, Docker.
- Frontend deployment: Vercel.
- Institutional incident storage: SQLite implementation,
  not exposed through the public demonstration.
- Explicit CORS origin configuration.
- Bounded public request sizes and resource controls.

## Public and institutional separation

The public demonstration does not register incidents in
the shared SOC repository.

Evidence previews contain client-supplied analysis.
Their integrity is not independently verified.
JSON exports are not digitally signed forensic certificates.

Institutional SOC capabilities exist in the development
history but require protected access, isolation and
additional validation before institutional deployment.

Public SOC operations remain disabled.

## Reproducible demonstration

Synthetic fixtures are available in:

    dataset/public-demo/

See:

- [Public demo guide](docs/PUBLIC_DEMO_GUIDE.md)
- [Release validation record](docs/PUBLIC_RELEASE_0.4.0-rc.1.md)
- [Institutional SOC roadmap](docs/INSTITUTIONAL_SOC_ROADMAP.md)

## Historical development

PHISH-TRACE AI originated during the TLN Cybersecurity
Challenge 2026.

Implementation began on September 19, 2026, after the
official hackathon opening.

The original TLN submission remains preserved on main:

    2b5f7ec8eee3f8372f788aa397fcadd373afe745

Historical production checkpoint:

    p1-production-green - 9b81644

Post-submission scoring v1.2 was developed separately
following a real-world judicial-phishing validation case.

See the historical record:

[Post-submission judicial validation](docs/POST_SUBMISSION_JUDICIAL_VALIDATION.md)

Historical deployment references in earlier documents
must not be interpreted as current service endpoints.

## Human control

PHISH-TRACE AI supports analyst decision-making.
It does not automatically execute remediation actions
or determine legal attribution.
