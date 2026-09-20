# PHISH-TRACE AI

**From Suspicious Email to Actionable Evidence**

Project developed for TLN Cybersecurity Challenge 2026.

## Hackathon Development

Implementation started on September 19, 2026 after the official hackathon opening.

PHISH-TRACE AI safely analyzes suspicious .eml files and transforms technical findings into explainable and actionable evidence.

## Core principle

Upload -> Analyze -> Explain -> Incident -> Evidence

## Security principles

- Untrusted email input
- No active HTML or JavaScript execution
- No attachment execution
- No automatic URL visits
- Deterministic technical analysis remains independently visible
- AI may assist analysis and explanation but does not determine attacker identity or legal responsibility
- Analyze by default. Retain by choice.

## Current production capabilities

PHISH-TRACE AI currently provides:

- Passive `.eml` analysis.
- SHA-256 evidence integrity.
- Deterministic identity, infrastructure, attachment and social-engineering findings.
- Explainable risk scoring.
- Explicit incident creation and JSON evidence export.
- Deterministic campaign correlation.
- Contextual risk assessment.
- Interactive Threat Graph.
- Human-controlled remediation guidance.

## Production

Frontend:
https://phish-trace-ai-psi.vercel.app

Backend:
https://phish-trace-ai-production.up.railway.app

Current validated checkpoint:

`p1-production-green` — commit `9b81644`

## Post-submission development

The TLN submission remains preserved on `main` with scoring v1.1.

A separate branch, `post-submission-judicial-hardening`, contains scoring v1.2 developed after the submission deadline from a real-world judicial-phishing validation case.

Preview v1.2:
https://phish-trace-ai-git-post-submission-judic-51097e-phish-trace-lab.vercel.app

Detailed validation record:
`docs/POST_SUBMISSION_JUDICIAL_VALIDATION.md`

## Human control

PHISH-TRACE AI supports analyst decision-making.

It does not automatically execute remediation actions, determine attacker identity or establish legal attribution.
