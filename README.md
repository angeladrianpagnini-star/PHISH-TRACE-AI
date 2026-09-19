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

## Human control

PHISH-TRACE AI supports analyst decision-making.

It does not automatically execute remediation actions, determine attacker identity or establish legal attribution.
