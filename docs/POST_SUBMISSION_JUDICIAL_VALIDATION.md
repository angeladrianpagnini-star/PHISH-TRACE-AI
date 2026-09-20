# Post-Submission Real-World Validation — Judicial Phishing Case

Date: 2026-09-20

## Scope

This document describes a **post-submission** validation and hardening cycle performed after the TLN Cybersecurity Challenge 2026 submission had already closed.

The submitted hackathon version remains preserved on `main` and is not modified by this work.

## Triggering case

A real unsolicited email presented itself as a judicial or labor-court notification.

Relevant passive indicators included:

- sender infrastructure from a public webmail provider;
- judicial/institutional language in the subject and body;
- a shortened URL;
- URL domain different from the sender domain;
- provider-side Junk classification signals;
- no attachment execution and no URL visit during analysis.

PHISH-TRACE AI does not treat SPF, DKIM or DMARC PASS as proof that an institutional identity claim is legitimate. Those mechanisms authenticate the sending domain/infrastructure, not the claimed real-world institution.

## Baseline result — scoring v1.1

The submitted scoring model classified the real message as:

- Score: **18 / 100**
- Classification: **LOW**
- Confidence: **MEDIUM**

The weighted signal was:

- `URL_DOMAIN_DIFFERS_FROM_SENDER`: +18

This result exposed a gap in contextual analysis rather than a failure of the passive parsing pipeline.

## Post-submission hardening — scoring v1.2

The following deterministic contextual findings were added:

- `URL_SHORTENER_PRESENT` — informational, weight 0.
- `SOCIAL_LEGAL_PRETEXT` — informational, weight 0.
- `URL_SHORTENER_WITH_LEGAL_PRETEXT` — +12.
- `INSTITUTIONAL_CLAIM_FREE_WEBMAIL` — +25.
- `PROVIDER_JUNK_VERDICT` — +8.

The existing `URL_DOMAIN_DIFFERS_FROM_SENDER` signal remains +18.

The design intentionally avoids scoring a generic shortener by itself. The additional score is applied only when the shortener appears together with a legal/judicial pretext.

## v1.2 result

The same real message produced:

- Score: **63 / 100**
- Classification: **HIGH**
- Confidence: **HIGH**
- Scoring version: **1.2**

Weighted reasons:

- +18 `URL_DOMAIN_DIFFERS_FROM_SENDER`
- +12 `URL_SHORTENER_WITH_LEGAL_PRETEXT`
- +25 `INSTITUTIONAL_CLAIM_FREE_WEBMAIL`
- +8 `PROVIDER_JUNK_VERDICT`

## False-positive control

A real promotional email using a URL shortener was re-tested.

Result:

- Score: **18 / 100**
- Classification: **LOW**
- Confidence: **MEDIUM**

Findings included `URL_SHORTENER_PRESENT`, but because the shortener is informational by itself, the message did not receive an artificial risk increase.

This control is important: the objective of v1.2 is not to score more aggressively, but to improve contextual discrimination.

## Final regression

The post-submission branch preserved the expected results:

- DS-AUTH-UNTRUSTED: 0 / LOW / LOW / v1.2
- DS-06: 67 / HIGH / HIGH / v1.2
- DS-07: 100 / CRITICAL / HIGH / v1.2
- DS-10: 64 / HIGH / HIGH / v1.2
- DS-11: 64 / HIGH / HIGH / v1.2
- PHISH-TRACE-ES-CONTROL: 67 / HIGH / HIGH / v1.2

DS-10 / DS-11 correlation remained:

- Relationship: `RELATED_CAMPAIGN`
- Confidence: `HIGH`
- Shared indicators: 3
- Attribution: `NOT_DETERMINED`
- Contextual risk: 75 / CRITICAL
- Correlation floor applied: true

## Isolation and deployment

Submitted TLN version:

- Branch: `main`
- Commit: `2b5f7ec`
- Tag: `p1-bilingual-hardening-green`
- Scoring: v1.1
- Frontend: https://phish-trace-ai-psi.vercel.app

Post-submission evolution:

- Branch: `post-submission-judicial-hardening`
- Validated hardening commit: `74a2bb5`
- Tag: `post-submission-judicial-hardening-green`
- Scoring: v1.2
- Preview frontend: https://phish-trace-ai-git-post-submission-judic-51097e-phish-trace-lab.vercel.app
- Preview backend: https://phish-trace-ai-v1-2-backend-production.up.railway.app

The v1.2 preview is intentionally isolated from the submitted hackathon production environment.

## Engineering conclusion

This case demonstrates a controlled post-submission hardening loop:

**real-world observation → explainable gap → deterministic contextual rule → false-positive control → full regression → isolated deployment**

The objective is to improve detection quality while preserving explainability, reproducibility, passive analysis, and human control.
