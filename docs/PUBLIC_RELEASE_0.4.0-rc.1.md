# PHISH-TRACE AI - Public Release Record

## Release identification

- Version: 0.4.0-rc.1
- Channel: public-demo
- Date: 2026-11-27
- Scoring model: v1.2
- Status: published and functionally validated
- Branch: release/public-demo

## Deployment references

Frontend:
https://phish-trace-ai-psi.vercel.app/

Validated frontend candidate:
https://phish-trace-a48y568yv-phish-trace-lab.vercel.app/

Frontend source checkpoint:

    5c4b21a261fa876b544983db1c71b020626d7b35

Backend:
https://phish-trace-ai-v1-2-backend-production.up.railway.app

Backend source checkpoint:

    1a1e6034d74cb508afba78018ac1929c2dfcc2c6

Original TLN main checkpoint:

    2b5f7ec8eee3f8372f788aa397fcadd373afe745

Frontend source provenance was established through an
audited package of exact Git blobs and explicit deployment
metadata. It is distinct from a native Git deployment.

## Validation summary

| Control | Result |
|---|---|
| Backend automated tests | 166/166 PASS |
| Frontend lint | PASS |
| Frontend production build | PASS |
| Pre-release remote controls | 29/29 PASS |
| Final production functional checks | 6/6 confirmed |
| Production frontend | HTTP 200 |
| Backend health | HTTP 200 / status ok |
| Production CORS preflight | HTTP 200 |
| Public SOC operations | Disabled / HTTP 503 |
| Preserved evidence files | 6/6 SHA-256 verified |

These results describe the recorded release validation.
They are not a continuous availability guarantee.

## Synthetic demonstration results

| Fixture | Score | Classification | Confidence |
|---|---:|---|---|
| DEMO-001.eml | 81 | CRITICAL | HIGH |
| DEMO-002.eml | 73 | HIGH | HIGH |
| DEMO-003-BENIGN.eml | 0 | LOW | LOW |

### Positive correlation

- Relationship: RELATED_CAMPAIGN.
- Confidence: HIGH.
- Shared technical indicators: 3.
- Combined risk: 81 / CRITICAL.
- Attribution: NOT_DETERMINED.

### Campaign correlation

- Campaign ID: CAMPAIGN-4AFA7AEF4D1A.
- Related messages in positive set: 2/2.
- Related messages in mixed set: 2/3.
- Aggregate risk: 81 / CRITICAL.
- Benign control excluded from the related group.

### Negative correlation

The benign control retains individual risk 0 / LOW.

Pairwise comparison with DEMO-001 produces no technical
relationship and zero shared indicators.

Combined comparison risk may remain 81 because it reflects
both messages. It does not reclassify the benign message.

## Evidence preservation

The external release evidence package contains:

| File | Bytes |
|---|---:|
| DEMO-001.eml | 616 |
| DEMO-002.eml | 630 |
| DEMO-003-BENIGN.eml | 593 |
| INC-20261127-E6A90FCC.json | 5609 |
| PREVIEW-INC-20261127-5B6A6B8F.json | 5609 |
| PREVIEW-INC-20261127-71DDB962.json | 2140 |

All six files were copied and verified against their
source SHA-256 fingerprints.

Manifest: SHA256-MANIFEST.csv

Manifest SHA-256:

    63b8e8734e120daea6703b826cc1da02e7fdbd6e11ef629f9ca3d1702f119d6e

Fixture fingerprints are tracked separately in:

    dataset/public-demo/SHA256SUMS.txt

The evidence package is maintained outside the source
repository. Raw evidence exports are not included in
the public frontend deployment.

Screenshots and console transcripts remain to be
consolidated into the external evidence archive.

## Security boundaries

- Passive email processing.
- No active HTML or attachment execution.
- No automatic URL visits or remote email content loading.
- Explicit public request resource controls.
- Explicit CORS origin configuration.
- Public SOC operations disabled.
- Public evidence previews are not registered incidents.
- No automatic remediation or legal attribution.

## Known limitations

- Risk scoring is deterministic and rule-based.
- Synthetic fixture results do not establish population-
  level detection accuracy or false-positive rates.
- Reported authentication headers are not independently
  verified.
- Public evidence previews use client-supplied analysis.
- JSON exports are not digitally signed forensic
  certificates.
- The preview JSON retains inherited incident-model fields,
  including status, lifecycle and ownership. These fields
  do not establish persistent incident registration.
- Public rate limiting is process-local. Distributed
  enforcement and proxy identity behavior require further
  validation.
- Malformed nested JSON handling requires additional
  robustness testing.
- Full Linux-container regression and sustained load
  testing remain separate validation tasks.
- Institutional authentication, isolation and persistent
  storage validation are not included in this release.

## Release disposition

Accepted for public demonstration using synthetic or
appropriately anonymized data.

Not approved for unrestricted institutional production
processing of confidential or personal information.

Institutional evaluation requires the protected SOC
environment defined in the separate roadmap.
