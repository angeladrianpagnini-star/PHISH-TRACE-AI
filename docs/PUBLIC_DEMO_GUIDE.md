# PHISH-TRACE AI - Public Demonstration Guide

Version: 0.4.0-rc.1

## Purpose

Demonstrate explainable email risk assessment,
technical correlation and evidence preparation using
reproducible synthetic messages.

## Preparation

Open:

https://phish-trace-ai-psi.vercel.app/

Confirm API ONLINE and backend version 0.4.0-rc.1.

Use the three files from dataset/public-demo/:

- DEMO-001.eml
- DEMO-002.eml
- DEMO-003-BENIGN.eml

Verify their fingerprints against SHA256SUMS.txt.

On Windows PowerShell:

    Get-FileHash dataset/public-demo/*.eml -Algorithm SHA256

Do not upload confidential or personal information.

## Test 1 - Critical email

Select DEMO-001.eml and click ANALYZE EMAIL.

Expected:

- Risk: 81 / CRITICAL.
- Confidence: HIGH.
- Scoring model: v1.2.
- Explainable weighted risk reasons.
- Original message SHA-256 available.

Set this message as the comparison baseline.
Add it to the multi-email campaign set.

## Test 2 - High-risk email

Select DEMO-002.eml and analyze.

Expected:

- Risk: 73 / HIGH.
- Confidence: HIGH.
- Individual risk reasons: 25 + 5 + 18 + 25.

## Test 3 - Positive technical correlation

Click CORRELATE WITH BASELINE.

Expected:

- Current email risk: 73 / HIGH.
- Combined comparison risk: 81 / CRITICAL.
- Relationship: RELATED_CAMPAIGN.
- Confidence: HIGH.
- Three shared technical indicators.
- Attribution: NOT_DETERMINED.

Inspect the technical correlation graph.

The graph represents shared evidence, not attack
direction, causality or legal attribution.

## Test 4 - Multi-email campaign

Add DEMO-002.eml to the campaign set.

Click BUILD CAMPAIGN CORRELATION.

Expected:

- Campaign ID: CAMPAIGN-4AFA7AEF4D1A.
- Related messages: 2/2.
- Aggregate risk: 81 / CRITICAL.
- Three shared technical indicators.

## Test 5 - Benign control

Analyze DEMO-003-BENIGN.eml.

Expected:

- Individual risk: 0 / LOW.
- Confidence: LOW.
- No weighted risk indicators detected.

Compare it with the original DEMO-001 baseline.

Expected:

- NO_TECHNICAL_RELATIONSHIP.
- Zero shared indicators.
- Individual risk remains 0 / LOW.

Add the benign message to the existing campaign set.

Rebuild campaign correlation.

Expected:

- Related messages: 2/3.
- Same campaign ID.
- Benign message excluded from the related group.

## Test 6 - Evidence preview and export

Generate a technical evidence preview for the current
analyzed message.

Confirm:

- Mode: PUBLIC DEMO - NON-PERSISTENT.
- Retention: PREVIEW.
- Server persistence: NO.

Click EXPORT PREVIEW JSON.

Verify the downloaded JSON contains the reported
message SHA-256, findings, risk and security controls.

Expected metadata:

    retention.mode = preview
    retention.persisted = false
    evidence_origin = CLIENT_SUPPLIED_ANALYSIS
    integrity_verified = false

For DEMO-003-BENIGN.eml, individual risk remains 0 / LOW.

The JSON is a technical preview, not a registered
SOC incident or signed forensic certificate.

## Completion

Record the test date, frontend URL, backend version,
fixture fingerprints and exported JSON fingerprints.

A successful demonstration validates the documented
workflow against these fixtures. It does not establish
general detection accuracy.
