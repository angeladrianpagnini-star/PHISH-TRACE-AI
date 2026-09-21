# CASE-001 — Judicial / Institutional Impersonation

## Status

Post-submission controlled validation and real-world hardening case.

This case was incorporated after the TLN Cybersecurity Challenge 2026 submission to validate how PHISH-TRACE AI can evolve from a competition prototype into an explainable security analysis and incident-response platform.

## 1. Context

A suspicious email may attempt to create credibility by presenting itself as a judicial, legal, governmental, or otherwise institutional communication.

A legal or judicial reference alone is not sufficient evidence that a message is malicious.

PHISH-TRACE therefore evaluates the message through multiple independent and contextual signals instead of treating institutional language as an automatic malicious verdict.

## 2. Threat Scenario

The controlled scenario represents a message that may combine:

- judicial or legal terminology;
- claims of institutional authority;
- public webmail as the sender infrastructure;
- shortened URLs;
- sender and URL domain inconsistencies;
- provider junk classification;
- urgency or other social-engineering indicators.

The objective is to identify suspicious combinations while avoiding unsupported attribution or conclusions.

## 3. Detection Logic

PHISH-TRACE currently evaluates relevant signals including:

### Legal / judicial pretext

Finding:

`SOCIAL_LEGAL_PRETEXT`

The system detects configured legal or judicial terminology in the subject and message content.

This finding is contextual evidence and does not independently increase the risk score.

### URL shortener

Finding:

`URL_SHORTENER_PRESENT`

The system identifies known URL-shortening domains.

A shortened URL is not automatically malicious and therefore does not independently increase the risk score.

PHISH-TRACE does not visit the detected URL during this analysis.

### URL shortener combined with legal pretext

Finding:

`URL_SHORTENER_WITH_LEGAL_PRETEXT`

When a known shortener appears together with a legal or judicial pretext, the combination is treated as stronger contextual evidence.

### Institutional claim from public webmail

Finding:

`INSTITUTIONAL_CLAIM_FREE_WEBMAIL`

When institutional terminology is combined with a sender using a configured public webmail domain, PHISH-TRACE records a high-severity identity inconsistency.

This remains a technical finding rather than proof of malicious intent.

### Provider junk verdict

Finding:

`PROVIDER_JUNK_VERDICT`

PHISH-TRACE can preserve provider-generated anti-spam signals, including Microsoft SCL and mailbox-delivery indicators.

Provider classification is treated as supporting evidence rather than an independent determination of malicious activity.

## 4. Additional Evidence

The analysis engine can also identify:

- Reply-To / From domain mismatch;
- Return-Path / From domain mismatch;
- URL domains different from the sender domain;
- reported SPF, DKIM and DMARC results;
- credential requests;
- account-verification language;
- urgency;
- restriction or suspension threats;
- potentially dangerous attachment extensions.

Authentication results extracted from message headers are preserved as reported evidence and are not treated as independently verified authentication results unless verification exists.

## 5. Risk Model

PHISH-TRACE uses deterministic weighted findings.

The model intentionally distinguishes between:

- contextual evidence;
- independently weighted indicators;
- combinations of indicators;
- unverified reported evidence.

Examples of the current design include:

- URL shortener alone: contextual, no direct score increase;
- legal pretext alone: contextual, no direct score increase;
- URL shortener + legal pretext: weighted contextual combination;
- institutional claim + public webmail: weighted identity inconsistency;
- provider junk verdict: supporting weighted signal.

Risk is classified as:

- LOW
- SUSPICIOUS
- HIGH
- CRITICAL

The score is capped at 100.

## 6. Safety Controls

The current controlled analysis follows explicit safety boundaries:

- URLs are extracted but not visited;
- remote content is not loaded;
- HTML content is not actively executed;
- attachments are not executed;
- dangerous attachment extensions are identified through metadata;
- findings do not constitute attribution;
- technical indicators do not constitute a legal conclusion.

These boundaries allow suspicious material to be analyzed without unnecessarily interacting with external infrastructure.

## 7. Evidence and Explainability

Each relevant finding is represented through structured evidence.

This supports an explainable workflow:

Message
→ Indicators
→ Findings
→ Weighted evidence
→ Risk classification

The objective is not only to classify a message but also to preserve why the system reached its result.

## 8. Validation Objective

CASE-001 validates that PHISH-TRACE can analyze a realistic institutional-impersonation scenario while maintaining conservative and explainable behavior.

The system must avoid:

- declaring a message malicious from institutional language alone;
- declaring a shortened URL malicious by itself;
- executing suspicious content;
- visiting external URLs;
- claiming attribution from insufficient evidence.

The system should instead identify and preserve combinations of evidence that justify further human review.

## 9. Current Limitations

The current prototype does not claim to provide:

- autonomous attribution of an attacker;
- legal identification of a responsible person;
- active investigation of third-party infrastructure;
- autonomous blocking of external systems;
- independently verified SPF/DKIM/DMARC authentication;
- full enterprise mail-gateway functionality;
- complete forensic chain-of-custody management.

These capabilities require additional architecture, infrastructure, authorization, governance and validation.

## 10. Enterprise Extension

In an authorized corporate environment, this model can evolve toward integration with:

- enterprise mail systems;
- secure mail gateways;
- SOC workflows;
- SIEM/SOAR platforms;
- threat-intelligence sources;
- quarantine and analyst-review processes;
- incident correlation;
- protected organization domains and brands;
- evidence retention and reporting.

An organization could define its own protected identities, official domains and institutional patterns.

## 11. Government / Institutional Extension

In an authorized governmental environment, the same architecture could support:

- detection of institutional impersonation;
- citizen-facing phishing analysis;
- incident correlation;
- evidence preservation;
- case identifiers;
- audit trails;
- controlled escalation;
- forensic reporting;
- chain-of-custody workflows.

Any deeper investigative capability should operate only within the applicable legal authority, authorized infrastructure and defined human-approval procedures.

PHISH-TRACE should preserve the distinction between:

1. raw evidence;
2. automated technical findings;
3. analyst interpretation;
4. investigative conclusions;
5. legal conclusions.

## 12. Future Controlled Cases

CASE-001 establishes the documentation model for additional synthetic and controlled validation scenarios.

Potential future cases include:

- CASE-002 — Banking Impersonation
- CASE-003 — Tax / Government Impersonation
- CASE-004 — Logistics / Parcel Impersonation
- CASE-005 — Account / Digital Identity Impersonation

The long-term objective is to generalize institutional-impersonation detection rather than create isolated hard-coded rules for individual organizations.

## 13. Engineering Principle

PHISH-TRACE should evolve according to the following principle:

`claimed identity + sender identity + authentication + infrastructure + social pretext + provider signals + campaign context → evidence → risk → incident`

This allows the same core analysis model to support controlled demonstrations and, with appropriate infrastructure and authorization, future corporate or governmental deployments.
