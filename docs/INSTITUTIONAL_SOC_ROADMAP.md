# PHISH-TRACE AI - Institutional SOC Roadmap

## Objective

Provide prospective institutional customers with a
protected environment to evaluate the complete
incident-management and SOC workflow.

The public demonstration must remain operational
and separate from institutional incident data.

## Existing implementation foundations

Previous development milestones include:

- Incident registry.
- Persistent incident repository.
- Incident detail panel.
- Analyst assignment.
- Incident lifecycle transitions.
- Persistent audit events.
- Audit timeline.
- Technical correlation and evidence export.

These foundations are not currently exposed through
the public demonstration.

## RC-12 - SOC functional recovery

- Restore the existing institutional SOC interface.
- Preserve the public demonstration interface.
- Verify registry, detail, assignment and lifecycle.
- Verify audit timeline integration.
- Preserve existing regression coverage.

## RC-13 - Protected institutional access

- Establish server-side authentication.
- Implement authorized role boundaries.
- Issue revocable, time-limited evaluation access.
- Keep API secrets out of browser bundles.
- Isolate institutional incident records.
- Establish controlled persistence and retention.
- Validate reset and deletion procedures.
- Prevent unauthorized cross-environment access.

Initial evaluation may use a dedicated isolated
environment for one institution at a time.

Infrastructure costs and resource requirements must
be reviewed before provisioning additional services.

## RC-14 - Institutional validation

- Authentication and authorization tests.
- Session expiry and revocation tests.
- Incident registration and retrieval.
- Analyst assignment and lifecycle transitions.
- Audit history and persistence after restart.
- Unauthorized access and isolation tests.
- Evidence integrity and export validation.
- Backup, recovery and deletion verification.
- Resource and load validation.

Synthetic data remains the initial evaluation dataset.

## RC-15 - Institutional presentation

- Controlled institutional demonstration.
- Evaluation access procedure.
- Technical architecture overview.
- Security and privacy boundaries.
- Operational guide.
- Commercial evaluation proposal.

## Future product evolution

The following capabilities are planned, not released:

- External cyber threat intelligence integration.
- Validated user-reported indicators.
- Threat intelligence alert portal.
- Indicator confidence, expiration and retraction.
- STIX/TAXII and MISP interoperability.

External intelligence sources require licensing,
privacy, quality and commercial-use review.

## Release boundary

No public SOC activation is authorized by this roadmap.

Institutional deployment requires explicit approval
after security, isolation and operational validation.
