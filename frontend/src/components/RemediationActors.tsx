"use client";

type RemediationActorsProps = {
  classification: string;
  correlationRelationship?: string;
};

const actors = [
  {
    name: "SOC / Security Operations",
    role: "Triage, containment and technical indicator handling.",
    action: "ACKNOWLEDGE",
  },
  {
    name: "Email / Identity Administrator",
    role: "Account protection, mailbox review and identity remediation.",
    action: "REMEDIATE",
  },
  {
    name: "Incident Response / Evidence Custodian",
    role: "Preserve evidence and maintain the incident record.",
    action: "PRESERVE",
  },
];

export default function RemediationActors({
  classification,
  correlationRelationship,
}: RemediationActorsProps) {
  return (
    <section
      style={{
        marginTop: "24px",
        border: "1px solid #155e75",
        borderRadius: "12px",
        padding: "20px",
        background: "#09151d",
      }}
    >
      <h3
        style={{
          margin: 0,
          color: "#22d3ee",
          letterSpacing: "1px",
        }}
      >
        RELEVANT REMEDIATION ACTORS
      </h3>

      <p
        style={{
          marginTop: "8px",
          color: "#94a3b8",
          fontSize: "13px",
          lineHeight: 1.6,
        }}
      >
        Suggested operational roles based on the technical findings. These are
        response recommendations, not automatic actions or legal
        determinations.
      </p>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: "14px",
          marginTop: "18px",
        }}
      >
        {actors.map((actor) => (
          <div
            key={actor.name}
            style={{
              border: "1px solid #334155",
              borderRadius: "9px",
              padding: "16px",
              background: "#0d1b26",
            }}
          >
            <strong
              style={{
                display: "block",
                color: "#f8fafc",
                marginBottom: "8px",
              }}
            >
              {actor.name}
            </strong>

            <p
              style={{
                color: "#cbd5e1",
                fontSize: "13px",
                lineHeight: 1.5,
                minHeight: "58px",
              }}
            >
              {actor.role}
            </p>

            <div
              style={{
                marginTop: "12px",
                display: "inline-block",
                border: "1px solid #22d3ee",
                borderRadius: "6px",
                padding: "7px 10px",
                color: "#67e8f9",
                fontSize: "11px",
                fontWeight: 700,
                letterSpacing: "0.8px",
              }}
            >
              {actor.action}
            </div>
          </div>
        ))}
      </div>

      <div
        style={{
          marginTop: "18px",
          paddingTop: "14px",
          borderTop: "1px solid #1e3a46",
          color: "#94a3b8",
          fontSize: "12px",
          lineHeight: 1.6,
        }}
      >
        Current technical classification:{" "}
        <strong style={{ color: "#e2e8f0" }}>{classification}</strong>
        {correlationRelationship && (
          <>
            {" "}
            · Correlation context:{" "}
            <strong style={{ color: "#e2e8f0" }}>
              {correlationRelationship.replaceAll("_", " ")}
            </strong>
          </>
        )}
        . Actions remain human-controlled and simulated in this MVP.
      </div>
    </section>
  );
}