"use client";

export type IncidentSocRecord = {
  incident_id: string;
  created_at: string;
  updated_at: string;
  status: string;
  incident_type: string;
  severity: string;
  priority: string;
  lifecycle: {
    state: string;
    closed_at: string | null;
  };
  ownership: {
    queue: string;
    assigned_to: string | null;
  };
  risk: {
    score: number;
    classification: string;
    confidence: string;
    scoring_version: string | null;
  };
  retention: {
    mode: string;
    persisted: boolean;
  };
};

type IncidentSocPanelProps = {
  incident: IncidentSocRecord;
  onExport: () => void;
};

function displayValue(value: string) {
  return value.replaceAll("_", " ");
}

export default function IncidentSocPanel({
  incident,
  onExport,
}: IncidentSocPanelProps) {
  const isPreview = incident.retention.mode === "preview";

  return (
    <>
      <div
        style={{
          marginTop: "18px",
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: "12px",
        }}
      >
        <div>
          <strong>{isPreview ? "Evidence Preview ID" : "Incident ID"}</strong>
          <div>{incident.incident_id}</div>
        </div>

        <div>
          <strong>Severity</strong>
          <div>{displayValue(incident.severity)}</div>
        </div>

        <div>
          <strong>{isPreview ? "Suggested priority" : "Priority"}</strong>
          <div>{incident.priority}</div>
        </div>

        {isPreview ? (
          <>
            <div>
              <strong>Confidence</strong>
              <div>{displayValue(incident.risk.confidence)}</div>
            </div>
            <div>
              <strong>Mode</strong>
              <div>PUBLIC PREVIEW</div>
            </div>
          </>
        ) : (
          <>
            <div>
              <strong>Lifecycle</strong>
              <div>{displayValue(incident.lifecycle.state)}</div>
            </div>

            <div>
              <strong>Status</strong>
              <div>{displayValue(incident.status)}</div>
            </div>

            <div>
              <strong>SOC Queue</strong>
              <div>{incident.ownership.queue}</div>
            </div>

            <div>
              <strong>Assigned analyst</strong>
              <div>{incident.ownership.assigned_to ?? "UNASSIGNED"}</div>
            </div>
          </>
        )}

        <div>
          <strong>Risk score</strong>
          <div>
            {incident.risk.score} ·{" "}
            {displayValue(incident.risk.classification)}
          </div>
        </div>
      </div>

      <div style={{ marginTop: "18px", lineHeight: 1.8 }}>
        <p>
          <strong>Created:</strong>{" "}
          {new Date(incident.created_at).toLocaleString()}
        </p>

        <p>
          <strong>Updated:</strong>{" "}
          {new Date(incident.updated_at).toLocaleString()}
        </p>

        <p>
          <strong>Retention:</strong>{" "}
          {incident.retention.mode.toUpperCase()}
        </p>

        <p>
          <strong>Server persistence:</strong>{" "}
          {incident.retention.persisted ? "YES" : "NO"}
        </p>
      </div>

      <button
        onClick={onExport}
        style={{
          marginTop: "10px",
          padding: "14px 24px",
          borderRadius: "8px",
          border: 0,
          fontWeight: 700,
          cursor: "pointer",
        }}
      >
        EXPORT EVIDENCE JSON
      </button>

      <p
        style={{
          marginTop: "16px",
          color: "#94a3b8",
          fontSize: "13px",
        }}
      >
        {isPreview
          ? "This preview preserves the reported message SHA-256, findings, risk assessment and security controls. It is not a registered SOC incident or an independently verified forensic certificate."
          : "Evidence export preserves the analyzed message SHA-256, findings, risk assessment and security controls."}
      </p>
    </>
  );
}
