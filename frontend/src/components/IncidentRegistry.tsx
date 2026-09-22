"use client";

import { IncidentSocRecord } from "./IncidentSocPanel";

type IncidentRegistryProps<T extends IncidentSocRecord> = {
  incidents: T[];
  selectedIncidentId: string | null;
  loading: boolean;
  onSelect: (incident: T) => void;
  onRefresh: () => void;
};

function displayValue(value: string) {
  return value.replaceAll("_", " ");
}

export default function IncidentRegistry<
  T extends IncidentSocRecord
>({
  incidents,
  selectedIncidentId,
  loading,
  onSelect,
  onRefresh,
}: IncidentRegistryProps<T>) {
  return (
    <section
      style={{
        marginBottom: "28px",
        padding: "24px",
        border: "1px solid #334155",
        borderRadius: "14px",
        background: "#0b1627",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: "16px",
          flexWrap: "wrap",
        }}
      >
        <div>
          <p
            style={{
              margin: 0,
              color: "#22d3ee",
              fontSize: "13px",
              fontWeight: 700,
              letterSpacing: "0.12em",
            }}
          >
            SOC INCIDENT REGISTRY
          </p>

          <p
            style={{
              margin: "8px 0 0",
              color: "#94a3b8",
              fontSize: "14px",
            }}
          >
            Persistent incident records available to the SOC.
          </p>
        </div>

        <button
          onClick={onRefresh}
          disabled={loading}
          style={{
            padding: "10px 16px",
            borderRadius: "8px",
            border: "1px solid #475569",
            fontWeight: 700,
            cursor: loading ? "not-allowed" : "pointer",
          }}
        >
          {loading ? "REFRESHING..." : "REFRESH REGISTRY"}
        </button>
      </div>

      {incidents.length === 0 ? (
        <p
          style={{
            marginTop: "18px",
            marginBottom: 0,
            color: "#94a3b8",
          }}
        >
          No persisted incidents are currently available.
        </p>
      ) : (
        <div
          style={{
            marginTop: "18px",
            display: "grid",
            gap: "10px",
          }}
        >
          {incidents.map((incident) => {
            const selected =
              incident.incident_id === selectedIncidentId;

            return (
              <button
                key={incident.incident_id}
                onClick={() => onSelect(incident)}
                style={{
                  width: "100%",
                  padding: "16px",
                  borderRadius: "10px",
                  border: selected
                    ? "1px solid #22d3ee"
                    : "1px solid #334155",
                  background: selected
                    ? "#10263a"
                    : "#07111f",
                  color: "#ffffff",
                  cursor: "pointer",
                  textAlign: "left",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    gap: "12px",
                    flexWrap: "wrap",
                  }}
                >
                  <strong>{incident.incident_id}</strong>

                  <span>
                    {incident.priority} ·{" "}
                    {displayValue(incident.severity)}
                  </span>
                </div>

                <div
                  style={{
                    marginTop: "8px",
                    color: "#cbd5e1",
                    fontSize: "14px",
                  }}
                >
                  {displayValue(incident.lifecycle.state)}
                  {" · "}
                  {incident.ownership.assigned_to ?? "UNASSIGNED"}
                  {" · "}
                  {new Date(incident.created_at).toLocaleString()}
                </div>
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
}
