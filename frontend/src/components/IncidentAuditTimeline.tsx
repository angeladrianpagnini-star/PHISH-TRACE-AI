"use client";

export type IncidentAuditEvent = {
  schema_version: string;
  event_id: string;
  incident_id: string;
  event_type: string;
  created_at: string;
  actor: string | null;
  details: Record<string, unknown>;
};

type IncidentAuditTimelineProps = {
  events: IncidentAuditEvent[];
  loading: boolean;
  onRefresh: () => void;
};

function displayValue(value: string) {
  return value.replaceAll("_", " ");
}

function detailValue(value: unknown) {
  if (value === null || value === undefined) {
    return "NONE";
  }

  if (typeof value === "string") {
    return displayValue(value);
  }

  return String(value);
}

function eventSummary(event: IncidentAuditEvent) {
  const details = event.details;

  if (event.event_type === "INCIDENT_CREATED") {
    return [
      `State: ${detailValue(details.state)}`,
      `Severity: ${detailValue(details.severity)}`,
      `Priority: ${detailValue(details.priority)}`,
    ];
  }

  if (event.event_type === "ASSIGNMENT_CHANGED") {
    return [
      `From: ${detailValue(details.from)}`,
      `To: ${detailValue(details.to)}`,
      `Queue: ${detailValue(details.queue)}`,
    ];
  }

  if (event.event_type === "STATE_CHANGED") {
    return [
      `From: ${detailValue(details.from)}`,
      `To: ${detailValue(details.to)}`,
      `Status: ${detailValue(details.status)}`,
    ];
  }

  return Object.entries(details).map(
    ([key, value]) =>
      `${displayValue(key)}: ${detailValue(value)}`
  );
}

export default function IncidentAuditTimeline({
  events,
  loading,
  onRefresh,
}: IncidentAuditTimelineProps) {
  return (
    <section
      style={{
        marginTop: "22px",
        paddingTop: "20px",
        borderTop: "1px solid #334155",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: "12px",
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
            AUDIT TIMELINE
          </p>

          <p
            style={{
              margin: "8px 0 0",
              color: "#94a3b8",
              fontSize: "14px",
            }}
          >
            Chronological incident history preserved by the SOC.
          </p>
        </div>

        <button
          onClick={onRefresh}
          disabled={loading}
          style={{
            padding: "10px 14px",
            borderRadius: "8px",
            border: "1px solid #475569",
            fontWeight: 700,
            cursor: loading ? "not-allowed" : "pointer",
          }}
        >
          {loading ? "REFRESHING..." : "REFRESH TIMELINE"}
        </button>
      </div>

      {loading && events.length === 0 ? (
        <p
          style={{
            marginTop: "18px",
            color: "#94a3b8",
          }}
        >
          Loading audit history...
        </p>
      ) : events.length === 0 ? (
        <p
          style={{
            marginTop: "18px",
            marginBottom: 0,
            color: "#94a3b8",
          }}
        >
          No audit events are available for this incident.
        </p>
      ) : (
        <div
          style={{
            marginTop: "18px",
            display: "grid",
            gap: "12px",
          }}
        >
          {events.map((event, index) => {
            const summary = eventSummary(event);

            return (
              <article
                key={event.event_id}
                style={{
                  padding: "16px",
                  borderRadius: "10px",
                  border: "1px solid #334155",
                  background: "#07111f",
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
                  <strong>
                    {index + 1}.{" "}
                    {displayValue(event.event_type)}
                  </strong>

                  <span
                    style={{
                      color: "#94a3b8",
                      fontSize: "13px",
                    }}
                  >
                    {new Date(
                      event.created_at
                    ).toLocaleString()}
                  </span>
                </div>

                <div
                  style={{
                    marginTop: "8px",
                    color: "#cbd5e1",
                    fontSize: "14px",
                  }}
                >
                  Actor: {event.actor ?? "NOT RECORDED"}
                </div>

                {summary.length > 0 && (
                  <div
                    style={{
                      marginTop: "10px",
                      display: "flex",
                      gap: "12px",
                      flexWrap: "wrap",
                      color: "#e2e8f0",
                      fontSize: "14px",
                    }}
                  >
                    {summary.map((item) => (
                      <span
                        key={`${event.event_id}:${item}`}
                      >
                        {item}
                      </span>
                    ))}
                  </div>
                )}

                <div
                  style={{
                    marginTop: "10px",
                    color: "#64748b",
                    fontSize: "12px",
                  }}
                >
                  {event.event_id}
                </div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}
