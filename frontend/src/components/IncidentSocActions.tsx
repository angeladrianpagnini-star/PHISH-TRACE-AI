"use client";

import { useState } from "react";
import { IncidentSocRecord } from "./IncidentSocPanel";

const NEXT_STATES: Record<string, string[]> = {
  NEW: ["TRIAGED"],
  TRIAGED: ["IN_PROGRESS", "RESOLVED"],
  IN_PROGRESS: ["RESOLVED"],
  RESOLVED: ["CLOSED"],
  CLOSED: [],
};

type IncidentSocActionsProps = {
  incident: IncidentSocRecord;
  busy: boolean;
  onAssign: (assignedTo: string | null) => Promise<void>;
  onTransition: (targetState: string) => Promise<void>;
};

function displayValue(value: string) {
  return value.replaceAll("_", " ");
}

export default function IncidentSocActions({
  incident,
  busy,
  onAssign,
  onTransition,
}: IncidentSocActionsProps) {
  const [assignee, setAssignee] = useState(
    incident.ownership.assigned_to ?? ""
  );

  const nextStates =
    NEXT_STATES[incident.lifecycle.state] ?? [];

  const normalizedAssignee = assignee.trim();

  return (
    <div
      style={{
        marginTop: "22px",
        paddingTop: "20px",
        borderTop: "1px solid #334155",
      }}
    >
      <p
        style={{
          margin: 0,
          color: "#22d3ee",
          fontSize: "13px",
          fontWeight: 700,
          letterSpacing: "0.12em",
        }}
      >
        SOC ACTIONS
      </p>

      <div
        style={{
          marginTop: "16px",
          display: "grid",
          gap: "18px",
        }}
      >
        <div>
          <label
            htmlFor="incident-assignee"
            style={{
              display: "block",
              marginBottom: "8px",
              fontWeight: 700,
            }}
          >
            Analyst assignment
          </label>

          <div
            style={{
              display: "flex",
              gap: "10px",
              flexWrap: "wrap",
            }}
          >
            <input
              id="incident-assignee"
              value={assignee}
              disabled={busy}
              onChange={(event) =>
                setAssignee(event.target.value)
              }
              placeholder="Analyst name"
              style={{
                flex: "1 1 240px",
                padding: "11px 12px",
                borderRadius: "8px",
                border: "1px solid #475569",
                background: "#07111f",
                color: "#ffffff",
              }}
            />

            <button
              disabled={busy || !normalizedAssignee}
              onClick={() => onAssign(normalizedAssignee)}
              style={{
                padding: "11px 16px",
                borderRadius: "8px",
                border: 0,
                fontWeight: 700,
                cursor:
                  busy || !normalizedAssignee
                    ? "not-allowed"
                    : "pointer",
              }}
            >
              ASSIGN
            </button>

            <button
              disabled={
                busy ||
                incident.ownership.assigned_to === null
              }
              onClick={() => onAssign(null)}
              style={{
                padding: "11px 16px",
                borderRadius: "8px",
                border: "1px solid #475569",
                fontWeight: 700,
                cursor:
                  busy ||
                  incident.ownership.assigned_to === null
                    ? "not-allowed"
                    : "pointer",
              }}
            >
              UNASSIGN
            </button>
          </div>
        </div>

        <div>
          <strong>Lifecycle actions</strong>

          {nextStates.length === 0 ? (
            <p
              style={{
                marginBottom: 0,
                color: "#94a3b8",
              }}
            >
              This incident is CLOSED. No further lifecycle
              transitions are available.
            </p>
          ) : (
            <div
              style={{
                display: "flex",
                gap: "10px",
                flexWrap: "wrap",
                marginTop: "10px",
              }}
            >
              {nextStates.map((targetState) => (
                <button
                  key={targetState}
                  disabled={busy}
                  onClick={() =>
                    onTransition(targetState)
                  }
                  style={{
                    padding: "11px 16px",
                    borderRadius: "8px",
                    border: "1px solid #22d3ee",
                    background: "#10263a",
                    color: "#ffffff",
                    fontWeight: 700,
                    cursor: busy
                      ? "not-allowed"
                      : "pointer",
                  }}
                >
                  MOVE TO {displayValue(targetState)}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
