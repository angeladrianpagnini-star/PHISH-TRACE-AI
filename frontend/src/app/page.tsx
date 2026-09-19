"use client";

import { ChangeEvent, useEffect, useState } from "react";

type HealthResponse = {
  status: string;
  service: string;
};

type IncidentResult = {
  incident_id: string;
  created_at: string;
  status: string;
  retention: {
    mode: string;
    persisted: boolean;
  };
  evidence: AnalysisResult;
};

type AnalysisResult = {
  filename: string;
  size_bytes: number;
  sha256: string;
  subject: string;
  from: string;
  to: string;
  reply_to: string;
  return_path: string;
  message_id: string;
  authentication_results: {
    reported: string;
    trust: string;
    verified: boolean;
  };
  urls: string[];
  attachments: Array<{
    filename: string;
    content_type: string;
    size_bytes: number;
    sha256: string;
    executed: boolean;
  }>;
  findings: Array<{
    id: string;
    category: string;
    severity: string;
    title: string;
    evidence: Record<string, unknown>;
  }>;
  risk: {
    score: number;
    classification: string;
    confidence: string;
    reasons: Array<{
      finding: string;
      weight: number;
      reason: string;
    }>;
    scoring_version: string;
  };
  security: {
    active_html_executed: boolean;
    attachments_executed: boolean;
    urls_visited: boolean;
    remote_content_loaded: boolean;
  };
};

type CorrelationResult = {
  relationship: string;
  confidence: string;
  shared_indicators: Array<{
    type: string;
    value: string;
  }>;
  shared_indicator_count: number;
  attribution: string;
  correlated_risk: {
    score: number;
    classification: string;
    correlation_floor_applied: boolean;
  };
};
function displayLabel(value: string) {
  return value.replaceAll("_", " ");
}
export default function Home() {
  const [apiStatus, setApiStatus] = useState("Checking...");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [incident, setIncident] = useState<IncidentResult | null>(null);
  const [correlationBaseline, setCorrelationBaseline] =
    useState<AnalysisResult | null>(null);
  const [correlation, setCorrelation] =
    useState<CorrelationResult | null>(null);
  const [correlating, setCorrelating] = useState(false);
  const [loading, setLoading] = useState(false);
  const [creatingIncident, setCreatingIncident] = useState(false);
  const [error, setError] = useState("");

  const apiBase =
    process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000";

  useEffect(() => {
    fetch(`${apiBase}/health`)
      .then((response) => {
        if (!response.ok) throw new Error("API unavailable");
        return response.json();
      })
      .then((data: HealthResponse) => {
        setApiStatus(data.status === "ok" ? "ONLINE" : "DEGRADED");
      })
      .catch(() => {
        setApiStatus("OFFLINE");
      });
  }, [apiBase]);

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    setError("");
    setAnalysis(null);
    setIncident(null);
    setCorrelation(null);

    const file = event.target.files?.[0] || null;

    if (!file) {
      setSelectedFile(null);
      return;
    }

    if (!file.name.toLowerCase().endsWith(".eml")) {
      setSelectedFile(null);
      setError("Only .eml files are accepted.");
      return;
    }

    setSelectedFile(file);
  }

  async function analyzeEmail() {
    if (!selectedFile) {
      setError("Select an .eml file first.");
      return;
    }

    setLoading(true);
    setError("");
    setAnalysis(null);
    setIncident(null);

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);

      const response = await fetch(`${apiBase}/analyze`, {
        method: "POST",
        body: formData,
      });

      const payload = await response.json();

      if (!response.ok) {
        throw new Error(payload.detail || "Analysis failed.");
      }

      setAnalysis(payload);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Unexpected analysis error."
      );
    } finally {
      setLoading(false);
    }
  }

  function setAsCorrelationBaseline() {
    if (!analysis) {
      setError("Analyze an email before setting a correlation baseline.");
      return;
    }

    setCorrelationBaseline(analysis);
    setCorrelation(null);
    setError("");
  }

  async function correlateWithBaseline() {
    if (!analysis || !correlationBaseline) {
      setError("A baseline analysis and a current analysis are required.");
      return;
    }

    setCorrelating(true);
    setCorrelation(null);
    setError("");

    try {
      const response = await fetch(`${apiBase}/correlate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          analysis_a: correlationBaseline,
          analysis_b: analysis,
        }),
      });

      const payload = await response.json();

      if (!response.ok) {
        throw new Error(payload.detail || "Correlation failed.");
      }

      setCorrelation(payload);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Unexpected correlation error."
      );
    } finally {
      setCorrelating(false);
    }
  }
  async function createIncident() {
    if (!analysis) {
      setError("Analyze an email before creating an incident.");
      return;
    }

    setCreatingIncident(true);
    setError("");

    try {
      const response = await fetch(`${apiBase}/incidents`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(analysis),
      });

      const payload = await response.json();

      if (!response.ok) {
        throw new Error(payload.detail || "Incident creation failed.");
      }

      setIncident(payload);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Unexpected incident error."
      );
    } finally {
      setCreatingIncident(false);
    }
  }

  function exportIncidentJson() {
    if (!incident) return;

    const blob = new Blob([JSON.stringify(incident, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");

    anchor.href = url;
    anchor.download = `${incident.incident_id}.json`;

    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();

    URL.revokeObjectURL(url);
  }

  return (
    <main
      style={{
        minHeight: "100vh",
        background: "#07111f",
        color: "#ffffff",
        fontFamily: "Arial, sans-serif",
        padding: "56px 24px",
      }}
    >
      <div style={{ maxWidth: "1050px", margin: "0 auto" }}>
        <p
          style={{
            color: "#22d3ee",
            fontWeight: 700,
            letterSpacing: "0.16em",
          }}
        >
          TLN CYBERSECURITY CHALLENGE 2026
        </p>

        <h1 style={{ fontSize: "60px", margin: "18px 0 8px" }}>
          PHISH-TRACE AI
        </h1>

        <h2
          style={{
            fontSize: "24px",
            fontWeight: 400,
            color: "#cbd5e1",
          }}
        >
          From Suspicious Email to Actionable Evidence
        </h2>

        <div
          style={{
            marginTop: "36px",
            padding: "28px",
            border: "1px solid #334155",
            borderRadius: "16px",
            background: "#0f1c2e",
          }}
        >
          <h3>Secure Email Analysis</h3>

          <p style={{ color: "#94a3b8", lineHeight: 1.6 }}>
            Upload a suspicious .eml file for passive technical analysis.
            Active content, attachments and URLs are never executed.
          </p>

          <input
            type="file"
            accept=".eml,message/rfc822"
            onChange={handleFileChange}
            style={{ marginTop: "18px" }}
          />

          {selectedFile && (
            <p style={{ color: "#cbd5e1" }}>
              Selected: <strong>{selectedFile.name}</strong>
            </p>
          )}

          <button
            onClick={analyzeEmail}
            disabled={!selectedFile || loading}
            style={{
              marginTop: "14px",
              padding: "14px 24px",
              borderRadius: "8px",
              border: 0,
              fontWeight: 700,
              cursor: selectedFile && !loading ? "pointer" : "not-allowed",
            }}
          >
            {loading ? "ANALYZING..." : "ANALYZE EMAIL"}
          </button>

          {error && (
            <p style={{ marginTop: "18px", color: "#f87171" }}>{error}</p>
          )}
        </div>

        {analysis && (
          <div
            style={{
              marginTop: "28px",
              padding: "28px",
              border: "1px solid #334155",
              borderRadius: "16px",
              background: "#0f1c2e",
            }}
          >
            <div
              style={{
                padding: "24px",
                marginBottom: "28px",
                border: "1px solid #475569",
                borderRadius: "14px",
                background: "#0b1627",
              }}
            >
              <p
                style={{
                  margin: 0,
                  color: "#94a3b8",
                  fontSize: "13px",
                  fontWeight: 700,
                  letterSpacing: "0.12em",
                }}
              >
                RISK ASSESSMENT
              </p>

              <div
                style={{
                  display: "flex",
                  alignItems: "baseline",
                  gap: "18px",
                  flexWrap: "wrap",
                  marginTop: "12px",
                }}
              >
                <span
                  style={{
                    fontSize: "52px",
                    fontWeight: 800,
                  }}
                >
                  {analysis.risk.score}
                </span>

                <span style={{ color: "#94a3b8" }}>/ 100</span>

                <strong
                  style={{
                    fontSize: "24px",
                    color:
                      analysis.risk.classification === "CRITICAL"
                        ? "#f87171"
                        : analysis.risk.classification === "HIGH"
                        ? "#fb923c"
                        : analysis.risk.classification === "SUSPICIOUS"
                        ? "#facc15"
                        : "#4ade80",
                  }}
                >
                  {analysis.risk.classification}
                </strong>
              </div>

              <p>
                <strong>Confidence:</strong> {analysis.risk.confidence}
              </p>

              <p>
                <strong>Scoring model:</strong> v{analysis.risk.scoring_version}
              </p>

              <h4 style={{ marginTop: "22px" }}>Why this score?</h4>

              {analysis.risk.reasons.length > 0 ? (
                <ul style={{ lineHeight: 1.8 }}>
                  {analysis.risk.reasons.map((item) => (
                    <li key={item.finding}>
                      <strong>+{item.weight}</strong> — {item.reason}
                    </li>
                  ))}
                </ul>
              ) : (
                <p style={{ color: "#94a3b8" }}>
                  No weighted risk indicators detected.
                </p>
              )}

              <p
                style={{
                  marginTop: "20px",
                  color: "#94a3b8",
                  fontSize: "13px",
                }}
              >
                Deterministic analysis. Authentication PASS does not imply
                message safety.
              </p>
            </div>

            <div
              style={{
                padding: "24px",
                marginBottom: "28px",
                border: "1px solid #a78bfa",
                borderRadius: "14px",
                background: "#0b1627",
              }}
            >
              <p
                style={{
                  margin: 0,
                  color: "#a78bfa",
                  fontSize: "13px",
                  fontWeight: 700,
                  letterSpacing: "0.12em",
                }}
              >
                CAMPAIGN CORRELATION
              </p>

              <p
                style={{
                  color: "#cbd5e1",
                  lineHeight: 1.6,
                  marginTop: "16px",
                }}
              >
                Compare technical indicators between two analyzed emails.
                Correlation identifies shared evidence, not attacker identity.
              </p>

              {!correlationBaseline ? (
                <button
                  onClick={setAsCorrelationBaseline}
                  style={{
                    marginTop: "8px",
                    padding: "14px 24px",
                    borderRadius: "8px",
                    border: 0,
                    fontWeight: 700,
                    cursor: "pointer",
                  }}
                >
                  SET AS BASELINE
                </button>
              ) : (
                <>
                  <p style={{ marginTop: "18px", color: "#cbd5e1" }}>
                    <strong>Baseline:</strong>{" "}
                    {correlationBaseline.filename}
                  </p>

                  <p
                    style={{
                      color: "#94a3b8",
                      fontSize: "13px",
                      overflowWrap: "anywhere",
                    }}
                  >
                    SHA-256: {correlationBaseline.sha256}
                  </p>

                  {analysis.sha256 !== correlationBaseline.sha256 ? (
                    <button
                      onClick={correlateWithBaseline}
                      disabled={correlating}
                      style={{
                        marginTop: "8px",
                        padding: "14px 24px",
                        borderRadius: "8px",
                        border: 0,
                        fontWeight: 700,
                        cursor: correlating ? "not-allowed" : "pointer",
                      }}
                    >
                      {correlating
                        ? "CORRELATING..."
                        : "CORRELATE WITH BASELINE"}
                    </button>
                  ) : (
                    <p style={{ color: "#94a3b8" }}>
                      Select and analyze another .eml file to compare it with
                      this baseline.
                    </p>
                  )}
                </>
              )}

              {correlation && (
                <div
                  style={{
                    marginTop: "24px",
                    paddingTop: "22px",
                    borderTop: "1px solid #334155",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      gap: "28px",
                      flexWrap: "wrap",
                      alignItems: "baseline",
                    }}
                  >
                    <div>
                      <p
                        style={{
                          margin: 0,
                          color: "#94a3b8",
                          fontSize: "12px",
                        }}
                      >
                        STANDALONE RISK
                      </p>

                      <strong style={{ fontSize: "28px" }}>
                        {analysis.risk.score}{" "}
                        {analysis.risk.classification}
                      </strong>
                    </div>

                    <div>
                      <p
                        style={{
                          margin: 0,
                          color: "#94a3b8",
                          fontSize: "12px",
                        }}
                      >
                        CONTEXTUAL RISK
                      </p>

                      <strong
                        style={{
                          fontSize: "28px",
                          color:
                            correlation.correlated_risk.classification ===
                            "CRITICAL"
                              ? "#f87171"
                              : correlation.correlated_risk.classification ===
                                "HIGH"
                              ? "#fb923c"
                              : correlation.correlated_risk.classification ===
                                "SUSPICIOUS"
                              ? "#facc15"
                              : "#4ade80",
                        }}
                      >
                        {correlation.correlated_risk.score}{" "}
                        {correlation.correlated_risk.classification}
                      </strong>
                    </div>
                  </div>

                  <div style={{ marginTop: "22px", lineHeight: 1.8 }}>
                    <p>
                      <strong>Relationship:</strong>{" "}
                      {displayLabel(correlation.relationship)}
                    </p>

                    <p>
                      <strong>Correlation confidence:</strong>{" "}
                      {correlation.confidence}
                    </p>

                    <p>
                      <strong>Shared technical indicators:</strong>{" "}
                      {correlation.shared_indicator_count}
                    </p>

                    <p>
                      <strong>Attribution:</strong>{" "}
                      {displayLabel(correlation.attribution)}
                    </p>
                  </div>

                  {correlation.shared_indicators.length > 0 && (
                    <>
                      <h4 style={{ marginTop: "22px" }}>
                        Shared Evidence
                      </h4>

                      <ul style={{ lineHeight: 1.8 }}>
                        {correlation.shared_indicators.map(
                          (indicator, index) => (
                            <li
                              key={`${indicator.type}-${indicator.value}-${index}`}
                            >
                              <strong>{indicator.type}</strong>:{" "}
                              {indicator.value}
                            </li>
                          )
                        )}
                      </ul>
                    </>
                  )}

                  <p
                    style={{
                      marginTop: "20px",
                      color: "#94a3b8",
                      fontSize: "13px",
                    }}
                  >
                    Technical correlation does not establish attacker identity
                    or legal attribution.
                  </p>
                </div>
              )}
            </div>
            <div
              style={{
                padding: "24px",
                marginBottom: "28px",
                border: "1px solid #22d3ee",
                borderRadius: "14px",
                background: "#0b1627",
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
                INCIDENT & EVIDENCE
              </p>

              {!incident ? (
                <>
                  <p
                    style={{
                      color: "#cbd5e1",
                      lineHeight: 1.6,
                      marginTop: "16px",
                    }}
                  >
                    Preserve this analysis as an explicit incident record.
                    Analysis alone does not retain evidence.
                  </p>

                  <button
                    onClick={createIncident}
                    disabled={creatingIncident}
                    style={{
                      marginTop: "8px",
                      padding: "14px 24px",
                      borderRadius: "8px",
                      border: 0,
                      fontWeight: 700,
                      cursor: creatingIncident ? "not-allowed" : "pointer",
                    }}
                  >
                    {creatingIncident
                      ? "CREATING INCIDENT..."
                      : "CREATE INCIDENT"}
                  </button>
                </>
              ) : (
                <>
                  <div style={{ marginTop: "18px", lineHeight: 1.8 }}>
                    <p>
                      <strong>Incident ID:</strong> {incident.incident_id}
                    </p>

                    <p>
                      <strong>Status:</strong> {incident.status}
                    </p>

                    <p>
                      <strong>Created:</strong>{" "}
                      {new Date(incident.created_at).toLocaleString()}
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
                    onClick={exportIncidentJson}
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
                    Evidence export preserves the analyzed message SHA-256,
                    findings, risk assessment and security controls.
                  </p>
                </>
              )}
            </div>

            <h3>Technical Evidence</h3>

            <p><strong>File:</strong> {analysis.filename}</p>
            <p><strong>SHA-256:</strong> {analysis.sha256}</p>
            <p><strong>Subject:</strong> {analysis.subject || "Not available"}</p>
            <p><strong>From:</strong> {analysis.from || "Not available"}</p>
            <p><strong>Reply-To:</strong> {analysis.reply_to || "Not available"}</p>
            <p><strong>Return-Path:</strong> {analysis.return_path || "Not available"}</p>

            <h4 style={{ marginTop: "24px" }}>Authentication Evidence</h4>
            <p>
              <strong>Reported:</strong>{" "}
              {analysis.authentication_results.reported || "Not available"}
            </p>
            <p>
              <strong>Trust:</strong> {analysis.authentication_results.trust}
            </p>
            <p>
              <strong>Verified:</strong>{" "}
              {analysis.authentication_results.verified ? "Yes" : "No"}
            </p>

            <h4 style={{ marginTop: "24px" }}>URLs</h4>
            {analysis.urls.length > 0 ? (
              <ul>
                {analysis.urls.map((url) => (
                  <li key={url}>{url}</li>
                ))}
              </ul>
            ) : (
              <p>No URLs detected.</p>
            )}

            <h4 style={{ marginTop: "24px" }}>Attachments</h4>
            {analysis.attachments.length > 0 ? (
              <ul>
                {analysis.attachments.map((item) => (
                  <li key={`${item.filename}-${item.sha256}`}>
                    {item.filename} — {item.content_type} — {item.size_bytes} bytes
                  </li>
                ))}
              </ul>
            ) : (
              <p>No attachments detected.</p>
            )}

            <h4 style={{ marginTop: "24px" }}>Security Controls</h4>
            <ul>
              <li>Active HTML executed: No</li>
              <li>Attachments executed: No</li>
              <li>URLs visited: No</li>
              <li>Remote content loaded: No</li>
            </ul>
          </div>
        )}

        <div style={{ marginTop: "28px", color: "#94a3b8" }}>
          API STATUS:{" "}
          <strong
            style={{
              color: apiStatus === "ONLINE" ? "#22c55e" : "#f59e0b",
            }}
          >
            {apiStatus}
          </strong>
        </div>

        <p style={{ marginTop: "32px", color: "#64748b" }}>
          Analyze by default. Retain by choice.
        </p>
      </div>
    </main>
  );
}
















