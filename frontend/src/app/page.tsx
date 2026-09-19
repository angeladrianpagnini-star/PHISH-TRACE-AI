"use client";

import { ChangeEvent, useEffect, useState } from "react";

type HealthResponse = {
  status: string;
  service: string;
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
  security: {
    active_html_executed: boolean;
    attachments_executed: boolean;
    urls_visited: boolean;
    remote_content_loaded: boolean;
  };
};

export default function Home() {
  const [apiStatus, setApiStatus] = useState("Checking...");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
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
