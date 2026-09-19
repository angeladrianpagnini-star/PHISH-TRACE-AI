"use client";

import { useEffect, useState } from "react";

type HealthResponse = {
  status: string;
  service: string;
};

export default function Home() {
  const [apiStatus, setApiStatus] = useState("Checking...");

  useEffect(() => {
    const apiBase =
      process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000";

    fetch(`${apiBase}/health`)
      .then((response) => {
        if (!response.ok) {
          throw new Error("API unavailable");
        }
        return response.json();
      })
      .then((data: HealthResponse) => {
        setApiStatus(data.status === "ok" ? "ONLINE" : "DEGRADED");
      })
      .catch(() => {
        setApiStatus("OFFLINE");
      });
  }, []);

  return (
    <main
      style={{
        minHeight: "100vh",
        background: "#07111f",
        color: "#ffffff",
        fontFamily: "Arial, sans-serif",
        padding: "72px 24px",
      }}
    >
      <div style={{ maxWidth: "960px", margin: "0 auto" }}>
        <p
          style={{
            color: "#22d3ee",
            fontWeight: 700,
            letterSpacing: "0.16em",
          }}
        >
          TLN CYBERSECURITY CHALLENGE 2026
        </p>

        <h1 style={{ fontSize: "64px", margin: "20px 0 8px" }}>
          PHISH-TRACE AI
        </h1>

        <h2
          style={{
            fontSize: "26px",
            fontWeight: 400,
            color: "#cbd5e1",
          }}
        >
          From Suspicious Email to Actionable Evidence
        </h2>

        <div
          style={{
            marginTop: "48px",
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

          <button
            disabled
            style={{
              marginTop: "20px",
              padding: "14px 24px",
              borderRadius: "8px",
              border: 0,
              fontWeight: 700,
            }}
          >
            UPLOAD YOUR .EML
          </button>
        </div>

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
