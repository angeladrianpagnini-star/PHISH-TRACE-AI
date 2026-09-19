"use client";

import {
  Background,
  Controls,
  Edge,
  MarkerType,
  Node,
  ReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

type SharedIndicator = {
  type: string;
  value: string;
};

type ThreatGraphProps = {
  baselineFilename: string;
  currentFilename: string;
  sharedIndicators: SharedIndicator[];
};

function readableType(type: string) {
  return type.replaceAll("_", " ");
}

export default function ThreatGraph({
  baselineFilename,
  currentFilename,
  sharedIndicators,
}: ThreatGraphProps) {
  const indicatorNodes: Node[] = sharedIndicators.map((indicator, index) => ({
    id: `indicator-${index}`,
    position: {
      x: 310,
      y: 35 + index * 115,
    },
    data: {
      label: (
        <div style={{ textAlign: "center" }}>
          <div
            style={{
              fontSize: "10px",
              letterSpacing: "1px",
              textTransform: "uppercase",
              opacity: 0.7,
              marginBottom: "5px",
            }}
          >
            {readableType(indicator.type)}
          </div>
          <strong>{indicator.value}</strong>
        </div>
      ),
    },
    style: {
      width: 230,
      padding: "12px",
      border: "1px solid #8b5cf6",
      borderRadius: "8px",
      background: "#171326",
      color: "#f5f3ff",
      fontSize: "12px",
    },
  }));

  const nodes: Node[] = [
    {
      id: "baseline",
      position: { x: 20, y: 135 },
      data: {
        label: (
          <div style={{ textAlign: "center" }}>
            <div
              style={{
                fontSize: "10px",
                letterSpacing: "1px",
                opacity: 0.7,
                marginBottom: "5px",
              }}
            >
              BASELINE EMAIL
            </div>
            <strong>{baselineFilename}</strong>
          </div>
        ),
      },
      style: {
        width: 190,
        padding: "14px",
        border: "1px solid #22d3ee",
        borderRadius: "8px",
        background: "#0d1b24",
        color: "#ecfeff",
      },
    },
    ...indicatorNodes,
    {
      id: "current",
      position: { x: 650, y: 135 },
      data: {
        label: (
          <div style={{ textAlign: "center" }}>
            <div
              style={{
                fontSize: "10px",
                letterSpacing: "1px",
                opacity: 0.7,
                marginBottom: "5px",
              }}
            >
              CURRENT EMAIL
            </div>
            <strong>{currentFilename}</strong>
          </div>
        ),
      },
      style: {
        width: 190,
        padding: "14px",
        border: "1px solid #ef4444",
        borderRadius: "8px",
        background: "#241014",
        color: "#fff1f2",
      },
    },
  ];

  const edges: Edge[] = sharedIndicators.flatMap((_, index) => [
    {
      id: `baseline-indicator-${index}`,
      source: "baseline",
      target: `indicator-${index}`,
      animated: true,
      markerEnd: {
        type: MarkerType.ArrowClosed,
      },
    },
    {
      id: `indicator-current-${index}`,
      source: `indicator-${index}`,
      target: "current",
      animated: true,
      markerEnd: {
        type: MarkerType.ArrowClosed,
      },
    },
  ]);

  if (sharedIndicators.length === 0) {
    return null;
  }

  return (
    <section
      style={{
        marginTop: "24px",
        border: "1px solid #3b2d5e",
        borderRadius: "12px",
        padding: "20px",
        background: "#100d18",
      }}
    >
      <div style={{ marginBottom: "14px" }}>
        <h3 style={{ margin: 0, color: "#c4b5fd" }}>THREAT GRAPH</h3>

        <p
          style={{
            margin: "7px 0 0",
            fontSize: "12px",
            opacity: 0.72,
          }}
        >
          Shared technical evidence between analyzed emails. Technical
          correlation does not establish attacker identity or legal
          attribution.
        </p>
      </div>

      <div
        style={{
          height: "390px",
          border: "1px solid #292238",
          borderRadius: "8px",
          overflow: "hidden",
          background: "#09070e",
        }}
      >
        <ReactFlow
          nodes={nodes}
          edges={edges}
          fitView
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable={false}
          panOnDrag
          zoomOnScroll
          minZoom={0.65}
          maxZoom={1.4}
        >
          <Background gap={22} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
    </section>
  );
}