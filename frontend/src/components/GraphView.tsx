"use client";

import cytoscape from "cytoscape";
import { useEffect, useRef } from "react";
import { toElements } from "@/lib/graph";
import type { VulnerabilityGraph } from "@/lib/types";

const COLORS = {
  confirmed: "#dc2626",
  possible: "#d97706",
  unknown: "#64748b",
  not_affected: "#059669",
  none: "#94a3b8",
};

export function GraphView({ graph }: { graph: VulnerabilityGraph }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!ref.current) return;
    const cy = cytoscape({
      container: ref.current,
      elements: toElements(graph),
      layout: { name: "breadthfirst", directed: true, spacingFactor: 1.2, padding: 16 },
      userZoomingEnabled: true,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "font-size": 11,
            "text-wrap": "wrap",
            "text-max-width": "110px",
            "text-valign": "bottom",
            "text-margin-y": 4,
            color: "#475569",
            width: 26,
            height: 26,
            "background-color": "#94a3b8",
          },
        },
        {
          selector: 'node[kind = "vulnerability"]',
          style: { shape: "diamond", "background-color": "#dc2626", width: 34, height: 34 },
        },
        {
          selector: 'node[kind = "software"]',
          style: { shape: "round-rectangle", "background-color": "#7c3aed" },
        },
        { selector: 'node[kind = "asset"]', style: { shape: "ellipse", "background-color": "#2563eb" } },
        { selector: 'node[critical = "yes"]', style: { "border-width": 3, "border-color": "#111827" } },
        {
          selector: "edge",
          style: {
            width: 2,
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "line-color": "#94a3b8",
            "target-arrow-color": "#94a3b8",
            label: "data(label)",
            "font-size": 10,
            color: "#475569",
            "text-background-color": "#ffffff",
            "text-background-opacity": 0.8,
            "text-background-padding": "2px",
          },
        },
        // confirmed is solid, possible dashed, unknown dotted: never colour alone
        {
          selector: 'edge[status = "confirmed"]',
          style: {
            "line-color": COLORS.confirmed,
            "target-arrow-color": COLORS.confirmed,
            "line-style": "solid",
            width: 3,
          },
        },
        {
          selector: 'edge[status = "possible"]',
          style: {
            "line-color": COLORS.possible,
            "target-arrow-color": COLORS.possible,
            "line-style": "dashed",
          },
        },
        {
          selector: 'edge[status = "unknown"]',
          style: {
            "line-color": COLORS.unknown,
            "target-arrow-color": COLORS.unknown,
            "line-style": "dotted",
          },
        },
        {
          selector: 'edge[status = "not_affected"]',
          style: {
            "line-color": COLORS.not_affected,
            "target-arrow-color": COLORS.not_affected,
            "line-style": "solid",
          },
        },
      ],
    });
    return () => cy.destroy();
  }, [graph]);

  return (
    <div>
      <div
        ref={ref}
        role="img"
        aria-label={`Graph of assets, software and ${graph.cve_id}. A table with the same information is shown above.`}
        data-testid="graph-canvas"
        className="h-96 w-full rounded border border-line bg-white"
      />
      <ul className="mt-2 flex flex-wrap gap-4 text-xs text-muted" aria-label="Legend">
        <li>◆ vulnerability</li>
        <li>▢ software</li>
        <li>● asset (black ring: high or critical)</li>
        <li>solid red line: confirmed</li>
        <li>dashed amber: possible</li>
        <li>dotted grey: unknown</li>
      </ul>
    </div>
  );
}
