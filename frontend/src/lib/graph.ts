import type { ElementDefinition } from "cytoscape";
import type { VulnerabilityGraph } from "./types";

/** Converts the API graph to Cytoscape elements. Edges whose ends are missing are dropped, never invented. */
export function toElements(graph: VulnerabilityGraph): ElementDefinition[] {
  const ids = new Set(graph.nodes.map((n) => n.id));
  const nodes: ElementDefinition[] = graph.nodes.map((n) => ({
    data: {
      id: n.id,
      label: n.label,
      kind: n.type,
      critical:
        n.type === "asset" && (n.criticality === "critical" || n.criticality === "high") ? "yes" : "no",
    },
  }));
  const edges: ElementDefinition[] = graph.edges
    .filter((e) => ids.has(e.source) && ids.has(e.target))
    .map((e, i) => ({
      data: {
        id: `e${i}`,
        source: e.source,
        target: e.target,
        kind: e.type,
        status: e.match_status ?? "none",
        label: e.type === "AFFECTED_BY" ? (e.match_status ?? "") : "runs",
      },
    }));
  return [...nodes, ...edges];
}
