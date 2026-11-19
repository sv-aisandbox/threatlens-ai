import { describe, expect, it } from "vitest";
import { describeSoftware, formatAge, formatTime, safeHref } from "./format";
import { toElements } from "./graph";
import { isAllowed, safeQuery } from "./proxy-policy";
import { canUseAnalyst, isAdmin, isExpired, readClaims } from "./token";
import type { VulnerabilityGraph } from "./types";

function jwt(payload: object): string {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "none" })}.${b64(payload)}.sig`;
}

describe("readClaims", () => {
  it("reads known roles, the tenant and the expiry", () => {
    const c = readClaims(
      jwt({ tenant_id: "T1", exp: 123, realm_access: { roles: ["ADMIN", "offline_access", "VIEWER"] } }),
    );
    expect(c).toEqual({ roles: ["ADMIN", "VIEWER"], tenantId: "T1", expiresAt: 123 });
  });
  it("ignores unknown roles and wrong types", () => {
    const c = readClaims(jwt({ tenant_id: 5, exp: "soon", realm_access: { roles: ["ROOT"] } }));
    expect(c).toEqual({ roles: [], tenantId: null, expiresAt: null });
  });
  it("returns nothing for missing or malformed tokens", () => {
    expect(readClaims(undefined).roles).toEqual([]);
    expect(readClaims("not-a-token").roles).toEqual([]);
    expect(readClaims("a.%%%.c").roles).toEqual([]);
  });
});

describe("roles and expiry", () => {
  it("shows admin actions only to ADMIN", () => {
    expect(isAdmin(["ADMIN"])).toBe(true);
    expect(isAdmin(["SECURITY_ANALYST"])).toBe(false);
    expect(isAdmin(["VIEWER"])).toBe(false);
  });
  it("lets analysts and admins use the analyst", () => {
    expect(canUseAnalyst(["SECURITY_ANALYST"])).toBe(true);
    expect(canUseAnalyst(["ADMIN"])).toBe(true);
    expect(canUseAnalyst(["VIEWER"])).toBe(false);
    expect(canUseAnalyst([])).toBe(false);
  });
  it("treats a missing or nearly expired token as expired", () => {
    expect(isExpired(null)).toBe(true);
    expect(isExpired(1000, 990)).toBe(true); // inside the 20 s skew
    expect(isExpired(1000, 900)).toBe(false);
  });
});

describe("proxy policy", () => {
  it("allows only the listed API calls with the listed methods", () => {
    expect(isAllowed("GET", "api/overview")).toBe(true);
    expect(isAllowed("POST", "api/analyst/ask")).toBe(true);
    expect(isAllowed("POST", "api/sources/nvd/sync")).toBe(true);
    expect(isAllowed("POST", "api/sources/kev/sync")).toBe(true);
    expect(isAllowed("POST", "api/sources/cisa_kev/sync")).toBe(false);
    expect(isAllowed("GET", "api/vulnerabilities/CVE-2021-44228/graph")).toBe(true);
    expect(isAllowed("GET", "api/analyst/ask")).toBe(false);
    expect(isAllowed("DELETE", "api/overview")).toBe(false);
    expect(isAllowed("GET", "actuator/health")).toBe(false);
    expect(isAllowed("POST", "api/sources/other/sync")).toBe(false);
  });
  it("rejects traversal and encoded paths", () => {
    expect(isAllowed("GET", "api/vulnerabilities/../../actuator/env")).toBe(false);
    expect(isAllowed("GET", "api//overview")).toBe(false);
    expect(isAllowed("GET", "api/overview%2f..")).toBe(false);
    expect(isAllowed("GET", "api/vulnerabilities/CVE-2021-44228x")).toBe(false);
  });
  it("never forwards a tenant parameter", () => {
    expect(safeQuery(new URLSearchParams("query=log4j&tenant_id=T2&Tenant=T3&limit=5"))).toBe(
      "?query=log4j&limit=5",
    );
    expect(safeQuery(new URLSearchParams("tenantId=x"))).toBe("");
    expect(safeQuery(new URLSearchParams())).toBe("");
  });
});

describe("format", () => {
  it("formats times in UTC and never hides missing data", () => {
    expect(formatTime("2026-11-19T10:05:30+00:00")).toBe("2026-11-19 10:05 UTC");
    expect(formatTime(null)).toBe("never");
    expect(formatTime("garbage")).toBe("unknown");
  });
  it("describes age without calling old data live", () => {
    expect(formatAge(null)).toBe("never");
    expect(formatAge(0.2)).toBe("less than an hour ago");
    expect(formatAge(5.9)).toBe("5 h ago");
    expect(formatAge(72)).toBe("3 days ago");
  });
  it("renders only http(s) links from feed data", () => {
    expect(safeHref("https://nvd.nist.gov/vuln/detail/CVE-2021-44228")).toContain("https://nvd.nist.gov");
    expect(safeHref("javascript:alert(1)")).toBeNull();
    expect(safeHref("data:text/html,<script>")).toBeNull();
    expect(safeHref("not a url")).toBeNull();
    expect(safeHref(null)).toBeNull();
  });
  it("describes software with missing parts", () => {
    expect(describeSoftware({ vendor: "Apache", product: "Log4j", version: "2.14.1" })).toBe(
      "Apache Log4j 2.14.1",
    );
    expect(describeSoftware({ product: "x", version: null })).toBe("x");
    expect(describeSoftware(null)).toBe("unknown software");
  });
});

describe("graph elements", () => {
  const graph: VulnerabilityGraph = {
    cve_id: "CVE-2021-44228",
    truncated: false,
    nodes: [
      { id: "CVE-2021-44228", type: "vulnerability", label: "CVE-2021-44228" },
      { id: "SW", type: "software", label: "Log4j" },
      { id: "A1", type: "asset", label: "web", criticality: "critical" },
      { id: "A2", type: "asset", label: "db", criticality: "low" },
    ],
    edges: [
      { source: "A1", target: "SW", type: "RUNS" },
      { source: "SW", target: "CVE-2021-44228", type: "AFFECTED_BY", match_status: "confirmed" },
      { source: "GHOST", target: "SW", type: "RUNS" },
    ],
  };
  it("keeps real nodes and edges and drops edges to missing nodes", () => {
    const els = toElements(graph);
    expect(els.filter((e) => e.data.source === undefined)).toHaveLength(4);
    expect(els.filter((e) => e.data.source !== undefined)).toHaveLength(2);
  });
  it("marks high-criticality assets and carries the match status on the edge", () => {
    const els = toElements(graph);
    expect(els.find((e) => e.data.id === "A1")?.data.critical).toBe("yes");
    expect(els.find((e) => e.data.id === "A2")?.data.critical).toBe("no");
    expect(els.find((e) => e.data.kind === "AFFECTED_BY")?.data.status).toBe("confirmed");
  });
});
