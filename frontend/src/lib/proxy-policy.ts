// Which backend calls the browser may make through /api/backend. Everything else is refused before leaving the server.

const ALLOWED: { method: string; pattern: RegExp }[] = [
  { method: "GET", pattern: /^api\/overview$/ },
  { method: "GET", pattern: /^api\/sources\/status$/ },
  { method: "POST", pattern: /^api\/sources\/(nvd|kev)\/sync$/ },
  { method: "GET", pattern: /^api\/vulnerabilities$/ },
  { method: "GET", pattern: /^api\/vulnerabilities\/CVE-\d{4}-\d{4,}(\/(graph|affected-assets))?$/ },
  { method: "POST", pattern: /^api\/inventory\/import$/ },
  { method: "GET", pattern: /^api\/inventory\/imports$/ },
  { method: "GET", pattern: /^api\/inventory\/imports\/[0-9a-f-]{36}$/ },
  { method: "POST", pattern: /^api\/analyst\/ask$/ },
];

/** Query parameters are forwarded as given, but never a tenant: the tenant comes from the token. */
const BLOCKED_PARAMS = new Set(["tenant_id", "tenantid", "tenant"]);

export function isAllowed(method: string, path: string): boolean {
  if (path.includes("..") || path.includes("//") || path.includes("%")) return false;
  return ALLOWED.some((rule) => rule.method === method.toUpperCase() && rule.pattern.test(path));
}

export function safeQuery(params: URLSearchParams): string {
  const out = new URLSearchParams();
  for (const [key, value] of params) {
    if (!BLOCKED_PARAMS.has(key.toLowerCase())) out.append(key, value);
  }
  const text = out.toString();
  return text ? `?${text}` : "";
}
