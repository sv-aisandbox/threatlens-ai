import type { Role } from "./types";

const ROLES: readonly Role[] = ["ADMIN", "SECURITY_ANALYST", "VIEWER"];

export interface TokenClaims {
  roles: Role[];
  tenantId: string | null;
  expiresAt: number | null; // epoch seconds
}

/**
 * Reads claims from an access token for DISPLAY decisions only (which buttons to show). The signature is not checked
 * here: the Spring backend validates every request and is the only thing that grants access.
 */
export function readClaims(accessToken: string | undefined | null): TokenClaims {
  const empty: TokenClaims = { roles: [], tenantId: null, expiresAt: null };
  if (!accessToken) return empty;
  try {
    const part = accessToken.split(".")[1];
    if (!part) return empty;
    const json = JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as {
      tenant_id?: unknown;
      exp?: unknown;
      realm_access?: { roles?: unknown };
    };
    const roles = Array.isArray(json.realm_access?.roles)
      ? ROLES.filter((r) => (json.realm_access?.roles as unknown[]).includes(r))
      : [];
    return {
      roles,
      tenantId: typeof json.tenant_id === "string" ? json.tenant_id : null,
      expiresAt: typeof json.exp === "number" ? json.exp : null,
    };
  } catch {
    return empty;
  }
}

export const isAdmin = (roles: readonly Role[]) => roles.includes("ADMIN");
export const canUseAnalyst = (roles: readonly Role[]) =>
  roles.includes("ADMIN") || roles.includes("SECURITY_ANALYST");
export const canViewImports = canUseAnalyst;

/** True when the token is missing, expired, or about to expire. */
export function isExpired(
  expiresAt: number | null | undefined,
  nowSeconds = Date.now() / 1000,
  skew = 20,
): boolean {
  return expiresAt == null || expiresAt - skew <= nowSeconds;
}
