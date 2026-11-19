import type { NextAuthOptions } from "next-auth";
import KeycloakProvider from "next-auth/providers/keycloak";
import type { JWT } from "next-auth/jwt";
import { isExpired, readClaims } from "./token";
import type { Role } from "./types";

declare module "next-auth" {
  // Only non-secret display data. The access token never leaves the server: it stays in the encrypted cookie.
  interface Session {
    roles: Role[];
    tenantId: string | null;
    error?: "RefreshFailed";
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    accessToken?: string;
    refreshToken?: string;
    expiresAt?: number;
    roles?: Role[];
    tenantId?: string | null;
    error?: "RefreshFailed";
  }
}

function setting(name: string, fallback?: string): string {
  const value = process.env[name] ?? fallback;
  if (!value) throw new Error(`Missing server setting ${name} (see frontend/.env.example)`);
  return value;
}

async function refresh(token: JWT): Promise<JWT> {
  if (!token.refreshToken) return { ...token, error: "RefreshFailed" };
  try {
    const response = await fetch(`${setting("KEYCLOAK_ISSUER")}/protocol/openid-connect/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: setting("KEYCLOAK_WEB_CLIENT_ID", "threatlens-web"),
        refresh_token: token.refreshToken,
      }),
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) return { ...token, error: "RefreshFailed" };
    const fresh = (await response.json()) as {
      access_token: string;
      refresh_token?: string;
      expires_in: number;
    };
    const claims = readClaims(fresh.access_token);
    return {
      ...token,
      accessToken: fresh.access_token,
      refreshToken: fresh.refresh_token ?? token.refreshToken,
      expiresAt: claims.expiresAt ?? Math.floor(Date.now() / 1000) + fresh.expires_in,
      roles: claims.roles,
      tenantId: claims.tenantId,
      error: undefined,
    };
  } catch {
    return { ...token, error: "RefreshFailed" };
  }
}

export const authOptions: NextAuthOptions = {
  secret: process.env.NEXTAUTH_SECRET,
  session: { strategy: "jwt", maxAge: 30 * 60 },
  pages: { signIn: "/login" },
  providers: [
    KeycloakProvider({
      clientId: process.env.KEYCLOAK_WEB_CLIENT_ID ?? "threatlens-web",
      clientSecret: "public-client", // threatlens-web is a public PKCE client; no secret exists
      issuer: process.env.KEYCLOAK_ISSUER ?? "http://127.0.0.1:8081/realms/threatlens",
      checks: ["pkce", "state"],
      client: { token_endpoint_auth_method: "none" },
    }),
  ],
  callbacks: {
    async jwt({ token, account }) {
      if (account?.access_token) {
        const claims = readClaims(account.access_token);
        return {
          ...token,
          accessToken: account.access_token,
          refreshToken: account.refresh_token,
          expiresAt: claims.expiresAt ?? account.expires_at,
          roles: claims.roles,
          tenantId: claims.tenantId,
          error: undefined,
        };
      }
      return isExpired(token.expiresAt) ? refresh(token) : token;
    },
    async session({ session, token }) {
      session.roles = token.roles ?? [];
      session.tenantId = token.tenantId ?? null;
      session.error = token.error;
      return session;
    },
  },
};
