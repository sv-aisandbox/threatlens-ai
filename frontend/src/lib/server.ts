import "server-only";
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { getServerSession } from "next-auth";
import { getToken } from "next-auth/jwt";
import type { NextRequest } from "next/server";
import { authOptions } from "./auth";
import { isExpired } from "./token";
import type { Problem, Role } from "./types";

export const BACKEND_URL = process.env.BACKEND_URL ?? "http://127.0.0.1:8080";

export interface Viewer {
  name: string;
  roles: Role[];
  tenantId: string | null;
}

/** Reads the access token out of the encrypted session cookie. Server only: it is never put in the page or in JS. */
export async function accessTokenFrom(req?: NextRequest): Promise<string | null> {
  const source = req ?? ({ cookies: await cookies(), headers: await headers() } as unknown as NextRequest);
  const token = await getToken({ req: source, secret: process.env.NEXTAUTH_SECRET });
  if (!token?.accessToken || token.error || isExpired(token.expiresAt)) return null;
  return token.accessToken;
}

/** For pages: returns the signed-in viewer and the token, or sends the browser to /login. */
export async function requireViewer(): Promise<{ viewer: Viewer; token: string }> {
  const session = await getServerSession(authOptions);
  const token = session ? await accessTokenFrom() : null;
  if (!session || !token) redirect("/login");
  return {
    token,
    viewer: {
      name: session.user?.name ?? "signed-in user",
      roles: session.roles,
      tenantId: session.tenantId,
    },
  };
}

export class BackendError extends Error {
  constructor(
    readonly status: number,
    readonly problem: Problem,
  ) {
    super(problem.detail ?? problem.title ?? `Request failed (${status})`);
  }
}

export async function backendGet<T>(path: string, token: string): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${BACKEND_URL}/${path}`, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
      cache: "no-store",
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    throw new BackendError(503, {
      status: 503,
      title: "Backend unavailable",
      detail: "The ThreatLens API did not respond.",
    });
  }
  if (!response.ok) {
    const problem = (await response.json().catch(() => ({}))) as Problem;
    throw new BackendError(response.status, { ...problem, status: response.status });
  }
  return (await response.json()) as T;
}

export type Loaded<T> = { ok: true; data: T } | { ok: false; error: BackendError };

/** Lets a page render the failure of one panel (403, 502, timeout) without losing the rest of the page. */
export async function load<T>(promise: Promise<T>): Promise<Loaded<T>> {
  try {
    return { ok: true, data: await promise };
  } catch (e) {
    if (e instanceof BackendError) return { ok: false, error: e };
    throw e;
  }
}
