import { NextResponse, type NextRequest } from "next/server";
import { isAllowed, safeQuery } from "@/lib/proxy-policy";
import { BACKEND_URL, accessTokenFrom } from "@/lib/server";

// Browser -> this route -> Spring Boot. The browser never holds a token; the user's access token is added here.
// The backend still decides what is allowed (roles, tenant); this route only narrows which paths are reachable.

export const dynamic = "force-dynamic";

async function forward(req: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  const target = path.join("/");
  if (!isAllowed(req.method, target)) {
    return NextResponse.json(
      { status: 404, title: "Not found" },
      { status: 404, headers: { "Content-Type": "application/problem+json" } },
    );
  }
  const token = await accessTokenFrom(req);
  if (!token) {
    return NextResponse.json(
      { status: 401, title: "Session expired", detail: "Your session has expired. Sign in again." },
      { status: 401, headers: { "Content-Type": "application/problem+json" } },
    );
  }

  const headers: Record<string, string> = { Authorization: `Bearer ${token}`, Accept: "application/json" };
  const contentType = req.headers.get("content-type");
  if (contentType) headers["Content-Type"] = contentType;
  const hasBody = req.method !== "GET" && req.method !== "HEAD";

  try {
    const upstream = await fetch(`${BACKEND_URL}/${target}${safeQuery(req.nextUrl.searchParams)}`, {
      method: req.method,
      headers,
      body: hasBody ? await req.arrayBuffer() : undefined,
      cache: "no-store",
      signal: AbortSignal.timeout(130_000),
    });
    return new NextResponse(await upstream.arrayBuffer(), {
      status: upstream.status,
      headers: { "Content-Type": upstream.headers.get("content-type") ?? "application/json" },
    });
  } catch {
    return NextResponse.json(
      { status: 503, title: "Backend unavailable", detail: "The ThreatLens API did not respond." },
      { status: 503, headers: { "Content-Type": "application/problem+json" } },
    );
  }
}

export { forward as GET, forward as POST };
