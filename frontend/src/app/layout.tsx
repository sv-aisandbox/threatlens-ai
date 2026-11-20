import type { Metadata } from "next";
import type { ReactNode } from "react";
import { getServerSession } from "next-auth";
import { Nav } from "@/components/Nav";
import { Providers } from "@/components/Providers";
import { authOptions } from "@/lib/auth";
import "./globals.css";

export const metadata: Metadata = {
  title: "ThreatLens AI",
  description: "Defensive threat intelligence and attack-path analysis (read-only, synthetic demo data).",
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  const session = await getServerSession(authOptions);
  return (
    <html lang="en">
      <body className="min-h-screen">
        <Providers>
          {session && (
            <Nav
              viewer={{
                name: session.user?.name ?? "signed-in user",
                roles: session.roles,
                tenantId: session.tenantId,
              }}
            />
          )}
          <main className="mx-auto max-w-6xl space-y-4 px-4 py-6">{children}</main>
        </Providers>
      </body>
    </html>
  );
}
