import Link from "next/link";
import type { Viewer } from "@/lib/server";
import { SignOutButton } from "./SignOutButton";

const LINKS = [
  { href: "/", label: "Overview" },
  { href: "/vulnerabilities", label: "Vulnerabilities" },
  { href: "/sources", label: "Data sources" },
  { href: "/analyst", label: "AI analyst" },
];

export function Nav({ viewer }: { viewer: Viewer }) {
  return (
    <header className="border-b border-line bg-panel">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
        <Link href="/" className="text-base font-bold tracking-tight">
          ThreatLens AI
        </Link>
        <nav aria-label="Main" className="flex flex-wrap gap-4 text-sm">
          {LINKS.map((l) => (
            <Link key={l.href} href={l.href} className="text-muted hover:text-ink">
              {l.label}
            </Link>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-3 text-xs text-muted" data-testid="whoami">
          <span>
            {viewer.name} · {viewer.roles.join(", ") || "no role"} · tenant {viewer.tenantId ?? "none"}
          </span>
          <SignOutButton />
        </div>
      </div>
    </header>
  );
}
