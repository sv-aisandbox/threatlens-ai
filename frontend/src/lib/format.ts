import type { MatchStatus } from "./types";

/** Fixed locale and UTC so server and browser render identical text (no hydration mismatch). */
export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "unknown";
  return `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export function formatAge(hours: number | null | undefined): string {
  if (hours == null) return "never";
  if (hours < 1) return "less than an hour ago";
  if (hours < 48) return `${Math.floor(hours)} h ago`;
  return `${Math.floor(hours / 24)} days ago`;
}

export const STATUS_LABEL: Record<MatchStatus, string> = {
  confirmed: "Confirmed",
  possible: "Possible",
  unknown: "Unknown",
  not_affected: "Not affected",
};

export const STATUS_HELP: Record<MatchStatus, string> = {
  confirmed: "The installed version is inside the affected range. Counts as exposure.",
  possible: "The product matches but the version evidence is incomplete. Needs a person to check.",
  unknown: "Not enough information to decide (for example the version is missing). Never treated as safe.",
  not_affected: "The installed version is outside the affected range.",
};

export function describeSoftware(
  sw: { vendor?: string | null; product?: string | null; version?: string | null } | null,
): string {
  if (!sw) return "unknown software";
  const name = [sw.vendor, sw.product].filter(Boolean).join(" ");
  return `${name || "unknown software"}${sw.version ? ` ${sw.version}` : ""}`;
}

/** Only http(s) links are ever rendered as links; the URL comes from feed data, which is untrusted. */
export function safeHref(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    return u.protocol === "https:" || u.protocol === "http:" ? u.toString() : null;
  } catch {
    return null;
  }
}
