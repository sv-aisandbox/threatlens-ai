import type { ReactNode } from "react";
import { STATUS_HELP, STATUS_LABEL, formatAge, formatTime } from "@/lib/format";
import type { MatchStatus } from "@/lib/types";
import type { BackendError } from "@/lib/server";

// Status is never colour alone: each badge carries an icon and a text label.
const STATUS_STYLE: Record<MatchStatus, { cls: string; icon: string }> = {
  confirmed: { cls: "border-red-600 bg-red-600/10 text-red-700 dark:text-red-300", icon: "●" },
  possible: { cls: "border-amber-600 bg-amber-500/10 text-amber-800 dark:text-amber-300", icon: "◐" },
  unknown: {
    cls: "border-slate-500 border-dashed bg-slate-500/10 text-slate-700 dark:text-slate-300",
    icon: "?",
  },
  not_affected: {
    cls: "border-emerald-600 bg-emerald-600/10 text-emerald-800 dark:text-emerald-300",
    icon: "✓",
  },
};

export function StatusBadge({ status }: { status: MatchStatus }) {
  const s = STATUS_STYLE[status];
  return (
    <span
      title={STATUS_HELP[status]}
      data-status={status}
      className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs font-semibold ${s.cls}`}
    >
      <span aria-hidden>{s.icon}</span>
      {STATUS_LABEL[status]}
    </span>
  );
}

export function Pill({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "neutral" | "red" | "amber";
}) {
  const cls =
    tone === "red"
      ? "border-red-600 text-red-700 dark:text-red-300"
      : tone === "amber"
        ? "border-amber-600 text-amber-800 dark:text-amber-300"
        : "border-line text-muted";
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${cls}`}>{children}</span>
  );
}

export function Panel({
  title,
  children,
  actions,
}: {
  title?: string;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className="rounded-lg border border-line bg-panel p-4 shadow-sm">
      {(title || actions) && (
        <header className="mb-3 flex items-center justify-between gap-3">
          {title && <h2 className="text-sm font-semibold uppercase tracking-wide text-muted">{title}</h2>}
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="rounded-lg border border-line bg-panel p-4 shadow-sm">
      <div className="text-xs font-semibold uppercase tracking-wide text-muted">{label}</div>
      <div className="mt-1 text-3xl font-semibold tabular-nums">{value}</div>
      {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function Banner({ tone, children }: { tone: "warn" | "error" | "info"; children: ReactNode }) {
  const cls =
    tone === "error"
      ? "border-red-600 bg-red-600/10"
      : tone === "warn"
        ? "border-amber-600 bg-amber-500/10"
        : "border-line bg-panel";
  return (
    <div role={tone === "info" ? "status" : "alert"} className={`rounded-lg border px-4 py-3 text-sm ${cls}`}>
      {children}
    </div>
  );
}

/** Shows both timestamps next to each other so old data is never mistaken for live data. */
export function FreshnessLine({
  nvd,
  kev,
  inventory,
}: {
  nvd: string | null | undefined;
  kev: string | null | undefined;
  inventory: string | null | undefined;
}) {
  return (
    <dl className="grid gap-x-6 gap-y-1 text-xs text-muted sm:grid-cols-3" data-testid="freshness">
      <div>
        <dt className="inline font-semibold">NVD synced: </dt>
        <dd className="inline">{formatTime(nvd)}</dd>
      </div>
      <div>
        <dt className="inline font-semibold">CISA KEV synced: </dt>
        <dd className="inline">{formatTime(kev)}</dd>
      </div>
      <div>
        <dt className="inline font-semibold">Inventory imported: </dt>
        <dd className="inline">{formatTime(inventory)}</dd>
      </div>
    </dl>
  );
}

export function AgeText({ hours }: { hours: number | null }) {
  return <span>{formatAge(hours)}</span>;
}

export function ErrorPanel({ error }: { error: BackendError }) {
  const denied = error.status === 403;
  return (
    <Banner tone="error">
      <p className="font-semibold">{denied ? "Access denied" : "This section could not be loaded"}</p>
      <p>
        {denied
          ? "Your role is not allowed to see this. The server refused the request."
          : (error.problem.detail ?? error.problem.title ?? `Request failed (${error.status}).`)}
      </p>
      {error.problem.correlationId && (
        <p className="mt-1 text-xs text-muted">Reference: {error.problem.correlationId}</p>
      )}
    </Banner>
  );
}

export function Th({ children }: { children?: ReactNode }) {
  return (
    <th className="border-b border-line px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-muted">
      {children}
    </th>
  );
}

export function Td({ children, className = "" }: { children?: ReactNode; className?: string }) {
  return <td className={`border-b border-line px-3 py-2 align-top text-sm ${className}`}>{children}</td>;
}
