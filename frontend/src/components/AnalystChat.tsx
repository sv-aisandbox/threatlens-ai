"use client";

import Link from "next/link";
import { useState } from "react";
import { describeSoftware, formatTime, safeHref } from "@/lib/format";
import type { AnalystAnswer, AnalystFinding, MatchStatus, Problem } from "@/lib/types";
import { Banner, FreshnessLine, Panel, Pill, StatusBadge } from "./ui";

const SAMPLE = "Which of my production assets are affected by CVE-2021-44228, and how sure are we?";

type Result =
  | { kind: "answer"; data: AnalystAnswer }
  | { kind: "denied"; message: string }
  | { kind: "error"; message: string };

export function AnalystChat({ canAsk }: { canAsk: boolean }) {
  const [question, setQuestion] = useState(SAMPLE);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result | null>(null);

  async function ask(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setResult(null);
    try {
      const response = await fetch("/api/backend/api/analyst/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question }),
      });
      if (response.ok) {
        setResult({ kind: "answer", data: (await response.json()) as AnalystAnswer });
      } else {
        const problem = (await response.json().catch(() => ({}))) as Problem;
        if (response.status === 403) {
          setResult({
            kind: "denied",
            message:
              "Access denied. Your role is not allowed to use the AI analyst. The server refused the request.",
          });
        } else if (response.status === 401) {
          setResult({ kind: "error", message: "Your session has expired. Sign in again." });
        } else if (response.status === 429) {
          setResult({
            kind: "error",
            message: "Too many questions in a short time. Wait a minute and try again.",
          });
        } else {
          setResult({
            kind: "error",
            message: problem.detail ?? problem.title ?? `The analyst could not answer (${response.status}).`,
          });
        }
      }
    } catch {
      setResult({ kind: "error", message: "The request could not be sent." });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <Panel>
        <form onSubmit={ask} className="space-y-2">
          <label className="block text-sm font-medium" htmlFor="question">
            Ask about your own assets and the vulnerabilities that affect them
          </label>
          <textarea
            id="question"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            minLength={3}
            maxLength={2000}
            rows={3}
            className="w-full rounded border border-line bg-bg p-2 text-sm"
          />
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="submit"
              disabled={busy || question.trim().length < 3}
              className="rounded bg-accent px-4 py-1.5 text-sm font-semibold text-white disabled:opacity-50 dark:text-black"
            >
              {busy ? "Investigating…" : "Ask"}
            </button>
            {!canAsk && (
              <span className="text-xs text-muted">
                Your role is not an analyst role; the server will refuse this request (shown so you can see
                the check working).
              </span>
            )}
          </div>
        </form>
      </Panel>

      {result?.kind === "denied" && (
        <div data-testid="denied">
          <Banner tone="error">{result.message}</Banner>
        </div>
      )}
      {result?.kind === "error" && <Banner tone="error">{result.message}</Banner>}
      {result?.kind === "answer" && <Answer a={result.data} />}
    </div>
  );
}

function Answer({ a }: { a: AnalystAnswer }) {
  const groups: [MatchStatus, AnalystFinding[]][] = [
    ["confirmed", a.findings.confirmed],
    ["possible", a.findings.possible],
    ["unknown", a.findings.unknown],
  ];
  const hrefs = new Map(a.evidence.map((e) => [e.evidence_id, e]));

  return (
    <div className="space-y-4" data-testid="analyst-answer">
      {a.warnings.map((w) => (
        <Banner key={w} tone="warn">
          {w}
        </Banner>
      ))}
      {!a.grounding.ok && (
        <Banner tone="warn">
          Some identifiers in the narrative could not be tied to tool results. Rely on the findings below, not
          the narrative.
        </Banner>
      )}

      <Panel title="Answer">
        {/* The narrative is model text: shown as plain text only. Findings below are built from tool results. */}
        <p className="whitespace-pre-wrap text-sm" data-testid="answer-text">
          {a.answer}
        </p>
        <p className="mt-3 text-sm">
          <strong>{a.summary.confirmed_exposures}</strong> confirmed · <strong>{a.summary.possible}</strong>{" "}
          possible · <strong>{a.summary.unknown}</strong> unknown
        </p>
        <div className="mt-2">
          <FreshnessLine
            nvd={a.freshness?.intelligence.nvd_last_success_at}
            kev={a.freshness?.intelligence.kev_last_success_at}
            inventory={a.freshness?.inventory_last_imported_at}
          />
        </div>
      </Panel>

      <Panel title="Findings (from tool results)">
        {groups.every(([, rows]) => rows.length === 0) ? (
          <p className="text-sm text-muted">
            No findings. This is not proof of safety if the data is out of date.
          </p>
        ) : (
          <div className="space-y-4" data-testid="findings">
            {groups.map(([status, rows]) =>
              rows.length === 0 ? null : (
                <div key={status}>
                  <div className="mb-1 flex items-center gap-2">
                    <StatusBadge status={status} />
                    <span className="text-xs text-muted">{rows.length}</span>
                  </div>
                  <ul className="space-y-1 text-sm">
                    {rows.map((f) => (
                      <li
                        key={`${f.asset_id}-${f.cve_id}-${f.software?.version}`}
                        className="rounded border border-line px-3 py-2"
                        data-status={status}
                      >
                        <span className="font-medium">{f.asset_name ?? f.asset_id}</span>{" "}
                        <span className="text-xs text-muted">
                          ({f.asset_id}, {f.environment ?? "?"}, {f.criticality ?? "?"})
                        </span>{" "}
                        runs {describeSoftware(f.software)} →{" "}
                        <Link href={`/vulnerabilities/${f.cve_id}`} className="text-accent underline">
                          {f.cve_id}
                        </Link>
                        <div className="text-xs text-muted">
                          {f.reason} · evidence:{" "}
                          {f.evidence_ids.length === 0
                            ? "none"
                            : f.evidence_ids.map((id) => hrefs.get(id)?.source_name ?? id).join(", ")}
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              ),
            )}
          </div>
        )}
      </Panel>

      <Panel title="Evidence">
        {a.evidence.length === 0 ? (
          <p className="text-sm text-muted">No evidence records were cited.</p>
        ) : (
          <ul className="space-y-1 text-sm" data-testid="evidence-panel">
            {a.evidence.map((e) => {
              const href = safeHref(e.source_url);
              return (
                <li key={e.evidence_id}>
                  {href ? (
                    <a
                      href={href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-accent underline"
                    >
                      {e.source_name}
                    </a>
                  ) : (
                    e.source_name
                  )}
                  <span className="text-muted"> · collected {formatTime(e.collected_at)}</span>
                </li>
              );
            })}
          </ul>
        )}
      </Panel>

      <Panel title={`Tool trace (${a.trace.length} call${a.trace.length === 1 ? "" : "s"})`}>
        <ol className="space-y-2" data-testid="trace">
          {a.trace.map((t) => (
            <li key={t.step} className="rounded border border-line">
              <details>
                <summary className="cursor-pointer px-3 py-2 text-sm">
                  <span className="font-mono font-semibold">{t.tool}</span>{" "}
                  <span className="text-muted">{t.result_summary ?? t.outcome}</span>{" "}
                  {t.outcome !== "ok" && <Pill tone="amber">{t.outcome}</Pill>}{" "}
                  {t.injection_suspected && <Pill tone="red">suspicious text neutralized</Pill>}
                </summary>
                <div className="border-t border-line px-3 py-2 text-xs">
                  <div className="font-semibold text-muted">Arguments</div>
                  <pre className="overflow-x-auto font-mono" data-testid="trace-args">
                    {JSON.stringify(t.args, null, 2)}
                  </pre>
                  <div className="mt-1 text-muted">
                    outcome {t.outcome} · {t.latency_ms ?? "?"} ms · call id {t.tool_correlation_id ?? "n/a"}
                  </div>
                </div>
              </details>
            </li>
          ))}
        </ol>
        {a.usage && (
          <p className="mt-2 text-xs text-muted">
            Model: {a.usage.provider}/{a.usage.model} · {a.usage.tool_calls} tool call(s) ·{" "}
            {a.usage.latency_ms} ms
            {a.correlation_id && ` · reference ${a.correlation_id}`}
          </p>
        )}
      </Panel>
    </div>
  );
}
