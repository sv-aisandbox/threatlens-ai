import Link from "next/link";
import { notFound } from "next/navigation";
import { GraphView } from "@/components/GraphView";
import { Banner, ErrorPanel, FreshnessLine, Panel, Pill, StatusBadge, Td, Th } from "@/components/ui";
import { describeSoftware, formatTime, safeHref } from "@/lib/format";
import { BackendError, backendGet, load, requireViewer } from "@/lib/server";
import type { AffectedAssets, MatchStatus, VulnerabilityDetails, VulnerabilityGraph } from "@/lib/types";

export const dynamic = "force-dynamic";

const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/;
const ORDER: MatchStatus[] = ["confirmed", "possible", "unknown", "not_affected"];

export default async function VulnerabilityPage({ params }: { params: Promise<{ cveId: string }> }) {
  const { cveId } = await params;
  if (!CVE_PATTERN.test(cveId)) notFound();
  const { token } = await requireViewer();

  const [details, affected, graph] = await Promise.all([
    load(backendGet<VulnerabilityDetails>(`api/vulnerabilities/${cveId}`, token)),
    load(backendGet<AffectedAssets>(`api/vulnerabilities/${cveId}/affected-assets`, token)),
    load(
      backendGet<VulnerabilityGraph>(`api/vulnerabilities/${cveId}/graph?includeNotAffected=false`, token),
    ),
  ]);
  if (!details.ok && details.error instanceof BackendError && details.error.status === 404) notFound();

  return (
    <div className="space-y-4">
      <p className="text-sm">
        <Link href="/vulnerabilities" className="text-accent underline">
          ← All vulnerabilities
        </Link>
      </p>

      {!details.ok ? (
        <ErrorPanel error={details.error} />
      ) : (
        <Panel>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-xl font-semibold">{details.data.cve_id}</h1>
            {details.data.kev_listed && <Pill tone="red">On CISA KEV (known exploited)</Pill>}
            {details.data.synthetic && <Pill>synthetic demo record</Pill>}
          </div>
          <p className="mt-1 text-sm text-muted">
            Score {details.data.cvss_score ?? "n/a"} {details.data.severity && `(${details.data.severity})`}
            {details.data.cvss_vector && ` · ${details.data.cvss_vector}`} · published{" "}
            {formatTime(details.data.published_at)}
          </p>
          {/* Feed text is untrusted: React escapes it, and it is shown only as plain text. */}
          <p className="mt-3 text-sm">{details.data.description}</p>
          {details.data.kev_listed && (
            <p className="mt-2 text-xs text-muted">
              KEV added {details.data.kev_date_added ?? "n/a"} · due {details.data.kev_due_date ?? "n/a"}
              {details.data.kev_ransomware_use && ` · ransomware use: ${details.data.kev_ransomware_use}`}
            </p>
          )}
          <EvidenceList title="Source evidence" evidence={details.data.evidence} />
        </Panel>
      )}

      <Panel title="Your affected assets">
        {!affected.ok ? (
          <ErrorPanel error={affected.error} />
        ) : (
          <>
            <FreshnessLine
              nvd={affected.data.freshness?.intelligence.nvd_last_success_at}
              kev={affected.data.freshness?.intelligence.kev_last_success_at}
              inventory={affected.data.freshness?.inventory_last_imported_at}
            />
            {affected.data.warnings.length > 0 && (
              <div className="mt-3 space-y-2">
                {affected.data.warnings.map((w) => (
                  <Banner key={w} tone="warn">
                    {w}
                  </Banner>
                ))}
              </div>
            )}
            {affected.data.results.length === 0 ? (
              <p className="mt-3 text-sm text-muted">
                No asset in your inventory is linked to this vulnerability. This does not prove safety if the
                inventory or the intelligence is out of date.
              </p>
            ) : (
              <div className="mt-3 overflow-x-auto">
                <table className="w-full" data-testid="affected-table">
                  <thead>
                    <tr>
                      <Th>Match</Th>
                      <Th>Asset</Th>
                      <Th>Environment</Th>
                      <Th>Software</Th>
                      <Th>Why</Th>
                      <Th>Evidence</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {[...affected.data.results]
                      .sort((a, b) => ORDER.indexOf(a.match_status) - ORDER.indexOf(b.match_status))
                      .map((r) => (
                        <tr
                          key={`${r.asset_id}-${r.software?.software_id ?? r.software?.product}`}
                          data-status={r.match_status}
                        >
                          <Td>
                            <StatusBadge status={r.match_status} />
                          </Td>
                          <Td>
                            <div className="font-medium">{r.asset_name ?? r.asset_id}</div>
                            <div className="text-xs text-muted">
                              {r.asset_id} · {r.criticality ?? "?"} criticality
                              {r.internet_exposed ? " · internet-exposed" : ""}
                            </div>
                          </Td>
                          <Td>{r.environment ?? "n/a"}</Td>
                          <Td>{describeSoftware(r.software)}</Td>
                          <Td className="max-w-xs text-muted">
                            {r.match_reason ?? "n/a"}
                            <div className="text-xs">matched {formatTime(r.matched_at)}</div>
                          </Td>
                          <Td>
                            <EvidenceLinks evidence={r.evidence} />
                          </Td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </Panel>

      <Panel title="Asset → software → vulnerability">
        {!graph.ok ? (
          <ErrorPanel error={graph.error} />
        ) : graph.data.nodes.length <= 1 ? (
          <p className="text-sm text-muted">No assets of yours are connected to this vulnerability.</p>
        ) : (
          <>
            {graph.data.truncated && (
              <Banner tone="info">
                The graph is limited to the first assets. Use the table for the full list.
              </Banner>
            )}
            <GraphView graph={graph.data} />
          </>
        )}
      </Panel>
    </div>
  );
}

function EvidenceList({
  title,
  evidence,
}: {
  title: string;
  evidence: {
    evidence_id: string;
    source_name: string;
    source_url: string | null;
    collected_at: string | null;
  }[];
}) {
  if (evidence.length === 0) return null;
  return (
    <div className="mt-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">{title}</h3>
      <ul className="mt-1 space-y-1 text-sm" data-testid="evidence-list">
        {evidence.map((e) => {
          const href = safeHref(e.source_url);
          return (
            <li key={e.evidence_id}>
              {href ? (
                <a href={href} target="_blank" rel="noopener noreferrer" className="text-accent underline">
                  {e.source_name}
                </a>
              ) : (
                <span>{e.source_name}</span>
              )}
              <span className="text-muted"> · collected {formatTime(e.collected_at)}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function EvidenceLinks({
  evidence,
}: {
  evidence: { evidence_id: string; source_name: string; source_url: string | null }[];
}) {
  if (evidence.length === 0) return <span className="text-xs text-muted">none</span>;
  return (
    <ul className="space-y-1 text-xs">
      {evidence.map((e) => {
        const href = safeHref(e.source_url);
        return (
          <li key={e.evidence_id}>
            {href ? (
              <a href={href} target="_blank" rel="noopener noreferrer" className="text-accent underline">
                {e.source_name}
              </a>
            ) : (
              e.source_name
            )}
          </li>
        );
      })}
    </ul>
  );
}
