import Link from "next/link";
import { Banner, ErrorPanel, Panel, Pill, Td, Th } from "@/components/ui";
import { backendGet, load, requireViewer } from "@/lib/server";
import type { VulnerabilitySearch } from "@/lib/types";

export const dynamic = "force-dynamic";

type Params = Promise<{ query?: string; kevOnly?: string; minCvss?: string }>;

export default async function VulnerabilitiesPage({ searchParams }: { searchParams: Params }) {
  const { token } = await requireViewer();
  const sp = await searchParams;
  const qs = new URLSearchParams();
  const query = sp.query?.trim();
  if (query) qs.set("query", query);
  if (sp.kevOnly === "true") qs.set("kevOnly", "true");
  if (sp.minCvss && sp.minCvss !== "") qs.set("minCvss", sp.minCvss);
  qs.set("limit", "30");
  const result = await load(backendGet<VulnerabilitySearch>(`api/vulnerabilities?${qs}`, token));

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Vulnerabilities</h1>
      <Panel>
        <form method="get" className="flex flex-wrap items-end gap-3" role="search">
          <label className="text-sm">
            <span className="block text-xs text-muted">CVE id or keyword</span>
            <input
              name="query"
              defaultValue={sp.query ?? ""}
              placeholder="log4j or CVE-2021-44228"
              minLength={2}
              maxLength={100}
              className="w-64 rounded border border-line bg-bg px-2 py-1"
            />
          </label>
          <label className="text-sm">
            <span className="block text-xs text-muted">Minimum score (0-10)</span>
            <input
              name="minCvss"
              type="number"
              min={0}
              max={10}
              step={0.1}
              defaultValue={sp.minCvss ?? ""}
              className="w-28 rounded border border-line bg-bg px-2 py-1"
            />
          </label>
          <label className="flex items-center gap-2 pb-1 text-sm">
            <input name="kevOnly" type="checkbox" value="true" defaultChecked={sp.kevOnly === "true"} />
            Known exploited only
          </label>
          <button
            type="submit"
            className="rounded bg-accent px-3 py-1.5 text-sm font-semibold text-white dark:text-black"
          >
            Search
          </button>
        </form>
      </Panel>

      {!result.ok ? (
        <ErrorPanel error={result.error} />
      ) : (
        <Panel title={`${result.data.results.length} result(s)`}>
          {result.data.results.length === 0 ? (
            <p className="text-sm text-muted">
              Nothing matches. Only vulnerabilities already loaded into the local database are searched.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full" data-testid="vuln-table">
                <thead>
                  <tr>
                    <Th>CVE</Th>
                    <Th>Score</Th>
                    <Th>KEV</Th>
                    <Th>Description (excerpt)</Th>
                  </tr>
                </thead>
                <tbody>
                  {result.data.results.map((v) => (
                    <tr key={v.cve_id}>
                      <Td className="whitespace-nowrap">
                        <Link
                          className="font-medium text-accent underline"
                          href={`/vulnerabilities/${v.cve_id}`}
                        >
                          {v.cve_id}
                        </Link>
                      </Td>
                      <Td className="whitespace-nowrap">
                        {v.cvss_score ?? "n/a"}{" "}
                        {v.severity && <span className="text-muted">({v.severity})</span>}
                      </Td>
                      <Td>{v.kev_listed ? <Pill tone="red">On KEV</Pill> : "No"}</Td>
                      <Td className="max-w-xl text-muted">{v.description}</Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {result.data.truncated && (
            <div className="mt-3">
              <Banner tone="info">More results exist. Narrow the search to see them.</Banner>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}
