import Link from "next/link";
import { AgeText, Banner, ErrorPanel, Panel, Pill, Stat, Td, Th } from "@/components/ui";
import { formatTime } from "@/lib/format";
import { backendGet, load, requireViewer } from "@/lib/server";
import type { Overview } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function OverviewPage() {
  const { token } = await requireViewer();
  const result = await load(backendGet<Overview>("api/overview", token));
  if (!result.ok) return <ErrorPanel error={result.error} />;
  const o = result.data;
  const anyStale = o.inventory.stale || o.sources.some((s) => s.stale);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h1 className="text-xl font-semibold">Security overview</h1>
        <span className="text-xs text-muted">
          Organization {o.tenant_id} · generated {formatTime(o.generated_at)}
        </span>
      </div>

      {anyStale && (
        <Banner tone="warn">
          <p className="font-semibold">
            Some data is older than {o.stale_after_hours} hours or has never been loaded.
          </p>
          <ul className="mt-1 list-disc pl-5">
            {o.warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
          <p className="mt-1 text-xs text-muted">
            Treat the numbers below as of the timestamps shown, not as live.
          </p>
        </Banner>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat
          label="Vulnerabilities in database"
          value={o.vulnerabilities.total}
          hint={`${o.vulnerabilities.critical_cvss} with a critical score`}
        />
        <Stat
          label="Known exploited (CISA KEV)"
          value={o.vulnerabilities.kev}
          hint="Actively exploited in the wild"
        />
        <Stat
          label="Critical assets affected"
          value={o.assets.affected_critical}
          hint={`of ${o.assets.critical} critical assets · ${o.assets.total} assets total`}
        />
        <Stat
          label="Confirmed exposures"
          value={o.exposure.confirmed}
          hint={`${o.exposure.possible} possible · ${o.exposure.unknown} unknown (not counted as exposure)`}
        />
      </div>

      <Panel title="Data freshness (per source, last successful sync)">
        <div className="overflow-x-auto">
          <table className="w-full" data-testid="freshness-table">
            <thead>
              <tr>
                <Th>Source</Th>
                <Th>Last successful sync</Th>
                <Th>Age</Th>
                <Th>State</Th>
              </tr>
            </thead>
            <tbody>
              {o.sources.map((s) => (
                <tr key={s.source_id}>
                  <Td>{s.label}</Td>
                  <Td>{formatTime(s.last_success_at)}</Td>
                  <Td>
                    <AgeText hours={s.age_hours} />
                  </Td>
                  <Td>{s.stale ? <Pill tone="amber">Stale or never synced</Pill> : <Pill>Fresh</Pill>}</Td>
                </tr>
              ))}
              <tr>
                <Td>Asset inventory (your upload)</Td>
                <Td>{formatTime(o.inventory.last_imported_at)}</Td>
                <Td>
                  <AgeText hours={o.inventory.age_hours} />
                </Td>
                <Td>
                  {o.inventory.stale ? <Pill tone="amber">Stale or never imported</Pill> : <Pill>Fresh</Pill>}
                </Td>
              </tr>
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="Top exposures (confirmed matches on your assets)">
        {o.top_exposures.length === 0 ? (
          <p className="text-sm text-muted">
            No confirmed exposures. That is not proof of safety: check the freshness above.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr>
                  <Th>CVE</Th>
                  <Th>Score</Th>
                  <Th>KEV</Th>
                  <Th>Confirmed assets</Th>
                </tr>
              </thead>
              <tbody>
                {o.top_exposures.map((t) => (
                  <tr key={t.cve_id}>
                    <Td>
                      <Link
                        className="font-medium text-accent underline"
                        href={`/vulnerabilities/${t.cve_id}`}
                      >
                        {t.cve_id}
                      </Link>
                      {t.synthetic && (
                        <span className="ml-2">
                          <Pill>synthetic</Pill>
                        </span>
                      )}
                    </Td>
                    <Td>
                      {t.cvss_score ?? "n/a"}{" "}
                      {t.severity && <span className="text-muted">({t.severity})</span>}
                    </Td>
                    <Td>{t.kev_listed ? <Pill tone="red">On KEV</Pill> : "No"}</Td>
                    <Td>{t.confirmed_assets}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
