import { InventoryUpload } from "@/components/InventoryUpload";
import { SyncButton } from "@/components/SyncButton";
import { ErrorPanel, Panel, Pill, Td, Th } from "@/components/ui";
import { formatTime } from "@/lib/format";
import { backendGet, load, requireViewer } from "@/lib/server";
import { canViewImports, isAdmin } from "@/lib/token";
import type { InventoryImportSummary, SourceStatus } from "@/lib/types";

export const dynamic = "force-dynamic";

// status reports "cisa_kev"; the sync endpoint calls the same source "kev"
const SYNC_ID: Record<string, string> = { nvd: "nvd", cisa_kev: "kev" };
const LABELS: Record<string, string> = { nvd: "NVD", cisa_kev: "CISA KEV" };

const EXPECTED = ["nvd", "cisa_kev"];

/** A source that has never run must still be listed (as "never run"), so a missing sync is visible and can be started. */
function withExpected(rows: SourceStatus[]): SourceStatus[] {
  const missing = EXPECTED.filter((id) => !rows.some((r) => r.source_id === id)).map(
    (source_id): SourceStatus => ({
      source_id,
      last_attempt_at: null,
      last_success_at: null,
      last_status: null,
      records_received: null,
      records_created: null,
      records_updated: null,
      records_rejected: null,
      error_summary: null,
      source_modified_at: null,
      sync_cursor_at: null,
    }),
  );
  return [
    ...EXPECTED.map((id) => rows.find((r) => r.source_id === id) ?? missing.find((m) => m.source_id === id)!),
    ...rows.filter((r) => !EXPECTED.includes(r.source_id)),
  ];
}

export default async function SourcesPage() {
  const { token, viewer } = await requireViewer();
  const admin = isAdmin(viewer.roles);
  const [status, imports] = await Promise.all([
    load(backendGet<SourceStatus[]>("api/sources/status", token)),
    canViewImports(viewer.roles)
      ? load(backendGet<InventoryImportSummary[]>("api/inventory/imports", token))
      : null,
  ]);

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Data sources</h1>

      <Panel title="Intelligence sources">
        {!status.ok ? (
          <ErrorPanel error={status.error} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full" data-testid="sources-table">
              <thead>
                <tr>
                  <Th>Source</Th>
                  <Th>Last attempt</Th>
                  <Th>Last success</Th>
                  <Th>Result</Th>
                  <Th>Records</Th>
                  {admin && <Th>Action</Th>}
                </tr>
              </thead>
              <tbody>
                {withExpected(status.data).map((s) => (
                  <tr key={s.source_id}>
                    <Td>{LABELS[s.source_id] ?? s.source_id}</Td>
                    <Td>{formatTime(s.last_attempt_at)}</Td>
                    <Td>{formatTime(s.last_success_at)}</Td>
                    <Td>
                      {s.last_status === "success" ? (
                        <Pill>success</Pill>
                      ) : (
                        <Pill tone="amber">{s.last_status ?? "never run"}</Pill>
                      )}
                      {s.error_summary && <div className="mt-1 text-xs text-muted">{s.error_summary}</div>}
                    </Td>
                    <Td className="text-xs text-muted">
                      {s.records_received ?? 0} received · {s.records_rejected ?? 0} rejected
                    </Td>
                    {admin && (
                      <Td>
                        <SyncButton
                          sourceId={SYNC_ID[s.source_id] ?? s.source_id}
                          label={LABELS[s.source_id] ?? s.source_id}
                        />
                      </Td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {!admin && <p className="mt-3 text-xs text-muted">Only administrators can start a sync.</p>}
      </Panel>

      <Panel title="Asset inventory">
        {admin ? (
          <InventoryUpload />
        ) : (
          <p className="text-sm text-muted">Only administrators can upload an inventory.</p>
        )}
        {imports && (
          <div className="mt-4">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">Import history</h3>
            {!imports.ok ? (
              <ErrorPanel error={imports.error} />
            ) : imports.data.length === 0 ? (
              <p className="mt-1 text-sm text-muted">No inventory has been imported yet.</p>
            ) : (
              <div className="mt-1 overflow-x-auto">
                <table className="w-full" data-testid="imports-table">
                  <thead>
                    <tr>
                      <Th>When</Th>
                      <Th>File</Th>
                      <Th>Rows</Th>
                      <Th>Rejected</Th>
                      <Th>Assets</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {imports.data.map((i) => (
                      <tr key={i.import_id}>
                        <Td>{formatTime(i.imported_at)}</Td>
                        <Td>{i.source_name}</Td>
                        <Td>
                          {i.rows_accepted}/{i.rows_received}
                        </Td>
                        <Td>{i.rows_rejected > 0 ? <Pill tone="amber">{i.rows_rejected}</Pill> : "0"}</Td>
                        <Td>{i.assets_imported}</Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </Panel>
    </div>
  );
}
