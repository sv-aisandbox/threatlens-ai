import type { InventoryReject } from "@/lib/types";

/** Rejected rows: which row, which field, what kind of problem. Row values are never echoed back. */
export function RejectReport({ rejects }: { rejects: InventoryReject[] }) {
  if (rejects.length === 0) return <p className="text-sm text-muted">No rows were rejected.</p>;
  return (
    <div className="overflow-x-auto" data-testid="reject-report">
      <p className="mb-1 text-sm font-semibold">{rejects.length} rejected row(s)</p>
      <table className="w-full text-sm">
        <thead>
          <tr>
            <th className="px-2 py-1 text-left text-xs text-muted">Row</th>
            <th className="px-2 py-1 text-left text-xs text-muted">Asset</th>
            <th className="px-2 py-1 text-left text-xs text-muted">Problem</th>
          </tr>
        </thead>
        <tbody>
          {rejects.map((r) => (
            <tr key={`${r.ref}-${r.asset_id}`}>
              <td className="px-2 py-1">{r.ref}</td>
              <td className="px-2 py-1">{r.asset_id ?? "n/a"}</td>
              <td className="px-2 py-1">
                {r.errors.map((e) => `${e.field}: ${e.type.replaceAll("_", " ")}`).join("; ")}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
