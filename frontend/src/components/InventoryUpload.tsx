"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { RejectReport } from "./RejectReport";
import type { InventoryImportResult, Problem } from "@/lib/types";

const MAX_BYTES = 5 * 1024 * 1024;

/** Shown to ADMIN only. The file is checked again by the server (type, size, columns, tenant). */
export function InventoryUpload() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<InventoryImportResult | null>(null);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const file = new FormData(event.currentTarget).get("file");
    setError(null);
    setResult(null);
    if (!(file instanceof File) || file.size === 0) return setError("Choose a CSV or JSON file first.");
    if (!/\.(csv|json)$/i.test(file.name)) return setError("Only .csv and .json files are accepted.");
    if (file.size > MAX_BYTES) return setError("The file is larger than 5 MB.");

    setBusy(true);
    try {
      const body = new FormData();
      body.set("file", file);
      const response = await fetch("/api/backend/api/inventory/import", { method: "POST", body });
      if (!response.ok) {
        const problem = (await response.json().catch(() => ({}))) as Problem;
        setError(problem.detail ?? problem.title ?? `The upload failed (${response.status}).`);
      } else {
        setResult((await response.json()) as InventoryImportResult);
        router.refresh();
      }
    } catch {
      setError("The upload could not be sent.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      <form onSubmit={submit} className="flex flex-wrap items-end gap-3" data-testid="upload-form">
        <label className="text-sm">
          <span className="block text-xs text-muted">Inventory file (CSV or JSON, up to 5 MB)</span>
          <input name="file" type="file" accept=".csv,.json" className="text-sm" />
        </label>
        <button
          type="submit"
          disabled={busy}
          className="rounded bg-accent px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-50 dark:text-black"
        >
          {busy ? "Importing…" : "Import"}
        </button>
      </form>
      <p className="text-xs text-muted">The organization is taken from your sign-in, never from the file.</p>
      {error && (
        <p
          role="alert"
          className="rounded border border-red-600 bg-red-600/10 px-3 py-2 text-sm"
          data-testid="upload-error"
        >
          {error}
        </p>
      )}
      {result && (
        <div className="space-y-2" data-testid="upload-result">
          <p className="text-sm">
            Imported {result.rows_accepted} of {result.rows_received} rows ({result.assets_imported} assets,{" "}
            {result.software_imported} software items).{" "}
            {result.matching
              ? `Matching: ${result.matching.created} new, ${result.matching.updated} updated, ${result.matching.removed} removed.`
              : "No software was imported, so nothing needed matching."}
          </p>
          <RejectReport rejects={result.rejects} />
        </div>
      )}
    </div>
  );
}
