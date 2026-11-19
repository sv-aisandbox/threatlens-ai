"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import type { Problem } from "@/lib/types";

/** Shown to ADMIN only. Hiding it is a convenience: the server refuses everyone else with 403. */
export function SyncButton({ sourceId, label }: { sourceId: string; label: string }) {
  const router = useRouter();
  const [state, setState] = useState<{ busy: boolean; message?: string; error?: boolean }>({ busy: false });

  async function start() {
    setState({ busy: true });
    try {
      const response = await fetch(`/api/backend/api/sources/${sourceId}/sync`, { method: "POST" });
      if (!response.ok) {
        const problem = (await response.json().catch(() => ({}))) as Problem;
        setState({
          busy: false,
          error: true,
          message: problem.detail ?? problem.title ?? `Failed (${response.status})`,
        });
        return;
      }
      setState({ busy: false, message: "Sync started. Status refreshes below." });
      for (let i = 0; i < 6; i++) {
        await new Promise((r) => setTimeout(r, 3000));
        router.refresh();
      }
    } catch {
      setState({ busy: false, error: true, message: "The request could not be sent." });
    }
  }

  return (
    <div className="space-y-1">
      <button
        type="button"
        onClick={start}
        disabled={state.busy}
        className="rounded border border-line px-3 py-1 text-sm font-medium hover:bg-bg disabled:opacity-50"
        data-testid={`sync-${sourceId}`}
      >
        {state.busy ? "Starting…" : `Sync ${label} now`}
      </button>
      {state.message && (
        <p
          role="status"
          className={`text-xs ${state.error ? "text-red-700 dark:text-red-300" : "text-muted"}`}
        >
          {state.message}
        </p>
      )}
    </div>
  );
}
