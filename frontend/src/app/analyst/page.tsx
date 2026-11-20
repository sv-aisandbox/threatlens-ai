import { AnalystChat } from "@/components/AnalystChat";
import { requireViewer } from "@/lib/server";
import { canUseAnalyst } from "@/lib/token";

export const dynamic = "force-dynamic";

export default async function AnalystPage() {
  const { viewer } = await requireViewer();
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">AI analyst</h1>
      <p className="text-sm text-muted">
        The analyst answers only from your organization&apos;s data, using read-only tools. Every tool it
        calls is listed under the answer. It never changes anything.
      </p>
      <AnalystChat canAsk={canUseAnalyst(viewer.roles)} />
    </div>
  );
}
