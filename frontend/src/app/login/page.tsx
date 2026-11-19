import { LoginButton } from "@/components/LoginButton";

export default function LoginPage() {
  return (
    <div className="mx-auto mt-16 max-w-md space-y-4 rounded-lg border border-line bg-panel p-6 shadow-sm">
      <h1 className="text-xl font-semibold">ThreatLens AI</h1>
      <p className="text-sm text-muted">
        Defensive, read-only threat intelligence for your own assets. Demo data is synthetic. Sign in with
        your organization account.
      </p>
      <LoginButton />
    </div>
  );
}
