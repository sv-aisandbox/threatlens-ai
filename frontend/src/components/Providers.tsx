"use client";

import { SessionProvider } from "next-auth/react";
import type { ReactNode } from "react";

// Polling the session endpoint is what lets next-auth refresh the short-lived access token before it expires.
export function Providers({ children }: { children: ReactNode }) {
  return (
    <SessionProvider refetchInterval={120} refetchOnWindowFocus>
      {children}
    </SessionProvider>
  );
}
