"use client";

import { signOut } from "next-auth/react";

export function SignOutButton() {
  return (
    <button
      type="button"
      onClick={() => signOut({ callbackUrl: "/login" })}
      className="rounded border border-line px-2 py-1 text-xs hover:bg-bg"
    >
      Sign out
    </button>
  );
}
