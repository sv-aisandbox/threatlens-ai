"use client";

import { signIn } from "next-auth/react";

export function LoginButton() {
  return (
    <button
      type="button"
      onClick={() => signIn("keycloak", { callbackUrl: "/" })}
      className="w-full rounded bg-accent px-4 py-2 text-sm font-semibold text-white dark:text-black"
    >
      Sign in
    </button>
  );
}
