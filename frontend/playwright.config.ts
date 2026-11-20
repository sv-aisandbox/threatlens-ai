import { defineConfig } from "@playwright/test";

// The e2e suite drives the real stack (Keycloak, Spring, Python, Memgraph, Postgres); start it with scripts/start-all.ps1.
export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  retries: 0,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://127.0.0.1:3000",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  // Uses the Chrome already installed on the machine (no browser download). Set E2E_BROWSER_CHANNEL=chromium
  // after `pnpm exec playwright install chromium` to use Playwright's own build instead (for example in CI).
  projects: [
    {
      name: "chromium",
      use: {
        browserName: "chromium",
        ...(process.env.E2E_BROWSER_CHANNEL === "chromium"
          ? {}
          : { channel: process.env.E2E_BROWSER_CHANNEL ?? "chrome" }),
      },
    },
  ],
});
