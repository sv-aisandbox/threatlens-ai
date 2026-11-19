import { expect, test } from "@playwright/test";
import { CVE, login, logout } from "./helpers";

// Runs against the real stack (scripts/start-all.ps1): Keycloak login, Spring, Python, Memgraph, Postgres.
// Spec section 18 demo steps 1-6 and 9.

test.describe("analyst (bob-analyst, TENANT-DEMO)", () => {
  test("login, overview loads with per-source freshness (demo 1)", async ({ page }) => {
    await login(page, "bob-analyst");
    await expect(page.getByRole("heading", { name: "Security overview" })).toBeVisible();
    await expect(page.getByText("Known exploited (CISA KEV)")).toBeVisible();
    await expect(page.getByText("Critical assets affected")).toBeVisible();
    const freshness = page.getByTestId("freshness-table");
    await expect(freshness).toContainText("NVD");
    await expect(freshness).toContainText("CISA Known Exploited Vulnerabilities");
    await expect(freshness).toContainText("Asset inventory");
    await expect(page.getByTestId("whoami")).toContainText("TENANT-DEMO");
  });

  test("open a CVE: evidence, affected assets with distinct match states, graph (demo 2-3)", async ({
    page,
  }) => {
    await login(page, "bob-analyst");
    await page.getByRole("link", { name: "Vulnerabilities", exact: true }).click();
    await page.getByPlaceholder("log4j or CVE-2021-44228").fill("log4j");
    await page.getByRole("button", { name: "Search" }).click();
    await expect(page.getByTestId("vuln-table")).toContainText(CVE);
    await page.getByRole("link", { name: CVE }).first().click();

    await expect(page.getByRole("heading", { name: CVE })).toBeVisible();
    await expect(page.getByText("On CISA KEV")).toBeVisible();
    await expect(page.getByTestId("evidence-list").locator("a").first()).toHaveAttribute(
      "href",
      /^https?:\/\//,
    );

    const rows = page.getByTestId("affected-table").locator("tbody tr");
    await expect(rows.first()).toBeVisible();
    for (const status of ["confirmed", "possible", "unknown"]) {
      await expect(
        page.locator(`[data-testid="affected-table"] tr[data-status="${status}"]`).first(),
      ).toBeVisible();
    }
    // never colour alone: every status badge has a text label
    await expect(
      page.locator('[data-status="confirmed"] span[data-status="confirmed"]').first(),
    ).toContainText("Confirmed");
    await expect(page.getByTestId("freshness")).toContainText("Inventory imported");

    const canvas = page.getByTestId("graph-canvas");
    await expect(canvas).toBeVisible();
    await expect(canvas.locator("canvas").first()).toBeVisible();
  });

  test("AI analyst answers, shows the tool trace and the evidence (demo 4-6)", async ({ page }) => {
    await login(page, "bob-analyst");
    await page.getByRole("link", { name: "AI analyst" }).click();
    await page.getByRole("button", { name: "Ask" }).click();

    await expect(page.getByTestId("analyst-answer")).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId("findings").locator('[data-status="confirmed"]').first()).toBeVisible();
    await expect(page.getByTestId("evidence-panel").locator("a").first()).toHaveAttribute(
      "href",
      /^https?:\/\//,
    );

    const step = page.getByTestId("trace").locator("li").first();
    await expect(step).toContainText("get_affected_assets");
    await step.locator("summary").click();
    await expect(step.getByTestId("trace-args")).toContainText(CVE);
    await expect(step.getByTestId("trace-args")).not.toContainText("tenant");
    await expect(step.locator("summary")).toContainText("asset(s)"); // result summary, built from tool fields
  });

  test("an analyst cannot sync or upload (buttons absent, server refuses)", async ({ page }) => {
    await login(page, "bob-analyst");
    await page.getByRole("link", { name: "Data sources" }).click();
    await expect(page.getByTestId("sources-table")).toBeVisible();
    await expect(page.getByTestId("sync-nvd")).toHaveCount(0);
    await expect(page.getByTestId("upload-form")).toHaveCount(0);
    const refused = await page.request.post("/api/backend/api/sources/nvd/sync");
    expect(refused.status()).toBe(403);
  });
});

test.describe("viewer (carol-viewer): unauthorized requests are denied (demo 9)", () => {
  test("viewer cannot trigger a sync, upload, or use the analyst", async ({ page }) => {
    await login(page, "carol-viewer");
    await expect(page.getByRole("heading", { name: "Security overview" })).toBeVisible();

    await page.getByRole("link", { name: "Data sources" }).click();
    await expect(page.getByTestId("sources-table")).toBeVisible();
    await expect(page.getByTestId("sync-nvd")).toHaveCount(0);
    await expect(page.getByTestId("sync-kev")).toHaveCount(0);
    await expect(page.getByTestId("upload-form")).toHaveCount(0);
    await expect(page.getByText("Only administrators can start a sync.")).toBeVisible();

    // The UI hides the buttons, but the real protection is the server: call the API directly.
    for (const target of ["nvd", "kev"]) {
      const res = await page.request.post(`/api/backend/api/sources/${target}/sync`);
      expect(res.status(), `viewer sync of ${target}`).toBe(403);
    }
    const upload = await page.request.post("/api/backend/api/inventory/import", {
      multipart: { file: { name: "x.csv", mimeType: "text/csv", buffer: Buffer.from("asset_id\nA\n") } },
    });
    expect(upload.status()).toBe(403);
    const history = await page.request.get("/api/backend/api/inventory/imports");
    expect(history.status()).toBe(403);

    // Asking the analyst shows the server's refusal, not an answer
    await page.getByRole("link", { name: "AI analyst" }).click();
    await page.getByRole("button", { name: "Ask" }).click();
    await expect(page.getByTestId("denied")).toContainText("Access denied");
    await expect(page.getByTestId("analyst-answer")).toHaveCount(0);
  });

  test("paths outside the allowlist are not reachable through the UI proxy", async ({ page }) => {
    await login(page, "carol-viewer");
    for (const path of ["actuator/env", "api/../actuator/health", "api/analyst/ask%2f..%2f"]) {
      const res = await page.request.get(`/api/backend/${path}`);
      expect(res.status(), path).toBe(404);
    }
  });

  test("an unauthenticated browser is sent to the login page and the proxy refuses", async ({
    page,
    request,
  }) => {
    await page.goto("/");
    await expect(page).toHaveURL(/\/login/);
    const res = await request.get("/api/backend/api/overview");
    expect(res.status()).toBe(401);
  });
});

test.describe("administrator (alice-admin)", () => {
  test("can see sync actions and upload an inventory with a reject report", async ({ page }) => {
    await login(page, "alice-admin");
    await page.getByRole("link", { name: "Data sources" }).click();
    await expect(page.getByTestId("sync-nvd")).toBeVisible();
    await expect(page.getByTestId("sync-kev")).toBeVisible();

    const csv = [
      "asset_id,name,asset_type,environment,criticality,internet_exposed",
      "ASSET-E2E-001,e2e web server,server,staging,low,false",
      "ASSET-E2E-002,e2e broken row,not-a-type,staging,low,false",
    ].join("\n");
    await page.setInputFiles('input[type="file"]', {
      name: "e2e-inventory.csv",
      mimeType: "text/csv",
      buffer: Buffer.from(csv),
    });
    await page.getByRole("button", { name: "Import" }).click();
    const result = page.getByTestId("upload-result");
    await expect(result).toContainText("Imported 1 of 2 rows", { timeout: 30_000 });
    await expect(page.getByTestId("reject-report")).toContainText("row 3");
    await expect(page.getByTestId("reject-report")).toContainText("asset_type");
    await expect(page.getByTestId("imports-table")).toContainText("e2e-inventory.csv");

    // a file the server rejects as a whole is explained in our wording
    await page.setInputFiles('input[type="file"]', {
      name: "bad.csv",
      mimeType: "text/csv",
      buffer: Buffer.from("name\nx\n"),
    });
    await page.getByRole("button", { name: "Import" }).click();
    await expect(page.getByTestId("upload-error")).toContainText("missing required columns");
  });
});

test.describe("tenant isolation (dave-analyst, TENANT-OTHER)", () => {
  test("another organization sees only its own assets for the same CVE", async ({ page }) => {
    await login(page, "dave-analyst");
    await expect(page.getByTestId("whoami")).toContainText("TENANT-OTHER");
    await page.goto(`/vulnerabilities/${CVE}`);
    const table = page.getByTestId("affected-table");
    await expect(table).toContainText("ASSET-O05");
    await expect(table).not.toContainText("ASSET-013");
    await logout(page);
  });
});
