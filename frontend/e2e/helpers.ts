import { expect, type Page } from "@playwright/test";

export const PASSWORD = "demo-password";
export const CVE = "CVE-2021-44228";

/** Signs in through the real Keycloak login page (no shortcuts), then waits for the overview. */
export async function login(page: Page, username: string): Promise<void> {
  await page.goto("/login");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.locator("#username").fill(username);
  await page.locator("#password").fill(PASSWORD);
  await page.locator("#kc-login").click();
  await expect(page.getByTestId("whoami")).toBeVisible({ timeout: 30_000 });
}

export async function logout(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
}
