// The scaffold's smoke test: the built page renders under the exact CSP of nginx.conf, loads its fonts
// from its own origin, and makes no request to any other host. `vite preview` sends no CSP, so the
// header of nginx.conf is applied here to the document response.
import { readFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";

const CSP = /add_header\s+Content-Security-Policy\s+"([^"]*)"\s+always;/.exec(
  readFileSync("nginx.conf", "utf8"),
)?.[1];

type CspWindow = Window & { __csp?: string[]; __inlineRan?: boolean };

async function openUnderCsp(
  page: Page,
  origin: string,
): Promise<{ foreign: string[]; woff2: number[] }> {
  expect(CSP, "nginx.conf must carry the CSP").toBeTruthy();
  await page.route("**/*", async (route) => {
    if (route.request().resourceType() !== "document") return route.continue();
    const response = await route.fetch();
    return route.fulfill({
      response,
      headers: { ...response.headers(), "content-security-policy": CSP ?? "" },
    });
  });
  // Playwright's init script is not subject to the page's CSP; it only records the violations.
  await page.addInitScript(() => {
    const w = window as CspWindow;
    w.__csp = [];
    document.addEventListener("securitypolicyviolation", (event) => {
      w.__csp?.push(`${event.violatedDirective} ${event.blockedURI}`);
    });
  });

  const foreign: string[] = [];
  const woff2: number[] = [];
  page.on("response", (response) => {
    if (!response.url().startsWith(origin)) foreign.push(response.url());
    if (new URL(response.url()).pathname.endsWith(".woff2")) woff2.push(response.status());
  });
  await page.goto("/");
  return { foreign, woff2 };
}

test("the page renders under the CSP with no violation and no foreign request", async ({
  page,
  baseURL,
}) => {
  const seen = await openUnderCsp(page, baseURL ?? "");
  await expect(page.getByText("AI Support SOC")).toBeVisible();
  await expect(page.getByRole("banner")).toBeVisible();
  await page.evaluate(() => document.fonts.ready.then(() => undefined));

  expect(await page.evaluate(() => (window as CspWindow).__csp)).toEqual([]);
  expect(seen.foreign).toEqual([]);
  // The IBM Plex subsets are bundled and served by the page's own origin (font-src 'self').
  expect(seen.woff2.length).toBeGreaterThan(0);
  expect(seen.woff2.every((status) => status === 200)).toBe(true);
});

test("the CSP is really in force: an inline script is refused", async ({ page, baseURL }) => {
  await openUnderCsp(page, baseURL ?? "");
  await expect(page.getByText("AI Support SOC")).toBeVisible();
  await page.evaluate(() => {
    const script = document.createElement("script");
    script.textContent = "window.__inlineRan = true;";
    document.head.append(script);
  });
  expect(await page.evaluate(() => (window as CspWindow).__inlineRan)).toBeUndefined();
  const violations = await page.evaluate(() => (window as CspWindow).__csp ?? []);
  expect(violations.some((v) => v.startsWith("script-src"))).toBe(true);
});
